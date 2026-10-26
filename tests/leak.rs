//! No descriptor outlives its connection or its server (Unix: counts open descriptors).
//!
//! Its own test binary: other tests' sockets would change the count. The number of
//! connections comes from `NET_IO_LEAK_CONNECTIONS` (default 1,000; the release
//! gate runs 100,000 in release mode). Clients close with RST, so the run does not
//! fill the ephemeral port range with TIME_WAIT entries.

#![cfg(unix)]

mod common;

use std::time::Duration;

use common::{addr, client, eventually, round_trip};
use net_io::{ConnectionInfo, Input, NetError, Session, SessionContext, Step, TcpConnection};

fn open_descriptors() -> usize {
    let dir = if cfg!(target_os = "linux") {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    };
    std::fs::read_dir(dir).expect("fd dir").count()
}

struct Echo;

impl Session for Echo {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let taken = cx.output().push_partial(input.bytes());
        input.consume(taken);
        Step::Write
    }
}

fn echo(conn: &mut TcpConnection) -> Result<(), NetError> {
    let mut buf = [0u8; 512];
    loop {
        let n = conn.recv(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        conn.send_all(&buf[..n])?;
    }
}

/// One receive on a net-io client connection from this thread.
fn warm_thread_wake() {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let mut c = net_io::connect(l.local_addr().expect("addr")).expect("connect");
    let (mut s, _) = l.accept().expect("accept");
    std::io::Write::write_all(&mut s, b"x").expect("write");
    let mut b = [0u8; 1];
    c.recv_exact(&mut b).expect("recv");
}

#[test]
fn test_no_descriptor_leaks() {
    let n: u64 = std::env::var("NET_IO_LEAK_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000);
    // A net-io client that waits (macOS, Windows) creates its thread's wake channel
    // on the first wait and keeps it for the thread's life: create it before
    // counting, so the counts compare connections only.
    warm_thread_wake();
    let before_servers = open_descriptors();
    {
        let sessions =
            net_io::serve_sessions("127.0.0.1:0", |_: &ConnectionInfo| Echo).expect("serve");
        let blocking = net_io::serve("127.0.0.1:0", echo).expect("serve");
        for s in [&sessions, &blocking] {
            let mut c = client(addr(s));
            assert_eq!(round_trip(&mut c, b"warm"), b"warm");
        }
        let closed = |want: u64| sessions.stats().closed + blocking.stats().closed == want;
        assert!(eventually(Duration::from_secs(5), || closed(2)));
        let steady = open_descriptors();
        for i in 0..n {
            let s = if i % 2 == 0 { &sessions } else { &blocking };
            let mut c = net_io::connect(addr(s)).expect("connect");
            let msg = i.to_le_bytes();
            c.send_all(&msg).expect("send");
            let mut back = [0u8; 8];
            c.recv_exact(&mut back).expect("recv");
            assert_eq!(back, msg);
            c.abort();
        }
        assert!(
            eventually(Duration::from_secs(30), || closed(n + 2)),
            "not every connection closed"
        );
        assert!(
            eventually(Duration::from_secs(5), || open_descriptors() == steady),
            "connections leaked descriptors: {} before, {} after {} connections",
            steady,
            open_descriptors(),
            n
        );
        let s = sessions.stats();
        let b = blocking.stats();
        assert_eq!(s.refused + b.refused, 0);
    }
    // Dropping the servers closes every descriptor they opened.
    assert_eq!(open_descriptors(), before_servers);
}
