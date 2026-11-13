//! A per-worker group on the reactor accepts in each worker's own loop (D-197): no
//! accept thread runs, the door, a removal, and the control line still work, and a
//! removed group's sockets are closed when `remove_listener` returns.

#![cfg(all(target_os = "linux", feature = "reactor"))]

mod common;

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use common::{client, round_trip};
use net_io::{
    AllowAll, ConnectionInfo, ControlState, DriverKind, Input, Limits, ListenOptions, ListenerSpec,
    PrefixPolicy, Server, ServerBuilder, Session, SessionContext, SimpleControl, Step,
};

/// Thread names are per process: one test at a time, so no other server's accept
/// threads are counted.
static ONE: Mutex<()> = Mutex::new(());

fn one() -> MutexGuard<'static, ()> {
    ONE.lock().unwrap_or_else(PoisonError::into_inner)
}

struct Echo;

impl Session for Echo {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let taken = cx.output().push_partial(input.bytes());
        input.consume(taken);
        Step::Write
    }
}

fn group() -> ListenerSpec {
    ListenerSpec::tcp_with("127.0.0.1:0", ListenOptions::new().per_worker(true))
}

fn server(listeners: Vec<ListenerSpec>, control: Option<Arc<SimpleControl>>) -> Server {
    let limits = Limits::builder()
        .max_per_source(256, PrefixPolicy::DEFAULT)
        .build()
        .expect("limits");
    let mut b = ServerBuilder::new();
    for l in listeners {
        b = b.listener(l);
    }
    if let Some(c) = control {
        b = b.control(c);
    }
    b.driver(DriverKind::Reactor)
        .workers(4)
        .limits(limits)
        .sessions(|_: &ConnectionInfo| Echo)
        .gate(AllowAll)
        .build()
        .expect("build")
}

fn addr_of(server: &Server, i: usize) -> SocketAddr {
    server.listeners()[i]
        .local
        .socket_addr()
        .expect("ip listener")
}

/// The names of this process's threads that start with `prefix`.
fn threads_named(prefix: &str) -> usize {
    let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
        return 0;
    };
    tasks
        .filter_map(Result::ok)
        .filter_map(|t| std::fs::read_to_string(t.path().join("comm")).ok())
        .filter(|name| name.starts_with(prefix))
        .count()
}

/// Whether a reply arrives within `within`.
fn answered_within(c: &mut TcpStream, within: Duration) -> bool {
    c.set_read_timeout(Some(within)).expect("timeout");
    let mut one = [0u8; 1];
    let got = match c.peek(&mut one) {
        Ok(n) => n > 0,
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => false,
        Err(e) => panic!("peek: {e}"),
    };
    c.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    got
}

#[test]
fn test_a_per_worker_group_accepts_without_accept_threads() {
    let _one = one();
    let server = server(vec![group()], None);
    server.open_door().expect("open");
    // Thread names are cut at 15 bytes: "net-io-accept-0".
    assert_eq!(threads_named("net-io-accept"), 0, "no accept thread");
    let mut conns: Vec<TcpStream> = (0..64).map(|_| client(addr_of(&server, 0))).collect();
    for (i, c) in conns.iter_mut().enumerate() {
        let msg = format!("hello {i}");
        assert_eq!(round_trip(c, msg.as_bytes()), msg.as_bytes());
    }
    assert_eq!(server.stats().accepted, 64);
    drop(conns);
}

#[test]
fn test_a_closed_door_holds_connections_until_it_opens() {
    let _one = one();
    let server = server(vec![group()], None);
    // Door closed: the connection completes in the kernel and waits in the backlog.
    let mut c = client(addr_of(&server, 0));
    c.write_all(b"early").expect("write");
    assert!(!answered_within(&mut c, Duration::from_millis(200)));
    server.open_door().expect("open");
    let mut back = [0u8; 5];
    c.read_exact(&mut back)
        .expect("answered once the door opened");
    assert_eq!(&back, b"early");
    // Closed and opened again: the next connection waits, then is answered.
    server.close_door();
    let mut d = client(addr_of(&server, 0));
    d.write_all(b"again").expect("write");
    assert!(!answered_within(&mut d, Duration::from_millis(200)));
    server.open_door().expect("open");
    let mut back = [0u8; 5];
    d.read_exact(&mut back)
        .expect("answered after the second opening");
    assert_eq!(&back, b"again");
    // The first connection still works.
    assert_eq!(round_trip(&mut c, b"x"), b"x");
}

#[test]
fn test_a_group_added_and_removed_at_run_time() {
    let _one = one();
    let mut server = server(vec![ListenerSpec::tcp("127.0.0.1:0")], None);
    let id = server.add_listener(group()).expect("add a group");
    server.open_door().expect("open");
    let at = addr_of(&server, 1);
    let mut conns: Vec<TcpStream> = (0..16).map(|_| client(at)).collect();
    for c in &mut conns {
        assert_eq!(round_trip(c, b"on"), b"on");
    }
    drop(conns);
    let report = server
        .remove_listener(id, Instant::now() + Duration::from_secs(2))
        .expect("remove");
    let _ = report;
    // Every socket of the group is closed when the removal returns.
    let refused = TcpStream::connect_timeout(&at, Duration::from_secs(1));
    assert!(
        matches!(&refused, Err(e) if e.kind() == ErrorKind::ConnectionRefused),
        "{refused:?}"
    );
    // The other listener is untouched.
    let mut c = client(addr_of(&server, 0));
    assert_eq!(round_trip(&mut c, b"still"), b"still");
}

#[test]
fn test_the_control_line_drains_a_server_with_only_a_group() {
    let _one = one();
    let control = Arc::new(SimpleControl::new());
    let server = server(vec![group()], Some(control.clone()));
    server.open_door().expect("open");
    let at = addr_of(&server, 0);
    let mut c = client(at);
    assert_eq!(round_trip(&mut c, b"before"), b"before");
    control.set(
        ControlState::Draining,
        Some(Instant::now() + Duration::from_secs(2)),
    );
    // A worker sees the line at its next accept: this connection is the nudge. It
    // is refused or waits; either way the drain begins.
    let _nudge = TcpStream::connect_timeout(&at, Duration::from_secs(1));
    let start = Instant::now();
    let report = server.wait_for_stop();
    assert!(start.elapsed() < Duration::from_secs(5), "{report:?}");
}

#[test]
fn test_shutdown_closes_the_group() {
    let _one = one();
    let server = server(vec![group()], None);
    server.open_door().expect("open");
    let at = addr_of(&server, 0);
    let mut c = client(at);
    assert_eq!(round_trip(&mut c, b"x"), b"x");
    drop(c);
    drop(server);
    let refused = TcpStream::connect_timeout(&at, Duration::from_secs(1));
    assert!(
        matches!(&refused, Err(e) if e.kind() == ErrorKind::ConnectionRefused),
        "{refused:?}"
    );
}
