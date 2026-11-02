//! Named pipes under a server, on both drivers (Windows).

#![cfg(all(windows, feature = "local"))]

mod common;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::eventually;
use net_io::{
    AllowAll, CloseReason, ConnectionInfo, DriverKind, Input, KillReason, ListenerSpec,
    PipeConnection, PipeOptions, Server, ServerBuilder, Session, SessionContext, Step, Transport,
};

const WAIT: Duration = Duration::from_secs(5);
const DRIVERS: [DriverKind; 2] = [DriverKind::Blocking, DriverKind::Reactor];

struct Echo;

impl Session for Echo {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let taken = cx.output().push_partial(input.bytes());
        input.consume(taken);
        Step::Write
    }
}

fn name() -> String {
    static N: AtomicU32 = AtomicU32::new(0);
    format!(
        "net-io-test-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

fn server(driver: DriverKind, pipe: &str) -> Server {
    let server = ServerBuilder::new()
        .listener(ListenerSpec::pipe(pipe, PipeOptions::new()))
        .driver(driver)
        .workers(2)
        .sessions(|info: &ConnectionInfo| {
            assert_eq!(info.transport, Transport::Pipe);
            assert_eq!(
                info.peer_credentials.and_then(|c| c.pid),
                Some(std::process::id())
            );
            Echo
        })
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    server
}

#[test]
fn test_echo_then_peer_closes() {
    for driver in DRIVERS {
        let n = name();
        let server = server(driver, &n);
        let mut c = PipeConnection::connect(&n, WAIT).expect("connect");
        let mut back = [0u8; 4];
        for _ in 0..50 {
            c.send_all(b"ping").expect("send");
            c.recv_exact(&mut back).expect("recv");
            assert_eq!(&back, b"ping");
        }
        drop(c);
        assert!(
            eventually(WAIT, || server.stats().closed == 1),
            "{driver:?}: {:?}",
            server.stats()
        );
        assert_eq!(server.stats().closed_for(CloseReason::PeerClosed), 1);
    }
}

#[test]
fn test_large_exchange() {
    for driver in DRIVERS {
        let n = name();
        let _server = server(driver, &n);
        let mut c = PipeConnection::connect(&n, WAIT).expect("connect");
        let body: Vec<u8> = (0..1u32 << 20).map(|i| (i % 251) as u8).collect();
        let mut back = vec![0u8; 32 * 1024];
        for chunk in body.chunks(back.len()) {
            c.send_all(chunk).expect("send");
            c.recv_exact(&mut back[..chunk.len()]).expect("recv");
            assert_eq!(&back[..chunk.len()], chunk, "{driver:?}");
        }
    }
}

#[test]
fn test_many_clients_at_once() {
    for driver in DRIVERS {
        let n = name();
        let server = server(driver, &n);
        std::thread::scope(|s| {
            // The blocking pool's default cap is one connection per worker.
            let clients = if driver == DriverKind::Blocking {
                2
            } else {
                32
            };
            for i in 0..clients {
                let n = n.clone();
                s.spawn(move || {
                    let mut c = PipeConnection::connect(&n, WAIT).expect("connect");
                    let mut back = [0u8; 1];
                    for _ in 0..20 {
                        c.send_all(&[i]).expect("send");
                        c.recv_exact(&mut back).expect("recv");
                        assert_eq!(back[0], i);
                    }
                });
            }
        });
        assert!(eventually(WAIT, || server.stats().open == 0), "{driver:?}");
    }
}

/// A shutdown with a connection idle on the pipe ends at once: the accept thread
/// wakes from its overlapped wait, and so does the connection's owner.
#[test]
fn test_shutdown_wakes_every_waiter() {
    for driver in DRIVERS {
        let n = name();
        let server = server(driver, &n);
        let _c = PipeConnection::connect(&n, WAIT).expect("connect");
        assert!(eventually(WAIT, || server.stats().open == 1), "{driver:?}");
        let started = std::time::Instant::now();
        drop(server);
        assert!(started.elapsed() < WAIT, "{driver:?}");
    }
}

#[test]
fn test_kill_ends_a_pending_read() {
    for driver in DRIVERS {
        let n = name();
        let ids = Arc::new(Mutex::new(Vec::new()));
        let seen = ids.clone();
        let server = ServerBuilder::new()
            .listener(ListenerSpec::pipe(&n, PipeOptions::new()))
            .driver(driver)
            .workers(2)
            .sessions(move |info: &ConnectionInfo| {
                seen.lock().expect("lock").push(info.id);
                Echo
            })
            .gate(AllowAll)
            .build()
            .expect("build");
        server.open_door().expect("open");
        let mut c = PipeConnection::connect(&n, WAIT).expect("connect");
        c.send_all(b"x").expect("send");
        let mut one = [0u8; 1];
        c.recv_exact(&mut one).expect("recv");
        let id = ids.lock().expect("lock")[0];
        assert!(server.handle().kill(id, KillReason(9)), "{driver:?}");
        assert_eq!(c.recv(&mut one).unwrap_or(0), 0, "{driver:?}");
        assert!(
            eventually(WAIT, || server.stats().killed == 1),
            "{driver:?}"
        );
    }
}
