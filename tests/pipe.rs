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

/// Denies every write; the session's refusal is 512 bytes.
struct DenyWrites;

impl net_io::Gate for DenyWrites {
    type Ticket = ();
    fn admit(
        &self,
        _: &ConnectionInfo,
        _: net_io::AdmitStage,
    ) -> Result<net_io::Admitted<()>, net_io::Refusal> {
        Ok(net_io::Admitted {
            lane: net_io::Lane(0),
            ticket: (),
            tag: net_io::GateTag(0),
        })
    }
    fn readmit(&self, _: &mut (), _: &ConnectionInfo) -> Result<(), net_io::Refusal> {
        Ok(())
    }
    fn check(&self, _: &mut (), _: &net_io::WriteCheck) -> Result<(), net_io::Denial> {
        Err(net_io::Denial { code: 7 })
    }
}

struct Refuses;

impl Session for Refuses {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        input.consume(input.bytes().len());
        let _ = cx.output().push(b"reply");
        Step::Write
    }

    fn on_denied(&mut self, _code: u16, output: &mut net_io::Output) {
        let _ = output.push(&[b'D'; 512]);
    }
}

/// A denial written to a pipe client that does not read leaves the write in the
/// kernel when the connection closes. On the reactor the pipe is on the worker's
/// completion port, and that write must neither reach the port as if it were one
/// of the worker's operations nor stall the worker: the worker serves the next
/// client, and shutdown returns. Run with no outbound buffer (the write cannot
/// finish at once), a one-byte buffer, and a large one.
#[test]
fn test_a_denial_to_a_pipe_client_that_does_not_read() {
    for driver in DRIVERS {
        for outbound in [0u32, 1, 64 * 1024] {
            let n = name();
            let server = ServerBuilder::new()
                .listener(ListenerSpec::pipe(
                    &n,
                    PipeOptions::new().buffer_sizes(64 * 1024, outbound),
                ))
                .driver(driver)
                .workers(1)
                .sessions(|_: &ConnectionInfo| Refuses)
                .gate(DenyWrites)
                .build()
                .expect("build");
            server.open_door().expect("open");
            let mut silent = PipeConnection::connect(&n, WAIT).expect("connect");
            silent.send_all(b"x").expect("send");
            assert!(
                eventually(WAIT, || server.stats().egress_denied == 1),
                "{driver:?} {outbound}: {:?}",
                server.stats()
            );
            std::thread::sleep(Duration::from_millis(200));
            drop(silent);
            // The same worker serves the next client. Whether that client reads the
            // refusal before the close depends on the pipe's buffer (a denial
            // close is abortive, as on TCP); that the worker denied it is what
            // shows the worker is alive.
            let mut reader = PipeConnection::connect(&n, WAIT).expect("connect again");
            reader.send_all(b"y").expect("send");
            let mut got = [0u8; 1];
            if reader.recv_exact(&mut got).is_ok() {
                assert_eq!(&got, b"D", "{driver:?} {outbound}");
            }
            assert!(
                eventually(WAIT, || server.stats().egress_denied == 2),
                "{driver:?} {outbound}: {:?}",
                server.stats()
            );
            drop(reader);
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = server.shutdown(std::time::Instant::now() + Duration::from_secs(1));
                let _ = tx.send(());
            });
            assert!(
                rx.recv_timeout(Duration::from_secs(10)).is_ok(),
                "{driver:?} {outbound}: shutdown did not return"
            );
        }
    }
}
