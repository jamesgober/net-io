//! `ListenerSpec::workers` (serve-net request 6): a listener's own reactor workers,
//! which no other listener's connections use.
#![cfg(feature = "reactor")]

mod common;

use std::io::Write;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use common::{addr, client, round_trip};
use net_io::{
    AllowAll, ConfigReason, ConnectionInfo, DriverKind, Input, ListenerSpec, NetError,
    ServerBuilder, Session, SessionContext, Step, WorkerId,
};

const WAIT: Duration = Duration::from_secs(5);

/// Echoes; `slow` holds its worker thread for a second first, as a flood's busy
/// connections would.
struct Echo;

impl Session for Echo {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        if input.bytes().starts_with(b"slow") {
            std::thread::sleep(Duration::from_secs(1));
        }
        let taken = cx.output().push_partial(input.bytes());
        input.consume(taken);
        Step::Write
    }
    fn on_writable(&mut self, _: &mut SessionContext<'_>) -> Step {
        Step::Read
    }
}

#[test]
fn test_a_listener_with_workers_of_its_own_runs_only_there() {
    let (tx, seen) = mpsc::channel::<(String, WorkerId)>();
    let tx = std::sync::Mutex::new(tx);
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0").name("public"))
        .listener(ListenerSpec::tcp("127.0.0.1:0").name("admin").workers(1))
        .driver(DriverKind::Reactor)
        .workers(2)
        .sessions(move |info: &ConnectionInfo| {
            let name = if info.listener.is_some_and(|l| l.get() == 1) {
                "admin"
            } else {
                "public"
            };
            let _ = tx
                .lock()
                .expect("lock")
                .send((name.to_string(), info.worker));
            Echo
        })
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let public = server.listeners()[0].local.socket_addr().expect("tcp");
    let admin = server.listeners()[1].local.socket_addr().expect("tcp");
    let mut clients = Vec::new();
    for _ in 0..6 {
        let mut c = std::net::TcpStream::connect(public).expect("public");
        assert_eq!(round_trip(&mut c, b"p"), b"p");
        clients.push(c);
    }
    for _ in 0..3 {
        let mut c = std::net::TcpStream::connect(admin).expect("admin");
        assert_eq!(round_trip(&mut c, b"a"), b"a");
        clients.push(c);
    }
    for _ in 0..9 {
        let (name, worker) = seen.recv_timeout(WAIT).expect("a session");
        match name.as_str() {
            "public" => assert!(worker.get() < 2, "public on shared worker {}", worker.get()),
            _ => assert_eq!(worker.get(), 2, "admin on its own worker"),
        }
    }
    // The shared workers are busy; the admin listener still answers at once.
    for c in clients.iter_mut().take(6) {
        c.write_all(b"slow").expect("write");
    }
    std::thread::sleep(Duration::from_millis(50));
    let start = Instant::now();
    assert_eq!(round_trip(&mut clients[6], b"ping"), b"ping");
    assert!(
        start.elapsed() < Duration::from_millis(500),
        "the admin listener waited for the busy workers: {:?}",
        start.elapsed()
    );
    drop(clients);
}

#[test]
fn test_listener_workers_are_refused_where_they_cannot_apply() {
    let invalid = |r: Result<net_io::Server, NetError>| match r {
        Err(NetError::InvalidConfig { field, reason }) => Some((field, reason)),
        _ => None,
    };
    let blocking = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0").workers(1))
        .driver(DriverKind::Blocking)
        .sessions(|_: &ConnectionInfo| Echo)
        .gate(AllowAll)
        .build();
    assert_eq!(
        invalid(blocking),
        Some(("workers", ConfigReason::Inconsistent))
    );
    let zero = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0").workers(0))
        .driver(DriverKind::Reactor)
        .sessions(|_: &ConnectionInfo| Echo)
        .gate(AllowAll)
        .build();
    assert_eq!(invalid(zero), Some(("workers", ConfigReason::Zero)));
    let mut server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .driver(DriverKind::Reactor)
        .sessions(|_: &ConnectionInfo| Echo)
        .gate(AllowAll)
        .build()
        .expect("build");
    let later = server.add_listener(ListenerSpec::tcp("127.0.0.1:0").workers(1));
    assert!(
        matches!(
            later,
            Err(NetError::InvalidConfig {
                field: "workers",
                ..
            })
        ),
        "{later:?}"
    );
    let mut c = {
        server.open_door().expect("open");
        client(addr(&server))
    };
    assert_eq!(round_trip(&mut c, b"x"), b"x");
}
