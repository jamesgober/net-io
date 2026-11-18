//! A drain and a connection that has not brought its first request yet
//! (`Limits::first_request_grace`): a client that connected just before the drain
//! and writes its request right after is answered, a silent one closes once the
//! grace has passed, and a shed closes it at once. Every test runs on both drivers.

mod common;

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{addr, client, closed_by_server, eventually};
use net_io::{
    AllowAll, ConnectionInfo, ControlState, DriverKind, Input, Lane, Limits, ListenerSpec, Server,
    ServerBuilder, Session, SessionContext, SimpleControl, Step,
};

#[cfg(feature = "reactor")]
const DRIVERS: [DriverKind; 2] = [DriverKind::Blocking, DriverKind::Reactor];
#[cfg(not(feature = "reactor"))]
const DRIVERS: [DriverKind; 1] = [DriverKind::Blocking];

const WAIT: Duration = Duration::from_secs(5);

struct Echo;

impl Session for Echo {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let taken = cx.output().push_partial(input.bytes());
        input.consume(taken);
        Step::Write
    }
}

fn echo(driver: DriverKind, grace: Option<Duration>, line: Option<Arc<SimpleControl>>) -> Server {
    let mut limits = Limits::builder();
    if let Some(g) = grace {
        limits = limits.first_request_grace(g);
    }
    let builder = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .driver(driver)
        .limits(limits.build().expect("limits"))
        .sessions(|_: &ConnectionInfo| Echo)
        .gate(AllowAll);
    let server = match line {
        Some(l) => builder.control(l).build(),
        None => builder.build(),
    }
    .expect("build");
    server.open_door().expect("open");
    server
}

/// Connects and waits until the server has the connection open.
fn connected(server: &Server) -> (std::net::TcpStream, Instant) {
    let at = Instant::now();
    let c = client(addr(server));
    assert!(
        eventually(WAIT, || server.stats().open == 1),
        "the connection did not open"
    );
    (c, at)
}

#[test]
fn test_a_request_written_just_after_the_drain_starts_is_answered() {
    for d in DRIVERS {
        let server = echo(d, None, None);
        let (mut c, _) = connected(&server);
        let report = std::thread::scope(|s| {
            let drain = s.spawn(|| server.drain(Instant::now() + WAIT));
            std::thread::sleep(Duration::from_millis(100));
            c.write_all(b"hi").expect("write");
            let mut got = [0u8; 2];
            c.read_exact(&mut got)
                .unwrap_or_else(|e| panic!("{d:?}: no reply: {e}"));
            assert_eq!(&got, b"hi", "{d:?}");
            // Answered, the connection is idle again and the drain closes it.
            assert!(closed_by_server(&mut c), "{d:?}");
            drain.join().expect("drain")
        });
        assert_eq!(
            (report.graceful, report.killed),
            (1, 0),
            "{d:?}: {report:?}"
        );
    }
}

#[test]
fn test_with_no_grace_a_silent_connection_closes_at_once() {
    for d in DRIVERS {
        let server = echo(d, Some(Duration::ZERO), None);
        let (mut c, _) = connected(&server);
        let report = server.drain(Instant::now() + WAIT);
        assert_eq!(report.killed, 0, "{d:?}: {report:?}");
        assert!(
            report.took < Duration::from_millis(500),
            "{d:?}: {report:?}"
        );
        assert!(closed_by_server(&mut c), "{d:?}");
    }
}

#[test]
fn test_a_silent_connection_closes_once_the_grace_passed() {
    let grace = Duration::from_millis(300);
    for d in DRIVERS {
        let server = echo(d, Some(grace), None);
        let (mut c, at) = connected(&server);
        let report = server.drain(Instant::now() + WAIT);
        assert!(at.elapsed() >= grace, "{d:?}: closed inside the grace");
        assert_eq!(report.killed, 0, "{d:?}: {report:?}");
        assert!(report.took < Duration::from_secs(3), "{d:?}: {report:?}");
        assert!(closed_by_server(&mut c), "{d:?}");
    }
}

#[test]
fn test_a_shed_closes_a_silent_connection_at_once() {
    for d in DRIVERS {
        let line = Arc::new(SimpleControl::new());
        let server = echo(d, Some(Duration::from_secs(30)), Some(line.clone()));
        let (mut c, _) = connected(&server);
        let start = Instant::now();
        line.set(ControlState::Shed { from_lane: Lane(0) }, None);
        server.handle().wake_all();
        assert!(closed_by_server(&mut c), "{d:?}");
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "{d:?}: the shed waited {:?}",
            start.elapsed()
        );
    }
}
