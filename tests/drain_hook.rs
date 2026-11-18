//! `Session::on_drain` (serve-net request 7): a drain tells an idle session, which
//! may say goodbye and close, or keep the connection until it closes it itself or
//! the drain deadline does. Every test runs on both drivers.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use common::{addr, client, round_trip};
use net_io::{
    AllowAll, CloseReason, ConnectionInfo, DriverKind, Input, ListenerSpec, Server, ServerBuilder,
    Session, SessionContext, Step,
};

#[cfg(feature = "reactor")]
const DRIVERS: [DriverKind; 2] = [DriverKind::Blocking, DriverKind::Reactor];
#[cfg(not(feature = "reactor"))]
const DRIVERS: [DriverKind; 1] = [DriverKind::Blocking];

/// Echoes; `ok` closes; a drain gets `bye\n`, then closes or (`keep`) waits for `ok`.
struct Polite {
    keep: bool,
}

impl Session for Polite {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        if input.bytes().starts_with(b"ok") {
            let n = input.bytes().len();
            input.consume(n);
            return Step::Close;
        }
        let taken = cx.output().push_partial(input.bytes());
        input.consume(taken);
        Step::Write
    }
    fn on_writable(&mut self, _: &mut SessionContext<'_>) -> Step {
        Step::Read
    }
    fn on_drain(&mut self, cx: &mut SessionContext<'_>) -> Step {
        let _ = cx.output().push(b"bye\n");
        if self.keep {
            // The goodbye goes out, then the session waits for the peer's answer.
            Step::Write
        } else {
            Step::Close
        }
    }
}

fn polite(driver: DriverKind, keep: bool) -> Server {
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .driver(driver)
        .sessions(move |_: &ConnectionInfo| Polite { keep })
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    server
}

fn read_line(c: &mut TcpStream) -> Vec<u8> {
    let mut got = [0u8; 4];
    c.read_exact(&mut got).expect("the goodbye");
    got.to_vec()
}

fn at_eof(c: &mut TcpStream) -> bool {
    let mut buf = [0u8; 16];
    matches!(c.read(&mut buf), Ok(0))
}

#[test]
fn test_on_drain_says_goodbye_then_closes() {
    for driver in DRIVERS {
        let server = polite(driver, false);
        let handle = server.handle();
        let mut c = client(addr(&server));
        assert_eq!(round_trip(&mut c, b"hi"), b"hi");
        let stop = std::thread::spawn(move || server.shutdown(Instant::now() + WAIT));
        assert_eq!(read_line(&mut c), b"bye\n", "{driver:?}");
        assert!(at_eof(&mut c), "{driver:?}: closed after the goodbye");
        let report = stop.join().expect("shutdown");
        assert_eq!((report.graceful, report.killed), (1, 0), "{driver:?}");
        assert_eq!(
            handle.stats().closed_for(CloseReason::Drained),
            1,
            "{driver:?}"
        );
    }
}

#[test]
fn test_on_drain_keeps_the_connection_until_the_session_closes() {
    for driver in DRIVERS {
        let server = polite(driver, true);
        let handle = server.handle();
        let mut c = client(addr(&server));
        assert_eq!(round_trip(&mut c, b"hi"), b"hi");
        let start = Instant::now();
        let stop = std::thread::spawn(move || server.shutdown(Instant::now() + WAIT));
        assert_eq!(read_line(&mut c), b"bye\n", "{driver:?}");
        // Kept through the drain: still open, still answering.
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(handle.stats().open, 1, "{driver:?}: kept");
        assert_eq!(round_trip(&mut c, b"still"), b"still", "{driver:?}");
        c.write_all(b"ok").expect("answer");
        assert!(at_eof(&mut c), "{driver:?}: the session closed it");
        let report = stop.join().expect("shutdown");
        assert_eq!((report.graceful, report.killed), (1, 0), "{driver:?}");
        assert!(start.elapsed() < Duration::from_secs(4), "{driver:?}");
    }
}

#[test]
fn test_a_kept_connection_ends_at_the_drain_deadline() {
    for driver in DRIVERS {
        let server = polite(driver, true);
        let mut c = client(addr(&server));
        assert_eq!(round_trip(&mut c, b"hi"), b"hi");
        let start = Instant::now();
        let stop = std::thread::spawn(move || {
            server.shutdown(Instant::now() + Duration::from_millis(400))
        });
        assert_eq!(read_line(&mut c), b"bye\n", "{driver:?}");
        let report = stop.join().expect("shutdown");
        let took = start.elapsed();
        assert_eq!((report.graceful, report.killed), (0, 1), "{driver:?}");
        assert!(took >= Duration::from_millis(350), "{driver:?}: {took:?}");
        assert!(took < Duration::from_secs(3), "{driver:?}: {took:?}");
    }
}

const WAIT: Duration = Duration::from_secs(5);
