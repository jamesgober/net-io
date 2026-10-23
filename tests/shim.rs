//! Fault injection: failures the OS rarely produces on demand.
//!
//! Runs only with `RUSTFLAGS="--cfg net_io_shim"`. The shim is process-wide, so
//! the tests take turns through one lock, and the clients use std sockets, which
//! the shim does not touch.

#![cfg(net_io_shim)]

mod common;

use std::io::ErrorKind;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use common::{addr, client, eventually, round_trip};
use net_io::__shim::{Fault, Op, clear, program};
use net_io::{CloseReason, ConnectionInfo, Input, Session, SessionContext, Step};

const WAIT: Duration = Duration::from_secs(5);

#[cfg(unix)]
const EMFILE: i32 = 24;
#[cfg(windows)]
const EMFILE: i32 = 10024;

static LOCK: Mutex<()> = Mutex::new(());

/// Holds the shim for one test and clears it on both ends.
struct Shim(#[allow(dead_code)] MutexGuard<'static, ()>);

impl Shim {
    fn take() -> Shim {
        let g = LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        clear();
        Shim(g)
    }
}

impl Drop for Shim {
    fn drop(&mut self) {
        clear();
    }
}

struct Echo;

impl Session for Echo {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let taken = cx.output().push_partial(input.bytes());
        input.consume(taken);
        Step::Write
    }
}

fn echo_server() -> net_io::Server {
    net_io::serve_sessions("127.0.0.1:0", |_: &ConnectionInfo| Echo).expect("serve")
}

#[test]
fn test_accept_out_of_descriptors_recovers() {
    let _shim = Shim::take();
    let server = echo_server();
    program(Op::Accept, 0, 1, Fault::Os(EMFILE));
    // The first connection meets the fault; it may be shed or served after the pause.
    let _first = client(addr(&server));
    assert!(eventually(WAIT, || server.stats().descriptor_pressure == 1));
    let mut c = client(addr(&server));
    assert_eq!(round_trip(&mut c, b"after"), b"after");
}

#[test]
fn test_short_writes_still_deliver_everything() {
    let _shim = Shim::take();
    let server = echo_server();
    let mut c = client(addr(&server));
    program(Op::Send, 0, 200, Fault::Short(7));
    let msg: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
    assert_eq!(round_trip(&mut c, &msg), msg);
}

#[test]
fn test_interrupted_receives_are_retried() {
    let _shim = Shim::take();
    let server = echo_server();
    let mut c = client(addr(&server));
    program(Op::Recv, 0, 5, Fault::Interrupt);
    assert_eq!(round_trip(&mut c, b"through"), b"through");
}

#[test]
fn test_receive_error_closes_only_that_connection() {
    let _shim = Shim::take();
    let server = echo_server();
    let mut first = client(addr(&server));
    assert_eq!(round_trip(&mut first, b"1"), b"1");
    program(Op::Recv, 0, 1, Fault::Kind(ErrorKind::ConnectionReset));
    let _ = std::io::Write::write_all(&mut first, b"2");
    assert!(eventually(WAIT, || server
        .stats()
        .closed_for(CloseReason::PeerReset)
        == 1));
    let mut second = client(addr(&server));
    assert_eq!(round_trip(&mut second, b"3"), b"3");
}

/// B-13: system calls per echo round trip on an established connection, counted
/// at net-io's own call sites: at most 2 on Unix (receive, send) and 3 on Windows
/// (wait, receive, send; decision D-052).
#[test]
fn test_system_calls_per_echo_round_trip() {
    use net_io::__shim::{counted, start_counting, stop_counting};
    let _shim = Shim::take();
    let budget = if cfg!(windows) { 3.0 } else { 2.0 };
    let blocking = net_io::serve("127.0.0.1:0", |conn: &mut net_io::TcpConnection| {
        let mut buf = [0u8; 512];
        loop {
            let n = conn.recv(&mut buf)?;
            if n == 0 {
                return Ok(());
            }
            conn.send_all(&buf[..n])?;
        }
    })
    .expect("serve");
    let sessions = echo_server();
    for (name, server) in [("blocking handler", &blocking), ("sessions", &sessions)] {
        let mut c = client(addr(server));
        for _ in 0..100 {
            assert_eq!(round_trip(&mut c, &[1u8; 64]), [1u8; 64]);
        }
        start_counting();
        let rounds = 1000;
        for _ in 0..rounds {
            assert_eq!(round_trip(&mut c, &[2u8; 64]), [2u8; 64]);
        }
        stop_counting();
        let calls = [Op::Recv, Op::Send, Op::Wait, Op::RecvTimeout].map(counted);
        let per = calls.iter().sum::<u64>() as f64 / f64::from(rounds);
        println!(
            "{name}: {per:.2} system calls per round trip (recv, send, wait, timeout: {calls:?})"
        );
        assert!(per <= budget + 0.01, "{name}: {per:.2} > {budget}");
    }
}

/// Records every event.
#[derive(Clone, Default)]
struct Recorder(std::sync::Arc<Mutex<Vec<net_io::Event>>>);

impl net_io::EventSink for Recorder {
    fn event(&self, event: &net_io::Event) {
        if let Ok(mut v) = self.0.lock() {
            v.push(*event);
        }
    }
}

impl Recorder {
    fn has(&self, f: impl Fn(&net_io::Event) -> bool) -> bool {
        self.0.lock().map(|v| v.iter().any(f)).unwrap_or(false)
    }
}

fn recorded_server(rec: &Recorder) -> net_io::Server {
    let server = net_io::ServerBuilder::new()
        .listener(net_io::ListenerSpec::tcp("127.0.0.1:0"))
        .workers(2)
        .sessions(|_: &ConnectionInfo| Echo)
        .gate(net_io::AllowAll)
        .events(rec.clone())
        .build()
        .expect("build");
    server.open_door().expect("open");
    server
}

#[cfg(target_os = "linux")]
mod codes {
    pub const ENFILE: Option<i32> = Some(23);
    pub const ECONNABORTED: i32 = 103;
    pub const EPERM: Option<i32> = Some(1);
    pub const ENOBUFS: i32 = 105;
    pub const EBADF: i32 = 9;
}
#[cfg(target_os = "macos")]
mod codes {
    pub const ENFILE: Option<i32> = Some(23);
    pub const ECONNABORTED: i32 = 53;
    pub const EPERM: Option<i32> = Some(1);
    pub const ENOBUFS: i32 = 55;
    pub const EBADF: i32 = 9;
}
#[cfg(windows)]
mod codes {
    pub const ENFILE: Option<i32> = None;
    pub const ECONNABORTED: i32 = 10053;
    pub const EPERM: Option<i32> = None;
    pub const ENOBUFS: i32 = 10055;
    pub const EBADF: i32 = 10009;
}

/// Edge cases 43 and 44: per-connection accept failures are counted and accepting continues.
#[test]
fn test_accept_per_connection_errors_continue() {
    for code in [Some(codes::ECONNABORTED), codes::EPERM]
        .into_iter()
        .flatten()
    {
        let _shim = Shim::take();
        let rec = Recorder::default();
        let server = recorded_server(&rec);
        program(Op::Accept, 0, 1, Fault::Os(code));
        let mut c = client(addr(&server));
        // The fault consumed one accept call; the connection itself is still pending and served.
        assert_eq!(round_trip(&mut c, b"on"), b"on", "errno {code}");
        assert!(
            rec.has(|e| matches!(e, net_io::Event::AcceptError { .. })),
            "errno {code}: no AcceptError event"
        );
        assert_eq!(server.stats().descriptor_pressure, 0);
    }
}

/// Edge cases 42 and 45: `ENFILE` (Unix) and `ENOBUFS` pause accepting, then it resumes.
#[test]
fn test_accept_resource_errors_pause_then_resume() {
    for code in [codes::ENFILE, Some(codes::ENOBUFS)].into_iter().flatten() {
        let _shim = Shim::take();
        let rec = Recorder::default();
        let server = recorded_server(&rec);
        program(Op::Accept, 0, 1, Fault::Os(code));
        let _first = client(addr(&server));
        assert!(
            eventually(WAIT, || server.stats().descriptor_pressure == 1),
            "errno {code}"
        );
        assert!(rec.has(|e| matches!(e, net_io::Event::DescriptorPressure { .. })));
        let mut c = client(addr(&server));
        assert_eq!(round_trip(&mut c, b"back"), b"back", "errno {code}");
    }
}

/// Edge case 46: a broken listener is reported once and its thread stops (no spin).
#[test]
fn test_accept_listener_failure_stops_without_spinning() {
    let _shim = Shim::take();
    let rec = Recorder::default();
    let server = recorded_server(&rec);
    program(Op::Accept, 0, 1, Fault::Os(codes::EBADF));
    let _c = client(addr(&server));
    assert!(eventually(WAIT, || rec
        .has(|e| matches!(e, net_io::Event::ListenerFailed { .. }))));
    clear();
    // The accept thread ended: no more accepts, and shutdown still completes.
    std::thread::sleep(Duration::from_millis(100));
    let failures = rec.0.lock().map(|v| {
        v.iter()
            .filter(|e| matches!(e, net_io::Event::ListenerFailed { .. }))
            .count()
    });
    assert_eq!(failures.ok(), Some(1));
    assert_eq!(server.stats().accepted, 0);
    let report = server.shutdown(std::time::Instant::now() + Duration::from_secs(1));
    assert_eq!(report.graceful + report.killed, 0);
}

/// Edge cases 18 and 24: partial writes of every small size continue from the exact offset.
#[test]
fn test_partial_writes_at_many_splits() {
    let _shim = Shim::take();
    let server = echo_server();
    let msg: Vec<u8> = (0..3000u32).map(|i| (i * 7) as u8).collect();
    for k in [1usize, 2, 3, 5, 7, 13, 64, 999] {
        let mut c = client(addr(&server));
        program(Op::Send, 0, 10_000, Fault::Short(k));
        assert_eq!(round_trip(&mut c, &msg), msg, "split {k}");
        clear();
    }
}

/// Edge case 19: a send that moves 0 bytes is "full" once, an error the second time.
#[test]
fn test_zero_byte_send_once_then_error() {
    let _shim = Shim::take();
    let server = echo_server();
    let mut c = client(addr(&server));
    program(Op::Send, 0, 1, Fault::Short(0));
    assert_eq!(round_trip(&mut c, b"once"), b"once");
    program(Op::Send, 0, 2, Fault::Short(0));
    std::io::Write::write_all(&mut c, b"twice").expect("write");
    assert!(eventually(WAIT, || server.stats().closed == 1));
    assert_eq!(
        server.stats().closed_for(CloseReason::PeerClosed),
        0,
        "an error, not a clean close"
    );
}
