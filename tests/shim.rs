//! Fault injection: failures the OS rarely produces on demand.
//!
//! Runs only with `RUSTFLAGS="--cfg net_io_shim"`. The shim is process-wide, so
//! the tests take turns through one lock, and the clients use std sockets, which
//! the shim does not touch.

#![cfg(net_io_shim)]

mod common;

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
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

fn blocking_echo_server() -> net_io::Server {
    driver_echo_server(net_io::DriverKind::Blocking)
}

fn driver_echo_server(driver: net_io::DriverKind) -> net_io::Server {
    let server = net_io::ServerBuilder::new()
        .listener(net_io::ListenerSpec::tcp("127.0.0.1:0"))
        .driver(driver)
        .sessions(|_: &ConnectionInfo| Echo)
        .gate(net_io::AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    server
}

#[test]
fn test_accept_out_of_descriptors_recovers() {
    let _shim = Shim::take();
    let server = echo_server();
    program(Op::Accept, 0, 1, Fault::Os(EMFILE));
    // The first connection meets the fault; it may be shed or served after the pause.
    let _first = TcpStream::connect(addr(&server));
    assert!(eventually(WAIT, || server.stats().descriptor_pressure == 1));
    // A connection accepted during the pause is shed too, and on the BSDs that can
    // reach the client inside `connect`.
    assert!(eventually(WAIT, || {
        TcpStream::connect(addr(&server)).is_ok_and(|mut c| {
            let _ = c.set_read_timeout(Some(WAIT));
            let mut b = [0u8; 5];
            c.write_all(b"after").is_ok() && c.read_exact(&mut b).is_ok() && &b == b"after"
        })
    }));
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
/// at net-io's own call sites: at most 2 on Linux (receive, send) and 3 on Windows
/// and macOS (wait, receive, send; decisions D-052, D-083).
#[test]
fn test_system_calls_per_echo_round_trip() {
    use net_io::__shim::{counted, start_counting, stop_counting};
    let _shim = Shim::take();
    // Linux: recv, send. Windows and macOS wait first (D-052, D-083).
    let budget = if cfg!(any(windows, not(target_os = "linux"))) {
        3.0
    } else {
        2.0
    };
    for name in ["blocking handler", "sessions"] {
        // One server at a time: the count is process-wide, and a worker still starting
        // makes its first wait inside the other server's measurement.
        let server = if name == "sessions" {
            echo_server()
        } else {
            net_io::serve("127.0.0.1:0", |conn: &mut net_io::TcpConnection| {
                let mut buf = [0u8; 512];
                loop {
                    let n = conn.recv(&mut buf)?;
                    if n == 0 {
                        return Ok(());
                    }
                    conn.send_all(&buf[..n])?;
                }
            })
            .expect("serve")
        };
        let mut c = client(addr(&server));
        for _ in 0..100 {
            assert_eq!(round_trip(&mut c, &[1u8; 64]), [1u8; 64]);
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
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
        // The reactor: wait, receive, send; on Windows also the zero-byte receive.
        let budget = match name {
            "sessions" if cfg!(net_io_force_blocking) => budget,
            "sessions" if cfg!(windows) => 4.0,
            "sessions" => 3.0,
            _ => budget,
        };
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
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
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

/// Edge case 6: a receive that would block after the socket looked ready is retried.
#[test]
fn test_spurious_would_block_is_retried() {
    let _shim = Shim::take();
    let server = blocking_echo_server();
    let mut c = client(addr(&server));
    program(Op::Recv, 0, 3, Fault::Kind(std::io::ErrorKind::WouldBlock));
    assert_eq!(round_trip(&mut c, b"again"), b"again");
}

/// Edge case 6 on an edge-triggered driver: after a spurious `WouldBlock` nothing
/// is lost, and the next arrival's edge reads everything.
#[cfg(unix)]
#[test]
fn test_spurious_would_block_recovers_at_the_next_edge() {
    use std::io::{Read, Write};
    let _shim = Shim::take();
    let server = driver_echo_server(net_io::DriverKind::Reactor);
    let mut c = client(addr(&server));
    program(Op::Recv, 0, 1, Fault::Kind(std::io::ErrorKind::WouldBlock));
    c.write_all(b"a").expect("write");
    std::thread::sleep(Duration::from_millis(50));
    c.write_all(b"b").expect("write");
    let mut back = [0; 2];
    c.read_exact(&mut back).expect("read");
    assert_eq!(&back, b"ab");
}

/// Edge case 8: the kernel timing the connection out (keepalive) is `Io(TimedOut)`,
/// not one of net-io's deadlines.
#[test]
fn test_keepalive_timeout_is_an_io_error_not_a_deadline() {
    #[cfg(target_os = "linux")]
    const ETIMEDOUT: i32 = 110;
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    const ETIMEDOUT: i32 = 60;
    #[cfg(windows)]
    const ETIMEDOUT: i32 = 10060;
    let _shim = Shim::take();
    let server = echo_server();
    let mut c = client(addr(&server));
    assert_eq!(round_trip(&mut c, b"1"), b"1");
    program(Op::Recv, 0, 1, Fault::Os(ETIMEDOUT));
    let _ = std::io::Write::write_all(&mut c, b"2");
    assert!(eventually(WAIT, || server.stats().closed == 1));
    let s = server.stats();
    assert_eq!(
        s.closed_for(CloseReason::Io(net_io::OsErrorClass::TimedOut)),
        1,
        "{s:?}"
    );
    assert_eq!(s.timeouts, 0, "not counted as a deadline");
}
