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
/// at net-io's own call sites: at most 3 on the blocking pool everywhere (wait,
/// receive, send; decisions D-052, D-083, and on Linux D-178, which waits before
/// an exchange's first receive so a drain reaches the owner through its wake).
#[test]
fn test_system_calls_per_echo_round_trip() {
    use net_io::__shim::{counted, start_counting, stop_counting};
    let _shim = Shim::take();
    // Every system waits before an exchange's first receive (D-052, D-083, D-178).
    let budget = 3.0;
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

/// A message that fills the read buffer can cost one more receive, the one that finds
/// the socket empty: readiness cannot say there is no more without asking.
#[test]
fn test_system_calls_for_a_message_as_large_as_the_buffer() {
    use net_io::__shim::{counted, start_counting, stop_counting};
    let _shim = Shim::take();
    let server = echo_server();
    let mut c = client(addr(&server));
    let body = vec![3u8; 16 * 1024];
    for _ in 0..100 {
        assert_eq!(round_trip(&mut c, &body), body);
    }
    std::thread::sleep(Duration::from_millis(200));
    start_counting();
    let rounds = 1000;
    for _ in 0..rounds {
        assert_eq!(round_trip(&mut c, &body), body);
    }
    stop_counting();
    let calls = [Op::Recv, Op::Send, Op::Wait, Op::RecvTimeout].map(counted);
    let per = calls.iter().sum::<u64>() as f64 / f64::from(rounds);
    println!("16 KiB: {per:.2} system calls per round trip (recv, send, wait, timeout: {calls:?})");
    assert!(per <= 4.01, "16 KiB: {per:.2} > 4");
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
    pub const EADDRINUSE: i32 = 98;
    pub const EINVAL: i32 = 22;
    pub const ECONNREFUSED: i32 = 111;
}
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod codes {
    pub const ENFILE: Option<i32> = Some(23);
    pub const ECONNABORTED: i32 = 53;
    pub const EPERM: Option<i32> = Some(1);
    pub const ENOBUFS: i32 = 55;
    pub const EBADF: i32 = 9;
    pub const EADDRINUSE: i32 = 48;
    pub const EINVAL: i32 = 22;
    pub const ECONNREFUSED: i32 = 61;
}
#[cfg(windows)]
mod codes {
    pub const ENFILE: Option<i32> = None;
    pub const ECONNABORTED: i32 = 10053;
    pub const EPERM: Option<i32> = None;
    pub const ENOBUFS: i32 = 10055;
    pub const EBADF: i32 = 10009;
    pub const EADDRINUSE: i32 = 10048;
    pub const EINVAL: i32 = 10022;
    pub const ECONNREFUSED: i32 = 10061;
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
        // The out-of-descriptors routine resets this one, and on a loaded host the
        // reset can arrive before `connect` returns.
        let _first = TcpStream::connect(addr(&server));
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

/// A file streamed to a fast reader gives way to the rest of the worker: at least
/// one look at the OS for every 256 KiB of file (D-141). Linux, where each piece is a
/// `sendfile` in the worker's own thread.
#[cfg(all(target_os = "linux", feature = "reactor", not(net_io_force_blocking)))]
#[test]
fn test_file_stream_looks_at_the_os_every_256_kib() {
    use net_io::__shim::{counted, start_counting, stop_counting};
    use std::sync::Arc;

    struct Stream(Arc<std::fs::File>, u64);
    impl Session for Stream {
        fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
            let n = input.bytes().len();
            input.consume(n);
            cx.output()
                .push_file(self.0.clone(), 0, self.1)
                .expect("push");
            Step::Close
        }
    }

    let _shim = Shim::take();
    let len: u64 = 64 << 20;
    let path = std::env::temp_dir().join(format!("nio-shim-bulk-{}", std::process::id()));
    std::fs::write(&path, vec![7u8; len as usize]).expect("write");
    let file = Arc::new(std::fs::File::open(&path).expect("open"));
    let server = net_io::ServerBuilder::new()
        .listener(net_io::ListenerSpec::tcp("127.0.0.1:0"))
        .driver(net_io::DriverKind::Reactor)
        .workers(1)
        .sessions(move |_: &ConnectionInfo| Stream(file.clone(), len))
        .gate(net_io::AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    std::thread::sleep(Duration::from_millis(100));
    let mut c = client(addr(&server));
    start_counting();
    c.write_all(b"go").expect("write");
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        match c.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => total += n as u64,
            Err(e) => panic!("{e}"),
        }
    }
    stop_counting();
    let _ = std::fs::remove_file(&path);
    let (waits, sends) = (counted(Op::Wait), counted(Op::Send));
    println!("{total} bytes: {waits} waits, {sends} sends");
    assert_eq!(total, len);
    let pieces = len / (256 << 10);
    assert!(sends >= pieces, "{sends} sends for {pieces} pieces");
    assert!(waits >= pieces, "{waits} waits for {pieces} pieces");
}

/// The reactor's wait failing: every connection on the worker closes at once with its
/// close counted and its caps returned, instead of waiting for completions that will
/// never be read (review finding).
#[cfg(all(feature = "reactor", not(net_io_force_blocking)))]
#[test]
fn test_reactor_wait_failure_closes_every_connection() {
    let _shim = Shim::take();
    let server = driver_echo_server(net_io::DriverKind::Reactor);
    let mut clients: Vec<TcpStream> = (0..4).map(|_| client(addr(&server))).collect();
    for c in &mut clients {
        assert_eq!(round_trip(c, b"hi"), b"hi");
    }
    assert!(eventually(WAIT, || server.stats().open == 4));
    // EBADF on Unix, WSAEINVAL-like on Windows: anything but an interrupt.
    program(Op::Wait, 0, 1_000, Fault::Os(9));
    for c in &mut clients {
        let _ = c.write_all(b"x");
    }
    assert!(
        eventually(WAIT, || server.stats().open == 0
            && server.stats().closed >= 4),
        "{:?}",
        server.stats()
    );
    clear();
}

/// Each `sys` site with an error injected: a clean error to the caller, and the next
/// call works (the shim coverage test in `src/sys/shim.rs` requires one per site).
#[test]
fn test_bind_listen_and_option_errors_are_clean() {
    let _shim = Shim::take();
    program(Op::Bind, 0, 1, Fault::Os(codes::EADDRINUSE));
    let err = net_io::TcpListener::bind("127.0.0.1:0")
        .map(|_| ())
        .unwrap_err();
    assert!(matches!(err, net_io::NetError::AddrInUse { .. }), "{err:?}");
    program(Op::Listen, 0, 1, Fault::Os(codes::ENOBUFS));
    assert!(net_io::TcpListener::bind("127.0.0.1:0").is_err());
    let with_buffer = net_io::ListenOptions::new().send_buffer(64 << 10);
    program(Op::SetOption, 0, 1, Fault::Os(codes::EINVAL));
    assert!(net_io::TcpListener::bind_with("127.0.0.1:0", with_buffer).is_err());
    // Nothing left behind: the same calls work now.
    let l = net_io::TcpListener::bind_with("127.0.0.1:0", with_buffer).expect("bind");
    let c = TcpStream::connect(l.local_addr().expect("addr")).expect("connect");
    drop((c, l));
}

#[test]
fn test_socket_and_connect_errors_then_a_retry_connects() {
    let _shim = Shim::take();
    let server = echo_server();
    program(Op::Socket, 0, 1, Fault::Os(codes::ENOBUFS));
    assert!(net_io::TcpConnection::connect(addr(&server)).is_err());
    program(Op::Connect, 0, 2, Fault::Os(codes::ECONNREFUSED));
    let mut backoff = net_io::Backoff::new()
        .first(Duration::from_millis(5))
        .attempts(5);
    let mut c = net_io::TcpConnection::connect_retry(
        addr(&server),
        net_io::ConnectOptions::new(),
        &mut backoff,
    )
    .expect("connects on the third attempt");
    assert_eq!(backoff.attempt(), 2);
    c.send_all(b"hi").expect("send");
    let mut back = [0u8; 2];
    c.recv_exact(&mut back).expect("recv");
    assert_eq!(&back, b"hi");
}

/// A registration the driver refuses closes that connection with one event; the
/// worker goes on serving.
#[cfg(all(feature = "reactor", not(net_io_force_blocking)))]
#[test]
fn test_register_error_closes_only_that_connection() {
    let _shim = Shim::take();
    let server = driver_echo_server(net_io::DriverKind::Reactor);
    program(Op::Register, 0, 1, Fault::Os(codes::ENOBUFS));
    let mut first = client(addr(&server));
    let _ = first.write_all(b"x");
    let mut b = [0u8; 1];
    assert!(!matches!(first.read(&mut b), Ok(n) if n > 0));
    assert!(
        eventually(WAIT, || server.stats().closed == 1),
        "{:?}",
        server.stats()
    );
    let mut c = client(addr(&server));
    assert_eq!(round_trip(&mut c, b"after"), b"after");
}

/// Linux sets `SO_RCVTIMEO` before a pool receive; that failing closes the
/// connection with its error. Elsewhere the site does not exist and nothing fails.
#[test]
fn test_receive_timeout_error_closes_the_connection() {
    let _shim = Shim::take();
    // Two receives before the reply: the second is inside the exchange, where Linux
    // receives under `SO_RCVTIMEO` (an exchange's first receive waits first, D-178).
    let server = net_io::serve("127.0.0.1:0", |conn: &mut net_io::TcpConnection| {
        let mut buf = [0u8; 8];
        let a = conn.recv(&mut buf)?;
        let b = conn.recv(&mut buf[a..])?;
        conn.send_all(&buf[..a + b])
    })
    .expect("serve");
    let mut c = client(addr(&server));
    program(Op::RecvTimeout, 0, 1, Fault::Os(codes::EINVAL));
    let _ = c.write_all(b"pi");
    std::thread::sleep(std::time::Duration::from_millis(50));
    let _ = c.write_all(b"ng");
    let mut b = [0u8; 4];
    let got = c.read(&mut b);
    if cfg!(target_os = "linux") {
        assert!(!matches!(got, Ok(n) if n > 0), "{got:?}");
        assert!(eventually(WAIT, || server.stats().closed == 1));
    }
    clear();
    let mut d = client(addr(&server));
    d.write_all(b"pi").expect("write");
    std::thread::sleep(std::time::Duration::from_millis(50));
    d.write_all(b"ng").expect("write");
    let mut back = [0u8; 4];
    d.read_exact(&mut back).expect("served after the fault");
    assert_eq!(&back, b"ping");
}

/// Clients of a reactor server, one at a time: how many got their byte back
/// within half a second each.
#[cfg(feature = "reactor")]
fn served_of(at: std::net::SocketAddr, n: u8) -> (usize, Vec<TcpStream>) {
    let mut served = 0;
    let mut held = Vec::new();
    for i in 0..n {
        let mut c = client(at);
        c.set_read_timeout(Some(Duration::from_millis(500)))
            .expect("timeout");
        c.write_all(&[i]).expect("write");
        let mut b = [0u8; 1];
        if matches!(c.read(&mut b), Ok(1)) {
            served += 1;
        }
        held.push(c);
    }
    (served, held)
}

/// One reactor worker's wait fails, so its loop ends: no new connection goes to it
/// (every client is answered by the other), what it held is closed and counted, and
/// a shutdown ends by its deadline.
#[cfg(feature = "reactor")]
#[test]
fn test_a_reactor_worker_that_dies_takes_no_more_connections() {
    let _shim = Shim::take();
    let server = net_io::ServerBuilder::new()
        .listener(net_io::ListenerSpec::tcp("127.0.0.1:0"))
        .driver(net_io::DriverKind::Reactor)
        .workers(2)
        .sessions(|_: &ConnectionInfo| Echo)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let at = addr(&server);
    // A first client is served; then its worker's next wait fails.
    let mut first = client(at);
    assert_eq!(round_trip(&mut first, b"a"), b"a");
    program(Op::Wait, 0, 1, Fault::Os(9));
    first.write_all(b"b").expect("write");
    assert!(eventually(WAIT, || server.stats().workers_lost == 1));
    clear();
    assert!(
        eventually(WAIT, || server.stats().open == 0),
        "{:?}",
        server.stats()
    );
    drop(first);

    let (served, held) = served_of(at, 8);
    assert_eq!(served, 8, "{:?}", server.stats());
    drop(held);
    let handle = server.handle();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let r = server.shutdown(std::time::Instant::now() + Duration::from_millis(500));
        let _ = tx.send(r);
    });
    assert!(
        rx.recv_timeout(Duration::from_secs(5)).is_ok(),
        "the shutdown did not end: {:?}",
        handle.stats()
    );
    assert_eq!(handle.stats().open, 0);
}

/// A per-worker group on the reactor (Linux): the kernel keeps sending a share of
/// connections to each worker's socket, so the socket of a worker that died is
/// taken up by another, and every client is still answered.
#[cfg(all(target_os = "linux", feature = "reactor"))]
#[test]
fn test_a_dead_workers_own_listening_socket_goes_to_an_heir() {
    let _shim = Shim::take();
    let server = net_io::ServerBuilder::new()
        .listener(net_io::ListenerSpec::tcp_with(
            "127.0.0.1:0",
            net_io::ListenOptions::new().per_worker(true),
        ))
        .driver(net_io::DriverKind::Reactor)
        .workers(2)
        .sessions(|_: &ConnectionInfo| Echo)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let at = addr(&server);
    // Clients until one lands on each worker; then the wait of one of them fails.
    let mut first = client(at);
    assert_eq!(round_trip(&mut first, b"a"), b"a");
    program(Op::Wait, 0, 1, Fault::Os(9));
    first.write_all(b"b").expect("write");
    assert!(eventually(WAIT, || server.stats().workers_lost == 1));
    clear();
    drop(first);
    // The kernel spreads these over both sockets by their ports.
    let (served, held) = served_of(at, 16);
    assert_eq!(served, 16, "{:?}", server.stats());
    drop(held);
    let report = server.shutdown(std::time::Instant::now() + Duration::from_millis(500));
    assert!(report.took < Duration::from_secs(3), "{report:?}");
}

/// Linux: a file error after bytes left the socket for the pipe fails the
/// receive. Those bytes cannot be received again, so going on with plain receives
/// would put the next bytes at the wrong offset, with a gap before them.
#[cfg(target_os = "linux")]
#[test]
fn test_recv_file_fails_when_the_file_fails_after_bytes_left_the_socket() {
    let _shim = Shim::take();
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let at = l.local_addr().expect("addr");
    let peer = std::thread::spawn(move || {
        let (mut c, _) = l.accept().expect("accept");
        let _ = c.write_all(&[5u8; 256 << 10]);
    });
    let mut conn = net_io::connect(at).expect("connect");
    let path = std::env::temp_dir().join(format!("nio-shim-file-{}", std::process::id()));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .expect("open");
    // `splice` into the file is turned down, then the copy of the pipe's bytes fails.
    program(Op::FileWrite, 0, 2, Fault::Os(22));
    let got = conn.recv_file(&file, 0, 256 << 10);
    drop(conn);
    let _ = peer.join();
    let _ = std::fs::remove_file(&path);
    let err = got.expect_err("bytes were lost: the receive must fail");
    assert!(
        matches!(err, net_io::NetError::Os { op: "write", .. }),
        "{err:?}"
    );
}
