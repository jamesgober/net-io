//! Flush-then-close (D-182): after a denial the connection closes with FIN and a
//! bounded linger instead of a reset, and `ServerHandle::close_after_flush` sends
//! what a connection queued before it closes. Every test runs on both drivers.

mod common;

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use common::{addr, client, eventually, round_trip};
use net_io::{
    AdmitStage, Admitted, AllowAll, CloseReason, ConnectOptions, ConnectionId, ConnectionInfo,
    Denial, DriverKind, Gate, GateTag, Input, KillReason, Lane, Limits, ListenOptions,
    ListenerSpec, NetError, Output, Phase, Refusal, Server, ServerBuilder, Session, SessionContext,
    Step, TcpConnection, TcpOptions, WriteCheck,
};

#[cfg(feature = "reactor")]
const DRIVERS: [DriverKind; 2] = [DriverKind::Blocking, DriverKind::Reactor];
#[cfg(not(feature = "reactor"))]
const DRIVERS: [DriverKind; 1] = [DriverKind::Blocking];
const WAIT: Duration = Duration::from_secs(5);

/// What `Big` queues at once, and what `Huge` queues: more than Windows loopback
/// absorbs (it took 8 MiB with a 32 KiB receive buffer), so the output stays
/// queued in the server while the client does not read.
const BIG: usize = 8 << 20;
const HUGE: usize = 256 << 20;
static BLOCK: [u8; 1 << 20] = [b'q'; 1 << 20];

/// 16 MiB of `q`, allocated once and shared by every `Huge` (static chunks copy nothing).
fn slab() -> &'static [u8] {
    static SLAB: std::sync::OnceLock<&'static [u8]> = std::sync::OnceLock::new();
    SLAB.get_or_init(|| Vec::leak(vec![b'q'; 16 << 20]))
}

fn limits(f: impl FnOnce(net_io::LimitsBuilder) -> net_io::LimitsBuilder) -> Limits {
    f(Limits::builder()).build().expect("limits")
}

/// Denies every write.
struct DenyAll;

impl Gate for DenyAll {
    type Ticket = ();
    fn admit(&self, _: &ConnectionInfo, _: AdmitStage) -> Result<Admitted<()>, Refusal> {
        Ok(Admitted {
            lane: Lane(0),
            ticket: (),
            tag: GateTag(0),
        })
    }
    fn readmit(&self, _: &mut (), _: &ConnectionInfo) -> Result<(), Refusal> {
        Ok(())
    }
    fn check(&self, _: &mut (), _: &WriteCheck) -> Result<(), Denial> {
        Err(Denial { code: 7 })
    }
}

/// Answers any input with a short reply; its denial is `denied\n`. Mid-request
/// from its first input, so the close after a denial lingers on both drivers.
struct Reply;

impl Session for Reply {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let n = input.bytes().len();
        input.consume(n);
        cx.set_phase(Phase::Receiving);
        cx.output().begin_response();
        let _ = cx.output().push(b"the reply\n");
        cx.output().end_response();
        Step::Write
    }
    fn on_writable(&mut self, _: &mut SessionContext<'_>) -> Step {
        Step::Read
    }
    fn on_denied(&mut self, _code: u16, output: &mut Output) {
        let _ = output.push(b"denied\n");
    }
}

/// Queues `BIG` bytes at once on its first input, then waits for more input.
struct Big;

impl Session for Big {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let n = input.bytes().len();
        input.consume(n);
        let mut queued = 0;
        while queued < BIG {
            cx.output().push_static(&BLOCK).expect("queued");
            queued += BLOCK.len();
        }
        Step::Write
    }
    fn on_writable(&mut self, _: &mut SessionContext<'_>) -> Step {
        Step::Read
    }
}

/// Queues `HUGE` bytes at once on its first input, then waits for more input.
struct Huge;

impl Session for Huge {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let n = input.bytes().len();
        input.consume(n);
        let mut queued = 0;
        while queued < HUGE {
            cx.output().push_static(slab()).expect("queued");
            queued += slab().len();
        }
        Step::Write
    }
    fn on_writable(&mut self, _: &mut SessionContext<'_>) -> Step {
        Step::Read
    }
}

/// Takes what arrives and answers nothing, always mid-request (so a close lingers
/// on both drivers, whatever the reactor last saw of the socket).
struct Sink;

impl Session for Sink {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let n = input.bytes().len();
        input.consume(n);
        cx.set_phase(Phase::Receiving);
        Step::Read
    }
}

/// Echoes what arrives.
struct Echo;

impl Session for Echo {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let taken = cx.output().push_partial(input.bytes());
        input.consume(taken);
        Step::Write
    }
    fn on_writable(&mut self, _: &mut SessionContext<'_>) -> Step {
        Step::Read
    }
}

fn denying(driver: DriverKind, lim: Limits) -> Server {
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .driver(driver)
        .limits(lim)
        .sessions(|_: &ConnectionInfo| Reply)
        .gate(DenyAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    server
}

/// A server whose sessions report their connection's id. A small send buffer keeps
/// `Big`'s output queued in the server (Windows autotuning would take all of it).
fn reporting<S: Session + 'static>(
    driver: DriverKind,
    make: fn() -> S,
) -> (Server, mpsc::Receiver<ConnectionId>) {
    let (tx, rx) = mpsc::channel();
    let tx = std::sync::Mutex::new(tx);
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp_with(
            "127.0.0.1:0",
            ListenOptions::new().send_buffer(64 * 1024),
        ))
        .driver(driver)
        .limits(limits(|b| {
            b.output_budget(u32::MAX)
                .graceful_linger(Duration::from_secs(10), 1 << 30)
                .write_timeout(Duration::from_secs(30))
        }))
        .sessions(move |info: &ConnectionInfo| {
            let _ = tx.lock().expect("lock").send(info.id);
            make()
        })
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    (server, rx)
}

/// A client with a small receive buffer, so a server's output backs up in the
/// server instead of in the client's kernel (Windows grows it to tens of MiB).
fn small_client(server: &Server) -> TcpConnection {
    let options = ConnectOptions::new()
        .tcp_options(TcpOptions::new().receive_buffer(32 * 1024))
        .limits(limits(|b| b.read_timeout(WAIT).idle_timeout(WAIT)));
    TcpConnection::connect_with(addr(server), options).expect("connect")
}

/// `read_until_closed` for a `TcpConnection` reading `Big`'s bytes: how many.
fn recv_until_closed(c: &mut TcpConnection) -> (usize, Result<(), NetError>) {
    let mut got = 0;
    let mut buf = [0u8; 64 << 10];
    loop {
        match c.recv(&mut buf) {
            Ok(0) => return (got, Ok(())),
            Ok(n) => {
                assert!(buf[..n].iter().all(|&b| b == b'q'));
                got += n;
            }
            Err(e) => return (got, Err(e)),
        }
    }
}

/// Reads until the server closes: the bytes, and `Ok` for FIN or the error (a reset).
fn read_until_closed(c: &mut TcpStream) -> (Vec<u8>, std::io::Result<()>) {
    c.set_read_timeout(Some(WAIT)).expect("timeout");
    let mut got = Vec::new();
    let mut buf = [0u8; 64 << 10];
    loop {
        match c.read(&mut buf) {
            Ok(0) => return (got, Ok(())),
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return (got, Err(e)),
        }
    }
}

#[test]
fn test_denial_is_followed_by_fin_not_a_reset() {
    for driver in DRIVERS {
        let server = denying(
            driver,
            limits(|b| b.graceful_linger(Duration::from_secs(10), 64 * 1024)),
        );
        let mut c = client(addr(&server));
        c.write_all(b"go").expect("write");
        let (got, end) = read_until_closed(&mut c);
        assert_eq!(got, b"denied\n", "{driver:?}");
        assert!(end.is_ok(), "{driver:?}: FIN after the denial, got {end:?}");
        drop(c);
        assert!(
            eventually(WAIT, || server
                .stats()
                .closed_for(CloseReason::EgressDenied(7))
                == 1),
            "{driver:?}"
        );
    }
}

#[test]
fn test_zero_denial_linger_resets_after_the_denial() {
    for driver in DRIVERS {
        let server = denying(driver, limits(|b| b.denial_linger(Duration::ZERO)));
        let mut c = client(addr(&server));
        c.write_all(b"go").expect("write");
        let (got, end) = read_until_closed(&mut c);
        assert!(got.is_empty() || got == b"denied\n", "{driver:?}: {got:?}");
        let e = end.expect_err("a reset, as before 0.8");
        assert!(
            matches!(
                e.kind(),
                ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
            ),
            "{driver:?}: {e:?}"
        );
    }
}

#[test]
fn test_denial_linger_is_bounded_for_a_peer_that_stays() {
    for driver in DRIVERS {
        let server = denying(
            driver,
            limits(|b| {
                b.graceful_linger(Duration::from_secs(10), 64 * 1024)
                    .denial_linger(Duration::from_millis(100))
            }),
        );
        let mut c = client(addr(&server));
        let start = Instant::now();
        c.write_all(b"go").expect("write");
        // The client neither reads nor closes; it keeps sending a little.
        let mut closed = false;
        while start.elapsed() < WAIT {
            if server.stats().closed_for(CloseReason::EgressDenied(7)) == 1 {
                closed = true;
                break;
            }
            let _ = c.write(b"more");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(closed, "{driver:?}: not closed");
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "{driver:?}: the denial linger, not the 10 s graceful one: {:?}",
            start.elapsed()
        );
    }
}

#[test]
fn test_close_after_flush_sends_what_was_queued() {
    for driver in DRIVERS {
        let (server, ids) = reporting(driver, || Big);
        let mut c = small_client(&server);
        c.send_all(b"go").expect("write");
        let id = ids.recv_timeout(WAIT).expect("id");
        // Let the output back up: the client reads nothing yet (on Windows the
        // kernel may take all of it; the bytes and the FIN are checked either way).
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            server
                .handle()
                .close_after_flush(id, KillReason(5), Duration::from_secs(20))
        );
        let (got, end) = recv_until_closed(&mut c);
        assert_eq!(got, BIG, "{driver:?}: everything queued arrives");
        assert!(end.is_ok(), "{driver:?}: FIN, got {end:?}");
        drop(c);
        assert!(
            eventually(WAIT, || server
                .stats()
                .closed_for(CloseReason::Killed(KillReason(5)))
                == 1),
            "{driver:?}"
        );
    }
}

#[test]
fn test_close_after_flush_on_an_idle_connection_closes_at_once() {
    for driver in DRIVERS {
        let (server, ids) = reporting(driver, || Echo);
        let mut c = client(addr(&server));
        assert_eq!(round_trip(&mut c, b"ping"), b"ping");
        let id = ids.recv_timeout(WAIT).expect("id");
        let start = Instant::now();
        assert!(
            server
                .handle()
                .close_after_flush(id, KillReason(6), Duration::from_secs(20))
        );
        let (got, end) = read_until_closed(&mut c);
        assert!(got.is_empty(), "{driver:?}");
        assert!(end.is_ok(), "{driver:?}: FIN, got {end:?}");
        assert!(start.elapsed() < Duration::from_secs(3), "{driver:?}");
        drop(c);
        assert!(
            eventually(WAIT, || server
                .stats()
                .closed_for(CloseReason::Killed(KillReason(6)))
                == 1),
            "{driver:?}"
        );
    }
}

#[test]
fn test_close_after_flush_is_bounded_for_a_peer_that_never_reads() {
    for driver in DRIVERS {
        let (server, ids) = reporting(driver, || Huge);
        let mut c = small_client(&server);
        c.send_all(b"go").expect("write");
        let id = ids.recv_timeout(WAIT).expect("id");
        std::thread::sleep(Duration::from_millis(100));
        let start = Instant::now();
        assert!(
            server
                .handle()
                .close_after_flush(id, KillReason(4), Duration::from_millis(300))
        );
        assert!(
            eventually(WAIT, || server
                .stats()
                .closed_for(CloseReason::Killed(KillReason(4)))
                == 1),
            "{driver:?}: not closed"
        );
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "{driver:?}: the bound, not the 30 s write timeout: {:?}",
            start.elapsed()
        );
        drop(c);
    }
}

/// A flush-then-close lingers whatever the phase: before the session has seen any
/// input the peer's request may be on its way, and closing at once would answer it
/// with a reset (D-182). Register R-47: under load the Linux reactor got the soft
/// kill before the first `on_data`, and the close took the idle shortcut.
#[test]
fn test_a_close_after_flush_lingers_before_any_input() {
    for driver in DRIVERS {
        let (server, ids) = reporting(driver, || Sink);
        let mut c = client(addr(&server));
        let id = ids.recv_timeout(WAIT).expect("id");
        std::thread::sleep(Duration::from_millis(50));
        let handle = server.handle();
        let soft_at = Instant::now();
        assert!(handle.close_after_flush(id, KillReason(2), Duration::from_secs(2)));
        std::thread::sleep(Duration::from_millis(300));
        let stats = server.stats();
        assert_eq!(
            stats.open,
            1,
            "{driver:?}: closed {:?} after the soft kill without its linger, closes {:?}",
            soft_at.elapsed(),
            stats.closes().collect::<Vec<_>>()
        );
        // The linger sends FIN first; the peer sees the end of the stream, not a reset.
        let mut buf = [0u8; 16];
        assert_eq!(
            c.read(&mut buf).map_err(|e| e.kind()),
            Ok(0),
            "{driver:?}: FIN"
        );
        assert!(
            eventually(WAIT, || server
                .stats()
                .closed_for(CloseReason::Killed(KillReason(2)))
                == 1),
            "{driver:?}: closed by the soft kill"
        );
        assert!(
            soft_at.elapsed() >= Duration::from_millis(1900),
            "{driver:?}: closed {:?} after the soft kill, before its bound",
            soft_at.elapsed()
        );
    }
}

#[test]
fn test_kill_ends_a_close_after_flush() {
    for driver in DRIVERS {
        let (server, ids) = reporting(driver, || Sink);
        let mut c = client(addr(&server));
        c.write_all(b"go").expect("write");
        let id = ids.recv_timeout(WAIT).expect("id");
        // The client keeps sending, so the close lingers reading it (up to 20 s).
        let mut w = c.try_clone().expect("clone");
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopped = stop.clone();
        let writer = std::thread::spawn(move || {
            while !stopped.load(std::sync::atomic::Ordering::Relaxed) {
                if w.write_all(&[b'x'; 1024]).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        std::thread::sleep(Duration::from_millis(50));
        let handle = server.handle();
        let soft_at = Instant::now();
        assert!(handle.close_after_flush(id, KillReason(2), Duration::from_secs(20)));
        assert!(
            !handle.close_after_flush(id, KillReason(3), Duration::from_secs(20)),
            "{driver:?}: once"
        );
        std::thread::sleep(Duration::from_millis(300));
        // A Linux pool worker inside an exchange is in a blocking receive the wake
        // channel cannot end: its read side is shut, so its linger ends at once
        // (D-182). Everywhere else the close is still lingering here.
        if driver == DriverKind::Blocking && cfg!(target_os = "linux") {
            assert!(
                eventually(WAIT, || server
                    .stats()
                    .closed_for(CloseReason::Killed(KillReason(2)))
                    == 1),
                "{driver:?}: closed by the soft kill"
            );
            assert!(!handle.kill(id, KillReason(8)), "{driver:?}: closed");
        } else {
            // Register R-47: under load the soft kill came before the first `on_data`
            // and the close skipped its linger (D-202); this says how, should it recur.
            let stats = server.stats();
            assert_eq!(
                stats.open,
                1,
                "{driver:?}: still lingering {:?} after the soft kill, closes {:?}",
                soft_at.elapsed(),
                stats.closes().collect::<Vec<_>>()
            );
            let start = Instant::now();
            assert!(
                handle.kill(id, KillReason(8)),
                "{driver:?}: a kill upgrades it"
            );
            assert!(!handle.kill(id, KillReason(9)), "{driver:?}: once");
            assert!(
                eventually(WAIT, || server
                    .stats()
                    .closed_for(CloseReason::Killed(KillReason(8)))
                    == 1),
                "{driver:?}: not closed"
            );
            assert!(start.elapsed() < Duration::from_secs(3), "{driver:?}");
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        drop(c);
        writer.join().expect("writer");
        assert!(!handle.close_after_flush(id, KillReason(1), Duration::from_secs(1)));
    }
}

#[test]
fn test_denials_past_the_soft_close_cap_reset_at_once() {
    for driver in DRIVERS {
        let server = denying(
            driver,
            limits(|b| {
                b.graceful_linger(Duration::from_secs(10), 64 * 1024)
                    .denial_linger(Duration::from_secs(3))
                    .denial_linger_max(1)
            }),
        );
        // The first denial takes the one place and lingers: its peer stays open.
        let mut first = client(addr(&server));
        first.write_all(b"go").expect("write");
        let (got, end) = read_until_closed(&mut first);
        assert_eq!(got, b"denied\n", "{driver:?}");
        assert!(end.is_ok(), "{driver:?}: FIN, got {end:?}");
        // The second finds no place: a reset, at once.
        let start = Instant::now();
        let mut second = client(addr(&server));
        second.write_all(b"go").expect("write");
        let (_, end) = read_until_closed(&mut second);
        let e = end.expect_err("a reset past the cap");
        assert!(
            matches!(
                e.kind(),
                ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
            ),
            "{driver:?}: {e:?}"
        );
        assert!(start.elapsed() < Duration::from_secs(2), "{driver:?}");
        drop(first);
        drop(second);
        assert!(
            eventually(WAIT, || server
                .stats()
                .closed_for(CloseReason::EgressDenied(7))
                == 2),
            "{driver:?}"
        );
    }
}
