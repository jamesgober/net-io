//! The blocking driver end to end: echo, caps, kill, drain, timeouts, slow peers, panics.

mod common;

use std::io::Write;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{addr, client, closed_by_server, eventually, refused, round_trip};
use net_io::{
    AllowAll, CloseReason, ConnectionInfo, DriverKind, Input, KillReason, Limits, ListenOptions,
    ListenerSpec, MinRate, NetError, Phase, PrefixPolicy, RefusalCause, ServerBuilder, Session,
    SessionContext, Step, TcpConnection,
};

const WAIT: Duration = Duration::from_secs(5);

/// Echoes until the peer closes.
fn echo_handler(conn: &mut TcpConnection) -> Result<(), NetError> {
    let mut buf = [0u8; 4096];
    loop {
        let n = conn.recv(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        conn.send_all(&buf[..n])?;
    }
}

/// Echoes, pushing as much as the output takes and letting net-io call again.
struct Echo;

impl Session for Echo {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let taken = cx.output().push_partial(input.bytes());
        input.consume(taken);
        Step::Write
    }
}

/// Starts an exchange on the first byte and never finishes it; reports the first byte.
struct Stall(Option<mpsc::Sender<()>>);

impl Session for Stall {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        cx.set_phase(Phase::Receiving);
        let n = input.bytes().len();
        input.consume(n);
        if let Some(tx) = self.0.take() {
            let _ = tx.send(());
        }
        Step::Read
    }
}

/// A factory of `Stall` sessions and the receiver of their first-byte signals.
fn stall_factory() -> (
    impl Fn(&ConnectionInfo) -> Stall + Send + Sync + 'static,
    mpsc::Receiver<()>,
) {
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let factory = move |_: &ConnectionInfo| Stall(tx.lock().ok().map(|t| t.clone()));
    (factory, rx)
}

fn limits(f: impl FnOnce(net_io::LimitsBuilder) -> net_io::LimitsBuilder) -> Limits {
    f(Limits::builder()).build().expect("limits")
}

#[test]
fn test_blocking_handler_echoes_and_counts() {
    let server = net_io::serve("127.0.0.1:0", echo_handler).expect("serve");
    let mut c = client(addr(&server));
    for msg in [&b"hello"[..], b"a longer line\n", &[7u8; 3000]] {
        assert_eq!(round_trip(&mut c, msg), msg);
    }
    drop(c);
    assert!(eventually(WAIT, || server.stats().closed == 1));
    let stats = server.stats();
    assert_eq!(stats.accepted, 1);
    assert_eq!(stats.open, 0);
    assert_eq!(stats.closed_for(CloseReason::PeerClosed), 1);
    assert_eq!(stats.bytes_in, 5 + 14 + 3000);
    assert_eq!(stats.bytes_out, stats.bytes_in);
}

#[test]
fn test_sessions_echo_large_message() {
    let server = net_io::serve_sessions("127.0.0.1:0", |_: &ConnectionInfo| Echo).expect("serve");
    let mut c = client(addr(&server));
    // Larger than the input buffer and the output budget: exercises partial pushes.
    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let writer = {
        let mut w = c.try_clone().expect("clone");
        let big = big.clone();
        std::thread::spawn(move || w.write_all(&big).expect("write"))
    };
    let mut back = vec![0u8; big.len()];
    std::io::Read::read_exact(&mut c, &mut back).expect("read");
    writer.join().expect("writer");
    assert!(back == big, "echo differs");
    drop(c);
    assert!(eventually(WAIT, || server.stats().closed == 1));
}

#[test]
fn test_many_clients_concurrently() {
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .driver(DriverKind::Blocking)
        // Headroom over the 8 clients (4x): a closing connection holds its slot until
        // the worker finishes it, and the next one from the same client may arrive first.
        .workers(32)
        // 8 clients connect back to back: on a slow runner a client's earlier
        // connections may not be counted closed yet, so raise the per-source cap
        // (16 by default) to the global cap; this test is about concurrency, not caps.
        .limits(limits(|b| b.max_per_source(32, PrefixPolicy::HOST)))
        .sessions(|_: &ConnectionInfo| Echo)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let a = addr(&server);
    let threads: Vec<_> = (0..8u8)
        .map(|t| {
            std::thread::spawn(move || {
                for i in 0..20u8 {
                    let mut c = client(a);
                    let msg = [t, i, 1, 2, 3];
                    assert_eq!(round_trip(&mut c, &msg), msg);
                }
            })
        })
        .collect();
    for t in threads {
        t.join().expect("client");
    }
    assert!(eventually(WAIT, || server.stats().closed == 160));
    assert_eq!(server.stats().refused, 0);
}

#[test]
fn test_global_cap_refuses_before_reading() {
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .workers(2)
        .limits(limits(|b| b.max_connections(1).max_per_listener(1)))
        .handler(echo_handler)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let mut first = client(addr(&server));
    assert_eq!(round_trip(&mut first, b"x"), b"x");
    assert!(
        refused(addr(&server)),
        "second connection should be refused"
    );
    assert!(eventually(WAIT, || server
        .stats()
        .refused_for(RefusalCause::GlobalCap)
        == 1));
    // The first connection is unaffected.
    assert_eq!(round_trip(&mut first, b"y"), b"y");
}

#[test]
fn test_per_source_cap() {
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .workers(4)
        .limits(limits(|b| {
            b.max_connections(4).max_per_source(1, PrefixPolicy::HOST)
        }))
        .handler(echo_handler)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let mut first = client(addr(&server));
    assert_eq!(round_trip(&mut first, b"x"), b"x");
    assert!(refused(addr(&server)));
    assert!(eventually(WAIT, || server
        .stats()
        .refused_for(RefusalCause::SourceCap)
        == 1));
    // Releasing the first frees the source slot.
    drop(first);
    assert!(eventually(WAIT, || server
        .stats()
        .closed_for(CloseReason::PeerClosed)
        == 1));
    let mut third = client(addr(&server));
    assert_eq!(round_trip(&mut third, b"z"), b"z");
}

#[test]
fn test_closed_door_leaves_connections_in_the_backlog() {
    let server = net_io::serve("127.0.0.1:0", echo_handler).expect("serve");
    server.close_door();
    assert_eq!(server.door(), net_io::DoorState::Closed);
    // The kernel completes the handshake; net-io does not accept while the door is closed.
    let mut c = client(addr(&server));
    c.write_all(b"back").expect("write");
    c.set_read_timeout(Some(Duration::from_millis(300)))
        .expect("timeout");
    let mut buf = [0u8; 4];
    assert!(
        std::io::Read::read(&mut c, &mut buf).is_err(),
        "no reply while the door is closed"
    );
    assert_eq!(server.stats().accepted, 0);
    // Opening the door accepts the waiting connection.
    server.open_door().expect("open");
    c.set_read_timeout(Some(WAIT)).expect("timeout");
    std::io::Read::read_exact(&mut c, &mut buf).expect("read");
    assert_eq!(&buf, b"back");
    assert_eq!(server.stats().refused, 0);
}

#[test]
fn test_kill_ends_a_blocked_handler() {
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let result = Arc::new(Mutex::new(None));
    let seen = result.clone();
    let server = net_io::serve("127.0.0.1:0", move |conn: &mut TcpConnection| {
        let _ = tx.lock().map(|t| t.send(conn.id()));
        let mut buf = [0u8; 16];
        let r = conn.recv(&mut buf);
        *seen.lock().expect("lock") = Some(r.map_err(|e| e.to_string()));
        Ok(())
    })
    .expect("serve");
    let mut c = client(addr(&server));
    let id = rx.recv_timeout(WAIT).expect("id");
    assert!(server.handle().kill(id, KillReason(7)));
    assert!(closed_by_server(&mut c));
    assert!(eventually(WAIT, || server.stats().killed == 1));
    let r = result
        .lock()
        .expect("lock")
        .clone()
        .expect("handler finished");
    assert!(r.is_err(), "recv should fail after a kill, got {r:?}");
    assert_eq!(
        server
            .stats()
            .closed_for(CloseReason::Killed(KillReason(0))),
        1
    );
    // A second kill of the same id is a no-op.
    assert!(!server.handle().kill(id, KillReason(7)));
}

#[test]
fn test_drain_closes_idle_sessions_gracefully() {
    let server = net_io::serve_sessions("127.0.0.1:0", |_: &ConnectionInfo| Echo).expect("serve");
    let mut c = client(addr(&server));
    assert_eq!(round_trip(&mut c, b"x"), b"x");
    let report = server.shutdown(Instant::now() + Duration::from_secs(2));
    assert!(
        report.took < Duration::from_millis(500),
        "idle connections close at once: {:?}",
        report.took
    );
    assert_eq!(report.graceful, 1);
    assert_eq!(report.killed, 0);
    assert!(closed_by_server(&mut c));
}

#[test]
fn test_drain_kills_busy_sessions_at_the_deadline() {
    let (factory, started) = stall_factory();
    let server = net_io::serve_sessions("127.0.0.1:0", factory).expect("serve");
    let mut c = client(addr(&server));
    c.write_all(b"start of a request").expect("write");
    started.recv_timeout(WAIT).expect("exchange started");
    let start = Instant::now();
    let report = server.shutdown(Instant::now() + Duration::from_millis(200));
    let took = start.elapsed();
    assert!(
        took >= Duration::from_millis(150),
        "drain returned early: {took:?}"
    );
    assert!(took < Duration::from_secs(3), "drain overran: {took:?}");
    assert_eq!(report.killed, 1);
    assert!(closed_by_server(&mut c));
}

#[test]
fn test_idle_timeout_closes() {
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .limits(limits(|b| b.idle_timeout(Duration::from_millis(150))))
        .sessions(|_: &ConnectionInfo| Echo)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let mut c = client(addr(&server));
    assert!(closed_by_server(&mut c));
    assert!(eventually(WAIT, || server
        .stats()
        .closed_for(CloseReason::Idle)
        == 1));
    assert_eq!(server.stats().timeouts, 1);
}

#[test]
fn test_read_timeout_inside_an_exchange() {
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .limits(limits(|b| b.read_timeout(Duration::from_millis(150))))
        .sessions(stall_factory().0)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let mut c = client(addr(&server));
    c.write_all(b"GET / HTTP/1.1\r\n").expect("write");
    assert!(closed_by_server(&mut c));
    assert!(eventually(WAIT, || server
        .stats()
        .closed_for(CloseReason::ReadTimeout)
        == 1));
}

#[test]
fn test_slow_peer_is_closed() {
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .limits(limits(|b| {
            b.min_rate(MinRate {
                bytes_per_sec: 1000,
                window: Duration::from_millis(500),
                grace: Duration::from_millis(300),
                check: Duration::from_millis(100),
            })
        }))
        .sessions(stall_factory().0)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let mut c = client(addr(&server));
    // One byte every 40 ms: far under 1000 B/s.
    let start = Instant::now();
    let mut closed = false;
    while start.elapsed() < WAIT {
        if c.write_all(b"x").is_err() {
            closed = true;
            break;
        }
        if server.stats().slow_peers == 1 {
            closed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    assert!(closed, "slow peer was not closed");
    assert!(eventually(WAIT, || server.stats().slow_peers == 1));
}

#[test]
fn test_session_panic_is_contained() {
    struct Boom;
    impl Session for Boom {
        fn on_data(&mut self, _cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
            if input.bytes().starts_with(b"boom") {
                panic!("session bug");
            }
            Step::Read
        }
    }
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .workers(1)
        .sessions(|_: &ConnectionInfo| Boom)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let mut c = client(addr(&server));
    c.write_all(b"boom").expect("write");
    assert!(closed_by_server(&mut c));
    assert!(
        eventually(WAIT, || server.stats().session_panics == 1),
        "{:?}",
        server.stats()
    );
    // The one worker survived and serves the next connection.
    let server2 = net_io::serve_sessions("127.0.0.1:0", |_: &ConnectionInfo| Echo).expect("serve");
    let mut c = client(addr(&server2));
    assert_eq!(round_trip(&mut c, b"ok"), b"ok");
    let mut again = client(addr(&server));
    again.write_all(b"boom").expect("write");
    assert!(closed_by_server(&mut again));
    assert!(eventually(WAIT, || server.stats().session_panics == 2));
}

#[test]
fn test_request_stop_ends_wait_for_stop() {
    let server = net_io::serve("127.0.0.1:0", echo_handler).expect("serve");
    let handle = server.handle();
    let a = addr(&server);
    let waiter = std::thread::spawn(move || server.wait_for_stop());
    let mut c = client(a);
    assert_eq!(round_trip(&mut c, b"x"), b"x");
    handle.request_stop();
    let report = waiter.join().expect("wait_for_stop");
    assert_eq!(report.graceful + report.killed, 1);
    assert!(closed_by_server(&mut c));
}

#[test]
fn test_reply_returns_an_auto_phase_connection_to_idle() {
    // The session never sets a phase: after its reply the idle timeout applies, not the read timeout.
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .limits(limits(|b| {
            b.idle_timeout(Duration::from_millis(200))
                .read_timeout(Duration::from_secs(30))
        }))
        .sessions(|_: &ConnectionInfo| Echo)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let mut c = client(addr(&server));
    assert_eq!(round_trip(&mut c, b"one"), b"one");
    assert_eq!(round_trip(&mut c, b"two"), b"two");
    let start = Instant::now();
    assert!(closed_by_server(&mut c));
    assert!(start.elapsed() < Duration::from_secs(3));
    assert!(eventually(WAIT, || server
        .stats()
        .closed_for(CloseReason::Idle)
        == 1));
}

#[test]
fn test_busy_when_every_worker_holds_a_connection() {
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .workers(1)
        .limits(limits(|b| b.max_connections(8).max_per_listener(8)))
        .handler(echo_handler)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    // The first connection is served at once, even on a fresh server.
    let mut first = client(addr(&server));
    assert_eq!(round_trip(&mut first, b"x"), b"x");
    assert!(refused(addr(&server)));
    assert!(eventually(WAIT, || server
        .stats()
        .refused_for(RefusalCause::Busy)
        == 1));
    drop(first);
    assert!(eventually(WAIT, || server.stats().closed == 1));
    let mut third = client(addr(&server));
    assert_eq!(round_trip(&mut third, b"z"), b"z");
}

#[test]
fn test_peer_that_never_reads_hits_the_write_timeout() {
    static BLOCK: [u8; 1 << 20] = [b'z'; 1 << 20];
    /// Answers the first byte with an endless response.
    struct Flood;
    impl Flood {
        fn fill(cx: &mut SessionContext<'_>) -> Step {
            while cx.output().push_static(&BLOCK).is_ok() {}
            Step::Write
        }
    }
    impl Session for Flood {
        fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
            let n = input.bytes().len();
            input.consume(n);
            Flood::fill(cx)
        }
        fn on_writable(&mut self, cx: &mut SessionContext<'_>) -> Step {
            Flood::fill(cx)
        }
    }
    // Windows autotunes socket buffers, and on loopback they grow large before a
    // send stalls; the endless response gets there on every platform.
    let options = ListenOptions::new().send_buffer(256 * 1024);
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp_with("127.0.0.1:0", options))
        .limits(limits(|b| {
            b.write_timeout(Duration::from_millis(300))
                .min_rate(MinRate::off())
        }))
        .sessions(|_: &ConnectionInfo| Flood)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let mut c = client(addr(&server));
    c.write_all(b"go").expect("write");
    // Never read: the server's sends stop making progress.
    assert!(
        eventually(Duration::from_secs(10), || server
            .stats()
            .closed_for(CloseReason::WriteTimeout)
            == 1),
        "{:?}",
        server.stats()
    );
    assert_eq!(server.stats().timeouts, 1);
}

#[test]
fn test_idle_override_applies_to_one_connection() {
    struct Short;
    impl Session for Short {
        fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
            cx.set_idle_timeout(Some(Duration::from_millis(100)));
            let taken = cx.output().push_partial(input.bytes());
            input.consume(taken);
            Step::Write
        }
    }
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .limits(limits(|b| b.idle_timeout(Duration::from_secs(30))))
        .sessions(|_: &ConnectionInfo| Short)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let mut c = client(addr(&server));
    assert_eq!(round_trip(&mut c, b"x"), b"x");
    let start = Instant::now();
    assert!(closed_by_server(&mut c));
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "the 30 s limit applied"
    );
    assert!(eventually(WAIT, || server
        .stats()
        .closed_for(CloseReason::Idle)
        == 1));
}

#[test]
fn test_exchange_timeout_can_answer_then_close_gracefully() {
    use net_io::TimeoutKind;
    struct Slow;
    impl Session for Slow {
        fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
            let n = input.bytes().len();
            input.consume(n);
            cx.set_phase(Phase::Receiving);
            let at = cx.now() + Duration::from_millis(100);
            cx.set_exchange_deadline(Some(at));
            Step::Read
        }
        fn on_timeout(&mut self, cx: &mut SessionContext<'_>, which: TimeoutKind) -> Step {
            assert_eq!(which, TimeoutKind::Exchange);
            let _ = cx.output().push(b"408\n");
            Step::Write
        }
        fn on_writable(&mut self, _cx: &mut SessionContext<'_>) -> Step {
            Step::Close
        }
    }
    let server = net_io::serve_sessions("127.0.0.1:0", |_: &ConnectionInfo| Slow).expect("serve");
    let mut c = client(addr(&server));
    c.write_all(b"GET / HTTP/1.1\r\n").expect("write");
    let mut reply = Vec::new();
    std::io::Read::read_to_end(&mut c, &mut reply).expect("graceful close, not a reset");
    assert_eq!(reply, b"408\n");
    assert!(eventually(WAIT, || server
        .stats()
        .closed_for(CloseReason::SessionClosed)
        == 1));
    assert_eq!(server.stats().closed_for(CloseReason::ExchangeDeadline), 0);
}
