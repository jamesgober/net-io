//! The blocking driver end to end: echo, caps, kill, drain, timeouts, slow peers, panics.

mod common;

use std::io::Write;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{DRIVERS, addr, client, closed_by_server, eventually, refused, round_trip};
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
    let (factory, first) = stall_factory();
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
        .sessions(factory)
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
    assert!(
        closed,
        "slow peer was not closed: {:?} after {:?}, first byte seen: {:?}",
        server.stats(),
        start.elapsed(),
        first.try_recv()
    );
    assert!(eventually(WAIT, || server.stats().slow_peers == 1));
}

/// A peer that passes the first check with a burst, then sends a byte far more
/// often than the check interval, is still measured: re-arming the timer on each
/// arrival must not push the check away for good.
#[test]
fn test_trickle_faster_than_the_check_is_closed() {
    for &driver in DRIVERS {
        let server = ServerBuilder::new()
            .listener(ListenerSpec::tcp("127.0.0.1:0"))
            .driver(driver)
            .limits(limits(|b| {
                b.min_rate(MinRate {
                    bytes_per_sec: 1000,
                    window: Duration::from_secs(2),
                    grace: Duration::from_millis(200),
                    check: Duration::from_secs(1),
                })
            }))
            .sessions(stall_factory().0)
            .gate(AllowAll)
            .build()
            .expect("build");
        server.open_door().expect("open");
        let mut c = client(addr(&server));
        c.write_all(&[b'x'; 2000]).expect("burst");
        let start = Instant::now();
        while start.elapsed() < WAIT && server.stats().slow_peers == 0 {
            if c.write_all(b"x").is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(40));
        }
        // The burst leaves the window at 2 s; a check every second must follow.
        assert!(
            eventually(Duration::from_millis(200), || server.stats().slow_peers
                == 1)
                && start.elapsed() < Duration::from_secs(4),
            "{driver:?}: {:?} after {:?}",
            server.stats(),
            start.elapsed()
        );
    }
}

/// The output side of the test above: a reader that takes a little often, but
/// less than the minimum rate, is closed while it reads. Linux only: elsewhere the
/// client's receive buffer grows to take the whole response, so the server never
/// waits on the reader.
#[cfg(target_os = "linux")]
#[test]
fn test_reader_slower_than_the_rate_is_closed_while_it_reads() {
    use std::io::Read;
    static BIG: [u8; 16 << 20] = [b'r'; 16 << 20];
    struct Flood(bool);
    impl Session for Flood {
        fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
            let n = input.bytes().len();
            input.consume(n);
            if !self.0 {
                self.0 = true;
                cx.output().push_static(&BIG).expect("push");
            }
            Step::Write
        }
    }
    for &driver in DRIVERS {
        let server = ServerBuilder::new()
            .listener(ListenerSpec::tcp_with(
                "127.0.0.1:0",
                ListenOptions::new().send_buffer(16 * 1024),
            ))
            .driver(driver)
            .limits(limits(|b| {
                b.min_rate(MinRate {
                    bytes_per_sec: 200_000,
                    window: Duration::from_secs(2),
                    grace: Duration::from_millis(200),
                    check: Duration::from_secs(1),
                })
                .write_timeout(Duration::from_secs(30))
            }))
            .sessions(|_: &ConnectionInfo| Flood(false))
            .gate(AllowAll)
            .build()
            .expect("build");
        server.open_door().expect("open");
        let mut c = client(addr(&server));
        c.write_all(b"go").expect("ask");
        let mut b = [0u8; 4096];
        let start = Instant::now();
        while start.elapsed() < WAIT && server.stats().slow_peers == 0 {
            match c.read(&mut b) {
                Ok(0) | Err(_) => break,
                Ok(_) => std::thread::sleep(Duration::from_millis(40)),
            }
        }
        assert!(
            eventually(Duration::from_millis(200), || server.stats().slow_peers
                == 1)
                && start.elapsed() < Duration::from_secs(4),
            "{driver:?}: {:?} after {:?}",
            server.stats(),
            start.elapsed()
        );
    }
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
    // 1 s against 30 s, so a loaded host cannot idle the connection out between the two round trips.
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .limits(limits(|b| {
            b.idle_timeout(Duration::from_secs(1))
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
    assert!(start.elapsed() < Duration::from_secs(10));
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

#[test]
fn test_per_source_cap_per_listener() {
    // Listener 0 allows one connection per source; listener 1 keeps the default.
    let server = ServerBuilder::new()
        .listener(
            ListenerSpec::tcp("127.0.0.1:0")
                .limits(limits(|b| b.max_per_source(1, PrefixPolicy::HOST))),
        )
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .workers(8)
        .handler(echo_handler)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let a = server.listeners()[0].local.socket_addr().expect("ip");
    let b = server.listeners()[1].local.socket_addr().expect("ip");
    let mut first = client(a);
    assert_eq!(round_trip(&mut first, b"x"), b"x");
    assert!(
        refused(a),
        "the second connection to the capped listener is refused"
    );
    let mut others: Vec<_> = (0..3).map(|_| client(b)).collect();
    for c in &mut others {
        assert_eq!(round_trip(c, b"y"), b"y");
    }
    assert_eq!(server.stats().refused_for(RefusalCause::SourceCap), 1);
}

/// Lines: each complete line is answered; a session that survives its read timeout
/// keeps waiting for the rest of a partial one.
struct Lines {
    timeouts: Arc<std::sync::atomic::AtomicU32>,
}

impl Session for Lines {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        while let Some(end) = input.bytes().iter().position(|&b| b == b'\n') {
            let line = input.bytes()[..=end].to_vec();
            input.consume(end + 1);
            cx.output().push(&line).expect("push");
        }
        Step::Write
    }

    fn on_writable(&mut self, _: &mut SessionContext<'_>) -> Step {
        Step::Read
    }

    fn on_timeout(&mut self, _: &mut SessionContext<'_>, _: net_io::TimeoutKind) -> Step {
        self.timeouts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Step::Read
    }
}

/// A complete line plus the start of the next, then silence past the read timeout:
/// the session survives the timeout while its partial line is with the receive in
/// flight, and the line completes later (review finding: the reactor indexed the
/// stand-in buffer and the worker panicked).
#[test]
fn test_session_survives_a_timeout_with_a_partial_message_held() {
    for &driver in DRIVERS {
        let timeouts = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let t2 = timeouts.clone();
        let limits = Limits::builder()
            .read_timeout(Duration::from_millis(300))
            .idle_timeout(Duration::from_millis(300))
            .build()
            .expect("limits");
        let server = ServerBuilder::new()
            .listener(ListenerSpec::tcp("127.0.0.1:0").limits(limits))
            .driver(driver)
            // One reactor worker serves both clients; the pool needs one each.
            .workers(if driver == DriverKind::Blocking { 2 } else { 1 })
            .sessions(move |_: &ConnectionInfo| Lines {
                timeouts: t2.clone(),
            })
            .gate(AllowAll)
            .build()
            .expect("build");
        server.open_door().expect("open");
        let mut c = client(addr(&server));
        c.write_all(b"one\npar").expect("write");
        let mut back = [0u8; 4];
        std::io::Read::read_exact(&mut c, &mut back).expect("first line");
        assert_eq!(&back, b"one\n", "{driver:?}");
        assert!(
            eventually(Duration::from_secs(5), || timeouts
                .load(std::sync::atomic::Ordering::SeqCst)
                >= 2),
            "{driver:?}: no timeout"
        );
        c.write_all(b"tial\n").expect("write");
        let mut back = [0u8; 8];
        std::io::Read::read_exact(&mut c, &mut back).expect("second line");
        assert_eq!(&back, b"partial\n", "{driver:?}");
        // The worker is still alive for others.
        let mut d = client(addr(&server));
        d.write_all(b"two\n").expect("write");
        std::io::Read::read_exact(&mut d, &mut back[..4]).expect("other client");
        assert_eq!(&back[..4], b"two\n", "{driver:?}");
    }
}

/// An event sink that panics on every close loses those events and nothing else:
/// caps come back and drain finishes, on both drivers (review finding).
#[test]
fn test_panicking_event_sink_loses_only_its_events() {
    struct Bad;
    impl net_io::EventSink for Bad {
        fn event(&self, e: &net_io::Event) {
            assert!(!matches!(e, net_io::Event::Closed { .. }), "sink bug");
        }
    }
    for &driver in DRIVERS {
        let server = ServerBuilder::new()
            .listener(ListenerSpec::tcp("127.0.0.1:0"))
            .driver(driver)
            .workers(1)
            .sessions(|_: &ConnectionInfo| Echo)
            .gate(AllowAll)
            .events(Bad)
            .build()
            .expect("build");
        server.open_door().expect("open");
        // One worker: a client that arrives while the last one's close is still
        // being finished (here, past the sink's panic) is refused `Busy`, which is
        // a refusal, not a lost slot; it tries again.
        let served = |n: usize| {
            for _ in 0..100 {
                let mut c = client(addr(&server));
                c.write_all(b"hi").expect("write");
                let mut back = [0u8; 2];
                if std::io::Read::read_exact(&mut c, &mut back).is_ok() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            panic!("{driver:?} round {n}: never served: {:?}", server.stats());
        };
        for n in 0..3 {
            served(n);
            assert!(eventually(Duration::from_secs(5), || server.stats().open == 0));
        }
        assert!(
            eventually(Duration::from_secs(5), || server.stats().open == 0),
            "{driver:?}: {:?}",
            server.stats()
        );
        // The worker and its slot came back each time: a lost one never serves.
        served(3);
        let started = Instant::now();
        let _ = server.shutdown(Instant::now() + Duration::from_secs(2));
        assert!(started.elapsed() < Duration::from_secs(4), "{driver:?}");
    }
}

/// A handler that gates its own accepted connection and is refused: the connection
/// closes, its slots come back, and the worker serves the next one (review finding).
#[test]
fn test_handler_refused_by_its_own_gate_releases_the_connection() {
    struct No;
    impl net_io::Gate for No {
        type Ticket = ();
        fn admit(
            &self,
            _: &ConnectionInfo,
            _: net_io::AdmitStage,
        ) -> Result<net_io::Admitted<()>, net_io::Refusal> {
            Err(net_io::Refusal::Reset { code: 7 })
        }
        fn readmit(&self, _: &mut (), _: &ConnectionInfo) -> Result<(), net_io::Refusal> {
            Ok(())
        }
        fn check(&self, _: &mut (), _: &net_io::WriteCheck) -> Result<(), net_io::Denial> {
            Ok(())
        }
    }
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .driver(DriverKind::Blocking)
        .workers(1)
        .handler(|conn: &mut TcpConnection| {
            let mut b = [0u8; 1];
            conn.recv(&mut b)?;
            if b[0] == b'g' {
                conn.set_gate(Arc::new(No))?;
            }
            conn.send_all(b"ok")
        })
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    for _ in 0..3 {
        let mut c = client(addr(&server));
        c.write_all(b"g").expect("write");
        assert!(closed_by_server(&mut c));
        // One worker: the next client waits for this close, or the pool says Busy.
        assert!(eventually(Duration::from_secs(5), || server.stats().open == 0));
    }
    assert!(
        eventually(Duration::from_secs(5), || server.stats().open == 0
            && server.stats().closed == 3),
        "{:?}",
        server.stats()
    );
    let mut c = client(addr(&server));
    c.write_all(b"x").expect("write");
    let mut back = [0u8; 2];
    std::io::Read::read_exact(&mut c, &mut back).expect("served");
    assert_eq!(&back, b"ok");
}

/// A listener cannot lift the server's cap: its own `max_connections` is refused at
/// build, and admission counts against the server's cap (review finding).
#[test]
fn test_listener_cannot_set_the_global_cap() {
    let raised = Limits::builder()
        .max_connections(100_000)
        .build()
        .expect("limits");
    let result = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0").limits(raised))
        .limits(limits(|b| b.max_connections(4)))
        .handler(echo_handler)
        .gate(AllowAll)
        .build();
    assert!(
        matches!(
            result,
            Err(NetError::InvalidConfig {
                field: "max_connections",
                ..
            })
        ),
        "{:?}",
        result.err()
    );
}

/// A session that sets "no idle limit" as `Duration::MAX`, and a client connect with
/// a `Duration::MAX` timeout, work instead of panicking (review finding).
#[test]
fn test_duration_max_is_held_to_a_year_not_a_panic() {
    struct Forever;
    impl Session for Forever {
        fn on_open(&mut self, cx: &mut SessionContext<'_>) -> Step {
            cx.set_idle_timeout(Some(Duration::MAX));
            Step::Read
        }
        fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
            let taken = cx.output().push_partial(input.bytes());
            input.consume(taken);
            Step::Write
        }
    }
    for &driver in DRIVERS {
        let server = ServerBuilder::new()
            .listener(ListenerSpec::tcp("127.0.0.1:0"))
            .driver(driver)
            .workers(1)
            .sessions(|_: &ConnectionInfo| Forever)
            .gate(AllowAll)
            .build()
            .expect("build");
        server.open_door().expect("open");
        let options = net_io::ConnectOptions::new().timeout(Duration::MAX);
        let mut c = TcpConnection::connect_with(addr(&server), options).expect("connect");
        for _ in 0..3 {
            c.send_all(b"ping").expect("send");
            let mut back = [0u8; 4];
            c.recv_exact(&mut back).expect("recv");
            assert_eq!(&back, b"ping", "{driver:?}");
        }
        assert_eq!(server.stats().session_panics, 0, "{driver:?}");
        assert_eq!(server.stats().closed, 0, "{driver:?}");
    }
}

/// A post from another thread reaches a connection that waits for input, not only a
/// parked one, on both drivers: a server push with nothing from the client (serve-net
/// request 7).
#[test]
fn test_post_wakes_a_connection_waiting_for_input() {
    use std::io::Read;
    struct Push(mpsc::Sender<(net_io::Completer, net_io::ConnectionId)>);
    impl Session for Push {
        fn on_open(&mut self, cx: &mut SessionContext<'_>) -> Step {
            let _ = self.0.send((cx.completer(), cx.info().id));
            Step::Read
        }
        fn on_data(&mut self, _: &mut SessionContext<'_>, input: &mut Input) -> Step {
            let n = input.bytes().len();
            input.consume(n);
            Step::Read
        }
        fn on_wake(&mut self, cx: &mut SessionContext<'_>, token: u32, value: u64) -> Step {
            let _ = cx
                .output()
                .push(format!("woke {token} {value}\n").as_bytes());
            Step::Write
        }
        fn on_writable(&mut self, _: &mut SessionContext<'_>) -> Step {
            Step::Read
        }
    }
    for &driver in DRIVERS {
        let (tx, rx) = mpsc::channel();
        let tx = Mutex::new(tx);
        let server = ServerBuilder::new()
            .listener(ListenerSpec::tcp("127.0.0.1:0"))
            .driver(driver)
            .workers(2)
            .sessions(move |_: &ConnectionInfo| Push(tx.lock().expect("lock").clone()))
            .gate(AllowAll)
            .build()
            .expect("build");
        server.open_door().expect("open");
        let mut c = client(addr(&server));
        let (completer, id) = rx.recv_timeout(Duration::from_secs(5)).expect("opened");
        // Let the connection settle into its read wait.
        std::thread::sleep(Duration::from_millis(100));
        std::thread::spawn(move || completer.post(id, 3, 42).expect("post"))
            .join()
            .expect("poster");
        let mut line = [0u8; 10];
        c.read_exact(&mut line).expect("pushed line");
        assert_eq!(&line, b"woke 3 42\n", "{driver:?}");
        // Still a normal connection afterwards.
        c.write_all(b"x").expect("write");
        assert_eq!(server.stats().closed, 0, "{driver:?}");
    }
}

/// serve-net 0.5 item 2: with an injected clock on the reactor, a connection that
/// answered its deadline and closed gracefully, then `shutdown`: it returns.
#[test]
fn test_manual_clock_close_then_shutdown_returns() {
    use std::io::Read;
    struct Late;
    impl Session for Late {
        fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
            let n = input.bytes().len();
            input.consume(n);
            let at = cx.now() + Duration::from_secs(1);
            cx.set_exchange_deadline(Some(at));
            cx.set_phase(Phase::Receiving);
            Step::Read
        }
        fn on_timeout(&mut self, cx: &mut SessionContext<'_>, _: net_io::TimeoutKind) -> Step {
            let _ = cx.output().push(b"408\n");
            Step::Write
        }
        fn on_writable(&mut self, _: &mut SessionContext<'_>) -> Step {
            Step::Close
        }
    }
    for &driver in DRIVERS {
        let clock = Arc::new(net_io::ManualClock::new());
        let server = ServerBuilder::new()
            .listener(ListenerSpec::tcp("127.0.0.1:0"))
            .driver(driver)
            .workers(1)
            .clock(clock.clone())
            .sessions(|_: &ConnectionInfo| Late)
            .gate(AllowAll)
            .build()
            .expect("build");
        server.open_door().expect("open");
        let mut c = client(addr(&server));
        c.write_all(b"go").expect("write");
        // Advance until the deadline fires: on a loaded host the session may set it
        // after a first advance.
        c.set_read_timeout(Some(Duration::from_millis(200)))
            .expect("timeout");
        let mut reply = [0u8; 4];
        let mut got = false;
        for _ in 0..50 {
            clock.advance(Duration::from_secs(2));
            if c.read_exact(&mut reply).is_ok() {
                got = true;
                break;
            }
        }
        assert!(got, "{driver:?}: no 408");
        assert_eq!(&reply, b"408\n", "{driver:?}");
        let started = Instant::now();
        let _ = server.shutdown(Instant::now() + Duration::from_secs(1));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{driver:?}: shutdown took {:?}",
            started.elapsed()
        );
    }
}

/// A session that writes several output buffers per flush, for well past the 3 s in
/// which ws-net saw 0.6.0's budget run out: its buffers are reused, the stream never
/// stalls, and nothing closes for want of budget, on both drivers.
#[test]
fn test_multi_buffer_flushes_reuse_their_buffers() {
    use std::io::Read;
    static BLOCK: [u8; 48 << 10] = [b'w'; 48 << 10];
    struct Writer(bool);
    impl Session for Writer {
        fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
            let n = input.bytes().len();
            input.consume(n);
            self.0 = true;
            self.on_writable(cx)
        }
        fn on_writable(&mut self, cx: &mut SessionContext<'_>) -> Step {
            if !self.0 {
                return Step::Read;
            }
            // Three MEDIUM buffers a flush, through the copying path.
            let mut at = 0;
            while at < BLOCK.len() {
                let n = cx.output().push_partial(&BLOCK[at..]);
                if n == 0 {
                    break;
                }
                at += n;
            }
            Step::Write
        }
    }
    for &driver in DRIVERS {
        let limits = Limits::builder()
            .buffer_budget(512 << 10)
            .build()
            .expect("limits");
        let server = ServerBuilder::new()
            .listener(ListenerSpec::tcp("127.0.0.1:0"))
            .driver(driver)
            // Two: the pool gives each connection its own worker.
            .workers(2)
            .limits(limits)
            .sessions(|_: &ConnectionInfo| Writer(false))
            .gate(AllowAll)
            .build()
            .expect("build");
        server.open_door().expect("open");
        let at = addr(&server);
        let streamer = std::thread::spawn(move || {
            let mut c = client(at);
            c.write_all(b"go").expect("write");
            let mut buf = vec![0u8; 256 << 10];
            let started = Instant::now();
            let mut total = 0u64;
            while started.elapsed() < Duration::from_secs(5) {
                match c.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => total += n as u64,
                }
            }
            total
        });
        // Well into the stream, another connection still gets buffers: the stream's
        // outputs reuse theirs instead of spending the budget (0.6.0 spent it in a few
        // flushes, and this round trip then waited for a buffer that never came).
        std::thread::sleep(Duration::from_secs(3));
        let mut other = client(at);
        other
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("timeout");
        other.write_all(b"x").expect("write");
        let mut first = [0u8; 1];
        let answered = other.read_exact(&mut first).is_ok();
        let total = streamer.join().expect("streamer");
        assert!(
            answered,
            "{driver:?}: no buffer for a second connection, {:?}",
            server.stats()
        );
        assert!(total > 16 << 20, "{driver:?}: {total} bytes streamed");
        assert_eq!(
            server
                .stats()
                .closed_for(CloseReason::Limit(net_io::LimitKind::BufferBudget)),
            0,
            "{driver:?}"
        );
    }
}

/// With the buffer budget spent (here by clients that never read), a session whose
/// push takes nothing is closed with `Limit(BufferBudget)` instead of being called
/// back at once for ever, which spun 0.6.0's worker and stalled every connection.
/// Linux only: elsewhere loopback takes each output into the kernel at once, so the
/// clients pin no buffers and the budget is never spent.
#[cfg(all(feature = "reactor", target_os = "linux"))]
#[test]
fn test_spent_budget_closes_instead_of_spinning() {
    use std::io::Read;
    static BLOCK: [u8; 64 << 10] = [b's'; 64 << 10];
    struct Fill;
    impl Session for Fill {
        fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
            let n = input.bytes().len();
            input.consume(n);
            self.on_writable(cx)
        }
        fn on_writable(&mut self, cx: &mut SessionContext<'_>) -> Step {
            let _ = cx.output().push_partial(&BLOCK);
            Step::Write
        }
    }
    let limits = Limits::builder()
        .buffer_budget(512 << 10)
        .write_timeout(Duration::from_secs(30))
        .min_rate(MinRate::off())
        .build()
        .expect("limits");
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp_with(
            "127.0.0.1:0",
            ListenOptions::new().send_buffer(4096),
        ))
        .driver(DriverKind::Reactor)
        .workers(1)
        .limits(limits)
        .sessions(|_: &ConnectionInfo| Fill)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let at = addr(&server);
    // Clients that never read: each pins its output's buffers.
    let mut held = Vec::new();
    for _ in 0..12 {
        let mut c = client(at);
        c.write_all(b"go").expect("write");
        held.push(c);
    }
    assert!(
        eventually(Duration::from_secs(10), || server
            .stats()
            .closed_for(CloseReason::Limit(net_io::LimitKind::BufferBudget))
            >= 1),
        "{:?}",
        server.stats()
    );
    // The worker is not spinning: a reader that drains gets data.
    let mut c = client(at);
    c.write_all(b"go").expect("write");
    let mut b = [0u8; 1024];
    let _ = c.read(&mut b);
    drop(held);
}

/// Short connections one after another spread over the reactor's workers: with
/// every load at 0, the hand-over took the first worker each time, and one core
/// served everything (found by tls-net's handshake benchmark).
#[cfg(feature = "reactor")]
#[test]
fn test_short_connections_spread_over_reactor_workers() {
    struct Mark(Arc<Mutex<std::collections::HashSet<String>>>);
    impl Session for Mark {
        fn on_open(&mut self, cx: &mut SessionContext<'_>) -> Step {
            if let Ok(mut seen) = self.0.lock() {
                seen.insert(format!("{:?}", cx.worker()));
            }
            Step::Read
        }
        fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
            let taken = cx.output().push_partial(input.bytes());
            input.consume(taken);
            Step::Close
        }
    }
    let seen = Arc::new(Mutex::new(std::collections::HashSet::new()));
    let marks = seen.clone();
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .driver(DriverKind::Reactor)
        .workers(4)
        .sessions(move |_: &ConnectionInfo| Mark(marks.clone()))
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    for i in 0..40u64 {
        let mut c = client(addr(&server));
        assert_eq!(round_trip(&mut c, b"x"), b"x");
        drop(c);
        assert!(eventually(WAIT, || server.stats().closed > i));
    }
    let used = seen.lock().expect("lock").len();
    assert_eq!(used, 4, "connections used {used} of 4 workers");
}

/// A session that answers and closes, with a client that closes at once: with a
/// FIN, a reset, or a reset from unread data, the server's close ends with the
/// client's, not at the linger's 2 s deadline. On the Windows reactor a reset held
/// every such close to the deadline (D-177; tls-net's handshake benchmark).
#[test]
fn test_close_after_reply_ends_with_a_reset() {
    use std::io::Read;
    struct Reply;
    impl Session for Reply {
        fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
            let n = input.bytes().len();
            input.consume(n);
            let _ = cx.output().push(&[b'r'; 70]);
            Step::Close
        }
    }
    for &driver in DRIVERS {
        let server = ServerBuilder::new()
            .listener(ListenerSpec::tcp("127.0.0.1:0"))
            .driver(driver)
            .workers(2)
            .sessions(|_: &ConnectionInfo| Reply)
            .gate(AllowAll)
            .build()
            .expect("build");
        server.open_door().expect("open");
        let at = addr(&server);
        let mut closed = 0u64;
        for how in ["fin", "reset", "unread"] {
            let mut worst = Duration::ZERO;
            for _ in 0..10 {
                match how {
                    "fin" => {
                        let mut c = client(at);
                        c.write_all(b"GET").expect("write");
                        let mut b = [0u8; 70];
                        c.read_exact(&mut b).expect("reply");
                    }
                    "reset" => {
                        let mut c = TcpConnection::connect(at).expect("connect");
                        c.send_all(b"GET").expect("send");
                        let mut b = [0u8; 70];
                        c.recv_exact(&mut b).expect("reply");
                        c.abort();
                    }
                    _ => {
                        let mut c = client(at);
                        c.write_all(b"GET").expect("write");
                        let mut b = [0u8; 10];
                        c.read_exact(&mut b).expect("part of the reply");
                    }
                }
                closed += 1;
                let t = Instant::now();
                assert!(
                    eventually(WAIT, || server.stats().closed >= closed),
                    "{driver:?} {how}: {:?}",
                    server.stats()
                );
                worst = worst.max(t.elapsed());
            }
            assert!(
                worst < Duration::from_millis(500),
                "{driver:?} {how}: a close waited {worst:?}"
            );
        }
    }
}
