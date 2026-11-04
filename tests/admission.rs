//! Lanes, lockdown, adaptive deadlines, and placement.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant};

use common::{DRIVERS, addr, client, eventually, round_trip};
use net_io::{
    AdmitStage, Admitted, AllowAll, ConnectionInfo, ControlState, Denial, DriverKind, Gate,
    GateTag, Input, Lane, Limits, ListenerSpec, NetError, Placement, PrefixPolicy, Pressure,
    Refusal, RefusalCause, ServerBuilder, Session, SessionContext, SimpleControl, Step, WriteCheck,
};

const WAIT: Duration = Duration::from_secs(5);

struct Echo;

impl Session for Echo {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let taken = cx.output().push_partial(input.bytes());
        input.consume(taken);
        Step::Write
    }
}

/// Puts every connection in one lane.
struct InLane(Lane);

impl Gate for InLane {
    type Ticket = ();
    fn admit(&self, _: &ConnectionInfo, _: AdmitStage) -> Result<Admitted<()>, Refusal> {
        Ok(Admitted {
            lane: self.0,
            ticket: (),
            tag: GateTag(0),
        })
    }
    fn readmit(&self, _: &mut (), _: &ConnectionInfo) -> Result<(), Refusal> {
        Ok(())
    }
    fn check(&self, _: &mut (), _: &WriteCheck) -> Result<(), Denial> {
        Ok(())
    }
}

#[test]
fn test_lane_reserve_keeps_slots_for_the_more_important() {
    for &driver in DRIVERS {
        let limits = Limits::builder()
            .max_connections(4)
            .lane_reserve(Lane(0), 3)
            .build()
            .expect("limits");
        let server = ServerBuilder::new()
            .listener(ListenerSpec::tcp("127.0.0.1:0"))
            .driver(driver)
            .workers(8)
            .limits(limits)
            .sessions(|_: &ConnectionInfo| Echo)
            .gate(InLane(Lane(1)))
            .build()
            .expect("build");
        server.open_door().expect("open");
        let mut first = client(addr(&server));
        assert_eq!(round_trip(&mut first, b"in"), b"in");
        // Refused: the reset may come before `connect` returns, and Linux reports it there.
        if let Ok(mut second) = TcpStream::connect(addr(&server)) {
            second
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
            let _ = second.write_all(b"x");
            let mut b = [0u8; 1];
            assert!(!matches!(second.read(&mut b), Ok(n) if n > 0), "{driver:?}");
        }
        assert!(
            eventually(WAIT, || server
                .stats()
                .refused_for(RefusalCause::LaneReserve)
                == 1),
            "{driver:?}: {:?}",
            server.stats()
        );
    }
}

#[test]
fn test_the_reserved_lane_itself_may_use_every_slot() {
    let limits = Limits::builder()
        .max_connections(4)
        .lane_reserve(Lane(0), 3)
        .build()
        .expect("limits");
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .limits(limits)
        .sessions(|_: &ConnectionInfo| Echo)
        .gate(InLane(Lane(0)))
        .build()
        .expect("build");
    server.open_door().expect("open");
    let mut all: Vec<TcpStream> = (0..4).map(|_| client(addr(&server))).collect();
    for c in &mut all {
        assert_eq!(round_trip(c, b"ok"), b"ok");
    }
}

#[test]
fn test_lockdown_leaves_the_allowed_listener_open() {
    let control = Arc::new(SimpleControl::new());
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .listener(ListenerSpec::tcp("127.0.0.1:0").lockdown_allowed(true))
        .sessions(|_: &ConnectionInfo| Echo)
        .control(control.clone())
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let (public, admin) = (
        server.listeners()[0].local.socket_addr().expect("ip"),
        server.listeners()[1].local.socket_addr().expect("ip"),
    );
    control.set(ControlState::Lockdown, None);
    // The control line is read before an accept batch: let one connection see it.
    assert!(eventually(WAIT, || {
        // A refusal can reach a BSD client inside `connect`.
        let Ok(mut c) = TcpStream::connect(public) else {
            return true;
        };
        let _ = c.write_all(b"x");
        let _ = c.set_read_timeout(Some(WAIT));
        let mut b = [0u8; 1];
        !matches!(c.read(&mut b), Ok(n) if n > 0)
    }));
    let mut c = client(admin);
    assert_eq!(round_trip(&mut c, b"admin"), b"admin");
}

#[test]
fn test_pressure_shrinks_idle_deadlines_and_lets_go() {
    for &driver in DRIVERS {
        let limits = Limits::builder()
            .max_connections(10)
            .max_per_source(10, PrefixPolicy::DEFAULT)
            .idle_timeout(Duration::from_secs(30))
            .pressure(Pressure {
                high: 0.5,
                low: 0.2,
                factor: 0.01,
            })
            .build()
            .expect("limits");
        let server = ServerBuilder::new()
            .listener(ListenerSpec::tcp("127.0.0.1:0"))
            .driver(driver)
            .workers(12)
            .limits(limits)
            .sessions(|_: &ConnectionInfo| Echo)
            .gate(AllowAll)
            .build()
            .expect("build");
        server.open_door().expect("open");
        // Four below the threshold go idle first, with 30 s ahead of them; the
        // crossing must reach them where they wait.
        let mut conns: Vec<TcpStream> = (0..4).map(|_| client(addr(&server))).collect();
        for c in &mut conns {
            assert_eq!(round_trip(c, b"hi"), b"hi");
        }
        std::thread::sleep(Duration::from_millis(200));
        for _ in 0..2 {
            let mut c = client(addr(&server));
            assert_eq!(round_trip(&mut c, b"hi"), b"hi");
            conns.push(c);
        }
        let started = Instant::now();
        // 30 s scaled to the floor of 1 s, on a tick or two; well under the 30.
        // Pressure lets go at 2 open (`low`), so 4 time out.
        assert!(
            eventually(Duration::from_secs(10), || server.stats().timeouts >= 4),
            "{driver:?}: {:?}",
            server.stats()
        );
        assert!(started.elapsed() < Duration::from_secs(10), "{driver:?}");
    }
}

#[test]
fn test_placement() {
    let result = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .workers(2)
        .placement(Placement::PinPerCore)
        .sessions(|_: &ConnectionInfo| Echo)
        .gate(AllowAll)
        .build();
    if cfg!(target_os = "macos") {
        assert!(matches!(result, Err(NetError::Unsupported { .. })));
    } else {
        let server = result.expect("build");
        server.open_door().expect("open");
        let mut c = client(addr(&server));
        assert_eq!(round_trip(&mut c, b"pinned"), b"pinned");
    }
    if !cfg!(target_os = "macos") {
        let empty = ServerBuilder::new()
            .listener(ListenerSpec::tcp("127.0.0.1:0"))
            .placement(Placement::Explicit(Vec::new()))
            .sessions(|_: &ConnectionInfo| Echo)
            .gate(AllowAll)
            .build();
        assert!(matches!(empty, Err(NetError::InvalidConfig { .. })));
    }
}

/// One socket per worker: the group answers on one port, and each socket feeds its
/// own worker.
#[cfg(all(target_os = "linux", feature = "reactor"))]
#[test]
fn test_per_worker_listeners() {
    let spec = ListenerSpec::tcp_with("127.0.0.1:0", net_io::ListenOptions::new().per_worker(true));
    let limits = Limits::builder()
        .max_per_source(64, PrefixPolicy::DEFAULT)
        .build()
        .expect("limits");
    let server = ServerBuilder::new()
        .listener(spec)
        .driver(DriverKind::Reactor)
        .workers(4)
        .limits(limits)
        .sessions(|_: &ConnectionInfo| Echo)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let mut conns: Vec<TcpStream> = (0..32).map(|_| client(addr(&server))).collect();
    for c in &mut conns {
        assert_eq!(round_trip(c, b"ok"), b"ok");
    }
    assert!(server.release_listeners().is_err(), "a group stays put");
    drop(conns);
    drop(server);
}

/// T-19: connections opening and closing as fast as a few clients can drive them
/// leave an established connection served. An accept takes a bounded batch per wake.
#[test]
fn test_accept_storm_leaves_established_connections_served() {
    const STORM: Duration = Duration::from_secs(1);
    // Each closed client port waits out TIME_WAIT (two minutes on Windows), and the
    // ephemeral range there is 16,384: a storm that used them all would make the
    // next connect in this run fail.
    const PER_DRIVER: i64 = 3_000;
    for &driver in DRIVERS {
        let limits = Limits::builder()
            .max_connections(4_096)
            .max_per_source(4_096, PrefixPolicy::DEFAULT)
            .build()
            .expect("limits");
        let server = ServerBuilder::new()
            .listener(ListenerSpec::tcp("127.0.0.1:0"))
            .driver(driver)
            .limits(limits)
            .sessions(|_: &ConnectionInfo| Echo)
            .gate(AllowAll)
            .build()
            .expect("build");
        server.open_door().expect("open");
        let target = addr(&server);
        let mut c = client(target);
        assert_eq!(round_trip(&mut c, b"ready"), b"ready");
        let until = Instant::now() + STORM;
        let left = Arc::new(AtomicI64::new(PER_DRIVER));
        let storm: Vec<_> = (0..4)
            .map(|_| {
                let left = left.clone();
                std::thread::spawn(move || {
                    let mut opened = 0u64;
                    while Instant::now() < until && left.fetch_sub(1, Ordering::Relaxed) > 0 {
                        if TcpStream::connect(target).is_ok() {
                            opened += 1;
                        }
                    }
                    opened
                })
            })
            .collect();
        let mut slowest = Duration::ZERO;
        while Instant::now() < until && !storm.iter().all(|t| t.is_finished()) {
            let started = Instant::now();
            assert_eq!(round_trip(&mut c, b"still here"), b"still here");
            slowest = slowest.max(started.elapsed());
        }
        let opened: u64 = storm.into_iter().map(|t| t.join().expect("storm")).sum();
        assert!(opened > 100, "{driver:?}: only {opened} connections");
        assert!(
            slowest < Duration::from_millis(500),
            "{driver:?}: a round trip took {slowest:?} during {opened} connects"
        );
    }
}

#[test]
fn test_per_worker_is_refused_where_it_cannot_work() {
    let spec = ListenerSpec::tcp_with("127.0.0.1:0", net_io::ListenOptions::new().per_worker(true));
    let built = ServerBuilder::new()
        .listener(spec)
        .driver(DriverKind::Blocking)
        .sessions(|_: &ConnectionInfo| Echo)
        .gate(AllowAll)
        .build();
    assert!(built.is_err());
}
