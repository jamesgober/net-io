//! Dialed connections under a gate: `Server::adopt` (admitted like an accepted
//! connection) and `TcpConnection::set_gate` (a standalone dialed connection).

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::eventually;
use net_io::{
    AdmitStage, Admitted, AdoptSpec, AllowAll, CloseReason, ConfigReason, ConnectionInfo, Denial,
    Gate, GateTag, Lane, ListenerSpec, NetError, Origin, Refusal, RefusalCause, ServerBuilder,
    TcpConnection, WriteCheck,
};

const WAIT: Duration = Duration::from_secs(5);

/// Records the stages it admitted and the reasons it was told about; refuses
/// when `refuse` is set and denies writes when `deny` is set.
#[derive(Default)]
struct State {
    stages: Mutex<Vec<AdmitStage>>,
    closed: Mutex<Vec<CloseReason>>,
    checks: AtomicU32,
    refuse: AtomicBool,
    deny: AtomicBool,
}

#[derive(Clone, Default)]
struct Watch(Arc<State>);

impl std::ops::Deref for Watch {
    type Target = State;
    fn deref(&self) -> &State {
        &self.0
    }
}

impl Gate for Watch {
    type Ticket = ();

    fn admit(&self, _info: &ConnectionInfo, stage: AdmitStage) -> Result<Admitted<()>, Refusal> {
        if let Ok(mut s) = self.stages.lock() {
            s.push(stage);
        }
        if self.refuse.load(Ordering::Acquire) {
            return Err(Refusal::Reset { code: 7 });
        }
        Ok(Admitted {
            lane: Lane(2),
            ticket: (),
            tag: GateTag(99),
        })
    }

    fn readmit(&self, _ticket: &mut (), _info: &ConnectionInfo) -> Result<(), Refusal> {
        Ok(())
    }

    fn check(&self, _ticket: &mut (), _write: &WriteCheck) -> Result<(), Denial> {
        self.checks.fetch_add(1, Ordering::AcqRel);
        if self.deny.load(Ordering::Acquire) {
            Err(Denial { code: 9 })
        } else {
            Ok(())
        }
    }

    fn closed(&self, _ticket: (), _info: &ConnectionInfo, reason: CloseReason) {
        if let Ok(mut c) = self.closed.lock() {
            c.push(reason);
        }
    }
}

/// Says how it was registered, then echoes one read.
fn origin(conn: &mut TcpConnection) -> Result<(), NetError> {
    let info = conn.info();
    let line = format!("{:?} {:?}\n", info.origin, info.lane);
    conn.send_all(line.as_bytes())?;
    let mut buf = [0u8; 16];
    let n = conn.recv(&mut buf)?;
    conn.send_all(&buf[..n])
}

#[test]
fn adopted_connection_runs_like_an_accepted_one() {
    let gate = Watch::default();
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0").name("main"))
        .workers(2)
        .handler(origin)
        .gate(gate.clone())
        .build()
        .expect("build");
    // The other end of a back-channel this process dials.
    let upstream = TcpListener::bind("127.0.0.1:0").expect("upstream");
    let dialed = net_io::connect(upstream.local_addr().expect("addr")).expect("dial");
    let (mut far, _) = upstream.accept().expect("accept");
    far.set_read_timeout(Some(WAIT)).expect("timeout");
    let id = server
        .adopt(dialed, AdoptSpec::new("main").lane(Lane(1)))
        .expect("adopt");
    assert_ne!(id.get(), 0);
    let mut line = [0u8; 64];
    let n = far.read(&mut line).expect("greeting");
    // The gate's lane wins over the hint.
    assert_eq!(
        &line[..n],
        format!("{:?} {:?}\n", Origin::Adopted, Lane(2)).as_bytes()
    );
    far.write_all(b"ping").expect("write");
    let mut echo = [0u8; 4];
    far.read_exact(&mut echo).expect("echo");
    assert_eq!(&echo, b"ping");
    drop(far);
    assert!(eventually(WAIT, || server.stats().closed == 1));
    assert_eq!(*gate.stages.lock().expect("lock"), vec![AdmitStage::Adopt]);
    assert_eq!(gate.closed.lock().expect("lock").len(), 1);

    // Unknown listener; a refusing gate resets the connection.
    let dialed = net_io::connect(upstream.local_addr().expect("addr")).expect("dial");
    let (_far, _) = upstream.accept().expect("accept");
    assert!(matches!(
        server.adopt(dialed, AdoptSpec::new("nope")),
        Err(NetError::InvalidConfig {
            field: "listener",
            reason: ConfigReason::Missing
        })
    ));
    gate.refuse.store(true, Ordering::Release);
    let dialed = net_io::connect(upstream.local_addr().expect("addr")).expect("dial");
    let (mut far, _) = upstream.accept().expect("accept");
    far.set_read_timeout(Some(WAIT)).expect("timeout");
    assert!(matches!(
        server.adopt(dialed, AdoptSpec::new("main")),
        Err(NetError::Refused {
            cause: RefusalCause::Gate(7)
        })
    ));
    let mut b = [0u8; 1];
    assert!(
        matches!(far.read(&mut b), Ok(0) | Err(_)),
        "closed without bytes"
    );
}

#[test]
fn set_gate_checks_writes_and_closes_once() {
    let upstream = TcpListener::bind("127.0.0.1:0").expect("upstream");
    let addr = upstream.local_addr().expect("addr");
    let gate = Watch::default();

    let mut conn = net_io::connect(addr).expect("dial");
    let (mut far, _) = upstream.accept().expect("accept");
    conn.set_gate(Arc::new(gate.clone())).expect("admitted");
    assert_eq!(conn.info().lane, Lane(2));
    assert_eq!(conn.info().gate, GateTag(99));
    assert!(matches!(
        conn.set_gate(Arc::new(gate.clone())),
        Err(NetError::InvalidConfig { field: "gate", .. })
    ));
    conn.send_all(b"one").expect("checked write");
    assert!(gate.checks.load(Ordering::Acquire) >= 1);
    // Read it now: the denial below closes with RST, which drops unread bytes.
    far.set_read_timeout(Some(WAIT)).expect("timeout");
    let mut one = [0u8; 3];
    far.read_exact(&mut one).expect("one");
    assert_eq!(&one, b"one");
    gate.deny.store(true, Ordering::Release);
    assert!(matches!(
        conn.send_all(b"two"),
        Err(NetError::EgressDenied { code: 9 })
    ));
    drop(conn);
    assert_eq!(
        *gate.closed.lock().expect("lock"),
        vec![CloseReason::EgressDenied(9)]
    );
    let mut rest = Vec::new();
    let _ = far.read_to_end(&mut rest);
    assert!(rest.is_empty(), "nothing after the denial");

    // A refusal at admission aborts the connection.
    gate.refuse.store(true, Ordering::Release);
    let mut conn = net_io::connect(addr).expect("dial");
    let (_far, _) = upstream.accept().expect("accept");
    assert!(matches!(
        conn.set_gate(Arc::new(gate.clone())),
        Err(NetError::Refused {
            cause: RefusalCause::Gate(7)
        })
    ));
    assert!(matches!(conn.send(b"x"), Err(NetError::Closed)));
    assert_eq!(
        gate.stages.lock().expect("lock").as_slice(),
        &[AdmitStage::Dialed, AdmitStage::Dialed]
    );
    // The refused connection was never admitted, so `closed` was not called again.
    assert_eq!(gate.closed.lock().expect("lock").len(), 1);
}

#[test]
fn monotonic_micros_moves_forward() {
    let a = net_io::monotonic_micros();
    std::thread::sleep(Duration::from_millis(20));
    let b = net_io::monotonic_micros();
    assert!(b - a >= 15_000, "{a} {b}");
}

#[test]
fn allow_all_is_a_gate_for_set_gate() {
    let upstream = TcpListener::bind("127.0.0.1:0").expect("upstream");
    let mut conn = net_io::connect(upstream.local_addr().expect("addr")).expect("dial");
    conn.set_gate(Arc::new(AllowAll)).expect("allow");
}

/// Edge case 111: `adopt` while the server drains is `ShuttingDown`.
#[test]
fn adopt_while_draining_is_shutting_down() {
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0").name("main"))
        .workers(1)
        .handler(origin)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let _ = server.drain(std::time::Instant::now());
    let upstream = TcpListener::bind("127.0.0.1:0").expect("upstream");
    let dialed = net_io::connect(upstream.local_addr().expect("addr")).expect("dial");
    assert!(matches!(
        server.adopt(dialed, AdoptSpec::new("main")),
        Err(NetError::ShuttingDown)
    ));
}
