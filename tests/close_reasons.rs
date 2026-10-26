//! Every close reason the blocking driver can produce in 0.3, each from a real
//! socket, each with exactly one `Closed` event carrying that reason.
//! (PROXY, TLS, and handshake reasons arrive with those features in 0.4.)

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{addr, client, eventually, round_trip};
use net_io::{
    AdmitStage, Admitted, AllowAll, CloseReason, ConnectionInfo, ControlState, Denial, Direction,
    Event, EventSink, Gate, GateTag, Input, KillReason, Lane, LimitKind, Limits, ListenOptions,
    ListenerSpec, MinRate, Phase, RefusalCause, ServerBuilder, Session, SessionContext,
    SessionFactory, SimpleControl, SizeClass, Step, WriteCheck,
};

const WAIT: Duration = Duration::from_secs(5);

#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<CloseReason>>>);

impl EventSink for Recorder {
    fn event(&self, event: &Event) {
        if let Event::Closed { reason, .. } = event {
            if let Ok(mut v) = self.0.lock() {
                v.push(*reason);
            }
        }
    }
}

impl Recorder {
    /// Waits for the first close, waits a little more for any second one, then
    /// asserts there was exactly one, with the same variant as `want`.
    fn expect_one(&self, want: CloseReason) {
        let seen = || self.0.lock().map(|v| v.len()).unwrap_or(0);
        assert!(
            eventually(WAIT, || seen() >= 1),
            "no Closed event (want {want:?})"
        );
        std::thread::sleep(Duration::from_millis(100));
        let v = self.0.lock().expect("lock").clone();
        assert_eq!(v.len(), 1, "exactly one Closed event: {v:?}");
        assert_eq!(v[0].as_str(), want.as_str(), "{:?}", v[0]);
    }
}

/// Echoes complete lines; a partial line keeps the exchange open.
struct Lines;

impl Session for Lines {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let Some(end) = input.bytes().iter().position(|&b| b == b'\n') else {
            cx.set_phase(Phase::Receiving);
            return Step::Read;
        };
        let taken = cx.output().push_partial(&input.bytes()[..=end]);
        input.consume(taken);
        cx.set_phase(Phase::Idle);
        Step::Write
    }
}

/// A session from a closure over `on_data`.
struct OnData<F>(F);

impl<F> Session for OnData<F>
where
    F: FnMut(&mut SessionContext<'_>, &mut Input) -> Step + Send + 'static,
{
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        (self.0)(cx, input)
    }
}

fn server<F: SessionFactory>(rec: &Recorder, limits: Limits, factory: F) -> net_io::Server {
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .workers(4)
        .limits(limits)
        .sessions(factory)
        .gate(AllowAll)
        .events(rec.clone())
        .build()
        .expect("build");
    server.open_door().expect("open");
    server
}

fn lines(rec: &Recorder, limits: Limits) -> net_io::Server {
    server(rec, limits, |_: &ConnectionInfo| Lines)
}

fn defaults() -> Limits {
    Limits::builder().build().expect("limits")
}

#[test]
fn reason_peer_closed() {
    let rec = Recorder::default();
    let s = lines(&rec, defaults());
    let mut c = client(addr(&s));
    assert_eq!(round_trip(&mut c, b"x\n"), b"x\n");
    drop(c);
    rec.expect_one(CloseReason::PeerClosed);
}

#[test]
fn reason_peer_reset() {
    let rec = Recorder::default();
    let s = lines(&rec, defaults());
    let mut conn = net_io::connect(addr(&s)).expect("connect");
    conn.send_all(b"partial").expect("send");
    std::thread::sleep(Duration::from_millis(50));
    conn.abort();
    rec.expect_one(CloseReason::PeerReset);
}

#[test]
fn reason_idle() {
    let rec = Recorder::default();
    let s = lines(
        &rec,
        Limits::builder()
            .idle_timeout(Duration::from_millis(100))
            .build()
            .expect("limits"),
    );
    let _c = client(addr(&s));
    rec.expect_one(CloseReason::Idle);
}

#[test]
fn reason_read_timeout() {
    let rec = Recorder::default();
    let s = lines(
        &rec,
        Limits::builder()
            .read_timeout(Duration::from_millis(100))
            .build()
            .expect("limits"),
    );
    let mut c = client(addr(&s));
    c.write_all(b"no newline").expect("write");
    rec.expect_one(CloseReason::ReadTimeout);
}

#[test]
fn reason_write_timeout() {
    static BLOCK: [u8; 1 << 20] = [b'w'; 1 << 20];
    /// Megabytes handed to the kernel so far: if this keeps growing while the peer
    /// never reads, the OS is absorbing the flood instead of stalling the sender.
    static FLUSHED_MB: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    struct Flood;
    impl Session for Flood {
        fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
            let n = input.bytes().len();
            input.consume(n);
            while cx.output().push_static(&BLOCK).is_ok() {}
            Step::Write
        }
        fn on_writable(&mut self, cx: &mut SessionContext<'_>) -> Step {
            FLUSHED_MB.fetch_add(64, std::sync::atomic::Ordering::Relaxed);
            while cx.output().push_static(&BLOCK).is_ok() {}
            Step::Write
        }
    }
    let rec = Recorder::default();
    let limits = Limits::builder()
        .write_timeout(Duration::from_millis(200))
        .min_rate(MinRate::off())
        .build()
        .expect("limits");
    let s = ServerBuilder::new()
        .listener(ListenerSpec::tcp_with(
            "127.0.0.1:0",
            ListenOptions::new().send_buffer(256 * 1024),
        ))
        .workers(2)
        .limits(limits)
        .sessions(|_: &ConnectionInfo| Flood)
        .gate(AllowAll)
        .events(rec.clone())
        .build()
        .expect("build");
    s.open_door().expect("open");
    let mut c = client(addr(&s));
    c.write_all(b"go").expect("write");
    let rec2 = rec.clone();
    let start = Instant::now();
    let closed = eventually(Duration::from_secs(10), || {
        rec2.0.lock().map(|v| !v.is_empty()).unwrap_or(false)
    });
    assert!(
        closed,
        "no close after {:?}; about {} MB flushed to a peer that never reads",
        start.elapsed(),
        FLUSHED_MB.load(std::sync::atomic::Ordering::Relaxed)
    );
    rec.expect_one(CloseReason::WriteTimeout);
}

#[test]
fn reason_exchange_deadline() {
    let rec = Recorder::default();
    let s = server(&rec, defaults(), |_: &ConnectionInfo| {
        OnData(|cx: &mut SessionContext<'_>, input: &mut Input| {
            let n = input.bytes().len();
            input.consume(n);
            cx.set_phase(Phase::Receiving);
            let at = cx.now() + Duration::from_millis(100);
            cx.set_exchange_deadline(Some(at));
            Step::Read
        })
    });
    let mut c = client(addr(&s));
    c.write_all(b"begin").expect("write");
    rec.expect_one(CloseReason::ExchangeDeadline);
}

#[test]
fn reason_park_deadline() {
    let rec = Recorder::default();
    let s = server(&rec, defaults(), |_: &ConnectionInfo| {
        OnData(|cx: &mut SessionContext<'_>, input: &mut Input| {
            let n = input.bytes().len();
            input.consume(n);
            Step::Park {
                until: Some(cx.now() + Duration::from_millis(100)),
            }
        })
    });
    let mut c = client(addr(&s));
    c.write_all(b"wait").expect("write");
    rec.expect_one(CloseReason::ParkDeadline);
}

#[test]
fn reason_slow_peer() {
    let rec = Recorder::default();
    let rate = MinRate {
        bytes_per_sec: 1000,
        window: Duration::from_millis(500),
        grace: Duration::from_millis(200),
        check: Duration::from_millis(100),
    };
    let s = lines(
        &rec,
        Limits::builder().min_rate(rate).build().expect("limits"),
    );
    let mut c = client(addr(&s));
    let end = Instant::now() + WAIT;
    while Instant::now() < end && rec.0.lock().map(|v| v.is_empty()).unwrap_or(false) {
        if c.write_all(b"x").is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    rec.expect_one(CloseReason::SlowPeer {
        direction: Direction::In,
    });
}

#[test]
fn reason_killed() {
    let rec = Recorder::default();
    let (tx, rx) = std::sync::mpsc::channel();
    let tx = Mutex::new(tx);
    let s = server(&rec, defaults(), move |info: &ConnectionInfo| {
        let _ = tx.lock().map(|t| t.send(info.id));
        Lines
    });
    let _c = client(addr(&s));
    let id = rx.recv_timeout(WAIT).expect("id");
    assert!(s.handle().kill(id, KillReason(5)));
    rec.expect_one(CloseReason::Killed(KillReason(5)));
}

#[test]
fn reason_egress_denied() {
    struct DenyAll;
    impl Gate for DenyAll {
        type Ticket = ();
        fn admit(
            &self,
            _: &ConnectionInfo,
            _: AdmitStage,
        ) -> Result<Admitted<()>, net_io::Refusal> {
            Ok(Admitted {
                lane: Lane(0),
                ticket: (),
                tag: GateTag(0),
            })
        }
        fn readmit(&self, _: &mut (), _: &ConnectionInfo) -> Result<(), net_io::Refusal> {
            Ok(())
        }
        fn check(&self, _: &mut (), _: &WriteCheck) -> Result<(), Denial> {
            Err(Denial { code: 4 })
        }
    }
    let rec = Recorder::default();
    let s = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .workers(2)
        .sessions(|_: &ConnectionInfo| Lines)
        .gate(DenyAll)
        .events(rec.clone())
        .build()
        .expect("build");
    s.open_door().expect("open");
    let mut c = client(addr(&s));
    c.write_all(b"x\n").expect("write");
    rec.expect_one(CloseReason::EgressDenied(4));
}

#[test]
fn reason_drained() {
    let rec = Recorder::default();
    let s = lines(&rec, defaults());
    let mut c = client(addr(&s));
    assert_eq!(round_trip(&mut c, b"x\n"), b"x\n");
    let report = s.drain(Instant::now() + Duration::from_secs(2));
    assert_eq!(report.graceful, 1);
    rec.expect_one(CloseReason::Drained);
}

/// `Lines` that reports its first bytes, so a test knows the exchange started.
struct Started(Option<std::sync::mpsc::Sender<()>>);

impl Session for Started {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        if let Some(tx) = self.0.take() {
            let _ = tx.send(());
        }
        Lines.on_data(cx, input)
    }
}

fn started() -> (
    impl Fn(&ConnectionInfo) -> Started + Send + Sync + 'static,
    std::sync::mpsc::Receiver<()>,
) {
    let (tx, rx) = std::sync::mpsc::channel();
    let tx = Mutex::new(tx);
    (
        move |_: &ConnectionInfo| Started(tx.lock().ok().map(|t| t.clone())),
        rx,
    )
}

#[test]
fn reason_drain_deadline() {
    let rec = Recorder::default();
    let (factory, begun) = started();
    let s = server(&rec, defaults(), factory);
    let mut c = client(addr(&s));
    c.write_all(b"mid-line").expect("write");
    begun.recv_timeout(WAIT).expect("exchange started");
    let report = s.drain(Instant::now() + Duration::from_millis(100));
    assert_eq!(report.killed, 1);
    rec.expect_one(CloseReason::DrainDeadline);
}

#[test]
fn reason_shed() {
    let rec = Recorder::default();
    let line = Arc::new(SimpleControl::new());
    let s = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .workers(2)
        .sessions(|_: &ConnectionInfo| Lines)
        .gate(AllowAll)
        .events(rec.clone())
        .control(line.clone())
        .build()
        .expect("build");
    s.open_door().expect("open");
    let mut c = client(addr(&s));
    assert_eq!(round_trip(&mut c, b"x\n"), b"x\n");
    line.set(ControlState::Shed { from_lane: Lane(0) }, None);
    s.handle().wake_all();
    rec.expect_one(CloseReason::Shed);
}

#[test]
fn reason_shutdown() {
    let rec = Recorder::default();
    let (factory, begun) = started();
    let line = Arc::new(SimpleControl::new());
    let s = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .workers(2)
        .sessions(factory)
        .gate(AllowAll)
        .events(rec.clone())
        .control(line.clone())
        .build()
        .expect("build");
    s.open_door().expect("open");
    let mut c = client(addr(&s));
    c.write_all(b"mid-line").expect("write");
    begun.recv_timeout(WAIT).expect("exchange started");
    line.set(ControlState::Stopping, None);
    s.handle().wake_all();
    rec.expect_one(CloseReason::Shutdown);
}

#[test]
fn reason_session_closed() {
    let rec = Recorder::default();
    let s = server(&rec, defaults(), |_: &ConnectionInfo| {
        OnData(|cx: &mut SessionContext<'_>, input: &mut Input| {
            let n = input.bytes().len();
            input.consume(n);
            let _ = cx.output().push(b"bye\n");
            Step::Close
        })
    });
    let mut c = client(addr(&s));
    c.write_all(b"x").expect("write");
    let mut reply = Vec::new();
    std::io::Read::read_to_end(&mut c, &mut reply).expect("read");
    assert_eq!(reply, b"bye\n");
    rec.expect_one(CloseReason::SessionClosed);
}

#[test]
fn reason_session_error() {
    let rec = Recorder::default();
    let s = server(&rec, defaults(), |_: &ConnectionInfo| {
        OnData(|_cx: &mut SessionContext<'_>, _input: &mut Input| Step::Abort)
    });
    let mut c = client(addr(&s));
    c.write_all(b"bad").expect("write");
    rec.expect_one(CloseReason::SessionError);
}

#[test]
fn reason_session_panicked() {
    let rec = Recorder::default();
    let s = server(&rec, defaults(), |_: &ConnectionInfo| {
        OnData(|_cx: &mut SessionContext<'_>, _input: &mut Input| -> Step { panic!("session bug") })
    });
    let mut c = client(addr(&s));
    c.write_all(b"boom").expect("write");
    rec.expect_one(CloseReason::SessionPanicked);
}

#[test]
fn reason_limit_read_buffer() {
    let rec = Recorder::default();
    let s = lines(
        &rec,
        Limits::builder()
            .read_class(SizeClass::SMALL, SizeClass::SMALL)
            .build()
            .expect("limits"),
    );
    let mut c = client(addr(&s));
    let _ = c.write_all(&[b'x'; 8192]);
    rec.expect_one(CloseReason::Limit(LimitKind::ReadBuffer));
}

#[test]
fn reason_refused_by_the_session_factory() {
    struct No;
    impl SessionFactory for No {
        type Session = Lines;
        fn open(&self, _info: &ConnectionInfo) -> Result<Lines, RefusalCause> {
            Err(RefusalCause::Session)
        }
    }
    let rec = Recorder::default();
    let s = server(&rec, defaults(), No);
    let _c = client(addr(&s));
    rec.expect_one(CloseReason::Refused(RefusalCause::Session));
}
