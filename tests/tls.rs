//! The TLS seam on server listeners, driven by a toy engine.
//!
//! The engine is not cryptography: a fixed hello/welcome exchange, then records of
//! `[length: u16][payload XOR 0x5A]`, with an empty record as `close_notify`. It
//! exercises every path of the seam (handshake records, plaintext decrypted in
//! place, records split across reads, `close_notify`, a refused hello) without a
//! TLS dependency.

#![cfg(feature = "tls")]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{addr, client, eventually};
use net_io::{
    AdmitStage, Admitted, AllowAll, CloseReason, ConfigReason, ConnectionInfo, Denial, Event,
    EventSink, Gate, GateTag, Input, Lane, Limits, ListenerSpec, NetError, Refusal, ServerBuilder,
    Session, SessionContext, Step, TcpConnection, TlsAcceptor, TlsCloseKind, TlsError, TlsEvent,
    TlsFailure, TlsInfo, TlsProgress, TlsSession, WriteCheck,
};

const WAIT: Duration = Duration::from_secs(5);
const MASK: u8 = 0x5A;

struct Toy;

impl TlsAcceptor for Toy {
    type Session = ToySession;
    fn session(&self, _info: &ConnectionInfo) -> Result<ToySession, TlsError> {
        Ok(ToySession::default())
    }
}

#[derive(Default)]
struct ToySession {
    /// 0: waiting for the hello; 1: welcome sent; 2: handshake complete.
    state: u8,
    closed: bool,
}

impl TlsSession for ToySession {
    fn step<'i>(
        &mut self,
        input: &'i mut [u8],
        output: &mut [u8],
    ) -> Result<TlsProgress<'i>, TlsError> {
        match self.state {
            0 => {
                if input.len() < 5 {
                    return Ok(TlsProgress {
                        consumed: 0,
                        written: 0,
                        event: TlsEvent::NeedInput,
                    });
                }
                if &input[..5] == b"BLOCK" {
                    return Err(TlsError::new(TlsFailure::HelloRefused, 1, None));
                }
                if &input[..5] != b"HELLO" {
                    return Err(TlsError::new(TlsFailure::Handshake, 2, None));
                }
                output[..7].copy_from_slice(b"WELCOME");
                self.state = 1;
                Ok(TlsProgress {
                    consumed: 5,
                    written: 7,
                    event: TlsEvent::Transmit,
                })
            }
            1 => {
                self.state = 2;
                Ok(TlsProgress {
                    consumed: 0,
                    written: 0,
                    event: TlsEvent::HandshakeComplete,
                })
            }
            _ => {
                if input.len() < 2 {
                    return Ok(TlsProgress {
                        consumed: 0,
                        written: 0,
                        event: TlsEvent::NeedInput,
                    });
                }
                let len = usize::from(u16::from_be_bytes([input[0], input[1]]));
                if len == 0 {
                    self.closed = true;
                    return Ok(TlsProgress {
                        consumed: 2,
                        written: 0,
                        event: TlsEvent::PeerClosed,
                    });
                }
                if input.len() < 2 + len {
                    return Ok(TlsProgress {
                        consumed: 0,
                        written: 0,
                        event: TlsEvent::NeedInput,
                    });
                }
                let body = &mut input[2..2 + len];
                for b in body.iter_mut() {
                    *b ^= MASK;
                }
                Ok(TlsProgress {
                    consumed: 2 + len,
                    written: 0,
                    event: TlsEvent::Data(body),
                })
            }
        }
    }

    fn encrypt(&mut self, plaintext: &[u8], output: &mut [u8]) -> Result<usize, TlsError> {
        let n = plaintext.len();
        if output.len() < n + 2 {
            return Err(TlsError::new(TlsFailure::OutputFull, 3, None));
        }
        output[..2].copy_from_slice(&u16::try_from(n).unwrap_or(u16::MAX).to_be_bytes());
        for (o, p) in output[2..2 + n].iter_mut().zip(plaintext) {
            *o = p ^ MASK;
        }
        Ok(n + 2)
    }

    fn close(&mut self, output: &mut [u8]) -> Result<usize, TlsError> {
        output[..2].copy_from_slice(&[0, 0]);
        Ok(2)
    }

    fn on_transport_closed(&mut self) -> TlsCloseKind {
        if self.closed {
            TlsCloseKind::Clean
        } else {
            TlsCloseKind::Unclean
        }
    }

    fn info(&self) -> Option<TlsInfo> {
        (self.state == 2)
            .then(|| TlsInfo::new(Some("example.test"), Some(b"h2"), 0x0304, 0x1301))
            .flatten()
    }

    fn input_capacity_required(&self) -> usize {
        2
    }
}

/// The toy protocol's client side over a std socket.
struct ToyClient(TcpStream);

impl ToyClient {
    fn connect(server: &net_io::Server) -> ToyClient {
        ToyClient::connect_at(addr(server))
    }

    fn connect_at(at: std::net::SocketAddr) -> ToyClient {
        let mut s = client(at);
        s.write_all(b"HELLO").expect("hello");
        let mut w = [0u8; 7];
        s.read_exact(&mut w).expect("welcome");
        assert_eq!(&w, b"WELCOME");
        ToyClient(s)
    }

    fn send(&mut self, plain: &[u8]) {
        for chunk in plain.chunks(60_000) {
            let mut rec = u16::try_from(chunk.len())
                .expect("len")
                .to_be_bytes()
                .to_vec();
            rec.extend(chunk.iter().map(|b| b ^ MASK));
            self.0.write_all(&rec).expect("send");
        }
    }

    /// The next record: `Some(plaintext)`, or `None` for `close_notify`.
    fn recv(&mut self) -> Option<Vec<u8>> {
        let mut h = [0u8; 2];
        self.0.read_exact(&mut h).expect("record header");
        let len = usize::from(u16::from_be_bytes(h));
        if len == 0 {
            return None;
        }
        let mut body = vec![0u8; len];
        self.0.read_exact(&mut body).expect("record body");
        Some(body.into_iter().map(|b| b ^ MASK).collect())
    }

    fn recv_exact(&mut self, n: usize) -> Vec<u8> {
        let mut out = Vec::new();
        while out.len() < n {
            out.extend(self.recv().expect("data, not close_notify"));
        }
        out
    }
}

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
    fn wait_close_within(&self, limit: Duration) -> Option<CloseReason> {
        if !eventually(limit, || {
            self.0.lock().map(|v| !v.is_empty()).unwrap_or(false)
        }) {
            return None;
        }
        self.0.lock().ok().map(|v| v[0])
    }

    fn wait_close(&self) -> CloseReason {
        assert!(
            eventually(WAIT, || self
                .0
                .lock()
                .map(|v| !v.is_empty())
                .unwrap_or(false)),
            "no close"
        );
        self.0.lock().expect("lock")[0]
    }
}

fn echo(conn: &mut TcpConnection) -> Result<(), NetError> {
    let sni = conn
        .info()
        .tls
        .as_ref()
        .and_then(|t| t.sni().map(str::to_owned));
    conn.send_all(format!("sni={sni:?};").as_bytes())?;
    let mut buf = [0u8; 4096];
    loop {
        let n = conn.recv(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        conn.send_all(&buf[..n])?;
    }
}

fn tls_server<W: net_io::Workload>(
    builder: ServerBuilder<W>,
    rec: &Recorder,
    limits: Limits,
) -> net_io::Server {
    let server = builder
        .listener(ListenerSpec::tcp("127.0.0.1:0").tls(true).limits(limits))
        .workers(4)
        .tls(Toy)
        .gate(AllowAll)
        .events(rec.clone())
        .build()
        .expect("build");
    server.open_door().expect("open");
    server
}

#[test]
fn test_handler_speaks_plaintext_over_the_engine() {
    let rec = Recorder::default();
    let server = tls_server(ServerBuilder::new().handler(echo), &rec, Limits::default());
    let mut c = ToyClient::connect(&server);
    let greeting = c.recv_exact(b"sni=Some(\"example.test\");".len());
    assert_eq!(greeting, b"sni=Some(\"example.test\");");
    c.send(b"over tls");
    assert_eq!(c.recv_exact(8), b"over tls");
    drop(c);
    assert_eq!(rec.wait_close(), CloseReason::PeerClosed);
}

#[test]
fn test_sessions_large_messages_cross_many_records() {
    struct Echo;
    impl Session for Echo {
        fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
            let taken = cx.output().push_partial(input.bytes());
            input.consume(taken);
            Step::Write
        }
    }
    let rec = Recorder::default();
    let server = tls_server(
        ServerBuilder::new().sessions(|_: &ConnectionInfo| Echo),
        &rec,
        Limits::default(),
    );
    let mut c = ToyClient::connect(&server);
    let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let mut writer = ToyClient(c.0.try_clone().expect("clone"));
    let data = big.clone();
    let t = std::thread::spawn(move || writer.send(&data));
    let back = c.recv_exact(big.len());
    t.join().expect("writer");
    assert!(back == big, "echo differs");
}

#[test]
fn test_graceful_close_sends_close_notify() {
    let rec = Recorder::default();
    let server = tls_server(
        ServerBuilder::new().handler(|conn: &mut TcpConnection| {
            conn.send_all(b"bye")?;
            Ok(())
        }),
        &rec,
        Limits::default(),
    );
    let mut c = ToyClient::connect(&server);
    assert_eq!(c.recv().as_deref(), Some(&b"bye"[..]));
    assert_eq!(c.recv(), None, "close_notify before the FIN");
    let mut rest = Vec::new();
    let _ = c.0.read_to_end(&mut rest);
    assert!(rest.is_empty());
}

#[test]
fn test_refused_hello_and_handshake_timeout() {
    let rec = Recorder::default();
    let server = tls_server(ServerBuilder::new().handler(echo), &rec, Limits::default());
    let mut c = client(addr(&server));
    c.write_all(b"BLOCK").expect("write");
    assert_eq!(rec.wait_close(), CloseReason::HelloRefused);

    let rec = Recorder::default();
    let limits = Limits::builder()
        .handshake_timeout(Duration::from_millis(200))
        .build()
        .expect("limits");
    let server = tls_server(ServerBuilder::new().handler(echo), &rec, limits);
    let _silent = client(addr(&server));
    assert_eq!(rec.wait_close(), CloseReason::HandshakeTimeout);

    let rec = Recorder::default();
    let server = tls_server(ServerBuilder::new().handler(echo), &rec, Limits::default());
    let mut c = client(addr(&server));
    c.write_all(b"NOPE!").expect("write");
    assert_eq!(rec.wait_close(), CloseReason::TlsFailed);
}

#[test]
fn test_gate_counts_plaintext_once() {
    struct Count(Arc<AtomicU64>);
    impl Gate for Count {
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
        fn check(&self, _: &mut (), w: &WriteCheck) -> Result<(), Denial> {
            self.0.fetch_add(u64::from(w.bytes), Ordering::SeqCst);
            Ok(())
        }
    }
    let counted = Arc::new(AtomicU64::new(0));
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0").tls(true))
        .workers(2)
        .tls(Toy)
        .handler(|conn: &mut TcpConnection| {
            conn.send_all(&[7u8; 100_000])?;
            Ok(())
        })
        .gate(Count(counted.clone()))
        .build()
        .expect("build");
    server.open_door().expect("open");
    let mut c = ToyClient::connect(&server);
    assert_eq!(c.recv_exact(100_000).len(), 100_000);
    assert!(eventually(WAIT, || counted.load(Ordering::SeqCst) >= 100_000));
    assert_eq!(
        counted.load(Ordering::SeqCst),
        100_000,
        "plaintext bytes, each counted once"
    );
}

#[cfg(feature = "proxy")]
#[test]
fn test_proxy_then_tls_in_one_segment() {
    let rec = Recorder::default();
    let server = ServerBuilder::new()
        .listener(
            ListenerSpec::tcp("127.0.0.1:0")
                .proxy(net_io::ProxyMode::Required {
                    versions: net_io::ProxyVersions::V1,
                })
                .trusted_proxies(net_io::TrustedProxies::loopback())
                .tls(true),
        )
        .workers(2)
        .tls(Toy)
        .handler(|conn: &mut TcpConnection| {
            let who = format!("{:?}", conn.info().client_addr());
            conn.send_all(who.as_bytes())?;
            Ok(())
        })
        .gate(AllowAll)
        .events(rec.clone())
        .build()
        .expect("build");
    server.open_door().expect("open");
    let mut s = client(addr(&server));
    s.write_all(b"PROXY TCP4 203.0.113.9 127.0.0.1 7 443\r\nHELLO")
        .expect("write");
    let mut w = [0u8; 7];
    s.read_exact(&mut w).expect("welcome");
    let mut c = ToyClient(s);
    assert_eq!(c.recv().as_deref(), Some(&b"Some(203.0.113.9:7)"[..]));
}

/// Sessions behind a PROXY header on a TLS listener: bytes read with the header go
/// to the engine, never to the session as plaintext, on both drivers.
#[test]
fn test_proxy_then_tls_on_sessions_feeds_read_ahead_to_the_engine() {
    struct Seen(Arc<Mutex<Vec<u8>>>);
    impl Session for Seen {
        fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
            if let Ok(mut v) = self.0.lock() {
                v.extend_from_slice(input.bytes());
            }
            let taken = cx.output().push_partial(input.bytes());
            input.consume(taken);
            Step::Write
        }
    }
    for &driver in common::DRIVERS {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let rec = Recorder::default();
        let s2 = seen.clone();
        let server = ServerBuilder::new()
            .listener(
                ListenerSpec::tcp("127.0.0.1:0")
                    .proxy(net_io::ProxyMode::Required {
                        versions: net_io::ProxyVersions::V1,
                    })
                    .trusted_proxies(net_io::TrustedProxies::loopback())
                    .tls(true),
            )
            .driver(driver)
            .workers(2)
            .tls(Toy)
            .sessions(move |_: &ConnectionInfo| Seen(s2.clone()))
            .gate(AllowAll)
            .events(rec.clone())
            .build()
            .expect("build");
        server.open_door().expect("open");

        // The hello in the header's segment: the handshake completes and data flows.
        let mut s = client(addr(&server));
        s.write_all(b"PROXY TCP4 203.0.113.9 127.0.0.1 7 443\r\nHELLO")
            .expect("write");
        let mut w = [0u8; 7];
        if let Err(e) = s.read_exact(&mut w) {
            std::thread::sleep(Duration::from_millis(300));
            panic!(
                "{driver:?}: {e}: {:?} {:?}",
                rec.0.lock().expect("lock"),
                server.stats()
            );
        }
        assert_eq!(&w, b"WELCOME", "{driver:?}");
        let mut c = ToyClient(s);
        c.send(b"ping");
        assert_eq!(c.recv_exact(4), b"ping", "{driver:?}");
        drop(c);

        // Bytes injected between the header and the hello reach the engine, which
        // refuses them; the session sees nothing.
        seen.lock().expect("lock").clear();
        let mut s = client(addr(&server));
        s.write_all(b"PROXY TCP4 203.0.113.9 127.0.0.1 7 443\r\nXYZ")
            .expect("write");
        std::thread::sleep(Duration::from_millis(100));
        let _ = s.write_all(b"HELLO");
        let mut rest = Vec::new();
        let _ = s.read_to_end(&mut rest);
        assert!(
            !rest.starts_with(b"WELCOME"),
            "{driver:?}: handshake completed over injected bytes"
        );
        assert!(
            eventually(WAIT, || server.stats().closed >= 2),
            "{driver:?}: {:?}",
            server.stats()
        );
        assert!(
            seen.lock().expect("lock").is_empty(),
            "{driver:?}: the session saw {:?}",
            seen.lock().expect("lock")
        );
    }
}

#[test]
fn test_tls_listener_needs_an_engine() {
    let r = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0").tls(true))
        .handler(echo)
        .gate(AllowAll)
        .build();
    assert!(matches!(
        r,
        Err(NetError::InvalidConfig {
            field: "tls",
            reason: ConfigReason::Missing
        })
    ));
}

/// An engine that panics on `BOOM` in place of a hello.
struct Panicky;

impl TlsAcceptor for Panicky {
    type Session = PanickySession;
    fn session(&self, _info: &ConnectionInfo) -> Result<PanickySession, TlsError> {
        Ok(PanickySession(ToySession::default()))
    }
}

struct PanickySession(ToySession);

impl TlsSession for PanickySession {
    fn step<'i>(
        &mut self,
        input: &'i mut [u8],
        output: &mut [u8],
    ) -> Result<TlsProgress<'i>, TlsError> {
        assert!(!input.starts_with(b"BOOM"), "engine bug");
        self.0.step(input, output)
    }
    fn encrypt(&mut self, plaintext: &[u8], output: &mut [u8]) -> Result<usize, TlsError> {
        self.0.encrypt(plaintext, output)
    }
    fn close(&mut self, output: &mut [u8]) -> Result<usize, TlsError> {
        self.0.close(output)
    }
    fn on_transport_closed(&mut self) -> TlsCloseKind {
        self.0.on_transport_closed()
    }
    fn info(&self) -> Option<TlsInfo> {
        self.0.info()
    }
    fn input_capacity_required(&self) -> usize {
        self.0.input_capacity_required()
    }
}

/// A panic inside the TLS engine closes only that connection, `TlsFailed`, on both
/// drivers: the worker, its caps, and drain survive.
#[test]
fn test_engine_panic_closes_only_that_connection() {
    struct Echo;
    impl Session for Echo {
        fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
            let taken = cx.output().push_partial(input.bytes());
            input.consume(taken);
            Step::Write
        }
    }
    for &driver in common::DRIVERS {
        let rec = Recorder::default();
        let server = ServerBuilder::new()
            .listener(ListenerSpec::tcp("127.0.0.1:0").tls(true))
            .driver(driver)
            .workers(1)
            .tls(Panicky)
            .sessions(|_: &ConnectionInfo| Echo)
            .gate(AllowAll)
            .events(rec.clone())
            .build()
            .expect("build");
        server.open_door().expect("open");
        for _ in 0..3 {
            let mut s = client(addr(&server));
            s.write_all(b"BOOM!").expect("write");
            let mut rest = Vec::new();
            let _ = s.read_to_end(&mut rest);
            // One worker: the next client waits for this close, or the pool says Busy.
            assert!(eventually(WAIT, || server.stats().open == 0));
        }
        assert!(
            eventually(WAIT, || server.stats().closed == 3
                && server.stats().open == 0),
            "{driver:?}: {:?}",
            server.stats()
        );
        assert!(
            rec.0
                .lock()
                .expect("lock")
                .iter()
                .all(|r| *r == CloseReason::TlsFailed),
            "{driver:?}: {:?}",
            rec.0.lock().expect("lock")
        );
        // The one worker still serves.
        let mut c = ToyClient::connect(&server);
        c.send(b"still here");
        assert_eq!(c.recv_exact(10), b"still here", "{driver:?}");
        drop(c);
        let report = server.shutdown(std::time::Instant::now() + Duration::from_secs(2));
        assert_eq!(report.killed, 0, "{driver:?}: {report:?}");
    }
}

/// A gate denial on a TLS connection goes out as a record, never as plaintext on the
/// socket, on both drivers.
#[test]
fn test_denial_under_tls_is_encrypted() {
    struct DenyAfterHandshake;
    impl Gate for DenyAfterHandshake {
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
            Err(Denial { code: 3 })
        }
    }
    struct Reply;
    impl Session for Reply {
        fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
            let n = input.bytes().len();
            input.consume(n);
            cx.output().begin_response();
            cx.output().push(b"the real reply").expect("push");
            Step::Write
        }
        fn on_denied(&mut self, _code: u16, output: &mut net_io::Output) {
            let _ = output.push(b"DENIED-IN-THE-CLEAR");
        }
    }
    for &driver in common::DRIVERS {
        let server = ServerBuilder::new()
            .listener(ListenerSpec::tcp("127.0.0.1:0").tls(true))
            .driver(driver)
            .workers(2)
            .tls(Toy)
            .sessions(|_: &ConnectionInfo| Reply)
            .gate(DenyAfterHandshake)
            .build()
            .expect("build");
        server.open_door().expect("open");
        let mut c = ToyClient::connect(&server);
        c.send(b"go");
        let mut wire = Vec::new();
        let _ = c.0.read_to_end(&mut wire);
        let clear = b"DENIED-IN-THE-CLEAR";
        assert!(
            !wire.windows(clear.len()).any(|w| w == clear),
            "{driver:?}: the denial crossed the wire unencrypted"
        );
        assert!(
            !wire.windows(14).any(|w| w == b"the real reply"),
            "{driver:?}"
        );
    }
}

/// An engine whose handshake flight is 60 KiB: more than the socket buffers hold.
struct BigFlight;

impl TlsAcceptor for BigFlight {
    type Session = BigSession;
    fn session(&self, _info: &ConnectionInfo) -> Result<BigSession, TlsError> {
        Ok(BigSession(false))
    }
}

struct BigSession(bool);

impl TlsSession for BigSession {
    fn step<'i>(
        &mut self,
        input: &'i mut [u8],
        output: &mut [u8],
    ) -> Result<TlsProgress<'i>, TlsError> {
        if self.0 || input.len() < 5 {
            return Ok(TlsProgress {
                consumed: 0,
                written: 0,
                event: TlsEvent::NeedInput,
            });
        }
        self.0 = true;
        let n = output.len().min(60 << 10);
        output[..n].fill(0xEE);
        Ok(TlsProgress {
            consumed: 5,
            written: n,
            event: TlsEvent::Transmit,
        })
    }
    fn encrypt(&mut self, _: &[u8], _: &mut [u8]) -> Result<usize, TlsError> {
        Err(TlsError::new(TlsFailure::State, 0, None))
    }
    fn close(&mut self, _: &mut [u8]) -> Result<usize, TlsError> {
        Ok(0)
    }
    fn on_transport_closed(&mut self) -> TlsCloseKind {
        TlsCloseKind::Unclean
    }
    fn info(&self) -> Option<TlsInfo> {
        None
    }
    fn input_capacity_required(&self) -> usize {
        0
    }
}

/// A peer that takes the handshake flight a byte at a time (here: not at all) is
/// closed at the handshake deadline, not after a write timeout each byte restarts,
/// on both drivers (the pool used to wait on the write timeout).
#[test]
fn test_handshake_flight_is_bounded_by_the_handshake_deadline() {
    struct Nothing;
    impl Session for Nothing {
        fn on_data(&mut self, _: &mut SessionContext<'_>, _: &mut Input) -> Step {
            Step::Close
        }
    }
    for &driver in common::DRIVERS {
        let rec = Recorder::default();
        let limits = Limits::builder()
            .handshake_timeout(Duration::from_millis(800))
            .write_timeout(Duration::from_secs(60))
            .build()
            .expect("limits");
        let server = ServerBuilder::new()
            .listener(
                ListenerSpec::tcp_with(
                    "127.0.0.1:0",
                    net_io::ListenOptions::new().send_buffer(4096),
                )
                .tls(true)
                .limits(limits),
            )
            .driver(driver)
            .workers(2)
            .tls(BigFlight)
            .sessions(|_: &ConnectionInfo| Nothing)
            .gate(AllowAll)
            .events(rec.clone())
            .build()
            .expect("build");
        server.open_door().expect("open");
        let options = net_io::ConnectOptions::new()
            .tcp_options(net_io::TcpOptions::new().receive_buffer(4096));
        let mut c = TcpConnection::connect_with(addr(&server), options).expect("connect");
        c.send_all(b"HELLO").expect("hello");
        let started = std::time::Instant::now();
        let reason = rec.wait_close_within(Duration::from_secs(10));
        assert_eq!(reason, Some(CloseReason::HandshakeTimeout), "{driver:?}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{driver:?}: {:?}",
            started.elapsed()
        );
        drop(c);
    }
}

/// A session that answers and closes, with a client that reads the answer and
/// closes at once (FIN, or with `close_notify` unread, which resets): the server's
/// close ends when the client's does, not at the linger's deadline, on both
/// drivers (tls-net's handshake benchmark held about 9,000 connections open).
#[test]
fn test_close_after_reply_ends_with_the_clients_close() {
    struct Reply;
    impl Session for Reply {
        fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
            let n = input.bytes().len();
            input.consume(n);
            let _ = cx.output().push(&[b'r'; 70]);
            Step::Close
        }
    }
    for &driver in common::DRIVERS {
        for read_notify in [true, false] {
            let server = ServerBuilder::new()
                .listener(ListenerSpec::tcp("127.0.0.1:0").tls(true))
                .driver(driver)
                .workers(2)
                .tls(Toy)
                .sessions(|_: &ConnectionInfo| Reply)
                .gate(AllowAll)
                .build()
                .expect("build");
            server.open_door().expect("open");
            let mut worst = Duration::ZERO;
            for i in 0..200u64 {
                let mut c = ToyClient::connect(&server);
                c.send(b"GET");
                assert_eq!(c.recv_exact(70), vec![b'r'; 70]);
                if read_notify {
                    assert_eq!(c.recv(), None, "close_notify");
                }
                drop(c);
                let t = std::time::Instant::now();
                assert!(
                    eventually(WAIT, || server.stats().closed > i),
                    "{driver:?} {read_notify}: {:?}",
                    server.stats()
                );
                worst = worst.max(t.elapsed());
            }
            eprintln!("{driver:?} read close_notify {read_notify}: worst {worst:?}");
            assert!(
                worst < Duration::from_millis(500),
                "{driver:?} {read_notify}: a close waited {worst:?}"
            );
        }
    }
}

/// Idle TLS connections hold no buffers on the reactor: with a budget for about 32
/// connections' pairs of 64 KiB buffers, 100 connections that each finish an
/// exchange and wait all stay open and are served again, and a new one is served
/// too (D-181; tls-net found the reactor capped at budget / 128 KiB connections).
#[cfg(feature = "reactor")]
#[test]
fn test_idle_tls_connections_hold_no_buffers() {
    struct Echo;
    impl Session for Echo {
        fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
            let taken = cx.output().push_partial(input.bytes());
            input.consume(taken);
            Step::Write
        }
    }
    let limits = Limits::builder()
        .buffer_budget(4 << 20)
        .max_connections(256)
        .max_per_source(256, net_io::PrefixPolicy::DEFAULT)
        .build()
        .expect("limits");
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0").tls(true))
        .driver(net_io::DriverKind::Reactor)
        .workers(2)
        .limits(limits)
        .tls(Toy)
        .sessions(|_: &ConnectionInfo| Echo)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let mut held = Vec::new();
    for i in 0..100u32 {
        let mut c = ToyClient::connect(&server);
        c.send(format!("hello {i}").as_bytes());
        assert_eq!(
            c.recv_exact(format!("hello {i}").len()),
            format!("hello {i}").as_bytes()
        );
        held.push(c);
    }
    for (i, c) in held.iter_mut().enumerate() {
        c.send(b"again");
        assert_eq!(c.recv_exact(5), b"again", "connection {i}");
    }
    let mut last = ToyClient::connect(&server);
    last.send(b"new");
    assert_eq!(last.recv_exact(3), b"new");
    assert_eq!(
        server
            .stats()
            .closed_for(CloseReason::Limit(net_io::LimitKind::BufferBudget)),
        0,
        "{:?}",
        server.stats()
    );
    assert_eq!(server.stats().open, 101, "{:?}", server.stats());
}

/// The same after a large reply (tls-net, on 0.7.0): each connection fetches a
/// 32 KiB page, which the session writes and then reads again from `on_writable`,
/// and goes idle. Its buffers go back too, the output's spares among them: 100
/// such connections fit a budget of 20 KiB each (D-200).
#[cfg(feature = "reactor")]
#[test]
fn test_idle_tls_connections_after_a_large_reply_hold_no_buffers() {
    const PAGE: usize = 32 << 10;
    struct Page;
    impl Session for Page {
        fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
            let n = input.bytes().len();
            input.consume(n);
            cx.output().push(&[b'p'; PAGE]).expect("push");
            Step::Write
        }
        fn on_writable(&mut self, _: &mut SessionContext<'_>) -> Step {
            Step::Read
        }
    }
    let limits = Limits::builder()
        .buffer_budget(2 << 20)
        .max_connections(256)
        .max_per_source(256, net_io::PrefixPolicy::DEFAULT)
        .build()
        .expect("limits");
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0").tls(true))
        .driver(net_io::DriverKind::Reactor)
        .workers(2)
        .limits(limits)
        .tls(Toy)
        .sessions(|_: &ConnectionInfo| Page)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let mut held = Vec::new();
    for i in 0..100u32 {
        let mut c = ToyClient::connect(&server);
        c.send(b"GET");
        assert_eq!(c.recv_exact(PAGE).len(), PAGE, "connection {i}");
        held.push(c);
    }
    for (i, c) in held.iter_mut().enumerate() {
        c.send(b"GET");
        assert_eq!(c.recv_exact(PAGE).len(), PAGE, "connection {i}, again");
    }
    assert_eq!(
        server
            .stats()
            .closed_for(CloseReason::Limit(net_io::LimitKind::BufferBudget)),
        0,
        "{:?}",
        server.stats()
    );
    assert_eq!(server.stats().open, 100, "{:?}", server.stats());
}

/// tls-net's report: on the pool, the first connection after a handshake timeout
/// was closed at once as a second `HandshakeTimeout`. A stalled hello times out,
/// then a fresh client must complete its handshake, again and again.
#[test]
fn test_a_connection_after_a_handshake_timeout_gets_its_own_deadline() {
    // A handler runs on the pool only.
    {
        let driver = net_io::DriverKind::Blocking;
        let rec = Recorder::default();
        let limits = Limits::blocking_defaults()
            .to_builder()
            .handshake_timeout(Duration::from_millis(300))
            .build()
            .expect("limits");
        let server = ServerBuilder::new()
            .listener(ListenerSpec::tcp("127.0.0.1:0").tls(true))
            .driver(driver)
            .workers(4)
            .limits(limits)
            .tls(Toy)
            .handler(echo)
            .gate(AllowAll)
            .events(rec.clone())
            .build()
            .expect("build");
        server.open_door().expect("open");
        for round in 0..30 {
            let before = rec.0.lock().expect("lock").len();
            let mut stalled = client(addr(&server));
            stalled.write_all(b"H").expect("one byte");
            assert!(
                eventually(WAIT, || rec.0.lock().expect("lock").len() > before),
                "{driver:?} round {round}: no close"
            );
            assert_eq!(
                rec.0.lock().expect("lock")[before],
                CloseReason::HandshakeTimeout,
                "{driver:?} round {round}"
            );
            let mut fresh = ToyClient::connect(&server);
            let greeting = b"sni=Some(\"example.test\");";
            assert_eq!(
                fresh.recv_exact(greeting.len()),
                greeting,
                "{driver:?} round {round}"
            );
            fresh.send(b"ping");
            assert_eq!(fresh.recv_exact(4), b"ping", "{driver:?} round {round}");
            drop(fresh);
            drop(stalled);
            assert!(
                eventually(WAIT, || rec.0.lock().expect("lock").len() == before + 2),
                "{driver:?} round {round}"
            );
            let closes = rec.0.lock().expect("lock").clone();
            assert_ne!(
                closes[before + 1],
                CloseReason::HandshakeTimeout,
                "{driver:?} round {round}: {closes:?}"
            );
        }
    }
}
/// Echoes and records the budget its worker's pool sees at each call.
#[cfg(feature = "reactor")]
struct Probe(Arc<AtomicU64>);

#[cfg(feature = "reactor")]
impl Session for Probe {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        self.0
            .store(cx.buffers().stats().budget_left, Ordering::SeqCst);
        let taken = cx.output().push_partial(input.bytes());
        input.consume(taken);
        Step::Write
    }
}

/// Sends one byte and waits up to `within` for it to come back.
#[cfg(feature = "reactor")]
fn echoes(c: &mut TcpStream, byte: u8, within: Duration) -> bool {
    if c.set_read_timeout(Some(within)).is_err() || c.write_all(&[byte]).is_err() {
        return false;
    }
    let mut b = [0u8; 1];
    matches!(c.read(&mut b), Ok(1)) && b[0] == byte
}

/// A reactor server with a plaintext listener (first) and a TLS listener (second)
/// on one worker.
#[cfg(feature = "reactor")]
fn plain_and_tls(budget: &Arc<AtomicU64>, limits: Limits) -> net_io::Server {
    let probe = budget.clone();
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .listener(ListenerSpec::tcp("127.0.0.1:0").tls(true))
        .driver(net_io::DriverKind::Reactor)
        .workers(1)
        .limits(limits)
        .tls(Toy)
        .sessions(move |_: &ConnectionInfo| Probe(probe.clone()))
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    server
}

/// A 1 MiB budget: room for eight handshakes' buffers (64 KiB in, 64 KiB out).
/// No minimum rate, so clients that stall are closed by the budget, not as slow.
#[cfg(feature = "reactor")]
fn mib_budget() -> Limits {
    Limits::builder()
        .buffer_budget(1 << 20)
        .min_rate(net_io::MinRate::off())
        .build()
        .expect("limits")
}

/// TLS clients that connect and send nothing hold no buffers on the reactor, so
/// they cannot spend the budget other listeners draw from: with room for eight
/// handshakes, sixteen silent clients leave a plaintext connection established
/// before them (its first request not sent yet) and a new one served, take
/// nothing from the budget, and leave service running after they go. Before, each
/// took 128 KiB at accept and held it to the handshake deadline.
#[cfg(feature = "reactor")]
#[test]
fn test_silent_tls_clients_do_not_stall_plaintext_connections() {
    const SILENT: u64 = 16;
    const BUDGET: u64 = 1 << 20;
    let budget = Arc::new(AtomicU64::new(0));
    let server = plain_and_tls(&budget, mib_budget());
    let plain = addr(&server);
    let tls = server.listeners()[1].local.socket_addr().expect("ip");
    let mut a = client(plain);

    let silent: Vec<TcpStream> = (0..SILENT).map(|_| client(tls)).collect();
    assert!(eventually(WAIT, || server.stats().accepted == SILENT + 1));
    std::thread::sleep(Duration::from_millis(300));
    let established = echoes(&mut a, b'b', Duration::from_secs(2));
    // Read in `a`'s first call: the budget less its 16 KiB input and whatever the
    // silent clients hold.
    let during = budget.load(Ordering::SeqCst);
    let mut fresh = client(plain);
    let new = echoes(&mut fresh, b'c', Duration::from_secs(2));
    let held = (BUDGET - u64::from(net_io::SizeClass::MEDIUM.bytes())).saturating_sub(during);
    if established {
        eprintln!("{SILENT} silent TLS clients hold {held} bytes of the budget");
    }
    assert!(
        established,
        "established connection stalled: {:?}",
        server.stats()
    );
    assert!(new, "new connection stalled: {:?}", server.stats());
    assert_eq!(held, 0, "silent TLS clients took from the budget");

    drop(silent);
    drop(fresh);
    assert!(eventually(WAIT, || server.stats().open == 1));
    let mut later = client(plain);
    assert!(
        echoes(&mut later, b'd', Duration::from_secs(2)),
        "no service after the silent clients left: {:?}",
        server.stats()
    );
}

/// The reactor's TLS start waits for the first bytes without buffers, then runs
/// the handshake as before: a hello split across segments completes, a hello
/// after a PROXY header in its own segment completes, a hello in the header's
/// segment (read ahead with it) completes, and a client that sends nothing is
/// closed at the handshake deadline with `HandshakeTimeout`.
#[cfg(feature = "reactor")]
#[test]
fn test_tls_handshake_after_a_wait_without_buffers() {
    struct Echo;
    impl Session for Echo {
        fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
            let taken = cx.output().push_partial(input.bytes());
            input.consume(taken);
            Step::Write
        }
    }
    let rec = Recorder::default();
    let limits = Limits::builder()
        .handshake_timeout(Duration::from_millis(500))
        .build()
        .expect("limits");
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0").tls(true).limits(limits))
        .driver(net_io::DriverKind::Reactor)
        .workers(1)
        .tls(Toy)
        .sessions(|_: &ConnectionInfo| Echo)
        .gate(AllowAll)
        .events(rec.clone())
        .build()
        .expect("build");
    server.open_door().expect("open");

    let mut s = client(addr(&server));
    s.write_all(b"HE").expect("write");
    std::thread::sleep(Duration::from_millis(50));
    s.write_all(b"LLO").expect("write");
    let mut w = [0u8; 7];
    s.read_exact(&mut w).expect("welcome");
    assert_eq!(&w, b"WELCOME");
    let mut c = ToyClient(s);
    c.send(b"split hello");
    assert_eq!(c.recv_exact(11), b"split hello");
    drop(c);
    assert_eq!(rec.wait_close(), CloseReason::PeerClosed);

    rec.0.lock().expect("lock").clear();
    let started = std::time::Instant::now();
    let silent = client(addr(&server));
    assert_eq!(rec.wait_close(), CloseReason::HandshakeTimeout);
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    drop(silent);

    #[cfg(feature = "proxy")]
    {
        let server = ServerBuilder::new()
            .listener(
                ListenerSpec::tcp("127.0.0.1:0")
                    .proxy(net_io::ProxyMode::Required {
                        versions: net_io::ProxyVersions::V1,
                    })
                    .trusted_proxies(net_io::TrustedProxies::loopback())
                    .tls(true),
            )
            .driver(net_io::DriverKind::Reactor)
            .workers(1)
            .tls(Toy)
            .sessions(|_: &ConnectionInfo| Echo)
            .gate(AllowAll)
            .build()
            .expect("build");
        server.open_door().expect("open");
        let header: &[u8] = b"PROXY TCP4 203.0.113.9 127.0.0.1 7 443\r\n";
        for split in [true, false] {
            let mut s = client(addr(&server));
            if split {
                s.write_all(header).expect("header");
                std::thread::sleep(Duration::from_millis(50));
                s.write_all(b"HELLO").expect("hello");
            } else {
                let mut both = header.to_vec();
                both.extend_from_slice(b"HELLO");
                s.write_all(&both).expect("write");
            }
            let mut w = [0u8; 7];
            s.read_exact(&mut w).expect("welcome");
            assert_eq!(&w, b"WELCOME", "split {split}");
            let mut c = ToyClient(s);
            c.send(b"ping");
            assert_eq!(c.recv_exact(4), b"ping", "split {split}");
        }
    }
}

/// Handshakes that hold buffers are capped per worker at a quarter of the budget:
/// with 1 MiB on one worker, two (128 KiB each). Clients that send part of a hello
/// and stall take the two places; the next are closed with `Limit(BufferBudget)`
/// while plaintext is served. A client that leaves frees its place, and so does a
/// handshake that finishes.
#[cfg(feature = "reactor")]
#[test]
fn test_handshakes_holding_buffers_are_capped() {
    let refused = CloseReason::Limit(net_io::LimitKind::BufferBudget);
    let budget = Arc::new(AtomicU64::new(0));
    let server = plain_and_tls(&budget, mib_budget());
    let plain = addr(&server);
    let tls = server.listeners()[1].local.socket_addr().expect("ip");
    let stall = |n: usize| -> Vec<TcpStream> {
        let v: Vec<TcpStream> = (0..n)
            .map(|_| {
                let mut s = client(tls);
                s.write_all(b"HE").expect("write");
                s
            })
            .collect();
        std::thread::sleep(Duration::from_millis(200));
        v
    };
    let mut a = client(plain);
    assert!(echoes(&mut a, b'a', WAIT));

    let first = stall(2);
    let over = stall(4);
    assert!(
        eventually(WAIT, || server.stats().closed_for(refused) == 4),
        "{:?}",
        server.stats()
    );
    assert!(echoes(&mut a, b'b', WAIT), "plaintext stalled");
    let mut fresh = client(plain);
    assert!(echoes(&mut fresh, b'c', WAIT), "new plaintext stalled");
    // A whole hello finds the places taken too.
    let mut whole = client(tls);
    whole.write_all(b"HELLO").expect("write");
    assert!(common::closed_by_server(&mut whole));
    assert!(eventually(WAIT, || server.stats().closed_for(refused) == 5));

    // The stalled clients leave: their places free.
    drop(first);
    drop(over);
    drop(whole);
    assert!(
        eventually(WAIT, || server.stats().open == 2),
        "{:?}",
        server.stats()
    );
    // Finished handshakes do not keep a place.
    let mut done: Vec<ToyClient> = (0..3).map(|_| ToyClient::connect_at(tls)).collect();
    for c in &mut done {
        c.send(b"ok");
        assert_eq!(c.recv_exact(2), b"ok");
    }
    let second = stall(2);
    let third = stall(1);
    assert!(
        eventually(WAIT, || server.stats().closed_for(refused) == 6),
        "{:?}",
        server.stats()
    );
    assert!(echoes(&mut a, b'd', WAIT), "plaintext stalled");
    drop(second);
    drop(third);
    assert_eq!(server.stats().closed_for(refused), 6);
}
