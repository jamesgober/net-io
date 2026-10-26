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
    EventSink, Gate, GateTag, Input, Lane, Limits, ListenerSpec, NetError, ProxyMode,
    ProxyVersions, Refusal, ServerBuilder, Session, SessionContext, Step, TcpConnection,
    TlsAcceptor, TlsCloseKind, TlsError, TlsEvent, TlsFailure, TlsInfo, TlsProgress, TlsSession,
    TrustedProxies, WriteCheck,
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
        let mut s = client(addr(server));
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
                .proxy(ProxyMode::Required {
                    versions: ProxyVersions::V1,
                })
                .trusted_proxies(TrustedProxies::loopback())
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
