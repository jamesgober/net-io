//! PROXY protocol on a server listener: trust, the header, the real client, the gate.

#![cfg(feature = "proxy")]

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{addr, client, eventually};
use net_io::{
    AdmitStage, Admitted, AllowAll, CloseReason, ConfigReason, ConnectionInfo, Denial, Event,
    EventSink, Gate, GateTag, Input, Lane, Limits, ListenerSpec, NetError, PrefixPolicy, ProxyMode,
    ProxyVersions, Refusal, RefusalCause, ServerBuilder, Session, SessionContext, Step,
    TcpConnection, TrustedProxies, WriteCheck,
};

const WAIT: Duration = Duration::from_secs(5);
const BOTH: ProxyMode = ProxyMode::Required {
    versions: ProxyVersions::Both,
};

#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<Event>>>);

impl EventSink for Recorder {
    fn event(&self, event: &Event) {
        if let Ok(mut v) = self.0.lock() {
            v.push(*event);
        }
    }
}

impl Recorder {
    fn closes(&self) -> Vec<CloseReason> {
        self.0
            .lock()
            .map(|v| {
                v.iter()
                    .filter_map(|e| match e {
                        Event::Closed { reason, .. } => Some(*reason),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn wait_close(&self) -> CloseReason {
        assert!(eventually(WAIT, || !self.closes().is_empty()), "no close");
        self.closes()[0]
    }
}

/// Replies with the client address net-io believes, then echoes one read.
fn whoami(conn: &mut TcpConnection) -> Result<(), NetError> {
    let client = conn.info().client_addr();
    conn.send_all(format!("{client:?}\n").as_bytes())?;
    let mut buf = [0u8; 64];
    let n = conn.recv(&mut buf)?;
    conn.send_all(&buf[..n])?;
    Ok(())
}

fn server_with(trusted: TrustedProxies, limits: Limits, rec: &Recorder) -> net_io::Server {
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0").proxy(BOTH).limits(limits))
        .trusted_proxies(trusted)
        .workers(4)
        .handler(whoami)
        .gate(AllowAll)
        .events(rec.clone())
        .build()
        .expect("build");
    server.open_door().expect("open");
    server
}

fn read_line(c: &mut TcpStream) -> String {
    let mut out = Vec::new();
    let mut b = [0u8; 1];
    while c.read(&mut b).map(|n| n == 1).unwrap_or(false) {
        if b[0] == b'\n' {
            break;
        }
        out.push(b[0]);
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn v2_ipv4(src: [u8; 4], sport: u16, local: bool) -> Vec<u8> {
    let mut h = vec![
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ];
    h.push(if local { 0x20 } else { 0x21 });
    h.push(0x11);
    h.extend_from_slice(&12u16.to_be_bytes());
    h.extend_from_slice(&src);
    h.extend_from_slice(&[127, 0, 0, 1]);
    h.extend_from_slice(&sport.to_be_bytes());
    h.extend_from_slice(&443u16.to_be_bytes());
    h
}

#[test]
fn test_v1_header_gives_the_real_client_and_keeps_the_rest() {
    let rec = Recorder::default();
    let server = server_with(TrustedProxies::loopback(), Limits::default(), &rec);
    let mut c = client(addr(&server));
    c.write_all(b"PROXY TCP4 203.0.113.7 127.0.0.1 40000 443\r\nhello")
        .expect("write");
    assert_eq!(read_line(&mut c), "Some(203.0.113.7:40000)");
    let mut echo = [0u8; 5];
    c.read_exact(&mut echo).expect("read");
    assert_eq!(&echo, b"hello", "bytes after the header are data");
    assert!(eventually(WAIT, || rec
        .0
        .lock()
        .map(|v| v.iter().any(|e| matches!(e, Event::ProxyResolved { .. })))
        .unwrap_or(false)));
}

#[test]
fn test_v2_header_and_local_command() {
    let rec = Recorder::default();
    let server = server_with(TrustedProxies::loopback(), Limits::default(), &rec);
    let mut c = client(addr(&server));
    c.write_all(&v2_ipv4([198, 51, 100, 9], 5555, false))
        .expect("write");
    assert_eq!(read_line(&mut c), "Some(198.51.100.9:5555)");
    // LOCAL: a health check from the proxy itself keeps the socket's addresses.
    let mut c = client(addr(&server));
    let local_port = c.local_addr().expect("addr").port();
    c.write_all(&v2_ipv4([198, 51, 100, 9], 5555, true))
        .expect("write");
    assert_eq!(read_line(&mut c), format!("Some(127.0.0.1:{local_port})"));
}

#[test]
fn test_untrusted_peer_is_closed_before_reading() {
    let rec = Recorder::default();
    let server = server_with(
        TrustedProxies::parse("10.0.0.0/8").expect("parse"),
        Limits::default(),
        &rec,
    );
    let mut c = client(addr(&server));
    let _ = c.write_all(b"PROXY TCP4 203.0.113.7 127.0.0.1 40000 443\r\n");
    assert_eq!(rec.wait_close(), CloseReason::ProxyUntrusted);
}

#[test]
fn test_missing_invalid_and_slow_headers() {
    let limits = Limits::builder()
        .handshake_timeout(Duration::from_millis(200))
        .build()
        .expect("limits");
    for (bytes, want) in [
        (&b"GET / HTTP/1.1\r\n\r\n"[..], CloseReason::ProxyMissing),
        (
            &b"PROXY TCP4 999.0.0.1 127.0.0.1 1 2\r\n"[..],
            CloseReason::ProxyInvalid,
        ),
        // Edge case 17: the first bytes of a header, then silence.
        (&b"PROXY "[..], CloseReason::HandshakeTimeout),
    ] {
        let rec = Recorder::default();
        let server = server_with(TrustedProxies::loopback(), limits.clone(), &rec);
        let mut c = client(addr(&server));
        c.write_all(bytes).expect("write");
        assert_eq!(
            rec.wait_close().as_str(),
            want.as_str(),
            "{:?}",
            String::from_utf8_lossy(bytes)
        );
    }
}

#[test]
fn test_source_cap_moves_to_the_real_client() {
    let rec = Recorder::default();
    let limits = Limits::builder()
        .max_per_source(1, PrefixPolicy::HOST)
        .build()
        .expect("limits");
    let server = server_with(TrustedProxies::loopback(), limits, &rec);
    let header = |ip: &str| format!("PROXY TCP4 {ip} 127.0.0.1 40000 443\r\n");
    // Two real clients behind one proxy address: both fit a cap of one each.
    let mut a = client(addr(&server));
    a.write_all(header("203.0.113.1").as_bytes())
        .expect("write");
    assert_eq!(read_line(&mut a), "Some(203.0.113.1:40000)");
    let mut b = client(addr(&server));
    b.write_all(header("203.0.113.2").as_bytes())
        .expect("write");
    assert_eq!(read_line(&mut b), "Some(203.0.113.2:40000)");
    // A second connection from the same real client is over its cap.
    let mut c = client(addr(&server));
    c.write_all(header("203.0.113.1").as_bytes())
        .expect("write");
    assert_eq!(
        rec.wait_close(),
        CloseReason::Refused(RefusalCause::SourceCap)
    );
}

#[test]
fn test_gate_readmits_the_real_client() {
    struct NoDocs;
    impl Gate for NoDocs {
        type Ticket = ();
        fn admit(&self, _: &ConnectionInfo, _: AdmitStage) -> Result<Admitted<()>, Refusal> {
            Ok(Admitted {
                lane: Lane(0),
                ticket: (),
                tag: GateTag(0),
            })
        }
        fn readmit(&self, _: &mut (), info: &ConnectionInfo) -> Result<(), Refusal> {
            // 192.0.2.0/24 (documentation range) is refused once it is known.
            match info.client_addr().map(|a| a.ip()) {
                Some(std::net::IpAddr::V4(v4)) if v4.octets()[..3] == [192, 0, 2] => {
                    Err(Refusal::WithBytes {
                        code: 7,
                        bytes: b"no\n",
                    })
                }
                _ => Ok(()),
            }
        }
        fn check(&self, _: &mut (), _: &WriteCheck) -> Result<(), Denial> {
            Ok(())
        }
    }
    let rec = Recorder::default();
    let server = ServerBuilder::new()
        .listener(
            ListenerSpec::tcp("127.0.0.1:0")
                .proxy(BOTH)
                .trusted_proxies(TrustedProxies::loopback()),
        )
        .workers(2)
        .handler(whoami)
        .gate(NoDocs)
        .events(rec.clone())
        .build()
        .expect("build");
    server.open_door().expect("open");
    let mut c = client(addr(&server));
    c.write_all(b"PROXY TCP4 192.0.2.50 127.0.0.1 40000 443\r\n")
        .expect("write");
    // The refusal bytes go out once, then RST. Windows discards bytes the peer
    // has not read when the RST arrives, so only a prefix may be seen there.
    let got = read_line(&mut c);
    assert!("no".starts_with(&got), "{got:?}");
    assert_eq!(
        rec.wait_close(),
        CloseReason::Refused(RefusalCause::Gate(7))
    );
}

#[test]
fn test_sessions_see_bytes_after_the_header() {
    struct Echo;
    impl Session for Echo {
        fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
            let taken = cx.output().push_partial(input.bytes());
            input.consume(taken);
            Step::Write
        }
    }
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0").proxy(BOTH))
        .trusted_proxies(TrustedProxies::loopback())
        .workers(2)
        .sessions(|_: &ConnectionInfo| Echo)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let mut c = client(addr(&server));
    let mut msg = v2_ipv4([203, 0, 113, 4], 1, false);
    msg.extend_from_slice(b"ping");
    c.write_all(&msg).expect("write");
    let mut back = [0u8; 4];
    c.read_exact(&mut back).expect("read");
    assert_eq!(&back, b"ping");
}

/// Edge case 122: `Required` with nobody to trust fails at build.
#[test]
fn test_required_without_trusted_proxies_fails_at_build() {
    let r = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0").proxy(BOTH))
        .handler(whoami)
        .gate(AllowAll)
        .build();
    assert!(matches!(
        r,
        Err(NetError::InvalidConfig {
            field: "trusted_proxies",
            reason: ConfigReason::Missing
        })
    ));
    let empty: SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let r = ServerBuilder::new()
        .listener(
            ListenerSpec::tcp(empty)
                .proxy(BOTH)
                .trusted_proxies(TrustedProxies::none()),
        )
        .handler(whoami)
        .gate(AllowAll)
        .build();
    assert!(r.is_err());
}
