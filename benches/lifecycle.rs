//! What a connection's life costs outside the data path: B-9 to B-12.
//!
//! ```text
//! ulimit -n 30000
//! cargo bench --bench lifecycle
//! ```
//!
//! B-9 parses PROXY headers; B-10 times `post` to `on_wake` on an idle worker; B-11
//! times `kill` to the reset reaching a blocked reader on loopback, so the reader's
//! own wake-up is inside the number; B-12 drains 10,000 idle connections, or as many
//! as the descriptor limit allows.

use std::hint::black_box;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Mutex;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use net_io::{
    AllowAll, Completer, ConnectionId, ConnectionInfo, DriverKind, Input, KillReason, Limits,
    ListenerSpec, PrefixPolicy, ProxyCommand, ProxyParser, ProxyProgress, ProxyVersions, Server,
    ServerBuilder, Session, SessionContext, Step, Tlv, encode_v1, encode_v2,
};

const HEADERS: u32 = 2_000_000;
const WAKES: usize = 2_000;
const KILLS: usize = 500;
const IDLE: u32 = 10_000;

fn percentile(samples: &mut [Duration], q: f64) -> f64 {
    samples.sort_unstable();
    let at = ((samples.len() - 1) as f64 * q) as usize;
    samples[at].as_secs_f64() * 1e6
}

fn proxy_headers() {
    let source: SocketAddr = "192.0.2.1:5000".parse().expect("address");
    let destination: SocketAddr = "192.0.2.2:443".parse().expect("address");
    let mut v1 = [0u8; 128];
    let n = encode_v1(source, destination, &mut v1).expect("encode");
    let v1 = &v1[..n];
    let mut v2 = [0u8; 256];
    let n = encode_v2(
        ProxyCommand::Proxy,
        Some(source),
        Some(destination),
        &[],
        false,
        &mut v2,
    )
    .expect("encode");
    let v2 = &v2[..n];
    let tlvs = [
        Tlv {
            kind: 0x01,
            value: b"h2",
        },
        Tlv {
            kind: 0x02,
            value: b"example.com",
        },
        Tlv {
            kind: 0x05,
            value: b"0123456789abcdef",
        },
        Tlv {
            kind: 0xE0,
            value: b"one",
        },
        Tlv {
            kind: 0xE1,
            value: b"two",
        },
    ];
    let mut rich = [0u8; 256];
    let n = encode_v2(
        ProxyCommand::Proxy,
        Some(source),
        Some(destination),
        &tlvs,
        true,
        &mut rich,
    )
    .expect("encode");
    let rich = &rich[..n];
    println!("B-9 PROXY header, ns per header ({HEADERS} of each)");
    for (name, header) in [
        ("v1 TCP4", v1),
        ("v2 IPv4, no TLVs", v2),
        ("v2 IPv4, 5 TLVs and CRC32C", rich),
    ] {
        let started = Instant::now();
        for _ in 0..HEADERS {
            let mut parser = ProxyParser::new(ProxyVersions::Both, 2048);
            match parser.feed(black_box(header)) {
                Ok(ProxyProgress::Done { consumed, .. }) => {
                    black_box(consumed);
                }
                other => panic!("did not parse: {other:?}"),
            }
        }
        let ns = started.elapsed().as_secs_f64() * 1e9 / f64::from(HEADERS);
        println!("{name:<28} {ns:7.1}");
    }
}

fn server<S, F>(driver: DriverKind, limits: Limits, sessions: F) -> Server
where
    S: Session,
    F: Fn(&ConnectionInfo) -> S + Send + Sync + 'static,
{
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .driver(driver)
        .limits(limits)
        .sessions(sessions)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    server
}

fn address(server: &Server) -> SocketAddr {
    server.listeners()[0].local.socket_addr().expect("ip")
}

struct Waker {
    parked: mpsc::Sender<(Completer, ConnectionId)>,
    woken: mpsc::Sender<Instant>,
}

impl Session for Waker {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        input.consume(input.bytes().len());
        let _ = self.parked.send((cx.completer(), cx.info().id));
        Step::Park {
            until: Some(Instant::now() + Duration::from_secs(120)),
        }
    }

    fn on_wake(&mut self, _cx: &mut SessionContext<'_>, _token: u32, _value: u64) -> Step {
        let _ = self.woken.send(Instant::now());
        Step::Park {
            until: Some(Instant::now() + Duration::from_secs(120)),
        }
    }
}

fn post_to_wake(driver: DriverKind) {
    let (parked, on_parked) = mpsc::channel();
    let (woken, on_woken) = mpsc::channel();
    let pair = Mutex::new((parked, woken));
    let limits = Limits::builder().build().expect("limits");
    let server = server(driver, limits, move |_: &ConnectionInfo| {
        let pair = pair.lock().expect("lock");
        Waker {
            parked: pair.0.clone(),
            woken: pair.1.clone(),
        }
    });
    let mut c = TcpStream::connect(address(&server)).expect("connect");
    c.write_all(b"x").expect("write");
    let (completer, id) = on_parked.recv().expect("parked");
    let mut samples = Vec::with_capacity(WAKES);
    for _ in 0..WAKES {
        // Long enough that the worker is back asleep in the OS.
        std::thread::sleep(Duration::from_micros(500));
        let started = Instant::now();
        completer.post(id, 1, 1).expect("post");
        let at = on_woken.recv().expect("woken");
        samples.push(at - started);
    }
    println!(
        "B-10 post to wake, {driver:?}: p50 {:.1} us, p99 {:.1} us ({WAKES} wakes)",
        percentile(&mut samples, 0.5),
        percentile(&mut samples, 0.99)
    );
}

struct Named(mpsc::Sender<ConnectionId>);

impl Session for Named {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        input.consume(input.bytes().len());
        let _ = self.0.send(cx.info().id);
        Step::Read
    }
}

/// The floor under B-11: the same reset and the same blocked reader with no server.
/// Closing a socket with unread bytes resets the connection.
fn plain_reset() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let target = listener.local_addr().expect("address");
    let mut samples = Vec::with_capacity(KILLS);
    for _ in 0..KILLS {
        let mut c = TcpStream::connect(target).expect("connect");
        let (peer, _) = listener.accept().expect("accept");
        c.write_all(b"x").expect("write");
        let (ended, at) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut b = [0u8; 8];
            let _ = c.read(&mut b);
            let _ = ended.send(Instant::now());
        });
        std::thread::sleep(Duration::from_millis(1));
        let started = Instant::now();
        drop(peer);
        let when = at.recv().expect("ended");
        reader.join().expect("reader");
        samples.push(when - started);
    }
    println!(
        "B-11 floor, a close that resets: p50 {:.1} us, p99 {:.1} us",
        percentile(&mut samples, 0.5),
        percentile(&mut samples, 0.99)
    );
}

fn kill_to_reset(driver: DriverKind) {
    let (named, ids) = mpsc::channel();
    let named = Mutex::new(named);
    let limits = Limits::builder().build().expect("limits");
    let server = server(driver, limits, move |_: &ConnectionInfo| {
        Named(named.lock().expect("lock").clone())
    });
    let handle = server.handle();
    let target = address(&server);
    let mut samples = Vec::with_capacity(KILLS);
    let mut resets = 0usize;
    for _ in 0..KILLS {
        let mut c = TcpStream::connect(target).expect("connect");
        c.write_all(b"x").expect("write");
        let id = ids.recv().expect("named");
        let (ended, at) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut b = [0u8; 8];
            let reset = matches!(
                c.read(&mut b).map_err(|e| e.kind()),
                Err(ErrorKind::ConnectionReset)
            );
            let _ = ended.send((Instant::now(), reset));
        });
        // The reader is blocked in the OS by now.
        std::thread::sleep(Duration::from_millis(1));
        let started = Instant::now();
        assert!(handle.kill(id, KillReason(1)), "kill");
        let (when, reset) = at.recv().expect("ended");
        reader.join().expect("reader");
        samples.push(when - started);
        resets += usize::from(reset);
    }
    println!(
        "B-11 kill to reset, {driver:?}: p50 {:.1} us, p99 {:.1} us ({resets} resets of {KILLS})",
        percentile(&mut samples, 0.5),
        percentile(&mut samples, 0.99)
    );
}

struct Echo;

impl Session for Echo {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let taken = cx.output().push_partial(input.bytes());
        input.consume(taken);
        Step::Write
    }
}

fn drain_idle() {
    let limits = Limits::builder()
        .max_connections(IDLE + 64)
        .max_per_source(IDLE + 64, PrefixPolicy::DEFAULT)
        .backlog(4_096)
        .build()
        .expect("limits");
    let server = server(DriverKind::Reactor, limits, |_: &ConnectionInfo| Echo);
    let target = address(&server);
    let mut clients = Vec::with_capacity(IDLE as usize);
    let mut b = [0u8; 1];
    for _ in 0..IDLE {
        let Ok(mut c) = TcpStream::connect(target) else {
            break;
        };
        if c.write_all(b"x").is_err() || c.read_exact(&mut b).is_err() {
            break;
        }
        clients.push(c);
    }
    let report = server.drain(Instant::now() + Duration::from_secs(10));
    println!(
        "B-12 drain, reactor: {} idle connections in {:.1} ms ({} graceful, {} killed)",
        clients.len(),
        report.took.as_secs_f64() * 1e3,
        report.graceful,
        report.killed
    );
}

fn main() {
    proxy_headers();
    plain_reset();
    for driver in [DriverKind::Reactor, DriverKind::Blocking] {
        post_to_wake(driver);
        kill_to_reset(driver);
    }
    drain_idle();
}
