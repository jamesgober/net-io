//! Echo benchmarks of net-io against other Rust stacks (B-2, B-3, B-4).
//!
//! Every server runs in a process of its own and every stack meets the same load
//! generator: a few threads, each driving its share of the connections closed-loop
//! on one `mio` poll, so the generator is the same cost in every row.
//!
//! ```text
//! cargo run --release                      all stacks, the full table
//! cargo run --release -- server tokio 127.0.0.1:9000
//! cargo run --release -- load 127.0.0.1:9000 1000 64 5
//! ```

use std::io::{ErrorKind, Read, Write};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use mio::net::TcpStream;
use mio::{Events, Interest, Poll, Token};

const STACKS: &[&str] = &[
    "std",
    "mio",
    "tokio",
    #[cfg(target_os = "linux")]
    "monoio",
    "net-io-pool",
    "net-io",
];

/// `(name, connections, message bytes)`.
const SHAPES: &[(&str, usize, usize)] = &[
    ("B-2 one connection, 64 B", 1, 64),
    ("B-3 100 connections, 64 B", 100, 64),
    ("B-3 1,000 connections, 64 B", 1_000, 64),
    ("B-3 10,000 connections, 64 B", 10_000, 64),
    ("B-4 1,000 connections, 16 KiB", 1_000, 16 * 1024),
];

/// A thread per connection does not get here: the shape would measure thread limits.
fn stack_takes(stack: &str, connections: usize) -> bool {
    connections <= 1_000 || !matches!(stack, "std" | "net-io-pool")
}

/// The most descriptors one client thread can use before it needs another source
/// address: an address has about 28,000 ephemeral ports.
const PORTS_PER_SOURCE: usize = 20_000;

const ROUNDS: usize = 3;
const SECONDS: u64 = 4;
const WARM_MS: u64 = 500;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("server") => server(
            &args[1],
            args[2].parse().expect("addr"),
            args.get(3).map_or(16_384, |c| c.parse().expect("capacity")),
        ),
        Some("load") => {
            let addr = args[1].parse().expect("addr");
            let r = load(
                addr,
                args[2].parse().expect("connections"),
                args[3].parse().expect("bytes"),
                Duration::from_secs(args[4].parse().expect("seconds")),
            );
            println!("{:.0} rt/s, p50 {} us, p99 {} us", r.rate, r.p50, r.p99);
        }
        _ => {
            accepts();
            table();
            idle(10_000, &IDLE_STACKS);
            let limit = descriptor_limit();
            if limit >= 230_000 {
                idle(100_000, &["tokio", "net-io"]);
            } else {
                println!("B-6 100,000 idle: skipped, the descriptor limit is {limit}");
            }
        }
    }
}

// ---- the table --------------------------------------------------------------

struct Measured {
    rate: f64,
    p50: u64,
    p99: u64,
    p999: u64,
    /// The server's CPU per round trip, user and system; 0 where `/proc` is missing.
    cpu_us: f64,
}

const IDLE_STACKS: [&str; 4] = [
    "mio",
    "tokio",
    #[cfg(target_os = "linux")]
    "monoio",
    #[cfg(not(target_os = "linux"))]
    "std",
    "net-io",
];

/// User and system time of a process, in the kernel's 100 Hz ticks.
fn cpu_ticks(pid: u32) -> u64 {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return 0;
    };
    let after = stat.rsplit(')').next().unwrap_or("");
    let fields: Vec<&str> = after.split_whitespace().collect();
    let tick = |i: usize| {
        fields
            .get(i)
            .and_then(|f| f.parse::<u64>().ok())
            .unwrap_or(0)
    };
    tick(11) + tick(12)
}

/// Resident bytes of a process.
fn resident(pid: u32) -> u64 {
    let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
        return 0;
    };
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|l| l.split_whitespace().next())
        .and_then(|kb| kb.parse::<u64>().ok())
        .map_or(0, |kb| kb * 1024)
}

fn descriptor_limit() -> u64 {
    std::fs::read_to_string("/proc/self/limits")
        .ok()
        .and_then(|l| {
            l.lines()
                .find(|l| l.starts_with("Max open files"))
                .and_then(|l| l.split_whitespace().nth(3).map(str::to_owned))
        })
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

fn start(stack: &str, port: u16) -> Child {
    start_with(stack, port, 16_384)
}

fn start_with(stack: &str, port: u16, capacity: usize) -> Child {
    let exe = std::env::current_exe().expect("this binary");
    let addr = format!("127.0.0.1:{port}");
    let child = Command::new(exe)
        .args(["server", stack, &addr, &capacity.to_string()])
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn");
    let target: SocketAddr = addr.parse().expect("addr");
    let deadline = Instant::now() + Duration::from_secs(5);
    while std::net::TcpStream::connect(target).is_err() {
        assert!(Instant::now() < deadline, "{stack} did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    child
}

fn table() {
    println!(
        "| Shape | Stack | Round trips/s | p50 us | p99 us | p99.9 us | Server CPU us/rt | vs tokio |"
    );
    println!("|---|---|---|---|---|---|---|---|");
    let mut port = 19_000;
    for (name, conns, bytes) in SHAPES {
        let mut results: Vec<(&str, Measured)> = Vec::new();
        for stack in STACKS.iter().filter(|s| stack_takes(s, *conns)) {
            port += 1;
            let mut child = start(stack, port);
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
            let mut runs: Vec<Measured> = (0..ROUNDS)
                .map(|_| {
                    let before = cpu_ticks(child.id());
                    let mut m = load(addr, *conns, *bytes, Duration::from_secs(SECONDS));
                    // Connecting and the warm-up count too, so this reads a little high.
                    let ticks = cpu_ticks(child.id()) - before;
                    m.cpu_us = ticks as f64 * 1e4 / (m.rate * SECONDS as f64);
                    m
                })
                .collect();
            let _ = child.kill();
            let _ = child.wait();
            runs.sort_by(|a, b| a.rate.total_cmp(&b.rate));
            results.push((stack, runs.remove(ROUNDS / 2)));
        }
        let tokio = results
            .iter()
            .find(|(s, _)| *s == "tokio")
            .map_or(1.0, |(_, m)| m.rate);
        for (stack, m) in &results {
            println!(
                "| {name} | {stack} | {:.0} | {} | {} | {} | {:.1} | {:.2}x |",
                m.rate,
                m.p50,
                m.p99,
                m.p999,
                m.cpu_us,
                m.rate / tokio
            );
        }
    }
}

// ---- B-1: accepts ------------------------------------------------------------

/// A connection, one byte each way, and a close that leaves no `TIME_WAIT`, so the
/// run does not stop for lack of ports.
fn one_connection(addr: SocketAddr) -> std::io::Result<()> {
    let mut s = std::net::TcpStream::connect(addr)?;
    s.set_nodelay(true)?;
    socket2::SockRef::from(&s).set_linger(Some(Duration::ZERO))?;
    s.write_all(b"x")?;
    let mut b = [0u8; 1];
    s.read_exact(&mut b)
}

fn accepts() {
    println!("| B-1 stack | Connections/s | p50 us | p99 us | vs tokio |");
    println!("|---|---|---|---|---|");
    let threads = std::thread::available_parallelism().map_or(2, |n| n.get() / 2);
    let mut port = 18_000;
    let mut results: Vec<(&str, Measured)> = Vec::new();
    for stack in STACKS {
        port += 1;
        let mut child = start(stack, port);
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                std::thread::spawn(move || {
                    let warm = Instant::now() + Duration::from_millis(WARM_MS);
                    let until = warm + Duration::from_secs(SECONDS);
                    let mut samples = Vec::new();
                    let mut count = 0u64;
                    loop {
                        let started = Instant::now();
                        if started >= until {
                            return (count, samples);
                        }
                        if one_connection(addr).is_ok() && started >= warm {
                            count += 1;
                            if count % SAMPLE_EVERY == 0 {
                                let us = started.elapsed().as_micros();
                                samples.push(u32::try_from(us).unwrap_or(u32::MAX));
                            }
                        }
                    }
                })
            })
            .collect();
        let mut samples = Vec::new();
        let mut count = 0u64;
        for h in handles {
            let (n, s) = h.join().expect("accept thread");
            count += n;
            samples.extend(s);
        }
        let _ = child.kill();
        let _ = child.wait();
        samples.sort_unstable();
        let pick = |q: f64| {
            samples
                .get(((samples.len() as f64 - 1.0) * q) as usize)
                .copied()
                .unwrap_or(0)
        };
        results.push((
            stack,
            Measured {
                rate: count as f64 / SECONDS as f64,
                p50: u64::from(pick(0.5)),
                p99: u64::from(pick(0.99)),
                p999: 0,
                cpu_us: 0.0,
            },
        ));
    }
    let tokio = results
        .iter()
        .find(|(s, _)| *s == "tokio")
        .map_or(1.0, |(_, m)| m.rate);
    for (stack, m) in &results {
        println!(
            "| {stack} | {:.0} | {} | {} | {:.2}x |",
            m.rate,
            m.p50,
            m.p99,
            m.rate / tokio
        );
    }
}

// ---- B-5, B-6: idle ----------------------------------------------------------

fn idle_connection(addr: SocketAddr, nth: usize) -> std::io::Result<std::net::TcpStream> {
    use socket2::{Domain, Socket, Type};
    let source = std::net::Ipv4Addr::new(127, 0, 1, (nth / PORTS_PER_SOURCE) as u8 + 1);
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    socket.bind(&SocketAddr::from((source, 0)).into())?;
    socket.connect(&addr.into())?;
    let mut s: std::net::TcpStream = socket.into();
    s.write_all(b"hello")?;
    let mut b = [0u8; 5];
    s.read_exact(&mut b)?;
    Ok(s)
}

fn idle(connections: usize, stacks: &[&str]) {
    println!("| Idle, {connections} connections | Reached | RSS bytes each | Idle CPU ms/s |");
    println!("|---|---|---|---|");
    let mut port = 17_000 + (connections / 1_000) as u16;
    for stack in stacks {
        port += 1;
        let mut child = start_with(stack, port, connections + 1_024);
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
        let first = idle_connection(addr, 0).expect("first connection");
        std::thread::sleep(Duration::from_millis(200));
        let base = resident(child.id());
        let mut held = Vec::with_capacity(connections);
        held.push(first);
        for nth in 1..connections {
            match idle_connection(addr, nth) {
                Ok(s) => held.push(s),
                Err(_) => break,
            }
        }
        std::thread::sleep(Duration::from_secs(1));
        let rss = resident(child.id());
        let before = cpu_ticks(child.id());
        std::thread::sleep(Duration::from_secs(2));
        let ticks = cpu_ticks(child.id()) - before;
        println!(
            "| {stack} | {} | {} | {:.1} |",
            held.len(),
            rss.saturating_sub(base) / held.len() as u64,
            ticks as f64 * 10.0 / 2.0
        );
        let _ = child.kill();
        let _ = child.wait();
    }
}

// ---- the load generator -----------------------------------------------------

struct Conn {
    stream: TcpStream,
    wrote: usize,
    read: usize,
    started: Instant,
}

/// Closed loop: each connection sends a message, reads it back, and sends the next.
fn load(addr: SocketAddr, conns: usize, bytes: usize, time: Duration) -> Measured {
    let threads = std::thread::available_parallelism()
        .map_or(2, |n| n.get() / 2)
        .clamp(1, conns);
    let ready = std::sync::Arc::new(std::sync::Barrier::new(threads));
    let handles: Vec<_> = (0..threads)
        .map(|t| {
            let share = conns / threads + usize::from(t < conns % threads);
            let ready = ready.clone();
            std::thread::spawn(move || drive(addr, share, bytes, time, &ready))
        })
        .collect();
    let mut samples = Vec::new();
    let mut trips = 0u64;
    for h in handles {
        let (n, s) = h.join().expect("load thread");
        trips += n;
        samples.extend(s);
    }
    samples.sort_unstable();
    let pick = |q: f64| {
        samples
            .get(((samples.len() as f64 - 1.0) * q) as usize)
            .copied()
            .unwrap_or(0)
    };
    Measured {
        rate: trips as f64 / time.as_secs_f64(),
        p50: u64::from(pick(0.5)),
        p99: u64::from(pick(0.99)),
        p999: u64::from(pick(0.999)),
        cpu_us: 0.0,
    }
}

/// Keeps one sample in this many, so a fast stack does not pay for its own success.
const SAMPLE_EVERY: u64 = 16;

fn drive(
    addr: SocketAddr,
    conns: usize,
    bytes: usize,
    time: Duration,
    ready: &std::sync::Barrier,
) -> (u64, Vec<u32>) {
    let mut poll = Poll::new().expect("poll");
    let mut all: Vec<Conn> = Vec::with_capacity(conns);
    for i in 0..conns {
        let s = std::net::TcpStream::connect(addr).expect("connect");
        s.set_nodelay(true).expect("nodelay");
        s.set_nonblocking(true).expect("nonblocking");
        let mut stream = TcpStream::from_std(s);
        poll.registry()
            .register(
                &mut stream,
                Token(i),
                Interest::READABLE | Interest::WRITABLE,
            )
            .expect("register");
        all.push(Conn {
            stream,
            wrote: 0,
            read: 0,
            started: Instant::now(),
        });
    }
    // Connecting is not timed: a small backlog makes it slow for some stacks.
    ready.wait();
    let warm = Instant::now() + Duration::from_millis(WARM_MS);
    let until = warm + time;
    let out = vec![7u8; bytes];
    let mut buf = vec![0u8; bytes.max(4096)];
    let mut events = Events::with_capacity(1024);
    let (mut trips, mut seen) = (0u64, 0u64);
    let mut samples = Vec::with_capacity(1 << 20);
    loop {
        let now = Instant::now();
        if now >= until {
            return (trips, samples);
        }
        poll.poll(&mut events, Some(until - now)).expect("wait");
        for e in &events {
            let c = &mut all[e.token().0];
            // Edge-triggered: run the state machine until the socket would block.
            loop {
                if c.wrote < bytes {
                    match c.stream.write(&out[c.wrote..]) {
                        Ok(n) => c.wrote += n,
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(e) => panic!("write: {e}"),
                    }
                    continue;
                }
                match c.stream.read(&mut buf) {
                    Ok(0) => panic!("the server closed"),
                    Ok(n) => {
                        c.read += n;
                        if c.read >= bytes {
                            let now = Instant::now();
                            if now >= warm {
                                trips += 1;
                                seen += 1;
                                if seen % SAMPLE_EVERY == 0 {
                                    let us = (now - c.started).as_micros();
                                    samples.push(u32::try_from(us).unwrap_or(u32::MAX));
                                }
                            }
                            c.read = 0;
                            c.wrote = 0;
                            c.started = now;
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => panic!("read: {e}"),
                }
            }
        }
    }
}

// ---- the servers ------------------------------------------------------------

fn server(stack: &str, addr: SocketAddr, capacity: u32) {
    match stack {
        "std" => std_echo(addr),
        "mio" => mio_echo(addr),
        "tokio" => tokio_echo(addr),
        #[cfg(target_os = "linux")]
        "monoio" => monoio_echo(addr),
        "net-io-pool" => net_io_echo(addr, net_io::DriverKind::Blocking, capacity),
        "net-io" => net_io_echo(addr, net_io::DriverKind::Reactor, capacity),
        other => panic!("unknown stack {other}"),
    }
}

fn std_echo(addr: SocketAddr) {
    let l = std::net::TcpListener::bind(addr).expect("bind");
    for s in l.incoming().flatten() {
        std::thread::spawn(move || {
            let mut s = s;
            s.set_nodelay(true).expect("nodelay");
            let mut buf = vec![0u8; 16 * 1024];
            while let Ok(n) = s.read(&mut buf) {
                if n == 0 || s.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
        });
    }
}

#[tokio::main]
async fn tokio_echo(addr: SocketAddr) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = tokio::net::TcpListener::bind(addr).await.expect("bind");
    loop {
        let (mut s, _) = l.accept().await.expect("accept");
        s.set_nodelay(true).expect("nodelay");
        tokio::spawn(async move {
            let mut buf = vec![0u8; 16 * 1024];
            while let Ok(n) = s.read(&mut buf).await {
                if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                    return;
                }
            }
        });
    }
}

#[cfg(target_os = "linux")]
fn monoio_echo(addr: SocketAddr) {
    use monoio::io::{AsyncReadRent, AsyncWriteRentExt};
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            std::thread::spawn(move || {
                let mut rt = monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
                    .build()
                    .expect("runtime");
                rt.block_on(async move {
                    let opts = monoio::net::ListenerOpts::new().reuse_port(true);
                    let l = monoio::net::TcpListener::bind_with_config(addr, &opts).expect("bind");
                    loop {
                        let (mut s, _) = l.accept().await.expect("accept");
                        s.set_nodelay(true).expect("nodelay");
                        monoio::spawn(async move {
                            let mut buf = vec![0u8; 16 * 1024];
                            loop {
                                let (r, b) = s.read(buf).await;
                                let n = match r {
                                    Ok(n) if n > 0 => n,
                                    _ => return,
                                };
                                let (w, mut b) = s
                                    .write_all(monoio::buf::Slice::new(b, 0, n))
                                    .await
                                    .map_into();
                                if w.is_err() {
                                    return;
                                }
                                b.truncate(16 * 1024);
                                b.resize(16 * 1024, 0);
                                buf = b;
                            }
                        });
                    }
                });
            })
        })
        .collect();
    for h in handles {
        let _ = h.join();
    }
}

#[cfg(target_os = "linux")]
trait MapInto {
    fn map_into(self) -> (std::io::Result<usize>, Vec<u8>);
}

#[cfg(target_os = "linux")]
impl MapInto for (std::io::Result<usize>, monoio::buf::Slice<Vec<u8>>) {
    fn map_into(self) -> (std::io::Result<usize>, Vec<u8>) {
        (self.0, self.1.into_inner())
    }
}

/// A plain event loop per CPU on `mio`, with no runtime and no limits: what a
/// hand-written server costs. Connections go to loops round robin.
fn mio_echo(addr: SocketAddr) {
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let mut senders = Vec::new();
    for _ in 0..threads {
        let (tx, rx) = std::sync::mpsc::channel::<std::net::TcpStream>();
        let poll = Poll::new().expect("poll");
        let waker = std::sync::Arc::new(mio::Waker::new(poll.registry(), WAKE).expect("waker"));
        senders.push((tx, waker));
        std::thread::spawn(move || mio_loop(poll, &rx));
    }
    let l = std::net::TcpListener::bind(addr).expect("bind");
    let mut next = 0;
    for s in l.incoming().flatten() {
        s.set_nodelay(true).expect("nodelay");
        s.set_nonblocking(true).expect("nonblocking");
        let (tx, waker) = &senders[next % threads];
        tx.send(s).expect("send");
        waker.wake().expect("wake");
        next += 1;
    }
}

const WAKE: Token = Token(usize::MAX);

fn mio_loop(mut poll: Poll, rx: &std::sync::mpsc::Receiver<std::net::TcpStream>) {
    let mut conns: Vec<Option<(TcpStream, Vec<u8>)>> = Vec::new();
    let mut events = Events::with_capacity(1024);
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        poll.poll(&mut events, None).expect("wait");
        for e in &events {
            if e.token() == WAKE {
                while let Ok(s) = rx.try_recv() {
                    let mut stream = TcpStream::from_std(s);
                    let token = Token(conns.len());
                    poll.registry()
                        .register(&mut stream, token, Interest::READABLE | Interest::WRITABLE)
                        .expect("register");
                    conns.push(Some((stream, Vec::new())));
                }
                continue;
            }
            let slot = &mut conns[e.token().0];
            let Some((stream, pending)) = slot.as_mut() else {
                continue;
            };
            if mio_turn(stream, pending, &mut buf).is_err() {
                *slot = None;
            }
        }
    }
}

fn mio_turn(stream: &mut TcpStream, pending: &mut Vec<u8>, buf: &mut [u8]) -> std::io::Result<()> {
    loop {
        while !pending.is_empty() {
            match stream.write(pending) {
                Ok(n) => {
                    pending.drain(..n);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(()),
                Err(e) => return Err(e),
            }
        }
        match stream.read(buf) {
            Ok(0) => return Err(ErrorKind::UnexpectedEof.into()),
            Ok(n) => pending.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(()),
            Err(e) => return Err(e),
        }
    }
}

struct Echo;

impl net_io::Session for Echo {
    fn on_data(
        &mut self,
        cx: &mut net_io::SessionContext<'_>,
        input: &mut net_io::Input,
    ) -> net_io::Step {
        // No copy: the filled buffer becomes the output, and an empty one the input.
        let class = input.class();
        if input.bytes().len() >= 8 * 1024 && cx.output().is_empty() {
            if let Some(mut swapped) = cx.buffers().take(class) {
                if input.swap(&mut swapped).is_ok() {
                    return match cx.output().push_buffer(swapped) {
                        Ok(()) => net_io::Step::Write,
                        Err(_) => net_io::Step::Close,
                    };
                }
                cx.release(swapped);
            }
        }
        let taken = cx.output().push_partial(input.bytes());
        input.consume(taken);
        net_io::Step::Write
    }
}

fn net_io_echo(addr: SocketAddr, driver: net_io::DriverKind, cap: u32) {
    use net_io::{AllowAll, ConnectionInfo, Limits, ListenerSpec, PrefixPolicy, ServerBuilder};
    let limits = Limits::builder()
        .max_connections(cap)
        .max_per_source(cap, PrefixPolicy::DEFAULT)
        .backlog(4_096)
        .buffer_budget(1 << 31)
        .build()
        .expect("limits");
    let mut builder = ServerBuilder::new()
        .listener(ListenerSpec::tcp(addr))
        .driver(driver)
        .limits(limits);
    if driver == net_io::DriverKind::Blocking {
        builder = builder.workers(2_048);
    }
    let server = builder
        .sessions(|_: &ConnectionInfo| Echo)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let _ = server.wait_for_stop();
}
