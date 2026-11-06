//! The soak (NFR-17): normal clients, a pooled client that reconnects through
//! kills, big writers whose replies take several output buffers a flush, and
//! hostile peers (slowloris, slow readers, idle hoarders, floods at the
//! cap) against one server, while memory, descriptors or handles, and open
//! connections are sampled.
//!
//! `NET_IO_SOAK_SECS` sets the length (default 15; the release soak is 86,400),
//! `NET_IO_SOAK_SAMPLE_SECS` the sampling interval (default 5), and
//! `NET_IO_SOAK_DRIVER` `blocking` or `reactor` (default: the server's choice).
//! It passes when no normal, pooled, or big exchange got stuck, no connection was
//! closed for want of buffer budget, every hostile peer was
//! closed by its limit, memory in the last quarter is within 10% (plus 8 MiB) of
//! the second quarter, and once the clients stop, every connection closes and the
//! descriptor or handle count returns to where it was before the server started.
//! Its own test binary: other tests' sockets would change the counts.

mod common;

use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use net_io::{
    AllowAll, Backoff, CloseReason, ConnectOptions, ConnectionId, ConnectionInfo, DriverKind,
    Event, EventSink, Health, Input, KillReason, LimitKind, Limits, ListenerSpec, MinRate,
    PrefixPolicy, ServerBuilder, Session, SessionContext, Step, TcpConnection,
};

/// One megabyte, sent sixteen times to `B` requests: what a slow reader is asked to take.
static BIG: [u8; 1 << 20] = [b'b'; 1 << 20];

/// What `W` asks for: copied out three output buffers a flush, the shape that
/// spent 0.6.0's buffer budget within seconds (D-169).
const STREAM: usize = 4 << 20;
static BLOCK: [u8; 48 << 10] = [b'w'; 48 << 10];

/// `B` asks for 16 MiB, more than socket buffers hold; `W` for `STREAM` bytes;
/// complete lines are echoed, so a peer that never finishes one is a slowloris to
/// the server.
#[derive(Default)]
struct Soak {
    left: usize,
}

impl Session for Soak {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        if input.bytes().first() == Some(&b'W') {
            let n = input.bytes().len();
            input.consume(n);
            self.left = STREAM;
            return self.on_writable(cx);
        }
        if input.bytes().first() == Some(&b'B') {
            let n = input.bytes().len();
            input.consume(n);
            for _ in 0..16 {
                let _ = cx.output().push_static(&BIG);
            }
            return Step::Close;
        }
        let Some(end) = input.bytes().iter().rposition(|&b| b == b'\n') else {
            return Step::Read;
        };
        let taken = cx.output().push_partial(&input.bytes()[..=end]);
        input.consume(taken);
        Step::Write
    }

    fn on_writable(&mut self, cx: &mut SessionContext<'_>) -> Step {
        if self.left == 0 {
            return Step::Read;
        }
        let want = self.left.min(BLOCK.len());
        let mut at = 0;
        while at < want {
            let n = cx.output().push_partial(&BLOCK[at..want]);
            if n == 0 {
                break;
            }
            at += n;
        }
        self.left -= at;
        Step::Write
    }
}

/// Keeps the ids of recent connections, for the thread that kills some of them.
#[derive(Clone, Default)]
struct Recent(Arc<Mutex<VecDeque<ConnectionId>>>);

impl EventSink for Recent {
    fn event(&self, e: &Event) {
        if let Event::Accepted { id, .. } = e {
            if let Ok(mut q) = self.0.lock() {
                if q.len() >= 256 {
                    q.pop_front();
                }
                q.push_back(*id);
            }
        }
    }
}

#[derive(Default)]
struct Counts {
    exchanges: AtomicU64,
    big: AtomicU64,
    stuck: AtomicU64,
    pool_reconnects: AtomicU64,
    hostile_closed: AtomicU64,
    hostile_held: AtomicU64,
    held_slowloris: AtomicU64,
    held_slow_reader: AtomicU64,
    held_hoarder: AtomicU64,
    kills: AtomicU64,
}

fn env_secs(name: &str, default: u64) -> Duration {
    Duration::from_secs(
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default),
    )
}

/// A small xorshift, so the run needs no dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

/// The resident set and the open descriptors or handles of this process.
fn sample() -> (u64, u64) {
    (resident_bytes(), descriptors())
}

#[cfg(target_os = "linux")]
fn resident_bytes() -> u64 {
    let statm = std::fs::read_to_string("/proc/self/statm").unwrap_or_default();
    let pages: u64 = statm
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    pages * 4096
}

#[cfg(all(unix, not(target_os = "linux")))]
fn resident_bytes() -> u64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output();
    out.ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map_or(0, |kib| kib * 1024)
}

#[cfg(unix)]
fn descriptors() -> u64 {
    let dir = if cfg!(target_os = "linux") {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    };
    std::fs::read_dir(dir).map_or(0, |d| d.count() as u64)
}

#[cfg(windows)]
fn resident_bytes() -> u64 {
    use windows_sys::Win32::System::ProcessStatus::{
        K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    // SAFETY: PROCESS_MEMORY_COUNTERS is plain data; all zeroes is a valid value.
    let mut c: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
    c.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    // SAFETY: `c` is a live, correctly sized PROCESS_MEMORY_COUNTERS.
    let ok = unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &raw mut c, c.cb) };
    if ok == 0 { 0 } else { c.WorkingSetSize as u64 }
}

#[cfg(windows)]
fn descriptors() -> u64 {
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};
    let mut n = 0u32;
    // SAFETY: the pseudo-handle of this process and a live u32.
    let ok = unsafe { GetProcessHandleCount(GetCurrentProcess(), &raw mut n) };
    if ok == 0 { 0 } else { u64::from(n) }
}

fn std_client(at: SocketAddr) -> Option<TcpStream> {
    let s = TcpStream::connect_timeout(&at, Duration::from_secs(5)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
    s.set_write_timeout(Some(Duration::from_secs(10))).ok()?;
    s.set_nodelay(true).ok()?;
    Some(s)
}

fn client_options() -> ConnectOptions {
    ConnectOptions::new()
        .timeout(Duration::from_secs(5))
        .limits(
            Limits::builder()
                .read_timeout(Duration::from_secs(10))
                .write_timeout(Duration::from_secs(10))
                .build()
                .expect("limits"),
        )
}

/// Whether a client error means the server stopped answering (not a kill or a
/// refusal, which the run causes on purpose).
fn stuck(e: &net_io::NetError) -> bool {
    let timed_out = matches!(e, net_io::NetError::TimedOut { .. });
    if timed_out {
        eprintln!("stuck: {e:?}");
    }
    timed_out
}

/// Connect, a few echoes of mixed sizes, then a reset (one in fifty closes
/// gracefully: a client that closes first keeps its port in TIME_WAIT, and Windows
/// has 16,384 of them for two minutes each).
fn normal(at: SocketAddr, stop: &AtomicBool, counts: &Counts, seed: u64) {
    let mut rng = Rng(seed | 1);
    let mut buf = vec![0u8; 16 << 10];
    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(20));
        let Ok(mut c) = TcpConnection::connect_with(at, client_options()) else {
            // Refused at the cap by the flood: try again shortly.
            continue;
        };
        let mut alive = true;
        for _ in 0..1 + rng.below(20) {
            let n = 2 + rng.below(2 << 10) as usize;
            let msg: Vec<u8> = (0..n - 1)
                .map(|i| b'a' + (i % 26) as u8)
                .chain(std::iter::once(b'\n'))
                .collect();
            match c.send_all(&msg).and_then(|()| c.recv_exact(&mut buf[..n])) {
                Ok(()) => {
                    assert_eq!(&buf[..n], &msg[..], "echo differs");
                    counts.exchanges.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    if stuck(&e) {
                        counts.stuck.fetch_add(1, Ordering::Relaxed);
                    }
                    alive = false;
                    break;
                }
            }
        }
        if alive && rng.below(50) == 0 {
            let _ = c.drain(Duration::from_millis(500));
        } else {
            c.abort();
        }
    }
}

/// Asks for `STREAM` bytes and reads them at full speed, again and again.
fn big_writer(at: SocketAddr, stop: &AtomicBool, counts: &Counts) {
    let mut buf = vec![0u8; 256 << 10];
    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(20));
        let Ok(mut c) = TcpConnection::connect_with(at, client_options()) else {
            continue;
        };
        let mut left = STREAM;
        let mut result = c.send_all(b"W");
        while result.is_ok() && left > 0 {
            let n = left.min(buf.len());
            result = c.recv_exact(&mut buf[..n]);
            left -= n;
        }
        match result {
            Ok(()) => {
                counts.big.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                if stuck(&e) {
                    counts.stuck.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        c.abort();
    }
}

/// A pool of connections a database client would keep: probe before reuse,
/// reconnect with backoff after a kill, drain when shrinking.
fn pooled(at: SocketAddr, stop: &AtomicBool, counts: &Counts, seed: u64) {
    let mut rng = Rng(seed | 1);
    let mut pool: Vec<TcpConnection> = Vec::new();
    let mut backoff = Backoff::new()
        .first(Duration::from_millis(5))
        .max(Duration::from_millis(200))
        .give_up_after(Duration::from_secs(30));
    while !stop.load(Ordering::Relaxed) {
        let reuse = pool
            .pop()
            .and_then(|mut c| matches!(c.probe(), Ok(Health::Open)).then_some(c));
        let mut conn = match reuse {
            Some(c) => c,
            None => {
                counts.pool_reconnects.fetch_add(1, Ordering::Relaxed);
                match TcpConnection::connect_retry(at, client_options(), &mut backoff) {
                    Ok(c) => {
                        backoff.reset();
                        c
                    }
                    Err(e) => {
                        eprintln!("pool could not reconnect: {e:?}");
                        counts.stuck.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                }
            }
        };
        let mut msg = [b'q'; 128];
        msg[127] = b'\n';
        let mut back = [0u8; 128];
        match conn
            .send_all(&msg)
            .and_then(|()| conn.recv_exact(&mut back))
        {
            Err(e) if stuck(&e) => {
                counts.stuck.fetch_add(1, Ordering::Relaxed);
            }
            Ok(()) => {
                counts.exchanges.fetch_add(1, Ordering::Relaxed);
                if pool.len() < 8 {
                    pool.push(conn);
                } else {
                    let _ = conn.drain(Duration::from_millis(500));
                }
            }
            // Killed while in the pool or mid-exchange: the next turn reconnects.
            Err(_) => {}
        }
        // Shrink now and then: a drain closes from the client's side, and each such
        // close keeps a port in TIME_WAIT (two minutes on Windows, 16,384 ports).
        if rng.below(2_000) == 0 {
            if let Some(c) = pool.pop() {
                let _ = c.drain(Duration::from_millis(500));
            }
        }
    }
    for c in pool {
        let _ = c.drain(Duration::from_millis(500));
    }
}

/// One byte every 400 ms until the server closes the connection.
fn slowloris(at: SocketAddr, stop: &AtomicBool, counts: &Counts, limit: Duration) {
    while !stop.load(Ordering::Relaxed) {
        let Some(mut c) = std_client(at) else {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        };
        let started = Instant::now();
        loop {
            if c.write_all(b"x").is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(400));
            if stop.load(Ordering::Relaxed) {
                return;
            }
            if started.elapsed() > limit {
                counts.hostile_held.fetch_add(1, Ordering::Relaxed);
                counts.held_slowloris.fetch_add(1, Ordering::Relaxed);
                break;
            }
        }
        counts.hostile_closed.fetch_add(1, Ordering::Relaxed);
    }
}

/// Asks for 16 MiB and takes 64 bytes a second, through a 64 KiB receive buffer.
fn slow_reader(at: SocketAddr, stop: &AtomicBool, counts: &Counts, limit: Duration) {
    while !stop.load(Ordering::Relaxed) {
        // Its own side measures nothing: only the server's limits may end this.
        let limits = Limits::builder()
            .read_timeout(Duration::from_secs(30))
            .min_rate(MinRate::off())
            .build()
            .expect("limits");
        let options = client_options()
            .limits(limits)
            .tcp_options(net_io::TcpOptions::new().receive_buffer(64 << 10));
        let Ok(mut c) = TcpConnection::connect_with(at, options) else {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        };
        let _ = c.send_all(b"B");
        let started = Instant::now();
        let mut buf = [0u8; 64];
        loop {
            match c.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            // The server's reset is pending on the socket, but Linux hands back what
            // is already in the receive buffer first: at 64 bytes a second that is
            // minutes, so the reset is read from `SO_ERROR` instead.
            if matches!(c.take_error(), Ok(Some(_)) | Err(_)) {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
            if stop.load(Ordering::Relaxed) {
                return;
            }
            if started.elapsed() > limit {
                // Only Linux keeps loopback buffers to what was set: elsewhere the
                // kernel takes all 16 MiB, the server finishes and closes, and the
                // reader is left with the kernel's copy (see `tests/server.rs`,
                // `test_reader_slower_than_the_rate_is_closed_while_it_reads`).
                if cfg!(target_os = "linux") {
                    counts.hostile_held.fetch_add(1, Ordering::Relaxed);
                }
                counts.held_slow_reader.fetch_add(1, Ordering::Relaxed);
                break;
            }
        }
        counts.hostile_closed.fetch_add(1, Ordering::Relaxed);
    }
}

/// Twenty silent connections at a time, until the idle timeout closes them.
fn hoarder(at: SocketAddr, stop: &AtomicBool, counts: &Counts, limit: Duration) {
    while !stop.load(Ordering::Relaxed) {
        let held: Vec<TcpStream> = (0..20).filter_map(|_| std_client(at)).collect();
        let started = Instant::now();
        for mut c in held {
            let mut b = [0u8; 1];
            let left = limit
                .saturating_sub(started.elapsed())
                .max(Duration::from_millis(1));
            let _ = c.set_read_timeout(Some(left));
            match c.read(&mut b) {
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    counts.hostile_held.fetch_add(1, Ordering::Relaxed);
                    counts.held_hoarder.fetch_add(1, Ordering::Relaxed);
                }
                _ => {
                    counts.hostile_closed.fetch_add(1, Ordering::Relaxed);
                }
            }
            if stop.load(Ordering::Relaxed) {
                return;
            }
        }
    }
}

/// Bursts of 200 connections at once, reset at once.
fn flood(at: SocketAddr, stop: &AtomicBool) {
    while !stop.load(Ordering::Relaxed) {
        let burst: Vec<TcpConnection> = (0..200)
            .filter_map(|_| TcpConnection::connect_with(at, client_options()).ok())
            .collect();
        for c in burst {
            c.abort();
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// One client loop, given the stop flag and the counts.
type Client = Box<dyn FnOnce(&AtomicBool, &Counts) + Send>;

/// Every kind of client the run uses, on its own threads.
fn clients(
    at: SocketAddr,
    stop: &Arc<AtomicBool>,
    counts: &Arc<Counts>,
    limit: Duration,
) -> Vec<std::thread::JoinHandle<()>> {
    let mut threads = Vec::new();
    let mut spawn = |f: Client| {
        let (stop, counts) = (stop.clone(), counts.clone());
        threads.push(std::thread::spawn(move || f(&stop, &counts)));
    };
    for i in 0..8u64 {
        spawn(Box::new(move |s, c| normal(at, s, c, 0x9e37 + i)));
    }
    for i in 0..4u64 {
        spawn(Box::new(move |s, c| pooled(at, s, c, 0x51ed + i)));
    }
    for _ in 0..4 {
        spawn(Box::new(move |s, c| big_writer(at, s, c)));
    }
    for _ in 0..4 {
        spawn(Box::new(move |s, c| slowloris(at, s, c, limit)));
    }
    for _ in 0..2 {
        spawn(Box::new(move |s, c| slow_reader(at, s, c, limit)));
        spawn(Box::new(move |s, c| hoarder(at, s, c, limit)));
    }
    spawn(Box::new(move |s, _| flood(at, s)));
    threads
}

fn warm_up(driver: DriverKind, workers: u16) {
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .driver(driver)
        .workers(workers)
        .sessions(|_: &ConnectionInfo| Soak::default())
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let at = common::addr(&server);
    // The same clients as the run, for two seconds: their first sockets and threads
    // make handles the OS keeps (six servers in a row leave the count where it was).
    let stop = Arc::new(AtomicBool::new(false));
    let counts = Arc::new(Counts::default());
    let threads = clients(at, &stop, &counts, Duration::from_secs(20));
    std::thread::sleep(Duration::from_secs(2));
    stop.store(true, Ordering::Relaxed);
    for t in threads {
        let _ = t.join();
    }
    let _ = server.shutdown(Instant::now() + Duration::from_secs(2));
}

#[test]
fn test_soak_with_normal_and_hostile_peers() {
    let length = env_secs("NET_IO_SOAK_SECS", 15);
    let every = env_secs("NET_IO_SOAK_SAMPLE_SECS", 5).max(Duration::from_secs(1));
    let driver = match std::env::var("NET_IO_SOAK_DRIVER").as_deref() {
        Ok("blocking") => DriverKind::Blocking,
        Ok("reactor") => DriverKind::Reactor,
        _ => DriverKind::Auto,
    };
    // Hostile peers must be closed well within this; the limits below add up to 6 s.
    let hostile_limit = Duration::from_secs(20);

    // The baseline after one server has run and stopped: the first sockets and
    // completion ports make handles the OS keeps for the life of the process.
    // The driver that runs: `Auto` is the pool without the `reactor` feature or
    // with `net_io_force_blocking`, and the pool needs a thread per connection.
    let pool = driver == DriverKind::Blocking
        || (driver == DriverKind::Auto
            && (cfg!(not(feature = "reactor")) || cfg!(net_io_force_blocking)));
    let workers: u16 = if pool { 256 } else { 4 };
    warm_up(driver, workers);
    let (_, baseline_descriptors) = sample();
    let recent = Recent::default();
    let limits = Limits::builder()
        .max_connections(1_500)
        .max_per_source(1_500, PrefixPolicy::DEFAULT)
        .idle_timeout(Duration::from_secs(2))
        .read_timeout(Duration::from_secs(2))
        .write_timeout(Duration::from_secs(4))
        .min_rate(MinRate {
            bytes_per_sec: 1_024,
            window: Duration::from_secs(3),
            grace: Duration::from_secs(1),
            check: Duration::from_secs(1),
        })
        .build()
        .expect("limits");
    let server = ServerBuilder::new()
        // A bounded send buffer, as an internet-facing Windows listener should have
        // (register R-4): otherwise the kernel takes a slow reader's whole reply.
        .listener(ListenerSpec::tcp_with(
            "127.0.0.1:0",
            net_io::ListenOptions::new().send_buffer(64 << 10),
        ))
        .driver(driver)
        .workers(workers)
        .limits(limits)
        .sessions(|_: &ConnectionInfo| Soak::default())
        .gate(AllowAll)
        .events(recent.clone())
        .build()
        .expect("build");
    server.open_door().expect("open");
    let at = common::addr(&server);
    let stop = Arc::new(AtomicBool::new(false));
    let counts = Arc::new(Counts::default());

    let mut threads = clients(at, &stop, &counts, hostile_limit);
    {
        // Kills a recent connection every 200 ms, as an operator or a gate would.
        let (stop, counts, recent) = (stop.clone(), counts.clone(), recent.clone());
        let handle = server.handle();
        threads.push(std::thread::spawn(move || {
            let mut rng = Rng(0x2545);
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(200));
                let id = recent.0.lock().ok().and_then(|q| {
                    let n = q.len() as u64;
                    (n > 0).then(|| q[rng.below(n) as usize])
                });
                if let Some(id) = id {
                    if handle.kill(id, KillReason(7)) {
                        counts.kills.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    let started = Instant::now();
    let mut samples: Vec<(Duration, u64, u64, u64)> = Vec::new();
    while started.elapsed() < length {
        std::thread::sleep(every.min(length.saturating_sub(started.elapsed())));
        let (rss, fds) = sample();
        let open = server.stats().open;
        let t = started.elapsed();
        println!(
            "soak {:>7.0}s rss {:>6} KiB handles {:>5} open {:>5} exchanges {} big {} stuck {} reconnects {} hostile closed {} held {} kills {}",
            t.as_secs_f64(),
            rss / 1024,
            fds,
            open,
            counts.exchanges.load(Ordering::Relaxed),
            counts.big.load(Ordering::Relaxed),
            counts.stuck.load(Ordering::Relaxed),
            counts.pool_reconnects.load(Ordering::Relaxed),
            counts.hostile_closed.load(Ordering::Relaxed),
            counts.hostile_held.load(Ordering::Relaxed),
            counts.kills.load(Ordering::Relaxed),
        );
        samples.push((t, rss, fds, open));
    }
    stop.store(true, Ordering::Relaxed);
    for t in threads {
        t.join().expect("client thread");
    }

    let stats = server.stats();
    println!("{stats:?}");
    println!(
        "held: slowloris {} slow readers {} hoarders {}",
        counts.held_slowloris.load(Ordering::Relaxed),
        counts.held_slow_reader.load(Ordering::Relaxed),
        counts.held_hoarder.load(Ordering::Relaxed)
    );
    assert_eq!(counts.stuck.load(Ordering::Relaxed), 0, "stuck exchanges");
    assert_eq!(
        counts.hostile_held.load(Ordering::Relaxed),
        0,
        "a hostile peer outlived its limits"
    );
    assert!(counts.exchanges.load(Ordering::Relaxed) > 0);
    assert!(
        counts.big.load(Ordering::Relaxed) > 0,
        "no big reply finished"
    );
    assert_eq!(
        stats.closed_for(CloseReason::Limit(LimitKind::BufferBudget)),
        0,
        "closed for want of buffer budget"
    );
    assert!(counts.hostile_closed.load(Ordering::Relaxed) > 0);
    assert!(
        common::eventually(Duration::from_secs(15), || server.stats().open == 0),
        "connections left open: {:?}",
        server.stats()
    );
    if samples.len() >= 8 {
        let quarter = samples.len() / 4;
        let median = |s: &[(Duration, u64, u64, u64)]| {
            let mut v: Vec<u64> = s.iter().map(|x| x.1).collect();
            v.sort_unstable();
            v[v.len() / 2]
        };
        let second = median(&samples[quarter..2 * quarter]);
        let last = median(&samples[3 * quarter..]);
        assert!(
            last <= second + second / 10 + (8 << 20),
            "memory grew: {} KiB to {} KiB",
            second / 1024,
            last / 1024
        );
    }
    let _ = server.shutdown(Instant::now() + Duration::from_secs(5));
    // Unix counts descriptors, exactly. Windows counts every kernel handle, and a run
    // ends 15 above its warm-up whether it lasted 30 s or 150 s, with the same
    // clients and the same server: a cost of the run's shape, not of its length.
    // A leak per connection would be millions over a soak.
    let slack = if cfg!(windows) { 32 } else { 8 };
    let after = common::eventually(Duration::from_secs(10), || {
        sample().1 <= baseline_descriptors + slack
    });
    assert!(
        after,
        "descriptors or handles: {} before the server, {} after",
        baseline_descriptors,
        sample().1
    );
}
