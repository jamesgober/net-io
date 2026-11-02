//! Echo baselines on loopback (B-2, and B-7 as a difference between two gates).
//!
//! ```text
//! cargo bench --bench echo
//! ```
//!
//! One connection, 64-byte messages, one round trip at a time. Prints round
//! trips per second, p50 and p99 for: a std thread-per-connection echo, the
//! net-io blocking handler, net-io sessions, and net-io sessions behind a gate
//! that does one atomic add per write. Loopback numbers measure the per-message
//! overhead of each stack, not network behaviour.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use net_io::{
    AdmitStage, Admitted, AllowAll, ConnectionInfo, Denial, DriverKind, Gate, GateTag, Input, Lane,
    Limits, ListenerSpec, NetError, PrefixPolicy, Refusal, ServerBuilder, Session, SessionContext,
    Step, TcpConnection, WriteCheck,
};

const WARM: usize = 2_000;
const ROUNDS: usize = 20_000;
const ROUNDS_OF: usize = 7;
const MANY: [usize; 2] = [64, 256];
const MANY_ROUNDS: usize = 2_000;
const CLIENT_THREADS: usize = 8;
const MSG: usize = 64;

struct Echo;

impl Session for Echo {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let taken = cx.output().push_partial(input.bytes());
        input.consume(taken);
        Step::Write
    }
}

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

/// One atomic add per write: the cheapest gate that does real work.
#[derive(Default)]
struct OneAtomic(AtomicU64);

impl Gate for OneAtomic {
    type Ticket = ();
    fn admit(&self, _info: &ConnectionInfo, _stage: AdmitStage) -> Result<Admitted<()>, Refusal> {
        Ok(Admitted {
            lane: Lane(0),
            ticket: (),
            tag: GateTag(0),
        })
    }
    fn readmit(&self, _ticket: &mut (), _info: &ConnectionInfo) -> Result<(), Refusal> {
        Ok(())
    }
    fn check(&self, _ticket: &mut (), write: &WriteCheck) -> Result<(), Denial> {
        self.0.fetch_add(u64::from(write.bytes), Ordering::Relaxed);
        Ok(())
    }
}

fn std_echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = s;
                let _ = s.set_nodelay(true);
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

fn measure(addr: SocketAddr) -> (f64, Duration, Duration) {
    let mut c = TcpStream::connect(addr).expect("connect");
    c.set_nodelay(true).expect("nodelay");
    let msg = [7u8; MSG];
    let mut back = [0u8; MSG];
    for _ in 0..WARM {
        c.write_all(&msg).expect("write");
        c.read_exact(&mut back).expect("read");
    }
    let mut lat = Vec::with_capacity(ROUNDS);
    let start = Instant::now();
    for _ in 0..ROUNDS {
        let t = Instant::now();
        c.write_all(&msg).expect("write");
        c.read_exact(&mut back).expect("read");
        lat.push(t.elapsed());
    }
    let total = start.elapsed();
    lat.sort_unstable();
    (
        ROUNDS as f64 / total.as_secs_f64(),
        lat[ROUNDS / 2],
        lat[ROUNDS * 99 / 100],
    )
}

fn us(d: Duration) -> f64 {
    d.as_secs_f64() * 1e6
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

/// Round trips per second over `many` connections at once, shared among a few client
/// threads: one client thread per connection would take the CPU from a reactor's
/// fewer threads and measure the scheduler.
fn measure_many(addr: SocketAddr, many: usize) -> f64 {
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(CLIENT_THREADS));
    let threads: Vec<_> = (0..CLIENT_THREADS)
        .map(|_| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut conns: Vec<TcpStream> = (0..many / CLIENT_THREADS)
                    .map(|_| {
                        let c = TcpStream::connect(addr).expect("connect");
                        c.set_nodelay(true).expect("nodelay");
                        c
                    })
                    .collect();
                let mut buf = [1u8; MSG];
                barrier.wait();
                for _ in 0..MANY_ROUNDS {
                    for c in &mut conns {
                        c.write_all(&buf).expect("write");
                    }
                    for c in &mut conns {
                        c.read_exact(&mut buf).expect("read");
                    }
                }
            })
        })
        .collect();
    let start = Instant::now();
    for t in threads {
        t.join().expect("client");
    }
    (many / CLIENT_THREADS * CLIENT_THREADS * MANY_ROUNDS) as f64 / start.elapsed().as_secs_f64()
}

/// This process's CPU time so far (Linux; elsewhere 0, and the line is skipped).
fn cpu_seconds() -> f64 {
    let Ok(stat) = std::fs::read_to_string("/proc/self/stat") else {
        return 0.0;
    };
    let after = stat.rsplit(')').next().unwrap_or("");
    let fields: Vec<&str> = after.split_whitespace().collect();
    let ticks = |i: usize| {
        fields
            .get(i)
            .and_then(|f| f.parse::<f64>().ok())
            .unwrap_or(0.0)
    };
    (ticks(11) + ticks(12)) / 100.0
}

fn many_connections(many: usize) {
    let workers: u16 = std::env::var("NET_IO_BENCH_WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get() as u16));
    let reactor = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .driver(DriverKind::Reactor)
        .workers(workers)
        .sessions(|_: &ConnectionInfo| Echo)
        .gate(AllowAll)
        .build()
        .expect("build");
    reactor.open_door().expect("open");
    let pool = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .driver(DriverKind::Blocking)
        .workers(2 * many as u16)
        .limits(
            Limits::builder()
                .max_per_source(2 * many as u32, PrefixPolicy::DEFAULT)
                .build()
                .expect("limits"),
        )
        .sessions(|_: &ConnectionInfo| Echo)
        .gate(AllowAll)
        .build()
        .expect("build");
    pool.open_door().expect("open");
    let ip = |s: &net_io::Server| s.listeners()[0].local.socket_addr().expect("ip");
    let (mut a, mut b) = (Vec::new(), Vec::new());
    let (mut cpu_a, mut cpu_b) = (0.0, 0.0);
    for _ in 0..ROUNDS_OF {
        let t0 = cpu_seconds();
        b.push(measure_many(ip(&pool), many));
        let t1 = cpu_seconds();
        a.push(measure_many(ip(&reactor), many));
        let t2 = cpu_seconds();
        cpu_b += t1 - t0;
        cpu_a += t2 - t1;
    }
    let (a, b) = (median(a), median(b));
    let trips = (many / CLIENT_THREADS * CLIENT_THREADS * MANY_ROUNDS * ROUNDS_OF) as f64;
    if cpu_a > 0.0 {
        println!(
            "CPU per round trip, both ends: blocking {:.1} us, reactor {:.1} us",
            cpu_b / trips * 1e6,
            cpu_a / trips * 1e6
        );
    }
    println!("B-1 echo, {MSG} B, {many} connections at once (loopback, medians)");
    println!("net-io blocking pool        {b:>9.0} rt/s");
    println!(
        "net-io reactor              {a:>9.0} rt/s  {:.2}x blocking",
        a / b
    );
}

fn main() {
    for many in MANY {
        many_connections(many);
    }
    // Start every server first, then measure them in rotating order over several
    // rounds and report medians: on a multi-die CPU, where the scheduler places the
    // client and server threads moves single runs by 2x, in either direction.
    let blocking = net_io::serve("127.0.0.1:0", echo_handler).expect("serve");
    let sessions = net_io::serve_sessions("127.0.0.1:0", |_: &ConnectionInfo| Echo).expect("serve");
    let gated = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .sessions(|_: &ConnectionInfo| Echo)
        .gate(OneAtomic::default())
        .build()
        .expect("build");
    gated.open_door().expect("open");
    let pool = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .driver(DriverKind::Blocking)
        .sessions(|_: &ConnectionInfo| Echo)
        .gate(AllowAll)
        .build()
        .expect("build");
    pool.open_door().expect("open");
    let ip = |s: &net_io::Server| s.listeners()[0].local.socket_addr().expect("ip");
    let targets = [
        ("std thread per connection", std_echo()),
        ("net-io blocking handler", ip(&blocking)),
        ("net-io sessions (AllowAll)", ip(&sessions)),
        ("net-io sessions (one atomic)", ip(&gated)),
        ("net-io sessions (blocking)", ip(&pool)),
    ];
    let mut results: Vec<Vec<(f64, Duration, Duration)>> = vec![Vec::new(); targets.len()];
    for round in 0..ROUNDS_OF {
        for k in 0..targets.len() {
            let i = (k + round) % targets.len();
            results[i].push(measure(targets[i].1));
        }
    }
    println!(
        "B-2 echo, {MSG} B, 1 connection, {ROUNDS} round trips x {ROUNDS_OF} rounds (loopback, medians)"
    );
    let med: Vec<(f64, f64, f64)> = results
        .iter()
        .map(|r| {
            (
                median(r.iter().map(|x| x.0).collect()),
                median(r.iter().map(|x| us(x.1)).collect()),
                median(r.iter().map(|x| us(x.2)).collect()),
            )
        })
        .collect();
    for (i, (name, _)) in targets.iter().enumerate() {
        let (rts, p50, p99) = med[i];
        let ratio = if i == 0 {
            String::new()
        } else {
            format!("  {:.2}x std", rts / med[0].0)
        };
        println!("{name:<28} {rts:>9.0} rt/s  p50 {p50:>6.1} us  p99 {p99:>6.1} us{ratio}");
    }
    let per_write = (med[3].1 - med[2].1) * 1000.0;
    println!(
        "B-7 gate check: p50 difference one-atomic vs AllowAll {per_write:.0} ns per round trip (one write each; below ~200 ns this is noise)"
    );
}
