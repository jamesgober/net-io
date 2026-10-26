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
    AdmitStage, Admitted, ConnectionInfo, Denial, Gate, GateTag, Input, Lane, ListenerSpec,
    NetError, Refusal, ServerBuilder, Session, SessionContext, Step, TcpConnection, WriteCheck,
};

const WARM: usize = 2_000;
const ROUNDS: usize = 20_000;
const ROUNDS_OF: usize = 7;
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

fn main() {
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
    let ip = |s: &net_io::Server| s.listeners()[0].local.socket_addr().expect("ip");
    let targets = [
        ("std thread per connection", std_echo()),
        ("net-io blocking handler", ip(&blocking)),
        ("net-io sessions (AllowAll)", ip(&sessions)),
        ("net-io sessions (one atomic)", ip(&gated)),
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
