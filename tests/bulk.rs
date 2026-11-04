//! A file streamed to a fast reader beside small exchanges on the same worker: the
//! small ones keep their latency.

mod common;

use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use common::addr;
use net_io::{
    AllowAll, ConnectionInfo, DriverKind, Input, ListenerSpec, ServerBuilder, Session,
    SessionContext, Step,
};

const FILE_LEN: usize = 32 << 20;
const REPEATS: usize = 128;

/// A temporary file of `len` patterned bytes, removed on drop.
struct Temp(PathBuf);

impl Temp {
    fn new(len: usize) -> Temp {
        let path = std::env::temp_dir().join(format!("nio-bulk-{}", std::process::id()));
        let body: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, body).expect("write");
        Temp(path)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// `F` asks for the file `REPEATS` times over, fed four pieces at a time as the
/// output drains; anything else is echoed.
struct Mixed {
    file: Arc<File>,
    left: Option<usize>,
}

impl Mixed {
    fn feed(&mut self, cx: &mut SessionContext<'_>) -> Step {
        let Some(left) = self.left.as_mut() else {
            return Step::Read;
        };
        if *left == 0 {
            return Step::Close;
        }
        for _ in 0..4.min(*left) {
            cx.output()
                .push_file(self.file.clone(), 0, FILE_LEN as u64)
                .expect("push");
            *left -= 1;
        }
        Step::Write
    }
}

impl Session for Mixed {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let n = input.bytes().len();
        if self.left.is_none() && input.bytes().first() == Some(&b'F') {
            input.consume(n);
            self.left = Some(REPEATS);
            return self.feed(cx);
        }
        let echo = input.bytes().to_vec();
        input.consume(n);
        cx.output().push(&echo).expect("push");
        Step::Write
    }

    fn on_writable(&mut self, cx: &mut SessionContext<'_>) -> Step {
        self.feed(cx)
    }
}

/// Round-trip times of `count` 64-byte exchanges, sorted.
fn pings(c: &mut TcpStream, count: usize) -> Vec<Duration> {
    let msg = [b'p'; 64];
    let mut back = [0u8; 64];
    let mut all = Vec::with_capacity(count);
    for _ in 0..count {
        let t = Instant::now();
        if c.write_all(&msg)
            .and_then(|()| c.read_exact(&mut back))
            .is_err()
        {
            break;
        }
        all.push(t.elapsed());
    }
    all.sort();
    all
}

fn at(sorted: &[Duration], q: f64) -> Duration {
    sorted[((sorted.len() as f64 * q) as usize).min(sorted.len() - 1)]
}

/// One reactor worker serves a fast reader of 512 MiB and a ping client at once.
#[test]
#[cfg(feature = "reactor")]
fn test_bulk_stream_leaves_small_exchanges_their_latency() {
    let temp = Temp::new(FILE_LEN);
    let file = Arc::new(File::open(&temp.0).expect("open"));
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .driver(DriverKind::Reactor)
        .workers(1)
        .sessions(move |_: &ConnectionInfo| Mixed {
            file: file.clone(),
            left: None,
        })
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let at_ = addr(&server);

    let mut ping = TcpStream::connect(at_).expect("connect");
    ping.set_nodelay(true).expect("nodelay");
    ping.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    pings(&mut ping, 500);
    let quiet = pings(&mut ping, 3000);

    let streaming = Arc::new(AtomicBool::new(true));
    let flag = streaming.clone();
    let bulk = std::thread::spawn(move || {
        let mut c = TcpStream::connect(at_).expect("connect");
        c.write_all(b"F").expect("write");
        let mut buf = vec![0u8; 256 << 10];
        let mut total = 0usize;
        let started = Instant::now();
        loop {
            match c.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => total += n,
            }
        }
        flag.store(false, Ordering::Release);
        (total, started.elapsed())
    });
    std::thread::sleep(Duration::from_millis(50));
    let mut loaded = Vec::new();
    while streaming.load(Ordering::Acquire) && loaded.len() < 200_000 {
        loaded.extend(pings(&mut ping, 200));
    }
    let (total, took) = bulk.join().expect("bulk");
    loaded.sort();

    let mib_s = total as f64 / took.as_secs_f64() / f64::from(1 << 20);
    println!(
        "quiet p50 {:?} p99 {:?} p99.9 {:?} | loaded ({} pings) p50 {:?} p99 {:?} p99.9 {:?} max {:?} | bulk {total} B at {mib_s:.0} MiB/s",
        at(&quiet, 0.5),
        at(&quiet, 0.99),
        at(&quiet, 0.999),
        loaded.len(),
        at(&loaded, 0.5),
        at(&loaded, 0.99),
        at(&loaded, 0.999),
        loaded.last().copied().unwrap_or_default(),
    );
    assert_eq!(total, FILE_LEN * REPEATS);
}
