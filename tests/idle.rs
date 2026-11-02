//! An idle connection on the reactor costs state, not buffers.
//!
//! Its own test binary: it installs an allocator that tracks live bytes. The count
//! is `NET_IO_IDLE_CONNECTIONS` (default 100, within a stock descriptor limit); the
//! `idle` CI job runs 10,000 under a raised limit.

#![cfg(feature = "reactor")]

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use common::{addr, eventually};
use net_io::{
    AllowAll, ConnectionInfo, DriverKind, Input, Limits, ListenerSpec, PrefixPolicy, ServerBuilder,
    Session, SessionContext, SizeClass, Step,
};

struct Tracking;

static LIVE: AtomicI64 = AtomicI64::new(0);

// SAFETY: forwards to the system allocator; only counts.
unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE.fetch_add(layout.size() as i64, Ordering::Relaxed);
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as i64, Ordering::Relaxed);
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LIVE.fetch_add(new_size as i64 - layout.size() as i64, Ordering::Relaxed);
        // SAFETY: same contract as the caller's.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Tracking = Tracking;

struct Echo;

impl Session for Echo {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let taken = cx.output().push_partial(input.bytes());
        input.consume(taken);
        Step::Write
    }
}

#[test]
fn test_idle_connections_hold_no_buffers() {
    let count: u32 = std::env::var("NET_IO_IDLE_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100);
    let limits = Limits::builder()
        .max_connections(count + 16)
        .max_per_source(count + 16, PrefixPolicy::DEFAULT)
        .backlog(4096)
        .idle_timeout(Duration::from_secs(600))
        .build()
        .expect("limits");
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .driver(DriverKind::Reactor)
        .workers(2)
        .limits(limits)
        .sessions(|_: &ConnectionInfo| Echo)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let target = addr(&server);

    // One exchange first: the workers' start-up does not count against connections.
    let mut first = TcpStream::connect(target).expect("connect");
    first.write_all(b"warm").expect("write");
    let mut back = [0u8; 4];
    first.read_exact(&mut back).expect("read");

    // The clients' sockets are measured with the server's state; `Vec` is sized
    // first so its growth does not count.
    let mut clients: Vec<TcpStream> = Vec::with_capacity(count as usize);
    let before = LIVE.load(Ordering::Relaxed);
    for _ in 0..count {
        clients.push(TcpStream::connect(target).expect("connect"));
    }
    let open = u64::from(count) + 1;
    assert!(
        eventually(Duration::from_secs(60), || server.stats().open == open),
        "{:?}",
        server.stats()
    );
    std::thread::sleep(Duration::from_millis(100));
    let per = (LIVE.load(Ordering::Relaxed) - before) / i64::from(count);
    eprintln!("{count} idle connections: {per} bytes of heap each");
    // State and bookkeeping, no input buffer. The bound holds the design: at least
    // one small buffer per connection would exceed it.
    assert!(
        per < i64::from(SizeClass::SMALL.bytes()),
        "{per} bytes per idle connection"
    );

    // They still work.
    for c in clients.iter_mut().step_by(97) {
        c.write_all(b"ping").expect("write");
        c.read_exact(&mut back).expect("read");
        assert_eq!(&back, b"ping");
    }
}
