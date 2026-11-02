//! Steady-state echo on an established connection allocates nothing on the server.
//!
//! Its own test binary: it installs a counting global allocator.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};

use common::{DRIVERS, addr, client, round_trip};
use net_io::{
    AllowAll, ConnectionInfo, DriverKind, Input, ListenerSpec, ServerBuilder, Session,
    SessionContext, Step,
};

struct Counting;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

// SAFETY: forwards to the system allocator; only counts.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: same contract as the caller's.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

struct Echo;

impl Session for Echo {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let taken = cx.output().push_partial(input.bytes());
        input.consume(taken);
        Step::Write
    }
}

/// Hands the filled input to the output with no copy.
struct Swapper;

impl Session for Swapper {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let class = input.class();
        if input.is_full() {
            if let Some(mut swapped) = cx.buffers().take(class) {
                input.swap(&mut swapped).expect("same class, empty");
                cx.output().push_buffer(swapped).expect("room");
                return Step::Write;
            }
        }
        let taken = cx.output().push_partial(input.bytes());
        input.consume(taken);
        Step::Write
    }
}

/// Allocations in 1,000 round trips of `size` bytes, after the pools have warmed up.
fn allocations<S, F>(driver: DriverKind, size: usize, sessions: F) -> u64
where
    S: Session,
    F: Fn(&ConnectionInfo) -> S + Send + Sync + 'static,
{
    // One worker, so the warm-up runs on the same thread as the measurement and no
    // worker thread is still starting (thread start-up allocates in std).
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .driver(driver)
        .workers(1)
        .sessions(sessions)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let mut c = client(addr(&server));
    let msg = vec![42u8; size];
    let mut back = vec![0u8; size];
    // Warm-up: the first exchanges fill the worker's pools.
    for _ in 0..50 {
        assert_eq!(round_trip(&mut c, &msg), msg);
    }
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..1000 {
        c.write_all(&msg).expect("write");
        c.read_exact(&mut back).expect("read");
    }
    ALLOCATIONS.load(Ordering::Relaxed) - before
}

// One test: the allocator's count is global, so these must not run side by side.
#[test]
fn test_steady_state_echo_does_not_allocate() {
    for &driver in DRIVERS {
        let copied = allocations(driver, 1000, |_: &ConnectionInfo| Echo);
        assert_eq!(copied, 0, "{driver:?}, copying: {copied} allocations");
        let swapped = allocations(driver, 16 * 1024, |_: &ConnectionInfo| Swapper);
        assert_eq!(
            swapped, 0,
            "{driver:?}, moving buffers: {swapped} allocations"
        );
    }
}
