//! Reactor behaviour the blocking driver has no counterpart for.

#![cfg(feature = "reactor")]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use common::{addr, eventually};
use net_io::{
    AllowAll, CloseReason, ConnectionInfo, DriverKind, Input, Limits, ListenerSpec, Server,
    ServerBuilder, Session, SessionContext, SizeClass, Step,
};

/// Holds its input until told to let go; counts what it lets go of.
struct Holder(Arc<AtomicUsize>);

impl Session for Holder {
    fn on_data(&mut self, _: &mut SessionContext<'_>, input: &mut Input) -> Step {
        if input.bytes().last() != Some(&b'H') {
            self.0.fetch_add(input.bytes().len(), Ordering::SeqCst);
            let all = input.bytes().len();
            input.consume(all);
        }
        Step::Read
    }
}

/// Room for exactly two input buffers on one worker.
fn server(seen: &Arc<AtomicUsize>) -> Server {
    let limits = Limits::builder()
        .buffer_budget(2 * u64::from(SizeClass::SMALL.bytes()))
        .read_class(SizeClass::SMALL, SizeClass::SMALL)
        .read_timeout(Duration::from_secs(30))
        .build()
        .expect("limits");
    let seen = seen.clone();
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .driver(DriverKind::Reactor)
        .workers(1)
        .limits(limits)
        .sessions(move |_: &ConnectionInfo| Holder(seen.clone()))
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    server
}

fn holding(server: &Server) -> TcpStream {
    let mut c = TcpStream::connect(addr(server)).expect("connect");
    c.write_all(b"H").expect("write");
    c
}

/// Edge case 11: with the budget spent, a connection's reading pauses instead of
/// failing, and resumes when a buffer frees.
#[test]
fn test_buffer_budget_pauses_reading() {
    let seen = Arc::new(AtomicUsize::new(0));
    let server = server(&seen);
    let mut first = holding(&server);
    let _second = holding(&server);
    std::thread::sleep(Duration::from_millis(50));
    let mut paused = TcpStream::connect(addr(&server)).expect("connect");
    paused.write_all(b"waits").expect("write");
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(seen.load(Ordering::SeqCst), 0, "reading is paused");
    assert_eq!(server.stats().closed, 0, "nothing is closed for it");

    // The first one lets go and goes idle: its buffer frees.
    first.write_all(b"!").expect("write");
    // Well before the 5 s rate grace, which would free the buffer on its own.
    assert!(eventually(Duration::from_secs(3), || seen
        .load(Ordering::SeqCst)
        == 2 + 5));
    assert_eq!(
        server
            .stats()
            .closed_for(CloseReason::Limit(net_io::LimitKind::BufferBudget)),
        0
    );
}

/// A paused connection that closes leaves nothing behind.
#[test]
fn test_paused_connection_closes_cleanly() {
    let seen = Arc::new(AtomicUsize::new(0));
    let server = server(&seen);
    let first = holding(&server);
    let second = holding(&server);
    std::thread::sleep(Duration::from_millis(50));
    let mut paused = TcpStream::connect(addr(&server)).expect("connect");
    paused.write_all(b"x").expect("write");
    std::thread::sleep(Duration::from_millis(50));
    drop(paused);
    drop(first);
    drop(second);
    assert!(eventually(Duration::from_secs(5), || server.stats().open == 0));
    let mut again = TcpStream::connect(addr(&server)).expect("connect");
    again.write_all(b"ok").expect("write");
    assert!(eventually(Duration::from_secs(5), || seen
        .load(Ordering::SeqCst)
        >= 2));
}

/// Echoes a line; holds anything without a newline in its input. Counts its calls.
struct LineEcho(Arc<AtomicUsize>);

impl Session for LineEcho {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        self.0.fetch_add(1, Ordering::SeqCst);
        if input.bytes().last() == Some(&b'\n') {
            let taken = cx.output().push_partial(input.bytes());
            input.consume(taken);
            return Step::Write;
        }
        Step::Read
    }
}

/// Buffers one size class gave back serve another: connections on a listener with
/// 64 KiB inputs spend a 1 MiB budget and leave, and a connection on a listener
/// with 16 KiB inputs is then served from the budget their buffers return. Before,
/// the 64 KiB buffers stayed in the worker's free list for their class and the
/// budget stayed spent until a restart.
#[test]
fn test_buffers_one_class_freed_serve_another() {
    let budget = 1u64 << 20;
    let large = Limits::builder()
        .read_class(SizeClass::LARGE, SizeClass::LARGE)
        .build()
        .expect("limits");
    let limits = Limits::builder()
        .buffer_budget(budget)
        .build()
        .expect("limits");
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0").limits(large))
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .driver(DriverKind::Reactor)
        .workers(1)
        .limits(limits)
        .sessions(move |_: &ConnectionInfo| LineEcho(counter.clone()))
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let medium = server.listeners()[1].local.socket_addr().expect("ip");
    let n = budget / u64::from(SizeClass::LARGE.bytes());
    let mut holders = Vec::new();
    for _ in 0..n {
        let mut c = TcpStream::connect(addr(&server)).expect("connect");
        c.write_all(b"x").expect("write");
        holders.push(c);
    }
    // Each holds a 64 KiB input with one byte in it: the budget is spent.
    assert!(eventually(Duration::from_secs(5), || calls
        .load(Ordering::SeqCst)
        == n as usize));
    drop(holders);
    assert!(eventually(Duration::from_secs(5), || server.stats().open == 0));
    let mut c = TcpStream::connect(medium).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    c.write_all(b"ping\n").expect("write");
    let mut back = [0u8; 5];
    let served = c.read_exact(&mut back).is_ok();
    assert!(
        served,
        "not served after the budget came back: {:?}",
        server.stats()
    );
    assert_eq!(&back, b"ping\n");
}
