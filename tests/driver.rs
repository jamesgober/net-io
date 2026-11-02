//! The public driver interface, on whichever backend this OS has.

#![cfg(feature = "reactor")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use net_io::{
    BorrowedSocket, BufferPool, Completion, Completions, Driver, Operation, OperationKind,
    OsErrorClass, SendChunks, SizeClass, Token, new_reactor_driver,
};

fn borrowed(s: &TcpStream) -> BorrowedSocket<'_> {
    #[cfg(unix)]
    {
        std::os::fd::AsFd::as_fd(s)
    }
    #[cfg(windows)]
    {
        std::os::windows::io::AsSocket::as_socket(s)
    }
}

fn pair() -> (TcpStream, TcpStream) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let c = TcpStream::connect(l.local_addr().expect("addr")).expect("connect");
    let (s, _) = l.accept().expect("accept");
    s.set_nonblocking(true).expect("nonblocking");
    (c, s)
}

fn next(driver: &mut dyn Driver, out: &mut Completions) -> Completion {
    for _ in 0..50 {
        driver
            .wait(out, Some(Duration::from_millis(100)))
            .expect("wait");
        if let Some(c) = out.drain().next() {
            return c;
        }
    }
    panic!("no completion");
}

#[test]
fn test_echo_through_the_public_interface() {
    let mut driver = new_reactor_driver(8).expect("driver");
    let mut pool = BufferPool::standalone(1 << 20);
    let mut done = Completions::new();
    let (mut client, server) = pair();
    let token = Token((1 << 32) | 3);
    driver.register(borrowed(&server), token).expect("register");

    client.write_all(b"ping").expect("write");
    driver
        .submit(Operation::ReceiveZero { token })
        .expect("submit");
    let ready = next(driver.as_mut(), &mut done);
    assert_eq!(ready.kind, OperationKind::Receive);
    assert!(ready.buffer.is_none(), "an idle wait holds no buffer");

    let buffer = pool.take(SizeClass::SMALL).expect("buffer");
    driver
        .submit(Operation::Receive { token, buffer })
        .expect("submit");
    let read = next(driver.as_mut(), &mut done);
    assert_eq!(read.result, Ok(4));
    let buffer = read.buffer.expect("the buffer comes back");
    assert_eq!(buffer.as_slice(), b"ping");

    driver
        .submit(Operation::Send {
            token,
            chunks: SendChunks::from_buffer(buffer),
        })
        .expect("submit");
    let sent = next(driver.as_mut(), &mut done);
    assert_eq!(sent.result, Ok(4));
    assert!(sent.chunks.is_some(), "the chunks come back");
    let mut back = [0u8; 4];
    client.read_exact(&mut back).expect("read");
    assert_eq!(&back, b"ping");
    driver.deregister(token).expect("deregister");
}

#[test]
fn test_rejected_operation_keeps_its_buffer() {
    let mut driver = new_reactor_driver(8).expect("driver");
    let mut pool = BufferPool::standalone(1 << 20);
    let buffer = pool.take(SizeClass::SMALL).expect("buffer");
    let rejected = driver
        .submit(Operation::Receive {
            token: Token(9),
            buffer,
        })
        .expect_err("not registered");
    assert!(matches!(rejected.operation, Operation::Receive { .. }));
}

#[test]
fn test_cancel_ends_in_one_aborted_completion() {
    let mut driver = new_reactor_driver(8).expect("driver");
    let mut pool = BufferPool::standalone(1 << 20);
    let mut done = Completions::new();
    let (_client, server) = pair();
    let token = Token(5);
    driver.register(borrowed(&server), token).expect("register");
    let buffer = pool.take(SizeClass::SMALL).expect("buffer");
    driver
        .submit(Operation::Receive { token, buffer })
        .expect("submit");
    driver
        .cancel(token, OperationKind::Receive)
        .expect("cancel");
    let c = next(driver.as_mut(), &mut done);
    assert_eq!(c.result, Err(OsErrorClass::Aborted));
    assert!(c.buffer.is_some());
}

#[test]
fn test_waker_ends_a_wait_from_another_thread() {
    let mut driver = new_reactor_driver(8).expect("driver");
    let waker = driver.waker();
    let mut done = Completions::new();
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(20));
        waker.wake();
    });
    let start = std::time::Instant::now();
    driver
        .wait(&mut done, Some(Duration::from_secs(10)))
        .expect("wait");
    assert!(start.elapsed() < Duration::from_secs(5));
    t.join().expect("thread");
}
