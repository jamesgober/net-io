//! The completion-shaped driver over readiness (epoll, kqueue): an operation
//! waits until the socket is ready, then the non-blocking call runs.
//!
//! A socket's readiness is remembered per direction, because the OS reports
//! edges. `Receive` makes the call at once when the socket is known to be ready;
//! a short read clears the flag, since the next arrival raises a new edge, so an
//! exchange costs one wait, one receive, and one send. `Send` always tries first:
//! a socket is writable nearly always, and the wait is the expensive part.

use std::collections::VecDeque;
use std::io::{self, IoSlice};
use std::time::Duration;

use super::{
    BorrowedSocket, Completion, Completions, Driver, DriverKind, DriverWaker, Operation,
    OperationKind, Rejected, SendChunks, Token, operation_token,
};
use crate::buf::Buffer;
use crate::error::{NetError, OsErrorClass};
use crate::sys::{self, PollEvent, Poller, Registered};

#[derive(Debug, Default)]
enum Recv {
    #[default]
    None,
    Zero,
    Accept,
    Into(Buffer),
}

#[derive(Debug, Default)]
enum Out {
    #[default]
    None,
    Connect,
    Chunks(SendChunks),
}

#[derive(Debug)]
struct Reg {
    token: u64,
    socket: Registered,
    readable: bool,
    writable: bool,
    /// The peer hung up: reads must go on until the end of stream, because no
    /// new edge will report it.
    hangup: bool,
    recv: Recv,
    out: Out,
    close: bool,
}

/// How many waits may skip the OS while local completions are queued, so a busy
/// worker still sees new events.
const FAIRNESS: u8 = 16;

/// The readiness driver of one worker.
#[derive(Debug)]
pub(crate) struct ReadyDriver {
    poller: Poller,
    regs: Vec<Option<Reg>>,
    local: VecDeque<Completion>,
    skipped: u8,
}

impl ReadyDriver {
    pub(crate) fn new(capacity: usize) -> Result<ReadyDriver, NetError> {
        let poller = Poller::new().map_err(|e| NetError::DriverSetup {
            driver: DriverKind::Reactor,
            source: e,
        })?;
        Ok(ReadyDriver {
            poller,
            regs: Vec::with_capacity(capacity),
            local: VecDeque::with_capacity(capacity.min(1024)),
            skipped: 0,
        })
    }

    fn try_recv(reg: &mut Reg, local: &mut VecDeque<Completion>) {
        let token = Token(reg.token);
        match std::mem::take(&mut reg.recv) {
            Recv::None => {}
            Recv::Accept if reg.readable => {
                // The caller accepts until `WouldBlock`, so this is a fresh edge.
                reg.readable = false;
                local.push_back(Completion::new(token, OperationKind::Accept, Ok(0)));
            }
            Recv::Zero if reg.readable => {
                local.push_back(Completion::new(token, OperationKind::Receive, Ok(0)));
            }
            Recv::Into(mut buffer) if reg.readable => {
                let room = buffer.spare().len();
                match reg.socket.recv(buffer.spare()) {
                    Ok(n) => {
                        let len = buffer.len() + n;
                        buffer.set_len(len);
                        if n < room && n > 0 && !reg.hangup {
                            // Short read: the socket is drained; the next arrival
                            // raises a new edge.
                            reg.readable = false;
                        }
                        let mut c = Completion::new(token, OperationKind::Receive, Ok(n));
                        c.buffer = Some(buffer);
                        local.push_back(c);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        reg.readable = false;
                        reg.hangup = false;
                        reg.recv = Recv::Into(buffer);
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                        reg.recv = Recv::Into(buffer);
                    }
                    Err(e) => {
                        let mut c = Completion::new(
                            token,
                            OperationKind::Receive,
                            Err(OsErrorClass::from_io(&e)),
                        );
                        c.buffer = Some(buffer);
                        local.push_back(c);
                    }
                }
            }
            other => reg.recv = other,
        }
    }

    fn try_send(reg: &mut Reg, local: &mut VecDeque<Completion>) {
        let token = Token(reg.token);
        match std::mem::take(&mut reg.out) {
            Out::None => {}
            Out::Chunks(chunks) if reg.writable => {
                let result = {
                    let mut slices = [IoSlice::new(&[]); sys::MAX_SLICES];
                    let n = chunks.slices(&mut slices);
                    reg.socket.send_vectored(&slices[..n])
                };
                match result {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        reg.writable = false;
                        reg.out = Out::Chunks(chunks);
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                        reg.out = Out::Chunks(chunks);
                    }
                    other => {
                        let result = other.map_err(|e| OsErrorClass::from_io(&e));
                        let mut c = Completion::new(token, OperationKind::Send, result);
                        c.chunks = Some(chunks);
                        local.push_back(c);
                    }
                }
            }
            Out::Connect if reg.writable => {
                let result = match reg.socket.take_error() {
                    Ok(None) => Ok(0),
                    Ok(Some(e)) | Err(e) => Err(OsErrorClass::from_io(&e)),
                };
                local.push_back(Completion::new(token, OperationKind::Connect, result));
            }
            other => reg.out = other,
        }
    }

    fn try_close(reg: &mut Reg, local: &mut VecDeque<Completion>) {
        if reg.close && matches!(reg.recv, Recv::None) && matches!(reg.out, Out::None) {
            reg.close = false;
            local.push_back(Completion::new(
                Token(reg.token),
                OperationKind::Close,
                Ok(0),
            ));
        }
    }

    fn on_event(regs: &mut [Option<Reg>], local: &mut VecDeque<Completion>, e: PollEvent) {
        let token = Token(e.key);
        let Some(reg) = regs
            .get_mut(token.index())
            .and_then(Option::as_mut)
            .filter(|r| r.token == e.key)
        else {
            return;
        };
        reg.readable |= e.readable;
        reg.writable |= e.writable;
        reg.hangup |= e.hangup;
        ReadyDriver::try_recv(reg, local);
        ReadyDriver::try_send(reg, local);
    }
}

impl Driver for ReadyDriver {
    fn kind(&self) -> DriverKind {
        DriverKind::Reactor
    }

    fn register(&mut self, socket: BorrowedSocket<'_>, token: Token) -> Result<(), NetError> {
        let i = token.index();
        if i >= self.regs.len() {
            self.regs.resize_with(i + 1, || None);
        }
        let registered = self
            .poller
            .add(socket, token.0)
            .map_err(|e| NetError::from_os("epoll_ctl", e))?;
        self.regs[i] = Some(Reg {
            token: token.0,
            socket: registered,
            readable: false,
            writable: true,
            hangup: false,
            recv: Recv::None,
            out: Out::None,
            close: false,
        });
        Ok(())
    }

    fn submit(&mut self, operation: Operation) -> Result<(), Rejected> {
        let token = operation_token(&operation);
        if let Operation::Nop { .. } = operation {
            self.local
                .push_back(Completion::new(token, OperationKind::Nop, Ok(0)));
            return Ok(());
        }
        let local = &mut self.local;
        let Some(reg) = self
            .regs
            .get_mut(token.index())
            .and_then(Option::as_mut)
            .filter(|r| r.token == token.0)
        else {
            return Err(Rejected { operation });
        };
        match operation {
            Operation::Accept { .. } if matches!(reg.recv, Recv::None) => {
                reg.recv = Recv::Accept;
                ReadyDriver::try_recv(reg, local);
            }
            Operation::ReceiveZero { .. } if matches!(reg.recv, Recv::None) => {
                reg.recv = Recv::Zero;
                ReadyDriver::try_recv(reg, local);
            }
            Operation::Receive { buffer, .. } if matches!(reg.recv, Recv::None) => {
                reg.recv = Recv::Into(buffer);
                ReadyDriver::try_recv(reg, local);
            }
            Operation::Send { chunks, .. } if matches!(reg.out, Out::None) => {
                reg.out = Out::Chunks(chunks);
                ReadyDriver::try_send(reg, local);
            }
            Operation::Connect { addr, .. } if matches!(reg.out, Out::None) => {
                match reg.socket.connect_start(addr) {
                    Ok(false) => {
                        local.push_back(Completion::new(token, OperationKind::Connect, Ok(0)));
                    }
                    Ok(true) => {
                        reg.writable = false;
                        reg.out = Out::Connect;
                    }
                    Err(e) => {
                        local.push_back(Completion::new(
                            token,
                            OperationKind::Connect,
                            Err(OsErrorClass::from_io(&e)),
                        ));
                    }
                }
            }
            Operation::Close { .. } => {
                reg.close = true;
                ReadyDriver::try_close(reg, local);
            }
            operation => return Err(Rejected { operation }),
        }
        Ok(())
    }

    fn wait(
        &mut self,
        out: &mut Completions,
        timeout: Option<Duration>,
    ) -> Result<usize, NetError> {
        let queued = !self.local.is_empty();
        if !queued || self.skipped >= FAIRNESS {
            self.skipped = 0;
            let timeout = if queued {
                Some(Duration::ZERO)
            } else {
                timeout
            };
            let (regs, local) = (&mut self.regs, &mut self.local);
            self.poller
                .wait(timeout, |e| ReadyDriver::on_event(regs, local, e))
                .map_err(|e| NetError::from_os("wait", e))?;
        } else {
            self.skipped += 1;
        }
        let mut n = 0;
        while out.has_room() {
            let Some(c) = self.local.pop_front() else {
                break;
            };
            out.push(c);
            n += 1;
        }
        Ok(n)
    }

    fn cancel(&mut self, token: Token, which: OperationKind) -> Result<(), NetError> {
        let local = &mut self.local;
        let Some(reg) = self
            .regs
            .get_mut(token.index())
            .and_then(Option::as_mut)
            .filter(|r| r.token == token.0)
        else {
            return Ok(());
        };
        let aborted = Err(OsErrorClass::Aborted);
        match which {
            OperationKind::Receive | OperationKind::Accept => {
                let kind = if matches!(reg.recv, Recv::Accept) {
                    OperationKind::Accept
                } else {
                    OperationKind::Receive
                };
                match std::mem::take(&mut reg.recv) {
                    Recv::None => {}
                    Recv::Into(buffer) => {
                        let mut c = Completion::new(token, kind, aborted);
                        c.buffer = Some(buffer);
                        local.push_back(c);
                    }
                    Recv::Zero | Recv::Accept => {
                        local.push_back(Completion::new(token, kind, aborted));
                    }
                }
            }
            OperationKind::Send | OperationKind::Connect => match std::mem::take(&mut reg.out) {
                Out::None => {}
                Out::Chunks(chunks) => {
                    let mut c = Completion::new(token, OperationKind::Send, aborted);
                    c.chunks = Some(chunks);
                    local.push_back(c);
                }
                Out::Connect => {
                    local.push_back(Completion::new(token, OperationKind::Connect, aborted));
                }
            },
            _ => {}
        }
        ReadyDriver::try_close(reg, local);
        Ok(())
    }

    fn deregister(&mut self, token: Token) -> Result<(), NetError> {
        let Some(slot) = self.regs.get_mut(token.index()) else {
            return Ok(());
        };
        if slot.as_ref().is_some_and(|r| r.token == token.0) {
            if let Some(reg) = slot.take() {
                self.poller
                    .remove(reg.socket)
                    .map_err(|e| NetError::from_os("epoll_ctl", e))?;
            }
        }
        // Completions still queued for it are dropped with their buffers.
        self.local.retain(|c| c.token != token);
        Ok(())
    }

    fn waker(&self) -> DriverWaker {
        DriverWaker {
            inner: self.poller.waker(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::SizeClass;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::AsFd;

    fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (s, _) = l.accept().unwrap();
        s.set_nonblocking(true).unwrap();
        (c, s)
    }

    fn one(d: &mut ReadyDriver) -> Completion {
        let mut out = Completions::new();
        for _ in 0..50 {
            if d.wait(&mut out, Some(Duration::from_millis(100))).unwrap() > 0 {
                return out.drain().next().unwrap();
            }
        }
        panic!("no completion");
    }

    #[test]
    fn test_receive_and_send_complete_with_their_buffers() {
        let mut d = ReadyDriver::new(8).unwrap();
        let (mut c, s) = pair();
        let t = Token(3);
        d.register(s.as_fd(), t).unwrap();
        c.write_all(b"ping").unwrap();
        d.submit(Operation::Receive {
            token: t,
            buffer: Buffer::detached(SizeClass::SMALL),
        })
        .unwrap();
        let done = one(&mut d);
        assert_eq!(done.kind, OperationKind::Receive);
        assert_eq!(done.result, Ok(4));
        let buf = done.buffer.unwrap();
        assert_eq!(buf.as_slice(), b"ping");
        d.submit(Operation::Send {
            token: t,
            chunks: SendChunks::from_buffer(buf),
        })
        .unwrap();
        let done = one(&mut d);
        assert_eq!((done.kind, done.result), (OperationKind::Send, Ok(4)));
        assert!(done.chunks.unwrap().into_buffer().is_some());
        let mut back = [0u8; 4];
        c.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn test_zero_receive_reports_readable_without_a_buffer() {
        let mut d = ReadyDriver::new(8).unwrap();
        let (mut c, s) = pair();
        let t = Token(0);
        d.register(s.as_fd(), t).unwrap();
        d.submit(Operation::ReceiveZero { token: t }).unwrap();
        let mut out = Completions::new();
        assert_eq!(
            d.wait(&mut out, Some(Duration::from_millis(50))).unwrap(),
            0
        );
        c.write_all(b"x").unwrap();
        let done = one(&mut d);
        assert_eq!((done.kind, done.result), (OperationKind::Receive, Ok(0)));
        assert!(done.buffer.is_none());
    }

    #[test]
    fn test_end_of_stream_is_a_receive_of_zero_with_a_buffer() {
        let mut d = ReadyDriver::new(8).unwrap();
        let (c, s) = pair();
        let t = Token(1);
        d.register(s.as_fd(), t).unwrap();
        drop(c);
        d.submit(Operation::Receive {
            token: t,
            buffer: Buffer::detached(SizeClass::SMALL),
        })
        .unwrap();
        let done = one(&mut d);
        assert_eq!(done.result, Ok(0));
        assert!(done.buffer.is_some());
    }

    #[test]
    fn test_full_socket_waits_for_writability() {
        let mut d = ReadyDriver::new(8).unwrap();
        let (mut c, s) = pair();
        let t = Token(2);
        d.register(s.as_fd(), t).unwrap();
        let mut total = 0usize;
        loop {
            let mut b = Buffer::detached(SizeClass::LARGE);
            let n = b.capacity();
            b.set_len(n);
            d.submit(Operation::Send {
                token: t,
                chunks: SendChunks::from_buffer(b),
            })
            .unwrap();
            let mut out = Completions::new();
            if d.wait(&mut out, Some(Duration::from_millis(100))).unwrap() == 0 {
                break; // pending: the socket is full
            }
            total += out.drain().next().unwrap().result.unwrap();
        }
        // Reading makes room; the pending send finishes.
        let mut sink = vec![0u8; total];
        c.read_exact(&mut sink).unwrap();
        let done = one(&mut d);
        assert_eq!(done.kind, OperationKind::Send);
        assert!(done.result.unwrap() > 0);
    }

    #[test]
    fn test_cancel_completes_exactly_once_with_the_buffer() {
        let mut d = ReadyDriver::new(8).unwrap();
        let (_c, s) = pair();
        let t = Token(4);
        d.register(s.as_fd(), t).unwrap();
        d.submit(Operation::Receive {
            token: t,
            buffer: Buffer::detached(SizeClass::SMALL),
        })
        .unwrap();
        d.cancel(t, OperationKind::Receive).unwrap();
        let done = one(&mut d);
        assert_eq!(done.result, Err(OsErrorClass::Aborted));
        assert!(done.buffer.is_some());
        let mut out = Completions::new();
        assert_eq!(
            d.wait(&mut out, Some(Duration::from_millis(20))).unwrap(),
            0
        );
        d.cancel(t, OperationKind::Receive).unwrap();
        assert_eq!(
            d.wait(&mut out, Some(Duration::from_millis(20))).unwrap(),
            0
        );
    }

    #[test]
    fn test_two_receives_are_rejected_with_their_buffer() {
        let mut d = ReadyDriver::new(8).unwrap();
        let (_c, s) = pair();
        let t = Token(5);
        d.register(s.as_fd(), t).unwrap();
        d.submit(Operation::ReceiveZero { token: t }).unwrap();
        let again = d.submit(Operation::Receive {
            token: t,
            buffer: Buffer::detached(SizeClass::SMALL),
        });
        assert!(matches!(
            again,
            Err(Rejected {
                operation: Operation::Receive { .. }
            })
        ));
        let unknown = d.submit(Operation::ReceiveZero { token: Token(99) });
        assert!(unknown.is_err());
    }

    #[test]
    fn test_waker_ends_a_wait_from_another_thread() {
        let mut d = ReadyDriver::new(8).unwrap();
        let w = d.waker();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            w.wake();
        });
        let mut out = Completions::new();
        let started = std::time::Instant::now();
        assert_eq!(d.wait(&mut out, Some(Duration::from_secs(10))).unwrap(), 0);
        assert!(started.elapsed() < Duration::from_secs(5));
        t.join().unwrap();
    }

    #[test]
    fn test_stale_token_events_and_deregister() {
        let mut d = ReadyDriver::new(8).unwrap();
        let (mut c, s) = pair();
        let old = Token(1 << 32 | 6);
        d.register(s.as_fd(), old).unwrap();
        d.submit(Operation::ReceiveZero { token: old }).unwrap();
        d.deregister(old).unwrap();
        c.write_all(b"x").unwrap();
        let mut out = Completions::new();
        assert_eq!(
            d.wait(&mut out, Some(Duration::from_millis(20))).unwrap(),
            0
        );
        // The same slot under a new generation does not answer to the old token.
        d.register(s.as_fd(), Token(2 << 32 | 6)).unwrap();
        assert!(d.submit(Operation::ReceiveZero { token: old }).is_err());
    }

    #[test]
    fn test_connect_completes_when_the_socket_is_writable() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let s = TcpStream::from(sys::tcp_socket(false).unwrap());
        s.set_nonblocking(true).unwrap();
        let mut d = ReadyDriver::new(8).unwrap();
        let t = Token(0);
        d.register(s.as_fd(), t).unwrap();
        d.submit(Operation::Connect { token: t, addr }).unwrap();
        let done = one(&mut d);
        assert_eq!((done.kind, done.result), (OperationKind::Connect, Ok(0)));
        assert!(l.accept().is_ok());
    }
}
