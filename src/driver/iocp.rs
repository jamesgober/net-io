//! The completion driver on Windows: operations go straight to the kernel.
//!
//! An idle connection waits with a zero-byte receive, so it pins no buffer; the
//! read that follows costs one more system call than epoll's round trip. Sockets
//! use `FILE_SKIP_COMPLETION_PORT_ON_SUCCESS`, so a call that finishes at once
//! completes here without a trip through the port.
//!
//! A connection's socket may not close until its operations are dequeued, which
//! the reactor ensures. `deregister` with operations out cancels them; their
//! packets find no registration and are dropped with their buffers (edge case 64).

use std::collections::VecDeque;
use std::time::Duration;

use super::{
    BorrowedSocket, Completion, Completions, Driver, DriverKind, DriverWaker, Operation,
    OperationKind, Rejected, Token, operation_token,
};
use crate::error::{NetError, OsErrorClass};
use crate::sys::{self, Associated, Finished, InFlight, OpKind, Port, Started};

#[derive(Debug)]
struct Reg {
    token: u64,
    socket: Associated,
    recv: Option<InFlight>,
    out: Option<InFlight>,
    close: bool,
}

/// How many waits may skip the port while local completions are queued, so a busy
/// worker still sees new packets.
const FAIRNESS: u8 = 16;

/// The completion driver of one worker.
#[derive(Debug)]
pub(crate) struct IocpDriver {
    port: Port,
    regs: Vec<Option<Reg>>,
    local: VecDeque<Completion>,
    skipped: u8,
}

fn class(e: &std::io::Error) -> OsErrorClass {
    if sys::is_aborted(e) {
        OsErrorClass::Aborted
    } else {
        OsErrorClass::from_io(e)
    }
}

fn completion(f: Finished) -> Completion {
    let kind = match f.kind {
        OpKind::Receive => OperationKind::Receive,
        OpKind::Send => OperationKind::Send,
        OpKind::Connect => OperationKind::Connect,
    };
    let result = f.result.as_ref().map(|n| *n).map_err(class);
    let mut c = Completion::new(Token(f.token), kind, result);
    c.buffer = f.buffer;
    c.chunks = f.chunks;
    if let (Some(b), Ok(n)) = (c.buffer.as_mut(), result) {
        let len = b.len() + n;
        b.set_len(len);
    }
    c
}

fn try_close(reg: &mut Reg, local: &mut VecDeque<Completion>) {
    if reg.close && reg.recv.is_none() && reg.out.is_none() {
        reg.close = false;
        local.push_back(Completion::new(
            Token(reg.token),
            OperationKind::Close,
            Ok(0),
        ));
    }
}

fn on_finished(regs: &mut [Option<Reg>], local: &mut VecDeque<Completion>, f: Finished) {
    let token = Token(f.token);
    let Some(reg) = regs
        .get_mut(token.index())
        .and_then(Option::as_mut)
        .filter(|r| r.token == f.token)
    else {
        // The slot moved on (edge case 64).
        return;
    };
    match f.kind {
        OpKind::Receive => reg.recv = None,
        OpKind::Send | OpKind::Connect => reg.out = None,
    }
    local.push_back(completion(f));
    try_close(reg, local);
}

impl IocpDriver {
    pub(crate) fn new(capacity: usize) -> Result<IocpDriver, NetError> {
        let port = Port::new().map_err(|e| NetError::DriverSetup {
            driver: DriverKind::Reactor,
            source: e,
        })?;
        Ok(IocpDriver::on(port, capacity))
    }

    /// As `register`, for a named pipe: a pipe is not a socket, so it has no place
    /// in the public signature.
    #[cfg(feature = "local")]
    pub(crate) fn register_pipe(
        &mut self,
        handle: std::os::windows::io::RawHandle,
        token: Token,
    ) -> Result<(), NetError> {
        let i = token.index();
        if i >= self.regs.len() {
            self.regs.resize_with(i + 1, || None);
        }
        let socket = self
            .port
            .associate_pipe(handle)
            .map_err(|e| NetError::from_os("CreateIoCompletionPort", e))?;
        self.regs[i] = Some(Reg {
            token: token.0,
            socket,
            recv: None,
            out: None,
            close: false,
        });
        Ok(())
    }

    fn on(port: Port, capacity: usize) -> IocpDriver {
        IocpDriver {
            port,
            regs: Vec::with_capacity(capacity),
            local: VecDeque::with_capacity(capacity.min(1024)),
            skipped: 0,
        }
    }

    fn reg(&mut self, token: Token) -> Option<&mut Reg> {
        self.regs
            .get_mut(token.index())
            .and_then(Option::as_mut)
            .filter(|r| r.token == token.0)
    }
}

impl Driver for IocpDriver {
    fn kind(&self) -> DriverKind {
        DriverKind::Reactor
    }

    fn register(&mut self, socket: BorrowedSocket<'_>, token: Token) -> Result<(), NetError> {
        let i = token.index();
        if i >= self.regs.len() {
            self.regs.resize_with(i + 1, || None);
        }
        let socket = self
            .port
            .associate(socket)
            .map_err(|e| NetError::from_os("CreateIoCompletionPort", e))?;
        self.regs[i] = Some(Reg {
            token: token.0,
            socket,
            recv: None,
            out: None,
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
        let Some(reg) = self.reg(token) else {
            return Err(Rejected { operation });
        };
        let (on, recv_free, out_free) = (reg.socket, reg.recv.is_none(), reg.out.is_none());
        let is_recv = matches!(
            operation,
            Operation::Receive { .. } | Operation::ReceiveZero { .. }
        );
        let started = match operation {
            Operation::ReceiveZero { .. } if recv_free => self.port.receive(on, token.0, None),
            Operation::Receive { buffer, .. } if recv_free => {
                self.port.receive(on, token.0, Some(buffer))
            }
            Operation::Send { chunks, .. } if out_free => self.port.send(on, token.0, chunks),
            Operation::Connect { addr, .. } if out_free => {
                match self.port.connect(on, token.0, addr) {
                    Ok(started) => started,
                    Err(e) => {
                        self.local.push_back(Completion::new(
                            token,
                            OperationKind::Connect,
                            Err(class(&e)),
                        ));
                        return Ok(());
                    }
                }
            }
            Operation::Close { abortive, .. } => {
                let local = &mut self.local;
                if let Some(reg) = self.regs.get_mut(token.index()).and_then(Option::as_mut) {
                    if abortive {
                        reg.socket.set_abortive();
                    }
                    reg.close = true;
                    try_close(reg, local);
                }
                return Ok(());
            }
            // A listener is never on a port (D-016), and a second operation of a kind
            // waits for the first.
            operation => return Err(Rejected { operation }),
        };
        match started {
            Started::Done(f) => self.local.push_back(completion(f)),
            Started::Pending(op) => {
                if let Some(reg) = self.reg(token) {
                    if is_recv {
                        reg.recv = Some(op);
                    } else {
                        reg.out = Some(op);
                    }
                }
            }
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
            self.port
                .wait(timeout, |f| on_finished(regs, local, f))
                .map_err(|e| NetError::from_os("GetQueuedCompletionStatusEx", e))?;
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
        let Some(reg) = self.reg(token) else {
            return Ok(());
        };
        let (on, op) = match which {
            OperationKind::Receive | OperationKind::Accept => (reg.socket, reg.recv),
            OperationKind::Send | OperationKind::Connect => (reg.socket, reg.out),
            _ => return Ok(()),
        };
        if let Some(op) = op {
            self.port
                .cancel(on, op)
                .map_err(|e| NetError::from_os("CancelIoEx", e))?;
        }
        Ok(())
    }

    fn deregister(&mut self, token: Token) -> Result<(), NetError> {
        let Some(slot) = self.regs.get_mut(token.index()) else {
            return Ok(());
        };
        if slot.as_ref().is_some_and(|r| r.token == token.0) {
            if let Some(reg) = slot.take() {
                for op in [reg.recv, reg.out].into_iter().flatten() {
                    let _ = self.port.cancel(reg.socket, op);
                }
            }
        }
        // Completions still queued for it are dropped with their buffers.
        self.local.retain(|c| c.token != token);
        Ok(())
    }

    fn waker(&self) -> DriverWaker {
        DriverWaker {
            inner: self.port.waker(),
        }
    }
}

impl Drop for IocpDriver {
    fn drop(&mut self) {
        for reg in self.regs.iter().flatten() {
            for op in [reg.recv, reg.out].into_iter().flatten() {
                let _ = self.port.cancel(reg.socket, op);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buf::Buffer;
    use crate::driver::SendChunks;
    use crate::limits::SizeClass;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::os::windows::io::AsSocket;

    fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (s, _) = l.accept().unwrap();
        s.set_nonblocking(true).unwrap();
        (c, s)
    }

    fn one(d: &mut IocpDriver) -> Completion {
        let mut out = Completions::new();
        for _ in 0..50 {
            if d.wait(&mut out, Some(Duration::from_millis(100))).unwrap() > 0 {
                return out.drain().next().unwrap();
            }
        }
        panic!("no completion");
    }

    fn both() -> [IocpDriver; 2] {
        [
            IocpDriver::on(Port::with_skip(true).unwrap(), 8),
            // Edge case 69: every completion through the port.
            IocpDriver::on(Port::with_skip(false).unwrap(), 8),
        ]
    }

    #[test]
    fn test_receive_and_send_complete_with_their_buffers() {
        for mut d in both() {
            let (mut c, s) = pair();
            let t = Token(3);
            d.register(s.as_socket(), t).unwrap();
            c.write_all(b"ping").unwrap();
            d.submit(Operation::Receive {
                token: t,
                buffer: Buffer::detached(SizeClass::SMALL),
            })
            .unwrap();
            let r = one(&mut d);
            assert_eq!(r.kind, OperationKind::Receive);
            assert_eq!(r.result, Ok(4));
            let buffer = r.buffer.unwrap();
            assert_eq!(buffer.as_slice(), b"ping");
            d.submit(Operation::Send {
                token: t,
                chunks: SendChunks::from_buffer(buffer),
            })
            .unwrap();
            let w = one(&mut d);
            assert_eq!(w.kind, OperationKind::Send);
            assert_eq!(w.result, Ok(4));
            assert!(w.chunks.is_some());
            let mut back = [0; 4];
            c.read_exact(&mut back).unwrap();
            assert_eq!(&back, b"ping");
            d.deregister(t).unwrap();
        }
    }

    #[test]
    fn test_receive_pends_until_bytes_arrive() {
        for mut d in both() {
            let (mut c, s) = pair();
            let t = Token(1);
            d.register(s.as_socket(), t).unwrap();
            d.submit(Operation::Receive {
                token: t,
                buffer: Buffer::detached(SizeClass::SMALL),
            })
            .unwrap();
            let mut out = Completions::new();
            assert_eq!(
                d.wait(&mut out, Some(Duration::from_millis(20))).unwrap(),
                0
            );
            c.write_all(b"late").unwrap();
            let r = one(&mut d);
            assert_eq!(r.result, Ok(4));
            assert_eq!(r.buffer.unwrap().as_slice(), b"late");
        }
    }

    #[test]
    fn test_zero_byte_receive_holds_no_buffer() {
        for mut d in both() {
            let (mut c, s) = pair();
            let t = Token(2);
            d.register(s.as_socket(), t).unwrap();
            d.submit(Operation::ReceiveZero { token: t }).unwrap();
            c.write_all(b"x").unwrap();
            let r = one(&mut d);
            assert_eq!(r.kind, OperationKind::Receive);
            assert_eq!(r.result, Ok(0));
            assert!(r.buffer.is_none());
            // Readable: the bytes are still there.
            d.submit(Operation::Receive {
                token: t,
                buffer: Buffer::detached(SizeClass::SMALL),
            })
            .unwrap();
            assert_eq!(one(&mut d).result, Ok(1));
        }
    }

    /// Edge case 68.
    #[test]
    fn test_zero_byte_receive_then_end_of_stream() {
        for mut d in both() {
            let (c, s) = pair();
            let t = Token(2);
            d.register(s.as_socket(), t).unwrap();
            d.submit(Operation::ReceiveZero { token: t }).unwrap();
            drop(c);
            assert_eq!(one(&mut d).result, Ok(0));
            d.submit(Operation::Receive {
                token: t,
                buffer: Buffer::detached(SizeClass::SMALL),
            })
            .unwrap();
            assert_eq!(one(&mut d).result, Ok(0), "end of stream");
        }
    }

    /// Exactly one completion, with the buffer back, after a cancel; a second
    /// cancel finds nothing (edge case 62).
    #[test]
    fn test_cancel_completes_once_with_the_buffer() {
        for mut d in both() {
            let (_c, s) = pair();
            let t = Token(5);
            d.register(s.as_socket(), t).unwrap();
            d.submit(Operation::Receive {
                token: t,
                buffer: Buffer::detached(SizeClass::SMALL),
            })
            .unwrap();
            d.cancel(t, OperationKind::Receive).unwrap();
            let r = one(&mut d);
            assert_eq!(r.result, Err(OsErrorClass::Aborted));
            assert!(r.buffer.is_some());
            d.cancel(t, OperationKind::Receive).unwrap();
            let mut out = Completions::new();
            assert_eq!(
                d.wait(&mut out, Some(Duration::from_millis(20))).unwrap(),
                0
            );
        }
    }

    /// Edge case 63: an operation that finished before the cancel keeps its result.
    #[test]
    fn test_cancel_after_success_keeps_the_result() {
        for mut d in both() {
            let (mut c, s) = pair();
            let t = Token(5);
            d.register(s.as_socket(), t).unwrap();
            d.submit(Operation::Receive {
                token: t,
                buffer: Buffer::detached(SizeClass::SMALL),
            })
            .unwrap();
            c.write_all(b"done").unwrap();
            std::thread::sleep(Duration::from_millis(20));
            d.cancel(t, OperationKind::Receive).unwrap();
            assert_eq!(one(&mut d).result, Ok(4));
        }
    }

    /// Edge case 64: a packet for a slot that moved on goes nowhere.
    #[test]
    fn test_stale_packet_is_dropped() {
        for mut d in both() {
            let (_c, s) = pair();
            let (_c2, s2) = pair();
            let old = Token(7 | 1 << 32);
            let new = Token(7 | 2 << 32);
            d.register(s.as_socket(), old).unwrap();
            d.submit(Operation::Receive {
                token: old,
                buffer: Buffer::detached(SizeClass::SMALL),
            })
            .unwrap();
            d.deregister(old).unwrap();
            d.register(s2.as_socket(), new).unwrap();
            let mut out = Completions::new();
            d.wait(&mut out, Some(Duration::from_millis(50))).unwrap();
            assert!(out.drain().all(|c| c.token != old));
        }
    }

    #[test]
    fn test_second_receive_and_unknown_token_are_rejected() {
        let mut d = IocpDriver::new(8).unwrap();
        let (_c, s) = pair();
        let t = Token(1);
        d.register(s.as_socket(), t).unwrap();
        d.submit(Operation::ReceiveZero { token: t }).unwrap();
        assert!(d.submit(Operation::ReceiveZero { token: t }).is_err());
        assert!(
            d.submit(Operation::ReceiveZero { token: Token(9) })
                .is_err()
        );
    }

    /// Edge case 67, D-016: a listener never joins a port, and `Accept` has no
    /// meaning here.
    #[test]
    fn test_listener_is_refused() {
        let mut d = IocpDriver::new(8).unwrap();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(d.register(l.as_socket(), Token(1)).is_err());
        let (_c, s) = pair();
        d.register(s.as_socket(), Token(2)).unwrap();
        assert!(d.submit(Operation::Accept { listener: Token(2) }).is_err());
    }

    #[test]
    fn test_waker_ends_a_wait() {
        let mut d = IocpDriver::new(8).unwrap();
        let w = d.waker();
        w.wake();
        w.wake();
        let mut out = Completions::new();
        let start = std::time::Instant::now();
        assert_eq!(d.wait(&mut out, Some(Duration::from_secs(5))).unwrap(), 0);
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn test_nop_and_close_complete() {
        for mut d in both() {
            let (_c, s) = pair();
            let t = Token(4);
            d.register(s.as_socket(), t).unwrap();
            d.submit(Operation::Nop { token: t }).unwrap();
            assert_eq!(one(&mut d).kind, OperationKind::Nop);
            d.submit(Operation::ReceiveZero { token: t }).unwrap();
            d.submit(Operation::Close {
                token: t,
                abortive: false,
            })
            .unwrap();
            d.cancel(t, OperationKind::Receive).unwrap();
            let mut kinds = Vec::new();
            let mut out = Completions::new();
            while kinds.len() < 2 {
                d.wait(&mut out, Some(Duration::from_secs(1))).unwrap();
                kinds.extend(out.drain().map(|c| c.kind));
            }
            assert_eq!(kinds, [OperationKind::Receive, OperationKind::Close]);
        }
    }

    #[test]
    fn test_connect() {
        for mut d in both() {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = l.local_addr().unwrap();
            let sock = sys::tcp_socket(false).unwrap();
            let t = Token(6);
            d.register(sock.as_socket(), t).unwrap();
            d.submit(Operation::Connect { token: t, addr }).unwrap();
            let c = one(&mut d);
            assert_eq!(c.kind, OperationKind::Connect);
            assert_eq!(c.result, Ok(0));
            let (mut s, peer) = l.accept().unwrap();
            let stream = TcpStream::from(sock);
            assert_eq!(stream.local_addr().unwrap(), peer, "context updated");
            s.write_all(b"z").unwrap();
            d.submit(Operation::Receive {
                token: t,
                buffer: Buffer::detached(SizeClass::SMALL),
            })
            .unwrap();
            assert_eq!(one(&mut d).result, Ok(1));
        }
    }

    #[test]
    fn test_connect_refused() {
        let mut d = IocpDriver::new(8).unwrap();
        let addr: SocketAddr = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        let sock = sys::tcp_socket(false).unwrap();
        let t = Token(6);
        d.register(sock.as_socket(), t).unwrap();
        d.submit(Operation::Connect { token: t, addr }).unwrap();
        assert_eq!(one(&mut d).result, Err(OsErrorClass::Refused));
    }

    /// The send pends once the peer stops reading; a cancel gives the chunks back.
    #[test]
    fn test_blocked_send_cancels_with_its_chunks() {
        for mut d in both() {
            let (_c, s) = pair();
            let t = Token(8);
            d.register(s.as_socket(), t).unwrap();
            let mut pending = false;
            for _ in 0..4096 {
                d.submit(Operation::Send {
                    token: t,
                    chunks: SendChunks::from_buffer({
                        let mut b = Buffer::detached(SizeClass::SMALL);
                        let room = b.spare().len();
                        b.set_len(room);
                        b
                    }),
                })
                .unwrap();
                let mut out = Completions::new();
                if d.wait(&mut out, Some(Duration::from_millis(5))).unwrap() == 0 {
                    pending = true;
                    break;
                }
            }
            assert!(pending, "the peer's window filled");
            d.cancel(t, OperationKind::Send).unwrap();
            let r = one(&mut d);
            assert_eq!(r.kind, OperationKind::Send);
            assert!(r.chunks.is_some());
        }
    }
}
