//! The records a TLS engine writes as its handshake ends (session tickets) leave
//! with the session's first reply, and a reply before `Step::Close` carries the
//! `close_notify`, on the reactor (D-180). The engine is a toy: `HELLO` draws
//! `WELCOME`, `FIN!` ends the handshake and draws a ticket record, then records of
//! `[length: u16][payload XOR 0x5A]`, with an empty record as `close_notify`.

#![cfg(feature = "tls")]

mod common;

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use common::{DRIVERS, addr, client};
use net_io::{
    AllowAll, ConnectionInfo, DriverKind, Input, ListenerSpec, ServerBuilder, Session,
    SessionContext, Step, TlsAcceptor, TlsCloseKind, TlsError, TlsEvent, TlsFailure, TlsInfo,
    TlsProgress, TlsSession,
};

const MASK: u8 = 0x5A;
const TICKET: &[u8] = b"TICKET";
/// How long the session takes over its reply: a record sent before the session
/// ran would reach the client within this.
const SLOW: Duration = Duration::from_millis(300);

struct Ticketing;

impl TlsAcceptor for Ticketing {
    type Session = TicketSession;
    fn session(&self, _info: &ConnectionInfo) -> Result<TicketSession, TlsError> {
        Ok(TicketSession::default())
    }
}

#[derive(Default)]
struct TicketSession {
    /// 0: waiting for the hello; 1: waiting for `FIN!`; 2: done.
    state: u8,
    closed: bool,
}

fn record(plain: &[u8], out: &mut [u8]) -> usize {
    let n = plain.len();
    out[..2].copy_from_slice(&u16::try_from(n).unwrap_or(u16::MAX).to_be_bytes());
    for (o, p) in out[2..2 + n].iter_mut().zip(plain) {
        *o = p ^ MASK;
    }
    n + 2
}

fn need<'i>() -> TlsProgress<'i> {
    TlsProgress {
        consumed: 0,
        written: 0,
        event: TlsEvent::NeedInput,
    }
}

impl TlsSession for TicketSession {
    fn step<'i>(
        &mut self,
        input: &'i mut [u8],
        output: &mut [u8],
    ) -> Result<TlsProgress<'i>, TlsError> {
        match self.state {
            0 => {
                if input.len() < 5 {
                    return Ok(need());
                }
                if &input[..5] != b"HELLO" {
                    return Err(TlsError::new(TlsFailure::Handshake, 1, None));
                }
                output[..7].copy_from_slice(b"WELCOME");
                self.state = 1;
                Ok(TlsProgress {
                    consumed: 5,
                    written: 7,
                    event: TlsEvent::Transmit,
                })
            }
            1 => {
                if input.len() < 4 {
                    return Ok(need());
                }
                if &input[..4] != b"FIN!" {
                    return Err(TlsError::new(TlsFailure::Handshake, 2, None));
                }
                self.state = 2;
                let written = record(TICKET, output);
                Ok(TlsProgress {
                    consumed: 4,
                    written,
                    event: TlsEvent::HandshakeComplete,
                })
            }
            _ => {
                if input.len() < 2 {
                    return Ok(need());
                }
                let len = usize::from(u16::from_be_bytes([input[0], input[1]]));
                if len == 0 {
                    self.closed = true;
                    return Ok(TlsProgress {
                        consumed: 2,
                        written: 0,
                        event: TlsEvent::PeerClosed,
                    });
                }
                if input.len() < 2 + len {
                    return Ok(need());
                }
                let body = &mut input[2..2 + len];
                for b in body.iter_mut() {
                    *b ^= MASK;
                }
                Ok(TlsProgress {
                    consumed: 2 + len,
                    written: 0,
                    event: TlsEvent::Data(body),
                })
            }
        }
    }

    fn encrypt(&mut self, plaintext: &[u8], output: &mut [u8]) -> Result<usize, TlsError> {
        if output.len() < plaintext.len() + 2 {
            return Err(TlsError::new(TlsFailure::OutputFull, 3, None));
        }
        Ok(record(plaintext, output))
    }

    fn close(&mut self, output: &mut [u8]) -> Result<usize, TlsError> {
        output[..2].copy_from_slice(&[0, 0]);
        Ok(2)
    }

    fn on_transport_closed(&mut self) -> TlsCloseKind {
        if self.closed {
            TlsCloseKind::Clean
        } else {
            TlsCloseKind::Unclean
        }
    }

    fn info(&self) -> Option<TlsInfo> {
        (self.state == 2)
            .then(|| TlsInfo::new(None, None, 0x0304, 0x1301))
            .flatten()
    }

    fn input_capacity_required(&self) -> usize {
        2
    }
}

/// Answers `ping` slowly with `pong`, says nothing to `quiet`, and closes after
/// `last`.
struct Slow;

impl Session for Slow {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let req = input.bytes().to_vec();
        input.consume(req.len());
        match req.as_slice() {
            b"ping" => {
                std::thread::sleep(SLOW);
                let _ = cx.output().push(b"pong");
                Step::Write
            }
            b"last" => {
                std::thread::sleep(SLOW);
                let _ = cx.output().push(b"bye");
                Step::Close
            }
            _ => Step::Read,
        }
    }
}

fn server(driver: DriverKind) -> net_io::Server {
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0").tls(true))
        .driver(driver)
        .workers(2)
        .sessions(|_: &ConnectionInfo| Slow)
        .tls(Ticketing)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    server
}

fn rec(plain: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; plain.len() + 2];
    let n = record(plain, &mut out);
    out.truncate(n);
    out
}

fn hello(server: &net_io::Server) -> TcpStream {
    let mut c = client(addr(server));
    c.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    c.write_all(b"HELLO").expect("hello");
    let mut w = [0u8; 7];
    c.read_exact(&mut w).expect("welcome");
    assert_eq!(&w, b"WELCOME");
    c
}

/// Whether anything arrives within `within`.
fn arrives_within(c: &mut TcpStream, within: Duration) -> bool {
    c.set_read_timeout(Some(within)).expect("timeout");
    let mut one = [0u8; 1];
    let got = match c.peek(&mut one) {
        Ok(n) => n > 0,
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => false,
        Err(e) => panic!("peek: {e}"),
    };
    c.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    got
}

#[test]
fn test_tickets_leave_with_the_first_reply() {
    for &driver in DRIVERS {
        let server = server(driver);
        let mut c = hello(&server);
        // The handshake's end and the request in one write, as a TLS 1.3 client
        // sends its Finished and its first request.
        let mut first = b"FIN!".to_vec();
        first.extend(rec(b"ping"));
        c.write_all(&first).expect("finished and request");
        if driver == DriverKind::Reactor {
            assert!(
                !arrives_within(&mut c, SLOW / 2),
                "the ticket left before the reply"
            );
        }
        let mut want = rec(TICKET);
        want.extend(rec(b"pong"));
        let mut got = vec![0u8; want.len()];
        c.read_exact(&mut got).expect("ticket and reply");
        assert_eq!(got, want, "{driver:?}");
        // The connection goes on as usual afterwards.
        c.write_all(&rec(b"ping")).expect("second");
        let mut got = vec![0u8; 6];
        c.read_exact(&mut got).expect("second reply");
        assert_eq!(got, rec(b"pong"), "{driver:?}");
    }
}

#[test]
fn test_tickets_go_at_once_without_a_request() {
    for &driver in DRIVERS {
        let server = server(driver);
        let mut c = hello(&server);
        c.write_all(b"FIN!").expect("finished");
        let mut got = vec![0u8; TICKET.len() + 2];
        c.read_exact(&mut got).expect("ticket");
        assert_eq!(got, rec(TICKET), "{driver:?}");
    }
}

#[test]
fn test_tickets_go_when_the_first_request_draws_no_reply() {
    for &driver in DRIVERS {
        let server = server(driver);
        let mut c = hello(&server);
        let mut first = b"FIN!".to_vec();
        first.extend(rec(b"quiet"));
        c.write_all(&first).expect("finished and request");
        let mut got = vec![0u8; TICKET.len() + 2];
        c.read_exact(&mut got).expect("ticket");
        assert_eq!(got, rec(TICKET), "{driver:?}");
        c.write_all(&rec(b"ping")).expect("ping");
        let mut got = vec![0u8; 6];
        c.read_exact(&mut got).expect("reply");
        assert_eq!(got, rec(b"pong"), "{driver:?}");
    }
}

#[test]
fn test_a_reply_before_a_close_carries_one_close_notify() {
    for &driver in DRIVERS {
        let server = server(driver);
        let mut c = hello(&server);
        let mut first = b"FIN!".to_vec();
        first.extend(rec(b"last"));
        c.write_all(&first).expect("finished and request");
        if driver == DriverKind::Reactor {
            assert!(
                !arrives_within(&mut c, SLOW / 2),
                "the ticket left before the reply"
            );
        }
        let mut got = Vec::new();
        c.read_to_end(&mut got).expect("to the end");
        let mut want = rec(TICKET);
        want.extend(rec(b"bye"));
        want.extend([0, 0]);
        assert_eq!(got, want, "{driver:?}: one close_notify, after the reply");
    }
}
