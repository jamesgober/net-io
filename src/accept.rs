//! Accept discipline: the reserve descriptor, backoff, and error classes (FR-9, FR-10).

use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use crate::error::OsErrorClass;
use crate::sys::{self, AcceptFailure, AsSock};

const BACKOFF_START: Duration = Duration::from_millis(1);
const BACKOFF_MAX: Duration = Duration::from_secs(1);

/// What one accept attempt produced.
#[derive(Debug)]
pub(crate) enum Accepted<C> {
    /// A connection.
    Conn(C),
    /// Nothing pending.
    Again,
    /// One connection failed before it was ours (counted, accepting continues).
    Skipped(OsErrorClass),
    /// Out of descriptors or memory: pause accepting for this long.
    Pause(Duration),
    /// The listener is broken.
    Failed(io::Error),
}

impl<C> Accepted<C> {
    /// The outcome without its connection (for an outcome that has none).
    pub(crate) fn without_conn(self) -> Accepted<()> {
        match self {
            Accepted::Conn(_) => Accepted::Conn(()),
            Accepted::Again => Accepted::Again,
            Accepted::Skipped(c) => Accepted::Skipped(c),
            Accepted::Pause(d) => Accepted::Pause(d),
            Accepted::Failed(e) => Accepted::Failed(e),
        }
    }
}

/// Per-acceptor state: a spare descriptor held for the `EMFILE` routine, and the backoff.
#[derive(Debug)]
pub(crate) struct Acceptor {
    #[cfg(unix)]
    reserve: Option<std::fs::File>,
    backoff: Duration,
}

impl Acceptor {
    pub(crate) fn new() -> Acceptor {
        Acceptor {
            #[cfg(unix)]
            reserve: open_reserve(),
            backoff: BACKOFF_START,
        }
    }

    fn next_backoff(&mut self) -> Duration {
        let current = self.backoff;
        self.backoff = (self.backoff * 2).min(BACKOFF_MAX);
        current
    }

    /// One accept. On descriptor exhaustion (Unix) the spare descriptor is released,
    /// one pending connection is accepted and reset so its client is not left
    /// waiting in the backlog, the spare is reopened, and accepting pauses.
    pub(crate) fn accept(&mut self, listener: &TcpListener) -> Accepted<(TcpStream, SocketAddr)> {
        match sys::accept(listener) {
            Ok((stream, peer)) => {
                self.backoff = BACKOFF_START;
                if !usable_peer(peer) {
                    // No usable peer address: nothing to key caps or the gate on. Close quietly.
                    let _ = sys::set_linger(stream.sock(), Some(Duration::ZERO));
                    return Accepted::Skipped(OsErrorClass::Other(0));
                }
                Accepted::Conn((stream, crate::addr::normalize_socket(peer)))
            }
            Err(e) => self.failed(e, |a| a.shed_one(listener)),
        }
    }

    /// One accept on a Unix listener, with the same discipline as TCP.
    #[cfg(all(unix, feature = "local"))]
    pub(crate) fn accept_unix(
        &mut self,
        listener: &std::os::unix::net::UnixListener,
    ) -> Accepted<std::os::unix::net::UnixStream> {
        match sys::accept_unix(listener) {
            Ok(stream) => {
                self.backoff = BACKOFF_START;
                Accepted::Conn(stream)
            }
            Err(e) => self.failed(e, |a| {
                a.reserve = None;
                drop(listener.accept());
                a.reserve = open_reserve();
            }),
        }
    }

    fn failed<C>(&mut self, e: io::Error, shed: impl FnOnce(&mut Acceptor)) -> Accepted<C> {
        if matches!(
            e.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        ) {
            return Accepted::Again;
        }
        match sys::classify_accept(&e) {
            AcceptFailure::PerConnection => Accepted::Skipped(OsErrorClass::from_io(&e)),
            AcceptFailure::ListenerFailed => Accepted::Failed(e),
            AcceptFailure::Pressure => Accepted::Pause(self.next_backoff()),
            AcceptFailure::Descriptors => {
                shed(self);
                Accepted::Pause(self.next_backoff())
            }
        }
    }

    #[cfg(unix)]
    fn shed_one(&mut self, listener: &TcpListener) {
        // Best effort: another thread can take the freed slot first; the backoff then applies.
        self.reserve = None;
        if let Ok((stream, _)) = listener.accept() {
            let _ = sys::set_linger(stream.sock(), Some(Duration::ZERO));
            drop(stream);
        }
        self.reserve = open_reserve();
    }

    #[cfg(windows)]
    fn shed_one(&mut self, _listener: &TcpListener) {}
}

/// Whether an accepted peer address can key caps and the gate (appendix A case 47).
fn usable_peer(peer: SocketAddr) -> bool {
    !peer.ip().is_unspecified() && peer.port() != 0
}

/// The spare descriptor; `None` when it cannot be opened (retried at the next `EMFILE`).
#[cfg(unix)]
fn open_reserve() -> Option<std::fs::File> {
    #[cfg(any(test, net_io_shim))]
    if sys::shim::check(sys::shim::Op::Reserve).is_err() {
        return None;
    }
    std::fs::File::open("/dev/null").ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff_doubles_to_one_second() {
        let mut a = Acceptor::new();
        let seq: Vec<_> = (0..13).map(|_| a.next_backoff()).collect();
        assert_eq!(seq[0], Duration::from_millis(1));
        assert_eq!(seq[1], Duration::from_millis(2));
        assert_eq!(*seq.last().unwrap(), BACKOFF_MAX);
    }

    #[test]
    fn test_accept_again_when_nothing_pending() {
        let l = sys::tcp_listener(
            "127.0.0.1:0".parse().unwrap(),
            &crate::opts::ListenOptions::new().params(),
        )
        .unwrap();
        let mut a = Acceptor::new();
        assert!(matches!(a.accept(&l), Accepted::Again));
        let _c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let mut got = false;
        for _ in 0..200 {
            if let Accepted::Conn(..) = a.accept(&l) {
                got = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(got);
    }

    #[test]
    fn test_unspecified_or_portless_peer_is_not_usable() {
        assert!(usable_peer("10.0.0.1:5000".parse().unwrap()));
        assert!(usable_peer("[2001:db8::1]:5000".parse().unwrap()));
        assert!(!usable_peer("0.0.0.0:5000".parse().unwrap()));
        assert!(!usable_peer("[::]:5000".parse().unwrap()));
        assert!(!usable_peer("10.0.0.1:0".parse().unwrap()));
    }

    /// Edge cases 40 and 41: `EMFILE` sheds one connection and pauses; a reserve
    /// that cannot be reopened is retried at the next `EMFILE`.
    #[cfg(unix)]
    #[test]
    fn test_emfile_sheds_and_retries_the_reserve() {
        use crate::sys::shim::{Fault, Op, clear_here, program_here};
        let l = sys::tcp_listener(
            "127.0.0.1:0".parse().unwrap(),
            &crate::opts::ListenOptions::new().params(),
        )
        .unwrap();
        let mut a = Acceptor::new();
        assert!(a.reserve.is_some());
        let mut c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        // Before the reset: macOS refuses setsockopt on a socket that was reset.
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        program_here(Op::Accept, 0, 2, Fault::Os(sys::errno::EMFILE));
        program_here(Op::Reserve, 0, 1, Fault::Os(sys::errno::EMFILE));
        assert!(matches!(a.accept(&l), Accepted::Pause(d) if d == BACKOFF_START));
        assert!(a.reserve.is_none(), "the reopen failed");
        // The shed connection was reset, not left in the backlog.
        let mut b = [0u8; 1];
        match std::io::Read::read(&mut c, &mut b) {
            Ok(0) => {}
            Err(e)
                if !matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            other => panic!("the shed connection was not reset: {other:?}"),
        }
        assert!(matches!(a.accept(&l), Accepted::Pause(d) if d == BACKOFF_START * 2));
        assert!(a.reserve.is_some(), "retried at the next EMFILE");
        clear_here();
    }
}
