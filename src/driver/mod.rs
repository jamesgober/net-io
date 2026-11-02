//! Drivers: what moves the bytes.
//!
//! The blocking pool ships in `0.3.0`, the reactor (epoll, kqueue, IOCP) in
//! `0.5.0`, io_uring after `1.0.0`. The [`Driver`] trait is public from `0.5.0`
//! (Tier 3, unstable until `1.0.0`) so an executor adapter and later drivers can
//! build on it.
//!
//! The interface is completion-shaped (decision D-005): an operation owns its
//! buffers until its completion hands them back, which is what IOCP and io_uring
//! need; epoll and kqueue adapt by making the non-blocking call when readiness
//! arrives. Cancellation always ends in exactly one completion.

#[cfg(all(feature = "reactor", windows))]
pub(crate) mod iocp;
#[cfg(all(feature = "reactor", unix))]
pub(crate) mod ready;

use std::collections::VecDeque;
use std::io::IoSlice;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::buf::Buffer;
use crate::error::{NetError, OsErrorClass};
use crate::session::{Chunk, Output};

/// Which driver moves the bytes.
///
/// `Auto` picks the reactor where it is built and available, otherwise the
/// blocking pool.
///
/// # Examples
///
/// ```
/// assert_eq!(net_io::DriverKind::default(), net_io::DriverKind::Auto);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum DriverKind {
    /// A bounded pool of threads, one connection per thread.
    Blocking,
    /// One event loop per worker (epoll, kqueue, IOCP); from `0.5.0`.
    Reactor,
    /// io_uring on Linux; after `1.0.0`.
    Uring,
    /// The reactor where available, otherwise the blocking pool.
    #[default]
    Auto,
}

impl DriverKind {
    /// The driver `Auto` resolves to in this build.
    pub(crate) fn resolve(self) -> DriverKind {
        match self {
            DriverKind::Auto if DriverKind::reactor_built() => DriverKind::Reactor,
            DriverKind::Auto => DriverKind::Blocking,
            other => other,
        }
    }

    /// Whether this build has a reactor for this OS.
    pub(crate) const fn reactor_built() -> bool {
        cfg!(feature = "reactor")
    }
}

/// A borrowed socket, as a [`Driver`] registers it.
#[cfg(unix)]
pub type BorrowedSocket<'a> = std::os::fd::BorrowedFd<'a>;
/// A borrowed socket, as a [`Driver`] registers it.
#[cfg(windows)]
pub type BorrowedSocket<'a> = std::os::windows::io::BorrowedSocket<'a>;

/// Names a registered socket. The low 32 bits index a dense table inside the
/// driver, so keep them small; the high bits are free for a generation.
///
/// ```
/// let t = net_io::Token(7);
/// assert_eq!(t, net_io::Token(7));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Token(pub u64);

impl Token {
    pub(crate) fn index(self) -> usize {
        (self.0 & 0xFFFF_FFFF) as usize
    }
}

/// What to do on a registered socket. The operation owns its buffers until its
/// completion returns them.
#[non_exhaustive]
#[derive(Debug)]
pub enum Operation {
    /// Completes when a connection is waiting (accept it from the listener).
    /// Refused on Windows, where a listener is never registered (D-016).
    Accept {
        /// The listener.
        listener: Token,
    },
    /// Receives into `buffer`'s spare room (at most once); `Ok(0)` is end of stream.
    Receive {
        /// The socket.
        token: Token,
        /// Where the bytes land; returned by the completion.
        buffer: Buffer,
    },
    /// Completes when bytes can be read, without holding a buffer: idle
    /// connections wait this way.
    ReceiveZero {
        /// The socket.
        token: Token,
    },
    /// Sends what `chunks` holds; the result says how many bytes went out, which
    /// can be fewer than all of them. The chunks come back with the completion.
    Send {
        /// The socket.
        token: Token,
        /// The bytes.
        chunks: SendChunks,
    },
    /// Connects a registered, non-blocking socket.
    Connect {
        /// The socket.
        token: Token,
        /// The peer.
        addr: SocketAddr,
    },
    /// Completes once every other operation on the socket has; the caller then
    /// closes it. Abortive when asked (linger 0).
    Close {
        /// The socket.
        token: Token,
        /// Reset instead of FIN.
        abortive: bool,
    },
    /// Completes at once (a turn of the loop).
    Nop {
        /// Echoed in the completion.
        token: Token,
    },
}

impl Operation {
    fn token(&self) -> Token {
        match self {
            Operation::Accept { listener } => *listener,
            Operation::Receive { token, .. }
            | Operation::ReceiveZero { token }
            | Operation::Send { token, .. }
            | Operation::Connect { token, .. }
            | Operation::Close { token, .. }
            | Operation::Nop { token } => *token,
        }
    }
}

/// Which operation a completion finishes.
///
/// ```
/// assert_ne!(net_io::OperationKind::Receive, net_io::OperationKind::Send);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationKind {
    /// [`Operation::Accept`].
    Accept,
    /// [`Operation::Receive`] and [`Operation::ReceiveZero`].
    Receive,
    /// [`Operation::Send`].
    Send,
    /// [`Operation::Connect`].
    Connect,
    /// [`Operation::Close`].
    Close,
    /// [`Operation::Nop`].
    Nop,
}

/// A finished operation.
#[non_exhaustive]
#[derive(Debug)]
pub struct Completion {
    /// The socket.
    pub token: Token,
    /// Which operation finished.
    pub kind: OperationKind,
    /// Bytes moved, or the error class. A cancelled operation is `Aborted`.
    pub result: Result<usize, OsErrorClass>,
    /// The receive buffer, returned with its new length.
    pub buffer: Option<Buffer>,
    /// The send chunks, returned as they were.
    pub chunks: Option<SendChunks>,
}

impl Completion {
    pub(crate) fn new(
        token: Token,
        kind: OperationKind,
        result: Result<usize, OsErrorClass>,
    ) -> Completion {
        Completion {
            token,
            kind,
            result,
            buffer: None,
            chunks: None,
        }
    }
}

/// How many completions one wait returns.
pub(crate) const COMPLETIONS: usize = 256;

/// What a wait fills; fixed capacity (256), so a wait never allocates.
#[derive(Debug)]
pub struct Completions {
    items: Vec<Completion>,
}

impl Default for Completions {
    fn default() -> Completions {
        Completions::new()
    }
}

impl Completions {
    /// Room for 256 completions.
    #[must_use]
    pub fn new() -> Completions {
        Completions {
            items: Vec::with_capacity(COMPLETIONS),
        }
    }

    /// How many completions are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether none are held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Takes the completions out, oldest first.
    pub fn drain(&mut self) -> impl Iterator<Item = Completion> + '_ {
        self.items.drain(..)
    }

    #[cfg(feature = "reactor")]
    pub(crate) fn push(&mut self, c: Completion) {
        self.items.push(c);
    }

    #[cfg(feature = "reactor")]
    pub(crate) fn has_room(&self) -> bool {
        self.items.len() < COMPLETIONS
    }
}

/// The bytes of one send: up to 64 chunks, taken from an [`Output`] or built from
/// a pool buffer.
#[derive(Debug, Default)]
pub struct SendChunks {
    pub(crate) chunks: VecDeque<Chunk>,
}

impl SendChunks {
    /// One pool buffer.
    #[must_use]
    pub fn from_buffer(buffer: Buffer) -> SendChunks {
        let mut chunks = VecDeque::with_capacity(1);
        chunks.push_back(Chunk::Pooled(buffer, 0));
        SendChunks { chunks }
    }

    /// Takes everything queued in `output`; give it back with [`SendChunks::restore`].
    pub(crate) fn take(output: &mut Output) -> SendChunks {
        SendChunks {
            chunks: std::mem::take(&mut output.chunks),
        }
    }

    /// Puts the chunks back into `output`, keeping the queue's allocation.
    pub(crate) fn restore(self, output: &mut Output) {
        output.chunks = self.chunks;
    }

    /// Bytes held.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.chunks.iter().map(|c| c.remaining().len()).sum()
    }

    /// Marks `n` bytes of the front chunks sent; `true` when bytes remain.
    #[cfg(feature = "reactor")]
    pub(crate) fn advance(&mut self, mut n: usize) -> bool {
        while let Some(front) = self.chunks.front_mut() {
            let rem = front.remaining().len();
            if n < rem {
                match front {
                    Chunk::Pooled(_, off) | Chunk::Static(_, off) => *off += n,
                }
                return true;
            }
            if self.chunks.len() == 1 {
                return false;
            }
            n -= rem;
            self.chunks.pop_front();
        }
        false
    }

    /// The first buffer back, for a send built with [`SendChunks::from_buffer`].
    pub(crate) fn into_buffer(mut self) -> Option<Buffer> {
        match self.chunks.pop_front() {
            Some(Chunk::Pooled(b, _)) => Some(b),
            _ => None,
        }
    }

    /// Fills `out` with the chunks' bytes; returns how many slices.
    #[cfg(feature = "reactor")]
    pub(crate) fn slices<'a>(&'a self, out: &mut [IoSlice<'a>]) -> usize {
        let mut n = 0;
        for chunk in self.chunks.iter().take(out.len()) {
            out[n] = IoSlice::new(chunk.remaining());
            n += 1;
        }
        n
    }
}

/// Why [`Driver::submit`] refused an operation; it comes back with its buffers.
#[derive(Debug)]
pub struct Rejected {
    /// The operation.
    pub operation: Operation,
}

/// Wakes a driver's [`Driver::wait`] from any thread.
#[derive(Clone, Debug)]
pub struct DriverWaker {
    pub(crate) inner: Arc<WakerInner>,
}

#[cfg(feature = "reactor")]
pub(crate) type WakerInner = crate::sys::PollWaker;
#[cfg(not(feature = "reactor"))]
#[derive(Debug)]
pub(crate) struct WakerInner;

impl DriverWaker {
    /// Ends the current or next wait. Cheap to call repeatedly.
    pub fn wake(&self) {
        #[cfg(feature = "reactor")]
        self.inner.wake();
    }
}

/// A driver: one per worker, used from one thread. See the module docs.
///
/// Unstable until `1.0.0`. A socket must stay open from [`Driver::register`] until
/// [`Driver::deregister`] returns.
pub trait Driver: Send {
    /// Which driver this is.
    fn kind(&self) -> DriverKind;

    /// Adds a non-blocking socket under `token`.
    ///
    /// # Errors
    ///
    /// `Os` when the OS refuses.
    fn register(&mut self, socket: BorrowedSocket<'_>, token: Token) -> Result<(), NetError>;

    /// Starts an operation; its completion arrives through [`Driver::wait`].
    ///
    /// # Errors
    ///
    /// [`Rejected`] gives the operation and its buffers back: the token is not
    /// registered, or the same kind of operation is already pending on it.
    fn submit(&mut self, operation: Operation) -> Result<(), Rejected>;

    /// Fills `out` with finished operations, waiting up to `timeout` for the
    /// first (`None`: until one finishes or the waker fires). Returns how many.
    ///
    /// # Errors
    ///
    /// `Os` when the wait itself fails.
    fn wait(&mut self, out: &mut Completions, timeout: Option<Duration>)
    -> Result<usize, NetError>;

    /// Cancels the pending operation of kind `which`; it still completes exactly
    /// once (with `Aborted`, or with its result if it already finished).
    ///
    /// # Errors
    ///
    /// `Os` when the OS refuses.
    fn cancel(&mut self, token: Token, which: OperationKind) -> Result<(), NetError>;

    /// Removes the socket; no completion arrives for it afterwards.
    ///
    /// # Errors
    ///
    /// `Os` when the OS refuses.
    fn deregister(&mut self, token: Token) -> Result<(), NetError>;

    /// A waker for this driver.
    fn waker(&self) -> DriverWaker;
}

pub(crate) fn operation_token(op: &Operation) -> Token {
    op.token()
}
