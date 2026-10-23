//! Sans-IO sessions: a protocol engine reacts to bytes and returns what to do next.

use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::buf::{Buffer, BufferPool};
use crate::completer::Completer;
use crate::error::{CloseReason, LimitKind, NetError, RefusalCause, TimeoutKind};
use crate::gate::KillHandle;
use crate::id::WorkerId;
use crate::info::{ConnectionInfo, GateTag};
use crate::limits::SizeClass;
use crate::link::Link;

/// A sans-IO protocol engine bound to one connection.
///
/// net-io reads, calls the session with the bytes, and does what the returned
/// [`Step`] says. Sessions are called only on the worker that owns the
/// connection, never concurrently.
///
/// # Examples
///
/// ```no_run
/// use net_io::{Input, Session, SessionContext, Step};
///
/// struct Echo;
/// impl Session for Echo {
///     fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
///         // Copy as much as the output budget takes; the rest stays in `input`,
///         // and net-io calls on_data again after the flush because the input changed.
///         let taken = cx.output().push_partial(input.bytes());
///         input.consume(taken);
///         Step::Write
///     }
/// }
///
/// let server = net_io::serve_sessions("127.0.0.1:7002", |_info: &net_io::ConnectionInfo| Echo)?;
/// server.wait_for_stop();
/// # Ok::<(), net_io::NetError>(())
/// ```
pub trait Session: Send + 'static {
    /// Once, after admission and the handshake.
    fn on_open(&mut self, cx: &mut SessionContext<'_>) -> Step {
        let _ = cx;
        Step::Read
    }

    /// Bytes arrived; `input` holds everything not yet consumed.
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step;

    /// After a `Step::Write` flushed all pending output.
    fn on_writable(&mut self, cx: &mut SessionContext<'_>) -> Step {
        let _ = cx;
        Step::Read
    }

    /// Another thread posted a completion through this connection's [`Completer`].
    fn on_wake(&mut self, cx: &mut SessionContext<'_>, token: u32, value: u64) -> Step {
        let _ = (cx, token, value);
        Step::Abort
    }

    /// A deadline passed. `Close` or `Abort` closes with the timeout's own reason
    /// and close style; anything else re-arms with the same limits.
    fn on_timeout(&mut self, cx: &mut SessionContext<'_>, which: TimeoutKind) -> Step {
        let _ = (cx, which);
        Step::Close
    }

    /// The peer sent FIN; the session may keep writing (half-close).
    fn on_peer_closed(&mut self, cx: &mut SessionContext<'_>) -> Step {
        let _ = cx;
        Step::Close
    }

    /// The gate denied a write and no byte of the current response has left:
    /// write the protocol's refusal for `code` into `output`.
    fn on_denied(&mut self, code: u16, output: &mut Output) {
        let _ = (code, output);
    }

    /// Exactly once, with the one close reason.
    fn on_close(&mut self, info: &ConnectionInfo, reason: CloseReason) {
        let _ = (info, reason);
    }
}

/// Creates one session per admitted connection. Any `Fn(&ConnectionInfo) -> S` is one.
///
/// # Examples
///
/// ```
/// use net_io::{ConnectionInfo, Input, RefusalCause, Session, SessionContext, SessionFactory, Step};
///
/// struct Discard;
/// impl Session for Discard {
///     fn on_data(&mut self, _cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
///         let n = input.bytes().len();
///         input.consume(n);
///         Step::Read
///     }
/// }
///
/// struct OnlyLoopback;
/// impl SessionFactory for OnlyLoopback {
///     type Session = Discard;
///     fn open(&self, info: &ConnectionInfo) -> Result<Discard, RefusalCause> {
///         match info.client_addr() {
///             Some(addr) if addr.ip().is_loopback() => Ok(Discard),
///             _ => Err(RefusalCause::Session),
///         }
///     }
/// }
///
/// let info = ConnectionInfo::for_testing("10.0.0.1:1".parse().unwrap());
/// assert!(OnlyLoopback.open(&info).is_err());
/// ```
pub trait SessionFactory: Send + Sync + 'static {
    /// The session type.
    type Session: Session;

    /// A session for this connection.
    ///
    /// # Errors
    ///
    /// Refusing closes the connection with `CloseReason::Refused(cause)`.
    fn open(&self, info: &ConnectionInfo) -> Result<Self::Session, RefusalCause>;
}

impl<F, S> SessionFactory for F
where
    F: Fn(&ConnectionInfo) -> S + Send + Sync + 'static,
    S: Session,
{
    type Session = S;
    fn open(&self, info: &ConnectionInfo) -> Result<S, RefusalCause> {
        Ok(self(info))
    }
}

/// What the session wants next.
///
/// ```
/// assert_ne!(net_io::Step::Close, net_io::Step::Abort);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Wait for more input.
    Read,
    /// Flush pending output, then `on_writable`.
    Write,
    /// No reads, no idle timer, until a completion or the park deadline.
    Park {
        /// The deadline; `None` uses the park timeout.
        until: Option<Instant>,
    },
    /// Graceful: flush, FIN, bounded linger.
    Close,
    /// RST now.
    Abort,
}

/// Which deadlines run.
///
/// ```
/// assert_eq!(net_io::Phase::default(), net_io::Phase::Idle);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Phase {
    /// Between exchanges: the idle timeout.
    #[default]
    Idle,
    /// Receiving an exchange: the read timeout, the inbound rate, the exchange deadline.
    Receiving,
    /// Sending: the write timeout, the outbound rate, the exchange deadline.
    Sending,
}

/// Why a swap was refused.
///
/// ```
/// assert_ne!(net_io::SwapError::NotEmpty, net_io::SwapError::Busy);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwapError {
    /// The buffers are of different size classes.
    ClassMismatch,
    /// The incoming buffer has data.
    NotEmpty,
    /// A driver operation holds the buffer.
    Busy,
}

impl fmt::Display for SwapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SwapError::ClassMismatch => "the buffers are of different size classes",
            SwapError::NotEmpty => "the incoming buffer is not empty",
            SwapError::Busy => "a driver operation holds the buffer",
        })
    }
}

impl std::error::Error for SwapError {}

/// The connection's read buffer: a zero-copy view of what was read and not yet consumed.
///
/// ```
/// let mut input = net_io::Input::from_bytes(b"GET / HTTP/1.1\r\n");
/// assert_eq!(input.bytes(), b"GET / HTTP/1.1\r\n");
/// input.consume(4);
/// assert_eq!(input.bytes(), b"/ HTTP/1.1\r\n");
/// ```
#[derive(Debug)]
pub struct Input {
    pub(crate) buf: Buffer,
    pub(crate) start: usize,
    pub(crate) changed: bool,
}

impl Input {
    pub(crate) fn new(buf: Buffer) -> Input {
        Input {
            buf,
            start: 0,
            changed: false,
        }
    }

    /// An input holding `bytes`, for tests of sessions (allocates).
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Input {
        let class = (bytes.len() as u32)
            .max(1024)
            .next_power_of_two()
            .max(SizeClass::SMALL.bytes());
        let class = SizeClass::new(class.min(1 << 20)).unwrap_or(SizeClass::LARGE);
        let mut pool = BufferPool::standalone(u64::from(class.bytes()));
        let mut input = Input::new(match pool.take(class) {
            Some(b) => b,
            None => return Input::new(Buffer::detached(class)),
        });
        let n = bytes.len().min(input.buf.capacity());
        input.buf.spare()[..n].copy_from_slice(&bytes[..n]);
        input.buf.set_len(n);
        input
    }

    /// The unconsumed bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.buf.as_slice()[self.start..]
    }

    /// Consumes `n` bytes (saturating at the length).
    pub fn consume(&mut self, n: usize) {
        let n = n.min(self.buf.len() - self.start);
        self.start += n;
        if n > 0 {
            self.changed = true;
        }
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        }
    }

    /// Whether the buffer is full: the session must consume or grow it.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.buf.len() == self.buf.capacity() && self.start == 0
    }

    /// The buffer's size class.
    #[must_use]
    pub fn class(&self) -> SizeClass {
        self.buf.class()
    }

    /// Exchanges the read buffer with an empty `other` of the same class in O(1):
    /// `other` now holds the unconsumed bytes, and the connection reads into the
    /// buffer it was given.
    ///
    /// # Errors
    ///
    /// [`SwapError::ClassMismatch`], [`SwapError::NotEmpty`].
    ///
    /// ```
    /// use net_io::{BufferPool, Input};
    /// let mut input = Input::from_bytes(b"body");
    /// let mut pool = BufferPool::standalone(1 << 20);
    /// let mut spare = pool.take(input.class()).unwrap();
    /// input.swap(&mut spare).unwrap();
    /// assert_eq!(spare.as_slice(), b"body");
    /// assert!(input.bytes().is_empty());
    /// ```
    pub fn swap(&mut self, other: &mut Buffer) -> Result<(), SwapError> {
        if other.class() != self.buf.class() {
            return Err(SwapError::ClassMismatch);
        }
        if !other.is_empty() {
            return Err(SwapError::NotEmpty);
        }
        if self.start > 0 {
            self.buf.compact(self.start);
            self.start = 0;
        }
        std::mem::swap(&mut self.buf, other);
        self.changed = true;
        Ok(())
    }

    /// Room to read into, compacting first when the free tail is under a quarter.
    pub(crate) fn spare_for_read(&mut self) -> &mut [u8] {
        let free = self.buf.capacity() - self.buf.len();
        if self.start > 0 && free < self.buf.capacity() / 4 {
            self.buf.compact(self.start);
            self.start = 0;
        }
        self.buf.spare()
    }

    pub(crate) fn filled(&mut self, n: usize) {
        let len = self.buf.len() + n;
        self.buf.set_len(len);
        self.changed = true;
    }
}

/// The output budget was reached; return `Step::Write` and continue after the flush.
///
/// ```
/// assert_eq!(net_io::OutputFull.to_string(), "the connection's output budget is full");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputFull;

impl fmt::Display for OutputFull {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the connection's output budget is full")
    }
}

impl std::error::Error for OutputFull {}

#[derive(Debug)]
pub(crate) enum Chunk {
    Pooled(Buffer, usize),
    Static(&'static [u8], usize),
}

impl Chunk {
    pub(crate) fn remaining(&self) -> &[u8] {
        match self {
            Chunk::Pooled(b, off) => &b.as_slice()[*off..],
            Chunk::Static(s, off) => &s[*off..],
        }
    }
}

/// What the session wants written: a bounded queue of chunks.
///
/// ```
/// let mut out = net_io::Output::standalone(64 * 1024);
/// out.push(b"hello ").unwrap();
/// out.push_static(b"world").unwrap();
/// assert_eq!(out.pending(), 11);
/// ```
#[derive(Debug)]
pub struct Output {
    pub(crate) chunks: VecDeque<Chunk>,
    free: Vec<Buffer>,
    budget: Arc<AtomicU64>,
    limit: u32,
    used: u32,
    wipe: bool,
    pub(crate) response_open: bool,
    pub(crate) response_tag: Option<GateTag>,
    pub(crate) bytes_since_begin: u64,
}

const OUTPUT_CLASS: SizeClass = SizeClass::MEDIUM;
const MAX_CHUNKS: usize = 64;

impl Output {
    pub(crate) fn new(budget: Arc<AtomicU64>, limit: u32, wipe: bool) -> Output {
        Output {
            chunks: VecDeque::with_capacity(MAX_CHUNKS),
            free: Vec::new(),
            budget,
            limit,
            used: 0,
            wipe,
            response_open: false,
            response_tag: None,
            bytes_since_begin: 0,
        }
    }

    /// An output with its own budget, for tests of sessions (allocates).
    #[must_use]
    pub fn standalone(limit: u32) -> Output {
        Output::new(Arc::new(AtomicU64::new(u64::from(limit))), limit, true)
    }

    fn take_buffer(&mut self) -> Option<Buffer> {
        if let Some(b) = self.free.pop() {
            return Some(b);
        }
        let bytes = u64::from(OUTPUT_CLASS.bytes());
        let mut left = self.budget.load(Ordering::Relaxed);
        loop {
            if left < bytes {
                return None;
            }
            match self.budget.compare_exchange_weak(
                left,
                left - bytes,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(Buffer::detached(OUTPUT_CLASS)),
                Err(actual) => left = actual,
            }
        }
    }

    fn room(&self) -> usize {
        let tail = match self.chunks.back() {
            Some(Chunk::Pooled(b, _)) => b.capacity() - b.len(),
            _ => 0,
        };
        let more = (self.limit.saturating_sub(self.used) / OUTPUT_CLASS.bytes()) as usize
            * OUTPUT_CLASS.bytes() as usize;
        tail + more
    }

    /// Copies as much of `bytes` as the budget allows; returns how many were taken.
    pub fn push_partial(&mut self, mut bytes: &[u8]) -> usize {
        let mut taken = 0;
        while !bytes.is_empty() {
            if let Some(Chunk::Pooled(b, _)) = self.chunks.back_mut() {
                let spare = b.spare();
                if !spare.is_empty() {
                    let n = spare.len().min(bytes.len());
                    spare[..n].copy_from_slice(&bytes[..n]);
                    let len = b.len() + n;
                    b.set_len(len);
                    bytes = &bytes[n..];
                    taken += n;
                    continue;
                }
            }
            if self.chunks.len() >= MAX_CHUNKS
                || self.used.saturating_add(OUTPUT_CLASS.bytes()) > self.limit
            {
                break;
            }
            match self.take_buffer() {
                Some(b) => {
                    self.used += OUTPUT_CLASS.bytes();
                    self.chunks.push_back(Chunk::Pooled(b, 0));
                }
                None => break,
            }
        }
        taken
    }

    /// Copies all of `bytes`, or nothing.
    ///
    /// # Errors
    ///
    /// [`OutputFull`] when the budget cannot take all of it.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), OutputFull> {
        if bytes.len() > self.room() {
            return Err(OutputFull);
        }
        let n = self.push_partial(bytes);
        if n == bytes.len() {
            Ok(())
        } else {
            Err(OutputFull)
        }
    }

    /// Moves an owned buffer in (no copy).
    ///
    /// # Errors
    ///
    /// [`OutputFull`] when the budget or the chunk limit is reached.
    pub fn push_buffer(&mut self, buffer: Buffer) -> Result<(), OutputFull> {
        let size = u32::try_from(buffer.capacity()).unwrap_or(u32::MAX);
        if self.chunks.len() >= MAX_CHUNKS || self.used.saturating_add(size) > self.limit {
            return Err(OutputFull);
        }
        self.used += size;
        self.chunks.push_back(Chunk::Pooled(buffer, 0));
        Ok(())
    }

    /// Queues a static slice (no copy, not counted against the budget).
    ///
    /// # Errors
    ///
    /// [`OutputFull`] when the chunk limit is reached.
    pub fn push_static(&mut self, bytes: &'static [u8]) -> Result<(), OutputFull> {
        if self.chunks.len() >= MAX_CHUNKS {
            return Err(OutputFull);
        }
        if !bytes.is_empty() {
            self.chunks.push_back(Chunk::Static(bytes, 0));
        }
        Ok(())
    }

    /// Marks the start of a response (for the gate's denial boundary).
    pub fn begin_response(&mut self) {
        self.response_open = true;
        self.response_tag = None;
        self.bytes_since_begin = 0;
    }

    /// Marks the start of a response and tags it for the gate (`WriteCheck::response`).
    pub fn begin_tagged_response(&mut self, tag: GateTag) {
        self.begin_response();
        self.response_tag = Some(tag);
    }

    /// Marks the end of the response; clears the tag.
    pub fn end_response(&mut self) {
        self.response_open = false;
        self.response_tag = None;
    }

    /// Bytes queued and not yet sent.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.chunks.iter().map(|c| c.remaining().len()).sum()
    }

    /// Whether nothing is queued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// Overwrites every pending chunk net-io owns with zeroes and drops it.
    pub fn wipe_all(&mut self) {
        while let Some(chunk) = self.chunks.pop_front() {
            if let Chunk::Pooled(mut b, _) = chunk {
                b.wipe();
                self.release_chunk(b);
            }
        }
        self.used = 0;
    }

    fn release_chunk(&mut self, mut b: Buffer) {
        self.used = self
            .used
            .saturating_sub(u32::try_from(b.capacity()).unwrap_or(u32::MAX));
        if self.wipe {
            b.wipe();
        } else {
            b.clear();
        }
        if b.class() == OUTPUT_CLASS {
            self.free.push(b);
        } else {
            // A buffer moved in with push_buffer goes back to the shared budget.
            self.budget
                .fetch_add(b.capacity() as u64, Ordering::Release);
        }
    }

    /// Marks `n` bytes as sent, releasing finished chunks.
    pub(crate) fn advance(&mut self, mut n: usize) {
        while let Some(front) = self.chunks.front_mut() {
            let rem = front.remaining().len();
            if n < rem {
                match front {
                    Chunk::Pooled(_, off) | Chunk::Static(_, off) => *off += n,
                }
                return;
            }
            n -= rem;
            if let Some(Chunk::Pooled(b, _)) = self.chunks.pop_front() {
                self.release_chunk(b);
            }
        }
    }

    /// Resets for the next connection.
    pub(crate) fn reset(&mut self) {
        self.wipe_all();
        self.response_open = false;
        self.response_tag = None;
        self.bytes_since_begin = 0;
    }
}

/// Everything a session may touch, for one call.
pub struct SessionContext<'a> {
    pub(crate) link: &'a mut Link,
    pub(crate) output: &'a mut Output,
    pub(crate) pool: &'a mut BufferPool,
    pub(crate) completer: &'a Completer,
    pub(crate) draining: bool,
    pub(crate) pressure: f32,
    pub(crate) worker: WorkerId,
    pub(crate) grow_to: Option<SizeClass>,
}

impl SessionContext<'_> {
    /// The connection's facts.
    #[must_use]
    pub fn info(&self) -> &ConnectionInfo {
        &self.link.info
    }

    /// The output queue.
    pub fn output(&mut self) -> &mut Output {
        self.output
    }

    /// The worker's clock.
    #[must_use]
    pub fn now(&self) -> Instant {
        self.link.now()
    }

    /// Chooses which deadlines run.
    pub fn set_phase(&mut self, phase: crate::session::Phase) {
        self.link.set_phase(phase);
    }

    /// The deadline for the current exchange (`None` clears it).
    pub fn set_exchange_deadline(&mut self, at: Option<Instant>) {
        self.link.set_exchange_deadline(at);
    }

    /// Overrides this connection's idle timeout from its next wait for an
    /// exchange on; `None` restores the listener's limit. For example, a
    /// protocol shortens keep-alive while the worker pool is nearly full.
    /// Values below the timer tick are raised to one tick.
    ///
    /// ```no_run
    /// use std::time::Duration;
    /// use net_io::{Input, Session, SessionContext, Step};
    ///
    /// struct KeepAlive;
    /// impl Session for KeepAlive {
    ///     fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
    ///         let n = input.bytes().len();
    ///         input.consume(n);
    ///         let short = (cx.pressure() > 0.75).then_some(Duration::from_secs(2));
    ///         cx.set_idle_timeout(short);
    ///         Step::Write
    ///     }
    /// }
    /// ```
    pub fn set_idle_timeout(&mut self, timeout: Option<Duration>) {
        self.link.set_idle_timeout(timeout);
    }

    /// Whether drain started: finish the current exchange, then close.
    #[must_use]
    pub fn draining(&self) -> bool {
        self.draining
    }

    /// 0.0 to 1.0: busy workers (blocking driver); 1.0 while the control line sheds.
    #[must_use]
    pub fn pressure(&self) -> f32 {
        self.pressure
    }

    /// A handle other threads can use to abort this connection.
    #[must_use]
    pub fn kill_handle(&self) -> KillHandle {
        KillHandle {
            slot: self.link.slot.clone(),
            generation: self.link.generation,
            id: self.link.info.id,
        }
    }

    /// This worker's completion queue.
    #[must_use]
    pub fn completer(&self) -> Completer {
        self.completer.clone()
    }

    /// The worker that runs this connection.
    #[must_use]
    pub fn worker(&self) -> WorkerId {
        self.worker
    }

    /// This worker's buffer pool.
    pub fn buffers(&mut self) -> &mut BufferPool {
        self.pool
    }

    /// Returns a buffer (for example one taken by `Input::swap`); it is wiped.
    pub fn release(&mut self, buffer: Buffer) {
        self.pool.put(buffer);
    }

    /// Moves the unconsumed input into a buffer of `class` after this call returns.
    ///
    /// # Errors
    ///
    /// `Limit { which: ReadBuffer }` above the maximum read class.
    pub fn grow_input(&mut self, class: SizeClass) -> Result<(), NetError> {
        if class > self.link.limits.read_class_max {
            return Err(NetError::Limit {
                which: LimitKind::ReadBuffer,
            });
        }
        self.grow_to = Some(class);
        Ok(())
    }
}

impl fmt::Debug for SessionContext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionContext")
            .field("id", &self.link.info.id)
            .field("draining", &self.draining)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_input_consume_saturates_and_resets() {
        let mut i = Input::from_bytes(b"abc");
        i.consume(10);
        assert!(i.bytes().is_empty());
        assert_eq!(i.start, 0);
    }

    #[test]
    fn test_input_swap_rules() {
        let mut i = Input::from_bytes(b"xyz");
        let mut pool = BufferPool::standalone(1 << 22);
        let mut wrong = pool.take(SizeClass::LARGE).unwrap();
        assert_eq!(i.swap(&mut wrong), Err(SwapError::ClassMismatch));
        let mut full = pool.take(i.class()).unwrap();
        full.set_len(1);
        assert_eq!(i.swap(&mut full), Err(SwapError::NotEmpty));
        let mut empty = pool.take(i.class()).unwrap();
        i.consume(1);
        i.swap(&mut empty).unwrap();
        assert_eq!(empty.as_slice(), b"yz");
    }

    #[test]
    fn test_output_push_all_or_nothing_and_partial() {
        let mut o = Output::standalone(OUTPUT_CLASS.bytes());
        let big = vec![7u8; OUTPUT_CLASS.bytes() as usize + 1];
        assert_eq!(o.push(&big), Err(OutputFull));
        assert!(o.is_empty());
        assert_eq!(o.push_partial(&big), OUTPUT_CLASS.bytes() as usize);
        assert_eq!(o.pending(), OUTPUT_CLASS.bytes() as usize);
    }

    #[test]
    fn test_output_advance_releases_chunks() {
        let mut o = Output::standalone(1 << 20);
        o.push(b"hello").unwrap();
        o.push_static(b" world").unwrap();
        o.advance(7);
        assert_eq!(o.pending(), 4);
        assert_eq!(o.chunks.len(), 1);
        assert_eq!(o.used, 0);
        o.advance(4);
        assert!(o.is_empty());
    }

    #[test]
    fn test_output_response_markers() {
        let mut o = Output::standalone(1 << 20);
        o.begin_tagged_response(GateTag(3));
        assert_eq!(o.response_tag, Some(GateTag(3)));
        o.end_response();
        assert_eq!(o.response_tag, None);
    }

    /// Property: whatever mix of pushes is accepted and however the sends split,
    /// the bytes that leave are the accepted bytes in order, and the budget returns.
    #[test]
    fn prop_output_stream_matches_accepted_pushes() {
        use crate::testing::Gen;
        static TEXT: [u8; 4096] = {
            let mut t = [0u8; 4096];
            let mut i = 0;
            while i < t.len() {
                t[i] = (i % 251) as u8;
                i += 1;
            }
            t
        };
        let mut g = Gen::new(0x0047_0041);
        for round in 0..if cfg!(miri) { 3 } else { 300 } {
            let mut o = Output::standalone(64 * 1024);
            let mut expected = Vec::new();
            let mut sent = Vec::new();
            for _ in 0..200 {
                match g.below(4) {
                    0 => {
                        let n = g.below(40_000) as usize;
                        let data: Vec<u8> = (0..n).map(|_| g.next_u64() as u8).collect();
                        let took = o.push_partial(&data);
                        expected.extend_from_slice(&data[..took]);
                    }
                    1 => {
                        let n = g.below(3000) as usize;
                        let data: Vec<u8> = (0..n).map(|_| g.next_u64() as u8).collect();
                        if o.push(&data).is_ok() {
                            expected.extend_from_slice(&data);
                        }
                    }
                    2 => {
                        let start = g.below(TEXT.len() as u64) as usize;
                        let piece = &TEXT[start..];
                        if o.push_static(piece).is_ok() {
                            expected.extend_from_slice(piece);
                        }
                    }
                    _ => {
                        // A send of a random size, taken from the front chunks as a vectored write would.
                        let mut want = g.below(70_000) as usize;
                        let mut taken = 0;
                        for chunk in o.chunks.iter() {
                            if want == 0 {
                                break;
                            }
                            let r = chunk.remaining();
                            let n = r.len().min(want);
                            sent.extend_from_slice(&r[..n]);
                            want -= n;
                            taken += n;
                        }
                        o.advance(taken);
                    }
                }
            }
            while !o.is_empty() {
                let n = o.chunks.front().map_or(0, |c| c.remaining().len());
                if let Some(c) = o.chunks.front() {
                    sent.extend_from_slice(c.remaining());
                }
                o.advance(n);
            }
            assert!(sent == expected, "round {round}: stream differs");
            assert_eq!(o.used, 0, "round {round}: budget not returned");
            assert_eq!(o.pending(), 0);
        }
    }
}
