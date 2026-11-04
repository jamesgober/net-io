//! The connection core shared by `TcpConnection` and the server's workers:
//! deadlines per phase, the minimum transfer rate, the gate check before every
//! send, kill detection, and graceful or abortive close.

use std::io::{self, IoSlice};
use std::net::Shutdown;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::buf::Buffer;
use crate::error::{
    CloseReason, Direction, KillReason, LimitKind, NetError, OsErrorClass, TimeoutKind,
};
use crate::gate::{Denial, ErasedGate, WriteCheck};
use crate::info::{ConnectionInfo, GateTag, Transport};
use crate::limits::Effective;
use crate::rate::Rate;
use crate::session::Phase;
use crate::sys::{self, AsSock, Interest, KillSlot, Ready, Wake};
use crate::tcp::Health;
use crate::time::Clock;
use crate::tls::{TlsError, TlsEvent, TlsFailure, TlsSession};

/// Where time comes from.
#[derive(Clone)]
pub(crate) enum ClockRef {
    Monotonic,
    Custom(Arc<dyn Clock>),
    /// The time of this reactor turn: one clock read per trip through the OS, however
    /// many connections and deadlines the turn touches. Off a worker's thread, the
    /// clock itself.
    #[cfg(feature = "reactor")]
    Turn,
}

#[cfg(feature = "reactor")]
thread_local! {
    static TURN: std::cell::Cell<Option<Instant>> = const { std::cell::Cell::new(None) };
}

/// A new reactor turn: reads the clock for it.
#[cfg(feature = "reactor")]
pub(crate) fn begin_turn() {
    TURN.with(|t| t.set(Some(Instant::now())));
}

impl ClockRef {
    #[inline]
    pub(crate) fn now(&self) -> Instant {
        match self {
            ClockRef::Monotonic => Instant::now(),
            ClockRef::Custom(c) => c.now(),
            #[cfg(feature = "reactor")]
            ClockRef::Turn => TURN.with(std::cell::Cell::get).unwrap_or_else(Instant::now),
        }
    }
}

/// The wake channel a connection's owner waits on.
#[derive(Clone, Debug)]
pub(crate) enum WakeSource {
    /// A worker's own channel, registered in the kill slot once.
    Fixed(Arc<Wake>),
    /// The calling thread's channel, registered around each wait.
    Thread,
    /// None: a reactor worker never waits on one connection.
    #[cfg_attr(not(feature = "reactor"), allow(dead_code))]
    Reactor,
}

thread_local! {
    static THREAD_WAKE: std::cell::OnceCell<Option<Arc<Wake>>> = const { std::cell::OnceCell::new() };
}

fn thread_wake() -> Option<Arc<Wake>> {
    THREAD_WAKE.with(|cell| cell.get_or_init(|| Wake::new().ok().map(Arc::new)).clone())
}

/// What a read produced.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Got {
    Data(usize),
    Eof,
    Woken,
}

pub(crate) struct Link {
    pub(crate) stream: sys::Stream,
    pub(crate) info: ConnectionInfo,
    pub(crate) limits: Arc<Effective>,
    clock: ClockRef,
    phase: Phase,
    progress_at: Instant,
    exchange_deadline: Option<Instant>,
    rate_in: Rate,
    rate_out: Rate,
    pub(crate) slot: Arc<KillSlot>,
    pub(crate) generation: u32,
    wake: WakeSource,
    recv_timeout_set: Option<Duration>,
    pub(crate) gate: Option<Box<dyn ErasedGate>>,
    pub(crate) bytes_in: u64,
    pub(crate) bytes_out: u64,
    pub(crate) response_started: bool,
    pub(crate) response_tag: Option<GateTag>,
    pub(crate) peer_closed: bool,
    /// The first fatal condition seen; it becomes the close reason.
    pub(crate) terminal: Option<CloseReason>,
    likely_more: bool,
    /// net-io chooses the phase (an accepted connection whose owner never set one).
    auto_phase: bool,
    /// Bytes went out since the last bytes came in.
    replied: bool,
    /// The idle timeout in force: the limits' value, or this connection's override.
    idle_timeout: Duration,
    /// While a PROXY (or TLS) handshake runs: its deadline replaces the phase's.
    handshake_deadline: Option<Instant>,
    /// What deadlines are multiplied by under pressure (1 otherwise).
    deadline_scale: f32,
    /// The owner reads the scale again when an idle wait ends (the pool's sessions).
    rescales: bool,
    /// Bytes read past a handshake, served before the socket (the buffer returns
    /// to the worker's pool at close).
    pending: Option<Buffer>,
    pending_at: usize,
    /// Bytes at the head of the next send that the gate already approved (the
    /// unsent tail of a partial send), so a byte-counting gate counts each once.
    approved: usize,
    /// TLS on this connection (feature `tls`).
    tls: Option<Box<TlsLayer>>,
}

/// TLS on a connection: the engine's session and its two buffers.
pub(crate) struct TlsLayer {
    session: Box<dyn TlsSession>,
    /// Ciphertext in; `[start, len)` is not yet consumed by the engine.
    cin: Buffer,
    start: usize,
    /// Decrypted plaintext not yet delivered: `[plain_at, plain_end)` inside `cin`.
    plain_at: usize,
    plain_end: usize,
    /// Ciphertext out: scratch, flushed within each call.
    cout: Buffer,
    done: bool,
    eof: bool,
    /// What the engine reported last, not acted on yet.
    event: Option<Ev>,
    /// The input range of the last engine step: plaintext must lie inside it.
    data_from: usize,
    data_to: usize,
}

/// What one round of the TLS engine produced.
enum Pump {
    Plain,
    Handshaken,
    Eof,
    Woken,
}

/// What the TLS machine needs next. Both drivers run the same machine: the
/// blocking driver sends and reads in place, the reactor through operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TlsNext {
    /// `cout` holds records to send.
    Transmit,
    /// The engine wants more ciphertext.
    NeedInput,
    /// Plaintext is ready to deliver.
    Plain,
    /// The handshake just finished.
    Handshaken,
    /// The stream ended.
    Eof,
}

/// The engine's event, without the borrow of the input.
#[derive(Clone, Copy)]
enum Ev {
    NeedInput,
    Transmit,
    Handshaken,
    Data(usize, usize),
    OutputFull,
    Closed,
}

/// How much of a file one gate check covers.
const FILE_CHUNK: u64 = 1 << 20;
/// The buffer of a file sent by reading and writing.
const FILE_COPY: usize = 64 * 1024;

/// The largest plaintext encrypted into one record.
const TLS_RECORD: usize = 16 * 1024;
/// Room kept per record for the TLS header, padding, and tag.
const TLS_OVERHEAD: usize = 2 * 1024;

/// `d` under a pressure scale: never below 1 s, never above `d`.
fn scale(d: Duration, by: f32) -> Duration {
    if by >= 1.0 {
        return d;
    }
    d.mul_f32(by).max(Duration::from_secs(1)).min(d)
}

impl Link {
    pub(crate) fn new(
        stream: sys::Stream,
        info: ConnectionInfo,
        limits: Arc<Effective>,
        clock: ClockRef,
        slot: Arc<KillSlot>,
        wake: WakeSource,
        phase: Phase,
    ) -> Link {
        let now = clock.now();
        let generation = slot.install(stream.sock());
        if let WakeSource::Fixed(w) = &wake {
            slot.set_wake(Some(w.clone()));
        }
        let rate_in = Rate::new(&limits.min_rate, now);
        let rate_out = Rate::new(&limits.min_rate, now);
        let idle_timeout = limits.idle_timeout;
        let mut link = Link {
            stream,
            info,
            limits,
            clock,
            phase,
            progress_at: now,
            exchange_deadline: None,
            rate_in,
            rate_out,
            slot,
            generation,
            wake,
            recv_timeout_set: None,
            gate: None,
            bytes_in: 0,
            bytes_out: 0,
            response_started: false,
            response_tag: None,
            peer_closed: false,
            terminal: None,
            likely_more: false,
            auto_phase: phase == Phase::Idle,
            replied: false,
            idle_timeout,
            handshake_deadline: None,
            deadline_scale: 1.0,
            rescales: false,
            pending: None,
            pending_at: 0,
            approved: 0,
            tls: None,
        };
        if phase == Phase::Receiving {
            link.rate_in.activate(now);
        }
        link
    }

    #[inline]
    pub(crate) fn now(&self) -> Instant {
        self.clock.now()
    }

    pub(crate) fn phase(&self) -> Phase {
        self.phase
    }

    /// The owner sets the phase; net-io stops choosing it.
    pub(crate) fn set_phase(&mut self, phase: Phase) {
        self.auto_phase = false;
        if phase == self.phase {
            return;
        }
        let now = self.now();
        self.phase = phase;
        self.progress_at = now;
        match phase {
            Phase::Idle => {
                self.rate_in.deactivate();
                self.exchange_deadline = None;
            }
            Phase::Receiving => self.rate_in.activate(now),
            Phase::Sending => self.rate_in.deactivate(),
        }
    }

    /// When net-io chooses the phase, an exchange ends once a reply went out and
    /// no input is left over (`done`): the connection goes back to `Idle`, so it
    /// waits under the idle timeout and a drain can close it at once. Input left
    /// over (a pipelined request) keeps the read deadline and inbound rate.
    pub(crate) fn settle_phase(&mut self, done: bool) {
        if done && self.auto_phase && self.replied && self.phase == Phase::Receiving {
            let now = self.now();
            self.phase = Phase::Idle;
            self.progress_at = now;
            self.rate_in.deactivate();
        }
        self.replied = false;
    }

    pub(crate) fn set_exchange_deadline(&mut self, at: Option<Instant>) {
        self.exchange_deadline = at;
    }

    pub(crate) fn set_limits(&mut self, limits: Effective) {
        let now = self.now();
        let in_active = self.rate_in.is_active(&self.limits.min_rate);
        self.idle_timeout = limits.idle_timeout;
        self.rate_in = Rate::new(&limits.min_rate, now);
        self.rate_out = Rate::new(&limits.min_rate, now);
        self.limits = Arc::new(limits);
        if in_active {
            self.rate_in.activate(now);
        }
    }

    /// Puts TLS on this connection: from now on reads return plaintext and
    /// writes encrypt. `cin` must hold the largest record the engine needs.
    ///
    /// Bytes read past a PROXY header are ciphertext: they move into `cin` here, so
    /// the engine reads them first and nothing reaches the session unencrypted. The
    /// emptied read-ahead buffer is returned for its pool.
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    #[must_use]
    pub(crate) fn attach_tls(
        &mut self,
        session: Box<dyn TlsSession>,
        mut cin: Buffer,
        mut cout: Buffer,
    ) -> Option<Buffer> {
        cin.set_len(0);
        cout.set_len(0);
        let ahead = self.pending.take();
        if let Some(p) = ahead.as_ref() {
            let rest = p.as_slice().get(self.pending_at..).unwrap_or(&[]);
            if rest.len() > cin.capacity() {
                // Cannot happen with the pool's classes; fail closed if it does.
                self.terminal.get_or_insert(CloseReason::TlsFailed);
            } else {
                cin.spare()[..rest.len()].copy_from_slice(rest);
                cin.set_len(rest.len());
            }
        }
        self.pending_at = 0;
        self.tls = Some(Box::new(TlsLayer {
            session,
            cin,
            start: 0,
            plain_at: 0,
            plain_end: 0,
            cout,
            done: false,
            eof: false,
            event: None,
            data_from: 0,
            data_to: 0,
        }));
        ahead
    }

    /// Whether TLS is on this connection.
    pub(crate) fn has_tls(&self) -> bool {
        self.tls.is_some()
    }

    /// The TLS buffers, for their pool.
    pub(crate) fn take_tls_buffers(&mut self) -> Option<(Buffer, Buffer)> {
        self.tls.take().map(|t| (t.cin, t.cout))
    }

    /// Runs the TLS handshake to completion (under the handshake deadline set by
    /// `begin_handshake`); the engine's facts land in `info.tls`.
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    pub(crate) fn tls_handshake(&mut self) -> Result<(), NetError> {
        let Some(mut t) = self.tls.take() else {
            return Ok(());
        };
        let r = loop {
            match self.tls_pump(&mut t) {
                Ok(Pump::Handshaken) => break Ok(()),
                // Plaintext before the handshake completed is not something net-io accepts.
                Ok(Pump::Plain) if !t.done => {
                    break Err(self.tls_error(TlsError::new(TlsFailure::State, 0, None)));
                }
                Ok(Pump::Plain) => break Ok(()),
                Ok(Pump::Eof) => break Err(self.fail(CloseReason::TlsFailed, NetError::Closed)),
                Ok(Pump::Woken) => {}
                Err(e) => break Err(e),
            }
        };
        self.tls = Some(t);
        r
    }

    /// Plaintext for a reader.
    fn read_tls(&mut self, t: &mut TlsLayer, buf: &mut [u8]) -> Result<Got, NetError> {
        loop {
            match self.tls_pump(t)? {
                Pump::Plain => {
                    let have = &t.cin.as_slice()[t.plain_at..t.plain_end];
                    let n = have.len().min(buf.len());
                    buf[..n].copy_from_slice(&have[..n]);
                    t.plain_at += n;
                    let now = self.now();
                    self.progress_at = now;
                    if self.phase == Phase::Idle {
                        self.phase = Phase::Receiving;
                        self.rate_in.activate(now);
                    }
                    return Ok(Got::Data(n));
                }
                Pump::Handshaken => {}
                Pump::Eof => {
                    self.peer_closed = true;
                    return Ok(Got::Eof);
                }
                Pump::Woken => return Ok(Got::Woken),
            }
        }
    }

    /// Drives the engine until it has plaintext to deliver, finished the
    /// handshake, or the transport ended. Records the engine writes (handshake,
    /// alerts, tickets) go out at once.
    fn tls_pump(&mut self, t: &mut TlsLayer) -> Result<Pump, NetError> {
        loop {
            match self.tls_advance(t)? {
                TlsNext::Plain => return Ok(Pump::Plain),
                TlsNext::Handshaken => return Ok(Pump::Handshaken),
                TlsNext::Eof => return Ok(Pump::Eof),
                TlsNext::Transmit => self.send_raw_all(t.cout.as_slice())?,
                TlsNext::NeedInput => {
                    if let Some(p) = self.tls_fill(t)? {
                        return Ok(p);
                    }
                }
            }
        }
    }

    /// One turn of the TLS machine: runs the engine until something outside it
    /// has to happen. Does no IO.
    fn tls_advance(&mut self, t: &mut TlsLayer) -> Result<TlsNext, NetError> {
        loop {
            if t.plain_at < t.plain_end {
                return Ok(TlsNext::Plain);
            }
            if t.eof {
                return Ok(TlsNext::Eof);
            }
            if let Some(ev) = t.event.take() {
                match ev {
                    Ev::NeedInput => return Ok(TlsNext::NeedInput),
                    Ev::Transmit | Ev::OutputFull => {}
                    Ev::Handshaken => {
                        t.done = true;
                        if let Some(info) = t.session.info() {
                            self.info.tls = Some(Arc::new(info));
                        }
                        return Ok(TlsNext::Handshaken);
                    }
                    Ev::Data(off, len) => {
                        // The plaintext must lie inside the input the engine was given.
                        if off < t.data_from || off.saturating_add(len) > t.data_to {
                            return Err(self.tls_error(TlsError::new(TlsFailure::State, 0, None)));
                        }
                        t.plain_at = off;
                        t.plain_end = off + len;
                    }
                    Ev::Closed => {
                        t.eof = true;
                        return Ok(TlsNext::Eof);
                    }
                }
                continue;
            }
            let start = t.start;
            let end = t.cin.len();
            let base = t.cin.as_slice().as_ptr() as usize;
            let TlsLayer {
                session, cin, cout, ..
            } = &mut *t;
            cout.set_len(0);
            let stepped = session
                .step(&mut cin.as_mut_slice()[start..end], cout.spare())
                .map(|p| {
                    let ev = match p.event {
                        TlsEvent::NeedInput => Ev::NeedInput,
                        TlsEvent::Transmit => Ev::Transmit,
                        TlsEvent::HandshakeComplete => Ev::Handshaken,
                        TlsEvent::Data(d) => match (d.as_ptr() as usize).checked_sub(base) {
                            Some(off) if !d.is_empty() => Ev::Data(off, d.len()),
                            Some(_) => Ev::Transmit,
                            None => Ev::Data(usize::MAX, 0),
                        },
                        TlsEvent::OutputFull => Ev::OutputFull,
                        TlsEvent::PeerClosed | TlsEvent::Closed => Ev::Closed,
                    };
                    (p.consumed, p.written, ev)
                });
            let (consumed, written, ev) = match stepped {
                Ok(v) => v,
                Err(e) => return Err(self.tls_error(e)),
            };
            t.start = (start + consumed).min(end);
            t.data_from = start;
            t.data_to = end;
            if matches!(ev, Ev::OutputFull) && written == 0 {
                return Err(self.tls_error(TlsError::new(TlsFailure::OutputFull, 0, None)));
            }
            t.event = Some(ev);
            if written > 0 {
                t.cout.set_len(written.min(t.cout.capacity()));
                return Ok(TlsNext::Transmit);
            }
        }
    }

    /// Reads more ciphertext after compacting the input. `Some` ends the pump.
    fn tls_fill(&mut self, t: &mut TlsLayer) -> Result<Option<Pump>, NetError> {
        self.tls_make_room(t)?;
        let len = t.cin.len();
        match self.read_raw(t.cin.spare())? {
            Got::Data(n) => {
                t.cin.set_len(len + n);
                Ok(None)
            }
            Got::Eof => {
                // An unclean end (no close_notify) still ends the stream; the
                // protocol above decides whether its message was complete.
                let _ = t.session.on_transport_closed();
                t.eof = true;
                Ok(Some(Pump::Eof))
            }
            Got::Woken => Ok(Some(Pump::Woken)),
        }
    }

    /// Compacts the ciphertext input and checks there is room for more.
    fn tls_make_room(&mut self, t: &mut TlsLayer) -> Result<(), NetError> {
        if t.start > 0 {
            let len = t.cin.len();
            t.cin.as_mut_slice().copy_within(t.start..len, 0);
            t.cin.set_len(len - t.start);
            t.start = 0;
            t.plain_at = 0;
            t.plain_end = 0;
        }
        let need = t.session.input_capacity_required();
        if need > t.cin.capacity() || t.cin.spare().is_empty() {
            return Err(self.fail(
                CloseReason::Limit(LimitKind::ReadBuffer),
                NetError::Limit {
                    which: LimitKind::ReadBuffer,
                },
            ));
        }
        Ok(())
    }

    /// The plaintext one vectored TLS write takes: whole records that fit the
    /// output buffer.
    fn tls_budget(&self) -> usize {
        self.tls.as_ref().map_or(0, |t| {
            (t.cout.capacity() / (TLS_RECORD + TLS_OVERHEAD)).max(1) * TLS_RECORD
        })
    }

    /// Encrypts `plain` (at most one record) and sends all of it.
    fn write_tls(&mut self, plain: &[u8]) -> Result<usize, NetError> {
        let Some(mut t) = self.tls.take() else {
            return Ok(0);
        };
        t.cout.set_len(0);
        let r = match t.session.encrypt(plain, t.cout.spare()) {
            Ok(n) => {
                t.cout.set_len(n.min(t.cout.capacity()));
                self.send_raw_all(t.cout.as_slice()).map(|()| plain.len())
            }
            Err(e) => Err(self.tls_error(e)),
        };
        self.tls = Some(t);
        r
    }

    /// Encrypts up to `take` plaintext bytes from `bufs` and sends all of it.
    fn write_vectored_tls(&mut self, bufs: &[IoSlice<'_>], take: usize) -> Result<usize, NetError> {
        let Some(mut t) = self.tls.take() else {
            return Ok(0);
        };
        let r = match self.tls_encrypt(&mut t, bufs, take) {
            Ok(taken) => self.send_raw_all(t.cout.as_slice()).map(|()| taken),
            Err(e) => Err(e),
        };
        self.tls = Some(t);
        r
    }

    /// Encrypts up to `take` plaintext bytes from `bufs` into `cout`.
    fn tls_encrypt(
        &mut self,
        t: &mut TlsLayer,
        bufs: &[IoSlice<'_>],
        take: usize,
    ) -> Result<usize, NetError> {
        t.cout.set_len(0);
        let mut taken = 0;
        let mut failed = None;
        'slices: for b in bufs.iter().take(sys::MAX_SLICES) {
            let mut s: &[u8] = b;
            while !s.is_empty() && taken < take {
                let chunk = s.len().min(TLS_RECORD).min(take - taken);
                if t.cout.spare().len() < chunk + TLS_OVERHEAD {
                    break 'slices;
                }
                let used = t.cout.len();
                match t.session.encrypt(&s[..chunk], t.cout.spare()) {
                    Ok(n) => t.cout.set_len(used + n),
                    Err(e) => {
                        failed = Some(e);
                        break 'slices;
                    }
                }
                taken += chunk;
                s = &s[chunk..];
            }
        }
        match failed {
            Some(e) => Err(self.tls_error(e)),
            None => Ok(taken),
        }
    }

    /// Sends `close_notify` once, without waiting (a graceful close).
    pub(crate) fn tls_close_notify(&mut self) {
        let Some(mut t) = self.tls.take() else {
            return;
        };
        if t.done && !t.eof {
            t.cout.set_len(0);
            if let Ok(n) = t.session.close(t.cout.spare()) {
                t.cout.set_len(n.min(t.cout.capacity()));
                if let Ok(sent) = sys::send(&self.stream, t.cout.as_slice()) {
                    self.bytes_out += sent as u64;
                }
            }
        }
        self.tls = Some(t);
    }

    /// Sends all of `bytes` without the gate check (TLS records the engine wrote).
    fn send_raw_all(&mut self, mut bytes: &[u8]) -> Result<(), NetError> {
        while !bytes.is_empty() {
            let n = self.send_raw(bytes)?;
            bytes = &bytes[n..];
        }
        Ok(())
    }

    fn tls_error(&mut self, e: TlsError) -> NetError {
        let reason = if e.kind == TlsFailure::HelloRefused {
            CloseReason::HelloRefused
        } else {
            CloseReason::TlsFailed
        };
        self.fail(reason, NetError::Tls(e))
    }

    /// Starts a handshake: reads time out at `deadline` with `HandshakeTimeout`.
    #[cfg_attr(not(feature = "proxy"), allow(dead_code))]
    pub(crate) fn begin_handshake(&mut self, deadline: Instant) {
        self.handshake_deadline = Some(deadline);
    }

    /// Ends a handshake. `rest` holds bytes read past it (`buffer[at..]`), served
    /// before the socket. The connection waits for its first exchange again.
    #[cfg_attr(not(feature = "proxy"), allow(dead_code))]
    pub(crate) fn end_handshake(&mut self, rest: Option<(Buffer, usize)>) {
        self.handshake_deadline = None;
        if let Some((buffer, at)) = rest {
            if at < buffer.len() {
                self.pending_at = at;
                self.pending = Some(buffer);
            } else {
                self.pending = Some(buffer);
                self.pending_at = usize::MAX;
            }
        }
        self.phase = Phase::Idle;
        self.progress_at = self.now();
        self.rate_in.deactivate();
    }

    /// The handshake buffer, for its pool.
    pub(crate) fn take_pending(&mut self) -> Option<Buffer> {
        self.pending_at = 0;
        self.pending.take()
    }

    /// Copies bytes read past a handshake into `buf`; 0 when none are left.
    fn read_pending(&mut self, buf: &mut [u8]) -> usize {
        let Some(p) = self.pending.as_ref() else {
            return 0;
        };
        let have = p.as_slice().get(self.pending_at..).unwrap_or(&[]);
        let n = have.len().min(buf.len());
        buf[..n].copy_from_slice(&have[..n]);
        self.pending_at = self.pending_at.saturating_add(n);
        n
    }

    /// Under pressure deadlines shrink by `scale`, never below 1 s.
    pub(crate) fn set_deadline_scale(&mut self, scale: f32) {
        self.deadline_scale = scale;
    }

    /// The owner reads the server's scale again when `read` returns `Woken`, so an
    /// idle wait may end at the deadline pressure would give.
    pub(crate) fn set_rescales(&mut self) {
        self.rescales = true;
    }

    pub(crate) fn scaled(&self, d: Duration) -> Duration {
        scale(d, self.deadline_scale)
    }

    /// The longest an idle wait may last before the scale is read again, so a
    /// crossing reaches a connection already waiting.
    fn idle_slice(&self) -> Option<Duration> {
        let p = self.limits.pressure.filter(|_| self.rescales)?;
        (self.phase == Phase::Idle && self.handshake_deadline.is_none())
            .then(|| scale(self.idle_timeout, p.factor))
    }

    /// This connection's idle timeout from its next idle wait on (`None`: the
    /// limits' value again). At least one tick.
    pub(crate) fn set_idle_timeout(&mut self, timeout: Option<Duration>) {
        self.idle_timeout = timeout.map_or(self.limits.idle_timeout, |t| t.max(self.limits.tick));
    }

    pub(crate) fn killed(&self) -> Option<KillReason> {
        self.slot.killed()
    }

    fn fail(&mut self, reason: CloseReason, err: NetError) -> NetError {
        if self.terminal.is_none() {
            self.terminal = Some(reason);
        }
        err
    }

    fn check_terminal(&mut self) -> Result<(), NetError> {
        if let Some(reason) = self.killed() {
            return Err(self.fail(CloseReason::Killed(reason), NetError::Killed { reason }));
        }
        match self.terminal {
            None => Ok(()),
            Some(CloseReason::EgressDenied(code)) => Err(NetError::EgressDenied { code }),
            Some(_) => Err(NetError::Closed),
        }
    }

    fn timed_out(&mut self, kind: TimeoutKind) -> NetError {
        self.fail(CloseReason::for_timeout(kind), NetError::TimedOut { kind })
    }

    fn os_error(&mut self, op: &'static str, e: io::Error) -> NetError {
        let reason = match e.kind() {
            io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe => CloseReason::PeerReset,
            _ => CloseReason::Io(OsErrorClass::from_io(&e)),
        };
        let err = NetError::from_os(op, e);
        self.fail(reason, err)
    }

    /// Runs a wait with the right wake channel registered.
    fn wait(&self, interest: Interest, timeout: Duration) -> io::Result<Ready> {
        match &self.wake {
            WakeSource::Fixed(w) => self.stream.wait(interest, Some(w), Some(timeout)),
            WakeSource::Thread => {
                let w = thread_wake();
                self.slot.set_wake(w.clone());
                let r = self.stream.wait(interest, w.as_deref(), Some(timeout));
                self.slot.set_wake(None);
                r
            }
            WakeSource::Reactor => Err(io::Error::from(io::ErrorKind::Unsupported)),
        }
    }

    /// One read into `buf`, honouring the phase's deadline, the exchange deadline,
    /// and the inbound minimum rate. `Woken` means the wake channel fired (drain,
    /// control line, kill); the caller re-checks and calls again.
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> Result<Got, NetError> {
        if buf.is_empty() {
            return Ok(Got::Data(0));
        }
        if let Some(mut t) = self.tls.take() {
            self.settle_phase(true);
            let r = self.read_tls(&mut t, buf);
            self.tls = Some(t);
            return r;
        }
        self.read_raw(buf)
    }

    /// One read from the socket (or from the bytes left after a handshake),
    /// under the phase's or the handshake's deadline.
    fn read_raw(&mut self, buf: &mut [u8]) -> Result<Got, NetError> {
        self.read_raw_with(buf, sys::recv)
    }

    /// As `read_raw`, with `recv` as the receive call.
    fn read_raw_with<R>(&mut self, buf: &mut [u8], mut recv: R) -> Result<Got, NetError>
    where
        R: FnMut(&sys::Stream, &mut [u8]) -> io::Result<usize>,
    {
        self.settle_phase(true);
        let n = self.read_pending(buf);
        if n > 0 {
            let now = self.now();
            self.progress_at = now;
            if self.phase == Phase::Idle {
                self.phase = Phase::Receiving;
                self.rate_in.activate(now);
            }
            return Ok(Got::Data(n));
        }
        loop {
            self.check_terminal()?;
            if self.peer_closed {
                return Ok(Got::Eof);
            }
            let now = self.now();
            let (op_deadline, op_kind) = self.read_deadline();
            if now >= op_deadline {
                return Err(self.timed_out(op_kind));
            }
            if self.exchange_deadline.is_some_and(|d| now >= d) {
                return Err(self.timed_out(TimeoutKind::Exchange));
            }
            if self.rate_in.too_slow(&self.limits.min_rate, now) {
                return Err(self.fail(
                    CloseReason::SlowPeer {
                        direction: Direction::In,
                    },
                    NetError::SlowPeer {
                        direction: Direction::In,
                    },
                ));
            }
            let mut until = op_deadline;
            if let Some(d) = self.exchange_deadline {
                until = until.min(d);
            }
            if let Some(c) = self.rate_in.next_check(&self.limits.min_rate, now) {
                until = until.min(c);
            }
            let recheck = self.idle_slice().map(|s| now + s).filter(|&r| r < until);
            if let Some(r) = recheck {
                until = r;
            }
            let timeout = until
                .saturating_duration_since(now)
                .max(Duration::from_millis(1));

            // Waiting for the next exchange: a drain may close the connection now.
            let idle = self.phase == Phase::Idle;
            if idle {
                self.slot.set_idle(true);
            }
            let got = self.wait_and_recv(buf, timeout, &mut recv);
            if idle {
                self.slot.set_idle(false);
            }
            if let Some(result) = got {
                return result;
            }
            if recheck.is_some_and(|r| self.now() >= r) {
                // The owner reads the server's scale again before the next wait.
                return Ok(Got::Woken);
            }
        }
    }

    /// One wait where the OS needs it (Windows and macOS: every receive; D-052,
    /// D-083) and one receive. Linux receives block under `SO_RCVTIMEO`, so an
    /// exchange costs one receive and one send. `None` means try again (timed out or would block).
    fn wait_and_recv<R>(
        &mut self,
        buf: &mut [u8],
        timeout: Duration,
        recv: &mut R,
    ) -> Option<Result<Got, NetError>>
    where
        R: FnMut(&sys::Stream, &mut [u8]) -> io::Result<usize>,
    {
        if sys::WAIT_BEFORE_RECV {
            if !self.likely_more {
                match self.wait(Interest::Read, timeout) {
                    Ok(Ready::TimedOut) => return None,
                    Ok(Ready::Woken) => {
                        if let Err(e) = self.check_terminal() {
                            return Some(Err(e));
                        }
                        if self.slot.drained() {
                            return Some(Err(self.fail(CloseReason::Drained, NetError::Closed)));
                        }
                        return Some(Ok(Got::Woken));
                    }
                    Ok(Ready::Socket) => {}
                    Err(e) => return Some(Err(self.os_error("wait", e))),
                }
            }
        } else {
            let want = Some(timeout);
            let tick = self.limits.tick;
            let stale = match (self.recv_timeout_set, want) {
                (Some(set), Some(w)) => set.abs_diff(w) > tick,
                _ => true,
            };
            if stale {
                if let Err(e) = sys::set_recv_timeout(&self.stream, want) {
                    return Some(Err(self.os_error("setsockopt", e)));
                }
                self.recv_timeout_set = want;
            }
        }
        match recv(&self.stream, buf) {
            Ok(0) => {
                // A kill or a drain shuts the read side, which also reads as 0.
                if let Err(e) = self.check_terminal() {
                    return Some(Err(e));
                }
                if self.slot.drained() {
                    return Some(Err(self.fail(CloseReason::Drained, NetError::Closed)));
                }
                self.peer_closed = true;
                self.likely_more = false;
                Some(Ok(Got::Eof))
            }
            Ok(n) => {
                let now = self.now();
                self.bytes_in += n as u64;
                self.progress_at = now;
                self.likely_more = n == buf.len();
                if self.phase == Phase::Idle {
                    self.phase = Phase::Receiving;
                    self.rate_in.activate(now);
                }
                self.rate_in.record(now, n);
                Some(Ok(Got::Data(n)))
            }
            // `SO_RCVTIMEO` expiring reads as `WouldBlock` on Linux, and Windows and
            // macOS sockets are non-blocking. `TimedOut` is the kernel giving up on the connection
            // (keepalive), which is `Io(TimedOut)`, not one of our deadlines.
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.likely_more = false;
                None
            }
            Err(e) => Some(Err(self.os_error("recv", e))),
        }
    }

    /// Asks the gate about a write of `bytes`.
    fn gate_check(&mut self, bytes: usize) -> Result<(), NetError> {
        if let Some(gate) = self.gate.as_mut() {
            let w = WriteCheck::new(
                self.info.id,
                self.info.lane,
                u32::try_from(bytes).unwrap_or(u32::MAX),
                self.response_started,
                self.response_tag,
            );
            if let Err(Denial { code }) = gate.check(&w) {
                return Err(self.fail(
                    CloseReason::EgressDenied(code),
                    NetError::EgressDenied { code },
                ));
            }
        }
        Ok(())
    }

    /// Waits until the socket can take bytes, honouring the write deadline, the
    /// exchange deadline, and the outbound minimum rate.
    fn wait_writable(&mut self) -> Result<(), NetError> {
        loop {
            self.check_terminal()?;
            let now = self.now();
            let deadline = self.progress_at + self.limits.write_timeout;
            if now >= deadline {
                return Err(self.timed_out(TimeoutKind::Write));
            }
            if self.exchange_deadline.is_some_and(|d| now >= d) {
                return Err(self.timed_out(TimeoutKind::Exchange));
            }
            if self.rate_out.too_slow(&self.limits.min_rate, now) {
                return Err(self.fail(
                    CloseReason::SlowPeer {
                        direction: Direction::Out,
                    },
                    NetError::SlowPeer {
                        direction: Direction::Out,
                    },
                ));
            }
            let mut until = deadline;
            if let Some(d) = self.exchange_deadline {
                until = until.min(d);
            }
            if let Some(c) = self.rate_out.next_check(&self.limits.min_rate, now) {
                until = until.min(c);
            }
            let timeout = until
                .saturating_duration_since(now)
                .max(Duration::from_millis(1));
            match self.wait(Interest::Write, timeout) {
                Ok(Ready::Socket) => return Ok(()),
                Ok(Ready::TimedOut | Ready::Woken) => continue,
                Err(e) => return Err(self.os_error("wait", e)),
            }
        }
    }

    fn sent(&mut self, n: usize) {
        let now = self.now();
        self.bytes_out += n as u64;
        self.replied = true;
        self.progress_at = now;
        self.rate_out.record(now, n);
        if n > 0 {
            self.response_started = true;
        }
    }

    /// One send (gate check first); may be partial. Waits while the socket is full.
    pub(crate) fn write(&mut self, buf: &[u8]) -> Result<usize, NetError> {
        if buf.is_empty() {
            return Ok(0);
        }
        let now = self.now();
        self.rate_out.activate(now);
        if self.phase == Phase::Idle {
            self.progress_at = now;
        }
        // One gate check per write, for the bytes the gate has not approved yet:
        // a retry after `WouldBlock`, or the tail of a partial send offered again,
        // is not counted twice by a byte-counting gate.
        self.check_terminal()?;
        if self.tls.is_some() {
            let chunk = buf.len().min(TLS_RECORD);
            self.gate_check(chunk)?;
            return self.write_tls(&buf[..chunk]);
        }
        self.gate_check(buf.len().saturating_sub(self.approved))?;
        let n = self.send_raw(buf)?;
        self.approved = buf.len() - n;
        Ok(n)
    }

    /// One send without the gate check (waits while the socket is full).
    fn send_raw(&mut self, buf: &[u8]) -> Result<usize, NetError> {
        let mut zero_writes = 0u8;
        loop {
            self.check_terminal()?;
            match sys::send(&self.stream, buf) {
                Ok(0) => {
                    // Should not happen on TCP; treat once as "full", then as an error.
                    zero_writes += 1;
                    if zero_writes > 1 {
                        break Err(self.os_error("send", io::Error::from(io::ErrorKind::WriteZero)));
                    }
                    self.wait_writable()?;
                }
                Ok(n) => {
                    self.sent(n);
                    break Ok(n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => self.wait_writable()?,
                Err(e) => break Err(self.os_error("send", e)),
            }
        }
    }

    /// One read that also takes descriptors passed with the bytes (`SCM_RIGHTS`),
    /// stored into `into` from index 0. Returns what was read and how many
    /// descriptors came with it.
    #[cfg(all(unix, feature = "local"))]
    pub(crate) fn read_with_fds(
        &mut self,
        buf: &mut [u8],
        into: &mut [Option<std::os::fd::OwnedFd>; sys::MAX_FDS],
    ) -> Result<(Got, usize), NetError> {
        if self.tls.is_some() {
            return Err(NetError::Unsupported {
                feature: "descriptor passing on a TLS connection",
                platform: std::env::consts::OS,
            });
        }
        if buf.is_empty() {
            return Ok((Got::Data(0), 0));
        }
        let mut fds = 0;
        let mut truncated = false;
        let got = self.read_raw_with(buf, |s, b| {
            let r = sys::recv_with_fds(s, b, into)?;
            fds = r.fds;
            truncated = r.truncated;
            Ok(r.bytes)
        })?;
        if truncated {
            // Every descriptor of the message was closed. The bytes came with
            // them, so the stream can no longer be framed: the connection fails.
            return Err(self.fail(
                CloseReason::SessionError,
                NetError::Handoff(crate::handoff::HandoffError::Truncated),
            ));
        }
        Ok((got, fds))
    }

    /// Sends all of `body` with `fds` attached to its first byte (`SCM_RIGHTS`).
    /// One gate check for the whole body.
    #[cfg(all(unix, feature = "local"))]
    pub(crate) fn write_with_fds(
        &mut self,
        body: &[u8],
        fds: &[std::os::fd::BorrowedFd<'_>],
    ) -> Result<(), NetError> {
        if self.tls.is_some() {
            return Err(NetError::Unsupported {
                feature: "descriptor passing on a TLS connection",
                platform: std::env::consts::OS,
            });
        }
        if body.is_empty() {
            return Err(NetError::InvalidConfig {
                field: "body",
                reason: crate::error::ConfigReason::Zero,
            });
        }
        if fds.len() > sys::MAX_FDS {
            return Err(NetError::InvalidConfig {
                field: "descriptors",
                reason: crate::error::ConfigReason::TooLarge {
                    max: sys::MAX_FDS as u64,
                },
            });
        }
        let now = self.now();
        self.rate_out.activate(now);
        self.check_terminal()?;
        self.gate_check(body.len())?;
        self.approved = 0;
        let mut zero_writes = 0u8;
        let first = loop {
            self.check_terminal()?;
            match sys::send_with_fds(&self.stream, body, fds) {
                Ok(0) => {
                    zero_writes += 1;
                    if zero_writes > 1 {
                        return Err(
                            self.os_error("sendmsg", io::Error::from(io::ErrorKind::WriteZero))
                        );
                    }
                    self.wait_writable()?;
                }
                Ok(n) => {
                    self.sent(n);
                    break n;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => self.wait_writable()?,
                Err(e) => return Err(self.os_error("sendmsg", e)),
            }
        };
        let mut rest = &body[first..];
        while !rest.is_empty() {
            let n = self.send_raw(rest)?;
            rest = &rest[n..];
        }
        self.rate_out.deactivate();
        Ok(())
    }

    /// Sends all of `buf`, continuing partial writes from the exact offset.
    pub(crate) fn write_all(&mut self, mut buf: &[u8]) -> Result<(), NetError> {
        let start = self.now();
        self.rate_out.activate(start);
        while !buf.is_empty() {
            let n = self.write(buf)?;
            buf = &buf[n..];
        }
        self.rate_out.deactivate();
        Ok(())
    }

    /// One vectored send (gate check first); may be partial.
    pub(crate) fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> Result<usize, NetError> {
        let total: usize = bufs.iter().take(sys::MAX_SLICES).map(|b| b.len()).sum();
        if total == 0 {
            return Ok(0);
        }
        let now = self.now();
        self.rate_out.activate(now);
        self.check_terminal()?;
        if self.tls.is_some() {
            let take = total.min(self.tls_budget());
            self.gate_check(take)?;
            return self.write_vectored_tls(bufs, take);
        }
        self.gate_check(total.saturating_sub(self.approved))?;
        let mut zero_writes = 0u8;
        loop {
            self.check_terminal()?;
            match sys::send_vectored(&self.stream, bufs) {
                Ok(n) if n > 0 => {
                    self.sent(n);
                    self.approved = total - n;
                    return Ok(n);
                }
                Ok(_) => {
                    // As in `write`: once "full", the second time an error.
                    zero_writes += 1;
                    if zero_writes > 1 {
                        return Err(
                            self.os_error("send", io::Error::from(io::ErrorKind::WriteZero))
                        );
                    }
                    self.wait_writable()?;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => self.wait_writable()?,
                Err(e) => return Err(self.os_error("send", e)),
            }
        }
    }

    /// Whether `sendfile` can take this connection: a plain socket, and on Windows only
    /// through the reactor's `TransmitFile`.
    pub(crate) fn sends_files_directly(&self) -> bool {
        self.tls.is_none()
            && (self.info.transport == Transport::Tcp
                || (self.info.transport == Transport::Unix && cfg!(target_os = "linux")))
    }

    /// Sends `len` bytes of `file` from `offset`, a gate check before each chunk; returns
    /// the count, which is `len`: a file that ends early fails the connection.
    pub(crate) fn send_file(
        &mut self,
        file: &std::fs::File,
        offset: u64,
        len: u64,
    ) -> Result<u64, NetError> {
        if len == 0 {
            return Ok(0);
        }
        let start = self.now();
        self.rate_out.activate(start);
        let direct = cfg!(unix) && self.sends_files_directly();
        let sent = if direct {
            self.send_file_direct(file, offset, len)?
        } else {
            0
        };
        let copied = self.send_file_copy(file, offset + sent, len - sent)?;
        self.rate_out.deactivate();
        Ok(sent + copied)
    }

    /// Zero copy until the file is done. Stops early, with the count so far, if the OS
    /// turns the file down, and the rest goes by reading and writing.
    fn send_file_direct(
        &mut self,
        file: &std::fs::File,
        offset: u64,
        len: u64,
    ) -> Result<u64, NetError> {
        // `sendfile` has no non-blocking flag, and Linux keeps sockets blocking here.
        let was_blocking = !sys::WAIT_BEFORE_RECV;
        if was_blocking {
            self.stream
                .set_nonblocking(true)
                .map_err(|e| self.fail_os("ioctl", e))?;
        }
        let result = self.send_file_chunks(file, offset, len);
        if was_blocking {
            let _ = self.stream.set_nonblocking(false);
        }
        result
    }

    fn send_file_chunks(
        &mut self,
        file: &std::fs::File,
        offset: u64,
        len: u64,
    ) -> Result<u64, NetError> {
        let mut sent = 0u64;
        while sent < len {
            let take = (len - sent).min(FILE_CHUNK) as usize;
            self.check_terminal()?;
            self.gate_check(take.saturating_sub(self.approved))?;
            self.approved = take;
            loop {
                self.check_terminal()?;
                match self.send_file_once(file, offset + sent, take) {
                    Ok(0) => return Err(self.file_truncated(sent)),
                    Ok(n) => {
                        self.sent(n);
                        self.approved = take - n;
                        sent += n as u64;
                        break;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => self.wait_writable()?,
                    Err(e) if sent == 0 && sys::send_file_refused(&e) => return Ok(0),
                    Err(e) => return Err(self.os_error("sendfile", e)),
                }
            }
        }
        Ok(sent)
    }

    #[cfg(unix)]
    fn send_file_once(&self, file: &std::fs::File, offset: u64, len: usize) -> io::Result<usize> {
        sys::send_file(self.stream.sock(), file, offset, len)
    }

    #[cfg(not(unix))]
    fn send_file_once(
        &self,
        _file: &std::fs::File,
        _offset: u64,
        _len: usize,
    ) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    /// Reads and writes, for what cannot use `sendfile`: TLS, pipes, and the blocking
    /// path on Windows.
    fn send_file_copy(
        &mut self,
        file: &std::fs::File,
        offset: u64,
        len: u64,
    ) -> Result<u64, NetError> {
        if len == 0 {
            return Ok(0);
        }
        let mut buf = vec![0u8; FILE_COPY.min(len as usize)];
        let mut sent = 0u64;
        while sent < len {
            let take = ((len - sent) as usize).min(buf.len());
            let n = sys::read_file_at(file, &mut buf[..take], offset + sent)
                .map_err(|e| self.os_error("read", e))?;
            if n == 0 {
                return Err(self.file_truncated(sent));
            }
            let mut at = 0;
            while at < n {
                at += self.write(&buf[at..n])?;
            }
            sent += n as u64;
        }
        Ok(sent)
    }

    fn file_truncated(&mut self, sent: u64) -> NetError {
        self.fail(
            CloseReason::Io(OsErrorClass::FileTruncated),
            NetError::FileTruncated { sent },
        )
    }

    fn fail_os(&mut self, op: &'static str, e: io::Error) -> NetError {
        self.os_error(op, e)
    }

    /// Sends every slice, advancing them in place (no copy).
    pub(crate) fn write_all_vectored(
        &mut self,
        mut bufs: &mut [IoSlice<'_>],
    ) -> Result<(), NetError> {
        IoSlice::advance_slices(&mut bufs, 0);
        while !bufs.is_empty() {
            let n = self.write_vectored(bufs)?;
            IoSlice::advance_slices(&mut bufs, n);
        }
        self.rate_out.deactivate();
        Ok(())
    }

    /// Output is flushed; the outbound rate check stops.
    pub(crate) fn output_done(&mut self) {
        self.rate_out.deactivate();
    }

    /// Half-close.
    pub(crate) fn shutdown(&mut self, how: Shutdown) -> Result<(), NetError> {
        match self.stream.shutdown(how) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotConnected => Ok(()),
            Err(e) => Err(NetError::from_os("shutdown", e)),
        }
    }

    /// What the next read would find, looked at without waiting and without
    /// consuming anything: one zero-timeout wait and, when the socket is readable,
    /// a one-byte peek (TCP; other streams report `Readable`).
    pub(crate) fn probe(&mut self) -> Result<Health, NetError> {
        self.check_terminal()?;
        let held = self
            .tls
            .as_ref()
            .is_some_and(|t| t.plain_at < t.plain_end || t.start < t.cin.len());
        if self.pending.is_some() || held {
            return Ok(Health::Readable);
        }
        if self.peer_closed {
            return Ok(Health::PeerClosed);
        }
        match self.stream.wait(Interest::Read, None, Some(Duration::ZERO)) {
            Ok(Ready::Socket) => {}
            Ok(_) => {
                return match sys::take_error(self.stream.sock()) {
                    Ok(None) => Ok(Health::Open),
                    Ok(Some(e)) | Err(e) => Err(self.os_error("probe", e)),
                };
            }
            Err(e) => return Err(NetError::from_os("poll", e)),
        }
        if self.stream.tcp().is_none() {
            return Ok(Health::Readable);
        }
        let mut one = [0u8; 1];
        match self.stream.peek(&mut one) {
            Ok(0) => Ok(Health::PeerClosed),
            Ok(_) => Ok(Health::Readable),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(Health::Open),
            Err(e) => Err(self.os_error("recv", e)),
        }
    }

    /// FIN, then reads and discards until the peer's FIN, `within`, or a kill.
    /// Returns whether the peer closed, and how many bytes were discarded.
    pub(crate) fn drain_for(&mut self, within: Duration) -> (bool, u64) {
        self.tls_close_notify();
        let _ = self.stream.shutdown(Shutdown::Write);
        if self.peer_closed {
            return (true, 0);
        }
        let deadline = self.now().checked_add(within);
        let mut discarded = 0u64;
        let mut scratch = [0u8; 4096];
        loop {
            if self.killed().is_some() {
                return (false, discarded);
            }
            let now = self.now();
            let timeout = match deadline {
                Some(d) if now >= d => return (false, discarded),
                Some(d) => d
                    .saturating_duration_since(now)
                    .max(Duration::from_millis(1)),
                None => Duration::from_secs(1),
            };
            match self.wait(Interest::Read, timeout) {
                Ok(Ready::Socket) => {}
                Ok(_) => continue,
                Err(_) => return (false, discarded),
            }
            match self.stream.read(&mut scratch) {
                Ok(0) => {
                    self.peer_closed = true;
                    return (true, discarded);
                }
                Ok(n) => discarded += n as u64,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => return (false, discarded),
            }
        }
    }

    /// The close reason: the first fatal condition, or `fallback`.
    pub(crate) fn reason_or(&self, fallback: CloseReason) -> CloseReason {
        match self.killed() {
            Some(k) => CloseReason::Killed(k),
            None => self.terminal.unwrap_or(fallback),
        }
    }

    // ---- the reactor: the same bookkeeping, without waiting -----------------------

    /// Puts the socket in non-blocking mode.
    #[cfg(feature = "reactor")]
    pub(crate) fn set_nonblocking(&self) -> io::Result<()> {
        self.stream.set_nonblocking(true)
    }

    /// Bytes arrived (the reactor made the call). `Err` is a peer below the minimum
    /// rate: the check runs here as well as on the timer, because a peer that sends
    /// more often than the check interval re-arms the timer before it can fire.
    #[cfg(feature = "reactor")]
    pub(crate) fn note_received(&mut self, n: usize) -> Result<(), NetError> {
        let now = self.now();
        self.bytes_in += n as u64;
        self.progress_at = now;
        if self.phase == Phase::Idle {
            self.phase = Phase::Receiving;
            self.rate_in.activate(now);
        }
        self.rate_in.record(now, n);
        self.check_rate_in(now)
    }

    /// Ciphertext arrived: it counts for the rate and the deadline; the plaintext
    /// starts the exchange when it is delivered. `Err` as for `note_received`.
    #[cfg(feature = "reactor")]
    pub(crate) fn note_cipher(&mut self, n: usize) -> Result<(), NetError> {
        let now = self.now();
        self.bytes_in += n as u64;
        self.progress_at = now;
        self.rate_in.record(now, n);
        self.check_rate_in(now)
    }

    /// `Err(SlowPeer)` when input is below the minimum rate.
    #[cfg(feature = "reactor")]
    fn check_rate_in(&mut self, now: Instant) -> Result<(), NetError> {
        if self.rate_in.too_slow(&self.limits.min_rate, now) {
            return Err(self.fail(
                CloseReason::SlowPeer {
                    direction: Direction::In,
                },
                NetError::SlowPeer {
                    direction: Direction::In,
                },
            ));
        }
        Ok(())
    }

    /// Bytes left (the reactor made the call). `Err` is a reader below the minimum
    /// rate, checked here for the reason given at `note_received`.
    #[cfg(feature = "reactor")]
    pub(crate) fn note_sent(&mut self, n: usize) -> Result<(), NetError> {
        self.sent(n);
        let now = self.now();
        self.check_rate_out(now)
    }

    /// Before a send: the output deadline starts, a dead connection stops here,
    /// and the gate is asked about the bytes it has not approved.
    #[cfg(feature = "reactor")]
    pub(crate) fn check_send(&mut self, bytes: usize) -> Result<(), NetError> {
        let now = self.now();
        self.rate_out.activate(now);
        if self.phase == Phase::Idle {
            self.progress_at = now;
        }
        self.check_terminal()?;
        self.gate_check(bytes.saturating_sub(self.approved))
    }

    /// After a send of `n` out of `total` offered: the tail stays approved.
    #[cfg(feature = "reactor")]
    pub(crate) fn sent_of(&mut self, total: usize, n: usize) {
        self.approved = total.saturating_sub(n);
    }

    /// The deadline that applies to a wait for input, and its kind.
    fn read_deadline(&self) -> (Instant, TimeoutKind) {
        match (self.handshake_deadline, self.phase) {
            (Some(d), _) => (d, TimeoutKind::Handshake),
            (None, Phase::Idle) => (
                self.progress_at + self.scaled(self.idle_timeout),
                TimeoutKind::Idle,
            ),
            (None, _) => (
                self.progress_at + self.limits.read_timeout,
                TimeoutKind::Read,
            ),
        }
    }

    /// When a wait for input must look at the clock again.
    #[cfg(feature = "reactor")]
    pub(crate) fn read_timer(&self, now: Instant) -> Instant {
        let mut until = self.read_deadline().0;
        if let Some(d) = self.exchange_deadline {
            until = until.min(d);
        }
        if let Some(c) = self.rate_in.next_check(&self.limits.min_rate, now) {
            until = until.min(c);
        }
        until
    }

    /// The checks of a wait for input, at the time its timer fired.
    #[cfg(feature = "reactor")]
    pub(crate) fn read_check(&mut self, now: Instant) -> Result<(), NetError> {
        self.check_terminal()?;
        let (deadline, kind) = self.read_deadline();
        if now >= deadline {
            return Err(self.timed_out(kind));
        }
        if self.exchange_deadline.is_some_and(|d| now >= d) {
            return Err(self.timed_out(TimeoutKind::Exchange));
        }
        self.check_rate_in(now)
    }

    /// When a wait for room to write must look at the clock again.
    #[cfg(feature = "reactor")]
    pub(crate) fn write_timer(&self, now: Instant) -> Instant {
        let mut until = self.progress_at + self.limits.write_timeout;
        if let Some(d) = self.exchange_deadline {
            until = until.min(d);
        }
        if let Some(c) = self.rate_out.next_check(&self.limits.min_rate, now) {
            until = until.min(c);
        }
        until
    }

    /// The checks of a wait for room to write, at the time its timer fired.
    #[cfg(feature = "reactor")]
    pub(crate) fn write_check(&mut self, now: Instant) -> Result<(), NetError> {
        self.check_terminal()?;
        if now >= self.progress_at + self.limits.write_timeout {
            return Err(self.timed_out(TimeoutKind::Write));
        }
        if self.exchange_deadline.is_some_and(|d| now >= d) {
            return Err(self.timed_out(TimeoutKind::Exchange));
        }
        self.check_rate_out(now)
    }

    /// `Err(SlowPeer)` when output is below the minimum rate.
    #[cfg(feature = "reactor")]
    fn check_rate_out(&mut self, now: Instant) -> Result<(), NetError> {
        if self.rate_out.too_slow(&self.limits.min_rate, now) {
            return Err(self.fail(
                CloseReason::SlowPeer {
                    direction: Direction::Out,
                },
                NetError::SlowPeer {
                    direction: Direction::Out,
                },
            ));
        }
        Ok(())
    }

    /// Records an OS failure class as the close reason.
    #[cfg(feature = "reactor")]
    pub(crate) fn note_failure(&mut self, class: OsErrorClass) {
        let reason = match class {
            OsErrorClass::Reset | OsErrorClass::Aborted => CloseReason::PeerReset,
            other => CloseReason::Io(other),
        };
        if self.terminal.is_none() {
            self.terminal = Some(reason);
        }
    }

    /// Whether the PROXY handshake already ran.
    #[cfg(feature = "reactor")]
    pub(crate) fn proxy_done(&self) -> bool {
        self.info.proxy.is_some()
    }

    /// Bytes read past a handshake, into `buf`; 0 when none are left.
    #[cfg(feature = "reactor")]
    pub(crate) fn take_read_ahead(&mut self, buf: &mut [u8]) -> usize {
        let n = self.read_pending(buf);
        if n > 0 {
            let now = self.now();
            self.progress_at = now;
            if self.phase == Phase::Idle {
                self.phase = Phase::Receiving;
                self.rate_in.activate(now);
            }
        }
        n
    }

    /// Whether bytes read past a handshake are waiting.
    #[cfg(feature = "reactor")]
    pub(crate) fn has_read_ahead(&self) -> bool {
        self.pending
            .as_ref()
            .is_some_and(|p| self.pending_at < p.len())
    }

    /// One turn of the TLS machine.
    #[cfg(feature = "reactor")]
    pub(crate) fn tls_next(&mut self) -> Result<TlsNext, NetError> {
        let Some(mut t) = self.tls.take() else {
            return Ok(TlsNext::Eof);
        };
        let r = self.tls_advance(&mut t);
        self.tls = Some(t);
        r
    }

    /// The records to send; give the buffer back with [`Link::tls_put_cout`].
    #[cfg(feature = "reactor")]
    pub(crate) fn tls_take_cout(&mut self) -> Option<Buffer> {
        let t = self.tls.as_mut()?;
        Some(std::mem::replace(&mut t.cout, Buffer::placeholder()))
    }

    #[cfg(feature = "reactor")]
    pub(crate) fn tls_put_cout(&mut self, buffer: Buffer) {
        if let Some(t) = self.tls.as_mut() {
            t.cout = buffer;
        }
    }

    /// The ciphertext input, compacted, for a receive; `tls_put_cin` gives it back.
    #[cfg(feature = "reactor")]
    pub(crate) fn tls_take_cin(&mut self) -> Result<Option<Buffer>, NetError> {
        let Some(mut t) = self.tls.take() else {
            return Ok(None);
        };
        let r = self.tls_make_room(&mut t);
        let cin = r.map(|()| std::mem::replace(&mut t.cin, Buffer::placeholder()));
        self.tls = Some(t);
        cin.map(Some)
    }

    #[cfg(feature = "reactor")]
    pub(crate) fn tls_put_cin(&mut self, buffer: Buffer) {
        if let Some(t) = self.tls.as_mut() {
            t.cin = buffer;
        }
    }

    /// The transport ended under TLS.
    #[cfg(feature = "reactor")]
    pub(crate) fn tls_transport_closed(&mut self) {
        if let Some(t) = self.tls.as_mut() {
            let _ = t.session.on_transport_closed();
            t.eof = true;
        }
    }

    /// Copies plaintext into `buf` (the machine said `Plain`).
    #[cfg(feature = "reactor")]
    pub(crate) fn tls_deliver(&mut self, buf: &mut [u8]) -> usize {
        let Some(t) = self.tls.as_mut() else {
            return 0;
        };
        let have = &t.cin.as_slice()[t.plain_at..t.plain_end];
        let n = have.len().min(buf.len());
        buf[..n].copy_from_slice(&have[..n]);
        t.plain_at += n;
        let now = self.now();
        self.progress_at = now;
        if self.phase == Phase::Idle {
            self.phase = Phase::Receiving;
            self.rate_in.activate(now);
        }
        n
    }

    /// Encrypts up to one budget of plaintext into the output buffer.
    #[cfg(feature = "reactor")]
    pub(crate) fn tls_seal(
        &mut self,
        bufs: &[IoSlice<'_>],
        take: usize,
    ) -> Result<usize, NetError> {
        let Some(mut t) = self.tls.take() else {
            return Ok(0);
        };
        let r = self.tls_encrypt(&mut t, bufs, take);
        self.tls = Some(t);
        r
    }

    /// The plaintext one sealed write may take.
    #[cfg(feature = "reactor")]
    pub(crate) fn tls_write_budget(&self) -> usize {
        self.tls_budget()
    }

    /// The gate check for a sealed write.
    #[cfg(feature = "reactor")]
    pub(crate) fn check_seal(&mut self, bytes: usize) -> Result<(), NetError> {
        let now = self.now();
        self.rate_out.activate(now);
        self.check_terminal()?;
        self.gate_check(bytes)
    }

    /// A graceful close on the reactor: FIN now. `true` when unread input may
    /// still arrive, so the socket must linger to protect the last response.
    #[cfg(feature = "reactor")]
    pub(crate) fn begin_graceful_close(&mut self, readable: bool) -> bool {
        self.tls_close_notify();
        let _ = self.stream.shutdown(Shutdown::Write);
        self.stream.half_closes() && !self.peer_closed && (self.phase != Phase::Idle || readable)
    }

    /// Closes the socket after the driver let go of it.
    #[cfg(feature = "reactor")]
    pub(crate) fn finish_reactor(mut self, reason: CloseReason) -> CloseReason {
        if reason.is_abortive() {
            self.stream.set_abortive();
        }
        self.slot.begin_close();
        if let Some(mut gate) = self.gate.take() {
            gate.close(&self.info, reason);
        }
        let Link { stream, slot, .. } = self;
        drop(stream);
        slot.uninstall();
        reason
    }

    /// Closes the connection with `reason`, gracefully (FIN, then a bounded linger
    /// that reads and discards) or abortively (RST), and gives the gate its ticket back.
    /// Gives the socket up for `Server::adopt`: nothing is written, and a gate
    /// registered with `set_gate` gets its close with `reason`. `None` (and the
    /// connection closes) when TLS runs on it or bytes were read ahead.
    pub(crate) fn into_stream(mut self, reason: CloseReason) -> Option<sys::Stream> {
        if self.tls.is_some() || self.pending.is_some() {
            self.finish(CloseReason::SessionError);
            return None;
        }
        self.slot.begin_close();
        if let Some(mut gate) = self.gate.take() {
            gate.close(&self.info, reason);
        }
        let Link { stream, .. } = self;
        Some(stream)
    }

    pub(crate) fn finish(mut self, reason: CloseReason) -> CloseReason {
        let mut reason = reason;
        if !reason.is_abortive() {
            self.tls_close_notify();
        }
        if !reason.is_abortive() && self.linger_gracefully() {
            // A kill arrived during the linger: close abortively at once.
            if let Some(k) = self.killed() {
                reason = CloseReason::Killed(k);
            }
        }
        if reason.is_abortive() {
            self.stream.set_abortive();
        }
        // No kill can start after this, and one in flight finishes first.
        self.slot.begin_close();
        if let Some(mut gate) = self.gate.take() {
            gate.close(&self.info, reason);
        }
        let Link { stream, slot, .. } = self;
        drop(stream);
        slot.uninstall();
        reason
    }

    /// Closes without the linger: never blocks (used when a connection is dropped).
    pub(crate) fn finish_quick(mut self, reason: CloseReason) -> CloseReason {
        if reason.is_abortive() {
            self.stream.set_abortive();
        } else {
            let _ = self.stream.shutdown(Shutdown::Write);
        }
        self.slot.begin_close();
        if let Some(mut gate) = self.gate.take() {
            gate.close(&self.info, reason);
        }
        let Link { stream, slot, .. } = self;
        drop(stream);
        slot.uninstall();
        reason
    }

    /// A timeout the session chose to survive: clear it and restart the clock.
    pub(crate) fn rearm(&mut self) {
        if matches!(
            self.terminal,
            Some(
                CloseReason::Idle
                    | CloseReason::ReadTimeout
                    | CloseReason::WriteTimeout
                    | CloseReason::ExchangeDeadline
                    | CloseReason::ParkDeadline
            )
        ) {
            self.terminal = None;
        }
        self.progress_at = self.now();
        if self
            .exchange_deadline
            .is_some_and(|d| d <= self.progress_at)
        {
            self.exchange_deadline = None;
        }
    }

    /// One send attempt without the gate check, for the denial bytes after a denial.
    pub(crate) fn send_denial_once(&mut self, buf: &[u8]) {
        if let Ok(n) = sys::send(&self.stream, buf) {
            self.bytes_out += n as u64;
            self.replied = true;
        }
    }

    /// FIN, then read and discard up to the linger budget so unread input does not
    /// turn into an RST that destroys the last response. Returns `true` if killed meanwhile.
    fn linger_gracefully(&mut self) -> bool {
        let _ = self.stream.shutdown(Shutdown::Write);
        if self.peer_closed || !self.stream.half_closes() {
            return false;
        }
        // Between exchanges with nothing unread there is nothing to protect from a
        // reset: close at once (one zero-timeout poll), so a drain of idle
        // connections does not wait out the linger.
        if self.phase == Phase::Idle
            && !matches!(self.wait(Interest::Read, Duration::ZERO), Ok(Ready::Socket))
        {
            return false;
        }
        let deadline = self.now() + self.limits.graceful_linger;
        let mut left = self.limits.graceful_linger_bytes as usize;
        let mut scratch = [0u8; 2048];
        while left > 0 {
            if self.killed().is_some() {
                return true;
            }
            let now = self.now();
            if now >= deadline {
                break;
            }
            let timeout = deadline
                .saturating_duration_since(now)
                .max(Duration::from_millis(1));
            match self.wait(Interest::Read, timeout) {
                Ok(Ready::Socket) => {}
                Ok(Ready::Woken) => continue,
                _ => break,
            }
            let take = left.min(scratch.len());
            match self.stream.read(&mut scratch[..take]) {
                Ok(0) => break,
                Ok(n) => left -= n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(_) => break,
            }
        }
        self.killed().is_some()
    }
}
