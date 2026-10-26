//! The connection core shared by `TcpConnection` and the server's workers:
//! deadlines per phase, the minimum transfer rate, the gate check before every
//! send, kill detection, and graceful or abortive close.

use std::io::{self, IoSlice, Read};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::buf::Buffer;
use crate::error::{
    CloseReason, Direction, KillReason, LimitKind, NetError, OsErrorClass, TimeoutKind,
};
use crate::gate::{Denial, ErasedGate, WriteCheck};
use crate::info::{ConnectionInfo, GateTag};
use crate::limits::Effective;
use crate::rate::Rate;
use crate::session::Phase;
use crate::sys::{self, AsSock, Interest, KillSlot, Ready, Wake};
use crate::time::Clock;
use crate::tls::{TlsError, TlsEvent, TlsFailure, TlsSession};

/// Where time comes from.
#[derive(Clone)]
pub(crate) enum ClockRef {
    Monotonic,
    Custom(Arc<dyn Clock>),
}

impl ClockRef {
    #[inline]
    pub(crate) fn now(&self) -> Instant {
        match self {
            ClockRef::Monotonic => Instant::now(),
            ClockRef::Custom(c) => c.now(),
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
    pub(crate) stream: TcpStream,
    pub(crate) info: ConnectionInfo,
    pub(crate) limits: Effective,
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
    /// The idle timeout from the limits, restored when an override is cleared.
    base_idle: Duration,
    /// While a PROXY (or TLS) handshake runs: its deadline replaces the phase's.
    handshake_deadline: Option<Instant>,
    /// Bytes read past a handshake, served before the socket (the buffer returns
    /// to the worker's pool at close).
    pending: Option<Buffer>,
    pending_at: usize,
    /// Bytes at the head of the next send that the gate already approved (the
    /// unsent tail of a partial send), so a byte-counting gate counts each once.
    approved: usize,
    /// TLS on this connection (feature `tls`).
    tls: Option<TlsLayer>,
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
}

/// What one round of the TLS engine produced.
enum Pump {
    Plain,
    Handshaken,
    Eof,
    Woken,
}

/// The engine's event, without the borrow of the input.
enum Ev {
    NeedInput,
    Transmit,
    Handshaken,
    Data(usize, usize),
    OutputFull,
    Closed,
}

/// The largest plaintext encrypted into one record.
const TLS_RECORD: usize = 16 * 1024;
/// Room kept per record for the TLS header, padding, and tag.
const TLS_OVERHEAD: usize = 2 * 1024;

impl Link {
    pub(crate) fn new(
        stream: TcpStream,
        info: ConnectionInfo,
        limits: Effective,
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
        let rate_in = Rate::new(limits.min_rate, now);
        let rate_out = Rate::new(limits.min_rate, now);
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
            base_idle: limits.idle_timeout,
            handshake_deadline: None,
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
        let in_active = self.rate_in.is_active();
        self.limits = limits;
        self.base_idle = limits.idle_timeout;
        self.rate_in = Rate::new(limits.min_rate, now);
        self.rate_out = Rate::new(limits.min_rate, now);
        if in_active {
            self.rate_in.activate(now);
        }
    }

    /// Puts TLS on this connection: from now on reads return plaintext and
    /// writes encrypt. `cin` must hold the largest record the engine needs.
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    pub(crate) fn attach_tls(
        &mut self,
        session: Box<dyn TlsSession>,
        mut cin: Buffer,
        mut cout: Buffer,
    ) {
        cin.set_len(0);
        cout.set_len(0);
        self.tls = Some(TlsLayer {
            session,
            cin,
            start: 0,
            plain_at: 0,
            plain_end: 0,
            cout,
            done: false,
            eof: false,
        });
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
            if t.plain_at < t.plain_end {
                return Ok(Pump::Plain);
            }
            if t.eof {
                return Ok(Pump::Eof);
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
            if written > 0 {
                t.cout.set_len(written.min(t.cout.capacity()));
                self.send_raw_all(t.cout.as_slice())?;
            }
            match ev {
                Ev::NeedInput => {
                    if let Some(p) = self.tls_fill(t)? {
                        return Ok(p);
                    }
                }
                Ev::Transmit => {}
                Ev::Handshaken => {
                    t.done = true;
                    if let Some(info) = t.session.info() {
                        self.info.tls = Some(Arc::new(info));
                    }
                    return Ok(Pump::Handshaken);
                }
                Ev::Data(off, len) => {
                    // The plaintext must lie inside the input the engine was given.
                    if off < start || off.saturating_add(len) > end {
                        return Err(self.tls_error(TlsError::new(TlsFailure::State, 0, None)));
                    }
                    t.plain_at = off;
                    t.plain_end = off + len;
                }
                Ev::OutputFull if written == 0 => {
                    return Err(self.tls_error(TlsError::new(TlsFailure::OutputFull, 0, None)));
                }
                Ev::OutputFull => {}
                Ev::Closed => {
                    t.eof = true;
                    return Ok(Pump::Eof);
                }
            }
        }
    }

    /// Reads more ciphertext after compacting the input. `Some` ends the pump.
    fn tls_fill(&mut self, t: &mut TlsLayer) -> Result<Option<Pump>, NetError> {
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
        let r = match failed {
            Some(e) => Err(self.tls_error(e)),
            None => self.send_raw_all(t.cout.as_slice()).map(|()| taken),
        };
        self.tls = Some(t);
        r
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

    /// This connection's idle timeout from its next idle wait on (`None`: the
    /// limits' value again). At least one tick.
    pub(crate) fn set_idle_timeout(&mut self, timeout: Option<Duration>) {
        self.limits.idle_timeout = timeout.map_or(self.base_idle, |t| t.max(self.limits.tick));
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
            WakeSource::Fixed(w) => sys::wait(self.stream.sock(), interest, Some(w), Some(timeout)),
            WakeSource::Thread => {
                let w = thread_wake();
                self.slot.set_wake(w.clone());
                let r = sys::wait(self.stream.sock(), interest, w.as_deref(), Some(timeout));
                self.slot.set_wake(None);
                r
            }
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
            let (op_deadline, op_kind) = match (self.handshake_deadline, self.phase) {
                (Some(d), _) => (d, TimeoutKind::Handshake),
                (None, phase) => match phase {
                    Phase::Idle => (
                        self.progress_at + self.limits.idle_timeout,
                        TimeoutKind::Idle,
                    ),
                    _ => (
                        self.progress_at + self.limits.read_timeout,
                        TimeoutKind::Read,
                    ),
                },
            };
            if now >= op_deadline {
                return Err(self.timed_out(op_kind));
            }
            if self.exchange_deadline.is_some_and(|d| now >= d) {
                return Err(self.timed_out(TimeoutKind::Exchange));
            }
            if self.rate_in.too_slow(now) {
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
            if let Some(c) = self.rate_in.next_check(now) {
                until = until.min(c);
            }
            let timeout = until
                .saturating_duration_since(now)
                .max(Duration::from_millis(1));

            // Waiting for the next exchange: a drain may close the connection now.
            let idle = self.phase == Phase::Idle;
            if idle {
                self.slot.set_idle(true);
            }
            let got = self.wait_and_recv(buf, timeout);
            if idle {
                self.slot.set_idle(false);
            }
            if let Some(result) = got {
                return result;
            }
        }
    }

    /// One wait where the OS needs it (Windows and macOS: every receive; D-052,
    /// D-083) and one receive. Linux receives block under `SO_RCVTIMEO`, so an
    /// exchange costs one receive and one send. `None` means try again (timed out or would block).
    fn wait_and_recv(
        &mut self,
        buf: &mut [u8],
        timeout: Duration,
    ) -> Option<Result<Got, NetError>> {
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
        match sys::recv(&self.stream, buf) {
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
            if self.rate_out.too_slow(now) {
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
            if let Some(c) = self.rate_out.next_check(now) {
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

    /// The close reason: the first fatal condition, or `fallback`.
    pub(crate) fn reason_or(&self, fallback: CloseReason) -> CloseReason {
        match self.killed() {
            Some(k) => CloseReason::Killed(k),
            None => self.terminal.unwrap_or(fallback),
        }
    }

    /// Closes the connection with `reason`, gracefully (FIN, then a bounded linger
    /// that reads and discards) or abortively (RST), and gives the gate its ticket back.
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
            let _ = sys::set_linger(self.stream.sock(), Some(Duration::ZERO));
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
            let _ = sys::set_linger(self.stream.sock(), Some(Duration::ZERO));
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
        if self.peer_closed {
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
            match (&self.stream).read(&mut scratch[..take]) {
                Ok(0) => break,
                Ok(n) => left -= n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(_) => break,
            }
        }
        self.killed().is_some()
    }
}
