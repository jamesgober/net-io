//! The connection core shared by `TcpConnection` and the server's workers:
//! deadlines per phase, the minimum transfer rate, the gate check before every
//! send, kill detection, and graceful or abortive close.

use std::io::{self, IoSlice, Read};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::error::{CloseReason, Direction, KillReason, NetError, OsErrorClass, TimeoutKind};
use crate::gate::{Denial, ErasedGate, WriteCheck};
use crate::info::{ConnectionInfo, GateTag};
use crate::limits::Effective;
use crate::rate::Rate;
use crate::session::Phase;
use crate::sys::{self, AsSock, Interest, KillSlot, Ready, Wake};
use crate::time::Clock;

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
}

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
        self.settle_phase(true);
        loop {
            self.check_terminal()?;
            if self.peer_closed {
                return Ok(Got::Eof);
            }
            let now = self.now();
            let (op_deadline, op_kind) = match self.phase {
                Phase::Idle => (
                    self.progress_at + self.limits.idle_timeout,
                    TimeoutKind::Idle,
                ),
                _ => (
                    self.progress_at + self.limits.read_timeout,
                    TimeoutKind::Read,
                ),
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

    /// One wait where the OS needs it (Windows: every receive; D-052) and one
    /// receive. Unix receives block under `SO_RCVTIMEO`, so an exchange costs one
    /// receive and one send. `None` means try again (timed out or would block).
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
            // `SO_RCVTIMEO` expiring reads as `WouldBlock` on Unix, and Windows sockets
            // are non-blocking. `TimedOut` is the kernel giving up on the connection
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
        // One gate check per write: a retry after `WouldBlock` sends the same bytes,
        // which the gate already approved (a byte-counting gate counts them once).
        self.check_terminal()?;
        self.gate_check(buf.len())?;
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
        self.gate_check(total)?;
        let mut zero_writes = 0u8;
        loop {
            self.check_terminal()?;
            match sys::send_vectored(&self.stream, bufs) {
                Ok(n) if n > 0 => {
                    self.sent(n);
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
