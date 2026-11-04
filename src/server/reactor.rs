//! The reactor: one event loop per worker, thousands of connections each.
//!
//! The accept threads and admission are the blocking driver's: a socket reaches
//! a worker through its bounded inbox, already admitted. From there each
//! connection is a state machine driven by driver completions, a timing wheel,
//! and a few commands. The rules are the blocking driver's (`engine::drive`), in
//! resumable form: whatever a blocking worker would wait for here is an operation
//! in flight and a state to come back to.
//!
//! ```text
//!  inbox ─► start ─► [PROXY] ─► [TLS] ─► open session ─► run(step)
//!                                                         │
//!        Read  : ReceiveZero (no buffer while idle) ─► Receive ─► on_data
//!        Write : gate check ─► Send ─► ... ─► on_writable
//!        Park  : no reads, the completer or the deadline ─► on_wake / on_timeout
//!        Close : flush, FIN, linger while input may still arrive, close
//! ```
//!
//! An idle connection holds no read buffer and no output queue, only its state.

use std::collections::VecDeque;
use std::io::IoSlice;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use super::Sessions;
use super::engine::{
    CAUSE_DRAIN, CAUSE_STOP, CMD_KILL_ALL, CMD_LISTENER_KILL, CMD_LISTENER_SWEEP, CMD_PRESSURE,
    CMD_SHED, CMD_SWEEP, Engine, Job, ListenerConf, RegisteredConn, Shared, count_drained,
    record_close,
};
use crate::addr::PrefixKey;
use crate::buf::{Buffer, BufferPool};
use crate::completer::Completer;
use crate::control::{ControlState, ControlView};
use crate::driver::{Completion, Completions, Driver, DriverWaker, Operation, OperationKind};
use crate::driver::{SendChunks, Token};
use crate::error::{CloseReason, LimitKind, NetError, OsErrorClass, TimeoutKind};
use crate::events::Event;
use crate::gate::{ErasedGate, Gate, GateCell, guarded};
use crate::id::WorkerId;
use crate::info::{ConnectionInfo, Lane};
use crate::limits::SizeClass;
use crate::link::{ClockRef, Link, TlsNext, WakeSource, begin_turn};
use crate::proxy::ProxyFacts;
use crate::session::{Input, Output, Phase, Session, SessionContext, SessionFactory, Step};
use crate::sys::{self, AsSock, KillSink, KillSlot};
use crate::wheel::{Ticks, TimerId, Wheel};

/// The driver this build's reactor runs on.
#[cfg(unix)]
pub(crate) type Backend = crate::driver::ready::ReadyDriver;
#[cfg(windows)]
pub(crate) type Backend = crate::driver::iocp::IocpDriver;

/// How much of a file one operation, and one gate check, covers: one
/// [`BULK_TURN`], so a worker never copies more than that between looks at the OS.
const FILE_CHUNK: u64 = BULK_TURN as u64;

/// How many file bytes a worker sends between two looks at the OS. A `sendfile`
/// copies in the calling thread, so a fast reader would otherwise hold the worker
/// for as long as its stream lasts (D-141).
const BULK_TURN: usize = 256 << 10;

/// How many rounds of finished-at-once completions run between looks at the OS.
const LOCAL_ROUNDS: usize = 16;

/// How often a worker with paused connections looks for a free buffer.
const STARVED_RETRY: Duration = Duration::from_millis(10);

/// How many expired timers one loop iteration handles, so IO keeps moving after
/// a clock jump.
const TIMERS_PER_TURN: usize = 1_024;

/// Kills reach the worker here: the index goes on the list, the loop wakes.
#[derive(Debug)]
pub(crate) struct KillNotes {
    killed: Mutex<Vec<u32>>,
    waker: DriverWaker,
}

impl KillSink for KillNotes {
    fn killed(&self, index: u32) {
        self.killed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(index);
        self.waker.wake();
    }
}

/// What a connection is waiting for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wait {
    /// A handshake's next bytes (PROXY) or the TLS machine.
    Handshake,
    /// Input for the session.
    Read,
    /// A flush, then `on_writable`.
    Flush,
    /// A flush, then the close.
    FlushClose,
    /// A completion or the deadline.
    Park(Instant),
    /// FIN sent: reading and discarding until the peer closes.
    Linger(Instant),
    /// Closing: waiting for operations in flight to come back.
    Closing,
}

/// The receive in flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Recv {
    None,
    /// Readiness only: no buffer.
    Zero,
    /// Into the session's input.
    Input,
    /// Into the TLS machine's input.
    Cipher,
    /// Into the PROXY handshake's buffer.
    Proxy,
    /// Into a buffer whose bytes are thrown away.
    Discard,
}

/// The send in flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sending {
    None,
    /// Output chunks: `total` bytes offered.
    Plain {
        total: usize,
    },
    /// A piece of the file at the output's front.
    File {
        total: usize,
    },
    /// Sealed records of `taken` plaintext bytes.
    Sealed {
        taken: usize,
    },
    /// Records the TLS machine wrote.
    Machine,
}

/// The PROXY handshake in progress.
struct ProxyWait {
    parser: crate::proxy_parse::ProxyParser,
    buffer: Option<Buffer>,
}

/// The state of one connection.
struct Conn<S> {
    link: Link,
    session: Option<S>,
    input: Option<Input>,
    output: Option<Box<Output>>,
    listener: Arc<ListenerConf>,
    source: Option<PrefixKey>,
    token: Token,
    wait: Wait,
    recv: Recv,
    sending: Sending,
    timer: Option<TimerId>,
    /// A zero-byte receive fired and nobody has read yet.
    readable: bool,
    /// The close reason, once closing started.
    closing: Option<CloseReason>,
    /// A completion that arrived before the session parked.
    posted: Option<(u32, u64)>,
    proxy: Option<Box<ProxyWait>>,
    /// Bytes the linger may still discard.
    linger_left: u32,
    /// The session runs; before that a handshake does.
    opened: bool,
    /// Reading waits for the buffer budget (edge case 11).
    paused: bool,
    /// The last send moved nothing: once is retried, twice is an error.
    zero_send: bool,
}

struct Slot<S> {
    generation: u32,
    conn: Option<Conn<S>>,
}

/// One worker.
// Borrowed, not `Arc`: every worker would write the same reference count on every
// clone, and that line would cross the cores with each event.
struct Reactor<'a, F: SessionFactory, G: Gate> {
    engine: &'a Engine<Sessions<F>, G>,
    shared: &'a Shared,
    idx: usize,
    driver: Backend,
    slots: Vec<Slot<F::Session>>,
    free: Vec<u32>,
    open: usize,
    wheel: Wheel,
    ticks: Ticks,
    pool: BufferPool,
    // Boxed so that a connection holds one pointer, and it travels without a copy.
    #[allow(clippy::vec_box)]
    outputs: Vec<Box<Output>>,
    completer: Completer,
    /// Connections waiting for a buffer, oldest first.
    starved: VecDeque<(u32, Token)>,
    /// File bytes sent since the last look at the OS.
    bulk_sent: usize,
    /// Connections whose next file piece waits for the next look at the OS.
    yielded: VecDeque<(u32, Token)>,
    view: ControlView,
    clock: ClockRef,
    notes: Arc<KillNotes>,
    slot_pool: Vec<Arc<KillSlot>>,
    cells: Vec<Box<GateCell<G>>>,
    facts_pool: Vec<Arc<ProxyFacts>>,
    done: Option<Completions>,
}

/// Runs one worker until the server stops.
pub(crate) fn run<F: SessionFactory, G: Gate>(engine: &Arc<Engine<Sessions<F>, G>>, idx: usize) {
    let Some(driver) = engine.take_driver(idx) else {
        return;
    };
    let shared: &Shared = &engine.shared;
    let ws = &shared.workers[idx];
    let start = engine.clock.now();
    let notes = Arc::new(KillNotes {
        killed: Mutex::new(Vec::new()),
        waker: driver.waker(),
    });
    let mut r = Reactor {
        engine,
        shared,
        idx,
        driver,
        slots: Vec::new(),
        free: Vec::new(),
        open: 0,
        wheel: Wheel::with_capacity(1024),
        ticks: Ticks::new(start, engine.limits.tick),
        pool: BufferPool::new(engine.budget.clone(), engine.wipe),
        outputs: Vec::new(),
        starved: VecDeque::new(),
        bulk_sent: 0,
        yielded: VecDeque::new(),
        completer: Completer {
            shared: ws.completer.clone(),
        },
        view: ControlView::new(),
        clock: match engine.clock {
            ClockRef::Monotonic => ClockRef::Turn,
            ref other => other.clone(),
        },
        notes,
        slot_pool: Vec::new(),
        cells: Vec::new(),
        facts_pool: Vec::new(),
        done: Some(Completions::new()),
    };
    if guarded(|| r.main()).is_none() {
        // A panic got past every inner boundary: nothing on this worker can be
        // trusted to finish, so each connection closes now and gives back what it held.
        r.abandon_all();
    }
}

impl<F: SessionFactory, G: Gate> Reactor<'_, F, G> {
    fn main(&mut self) {
        loop {
            begin_turn();
            self.take_inbox();
            self.run_commands();
            self.take_kills();
            self.take_posted();
            self.fire_timers();
            self.resume_starved();
            if self.shared.is_stopping() {
                self.close_all(CloseReason::Shutdown);
                if self.open == 0 && self.engine.inbox_empty(self.idx) {
                    return;
                }
            }
            let timeout = self.wait_timeout();
            let Some(mut done) = self.done.take() else {
                return;
            };
            if self.driver.wait(&mut done, timeout).is_err() {
                // The wait itself failed: nothing more can happen on this worker.
                self.close_all(CloseReason::Shutdown);
                return;
            }
            begin_turn();
            self.bulk_sent = 0;
            self.resume_yielded();
            for c in done.drain() {
                self.on_completion(c);
            }
            // What those finished at once needs no trip through the OS or the checks
            // above; bounded, so a chatty connection cannot hold them off.
            for _ in 0..LOCAL_ROUNDS {
                if self.driver.take_local(&mut done) == 0 {
                    break;
                }
                for c in done.drain() {
                    self.on_completion(c);
                }
            }
            self.done = Some(done);
            if !self.yielded.is_empty() {
                self.driver.poll_next();
            }
        }
    }

    /// Until the next occupied timer slot. A worker with an injected clock also
    /// looks up regularly, since that clock moves without waking anyone.
    fn wait_timeout(&self) -> Option<Duration> {
        let now = self.clock.now();
        let timer = self
            .wheel
            .next_expiry()
            .map(|t| self.ticks.until(t, now).max(Duration::from_micros(100)));
        if !self.yielded.is_empty() {
            return Some(Duration::ZERO);
        }
        // Buffers free on any worker, and nothing wakes this one for them.
        let starved = !self.starved.is_empty();
        match self.clock {
            ClockRef::Monotonic | ClockRef::Turn if !starved => timer,
            ClockRef::Monotonic | ClockRef::Turn => {
                let cap = STARVED_RETRY;
                Some(timer.map_or(cap, |t| t.min(cap)))
            }
            ClockRef::Custom(_) => {
                let cap = Duration::from_millis(5);
                Some(timer.map_or(cap, |t| t.min(cap)))
            }
        }
    }

    /// File sends that gave way at the last look at the OS go on, oldest first.
    fn resume_yielded(&mut self) {
        for _ in 0..self.yielded.len() {
            let Some((index, token)) = self.yielded.pop_front() else {
                return;
            };
            let wait = match self.conn(index) {
                Some(c)
                    if c.token == token && c.sending == Sending::None && c.closing.is_none() =>
                {
                    c.wait
                }
                _ => continue,
            };
            self.flush_and_continue(index, wait);
        }
    }

    /// Reading resumes, oldest connection first, as buffers free up.
    fn resume_starved(&mut self) {
        while let Some(&(index, token)) = self.starved.front() {
            let class = match self.conn(index) {
                Some(c) if c.token == token && c.paused && c.wait == Wait::Read => {
                    c.link.limits.read_class
                }
                _ => {
                    self.starved.pop_front();
                    continue;
                }
            };
            let Some(buffer) = self.pool.take(class) else {
                return;
            };
            self.starved.pop_front();
            if let Some(c) = self.conn(index) {
                c.paused = false;
                c.input = Some(Input::new(buffer));
            }
            self.read(index);
        }
    }

    fn token_of(&self, index: u32) -> Token {
        let generation = self.slots[index as usize].generation;
        Token((u64::from(generation) << 32) | u64::from(index))
    }

    fn conn(&mut self, index: u32) -> Option<&mut Conn<F::Session>> {
        self.slots
            .get_mut(index as usize)
            .and_then(|s| s.conn.as_mut())
    }

    // ---- a connection arrives ---------------------------------------------------

    fn take_inbox(&mut self) {
        while let Some(job) = self.engine.next_inbox(self.idx) {
            self.start(job);
        }
    }

    fn start(&mut self, job: Job<G::Ticket>) {
        let (stream, mut info, ticket, listener, source) = job.into_parts();
        let shared = self.shared;
        info.worker = WorkerId(self.idx as u16);
        let index = match self.free.pop() {
            Some(i) => i,
            None => {
                self.slots.push(Slot {
                    generation: 0,
                    conn: None,
                });
                (self.slots.len() - 1) as u32
            }
        };
        self.slots[index as usize].generation =
            self.slots[index as usize].generation.wrapping_add(1);
        let token = self.token_of(index);
        let slot = self
            .slot_pool
            .pop()
            .unwrap_or_else(|| Arc::new(KillSlot::new()));
        let limits = listener.limits.clone();
        let mut link = Link::new(
            stream,
            info,
            limits,
            self.clock.clone(),
            slot.clone(),
            WakeSource::Reactor,
            Phase::Idle,
        );
        slot.set_sink(self.notes.clone(), index);
        let mut cell = self.cells.pop().unwrap_or_else(|| {
            Box::new(GateCell {
                gate: self.engine.gate.clone(),
                ticket: None,
            })
        });
        cell.ticket = Some(ticket);
        if self.engine.gated {
            link.gate = Some(cell as Box<dyn ErasedGate>);
        } else {
            self.cells.push(cell);
        }
        shared.register_conn(
            link.info.id,
            RegisteredConn {
                slot,
                generation: link.generation,
                worker: self.idx as u32,
                index,
            },
        );
        self.open += 1;
        let conn = Conn {
            link,
            session: None,
            input: None,
            output: None,
            listener,
            source,
            token,
            wait: Wait::Handshake,
            recv: Recv::None,
            sending: Sending::None,
            timer: None,
            readable: false,
            closing: None,
            posted: None,
            proxy: None,
            linger_left: 0,
            opened: false,
            paused: false,
            zero_send: false,
        };
        self.slots[index as usize].conn = Some(conn);
        let setup = {
            let Some(c) = self.conn(index) else { return };
            c.link.set_nonblocking()
        };
        let registered = setup.and_then(|()| {
            let Some(c) = self.slots[index as usize].conn.as_ref() else {
                return Ok(());
            };
            #[cfg(all(windows, feature = "local"))]
            if let Some(handle) = c.link.stream.pipe_handle() {
                return self
                    .driver
                    .register_pipe(handle, token)
                    .map_err(std::io::Error::from);
            }
            self.driver
                .register(c.link.stream.sock(), token)
                .map_err(std::io::Error::from)
        });
        if let Err(e) = registered {
            let class = OsErrorClass::from_io(&e);
            self.finish(index, CloseReason::Io(class), false);
            return;
        }
        // Queued before its listener was removed: close it unread.
        if self
            .conn(index)
            .is_some_and(|c| c.listener.removed.load(Ordering::Acquire))
        {
            return self.close(index, CloseReason::Drained);
        }
        self.handshake(index);
    }

    /// PROXY first, then TLS, then the session.
    fn handshake(&mut self, index: u32) {
        #[cfg(feature = "tls")]
        let acceptor = self.shared.tls.clone();
        let scale = self.shared.deadline_scale();
        let Some(c) = self.conn(index) else { return };
        let accepted = c.link.info.accepted_at;
        c.link.set_deadline_scale(scale);
        let timeout = c.link.scaled(c.link.limits.handshake_timeout);
        #[cfg(feature = "proxy")]
        if let Some(settings) = c.listener.proxy.clone() {
            if c.proxy.is_none() && !c.link.proxy_done() {
                if !settings.is_trusted(&c.link.info) {
                    return self.close(index, CloseReason::ProxyUntrusted);
                }
                c.link.begin_handshake(accepted + timeout);
                let limits = *c.link.limits;
                let need = 16 + u32::from(limits.proxy_header_max);
                let class = if need <= SizeClass::SMALL.bytes() {
                    SizeClass::SMALL
                } else if need <= SizeClass::MEDIUM.bytes() {
                    SizeClass::MEDIUM
                } else {
                    SizeClass::LARGE
                };
                let Some(buffer) = self.pool.take(class) else {
                    return self.close(index, CloseReason::Limit(LimitKind::BufferBudget));
                };
                let body_max = u16::try_from(buffer.capacity().saturating_sub(16))
                    .unwrap_or(u16::MAX)
                    .min(limits.proxy_header_max);
                let parser = crate::proxy_parse::ProxyParser::new(settings.versions, body_max);
                let Some(c) = self.conn(index) else { return };
                c.proxy = Some(Box::new(ProxyWait {
                    parser,
                    buffer: Some(buffer),
                }));
                return self.proxy_read(index);
            }
        }
        #[cfg(feature = "tls")]
        if c.listener.tls && !c.link.has_tls() {
            let Some(acceptor) = acceptor else {
                return self.close(index, CloseReason::TlsFailed);
            };
            let session = match acceptor.session_boxed(&c.link.info) {
                Ok(s) => s,
                Err(e) if e.kind == crate::tls::TlsFailure::HelloRefused => {
                    return self.close(index, CloseReason::HelloRefused);
                }
                Err(_) => return self.close(index, CloseReason::TlsFailed),
            };
            let limits = *c.link.limits;
            let Some(cin) = self.pool.take(limits.read_class_max) else {
                return self.close(index, CloseReason::Limit(LimitKind::BufferBudget));
            };
            let Some(cout) = self.pool.take(SizeClass::LARGE) else {
                self.pool.put(cin);
                return self.close(index, CloseReason::Limit(LimitKind::BufferBudget));
            };
            let Some(c) = self.conn(index) else { return };
            let ahead = c.link.attach_tls(session, cin, cout);
            c.link.begin_handshake(accepted + timeout);
            if let Some(ahead) = ahead {
                self.pool.put(ahead);
            }
            let Some(c) = self.conn(index) else { return };
            c.wait = Wait::Handshake;
            return self.tls_turn(index);
        }
        self.open_session(index);
    }

    fn open_session(&mut self, index: u32) {
        let engine = self.engine;
        let factory = engine.work.factory();
        let Some(c) = self.conn(index) else { return };
        match guarded(|| factory.open(&c.link.info)) {
            Some(Ok(s)) => c.session = Some(s),
            Some(Err(cause)) => return self.close(index, CloseReason::Refused(cause)),
            None => return self.close(index, CloseReason::SessionPanicked),
        }
        c.opened = true;
        match self.call(index, |s, cx| s.on_open(cx)) {
            Some(step) => self.run(index, step),
            None => self.close(index, CloseReason::SessionPanicked),
        }
    }

    // ---- the PROXY handshake ------------------------------------------------------

    #[cfg(feature = "proxy")]
    fn proxy_read(&mut self, index: u32) {
        let Some(c) = self.conn(index) else { return };
        c.wait = Wait::Handshake;
        let Some(buffer) = c.proxy.as_mut().and_then(|p| p.buffer.take()) else {
            return;
        };
        c.recv = Recv::Proxy;
        let token = c.token;
        self.submit_receive(index, token, buffer);
        self.arm_timer(index);
    }

    #[cfg(not(feature = "proxy"))]
    fn proxy_read(&mut self, _index: u32) {}

    #[cfg(feature = "proxy")]
    fn proxy_data(&mut self, index: u32, mut buffer: Buffer, n: usize) {
        use crate::proxy_parse::{ProxyAddress, ProxyCommand, ProxyProgress};
        let shared = self.shared;
        let Some(c) = self.slots[index as usize].conn.as_mut() else {
            return;
        };
        if c.proxy.is_none() {
            return;
        }
        if n == 0 {
            self.pool.put(buffer);
            return self.close(index, CloseReason::ProxyMissing);
        }
        if c.link.note_cipher(n).is_err() {
            self.pool.put(buffer);
            let reason = c.link.reason_or(CloseReason::Io(OsErrorClass::Other(0)));
            return self.close(index, reason);
        }
        let Some(wait) = c.proxy.as_mut() else { return };
        let verdict = match wait.parser.feed(buffer.as_slice()) {
            Ok(ProxyProgress::Done { header, consumed }) => {
                let real = match (header.command, header.source) {
                    (ProxyCommand::Proxy, Some(ProxyAddress::Ip(a))) => {
                        Some(crate::addr::normalize_socket(a))
                    }
                    _ => None,
                };
                Ok(Some((header.to_facts(), real, consumed)))
            }
            Ok(ProxyProgress::NeedMore { .. }) => {
                if buffer.spare().is_empty() {
                    Err(CloseReason::ProxyInvalid)
                } else {
                    Ok(None)
                }
            }
            Err(crate::proxy::ProxyError::NotProxy) => Err(CloseReason::ProxyMissing),
            Err(_) => Err(CloseReason::ProxyInvalid),
        };
        match verdict {
            Err(reason) => {
                self.pool.put(buffer);
                self.close(index, reason);
            }
            Ok(None) => {
                wait.buffer = Some(buffer);
                self.proxy_read(index);
            }
            Ok(Some((facts, real, consumed))) => {
                c.proxy = None;
                c.link.end_handshake(Some((buffer, consumed)));
                let result = super::engine::proxy_resolved(
                    shared,
                    &mut c.link,
                    &c.listener,
                    &mut c.source,
                    facts,
                    real,
                    &mut self.facts_pool,
                );
                match result {
                    Ok(()) => self.handshake(index),
                    Err(reason) => self.close(index, reason),
                }
            }
        }
    }

    #[cfg(not(feature = "proxy"))]
    fn proxy_data(&mut self, _index: u32, buffer: Buffer, _n: usize) {
        self.pool.put(buffer);
    }

    // ---- the TLS machine ----------------------------------------------------------

    /// Turns the machine until it waits for something. Plaintext goes to the
    /// session's input; the handshake's end starts the session.
    fn tls_turn(&mut self, index: u32) {
        loop {
            let Some(c) = self.conn(index) else { return };
            if c.closing.is_some() {
                return;
            }
            let next = match c.link.tls_next() {
                Ok(n) => n,
                Err(_) => {
                    let reason = c.link.reason_or(CloseReason::TlsFailed);
                    return self.close(index, reason);
                }
            };
            match next {
                TlsNext::Transmit => {
                    let token = c.token;
                    let Some(cout) = c.link.tls_take_cout() else {
                        return self.close(index, CloseReason::TlsFailed);
                    };
                    c.sending = Sending::Machine;
                    self.submit_send(index, token, SendChunks::from_buffer(cout));
                    return;
                }
                TlsNext::NeedInput => {
                    if c.recv != Recv::None {
                        return;
                    }
                    let token = c.token;
                    let cin = match c.link.tls_take_cin() {
                        Ok(Some(b)) => b,
                        Ok(None) => return self.close(index, CloseReason::TlsFailed),
                        Err(_) => {
                            let reason = c.link.reason_or(CloseReason::TlsFailed);
                            return self.close(index, reason);
                        }
                    };
                    c.recv = Recv::Cipher;
                    self.submit_receive(index, token, cin);
                    self.arm_timer(index);
                    return;
                }
                TlsNext::Handshaken => {
                    c.link.end_handshake(None);
                    if !c.opened {
                        return self.open_session(index);
                    }
                }
                TlsNext::Plain => {
                    if c.wait != Wait::Read {
                        // The session is not reading: the plaintext waits in the machine.
                        return;
                    }
                    if !self.ensure_input(index) {
                        return;
                    }
                    let Some(c) = self.conn(index) else { return };
                    let Some(input) = c.input.as_mut() else {
                        return;
                    };
                    let n = c.link.tls_deliver(input.spare_for_read());
                    input.filled(n);
                    return self.input_arrived(index);
                }
                TlsNext::Eof => {
                    c.link.peer_closed = true;
                    if !c.opened {
                        return self.close(index, CloseReason::TlsFailed);
                    }
                    if c.wait == Wait::Read {
                        return self.peer_closed(index);
                    }
                    return;
                }
            }
        }
    }

    // ---- sessions ---------------------------------------------------------------

    fn call<R>(
        &mut self,
        index: u32,
        f: impl FnOnce(&mut F::Session, &mut SessionContext<'_>) -> R,
    ) -> Option<R> {
        self.ensure_output(index);
        let draining = self.shared.is_draining();
        let pressure = self.pressure();
        let worker = WorkerId(self.idx as u16);
        let slot = self.slots.get_mut(index as usize)?;
        let c = slot.conn.as_mut()?;
        let session = c.session.as_mut()?;
        let output = c.output.as_mut()?;
        let mut cx = SessionContext {
            link: &mut c.link,
            output,
            pool: &mut self.pool,
            completer: &self.completer,
            draining,
            pressure,
            worker,
            grow_to: None,
        };
        guarded(|| f(session, &mut cx))
    }

    fn call_on_data(&mut self, index: u32) -> Option<Step> {
        self.ensure_output(index);
        let draining = self.shared.is_draining();
        let pressure = self.pressure();
        let worker = WorkerId(self.idx as u16);
        let slot = self.slots.get_mut(index as usize)?;
        let c = slot.conn.as_mut()?;
        let session = c.session.as_mut()?;
        let output = c.output.as_mut()?;
        let input = c.input.as_mut()?;
        let mut cx = SessionContext {
            link: &mut c.link,
            output,
            pool: &mut self.pool,
            completer: &self.completer,
            draining,
            pressure,
            worker,
            grow_to: None,
        };
        let step = guarded(|| session.on_data(&mut cx, input));
        let grow = cx.grow_to;
        if let Some(class) = grow {
            if class > input.buf.class() && !input.lent() {
                if let Some(mut bigger) = self.pool.take(class) {
                    let bytes = input.bytes();
                    bigger.spare()[..bytes.len()].copy_from_slice(bytes);
                    bigger.set_len(bytes.len());
                    let old = std::mem::replace(&mut input.buf, bigger);
                    input.start = 0;
                    self.pool.put(old);
                }
            }
        }
        step
    }

    fn pressure(&self) -> f32 {
        if matches!(self.view.state(), ControlState::Shed { .. }) {
            return 1.0;
        }
        self.shared.occupancy()
    }

    fn ensure_output(&mut self, index: u32) {
        let need = self.conn(index).is_some_and(|c| c.output.is_none());
        if need {
            let limit = self.engine.limits.output_budget;
            let output = self.outputs.pop().unwrap_or_else(|| {
                Box::new(Output::new(
                    self.engine.budget.clone(),
                    limit,
                    self.engine.wipe,
                ))
            });
            if let Some(c) = self.conn(index) {
                c.output = Some(output);
            }
        }
    }

    /// The input buffer, taken from the pool if the connection has none.
    fn ensure_input(&mut self, index: u32) -> bool {
        let Some(c) = self.conn(index) else {
            return false;
        };
        if c.input.is_some() {
            return true;
        }
        let class = c.link.limits.read_class;
        match self.pool.take(class) {
            Some(b) => {
                if let Some(c) = self.conn(index) {
                    c.input = Some(Input::new(b));
                }
                true
            }
            None => {
                // Reading pauses (edge case 11): the peer's bytes wait in the kernel,
                // TCP pushes back, and the connection's read deadline keeps running.
                if let Some(c) = self.conn(index) {
                    c.paused = true;
                    let token = c.token;
                    self.starved.push_back((index, token));
                }
                self.arm_timer(index);
                false
            }
        }
    }

    /// Gives back what an idle connection does not need.
    fn release_idle(&mut self, index: u32) {
        let Some(c) = self.conn(index) else { return };
        if c.input
            .as_ref()
            .is_some_and(|i| !i.lent() && i.bytes().is_empty())
        {
            if let Some(input) = c.input.take() {
                self.pool.put(input.buf);
            }
        }
        let Some(c) = self.conn(index) else { return };
        if c.output.as_ref().is_some_and(|o| o.is_empty()) {
            if let Some(mut output) = c.output.take() {
                output.reset();
                self.outputs.push(output);
            }
        }
    }

    /// What `engine::drive` does between steps, until the step needs to wait.
    fn run(&mut self, index: u32, mut step: Step) {
        loop {
            if let Some(reason) = self.control() {
                return self.close(index, reason);
            }
            let Some(c) = self.conn(index) else { return };
            if c.closing.is_some() {
                return;
            }
            match step {
                Step::Read if c.input.as_ref().is_some_and(Input::lent) => {
                    // The receive that holds the input is still out (the session
                    // survived a timeout, or wrote and read again): wait for it.
                    c.wait = Wait::Read;
                    return self.read(index);
                }
                Step::Read => {
                    if let Some(input) = c.input.as_mut() {
                        if input.changed && !input.bytes().is_empty() {
                            input.changed = false;
                            match self.call_on_data(index) {
                                Some(next) => step = next,
                                None => return self.close(index, CloseReason::SessionPanicked),
                            }
                            continue;
                        }
                        input.changed = false;
                    }
                    let empty = c.input.as_ref().is_none_or(|i| i.bytes().is_empty());
                    c.link.settle_phase(empty);
                    let idle = c.link.phase() == Phase::Idle && empty;
                    let lane = c.link.info.lane;
                    if idle && self.shared.is_draining() {
                        return self.close(index, CloseReason::Drained);
                    }
                    if idle && self.shed(lane) {
                        return self.close(index, CloseReason::Shed);
                    }
                    let Some(c) = self.conn(index) else { return };
                    if c.input.as_ref().is_some_and(Input::is_full) {
                        return self.close(index, CloseReason::Limit(LimitKind::ReadBuffer));
                    }
                    c.wait = Wait::Read;
                    return self.read(index);
                }
                Step::Write => match self.flush(index, Wait::Flush) {
                    Flushed::Done => match self.call(index, |s, cx| s.on_writable(cx)) {
                        Some(next) => step = next,
                        None => return self.close(index, CloseReason::SessionPanicked),
                    },
                    Flushed::Waiting => return,
                },
                Step::Park { until } => {
                    let deadline =
                        until.unwrap_or_else(|| c.link.now() + c.link.limits.park_timeout);
                    c.wait = Wait::Park(deadline);
                    if let Some((token, value)) = c.posted.take() {
                        match self.call(index, |s, cx| s.on_wake(cx, token, value)) {
                            Some(next) => step = next,
                            None => return self.close(index, CloseReason::SessionPanicked),
                        }
                        continue;
                    }
                    self.release_idle(index);
                    return self.arm_timer(index);
                }
                Step::Close => match self.flush(index, Wait::FlushClose) {
                    Flushed::Done => return self.session_closed(index),
                    Flushed::Waiting => return,
                },
                _ => {
                    let reason = c.link.reason_or(CloseReason::SessionError);
                    return self.close(index, reason);
                }
            }
        }
    }

    fn session_closed(&mut self, index: u32) {
        let draining = self.shared.is_draining();
        let Some(c) = self.conn(index) else { return };
        let reason = if draining {
            CloseReason::Drained
        } else if c.link.peer_closed {
            CloseReason::PeerClosed
        } else {
            CloseReason::SessionClosed
        };
        self.close(index, reason);
    }

    fn shed(&self, lane: Lane) -> bool {
        matches!(self.view.state(), ControlState::Shed { from_lane } if lane >= from_lane)
    }

    fn control(&mut self) -> Option<CloseReason> {
        if self.shared.is_stopping() {
            return Some(CloseReason::Shutdown);
        }
        if self.view.refresh(self.shared.control_line()) {
            self.shared.event(Event::ControlReacted {
                state: self.view.state(),
            });
        }
        match self.view.state() {
            ControlState::Stopping => Some(CloseReason::Shutdown),
            _ => None,
        }
    }

    /// Input for the session: bytes read past a handshake first, then the socket.
    fn read(&mut self, index: u32) {
        let Some(c) = self.conn(index) else { return };
        // Under TLS the read-ahead went to the engine at attach (`Link::attach_tls`).
        if c.link.has_read_ahead() && !c.link.has_tls() {
            if !self.ensure_input(index) {
                return;
            }
            let Some(c) = self.conn(index) else { return };
            let Some(input) = c.input.as_mut() else {
                return;
            };
            let n = c.link.take_read_ahead(input.spare_for_read());
            input.filled(n);
            return self.input_arrived(index);
        }
        if c.link.has_tls() {
            self.arm_timer(index);
            return self.tls_turn(index);
        }
        if c.recv != Recv::None || c.paused {
            return self.arm_timer(index);
        }
        let token = c.token;
        let holding = c.input.as_ref().is_some_and(|i| !i.bytes().is_empty());
        if holding || c.readable {
            // A partial message, or the socket already reported bytes: read now.
            if !self.ensure_input(index) {
                return;
            }
            let Some(c) = self.conn(index) else { return };
            c.readable = false;
            let Some(input) = c.input.as_mut() else {
                return;
            };
            let buffer = input.lend();
            c.recv = Recv::Input;
            self.submit_receive(index, token, buffer);
        } else {
            // Nothing to keep: a silent peer pins no buffer, in any phase.
            self.release_idle(index);
            let Some(c) = self.conn(index) else { return };
            c.recv = Recv::Zero;
            if self
                .driver
                .submit(Operation::ReceiveZero { token })
                .is_err()
            {
                return self.close(index, CloseReason::Io(OsErrorClass::Other(0)));
            }
        }
        self.arm_timer(index);
    }

    fn submit_receive(&mut self, index: u32, token: Token, buffer: Buffer) {
        if let Err(rejected) = self.driver.submit(Operation::Receive { token, buffer }) {
            if let Operation::Receive { buffer, .. } = rejected.operation {
                self.pool.put(buffer);
            }
            if let Some(c) = self.conn(index) {
                c.recv = Recv::None;
            }
            self.close(index, CloseReason::Io(OsErrorClass::Other(0)));
        }
    }

    fn submit_send(&mut self, index: u32, token: Token, chunks: SendChunks) {
        if let Err(rejected) = self.driver.submit(Operation::Send { token, chunks }) {
            if let Operation::Send { chunks, .. } = rejected.operation {
                if let Some(c) = self.conn(index) {
                    c.sending = Sending::None;
                    if let Some(output) = c.output.as_mut() {
                        chunks.restore(output);
                    }
                }
            }
            self.close(index, CloseReason::Io(OsErrorClass::Other(0)));
        }
    }

    fn input_arrived(&mut self, index: u32) {
        let Some(c) = self.conn(index) else { return };
        if let Some(input) = c.input.as_mut() {
            input.changed = false;
        }
        match self.call_on_data(index) {
            Some(step) => self.run(index, step),
            None => self.close(index, CloseReason::SessionPanicked),
        }
    }

    fn peer_closed(&mut self, index: u32) {
        match self.call(index, |s, cx| s.on_peer_closed(cx)) {
            Some(step) => self.run(index, step),
            None => self.close(index, CloseReason::SessionPanicked),
        }
    }

    /// Starts sending what is queued: the gate first, one operation at a time.
    fn flush(&mut self, index: u32, after: Wait) -> Flushed {
        let bulk_room = self.bulk_sent < BULK_TURN;
        let Some(c) = self.conn(index) else {
            return Flushed::Waiting;
        };
        let Some(output) = c.output.as_mut() else {
            return Flushed::Done;
        };
        if c.sending != Sending::None {
            c.wait = after;
            return Flushed::Waiting;
        }
        if output.is_empty() {
            c.link.output_done();
            return Flushed::Done;
        }
        c.link.response_started = if output.response_open {
            output.bytes_since_begin > 0
        } else {
            c.link.bytes_out > 0
        };
        c.link.response_tag = output.response_tag;
        if output.front_file().is_some() && !c.link.sends_files_directly() {
            // TLS and pipes take bytes: this piece becomes a chunk like any other.
            if let Err(reason) = output.pull_file() {
                self.close(index, reason);
                return Flushed::Waiting;
            }
        }
        if let Some((file, offset, left)) = output.front_file() {
            let len = left.min(FILE_CHUNK) as usize;
            let token = c.token;
            if !bulk_room {
                c.wait = after;
                self.yielded.push_back((index, token));
                return Flushed::Waiting;
            }
            return match c.link.check_send(len) {
                Ok(()) => {
                    c.sending = Sending::File { total: len };
                    c.wait = after;
                    let op = Operation::SendFile {
                        token,
                        file,
                        offset,
                        len: len as u32,
                    };
                    self.bulk_sent += len;
                    if self.driver.submit(op).is_err() {
                        if let Some(c) = self.conn(index) {
                            c.sending = Sending::None;
                        }
                        self.close(index, CloseReason::Io(OsErrorClass::Other(0)));
                    } else {
                        self.arm_timer(index);
                    }
                    Flushed::Waiting
                }
                Err(NetError::EgressDenied { code }) => {
                    self.denied(index, code);
                    Flushed::Waiting
                }
                Err(_) => {
                    let reason = c.link.reason_or(CloseReason::Io(OsErrorClass::Other(0)));
                    self.close(index, reason);
                    Flushed::Waiting
                }
            };
        }
        let total = output.pending_in_send();
        let tls = c.link.has_tls();
        let token = c.token;
        let checked = if tls {
            let take = total.min(c.link.tls_write_budget());
            c.link.check_seal(take).map(|()| take)
        } else {
            c.link.check_send(total).map(|()| total)
        };
        match checked {
            Ok(take) if tls => {
                let sealed = {
                    let mut slices = [IoSlice::new(&[]); sys::MAX_SLICES];
                    let n = output.fill_slices(&mut slices);
                    c.link.tls_seal(&slices[..n], take)
                };
                match sealed {
                    Ok(taken) => {
                        let Some(cout) = c.link.tls_take_cout() else {
                            self.close(index, CloseReason::TlsFailed);
                            return Flushed::Waiting;
                        };
                        c.sending = Sending::Sealed { taken };
                        c.wait = after;
                        self.submit_send(index, token, SendChunks::from_buffer(cout));
                        self.arm_timer(index);
                        Flushed::Waiting
                    }
                    Err(_) => {
                        let reason = c.link.reason_or(CloseReason::TlsFailed);
                        self.close(index, reason);
                        Flushed::Waiting
                    }
                }
            }
            Ok(_) => {
                let chunks = SendChunks::take(output);
                c.sending = Sending::Plain { total };
                c.wait = after;
                self.submit_send(index, token, chunks);
                self.arm_timer(index);
                Flushed::Waiting
            }
            Err(NetError::EgressDenied { code }) => {
                self.denied(index, code);
                Flushed::Waiting
            }
            Err(_) => {
                let reason = c.link.reason_or(CloseReason::Io(OsErrorClass::Other(0)));
                self.close(index, reason);
                Flushed::Waiting
            }
        }
    }

    /// The gate denied a write: the refusal if no byte of the response left, then close.
    fn denied(&mut self, index: u32, code: u16) {
        let Some(c) = self.conn(index) else { return };
        let started = c.link.response_started;
        if let (Some(output), Some(session)) = (c.output.as_mut(), c.session.as_mut()) {
            output.wipe_all();
            if !started {
                let out = &mut **output;
                if guarded(|| session.on_denied(code, out)).is_some() {
                    // One bounded attempt, not checked again (it is the denial).
                    let mut budget = usize::from(c.link.limits.refusal_bytes_max);
                    for chunk in &output.chunks {
                        let bytes = chunk.remaining();
                        let take = bytes.len().min(budget);
                        if take == 0 {
                            break;
                        }
                        c.link.send_denial_once(&bytes[..take]);
                        budget -= take;
                    }
                }
                output.wipe_all();
            }
        }
        self.close(index, CloseReason::EgressDenied(code));
    }

    // ---- completions ------------------------------------------------------------

    fn on_completion(&mut self, done: Completion) {
        let index = (done.token.0 & 0xFFFF_FFFF) as u32;
        let current = self
            .slots
            .get(index as usize)
            .is_some_and(|s| u64::from(s.generation) == done.token.0 >> 32 && s.conn.is_some());
        if !current {
            if let Some(b) = done.buffer {
                self.pool.put(b);
            }
            return;
        }
        match done.kind {
            OperationKind::Receive => self.on_receive(index, done),
            OperationKind::Send | OperationKind::SendFile => self.on_send(index, done),
            _ => {}
        }
    }

    fn on_receive(&mut self, index: u32, done: Completion) {
        let Some(c) = self.conn(index) else { return };
        let kind = std::mem::replace(&mut c.recv, Recv::None);
        let wait = c.wait;
        let closing = c.closing.is_some();
        let n = match done.result {
            Ok(n) => n,
            Err(class) => {
                if let Some(b) = done.buffer {
                    self.give_back(index, kind, b);
                }
                if closing || wait == Wait::Closing {
                    return self.settle(index);
                }
                if let Some(c) = self.conn(index) {
                    c.link.note_failure(class);
                    let reason = c.link.reason_or(CloseReason::Io(class));
                    self.close(index, reason);
                }
                return;
            }
        };
        match kind {
            Recv::None => {
                if let Some(b) = done.buffer {
                    self.pool.put(b);
                }
            }
            Recv::Zero => {
                if closing {
                    return self.settle(index);
                }
                if matches!(wait, Wait::Read) {
                    // Bytes are there: now a buffer is worth taking.
                    c.readable = true;
                    self.read(index);
                } else {
                    c.readable = true;
                }
            }
            Recv::Input => {
                let Some(buffer) = done.buffer else { return };
                let Some(input) = c.input.as_mut() else {
                    self.pool.put(buffer);
                    return;
                };
                input.give_back(buffer);
                if closing {
                    return self.settle(index);
                }
                if n == 0 {
                    c.link.peer_closed = true;
                    if wait == Wait::Read {
                        return self.peer_closed(index);
                    }
                    return;
                }
                input.changed = true;
                if c.link.note_received(n).is_err() {
                    let reason = c.link.reason_or(CloseReason::Io(OsErrorClass::Other(0)));
                    return self.close(index, reason);
                }
                if wait == Wait::Read {
                    self.input_arrived(index);
                }
            }
            Recv::Cipher => {
                let Some(buffer) = done.buffer else { return };
                c.link.tls_put_cin(buffer);
                if closing {
                    return self.settle(index);
                }
                if n == 0 {
                    c.link.tls_transport_closed();
                } else if c.link.note_cipher(n).is_err() {
                    let reason = c.link.reason_or(CloseReason::Io(OsErrorClass::Other(0)));
                    return self.close(index, reason);
                }
                self.tls_turn(index);
            }
            Recv::Proxy => {
                let Some(buffer) = done.buffer else { return };
                if closing {
                    self.pool.put(buffer);
                    return self.settle(index);
                }
                self.proxy_data(index, buffer, n);
            }
            Recv::Discard => {
                let Some(mut buffer) = done.buffer else {
                    return;
                };
                buffer.clear();
                let Wait::Linger(until) = wait else {
                    self.pool.put(buffer);
                    return self.settle(index);
                };
                c.linger_left = c
                    .linger_left
                    .saturating_sub(u32::try_from(n).unwrap_or(u32::MAX));
                if n == 0 || c.linger_left == 0 {
                    self.pool.put(buffer);
                    return self.finish_closing(index);
                }
                c.recv = Recv::Discard;
                let token = c.token;
                let _ = until;
                self.submit_receive(index, token, buffer);
            }
        }
    }

    /// A failed receive's buffer goes back where it came from.
    fn give_back(&mut self, index: u32, kind: Recv, buffer: Buffer) {
        let Some(c) = self.conn(index) else {
            return self.pool.put(buffer);
        };
        match kind {
            Recv::Input => match c.input.as_mut() {
                Some(input) => input.give_back(buffer),
                None => self.pool.put(buffer),
            },
            Recv::Cipher => c.link.tls_put_cin(buffer),
            _ => self.pool.put(buffer),
        }
    }

    fn on_send(&mut self, index: u32, mut done: Completion) {
        let Some(c) = self.conn(index) else { return };
        let moved_nothing =
            done.result == Ok(0) && done.chunks.as_ref().is_some_and(|ch| ch.pending() > 0);
        if !moved_nothing {
            c.zero_send = false;
        } else if c.zero_send {
            done.result = Err(OsErrorClass::Other(0));
        } else if let Some(chunks) = done.chunks.take() {
            c.zero_send = true;
            let token = c.token;
            return self.submit_send(index, token, chunks);
        }
        let sending = std::mem::replace(&mut c.sending, Sending::None);
        let wait = c.wait;
        let chunks = done.chunks;
        let closing = c.closing.is_some();
        match sending {
            Sending::Plain { total } => {
                if let (Some(chunks), Some(output)) = (chunks, c.output.as_mut()) {
                    chunks.restore(output);
                }
                match done.result {
                    Ok(n) => {
                        let rate = c.link.note_sent(n);
                        c.link.sent_of(total, n);
                        if let Some(output) = c.output.as_mut() {
                            output.advance(n);
                            output.bytes_since_begin += n as u64;
                        }
                        if rate.is_err() && !closing {
                            let reason = c.link.reason_or(CloseReason::Io(OsErrorClass::Other(0)));
                            return self.close(index, reason);
                        }
                    }
                    Err(class) => {
                        if closing {
                            return self.settle(index);
                        }
                        c.link.note_failure(class);
                        let reason = c.link.reason_or(CloseReason::Io(class));
                        return self.close(index, reason);
                    }
                }
            }
            Sending::File { total } => match done.result {
                Ok(0) => {
                    if closing {
                        return self.settle(index);
                    }
                    return self.close(index, CloseReason::Io(OsErrorClass::FileTruncated));
                }
                Ok(n) => {
                    let rate = c.link.note_sent(n);
                    c.link.sent_of(total, n);
                    if let Some(output) = c.output.as_mut() {
                        output.advance(n);
                        output.bytes_since_begin += n as u64;
                    }
                    if rate.is_err() && !closing {
                        let reason = c.link.reason_or(CloseReason::Io(OsErrorClass::Other(0)));
                        return self.close(index, reason);
                    }
                }
                Err(class) => {
                    if closing {
                        return self.settle(index);
                    }
                    c.link.note_failure(class);
                    let reason = c.link.reason_or(CloseReason::Io(class));
                    return self.close(index, reason);
                }
            },
            Sending::Sealed { taken } => {
                let Some(mut chunks) = chunks else { return };
                match done.result {
                    Ok(n) => {
                        if c.link.note_sent(n).is_err() && !closing {
                            if let Some(cout) = chunks.into_buffer() {
                                c.link.tls_put_cout(cout);
                            }
                            let reason = c.link.reason_or(CloseReason::Io(OsErrorClass::Other(0)));
                            return self.close(index, reason);
                        }
                        if chunks.advance(n) {
                            // A partial send of the records: the rest goes first.
                            c.sending = Sending::Sealed { taken };
                            let token = c.token;
                            self.submit_send(index, token, chunks);
                            return;
                        }
                        if let Some(cout) = chunks.into_buffer() {
                            c.link.tls_put_cout(cout);
                        }
                        if let Some(output) = c.output.as_mut() {
                            output.advance(taken);
                            output.bytes_since_begin += taken as u64;
                        }
                    }
                    Err(class) => {
                        if let Some(cout) = chunks.into_buffer() {
                            c.link.tls_put_cout(cout);
                        }
                        if closing {
                            return self.settle(index);
                        }
                        c.link.note_failure(class);
                        let reason = c.link.reason_or(CloseReason::Io(class));
                        return self.close(index, reason);
                    }
                }
            }
            Sending::Machine => {
                let Some(mut chunks) = chunks else { return };
                match done.result {
                    Ok(n) => {
                        if c.link.note_sent(n).is_err() && !closing {
                            if let Some(cout) = chunks.into_buffer() {
                                c.link.tls_put_cout(cout);
                            }
                            let reason = c.link.reason_or(CloseReason::Io(OsErrorClass::Other(0)));
                            return self.close(index, reason);
                        }
                        if chunks.advance(n) {
                            c.sending = Sending::Machine;
                            let token = c.token;
                            self.submit_send(index, token, chunks);
                            return;
                        }
                        if let Some(cout) = chunks.into_buffer() {
                            c.link.tls_put_cout(cout);
                        }
                    }
                    Err(class) => {
                        if let Some(cout) = chunks.into_buffer() {
                            c.link.tls_put_cout(cout);
                        }
                        if closing {
                            return self.settle(index);
                        }
                        c.link.note_failure(class);
                        let reason = c.link.reason_or(CloseReason::TlsFailed);
                        return self.close(index, reason);
                    }
                }
                if !closing {
                    self.tls_turn(index);
                    return;
                }
            }
            Sending::None => return,
        }
        // Before anything below can park the output with the connection idle.
        let pool = &mut self.pool;
        if let Some(output) = self
            .slots
            .get_mut(index as usize)
            .and_then(|s| s.conn.as_mut())
            .and_then(|c| c.output.as_mut())
        {
            output.return_spares(pool);
        }
        if closing {
            return self.settle(index);
        }
        self.flush_and_continue(index, wait);
    }

    /// Sends the next piece and, when the output is empty, does what the wait was
    /// for.
    fn flush_and_continue(&mut self, index: u32, wait: Wait) {
        match wait {
            Wait::Flush => match self.flush(index, Wait::Flush) {
                Flushed::Done => match self.call(index, |s, cx| s.on_writable(cx)) {
                    Some(next) => self.run(index, next),
                    None => self.close(index, CloseReason::SessionPanicked),
                },
                Flushed::Waiting => {}
            },
            Wait::FlushClose => match self.flush(index, Wait::FlushClose) {
                Flushed::Done => self.session_closed(index),
                Flushed::Waiting => {}
            },
            _ => {}
        }
    }

    // ---- timers -----------------------------------------------------------------

    fn arm_timer(&mut self, index: u32) {
        let now = self.clock.now();
        let ticks = self.ticks;
        let Some(c) = self
            .slots
            .get_mut(index as usize)
            .and_then(|s| s.conn.as_mut())
        else {
            return;
        };
        let at = match c.wait {
            Wait::Handshake | Wait::Read => c.link.read_timer(now),
            Wait::Flush | Wait::FlushClose => c.link.write_timer(now),
            Wait::Park(until) | Wait::Linger(until) => until,
            Wait::Closing => return,
        };
        let tick = ticks.deadline(at);
        let token = c.token;
        match c.timer {
            Some(id) if self.wheel.reschedule(id, tick) => {}
            _ => c.timer = Some(self.wheel.insert(tick, token.0)),
        }
    }

    fn fire_timers(&mut self) {
        let now_tick = self.ticks.now(self.clock.now());
        for _ in 0..TIMERS_PER_TURN {
            let Some(fired) = self.wheel.pop_expired(now_tick) else {
                return;
            };
            let index = (fired.payload & 0xFFFF_FFFF) as u32;
            let current = self.slots.get(index as usize).is_some_and(|s| {
                u64::from(s.generation) == fired.payload >> 32 && s.conn.is_some()
            });
            if !current {
                continue;
            }
            if let Some(c) = self.conn(index) {
                c.timer = None;
            }
            self.on_timer(index);
        }
    }

    fn on_timer(&mut self, index: u32) {
        let now = self.clock.now();
        let Some(c) = self.conn(index) else { return };
        match c.wait {
            Wait::Handshake | Wait::Read => match c.link.read_check(now) {
                Ok(()) => self.arm_timer(index),
                Err(NetError::TimedOut { kind }) if c.opened => self.timed_out(index, kind),
                Err(_) => {
                    let reason = c.link.reason_or(CloseReason::Io(OsErrorClass::Other(0)));
                    self.close(index, reason);
                }
            },
            Wait::Flush | Wait::FlushClose => match c.link.write_check(now) {
                Ok(()) => self.arm_timer(index),
                Err(_) => {
                    let reason = c.link.reason_or(CloseReason::Io(OsErrorClass::Other(0)));
                    self.close(index, reason);
                }
            },
            Wait::Park(until) => {
                if now >= until {
                    self.timed_out(index, TimeoutKind::Park);
                } else {
                    self.arm_timer(index);
                }
            }
            Wait::Linger(until) => {
                if now >= until {
                    self.finish_closing(index);
                } else {
                    self.arm_timer(index);
                }
            }
            Wait::Closing => {}
        }
    }

    fn timed_out(&mut self, index: u32, kind: TimeoutKind) {
        match self.call(index, |s, cx| s.on_timeout(cx, kind)) {
            None => self.close(index, CloseReason::SessionPanicked),
            Some(Step::Close | Step::Abort) => self.close(index, CloseReason::for_timeout(kind)),
            Some(next) => {
                if let Some(c) = self.conn(index) {
                    c.link.rearm();
                }
                self.run(index, next);
            }
        }
    }

    // ---- other threads ------------------------------------------------------------

    fn take_kills(&mut self) {
        let list = std::mem::take(
            &mut *self
                .notes
                .killed
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        if list.is_empty() {
            return;
        }
        for index in &list {
            let index = *index;
            let Some(c) = self.conn(index) else { continue };
            let Some(k) = c.link.killed() else { continue };
            if c.closing.is_none() {
                self.close(index, CloseReason::Killed(k));
            } else {
                // A kill during the linger ends it at once, abortively.
                c.closing = Some(CloseReason::Killed(k));
                if matches!(c.wait, Wait::Linger(_)) {
                    self.finish_closing(index);
                }
            }
        }
        let mut list = list;
        list.clear();
        let mut guard = self
            .notes
            .killed
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if guard.is_empty() {
            *guard = list;
        }
    }

    fn take_posted(&mut self) {
        let shared = self.shared;
        let ws = &shared.workers[self.idx];
        // Read first: this runs on every turn, and a write would own the line.
        if ws.completer.wake_pending.load(Ordering::Acquire) {
            ws.completer.wake_pending.store(false, Ordering::Release);
        }
        while let Some(p) = ws.completer.ring.pop() {
            match shared.conn_index(p.connection, self.idx as u32) {
                Some(index) => self.posted(index, p.token, p.value),
                None => {
                    ws.stats.count_stale();
                    shared.event(Event::StaleCompletion {
                        worker: WorkerId(self.idx as u16),
                    });
                }
            }
        }
    }

    fn posted(&mut self, index: u32, token: u32, value: u64) {
        let Some(c) = self.conn(index) else { return };
        if matches!(c.wait, Wait::Park(_)) {
            match self.call(index, |s, cx| s.on_wake(cx, token, value)) {
                Some(step) => self.run(index, step),
                None => self.close(index, CloseReason::SessionPanicked),
            }
        } else {
            c.posted = Some((token, value));
        }
    }

    fn run_commands(&mut self) {
        let shared = self.shared;
        let ws = &shared.workers[self.idx];
        if ws.cmd.load(Ordering::Acquire) == 0 {
            return;
        }
        let cmd = ws.cmd.swap(0, Ordering::AcqRel);
        if cmd & CMD_SWEEP != 0 {
            self.sweep(|_| true, CloseReason::Drained);
        }
        if cmd & CMD_PRESSURE != 0 {
            let scale = shared.deadline_scale();
            for i in 0..self.slots.len() as u32 {
                if let Some(c) = self.conn(i) {
                    c.link.set_deadline_scale(scale);
                    self.arm_timer(i);
                }
            }
        }
        if cmd & CMD_SHED != 0 {
            let lane = Lane(ws.lane.load(Ordering::Acquire));
            self.sweep(move |info| info.lane >= lane, CloseReason::Shed);
        }
        if cmd & CMD_KILL_ALL != 0 {
            let reason = match ws.kill_cause.load(Ordering::Acquire) {
                CAUSE_DRAIN => CloseReason::DrainDeadline,
                CAUSE_STOP => CloseReason::Shutdown,
                _ => CloseReason::Shutdown,
            };
            self.close_all(reason);
        }
        let listener = ws.listener.load(Ordering::Acquire);
        if cmd & CMD_LISTENER_SWEEP != 0 {
            self.sweep(
                move |info| {
                    info.listener
                        .is_some_and(|l| u32::from(l.get()) == listener)
                },
                CloseReason::Drained,
            );
        }
        if cmd & CMD_LISTENER_KILL != 0 {
            for i in 0..self.slots.len() as u32 {
                let hit = self.conn(i).is_some_and(|c| {
                    c.closing.is_none()
                        && c.link
                            .info
                            .listener
                            .is_some_and(|l| u32::from(l.get()) == listener)
                });
                if hit {
                    if let Some(c) = self.conn(i) {
                        c.listener.note_killed();
                    }
                    self.close(i, CloseReason::DrainDeadline);
                }
            }
        }
    }

    /// Closes the connections that wait for their next exchange, among those
    /// `pick` chooses.
    fn sweep(&mut self, pick: impl Fn(&ConnectionInfo) -> bool, reason: CloseReason) {
        for i in 0..self.slots.len() as u32 {
            let idle = self.conn(i).is_some_and(|c| {
                c.wait == Wait::Read
                    && c.closing.is_none()
                    && c.link.phase() == Phase::Idle
                    && c.input
                        .as_ref()
                        .is_none_or(|n| !n.lent() && n.bytes().is_empty())
                    && pick(&c.link.info)
            });
            if idle {
                self.close(i, reason);
            }
        }
    }

    fn close_all(&mut self, reason: CloseReason) {
        for i in 0..self.slots.len() as u32 {
            if self.conn(i).is_some_and(|c| c.closing.is_none()) {
                self.close(i, reason);
            }
        }
    }

    // ---- closing ------------------------------------------------------------------

    /// Starts the close. Graceful closes flush nothing here (the session's `Close`
    /// already did): FIN, then a bounded linger while input may still arrive.
    fn close(&mut self, index: u32, reason: CloseReason) {
        let Some(c) = self.conn(index) else { return };
        if c.closing.is_some() {
            return;
        }
        // A kill wins over whatever was about to happen.
        let reason = c.link.killed().map_or(reason, CloseReason::Killed);
        c.closing = Some(reason);
        if !reason.is_abortive() {
            let linger = c.link.begin_graceful_close(c.readable);
            if linger && c.sending == Sending::None {
                let until = c.link.now() + c.link.limits.graceful_linger;
                c.linger_left = c.link.limits.graceful_linger_bytes;
                c.wait = Wait::Linger(until);
                self.arm_timer(index);
                if self.conn(index).is_some_and(|c| c.recv == Recv::None) {
                    self.linger_read(index);
                }
                return;
            }
        }
        self.finish_closing(index);
    }

    fn linger_read(&mut self, index: u32) {
        let Some(buffer) = self.pool.take(SizeClass::SMALL) else {
            return self.finish_closing(index);
        };
        let Some(c) = self.conn(index) else { return };
        c.recv = Recv::Discard;
        let token = c.token;
        self.submit_receive(index, token, buffer);
    }

    /// No more linger: cancels what is in flight; the last completion finishes it.
    fn finish_closing(&mut self, index: u32) {
        let Some(c) = self.conn(index) else { return };
        c.wait = Wait::Closing;
        if let Some(id) = c.timer.take() {
            self.wheel.cancel(id);
        }
        let Some(c) = self.conn(index) else { return };
        let (recv, sending, token) = (c.recv, c.sending, c.token);
        if recv != Recv::None {
            let _ = self.driver.cancel(token, OperationKind::Receive);
        }
        if sending != Sending::None {
            let _ = self.driver.cancel(token, OperationKind::Send);
        }
        self.settle(index);
    }

    /// Finishes the close once nothing is in flight.
    fn settle(&mut self, index: u32) {
        let Some(c) = self.conn(index) else { return };
        if c.wait == Wait::Closing && c.recv == Recv::None && c.sending == Sending::None {
            // A kill also ends the linger's read: it may arrive here first.
            let reason = match c.link.killed() {
                Some(k) => CloseReason::Killed(k),
                None => c.closing.unwrap_or(CloseReason::SessionClosed),
            };
            self.finish(index, reason, true);
        }
    }

    /// Closes the socket, frees the slot, tells everyone. Exactly once per connection.
    fn finish(&mut self, index: u32, reason: CloseReason, registered: bool) {
        let shared = self.shared;
        let ws = &shared.workers[self.idx];
        let Some(mut c) = self.slots[index as usize].conn.take() else {
            return;
        };
        if let Some(id) = c.timer.take() {
            self.wheel.cancel(id);
        }
        if registered {
            let _ = self.driver.deregister(c.token);
        }
        if let Some(input) = c.input.take() {
            self.pool.put(input.buf);
        }
        if let Some(mut output) = c.output.take() {
            output.reset();
            self.outputs.push(output);
        }
        if let Some(mut p) = c.proxy.take() {
            if let Some(b) = p.buffer.take() {
                self.pool.put(b);
            }
        }
        let mut link = c.link;
        if let Some(b) = link.take_pending() {
            self.pool.put(b);
        }
        if let Some((cin, cout)) = link.take_tls_buffers() {
            self.pool.put(cin);
            self.pool.put(cout);
        }
        // A drain turns a graceful close into `Drained`, as on the blocking driver.
        let reason = if shared.is_draining() && !reason.is_abortive() {
            CloseReason::Drained
        } else {
            reason
        };
        let info = link.info.clone();
        let (bytes_in, bytes_out) = (link.bytes_in, link.bytes_out);
        let lifetime = self.clock.now().saturating_duration_since(info.accepted_at);
        let slot = link.slot.clone();
        // The ticket comes back with the gate's `closed`; keep the cell.
        let erased = link.gate.take();
        let reason = link.finish_reactor(reason);
        if let Some(mut g) = erased {
            g.close(&info, reason);
            if let Ok(cell) = g.into_any().downcast::<GateCell<G>>() {
                self.cells.push(cell);
            }
        }
        shared.unregister_conn(info.id);
        self.slot_pool.push(slot);
        self.free.push(index);
        self.open -= 1;
        ws.load.fetch_sub(1, Ordering::Relaxed);
        count_drained(shared, reason);
        shared.release(&c.listener, c.source);
        record_close(shared, ws, &info, reason, bytes_in, bytes_out, lifetime);
        if let Some(mut session) = c.session.take() {
            let _ = guarded(|| session.on_close(&info, reason));
        }
        if let Some(mut facts) = info.proxy {
            if Arc::get_mut(&mut facts).is_some() && self.facts_pool.len() < 4 {
                self.facts_pool.push(facts);
            }
        }
        shared.notify_progress();
    }
}

impl<F: SessionFactory, G: Gate> Reactor<'_, F, G> {
    /// After a panic in the loop: every connection is reset, its gate ticket and caps
    /// returned, and its close counted, so `stats`, drains, and admission stay right.
    fn abandon_all(&mut self) {
        let shared = self.shared;
        let ws = &shared.workers[self.idx];
        for i in 0..self.slots.len() {
            let Some(c) = self.slots[i].conn.take() else {
                continue;
            };
            let _ = self.driver.deregister(c.token);
            let mut link = c.link;
            let info = link.info.clone();
            let (bytes_in, bytes_out) = (link.bytes_in, link.bytes_out);
            let lifetime = self.clock.now().saturating_duration_since(info.accepted_at);
            let erased = link.gate.take();
            let reason = link.finish_reactor(CloseReason::SessionPanicked);
            if let Some(mut g) = erased {
                g.close(&info, reason);
            }
            shared.unregister_conn(info.id);
            ws.load.fetch_sub(1, Ordering::Relaxed);
            count_drained(shared, reason);
            shared.release(&c.listener, c.source);
            record_close(shared, ws, &info, reason, bytes_in, bytes_out, lifetime);
        }
        self.open = 0;
        shared.notify_progress();
    }
}

/// Where `flush` left things.
enum Flushed {
    Done,
    Waiting,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An idle connection's state: the 512-byte target (`docs/API.md`).
    #[test]
    fn test_idle_connection_state_size() {
        let size = size_of::<Conn<()>>();
        eprintln!(
            "Conn {size}, Link {}, ConnectionInfo {}",
            size_of::<Link>(),
            size_of::<ConnectionInfo>()
        );
        // 512 is the goal (register R-18); this keeps it from growing meanwhile.
        assert!(size <= 900, "{size} bytes per idle connection");
    }
}
