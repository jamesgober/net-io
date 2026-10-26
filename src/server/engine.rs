//! The blocking driver: one accept thread per listener, a bounded pool of
//! workers, and a bounded hand-over queue between them.
//!
//! ```text
//!  accept thread (per listener)                    workers (bounded pool)
//!    wait(listener, wake)                            take a job (blocks, zero CPU)
//!    accept: reserve descriptor on EMFILE            run the handler or drive the session
//!    caps: global, listener, source                  close with one reason, release caps
//!    Gate::admit (no byte read)
//!    hand-over (full: refuse Busy with RST)
//! ```

use std::any::TypeId;
use std::collections::VecDeque;
use std::io::IoSlice;
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering, fence};
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError, Weak};
use std::time::{Duration, Instant};

use super::source::SourceTable;
use super::{BlockingHandler, DoorState, DrainReport, ListenerSpec, Server, Sessions, Stats};
use crate::accept::{Accepted, Acceptor};
use crate::addr::PrefixKey;
use crate::buf::{Buffer, BufferPool};
use crate::completer::{Completer, CompleterShared, CompleterTarget};
use crate::control::{ControlLine, ControlState, ControlView, NoControl};
use crate::driver::DriverKind;
use crate::error::{CloseReason, KillReason, NetError, OsErrorClass, RefusalCause, TimeoutKind};
use crate::events::{CoalescedKind, Coalescer, Event, EventSink, NoopSink};
use crate::gate::{AdmitStage, AllowAll, ErasedGate, Gate, GateCell, Refusal, guarded};
use crate::id::{ConnectionId, IdBlock, ListenerId, WorkerId};
use crate::info::{ConnectionInfo, Lane, Origin};
use crate::limits::{Effective, Limits};
use crate::link::{ClockRef, Got, Link, WakeSource};
use crate::opts::{ListenOptions, TcpOptions};
use crate::session::{Input, Output, Phase, Session, SessionContext, SessionFactory, Step};
use crate::sys::{self, AsSock, Interest, KillSlot, Wake};
use crate::tcp::{TcpConnection, TcpListener};
use crate::time::Clock;

const WORKER_STACK: usize = 256 * 1024;
const DRAIN_KILL: KillReason = KillReason(0);

/// `WorkerShared::kill_cause`: a user's kill, the drain deadline, or `Stopping`.
const CAUSE_USER: u8 = 0;
const CAUSE_DRAIN: u8 = 1;
const CAUSE_STOP: u8 = 2;

/// `WorkerShared::idle_cause`: an idle connection closed by a drain or by shedding.
const IDLE_DRAIN: u8 = 0;
const IDLE_SHED: u8 = 1;

/// How often a drain looks again for connections that became idle.
const DRAIN_PASS: Duration = Duration::from_millis(10);

/// Increments `counter` unless it already reached `cap`; `true` when a slot was taken.
#[inline]
fn take_slot(counter: &AtomicU32, cap: u32) -> bool {
    let mut n = counter.load(Ordering::Acquire);
    while n < cap {
        match counter.compare_exchange_weak(n, n + 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(seen) => n = seen,
        }
    }
    false
}

pub(crate) struct Config<W, G, S> {
    pub listeners: Vec<ListenerSpec>,
    pub driver: DriverKind,
    pub workers: u16,
    pub limits: Limits,
    pub work: W,
    pub gate: G,
    pub sink: S,
    pub control: Option<Arc<dyn ControlLine>>,
    pub wipe: bool,
    pub clock: Option<Arc<dyn Clock>>,
}

/// One worker's counters. The worker is the only writer; `seq` makes a reader's
/// snapshot of one worker consistent (a sequence lock: odd while a close is being
/// counted). Cost: two stores per close for the writer; readers retry a torn read.
#[derive(Default)]
pub(crate) struct WorkerStats {
    seq: AtomicU64,
    closed: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    egress_denied: AtomicU64,
    killed: AtomicU64,
    slow_peers: AtomicU64,
    timeouts: AtomicU64,
    stale_completions: AtomicU64,
    session_panics: AtomicU64,
    closed_by: [AtomicU64; CloseReason::COUNT],
}

impl WorkerStats {
    #[inline]
    fn begin_write(&self) {
        let s = self.seq.load(Ordering::Relaxed);
        self.seq.store(s.wrapping_add(1), Ordering::Relaxed);
        fence(Ordering::Release);
    }

    #[inline]
    fn end_write(&self) {
        let s = self.seq.load(Ordering::Relaxed);
        self.seq.store(s.wrapping_add(1), Ordering::Release);
    }

    /// Adds this worker's counters to `s` and `closed_by` as one consistent snapshot.
    fn read_into(&self, s: &mut Stats, closed_by: &mut [u64; CloseReason::COUNT]) {
        loop {
            let before = self.seq.load(Ordering::Acquire);
            if before & 1 == 1 {
                std::hint::spin_loop();
                continue;
            }
            let snap = [
                self.closed.load(Ordering::Relaxed),
                self.bytes_in.load(Ordering::Relaxed),
                self.bytes_out.load(Ordering::Relaxed),
                self.egress_denied.load(Ordering::Relaxed),
                self.killed.load(Ordering::Relaxed),
                self.slow_peers.load(Ordering::Relaxed),
                self.timeouts.load(Ordering::Relaxed),
                self.stale_completions.load(Ordering::Relaxed),
                self.session_panics.load(Ordering::Relaxed),
            ];
            let mut by = [0u64; CloseReason::COUNT];
            for (b, c) in by.iter_mut().zip(&self.closed_by) {
                *b = c.load(Ordering::Relaxed);
            }
            fence(Ordering::Acquire);
            if self.seq.load(Ordering::Relaxed) != before {
                continue;
            }
            s.closed += snap[0];
            s.bytes_in += snap[1];
            s.bytes_out += snap[2];
            s.egress_denied += snap[3];
            s.killed += snap[4];
            s.slow_peers += snap[5];
            s.timeouts += snap[6];
            s.stale_completions += snap[7];
            s.session_panics += snap[8];
            for (total, b) in closed_by.iter_mut().zip(by) {
                *total += b;
            }
            return;
        }
    }
}

pub(crate) struct WorkerShared {
    slot: Arc<KillSlot>,
    wake: Arc<Wake>,
    current: AtomicU64,
    /// The current connection's lane, for shedding.
    lane: AtomicU8,
    /// Why net-io itself killed the current connection (`CAUSE_*`).
    kill_cause: AtomicU8,
    /// Why net-io closed the current connection while idle (`IDLE_*`).
    idle_cause: AtomicU8,
    completer: Arc<CompleterShared>,
    stats: WorkerStats,
}

struct WorkerTarget {
    shared: Weak<Shared>,
    idx: usize,
}

impl CompleterTarget for WorkerTarget {
    fn owns(&self, id: ConnectionId) -> bool {
        self.shared
            .upgrade()
            .is_some_and(|s| s.workers[self.idx].current.load(Ordering::Acquire) == id.get())
    }
    fn wake(&self) {
        if let Some(s) = self.shared.upgrade() {
            s.workers[self.idx].wake.wake();
        }
    }
    fn stopped(&self) -> bool {
        self.shared
            .upgrade()
            .is_none_or(|s| s.stopping.load(Ordering::Acquire))
    }
}

/// The non-generic state `Server` and `ServerHandle` share with the threads.
pub(crate) struct Shared {
    pid: u32,
    door: AtomicBool,
    draining: AtomicBool,
    stopping: AtomicBool,
    stop: Mutex<Option<Option<Instant>>>,
    stop_cv: Condvar,
    progress: Mutex<()>,
    progress_cv: Condvar,
    workers: Vec<WorkerShared>,
    accept_wakes: Vec<Arc<Wake>>,
    queue_notify: OnceLock<Box<dyn Fn() + Send + Sync>>,
    queue_len: AtomicUsize,
    control: Arc<dyn ControlLine>,
    sink: Option<Arc<dyn EventSink>>,
    open: AtomicU32,
    busy: AtomicU32,
    accepted: AtomicU64,
    refused: AtomicU64,
    refused_by: [AtomicU64; RefusalCause::COUNT],
    descriptor_pressure: AtomicU64,
    drained_graceful: AtomicU32,
    drained_killed: AtomicU32,
    pub(crate) drain_timeout: Duration,
    listener_counts: Vec<AtomicU32>,
    listener_limits: Vec<Effective>,
    listener_tcp: Vec<TcpOptions>,
    sources: SourceTable,
}

impl Shared {
    fn event(&self, e: Event) {
        if let Some(s) = &self.sink {
            s.event(&e);
        }
    }

    fn forked(&self) -> bool {
        std::process::id() != self.pid
    }

    pub(crate) fn open_door(&self) -> Result<(), NetError> {
        if self.forked() {
            return Err(NetError::ForkedChild);
        }
        if self.draining.load(Ordering::Acquire) || self.stopping.load(Ordering::Acquire) {
            return Err(NetError::ShuttingDown);
        }
        if !self.door.swap(true, Ordering::AcqRel) {
            self.event(Event::DoorOpened);
            for w in &self.accept_wakes {
                w.wake();
            }
        }
        Ok(())
    }

    pub(crate) fn close_door(&self) {
        if self.door.swap(false, Ordering::AcqRel) {
            self.event(Event::DoorClosed);
            for w in &self.accept_wakes {
                w.wake();
            }
        }
    }

    pub(crate) fn door(&self) -> DoorState {
        if self.door.load(Ordering::Acquire) {
            DoorState::Open
        } else {
            DoorState::Closed
        }
    }

    pub(crate) fn request_stop(&self, deadline: Option<Instant>) {
        let mut stop = self.stop.lock().unwrap_or_else(PoisonError::into_inner);
        if stop.is_none() {
            *stop = Some(deadline);
        }
        self.stop_cv.notify_all();
    }

    pub(crate) fn wait_for_stop_request(&self) -> Instant {
        let mut stop = self.stop.lock().unwrap_or_else(PoisonError::into_inner);
        while stop.is_none() {
            stop = self
                .stop_cv
                .wait(stop)
                .unwrap_or_else(PoisonError::into_inner);
        }
        stop.flatten()
            .unwrap_or_else(|| Instant::now() + self.drain_timeout)
    }

    pub(crate) fn wake_all(&self) {
        for w in &self.accept_wakes {
            w.wake();
        }
        for w in &self.workers {
            w.wake.wake();
        }
    }

    pub(crate) fn kill(&self, id: ConnectionId, reason: KillReason) -> bool {
        for w in &self.workers {
            if w.current.load(Ordering::Acquire) != id.get() {
                continue;
            }
            let generation = w.slot.generation();
            if w.current.load(Ordering::Acquire) != id.get() {
                return false;
            }
            return w.slot.kill(generation, reason);
        }
        false
    }

    pub(crate) fn completer(&self, worker: WorkerId) -> Option<Completer> {
        self.workers.get(usize::from(worker.0)).map(|w| Completer {
            shared: w.completer.clone(),
        })
    }

    pub(crate) fn stats(&self) -> Stats {
        let mut s = Stats {
            open: u64::from(self.open.load(Ordering::Relaxed)),
            accepted: self.accepted.load(Ordering::Relaxed),
            refused: self.refused.load(Ordering::Relaxed),
            descriptor_pressure: self.descriptor_pressure.load(Ordering::Relaxed),
            ..Stats::default()
        };
        let mut closed_by = [0u64; CloseReason::COUNT];
        for w in &self.workers {
            w.stats.read_into(&mut s, &mut closed_by);
        }
        let mut refused_by = [0u64; RefusalCause::COUNT];
        for (i, c) in self.refused_by.iter().enumerate() {
            refused_by[i] = c.load(Ordering::Relaxed);
        }
        Stats::from_parts(s, refused_by, closed_by)
    }

    /// Wakes a drain waiting for connections to finish.
    fn notify_progress(&self) {
        let _g = self.progress.lock().unwrap_or_else(PoisonError::into_inner);
        self.progress_cv.notify_all();
    }

    fn idle(&self) -> bool {
        self.busy.load(Ordering::Acquire) == 0 && self.queue_len.load(Ordering::Acquire) == 0
    }

    pub(crate) fn drain(&self, deadline: Instant) -> DrainReport {
        let start = Instant::now();
        self.close_door();
        if !self.draining.swap(true, Ordering::AcqRel) {
            self.drained_graceful.store(0, Ordering::Relaxed);
            self.drained_killed.store(0, Ordering::Relaxed);
            self.event(Event::DrainStarted {
                open: self.open.load(Ordering::Relaxed),
            });
        }
        let mut guard = self.progress.lock().unwrap_or_else(PoisonError::into_inner);
        let mut killed_at_deadline = false;
        while !self.idle() {
            // Close every connection that waits for its next exchange; repeated each
            // pass for connections that finish an exchange during the drain.
            for w in &self.workers {
                if w.current.load(Ordering::Acquire) != 0 && !w.slot.drained() {
                    w.idle_cause.store(IDLE_DRAIN, Ordering::Release);
                    w.slot.drain_idle(w.slot.generation());
                }
            }
            let now = Instant::now();
            if now >= deadline && !killed_at_deadline {
                killed_at_deadline = true;
                self.kill_all(CAUSE_DRAIN);
            }
            let wait = if killed_at_deadline {
                Duration::from_millis(50)
            } else {
                deadline
                    .saturating_duration_since(now)
                    .clamp(Duration::from_millis(1), DRAIN_PASS)
            };
            guard = self
                .progress_cv
                .wait_timeout(guard, wait)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        drop(guard);
        let report = DrainReport {
            graceful: self.drained_graceful.load(Ordering::Relaxed),
            killed: self.drained_killed.load(Ordering::Relaxed),
            took: start.elapsed(),
        };
        self.event(Event::DrainFinished {
            graceful: report.graceful,
            killed: report.killed,
        });
        report
    }

    /// Kills every open connection on net-io's own behalf (`cause` names why).
    fn kill_all(&self, cause: u8) {
        for w in &self.workers {
            if w.current.load(Ordering::Acquire) != 0 {
                // Claim the cause first (the owner reads it once it sees the kill). A
                // concurrent drain or stop that already claimed it keeps its cause.
                let claimed = w
                    .kill_cause
                    .compare_exchange(CAUSE_USER, cause, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok();
                if !w.slot.kill(w.slot.generation(), DRAIN_KILL) && claimed {
                    // Already closed, or a user's kill won: that reason stands.
                    w.kill_cause.store(CAUSE_USER, Ordering::Release);
                }
            }
        }
    }

    /// `ControlState::Shed`: closes the idle connections in shed lanes now; busy
    /// ones see `pressure()` 1.0 and close at their next idle point.
    fn shed_idle(&self, from_lane: Lane) {
        for w in &self.workers {
            if w.current.load(Ordering::Acquire) != 0
                && w.lane.load(Ordering::Acquire) >= from_lane.0
                && !w.slot.drained()
            {
                w.idle_cause.store(IDLE_SHED, Ordering::Release);
                if !w.slot.drain_idle(w.slot.generation()) {
                    w.idle_cause.store(IDLE_DRAIN, Ordering::Release);
                }
            }
        }
    }

    pub(crate) fn stop_threads(&self) {
        self.stopping.store(true, Ordering::Release);
        self.request_stop(None);
        if let Some(n) = self.queue_notify.get() {
            n();
        }
        self.wake_all();
    }

    fn release(&self, listener: usize, source: Option<PrefixKey>) {
        self.open.fetch_sub(1, Ordering::AcqRel);
        if let Some(c) = self.listener_counts.get(listener) {
            c.fetch_sub(1, Ordering::AcqRel);
        }
        if let Some(k) = source {
            self.sources.release(k);
        }
    }
}

/// An accepted, admitted connection waiting for a worker.
pub struct Job<T> {
    stream: TcpStream,
    info: ConnectionInfo,
    ticket: T,
    listener: usize,
    source: Option<PrefixKey>,
}

struct ListenerRuntime {
    listener: TcpListener,
}

struct Engine<W, G: Gate> {
    shared: Arc<Shared>,
    work: W,
    gate: Arc<G>,
    gated: bool,
    queue: Mutex<VecDeque<Job<G::Ticket>>>,
    queue_cv: Condvar,
    listeners: Vec<ListenerRuntime>,
    clock: ClockRef,
    wipe: bool,
    budget: Arc<AtomicU64>,
    limits: Effective,
}

pub(crate) fn start<W, G, S>(cfg: Config<W, G, S>) -> Result<Server, NetError>
where
    W: super::Workload,
    G: Gate,
    S: EventSink,
{
    let _ = cfg.driver;
    let limits = cfg.limits.effective(DriverKind::Blocking);
    let mut runtimes = Vec::with_capacity(cfg.listeners.len());
    let mut infos = Vec::with_capacity(cfg.listeners.len());
    let mut listener_limits = Vec::with_capacity(cfg.listeners.len());
    let mut listener_tcp = Vec::with_capacity(cfg.listeners.len());
    for (i, spec) in cfg.listeners.into_iter().enumerate() {
        let lim = cfg
            .limits
            .overlay(&spec.limits)
            .effective(DriverKind::Blocking);
        let addrs = match spec.addrs {
            Ok(a) if !a.is_empty() => a,
            Ok(_) => return Err(NetError::NoAddresses),
            Err(text) => {
                return Err(NetError::Os {
                    op: "resolve",
                    source: std::io::Error::other(text),
                });
            }
        };
        let options = spec
            .options
            .unwrap_or_else(|| ListenOptions::new().backlog(lim.backlog));
        let id = ListenerId(u16::try_from(i).unwrap_or(u16::MAX));
        let mut bound = None;
        let mut last = NetError::NoAddresses;
        for a in addrs {
            match sys::tcp_listener(a, &options.params()) {
                Ok(l) => {
                    bound = Some(TcpListener::finish(l, options, id, spec.name.clone())?);
                    break;
                }
                Err(e) => last = crate::tcp::bind_error(a, e),
            }
        }
        let listener = bound.ok_or(last)?;
        infos.push(listener.info().clone());
        listener_limits.push(lim);
        listener_tcp.push(*listener.tcp_options());
        runtimes.push(ListenerRuntime { listener });
    }

    let sink: Option<Arc<dyn EventSink>> = if TypeId::of::<S>() == TypeId::of::<NoopSink>() {
        None
    } else {
        Some(Arc::new(cfg.sink))
    };
    let accept_wakes = (0..runtimes.len())
        .map(|_| Wake::new().map(Arc::new))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| NetError::DriverSetup {
            driver: DriverKind::Blocking,
            source: e,
        })?;
    let mut worker_wakes = Vec::with_capacity(usize::from(cfg.workers));
    for _ in 0..cfg.workers {
        worker_wakes.push(
            Wake::new()
                .map(Arc::new)
                .map_err(|e| NetError::DriverSetup {
                    driver: DriverKind::Blocking,
                    source: e,
                })?,
        );
    }
    let queue_capacity = limits.completion_queue as usize;
    let shared = Arc::new_cyclic(|weak: &Weak<Shared>| Shared {
        pid: std::process::id(),
        door: AtomicBool::new(false),
        draining: AtomicBool::new(false),
        stopping: AtomicBool::new(false),
        stop: Mutex::new(None),
        stop_cv: Condvar::new(),
        progress: Mutex::new(()),
        progress_cv: Condvar::new(),
        workers: worker_wakes
            .into_iter()
            .enumerate()
            .map(|(i, wake)| WorkerShared {
                slot: Arc::new(KillSlot::new()),
                wake,
                current: AtomicU64::new(0),
                lane: AtomicU8::new(0),
                kill_cause: AtomicU8::new(CAUSE_USER),
                idle_cause: AtomicU8::new(IDLE_DRAIN),
                completer: Arc::new(CompleterShared::new(
                    queue_capacity,
                    Arc::new(WorkerTarget {
                        shared: weak.clone(),
                        idx: i,
                    }),
                    WorkerId(u16::try_from(i).unwrap_or(u16::MAX)),
                )),
                stats: WorkerStats::default(),
            })
            .collect(),
        accept_wakes,
        queue_notify: OnceLock::new(),
        queue_len: AtomicUsize::new(0),
        control: cfg.control.unwrap_or_else(|| Arc::new(NoControl)),
        sink,
        open: AtomicU32::new(0),
        busy: AtomicU32::new(0),
        accepted: AtomicU64::new(0),
        refused: AtomicU64::new(0),
        refused_by: Default::default(),
        descriptor_pressure: AtomicU64::new(0),
        drained_graceful: AtomicU32::new(0),
        drained_killed: AtomicU32::new(0),
        drain_timeout: limits.drain_timeout,
        listener_counts: (0..listener_limits.len())
            .map(|_| AtomicU32::new(0))
            .collect(),
        listener_limits,
        listener_tcp,
        sources: SourceTable::new(limits.max_connections, limits.max_per_source),
    });
    for (i, info) in infos.iter().enumerate() {
        shared.event(Event::ListenerOpened {
            listener: ListenerId(u16::try_from(i).unwrap_or(u16::MAX)),
            local: info.local.socket_addr(),
            backlog: info.backlog,
        });
    }

    let engine = Arc::new(Engine {
        shared: shared.clone(),
        work: cfg.work,
        gated: TypeId::of::<G>() != TypeId::of::<AllowAll>(),
        gate: Arc::new(cfg.gate),
        queue: Mutex::new(VecDeque::with_capacity(usize::from(cfg.workers))),
        queue_cv: Condvar::new(),
        listeners: runtimes,
        clock: cfg.clock.map_or(ClockRef::Monotonic, ClockRef::Custom),
        wipe: cfg.wipe,
        budget: Arc::new(AtomicU64::new(limits.buffer_budget)),
        limits,
    });
    let weak = Arc::downgrade(&engine);
    let _ = shared.queue_notify.set(Box::new(move || {
        if let Some(e) = weak.upgrade() {
            let _g = e.queue.lock().unwrap_or_else(PoisonError::into_inner);
            e.queue_cv.notify_all();
        }
    }));

    let mut threads = Vec::with_capacity(usize::from(cfg.workers) + engine.listeners.len());
    let spawn_error = |e: std::io::Error| NetError::DriverSetup {
        driver: DriverKind::Blocking,
        source: e,
    };
    let mut failure = None;
    for i in 0..usize::from(cfg.workers) {
        let e = engine.clone();
        match std::thread::Builder::new()
            .name(format!("net-io-worker-{i}"))
            .stack_size(WORKER_STACK)
            .spawn(move || worker_loop(&e, i))
        {
            Ok(t) => threads.push(t),
            Err(err) => {
                failure = Some(spawn_error(err));
                break;
            }
        }
    }
    if failure.is_none() {
        for li in 0..engine.listeners.len() {
            let e = engine.clone();
            match std::thread::Builder::new()
                .name(format!("net-io-accept-{li}"))
                .spawn(move || accept_loop(&e, li))
            {
                Ok(t) => threads.push(t),
                Err(err) => {
                    failure = Some(spawn_error(err));
                    break;
                }
            }
        }
    }
    drop(engine);
    if let Some(err) = failure {
        shared.stop_threads();
        for t in threads {
            let _ = t.join();
        }
        return Err(err);
    }
    Ok(Server {
        shared,
        threads,
        listeners: infos,
        stopped: false,
    })
}

// ---- accept ---------------------------------------------------------------

fn accept_loop<W: super::Workload, G: Gate>(engine: &Arc<Engine<W, G>>, li: usize) {
    let shared = &engine.shared;
    let wake = shared.accept_wakes[li].clone();
    let rt = &engine.listeners[li];
    let batch = shared.listener_limits[li].accept_batch;
    let mut acceptor = Acceptor::new();
    let mut ids = IdBlock::new();
    let mut view = ControlView::new();
    let mut coalescer = Coalescer::new();
    let mut pause_until: Option<Instant> = None;
    loop {
        if shared.stopping.load(Ordering::Acquire) {
            return;
        }
        if view.refresh(shared.control.as_ref()) {
            shared.event(Event::ControlReacted {
                state: view.state(),
            });
            match view.state() {
                ControlState::Draining => {
                    shared.close_door();
                    shared.request_stop(view.deadline());
                    // The drain runs here: the door is closed, so this thread has
                    // nothing else to do until it ends.
                    let deadline = view
                        .deadline()
                        .unwrap_or_else(|| Instant::now() + shared.drain_timeout);
                    shared.drain(deadline);
                }
                ControlState::Stopping => {
                    shared.close_door();
                    shared.request_stop(Some(Instant::now()));
                    shared.kill_all(CAUSE_STOP);
                }
                ControlState::Shed { from_lane } => shared.shed_idle(from_lane),
                _ => {}
            }
        }
        let accepting =
            shared.door.load(Ordering::Acquire) && !shared.draining.load(Ordering::Acquire);
        let now = engine.clock.now();
        if !accepting {
            let _ = sys::wait_wake(&wake, None);
            continue;
        }
        if let Some(until) = pause_until {
            if now < until {
                let _ = sys::wait_wake(&wake, Some(until - now));
                continue;
            }
            pause_until = None;
        }
        for _ in 0..batch {
            match acceptor.accept(rt.listener.std()) {
                Accepted::Conn(stream, peer) => {
                    engine.admit_one(stream, peer, li, &mut ids, &view, &mut coalescer)
                }
                Accepted::Skipped(class) => shared.event(Event::AcceptError {
                    listener: ListenerId(li as u16),
                    class,
                }),
                Accepted::Again => {
                    let _ = sys::wait(rt.listener.std().sock(), Interest::Read, Some(&wake), None);
                    break;
                }
                Accepted::Pause(backoff) => {
                    shared.descriptor_pressure.fetch_add(1, Ordering::Relaxed);
                    shared.event(Event::DescriptorPressure {
                        listener: ListenerId(li as u16),
                        backoff,
                    });
                    pause_until = Some(engine.clock.now() + backoff);
                    break;
                }
                Accepted::Failed(e) => {
                    shared.event(Event::ListenerFailed {
                        listener: ListenerId(li as u16),
                        class: OsErrorClass::from_io(&e),
                    });
                    return;
                }
            }
        }
    }
}

impl<W: super::Workload, G: Gate> Engine<W, G> {
    fn refuse(
        &self,
        stream: TcpStream,
        peer: SocketAddr,
        cause: RefusalCause,
        bytes: Option<&[u8]>,
        co: &mut Coalescer,
    ) {
        let shared = &self.shared;
        if let Some(b) = bytes {
            let max = usize::from(self.limits.refusal_bytes_max);
            if b.len() <= max {
                let _ = sys::send(&stream, b);
            }
        }
        let _ = sys::set_linger(stream.sock(), Some(Duration::ZERO));
        drop(stream);
        shared.refused.fetch_add(1, Ordering::Relaxed);
        shared.refused_by[cause.index()].fetch_add(1, Ordering::Relaxed);
        if let Some(sink) = &shared.sink {
            co.emit(
                sink.as_ref(),
                self.clock.now(),
                CoalescedKind::Refused(cause),
                Event::Refused {
                    peer: Some(peer),
                    cause,
                },
            );
        }
    }

    fn admit_one(
        &self,
        stream: TcpStream,
        peer: SocketAddr,
        li: usize,
        ids: &mut IdBlock,
        view: &ControlView,
        co: &mut Coalescer,
    ) {
        let shared = &self.shared;
        let lim = &shared.listener_limits[li];
        let count = &shared.listener_counts[li];
        // Caps before any byte is read.
        if !take_slot(&shared.open, lim.max_connections) {
            return self.refuse(stream, peer, RefusalCause::GlobalCap, None, co);
        }
        if !take_slot(count, lim.max_per_listener) {
            shared.open.fetch_sub(1, Ordering::AcqRel);
            return self.refuse(stream, peer, RefusalCause::ListenerCap, None, co);
        }
        let source = PrefixKey::of(peer.ip(), lim.source_policy);
        if !shared.sources.acquire(source) {
            shared.open.fetch_sub(1, Ordering::AcqRel);
            count.fetch_sub(1, Ordering::AcqRel);
            return self.refuse(stream, peer, RefusalCause::SourceCap, None, co);
        }
        let release = |s: &Self| s.shared.release(li, Some(source));
        if matches!(view.state(), ControlState::Lockdown) {
            release(self);
            return self.refuse(stream, peer, RefusalCause::Lockdown, None, co);
        }
        let local = match stream.local_addr() {
            Ok(a) => a,
            Err(_) => {
                release(self);
                drop(stream);
                return;
            }
        };
        let id = ids.issue();
        let mut info = ConnectionInfo::new_tcp(
            id,
            Some(ListenerId(li as u16)),
            WorkerId(0),
            Origin::Accepted,
            local,
            peer,
            self.clock.now(),
        );
        let admitted = match guarded(|| self.gate.admit(&info, AdmitStage::Accept)) {
            Some(Ok(a)) => a,
            Some(Err(refusal)) => {
                release(self);
                let (code, bytes) = match refusal {
                    Refusal::Reset { code } => (code, None),
                    Refusal::WithBytes { code, bytes } => (code, Some(bytes)),
                    #[allow(unreachable_patterns)]
                    _ => (refusal.code(), None),
                };
                return self.refuse(stream, peer, RefusalCause::Gate(code), bytes, co);
            }
            None => {
                release(self);
                return self.refuse(stream, peer, RefusalCause::Gate(0), None, co);
            }
        };
        info.lane = admitted.lane;
        info.gate = admitted.tag;
        let ticket = admitted.ticket;
        if let ControlState::Shed { from_lane } = view.state() {
            if info.lane >= from_lane {
                let _ = guarded(|| {
                    self.gate
                        .closed(ticket, &info, CloseReason::Refused(RefusalCause::Shed))
                });
                release(self);
                return self.refuse(stream, peer, RefusalCause::Shed, None, co);
            }
        }
        // Hand over; refuse with Busy when every worker has a connection or one waiting.
        // A worker counts as busy from the moment it takes a job (under this lock),
        // so a worker that is starting or between connections counts as free.
        let job = Job {
            stream,
            info,
            ticket,
            listener: li,
            source: Some(source),
        };
        let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        let busy = shared.busy.load(Ordering::Acquire) as usize;
        if queue.len() + busy >= shared.workers.len() {
            drop(queue);
            let Job {
                stream,
                info,
                ticket,
                ..
            } = job;
            let _ = guarded(|| {
                self.gate
                    .closed(ticket, &info, CloseReason::Refused(RefusalCause::Busy))
            });
            release(self);
            return self.refuse(stream, peer, RefusalCause::Busy, None, co);
        }
        let (event_id, event_lane) = (job.info.id, job.info.lane);
        queue.push_back(job);
        shared.queue_len.store(queue.len(), Ordering::Release);
        drop(queue);
        self.queue_cv.notify_one();
        shared.accepted.fetch_add(1, Ordering::Relaxed);
        shared.event(Event::Accepted {
            id: event_id,
            peer: Some(peer),
            listener: ListenerId(li as u16),
        });
        shared.event(Event::Admitted {
            id: event_id,
            lane: event_lane,
        });
    }

    fn next_job(&self) -> Option<Job<G::Ticket>> {
        let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if self.shared.stopping.load(Ordering::Acquire) && queue.is_empty() {
                return None;
            }
            if let Some(job) = queue.pop_front() {
                self.shared.busy.fetch_add(1, Ordering::AcqRel);
                self.shared.queue_len.store(queue.len(), Ordering::Release);
                return Some(job);
            }
            queue = self
                .queue_cv
                .wait(queue)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}

// ---- workers --------------------------------------------------------------

/// What a workload does with one connection. Sealed through `Workload`.
pub trait Serve: Send + Sync + 'static {
    /// Serves one admitted connection on a worker.
    fn serve<G: Gate>(&self, w: &mut Worker<G>, job: Job<G::Ticket>);
}

/// One worker's state, reused across its connections (no allocation after warm-up).
pub struct Worker<G: Gate> {
    shared: Arc<Shared>,
    idx: usize,
    gated: bool,
    gate: Arc<G>,
    gate_cell: Option<Box<GateCell<G>>>,
    pool: BufferPool,
    output: Output,
    input_buf: Option<Buffer>,
    completer: Completer,
    view: ControlView,
    clock: ClockRef,
}

fn worker_loop<W: super::Workload, G: Gate>(engine: &Arc<Engine<W, G>>, idx: usize) {
    let shared = engine.shared.clone();
    let ws = &shared.workers[idx];
    ws.wake.bind_thread(std::thread::current());
    ws.slot.set_wake(Some(ws.wake.clone()));
    let mut w = Worker {
        shared: shared.clone(),
        idx,
        gated: engine.gated,
        gate: engine.gate.clone(),
        gate_cell: Some(Box::new(GateCell {
            gate: engine.gate.clone(),
            ticket: None,
        })),
        pool: BufferPool::new(engine.budget.clone(), engine.wipe),
        output: Output::new(
            engine.budget.clone(),
            engine.limits.output_budget,
            engine.wipe,
        ),
        input_buf: None,
        completer: Completer {
            shared: ws.completer.clone(),
        },
        view: ControlView::new(),
        clock: engine.clock.clone(),
    };
    while let Some(job) = engine.next_job() {
        engine.work.serve(&mut w, job);
    }
}

impl<G: Gate> Worker<G> {
    /// Starts serving a job: options (where not inherited), the kill slot, the gate ticket.
    fn begin(&mut self, job: Job<G::Ticket>) -> Option<(Link, usize, Option<PrefixKey>)> {
        let Job {
            stream,
            mut info,
            ticket,
            listener,
            source,
        } = job;
        let shared = self.shared.clone();
        let limits = shared.listener_limits[listener];
        info.worker = WorkerId(self.idx as u16);
        let mut cell = self.gate_cell.take().unwrap_or_else(|| {
            Box::new(GateCell {
                gate: self.gate.clone(),
                ticket: None,
            })
        });
        cell.ticket = Some(ticket);
        // Where accepted sockets do not inherit the listener's options (macOS), set
        // them now. A peer that already reset makes this fail (macOS: `EINVAL`); the
        // connection then closes through `end` like any other, with one event.
        let mut failed = None;
        if !cfg!(any(target_os = "linux", windows)) {
            let tcp = shared.listener_tcp[listener];
            let v6 = info.local.socket_addr().is_some_and(|a| a.is_ipv6());
            if !tcp.is_empty() {
                if let Err(e) = tcp.apply(&stream, v6) {
                    failed = Some(match e.os_error_code() {
                        Some(code) => CloseReason::Io(OsErrorClass::Other(code)),
                        None => CloseReason::Io(OsErrorClass::Other(0)),
                    });
                }
            }
        }
        let ws = &shared.workers[self.idx];
        ws.kill_cause.store(CAUSE_USER, Ordering::Release);
        ws.idle_cause.store(IDLE_DRAIN, Ordering::Release);
        ws.lane.store(info.lane.0, Ordering::Release);
        let mut link = Link::new(
            stream,
            info,
            limits,
            self.clock.clone(),
            ws.slot.clone(),
            WakeSource::Fixed(ws.wake.clone()),
            Phase::Idle,
        );
        ws.current.store(link.info.id.get(), Ordering::Release);
        if self.gated {
            link.gate = Some(cell as Box<dyn ErasedGate>);
        } else {
            self.gate_cell = Some(cell);
        }
        if let Some(reason) = failed {
            self.end(link, reason, listener, source);
            return None;
        }
        Some((link, listener, source))
    }

    /// Closes the connection with one reason and releases everything it held.
    fn end(
        &mut self,
        link: Link,
        reason: CloseReason,
        listener: usize,
        source: Option<PrefixKey>,
    ) -> (ConnectionInfo, CloseReason) {
        let shared = self.shared.clone();
        let ws = &shared.workers[self.idx];
        let mut link = link;
        let mut reason = reason;
        if let Some(k) = link.killed() {
            reason = match (ws.kill_cause.load(Ordering::Acquire), k == DRAIN_KILL) {
                (CAUSE_DRAIN, true) => CloseReason::DrainDeadline,
                (CAUSE_STOP, true) => CloseReason::Shutdown,
                _ => CloseReason::Killed(k),
            };
        } else if reason == CloseReason::Drained
            && ws.idle_cause.load(Ordering::Acquire) == IDLE_SHED
        {
            reason = CloseReason::Shed;
        } else if shared.draining.load(Ordering::Acquire) && !reason.is_abortive() {
            reason = CloseReason::Drained;
        }
        let info = link.info.clone();
        let (bytes_in, bytes_out) = (link.bytes_in, link.bytes_out);
        let erased = link.gate.take();
        let lifetime = self.clock.now().saturating_duration_since(info.accepted_at);
        let reason = link.finish(reason);
        // Give the gate its ticket back with the reason; keep the cell for the next connection.
        match erased {
            Some(mut g) => {
                g.close(&info, reason);
                if let Ok(cell) = g.into_any().downcast::<GateCell<G>>() {
                    self.gate_cell = Some(cell);
                }
            }
            None => {
                if let Some(cell) = self.gate_cell.as_mut() {
                    cell.close(&info, reason);
                }
            }
        }
        self.output.reset();
        ws.current.store(0, Ordering::Release);
        shared.release(listener, source);
        // Single writer: plain load and store, inside the sequence lock.
        let st = &ws.stats;
        let bump =
            |c: &AtomicU64, n: u64| c.store(c.load(Ordering::Relaxed) + n, Ordering::Relaxed);
        st.begin_write();
        bump(&st.closed, 1);
        bump(&st.bytes_in, bytes_in);
        bump(&st.bytes_out, bytes_out);
        bump(&st.closed_by[reason.index()], 1);
        match reason {
            CloseReason::EgressDenied(_) => bump(&st.egress_denied, 1),
            CloseReason::Killed(_) => bump(&st.killed, 1),
            CloseReason::SlowPeer { .. } => bump(&st.slow_peers, 1),
            CloseReason::Idle
            | CloseReason::ReadTimeout
            | CloseReason::WriteTimeout
            | CloseReason::ExchangeDeadline
            | CloseReason::ParkDeadline
            | CloseReason::HandshakeTimeout => bump(&st.timeouts, 1),
            CloseReason::SessionPanicked => bump(&st.session_panics, 1),
            _ => {}
        }
        st.end_write();
        match reason {
            CloseReason::EgressDenied(code) => {
                shared.event(Event::EgressDenied { id: info.id, code })
            }
            CloseReason::Killed(k) => shared.event(Event::Killed {
                id: info.id,
                reason: k,
            }),
            CloseReason::SessionPanicked => shared.event(Event::SessionPanicked { id: info.id }),
            _ => {}
        }
        if shared.draining.load(Ordering::Acquire) {
            if reason == CloseReason::DrainDeadline {
                shared.drained_killed.fetch_add(1, Ordering::Relaxed);
            } else {
                shared.drained_graceful.fetch_add(1, Ordering::Relaxed);
            }
        }
        shared.event(Event::Closed {
            id: info.id,
            reason,
            bytes_in,
            bytes_out,
            lifetime,
        });
        shared.busy.fetch_sub(1, Ordering::AcqRel);
        shared.notify_progress();
        (info, reason)
    }

    fn draining(&self) -> bool {
        self.shared.draining.load(Ordering::Acquire)
    }

    /// The control line's reaction for a running connection.
    fn control(&mut self) -> Option<CloseReason> {
        if self.shared.stopping.load(Ordering::Acquire) {
            return Some(CloseReason::Shutdown);
        }
        if self.view.refresh(self.shared.control.as_ref()) {
            self.shared.event(Event::ControlReacted {
                state: self.view.state(),
            });
        }
        match self.view.state() {
            ControlState::Stopping => Some(CloseReason::Shutdown),
            _ => None,
        }
    }

    /// Whether the control line sheds `lane`.
    fn shed(&self, lane: Lane) -> bool {
        matches!(self.view.state(), ControlState::Shed { from_lane } if lane >= from_lane)
    }

    fn pressure(&self) -> f32 {
        if matches!(self.view.state(), ControlState::Shed { .. }) {
            return 1.0;
        }
        let busy = self.shared.busy.load(Ordering::Relaxed) as f32;
        let total = self.shared.workers.len().max(1) as f32;
        (busy / total).min(1.0)
    }
}

impl<H> Serve for BlockingHandler<H>
where
    H: Fn(&mut TcpConnection) -> Result<(), NetError> + Send + Sync + 'static,
{
    fn serve<G: Gate>(&self, w: &mut Worker<G>, job: Job<G::Ticket>) {
        let Some((link, listener, source)) = w.begin(job) else {
            return;
        };
        let mut conn = TcpConnection::from_link(link);
        let result = guarded(|| (self.handler)(&mut conn));
        let Some(link) = conn.take_link() else { return };
        drop(conn);
        let reason = match result {
            None => CloseReason::SessionPanicked,
            Some(Ok(())) if link.peer_closed => link.reason_or(CloseReason::PeerClosed),
            Some(Ok(())) => link.reason_or(CloseReason::SessionClosed),
            Some(Err(_)) => link.reason_or(CloseReason::SessionError),
        };
        w.end(link, reason, listener, source);
    }
}

impl<F: SessionFactory> Serve for Sessions<F> {
    fn serve<G: Gate>(&self, w: &mut Worker<G>, job: Job<G::Ticket>) {
        let Some((mut link, listener, source)) = w.begin(job) else {
            return;
        };
        let mut session = match guarded(|| self.factory.open(&link.info)) {
            Some(Ok(s)) => s,
            Some(Err(cause)) => {
                w.end(link, CloseReason::Refused(cause), listener, source);
                return;
            }
            None => {
                w.end(link, CloseReason::SessionPanicked, listener, source);
                return;
            }
        };
        let class = link.limits.read_class;
        let buf = match w.input_buf.take() {
            Some(b) if b.class() == class => Some(b),
            Some(other) => {
                w.pool.put(other);
                w.pool.take(class)
            }
            None => w.pool.take(class),
        };
        let reason = match buf {
            None => CloseReason::Limit(crate::error::LimitKind::BufferBudget),
            Some(buf) => {
                let mut input = Input::new(buf);
                let reason = drive(w, &mut link, &mut session, &mut input);
                // Wipe on release, then keep the buffer for the next connection.
                let mut buf = input.buf;
                buf.set_len(buf.capacity());
                w.pool.put(buf);
                w.input_buf = w.pool.take(class);
                reason
            }
        };
        let (info, reason) = w.end(link, reason, listener, source);
        let _ = guarded(|| session.on_close(&info, reason));
    }
}

/// Calls a session hook with a context; the result is `None` when it panicked.
fn call<G: Gate, S: Session, R>(
    w: &mut Worker<G>,
    link: &mut Link,
    session: &mut S,
    f: impl FnOnce(&mut S, &mut SessionContext<'_>) -> R,
) -> (Option<R>, Option<crate::limits::SizeClass>) {
    let draining = w.draining();
    let pressure = w.pressure();
    let worker = WorkerId(w.idx as u16);
    let mut cx = SessionContext {
        link,
        output: &mut w.output,
        pool: &mut w.pool,
        completer: &w.completer,
        draining,
        pressure,
        worker,
        grow_to: None,
    };
    let r = guarded(|| f(session, &mut cx));
    let grow = cx.grow_to;
    (r, grow)
}

fn drive<G: Gate, S: Session>(
    w: &mut Worker<G>,
    link: &mut Link,
    s: &mut S,
    input: &mut Input,
) -> CloseReason {
    let Some(mut step) = call(w, link, s, |s, cx| s.on_open(cx)).0 else {
        return CloseReason::SessionPanicked;
    };
    loop {
        if let Some(reason) = w.control() {
            return reason;
        }
        match step {
            Step::Read => {
                if input.changed && !input.bytes().is_empty() {
                    input.changed = false;
                    match on_data(w, link, s, input) {
                        Some(next) => step = next,
                        None => return CloseReason::SessionPanicked,
                    }
                    continue;
                }
                input.changed = false;
                link.settle_phase(input.bytes().is_empty());
                let idle = link.phase() == Phase::Idle && input.bytes().is_empty();
                if w.draining() && idle {
                    return CloseReason::Drained;
                }
                if idle && w.shed(link.info.lane) {
                    return CloseReason::Shed;
                }
                if input.is_full() {
                    return CloseReason::Limit(crate::error::LimitKind::ReadBuffer);
                }
                let got = link.read(input.spare_for_read());
                match got {
                    Ok(Got::Data(n)) => {
                        input.filled(n);
                        input.changed = false;
                        match on_data(w, link, s, input) {
                            Some(next) => step = next,
                            None => return CloseReason::SessionPanicked,
                        }
                    }
                    Ok(Got::Eof) => match call(w, link, s, |s, cx| s.on_peer_closed(cx)).0 {
                        Some(next) => step = next,
                        None => return CloseReason::SessionPanicked,
                    },
                    Ok(Got::Woken) => {}
                    Err(NetError::TimedOut { kind }) => match timeout(w, link, s, kind) {
                        Ok(next) => step = next,
                        Err(reason) => return reason,
                    },
                    Err(_) => return link.reason_or(CloseReason::Io(OsErrorClass::Other(0))),
                }
            }
            Step::Write => match flush(w, link, s) {
                Ok(()) => match call(w, link, s, |s, cx| s.on_writable(cx)).0 {
                    Some(next) => step = next,
                    None => return CloseReason::SessionPanicked,
                },
                Err(reason) => return reason,
            },
            Step::Park { until } => match park(w, link, until) {
                Parked::Wake(token, value) => {
                    match call(w, link, s, |s, cx| s.on_wake(cx, token, value)).0 {
                        Some(next) => step = next,
                        None => return CloseReason::SessionPanicked,
                    }
                }
                Parked::Timeout => match timeout(w, link, s, TimeoutKind::Park) {
                    Ok(next) => step = next,
                    Err(reason) => return reason,
                },
                Parked::Closed(reason) => return reason,
            },
            Step::Close => {
                if let Err(reason) = flush(w, link, s) {
                    return reason;
                }
                return if w.draining() {
                    CloseReason::Drained
                } else if link.peer_closed {
                    // Closing after the peer's FIN: the peer ended the connection.
                    CloseReason::PeerClosed
                } else {
                    CloseReason::SessionClosed
                };
            }
            _ => return link.reason_or(CloseReason::SessionError),
        }
    }
}

fn on_data<G: Gate, S: Session>(
    w: &mut Worker<G>,
    link: &mut Link,
    s: &mut S,
    input: &mut Input,
) -> Option<Step> {
    let (step, grow) = call(w, link, s, |s, cx| s.on_data(cx, input));
    if let Some(class) = grow {
        if class > input.buf.class() {
            if let Some(mut bigger) = w.pool.take(class) {
                let bytes = input.bytes();
                bigger.spare()[..bytes.len()].copy_from_slice(bytes);
                bigger.set_len(bytes.len());
                let old = std::mem::replace(&mut input.buf, bigger);
                input.start = 0;
                w.pool.put(old);
            }
        }
    }
    step
}

fn timeout<G: Gate, S: Session>(
    w: &mut Worker<G>,
    link: &mut Link,
    s: &mut S,
    kind: TimeoutKind,
) -> Result<Step, CloseReason> {
    match call(w, link, s, |s, cx| s.on_timeout(cx, kind)).0 {
        None => Err(CloseReason::SessionPanicked),
        Some(Step::Close | Step::Abort) => Err(CloseReason::for_timeout(kind)),
        Some(next) => {
            link.rearm();
            Ok(next)
        }
    }
}

/// Sends everything pending, with the gate check before every system call.
fn flush<G: Gate, S: Session>(
    w: &mut Worker<G>,
    link: &mut Link,
    s: &mut S,
) -> Result<(), CloseReason> {
    while !w.output.is_empty() {
        link.response_started = if w.output.response_open {
            w.output.bytes_since_begin > 0
        } else {
            link.bytes_out > 0
        };
        link.response_tag = w.output.response_tag;
        let result = {
            let mut slices = [IoSlice::new(&[]); 64];
            let mut k = 0;
            for chunk in w.output.chunks.iter().take(slices.len()) {
                slices[k] = IoSlice::new(chunk.remaining());
                k += 1;
            }
            link.write_vectored(&slices[..k])
        };
        match result {
            Ok(n) => {
                w.output.advance(n);
                w.output.bytes_since_begin += n as u64;
            }
            Err(NetError::EgressDenied { code }) => {
                let started = link.response_started;
                w.output.wipe_all();
                if !started {
                    let out = &mut w.output;
                    if guarded(|| s.on_denied(code, out)).is_some() {
                        // One bounded attempt, not checked again (it is the denial).
                        let mut budget = usize::from(link.limits.refusal_bytes_max);
                        for chunk in &w.output.chunks {
                            let bytes = chunk.remaining();
                            let take = bytes.len().min(budget);
                            if take == 0 {
                                break;
                            }
                            link.send_denial_once(&bytes[..take]);
                            budget -= take;
                        }
                    }
                    w.output.wipe_all();
                }
                return Err(CloseReason::EgressDenied(code));
            }
            Err(_) => return Err(link.reason_or(CloseReason::Io(OsErrorClass::Other(0)))),
        }
    }
    link.output_done();
    Ok(())
}

enum Parked {
    Wake(u32, u64),
    Timeout,
    Closed(CloseReason),
}

/// No reads, no idle timer: waits for a completion, a kill, a stop, or the deadline.
fn park<G: Gate>(w: &mut Worker<G>, link: &mut Link, until: Option<Instant>) -> Parked {
    let deadline = until.unwrap_or_else(|| link.now() + link.limits.park_timeout);
    let shared = w.shared.clone();
    let ws = &shared.workers[w.idx];
    loop {
        ws.completer.wake_pending.store(false, Ordering::Release);
        while let Some(p) = ws.completer.ring.pop() {
            if p.connection == link.info.id {
                return Parked::Wake(p.token, p.value);
            }
            ws.stats.begin_write();
            ws.stats.stale_completions.fetch_add(1, Ordering::Relaxed);
            ws.stats.end_write();
            shared.event(Event::StaleCompletion {
                worker: WorkerId(w.idx as u16),
            });
        }
        if let Some(k) = link.killed() {
            return Parked::Closed(CloseReason::Killed(k));
        }
        if let Some(reason) = w.control() {
            return Parked::Closed(reason);
        }
        let now = link.now();
        if now >= deadline {
            return Parked::Timeout;
        }
        std::thread::park_timeout(deadline - now);
    }
}
