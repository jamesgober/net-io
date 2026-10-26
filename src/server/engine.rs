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
use std::thread::JoinHandle;
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
use crate::handoff::ListenerHandle;
use crate::id::{ConnectionId, IdBlock, ListenerId, WorkerId};
#[cfg(all(unix, feature = "local"))]
use crate::info::Endpoint;
use crate::info::{ConnectionInfo, Lane, Origin, Transport};
#[cfg(any(feature = "proxy", feature = "tls"))]
use crate::limits::SizeClass;
use crate::limits::{Effective, Limits};
use crate::link::{ClockRef, Got, Link, WakeSource};
#[cfg(all(unix, feature = "local"))]
use crate::local::UnixListener;
use crate::opts::{ListenOptions, TcpOptions};
use crate::proxy::{ProxyFacts, ProxyMode, ProxyVersions};
use crate::session::{Input, Output, Phase, Session, SessionContext, SessionFactory, Step};
use crate::sys::{self, AsSock, Interest, KillSlot, Wake};
use crate::tcp::{ListenerInfo, TcpConnection, TcpListener};
use crate::time::Clock;
use crate::tls::ErasedAcceptor;
use crate::trusted::TrustedProxies;

const WORKER_STACK: usize = 256 * 1024;
const DRAIN_KILL: KillReason = KillReason(0);

/// `WorkerShared::kill_cause`: a user's kill, the drain deadline, or `Stopping`.
const CAUSE_USER: u8 = 0;
const CAUSE_DRAIN: u8 = 1;
const CAUSE_STOP: u8 = 2;

/// `WorkerShared::idle_cause`: an idle connection closed by a drain or by shedding.
const IDLE_DRAIN: u8 = 0;
const IDLE_SHED: u8 = 1;

/// `WorkerShared::listener` when the worker has no connection.
const NO_LISTENER: u32 = u32::MAX;

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
    pub tls: Option<Arc<dyn ErasedAcceptor>>,
    pub trusted: Option<Arc<TrustedProxies>>,
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
    /// The current connection's listener id (`NO_LISTENER` when none), for
    /// `remove_listener`'s drain.
    listener: AtomicU32,
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
    /// The listeners and their accept threads (D-097). Locked only on cold paths
    /// (doors, wake-ups, adding, removing, releasing, shutdown).
    listeners: Mutex<Vec<ListenerEntry>>,
    /// The next listener id; ids are never reused.
    next_listener: AtomicU32,
    /// Starts an accept thread for a listener (holds the engine weakly).
    spawn_accept: OnceLock<SpawnAccept>,
    /// Admits an adopted connection (holds the engine weakly).
    adopt: OnceLock<AdoptFn>,
    /// The server's limits, for listeners added later.
    pub(crate) base_limits: Limits,
    /// The server's trusted proxies, for listeners added later.
    pub(crate) trusted: Option<Arc<TrustedProxies>>,
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
    /// The TLS engine, when any listener serves TLS.
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    pub(crate) tls: Option<Arc<dyn ErasedAcceptor>>,
}

/// Admits an adopted connection on a listener.
type AdoptFn = Box<
    dyn Fn(
            TcpStream,
            SocketAddr,
            SocketAddr,
            &Arc<ListenerConf>,
            Option<Lane>,
        ) -> Result<ConnectionId, NetError>
        + Send
        + Sync,
>;

/// Starts the accept thread of one listener.
type SpawnAccept = Box<
    dyn Fn(Arc<ListenerConf>, Arc<ListenerRuntime>) -> std::io::Result<JoinHandle<()>>
        + Send
        + Sync,
>;

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
        let opened = !self.door.swap(true, Ordering::AcqRel);
        // Every listener's door opens, including listeners added since the last call.
        for e in self.lock_listeners().iter() {
            if !e.conf.door.swap(true, Ordering::AcqRel) {
                e.conf.wake.wake();
            }
        }
        if opened {
            self.event(Event::DoorOpened);
        }
        Ok(())
    }

    pub(crate) fn close_door(&self) {
        let closed = self.door.swap(false, Ordering::AcqRel);
        for e in self.lock_listeners().iter() {
            if e.conf.door.swap(false, Ordering::AcqRel) {
                e.conf.wake.wake();
            }
        }
        if closed {
            self.event(Event::DoorClosed);
        }
    }

    fn lock_listeners(&self) -> std::sync::MutexGuard<'_, Vec<ListenerEntry>> {
        self.listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Starts the accept thread of every listener that has none.
    fn spawn_listener_threads(&self) -> std::io::Result<()> {
        let Some(spawn) = self.spawn_accept.get() else {
            return Ok(());
        };
        for e in self.lock_listeners().iter_mut() {
            if e.thread.is_none() {
                e.thread = Some(spawn(e.conf.clone(), e.runtime.clone())?);
            }
        }
        Ok(())
    }

    /// Ends every accept thread, joins it, and closes the listening sockets.
    pub(crate) fn join_listeners(&self) {
        let entries = std::mem::take(&mut *self.lock_listeners());
        for e in &entries {
            e.conf.removed.store(true, Ordering::Release);
            e.conf.wake.wake();
        }
        for mut e in entries {
            if let Some(t) = e.thread.take() {
                let _ = t.join();
            }
        }
    }

    /// `Server::adopt`: finds the listener by name and admits the connection.
    pub(crate) fn adopt(
        &self,
        stream: TcpStream,
        peer: SocketAddr,
        local: SocketAddr,
        listener: &str,
        lane: Option<Lane>,
    ) -> Result<ConnectionId, NetError> {
        let conf = self
            .lock_listeners()
            .iter()
            .find(|e| e.runtime.info().name.as_deref() == Some(listener))
            .map(|e| e.conf.clone())
            .ok_or(NetError::InvalidConfig {
                field: "listener",
                reason: crate::error::ConfigReason::Missing,
            })?;
        match self.adopt.get() {
            Some(f) => f(stream, peer, local, &conf, lane),
            None => Err(NetError::ShuttingDown),
        }
    }

    pub(crate) fn release_listeners(&self) -> Result<Vec<ListenerHandle>, NetError> {
        if self.forked() {
            return Err(NetError::ForkedChild);
        }
        let list = self.lock_listeners();
        let mut out = Vec::with_capacity(list.len());
        for e in list.iter() {
            let info = e.runtime.info();
            let sock = e
                .runtime
                .duplicate()
                .map_err(|err| NetError::from_os("dup", err))?;
            out.push(ListenerHandle::new(
                info.transport,
                info.name.clone(),
                info.local.clone(),
                sock,
            ));
        }
        Ok(out)
    }

    /// Binds a listener for a running server and starts its accept thread; its
    /// door stays closed until the next `open_door`.
    pub(crate) fn add_listener(&self, spec: ListenerSpec) -> Result<ListenerInfo, NetError> {
        if self.forked() {
            return Err(NetError::ForkedChild);
        }
        if self.draining.load(Ordering::Acquire) || self.stopping.load(Ordering::Acquire) {
            return Err(NetError::ShuttingDown);
        }
        let n = self.next_listener.fetch_add(1, Ordering::AcqRel);
        let id = ListenerId(u16::try_from(n).map_err(|_| NetError::InvalidConfig {
            field: "listener",
            reason: crate::error::ConfigReason::TooLarge {
                max: u64::from(u16::MAX),
            },
        })?);
        let (mut entry, info) = bind_listener(spec, id, &self.base_limits)?;
        let Some(spawn) = self.spawn_accept.get() else {
            return Err(NetError::ShuttingDown);
        };
        entry.thread = Some(
            spawn(entry.conf.clone(), entry.runtime.clone()).map_err(|e| {
                NetError::DriverSetup {
                    driver: DriverKind::Blocking,
                    source: e,
                }
            })?,
        );
        self.lock_listeners().push(entry);
        self.event(Event::ListenerOpened {
            listener: id,
            local: info.local.socket_addr(),
            backlog: info.backlog,
        });
        Ok(info)
    }

    /// Closes one listener (its socket at once) and drains its connections:
    /// idle ones close now, the rest finish until `deadline` and are then killed.
    pub(crate) fn remove_listener(
        &self,
        id: ListenerId,
        deadline: Instant,
    ) -> Result<DrainReport, NetError> {
        if self.forked() {
            return Err(NetError::ForkedChild);
        }
        let entry = {
            let mut list = self.lock_listeners();
            let Some(i) = list.iter().position(|e| e.conf.id == id) else {
                return Err(NetError::InvalidConfig {
                    field: "listener",
                    reason: crate::error::ConfigReason::Missing,
                });
            };
            list.remove(i)
        };
        let ListenerEntry {
            conf,
            runtime,
            thread,
        } = entry;
        conf.door.store(false, Ordering::Release);
        conf.removed.store(true, Ordering::Release);
        conf.wake.wake();
        if let Some(t) = thread {
            let _ = t.join();
        }
        drop(runtime);
        self.event(Event::ListenerClosed { listener: id });
        Ok(self.drain_listener(&conf, deadline))
    }

    /// The drain of one listener's connections (see `remove_listener`).
    fn drain_listener(&self, conf: &ListenerConf, deadline: Instant) -> DrainReport {
        let start = Instant::now();
        let id = u32::from(conf.id.0);
        let initial = conf.count.load(Ordering::Acquire);
        let mut killed = 0u32;
        let mut killed_at_deadline = false;
        let mut guard = self.progress.lock().unwrap_or_else(PoisonError::into_inner);
        while conf.count.load(Ordering::Acquire) > 0 {
            let mine = |w: &&WorkerShared| {
                w.listener.load(Ordering::Acquire) == id && w.current.load(Ordering::Acquire) != 0
            };
            for w in self.workers.iter().filter(mine) {
                if !w.slot.drained() {
                    w.idle_cause.store(IDLE_DRAIN, Ordering::Release);
                    w.slot.drain_idle(w.slot.generation());
                }
            }
            let now = Instant::now();
            if now >= deadline && !killed_at_deadline {
                killed_at_deadline = true;
                for w in self.workers.iter().filter(mine) {
                    let claimed = w
                        .kill_cause
                        .compare_exchange(
                            CAUSE_USER,
                            CAUSE_DRAIN,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok();
                    if w.slot.kill(w.slot.generation(), DRAIN_KILL) {
                        killed += 1;
                    } else if claimed {
                        w.kill_cause.store(CAUSE_USER, Ordering::Release);
                    }
                }
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
        DrainReport {
            graceful: initial.saturating_sub(killed),
            killed,
            took: start.elapsed(),
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

    pub(crate) fn worker_count(&self) -> usize {
        self.workers.len()
    }

    pub(crate) fn wake_all(&self) {
        for e in self.lock_listeners().iter() {
            e.conf.wake.wake();
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

    fn release(&self, listener: &ListenerConf, source: Option<PrefixKey>) {
        self.open.fetch_sub(1, Ordering::AcqRel);
        listener.count.fetch_sub(1, Ordering::AcqRel);
        if let Some(k) = source {
            listener.sources.release(k);
        }
    }
}

/// A listener's PROXY requirement and whom it trusts.
#[derive(Clone)]
#[cfg_attr(not(feature = "proxy"), allow(dead_code))]
pub(crate) struct ListenerProxy {
    versions: ProxyVersions,
    /// `None` on a Unix socket listener: every peer that can connect is trusted.
    trusted: Option<Arc<TrustedProxies>>,
}

/// One listener's settings and counters (D-097). Its accept thread and every
/// connection it admitted hold it, so a removed listener's connections keep
/// their limits and give their cap slots back where they took them.
pub(crate) struct ListenerConf {
    id: ListenerId,
    limits: Effective,
    tcp: TcpOptions,
    /// `Some` when the listener requires a PROXY header.
    #[cfg_attr(not(feature = "proxy"), allow(dead_code))]
    proxy: Option<ListenerProxy>,
    /// Whether the listener serves TLS.
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    tls: bool,
    /// Connections admitted and not yet closed (the per-listener cap).
    count: AtomicU32,
    /// The per-source cap's table, sized from this listener's limits (D-085).
    sources: SourceTable,
    /// This listener's door: `open_door` and `close_door` set every one.
    door: AtomicBool,
    /// Set by `remove_listener` and at shutdown: the accept thread ends and
    /// queued connections close with `Drained`.
    removed: AtomicBool,
    wake: Arc<Wake>,
}

/// A listener the server owns: settings, socket, accept thread.
struct ListenerEntry {
    conf: Arc<ListenerConf>,
    runtime: Arc<ListenerRuntime>,
    thread: Option<JoinHandle<()>>,
}

/// Binds (or adopts) the socket of `spec` and builds its settings.
fn bind_listener(
    spec: ListenerSpec,
    id: ListenerId,
    base: &Limits,
) -> Result<(ListenerEntry, ListenerInfo), NetError> {
    let lim = base.overlay(&spec.limits).effective(DriverKind::Blocking);
    let proxy = match spec.proxy {
        ProxyMode::Required { versions } => Some(ListenerProxy {
            versions,
            trusted: spec.trusted.clone(),
        }),
        _ => None,
    };
    let (runtime, info, tcp) = 'bound: {
        if let Some(handle) = spec.adopt {
            let name = spec.name.clone();
            match handle.kind() {
                Transport::Tcp => {
                    let std = std::net::TcpListener::from(handle.into_sock());
                    let mut listener = TcpListener::from_std(std)?;
                    listener.set_identity(id, name);
                    listener.set_proxy_mode(spec.proxy);
                    listener.set_tls(spec.tls);
                    let info = listener.info().clone();
                    let tcp = *listener.tcp_options();
                    break 'bound (ListenerRuntime::Tcp(listener), info, tcp);
                }
                #[cfg(all(unix, feature = "local"))]
                Transport::Unix => {
                    let mut listener = UnixListener::adopt(handle.into_sock())?;
                    listener.set_identity(id, name);
                    listener.set_proxy_mode(spec.proxy);
                    listener.set_tls(spec.tls);
                    let info = listener.info().clone();
                    break 'bound (ListenerRuntime::Unix(listener), info, TcpOptions::default());
                }
                _ => {
                    return Err(NetError::InvalidConfig {
                        field: "socket",
                        reason: crate::error::ConfigReason::NotListening,
                    });
                }
            }
        }
        #[cfg(all(unix, feature = "local"))]
        if let Some((path, options)) = spec.unix {
            let mut listener = UnixListener::bind_with(&path, options)?;
            listener.set_identity(id, spec.name.clone());
            listener.set_proxy_mode(spec.proxy);
            listener.set_tls(spec.tls);
            let info = listener.info().clone();
            break 'bound (ListenerRuntime::Unix(listener), info, TcpOptions::default());
        }
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
        let mut listener = bound.ok_or(last)?;
        listener.set_proxy_mode(spec.proxy);
        listener.set_tls(spec.tls);
        let info = listener.info().clone();
        let tcp = *listener.tcp_options();
        (ListenerRuntime::Tcp(listener), info, tcp)
    };
    let wake = Wake::new()
        .map(Arc::new)
        .map_err(|e| NetError::DriverSetup {
            driver: DriverKind::Blocking,
            source: e,
        })?;
    let conf = Arc::new(ListenerConf {
        id,
        limits: lim,
        tcp,
        proxy,
        tls: spec.tls,
        count: AtomicU32::new(0),
        sources: SourceTable::new(lim.max_per_listener, lim.max_per_source),
        door: AtomicBool::new(false),
        removed: AtomicBool::new(false),
        wake,
    });
    Ok((
        ListenerEntry {
            conf,
            runtime: Arc::new(runtime),
            thread: None,
        },
        info,
    ))
}

/// An accepted, admitted connection waiting for a worker.
pub struct Job<T> {
    stream: sys::Stream,
    info: ConnectionInfo,
    ticket: T,
    listener: Arc<ListenerConf>,
    source: Option<PrefixKey>,
}

enum ListenerRuntime {
    Tcp(TcpListener),
    #[cfg(all(unix, feature = "local"))]
    Unix(UnixListener),
}

impl ListenerRuntime {
    fn sock(&self) -> sys::Sock<'_> {
        match self {
            ListenerRuntime::Tcp(l) => l.std().sock(),
            #[cfg(all(unix, feature = "local"))]
            ListenerRuntime::Unix(l) => std::os::fd::AsFd::as_fd(l.std()),
        }
    }

    fn info(&self) -> &ListenerInfo {
        match self {
            ListenerRuntime::Tcp(l) => l.info(),
            #[cfg(all(unix, feature = "local"))]
            ListenerRuntime::Unix(l) => l.info(),
        }
    }

    /// An owned duplicate of the socket (close-on-exec), for a hand-off.
    fn duplicate(&self) -> std::io::Result<sys::OwnedSock> {
        match self {
            ListenerRuntime::Tcp(l) => l.std().try_clone().map(sys::OwnedSock::from),
            #[cfg(all(unix, feature = "local"))]
            ListenerRuntime::Unix(l) => {
                let dup = l.std().try_clone().map(sys::OwnedSock::from)?;
                // The next process serves this path now: never remove its file.
                l.keep_file();
                Ok(dup)
            }
        }
    }
}

struct Engine<W, G: Gate> {
    shared: Arc<Shared>,
    work: W,
    gate: Arc<G>,
    gated: bool,
    queue: Mutex<VecDeque<Job<G::Ticket>>>,
    queue_cv: Condvar,
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
    let mut entries = Vec::with_capacity(cfg.listeners.len());
    let mut infos = Vec::with_capacity(cfg.listeners.len());
    for (i, spec) in cfg.listeners.into_iter().enumerate() {
        let id = ListenerId(u16::try_from(i).unwrap_or(u16::MAX));
        let (entry, info) = bind_listener(spec, id, &cfg.limits)?;
        entries.push(entry);
        infos.push(info);
    }

    let sink: Option<Arc<dyn EventSink>> = if TypeId::of::<S>() == TypeId::of::<NoopSink>() {
        None
    } else {
        Some(Arc::new(cfg.sink))
    };
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
    let next_listener = u32::try_from(infos.len()).unwrap_or(u32::MAX);
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
                listener: AtomicU32::new(NO_LISTENER),
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
        listeners: Mutex::new(entries),
        next_listener: AtomicU32::new(next_listener),
        spawn_accept: OnceLock::new(),
        adopt: OnceLock::new(),
        base_limits: cfg.limits.clone(),
        trusted: cfg.trusted.clone(),
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
        tls: cfg.tls,
    });
    for info in &infos {
        shared.event(Event::ListenerOpened {
            listener: info.id,
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
    let weak = Arc::downgrade(&engine);
    let _ = shared.adopt.set(Box::new(
        move |stream, peer, local, conf, lane| match weak.upgrade() {
            Some(e) => e.adopt(stream, peer, local, conf, lane),
            None => Err(NetError::ShuttingDown),
        },
    ));
    let weak = Arc::downgrade(&engine);
    let _ = shared.spawn_accept.set(Box::new(move |conf, rt| {
        let Some(e) = weak.upgrade() else {
            return Err(std::io::Error::other("the server stopped"));
        };
        std::thread::Builder::new()
            .name(format!("net-io-accept-{}", conf.id.0))
            .spawn(move || accept_loop(&e, &conf, &rt))
    }));

    let mut threads = Vec::with_capacity(usize::from(cfg.workers));
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
        if let Err(err) = shared.spawn_listener_threads() {
            failure = Some(spawn_error(err));
        }
    }
    drop(engine);
    if let Some(err) = failure {
        shared.stop_threads();
        for t in threads {
            let _ = t.join();
        }
        shared.join_listeners();
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

fn accept_loop<W: super::Workload, G: Gate>(
    engine: &Arc<Engine<W, G>>,
    conf: &Arc<ListenerConf>,
    rt: &ListenerRuntime,
) {
    let shared = &engine.shared;
    let wake = conf.wake.clone();
    let batch = conf.limits.accept_batch;
    let mut acceptor = Acceptor::new();
    let mut ids = IdBlock::new();
    let mut view = ControlView::new();
    let mut coalescer = Coalescer::new();
    let mut pause_until: Option<Instant> = None;
    loop {
        if shared.stopping.load(Ordering::Acquire) || conf.removed.load(Ordering::Acquire) {
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
        let accepting = shared.door.load(Ordering::Acquire)
            && conf.door.load(Ordering::Acquire)
            && !shared.draining.load(Ordering::Acquire);
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
            let outcome = match rt {
                ListenerRuntime::Tcp(l) => match acceptor.accept(l.std()) {
                    Accepted::Conn((stream, peer)) => {
                        engine.admit_tcp(stream, peer, conf, &mut ids, &view, &mut coalescer);
                        continue;
                    }
                    other => other.without_conn(),
                },
                #[cfg(all(unix, feature = "local"))]
                ListenerRuntime::Unix(l) => match acceptor.accept_unix(l.std()) {
                    Accepted::Conn(stream) => {
                        engine.admit_unix(l, stream, conf, &mut ids, &view, &mut coalescer);
                        continue;
                    }
                    other => other.without_conn(),
                },
            };
            match outcome {
                Accepted::Conn(()) => {}
                Accepted::Skipped(class) => shared.event(Event::AcceptError {
                    listener: conf.id,
                    class,
                }),
                Accepted::Again => {
                    let _ = sys::wait(rt.sock(), Interest::Read, Some(&wake), None);
                    break;
                }
                Accepted::Pause(backoff) => {
                    shared.descriptor_pressure.fetch_add(1, Ordering::Relaxed);
                    shared.event(Event::DescriptorPressure {
                        listener: conf.id,
                        backoff,
                    });
                    pause_until = Some(engine.clock.now() + backoff);
                    break;
                }
                Accepted::Failed(e) => {
                    shared.event(Event::ListenerFailed {
                        listener: conf.id,
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
        stream: sys::Stream,
        peer: Option<SocketAddr>,
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
                Event::Refused { peer, cause },
            );
        }
    }

    fn admit_tcp(
        &self,
        stream: TcpStream,
        peer: SocketAddr,
        conf: &Arc<ListenerConf>,
        ids: &mut IdBlock,
        view: &ControlView,
        co: &mut Coalescer,
    ) {
        let source = PrefixKey::of(peer.ip(), conf.limits.source_policy);
        let id = conf.id;
        let _ = self.admit_one(
            sys::Stream::Tcp(stream),
            Some(peer),
            Some(source),
            conf,
            &mut || ids.issue(),
            view,
            co,
            AdmitStage::Accept,
            |stream, cid, at| {
                let local = stream.tcp()?.local_addr().ok()?;
                Some(ConnectionInfo::new_tcp(
                    cid,
                    Some(id),
                    WorkerId(0),
                    Origin::Accepted,
                    local,
                    peer,
                    at,
                ))
            },
        );
    }

    /// A Unix socket connection: credentials read once, `require_uid` before
    /// anything else, and no per-source cap (there is no source address).
    #[cfg(all(unix, feature = "local"))]
    fn admit_unix(
        &self,
        listener: &UnixListener,
        stream: std::os::unix::net::UnixStream,
        conf: &Arc<ListenerConf>,
        ids: &mut IdBlock,
        view: &ControlView,
        co: &mut Coalescer,
    ) {
        let credentials = crate::local::credentials_of(&stream);
        let stream = sys::Stream::Unix(stream);
        if !listener.permits(credentials) {
            return self.refuse(stream, None, RefusalCause::Credentials, None, co);
        }
        let path = listener.shared_path().clone();
        let id = conf.id;
        let next = &mut || ids.issue();
        let stage = AdmitStage::Accept;
        let _ = self.admit_one(
            stream,
            None,
            None,
            conf,
            next,
            view,
            co,
            stage,
            |_, cid, at| {
                Some(ConnectionInfo::new_unix(
                    cid,
                    Some(id),
                    Origin::Accepted,
                    Endpoint::Unix(path),
                    Endpoint::Unnamed,
                    credentials,
                    at,
                ))
            },
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn admit_one(
        &self,
        stream: sys::Stream,
        peer: Option<SocketAddr>,
        source: Option<PrefixKey>,
        conf: &Arc<ListenerConf>,
        next_id: &mut dyn FnMut() -> ConnectionId,
        view: &ControlView,
        co: &mut Coalescer,
        stage: AdmitStage,
        make_info: impl FnOnce(&sys::Stream, ConnectionId, Instant) -> Option<ConnectionInfo>,
    ) -> Result<ConnectionId, Option<RefusalCause>> {
        let shared = &self.shared;
        let lim = &conf.limits;
        let count = &conf.count;
        // Caps before any byte is read.
        if !take_slot(&shared.open, lim.max_connections) {
            {
                self.refuse(stream, peer, RefusalCause::GlobalCap, None, co);
                return Err(Some(RefusalCause::GlobalCap));
            }
        }
        if !take_slot(count, lim.max_per_listener) {
            shared.open.fetch_sub(1, Ordering::AcqRel);
            {
                self.refuse(stream, peer, RefusalCause::ListenerCap, None, co);
                return Err(Some(RefusalCause::ListenerCap));
            }
        }
        if let Some(source) = source {
            if !conf.sources.acquire(source) {
                shared.open.fetch_sub(1, Ordering::AcqRel);
                count.fetch_sub(1, Ordering::AcqRel);
                {
                    self.refuse(stream, peer, RefusalCause::SourceCap, None, co);
                    return Err(Some(RefusalCause::SourceCap));
                }
            }
        }
        let release = |s: &Self| s.shared.release(conf, source);
        if matches!(view.state(), ControlState::Lockdown) {
            release(self);
            {
                self.refuse(stream, peer, RefusalCause::Lockdown, None, co);
                return Err(Some(RefusalCause::Lockdown));
            }
        }
        let id = next_id();
        let Some(mut info) = make_info(&stream, id, self.clock.now()) else {
            release(self);
            drop(stream);
            return Err(None);
        };
        let admitted = match guarded(|| self.gate.admit(&info, stage)) {
            Some(Ok(a)) => a,
            Some(Err(refusal)) => {
                release(self);
                let (code, bytes) = match refusal {
                    Refusal::Reset { code } => (code, None),
                    Refusal::WithBytes { code, bytes } => (code, Some(bytes)),
                    #[allow(unreachable_patterns)]
                    _ => (refusal.code(), None),
                };
                {
                    self.refuse(stream, peer, RefusalCause::Gate(code), bytes, co);
                    return Err(Some(RefusalCause::Gate(code)));
                }
            }
            None => {
                release(self);
                {
                    self.refuse(stream, peer, RefusalCause::Gate(0), None, co);
                    return Err(Some(RefusalCause::Gate(0)));
                }
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
                {
                    self.refuse(stream, peer, RefusalCause::Shed, None, co);
                    return Err(Some(RefusalCause::Shed));
                }
            }
        }
        // Hand over; refuse with Busy when every worker has a connection or one waiting.
        // A worker counts as busy from the moment it takes a job (under this lock),
        // so a worker that is starting or between connections counts as free.
        let job = Job {
            stream,
            info,
            ticket,
            listener: conf.clone(),
            source,
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
            {
                self.refuse(stream, peer, RefusalCause::Busy, None, co);
                return Err(Some(RefusalCause::Busy));
            }
        }
        let (event_id, event_lane) = (job.info.id, job.info.lane);
        queue.push_back(job);
        shared.queue_len.store(queue.len(), Ordering::Release);
        drop(queue);
        self.queue_cv.notify_one();
        shared.accepted.fetch_add(1, Ordering::Relaxed);
        shared.event(Event::Accepted {
            id: event_id,
            peer,
            listener: conf.id,
        });
        shared.event(Event::Admitted {
            id: event_id,
            lane: event_lane,
        });
        Ok(event_id)
    }

    /// `Server::adopt`: a dialed connection admitted like an accepted one on
    /// `conf`'s listener (`AdmitStage::Adopt`).
    fn adopt(
        &self,
        stream: TcpStream,
        peer: SocketAddr,
        local: SocketAddr,
        conf: &Arc<ListenerConf>,
        lane: Option<Lane>,
    ) -> Result<ConnectionId, NetError> {
        let shared = &self.shared;
        if shared.forked() {
            return Err(NetError::ForkedChild);
        }
        if shared.draining.load(Ordering::Acquire) || shared.stopping.load(Ordering::Acquire) {
            return Err(NetError::ShuttingDown);
        }
        let mut view = ControlView::new();
        view.refresh(shared.control.as_ref());
        let mut co = Coalescer::new();
        let peer = crate::addr::normalize_socket(peer);
        let source = PrefixKey::of(peer.ip(), conf.limits.source_policy);
        let listener = conf.id;
        let result = self.admit_one(
            sys::Stream::Tcp(stream),
            Some(peer),
            Some(source),
            conf,
            &mut crate::id::issue_single,
            &view,
            &mut co,
            AdmitStage::Adopt,
            |_, cid, at| {
                let mut info = ConnectionInfo::new_tcp(
                    cid,
                    Some(listener),
                    WorkerId(0),
                    Origin::Adopted,
                    local,
                    peer,
                    at,
                );
                if let Some(l) = lane {
                    info.lane = l;
                }
                Some(info)
            },
        );
        match result {
            Ok(id) => Ok(id),
            Err(Some(cause)) => Err(NetError::Refused { cause }),
            Err(None) => Err(NetError::Closed),
        }
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
    /// Recycled PROXY facts (D-061): reused when no one else holds them.
    facts_pool: Vec<Arc<ProxyFacts>>,
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
        facts_pool: Vec::new(),
    };
    while let Some(job) = engine.next_job() {
        engine.work.serve(&mut w, job);
    }
}

impl<G: Gate> Worker<G> {
    /// Returns a closed connection's PROXY facts to the pool when nothing else
    /// holds them.
    fn recycle(&mut self, info: ConnectionInfo) {
        if let Some(mut facts) = info.proxy {
            if Arc::get_mut(&mut facts).is_some() && self.facts_pool.len() < 4 {
                self.facts_pool.push(facts);
            }
        }
    }

    /// Starts TLS on the connection (`ListenerSpec::tls`): the engine's session,
    /// a read buffer of the largest read class and a write buffer, then the
    /// handshake under the handshake deadline.
    #[cfg(feature = "tls")]
    fn tls_handshake(&mut self, link: &mut Link) -> Result<(), CloseReason> {
        let Some(acceptor) = self.shared.tls.clone() else {
            return Err(CloseReason::TlsFailed);
        };
        let session = match acceptor.session_boxed(&link.info) {
            Ok(s) => s,
            Err(e) if e.kind == crate::tls::TlsFailure::HelloRefused => {
                return Err(CloseReason::HelloRefused);
            }
            Err(_) => return Err(CloseReason::TlsFailed),
        };
        let lim = link.limits;
        let Some(cin) = self.pool.take(lim.read_class_max) else {
            return Err(CloseReason::Limit(crate::error::LimitKind::BufferBudget));
        };
        let Some(cout) = self.pool.take(SizeClass::LARGE) else {
            self.pool.put(cin);
            return Err(CloseReason::Limit(crate::error::LimitKind::BufferBudget));
        };
        link.attach_tls(session, cin, cout);
        link.begin_handshake(link.info.accepted_at + lim.handshake_timeout);
        let r = link.tls_handshake();
        link.end_handshake(None);
        match r {
            Ok(()) => Ok(()),
            Err(_) => Err(link.reason_or(CloseReason::TlsFailed)),
        }
    }

    /// Reads and checks the PROXY header (`ListenerSpec::proxy`): trust before any
    /// read, the header under the handshake deadline, then the real client takes
    /// over the per-source slot and the gate readmits it. Bytes after the header
    /// stay input for the protocol.
    #[cfg(feature = "proxy")]
    fn proxy_handshake(
        &mut self,
        link: &mut Link,
        proxy: &ListenerProxy,
        listener: &ListenerConf,
        source: &mut Option<PrefixKey>,
    ) -> Result<(), CloseReason> {
        use crate::proxy_parse::{ProxyAddress, ProxyCommand, ProxyParser, ProxyProgress};
        // A TCP peer must be a trusted proxy; on a Unix socket listener the file's
        // permissions already decided who may connect (`trusted` is `None`).
        let trusted = match (&proxy.trusted, link.info.peer.socket_addr()) {
            (Some(list), Some(peer)) => list.contains(peer.ip()),
            (None, None) => link.info.transport == Transport::Unix,
            _ => false,
        };
        if !trusted {
            return Err(CloseReason::ProxyUntrusted);
        }
        let lim = link.limits;
        // The header must fit the buffer: at most 16 fixed bytes plus the body limit.
        let need = 16 + u32::from(lim.proxy_header_max);
        let class = if need <= SizeClass::SMALL.bytes() {
            SizeClass::SMALL
        } else if need <= SizeClass::MEDIUM.bytes() {
            SizeClass::MEDIUM
        } else {
            SizeClass::LARGE
        };
        let Some(mut buf) = self.pool.take(class) else {
            return Err(CloseReason::Limit(crate::error::LimitKind::BufferBudget));
        };
        let body_max = u16::try_from(buf.capacity().saturating_sub(16))
            .unwrap_or(u16::MAX)
            .min(lim.proxy_header_max);
        let mut parser = ProxyParser::new(proxy.versions, body_max);
        link.begin_handshake(link.info.accepted_at + lim.handshake_timeout);
        let outcome = loop {
            match parser.feed(buf.as_slice()) {
                Ok(ProxyProgress::Done { header, consumed }) => {
                    let real = match (header.command, header.source) {
                        (ProxyCommand::Proxy, Some(ProxyAddress::Ip(a))) => {
                            Some(crate::addr::normalize_socket(a))
                        }
                        _ => None,
                    };
                    break Ok((header.to_facts(), real, consumed));
                }
                Ok(ProxyProgress::NeedMore { .. }) => {}
                Err(crate::proxy::ProxyError::NotProxy) => break Err(CloseReason::ProxyMissing),
                Err(_) => break Err(CloseReason::ProxyInvalid),
            }
            if buf.spare().is_empty() {
                break Err(CloseReason::ProxyInvalid);
            }
            match link.read(buf.spare()) {
                Ok(Got::Data(n)) => buf.set_len(buf.len() + n),
                Ok(Got::Eof) => break Err(CloseReason::ProxyMissing),
                Ok(Got::Woken) => {}
                Err(_) => break Err(link.reason_or(CloseReason::Io(OsErrorClass::Other(0)))),
            }
        };
        let (facts, real, consumed) = match outcome {
            Ok(v) => v,
            Err(reason) => {
                link.end_handshake(Some((buf, usize::MAX)));
                return Err(reason);
            }
        };
        let shared = self.shared.clone();
        let result = (|| {
            let Some(real) = real else {
                // LOCAL (the proxy itself) and UNKNOWN keep the socket's addresses.
                return Ok(());
            };
            // The per-source slot moves from the proxy to the real client.
            let key = PrefixKey::of(real.ip(), lim.source_policy);
            if Some(key) != *source {
                let table = &listener.sources;
                if !table.acquire(key) {
                    return Err(CloseReason::Refused(RefusalCause::SourceCap));
                }
                if let Some(old) = source.replace(key) {
                    table.release(old);
                }
            }
            link.info.real_peer = Some(real);
            Ok(())
        })();
        if let Err(reason) = result {
            link.end_handshake(Some((buf, usize::MAX)));
            return Err(reason);
        }
        let mut arc = self
            .facts_pool
            .pop()
            .unwrap_or_else(|| Arc::new(ProxyFacts::default()));
        if let Some(f) = Arc::get_mut(&mut arc) {
            *f = facts;
        } else {
            arc = Arc::new(facts);
        }
        link.info.proxy = Some(arc);
        link.end_handshake(Some((buf, consumed)));
        if let Some(real) = link.info.real_peer {
            let readmitted = match link.gate.as_mut() {
                Some(g) => g.readmit(&link.info),
                None => match self.gate_cell.as_mut() {
                    Some(c) => c.readmit(&link.info),
                    None => Ok(()),
                },
            };
            if let Err(refusal) = readmitted {
                if let Refusal::WithBytes { bytes, .. } = refusal {
                    let max = usize::from(lim.refusal_bytes_max);
                    if bytes.len() <= max {
                        link.send_denial_once(bytes);
                    }
                }
                return Err(CloseReason::Refused(RefusalCause::Gate(refusal.code())));
            }
            shared.event(Event::ProxyResolved {
                id: link.info.id,
                real_peer: real,
            });
        }
        Ok(())
    }
    /// Starts serving a job: options (where not inherited), the kill slot, the gate ticket.
    #[allow(clippy::type_complexity)]
    fn begin(
        &mut self,
        job: Job<G::Ticket>,
    ) -> Option<(Link, Arc<ListenerConf>, Option<PrefixKey>)> {
        let Job {
            stream,
            mut info,
            ticket,
            listener,
            source,
        } = job;
        let shared = self.shared.clone();
        let limits = listener.limits;
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
            let tcp = listener.tcp;
            let v6 = info.local.socket_addr().is_some_and(|a| a.is_ipv6());
            if let (false, Some(stream)) = (tcp.is_empty(), stream.tcp()) {
                if let Err(e) = tcp.apply(stream, v6) {
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
        ws.listener
            .store(u32::from(listener.id.0), Ordering::Release);
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
        // Queued before its listener was removed: close it unread.
        let failed = if listener.removed.load(Ordering::Acquire) {
            Some(CloseReason::Drained)
        } else {
            failed
        };
        if let Some(reason) = failed {
            self.end(link, reason, listener, source);
            return None;
        }
        #[cfg(feature = "proxy")]
        let mut source = source;
        #[cfg(feature = "proxy")]
        if let Some(proxy) = listener.proxy.clone() {
            if let Err(reason) = self.proxy_handshake(&mut link, &proxy, &listener, &mut source) {
                self.end(link, reason, listener, source);
                return None;
            }
        }
        #[cfg(feature = "tls")]
        if listener.tls {
            if let Err(reason) = self.tls_handshake(&mut link) {
                self.end(link, reason, listener, source);
                return None;
            }
        }
        Some((link, listener, source))
    }

    /// Closes the connection with one reason and releases everything it held.
    fn end(
        &mut self,
        link: Link,
        reason: CloseReason,
        listener: Arc<ListenerConf>,
        source: Option<PrefixKey>,
    ) -> (ConnectionInfo, CloseReason) {
        let shared = self.shared.clone();
        let ws = &shared.workers[self.idx];
        let mut link = link;
        if let Some(b) = link.take_pending() {
            self.pool.put(b);
        }
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
        // close_notify on a graceful close, then the TLS buffers go back to the pool.
        if !reason.is_abortive() {
            link.tls_close_notify();
        }
        if let Some((cin, cout)) = link.take_tls_buffers() {
            self.pool.put(cin);
            self.pool.put(cout);
        }
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
        ws.listener.store(NO_LISTENER, Ordering::Release);
        shared.release(&listener, source);
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
        let (info, _) = w.end(link, reason, listener, source);
        w.recycle(info);
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
        drop(session);
        w.recycle(info);
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
