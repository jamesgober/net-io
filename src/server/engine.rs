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

#[cfg(feature = "reactor")]
use super::reactor::Backend;
#[cfg(feature = "reactor")]
use crate::driver::DriverWaker;
#[cfg(feature = "reactor")]
use std::collections::HashMap;

const WORKER_STACK: usize = 256 * 1024;
const DRAIN_KILL: KillReason = KillReason(0);

/// `WorkerShared::kill_cause`: a user's kill, the drain deadline, or `Stopping`.
const CAUSE_USER: u8 = 0;
pub(crate) const CAUSE_DRAIN: u8 = 1;
pub(crate) const CAUSE_STOP: u8 = 2;

/// Commands for a reactor worker, run at the top of its loop.
#[cfg(feature = "reactor")]
pub(crate) const CMD_SWEEP: u32 = 1;
#[cfg(feature = "reactor")]
pub(crate) const CMD_SHED: u32 = 2;
#[cfg(feature = "reactor")]
pub(crate) const CMD_KILL_ALL: u32 = 4;
#[cfg(feature = "reactor")]
pub(crate) const CMD_LISTENER_SWEEP: u32 = 8;
#[cfg(feature = "reactor")]
pub(crate) const CMD_LISTENER_KILL: u32 = 16;
/// Deadlines shrank or returned: every waiting connection looks again.
#[cfg(feature = "reactor")]
pub(crate) const CMD_PRESSURE: u32 = 32;

/// How many admitted connections wait for one reactor worker before new ones are
/// refused with `Busy`.
#[cfg(feature = "reactor")]
const INBOX_MAX: usize = 4_096;

/// Shards of the reactor's table of open connections.
#[cfg(feature = "reactor")]
const CONN_SHARDS: usize = 16;

/// `WorkerShared::idle_cause`: an idle connection closed by a drain or by shedding.
const IDLE_DRAIN: u8 = 0;
const IDLE_SHED: u8 = 1;

/// `WorkerShared::listener` when the worker has no connection.
const NO_LISTENER: u32 = u32::MAX;

/// How often a drain looks again for connections that became idle.
const DRAIN_PASS: Duration = Duration::from_millis(10);

/// Accept errors in a row, none of them a connection, before the accept loop pauses.
const SKIPS_BEFORE_PAUSE: u32 = 64;

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
    pub placement: super::Placement,
    #[cfg(feature = "udp")]
    pub udp: Option<Arc<dyn crate::udp::UdpSessionFactory>>,
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

    /// A completion for a connection that is gone.
    #[cfg(feature = "reactor")]
    pub(crate) fn count_stale(&self) {
        self.begin_write();
        self.stale_completions.fetch_add(1, Ordering::Relaxed);
        self.end_write();
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

// Aligned past a cache line and its prefetched neighbour: each worker writes its own
// counters on every event, and must not take the next worker's line with it.
#[repr(align(128))]
pub(crate) struct WorkerShared {
    slot: Arc<KillSlot>,
    wake: Arc<Wake>,
    current: AtomicU64,
    /// The current connection's listener id (`NO_LISTENER` when none), for
    /// `remove_listener`'s drain. On the reactor: the listener being removed.
    pub(crate) listener: AtomicU32,
    /// The current connection's lane, for shedding. On the reactor: the lane
    /// shedding starts from.
    pub(crate) lane: AtomicU8,
    /// Why net-io itself killed the current connection (`CAUSE_*`).
    pub(crate) kill_cause: AtomicU8,
    /// Why net-io closed the current connection while idle (`IDLE_*`).
    idle_cause: AtomicU8,
    pub(crate) completer: Arc<CompleterShared>,
    pub(crate) stats: WorkerStats,
    /// Pending commands (`CMD_*`), reactor only.
    #[cfg(feature = "reactor")]
    pub(crate) cmd: AtomicU32,
    /// Open connections on this worker, reactor only.
    #[cfg(feature = "reactor")]
    pub(crate) load: AtomicU32,
    /// Wakes this worker's loop, reactor only.
    #[cfg(feature = "reactor")]
    pub(crate) waker: OnceLock<DriverWaker>,
}

/// A worker's inbox, on cache lines of its own: its owner locks it on every turn.
#[cfg(feature = "reactor")]
#[repr(align(128))]
struct Inbox<T>(Mutex<VecDeque<T>>);

/// Where the reactor finds an open connection by id.
#[cfg(feature = "reactor")]
pub(crate) struct RegisteredConn {
    pub(crate) slot: Arc<KillSlot>,
    pub(crate) generation: u32,
    pub(crate) worker: u32,
    pub(crate) index: u32,
}

struct WorkerTarget {
    shared: Weak<Shared>,
    idx: usize,
}

impl CompleterTarget for WorkerTarget {
    fn owns(&self, id: ConnectionId) -> bool {
        self.shared.upgrade().is_some_and(|s| {
            #[cfg(feature = "reactor")]
            if s.reactor {
                return s.conn_worker(id) == Some(self.idx as u32);
            }
            s.workers[self.idx].current.load(Ordering::Acquire) == id.get()
        })
    }
    fn wake(&self) {
        if let Some(s) = self.shared.upgrade() {
            s.wake_worker(self.idx);
        }
    }
    fn stopped(&self) -> bool {
        self.shared
            .upgrade()
            .is_none_or(|s| s.stopping.load(Ordering::Acquire))
    }
}

/// The non-generic state `Server` and `ServerHandle` share with the threads.
/// How many workers there are and where they run: what a listener group is built from.
#[derive(Clone, Debug)]
struct Layout {
    workers: u16,
    placement: super::Placement,
}

impl Layout {
    /// The CPU worker `i` runs on, when it is pinned.
    fn cpu_of(&self, i: usize) -> Option<usize> {
        match &self.placement {
            super::Placement::Off => None,
            super::Placement::PinPerCore => Some(i),
            super::Placement::Explicit(cpus) => Some(cpus[i % cpus.len()]),
        }
    }
}

pub(crate) struct Shared {
    layout: Layout,
    /// Adaptive deadlines, when set.
    pressure: Option<crate::limits::Pressure>,
    /// Open connections passed `pressure.high` and have not yet fallen below `low`.
    pressured: AtomicBool,
    /// Makes the session of each UDP listener.
    #[cfg(feature = "udp")]
    udp: Option<Arc<dyn crate::udp::UdpSessionFactory>>,
    /// The reactor runs this server (the blocking pool otherwise).
    #[cfg(feature = "reactor")]
    pub(crate) reactor: bool,
    /// Where the next hand-over starts looking for the least-loaded worker, so
    /// ties go round the workers (reactor only).
    #[cfg(feature = "reactor")]
    next_worker: AtomicUsize,
    /// Open connections by id, reactor only: kills and completions find them here.
    #[cfg(feature = "reactor")]
    conns: Box<[Mutex<HashMap<u64, RegisteredConn>>]>,
    pid: u32,
    door: AtomicBool,
    draining: AtomicBool,
    stopping: AtomicBool,
    stop: Mutex<Option<Option<Instant>>>,
    stop_cv: Condvar,
    progress: Mutex<()>,
    progress_cv: Condvar,
    pub(crate) workers: Vec<WorkerShared>,
    /// The listeners and their accept threads (D-097). Locked only on cold paths
    /// (doors, wake-ups, adding, removing, releasing, shutdown).
    listeners: Mutex<Vec<ListenerEntry>>,
    /// The next listener id; ids are never reused.
    next_listener: AtomicU32,
    /// Starts an accept thread for a listener (holds the engine weakly).
    spawn_accept: OnceLock<SpawnAccept>,
    /// Admits an adopted connection (holds the engine weakly).
    adopt: OnceLock<AdoptFn>,
    /// The driver the limits resolve for.
    driver: DriverKind,
    /// The global cap, for `pressure`.
    #[cfg_attr(not(feature = "reactor"), allow(dead_code))]
    max_open: u32,
    /// Workers shared by every listener without workers of its own: the first
    /// `shared_workers` of `workers`.
    #[cfg_attr(not(feature = "reactor"), allow(dead_code))]
    shared_workers: usize,
    /// Soft closes in progress, against `Limits::denial_linger_max` (D-182).
    pub(crate) soft_closes: Arc<crate::link::SoftCloses>,
    /// The server's limits, for listeners added later.
    pub(crate) base_limits: Limits,
    /// The server's trusted proxies, for listeners added later.
    pub(crate) trusted: Option<Arc<TrustedProxies>>,
    queue_notify: OnceLock<Box<dyn Fn() + Send + Sync>>,
    queue_len: AtomicUsize,
    /// Accept threads between their door check and the end of an admission: a
    /// drain is not over while one is (D-179).
    admitting: AtomicUsize,
    /// Moves on every change to the listeners reactor workers accept on themselves
    /// (D-197): a worker rescans its own when this differs from the one it saw.
    #[cfg(feature = "reactor")]
    pub(crate) listener_epoch: AtomicU64,
    /// A drain the control line asked for has its thread: a worker that sees it
    /// cannot wait in it the way an accept thread does (D-197).
    #[cfg(feature = "reactor")]
    control_drain: AtomicBool,
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
    dyn Fn(Arc<ListenerConf>, Arc<ListenerRuntime>, usize) -> std::io::Result<JoinHandle<()>>
        + Send
        + Sync,
>;

impl Shared {
    /// A sink that panics loses that event and nothing else.
    pub(crate) fn event(&self, e: Event) {
        if let Some(s) = &self.sink {
            let _ = guarded(|| s.event(&e));
        }
    }

    #[cfg_attr(not(feature = "reactor"), allow(dead_code))]
    pub(crate) fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }

    #[cfg_attr(not(feature = "reactor"), allow(dead_code))]
    pub(crate) fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    #[cfg(feature = "reactor")]
    pub(crate) fn control_line(&self) -> &dyn ControlLine {
        self.control.as_ref()
    }

    /// Connections in use against the global cap, 0.0 to 1.0.
    pub(crate) fn occupancy(&self) -> f32 {
        let open = self.open.load(Ordering::Relaxed) as f32;
        (open / self.max_open.max(1) as f32).min(1.0)
    }

    #[cfg(feature = "reactor")]
    fn conn_shard(&self, id: u64) -> std::sync::MutexGuard<'_, HashMap<u64, RegisteredConn>> {
        self.conns[(id as usize) % CONN_SHARDS]
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    #[cfg(feature = "reactor")]
    pub(crate) fn register_conn(&self, id: ConnectionId, conn: RegisteredConn) {
        self.conn_shard(id.get()).insert(id.get(), conn);
    }

    #[cfg(feature = "reactor")]
    pub(crate) fn unregister_conn(&self, id: ConnectionId) {
        self.conn_shard(id.get()).remove(&id.get());
    }

    #[cfg(feature = "reactor")]
    fn conn_worker(&self, id: ConnectionId) -> Option<u32> {
        self.conn_shard(id.get()).get(&id.get()).map(|c| c.worker)
    }

    /// The table index of an open connection of `worker`.
    #[cfg(feature = "reactor")]
    pub(crate) fn conn_index(&self, id: ConnectionId, worker: u32) -> Option<u32> {
        self.conn_shard(id.get())
            .get(&id.get())
            .filter(|c| c.worker == worker)
            .map(|c| c.index)
    }

    fn wake_worker(&self, idx: usize) {
        #[cfg(feature = "reactor")]
        if self.reactor {
            if let Some(w) = self.workers[idx].waker.get() {
                w.wake();
            }
            return;
        }
        self.workers[idx].wake.wake();
    }

    /// Tells every reactor worker to run a command.
    #[cfg(feature = "reactor")]
    fn command(&self, bit: u32) {
        for (i, w) in self.workers.iter().enumerate() {
            w.cmd.fetch_or(bit, Ordering::AcqRel);
            self.wake_worker(i);
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
        let mut workers = false;
        for e in self.lock_listeners().iter() {
            if !e.conf.door.swap(true, Ordering::AcqRel) {
                e.conf.wake.wake();
                workers |= e.conf.on_workers;
            }
        }
        if workers {
            self.wake_workers();
        }
        if opened {
            self.event(Event::DoorOpened);
        }
        Ok(())
    }

    pub(crate) fn close_door(&self) {
        let closed = self.door.swap(false, Ordering::SeqCst);
        for e in self.lock_listeners().iter() {
            if e.conf.door.swap(false, Ordering::SeqCst) {
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
            if e.thread.is_none() && !e.conf.on_workers {
                e.thread = Some(spawn(e.conf.clone(), e.runtime.clone(), 0)?);
                for (i, s) in e.siblings.iter_mut().enumerate() {
                    s.thread = Some(spawn(e.conf.clone(), s.runtime.clone(), i + 1)?);
                }
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
        #[cfg(feature = "reactor")]
        for e in entries.iter().filter(|e| e.conf.on_workers) {
            let mut all = vec![&e.runtime];
            all.extend(e.siblings.iter().map(|s| &s.runtime));
            self.release_from_workers(&all);
        }
        for mut e in entries {
            if let Some(t) = e.thread.take() {
                let _ = t.join();
            }
            for s in &mut e.siblings {
                if let Some(t) = s.thread.take() {
                    let _ = t.join();
                }
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
            if !e.siblings.is_empty() {
                return Err(NetError::Unsupported {
                    feature: "handing off a per-worker listener",
                    platform: std::env::consts::OS,
                });
            }
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
        let (mut entry, info) =
            bind_listener(spec, id, &self.base_limits, self.driver, &self.layout, None)?;
        let Some(spawn) = self.spawn_accept.get() else {
            return Err(NetError::ShuttingDown);
        };
        let setup = |e| NetError::DriverSetup {
            driver: DriverKind::Blocking,
            source: e,
        };
        let on_workers = entry.conf.on_workers;
        if !on_workers {
            entry.thread =
                Some(spawn(entry.conf.clone(), entry.runtime.clone(), 0).map_err(setup)?);
            for (i, s) in entry.siblings.iter_mut().enumerate() {
                s.thread =
                    Some(spawn(entry.conf.clone(), s.runtime.clone(), i + 1).map_err(setup)?);
            }
        }
        self.lock_listeners().push(entry);
        #[cfg(feature = "reactor")]
        if on_workers {
            self.listener_epoch.fetch_add(1, Ordering::AcqRel);
            self.wake_workers();
        }
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
            siblings,
        } = entry;
        conf.door.store(false, Ordering::Release);
        conf.removed.store(true, Ordering::Release);
        conf.wake.wake();
        #[cfg(feature = "reactor")]
        if conf.on_workers {
            let mut all = vec![&runtime];
            all.extend(siblings.iter().map(|s| &s.runtime));
            self.release_from_workers(&all);
        }
        if let Some(t) = thread {
            let _ = t.join();
        }
        for s in siblings {
            if let Some(t) = s.thread {
                let _ = t.join();
            }
        }
        drop(runtime);
        self.event(Event::ListenerClosed { listener: id });
        Ok(self.drain_listener(&conf, deadline))
    }

    /// As `drain_listener`, through the workers' command words.
    #[cfg(feature = "reactor")]
    fn drain_listener_reactor(&self, conf: &ListenerConf, deadline: Instant) -> DrainReport {
        let start = Instant::now();
        let id = u32::from(conf.id.0);
        let initial = conf.count.load(Ordering::Acquire);
        for w in &self.workers {
            w.listener.store(id, Ordering::Release);
        }
        let mut killed_at_deadline = false;
        let mut guard = self.progress.lock().unwrap_or_else(PoisonError::into_inner);
        while conf.count.load(Ordering::Acquire) > 0 {
            self.command(CMD_LISTENER_SWEEP);
            let now = Instant::now();
            if now >= deadline && !killed_at_deadline {
                killed_at_deadline = true;
                self.command(CMD_LISTENER_KILL);
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
        let killed = conf.killed.load(Ordering::Acquire);
        DrainReport {
            graceful: initial.saturating_sub(killed),
            killed,
            took: start.elapsed(),
        }
    }

    /// The drain of one listener's connections (see `remove_listener`).
    fn drain_listener(&self, conf: &ListenerConf, deadline: Instant) -> DrainReport {
        let start = Instant::now();
        let id = u32::from(conf.id.0);
        let initial = conf.count.load(Ordering::Acquire);
        let mut killed = 0u32;
        let mut killed_at_deadline = false;
        #[cfg(feature = "reactor")]
        if self.reactor {
            return self.drain_listener_reactor(conf, deadline);
        }
        let mut guard = self.progress.lock().unwrap_or_else(PoisonError::into_inner);
        while conf.count.load(Ordering::Acquire) > 0 {
            let mine = |w: &&WorkerShared| {
                w.listener.load(Ordering::Acquire) == id && w.current.load(Ordering::Acquire) != 0
            };
            // The generation first, then whose connection it is: read the other way
            // round, the worker's next connection (another listener's) could be hit.
            for w in &self.workers {
                let generation = w.slot.generation();
                if mine(&w) && !w.slot.drained() {
                    w.idle_cause.store(IDLE_DRAIN, Ordering::Release);
                    w.slot.drain_idle(generation);
                }
            }
            let now = Instant::now();
            if now >= deadline && !killed_at_deadline {
                killed_at_deadline = true;
                for w in &self.workers {
                    let generation = w.slot.generation();
                    if !mine(&w) {
                        continue;
                    }
                    let claimed = w
                        .kill_cause
                        .compare_exchange(
                            CAUSE_USER,
                            CAUSE_DRAIN,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok();
                    if w.slot.kill(generation, DRAIN_KILL) {
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

    /// Wakes every worker (not the accept threads).
    fn wake_workers(&self) {
        for i in 0..self.workers.len() {
            self.wake_worker(i);
        }
    }

    /// Returns once no worker holds these listening sockets: each one that accepts
    /// on them sees the epoch move, deregisters, and drops its handle, so the
    /// sockets close when the caller drops its own, as a joined accept thread's do.
    /// A worker answers at its next turn; one held in a session callback holds
    /// this, as a gate callback holds an accept thread's join.
    #[cfg(feature = "reactor")]
    fn release_from_workers(&self, runtimes: &[&Arc<ListenerRuntime>]) {
        self.listener_epoch.fetch_add(1, Ordering::AcqRel);
        while runtimes.iter().any(|r| Arc::strong_count(r) > 1) {
            self.wake_workers();
            std::thread::sleep(Duration::from_micros(200));
        }
    }

    /// The listeners worker `idx` accepts on itself (D-197): for each listener of a
    /// per-worker group, the socket of that worker's place in the group.
    #[cfg(feature = "reactor")]
    pub(crate) fn worker_listeners(
        &self,
        idx: usize,
    ) -> Vec<(Arc<ListenerConf>, Arc<ListenerRuntime>)> {
        self.lock_listeners()
            .iter()
            .filter(|e| e.conf.on_workers && !e.conf.removed.load(Ordering::Acquire))
            .filter_map(|e| {
                let rt = match idx {
                    0 => &e.runtime,
                    i => &e.siblings.get(i - 1)?.runtime,
                };
                Some((e.conf.clone(), rt.clone()))
            })
            .collect()
    }

    pub(crate) fn wake_all(&self) {
        for e in self.lock_listeners().iter() {
            e.conf.wake.wake();
        }
        for i in 0..self.workers.len() {
            self.wake_worker(i);
        }
    }

    pub(crate) fn kill(&self, id: ConnectionId, reason: KillReason) -> bool {
        self.with_slot(id, |slot, generation| slot.kill(generation, reason))
    }

    /// A soft kill: the owner sends what is queued, then closes gracefully, all
    /// within `within` (`ServerHandle::close_after_flush`).
    pub(crate) fn close_after_flush(
        &self,
        id: ConnectionId,
        reason: KillReason,
        within: Duration,
    ) -> bool {
        let within = within.min(crate::time::LONGEST);
        self.with_slot(id, |slot, generation| {
            slot.kill_soft(generation, reason, within)
        })
    }

    /// Runs `f` on the kill slot of connection `id` with its generation; `false`
    /// when no open connection of this server has that id.
    fn with_slot(&self, id: ConnectionId, f: impl FnOnce(&KillSlot, u32) -> bool) -> bool {
        #[cfg(feature = "reactor")]
        if self.reactor {
            let found = self
                .conn_shard(id.get())
                .get(&id.get())
                .map(|c| (c.slot.clone(), c.generation));
            return found.is_some_and(|(slot, generation)| f(&slot, generation));
        }
        for w in &self.workers {
            if w.current.load(Ordering::Acquire) != id.get() {
                continue;
            }
            let generation = w.slot.generation();
            if w.current.load(Ordering::Acquire) != id.get() {
                return false;
            }
            return f(&w.slot, generation);
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
    pub(crate) fn notify_progress(&self) {
        let _g = self.progress.lock().unwrap_or_else(PoisonError::into_inner);
        self.progress_cv.notify_all();
    }

    fn idle(&self) -> bool {
        // Read after the door closed (sequentially consistent with the accept
        // thread's count and door check): an admission past its check is seen here.
        if self.admitting.load(Ordering::SeqCst) != 0 {
            return false;
        }
        #[cfg(feature = "reactor")]
        if self.reactor {
            return self.open.load(Ordering::Acquire) == 0;
        }
        self.busy.load(Ordering::Acquire) == 0 && self.queue_len.load(Ordering::Acquire) == 0
    }

    pub(crate) fn drain(&self, deadline: Instant) -> DrainReport {
        let start = Instant::now();
        self.close_door();
        let first = !self.draining.swap(true, Ordering::AcqRel);
        if first {
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
            self.drain_idle_pass();
            let now = Instant::now();
            // A stop that arrives during the drain (the control line escalating to
            // `Stopping`, or `request_stop`) ends it now, not at the drain's deadline.
            let stop = self.stopping.load(Ordering::Acquire)
                || self.control.state() == ControlState::Stopping;
            if stop {
                self.kill_all(CAUSE_STOP);
                killed_at_deadline = true;
            } else if now >= deadline {
                // Every pass, not once: a connection admitted late is killed too.
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
        // One drain, one event, however many threads waited on it.
        if first {
            self.event(Event::DrainFinished {
                graceful: report.graceful,
                killed: report.killed,
            });
        }
        report
    }

    fn drain_idle_pass(&self) {
        #[cfg(feature = "reactor")]
        if self.reactor {
            return self.command(CMD_SWEEP);
        }
        for w in &self.workers {
            if w.current.load(Ordering::Acquire) != 0 && !w.slot.drained() {
                w.idle_cause.store(IDLE_DRAIN, Ordering::Release);
                w.slot.drain_idle(w.slot.generation());
            }
        }
    }

    /// Kills every open connection on net-io's own behalf (`cause` names why).
    fn kill_all(&self, cause: u8) {
        #[cfg(feature = "reactor")]
        if self.reactor {
            for w in &self.workers {
                w.kill_cause.store(cause, Ordering::Release);
            }
            return self.command(CMD_KILL_ALL);
        }
        for w in &self.workers {
            let generation = w.slot.generation();
            if w.current.load(Ordering::Acquire) != 0 {
                // Claim the cause first (the owner reads it once it sees the kill). A
                // concurrent drain or stop that already claimed it keeps its cause.
                let claimed = w
                    .kill_cause
                    .compare_exchange(CAUSE_USER, cause, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok();
                if !w.slot.kill(generation, DRAIN_KILL) && claimed {
                    // Already closed, or a user's kill won: that reason stands.
                    w.kill_cause.store(CAUSE_USER, Ordering::Release);
                }
            }
        }
    }

    /// `ControlState::Shed`: closes the idle connections in shed lanes now; busy
    /// ones see `pressure()` 1.0 and close at their next idle point.
    fn shed_idle(&self, from_lane: Lane) {
        #[cfg(feature = "reactor")]
        if self.reactor {
            for w in &self.workers {
                w.lane.store(from_lane.0, Ordering::Release);
            }
            return self.command(CMD_SHED);
        }
        for w in &self.workers {
            let generation = w.slot.generation();
            if w.current.load(Ordering::Acquire) != 0
                && w.lane.load(Ordering::Acquire) >= from_lane.0
                && !w.slot.drained()
            {
                w.idle_cause.store(IDLE_SHED, Ordering::Release);
                if !w.slot.shed_idle(generation) {
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

    /// Moves the pressure state when the open count crossed a threshold.
    fn update_pressure(&self) {
        let Some(p) = self.pressure else { return };
        let fill = self.occupancy();
        let on = self.pressured.load(Ordering::Acquire);
        if on != (fill >= p.high) && (!on || fill <= p.low) {
            self.pressured.store(!on, Ordering::Release);
            #[cfg(feature = "reactor")]
            if self.reactor {
                self.command(CMD_PRESSURE);
            }
        }
    }

    /// What deadlines are multiplied by right now.
    pub(crate) fn deadline_scale(&self) -> f32 {
        match self.pressure {
            Some(p) if self.pressured.load(Ordering::Acquire) => p.factor,
            _ => 1.0,
        }
    }

    pub(crate) fn release(&self, listener: &ListenerConf, source: Option<PrefixKey>) {
        self.open.fetch_sub(1, Ordering::AcqRel);
        self.update_pressure();
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
    pub(crate) versions: ProxyVersions,
    /// `None` on a Unix socket listener: every peer that can connect is trusted.
    trusted: Option<Arc<TrustedProxies>>,
}

impl ListenerProxy {
    /// A TCP peer must be a trusted proxy; on a Unix socket listener the file's
    /// permissions already decided who may connect.
    #[cfg_attr(not(any(feature = "reactor", feature = "proxy")), allow(dead_code))]
    pub(crate) fn is_trusted(&self, info: &ConnectionInfo) -> bool {
        match (&self.trusted, info.peer.socket_addr()) {
            (Some(list), Some(peer)) => list.contains(peer.ip()),
            (None, None) => info.transport == Transport::Unix,
            _ => false,
        }
    }
}

/// One listener's settings and counters (D-097). Its accept thread and every
/// connection it admitted hold it, so a removed listener's connections keep
/// their limits and give their cap slots back where they took them.
pub(crate) struct ListenerConf {
    pub(crate) id: ListenerId,
    pub(crate) limits: Arc<Effective>,
    tcp: TcpOptions,
    /// `Some` when the listener requires a PROXY header.
    #[cfg_attr(not(feature = "proxy"), allow(dead_code))]
    pub(crate) proxy: Option<ListenerProxy>,
    /// Connections are still admitted under `ControlState::Lockdown`.
    lockdown_allowed: bool,
    /// Whether the listener serves TLS.
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    pub(crate) tls: bool,
    /// Connections a removal killed at its deadline, reactor only.
    #[cfg(feature = "reactor")]
    killed: AtomicU32,
    /// Connections admitted and not yet closed (the per-listener cap).
    count: AtomicU32,
    /// The per-source cap's table, sized from this listener's limits (D-085).
    sources: SourceTable,
    /// This listener's door: `open_door` and `close_door` set every one.
    door: AtomicBool,
    /// Set by `remove_listener` and at shutdown: the accept thread ends and
    /// queued connections close with `Drained`.
    pub(crate) removed: AtomicBool,
    wake: Wakes,
    /// Reactor workers of its own: the first index and how many (`None`: the
    /// server's shared workers).
    #[cfg_attr(not(feature = "reactor"), allow(dead_code))]
    pub(crate) workers: Option<(usize, usize)>,
    /// A per-worker group on the reactor: each worker accepts on its own socket in
    /// its own loop, and no accept thread runs (D-197).
    pub(crate) on_workers: bool,
}

#[cfg(feature = "reactor")]
impl ListenerConf {
    pub(crate) fn note_killed(&self) {
        self.killed.fetch_add(1, Ordering::AcqRel);
    }
}

/// A listener the server owns: settings, socket, accept thread.
struct ListenerEntry {
    conf: Arc<ListenerConf>,
    runtime: Arc<ListenerRuntime>,
    thread: Option<JoinHandle<()>>,
    /// The other sockets of a per-worker group, one for each worker after the first.
    siblings: Vec<Sibling>,
}

struct Sibling {
    runtime: Arc<ListenerRuntime>,
    thread: Option<JoinHandle<()>>,
}

/// The wake channels of a listener's accept threads, one each: a wake is read by
/// whoever reads it, so threads cannot share a channel.
struct Wakes(Vec<Arc<Wake>>);

impl Wakes {
    fn wake(&self) {
        for w in &self.0 {
            w.wake();
        }
    }
}

thread_local! {
    /// On an accept thread of a per-worker group, the worker it feeds; during a
    /// reactor worker's own accepts, that worker, with `true`: it takes its inbox
    /// after the batch, so no wake is sent (D-197).
    static FEEDS: std::cell::Cell<Option<(usize, bool)>> = const { std::cell::Cell::new(None) };
}

/// One accept thread inside an admission, for the drain (see `Shared::admitting`).
struct Admitting<'a>(&'a Shared);

impl<'a> Admitting<'a> {
    fn enter(shared: &'a Shared) -> Admitting<'a> {
        shared.admitting.fetch_add(1, Ordering::SeqCst);
        Admitting(shared)
    }
}

impl Drop for Admitting<'_> {
    fn drop(&mut self) {
        self.0.admitting.fetch_sub(1, Ordering::SeqCst);
        if self.0.draining.load(Ordering::Acquire) {
            self.0.notify_progress();
        }
    }
}

/// Binds (or adopts) the socket of `spec` and builds its settings.
fn bind_listener(
    spec: ListenerSpec,
    id: ListenerId,
    base: &Limits,
    driver: DriverKind,
    layout: &Layout,
    dedicated: Option<(usize, usize)>,
) -> Result<(ListenerEntry, ListenerInfo), NetError> {
    let per_worker = spec.options.is_some_and(|o| o.per_worker);
    if let Some(n) = spec.workers {
        let reason = if n == 0 {
            crate::error::ConfigReason::Zero
        } else {
            crate::error::ConfigReason::Inconsistent
        };
        #[cfg(feature = "udp")]
        let udp = spec.udp.is_some();
        #[cfg(not(feature = "udp"))]
        let udp = false;
        if n == 0
            || per_worker
            || udp
            || driver.resolve() != DriverKind::Reactor
            || dedicated.is_none()
        {
            return Err(NetError::InvalidConfig {
                field: "workers",
                reason,
            });
        }
    }
    if per_worker && !cfg!(target_os = "linux") {
        return Err(NetError::Unsupported {
            feature: "per-worker listeners",
            platform: std::env::consts::OS,
        });
    }
    if per_worker && driver.resolve() != DriverKind::Reactor {
        return Err(NetError::InvalidConfig {
            field: "per_worker",
            reason: crate::error::ConfigReason::Inconsistent,
        });
    }
    let lim = base.overlay(&spec.limits).effective(driver);
    let proxy = match spec.proxy {
        ProxyMode::Required { versions } => Some(ListenerProxy {
            versions,
            trusted: spec.trusted.clone(),
        }),
        _ => None,
    };
    let group_options = spec.options;
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
        #[cfg(feature = "udp")]
        if let Some(options) = spec.udp {
            let addrs = spec.addrs.clone().map_err(|text| NetError::Os {
                op: "resolve",
                source: std::io::Error::other(text),
            })?;
            let socket = crate::udp::UdpSocket::bind_with(&addrs[..], options)?;
            socket.set_nonblocking()?;
            let local = socket.local_addr()?;
            let info = ListenerInfo {
                id,
                name: spec.name.clone(),
                local: crate::info::Endpoint::Ip(local),
                backlog: None,
                transport: Transport::Udp,
                proxy: ProxyMode::Off,
                tls: false,
            };
            break 'bound (
                ListenerRuntime::Udp(Mutex::new(socket), info.clone()),
                info,
                TcpOptions::default(),
            );
        }
        #[cfg(all(windows, feature = "local"))]
        if let Some((path, options)) = spec.unix {
            let mut listener = crate::local_windows::UnixListener::bind_with(&path, options)?;
            listener.set_identity(id, spec.name.clone());
            listener.set_proxy_mode(spec.proxy);
            listener.set_tls(spec.tls);
            let info = listener.info().clone();
            break 'bound (
                ListenerRuntime::AfUnix(listener),
                info,
                TcpOptions::default(),
            );
        }
        #[cfg(all(windows, feature = "local"))]
        if let Some((name, options)) = spec.pipe {
            let mut listener = crate::pipe::PipeListener::create_with(&name, options)?;
            listener.set_identity(id, spec.name.clone());
            listener.set_proxy_mode(spec.proxy);
            listener.set_tls(spec.tls);
            let info = listener.info().clone();
            break 'bound (ListenerRuntime::Pipe(listener), info, TcpOptions::default());
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
    let threads = if per_worker {
        usize::from(layout.workers)
    } else {
        1
    };
    let mut siblings = Vec::with_capacity(threads.saturating_sub(1));
    if let (true, Some(options), Some(local)) =
        (per_worker, group_options, info.local.socket_addr())
    {
        for i in 1..threads {
            let cpu = layout.cpu_of(i).and_then(|c| u32::try_from(c).ok());
            let params = options.incoming_cpu(cpu).params();
            let socket =
                sys::tcp_listener(local, &params).map_err(|e| crate::tcp::bind_error(local, e))?;
            let mut l = TcpListener::finish(socket, options, id, spec.name.clone())?;
            l.set_proxy_mode(spec.proxy);
            l.set_tls(spec.tls);
            siblings.push(Sibling {
                runtime: Arc::new(ListenerRuntime::Tcp(l)),
                thread: None,
            });
        }
    }
    let wakes = (0..threads)
        .map(|_| Wake::new().map(Arc::new))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|e| NetError::DriverSetup {
            driver: DriverKind::Blocking,
            source: e,
        })?;
    let wake = Wakes(wakes);
    let on_workers =
        per_worker && cfg!(feature = "reactor") && matches!(runtime, ListenerRuntime::Tcp(_));
    let conf = Arc::new(ListenerConf {
        id,
        limits: Arc::new(lim),
        tcp,
        proxy,
        lockdown_allowed: spec.lockdown_allowed,
        tls: spec.tls,
        #[cfg(feature = "reactor")]
        killed: AtomicU32::new(0),
        count: AtomicU32::new(0),
        sources: SourceTable::new(lim.max_per_listener, lim.max_per_source),
        door: AtomicBool::new(false),
        removed: AtomicBool::new(false),
        wake,
        workers: dedicated,
        on_workers,
    });
    Ok((
        ListenerEntry {
            conf,
            runtime: Arc::new(runtime),
            thread: None,
            siblings,
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

/// A job's parts, for the worker that takes it.
#[cfg(feature = "reactor")]
pub(crate) type JobParts<T> = (
    sys::Stream,
    ConnectionInfo,
    T,
    Arc<ListenerConf>,
    Option<PrefixKey>,
);

#[cfg(feature = "reactor")]
impl<T> Job<T> {
    pub(crate) fn into_parts(self) -> JobParts<T> {
        (
            self.stream,
            self.info,
            self.ticket,
            self.listener,
            self.source,
        )
    }
}

// Listeners are few, and each lives as long as its thread.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ListenerRuntime {
    Tcp(TcpListener),
    #[cfg(feature = "udp")]
    Udp(Mutex<crate::udp::UdpSocket>, ListenerInfo),
    #[cfg(all(unix, feature = "local"))]
    Unix(UnixListener),
    #[cfg(all(windows, feature = "local"))]
    AfUnix(crate::local_windows::UnixListener),
    #[cfg(all(windows, feature = "local"))]
    Pipe(crate::pipe::PipeListener),
}

impl ListenerRuntime {
    /// The listening TCP socket, for a worker that accepts on it (D-197).
    #[cfg(feature = "reactor")]
    pub(crate) fn tcp_sock(&self) -> Option<sys::Sock<'_>> {
        match self {
            ListenerRuntime::Tcp(l) => Some(l.std().sock()),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    /// Until a connection waits, or `wake` fires. A pipe's accept does this itself.
    fn wait(&self, wake: &sys::Wake) {
        let sock = match self {
            ListenerRuntime::Tcp(l) => l.std().sock(),
            #[cfg(all(unix, feature = "local"))]
            ListenerRuntime::Unix(l) => std::os::fd::AsFd::as_fd(l.std()),
            #[cfg(all(windows, feature = "local"))]
            ListenerRuntime::AfUnix(l) => l.std().sock(),
            #[cfg(all(windows, feature = "local"))]
            ListenerRuntime::Pipe(_) => return,
            #[cfg(feature = "udp")]
            ListenerRuntime::Udp(..) => return,
        };
        let _ = sys::wait(sock, Interest::Read, Some(wake), None);
    }

    fn info(&self) -> &ListenerInfo {
        match self {
            ListenerRuntime::Tcp(l) => l.info(),
            #[cfg(all(unix, feature = "local"))]
            ListenerRuntime::Unix(l) => l.info(),
            #[cfg(all(windows, feature = "local"))]
            ListenerRuntime::AfUnix(l) => l.info(),
            #[cfg(all(windows, feature = "local"))]
            ListenerRuntime::Pipe(l) => l.info(),
            #[cfg(feature = "udp")]
            ListenerRuntime::Udp(_, info) => info,
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
            #[cfg(all(windows, feature = "local"))]
            ListenerRuntime::AfUnix(_) | ListenerRuntime::Pipe(_) => {
                Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
            }
            #[cfg(feature = "udp")]
            ListenerRuntime::Udp(..) => Err(std::io::Error::from(std::io::ErrorKind::Unsupported)),
        }
    }
}

pub(crate) struct Engine<W, G: Gate> {
    pub(crate) shared: Arc<Shared>,
    pub(crate) work: W,
    pub(crate) gate: Arc<G>,
    pub(crate) gated: bool,
    queue: Mutex<VecDeque<Job<G::Ticket>>>,
    queue_cv: Condvar,
    pub(crate) clock: ClockRef,
    pub(crate) wipe: bool,
    pub(crate) budget: Arc<AtomicU64>,
    pub(crate) limits: Effective,
    /// One bounded inbox per reactor worker.
    #[cfg(feature = "reactor")]
    inboxes: Vec<Inbox<Job<G::Ticket>>>,
    /// Each reactor worker's driver, until its thread takes it.
    #[cfg(feature = "reactor")]
    drivers: Mutex<Vec<Option<Backend>>>,
}

#[cfg(feature = "reactor")]
impl<W, G: Gate> Engine<W, G> {
    pub(crate) fn take_driver(&self, idx: usize) -> Option<Backend> {
        self.drivers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(idx)
            .and_then(Option::take)
    }

    pub(crate) fn next_inbox(&self, idx: usize) -> Option<Job<G::Ticket>> {
        self.inboxes[idx]
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
    }

    pub(crate) fn inbox_empty(&self, idx: usize) -> bool {
        self.inboxes[idx]
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty()
    }

    /// The least-loaded worker takes the connection, ties going round the workers.
    /// A full inbox refuses.
    // A refused job goes straight back to its caller, on the path a flood takes;
    // a `Box` here would allocate there.
    #[allow(clippy::result_large_err)]
    fn hand_to_worker(&self, job: Job<G::Ticket>) -> Result<(), Job<G::Ticket>> {
        let shared = &self.shared;
        let (base, len) = job.listener.workers.unwrap_or((0, shared.shared_workers));
        let feed = FEEDS.with(std::cell::Cell::get);
        let idx = feed.map_or_else(
            || base + least_loaded(&shared.workers[base..base + len], &shared.next_worker),
            |(i, _)| i,
        );
        {
            let mut inbox = self.inboxes[idx]
                .0
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if inbox.len() >= INBOX_MAX {
                return Err(job);
            }
            // Counted now, so a burst spreads over the workers.
            shared.workers[idx].load.fetch_add(1, Ordering::Relaxed);
            inbox.push_back(job);
        }
        if !feed.is_some_and(|(_, own)| own) {
            shared.wake_worker(idx);
        }
        Ok(())
    }
}

/// The worker with the fewest open connections, looking from a start that moves on
/// by one each call: with short connections every load is usually 0, and taking the
/// first minimum gave every connection to worker 0 (found by tls-net, D-174). Stops
/// at the first idle worker.
#[cfg(feature = "reactor")]
fn least_loaded(workers: &[WorkerShared], next: &AtomicUsize) -> usize {
    let n = workers.len();
    if n <= 1 {
        return 0;
    }
    let start = next.fetch_add(1, Ordering::Relaxed) % n;
    let mut best = start;
    let mut least = u32::MAX;
    for k in 0..n {
        let i = (start + k) % n;
        let load = workers[i].load.load(Ordering::Relaxed);
        if load < least {
            least = load;
            best = i;
            if load == 0 {
                break;
            }
        }
    }
    best
}

pub(crate) fn start<W, G, S>(cfg: Config<W, G, S>) -> Result<Server, NetError>
where
    W: super::Workload,
    G: Gate,
    S: EventSink,
{
    let driver = cfg.driver;
    let reactor = driver == DriverKind::Reactor;
    let limits = cfg.limits.effective(driver);
    // Listeners with workers of their own get them after the server's shared ones,
    // in listener order (`ListenerSpec::workers`).
    let shared_workers = usize::from(cfg.workers);
    let mut ranges = Vec::with_capacity(cfg.listeners.len());
    let mut total = shared_workers;
    for spec in &cfg.listeners {
        ranges.push(spec.workers.filter(|&n| n > 0).map(|n| {
            let range = (total, usize::from(n));
            total += usize::from(n);
            range
        }));
    }
    let Ok(all_workers) = u16::try_from(total) else {
        return Err(NetError::InvalidConfig {
            field: "workers",
            reason: crate::error::ConfigReason::TooLarge {
                max: u64::from(u16::MAX),
            },
        });
    };
    let layout = Layout {
        workers: all_workers,
        placement: cfg.placement.clone(),
    };
    let mut entries = Vec::with_capacity(cfg.listeners.len());
    let mut infos = Vec::with_capacity(cfg.listeners.len());
    for (i, (spec, range)) in cfg.listeners.into_iter().zip(ranges).enumerate() {
        let id = ListenerId(u16::try_from(i).unwrap_or(u16::MAX));
        let (entry, info) = bind_listener(spec, id, &cfg.limits, driver, &layout, range)?;
        entries.push(entry);
        infos.push(info);
    }

    let sink: Option<Arc<dyn EventSink>> = if TypeId::of::<S>() == TypeId::of::<NoopSink>() {
        None
    } else {
        Some(Arc::new(cfg.sink))
    };
    let mut worker_wakes = Vec::with_capacity(total);
    for _ in 0..all_workers {
        worker_wakes.push(
            Wake::new()
                .map(Arc::new)
                .map_err(|e| NetError::DriverSetup {
                    driver: DriverKind::Blocking,
                    source: e,
                })?,
        );
    }
    #[cfg(feature = "reactor")]
    let mut backends = Vec::with_capacity(total);
    #[cfg(feature = "reactor")]
    if reactor {
        for _ in 0..all_workers {
            backends.push(Some(Backend::new(1024)?));
        }
    }
    #[cfg(not(feature = "reactor"))]
    let _ = reactor;
    let queue_capacity = limits.completion_queue as usize;
    let next_listener = u32::try_from(infos.len()).unwrap_or(u32::MAX);
    let shared = Arc::new_cyclic(|weak: &Weak<Shared>| Shared {
        layout: layout.clone(),
        pressure: limits.pressure,
        pressured: AtomicBool::new(false),
        #[cfg(feature = "udp")]
        udp: cfg.udp,
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
                #[cfg(feature = "reactor")]
                cmd: AtomicU32::new(0),
                #[cfg(feature = "reactor")]
                load: AtomicU32::new(0),
                #[cfg(feature = "reactor")]
                waker: OnceLock::new(),
            })
            .collect(),
        #[cfg(feature = "reactor")]
        reactor,
        #[cfg(feature = "reactor")]
        next_worker: AtomicUsize::new(0),
        #[cfg(feature = "reactor")]
        conns: (0..CONN_SHARDS)
            .map(|_| Mutex::new(HashMap::new()))
            .collect(),
        driver,
        max_open: limits.max_connections,
        soft_closes: crate::link::SoftCloses::new(limits.denial_linger_max),
        shared_workers,
        listeners: Mutex::new(entries),
        next_listener: AtomicU32::new(next_listener),
        spawn_accept: OnceLock::new(),
        adopt: OnceLock::new(),
        base_limits: cfg.limits.clone(),
        trusted: cfg.trusted.clone(),
        queue_notify: OnceLock::new(),
        queue_len: AtomicUsize::new(0),
        admitting: AtomicUsize::new(0),
        #[cfg(feature = "reactor")]
        listener_epoch: AtomicU64::new(0),
        #[cfg(feature = "reactor")]
        control_drain: AtomicBool::new(false),
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

    #[cfg(feature = "reactor")]
    for (i, b) in backends.iter().enumerate() {
        if let Some(b) = b {
            let _ = shared.workers[i].waker.set(crate::driver::Driver::waker(b));
        }
    }
    let engine = Arc::new(Engine {
        shared: shared.clone(),
        #[cfg(feature = "reactor")]
        inboxes: (0..backends.len())
            .map(|_| Inbox(Mutex::new(VecDeque::new())))
            .collect(),
        #[cfg(feature = "reactor")]
        drivers: Mutex::new(backends),
        work: cfg.work,
        gated: TypeId::of::<G>() != TypeId::of::<AllowAll>(),
        gate: Arc::new(cfg.gate),
        queue: Mutex::new(VecDeque::with_capacity(total)),
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
    let _ = shared.spawn_accept.set(Box::new(move |conf, rt, slot| {
        let Some(e) = weak.upgrade() else {
            return Err(std::io::Error::other("the server stopped"));
        };
        std::thread::Builder::new()
            .name(format!("net-io-accept-{}", conf.id.0))
            .spawn(move || accept_loop(&e, &conf, &rt, slot))
    }));

    let mut threads = Vec::with_capacity(total);
    let spawn_error = |e: std::io::Error| NetError::DriverSetup {
        driver: DriverKind::Blocking,
        source: e,
    };
    let mut failure = None;
    for i in 0..total {
        let e = engine.clone();
        let cpu = layout.cpu_of(i);
        match std::thread::Builder::new()
            .name(format!("net-io-worker-{i}"))
            .stack_size(WORKER_STACK)
            .spawn(move || {
                if let Some(cpu) = cpu {
                    // Placement is a tuning hint: a CPU this process may not use leaves
                    // the worker where it is, working.
                    let _ = sys::pin_current_thread(cpu);
                }
                W::run_worker(&e, i);
            }) {
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

// ---- UDP ------------------------------------------------------------------

/// Datagrams read per wait, so a flood cannot keep this loop from a stop.
#[cfg(feature = "udp")]
const UDP_TURN: usize = 64;

/// One UDP listener: its thread owns the socket, so the guard needs no lock on the data
/// path. The door gates reading, and a closed door leaves datagrams in the kernel.
#[cfg(feature = "udp")]
fn udp_loop(
    shared: &Arc<Shared>,
    conf: &Arc<ListenerConf>,
    socket: &Mutex<crate::udp::UdpSocket>,
    info: &ListenerInfo,
) {
    let Some(factory) = shared.udp.as_ref() else {
        return;
    };
    let mut session = factory.open(info);
    let mut socket = socket.lock().unwrap_or_else(PoisonError::into_inner);
    let wake = conf.wake.0[0].clone();
    let mut buf = vec![0u8; 65_536];
    loop {
        if shared.stopping.load(Ordering::Acquire)
            || shared.draining.load(Ordering::Acquire)
            || conf.removed.load(Ordering::Acquire)
        {
            return;
        }
        if !shared.door.load(Ordering::Acquire) || !conf.door.load(Ordering::Acquire) {
            let _ = sys::wait_wake(&wake, None);
            continue;
        }
        let _ = sys::wait(socket.raw_sock(), Interest::Read, Some(&wake), None);
        for _ in 0..UDP_TURN {
            let Ok(d) = socket.recv_from(&mut buf) else {
                break;
            };
            let mut cx = crate::udp::UdpContext {
                socket: &mut socket,
            };
            let bytes = &buf[..d.len.min(65_536)];
            let called = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                session.on_datagram(&mut cx, d.from, bytes);
            }));
            // A session that panics loses this datagram, and the socket goes on.
            let _ = called;
        }
    }
}

// ---- accept ---------------------------------------------------------------

fn accept_loop<W: super::Workload, G: Gate>(
    engine: &Arc<Engine<W, G>>,
    conf: &Arc<ListenerConf>,
    rt: &ListenerRuntime,
    slot: usize,
) {
    let shared = &engine.shared;
    #[cfg(feature = "udp")]
    if let ListenerRuntime::Udp(socket, info) = rt {
        return udp_loop(shared, conf, socket, info);
    }
    let wake = conf.wake.0[slot].clone();
    if conf.wake.0.len() > 1 {
        FEEDS.with(|f| f.set(Some((slot, false))));
    }
    let mut st = AcceptState::new();
    loop {
        if shared.stopping.load(Ordering::Acquire) || conf.removed.load(Ordering::Acquire) {
            return;
        }
        if st.view.refresh(shared.control.as_ref()) {
            shared.event(Event::ControlReacted {
                state: st.view.state(),
            });
            match st.view.state() {
                ControlState::Draining => {
                    shared.close_door();
                    shared.request_stop(st.view.deadline());
                    // The drain runs here: the door is closed, so this thread has
                    // nothing else to do until it ends.
                    let deadline = st
                        .view
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
        let now = engine.clock.now();
        if !accepting(shared, conf) {
            let _ = sys::wait_wake(&wake, None);
            continue;
        }
        if let Some(until) = st.pause_until {
            if now < until {
                let _ = sys::wait_wake(&wake, Some(until - now));
                continue;
            }
            st.pause_until = None;
        }
        match engine.accept_some(conf, rt, &mut st, &wake) {
            BatchEnd::More => {}
            BatchEnd::Again => rt.wait(&wake),
            BatchEnd::Failed => return,
        }
    }
}

/// The door is open for `conf`, and no drain runs.
fn accepting(shared: &Shared, conf: &ListenerConf) -> bool {
    shared.door.load(Ordering::Acquire)
        && conf.door.load(Ordering::Acquire)
        && !shared.draining.load(Ordering::Acquire)
}

/// One accept loop's own state: an accept thread's, or a reactor worker's for each
/// listener it accepts on (D-197).
pub(crate) struct AcceptState {
    acceptor: Acceptor,
    ids: IdBlock,
    view: ControlView,
    coalescer: Coalescer,
    pause_until: Option<Instant>,
    skipped: u32,
}

impl AcceptState {
    pub(crate) fn new() -> AcceptState {
        AcceptState {
            acceptor: Acceptor::new(),
            ids: IdBlock::new(),
            view: ControlView::new(),
            coalescer: Coalescer::new(),
            pause_until: None,
            skipped: 0,
        }
    }
}

/// How a batch of accepts ended.
enum BatchEnd {
    /// The batch ran out, the door closed, the control line moved, or a pause
    /// began: the caller looks again.
    More,
    /// No connection waits.
    Again,
    /// The listener failed (`ListenerFailed` is out).
    Failed,
}

/// What a reactor worker does next with a listener it accepts on (D-197).
#[cfg(feature = "reactor")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkerAccept {
    /// No connection waits: arm `Operation::Accept`.
    Armed,
    /// More may wait: come back after this turn's other work.
    Kick,
    /// The door is closed or a drain runs: nothing until it opens.
    Park,
    /// Out of descriptors: nothing until then.
    Paused(Instant),
    /// The listener failed, or the server stops.
    Gone,
}

impl<W: super::Workload, G: Gate> Engine<W, G> {
    /// One batch of accepts and admissions on `rt`, bounded by `accept_batch`.
    fn accept_some(
        &self,
        conf: &Arc<ListenerConf>,
        rt: &ListenerRuntime,
        st: &mut AcceptState,
        wake: &Wake,
    ) -> BatchEnd {
        let shared = &self.shared;
        let _ = wake;
        for _ in 0..conf.limits.accept_batch {
            // Counted before the door is read: a drain that closes the door either
            // stops this accept or waits for this admission to finish, so a
            // connection it takes is queued and served, never closed unread when the
            // stop that follows the drain finds it (D-179).
            let admitting = Admitting::enter(shared);
            // Each admission sees the door, a drain, a stop, and the control line as
            // they are now, not as they were when the batch began: three loads and the
            // line's epoch, against an accept's system call.
            if !shared.door.load(Ordering::SeqCst)
                || !conf.door.load(Ordering::SeqCst)
                || shared.draining.load(Ordering::Acquire)
                || shared.stopping.load(Ordering::Acquire)
                || st.view.moved(shared.control.as_ref())
            {
                break;
            }
            let outcome = match rt {
                ListenerRuntime::Tcp(l) => match st.acceptor.accept(l.std()) {
                    Accepted::Conn((stream, peer)) => {
                        st.skipped = 0;
                        self.admit_tcp(
                            stream,
                            peer,
                            conf,
                            &mut st.ids,
                            &st.view,
                            &mut st.coalescer,
                        );
                        continue;
                    }
                    other => other.without_conn(),
                },
                #[cfg(all(unix, feature = "local"))]
                ListenerRuntime::Unix(l) => match st.acceptor.accept_unix(l.std()) {
                    Accepted::Conn(stream) => {
                        st.skipped = 0;
                        self.admit_unix(l, stream, conf, &mut st.ids, &st.view, &mut st.coalescer);
                        continue;
                    }
                    other => other.without_conn(),
                },
                #[cfg(feature = "udp")]
                ListenerRuntime::Udp(..) => return BatchEnd::Failed,
                #[cfg(all(windows, feature = "local"))]
                ListenerRuntime::AfUnix(l) => match st.acceptor.accept_af_unix(l.std()) {
                    Accepted::Conn(stream) => {
                        st.skipped = 0;
                        self.admit_af_unix(
                            l,
                            stream,
                            conf,
                            &mut st.ids,
                            &st.view,
                            &mut st.coalescer,
                        );
                        continue;
                    }
                    other => other.without_conn(),
                },
                #[cfg(all(windows, feature = "local"))]
                ListenerRuntime::Pipe(l) => match l.accept_or_wake(wake) {
                    Ok(Some(stream)) => {
                        st.skipped = 0;
                        self.admit_pipe(l, stream, conf, &mut st.ids, &st.view, &mut st.coalescer);
                        continue;
                    }
                    // The wake: the top of the loop decides what it meant.
                    Ok(None) => break,
                    // Someone else holds the name now (D-154): this listener is gone,
                    // and pausing would hide that.
                    Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => Accepted::Failed(e),
                    // Out of instances or handles: the same pause as out of descriptors.
                    Err(_) => st.acceptor.pause(),
                },
            };
            // No connection in hand: nothing for a drain to wait for, and what follows
            // may wait for the next connection.
            drop(admitting);
            match outcome {
                Accepted::Conn(()) => {}
                Accepted::Skipped(class) => {
                    shared.event(Event::AcceptError {
                        listener: conf.id,
                        class,
                    });
                    // An error that never consumes a backlog entry (the network
                    // subsystem failing) would otherwise spin: after a batch of them
                    // in a row, pause as for descriptor pressure.
                    st.skipped += 1;
                    if st.skipped >= SKIPS_BEFORE_PAUSE {
                        st.skipped = 0;
                        if let Accepted::Pause(backoff) = st.acceptor.pause() {
                            st.pause_until = Some(self.clock.now() + backoff);
                            break;
                        }
                    }
                }
                Accepted::Again => {
                    st.skipped = 0;
                    // A flood that stopped reports its folded tail now, not at the next
                    // refusal, which may be hours away.
                    if let Some(sink) = &shared.sink {
                        st.coalescer.flush(&**sink);
                    }
                    return BatchEnd::Again;
                }
                Accepted::Pause(backoff) => {
                    shared.descriptor_pressure.fetch_add(1, Ordering::Relaxed);
                    shared.event(Event::DescriptorPressure {
                        listener: conf.id,
                        backoff,
                    });
                    st.pause_until = Some(self.clock.now() + backoff);
                    break;
                }
                Accepted::Failed(e) => {
                    shared.event(Event::ListenerFailed {
                        listener: conf.id,
                        class: OsErrorClass::from_io(&e),
                    });
                    return BatchEnd::Failed;
                }
            }
        }
        BatchEnd::More
    }

    /// A reactor worker's turn on a listener it accepts on itself (D-197): what one
    /// pass of the accept thread's loop does, without waiting. Admitted connections
    /// go to this worker's own inbox, which it takes after the batch, so no wake
    /// crosses threads. The gate runs here, on the worker.
    #[cfg(feature = "reactor")]
    pub(crate) fn worker_accept(
        &self,
        conf: &Arc<ListenerConf>,
        rt: &ListenerRuntime,
        idx: usize,
        st: &mut AcceptState,
    ) -> WorkerAccept {
        let shared = &self.shared;
        if shared.stopping.load(Ordering::Acquire) || conf.removed.load(Ordering::Acquire) {
            return WorkerAccept::Gone;
        }
        if st.view.refresh(shared.control.as_ref()) {
            shared.event(Event::ControlReacted {
                state: st.view.state(),
            });
            match st.view.state() {
                ControlState::Draining => {
                    shared.close_door();
                    shared.request_stop(st.view.deadline());
                    // An accept thread runs the drain itself; a worker cannot wait in
                    // it, so one thread does, once.
                    if !shared.control_drain.swap(true, Ordering::AcqRel) {
                        let deadline = st
                            .view
                            .deadline()
                            .unwrap_or_else(|| Instant::now() + shared.drain_timeout);
                        let s = shared.clone();
                        let _ = std::thread::Builder::new()
                            .name(String::from("net-io-drain"))
                            .spawn(move || {
                                let _ = s.drain(deadline);
                            });
                    }
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
        if !accepting(shared, conf) {
            return WorkerAccept::Park;
        }
        if let Some(until) = st.pause_until {
            if self.clock.now() < until {
                return WorkerAccept::Paused(until);
            }
            st.pause_until = None;
        }
        FEEDS.with(|f| f.set(Some((idx, true))));
        let end = self.accept_some(conf, rt, st, &conf.wake.0[0]);
        FEEDS.with(|f| f.set(None));
        match end {
            BatchEnd::Again => WorkerAccept::Armed,
            BatchEnd::Failed => WorkerAccept::Gone,
            BatchEnd::More => match st.pause_until {
                Some(until) => WorkerAccept::Paused(until),
                None if !accepting(shared, conf) => WorkerAccept::Park,
                None => WorkerAccept::Kick,
            },
        }
    }

    /// The door is open for `conf` and no drain runs (a parked listener's check).
    #[cfg(feature = "reactor")]
    pub(crate) fn accepting(&self, conf: &ListenerConf) -> bool {
        accepting(&self.shared, conf)
    }
}

impl<W, G: Gate> Engine<W, G> {
    fn refuse(
        &self,
        stream: sys::Stream,
        peer: Option<SocketAddr>,
        cause: RefusalCause,
        bytes: Option<&[u8]>,
        co: &mut Coalescer,
    ) {
        let shared = &self.shared;
        // Counted before the peer can see the refusal, so `stats` already shows it
        // to a client that saw the reset or the FIN.
        shared.refused.fetch_add(1, Ordering::Relaxed);
        shared.refused_by[cause.index()].fetch_add(1, Ordering::Relaxed);
        let mut sent = false;
        if let Some(b) = bytes {
            let max = usize::from(self.limits.refusal_bytes_max);
            if b.len() <= max {
                sent = sys::send(&stream, b).is_ok_and(|n| n > 0);
            }
        }
        if sent && !self.limits.denial_linger.is_zero() {
            // The reply is followed by FIN, not a reset, which could destroy it before
            // the peer reads it (D-182). The accept thread does not linger: nothing is
            // read, and input the peer already sent still turns the close into a reset.
            let _ = stream.shutdown(std::net::Shutdown::Write);
        } else {
            let _ = sys::set_linger(stream.sock(), Some(Duration::ZERO));
        }
        drop(stream);
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

    /// An AF_UNIX client on Windows: no address, so no per-source cap.
    #[cfg(all(windows, feature = "local"))]
    fn admit_af_unix(
        &self,
        listener: &crate::local_windows::UnixListener,
        stream: TcpStream,
        conf: &Arc<ListenerConf>,
        ids: &mut IdBlock,
        view: &ControlView,
        co: &mut Coalescer,
    ) {
        let next = &mut || ids.issue();
        let stage = AdmitStage::Accept;
        let _ = self.admit_one(
            sys::Stream::Tcp(stream),
            None,
            None,
            conf,
            next,
            view,
            co,
            stage,
            |stream, cid, at| stream.tcp().map(|s| listener.info_of(s, cid, at)),
        );
    }

    /// A named pipe client: no address, so no per-source cap.
    #[cfg(all(windows, feature = "local"))]
    fn admit_pipe(
        &self,
        listener: &crate::pipe::PipeListener,
        stream: sys::PipeStream,
        conf: &Arc<ListenerConf>,
        ids: &mut IdBlock,
        view: &ControlView,
        co: &mut Coalescer,
    ) {
        let stream = sys::Stream::Pipe(stream);
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
            |stream, cid, at| match stream {
                sys::Stream::Pipe(p) => Some(listener.info_of(p, cid, at)),
                _ => None,
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
        // The server's cap, whatever the listener's limits say (a listener has
        // `max_per_listener`; its own `max_connections` is refused at build).
        if !take_slot(&shared.open, shared.max_open) {
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
        shared.update_pressure();
        let release = |s: &Self| s.shared.release(conf, source);
        if matches!(view.state(), ControlState::Lockdown) && !conf.lockdown_allowed {
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
        // What is left must cover what the more important lanes keep for themselves.
        let reserved = lim.reserved_above(info.lane);
        if reserved > 0
            && shared.open.load(Ordering::Acquire).saturating_add(reserved) > shared.max_open
        {
            let _ = guarded(|| {
                self.gate.closed(
                    ticket,
                    &info,
                    CloseReason::Refused(RefusalCause::LaneReserve),
                )
            });
            release(self);
            self.refuse(stream, peer, RefusalCause::LaneReserve, None, co);
            return Err(Some(RefusalCause::LaneReserve));
        }
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
        let (event_id, event_lane) = (job.info.id, job.info.lane);
        if let Err(job) = self.hand_over(job) {
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
            self.refuse(stream, peer, RefusalCause::Busy, None, co);
            return Err(Some(RefusalCause::Busy));
        }
        shared.accepted.fetch_add(1, Ordering::Relaxed);
        // `Accepted` and `Admitted` come from the worker that takes the job
        // (`announce`): from here, it could close the connection before they went out.
        let _ = (peer, event_lane);
        Ok(event_id)
    }

    #[allow(clippy::result_large_err)]
    fn hand_over(&self, job: Job<G::Ticket>) -> Result<(), Job<G::Ticket>> {
        #[cfg(feature = "reactor")]
        if self.shared.reactor {
            return self.hand_to_worker(job);
        }
        let shared = &self.shared;
        let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        let busy = shared.busy.load(Ordering::Acquire) as usize;
        if queue.len() + busy >= shared.workers.len() {
            return Err(job);
        }
        queue.push_back(job);
        shared.queue_len.store(queue.len(), Ordering::Release);
        drop(queue);
        self.queue_cv.notify_one();
        Ok(())
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
pub trait Serve: Send + Sync + Sized + 'static {
    /// Whether this workload needs a thread per connection (a blocking handler).
    const BLOCKING_ONLY: bool;

    /// Whether this server has no TCP work at all.
    const UDP_ONLY: bool = false;

    /// Serves one admitted connection on a worker.
    fn serve<G: Gate>(&self, w: &mut Worker<G>, job: Job<G::Ticket>);

    /// One worker thread. The reactor runs sessions its own way.
    #[allow(private_interfaces)]
    fn run_worker<G: Gate>(engine: &Arc<Engine<Self, G>>, idx: usize) {
        worker_loop(engine, idx);
    }
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
    /// A job's slots are taken and `end` has not given them back yet.
    holding: bool,
}

fn worker_loop<W: Serve, G: Gate>(engine: &Arc<Engine<W, G>>, idx: usize) {
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
        holding: false,
    };
    while let Some(job) = engine.next_job() {
        let (listener, source, info) = (job.listener.clone(), job.source, job.info.clone());
        w.holding = true;
        let served = guarded(|| engine.work.serve(&mut w, job)).is_some();
        if w.holding {
            // The job ended without `end`: a panic got past every inner boundary
            // (the gate, the session, the TLS engine, and the event sink each have
            // their own), or the link left the connection. The socket is already
            // closed; what it held goes back, so the caps, `busy`, and any drain stay
            // right and the worker serves the next job.
            let reason = if served {
                CloseReason::SessionError
            } else {
                CloseReason::SessionPanicked
            };
            w.abandon(&info, &listener, source, reason);
        }
        w.holding = false;
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
        let lim = *link.limits;
        let Some(cin) = self.pool.take(lim.read_class_max) else {
            return Err(CloseReason::Limit(crate::error::LimitKind::BufferBudget));
        };
        let Some(cout) = self.pool.take(SizeClass::LARGE) else {
            self.pool.put(cin);
            return Err(CloseReason::Limit(crate::error::LimitKind::BufferBudget));
        };
        if let Some(ahead) = link.attach_tls(session, cin, cout) {
            self.pool.put(ahead);
        }
        link.set_deadline_scale(self.shared.deadline_scale());
        link.begin_handshake(link.info.accepted_at + link.scaled(lim.handshake_timeout));
        let r = link.tls_handshake();
        let _ = link.end_handshake(None);
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
        if !proxy.is_trusted(&link.info) {
            return Err(CloseReason::ProxyUntrusted);
        }
        let lim = *link.limits;
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
        link.set_deadline_scale(self.shared.deadline_scale());
        link.begin_handshake(link.info.accepted_at + link.scaled(lim.handshake_timeout));
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
                if let Some(b) = link.end_handshake(Some((buf, usize::MAX))) {
                    self.pool.put(b);
                }
                return Err(reason);
            }
        };
        if let Some(b) = link.end_handshake(Some((buf, consumed))) {
            self.pool.put(b);
        }
        proxy_resolved(
            &self.shared,
            link,
            listener,
            source,
            facts,
            real,
            &mut self.facts_pool,
        )
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
        let limits = listener.limits.clone();
        info.worker = WorkerId(self.idx as u16);
        announce(&shared, &info, &listener);
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
        link.set_soft_closes(&shared.soft_closes);
        ws.current.store(link.info.id.get(), Ordering::Release);
        if self.gated {
            link.gate = Some(cell as Box<dyn ErasedGate>);
        } else {
            self.gate_cell = Some(cell);
        }
        // Queued before its listener was removed, or before a stop: close it unread.
        let failed = if listener.removed.load(Ordering::Acquire) {
            Some(CloseReason::Drained)
        } else if self.shared.stopping.load(Ordering::Acquire) {
            Some(CloseReason::Shutdown)
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
        count_drained(&shared, reason);
        self.holding = false;
        shared.release(&listener, source);
        record_close(&shared, ws, &info, reason, bytes_in, bytes_out, lifetime);
        shared.busy.fetch_sub(1, Ordering::AcqRel);
        shared.notify_progress();
        (info, reason)
    }

    fn draining(&self) -> bool {
        self.shared.draining.load(Ordering::Acquire)
    }

    /// `end` for a job whose link was lost to a panic or left the connection.
    fn abandon(
        &mut self,
        info: &ConnectionInfo,
        listener: &ListenerConf,
        source: Option<PrefixKey>,
        reason: CloseReason,
    ) {
        let shared = self.shared.clone();
        let ws = &shared.workers[self.idx];
        self.output.reset();
        self.input_buf = None;
        if self.gate_cell.is_none() {
            self.gate_cell = Some(Box::new(GateCell {
                gate: self.gate.clone(),
                ticket: None,
            }));
        }
        ws.current.store(0, Ordering::Release);
        ws.listener.store(NO_LISTENER, Ordering::Release);
        count_drained(&shared, reason);
        shared.release(listener, source);
        let lifetime = self.clock.now().saturating_duration_since(info.accepted_at);
        record_close(&shared, ws, info, reason, 0, 0, lifetime);
        shared.busy.fetch_sub(1, Ordering::AcqRel);
        shared.notify_progress();
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
    const BLOCKING_ONLY: bool = true;

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

#[cfg(feature = "udp")]
impl Serve for super::UdpOnly {
    // The pool never gets a job: there is nothing for a reactor to run.
    const BLOCKING_ONLY: bool = true;
    const UDP_ONLY: bool = true;

    fn serve<G: Gate>(&self, _w: &mut Worker<G>, _job: Job<G::Ticket>) {}
}

impl<F: SessionFactory> Serve for Sessions<F> {
    const BLOCKING_ONLY: bool = false;

    #[cfg(feature = "reactor")]
    #[allow(private_interfaces)]
    fn run_worker<G: Gate>(engine: &Arc<Engine<Self, G>>, idx: usize) {
        if engine.shared.reactor {
            super::reactor::run(engine, idx);
        } else {
            worker_loop(engine, idx);
        }
    }

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

/// Counts one close and tells the event sink. Both drivers end here.
/// Counts a close for a running drain's report. Before the connection is released:
/// a drain ends when the last one is, and reads its report then.
/// The events of a connection's start, sent by the worker that took it, before
/// anything that worker does with it.
pub(crate) fn announce(shared: &Shared, info: &ConnectionInfo, listener: &ListenerConf) {
    shared.event(Event::Accepted {
        id: info.id,
        peer: info.peer.socket_addr(),
        listener: listener.id,
    });
    shared.event(Event::Admitted {
        id: info.id,
        lane: info.lane,
    });
}

pub(crate) fn count_drained(shared: &Shared, reason: CloseReason) {
    if shared.draining.load(Ordering::Acquire) {
        if reason == CloseReason::DrainDeadline {
            shared.drained_killed.fetch_add(1, Ordering::Relaxed);
        } else {
            shared.drained_graceful.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub(crate) fn record_close(
    shared: &Shared,
    ws: &WorkerShared,
    info: &ConnectionInfo,
    reason: CloseReason,
    bytes_in: u64,
    bytes_out: u64,
    lifetime: Duration,
) {
    // Single writer: plain load and store, inside the sequence lock.
    let st = &ws.stats;
    let bump = |c: &AtomicU64, n: u64| c.store(c.load(Ordering::Relaxed) + n, Ordering::Relaxed);
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
        CloseReason::EgressDenied(code) => shared.event(Event::EgressDenied { id: info.id, code }),
        CloseReason::Killed(k) => shared.event(Event::Killed {
            id: info.id,
            reason: k,
        }),
        CloseReason::SessionPanicked => shared.event(Event::SessionPanicked { id: info.id }),
        _ => {}
    }
    shared.event(Event::Closed {
        id: info.id,
        reason,
        bytes_in,
        bytes_out,
        lifetime,
    });
}

/// A valid PROXY header arrived (the handshake is over): the real client takes
/// over the per-source slot, the facts land on the connection, and the gate
/// admits again. Both drivers end here.
#[cfg(feature = "proxy")]
pub(crate) fn proxy_resolved(
    shared: &Shared,
    link: &mut Link,
    listener: &ListenerConf,
    source: &mut Option<PrefixKey>,
    facts: ProxyFacts,
    real: Option<SocketAddr>,
    facts_pool: &mut Vec<Arc<ProxyFacts>>,
) -> Result<(), CloseReason> {
    let lim = *link.limits;
    // LOCAL (the proxy itself) and UNKNOWN keep the socket's addresses.
    if let Some(real) = real {
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
    }
    let mut arc = facts_pool
        .pop()
        .unwrap_or_else(|| Arc::new(ProxyFacts::default()));
    if let Some(f) = Arc::get_mut(&mut arc) {
        *f = facts;
    } else {
        arc = Arc::new(facts);
    }
    link.info.proxy = Some(arc);
    if let Some(real) = link.info.real_peer {
        let readmitted = match link.gate.as_mut() {
            Some(g) => g.readmit(&link.info),
            None => Ok(()),
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
    link.hear_drains();
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
                link.set_deadline_scale(w.shared.deadline_scale());
                link.set_rescales();
                let idle = link.phase() == Phase::Idle && input.bytes().is_empty();
                // A request that already arrived is answered before the drain closes,
                // and a fresh connection may still bring its first one.
                if w.draining()
                    && idle
                    && !link.drain_kept()
                    && !link.input_waiting()
                    && !link.awaits_first_request()
                {
                    match drain_reached(w, link, s) {
                        Ok(next) => step = next,
                        Err(reason) => return reason,
                    }
                    continue;
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
                    // The wake channel fired: a post for this connection (serve-net
                    // request 7) reaches the session now; a drain, a kill, or the
                    // control line is seen at the top of the loop.
                    Ok(Got::Woken) => {
                        if link.take_drain_reached() {
                            match drain_reached(w, link, s) {
                                Ok(next) => step = next,
                                Err(reason) => return reason,
                            }
                        } else if let Some((token, value)) = take_post(w, link) {
                            match call(w, link, s, |s, cx| s.on_wake(cx, token, value)).0 {
                                Some(next) => step = next,
                                None => return CloseReason::SessionPanicked,
                            }
                        }
                    }
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

/// A drain reached the connection between exchanges: the session's `on_drain`
/// decides, once. `Close` flushes what it queued and closes with `Drained`; any other
/// step keeps the connection through the drain (its deadline still bounds it).
fn drain_reached<G: Gate, S: Session>(
    w: &mut Worker<G>,
    link: &mut Link,
    s: &mut S,
) -> Result<Step, CloseReason> {
    match call(w, link, s, |s, cx| s.on_drain(cx)).0 {
        None => Err(CloseReason::SessionPanicked),
        Some(Step::Close) => {
            flush(w, link, s)?;
            Err(CloseReason::Drained)
        }
        Some(next) => {
            link.keep_through_drain();
            Ok(next)
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
    // Read and cleared on every flush: only a step that queued nothing because the
    // budget refused it closes here.
    if w.output.take_refused() && w.output.is_empty() {
        // Nothing to send because the buffer budget is spent: calling the session
        // back now would spin the worker.
        return Err(CloseReason::Limit(crate::error::LimitKind::BufferBudget));
    }
    while !w.output.is_empty() {
        link.response_started = if w.output.response_open {
            w.output.bytes_since_begin > 0
        } else {
            link.bytes_out > 0
        };
        link.response_tag = w.output.response_tag;
        let result = if let Some((file, offset, left)) = w.output.front_file() {
            link.send_file(&file, offset, left).map(|n| n as usize)
        } else {
            let mut slices = [IoSlice::new(&[]); 64];
            let mut k = 0;
            for chunk in w
                .output
                .chunks
                .iter()
                .take(slices.len())
                .take_while(|c| !c.is_file())
            {
                slices[k] = IoSlice::new(chunk.remaining());
                k += 1;
            }
            link.write_vectored(&slices[..k])
        };
        match result {
            Ok(n) => {
                w.output.advance(n);
                w.output.return_spares(&mut w.pool);
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
/// The next post for this connection; posts for an earlier connection of the
/// worker are counted stale and dropped.
fn take_post<G: Gate>(w: &Worker<G>, link: &Link) -> Option<(u32, u64)> {
    let shared = &w.shared;
    let ws = &shared.workers[w.idx];
    // A swap, so a producer that saw the flag set cannot push after the ring was
    // found empty and leave its post unannounced.
    ws.completer.wake_pending.swap(false, Ordering::AcqRel);
    while let Some(p) = ws.completer.ring.pop() {
        if p.connection == link.info.id {
            return Some((p.token, p.value));
        }
        ws.stats.begin_write();
        ws.stats.stale_completions.fetch_add(1, Ordering::Relaxed);
        ws.stats.end_write();
        shared.event(Event::StaleCompletion {
            worker: WorkerId(w.idx as u16),
        });
    }
    None
}

fn park<G: Gate>(w: &mut Worker<G>, link: &mut Link, until: Option<Instant>) -> Parked {
    let deadline = until.unwrap_or_else(|| link.now() + link.limits.park_timeout);
    loop {
        if let Some((token, value)) = take_post(w, link) {
            return Parked::Wake(token, value);
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
