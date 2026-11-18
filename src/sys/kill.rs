//! The kill guard (decision D-053).
//!
//! A kill from another thread must wake the connection's owner, which means a
//! system call on the connection's socket (Unix: `shutdown` of the read side) or
//! on a wake channel. The killer must never make that call on a descriptor the
//! owner already closed and the OS reused for something else. The state word's
//! `KILLING` bit keeps the owner from closing while a kill is in flight; the
//! owner's wait is bounded by one system call in the killer.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

#[cfg(not(net_io_loom))]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(net_io_loom)]
use loom::sync::atomic::{AtomicU64, Ordering};

use super::{RawSock, Sock, Wake};
use crate::error::KillReason;

const ACTIVE: u64 = 1;
const CLOSING: u64 = 2;
const KILLED: u64 = 4;
const KILLING: u64 = 8;
/// The owner waits for the next exchange (set and cleared by the owner around the wait).
const IDLE: u64 = 16;
/// A drain shut the read side of the idle connection.
const DRAINED: u64 = 32;
/// With `KILLED`: the kill lets the owner flush first (`Server::close_after_flush`).
/// Reads end, queued output still goes out until the bound, then a graceful close.
/// A hard kill clears it.
const SOFT: u64 = 64;
/// With `DRAINED`: the mark is a shed (`ControlState::Shed`), not a drain, so a
/// connection that has not brought its first request yet closes too.
const SHED: u64 = 128;
const REASON_SHIFT: u32 = 16;
const GEN_SHIFT: u32 = 32;

fn gen_of(state: u64) -> u32 {
    (state >> GEN_SHIFT) as u32
}

/// Hears kills for a reactor worker: the connection's table index goes on the
/// worker's list and its loop wakes.
pub(crate) trait KillSink: Send + Sync + std::fmt::Debug {
    fn killed(&self, index: u32);
}

/// One connection's kill state: generation, flags, the kill reason, the raw socket,
/// and the wake channel its owner waits on.
#[derive(Debug)]
pub(crate) struct KillSlot {
    state: AtomicU64,
    raw: AtomicU64,
    /// A soft kill's bound in microseconds, written before its `KILLED | SOFT`.
    soft_bound: AtomicU64,
    /// The server's soft-close places (`Limits::denial_linger_max`), set once for a
    /// slot a server's worker owns.
    soft_closes: std::sync::OnceLock<Arc<crate::link::SoftCloses>>,
    wake: Mutex<Option<Arc<Wake>>>,
    sink: Mutex<Option<(Arc<dyn KillSink>, u32)>>,
}

impl KillSlot {
    pub(crate) fn new() -> KillSlot {
        KillSlot {
            state: AtomicU64::new(0),
            raw: AtomicU64::new(0),
            soft_bound: AtomicU64::new(0),
            soft_closes: std::sync::OnceLock::new(),
            wake: Mutex::new(None),
            sink: Mutex::new(None),
        }
    }

    /// Where a reactor worker hears about kills of this connection.
    #[cfg_attr(not(feature = "reactor"), allow(dead_code))]
    pub(crate) fn set_sink(&self, sink: Arc<dyn KillSink>, index: u32) {
        *self.sink.lock().unwrap_or_else(PoisonError::into_inner) = Some((sink, index));
    }

    fn tell_sink(&self) {
        let sink = self
            .sink
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some((sink, index)) = sink {
            sink.killed(index);
        }
    }

    /// Starts a new connection in this slot and returns its generation.
    pub(crate) fn install(&self, sock: Sock<'_>) -> u32 {
        self.raw
            .store(super::raw_of(sock) as u64, Ordering::Relaxed);
        let generation = gen_of(self.state.load(Ordering::Relaxed)).wrapping_add(1);
        self.state.store(
            (u64::from(generation) << GEN_SHIFT) | ACTIVE,
            Ordering::Release,
        );
        generation
    }

    /// The wake channel the owner waits on (a worker sets it once; a standalone
    /// connection sets it around each wait).
    pub(crate) fn set_wake(&self, wake: Option<Arc<Wake>>) {
        *self.wake.lock().unwrap_or_else(PoisonError::into_inner) = wake;
    }

    /// The current generation.
    pub(crate) fn generation(&self) -> u32 {
        gen_of(self.state.load(Ordering::Acquire))
    }

    /// Whether the connection of `generation` is still open and not killed.
    pub(crate) fn is_open(&self, generation: u32) -> bool {
        let s = self.state.load(Ordering::Acquire);
        gen_of(s) == generation && s & ACTIVE != 0 && s & (CLOSING | KILLED) == 0
    }

    /// The kill reason, once the connection was killed.
    pub(crate) fn killed(&self) -> Option<KillReason> {
        let s = self.state.load(Ordering::Acquire);
        (s & KILLED != 0).then_some(KillReason(((s >> REASON_SHIFT) & 0xFFFF) as u16))
    }

    /// A server's slot: where its connections take a place for a soft close.
    pub(crate) fn set_soft_closes(&self, places: &Arc<crate::link::SoftCloses>) {
        let _ = self.soft_closes.get_or_init(|| places.clone());
    }

    /// The soft-close places, for a server's slot.
    pub(crate) fn soft_closes(&self) -> Option<&Arc<crate::link::SoftCloses>> {
        self.soft_closes.get()
    }

    /// The bound of a soft kill (`close_after_flush`), while it is not upgraded.
    pub(crate) fn soft_kill(&self) -> Option<Duration> {
        let s = self.state.load(Ordering::Acquire);
        (s & (KILLED | SOFT) == KILLED | SOFT)
            .then(|| Duration::from_micros(self.soft_bound.load(Ordering::Relaxed)))
    }

    /// A kill that lets the owner flush first: reads end, output already queued goes
    /// out until `bound`, then FIN and a linger bounded by what is left of it. Only
    /// the owner is woken: the socket is not shut, so a linger can still read the
    /// peer's FIN (an owner without a wake channel has its read side shut, as for a
    /// kill). Returns `false` if it already closed, is closing, or was killed.
    pub(crate) fn kill_soft(&self, generation: u32, reason: KillReason, bound: Duration) -> bool {
        let mut s = self.state.load(Ordering::Acquire);
        loop {
            if gen_of(s) != generation || s & ACTIVE == 0 || s & (CLOSING | KILLED) != 0 {
                return false;
            }
            if s & KILLING != 0 {
                std::hint::spin_loop();
                s = self.state.load(Ordering::Acquire);
                continue;
            }
            let micros = u64::try_from(bound.as_micros()).unwrap_or(u64::MAX);
            self.soft_bound.store(micros, Ordering::Relaxed);
            let new = (s & !(0xFFFF << REASON_SHIFT))
                | KILLED
                | KILLING
                | SOFT
                | (u64::from(reason.0) << REASON_SHIFT);
            match self
                .state
                .compare_exchange_weak(s, new, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(actual) => s = actual,
            }
        }
        let raw = self.raw.load(Ordering::Relaxed) as RawSock;
        let wake = self
            .wake
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let reactor = self
            .sink
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some();
        // A pool owner inside an exchange on a system that receives without waiting
        // first (Linux) is in a blocking receive the wake channel cannot end: its read
        // side is shut, as for a kill (the exchange is cut either way; output still
        // goes out), and so is an owner with no way to be woken. A reactor hears it
        // through its sink; everyone else is woken. Both linger with the read side open.
        let blocked = !super::WAIT_BEFORE_RECV && s & IDLE == 0;
        if !reactor && (wake.is_none() || blocked) {
            // SAFETY: the KILLING bit is set; the owner's `begin_close` waits for it to
            // clear before it closes the socket, so `raw` is open for this call.
            unsafe { super::shutdown_read_raw(raw) };
        }
        if let Some(w) = wake {
            w.wake();
        }
        self.tell_sink();
        self.state.fetch_and(!KILLING, Ordering::Release);
        true
    }

    /// Kills the connection of `generation`: sets the flag, wakes the owner.
    /// Returns `false` if it already closed, is closing, or was already killed
    /// (a soft kill is upgraded: the owner stops flushing and closes with a reset).
    pub(crate) fn kill(&self, generation: u32, reason: KillReason) -> bool {
        self.kill_with(generation, reason, |raw, wake| {
            // SAFETY: the KILLING bit is set; the owner's `begin_close` waits for it to
            // clear before it closes the socket, so `raw` is open for this call.
            unsafe { super::shutdown_read_raw(raw) };
            if let Some(w) = wake {
                w.wake();
            }
            self.tell_sink();
        })
    }

    pub(crate) fn kill_with(
        &self,
        generation: u32,
        reason: KillReason,
        action: impl FnOnce(RawSock, Option<Arc<Wake>>),
    ) -> bool {
        let mut s = self.state.load(Ordering::Acquire);
        loop {
            let upgrade = s & (KILLED | SOFT) == KILLED | SOFT;
            if gen_of(s) != generation
                || s & ACTIVE == 0
                || s & CLOSING != 0
                || (s & KILLED != 0 && !upgrade)
            {
                return false;
            }
            if s & KILLING != 0 {
                // A drain's shutdown is in flight (one system call): its guard must
                // clear before this kill takes it.
                std::hint::spin_loop();
                s = self.state.load(Ordering::Acquire);
                continue;
            }
            let new = (s & !((0xFFFF << REASON_SHIFT) | SOFT))
                | KILLED
                | KILLING
                | (u64::from(reason.0) << REASON_SHIFT);
            match self
                .state
                .compare_exchange_weak(s, new, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(actual) => s = actual,
            }
        }
        let raw = self.raw.load(Ordering::Relaxed) as RawSock;
        let wake = self
            .wake
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        action(raw, wake);
        self.state.fetch_and(!KILLING, Ordering::Release);
        true
    }

    /// The owner marks the wait for the next exchange (`true` before, `false` after).
    #[inline]
    pub(crate) fn set_idle(&self, idle: bool) {
        if idle {
            self.state.fetch_or(IDLE, Ordering::AcqRel);
        } else {
            self.state.fetch_and(!IDLE, Ordering::AcqRel);
        }
    }

    /// A drain closes an idle connection: when the connection of `generation` is
    /// waiting for its next exchange, shut its read side (Unix; Windows uses the
    /// wake channel alone) under the same guard as a kill, and wake its owner, who
    /// then closes it with `Drained`. A reply already in progress still goes out:
    /// writes are untouched. Returns `false` when the
    /// connection is not idle, already drained, killed, or closing.
    pub(crate) fn drain_idle(&self, generation: u32) -> bool {
        self.mark_idle(generation, DRAINED)
    }

    /// As `drain_idle`, for a shed: the owner closes it even before its first request.
    pub(crate) fn shed_idle(&self, generation: u32) -> bool {
        self.mark_idle(generation, DRAINED | SHED)
    }

    fn mark_idle(&self, generation: u32, mark: u64) -> bool {
        let mut s = self.state.load(Ordering::Acquire);
        loop {
            if gen_of(s) != generation
                || s & (ACTIVE | IDLE) != (ACTIVE | IDLE)
                || s & (CLOSING | KILLED | KILLING | DRAINED) != 0
            {
                return false;
            }
            match self.state.compare_exchange_weak(
                s,
                s | mark | KILLING,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => s = actual,
            }
        }
        let raw = self.raw.load(Ordering::Relaxed) as RawSock;
        let wake = self
            .wake
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        // An owner with a wake channel is reached through it alone and decides at
        // its wait, where it can see a request that already arrived: a shut read
        // side cannot be opened again, and a drain that saw that request too late
        // would cut it short (D-178). On Windows the cancel would also end a pipe
        // write already reported as sent (D-156). Only an owner without a wake
        // channel has its read side shut (Unix) or its IO cancelled (Windows).
        if wake.is_none() {
            // A request that already arrived is read and answered first: the read
            // side, once shut, stays shut, and the rest of that exchange would read
            // as end of stream. The mark is taken back, and a later pass closes the
            // connection at its next wait (D-176).
            #[cfg(unix)]
            // SAFETY: the KILLING bit is set, so `raw` is open for this call (as below).
            if unsafe { super::input_waiting_raw(raw) } {
                self.state
                    .fetch_and(!(DRAINED | SHED | KILLING), Ordering::Release);
                return false;
            }
            // SAFETY: the KILLING bit is set; the owner's `begin_close` waits for it to
            // clear before it closes the socket, so `raw` is open for this call.
            unsafe { super::shutdown_read_raw(raw) };
        }
        if let Some(w) = wake {
            w.wake();
        }
        self.state.fetch_and(!KILLING, Ordering::Release);
        true
    }

    /// The owner keeps a connection a drain marked (its next request had already
    /// arrived): a later pass may mark it again.
    #[inline]
    pub(crate) fn undrain(&self) {
        self.state.fetch_and(!(DRAINED | SHED), Ordering::AcqRel);
    }

    /// Whether the mark is a shed's.
    #[inline]
    pub(crate) fn shed(&self) -> bool {
        self.state.load(Ordering::Acquire) & SHED != 0
    }

    /// Whether a drain marked this connection.
    #[inline]
    pub(crate) fn drained(&self) -> bool {
        self.state.load(Ordering::Acquire) & DRAINED != 0
    }

    /// The owner is about to close the socket: no kill can start after this, and
    /// a kill in flight finishes first. Returns the kill reason if it was killed.
    pub(crate) fn begin_close(&self) -> Option<KillReason> {
        let s = self.state.fetch_or(CLOSING, Ordering::AcqRel);
        let mut s = s | CLOSING;
        let mut spins = 0u32;
        while s & KILLING != 0 {
            spins += 1;
            if spins < 64 {
                std::hint::spin_loop();
            } else {
                yield_now();
            }
            s = self.state.load(Ordering::Acquire);
        }
        (s & KILLED != 0).then_some(KillReason(((s >> REASON_SHIFT) & 0xFFFF) as u16))
    }

    /// The connection is closed; the slot is free for the next one.
    pub(crate) fn uninstall(&self) {
        let s = self.state.load(Ordering::Acquire);
        self.state
            .store(u64::from(gen_of(s)) << GEN_SHIFT, Ordering::Release);
    }

    /// `begin_close` then `uninstall`, when the connection of `generation` still
    /// holds the slot (its owner's close did not run). Only the owner installs, so
    /// the slot cannot move to another connection between the check and the close.
    fn release(&self, generation: u32) {
        let s = self.state.load(Ordering::Acquire);
        if gen_of(s) != generation || s & ACTIVE == 0 {
            return;
        }
        let _ = self.begin_close();
        self.uninstall();
    }
}

/// A connection's hold on its kill slot, for as long as the connection holds its
/// socket. Declared before the socket in its owner, so it drops first: a close that
/// never ran (a panic unwinding past the owner) still ends the slot before the
/// descriptor closes, and a kill handle kept elsewhere can no longer act on that
/// number once the OS gives it to another socket. The owner's own close uninstalls
/// the slot first, and then this does nothing.
#[derive(Debug)]
pub(crate) struct SlotLease {
    slot: Arc<KillSlot>,
    generation: u32,
}

impl SlotLease {
    /// Holds `slot` for the connection of `generation` (what `install` returned).
    pub(crate) fn new(slot: Arc<KillSlot>, generation: u32) -> SlotLease {
        SlotLease { slot, generation }
    }

    /// The generation the connection holds the slot with, not the slot's current
    /// one (`KillSlot::generation`).
    pub(crate) fn generation(&self) -> u32 {
        self.generation
    }
}

impl std::ops::Deref for SlotLease {
    type Target = Arc<KillSlot>;
    fn deref(&self) -> &Arc<KillSlot> {
        &self.slot
    }
}

impl Drop for SlotLease {
    fn drop(&mut self) {
        self.slot.release(self.generation);
    }
}

#[cfg(not(net_io_loom))]
fn yield_now() {
    std::thread::yield_now();
}

#[cfg(net_io_loom)]
fn yield_now() {
    loom::thread::yield_now();
}

#[cfg(all(test, not(net_io_loom)))]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn test_kill_once_then_false() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let slot = KillSlot::new();
        let generation = slot.install(super::super::AsSock::sock(&l));
        assert!(slot.is_open(generation));
        let mut calls = 0;
        assert!(slot.kill_with(generation, KillReason(7), |_, _| calls += 1));
        assert!(!slot.kill_with(generation, KillReason(8), |_, _| calls += 1));
        assert_eq!(calls, 1);
        assert_eq!(slot.killed(), Some(KillReason(7)));
        assert_eq!(slot.begin_close(), Some(KillReason(7)));
    }

    #[test]
    fn test_soft_kill_is_upgraded_by_a_kill_once() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let slot = KillSlot::new();
        let generation = slot.install(super::super::AsSock::sock(&l));
        slot.set_wake(Some(Arc::new(Wake::new().unwrap())));
        assert!(slot.kill_soft(generation, KillReason(3), Duration::from_millis(250)));
        assert!(!slot.kill_soft(generation, KillReason(4), Duration::from_secs(1)));
        assert_eq!(slot.killed(), Some(KillReason(3)));
        assert_eq!(slot.soft_kill(), Some(Duration::from_millis(250)));
        assert!(!slot.is_open(generation));
        let mut calls = 0;
        assert!(slot.kill_with(generation, KillReason(5), |_, _| calls += 1));
        assert!(!slot.kill_with(generation, KillReason(6), |_, _| calls += 1));
        assert_eq!(calls, 1);
        assert_eq!(slot.soft_kill(), None);
        assert_eq!(slot.begin_close(), Some(KillReason(5)));
    }

    #[test]
    fn test_kill_wrong_generation_or_closing_refused() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let slot = KillSlot::new();
        let generation = slot.install(super::super::AsSock::sock(&l));
        assert!(!slot.kill_with(generation + 1, KillReason(1), |_, _| {}));
        assert_eq!(slot.begin_close(), None);
        assert!(!slot.kill_with(generation, KillReason(1), |_, _| {}));
        slot.uninstall();
        let next = slot.install(super::super::AsSock::sock(&l));
        assert_eq!(next, generation + 1);
        assert!(!slot.kill_with(generation, KillReason(1), |_, _| {}));
    }

    #[test]
    fn test_drain_only_touches_an_idle_connection_once() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let slot = KillSlot::new();
        let generation = slot.install(super::super::AsSock::sock(&l));
        assert!(!slot.drain_idle(generation), "busy: not drained");
        slot.set_idle(true);
        assert!(!slot.drain_idle(generation + 1), "wrong generation");
        assert!(slot.drain_idle(generation));
        assert!(!slot.drain_idle(generation), "once");
        assert!(slot.drained());
        assert_eq!(slot.killed(), None, "a drain is not a kill");
        assert!(
            slot.kill_with(generation, KillReason(2), |_, _| {}),
            "a kill still works"
        );
        slot.set_idle(false);
        assert_eq!(slot.begin_close(), Some(KillReason(2)));
    }

    /// A drain leaves an idle connection whose next request already arrived: its
    /// read side stays open, so the whole exchange can be read; once the input is
    /// read, the drain goes through (D-176, a Linux pool race seen in CI).
    #[cfg(unix)]
    #[test]
    fn test_drain_leaves_a_connection_with_input_waiting() {
        use std::io::{Read, Write};
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peer = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (mut conn, _) = l.accept().unwrap();
        let slot = KillSlot::new();
        let generation = slot.install(super::super::AsSock::sock(&conn));
        slot.set_idle(true);
        peer.write_all(b"req").unwrap();
        let raw = super::super::raw_of(super::super::AsSock::sock(&conn));
        let waited = std::time::Instant::now();
        // SAFETY: `conn` is open for the whole loop.
        while !unsafe { super::super::input_waiting_raw(raw) } {
            assert!(waited.elapsed() < std::time::Duration::from_secs(5));
            std::thread::yield_now();
        }
        assert!(!slot.drain_idle(generation), "input waiting: left alone");
        assert!(!slot.drained());
        let mut b = [0u8; 3];
        conn.read_exact(&mut b).unwrap();
        peer.write_all(b"rest").unwrap();
        let mut rest = [0u8; 4];
        conn.read_exact(&mut rest).expect("read side still open");
        assert!(slot.drain_idle(generation), "nothing waiting: drained");
        assert!(slot.drained());
    }

    /// A lease dropped without its owner's close (a panic unwinding past it) ends
    /// the slot: a kill for that connection is refused from then on. One dropped
    /// after the owner's close, or after the next connection took the slot, leaves
    /// the slot alone.
    #[test]
    fn test_lease_dropped_without_a_close_ends_the_slot() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let slot = Arc::new(KillSlot::new());
        let generation = slot.install(super::super::AsSock::sock(&l));
        drop(SlotLease::new(slot.clone(), generation));
        assert!(!slot.is_open(generation));
        assert!(!slot.kill_with(generation, KillReason(1), |_, _| {}));

        let next = slot.install(super::super::AsSock::sock(&l));
        let stale = SlotLease::new(slot.clone(), generation);
        drop(stale);
        assert!(
            slot.is_open(next),
            "an old lease does not end the next connection"
        );
        let lease = SlotLease::new(slot.clone(), next);
        assert_eq!(slot.begin_close(), None);
        slot.uninstall();
        drop(lease);
        assert!(!slot.is_open(next));
    }

    #[test]
    fn test_kill_from_many_threads_exactly_one_wins() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let slot = Arc::new(KillSlot::new());
        let generation = slot.install(super::super::AsSock::sock(&l));
        let winners: usize = (0..64)
            .map(|i| {
                let slot = slot.clone();
                std::thread::spawn(move || {
                    usize::from(slot.kill_with(generation, KillReason(i), |_, _| {}))
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .sum();
        assert_eq!(winners, 1);
    }
}

#[cfg(all(test, net_io_loom))]
mod loom_tests {
    use super::*;
    use loom::sync::atomic::AtomicBool;

    #[test]
    fn loom_kill_never_acts_after_close() {
        loom::model(|| {
            // The rest from `new`, so a field added later cannot break this build.
            let slot = loom::sync::Arc::new(KillSlot {
                state: AtomicU64::new((1 << GEN_SHIFT) | ACTIVE),
                raw: AtomicU64::new(3),
                ..KillSlot::new()
            });
            let closed = loom::sync::Arc::new(AtomicBool::new(false));
            let (s2, c2) = (slot.clone(), closed.clone());
            let killer = loom::thread::spawn(move || {
                s2.kill_with(1, KillReason(1), |_, _| {
                    assert!(!c2.load(Ordering::SeqCst), "kill acted on a closed socket");
                })
            });
            slot.begin_close();
            closed.store(true, Ordering::SeqCst);
            let _ = killer.join().unwrap();
        });
    }

    /// A connection's lease dropped without its owner's close (a panic unwinding past
    /// the owner), then its descriptor number closed and given to the next
    /// connection, which installs in the same slot: a kill for the first connection,
    /// racing all of it, never acts on the number while the next connection owns it.
    #[test]
    fn loom_unwound_lease_keeps_a_stale_kill_off_a_reused_number() {
        loom::model(|| {
            let slot = std::sync::Arc::new(KillSlot {
                state: AtomicU64::new((1 << GEN_SHIFT) | ACTIVE),
                raw: AtomicU64::new(3),
                ..KillSlot::new()
            });
            // Who owns descriptor number 3: connection 1, nobody (0), or 2.
            let owner = loom::sync::Arc::new(loom::sync::atomic::AtomicU32::new(1));
            let (s2, o2) = (slot.clone(), owner.clone());
            let killer = loom::thread::spawn(move || {
                s2.kill_with(1, KillReason(1), |raw, _| {
                    assert_eq!(raw, 3);
                    assert_eq!(
                        o2.load(Ordering::SeqCst),
                        1,
                        "kill acted on a reused number"
                    );
                })
            });
            drop(SlotLease::new(slot.clone(), 1));
            owner.store(0, Ordering::SeqCst);
            owner.store(2, Ordering::SeqCst);
            slot.state
                .store((2 << GEN_SHIFT) | ACTIVE, Ordering::Release);
            let _ = killer.join().unwrap();
        });
    }
}
