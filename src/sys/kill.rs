//! The kill guard (decision D-053).
//!
//! A kill from another thread must wake the connection's owner, which means a
//! system call on the connection's socket (Unix: `shutdown` of the read side) or
//! on a wake channel. The killer must never make that call on a descriptor the
//! owner already closed and the OS reused for something else. The state word's
//! `KILLING` bit keeps the owner from closing while a kill is in flight; the
//! owner's wait is bounded by one system call in the killer.

use std::sync::{Arc, Mutex, PoisonError};

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
    wake: Mutex<Option<Arc<Wake>>>,
    sink: Mutex<Option<(Arc<dyn KillSink>, u32)>>,
}

impl KillSlot {
    pub(crate) fn new() -> KillSlot {
        KillSlot {
            state: AtomicU64::new(0),
            raw: AtomicU64::new(0),
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

    /// Kills the connection of `generation`: sets the flag, wakes the owner.
    /// Returns `false` if it already closed, is closing, or was already killed.
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
            if gen_of(s) != generation || s & ACTIVE == 0 || s & (CLOSING | KILLED) != 0 {
                return false;
            }
            if s & KILLING != 0 {
                // A drain's shutdown is in flight (one system call): its guard must
                // clear before this kill takes it.
                std::hint::spin_loop();
                s = self.state.load(Ordering::Acquire);
                continue;
            }
            let new = (s & !(0xFFFF << REASON_SHIFT))
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
    /// waiting for its next exchange, shut its read side (under the same guard as a
    /// kill) and wake its owner, who then closes it with `Drained`. A reply already
    /// in progress still goes out: writes are untouched. Returns `false` when the
    /// connection is not idle, already drained, killed, or closing.
    pub(crate) fn drain_idle(&self, generation: u32) -> bool {
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
                s | DRAINED | KILLING,
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
        // would cut it short (D-178). Only an owner without a wake channel has its
        // read side shut.
        if wake.is_none() {
            // A request that already arrived is read and answered first; the mark
            // is taken back, and a later pass closes the connection at its next
            // wait (D-176).
            #[cfg(unix)]
            // SAFETY: the KILLING bit is set, so `raw` is open for this call (as below).
            if unsafe { super::input_waiting_raw(raw) } {
                self.state
                    .fetch_and(!(DRAINED | KILLING), Ordering::Release);
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
        self.state.fetch_and(!DRAINED, Ordering::AcqRel);
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
            let slot = loom::sync::Arc::new(KillSlot {
                state: AtomicU64::new((1 << GEN_SHIFT) | ACTIVE),
                raw: AtomicU64::new(3),
                wake: Mutex::new(None),
                sink: Mutex::new(None),
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
}
