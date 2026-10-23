//! The per-worker completion queue: other threads hand results back to a parked connection.

use std::fmt;
use std::sync::Arc;

#[cfg(loom)]
use loom::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
#[cfg(not(loom))]
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::id::{ConnectionId, WorkerId};

/// Why a post was refused.
///
/// ```
/// assert_eq!(net_io::PostError::Full.to_string(), "the worker's completion queue is full");
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PostError {
    /// The ring is full; the poster decides what to do (for example answer 503).
    Full,
    /// The connection belongs to another worker.
    WrongWorker,
    /// The server has stopped.
    ServerStopped,
}

impl fmt::Display for PostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PostError::Full => "the worker's completion queue is full",
            PostError::WrongWorker => "the connection belongs to another worker",
            PostError::ServerStopped => "the server has stopped",
        })
    }
}

impl std::error::Error for PostError {}

/// One posted completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Posted {
    pub connection: ConnectionId,
    pub token: u32,
    pub value: u64,
}

struct Slot {
    seq: AtomicUsize,
    id: AtomicU64,
    token: AtomicU64,
    value: AtomicU64,
}

/// A bounded multi-producer, single-consumer ring (Vyukov's bounded queue):
/// one sequence number per slot, no allocation after creation, never blocks.
pub(crate) struct Ring {
    slots: Box<[Slot]>,
    mask: usize,
    head: AtomicUsize,
    tail: AtomicUsize,
}

impl Ring {
    /// A ring of `capacity` rounded up to a power of two (at least 1).
    pub(crate) fn new(capacity: usize) -> Ring {
        let cap = capacity.max(1).next_power_of_two();
        let slots = (0..cap)
            .map(|i| Slot {
                seq: AtomicUsize::new(i),
                id: AtomicU64::new(0),
                token: AtomicU64::new(0),
                value: AtomicU64::new(0),
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Ring {
            slots,
            mask: cap - 1,
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    pub(crate) fn capacity(&self) -> usize {
        self.mask + 1
    }

    /// Pushes from any thread; `false` when full.
    pub(crate) fn push(&self, item: Posted) -> bool {
        let mut pos = self.tail.load(Ordering::Relaxed);
        loop {
            let slot = &self.slots[pos & self.mask];
            let seq = slot.seq.load(Ordering::Acquire);
            let diff = seq as isize - pos as isize;
            match diff.cmp(&0) {
                std::cmp::Ordering::Equal => match self.tail.compare_exchange_weak(
                    pos,
                    pos.wrapping_add(1),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        slot.id.store(item.connection.get(), Ordering::Relaxed);
                        slot.token.store(u64::from(item.token), Ordering::Relaxed);
                        slot.value.store(item.value, Ordering::Relaxed);
                        slot.seq.store(pos.wrapping_add(1), Ordering::Release);
                        return true;
                    }
                    Err(actual) => pos = actual,
                },
                // The slot still holds an item the consumer has not taken: full.
                std::cmp::Ordering::Less => return false,
                std::cmp::Ordering::Greater => pos = self.tail.load(Ordering::Relaxed),
            }
        }
    }

    /// Pops on the owning thread only.
    pub(crate) fn pop(&self) -> Option<Posted> {
        let pos = self.head.load(Ordering::Relaxed);
        let slot = &self.slots[pos & self.mask];
        let seq = slot.seq.load(Ordering::Acquire);
        if seq != pos.wrapping_add(1) {
            return None;
        }
        let item = Posted {
            connection: ConnectionId::new(slot.id.load(Ordering::Relaxed))?,
            token: slot.token.load(Ordering::Relaxed) as u32,
            value: slot.value.load(Ordering::Relaxed),
        };
        slot.seq
            .store(pos.wrapping_add(self.mask + 1), Ordering::Release);
        self.head.store(pos.wrapping_add(1), Ordering::Relaxed);
        Some(item)
    }

    #[cfg(all(test, not(loom)))]
    pub(crate) fn is_empty(&self) -> bool {
        let pos = self.head.load(Ordering::Relaxed);
        self.slots[pos & self.mask].seq.load(Ordering::Acquire) != pos.wrapping_add(1)
    }
}

/// What a completer needs from the worker that owns it.
pub(crate) trait CompleterTarget: Send + Sync {
    /// Whether `id` is (or was) a connection of this worker.
    fn owns(&self, id: ConnectionId) -> bool;
    /// Wakes the worker.
    fn wake(&self);
    /// Whether the server stopped.
    fn stopped(&self) -> bool;
}

pub(crate) struct CompleterShared {
    pub(crate) ring: Ring,
    pub(crate) wake_pending: AtomicBool,
    pub(crate) target: Arc<dyn CompleterTarget>,
    pub(crate) worker: WorkerId,
}

impl CompleterShared {
    pub(crate) fn new(
        capacity: usize,
        target: Arc<dyn CompleterTarget>,
        worker: WorkerId,
    ) -> CompleterShared {
        CompleterShared {
            ring: Ring::new(capacity),
            wake_pending: AtomicBool::new(false),
            target,
            worker,
        }
    }
}

/// A worker's completion queue, for other threads to hand results back to a
/// connection that returned `Step::Park`.
///
/// # Examples
///
/// ```no_run
/// use net_io::{Input, Session, SessionContext, Step};
///
/// struct Slow;
/// impl Session for Slow {
///     fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
///         let n = input.bytes().len();
///         input.consume(n);
///         let (completer, id) = (cx.completer(), cx.info().id);
///         std::thread::spawn(move || {
///             let _ = completer.post(id, 1, 42);
///         });
///         Step::Park { until: None }
///     }
///     fn on_wake(&mut self, cx: &mut SessionContext<'_>, _token: u32, value: u64) -> Step {
///         let _ = cx.output().push(format!("{value}\n").as_bytes());
///         Step::Write
///     }
/// }
/// ```
#[derive(Clone)]
pub struct Completer {
    pub(crate) shared: Arc<CompleterShared>,
}

impl Completer {
    /// Posts a completion for `connection`. Never blocks.
    ///
    /// # Errors
    ///
    /// [`PostError::Full`], [`PostError::WrongWorker`], [`PostError::ServerStopped`].
    pub fn post(&self, connection: ConnectionId, token: u32, value: u64) -> Result<(), PostError> {
        let s = &self.shared;
        if s.target.stopped() {
            return Err(PostError::ServerStopped);
        }
        if !s.target.owns(connection) {
            return Err(PostError::WrongWorker);
        }
        if !s.ring.push(Posted {
            connection,
            token,
            value,
        }) {
            return Err(PostError::Full);
        }
        // One wake per burst: only the post that finds no wake pending wakes the worker.
        if !s.wake_pending.swap(true, Ordering::AcqRel) {
            s.target.wake();
        }
        Ok(())
    }

    /// The worker this queue belongs to.
    #[must_use]
    pub fn worker(&self) -> WorkerId {
        self.shared.worker
    }

    /// The ring's capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.shared.ring.capacity()
    }
}

impl fmt::Debug for Completer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Completer")
            .field("worker", &self.shared.worker)
            .field("capacity", &self.capacity())
            .finish()
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    fn post(id: u64) -> Posted {
        Posted {
            connection: ConnectionId::new(id).unwrap(),
            token: 1,
            value: id * 10,
        }
    }

    #[test]
    fn test_ring_fifo_and_full() {
        let r = Ring::new(3);
        assert_eq!(r.capacity(), 4);
        for i in 1..=4 {
            assert!(r.push(post(i)));
        }
        assert!(!r.push(post(5)));
        for i in 1..=4 {
            assert_eq!(r.pop(), Some(post(i)));
        }
        assert_eq!(r.pop(), None);
        assert!(r.is_empty());
        assert!(r.push(post(6)));
        assert_eq!(r.pop(), Some(post(6)));
    }

    #[test]
    fn test_ring_many_producers_never_exceeds_capacity() {
        let r = Arc::new(Ring::new(64));
        let handles: Vec<_> = (0..8u64)
            .map(|t| {
                let r = r.clone();
                std::thread::spawn(move || {
                    (0..1000u64)
                        .filter(|i| r.push(post(t * 1000 + i + 1)))
                        .count()
                })
            })
            .collect();
        let pushed: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
        let mut popped = 0;
        while r.pop().is_some() {
            popped += 1;
        }
        assert_eq!(pushed, popped);
        assert!(popped <= 64);
    }
}

#[cfg(all(test, loom))]
mod loom_tests {
    use super::*;

    #[test]
    fn loom_ring_two_producers_one_consumer() {
        loom::model(|| {
            let r = loom::sync::Arc::new(Ring::new(2));
            let mk = |id: u64| Posted {
                connection: ConnectionId::new(id).unwrap(),
                token: 0,
                value: id,
            };
            let r1 = r.clone();
            let t1 = loom::thread::spawn(move || r1.push(mk(1)));
            let r2 = r.clone();
            let t2 = loom::thread::spawn(move || r2.push(mk(2)));
            let mut got = Vec::new();
            for _ in 0..3 {
                if let Some(p) = r.pop() {
                    got.push(p.value);
                }
            }
            let a = t1.join().unwrap();
            let b = t2.join().unwrap();
            while let Some(p) = r.pop() {
                got.push(p.value);
            }
            assert!(a && b);
            got.sort_unstable();
            assert_eq!(got, vec![1, 2]);
        });
    }
}
