//! Connection, listener, and worker identities.

use std::fmt;
use std::num::NonZeroU64;

use std::sync::atomic::{AtomicU64, Ordering};

/// The identity of one connection, unique and never reused within a process.
///
/// Workers take blocks of 1,024 ids from one process-wide counter, so ids are
/// ordered within a worker, not globally.
///
/// # Examples
///
/// ```
/// let id = net_io::ConnectionId::new(42).unwrap();
/// assert_eq!(id.get(), 42);
/// assert!(net_io::ConnectionId::new(0).is_none());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionId(NonZeroU64);

impl ConnectionId {
    /// The id as a number.
    #[inline]
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// An id from a number, for tests and conversions; `None` for 0.
    ///
    /// An id built this way is not reserved: use it only to name a connection
    /// net-io issued, or in tests.
    #[must_use]
    pub const fn new(id: u64) -> Option<ConnectionId> {
        match NonZeroU64::new(id) {
            Some(n) => Some(ConnectionId(n)),
            None => None,
        }
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// The index of a listener within one server.
///
/// ```
/// # fn main() -> Result<(), net_io::NetError> {
/// let server = net_io::serve("127.0.0.1:0", |_conn| Ok(()))?;
/// assert_eq!(server.listeners()[0].id.get(), 0);
/// # server.handle().request_stop(); let _ = server.wait_for_stop(); Ok(()) }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ListenerId(pub(crate) u16);

impl ListenerId {
    /// The index as a number.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// The index of a worker within one server.
///
/// ```
/// # fn main() -> Result<(), net_io::NetError> {
/// let server = net_io::serve("127.0.0.1:0", |_conn| Ok(()))?;
/// assert!(server.handle().completer(net_io::WorkerId::first()).is_some());
/// # server.handle().request_stop(); let _ = server.wait_for_stop(); Ok(()) }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WorkerId(pub(crate) u16);

impl WorkerId {
    /// The index as a number.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }

    /// Worker 0.
    #[must_use]
    pub const fn first() -> WorkerId {
        WorkerId(0)
    }

    /// Worker `index`, for tests of per-worker state (a server never hands out a
    /// worker it does not have).
    ///
    /// ```
    /// assert_eq!(net_io::WorkerId::for_testing(3).get(), 3);
    /// ```
    #[must_use]
    pub const fn for_testing(index: u16) -> WorkerId {
        WorkerId(index)
    }
}

/// Ids handed out per block.
pub(crate) const BLOCK: u64 = 1024;

/// The process-wide counter of ids. Starts at 1 so id 0 is never issued; at one
/// million ids per second it would take about 584,000 years to wrap.
static NEXT: AtomicU64 = AtomicU64::new(1);

/// A block of ids owned by one worker.
#[derive(Debug)]
pub(crate) struct IdBlock {
    next: u64,
    end: u64,
}

impl IdBlock {
    /// An empty block; the first `issue` takes a block from the counter.
    pub(crate) const fn new() -> IdBlock {
        IdBlock { next: 0, end: 0 }
    }

    /// The next id; `take` returns the start of a fresh block when this one is used up.
    pub(crate) fn issue_with(&mut self, take: impl FnOnce() -> u64) -> ConnectionId {
        if self.next >= self.end {
            let start = take();
            self.next = start;
            self.end = start.saturating_add(BLOCK);
        }
        let id = self.next;
        self.next += 1;
        to_id(id)
    }

    /// The next id from the process-wide counter.
    pub(crate) fn issue(&mut self) -> ConnectionId {
        self.issue_with(|| NEXT.fetch_add(BLOCK, Ordering::Relaxed))
    }
}

fn to_id(n: u64) -> ConnectionId {
    match NonZeroU64::new(n) {
        Some(n) => ConnectionId(n),
        // The counter starts at 1 and only grows, so this arm is not reached.
        None => ConnectionId(NonZeroU64::MIN),
    }
}

/// One id for a caller without a block (standalone connections, tests).
pub(crate) fn issue_single() -> ConnectionId {
    to_id(NEXT.fetch_add(1, Ordering::Relaxed))
}

#[cfg(all(test, not(net_io_loom)))]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_id_zero_never_issued() {
        let counter = AtomicU64::new(1);
        let mut block = IdBlock::new();
        let first = block.issue_with(|| counter.fetch_add(BLOCK, Ordering::Relaxed));
        assert_eq!(first.get(), 1);
    }

    #[test]
    fn test_id_block_takes_new_block_after_1024() {
        let counter = AtomicU64::new(1);
        let mut block = IdBlock::new();
        for _ in 0..BLOCK {
            block.issue_with(|| counter.fetch_add(BLOCK, Ordering::Relaxed));
        }
        let next = block.issue_with(|| counter.fetch_add(BLOCK, Ordering::Relaxed));
        assert_eq!(next.get(), 1 + BLOCK);
        assert_eq!(counter.load(Ordering::Relaxed), 1 + 2 * BLOCK);
    }

    #[test]
    fn test_ids_unique_across_threads() {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                std::thread::spawn(|| {
                    let mut block = IdBlock::new();
                    (0..5000).map(|_| block.issue().get()).collect::<Vec<_>>()
                })
            })
            .collect();
        let mut all = HashSet::new();
        for h in handles {
            for id in h.join().unwrap() {
                assert!(all.insert(id), "id {id} issued twice");
            }
        }
        for _ in 0..100 {
            assert!(all.insert(issue_single().get()));
        }
    }

    #[test]
    fn test_connection_id_new_and_display() {
        assert!(ConnectionId::new(0).is_none());
        assert_eq!(ConnectionId::new(9).unwrap().to_string(), "#9");
    }
}

#[cfg(all(test, net_io_loom))]
mod loom_tests {
    use super::*;
    use loom::sync::Arc;

    #[test]
    fn loom_id_blocks_never_overlap() {
        loom::model(|| {
            let counter = Arc::new(loom::sync::atomic::AtomicU64::new(1));
            let c2 = counter.clone();
            let t = loom::thread::spawn(move || {
                let mut b = IdBlock::new();
                b.issue_with(|| c2.fetch_add(BLOCK, loom::sync::atomic::Ordering::Relaxed))
                    .get()
            });
            let mut b = IdBlock::new();
            let a = b
                .issue_with(|| counter.fetch_add(BLOCK, loom::sync::atomic::Ordering::Relaxed))
                .get();
            let other = t.join().unwrap();
            assert_ne!(a, other);
            assert!(a.abs_diff(other) >= BLOCK);
        });
    }
}
