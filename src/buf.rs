//! Pooled buffers with a total budget, wiped on release.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::limits::SizeClass;

/// A byte buffer from a pool: a fixed capacity (its size class) and a filled length.
///
/// # Examples
///
/// ```
/// use net_io::{BufferPool, SizeClass};
/// let mut pool = BufferPool::standalone(1 << 20);
/// let mut buf = pool.take(SizeClass::SMALL).unwrap();
/// buf.spare()[..5].copy_from_slice(b"hello");
/// buf.set_len(5);
/// assert_eq!(buf.as_slice(), b"hello");
/// pool.put(buf);
/// ```
pub struct Buffer {
    data: Box<[u8]>,
    len: usize,
    class: SizeClass,
}

impl Buffer {
    /// A buffer not drawn from any pool's free list (the caller already charged the budget).
    pub(crate) fn detached(class: SizeClass) -> Buffer {
        Buffer::new(class)
    }

    /// An empty stand-in that owns no memory, left where a buffer travels with a
    /// driver operation.
    #[cfg(feature = "reactor")]
    pub(crate) fn placeholder() -> Buffer {
        Buffer {
            data: Box::default(),
            len: 0,
            class: SizeClass::SMALL,
        }
    }

    fn new(class: SizeClass) -> Buffer {
        Buffer {
            data: vec![0u8; class.bytes() as usize].into_boxed_slice(),
            len: 0,
            class,
        }
    }

    /// The filled part.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// The filled part, mutable.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }

    /// The unfilled tail.
    pub fn spare(&mut self) -> &mut [u8] {
        &mut self.data[self.len..]
    }

    /// The filled length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether nothing is filled.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Sets the filled length; saturates at the capacity.
    pub fn set_len(&mut self, n: usize) {
        self.len = n.min(self.data.len());
    }

    /// The capacity in bytes.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    /// The size class.
    #[must_use]
    pub fn class(&self) -> SizeClass {
        self.class
    }

    /// Empties the buffer (does not wipe; the pool wipes on release).
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// Overwrites the filled part with zeroes and empties the buffer.
    pub(crate) fn wipe(&mut self) {
        let used = &mut self.data[..self.len];
        used.fill(0);
        // The buffer stays reachable and is read again by the next owner, so the
        // stores cannot be removed as dead; black_box makes that explicit.
        std::hint::black_box(&*used);
        self.len = 0;
    }

    /// Moves the bytes `from..` to the front.
    pub(crate) fn compact(&mut self, from: usize) {
        let from = from.min(self.len);
        self.data.copy_within(from..self.len, 0);
        self.len -= from;
    }
}

impl fmt::Debug for Buffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Buffer")
            .field("len", &self.len)
            .field("capacity", &self.data.len())
            .finish()
    }
}

/// Counts of one pool.
///
/// ```
/// let pool = net_io::BufferPool::standalone(1 << 20);
/// assert_eq!(pool.stats().allocated, 0);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PoolStats {
    /// Buffers this pool allocated.
    pub allocated: u64,
    /// Buffers in its free lists.
    pub free: u64,
    /// Bytes left in the shared budget.
    pub budget_left: u64,
    /// Takes refused because the budget was spent.
    pub budget_refusals: u64,
    /// Buffers this pool freed and gave back to the shared budget: released above
    /// what the pool keeps, or freed to make room for a buffer of another class.
    pub freed: u64,
}

/// A worker's buffer pool: free lists per size class, drawing new buffers from a
/// budget shared by every worker of a server.
///
/// The budget comes back: a pool keeps at most a fixed number of bytes in its free
/// lists (a server's pools keep the budget divided by the workers, a fair share)
/// and frees what is released above that, and a take that finds its own class's
/// list empty and the budget short frees buffers of other classes first, so a
/// burst of one size class does not hold the budget from the others for good.
pub struct BufferPool {
    lists: Vec<(SizeClass, Vec<Buffer>)>,
    budget: Arc<AtomicU64>,
    wipe: bool,
    allocated: u64,
    refusals: u64,
    /// Bytes in the free lists.
    free_bytes: u64,
    /// The most bytes the free lists hold; a release above it frees the buffer.
    keep: u64,
    freed: u64,
}

impl BufferPool {
    /// A pool drawing on `budget` that keeps at most `keep` bytes in its free lists.
    pub(crate) fn new(budget: Arc<AtomicU64>, wipe: bool, keep: u64) -> BufferPool {
        BufferPool {
            lists: Vec::with_capacity(4),
            budget,
            wipe,
            allocated: 0,
            refusals: 0,
            free_bytes: 0,
            keep,
            freed: 0,
        }
    }

    /// A pool with its own budget of `bytes`, for use outside a server. It keeps
    /// every buffer released to it, up to the whole budget.
    ///
    /// ```
    /// let mut pool = net_io::BufferPool::standalone(64 * 1024);
    /// assert!(pool.take(net_io::SizeClass::LARGE).is_some());
    /// assert!(pool.take(net_io::SizeClass::LARGE).is_none()); // budget spent
    /// ```
    #[must_use]
    pub fn standalone(bytes: u64) -> BufferPool {
        BufferPool::new(Arc::new(AtomicU64::new(bytes)), true, bytes)
    }

    /// A buffer of `class`, or `None` when the free list is empty and the budget is
    /// spent even after freeing what this pool holds of other classes.
    ///
    /// ```
    /// use net_io::{BufferPool, SizeClass};
    /// let mut pool = BufferPool::standalone(64 * 1024);
    /// let large = pool.take(SizeClass::LARGE).unwrap();
    /// pool.put(large); // the budget is spent, the buffer is cached
    /// // A smaller class frees the cached 64 KiB buffer to make room.
    /// assert!(pool.take(SizeClass::MEDIUM).is_some());
    /// assert_eq!(pool.stats().freed, 1);
    /// ```
    pub fn take(&mut self, class: SizeClass) -> Option<Buffer> {
        if let Some(buf) = self.pop(class) {
            return Some(buf);
        }
        let bytes = u64::from(class.bytes());
        while !self.charge(bytes) {
            // Buffers cached for other classes hold budget this class needs: free
            // them, the largest first, until the charge fits. Its own list is empty
            // here, so `free_bytes` is theirs; when even all of it cannot cover the
            // charge, nothing is freed for nothing.
            let reachable = self
                .budget
                .load(Ordering::Relaxed)
                .saturating_add(self.free_bytes);
            if reachable < bytes || !self.free_other(class) {
                self.refusals += 1;
                return None;
            }
        }
        self.allocated += 1;
        Some(Buffer::new(class))
    }

    /// Takes `bytes` from the shared budget; `false`, with nothing taken, when
    /// fewer are left.
    fn charge(&self, bytes: u64) -> bool {
        let mut left = self.budget.load(Ordering::Relaxed);
        loop {
            if left < bytes {
                return false;
            }
            match self.budget.compare_exchange_weak(
                left,
                left - bytes,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => left = actual,
            }
        }
    }

    /// Frees one cached buffer of a class other than `class`, the largest class
    /// first, and gives its bytes back to the budget; `false` when there is none.
    fn free_other(&mut self, class: SizeClass) -> bool {
        let pick = self
            .lists
            .iter()
            .enumerate()
            .filter(|(_, (c, l))| *c != class && !l.is_empty())
            .max_by_key(|(_, (c, _))| *c)
            .map(|(i, _)| i);
        let Some(buf) = pick.and_then(|i| self.lists[i].1.pop()) else {
            return false;
        };
        self.free_bytes = self.free_bytes.saturating_sub(buf.capacity() as u64);
        self.refund(buf);
        true
    }

    /// Drops a buffer this pool will not keep and gives its bytes back to the
    /// shared budget. The caller wiped it already (or wiping is off): every buffer
    /// in a free list was wiped by `put`.
    fn refund(&mut self, buf: Buffer) {
        let bytes = buf.capacity() as u64;
        drop(buf);
        self.budget.fetch_add(bytes, Ordering::Release);
        self.freed += 1;
    }

    /// Frees cached buffers of classes other than `class` until the budget holds
    /// one buffer of `class`, for an output that charges the budget itself
    /// (`Output::refill`). Looks at the shared budget only when this pool caches
    /// something, so the common case costs no atomic read.
    pub(crate) fn make_room(&mut self, class: SizeClass) {
        let bytes = u64::from(class.bytes());
        while self.free_bytes > 0 && self.budget.load(Ordering::Relaxed) < bytes {
            if !self.free_other(class) {
                return;
            }
        }
    }

    /// A buffer of `class` this pool already holds; never allocates or charges the
    /// budget.
    pub(crate) fn take_cached(&mut self, class: SizeClass) -> Option<Buffer> {
        self.pop(class)
    }

    fn pop(&mut self, class: SizeClass) -> Option<Buffer> {
        let buf = self.list(class).pop()?;
        self.free_bytes = self.free_bytes.saturating_sub(buf.capacity() as u64);
        Some(buf)
    }

    /// Returns a buffer; its used part is wiped first unless wiping is off.
    ///
    /// A buffer from another worker's pool is accepted (it is just memory). When the
    /// free lists already hold what this pool keeps, the buffer is freed and its
    /// bytes go back to the shared budget instead.
    ///
    /// ```
    /// use net_io::{BufferPool, SizeClass};
    /// let mut pool = BufferPool::standalone(1 << 20);
    /// let b = pool.take(SizeClass::SMALL).unwrap();
    /// pool.put(b);
    /// assert_eq!(pool.stats().free, 1);
    /// ```
    pub fn put(&mut self, mut buf: Buffer) {
        if buf.data.is_empty() {
            // A stand-in owns no memory and was never charged to the budget.
            return;
        }
        // Wiped before it is kept or freed: freed memory goes back to the
        // allocator, which hands it to other code in the process.
        if self.wipe {
            buf.wipe();
        } else {
            buf.clear();
        }
        let bytes = buf.capacity() as u64;
        if self.free_bytes.saturating_add(bytes) > self.keep {
            return self.refund(buf);
        }
        self.free_bytes += bytes;
        let class = buf.class;
        self.list(class).push(buf);
    }

    /// Counts of this pool.
    #[must_use]
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            allocated: self.allocated,
            free: self.lists.iter().map(|(_, l)| l.len() as u64).sum(),
            budget_left: self.budget.load(Ordering::Relaxed),
            budget_refusals: self.refusals,
            freed: self.freed,
        }
    }

    fn list(&mut self, class: SizeClass) -> &mut Vec<Buffer> {
        let pos = match self.lists.iter().position(|(c, _)| *c == class) {
            Some(p) => p,
            None => {
                self.lists.push((class, Vec::new()));
                self.lists.len() - 1
            }
        };
        &mut self.lists[pos].1
    }
}

impl fmt::Debug for BufferPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BufferPool")
            .field("stats", &self.stats())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_reuses_and_wipes() {
        let mut pool = BufferPool::standalone(1 << 20);
        let mut b = pool.take(SizeClass::SMALL).unwrap();
        b.spare()[..6].copy_from_slice(b"secret");
        b.set_len(6);
        pool.put(b);
        let mut b = pool.take(SizeClass::SMALL).unwrap();
        assert_eq!(pool.stats().allocated, 1);
        assert!(b.is_empty());
        b.set_len(6);
        assert_eq!(b.as_slice(), &[0u8; 6]);
    }

    #[test]
    fn test_pool_budget_bounds_allocation() {
        let mut pool = BufferPool::standalone(u64::from(SizeClass::SMALL.bytes()) * 2);
        let a = pool.take(SizeClass::SMALL).unwrap();
        let _b = pool.take(SizeClass::SMALL).unwrap();
        assert!(pool.take(SizeClass::SMALL).is_none());
        assert_eq!(pool.stats().budget_refusals, 1);
        pool.put(a);
        assert!(pool.take(SizeClass::SMALL).is_some());
    }

    #[test]
    fn test_set_len_saturates_and_compact_moves_tail() {
        let mut pool = BufferPool::standalone(1 << 20);
        let mut b = pool.take(SizeClass::SMALL).unwrap();
        b.set_len(usize::MAX);
        assert_eq!(b.len(), b.capacity());
        b.set_len(0);
        b.spare()[..4].copy_from_slice(b"abcd");
        b.set_len(4);
        b.compact(2);
        assert_eq!(b.as_slice(), b"cd");
        b.compact(99);
        assert!(b.is_empty());
    }

    #[test]
    fn test_pool_without_wipe_keeps_bytes_but_empties() {
        let mut pool = BufferPool::new(Arc::new(AtomicU64::new(1 << 20)), false, 1 << 20);
        let mut b = pool.take(SizeClass::SMALL).unwrap();
        b.spare()[0] = 9;
        b.set_len(1);
        pool.put(b);
        let b = pool.take(SizeClass::SMALL).unwrap();
        assert!(b.is_empty());
    }

    const LARGE: u64 = SizeClass::LARGE.bytes() as u64;
    const MEDIUM: u64 = SizeClass::MEDIUM.bytes() as u64;

    /// A take whose class has nothing cached and finds the budget spent frees what
    /// the pool caches of other classes, the largest first, and only as much as the
    /// charge needs (before, those bytes stayed spent until the process ended).
    #[test]
    fn test_take_frees_other_classes_for_the_charge() {
        let mut pool = BufferPool::standalone(2 * LARGE + 2 * u64::from(SizeClass::SMALL.bytes()));
        let held: Vec<Buffer> = vec![
            pool.take(SizeClass::LARGE).unwrap(),
            pool.take(SizeClass::LARGE).unwrap(),
            pool.take(SizeClass::SMALL).unwrap(),
            pool.take(SizeClass::SMALL).unwrap(),
        ];
        assert!(pool.take(SizeClass::MEDIUM).is_none(), "budget spent");
        assert_eq!(pool.stats().budget_refusals, 1);
        for b in held {
            pool.put(b);
        }
        assert_eq!(pool.stats().budget_left, 0);
        assert_eq!(pool.stats().free, 4);

        let m = pool
            .take(SizeClass::MEDIUM)
            .expect("room made from other classes");
        assert_eq!(m.capacity() as u64, MEDIUM);
        let s = pool.stats();
        assert_eq!(s.freed, 1, "one 64 KiB buffer covers the charge: {s:?}");
        assert_eq!(s.budget_left, LARGE - MEDIUM);
        assert_eq!(s.free, 3, "the small buffers and one large stay cached");
        // Its own class is reused before anything is freed.
        pool.put(m);
        let m = pool.take(SizeClass::MEDIUM).unwrap();
        assert_eq!(pool.stats().freed, 1);
        // A charge that all the cached buffers could not cover is refused without
        // freeing any of them.
        let big = SizeClass::new(1 << 20).unwrap();
        assert!(pool.take(big).is_none());
        let s = pool.stats();
        assert_eq!((s.budget_refusals, s.freed, s.free), (2, 1, 3), "{s:?}");
        drop(m);
    }

    /// A release above what a pool keeps frees the buffer and refunds the budget;
    /// below it the buffer is cached as before.
    #[test]
    fn test_put_above_the_keep_limit_refunds_the_budget() {
        let budget = Arc::new(AtomicU64::new(4 * LARGE));
        let mut pool = BufferPool::new(budget.clone(), true, LARGE + MEDIUM);
        let held: Vec<Buffer> = (0..4)
            .map(|_| pool.take(SizeClass::LARGE).unwrap())
            .collect();
        assert_eq!(budget.load(Ordering::Relaxed), 0);
        for b in held {
            pool.put(b);
        }
        let s = pool.stats();
        assert_eq!(s.free, 1, "{s:?}");
        assert_eq!(s.freed, 3);
        assert_eq!(s.budget_left, 3 * LARGE, "memory freed, budget refunded");
        // A smaller buffer still fits beside the kept one.
        let m = pool.take(SizeClass::MEDIUM).unwrap();
        pool.put(m);
        assert_eq!(pool.stats().free, 2);
        assert_eq!(pool.stats().freed, 3);
        // A stand-in is neither kept nor refunded.
        #[cfg(feature = "reactor")]
        pool.put(Buffer::placeholder());
        assert_eq!(pool.stats().freed, 3);
        assert_eq!(budget.load(Ordering::Relaxed), 3 * LARGE - MEDIUM);
    }

    /// `standalone` keeps everything released to it, as before: its keep limit is
    /// its whole budget, so released buffers are reused and the budget stays spent.
    #[test]
    fn test_standalone_pool_keeps_what_it_releases() {
        let mut pool = BufferPool::standalone(4 * LARGE);
        let held: Vec<Buffer> = (0..4)
            .map(|_| pool.take(SizeClass::LARGE).unwrap())
            .collect();
        for b in held {
            pool.put(b);
        }
        let s = pool.stats();
        assert_eq!((s.free, s.freed, s.budget_left), (4, 0, 0), "{s:?}");
        for _ in 0..4 {
            assert!(pool.take(SizeClass::LARGE).is_some());
        }
        assert_eq!(pool.stats().allocated, 4, "reused, not allocated again");
    }

    /// An output's room comes from other classes' cached buffers too.
    #[test]
    fn test_make_room_frees_other_classes_only_when_short() {
        let mut pool = BufferPool::standalone(LARGE + MEDIUM);
        let l = pool.take(SizeClass::LARGE).unwrap();
        pool.put(l);
        pool.make_room(SizeClass::MEDIUM);
        assert_eq!(pool.stats().freed, 0, "the budget already holds one");
        let m = pool.take(SizeClass::MEDIUM).unwrap();
        pool.make_room(SizeClass::MEDIUM);
        let s = pool.stats();
        assert_eq!((s.freed, s.budget_left, s.free), (1, LARGE, 0), "{s:?}");
        drop(m);
    }

    /// The cost of T-16: `cargo test --release --lib bench_ -- --ignored --nocapture`.
    #[test]
    #[ignore = "a benchmark"]
    fn bench_wipe() {
        for (name, used) in [("2 KiB", 2048), ("16 KiB", 16 * 1024)] {
            let mut b = Buffer::new(SizeClass::MEDIUM);
            let rounds = 1_000_000u32;
            let started = std::time::Instant::now();
            for _ in 0..rounds {
                b.set_len(used);
                b.wipe();
            }
            let ns = started.elapsed().as_nanos() as f64 / f64::from(rounds);
            println!("Wipe {name}: {ns:.1} ns");
        }
    }
}
