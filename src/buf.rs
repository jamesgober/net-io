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
}

/// A worker's buffer pool: free lists per size class, drawing new buffers from a
/// budget shared by every worker of a server.
pub struct BufferPool {
    lists: Vec<(SizeClass, Vec<Buffer>)>,
    budget: Arc<AtomicU64>,
    wipe: bool,
    allocated: u64,
    refusals: u64,
}

impl BufferPool {
    pub(crate) fn new(budget: Arc<AtomicU64>, wipe: bool) -> BufferPool {
        BufferPool {
            lists: Vec::with_capacity(4),
            budget,
            wipe,
            allocated: 0,
            refusals: 0,
        }
    }

    /// A pool with its own budget of `bytes`, for use outside a server.
    ///
    /// ```
    /// let mut pool = net_io::BufferPool::standalone(64 * 1024);
    /// assert!(pool.take(net_io::SizeClass::LARGE).is_some());
    /// assert!(pool.take(net_io::SizeClass::LARGE).is_none()); // budget spent
    /// ```
    #[must_use]
    pub fn standalone(bytes: u64) -> BufferPool {
        BufferPool::new(Arc::new(AtomicU64::new(bytes)), true)
    }

    /// A buffer of `class`, or `None` when the free list is empty and the budget is spent.
    pub fn take(&mut self, class: SizeClass) -> Option<Buffer> {
        if let Some(buf) = self.list(class).pop() {
            return Some(buf);
        }
        let bytes = u64::from(class.bytes());
        let mut left = self.budget.load(Ordering::Relaxed);
        loop {
            if left < bytes {
                self.refusals += 1;
                return None;
            }
            match self.budget.compare_exchange_weak(
                left,
                left - bytes,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => left = actual,
            }
        }
        self.allocated += 1;
        Some(Buffer::new(class))
    }

    /// Returns a buffer; its used part is wiped first unless wiping is off.
    ///
    /// A buffer from another worker's pool is accepted (it is just memory).
    pub fn put(&mut self, mut buf: Buffer) {
        if self.wipe {
            buf.wipe();
        } else {
            buf.clear();
        }
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
        let mut pool = BufferPool::new(Arc::new(AtomicU64::new(1 << 20)), false);
        let mut b = pool.take(SizeClass::SMALL).unwrap();
        b.spare()[0] = 9;
        b.set_len(1);
        pool.put(b);
        let b = pool.take(SizeClass::SMALL).unwrap();
        assert!(b.is_empty());
    }
}
