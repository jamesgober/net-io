//! Test support: a small seeded generator for property tests, so they need no
//! extra dependency and every failure reproduces from its seed.

/// xorshift64* (Vigna): fast, full period, good enough to drive test inputs.
pub(crate) struct Gen(u64);

impl Gen {
    pub(crate) fn new(seed: u64) -> Gen {
        Gen(seed.max(1))
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A value in `0..n` (`n` > 0).
    pub(crate) fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    pub(crate) fn chance(&mut self, one_in: u64) -> bool {
        self.below(one_in) == 0
    }
}
