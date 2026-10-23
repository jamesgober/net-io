//! The minimum transfer rate: a sliding window of byte counters per direction.

use std::time::{Duration, Instant};

use crate::limits::MinRate;

const MAX_BUCKETS: usize = 64;

/// Bytes moved in one direction over a sliding window of `check`-wide buckets.
///
/// A slowloris client sends one byte every few seconds, which passes any
/// per-read timeout; this does not let it pass.
#[derive(Debug, Clone)]
pub(crate) struct Rate {
    cfg: MinRate,
    width: Duration,
    n: usize,
    buckets: [u64; MAX_BUCKETS],
    base: Instant,
    head: u64,
    since: Option<Instant>,
}

impl Rate {
    pub(crate) fn new(cfg: MinRate, now: Instant) -> Rate {
        let width = if cfg.check.is_zero() {
            Duration::from_secs(1)
        } else {
            cfg.check
        };
        let n = usize::try_from(cfg.window.as_nanos() / width.as_nanos().max(1))
            .unwrap_or(MAX_BUCKETS)
            .clamp(1, MAX_BUCKETS);
        Rate {
            cfg,
            width,
            n,
            buckets: [0; MAX_BUCKETS],
            base: now,
            head: 0,
            since: None,
        }
    }

    /// The direction became active (an exchange started, or output is pending).
    pub(crate) fn activate(&mut self, now: Instant) {
        if self.since.is_none() {
            self.since = Some(now);
            self.base = now;
            self.head = 0;
            self.buckets[..self.n].fill(0);
        }
    }

    /// The direction became idle; the check stops.
    pub(crate) fn deactivate(&mut self) {
        self.since = None;
    }

    pub(crate) fn is_active(&self) -> bool {
        self.since.is_some() && !self.cfg.is_off()
    }

    fn index(&self, now: Instant) -> u64 {
        let elapsed = now.saturating_duration_since(self.base).as_nanos();
        u64::try_from(elapsed / self.width.as_nanos().max(1)).unwrap_or(u64::MAX)
    }

    fn advance(&mut self, now: Instant) {
        let idx = self.index(now);
        if idx <= self.head {
            return;
        }
        let steps = (idx - self.head).min(self.n as u64);
        for i in 1..=steps {
            let b = ((self.head + i) % self.n as u64) as usize;
            self.buckets[b] = 0;
        }
        self.head = idx;
    }

    /// Records bytes moved now.
    pub(crate) fn record(&mut self, now: Instant, bytes: usize) {
        if self.since.is_none() {
            return;
        }
        self.advance(now);
        let b = (self.head % self.n as u64) as usize;
        self.buckets[b] = self.buckets[b].saturating_add(bytes as u64);
    }

    /// Whether the peer is below the minimum rate (only after the grace period).
    pub(crate) fn too_slow(&mut self, now: Instant) -> bool {
        let Some(since) = self.since else {
            return false;
        };
        if self.cfg.is_off() {
            return false;
        }
        let active = now.saturating_duration_since(since);
        if active < self.cfg.grace {
            return false;
        }
        self.advance(now);
        // The buckets cover the full older ones plus the elapsed part of the current
        // one; require the rate over exactly that time (and never before activation).
        let width = self.width.as_nanos();
        let into_current = now
            .saturating_duration_since(self.base)
            .as_nanos()
            .saturating_sub(u128::from(self.head) * width);
        let covered = (width * (self.n as u128 - 1) + into_current).min(active.as_nanos());
        let moved: u64 = self.buckets[..self.n].iter().sum();
        let required = u128::from(self.cfg.bytes_per_sec) * covered / 1_000_000_000;
        u128::from(moved) < required
    }

    /// When the next check is due, if the direction is active.
    pub(crate) fn next_check(&self, now: Instant) -> Option<Instant> {
        let since = self.since?;
        if self.cfg.is_off() {
            return None;
        }
        let grace_end = since + self.cfg.grace;
        Some(if now < grace_end {
            grace_end
        } else {
            now + self.width
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rate() -> MinRate {
        MinRate::new(100, Duration::from_secs(10))
    }

    #[test]
    fn test_rate_no_check_before_grace() {
        let t = Instant::now();
        let mut r = Rate::new(rate(), t);
        r.activate(t);
        assert!(!r.too_slow(t + Duration::from_secs(4)));
    }

    #[test]
    fn test_rate_trickle_is_too_slow() {
        let t = Instant::now();
        let mut r = Rate::new(rate(), t);
        r.activate(t);
        for s in 0..10 {
            r.record(t + Duration::from_secs(s), 1);
        }
        assert!(r.too_slow(t + Duration::from_secs(10)));
    }

    #[test]
    fn test_rate_fast_peer_passes() {
        let t = Instant::now();
        let mut r = Rate::new(rate(), t);
        r.activate(t);
        for s in 0..20 {
            r.record(t + Duration::from_secs(s), 200);
        }
        assert!(!r.too_slow(t + Duration::from_secs(20)));
    }

    #[test]
    fn test_rate_window_slides() {
        let t = Instant::now();
        let mut r = Rate::new(rate(), t);
        r.activate(t);
        // A burst at the start, then nothing: after the window passes, it is too slow.
        r.record(t, 10_000);
        assert!(!r.too_slow(t + Duration::from_secs(6)));
        assert!(r.too_slow(t + Duration::from_secs(25)));
    }

    #[test]
    fn test_rate_off_and_inactive_never_slow() {
        let t = Instant::now();
        let mut off = Rate::new(MinRate::off(), t);
        off.activate(t);
        assert!(!off.too_slow(t + Duration::from_secs(100)));
        let mut idle = Rate::new(rate(), t);
        assert!(!idle.too_slow(t + Duration::from_secs(100)));
        assert!(idle.next_check(t).is_none());
        idle.activate(t);
        idle.deactivate();
        assert!(!idle.is_active());
    }

    /// Property: a peer at or above the rate is never too slow, whatever its burst
    /// pattern; a peer that stops is too slow once the window has passed.
    #[test]
    fn prop_rate_never_flags_a_fast_peer() {
        use crate::testing::Gen;
        let mut g = Gen::new(0x5a7e_u64);
        for _ in 0..if cfg!(miri) { 5 } else { 200 } {
            let bps = 1 + g.below(10_000) as u32;
            let window = Duration::from_millis(1000 + g.below(9000));
            let cfg = MinRate {
                bytes_per_sec: bps,
                window,
                grace: Duration::from_millis(g.below(3000)),
                check: Duration::from_millis(100 + g.below(900)),
            };
            let t0 = Instant::now();
            let mut r = Rate::new(cfg, t0);
            r.activate(t0);
            // Twice the rate, delivered in random bursts every 1 to 200 ms.
            let mut now = t0;
            let mut owed = 0f64;
            let end = t0 + window * 3;
            while now < end {
                let step = Duration::from_millis(1 + g.below(200));
                now += step;
                owed += 2.0 * f64::from(bps) * step.as_secs_f64();
                let bytes = owed.floor() as usize;
                owed -= bytes as f64;
                r.record(now, bytes);
                assert!(!r.too_slow(now), "{cfg:?} flagged at {:?}", now - t0);
            }
            // Then silence for a whole window and one check.
            let quiet = now + window + cfg.check + Duration::from_millis(1);
            assert!(r.too_slow(quiet), "{cfg:?} silent peer not flagged");
        }
    }
}
