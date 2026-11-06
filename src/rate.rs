//! The minimum transfer rate: a sliding window of byte counters per direction.

use std::time::{Duration, Instant};

use crate::limits::MinRate;

/// The default window takes ten one-second buckets; a longer one widens its
/// buckets, so an idle connection stays small.
const MAX_BUCKETS: usize = 10;

/// Bytes moved in one direction over a sliding window of `check`-wide buckets.
///
/// A slowloris client sends one byte every few seconds, which passes any
/// per-read timeout; this does not let it pass. The settings stay with the
/// limits, shared by every connection that has them.
#[derive(Debug, Clone)]
pub(crate) struct Rate {
    width: Duration,
    n: usize,
    buckets: [u32; MAX_BUCKETS],
    base: Instant,
    head: u64,
    since: Option<Instant>,
}

impl Rate {
    pub(crate) fn new(cfg: &MinRate, now: Instant) -> Rate {
        let mut width = if cfg.check.is_zero() {
            Duration::from_secs(1)
        } else {
            cfg.check
        };
        let want = cfg.window.as_nanos() / width.as_nanos().max(1);
        if want > MAX_BUCKETS as u128 {
            width = cfg.window / MAX_BUCKETS as u32;
        } else if want < 2 {
            // One bucket covers nothing at its own boundary, which is when the timer's
            // check runs: a silent peer would never be too slow (found by the `rate`
            // fuzz target, with a window under twice the check interval).
            width = cfg.window / 2;
        }
        let n = usize::try_from(cfg.window.as_nanos() / width.as_nanos().max(1))
            .unwrap_or(MAX_BUCKETS)
            .clamp(1, MAX_BUCKETS);
        Rate {
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

    pub(crate) fn is_active(&self, cfg: &MinRate) -> bool {
        self.since.is_some() && !cfg.is_off()
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
        let bytes = u32::try_from(bytes).unwrap_or(u32::MAX);
        self.buckets[b] = self.buckets[b].saturating_add(bytes);
    }

    /// Whether the peer is below the minimum rate (only after the grace period).
    pub(crate) fn too_slow(&mut self, cfg: &MinRate, now: Instant) -> bool {
        let Some(since) = self.since else {
            return false;
        };
        if cfg.is_off() {
            return false;
        }
        let active = now.saturating_duration_since(since);
        if active < cfg.grace {
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
        let moved: u64 = self.buckets[..self.n].iter().map(|&b| u64::from(b)).sum();
        // Rounded up: at 1 B/s over 200 ms the requirement is one byte, not none, so a
        // silent peer is too slow whatever the rate and window (found by the `rate`
        // fuzz target).
        let required = (u128::from(cfg.bytes_per_sec) * covered).div_ceil(1_000_000_000);
        u128::from(moved) < required
    }

    /// When the next check is due, if the direction is active.
    pub(crate) fn next_check(&self, cfg: &MinRate, now: Instant) -> Option<Instant> {
        let since = self.since?;
        if cfg.is_off() {
            return None;
        }
        let grace_end = since + cfg.grace;
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
        let mut r = Rate::new(&rate(), t);
        r.activate(t);
        assert!(!r.too_slow(&rate(), t + Duration::from_secs(4)));
    }

    #[test]
    fn test_rate_silent_peer_is_too_slow_at_a_low_rate() {
        let cfg = MinRate {
            bytes_per_sec: 1,
            window: Duration::from_millis(200),
            grace: Duration::from_millis(1),
            check: Duration::from_millis(50),
        };
        let t0 = Instant::now();
        let mut r = Rate::new(&cfg, t0);
        r.activate(t0);
        assert!(r.too_slow(&cfg, t0 + Duration::from_millis(500)));
    }

    #[test]
    fn test_rate_short_window_still_measures_at_check_boundaries() {
        let cfg = MinRate {
            bytes_per_sec: 97,
            window: Duration::from_millis(200),
            grace: Duration::from_millis(1_921),
            check: Duration::from_millis(101),
        };
        let t0 = Instant::now();
        let mut r = Rate::new(&cfg, t0);
        r.activate(t0);
        // Exactly on a multiple of the check interval.
        assert!(r.too_slow(&cfg, t0 + Duration::from_millis(2_222)));
    }

    #[test]
    fn test_rate_trickle_is_too_slow() {
        let t = Instant::now();
        let mut r = Rate::new(&rate(), t);
        r.activate(t);
        for s in 0..10 {
            r.record(t + Duration::from_secs(s), 1);
        }
        assert!(r.too_slow(&rate(), t + Duration::from_secs(10)));
    }

    #[test]
    fn test_rate_fast_peer_passes() {
        let t = Instant::now();
        let mut r = Rate::new(&rate(), t);
        r.activate(t);
        for s in 0..20 {
            r.record(t + Duration::from_secs(s), 200);
        }
        assert!(!r.too_slow(&rate(), t + Duration::from_secs(20)));
    }

    #[test]
    fn test_rate_window_slides() {
        let t = Instant::now();
        let mut r = Rate::new(&rate(), t);
        r.activate(t);
        // A burst at the start, then nothing: after the window passes, it is too slow.
        r.record(t, 10_000);
        assert!(!r.too_slow(&rate(), t + Duration::from_secs(6)));
        assert!(r.too_slow(&rate(), t + Duration::from_secs(25)));
    }

    #[test]
    fn test_rate_off_and_inactive_never_slow() {
        let t = Instant::now();
        let mut off = Rate::new(&MinRate::off(), t);
        off.activate(t);
        assert!(!off.too_slow(&MinRate::off(), t + Duration::from_secs(100)));
        let mut idle = Rate::new(&rate(), t);
        assert!(!idle.too_slow(&rate(), t + Duration::from_secs(100)));
        assert!(idle.next_check(&rate(), t).is_none());
        idle.activate(t);
        idle.deactivate();
        assert!(!idle.is_active(&rate()));
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
            let mut r = Rate::new(&cfg, t0);
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
                assert!(!r.too_slow(&cfg, now), "{cfg:?} flagged at {:?}", now - t0);
            }
            // Then silence for a whole window and one check.
            let quiet = now + window + cfg.check + Duration::from_millis(1);
            assert!(r.too_slow(&cfg, quiet), "{cfg:?} silent peer not flagged");
        }
    }
}

/// The fuzz target `rate`: arbitrary arrivals and clock steps never panic, a
/// counter is never too slow before its grace ends or while inactive, and a peer
/// that sent nothing for a whole window after its grace is too slow.
#[cfg(fuzzing)]
pub(crate) fn fuzz_rate(data: &[u8]) {
    let Some((head, ops)) = data.split_first_chunk::<4>() else {
        return;
    };
    let cfg = MinRate {
        bytes_per_sec: u32::from(head[0]) * 16 + 1,
        window: Duration::from_millis(u64::from(head[1]) * 40 + 200),
        grace: Duration::from_millis(u64::from(head[2]) * 20 + 1),
        check: Duration::from_millis(u64::from(head[3]) % 200 + 1),
    };
    if cfg.window < cfg.check {
        return;
    }
    let start = Instant::now();
    let mut now = start;
    let mut r = Rate::new(&cfg, now);
    let mut active_at = None;
    for op in ops.chunks(3) {
        let arg = op.get(1..).map_or(0u64, |b| {
            b.iter().fold(0u64, |a, &x| (a << 8) | u64::from(x))
        });
        match op[0] % 5 {
            0 => {
                r.activate(now);
                active_at.get_or_insert(now);
            }
            1 => {
                r.deactivate();
                active_at = None;
            }
            2 => r.record(now, arg as usize),
            3 => now += Duration::from_micros(arg * 97),
            _ => {
                let slow = r.too_slow(&cfg, now);
                match active_at {
                    None => assert!(!slow, "too slow while inactive"),
                    Some(at) if now < at + cfg.grace => assert!(!slow, "too slow in its grace"),
                    _ => {}
                }
                let _ = r.next_check(&cfg, now);
            }
        }
    }
    if let Some(at) = active_at {
        // Silence for a full window after the grace: too slow, whatever came before.
        let later = now.max(at + cfg.grace) + cfg.window + cfg.check;
        assert!(
            r.too_slow(&cfg, later),
            "silent for a window and not too slow"
        );
    }
}
