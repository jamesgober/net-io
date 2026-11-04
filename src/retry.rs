//! Delays between reconnect attempts: doubling, capped, and spread so a fleet of
//! clients that lost the same server does not return in step.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::time::{Duration, Instant};

/// Delays between attempts: `first`, doubling each attempt up to `max`, each one
/// drawn from the upper half of its step when jitter is on, so retries spread out
/// but never come faster than half the step (D-142).
///
/// ```
/// use net_io::Backoff;
/// use std::time::Duration;
///
/// let mut b = Backoff::new()
///     .first(Duration::from_millis(100))
///     .max(Duration::from_secs(2))
///     .jitter(false)
///     .attempts(3);
/// assert_eq!(b.next_delay(), Some(Duration::from_millis(100)));
/// assert_eq!(b.next_delay(), Some(Duration::from_millis(200)));
/// assert_eq!(b.next_delay(), Some(Duration::from_millis(400)));
/// assert_eq!(b.next_delay(), None);
/// b.reset();
/// assert_eq!(b.attempt(), 0);
/// ```
#[must_use]
#[derive(Clone, Debug)]
pub struct Backoff {
    first: Duration,
    max: Duration,
    jitter: bool,
    attempts: Option<u32>,
    give_up_after: Option<Duration>,
    attempt: u32,
    started: Option<Instant>,
    state: u64,
}

impl Default for Backoff {
    fn default() -> Backoff {
        Backoff::new()
    }
}

impl Backoff {
    /// 100 ms doubling to 30 s, jitter on, no limit on attempts or time.
    pub fn new() -> Backoff {
        let mut h = RandomState::new().build_hasher();
        h.write_u64(0x6e65_742d_696f);
        Backoff {
            first: Duration::from_millis(100),
            max: Duration::from_secs(30),
            jitter: true,
            attempts: None,
            give_up_after: None,
            attempt: 0,
            started: None,
            // xorshift never leaves zero.
            state: h.finish() | 1,
        }
    }

    /// The first delay (at least 1 ms).
    pub fn first(mut self, d: Duration) -> Backoff {
        self.first = d.max(Duration::from_millis(1));
        self.max = self.max.max(self.first);
        self
    }

    /// The longest delay (at least `first`).
    pub fn max(mut self, d: Duration) -> Backoff {
        self.max = d.max(self.first);
        self
    }

    /// Whether each delay is drawn from the upper half of its step (on by default).
    pub fn jitter(mut self, on: bool) -> Backoff {
        self.jitter = on;
        self
    }

    /// At most `n` delays; then [`Backoff::next_delay`] returns `None`.
    pub fn attempts(mut self, n: u32) -> Backoff {
        self.attempts = Some(n);
        self
    }

    /// `next_delay` returns `None` once waiting the next delay would end later
    /// than `total` after the first call.
    pub fn give_up_after(mut self, total: Duration) -> Backoff {
        self.give_up_after = Some(total);
        self
    }

    /// The delay before the next attempt, or `None` when the attempts or the time
    /// are spent.
    pub fn next_delay(&mut self) -> Option<Duration> {
        if self.attempts.is_some_and(|n| self.attempt >= n) {
            return None;
        }
        let now = Instant::now();
        let started = *self.started.get_or_insert(now);
        let step = self
            .first
            .checked_mul(1u32.checked_shl(self.attempt).unwrap_or(u32::MAX))
            .unwrap_or(self.max)
            .min(self.max);
        let delay = if self.jitter {
            let half = step / 2;
            let span = u64::try_from((step - half).as_nanos()).unwrap_or(u64::MAX);
            half + Duration::from_nanos(self.random() % span.saturating_add(1))
        } else {
            step
        };
        if let Some(total) = self.give_up_after {
            let ends = now.saturating_duration_since(started).checked_add(delay);
            if ends.is_none_or(|e| e > total) {
                return None;
            }
        }
        self.attempt = self.attempt.saturating_add(1);
        Some(delay)
    }

    /// Delays handed out since the last reset.
    #[must_use]
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Back to the first delay, with the time limit counted again from the next call.
    pub fn reset(&mut self) {
        self.attempt = 0;
        self.started = None;
    }

    fn random(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff_doubles_to_the_cap() {
        let mut b = Backoff::new()
            .first(Duration::from_millis(10))
            .max(Duration::from_millis(50))
            .jitter(false);
        let got: Vec<u128> = (0..5)
            .map(|_| b.next_delay().map_or(0, |d| d.as_millis()))
            .collect();
        assert_eq!(got, [10, 20, 40, 50, 50]);
    }

    #[test]
    fn test_backoff_jitter_stays_in_the_upper_half() {
        let mut b = Backoff::new()
            .first(Duration::from_millis(100))
            .max(Duration::from_millis(100));
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1_000 {
            let d = b.next_delay().unwrap_or_default();
            assert!(d >= Duration::from_millis(50) && d <= Duration::from_millis(100));
            seen.insert(d.as_micros() / 1_000);
        }
        // Spread, not one value.
        assert!(seen.len() > 20, "{}", seen.len());
    }

    #[test]
    fn test_backoff_never_overflows() {
        let mut b = Backoff::new()
            .first(Duration::from_secs(1))
            .max(Duration::MAX);
        for _ in 0..200 {
            assert!(b.next_delay().is_some());
        }
        assert_eq!(b.attempt(), 200);
        let mut b = Backoff::new()
            .first(Duration::MAX)
            .jitter(true)
            .attempts(u32::MAX);
        assert!(b.next_delay().is_some_and(|d| d >= Duration::MAX / 2));
    }

    #[test]
    fn test_backoff_gives_up_on_time_and_count() {
        let mut b = Backoff::new()
            .first(Duration::from_secs(1))
            .jitter(false)
            .give_up_after(Duration::from_millis(2_500));
        assert_eq!(b.next_delay(), Some(Duration::from_secs(1)));
        assert_eq!(b.next_delay(), Some(Duration::from_secs(2)));
        // Almost no time has passed, but the next delay, 4 s, ends past 2.5 s.
        assert_eq!(b.next_delay(), None);
        b.reset();
        assert_eq!(b.next_delay(), Some(Duration::from_secs(1)));
        let mut b = Backoff::new().attempts(0);
        assert_eq!(b.next_delay(), None);
    }

    #[test]
    fn test_backoff_instances_spread_differently() {
        let draw = || {
            let mut b = Backoff::new().first(Duration::from_secs(10));
            b.next_delay()
        };
        let all: std::collections::HashSet<_> = (0..16).map(|_| draw()).collect();
        assert!(all.len() > 8, "{}", all.len());
    }
}
