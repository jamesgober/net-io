//! Clocks. Deadlines read time through a [`Clock`] so tests can move it by hand.

use std::sync::Mutex;
use std::sync::PoisonError;
use std::time::{Duration, Instant};

/// A source of monotonic time.
///
/// # Examples
///
/// ```
/// use net_io::{Clock, MonotonicClock};
/// let a = MonotonicClock.now();
/// assert!(MonotonicClock.now() >= a);
/// ```
pub trait Clock: Send + Sync + 'static {
    /// The current instant.
    fn now(&self) -> Instant;
}

/// `Instant::now()`.
///
/// ```
/// use net_io::Clock;
/// let _ = net_io::MonotonicClock.now();
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct MonotonicClock;

impl Clock for MonotonicClock {
    #[inline]
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// A clock that moves only when told to, for deterministic timeout tests.
///
/// ```
/// use net_io::{Clock, ManualClock};
/// use std::time::Duration;
/// let clock = ManualClock::new();
/// let start = clock.now();
/// clock.advance(Duration::from_secs(61));
/// assert_eq!(clock.now() - start, Duration::from_secs(61));
/// ```
#[derive(Debug)]
pub struct ManualClock {
    now: Mutex<Instant>,
}

impl ManualClock {
    /// A clock frozen at the current instant.
    #[must_use]
    pub fn new() -> ManualClock {
        ManualClock {
            now: Mutex::new(Instant::now()),
        }
    }

    /// Moves the clock forward.
    pub fn advance(&self, by: Duration) {
        let mut now = self.now.lock().unwrap_or_else(PoisonError::into_inner);
        *now = now.checked_add(by).unwrap_or(*now);
    }

    /// Moves the clock to `at`; never backwards.
    ///
    /// ```
    /// use net_io::{Clock, ManualClock};
    /// let clock = ManualClock::new();
    /// let t = clock.now();
    /// clock.set(t - std::time::Duration::from_secs(1));
    /// assert_eq!(clock.now(), t);
    /// ```
    pub fn set(&self, at: Instant) {
        let mut now = self.now.lock().unwrap_or_else(PoisonError::into_inner);
        if at > *now {
            *now = at;
        }
    }
}

impl Default for ManualClock {
    fn default() -> ManualClock {
        ManualClock::new()
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Instant {
        *self.now.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manual_clock_frozen_until_advanced() {
        let c = ManualClock::new();
        let a = c.now();
        std::thread::sleep(Duration::from_millis(2));
        assert_eq!(c.now(), a);
        c.advance(Duration::from_millis(5));
        assert_eq!(c.now(), a + Duration::from_millis(5));
    }

    #[test]
    fn test_manual_clock_set_forward_only() {
        let c = ManualClock::new();
        let a = c.now();
        c.set(a + Duration::from_secs(3));
        c.set(a);
        assert_eq!(c.now(), a + Duration::from_secs(3));
    }
}
