//! The control line: a process-wide signal every worker reads with one atomic load.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use crate::info::Lane;

/// A process-wide signal (shed, lockdown, drain, stop) that net-io's workers read
/// at the top of each loop, before each accept batch, and before each admission.
///
/// The epoch changes on every state change; the state is read only when it moved.
pub trait ControlLine: Send + Sync + 'static {
    /// The current epoch (an `Acquire` load).
    fn epoch(&self) -> u64;
    /// The current state; read only when the epoch moved.
    fn state(&self) -> ControlState;
    /// The deadline for `Draining`, if the line carries one.
    fn deadline(&self) -> Option<Instant>;
}

/// What the control line asks for.
///
/// ```
/// use net_io::{ControlState, Lane};
/// let shed = ControlState::Shed { from_lane: Lane(2) };
/// assert_ne!(shed, ControlState::Normal);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ControlState {
    /// No reaction.
    #[default]
    Normal,
    /// Refuse new connections in `from_lane` and every less important lane.
    Shed {
        /// The most important lane that is refused.
        from_lane: Lane,
    },
    /// Refuse new connections on listeners not marked `lockdown_allowed`.
    Lockdown,
    /// Close the door and drain.
    Draining,
    /// Kill every remaining connection.
    Stopping,
}

/// A control line that never changes: `epoch()` is always 0.
///
/// ```
/// use net_io::{ControlLine, NoControl};
/// assert_eq!(NoControl.epoch(), 0);
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct NoControl;

impl ControlLine for NoControl {
    #[inline]
    fn epoch(&self) -> u64 {
        0
    }
    fn state(&self) -> ControlState {
        ControlState::Normal
    }
    fn deadline(&self) -> Option<Instant> {
        None
    }
}

/// A control line for programs without their own.
///
/// ```
/// use net_io::{ControlLine, ControlState, SimpleControl};
/// let line = SimpleControl::new();
/// let before = line.epoch();
/// line.set(ControlState::Lockdown, None);
/// assert!(line.epoch() > before);
/// assert_eq!(line.state(), ControlState::Lockdown);
/// ```
#[derive(Debug, Default)]
pub struct SimpleControl {
    epoch: AtomicU64,
    inner: Mutex<(ControlState, Option<Instant>)>,
}

impl SimpleControl {
    /// A line in `Normal`.
    #[must_use]
    pub fn new() -> SimpleControl {
        SimpleControl::default()
    }

    /// Changes the state and bumps the epoch.
    pub fn set(&self, state: ControlState, deadline: Option<Instant>) {
        *self.inner.lock().unwrap_or_else(PoisonError::into_inner) = (state, deadline);
        self.epoch.fetch_add(1, Ordering::Release);
    }
}

impl ControlLine for SimpleControl {
    #[inline]
    fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }
    fn state(&self) -> ControlState {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner).0
    }
    fn deadline(&self) -> Option<Instant> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner).1
    }
}

/// A worker's cached view of the line: one load per check, a state read only on change.
#[derive(Debug)]
pub(crate) struct ControlView {
    epoch: u64,
    state: ControlState,
    deadline: Option<Instant>,
}

impl ControlView {
    pub(crate) fn new() -> ControlView {
        ControlView {
            epoch: 0,
            state: ControlState::Normal,
            deadline: None,
        }
    }

    /// Refreshes from `line`; returns `true` when the state changed.
    #[inline]
    pub(crate) fn refresh(&mut self, line: &dyn ControlLine) -> bool {
        let epoch = line.epoch();
        if epoch == self.epoch {
            return false;
        }
        self.epoch = epoch;
        let state = line.state();
        self.deadline = line.deadline();
        let changed = state != self.state;
        self.state = state;
        changed
    }

    pub(crate) fn state(&self) -> ControlState {
        self.state
    }

    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.deadline
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_view_sees_only_final_state() {
        let line = SimpleControl::new();
        let mut view = ControlView::new();
        assert!(!view.refresh(&line));
        line.set(ControlState::Shed { from_lane: Lane(1) }, None);
        line.set(ControlState::Normal, None);
        // The epoch moved but the final state equals the cached one.
        assert!(!view.refresh(&line));
        assert_eq!(view.state(), ControlState::Normal);
        line.set(ControlState::Draining, None);
        assert!(view.refresh(&line));
        assert_eq!(view.state(), ControlState::Draining);
    }

    #[test]
    fn test_no_control_never_changes() {
        let mut view = ControlView::new();
        assert!(!view.refresh(&NoControl));
    }
}
