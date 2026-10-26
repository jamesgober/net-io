//! Typed events for logs, metrics, and detection.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::control::ControlState;
use crate::driver::DriverKind;
use crate::error::{CloseReason, KillReason, LimitKind, OsErrorClass, RefusalCause};
use crate::id::{ConnectionId, ListenerId, WorkerId};
use crate::info::Lane;

/// Receives events. Runs on worker threads: copy what you need and return.
///
/// # Examples
///
/// ```
/// use net_io::{CoalescedKind, Event, EventSink};
/// use std::sync::atomic::{AtomicU64, Ordering};
///
/// #[derive(Default)]
/// struct Counts { closed: AtomicU64, refused: AtomicU64, limits: AtomicU64 }
/// impl EventSink for Counts {
///     fn event(&self, event: &Event) {
///         match event {
///             Event::Closed { .. } => { self.closed.fetch_add(1, Ordering::Relaxed); }
///             Event::Refused { .. } => { self.refused.fetch_add(1, Ordering::Relaxed); }
///             Event::LimitHit { .. } => { self.limits.fetch_add(1, Ordering::Relaxed); }
///             Event::Coalesced { kind: CoalescedKind::Refused(_), count } => { self.refused.fetch_add(u64::from(*count), Ordering::Relaxed); }
///             Event::Coalesced { kind: CoalescedKind::LimitHit(_), count } => { self.limits.fetch_add(u64::from(*count), Ordering::Relaxed); }
///             _ => {}
///         }
///     }
/// }
/// ```
pub trait EventSink: Send + Sync + 'static {
    /// One event.
    fn event(&self, event: &Event);
}

/// Discards every event; the builder's default. Compiles to nothing.
///
/// ```
/// use net_io::{Event, EventSink, NoopSink};
/// NoopSink.event(&Event::DoorOpened);
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopSink;

impl EventSink for NoopSink {
    #[inline(always)]
    fn event(&self, _: &Event) {}
}

/// What was folded into a [`Event::Coalesced`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoalescedKind {
    /// Refusals with this cause.
    Refused(RefusalCause),
    /// Limit hits of this kind.
    LimitHit(LimitKind),
}

/// One event: fixed size, `Copy`, borrowing nothing.
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub enum Event {
    /// A listener was bound.
    ListenerOpened {
        /// The listener.
        listener: ListenerId,
        /// Its address.
        local: Option<SocketAddr>,
        /// The effective backlog, when known.
        backlog: Option<u32>,
    },
    /// Accepting started.
    DoorOpened,
    /// Accepting stopped.
    DoorClosed,
    /// A connection was accepted.
    Accepted {
        /// The connection.
        id: ConnectionId,
        /// Its peer.
        peer: Option<SocketAddr>,
        /// The listener.
        listener: ListenerId,
    },
    /// A connection was refused.
    Refused {
        /// Its peer.
        peer: Option<SocketAddr>,
        /// Why.
        cause: RefusalCause,
    },
    /// The gate admitted a connection.
    Admitted {
        /// The connection.
        id: ConnectionId,
        /// Its lane.
        lane: Lane,
    },
    /// A trusted PROXY header named the real client.
    ProxyResolved {
        /// The connection.
        id: ConnectionId,
        /// The real client.
        real_peer: SocketAddr,
    },
    /// The handshake finished.
    HandshakeDone {
        /// The connection.
        id: ConnectionId,
        /// How long it took.
        took: Duration,
    },
    /// A configured bound was hit.
    LimitHit {
        /// The connection, if one.
        id: Option<ConnectionId>,
        /// Which bound.
        which: LimitKind,
    },
    /// A connection was killed.
    Killed {
        /// The connection.
        id: ConnectionId,
        /// The caller's code.
        reason: KillReason,
    },
    /// The gate denied a write.
    EgressDenied {
        /// The connection.
        id: ConnectionId,
        /// The gate's code.
        code: u16,
    },
    /// A connection closed: exactly once per connection.
    Closed {
        /// The connection.
        id: ConnectionId,
        /// Why.
        reason: CloseReason,
        /// Bytes received.
        bytes_in: u64,
        /// Bytes sent.
        bytes_out: u64,
        /// How long it was open.
        lifetime: Duration,
    },
    /// An accept failed for a reason that affects only one connection.
    AcceptError {
        /// The listener.
        listener: ListenerId,
        /// The OS error class.
        class: OsErrorClass,
    },
    /// The process ran out of descriptors; accepting pauses.
    DescriptorPressure {
        /// The listener.
        listener: ListenerId,
        /// How long accepting pauses.
        backoff: Duration,
    },
    /// A listener failed and was closed.
    ListenerFailed {
        /// The listener.
        listener: ListenerId,
        /// The OS error class.
        class: OsErrorClass,
    },
    /// A drain started.
    DrainStarted {
        /// Connections open when it started.
        open: u32,
    },
    /// A drain finished.
    DrainFinished {
        /// Connections that finished in time.
        graceful: u32,
        /// Connections killed at the deadline.
        killed: u32,
    },
    /// Workers reacted to a control-line change.
    ControlReacted {
        /// The new state.
        state: ControlState,
    },
    /// A completion arrived for a connection that had closed.
    StaleCompletion {
        /// The worker.
        worker: WorkerId,
    },
    /// A session panicked; its connection was closed.
    SessionPanicked {
        /// The connection.
        id: ConnectionId,
    },
    /// The requested driver could not run; another was used.
    DriverFallback {
        /// The requested driver.
        wanted: DriverKind,
        /// The driver in use.
        using: DriverKind,
    },
    /// Refusals or limit hits above 1,000 per second per worker, folded into one event.
    Coalesced {
        /// What was folded.
        kind: CoalescedKind,
        /// How many.
        count: u32,
    },
}

/// Folds floods of refusal and limit events: above 1,000 per second (per
/// accepting thread or worker) they become one `Coalesced` event per second.
#[derive(Debug)]
pub(crate) struct Coalescer {
    window_start: Option<Instant>,
    in_window: u32,
    folded: [(CoalescedKind, u32); 8],
    folded_len: usize,
}

const COALESCE_ABOVE: u32 = 1000;

impl Coalescer {
    pub(crate) fn new() -> Coalescer {
        Coalescer {
            window_start: None,
            in_window: 0,
            folded: [(CoalescedKind::LimitHit(LimitKind::Connections), 0); 8],
            folded_len: 0,
        }
    }

    /// Emits `event` (a `Refused` or `LimitHit`) or folds it.
    pub(crate) fn emit(
        &mut self,
        sink: &dyn EventSink,
        now: Instant,
        kind: CoalescedKind,
        event: Event,
    ) {
        let start = *self.window_start.get_or_insert(now);
        if now.duration_since(start) >= Duration::from_secs(1) {
            self.flush(sink);
            self.window_start = Some(now);
            self.in_window = 0;
        }
        self.in_window = self.in_window.saturating_add(1);
        if self.in_window <= COALESCE_ABOVE {
            sink.event(&event);
            return;
        }
        if let Some(entry) = self.folded[..self.folded_len]
            .iter_mut()
            .find(|(k, _)| *k == kind)
        {
            entry.1 = entry.1.saturating_add(1);
        } else if self.folded_len < self.folded.len() {
            self.folded[self.folded_len] = (kind, 1);
            self.folded_len += 1;
        } else {
            // More distinct kinds than slots in one second: count them under the last slot.
            self.folded[self.folded.len() - 1].1 =
                self.folded[self.folded.len() - 1].1.saturating_add(1);
        }
    }

    pub(crate) fn flush(&mut self, sink: &dyn EventSink) {
        for (kind, count) in &self.folded[..self.folded_len] {
            sink.event(&Event::Coalesced {
                kind: *kind,
                count: *count,
            });
        }
        self.folded_len = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Default)]
    struct Count {
        plain: AtomicU64,
        folded: AtomicU64,
    }
    impl EventSink for Count {
        fn event(&self, e: &Event) {
            match e {
                Event::Coalesced { count, .. } => {
                    self.folded.fetch_add(u64::from(*count), Ordering::Relaxed);
                }
                _ => {
                    self.plain.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    #[test]
    fn test_event_size_at_most_64_bytes() {
        assert!(
            std::mem::size_of::<Event>() <= 64,
            "{}",
            std::mem::size_of::<Event>()
        );
    }

    #[test]
    fn test_coalescer_folds_above_threshold() {
        let sink = Count::default();
        let mut c = Coalescer::new();
        let t = Instant::now();
        let kind = CoalescedKind::Refused(RefusalCause::GlobalCap);
        let ev = Event::Refused {
            peer: None,
            cause: RefusalCause::GlobalCap,
        };
        for _ in 0..5000 {
            c.emit(&sink, t, kind, ev);
        }
        c.emit(&sink, t + Duration::from_secs(1), kind, ev);
        assert_eq!(sink.plain.load(Ordering::Relaxed), 1001);
        assert_eq!(sink.folded.load(Ordering::Relaxed), 4000);
    }
}
