//! The gate seam: admission before any byte is read, a check before every write.

use std::fmt;
use std::sync::Arc;

use crate::error::{CloseReason, KillReason};
use crate::id::ConnectionId;
use crate::info::{ConnectionInfo, GateTag, Lane};
use crate::sys::KillSlot;

/// Decides who may connect and whether bytes may still leave.
///
/// net-io calls `admit` after accept and before any read, `readmit` after a
/// trusted PROXY header, `check` before every write system call, and `closed`
/// exactly once when an admitted connection closes. A method that panics counts
/// as a refusal or a denial (fail closed).
///
/// # Examples
///
/// ```
/// use net_io::{Admitted, AdmitStage, CloseReason, ConnectionInfo, Denial, Gate, GateTag, Lane, Refusal, WriteCheck};
/// use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
///
/// /// One global kill switch and a count of open connections.
/// struct Switch { revoked: AtomicBool, open: AtomicU64 }
///
/// impl Gate for Switch {
///     type Ticket = ();
///     fn admit(&self, info: &ConnectionInfo, _stage: AdmitStage) -> Result<Admitted<()>, Refusal> {
///         if self.revoked.load(Ordering::Acquire) {
///             return Err(Refusal::Reset { code: 1 });
///         }
///         let lane = if info.client_addr().is_some_and(|a| a.ip().is_loopback()) { Lane(0) } else { Lane(3) };
///         self.open.fetch_add(1, Ordering::Relaxed);
///         Ok(Admitted { lane, ticket: (), tag: GateTag(0) })
///     }
///     fn readmit(&self, _ticket: &mut (), _info: &ConnectionInfo) -> Result<(), Refusal> {
///         Ok(())
///     }
///     fn check(&self, _ticket: &mut (), _write: &WriteCheck) -> Result<(), Denial> {
///         if self.revoked.load(Ordering::Acquire) { Err(Denial { code: 503 }) } else { Ok(()) }
///     }
///     fn closed(&self, _ticket: (), _info: &ConnectionInfo, _reason: CloseReason) {
///         self.open.fetch_sub(1, Ordering::Relaxed);
///     }
/// }
///
/// let gate = Switch { revoked: AtomicBool::new(false), open: AtomicU64::new(0) };
/// let info = ConnectionInfo::for_testing("127.0.0.1:9".parse().unwrap());
/// let admitted = gate.admit(&info, AdmitStage::Accept).unwrap();
/// assert_eq!(admitted.lane, Lane(0));
/// ```
pub trait Gate: Send + Sync + 'static {
    /// Per-connection state the gate keeps; net-io stores it beside the connection.
    type Ticket: Send + 'static;

    /// After accept and before any read (`Accept`), on `Server::adopt` (`Adopt`),
    /// or when a client connection gets a gate (`Dialed`).
    ///
    /// # Errors
    ///
    /// A [`Refusal`] closes the connection abortively without reading.
    fn admit(
        &self,
        info: &ConnectionInfo,
        stage: AdmitStage,
    ) -> Result<Admitted<Self::Ticket>, Refusal>;

    /// After a trusted PROXY header revealed the real client (`info.real_peer` is set).
    ///
    /// There is no default: a gate that does not care about proxies writes `Ok(())`
    /// on purpose (decision D-060).
    ///
    /// # Errors
    ///
    /// A [`Refusal`] closes the connection abortively.
    fn readmit(&self, ticket: &mut Self::Ticket, info: &ConnectionInfo) -> Result<(), Refusal>;

    /// Before every write system call. The path where nothing is revoked should be one atomic load.
    ///
    /// # Errors
    ///
    /// A [`Denial`] wipes pending output, writes the session's denial if no byte of
    /// the current response has left, and resets the connection.
    fn check(&self, ticket: &mut Self::Ticket, write: &WriteCheck) -> Result<(), Denial>;

    /// Exactly once per admitted connection, after it closed, with its one close reason.
    fn closed(&self, ticket: Self::Ticket, info: &ConnectionInfo, reason: CloseReason) {
        let _ = (ticket, info, reason);
    }
}

/// When `Gate::admit` runs.
///
/// ```
/// assert_ne!(net_io::AdmitStage::Accept, net_io::AdmitStage::Dialed);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AdmitStage {
    /// After accept, before any read.
    Accept,
    /// A dialed connection adopted into a server.
    Adopt,
    /// A client connection that got a gate.
    Dialed,
}

/// What admission grants.
///
/// ```
/// let a = net_io::Admitted { lane: net_io::Lane(1), ticket: (), tag: net_io::GateTag(5) };
/// assert_eq!(a.tag.0, 5);
/// ```
#[derive(Debug)]
pub struct Admitted<T> {
    /// The connection's lane.
    pub lane: Lane,
    /// The gate's per-connection state.
    pub ticket: T,
    /// The gate's opaque name for the connection, stored in `ConnectionInfo::gate`.
    pub tag: GateTag,
}

/// How a connection is refused.
///
/// ```
/// let r = net_io::Refusal::WithBytes { code: 3, bytes: b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 5\r\n\r\n" };
/// assert_eq!(r.code(), 3);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Close with RST.
    Reset {
        /// The gate's code.
        code: u16,
    },
    /// Write these bytes once (non-blocking, at most 512), then RST.
    WithBytes {
        /// The gate's code.
        code: u16,
        /// The reply.
        bytes: &'static [u8],
    },
}

impl Refusal {
    /// The gate's code.
    #[must_use]
    pub fn code(&self) -> u16 {
        match self {
            Refusal::Reset { code } | Refusal::WithBytes { code, .. } => *code,
        }
    }
}

/// The write the gate is asked about.
///
/// ```
/// use net_io::{ConnectionId, Lane, WriteCheck};
/// let w = WriteCheck::new(ConnectionId::new(1).unwrap(), Lane(0), 512, false, None);
/// assert_eq!(w.bytes, 512);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteCheck {
    /// The connection.
    pub id: ConnectionId,
    /// Its lane.
    pub lane: Lane,
    /// The size of the chunk about to be written.
    pub bytes: u32,
    /// Whether a byte of the current response already left.
    pub response_started: bool,
    /// The tag the session gave `Output::begin_tagged_response`.
    pub response: Option<GateTag>,
}

impl WriteCheck {
    /// Builds a check (for tests of gates).
    #[must_use]
    pub fn new(
        id: ConnectionId,
        lane: Lane,
        bytes: u32,
        response_started: bool,
        response: Option<GateTag>,
    ) -> WriteCheck {
        WriteCheck {
            id,
            lane,
            bytes,
            response_started,
            response,
        }
    }
}

/// A gate's refusal of a write.
///
/// ```
/// let d = net_io::Denial { code: 403 };
/// assert_eq!(d.code, 403);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Denial {
    /// The gate's code, given to `Session::on_denied`.
    pub code: u16,
}

/// The explicit "no gate": admits every connection in `Lane(0)` with `GateTag(0)` and never denies.
///
/// ```
/// use net_io::{AdmitStage, AllowAll, ConnectionInfo, Gate};
/// let info = ConnectionInfo::for_testing("127.0.0.1:1".parse().unwrap());
/// assert!(AllowAll.admit(&info, AdmitStage::Accept).is_ok());
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct AllowAll;

impl Gate for AllowAll {
    type Ticket = ();
    #[inline(always)]
    fn admit(&self, _info: &ConnectionInfo, _stage: AdmitStage) -> Result<Admitted<()>, Refusal> {
        Ok(Admitted {
            lane: Lane::MOST_IMPORTANT,
            ticket: (),
            tag: GateTag(0),
        })
    }
    #[inline(always)]
    fn readmit(&self, _ticket: &mut (), _info: &ConnectionInfo) -> Result<(), Refusal> {
        Ok(())
    }
    #[inline(always)]
    fn check(&self, _ticket: &mut (), _write: &WriteCheck) -> Result<(), Denial> {
        Ok(())
    }
}

/// Calls `f`, turning a panic into `None` (fail closed for gate and session hooks).
pub(crate) fn guarded<R>(f: impl FnOnce() -> R) -> Option<R> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).ok()
}

/// A gate and one connection's ticket, type-erased for `TcpConnection`.
pub(crate) trait ErasedGate: Send {
    fn check(&mut self, write: &WriteCheck) -> Result<(), Denial>;
    /// `Gate::readmit` with the current ticket (a panic refuses).
    #[cfg_attr(not(feature = "proxy"), allow(dead_code))]
    fn readmit(&mut self, info: &ConnectionInfo) -> Result<(), Refusal>;
    fn close(&mut self, info: &ConnectionInfo, reason: CloseReason);
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any + Send>;
}

/// The erased form of a gate plus its current ticket.
pub(crate) struct GateCell<G: Gate> {
    pub(crate) gate: Arc<G>,
    pub(crate) ticket: Option<G::Ticket>,
}

impl<G: Gate> ErasedGate for GateCell<G> {
    fn check(&mut self, write: &WriteCheck) -> Result<(), Denial> {
        let gate = &self.gate;
        match self.ticket.as_mut() {
            Some(ticket) => {
                guarded(|| gate.check(ticket, write)).unwrap_or(Err(Denial { code: 0 }))
            }
            None => Err(Denial { code: 0 }),
        }
    }

    fn readmit(&mut self, info: &ConnectionInfo) -> Result<(), Refusal> {
        let gate = &self.gate;
        match self.ticket.as_mut() {
            Some(ticket) => {
                guarded(|| gate.readmit(ticket, info)).unwrap_or(Err(Refusal::Reset { code: 0 }))
            }
            None => Err(Refusal::Reset { code: 0 }),
        }
    }

    fn close(&mut self, info: &ConnectionInfo, reason: CloseReason) {
        if let Some(ticket) = self.ticket.take() {
            let gate = &self.gate;
            let _ = guarded(|| gate.closed(ticket, info, reason));
        }
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any + Send> {
        self
    }
}

/// Closes one connection abortively from any thread.
///
/// The owning thread does the close; the killer only sets a flag and wakes it,
/// so it can never close a reused descriptor number.
///
/// # Examples
///
/// ```no_run
/// use net_io::KillReason;
/// let mut conn = net_io::connect("127.0.0.1:7000")?;
/// let kill = conn.kill_handle();
/// std::thread::spawn(move || {
///     std::thread::sleep(std::time::Duration::from_secs(1));
///     kill.kill(KillReason(1));
/// });
/// let mut buf = [0u8; 16];
/// assert!(matches!(conn.recv(&mut buf), Err(net_io::NetError::Killed { .. })));
/// # Ok::<(), net_io::NetError>(())
/// ```
#[derive(Clone)]
pub struct KillHandle {
    pub(crate) slot: Arc<KillSlot>,
    pub(crate) generation: u32,
    pub(crate) id: ConnectionId,
}

impl KillHandle {
    /// Kills the connection; `false` if it already closed (or was already killed).
    pub fn kill(&self, reason: KillReason) -> bool {
        self.slot.kill(self.generation, reason)
    }

    /// The connection's id.
    #[must_use]
    pub fn id(&self) -> ConnectionId {
        self.id
    }

    /// Whether the connection is still open: a snapshot, for diagnostics only.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.slot.is_open(self.generation)
    }
}

impl fmt::Debug for KillHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KillHandle")
            .field("id", &self.id)
            .field("open", &self.is_open())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Panics;
    impl Gate for Panics {
        type Ticket = ();
        fn admit(&self, _: &ConnectionInfo, _: AdmitStage) -> Result<Admitted<()>, Refusal> {
            Err(Refusal::Reset { code: 1 })
        }
        fn readmit(&self, _: &mut (), _: &ConnectionInfo) -> Result<(), Refusal> {
            Ok(())
        }
        #[allow(clippy::panic)]
        fn check(&self, _: &mut (), _: &WriteCheck) -> Result<(), Denial> {
            panic!("gate bug")
        }
    }

    #[test]
    fn test_gate_panic_in_check_denies() {
        let mut cell = GateCell {
            gate: Arc::new(Panics),
            ticket: Some(()),
        };
        let w = WriteCheck::new(ConnectionId::new(1).unwrap(), Lane(0), 1, false, None);
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let r = cell.check(&w);
        std::panic::set_hook(prev);
        assert_eq!(r, Err(Denial { code: 0 }));
    }

    #[test]
    fn test_allow_all_admits_and_allows() {
        let info = ConnectionInfo::for_testing("127.0.0.1:1".parse().unwrap());
        assert!(AllowAll.admit(&info, AdmitStage::Accept).is_ok());
        let mut cell = GateCell {
            gate: Arc::new(AllowAll),
            ticket: Some(()),
        };
        let w = WriteCheck::new(info.id, Lane(0), 10, false, None);
        assert!(cell.check(&w).is_ok());
        cell.close(&info, CloseReason::SessionClosed);
        assert!(cell.check(&w).is_err());
    }

    #[test]
    fn test_refusal_code() {
        assert_eq!(Refusal::Reset { code: 9 }.code(), 9);
    }
}
