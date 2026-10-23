//! Errors, close reasons, and the small enums they carry.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::addr::AddrError;
use crate::driver::DriverKind;
use crate::handoff::HandoffError;
use crate::inherit::InheritError;
use crate::proxy::ProxyError;
use crate::tls::TlsError;

/// The one error type of the crate.
///
/// Every variant's `Display` says what happened and what to do about it.
///
/// # Examples
///
/// ```no_run
/// use net_io::{ErrorClass, NetError};
///
/// match net_io::connect("127.0.0.1:9") {
///     Ok(_) => {}
///     Err(NetError::ConnectionRefused { addr }) => eprintln!("nothing listens on {addr}"),
///     Err(e) if e.class() == ErrorClass::Timeout => eprintln!("slow network: {e}"),
///     Err(e) => return Err(e),
/// }
/// # Ok::<(), NetError>(())
/// ```
#[non_exhaustive]
#[derive(Debug)]
pub enum NetError {
    /// Binding failed for a reason without its own variant; `source` has the OS error.
    Bind {
        /// The address that could not be bound.
        addr: SocketAddr,
        /// The OS error.
        source: io::Error,
    },
    /// Another socket holds the address.
    AddrInUse {
        /// The address in use.
        addr: SocketAddr,
    },
    /// The address is not on this host, or IPv6 is disabled.
    AddrNotAvailable {
        /// The address that is not available.
        addr: SocketAddr,
    },
    /// The OS refused the operation for lack of permission.
    PermissionDenied {
        /// What was refused.
        what: &'static str,
    },
    /// Name resolution returned no address.
    NoAddresses,
    /// No answer from the peer within the connect deadline.
    ConnectTimeout {
        /// The address that did not answer.
        addr: SocketAddr,
        /// How long the attempt waited.
        after: Duration,
    },
    /// Nothing listens at the address.
    ConnectionRefused {
        /// The address that refused.
        addr: SocketAddr,
    },
    /// No route to the host.
    HostUnreachable {
        /// The unreachable address.
        addr: SocketAddr,
    },
    /// No route to the network.
    NetworkUnreachable {
        /// The unreachable address.
        addr: SocketAddr,
    },
    /// One of net-io's deadlines passed.
    TimedOut {
        /// Which deadline.
        kind: TimeoutKind,
    },
    /// The peer reset the connection.
    ConnectionReset,
    /// A write after the peer closed the connection.
    BrokenPipe,
    /// The connection was already closed by this side or the peer.
    Closed,
    /// A kill handle closed the connection.
    Killed {
        /// The caller's code.
        reason: KillReason,
    },
    /// The gate denied a write; the connection was reset.
    EgressDenied {
        /// The gate's code.
        code: u16,
    },
    /// The connection was refused.
    Refused {
        /// Why.
        cause: RefusalCause,
    },
    /// A configured bound was hit.
    Limit {
        /// Which bound.
        which: LimitKind,
    },
    /// The minimum transfer rate was not met.
    SlowPeer {
        /// In which direction.
        direction: Direction,
    },
    /// A builder or option value is out of range or inconsistent.
    InvalidConfig {
        /// The setter or field that holds the value.
        field: &'static str,
        /// The rule it broke.
        reason: ConfigReason,
    },
    /// The platform lacks the feature.
    Unsupported {
        /// The feature.
        feature: &'static str,
        /// The platform.
        platform: &'static str,
    },
    /// A Unix socket path exceeds the platform limit.
    PathTooLong {
        /// The limit in bytes, including the terminator.
        max: usize,
    },
    /// A live listener owns the socket path, or the path is not a socket.
    StaleSocketInUse {
        /// The path.
        path: PathBuf,
    },
    /// Another process created the named pipe first.
    PipeNameInUse {
        /// The pipe name.
        name: String,
    },
    /// No local endpoint with that name.
    NotFound,
    /// A file shrank while it was being sent.
    FileTruncated {
        /// Bytes sent before the file ended.
        sent: u64,
    },
    /// An address, CIDR block, or trusted-proxy list did not parse.
    Address(AddrError),
    /// A PROXY protocol header was invalid.
    Proxy(ProxyError),
    /// The TLS engine failed.
    Tls(TlsError),
    /// Inherited descriptors failed verification.
    Inherit(InheritError),
    /// A listener hand-off failed; nothing was adopted.
    Handoff(HandoffError),
    /// The selected driver could not start.
    DriverSetup {
        /// The driver that failed.
        driver: DriverKind,
        /// The OS error.
        source: io::Error,
    },
    /// The operation needs the door open.
    DoorClosed,
    /// The server is draining or stopped.
    ShuttingDown,
    /// A server was used in a process created by `fork` after it was built.
    ForkedChild,
    /// Any other OS failure.
    Os {
        /// The operation that failed.
        op: &'static str,
        /// The OS error.
        source: io::Error,
    },
}

/// The broad kind of a [`NetError`], for policy decisions.
///
/// # Examples
///
/// ```
/// use net_io::{ErrorClass, NetError};
/// assert_eq!(NetError::ConnectionReset.class(), ErrorClass::Peer);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorClass {
    /// Fix the configuration.
    Config,
    /// Descriptors, memory, or buffers ran out; retry later.
    Resource,
    /// The other side misbehaved or left.
    Peer,
    /// A deadline passed.
    Timeout,
    /// The gate, a limit, or a refusal stopped it.
    Policy,
    /// The platform lacks the feature.
    Platform,
    /// A contract was broken by the caller.
    Bug,
}

impl NetError {
    /// The broad kind of this error.
    ///
    /// ```
    /// use net_io::{ErrorClass, NetError, TimeoutKind};
    /// assert_eq!(NetError::TimedOut { kind: TimeoutKind::Read }.class(), ErrorClass::Timeout);
    /// ```
    #[must_use]
    pub fn class(&self) -> ErrorClass {
        match self {
            NetError::InvalidConfig { .. }
            | NetError::Address(_)
            | NetError::AddrInUse { .. }
            | NetError::AddrNotAvailable { .. }
            | NetError::PermissionDenied { .. }
            | NetError::NoAddresses
            | NetError::PathTooLong { .. }
            | NetError::StaleSocketInUse { .. }
            | NetError::PipeNameInUse { .. }
            | NetError::NotFound
            | NetError::Bind { .. } => ErrorClass::Config,
            NetError::Limit { which } => match which {
                LimitKind::BufferBudget | LimitKind::Descriptors | LimitKind::CompletionQueue => {
                    ErrorClass::Resource
                }
                _ => ErrorClass::Policy,
            },
            NetError::ConnectTimeout { .. } | NetError::TimedOut { .. } => ErrorClass::Timeout,
            NetError::ConnectionRefused { .. }
            | NetError::HostUnreachable { .. }
            | NetError::NetworkUnreachable { .. }
            | NetError::ConnectionReset
            | NetError::BrokenPipe
            | NetError::Closed
            | NetError::FileTruncated { .. }
            | NetError::Proxy(_)
            | NetError::Tls(_)
            | NetError::SlowPeer { .. } => ErrorClass::Peer,
            NetError::Killed { .. }
            | NetError::EgressDenied { .. }
            | NetError::Refused { .. }
            | NetError::DoorClosed
            | NetError::ShuttingDown => ErrorClass::Policy,
            NetError::Unsupported { .. } | NetError::DriverSetup { .. } => ErrorClass::Platform,
            NetError::ForkedChild => ErrorClass::Bug,
            NetError::Inherit(_) | NetError::Handoff(_) => ErrorClass::Config,
            NetError::Os { source, .. } => class_of_io(source),
        }
    }

    /// Whether retrying the same operation later can succeed.
    ///
    /// ```
    /// use net_io::NetError;
    /// assert!(!NetError::ConnectionReset.is_retryable());
    /// ```
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            NetError::ConnectTimeout { .. }
                | NetError::TimedOut {
                    kind: TimeoutKind::Connect
                }
        ) || self.class() == ErrorClass::Resource
    }

    /// The raw OS error number, when the error came from the OS.
    ///
    /// ```
    /// use net_io::NetError;
    /// assert_eq!(NetError::Closed.os_error_code(), None);
    /// ```
    #[must_use]
    pub fn os_error_code(&self) -> Option<i32> {
        match self {
            NetError::Bind { source, .. }
            | NetError::DriverSetup { source, .. }
            | NetError::Os { source, .. } => source.raw_os_error(),
            _ => None,
        }
    }

    /// Builds the error for a failed OS call, mapping the common kinds to their own variants.
    pub(crate) fn from_os(op: &'static str, source: io::Error) -> NetError {
        match source.kind() {
            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted => {
                NetError::ConnectionReset
            }
            io::ErrorKind::BrokenPipe => NetError::BrokenPipe,
            io::ErrorKind::NotConnected => NetError::Closed,
            _ => NetError::Os { op, source },
        }
    }
}

fn class_of_io(e: &io::Error) -> ErrorClass {
    match e.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => ErrorClass::Timeout,
        io::ErrorKind::OutOfMemory => ErrorClass::Resource,
        io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidInput => ErrorClass::Config,
        io::ErrorKind::Unsupported => ErrorClass::Platform,
        _ => ErrorClass::Peer,
    }
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetError::Bind { addr, source } => write!(f, "could not bind {addr}: {source}"),
            NetError::AddrInUse { addr } => write!(
                f,
                "another socket is listening on {addr}; stop it or choose another port (on restart, use listener hand-off)"
            ),
            NetError::AddrNotAvailable { addr } => write!(
                f,
                "{addr} is not an address of this host (or IPv6 is disabled); bind an address this host owns"
            ),
            NetError::PermissionDenied { what } => write!(
                f,
                "permission denied: {what}; ports below 1024 need privileges: bind before dropping them, or use a high port behind a reverse proxy"
            ),
            NetError::NoAddresses => {
                f.write_str("name resolution returned no address; check the host name")
            }
            NetError::ConnectTimeout { addr, after } => write!(
                f,
                "no answer from {addr} within {after:?}; check reachability or raise the connect timeout"
            ),
            NetError::ConnectionRefused { addr } => {
                write!(f, "{addr} refused the connection; nothing listens there")
            }
            NetError::HostUnreachable { addr } => write!(f, "no route to host {addr}"),
            NetError::NetworkUnreachable { addr } => write!(f, "no route to the network of {addr}"),
            NetError::TimedOut { kind } => write!(
                f,
                "the {} deadline passed; the peer is too slow, or the limit is too low for this workload",
                kind.as_str()
            ),
            NetError::ConnectionReset => f.write_str("the peer reset the connection"),
            NetError::BrokenPipe => f.write_str("write after the peer closed the connection"),
            NetError::Closed => f.write_str("the connection is already closed"),
            NetError::Killed { reason } => {
                write!(f, "the connection was killed (code {})", reason.0)
            }
            NetError::EgressDenied { code } => {
                write!(
                    f,
                    "the gate denied a write (code {code}); the connection was reset"
                )
            }
            NetError::Refused { cause } => {
                write!(f, "the connection was refused: {}", cause.as_str())
            }
            NetError::Limit { which } => {
                write!(
                    f,
                    "the {} limit was reached; raise it or shed load",
                    which.as_str()
                )
            }
            NetError::SlowPeer { direction } => write!(
                f,
                "the peer did not reach the minimum transfer rate ({})",
                direction.as_str()
            ),
            NetError::InvalidConfig { field, reason } => {
                write!(f, "invalid configuration for `{field}`: {reason}")
            }
            NetError::Unsupported { feature, platform } => {
                write!(f, "{feature} is not supported on {platform}")
            }
            NetError::PathTooLong { max } => write!(
                f,
                "the socket path is longer than the platform allows ({max} bytes including the terminator); use a shorter path"
            ),
            NetError::StaleSocketInUse { path } => write!(
                f,
                "{} is in use by a live listener or is not a socket; stop that listener or choose another path",
                path.display()
            ),
            NetError::PipeNameInUse { name } => write!(
                f,
                "another process created the pipe {name} first (possible squatting); choose another name or find that process"
            ),
            NetError::NotFound => {
                f.write_str("no local endpoint with that name; start the server first")
            }
            NetError::FileTruncated { sent } => write!(
                f,
                "the file ended after {sent} bytes while it was being sent; the connection was reset"
            ),
            NetError::Address(e) => write!(f, "{e}"),
            NetError::Proxy(e) => write!(f, "PROXY protocol: {e}"),
            NetError::Tls(e) => write!(f, "TLS: {e}"),
            NetError::Inherit(e) => write!(f, "inherited listeners: {e}"),
            NetError::Handoff(e) => write!(f, "listener hand-off: {e}"),
            NetError::DriverSetup { driver, source } => write!(
                f,
                "the {driver:?} driver could not start: {source}; use DriverKind::Auto or the blocking driver"
            ),
            NetError::DoorClosed => f.write_str("the door is closed; call open_door first"),
            NetError::ShuttingDown => f.write_str("the server is draining or stopped"),
            NetError::ForkedChild => f.write_str(
                "a server was used in a child process after fork; create servers after forking",
            ),
            NetError::Os { op, source } => write!(f, "{op} failed: {source}"),
        }
    }
}

impl std::error::Error for NetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NetError::Bind { source, .. }
            | NetError::DriverSetup { source, .. }
            | NetError::Os { source, .. } => Some(source),
            NetError::Address(e) => Some(e),
            NetError::Proxy(e) => Some(e),
            NetError::Tls(e) => Some(e),
            NetError::Inherit(e) => Some(e),
            NetError::Handoff(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for NetError {
    fn from(e: io::Error) -> NetError {
        match e.kind() {
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => NetError::TimedOut {
                kind: TimeoutKind::Read,
            },
            _ => NetError::from_os("io", e),
        }
    }
}

impl From<AddrError> for NetError {
    fn from(e: AddrError) -> NetError {
        NetError::Address(e)
    }
}

impl From<NetError> for io::Error {
    fn from(e: NetError) -> io::Error {
        let kind = match &e {
            NetError::TimedOut { .. }
            | NetError::ConnectTimeout { .. }
            | NetError::SlowPeer { .. } => io::ErrorKind::TimedOut,
            NetError::ConnectionReset | NetError::Killed { .. } | NetError::EgressDenied { .. } => {
                io::ErrorKind::ConnectionReset
            }
            NetError::BrokenPipe => io::ErrorKind::BrokenPipe,
            NetError::Closed => io::ErrorKind::NotConnected,
            NetError::ConnectionRefused { .. } => io::ErrorKind::ConnectionRefused,
            NetError::AddrInUse { .. } => io::ErrorKind::AddrInUse,
            NetError::AddrNotAvailable { .. } => io::ErrorKind::AddrNotAvailable,
            NetError::PermissionDenied { .. } => io::ErrorKind::PermissionDenied,
            NetError::NotFound => io::ErrorKind::NotFound,
            NetError::Unsupported { .. } => io::ErrorKind::Unsupported,
            NetError::InvalidConfig { .. } | NetError::Address(_) => io::ErrorKind::InvalidInput,
            _ => io::ErrorKind::Other,
        };
        io::Error::new(kind, e)
    }
}

/// Why a connection closed. Every connection ends with exactly one.
///
/// # Examples
///
/// ```
/// use net_io::{CloseReason, Direction};
/// let reason = CloseReason::SlowPeer { direction: Direction::In };
/// assert_eq!(reason.as_str(), "slow_peer_in");
/// assert!(reason.is_abortive());
/// assert!(!CloseReason::PeerClosed.is_abortive());
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CloseReason {
    /// The peer closed its side and the session closed.
    PeerClosed,
    /// The peer sent RST.
    PeerReset,
    /// No exchange started within the idle timeout.
    Idle,
    /// The PROXY header and TLS handshake did not finish within the handshake timeout.
    HandshakeTimeout,
    /// No progress within the read timeout.
    ReadTimeout,
    /// No progress within the write timeout.
    WriteTimeout,
    /// The session's deadline for the current exchange passed.
    ExchangeDeadline,
    /// A parked connection was not woken in time.
    ParkDeadline,
    /// The minimum transfer rate was not met.
    SlowPeer {
        /// In which direction.
        direction: Direction,
    },
    /// Refused at accept or by the session factory.
    Refused(RefusalCause),
    /// A PROXY-required listener got a connection from an untrusted peer.
    ProxyUntrusted,
    /// A trusted peer sent no PROXY header.
    ProxyMissing,
    /// The PROXY header was malformed or too large.
    ProxyInvalid,
    /// The TLS engine failed.
    TlsFailed,
    /// The TLS engine's hello hook refused the ClientHello.
    HelloRefused,
    /// A kill handle closed the connection.
    Killed(KillReason),
    /// The gate denied a write.
    EgressDenied(u16),
    /// The session finished after drain started.
    Drained,
    /// The session had not finished when the drain deadline passed.
    DrainDeadline,
    /// The control line shed this lane.
    Shed,
    /// The control line said `Stopping`, or the server shut down.
    Shutdown,
    /// The session returned `Step::Close`.
    SessionClosed,
    /// The session returned `Step::Abort`, or a handler returned an error.
    SessionError,
    /// The session panicked.
    SessionPanicked,
    /// A per-connection bound was hit.
    Limit(LimitKind),
    /// The OS reported an error not covered above.
    Io(OsErrorClass),
}

impl CloseReason {
    /// A stable snake_case name for logs.
    ///
    /// ```
    /// assert_eq!(net_io::CloseReason::Idle.as_str(), "idle");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            CloseReason::PeerClosed => "peer_closed",
            CloseReason::PeerReset => "peer_reset",
            CloseReason::Idle => "idle",
            CloseReason::HandshakeTimeout => "handshake_timeout",
            CloseReason::ReadTimeout => "read_timeout",
            CloseReason::WriteTimeout => "write_timeout",
            CloseReason::ExchangeDeadline => "exchange_deadline",
            CloseReason::ParkDeadline => "park_deadline",
            CloseReason::SlowPeer {
                direction: Direction::In,
            } => "slow_peer_in",
            CloseReason::SlowPeer {
                direction: Direction::Out,
            } => "slow_peer_out",
            CloseReason::Refused(_) => "refused",
            CloseReason::ProxyUntrusted => "proxy_untrusted",
            CloseReason::ProxyMissing => "proxy_missing",
            CloseReason::ProxyInvalid => "proxy_invalid",
            CloseReason::TlsFailed => "tls_failed",
            CloseReason::HelloRefused => "hello_refused",
            CloseReason::Killed(_) => "killed",
            CloseReason::EgressDenied(_) => "egress_denied",
            CloseReason::Drained => "drained",
            CloseReason::DrainDeadline => "drain_deadline",
            CloseReason::Shed => "shed",
            CloseReason::Shutdown => "shutdown",
            CloseReason::SessionClosed => "session_closed",
            CloseReason::SessionError => "session_error",
            CloseReason::SessionPanicked => "session_panicked",
            CloseReason::Limit(_) => "limit",
            CloseReason::Io(_) => "io",
        }
    }

    /// Whether the connection is closed with RST (`true`) or gracefully with FIN (`false`).
    ///
    /// ```
    /// assert!(net_io::CloseReason::ReadTimeout.is_abortive());
    /// ```
    #[must_use]
    pub fn is_abortive(&self) -> bool {
        !matches!(
            self,
            CloseReason::PeerClosed
                | CloseReason::Idle
                | CloseReason::Drained
                | CloseReason::SessionClosed
        )
    }

    /// An index per variant for per-reason counters (inner values ignored).
    pub(crate) fn index(&self) -> usize {
        match self {
            CloseReason::PeerClosed => 0,
            CloseReason::PeerReset => 1,
            CloseReason::Idle => 2,
            CloseReason::HandshakeTimeout => 3,
            CloseReason::ReadTimeout => 4,
            CloseReason::WriteTimeout => 5,
            CloseReason::ExchangeDeadline => 6,
            CloseReason::ParkDeadline => 7,
            CloseReason::SlowPeer { .. } => 8,
            CloseReason::Refused(_) => 9,
            CloseReason::ProxyUntrusted => 10,
            CloseReason::ProxyMissing => 11,
            CloseReason::ProxyInvalid => 12,
            CloseReason::TlsFailed => 13,
            CloseReason::HelloRefused => 14,
            CloseReason::Killed(_) => 15,
            CloseReason::EgressDenied(_) => 16,
            CloseReason::Drained => 17,
            CloseReason::DrainDeadline => 18,
            CloseReason::Shed => 19,
            CloseReason::Shutdown => 20,
            CloseReason::SessionClosed => 21,
            CloseReason::SessionError => 22,
            CloseReason::SessionPanicked => 23,
            CloseReason::Limit(_) => 24,
            CloseReason::Io(_) => 25,
        }
    }

    /// The number of distinct indexes [`CloseReason::index`] returns.
    pub(crate) const COUNT: usize = 26;

    /// The close reason for a timeout of this kind.
    pub(crate) fn for_timeout(kind: TimeoutKind) -> CloseReason {
        match kind {
            TimeoutKind::Handshake => CloseReason::HandshakeTimeout,
            TimeoutKind::Idle => CloseReason::Idle,
            TimeoutKind::Read | TimeoutKind::Connect => CloseReason::ReadTimeout,
            TimeoutKind::Write => CloseReason::WriteTimeout,
            TimeoutKind::Exchange => CloseReason::ExchangeDeadline,
            TimeoutKind::Park => CloseReason::ParkDeadline,
            TimeoutKind::Drain => CloseReason::DrainDeadline,
        }
    }
}

impl fmt::Display for CloseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a connection was refused.
///
/// ```
/// assert_eq!(net_io::RefusalCause::SourceCap.as_str(), "source_cap");
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RefusalCause {
    /// The global connection cap was reached.
    GlobalCap,
    /// The listener's connection cap was reached.
    ListenerCap,
    /// The per-source concurrency cap was reached.
    SourceCap,
    /// The lane's reservation was used up.
    LaneReserve,
    /// The gate refused, with its code.
    Gate(u16),
    /// The session factory refused.
    Session,
    /// The blocking driver had no free worker.
    Busy,
    /// The door was closed.
    DoorClosed,
    /// The control line shed this lane.
    Shed,
    /// The control line is in lockdown and the listener does not allow it.
    Lockdown,
}

impl RefusalCause {
    /// A stable snake_case name for logs.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            RefusalCause::GlobalCap => "global_cap",
            RefusalCause::ListenerCap => "listener_cap",
            RefusalCause::SourceCap => "source_cap",
            RefusalCause::LaneReserve => "lane_reserve",
            RefusalCause::Gate(_) => "gate",
            RefusalCause::Session => "session",
            RefusalCause::Busy => "busy",
            RefusalCause::DoorClosed => "door_closed",
            RefusalCause::Shed => "shed",
            RefusalCause::Lockdown => "lockdown",
        }
    }

    pub(crate) fn index(&self) -> usize {
        match self {
            RefusalCause::GlobalCap => 0,
            RefusalCause::ListenerCap => 1,
            RefusalCause::SourceCap => 2,
            RefusalCause::LaneReserve => 3,
            RefusalCause::Gate(_) => 4,
            RefusalCause::Session => 5,
            RefusalCause::Busy => 6,
            RefusalCause::DoorClosed => 7,
            RefusalCause::Shed => 8,
            RefusalCause::Lockdown => 9,
        }
    }

    pub(crate) const COUNT: usize = 10;
}

/// Which configured bound was hit.
///
/// ```
/// assert_eq!(net_io::LimitKind::OutputBudget.as_str(), "output_budget");
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LimitKind {
    /// The global connection cap.
    Connections,
    /// A listener's connection cap.
    PerListener,
    /// The per-source concurrency cap.
    PerSource,
    /// The total buffer budget.
    BufferBudget,
    /// A connection's output budget.
    OutputBudget,
    /// A worker's completion queue.
    CompletionQueue,
    /// The PROXY header size.
    ProxyHeader,
    /// The accept batch.
    AcceptBatch,
    /// A connection's read buffer (full and not consumed).
    ReadBuffer,
    /// The UDP amplification guard.
    Amplification,
    /// A UDP source budget.
    SourceBudget,
    /// The process's descriptor limit.
    Descriptors,
}

impl LimitKind {
    /// A stable snake_case name for logs.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            LimitKind::Connections => "connections",
            LimitKind::PerListener => "per_listener",
            LimitKind::PerSource => "per_source",
            LimitKind::BufferBudget => "buffer_budget",
            LimitKind::OutputBudget => "output_budget",
            LimitKind::CompletionQueue => "completion_queue",
            LimitKind::ProxyHeader => "proxy_header",
            LimitKind::AcceptBatch => "accept_batch",
            LimitKind::ReadBuffer => "read_buffer",
            LimitKind::Amplification => "amplification",
            LimitKind::SourceBudget => "source_budget",
            LimitKind::Descriptors => "descriptors",
        }
    }
}

/// Which deadline passed.
///
/// ```
/// assert_eq!(net_io::TimeoutKind::Idle.as_str(), "idle");
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TimeoutKind {
    /// The handshake (PROXY and TLS).
    Handshake,
    /// Waiting for the next exchange.
    Idle,
    /// Waiting for bytes during an exchange.
    Read,
    /// Waiting for the peer to take bytes.
    Write,
    /// The session's total deadline for the exchange.
    Exchange,
    /// A parked connection.
    Park,
    /// An outbound connect.
    Connect,
    /// A drain.
    Drain,
}

impl TimeoutKind {
    /// A stable snake_case name for logs.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            TimeoutKind::Handshake => "handshake",
            TimeoutKind::Idle => "idle",
            TimeoutKind::Read => "read",
            TimeoutKind::Write => "write",
            TimeoutKind::Exchange => "exchange",
            TimeoutKind::Park => "park",
            TimeoutKind::Connect => "connect",
            TimeoutKind::Drain => "drain",
        }
    }
}

/// A caller-defined code for a kill.
///
/// ```
/// let reason = net_io::KillReason(7);
/// assert_eq!(reason.0, 7);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KillReason(pub u16);

/// A direction of transfer.
///
/// ```
/// assert_eq!(net_io::Direction::In.as_str(), "in");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    /// From the peer to us.
    In,
    /// From us to the peer.
    Out,
}

impl Direction {
    /// `"in"` or `"out"`.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Direction::In => "in",
            Direction::Out => "out",
        }
    }
}

/// The class of an OS error, without its message text.
///
/// ```
/// use net_io::OsErrorClass;
/// let class = OsErrorClass::from_io(&std::io::Error::from(std::io::ErrorKind::ConnectionReset));
/// assert_eq!(class, OsErrorClass::Reset);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OsErrorClass {
    /// The peer reset the connection.
    Reset,
    /// The connection was aborted locally.
    Aborted,
    /// The OS timed the connection out (for example failed keepalive probes).
    TimedOut,
    /// The connection was refused.
    Refused,
    /// No route.
    Unreachable,
    /// A file ended while it was being sent.
    FileTruncated,
    /// Any other OS error, by number.
    Other(i32),
}

impl OsErrorClass {
    /// Classifies an `io::Error`.
    #[must_use]
    pub fn from_io(e: &io::Error) -> OsErrorClass {
        match e.kind() {
            io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe => OsErrorClass::Reset,
            io::ErrorKind::ConnectionAborted => OsErrorClass::Aborted,
            io::ErrorKind::TimedOut => OsErrorClass::TimedOut,
            io::ErrorKind::ConnectionRefused => OsErrorClass::Refused,
            io::ErrorKind::HostUnreachable | io::ErrorKind::NetworkUnreachable => {
                OsErrorClass::Unreachable
            }
            _ => OsErrorClass::Other(e.raw_os_error().unwrap_or(0)),
        }
    }
}

/// The rule a configuration value broke.
///
/// ```
/// use net_io::ConfigReason;
/// assert_eq!(ConfigReason::Zero.to_string(), "zero is not allowed here");
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigReason {
    /// Zero where zero is meaningless.
    Zero,
    /// Above the maximum.
    TooLarge {
        /// The maximum.
        max: u64,
    },
    /// Below the minimum.
    TooSmall {
        /// The minimum.
        min: u64,
    },
    /// A per-listener or per-source cap above the global cap.
    AboveGlobal,
    /// A deadline shorter than one timer tick.
    BelowTick,
    /// The minimum-rate window is shorter than its check interval.
    WindowBelowCheck,
    /// The buffer budget is below workers times the largest class times two.
    BudgetBelowWorkers {
        /// The smallest valid budget in bytes.
        need: u64,
    },
    /// The caps exceed the process's descriptor limit.
    DescriptorLimit {
        /// The descriptor limit.
        have: u64,
        /// Descriptors the configuration needs.
        need: u64,
    },
    /// A required part is not set.
    Missing,
    /// An adopted socket is not a listening socket.
    NotListening,
    /// Values that contradict each other.
    Inconsistent,
}

impl fmt::Display for ConfigReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigReason::Zero => f.write_str("zero is not allowed here"),
            ConfigReason::TooLarge { max } => write!(f, "above the maximum of {max}"),
            ConfigReason::TooSmall { min } => write!(f, "below the minimum of {min}"),
            ConfigReason::AboveGlobal => f.write_str("above the global connection cap"),
            ConfigReason::BelowTick => f.write_str("shorter than one timer tick"),
            ConfigReason::WindowBelowCheck => {
                f.write_str("the minimum-rate window is shorter than its check interval")
            }
            ConfigReason::BudgetBelowWorkers { need } => write!(
                f,
                "the buffer budget must be at least {need} bytes (workers x largest class x 2)"
            ),
            ConfigReason::DescriptorLimit { have, need } => write!(
                f,
                "needs {need} descriptors but the process limit is {have}; raise the limit or lower the caps"
            ),
            ConfigReason::Missing => f.write_str("a required part is not set"),
            ConfigReason::NotListening => {
                f.write_str("the socket is not a listening stream socket")
            }
            ConfigReason::Inconsistent => f.write_str("values contradict each other"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_close_reason_index_covers_every_variant_once() {
        let all = [
            CloseReason::PeerClosed,
            CloseReason::PeerReset,
            CloseReason::Idle,
            CloseReason::HandshakeTimeout,
            CloseReason::ReadTimeout,
            CloseReason::WriteTimeout,
            CloseReason::ExchangeDeadline,
            CloseReason::ParkDeadline,
            CloseReason::SlowPeer {
                direction: Direction::Out,
            },
            CloseReason::Refused(RefusalCause::Busy),
            CloseReason::ProxyUntrusted,
            CloseReason::ProxyMissing,
            CloseReason::ProxyInvalid,
            CloseReason::TlsFailed,
            CloseReason::HelloRefused,
            CloseReason::Killed(KillReason(1)),
            CloseReason::EgressDenied(1),
            CloseReason::Drained,
            CloseReason::DrainDeadline,
            CloseReason::Shed,
            CloseReason::Shutdown,
            CloseReason::SessionClosed,
            CloseReason::SessionError,
            CloseReason::SessionPanicked,
            CloseReason::Limit(LimitKind::ReadBuffer),
            CloseReason::Io(OsErrorClass::Reset),
        ];
        let mut seen = [false; CloseReason::COUNT];
        for r in all {
            assert!(!seen[r.index()], "duplicate index for {r:?}");
            seen[r.index()] = true;
        }
        assert!(seen.iter().all(|s| *s));
    }

    #[test]
    fn test_close_reason_size_is_eight_bytes() {
        assert!(std::mem::size_of::<CloseReason>() <= 8);
    }

    #[test]
    fn test_close_style_graceful_reasons_are_not_abortive() {
        for r in [
            CloseReason::PeerClosed,
            CloseReason::Idle,
            CloseReason::Drained,
            CloseReason::SessionClosed,
        ] {
            assert!(!r.is_abortive());
        }
        assert!(CloseReason::DrainDeadline.is_abortive());
        assert!(CloseReason::Killed(KillReason(0)).is_abortive());
    }

    #[test]
    fn test_from_io_timed_out_maps_to_read_timeout() {
        let e: NetError = io::Error::from(io::ErrorKind::TimedOut).into();
        assert!(matches!(
            e,
            NetError::TimedOut {
                kind: TimeoutKind::Read
            }
        ));
    }

    #[test]
    fn test_from_io_reset_maps_to_connection_reset() {
        let e: NetError = io::Error::from(io::ErrorKind::ConnectionReset).into();
        assert!(matches!(e, NetError::ConnectionReset));
        assert_eq!(e.class(), ErrorClass::Peer);
    }

    #[test]
    fn test_into_io_keeps_kind_and_source() {
        let io_err: io::Error = NetError::BrokenPipe.into();
        assert_eq!(io_err.kind(), io::ErrorKind::BrokenPipe);
        assert!(io_err.get_ref().is_some());
    }

    #[test]
    fn test_retryable_connect_timeout_true_reset_false() {
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert!(
            NetError::ConnectTimeout {
                addr,
                after: Duration::from_secs(1)
            }
            .is_retryable()
        );
        assert!(!NetError::ConnectionReset.is_retryable());
        assert!(
            NetError::Limit {
                which: LimitKind::BufferBudget
            }
            .is_retryable()
        );
    }

    #[test]
    fn test_display_says_what_to_do() {
        let addr: SocketAddr = "0.0.0.0:443".parse().unwrap();
        let text = NetError::AddrInUse { addr }.to_string();
        assert!(text.contains("0.0.0.0:443"));
        assert!(text.contains("hand-off"));
    }

    #[test]
    fn test_os_error_code_present_only_for_os_errors() {
        let e = NetError::Os {
            op: "x",
            source: io::Error::from_raw_os_error(5),
        };
        assert_eq!(e.os_error_code(), Some(5));
        assert_eq!(NetError::NotFound.os_error_code(), None);
    }

    #[test]
    fn test_timeout_kind_maps_to_close_reason() {
        assert_eq!(
            CloseReason::for_timeout(TimeoutKind::Idle),
            CloseReason::Idle
        );
        assert_eq!(
            CloseReason::for_timeout(TimeoutKind::Write),
            CloseReason::WriteTimeout
        );
    }
}
