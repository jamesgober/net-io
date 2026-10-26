//! # net_io
//!
//! The network IO substrate for the `-net` and `-io` crates: the entrance and
//! exit every service shares. It owns listeners and sockets, the life of each
//! connection, the limits and timeouts that keep a peer from holding what it
//! should not, graceful drain, and the seams a connection gate and a TLS engine
//! plug into. It is protocol-free and has no runtime dependencies.
//!
//! ## Quick start
//!
//! ```no_run
//! fn main() -> Result<(), net_io::NetError> {
//!     // An echo server: one handler call per connection on a bounded worker pool,
//!     // with every default limit (idle, read, write, minimum rate, caps) applied.
//!     let server = net_io::serve("127.0.0.1:7000", |conn| {
//!         let mut buf = [0u8; 4096];
//!         loop {
//!             let n = conn.recv(&mut buf)?;
//!             if n == 0 {
//!                 return Ok(()); // the peer closed its side
//!             }
//!             conn.send_all(&buf[..n])?;
//!         }
//!     })?;
//!
//!     // A client.
//!     let mut conn = net_io::connect("127.0.0.1:7000")?;
//!     conn.send_all(b"ping")?;
//!     let mut reply = [0u8; 4];
//!     conn.recv_exact(&mut reply)?;
//!     assert_eq!(&reply, b"ping");
//!
//!     // Stop: close the door, drain open connections, join the workers.
//!     server.handle().request_stop();
//!     let report = server.wait_for_stop();
//!     println!("{} closed gracefully, {} killed", report.graceful, report.killed);
//!     Ok(())
//! }
//! ```
//!
//! Everything else (several listeners, a gate, events, the control line) goes
//! through [`ServerBuilder`]. The full reference with every item, its errors,
//! and its cost is `docs/API.md` in the
//! [repository](https://github.com/jamesgober/net-io).
//!
//! ## Status
//!
//! `0.4.0`: TCP, Unix domain sockets, and UDP on the blocking driver (Linux,
//! macOS, Windows; Unix sockets and hand-off on Unix), the PROXY protocol, the
//! TLS seam on listeners, systemd and FastCGI inheritance, and listener
//! hand-off. The reactor and Windows named pipes arrive in `0.5.0`.

#![doc(html_root_url = "https://docs.rs/net-io")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::dbg_macro,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]

mod accept;
mod addr;
mod buf;
mod completer;
mod control;
mod crc32c;
mod driver;
mod error;
mod events;
mod gate;
mod handoff;
mod id;
mod info;
mod inherit;
mod limits;
mod link;
#[cfg(feature = "local")]
mod local;
mod opts;
mod proxy;
#[cfg(feature = "proxy")]
mod proxy_parse;
mod rate;
mod server;
mod session;
mod sys;
mod tcp;
#[cfg(test)]
mod testing;
mod time;
mod tls;
mod trusted;
#[cfg(feature = "udp")]
mod udp;

/// Entry points for net-io's fuzz targets (`fuzz/`), compiled only under
/// cargo-fuzz (`--cfg fuzzing`). Not part of the public API and not covered by semver.
#[cfg(fuzzing)]
#[doc(hidden)]
pub mod __fuzz {
    /// The hand-off manifest decoder.
    pub fn manifest(data: &[u8]) {
        crate::handoff::fuzz_manifest(data);
    }

    /// The systemd environment reader.
    pub fn systemd_env(data: &[u8]) {
        crate::inherit::fuzz_systemd_env(data);
    }
}

/// Fault injection for net-io's own tests, compiled only with `--cfg net_io_shim`.
/// Not part of the public API and not covered by semver.
#[cfg(net_io_shim)]
#[doc(hidden)]
pub mod __shim {
    pub use crate::sys::shim::{Fault, Op, clear, counted, program, start_counting, stop_counting};
}

use std::net::ToSocketAddrs;

pub use addr::{AddrError, Cidr, PrefixKey, PrefixPolicy, normalize, normalize_socket};
pub use buf::{Buffer, BufferPool, PoolStats};
pub use completer::{Completer, PostError};
pub use control::{ControlLine, ControlState, NoControl, SimpleControl};
pub use driver::DriverKind;
pub use error::{
    CloseReason, ConfigReason, Direction, ErrorClass, KillReason, LimitKind, NetError,
    OsErrorClass, RefusalCause, TimeoutKind,
};
pub use events::{CoalescedKind, Event, EventSink, NoopSink};
pub use gate::{AdmitStage, Admitted, AllowAll, Denial, Gate, KillHandle, Refusal, WriteCheck};
pub use handoff::{HandoffError, HandoffPeer, ListenerHandle};
#[cfg(all(unix, feature = "local"))]
pub use handoff::{recv_listeners, send_listeners};
pub use id::{ConnectionId, ListenerId, WorkerId};
pub use info::{
    ConnectionInfo, Endpoint, GateTag, Lane, Origin, PeerCredentials, PipeName, Transport, UnixPath,
};
#[cfg(unix)]
pub use inherit::fastcgi_listener;
pub use inherit::{InheritError, InheritedListener, systemd, systemd_named};
pub use limits::{Limits, LimitsBuilder, MinRate, Pressure, SizeClass};
#[cfg(all(unix, feature = "local"))]
pub use local::{Descriptors, UnixConnection, UnixListener};
#[cfg(feature = "local")]
pub use local::{LocalConnection, LocalListener};
pub use opts::{Keepalive, Linger, ListenOptions, LocalOptions, SocketOptions, TcpOptions};
pub use proxy::{ProxyError, ProxyFacts, ProxyMode, ProxyVersions};
#[cfg(feature = "proxy")]
pub use proxy_parse::{
    ProxyAddress, ProxyCommand, ProxyHeader, ProxyParser, ProxyProgress, ProxySsl, ProxyTransport,
    Tlv, Tlvs,
};
pub use server::{
    AdoptSpec, BlockingHandler, DoorState, DrainReport, ListenerSpec, NoGate, NoWork, Server,
    ServerBuilder, ServerHandle, Sessions, Stats, Workload,
};
pub use session::{
    Input, Output, OutputFull, Phase, Session, SessionContext, SessionFactory, Step, SwapError,
};
pub use tcp::{ConnectOptions, ListenerInfo, TcpConnection, TcpListener};
pub use time::{Clock, ManualClock, MonotonicClock, monotonic_micros};
pub use tls::{
    NoTls, NoTlsSession, TlsAcceptor, TlsCloseKind, TlsError, TlsEvent, TlsFailure, TlsInfo,
    TlsProgress, TlsSession,
};
pub use trusted::TrustedProxies;
#[cfg(feature = "udp")]
pub use udp::{Datagram, UdpBudget, UdpOptions, UdpSocket, UdpStats};

/// Crate version string, populated by Cargo at build time.
///
/// ```
/// assert!(!net_io::VERSION.is_empty());
/// ```
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Binds a TCP listener with safe defaults: backlog 1,024 (capped by the OS);
/// `SO_REUSEADDR` on Unix; `SO_EXCLUSIVEADDRUSE` on Windows; IPv6-only for IPv6
/// addresses; close-on-exec. The first resolved address that binds wins.
///
/// # Errors
///
/// `AddrInUse`, `PermissionDenied`, `AddrNotAvailable`, `NoAddresses`, `Bind`.
///
/// # Examples
///
/// ```
/// let listener = net_io::listen("127.0.0.1:0")?;
/// let addr = listener.local_addr()?;
/// println!("listening on {addr}, backlog {:?}", listener.info().backlog);
/// # Ok::<(), net_io::NetError>(())
/// ```
pub fn listen<A: ToSocketAddrs>(addr: A) -> Result<TcpListener, NetError> {
    TcpListener::bind(addr)
}

/// Connects with a total timeout of 10 s across every resolved address,
/// `TCP_NODELAY` on, and default limits (read and write timeouts 30 s).
///
/// # Errors
///
/// `ConnectTimeout`, `ConnectionRefused`, `HostUnreachable`, `NetworkUnreachable`, `NoAddresses`.
///
/// # Examples
///
/// ```no_run
/// let mut conn = net_io::connect("example.com:80")?;
/// conn.send_all(b"HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")?;
/// let mut head = [0u8; 512];
/// let n = conn.recv(&mut head)?;
/// println!("{}", String::from_utf8_lossy(&head[..n]));
/// # Ok::<(), net_io::NetError>(())
/// ```
pub fn connect<A: ToSocketAddrs>(addr: A) -> Result<TcpConnection, NetError> {
    TcpConnection::connect(addr)
}

/// Starts a server on the blocking driver that runs `handler` once per
/// connection on a pool worker, with default limits and [`AllowAll`] as the
/// gate; the door is open on return. `Ok(())` closes the connection
/// gracefully; `Err` closes it abortively.
///
/// Keep the returned `Server`: dropping it stops the server. A server facing
/// the internet should set a [`Gate`] through [`ServerBuilder`].
///
/// # Errors
///
/// As [`listen`]; `InvalidConfig` when the worker count exceeds the descriptor limit.
///
/// # Examples
///
/// ```no_run
/// use std::io::{BufRead, BufReader, Write};
///
/// // Handlers can use std::io traits: TcpConnection implements Read and Write.
/// let server = net_io::serve("127.0.0.1:7001", |conn| {
///     let mut line = String::new();
///     BufReader::new(&mut *conn).read_line(&mut line)?;
///     conn.write_all(line.to_uppercase().as_bytes())?;
///     Ok(())
/// })?;
/// server.wait_for_stop();
/// # Ok::<(), net_io::NetError>(())
/// ```
pub fn serve<A, F>(addr: A, handler: F) -> Result<Server, NetError>
where
    A: ToSocketAddrs,
    F: Fn(&mut TcpConnection) -> Result<(), NetError> + Send + Sync + 'static,
{
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp(addr))
        .driver(DriverKind::Blocking)
        .handler(handler)
        .gate(AllowAll)
        .build()?;
    server.open_door()?;
    Ok(server)
}

/// Starts a server that drives sans-IO [`Session`]s, with default limits and
/// [`AllowAll`] as the gate; the door is open on return. Any
/// `Fn(&ConnectionInfo) -> S` is a factory.
///
/// # Errors
///
/// As [`serve`].
///
/// # Examples
///
/// ```no_run
/// use net_io::{Input, Session, SessionContext, Step};
///
/// struct Echo;
/// impl Session for Echo {
///     fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
///         let taken = cx.output().push_partial(input.bytes());
///         input.consume(taken);
///         Step::Write
///     }
/// }
///
/// let server = net_io::serve_sessions("127.0.0.1:7002", |_info: &net_io::ConnectionInfo| Echo)?;
/// server.wait_for_stop();
/// # Ok::<(), net_io::NetError>(())
/// ```
pub fn serve_sessions<A, F>(addr: A, factory: F) -> Result<Server, NetError>
where
    A: ToSocketAddrs,
    F: SessionFactory,
{
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp(addr))
        .sessions(factory)
        .gate(AllowAll)
        .build()?;
    server.open_door()?;
    Ok(server)
}

/// Opens a local IPC listener: on Unix, a Unix domain socket at the path `name`
/// with mode `0600` (only the owner may connect; [`LocalOptions`] and
/// `UnixListener::bind_with` for more). On Windows, named pipes arrive in
/// `0.5.0`; until then this returns `Unsupported`.
///
/// # Errors
///
/// `PathTooLong`, `StaleSocketInUse` (a live listener owns the path, or it is
/// not a socket), `PermissionDenied`, `NotFound`, `Unsupported`, `Os`.
///
/// ```no_run
/// let listener = net_io::listen_local("/run/myapp/control.sock")?;
/// let (mut conn, info) = listener.accept()?;
/// println!("peer process {:?}", info.peer_credentials.and_then(|c| c.pid));
/// conn.send_all(b"ok\n")?;
/// # Ok::<(), net_io::NetError>(())
/// ```
#[cfg(feature = "local")]
pub fn listen_local(name: &str) -> Result<LocalListener, NetError> {
    local::listen(name)
}

/// Connects to a local IPC listener (see [`listen_local`]); waits up to 10 s
/// when its backlog is full.
///
/// # Errors
///
/// `NotFound` (no socket, or nobody listening), `PermissionDenied`,
/// `TimedOut { kind: Connect }`, `PathTooLong`, `Unsupported`, `Os`.
///
/// ```no_run
/// let mut conn = net_io::connect_local("/run/myapp/control.sock")?;
/// conn.send_all(b"status\n")?;
/// # Ok::<(), net_io::NetError>(())
/// ```
#[cfg(feature = "local")]
pub fn connect_local(name: &str) -> Result<LocalConnection, NetError> {
    local::connect(name)
}

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn test_version_matches_manifest() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert_eq!(VERSION.split('.').count(), 3, "expected MAJOR.MINOR.PATCH");
    }
}
