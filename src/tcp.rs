//! TCP listeners and connections.

use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::net::{Shutdown, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::accept::{Accepted, Acceptor};
use crate::driver::DriverKind;
use crate::error::{CloseReason, ConfigReason, LimitKind, NetError, TimeoutKind};
use crate::gate::KillHandle;
use crate::id::{ConnectionId, ListenerId, WorkerId};
use crate::info::{ConnectionInfo, Endpoint, Origin, Transport};
use crate::limits::{Effective, Limits};
use crate::link::{ClockRef, Got, Link, WakeSource};
use crate::opts::{ListenOptions, SocketOptions, TcpOptions};
use crate::proxy::ProxyMode;
use crate::session::Phase;
use crate::sys::{self, AddrFailure, AsSock, Interest, KillSlot, Ready};

/// Facts about one bound listener.
///
/// ```
/// let listener = net_io::listen("127.0.0.1:0")?;
/// assert!(listener.info().local.socket_addr().is_some());
/// # Ok::<(), net_io::NetError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct ListenerInfo {
    /// The listener's index in its server (0 for a plain listener).
    pub id: ListenerId,
    /// Its name, if one was given.
    pub name: Option<String>,
    /// The bound address.
    pub local: Endpoint,
    /// The effective backlog; `None` when it cannot be read (macOS, adopted sockets).
    pub backlog: Option<u32>,
    /// The kind of socket.
    pub transport: Transport,
    /// Whether it expects a PROXY header.
    pub proxy: ProxyMode,
    /// Whether it serves TLS.
    pub tls: bool,
}

/// Linux silently caps the backlog at `net.core.somaxconn`; read it once.
pub(crate) fn effective_backlog(requested: u32) -> Option<u32> {
    if cfg!(target_os = "linux") {
        let cap = std::fs::read_to_string("/proc/sys/net/core/somaxconn")
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok());
        Some(cap.map_or(requested, |c| requested.min(c)))
    } else if cfg!(windows) {
        Some(requested)
    } else {
        None
    }
}

/// Whether accepted sockets inherit the listener's options (spike S-4, decision D-055).
const OPTIONS_INHERITED: bool = cfg!(any(target_os = "linux", windows));

pub(crate) fn bind_error(addr: SocketAddr, e: io::Error) -> NetError {
    match sys::classify_addr_error(&e) {
        AddrFailure::InUse => NetError::AddrInUse { addr },
        AddrFailure::NotAvailable => NetError::AddrNotAvailable { addr },
        AddrFailure::Permission => NetError::PermissionDenied { what: "bind" },
        _ if e.kind() == io::ErrorKind::Unsupported => NetError::Unsupported {
            feature: "SO_REUSEPORT",
            platform: std::env::consts::OS,
        },
        _ => NetError::Bind { addr, source: e },
    }
}

fn connect_error(addr: SocketAddr, after: Duration, e: io::Error) -> NetError {
    match sys::classify_addr_error(&e) {
        AddrFailure::Refused => NetError::ConnectionRefused { addr },
        AddrFailure::HostUnreachable => NetError::HostUnreachable { addr },
        AddrFailure::NetworkUnreachable => NetError::NetworkUnreachable { addr },
        AddrFailure::TimedOut => NetError::ConnectTimeout { addr, after },
        AddrFailure::NotAvailable => NetError::AddrNotAvailable { addr },
        AddrFailure::Permission => NetError::PermissionDenied { what: "connect" },
        _ => NetError::Os {
            op: "connect",
            source: e,
        },
    }
}

fn resolve<A: ToSocketAddrs>(addr: A) -> Result<Vec<SocketAddr>, NetError> {
    let addrs: Vec<SocketAddr> = addr
        .to_socket_addrs()
        .map_err(|e| NetError::Os {
            op: "resolve",
            source: e,
        })?
        .collect();
    if addrs.is_empty() {
        return Err(NetError::NoAddresses);
    }
    Ok(addrs)
}

/// A listening TCP socket created by net-io, so options that must precede `bind` can be set.
///
/// # Examples
///
/// ```no_run
/// let listener = net_io::listen("0.0.0.0:7000")?;
/// loop {
///     let (mut conn, info) = listener.accept()?;
///     println!("connection {} from {:?}", info.id, info.client_addr());
///     conn.send_all(b"hello\n")?;
///     conn.close()?;
/// }
/// # Ok::<(), net_io::NetError>(())
/// ```
#[derive(Debug)]
pub struct TcpListener {
    inner: std::net::TcpListener,
    info: ListenerInfo,
    tcp: TcpOptions,
    acceptor: Mutex<Acceptor>,
}

impl TcpListener {
    /// Binds with safe defaults (see [`crate::listen`]).
    ///
    /// # Errors
    ///
    /// `AddrInUse`, `PermissionDenied`, `AddrNotAvailable`, `NoAddresses`, `Bind`.
    pub fn bind<A: ToSocketAddrs>(addr: A) -> Result<TcpListener, NetError> {
        TcpListener::bind_with(addr, ListenOptions::new())
    }

    /// Binds with `options`, applied in the order `docs/API.md` gives.
    ///
    /// # Errors
    ///
    /// As [`TcpListener::bind`]; `Unsupported` for an option the platform lacks.
    pub fn bind_with<A: ToSocketAddrs>(
        addr: A,
        options: ListenOptions,
    ) -> Result<TcpListener, NetError> {
        let mut last = NetError::NoAddresses;
        for a in resolve(addr)? {
            match sys::tcp_listener(a, &options.params()) {
                Ok(l) => return TcpListener::finish(l, options, ListenerId(0), None),
                Err(e) => last = bind_error(a, e),
            }
        }
        Err(last)
    }

    pub(crate) fn finish(
        inner: std::net::TcpListener,
        options: ListenOptions,
        id: ListenerId,
        name: Option<String>,
    ) -> Result<TcpListener, NetError> {
        let local = inner
            .local_addr()
            .map_err(|e| NetError::from_os("getsockname", e))?;
        if OPTIONS_INHERITED && !options.tcp.is_empty() {
            options.tcp.apply(&inner, local.is_ipv6())?;
        }
        Ok(TcpListener {
            info: ListenerInfo {
                id,
                name,
                local: Endpoint::Ip(local),
                backlog: effective_backlog(options.backlog),
                transport: Transport::Tcp,
                proxy: ProxyMode::Off,
                tls: false,
            },
            inner,
            tcp: options.tcp,
            acceptor: Mutex::new(Acceptor::new()),
        })
    }

    /// Blocks until a connection arrives; applies per-connection options, normalizes
    /// the peer, issues a `ConnectionId`. No admission: a plain listener has no gate.
    ///
    /// # Errors
    ///
    /// `Limit { which: Descriptors }` when exhaustion persists past one backoff step; `Os`.
    pub fn accept(&self) -> Result<(TcpConnection, ConnectionInfo), NetError> {
        match self.accept_until(None)? {
            Some(pair) => Ok(pair),
            None => Err(NetError::TimedOut {
                kind: TimeoutKind::Read,
            }),
        }
    }

    /// As [`TcpListener::accept`], but `Ok(None)` when nothing arrived within `timeout`.
    ///
    /// # Errors
    ///
    /// As [`TcpListener::accept`].
    ///
    /// ```
    /// let listener = net_io::listen("127.0.0.1:0")?;
    /// let got = listener.accept_timeout(std::time::Duration::from_millis(10))?;
    /// assert!(got.is_none());
    /// # Ok::<(), net_io::NetError>(())
    /// ```
    pub fn accept_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Option<(TcpConnection, ConnectionInfo)>, NetError> {
        self.accept_until(Some(Instant::now() + timeout))
    }

    fn accept_until(
        &self,
        deadline: Option<Instant>,
    ) -> Result<Option<(TcpConnection, ConnectionInfo)>, NetError> {
        let mut paused_once = false;
        loop {
            let outcome = self
                .acceptor
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .accept(&self.inner);
            match outcome {
                Accepted::Conn((stream, peer)) => {
                    let conn = TcpConnection::accepted(stream, peer, &self.tcp, self.info.id)?;
                    let info = conn.info().clone();
                    return Ok(Some((conn, info)));
                }
                Accepted::Skipped(_) => continue,
                Accepted::Again => {
                    let timeout = match deadline {
                        None => None,
                        Some(d) => {
                            let left = d.saturating_duration_since(Instant::now());
                            if left.is_zero() {
                                return Ok(None);
                            }
                            Some(left)
                        }
                    };
                    match sys::wait(self.inner.sock(), Interest::Read, None, timeout) {
                        Ok(Ready::TimedOut) => return Ok(None),
                        Ok(_) => continue,
                        Err(e) => return Err(NetError::from_os("poll", e)),
                    }
                }
                Accepted::Pause(backoff) => {
                    if paused_once {
                        return Err(NetError::Limit {
                            which: LimitKind::Descriptors,
                        });
                    }
                    paused_once = true;
                    std::thread::sleep(backoff);
                }
                Accepted::Failed(e) => return Err(NetError::from_os("accept", e)),
            }
        }
    }

    pub(crate) fn std(&self) -> &std::net::TcpListener {
        &self.inner
    }

    /// Records whether the listener serves TLS in its facts.
    pub(crate) fn set_tls(&mut self, on: bool) {
        self.info.tls = on;
    }

    /// Records the listener's PROXY requirement in its facts.
    pub(crate) fn set_proxy_mode(&mut self, mode: crate::proxy::ProxyMode) {
        self.info.proxy = mode;
    }

    pub(crate) fn tcp_options(&self) -> &TcpOptions {
        &self.tcp
    }

    /// Facts about this listener.
    #[must_use]
    pub fn info(&self) -> &ListenerInfo {
        &self.info
    }

    /// The bound address.
    ///
    /// # Errors
    ///
    /// `Os` when `getsockname` fails.
    pub fn local_addr(&self) -> Result<SocketAddr, NetError> {
        self.inner
            .local_addr()
            .map_err(|e| NetError::from_os("getsockname", e))
    }

    /// Adopts an existing listening socket (checked with `SO_ACCEPTCONN` and `SO_TYPE`).
    ///
    /// # Errors
    ///
    /// `InvalidConfig { field: "socket", reason: NotListening }`.
    ///
    /// ```
    /// let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    /// let listener = net_io::TcpListener::from_std(std_listener)?;
    /// assert!(listener.local_addr().is_ok());
    /// # Ok::<(), net_io::NetError>(())
    /// ```
    pub fn from_std(listener: std::net::TcpListener) -> Result<TcpListener, NetError> {
        match sys::is_listening_stream(listener.sock()) {
            Ok(true) => {}
            Ok(false) => {
                return Err(NetError::InvalidConfig {
                    field: "socket",
                    reason: ConfigReason::NotListening,
                });
            }
            Err(e) => return Err(NetError::from_os("getsockopt", e)),
        }
        listener
            .set_nonblocking(true)
            .map_err(|e| NetError::from_os("ioctl", e))?;
        TcpListener::finish(
            listener,
            ListenOptions::new().tcp_options(TcpOptions::new()),
            ListenerId(0),
            None,
        )
        .map(|mut l| {
            l.info.backlog = None;
            l
        })
    }

    /// Gives the socket up (it stays non-blocking).
    #[must_use]
    pub fn into_std(self) -> std::net::TcpListener {
        self.inner
    }

    /// A second handle to the same listening socket.
    ///
    /// # Errors
    ///
    /// `Os` when duplication fails.
    pub fn try_clone(&self) -> Result<TcpListener, NetError> {
        let inner = self
            .inner
            .try_clone()
            .map_err(|e| NetError::from_os("dup", e))?;
        Ok(TcpListener {
            inner,
            info: self.info.clone(),
            tcp: self.tcp,
            acceptor: Mutex::new(Acceptor::new()),
        })
    }
}

#[cfg(unix)]
impl std::os::fd::AsFd for TcpListener {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

#[cfg(unix)]
impl From<TcpListener> for std::os::fd::OwnedFd {
    fn from(l: TcpListener) -> std::os::fd::OwnedFd {
        l.inner.into()
    }
}

#[cfg(unix)]
impl TryFrom<std::os::fd::OwnedFd> for TcpListener {
    type Error = NetError;
    fn try_from(fd: std::os::fd::OwnedFd) -> Result<TcpListener, NetError> {
        TcpListener::from_std(std::net::TcpListener::from(fd))
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsSocket for TcpListener {
    fn as_socket(&self) -> std::os::windows::io::BorrowedSocket<'_> {
        self.inner.as_socket()
    }
}

#[cfg(windows)]
impl From<TcpListener> for std::os::windows::io::OwnedSocket {
    fn from(l: TcpListener) -> std::os::windows::io::OwnedSocket {
        l.inner.into()
    }
}

#[cfg(windows)]
impl TryFrom<std::os::windows::io::OwnedSocket> for TcpListener {
    type Error = NetError;
    fn try_from(s: std::os::windows::io::OwnedSocket) -> Result<TcpListener, NetError> {
        TcpListener::from_std(std::net::TcpListener::from(s))
    }
}

/// Options for an outbound connection.
///
/// ```no_run
/// use net_io::{ConnectOptions, TcpConnection};
/// use std::time::Duration;
/// let options = ConnectOptions::new().timeout(Duration::from_secs(3));
/// let conn = TcpConnection::connect_host("example.com", 443, options)?;
/// println!("connected to {}", conn.peer_addr());
/// # Ok::<(), net_io::NetError>(())
/// ```
#[must_use]
#[derive(Clone, Debug)]
pub struct ConnectOptions {
    timeout: Duration,
    local_addr: Option<SocketAddr>,
    tcp: TcpOptions,
    limits: Limits,
}

impl Default for ConnectOptions {
    fn default() -> ConnectOptions {
        ConnectOptions {
            timeout: Duration::from_secs(10),
            local_addr: None,
            tcp: TcpOptions::new().nodelay(true),
            limits: Limits::default(),
        }
    }
}

impl ConnectOptions {
    /// Timeout 10 s, `TCP_NODELAY` on, no local bind.
    pub fn new() -> ConnectOptions {
        ConnectOptions::default()
    }

    /// The total time for all attempts.
    pub fn timeout(mut self, total: Duration) -> ConnectOptions {
        self.timeout = total;
        self
    }

    /// Binds to this address before connecting.
    pub fn local_addr(mut self, addr: SocketAddr) -> ConnectOptions {
        self.local_addr = Some(addr);
        self
    }

    /// Options applied before the connect.
    pub fn tcp_options(mut self, options: TcpOptions) -> ConnectOptions {
        self.tcp = options;
        self
    }

    /// Limits for the connection.
    pub fn limits(mut self, limits: Limits) -> ConnectOptions {
        self.limits = limits;
        self
    }
}

/// A connected TCP socket that carries its own limits.
///
/// Every read honours the current phase's deadline (a connection from `accept`
/// starts `Idle` under the idle timeout; one from `connect` starts `Receiving`
/// under the read timeout), the exchange deadline, and the inbound minimum
/// rate; every write honours the write deadline and the outbound minimum rate.
/// One owner: other threads act on it only through its [`KillHandle`].
///
/// # Examples
///
/// ```no_run
/// use net_io::{Limits, Phase};
/// use std::time::{Duration, Instant};
///
/// let mut conn = net_io::connect("127.0.0.1:7000")?;
/// conn.set_limits(Limits::builder().read_timeout(Duration::from_secs(5)).build()?);
/// conn.set_phase(Phase::Receiving);
/// conn.set_exchange_deadline(Some(Instant::now() + Duration::from_secs(20)));
/// let mut buf = [0u8; 1024];
/// let n = conn.recv(&mut buf)?;
/// # let _ = n;
/// # Ok::<(), net_io::NetError>(())
/// ```
pub struct TcpConnection {
    link: Option<Link>,
}

impl TcpConnection {
    /// Connects with a 10 s timeout across every resolved address (see [`crate::connect`]).
    ///
    /// # Errors
    ///
    /// `ConnectTimeout`, `ConnectionRefused`, `HostUnreachable`, `NetworkUnreachable`, `NoAddresses`.
    pub fn connect<A: ToSocketAddrs>(addr: A) -> Result<TcpConnection, NetError> {
        TcpConnection::connect_with(addr, ConnectOptions::new())
    }

    /// Connects with `options`.
    ///
    /// # Errors
    ///
    /// As [`TcpConnection::connect`].
    pub fn connect_with<A: ToSocketAddrs>(
        addr: A,
        options: ConnectOptions,
    ) -> Result<TcpConnection, NetError> {
        let addrs = resolve(addr)?;
        TcpConnection::connect_addrs(&addrs, &options)
    }

    /// Resolves `host` with the standard library and connects to the addresses in
    /// order; each attempt gets the remaining time divided by the remaining
    /// addresses (at least 1 s).
    ///
    /// # Errors
    ///
    /// `NoAddresses`, or the last connect error.
    pub fn connect_host(
        host: &str,
        port: u16,
        options: ConnectOptions,
    ) -> Result<TcpConnection, NetError> {
        let addrs = resolve((host, port))?;
        TcpConnection::connect_addrs(&addrs, &options)
    }

    fn connect_addrs(
        addrs: &[SocketAddr],
        options: &ConnectOptions,
    ) -> Result<TcpConnection, NetError> {
        let start = Instant::now();
        let deadline = start + options.timeout;
        let mut last = NetError::NoAddresses;
        for (i, addr) in addrs.iter().enumerate() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            let remaining = (addrs.len() - i) as u32;
            let attempt = (left / remaining).max(Duration::from_secs(1)).min(left);
            match connect_one(*addr, options, attempt) {
                Ok(conn) => return Ok(conn),
                Err(e) => last = e,
            }
        }
        if matches!(last, NetError::NoAddresses) {
            if let Some(addr) = addrs.first() {
                last = NetError::ConnectTimeout {
                    addr: *addr,
                    after: options.timeout,
                };
            }
        }
        Err(last)
    }

    pub(crate) fn accepted(
        stream: std::net::TcpStream,
        peer: SocketAddr,
        tcp: &TcpOptions,
        listener: ListenerId,
    ) -> Result<TcpConnection, NetError> {
        let local = stream
            .local_addr()
            .map_err(|e| NetError::from_os("getsockname", e))?;
        if !OPTIONS_INHERITED && !tcp.is_empty() {
            tcp.apply(&stream, local.is_ipv6())?;
        }
        let info = ConnectionInfo::new_tcp(
            crate::id::issue_single(),
            Some(listener),
            WorkerId(0),
            Origin::Accepted,
            local,
            peer,
            Instant::now(),
        );
        let limits = Limits::default().effective(DriverKind::Blocking);
        Ok(TcpConnection::from_link(Link::new(
            sys::Stream::Tcp(stream),
            info,
            limits,
            ClockRef::Monotonic,
            Arc::new(KillSlot::new()),
            WakeSource::Thread,
            Phase::Idle,
        )))
    }

    pub(crate) fn from_link(link: Link) -> TcpConnection {
        TcpConnection { link: Some(link) }
    }

    pub(crate) fn take_link(&mut self) -> Option<Link> {
        self.link.take()
    }

    pub(crate) fn link(&mut self) -> Result<&mut Link, NetError> {
        self.link.as_mut().ok_or(NetError::Closed)
    }

    pub(crate) fn link_ref(&self) -> &Link {
        match &self.link {
            Some(l) => l,
            // Only `take_link` (crate-internal, at the end of a handler) empties it.
            None => unreachable_link(),
        }
    }

    /// One receive; `Ok(0)` means the peer closed its side. A zero-length `buf`
    /// returns `Ok(0)` without a system call (check `buf.len()`).
    ///
    /// # Errors
    ///
    /// `TimedOut { kind }`, `SlowPeer { In }`, `ConnectionReset`, `Killed`, `Closed`.
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
        let link = self.link()?;
        loop {
            match link.read(buf)? {
                Got::Data(n) => return Ok(n),
                Got::Eof => return Ok(0),
                Got::Woken => continue,
            }
        }
    }

    /// Receives until `buf` is full.
    ///
    /// # Errors
    ///
    /// As [`TcpConnection::recv`]; `Closed` when the peer closes first.
    pub fn recv_exact(&mut self, buf: &mut [u8]) -> Result<(), NetError> {
        let mut filled = 0;
        while filled < buf.len() {
            match self.recv(&mut buf[filled..])? {
                0 => return Err(NetError::Closed),
                n => filled += n,
            }
        }
        Ok(())
    }

    /// One receive into the first non-empty slice.
    ///
    /// # Errors
    ///
    /// As [`TcpConnection::recv`].
    pub fn recv_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> Result<usize, NetError> {
        match bufs.iter_mut().find(|b| !b.is_empty()) {
            Some(first) => self.recv(first),
            None => Ok(0),
        }
    }

    /// Reads without consuming (`MSG_PEEK`), within the read timeout.
    ///
    /// # Errors
    ///
    /// As [`TcpConnection::recv`]; `Unsupported` on a TLS connection.
    pub fn peek(&self, buf: &mut [u8]) -> Result<usize, NetError> {
        let link = self.link_ref();
        if buf.is_empty() {
            return Ok(0);
        }
        if link.has_tls() {
            // The socket holds ciphertext; peeking at it would mean nothing here.
            return Err(NetError::Unsupported {
                feature: "peek on a TLS connection",
                platform: std::env::consts::OS,
            });
        }
        let timeout = link.limits.read_timeout;
        match sys::wait(link.stream.sock(), Interest::Read, None, Some(timeout)) {
            Ok(Ready::TimedOut) => {
                return Err(NetError::TimedOut {
                    kind: TimeoutKind::Read,
                });
            }
            Ok(_) => {}
            Err(e) => return Err(NetError::from_os("poll", e)),
        }
        link.stream
            .peek(buf)
            .map_err(|e| NetError::from_os("recv", e))
    }

    /// One send after the gate check; may be partial.
    ///
    /// # Errors
    ///
    /// `TimedOut`, `SlowPeer { Out }`, `BrokenPipe`, `ConnectionReset`, `EgressDenied`, `Killed`.
    pub fn send(&mut self, buf: &[u8]) -> Result<usize, NetError> {
        self.link()?.write(buf)
    }

    /// Sends all of `buf`, continuing from the exact offset; the gate check runs
    /// before every system call.
    ///
    /// # Errors
    ///
    /// As [`TcpConnection::send`].
    pub fn send_all(&mut self, buf: &[u8]) -> Result<(), NetError> {
        self.link()?.write_all(buf)
    }

    /// One vectored send (up to 64 slices) after the gate check; may be partial.
    ///
    /// # Errors
    ///
    /// As [`TcpConnection::send`].
    pub fn send_vectored(&mut self, bufs: &[IoSlice<'_>]) -> Result<usize, NetError> {
        self.link()?.write_vectored(bufs)
    }

    /// Sends every slice, advancing them in place (no copy).
    ///
    /// # Errors
    ///
    /// As [`TcpConnection::send`].
    pub fn send_all_vectored(&mut self, bufs: &mut [IoSlice<'_>]) -> Result<(), NetError> {
        self.link()?.write_all_vectored(bufs)
    }

    /// Half-close: `Write` sends FIN and keeps reading; `Read` stops reading.
    ///
    /// # Errors
    ///
    /// `Closed`, `Os`.
    pub fn shutdown(&mut self, how: Shutdown) -> Result<(), NetError> {
        self.link()?.shutdown(how)
    }

    /// Graceful close: FIN, then reads and discards up to 64 KiB for up to 2 s so
    /// unread input does not cause an RST that destroys the last response.
    ///
    /// # Errors
    ///
    /// None in this version; the signature leaves room for a flush error.
    pub fn close(mut self) -> Result<(), NetError> {
        if let Some(link) = self.link.take() {
            let reason = link.reason_or(CloseReason::SessionClosed);
            link.finish(reason);
        }
        Ok(())
    }

    /// Abortive close: RST, kernel resources freed at once.
    pub fn abort(mut self) {
        if let Some(link) = self.link.take() {
            let reason = link.reason_or(CloseReason::SessionError);
            let reason = if reason.is_abortive() {
                reason
            } else {
                CloseReason::SessionError
            };
            link.finish(reason);
        }
    }

    /// What net-io knows about this connection.
    #[must_use]
    pub fn info(&self) -> &ConnectionInfo {
        &self.link_ref().info
    }

    /// The connection's id.
    #[must_use]
    pub fn id(&self) -> ConnectionId {
        self.link_ref().info.id
    }

    /// The socket peer.
    #[must_use]
    pub fn peer_addr(&self) -> SocketAddr {
        self.link_ref()
            .info
            .peer
            .socket_addr()
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)))
    }

    /// Our end.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.link_ref()
            .info
            .local
            .socket_addr()
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)))
    }

    /// A handle other threads can use to abort this connection.
    #[must_use]
    pub fn kill_handle(&self) -> KillHandle {
        let link = self.link_ref();
        KillHandle {
            slot: link.slot.clone(),
            generation: link.generation,
            id: link.info.id,
        }
    }

    /// Replaces the limits from the next operation on (unset values: blocking-driver defaults).
    pub fn set_limits(&mut self, limits: Limits) {
        if let Ok(link) = self.link() {
            let e: Effective = limits.effective(DriverKind::Blocking);
            link.set_limits(e);
        }
    }

    /// Chooses which deadlines apply.
    pub fn set_phase(&mut self, phase: Phase) {
        if let Ok(link) = self.link() {
            link.set_phase(phase);
        }
    }

    /// The deadline for the current exchange (`None` clears it).
    pub fn set_exchange_deadline(&mut self, at: Option<Instant>) {
        if let Ok(link) = self.link() {
            link.set_exchange_deadline(at);
        }
    }

    /// Live socket options.
    #[must_use]
    pub fn options(&self) -> SocketOptions<'_> {
        let link = self.link_ref();
        SocketOptions {
            sock: link.stream.sock(),
            v6: link.info.local.socket_addr().is_some_and(|a| a.is_ipv6()),
        }
    }

    /// The socket's pending error (`SO_ERROR`).
    ///
    /// # Errors
    ///
    /// `Os` when the OS call fails.
    pub fn take_error(&self) -> Result<Option<io::Error>, NetError> {
        sys::take_error(self.link_ref().stream.sock())
            .map_err(|e| NetError::from_os("getsockopt", e))
    }
}

#[cold]
fn unreachable_link() -> ! {
    // A TcpConnection is emptied only by the server after its handler returned,
    // when no code can reach it any more.
    std::process::abort()
}

fn connect_one(
    addr: SocketAddr,
    options: &ConnectOptions,
    attempt: Duration,
) -> Result<TcpConnection, NetError> {
    let owned = sys::tcp_socket(addr.is_ipv6()).map_err(|e| NetError::from_os("socket", e))?;
    let stream = std::net::TcpStream::from(owned);
    stream
        .set_nonblocking(true)
        .map_err(|e| NetError::from_os("ioctl", e))?;
    options.tcp.apply(&stream, addr.is_ipv6())?;
    if let Some(local) = options.local_addr {
        sys::bind_to(stream.sock(), local).map_err(|e| bind_error(local, e))?;
    }
    let started = Instant::now();
    match sys::connect_start(stream.sock(), addr) {
        Ok(false) => {}
        Ok(true) => {
            match sys::wait(stream.sock(), Interest::Write, None, Some(attempt)) {
                Ok(Ready::TimedOut) => {
                    return Err(NetError::ConnectTimeout {
                        addr,
                        after: attempt,
                    });
                }
                Ok(_) => {}
                Err(e) => return Err(NetError::from_os("poll", e)),
            }
            match sys::take_error(stream.sock()) {
                Ok(None) => {}
                Ok(Some(e)) => return Err(connect_error(addr, started.elapsed(), e)),
                Err(e) => return Err(NetError::from_os("getsockopt", e)),
            }
        }
        Err(e) => return Err(connect_error(addr, started.elapsed(), e)),
    }
    sys::prepare_dialed(&stream).map_err(|e| NetError::from_os("ioctl", e))?;
    let local = stream
        .local_addr()
        .map_err(|e| NetError::from_os("getsockname", e))?;
    let info = ConnectionInfo::new_tcp(
        crate::id::issue_single(),
        None,
        WorkerId(0),
        Origin::Dialed,
        local,
        crate::addr::normalize_socket(addr),
        Instant::now(),
    );
    Ok(TcpConnection::from_link(Link::new(
        sys::Stream::Tcp(stream),
        info,
        options.limits.effective(DriverKind::Blocking),
        ClockRef::Monotonic,
        Arc::new(KillSlot::new()),
        WakeSource::Thread,
        Phase::Receiving,
    )))
}

impl Read for TcpConnection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv(buf).map_err(io::Error::from)
    }
}

impl Write for TcpConnection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send(buf).map_err(io::Error::from)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.send_vectored(bufs).map_err(io::Error::from)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for TcpConnection {
    /// Never blocks: FIN, then close without the linger; use `close()` for the full graceful close.
    fn drop(&mut self) {
        if let Some(link) = self.link.take() {
            let reason = link.reason_or(CloseReason::SessionClosed);
            link.finish_quick(reason);
        }
    }
}

impl std::fmt::Debug for TcpConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.link {
            Some(l) => f
                .debug_struct("TcpConnection")
                .field("info", &l.info)
                .finish(),
            None => f.write_str("TcpConnection(closed)"),
        }
    }
}

#[cfg(unix)]
impl std::os::fd::AsFd for TcpConnection {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        std::os::fd::AsFd::as_fd(&self.link_ref().stream)
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsSocket for TcpConnection {
    fn as_socket(&self) -> std::os::windows::io::BorrowedSocket<'_> {
        std::os::windows::io::AsSocket::as_socket(&self.link_ref().stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_listen_accept_echo_round_trip() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let (mut c, info) = l.accept().unwrap();
            assert_eq!(info.origin, Origin::Accepted);
            let mut buf = [0u8; 4];
            c.recv_exact(&mut buf).unwrap();
            c.send_all(&buf).unwrap();
            c.close().unwrap();
        });
        let mut c = TcpConnection::connect(addr).unwrap();
        c.send_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        c.recv_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        assert_eq!(c.recv(&mut buf).unwrap(), 0);
        t.join().unwrap();
    }

    #[test]
    fn test_connect_refused_maps_to_connection_refused() {
        // Bind then drop to get a free port with nothing listening.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let err = TcpConnection::connect_with(
            ("127.0.0.1", port),
            ConnectOptions::new().timeout(Duration::from_secs(5)),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                NetError::ConnectionRefused { .. } | NetError::ConnectTimeout { .. }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn test_bind_in_use_maps_to_addr_in_use() {
        let a = TcpListener::bind("127.0.0.1:0").unwrap();
        let err = TcpListener::bind(a.local_addr().unwrap()).unwrap_err();
        assert!(matches!(err, NetError::AddrInUse { .. }), "{err:?}");
    }

    /// Edge cases 127 and 128: bind errors map by class, whatever the OS's number.
    #[test]
    fn test_bind_errors_map_by_class() {
        #[cfg(unix)]
        use crate::sys::errno::{EACCES as ACCESS, EADDRNOTAVAIL as NOT_AVAILABLE};
        #[cfg(windows)]
        use crate::sys::errno::{WSAEACCES as ACCESS, WSAEADDRNOTAVAIL as NOT_AVAILABLE};
        let addr: SocketAddr = "[::1]:80".parse().unwrap();
        let e = bind_error(addr, io::Error::from_raw_os_error(NOT_AVAILABLE));
        assert!(matches!(e, NetError::AddrNotAvailable { .. }), "{e:?}");
        let e = bind_error(addr, io::Error::from_raw_os_error(ACCESS));
        assert!(matches!(e, NetError::PermissionDenied { .. }), "{e:?}");
    }

    #[test]
    fn test_read_timeout_fires() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let _server = std::thread::spawn(move || {
            let (c, _) = l.accept().unwrap();
            std::thread::sleep(Duration::from_secs(2));
            drop(c);
        });
        let limits = Limits::builder()
            .read_timeout(Duration::from_millis(200))
            .min_rate(crate::limits::MinRate::off())
            .build()
            .unwrap();
        let mut c =
            TcpConnection::connect_with(addr, ConnectOptions::new().limits(limits)).unwrap();
        let mut buf = [0u8; 8];
        let start = Instant::now();
        let err = c.recv(&mut buf).unwrap_err();
        assert!(
            matches!(
                err,
                NetError::TimedOut {
                    kind: TimeoutKind::Read
                }
            ),
            "{err:?}"
        );
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn test_kill_wakes_blocked_recv() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let _server = std::thread::spawn(move || {
            let (c, _) = l.accept().unwrap();
            std::thread::sleep(Duration::from_secs(3));
            drop(c);
        });
        let mut c = TcpConnection::connect(addr).unwrap();
        let kill = c.kill_handle();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            assert!(kill.kill(crate::error::KillReason(4)));
        });
        let mut buf = [0u8; 8];
        let start = Instant::now();
        let err = c.recv(&mut buf).unwrap_err();
        assert!(matches!(err, NetError::Killed { .. }), "{err:?}");
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
