//! Unix domain sockets on Windows (AF_UNIX, Windows 10 1803 and later).
//!
//! Stream sockets only: no descriptor passing, and the file's NTFS ACL decides who
//! may connect, so the mode and owner options do not apply. The socket is a Winsock
//! socket like any other, so it runs on the connection core as `Stream::Tcp`.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::accept::{Accepted, Acceptor};
use crate::driver::DriverKind;
use crate::error::{ConfigReason, LimitKind, NetError, TimeoutKind};
use crate::gate::KillHandle;
use crate::id::{ConnectionId, ListenerId};
use crate::info::{ConnectionInfo, Endpoint, Origin, PeerCredentials, Transport, UnixPath};
use crate::limits::Limits;
use crate::link::{ClockRef, Link, WakeSource};
use crate::opts::LocalOptions;
use crate::proxy::ProxyMode;
use crate::session::Phase;
use crate::sys::{self, AsSock, Interest, KillSlot, Ready};
use crate::tcp::{ListenerInfo, TcpConnection};

/// `FILE_ATTRIBUTE_REPARSE_POINT`: what an AF_UNIX socket file is.
const REPARSE_POINT: u32 = 0x400;
/// `WSAEAFNOSUPPORT`: a Windows from before 1803.
const NO_AF_UNIX: i32 = 10047;

fn os_error(op: &'static str, e: io::Error) -> NetError {
    match e.kind() {
        io::ErrorKind::PermissionDenied => NetError::PermissionDenied {
            what: "the socket path",
        },
        _ if e.raw_os_error() == Some(NO_AF_UNIX) => NetError::Unsupported {
            feature: "Unix domain sockets (Windows 10 1803 or later)",
            platform: std::env::consts::OS,
        },
        _ => NetError::from_os(op, e),
    }
}

fn path_bytes(path: &Path) -> Result<&[u8], NetError> {
    let bytes = path.to_str().ok_or(NetError::InvalidConfig {
        field: "path",
        reason: ConfigReason::Malformed,
    })?;
    if bytes.is_empty() || bytes.contains('\0') {
        return Err(NetError::InvalidConfig {
            field: "path",
            reason: ConfigReason::Malformed,
        });
    }
    if bytes.len() >= sys::UNIX_PATH_MAX {
        return Err(NetError::PathTooLong {
            max: sys::UNIX_PATH_MAX,
        });
    }
    Ok(bytes.as_bytes())
}

fn in_use(path: &Path) -> NetError {
    NetError::StaleSocketInUse {
        path: path.to_path_buf(),
    }
}

/// Removes a socket file nobody listens on; anything else at the path stays.
fn clear_stale(path: &Path, bytes: &[u8], options: &LocalOptions) -> Result<(), NetError> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(os_error("stat", e)),
    };
    // Every kind of reparse point has the attribute; only the AF_UNIX tag is a
    // socket file. A file that cannot be read stays.
    let socket_file = meta.file_attributes() & REPARSE_POINT != 0
        && !meta.file_type().is_symlink()
        && sys::is_unix_socket_file(path).unwrap_or(false);
    if !socket_file || !options.remove_stale {
        return Err(in_use(path));
    }
    let probe = sys::unix_socket().map_err(|e| os_error("socket", e))?;
    if sys::unix_connect(probe.sock(), bytes).is_ok() {
        return Err(in_use(path));
    }
    std::fs::remove_file(path).map_err(|e| os_error("delete", e))
}

/// The options that mean something on this OS.
fn check_options(options: &LocalOptions) -> Result<(), NetError> {
    if options.mode != LocalOptions::new().mode
        || options.owner.is_some()
        || options.group.is_some()
        || options.require_uid.is_some()
    {
        return Err(NetError::Unsupported {
            feature: "socket file modes and owners (NTFS ACLs decide on Windows)",
            platform: std::env::consts::OS,
        });
    }
    Ok(())
}

pub(crate) fn credentials_of(stream: &TcpStream) -> Option<PeerCredentials> {
    sys::unix_peer_pid(stream.sock())
        .ok()
        .map(|pid| PeerCredentials {
            pid: Some(pid),
            uid: None,
            gid: None,
        })
}

/// A listening Unix domain socket on Windows. Permissions come from the directory's
/// NTFS ACL; keep the socket in a private directory. The socket file is removed on
/// drop.
///
/// ```no_run
/// let listener = net_io::UnixListener::bind(r"C:\ProgramData\myapp\api.sock")?;
/// let (mut conn, _) = listener.accept()?;
/// conn.send_all(b"ready\n")?;
/// # Ok::<(), net_io::NetError>(())
/// ```
#[cfg_attr(docsrs, doc(cfg(unix)))]
#[derive(Debug)]
pub struct UnixListener {
    inner: TcpListener,
    path: PathBuf,
    shared_path: Arc<UnixPath>,
    info: ListenerInfo,
    acceptor: Mutex<Acceptor>,
}

impl UnixListener {
    /// Binds with the default options.
    ///
    /// # Errors
    ///
    /// As [`UnixListener::bind_with`].
    pub fn bind<P: AsRef<Path>>(path: P) -> Result<UnixListener, NetError> {
        UnixListener::bind_with(path, LocalOptions::new())
    }

    /// Binds at `path`. A socket file nobody listens on is removed first, unless
    /// `options` say otherwise; a live one, a regular file, a directory, or a link is
    /// left alone.
    ///
    /// # Errors
    ///
    /// `PathTooLong`, `StaleSocketInUse`, `PermissionDenied`, `InvalidConfig`,
    /// `Unsupported` (an older Windows, or options that do not apply here), `Os`.
    pub fn bind_with<P: AsRef<Path>>(
        path: P,
        options: LocalOptions,
    ) -> Result<UnixListener, NetError> {
        let path = path.as_ref();
        check_options(&options)?;
        let bytes = path_bytes(path)?;
        clear_stale(path, bytes, &options)?;
        let sock = sys::unix_socket().map_err(|e| os_error("socket", e))?;
        sys::unix_bind(sock.sock(), bytes, options.backlog).map_err(|e| {
            if e.kind() == io::ErrorKind::AddrInUse {
                in_use(path)
            } else {
                os_error("bind", e)
            }
        })?;
        let inner = TcpListener::from(sock);
        inner
            .set_nonblocking(true)
            .map_err(|e| NetError::from_os("ioctl", e))?;
        let shared_path = Arc::new(UnixPath::new(bytes).ok_or(NetError::PathTooLong {
            max: sys::UNIX_PATH_MAX,
        })?);
        Ok(UnixListener {
            inner,
            path: path.to_path_buf(),
            info: ListenerInfo {
                id: ListenerId(0),
                name: None,
                local: Endpoint::Unix(shared_path.clone()),
                backlog: Some(options.backlog),
                transport: Transport::Unix,
                proxy: ProxyMode::Off,
                tls: false,
            },
            shared_path,
            acceptor: Mutex::new(Acceptor::new()),
        })
    }

    /// Blocks until a connection arrives.
    ///
    /// # Errors
    ///
    /// `Limit { which: Descriptors }`, `Os`.
    pub fn accept(&self) -> Result<(UnixConnection, ConnectionInfo), NetError> {
        match self.accept_until(None)? {
            Some(pair) => Ok(pair),
            None => Err(NetError::TimedOut {
                kind: TimeoutKind::Read,
            }),
        }
    }

    /// As [`UnixListener::accept`], but `Ok(None)` when nothing arrived within `timeout`.
    ///
    /// # Errors
    ///
    /// As [`UnixListener::accept`].
    pub fn accept_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Option<(UnixConnection, ConnectionInfo)>, NetError> {
        self.accept_until(Some(Instant::now() + timeout))
    }

    fn accept_until(
        &self,
        deadline: Option<Instant>,
    ) -> Result<Option<(UnixConnection, ConnectionInfo)>, NetError> {
        let mut paused = false;
        loop {
            let outcome = self
                .acceptor
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .accept_af_unix(&self.inner);
            match outcome {
                Accepted::Conn(stream) => {
                    let info = self.info_of(&stream, crate::id::issue_single(), Instant::now());
                    let conn = UnixConnection::from_stream(stream, info.clone(), Phase::Idle);
                    return Ok(Some((conn, info)));
                }
                Accepted::Skipped(_) => {}
                Accepted::Again => {
                    let left = deadline.map(|d| d.saturating_duration_since(Instant::now()));
                    if left == Some(Duration::ZERO) {
                        return Ok(None);
                    }
                    let ready = sys::wait(self.inner.sock(), Interest::Read, None, left)
                        .map_err(|e| NetError::from_os("poll", e))?;
                    if ready == Ready::TimedOut {
                        return Ok(None);
                    }
                }
                Accepted::Pause(backoff) => {
                    if paused {
                        return Err(NetError::Limit {
                            which: LimitKind::Descriptors,
                        });
                    }
                    paused = true;
                    std::thread::sleep(backoff);
                }
                Accepted::Failed(e) => return Err(NetError::from_os("accept", e)),
            }
        }
    }

    /// What a connection accepted from this listener knows of itself.
    pub(crate) fn info_of(
        &self,
        stream: &TcpStream,
        id: ConnectionId,
        at: Instant,
    ) -> ConnectionInfo {
        ConnectionInfo::new_unix(
            id,
            Some(self.info.id),
            Origin::Accepted,
            Endpoint::Unix(self.shared_path.clone()),
            Endpoint::Unnamed,
            credentials_of(stream),
            at,
        )
    }

    /// What this listener is.
    #[must_use]
    pub fn info(&self) -> &ListenerInfo {
        &self.info
    }

    /// The path it listens on.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        Some(&self.path)
    }

    pub(crate) fn std(&self) -> &TcpListener {
        &self.inner
    }

    pub(crate) fn set_identity(&mut self, id: ListenerId, name: Option<String>) {
        self.info.id = id;
        self.info.name = name;
    }

    pub(crate) fn set_proxy_mode(&mut self, mode: ProxyMode) {
        self.info.proxy = mode;
    }

    pub(crate) fn set_tls(&mut self, on: bool) {
        self.info.tls = on;
    }
}

impl Drop for UnixListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A connection on a Unix domain socket on Windows, with the same limits, deadlines,
/// and close behaviour as [`TcpConnection`].
///
/// ```no_run
/// let mut conn = net_io::UnixConnection::connect(r"C:\ProgramData\myapp\api.sock")?;
/// conn.send_all(b"status\n")?;
/// # Ok::<(), net_io::NetError>(())
/// ```
#[cfg_attr(docsrs, doc(cfg(unix)))]
#[derive(Debug)]
pub struct UnixConnection {
    inner: TcpConnection,
}

impl UnixConnection {
    fn from_stream(stream: TcpStream, info: ConnectionInfo, phase: Phase) -> UnixConnection {
        let limits = Arc::new(Limits::default().effective(DriverKind::Blocking));
        UnixConnection {
            inner: TcpConnection::from_link(Link::new(
                sys::Stream::Tcp(stream),
                info,
                limits,
                ClockRef::Monotonic,
                Arc::new(KillSlot::new()),
                WakeSource::Thread,
                phase,
            )),
        }
    }

    /// Connects to the socket at `path`.
    ///
    /// # Errors
    ///
    /// `NotFound` (no socket, or nobody listening), `PermissionDenied`,
    /// `PathTooLong`, `Unsupported` (an older Windows), `Os`.
    pub fn connect<P: AsRef<Path>>(path: P) -> Result<UnixConnection, NetError> {
        let bytes = path_bytes(path.as_ref())?;
        let shared = Arc::new(UnixPath::new(bytes).ok_or(NetError::PathTooLong {
            max: sys::UNIX_PATH_MAX,
        })?);
        let sock = sys::unix_socket().map_err(|e| os_error("socket", e))?;
        if let Err(e) = sys::unix_connect(sock.sock(), bytes) {
            return Err(match e.kind() {
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => NetError::NotFound,
                _ => os_error("connect", e),
            });
        }
        let stream = TcpStream::from(sock);
        stream
            .set_nonblocking(true)
            .map_err(|e| NetError::from_os("ioctl", e))?;
        let info = ConnectionInfo::new_unix(
            crate::id::issue_single(),
            None,
            Origin::Dialed,
            Endpoint::Unnamed,
            Endpoint::Unix(shared),
            credentials_of(&stream),
            Instant::now(),
        );
        Ok(UnixConnection::from_stream(stream, info, Phase::Receiving))
    }

    /// One receive; `Ok(0)` means the peer closed its side.
    ///
    /// # Errors
    ///
    /// As [`TcpConnection::recv`].
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
        self.inner.recv(buf)
    }

    /// Receives until `buf` is full.
    ///
    /// # Errors
    ///
    /// As [`TcpConnection::recv_exact`].
    pub fn recv_exact(&mut self, buf: &mut [u8]) -> Result<(), NetError> {
        self.inner.recv_exact(buf)
    }

    /// One send after the gate check; may be partial.
    ///
    /// # Errors
    ///
    /// As [`TcpConnection::send`].
    pub fn send(&mut self, buf: &[u8]) -> Result<usize, NetError> {
        self.inner.send(buf)
    }

    /// Sends all of `buf`.
    ///
    /// # Errors
    ///
    /// As [`TcpConnection::send_all`].
    pub fn send_all(&mut self, buf: &[u8]) -> Result<(), NetError> {
        self.inner.send_all(buf)
    }

    /// Half-close.
    ///
    /// # Errors
    ///
    /// `Closed`, `Os`.
    pub fn shutdown(&mut self, how: Shutdown) -> Result<(), NetError> {
        self.inner.shutdown(how)
    }

    /// Graceful close, as [`TcpConnection::close`].
    ///
    /// # Errors
    ///
    /// None in this version.
    pub fn close(self) -> Result<(), NetError> {
        self.inner.close()
    }

    /// Closes at once without the graceful linger.
    pub fn abort(self) {
        self.inner.abort();
    }

    pub(crate) fn close_in_place(&mut self) -> Result<(), NetError> {
        match self.inner.take_link() {
            Some(link) => TcpConnection::from_link(link).close(),
            None => Ok(()),
        }
    }

    pub(crate) fn abort_in_place(&mut self) {
        if let Some(link) = self.inner.take_link() {
            TcpConnection::from_link(link).abort();
        }
    }

    /// What net-io knows about this connection.
    #[must_use]
    pub fn info(&self) -> &ConnectionInfo {
        self.inner.info()
    }

    /// This connection's id.
    #[must_use]
    pub fn id(&self) -> ConnectionId {
        self.inner.id()
    }

    /// A handle other threads can use to abort this connection.
    #[must_use]
    pub fn kill_handle(&self) -> KillHandle {
        self.inner.kill_handle()
    }

    /// Replaces the limits (the deadlines start from the next wait).
    pub fn set_limits(&mut self, limits: Limits) {
        self.inner.set_limits(limits);
    }

    /// Which deadlines apply: idle, receiving, or sending.
    pub fn set_phase(&mut self, phase: Phase) {
        self.inner.set_phase(phase);
    }

    /// An overall deadline for the current exchange.
    pub fn set_exchange_deadline(&mut self, at: Option<Instant>) {
        self.inner.set_exchange_deadline(at);
    }

    /// The peer's process, as read when the connection was made.
    ///
    /// # Errors
    ///
    /// `Unsupported` when the OS did not report it.
    pub fn peer_credentials(&self) -> Result<PeerCredentials, NetError> {
        self.info().peer_credentials.ok_or(NetError::Unsupported {
            feature: "peer credentials",
            platform: std::env::consts::OS,
        })
    }
}

impl Read for UnixConnection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for UnixConnection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
