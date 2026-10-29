//! Local sockets: Unix domain sockets (feature `local`). Windows named pipes and
//! Windows AF_UNIX arrive in `0.5.0`; until then the cross-platform entry points
//! return `Unsupported` there.

use std::io::{self, Read, Write};
use std::net::Shutdown;
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::{Arc, Mutex, PoisonError};
#[cfg(unix)]
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

#[cfg(unix)]
use crate::accept::{Accepted, Acceptor};
#[cfg(unix)]
use crate::driver::DriverKind;
use crate::error::NetError;
#[cfg(unix)]
use crate::error::{ConfigReason, LimitKind, TimeoutKind};
use crate::gate::KillHandle;
#[cfg(unix)]
use crate::id::{ConnectionId, ListenerId};
use crate::info::ConnectionInfo;
#[cfg(unix)]
use crate::info::{Endpoint, Origin, PeerCredentials, Transport, UnixPath};
use crate::limits::Limits;
#[cfg(unix)]
use crate::link::{ClockRef, Got, Link, WakeSource};
#[cfg(unix)]
use crate::opts::LocalOptions;
#[cfg(unix)]
use crate::proxy::ProxyMode;
#[cfg(unix)]
use crate::session::Phase;
#[cfg(unix)]
use crate::sys::{self, Interest, KillSlot, Ready};
#[cfg(unix)]
use crate::tcp::{ListenerInfo, TcpConnection};

/// How long `connect` waits for a listener whose backlog is full.
#[cfg(unix)]
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Descriptors received with [`UnixConnection::recv_descriptors`]: up to 64,
/// owned, close-on-exec. Descriptors not taken are closed when this is dropped
/// or reused.
///
/// ```
/// let fds = net_io::Descriptors::new();
/// assert!(fds.is_empty());
/// ```
#[cfg(unix)]
pub struct Descriptors {
    slots: [Option<OwnedFd>; sys::MAX_FDS],
    len: usize,
}

#[cfg(unix)]
impl Descriptors {
    /// Room for 64 descriptors.
    #[must_use]
    pub fn new() -> Descriptors {
        Descriptors {
            slots: [const { None }; sys::MAX_FDS],
            len: 0,
        }
    }

    /// How many descriptors are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether none are held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Takes the descriptors, in the order they were sent.
    pub fn take(&mut self) -> impl Iterator<Item = OwnedFd> + '_ {
        self.len = 0;
        self.slots.iter_mut().filter_map(Option::take)
    }

    fn clear(&mut self) {
        for slot in &mut self.slots {
            *slot = None;
        }
        self.len = 0;
    }
}

#[cfg(unix)]
impl Default for Descriptors {
    fn default() -> Descriptors {
        Descriptors::new()
    }
}

#[cfg(unix)]
impl std::fmt::Debug for Descriptors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Descriptors")
            .field("len", &self.len)
            .finish()
    }
}

/// The identity of a file: its device and inode.
#[cfg(unix)]
type FileId = (u64, u64);

#[cfg(unix)]
fn file_id(path: &Path) -> Option<(FileId, bool)> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    // lstat: a symbolic link is reported as itself, never followed.
    let meta = std::fs::symlink_metadata(path).ok()?;
    Some(((meta.dev(), meta.ino()), meta.file_type().is_socket()))
}

/// Checks a socket path: no NUL byte, and short enough for `sockaddr_un`.
#[cfg(unix)]
fn path_bytes(path: &Path) -> Result<&[u8], NetError> {
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.is_empty() {
        return Err(NetError::InvalidConfig {
            field: "path",
            reason: ConfigReason::Zero,
        });
    }
    if bytes.contains(&0) {
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
    Ok(bytes)
}

#[cfg(unix)]
fn os_error(op: &'static str, e: io::Error) -> NetError {
    match e.kind() {
        io::ErrorKind::PermissionDenied => NetError::PermissionDenied { what: op },
        io::ErrorKind::NotFound => NetError::NotFound,
        _ => NetError::Os { op, source: e },
    }
}

/// Whether something accepts connections on `path` (a probe connect).
#[cfg(unix)]
fn live(path: &[u8]) -> Result<bool, NetError> {
    let sock = sys::unix_socket().map_err(|e| NetError::from_os("socket", e))?;
    let probe = std::os::unix::net::UnixStream::from(sock);
    // A full backlog would make the probe wait (Linux); a second is plenty.
    let _ = probe.set_write_timeout(Some(Duration::from_secs(1)));
    match sys::unix_connect(probe.as_fd(), path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => Ok(false),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        // A full backlog: someone is listening.
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            Ok(true)
        }
        Err(e) => Err(os_error("connect", e)),
    }
}

/// A Unix domain socket listener. Dropping it removes its socket file, but only
/// while the path still names the file this listener created.
///
/// ```no_run
/// let listener = net_io::UnixListener::bind("/run/myapp/control.sock")?;
/// let (mut conn, info) = listener.accept()?;
/// println!("uid {:?}", info.peer_credentials.and_then(|c| c.uid));
/// conn.send_all(b"ready\n")?;
/// # Ok::<(), net_io::NetError>(())
/// ```
#[cfg(unix)]
pub struct UnixListener {
    inner: std::os::unix::net::UnixListener,
    path: PathBuf,
    created: Option<FileId>,
    /// Set when the socket was released for a hand-off: the file stays.
    keep: std::sync::atomic::AtomicBool,
    shared_path: Arc<UnixPath>,
    info: ListenerInfo,
    require_uid: Option<u32>,
    acceptor: Mutex<Acceptor>,
}

#[cfg(unix)]
impl UnixListener {
    /// Binds `path` with [`LocalOptions::new`]: mode `0600`, a stale socket file removed.
    ///
    /// # Errors
    ///
    /// `PathTooLong`, `StaleSocketInUse`, `PermissionDenied`, `NotFound` (no such
    /// directory), `InvalidConfig { field: "path" }`, `Os`.
    pub fn bind<P: AsRef<Path>>(path: P) -> Result<UnixListener, NetError> {
        UnixListener::bind_with(path, LocalOptions::new())
    }

    /// Binds `path` with `options`: the socket is bound, given its mode and owner,
    /// and only then listens, so no connection is accepted under the umask's
    /// permissions.
    ///
    /// # Errors
    ///
    /// As [`UnixListener::bind`].
    pub fn bind_with<P: AsRef<Path>>(
        path: P,
        options: LocalOptions,
    ) -> Result<UnixListener, NetError> {
        UnixListener::create(path.as_ref(), &options, false)
    }

    /// As [`UnixListener::bind_with`], but bound under a temporary name in the
    /// same directory and renamed into place once it listens with its final
    /// mode: the path never names a socket that refuses or is not ready.
    ///
    /// # Errors
    ///
    /// As [`UnixListener::bind`].
    pub fn bind_atomic<P: AsRef<Path>>(
        path: P,
        options: LocalOptions,
    ) -> Result<UnixListener, NetError> {
        UnixListener::create(path.as_ref(), &options, true)
    }

    fn create(path: &Path, options: &LocalOptions, atomic: bool) -> Result<UnixListener, NetError> {
        let bytes = path_bytes(path)?;
        let shared_path = Arc::new(UnixPath::new(bytes).ok_or(NetError::PathTooLong {
            max: sys::UNIX_PATH_MAX,
        })?);
        // An existing file: a live listener's socket, a stale one, or not a socket.
        if let Some((_, is_socket)) = file_id(path) {
            let stale = is_socket && !live(bytes)?;
            if !stale {
                return Err(NetError::StaleSocketInUse {
                    path: path.to_path_buf(),
                });
            }
            if !options.remove_stale {
                return Err(NetError::StaleSocketInUse {
                    path: path.to_path_buf(),
                });
            }
            if !atomic {
                // The rename of `bind_atomic` replaces it in one step instead.
                std::fs::remove_file(path).map_err(|e| os_error("unlink", e))?;
            }
        }
        let target = if atomic {
            temporary_name(path)?
        } else {
            path.to_path_buf()
        };
        let target_bytes = path_bytes(&target)?;
        let sock = sys::unix_socket().map_err(|e| NetError::from_os("socket", e))?;
        if let Err(e) = sys::unix_bind(sock.as_fd(), target_bytes) {
            return Err(match e.kind() {
                io::ErrorKind::AddrInUse => NetError::StaleSocketInUse {
                    path: path.to_path_buf(),
                },
                _ => os_error("bind", e),
            });
        }
        let result = (|| {
            let created = match file_id(&target) {
                Some((id, true)) => id,
                _ => return Err(replaced(&target)),
            };
            set_access(&target, options)?;
            // The mode and owner were set on the file this socket created.
            if file_id(&target) != Some((created, true)) {
                return Err(replaced(&target));
            }
            sys::unix_listen(sock.as_fd(), options.backlog)
                .map_err(|e| NetError::from_os("listen", e))?;
            if atomic {
                std::fs::rename(&target, path).map_err(|e| os_error("rename", e))?;
            }
            Ok(created)
        })();
        let created = match result {
            Ok(id) => id,
            Err(e) => {
                if file_id(&target).is_some_and(|(_, sock)| sock) {
                    let _ = std::fs::remove_file(&target);
                }
                return Err(e);
            }
        };
        let inner = std::os::unix::net::UnixListener::from(sock);
        // Accepts wait in poll, like TCP listeners.
        inner
            .set_nonblocking(true)
            .map_err(|e| NetError::from_os("ioctl", e))?;
        Ok(UnixListener {
            inner,
            path: path.to_path_buf(),
            created: Some(created),
            keep: std::sync::atomic::AtomicBool::new(false),
            info: ListenerInfo {
                id: ListenerId(0),
                name: None,
                local: Endpoint::Unix(shared_path.clone()),
                backlog: if cfg!(target_os = "linux") {
                    crate::tcp::effective_backlog(options.backlog)
                } else {
                    None
                },
                transport: Transport::Unix,
                proxy: ProxyMode::Off,
                tls: false,
            },
            shared_path,
            require_uid: options.require_uid,
            acceptor: Mutex::new(Acceptor::new()),
        })
    }

    /// Blocks until a connection arrives. Peer credentials are read once and
    /// stored in `ConnectionInfo`; with `require_uid`, other users' connections
    /// are closed before any read and accepting continues.
    ///
    /// # Errors
    ///
    /// `Limit { which: Descriptors }` when exhaustion persists past one backoff step; `Os`.
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
        let mut paused_once = false;
        loop {
            let outcome = self
                .acceptor
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .accept_unix(&self.inner);
            match outcome {
                Accepted::Conn(stream) => {
                    let credentials = credentials_of(&stream);
                    if !self.permits(credentials) {
                        continue;
                    }
                    let info = ConnectionInfo::new_unix(
                        crate::id::issue_single(),
                        Some(self.info.id),
                        Origin::Accepted,
                        Endpoint::Unix(self.shared_path.clone()),
                        Endpoint::Unnamed,
                        credentials,
                        Instant::now(),
                    );
                    let conn = UnixConnection::from_stream(stream, info.clone(), Phase::Idle);
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
                    match sys::wait(self.inner.as_fd(), Interest::Read, None, timeout) {
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

    /// A listening Unix socket this process was given (inherited, received in a
    /// hand-off). Its file is never removed by this listener.
    pub(crate) fn adopt(sock: OwnedFd) -> Result<UnixListener, NetError> {
        let inner = std::os::unix::net::UnixListener::from(sock);
        inner
            .set_nonblocking(true)
            .map_err(|e| NetError::from_os("ioctl", e))?;
        let path = inner
            .local_addr()
            .ok()
            .and_then(|a| a.as_pathname().map(Path::to_path_buf))
            .unwrap_or_default();
        let shared_path = Arc::new(UnixPath::new(path.as_os_str().as_encoded_bytes()).ok_or(
            NetError::PathTooLong {
                max: sys::UNIX_PATH_MAX,
            },
        )?);
        let local = if path.as_os_str().is_empty() {
            Endpoint::Unnamed
        } else {
            Endpoint::Unix(shared_path.clone())
        };
        Ok(UnixListener {
            inner,
            path,
            created: None,
            keep: std::sync::atomic::AtomicBool::new(true),
            info: ListenerInfo {
                id: ListenerId(0),
                name: None,
                local,
                backlog: None,
                transport: Transport::Unix,
                proxy: ProxyMode::Off,
                tls: false,
            },
            shared_path,
            require_uid: None,
            acceptor: Mutex::new(Acceptor::new()),
        })
    }

    /// Leaves the socket file in place when this listener is dropped.
    pub(crate) fn keep_file(&self) {
        self.keep.store(true, std::sync::atomic::Ordering::Release);
    }

    /// Whether a peer with these credentials may stay (`require_uid`).
    pub(crate) fn permits(&self, credentials: Option<PeerCredentials>) -> bool {
        match self.require_uid {
            None => true,
            Some(uid) => credentials.and_then(|c| c.uid) == Some(uid),
        }
    }

    pub(crate) fn std(&self) -> &std::os::unix::net::UnixListener {
        &self.inner
    }

    pub(crate) fn shared_path(&self) -> &Arc<UnixPath> {
        &self.shared_path
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

    /// Facts about this listener.
    #[must_use]
    pub fn info(&self) -> &ListenerInfo {
        &self.info
    }

    /// The path this listener was bound to (recorded at bind, not read back:
    /// decision D-058); for an adopted socket, the path the OS reports.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        (!self.path.as_os_str().is_empty()).then_some(self.path.as_path())
    }
}

#[cfg(unix)]
impl Drop for UnixListener {
    /// Removes the socket file only if the path still names the file this
    /// listener created, never a replacement someone else bound.
    fn drop(&mut self) {
        if self.keep.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        if let Some(created) = self.created {
            if file_id(&self.path) == Some((created, true)) {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
}

#[cfg(unix)]
impl AsFd for UnixListener {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

#[cfg(unix)]
impl std::fmt::Debug for UnixListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnixListener")
            .field("path", &self.path)
            .field("info", &self.info)
            .finish()
    }
}

#[cfg(unix)]
fn replaced(path: &Path) -> NetError {
    NetError::StaleSocketInUse {
        path: path.to_path_buf(),
    }
}

/// Sets the socket file's mode, then its owner and group (`lchown`: a symbolic
/// link put in its place is never followed).
#[cfg(unix)]
fn set_access(path: &Path, options: &LocalOptions) -> Result<(), NetError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(options.mode))
        .map_err(|e| os_error("chmod", e))?;
    if options.owner.is_some() || options.group.is_some() {
        std::os::unix::fs::lchown(path, options.owner, options.group)
            .map_err(|e| os_error("chown", e))?;
    }
    Ok(())
}

/// A temporary name next to `path`: `.<name>.<pid>.<n>`.
#[cfg(unix)]
fn temporary_name(path: &Path) -> Result<PathBuf, NetError> {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let file = path.file_name().ok_or(NetError::InvalidConfig {
        field: "path",
        reason: ConfigReason::Malformed,
    })?;
    let mut name = std::ffi::OsString::from(".");
    name.push(file);
    name.push(format!(
        ".{}.{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    Ok(path.with_file_name(name))
}

#[cfg(unix)]
pub(crate) fn credentials_of(stream: &std::os::unix::net::UnixStream) -> Option<PeerCredentials> {
    sys::peer_credentials(stream.as_fd())
        .ok()
        .map(|(pid, uid, gid)| PeerCredentials {
            pid,
            uid: Some(uid),
            gid: Some(gid),
        })
}

/// A connection on a Unix domain socket, with the same limits, deadlines,
/// and close behaviour as [`TcpConnection`].
///
/// ```no_run
/// let mut conn = net_io::UnixConnection::connect("/run/myapp/control.sock")?;
/// conn.send_all(b"status\n")?;
/// # Ok::<(), net_io::NetError>(())
/// ```
#[cfg(unix)]
pub struct UnixConnection {
    inner: TcpConnection,
}

#[cfg(unix)]
impl UnixConnection {
    /// Connects to the socket at `path`; waits up to 10 s when its backlog is full.
    ///
    /// # Errors
    ///
    /// `NotFound` (no socket, or nobody listening), `PermissionDenied`,
    /// `TimedOut { kind: Connect }`, `PathTooLong`, `InvalidConfig { field: "path" }`, `Os`.
    pub fn connect<P: AsRef<Path>>(path: P) -> Result<UnixConnection, NetError> {
        let path = path.as_ref();
        let bytes = path_bytes(path)?;
        let shared = Arc::new(UnixPath::new(bytes).ok_or(NetError::PathTooLong {
            max: sys::UNIX_PATH_MAX,
        })?);
        let sock = sys::unix_socket().map_err(|e| NetError::from_os("socket", e))?;
        let stream = std::os::unix::net::UnixStream::from(sock);
        stream
            .set_write_timeout(Some(CONNECT_TIMEOUT))
            .map_err(|e| NetError::from_os("setsockopt", e))?;
        if let Err(e) = sys::unix_connect(stream.as_fd(), bytes) {
            return Err(match e.kind() {
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => NetError::NotFound,
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => NetError::TimedOut {
                    kind: TimeoutKind::Connect,
                },
                _ => os_error("connect", e),
            });
        }
        stream
            .set_write_timeout(None)
            .map_err(|e| NetError::from_os("setsockopt", e))?;
        if sys::WAIT_BEFORE_RECV {
            stream
                .set_nonblocking(true)
                .map_err(|e| NetError::from_os("ioctl", e))?;
        }
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

    fn from_stream(
        stream: std::os::unix::net::UnixStream,
        info: ConnectionInfo,
        phase: Phase,
    ) -> UnixConnection {
        let limits = Limits::default().effective(DriverKind::Blocking);
        UnixConnection {
            inner: TcpConnection::from_link(Link::new(
                sys::Stream::Unix(stream),
                info,
                limits,
                ClockRef::Monotonic,
                Arc::new(KillSlot::new()),
                WakeSource::Thread,
                phase,
            )),
        }
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

    fn close_in_place(&mut self) -> Result<(), NetError> {
        match self.inner.take_link() {
            Some(link) => TcpConnection::from_link(link).close(),
            None => Ok(()),
        }
    }

    fn abort_in_place(&mut self) {
        if let Some(link) = self.inner.take_link() {
            TcpConnection::from_link(link).abort();
        }
    }

    /// What net-io knows about this connection.
    #[must_use]
    pub fn info(&self) -> &ConnectionInfo {
        self.inner.info()
    }

    /// The connection's id.
    #[must_use]
    pub fn id(&self) -> ConnectionId {
        self.inner.id()
    }

    /// A handle other threads can use to abort this connection.
    #[must_use]
    pub fn kill_handle(&self) -> KillHandle {
        self.inner.kill_handle()
    }

    /// Replaces the limits from the next operation on.
    pub fn set_limits(&mut self, limits: Limits) {
        self.inner.set_limits(limits);
    }

    /// Chooses which deadlines apply.
    pub fn set_phase(&mut self, phase: Phase) {
        self.inner.set_phase(phase);
    }

    /// The deadline for the current exchange (`None` clears it).
    pub fn set_exchange_deadline(&mut self, at: Option<Instant>) {
        self.inner.set_exchange_deadline(at);
    }

    /// The peer's process, user, and group, as read when the connection was made.
    ///
    /// # Errors
    ///
    /// `Unsupported` when the OS did not report them.
    pub fn peer_credentials(&self) -> Result<PeerCredentials, NetError> {
        self.info().peer_credentials.ok_or(NetError::Unsupported {
            feature: "peer credentials",
            platform: std::env::consts::OS,
        })
    }

    /// Sends all of `body` (not empty) with up to 64 descriptors attached to its
    /// first byte (`SCM_RIGHTS`). The descriptors stay open here; the receiver
    /// gets its own copies.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` (empty body, more than 64 descriptors), as [`UnixConnection::send`].
    pub fn send_descriptors(
        &mut self,
        body: &[u8],
        descriptors: &[BorrowedFd<'_>],
    ) -> Result<(), NetError> {
        self.inner.link()?.write_with_fds(body, descriptors)
    }

    /// One receive that also takes descriptors sent with the bytes, into `into`
    /// (descriptors it still holds are closed first). `Ok(0)` means the peer
    /// closed its side.
    ///
    /// # Errors
    ///
    /// `Handoff(Truncated)` when the control message was cut short: every
    /// descriptor of it was closed and the connection fails, since the bytes
    /// can no longer be framed; as [`UnixConnection::recv`].
    pub fn recv_descriptors(
        &mut self,
        body: &mut [u8],
        into: &mut Descriptors,
    ) -> Result<usize, NetError> {
        into.clear();
        let link = self.inner.link()?;
        loop {
            match link.read_with_fds(body, &mut into.slots)? {
                (Got::Data(n), fds) => {
                    into.len = fds;
                    return Ok(n);
                }
                (Got::Eof, _) => return Ok(0),
                (Got::Woken, _) => continue,
            }
        }
    }
}

#[cfg(unix)]
impl Read for UnixConnection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

#[cfg(unix)]
impl Write for UnixConnection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(unix)]
impl AsFd for UnixConnection {
    fn as_fd(&self) -> BorrowedFd<'_> {
        AsFd::as_fd(&self.inner.link_ref().stream)
    }
}

#[cfg(unix)]
impl std::fmt::Debug for UnixConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnixConnection")
            .field("info", self.inner.info())
            .finish()
    }
}

/// Runs `$body` with the value inside a `Local*` enum. Before named pipes
/// (`0.5.0`) the enums have no variant on Windows, and nothing can run.
#[cfg(unix)]
macro_rules! inside {
    ($kind:ident, $this:expr, $v:ident => $body:expr) => {
        match $this {
            $kind::Unix($v) => $body,
        }
    };
}

#[cfg(not(unix))]
macro_rules! inside {
    ($kind:ident, $this:expr, $v:ident => $body:expr) => {
        match *$this {}
    };
}

/// A local IPC listener: a Unix domain socket (a Windows named pipe from `0.5.0`).
#[non_exhaustive]
#[derive(Debug)]
pub enum LocalListener {
    /// A Unix domain socket.
    #[cfg(unix)]
    Unix(UnixListener),
}

impl LocalListener {
    /// Blocks until a connection arrives.
    ///
    /// # Errors
    ///
    /// As `UnixListener::accept`.
    pub fn accept(&self) -> Result<(LocalConnection, ConnectionInfo), NetError> {
        inside!(LocalListener, self, l => l
            .accept()
            .map(|(c, info)| (LocalConnection::Unix(c), info)))
    }
}

/// A local IPC connection: a Unix domain socket (a Windows named pipe from `0.5.0`).
#[non_exhaustive]
#[derive(Debug)]
pub enum LocalConnection {
    /// A Unix domain socket.
    #[cfg(unix)]
    Unix(UnixConnection),
}

#[cfg_attr(not(unix), allow(unused_variables))]
impl LocalConnection {
    /// One receive; `Ok(0)` means the peer closed its side.
    ///
    /// # Errors
    ///
    /// As [`TcpConnection::recv`](crate::TcpConnection::recv).
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
        inside!(LocalConnection, self, c => c.recv(buf))
    }

    /// Receives until `buf` is full.
    ///
    /// # Errors
    ///
    /// As [`TcpConnection::recv_exact`](crate::TcpConnection::recv_exact).
    pub fn recv_exact(&mut self, buf: &mut [u8]) -> Result<(), NetError> {
        inside!(LocalConnection, self, c => c.recv_exact(buf))
    }

    /// One send; may be partial.
    ///
    /// # Errors
    ///
    /// As [`TcpConnection::send`](crate::TcpConnection::send).
    pub fn send(&mut self, buf: &[u8]) -> Result<usize, NetError> {
        inside!(LocalConnection, self, c => c.send(buf))
    }

    /// Sends all of `buf`.
    ///
    /// # Errors
    ///
    /// As [`TcpConnection::send_all`](crate::TcpConnection::send_all).
    pub fn send_all(&mut self, buf: &[u8]) -> Result<(), NetError> {
        inside!(LocalConnection, self, c => c.send_all(buf))
    }

    /// Half-close.
    ///
    /// # Errors
    ///
    /// `Closed`, `Os`.
    pub fn shutdown(&mut self, how: Shutdown) -> Result<(), NetError> {
        inside!(LocalConnection, self, c => c.shutdown(how))
    }

    /// Graceful close.
    ///
    /// # Errors
    ///
    /// None in this version.
    pub fn close(mut self) -> Result<(), NetError> {
        let this = &mut self;
        inside!(LocalConnection, this, c => c.close_in_place())
    }

    /// Closes at once.
    pub fn abort(mut self) {
        let this = &mut self;
        inside!(LocalConnection, this, c => c.abort_in_place());
    }

    /// What net-io knows about this connection.
    #[must_use]
    pub fn info(&self) -> &ConnectionInfo {
        inside!(LocalConnection, self, c => c.info())
    }

    /// A handle other threads can use to abort this connection.
    #[must_use]
    pub fn kill_handle(&self) -> KillHandle {
        inside!(LocalConnection, self, c => c.kill_handle())
    }

    /// Replaces the limits from the next operation on.
    pub fn set_limits(&mut self, limits: Limits) {
        inside!(LocalConnection, self, c => c.set_limits(limits));
    }
}

impl Read for LocalConnection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv(buf).map_err(io::Error::from)
    }
}

impl Write for LocalConnection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send(buf).map_err(io::Error::from)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Unsupported until named pipes arrive (`0.5.0`).
#[cfg(not(unix))]
fn unsupported() -> NetError {
    NetError::Unsupported {
        feature: "local sockets (Windows named pipes arrive in 0.5.0)",
        platform: std::env::consts::OS,
    }
}

/// Opens a local IPC listener (see [`crate::listen_local`]).
pub(crate) fn listen(name: &str) -> Result<LocalListener, NetError> {
    #[cfg(unix)]
    {
        UnixListener::bind(name).map(LocalListener::Unix)
    }
    #[cfg(not(unix))]
    {
        let _ = name;
        Err(unsupported())
    }
}

/// Connects to a local IPC listener (see [`crate::connect_local`]).
pub(crate) fn connect(name: &str) -> Result<LocalConnection, NetError> {
    #[cfg(unix)]
    {
        UnixConnection::connect(name).map(LocalConnection::Unix)
    }
    #[cfg(not(unix))]
    {
        let _ = name;
        Err(unsupported())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A fresh private directory under the temp dir.
    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("nio-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir(&d).unwrap();
        d
    }

    #[test]
    fn test_bind_accept_echo_and_credentials() {
        let d = dir("echo");
        let path = d.join("s.sock");
        let l = UnixListener::bind(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(l.path(), Some(path.as_path()));
        let p2 = path.clone();
        let t = std::thread::spawn(move || {
            let mut c = UnixConnection::connect(&p2).unwrap();
            assert_eq!(c.info().transport, Transport::Unix);
            assert_eq!(c.info().origin, Origin::Dialed);
            c.send_all(b"ping").unwrap();
            let mut b = [0u8; 4];
            c.recv_exact(&mut b).unwrap();
            assert_eq!(&b, b"ping");
            c.peer_credentials().unwrap()
        });
        let (mut c, info) = l.accept().unwrap();
        assert_eq!(info.transport, Transport::Unix);
        assert_eq!(info.peer, Endpoint::Unnamed);
        let creds = info.peer_credentials.unwrap();
        assert_eq!(creds.pid, Some(std::process::id()));
        let mut b = [0u8; 4];
        c.recv_exact(&mut b).unwrap();
        c.send_all(&b).unwrap();
        let theirs = t.join().unwrap();
        assert_eq!(theirs.uid, creds.uid);
        assert_eq!(c.recv(&mut b).unwrap(), 0);
        drop(l);
        assert!(!path.exists(), "the listener removed its file");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn test_stale_socket_removed_live_one_refused() {
        let d = dir("stale");
        let path = d.join("s.sock");
        // A stale socket file: bound, never listening, closed.
        {
            let s = sys::unix_socket().unwrap();
            sys::unix_bind(s.as_fd(), path.as_os_str().as_encoded_bytes()).unwrap();
        }
        assert!(path.exists());
        let refused = UnixListener::bind_with(&path, LocalOptions::new().remove_stale(false));
        assert!(matches!(refused, Err(NetError::StaleSocketInUse { .. })));
        let l = UnixListener::bind(&path).unwrap();
        // A live listener owns the path.
        assert!(matches!(
            UnixListener::bind(&path),
            Err(NetError::StaleSocketInUse { .. })
        ));
        drop(l);
        // Not a socket: never removed.
        std::fs::write(&path, b"data").unwrap();
        assert!(matches!(
            UnixListener::bind(&path),
            Err(NetError::StaleSocketInUse { .. })
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"data");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Edge cases 76 and 80: a path exactly at the maximum binds; a directory
    /// or a symbolic link at the path is never removed.
    #[test]
    fn test_longest_path_binds_and_non_sockets_stay() {
        let d = dir("max");
        let base = d.as_os_str().len() + 1;
        let name = "a".repeat(sys::UNIX_PATH_MAX - 1 - base);
        let longest = d.join(&name);
        assert_eq!(longest.as_os_str().len(), sys::UNIX_PATH_MAX - 1);
        let l = UnixListener::bind(&longest).unwrap();
        let _c = UnixConnection::connect(&longest).unwrap();
        drop(l);
        let too_long = d.join(format!("{name}a"));
        assert!(matches!(
            UnixListener::bind(&too_long),
            Err(NetError::PathTooLong { .. })
        ));
        let sub = d.join("sub");
        std::fs::create_dir(&sub).unwrap();
        assert!(matches!(
            UnixListener::bind(&sub),
            Err(NetError::StaleSocketInUse { .. })
        ));
        assert!(sub.is_dir());
        let target = d.join("t.sock");
        let live = UnixListener::bind(&target).unwrap();
        let link = d.join("link.sock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(
            UnixListener::bind(&link),
            Err(NetError::StaleSocketInUse { .. })
        ));
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        drop(live);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Edge case 84: credentials the OS did not report never satisfy `require_uid`.
    #[test]
    fn test_unknown_credentials_fail_require_uid() {
        let d = dir("nocreds");
        let path = d.join("s.sock");
        let l = UnixListener::bind_with(&path, LocalOptions::new().require_uid(0)).unwrap();
        assert!(!l.permits(None));
        let no_uid = PeerCredentials {
            pid: Some(1),
            uid: None,
            gid: None,
        };
        assert!(!l.permits(Some(no_uid)));
        let root = PeerCredentials {
            pid: None,
            uid: Some(0),
            gid: None,
        };
        assert!(l.permits(Some(root)));
        let open = UnixListener::bind(d.join("o.sock")).unwrap();
        assert!(open.permits(None));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn test_drop_leaves_a_replacement_alone() {
        let d = dir("replace");
        let path = d.join("s.sock");
        let l = UnixListener::bind(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let other = UnixListener::bind(&path).unwrap();
        drop(l);
        assert!(
            path.exists(),
            "the first listener did not remove the second's file"
        );
        drop(other);
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn test_bind_atomic_sets_mode_and_leaves_no_temporary() {
        let d = dir("atomic");
        let path = d.join("s.sock");
        let l = UnixListener::bind_atomic(&path, LocalOptions::new().mode(0o640)).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
        let names: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
        let c = UnixConnection::connect(&path).unwrap();
        let (_s, _) = l.accept().unwrap();
        drop(c);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn test_path_checks() {
        let long = format!("/tmp/{}", "a".repeat(sys::UNIX_PATH_MAX));
        assert!(matches!(
            UnixListener::bind(&long),
            Err(NetError::PathTooLong { max }) if max == sys::UNIX_PATH_MAX
        ));
        assert!(matches!(
            UnixConnection::connect(&long),
            Err(NetError::PathTooLong { .. })
        ));
        let nul = <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(b"/tmp/a\0b");
        assert!(matches!(
            UnixListener::bind(nul),
            Err(NetError::InvalidConfig {
                field: "path",
                reason: ConfigReason::Malformed
            })
        ));
        let d = dir("missing");
        assert!(matches!(
            UnixConnection::connect(d.join("none.sock")),
            Err(NetError::NotFound)
        ));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn test_require_uid_closes_other_users() {
        let d = dir("uid");
        let path = d.join("s.sock");
        let me = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&d).unwrap());
        let l = UnixListener::bind_with(&path, LocalOptions::new().require_uid(me.wrapping_add(1)))
            .unwrap();
        let mut c = UnixConnection::connect(&path).unwrap();
        assert!(
            l.accept_timeout(Duration::from_millis(200))
                .unwrap()
                .is_none()
        );
        // The connection was closed before any read.
        c.set_limits(
            Limits::builder()
                .read_timeout(Duration::from_secs(2))
                .build()
                .unwrap(),
        );
        let mut b = [0u8; 1];
        assert!(matches!(
            c.recv(&mut b),
            Ok(0) | Err(NetError::ConnectionReset)
        ));
        drop(l);
        let l = UnixListener::bind_with(&path, LocalOptions::new().require_uid(me)).unwrap();
        let _c = UnixConnection::connect(&path).unwrap();
        assert!(l.accept_timeout(Duration::from_secs(2)).unwrap().is_some());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn test_descriptors_travel_with_bytes() {
        let d = dir("fds");
        let path = d.join("s.sock");
        let l = UnixListener::bind(&path).unwrap();
        let p2 = path.clone();
        let t = std::thread::spawn(move || {
            let mut c = UnixConnection::connect(&p2).unwrap();
            let (mut mine, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
            c.send_descriptors(b"take this", &[theirs.as_fd()]).unwrap();
            drop(theirs);
            mine.write_all(b"hello").unwrap();
            let mut b = [0u8; 1];
            let _ = c.recv(&mut b);
        });
        let (mut c, _) = l.accept().unwrap();
        let mut fds = Descriptors::new();
        let mut body = [0u8; 32];
        // One sendmsg of 9 bytes with its descriptor arrives as one message.
        let n = c.recv_descriptors(&mut body, &mut fds).unwrap();
        assert_eq!(&body[..n], b"take this");
        assert_eq!(fds.len(), 1);
        let fd = fds.take().next().unwrap();
        assert!(fds.is_empty());
        let mut s = std::os::unix::net::UnixStream::from(fd);
        let mut b = [0u8; 5];
        s.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"hello");
        assert!(matches!(
            c.send_descriptors(b"", &[]),
            Err(NetError::InvalidConfig { field: "body", .. })
        ));
        c.close().unwrap();
        t.join().unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn test_local_enums_round_trip() {
        let d = dir("enums");
        let path = d.join("s.sock");
        let name = path.to_str().unwrap().to_owned();
        let l = listen(&name).unwrap();
        let n2 = name.clone();
        let t = std::thread::spawn(move || {
            let mut c = connect(&n2).unwrap();
            c.send_all(b"hi").unwrap();
            c.close().unwrap();
        });
        let (mut c, info) = l.accept().unwrap();
        assert_eq!(info.transport, Transport::Unix);
        let mut b = [0u8; 2];
        c.recv_exact(&mut b).unwrap();
        assert_eq!(&b, b"hi");
        t.join().unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }
}
