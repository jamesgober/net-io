//! Windows named pipes (feature `local`).
//!
//! A `PipeConnection` runs on the same connection core as TCP and Unix sockets:
//! the same limits, deadlines, kill handle, and gate.

use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::driver::DriverKind;
use crate::error::{ConfigReason, NetError, TimeoutKind};
use crate::gate::KillHandle;
use crate::id::{ConnectionId, ListenerId};
use crate::info::{ConnectionInfo, Endpoint, Origin, PeerCredentials, PipeName, Transport};
use crate::limits::Limits;
use crate::link::{ClockRef, Link, WakeSource};
use crate::proxy::ProxyMode;
use crate::session::Phase;
use crate::sys::{self, Descriptor, KillSlot, PipeParams, PipeServer, PipeStream};
use crate::tcp::{ListenerInfo, TcpConnection};

/// Who may open a pipe.
///
/// ```
/// let open = net_io::PipeSecurity::OwnerAndSystem;
/// # let _ = open;
/// ```
#[cfg_attr(docsrs, doc(cfg(windows)))]
#[non_exhaustive]
#[derive(Clone, Debug, Default)]
pub enum PipeSecurity {
    /// The user who created the pipe.
    #[default]
    OwnerOnly,
    /// That user and the local system account.
    OwnerAndSystem,
    /// A security descriptor in SDDL.
    Sddl(String),
}

/// How a pipe is created.
///
/// ```
/// use net_io::{PipeOptions, PipeSecurity};
/// let options = PipeOptions::new().max_instances(16).security(PipeSecurity::OwnerAndSystem);
/// # let _ = options;
/// ```
#[cfg_attr(docsrs, doc(cfg(windows)))]
#[must_use]
#[derive(Clone, Debug)]
pub struct PipeOptions {
    max_instances: u8,
    security: PipeSecurity,
    inbound: u32,
    outbound: u32,
}

impl Default for PipeOptions {
    fn default() -> PipeOptions {
        PipeOptions::new()
    }
}

impl PipeOptions {
    /// Owner only, 255 instances, 64 KiB buffers each way.
    pub fn new() -> PipeOptions {
        PipeOptions {
            max_instances: 255,
            security: PipeSecurity::OwnerOnly,
            inbound: 64 * 1024,
            outbound: 64 * 1024,
        }
    }

    /// The most connections at once (at least 1; 255 is the OS's "unlimited").
    pub fn max_instances(mut self, n: u8) -> PipeOptions {
        self.max_instances = n;
        self
    }

    /// Who may open the pipe.
    pub fn security(mut self, security: PipeSecurity) -> PipeOptions {
        self.security = security;
        self
    }

    /// The kernel's buffer in each direction, in bytes.
    pub fn buffer_sizes(mut self, inbound: u32, outbound: u32) -> PipeOptions {
        self.inbound = inbound;
        self.outbound = outbound;
        self
    }
}

fn os_error(op: &'static str, e: io::Error) -> NetError {
    match e.kind() {
        io::ErrorKind::PermissionDenied => NetError::PermissionDenied { what: "the pipe" },
        _ => NetError::from_os(op, e),
    }
}

/// The longest name part: the OS takes at most 256 characters for the whole path,
/// and `\\.\pipe\` is nine of them.
const NAME_MAX: usize = 256 - 9;

/// The name part of `\\.\pipe\<name>`. Windows rewrites a `\\.\` path before it
/// opens it: `/` becomes `\`, and `.` and `..` components are resolved. So a name
/// holds no separator of either kind and is not `.` or `..`; otherwise
/// `../C:/file` would open a file, and `../UNC/host/share` a network path, instead
/// of a pipe. A name with no separator is one component, so nothing in it can
/// climb out of `\\.\pipe\`.
fn check_name(name: &str) -> Result<Arc<PipeName>, NetError> {
    if name.is_empty() || name.contains(['\\', '/', '\0']) || name == "." || name == ".." {
        return Err(NetError::InvalidConfig {
            field: "name",
            reason: ConfigReason::Malformed,
        });
    }
    let too_long = NetError::InvalidConfig {
        field: "name",
        reason: ConfigReason::TooLarge {
            max: NAME_MAX as u64,
        },
    };
    if name.encode_utf16().count() > NAME_MAX {
        return Err(too_long);
    }
    PipeName::new(name).map(Arc::new).ok_or(too_long)
}

/// Listens on `\\.\pipe\<name>`. Remote clients are always rejected, and the first
/// instance claims the name, so a process that took it first is an error rather
/// than a shared pipe.
///
/// ```no_run
/// use net_io::PipeListener;
/// let listener = PipeListener::create("myapp-control")?;
/// let (mut conn, info) = listener.accept()?;
/// println!("client process {:?}", info.peer_credentials.and_then(|c| c.pid));
/// conn.send_all(b"ok\n")?;
/// # Ok::<(), net_io::NetError>(())
/// ```
#[cfg_attr(docsrs, doc(cfg(windows)))]
#[derive(Debug)]
pub struct PipeListener {
    server: PipeServer,
    name: Arc<PipeName>,
    info: ListenerInfo,
}

impl PipeListener {
    /// Creates the pipe with the default options: only this user may connect.
    ///
    /// # Errors
    ///
    /// As [`PipeListener::create_with`].
    pub fn create(name: &str) -> Result<PipeListener, NetError> {
        PipeListener::create_with(name, PipeOptions::new())
    }

    /// Creates the pipe.
    ///
    /// # Errors
    ///
    /// `PipeNameInUse` (another process owns the name: possible squatting),
    /// `InvalidConfig` (an empty name, a `\` or `/`, the name `.` or `..`, more
    /// than 247 characters, or bad SDDL),
    /// `PermissionDenied`, `Os`.
    pub fn create_with(name: &str, options: PipeOptions) -> Result<PipeListener, NetError> {
        let shared = check_name(name)?;
        let sddl = match options.security {
            PipeSecurity::OwnerOnly => sys::owner_sddl(false),
            PipeSecurity::OwnerAndSystem => sys::owner_sddl(true),
            PipeSecurity::Sddl(text) => Ok(text),
        }
        .map_err(|e| NetError::from_os("security descriptor", e))?;
        let descriptor = Descriptor::from_sddl(&sddl).map_err(|_| NetError::InvalidConfig {
            field: "security",
            reason: ConfigReason::Malformed,
        })?;
        let params = PipeParams {
            max_instances: options.max_instances.max(1),
            inbound: options.inbound,
            outbound: options.outbound,
        };
        let server = PipeServer::create(name, params, descriptor).map_err(|e| {
            if sys::is_name_taken(&e) {
                NetError::PipeNameInUse {
                    name: name.to_owned(),
                }
            } else {
                os_error("CreateNamedPipeW", e)
            }
        })?;
        Ok(PipeListener {
            server,
            info: ListenerInfo {
                id: ListenerId(0),
                name: None,
                local: Endpoint::Pipe(shared.clone()),
                backlog: None,
                transport: Transport::Pipe,
                proxy: ProxyMode::Off,
                tls: false,
            },
            name: shared,
        })
    }

    /// Blocks until a client connects. The next instance exists before this
    /// returns, so a client never finds none.
    ///
    /// # Errors
    ///
    /// `Os`.
    pub fn accept(&self) -> Result<(PipeConnection, ConnectionInfo), NetError> {
        loop {
            let stream = self
                .server
                .accept(None)
                .map_err(|e| NetError::from_os("ConnectNamedPipe", e))?;
            if let Some(stream) = stream {
                let info = self.info_of(&stream, crate::id::issue_single(), Instant::now());
                let conn = PipeConnection::from_stream(stream, info.clone(), Phase::Idle);
                return Ok((conn, info));
            }
        }
    }

    /// Waits for a client or for `wake`; `None` when `wake` fired.
    pub(crate) fn accept_or_wake(&self, wake: &sys::Wake) -> io::Result<Option<PipeStream>> {
        self.server.accept(Some(wake))
    }

    /// What a connection accepted from this listener knows of itself.
    pub(crate) fn info_of(
        &self,
        stream: &PipeStream,
        id: ConnectionId,
        at: Instant,
    ) -> ConnectionInfo {
        let credentials = stream.client_pid().ok().map(|pid| PeerCredentials {
            uid: None,
            gid: None,
            pid: Some(pid),
        });
        let mut info = ConnectionInfo::new_unix(
            id,
            Some(self.info.id),
            Origin::Accepted,
            Endpoint::Pipe(self.name.clone()),
            Endpoint::Unnamed,
            credentials,
            at,
        );
        info.transport = Transport::Pipe;
        info
    }

    /// What this listener is.
    #[must_use]
    pub fn info(&self) -> &ListenerInfo {
        &self.info
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

/// A connected named pipe, either end. It has the connection core of
/// [`TcpConnection`]: limits, deadlines, a kill handle, a graceful close. A pipe has
/// no half-close of its read side, and the OS keeps what was written readable after
/// a close, so a graceful close has no linger.
///
/// ```no_run
/// use std::time::Duration;
/// use net_io::PipeConnection;
/// let mut conn = PipeConnection::connect("myapp-control", Duration::from_secs(5))?;
/// conn.send_all(b"status\n")?;
/// # Ok::<(), net_io::NetError>(())
/// ```
#[cfg_attr(docsrs, doc(cfg(windows)))]
#[derive(Debug)]
pub struct PipeConnection {
    inner: TcpConnection,
}

impl PipeConnection {
    fn from_stream(stream: PipeStream, info: ConnectionInfo, phase: Phase) -> PipeConnection {
        let limits = Arc::new(Limits::default().effective(DriverKind::Blocking));
        PipeConnection {
            inner: TcpConnection::from_link(Link::new(
                sys::Stream::Pipe(stream),
                info,
                limits,
                ClockRef::Monotonic,
                Arc::new(KillSlot::new()),
                WakeSource::Thread,
                phase,
            )),
        }
    }

    /// Opens `\\.\pipe\<name>`, waiting up to `timeout` for a free instance. The
    /// server can identify this process, and cannot impersonate it.
    ///
    /// # Errors
    ///
    /// `NotFound` (nobody serves the name), `PermissionDenied`,
    /// `TimedOut { kind: Connect }`, `InvalidConfig` (a name `create_with` refuses),
    /// `Os`.
    pub fn connect(name: &str, timeout: Duration) -> Result<PipeConnection, NetError> {
        let shared = check_name(name)?;
        let stream = sys::pipe_connect(name, timeout).map_err(|e| {
            if sys::is_no_pipe(&e) {
                NetError::NotFound
            } else if e.kind() == io::ErrorKind::TimedOut {
                NetError::TimedOut {
                    kind: TimeoutKind::Connect,
                }
            } else {
                os_error("CreateFileW", e)
            }
        })?;
        let mut info = ConnectionInfo::new_unix(
            crate::id::issue_single(),
            None,
            Origin::Dialed,
            Endpoint::Unnamed,
            Endpoint::Pipe(shared),
            None,
            Instant::now(),
        );
        info.transport = Transport::Pipe;
        Ok(PipeConnection::from_stream(stream, info, Phase::Receiving))
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

    /// `Shutdown::Write` does nothing a pipe can show the peer until the close;
    /// the read side has no shutdown.
    ///
    /// # Errors
    ///
    /// `Unsupported` for the read side, `Closed`.
    pub fn shutdown(&mut self, how: Shutdown) -> Result<(), NetError> {
        if how != Shutdown::Write {
            return Err(NetError::Unsupported {
                feature: "shutting down a pipe's read side",
                platform: std::env::consts::OS,
            });
        }
        self.inner.shutdown(how)
    }

    /// Graceful close.
    ///
    /// # Errors
    ///
    /// None in this version.
    pub fn close(self) -> Result<(), NetError> {
        self.inner.close()
    }

    /// Closes at once; bytes the kernel has not taken are dropped.
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

    /// The process at the other end (`GetNamedPipeClientProcessId`).
    ///
    /// # Errors
    ///
    /// `Closed`, `Os`.
    pub fn client_pid(&self) -> Result<u32, NetError> {
        self.inner.pipe_pid(false)
    }

    /// The process at the far end, whichever end this is.
    pub(crate) fn peer_pid(&self) -> Result<u32, NetError> {
        self.inner.pipe_pid(self.info().origin == Origin::Dialed)
    }

    /// The pipe's handle, for tests that need its value.
    #[cfg(test)]
    pub(crate) fn raw_handle(&self) -> std::os::windows::io::RawHandle {
        match &self.inner.link_ref().stream {
            sys::Stream::Pipe(p) => p.raw(),
            _ => std::ptr::null_mut(),
        }
    }
}

impl Read for PipeConnection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for PipeConnection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn name() -> String {
        static N: AtomicU32 = AtomicU32::new(0);
        format!(
            "net-io-unit-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn pair() -> (PipeConnection, PipeConnection) {
        let n = name();
        let listener = PipeListener::create(&n).unwrap();
        let client = std::thread::spawn({
            let n = n.clone();
            move || PipeConnection::connect(&n, Duration::from_secs(5)).unwrap()
        });
        let (server, _) = listener.accept().unwrap();
        (server, client.join().unwrap())
    }

    #[test]
    fn test_round_trip_and_end_of_stream() {
        let (mut server, mut client) = pair();
        client.send_all(b"ping").unwrap();
        let mut buf = [0; 4];
        server.recv_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        server.send_all(b"pong").unwrap();
        client.recv_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");
        drop(server);
        assert_eq!(client.recv(&mut buf).unwrap(), 0);
    }

    #[test]
    fn test_large_transfer_both_ways_at_once() {
        let (mut server, mut client) = pair();
        let body = vec![7u8; 1 << 20];
        let writer = std::thread::spawn({
            let body = body.clone();
            move || {
                client.send_all(&body).unwrap();
                let mut back = vec![0u8; body.len()];
                client.recv_exact(&mut back).unwrap();
                back
            }
        });
        let mut got = vec![0u8; body.len()];
        server.recv_exact(&mut got).unwrap();
        server.send_all(&got).unwrap();
        assert_eq!(writer.join().unwrap(), body);
    }

    #[test]
    fn test_write_then_close_delivers_everything() {
        let (mut server, mut client) = pair();
        let body = vec![9u8; 200 * 1024];
        let reader = std::thread::spawn(move || {
            let mut all = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                match client.recv(&mut buf).unwrap() {
                    0 => return all.len(),
                    n => all.extend_from_slice(&buf[..n]),
                }
            }
        });
        server.send_all(&body).unwrap();
        server.close().unwrap();
        assert_eq!(reader.join().unwrap(), body.len());
    }

    #[test]
    fn test_read_timeout_and_kill() {
        let (mut server, _client) = pair();
        server.set_phase(Phase::Receiving);
        server.set_limits(
            Limits::builder()
                .read_timeout(Duration::from_millis(50))
                .build()
                .unwrap(),
        );
        let mut buf = [0; 4];
        assert!(matches!(
            server.recv(&mut buf),
            Err(NetError::TimedOut {
                kind: TimeoutKind::Read
            })
        ));

        let (mut server, _client) = pair();
        let kill = server.kill_handle();
        let killer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            kill.kill(crate::error::KillReason(7));
        });
        assert!(matches!(
            server.recv(&mut buf),
            Err(NetError::Killed { .. })
        ));
        killer.join().unwrap();
    }

    #[test]
    fn test_client_pid_and_credentials() {
        let n = name();
        let listener = PipeListener::create(&n).unwrap();
        let client = PipeConnection::connect(&n, Duration::from_secs(5)).unwrap();
        let (server, info) = listener.accept().unwrap();
        let me = std::process::id();
        assert_eq!(server.client_pid().unwrap(), me);
        assert_eq!(client.client_pid().unwrap(), me);
        assert_eq!(info.transport, Transport::Pipe);
        assert_eq!(info.peer_credentials.and_then(|c| c.pid), Some(me));
    }

    /// Edge cases 86 and 87: a name held by someone else is an error, and a client
    /// is never without an instance.
    #[test]
    fn test_name_in_use_and_next_instance() {
        let n = name();
        let first = PipeListener::create(&n).unwrap();
        assert!(matches!(
            PipeListener::create(&n),
            Err(NetError::PipeNameInUse { .. })
        ));
        let one = PipeConnection::connect(&n, Duration::from_secs(1)).unwrap();
        let (_a, _) = first.accept().unwrap();
        // accept() already made the next instance: no waiting here.
        let two = PipeConnection::connect(&n, Duration::from_millis(100)).unwrap();
        let (_b, _) = first.accept().unwrap();
        drop((one, two));
    }

    #[test]
    fn test_names_are_checked_before_any_call() {
        let long = "n".repeat(NAME_MAX + 1);
        for bad in [
            "",
            "a\\b",
            "a\0b",
            "a/b",
            ".",
            "..",
            "../C:/Windows/win.ini",
            "../UNC/host/share",
            "x/../../C:/file",
            &long,
        ] {
            assert!(matches!(
                PipeListener::create(bad),
                Err(NetError::InvalidConfig { .. })
            ));
            assert!(
                matches!(
                    PipeConnection::connect(bad, Duration::from_millis(50)),
                    Err(NetError::InvalidConfig { .. })
                ),
                "{bad:?}"
            );
        }
        // The longest name the OS takes still works.
        let longest: String = format!("{}{}", name(), "n".repeat(NAME_MAX))
            .chars()
            .take(NAME_MAX)
            .collect();
        assert!(PipeListener::create(&longest).is_ok());
        assert!(matches!(
            PipeConnection::connect("nobody-serves-this-name", Duration::from_millis(50)),
            Err(NetError::NotFound)
        ));
    }

    #[test]
    fn test_instance_cap_makes_a_client_wait() {
        let n = name();
        let listener = PipeListener::create_with(&n, PipeOptions::new().max_instances(1)).unwrap();
        let one = PipeConnection::connect(&n, Duration::from_secs(1)).unwrap();
        let (server, _) = listener.accept().unwrap();
        assert!(matches!(
            PipeConnection::connect(&n, Duration::from_millis(50)),
            Err(NetError::TimedOut {
                kind: TimeoutKind::Connect
            })
        ));
        drop((one, server));
    }

    /// Edge case 88: a client that came and went before the accept costs nothing.
    #[test]
    fn test_client_gone_before_accept() {
        let n = name();
        let listener = PipeListener::create(&n).unwrap();
        drop(PipeConnection::connect(&n, Duration::from_secs(1)).unwrap());
        let next = std::thread::spawn({
            let n = n.clone();
            move || PipeConnection::connect(&n, Duration::from_secs(5)).unwrap()
        });
        let (mut server, _) = listener.accept().unwrap();
        let mut client = next.join().unwrap();
        client.send_all(b"k").unwrap();
        let mut one = [0u8; 1];
        server.recv_exact(&mut one).unwrap();
        assert_eq!(&one, b"k");
    }

    #[test]
    fn test_security_keeps_this_user_out_when_told_to() {
        let n = name();
        let _listener = PipeListener::create_with(
            &n,
            PipeOptions::new().security(PipeSecurity::Sddl("D:P(A;;GA;;;SY)".into())),
        )
        .unwrap();
        assert!(matches!(
            PipeConnection::connect(&n, Duration::from_secs(1)),
            Err(NetError::PermissionDenied { .. })
        ));
    }

    #[test]
    fn test_bad_sddl_is_a_config_error() {
        let err = PipeListener::create_with(
            &name(),
            PipeOptions::new().security(PipeSecurity::Sddl("not sddl".into())),
        );
        assert!(matches!(err, Err(NetError::InvalidConfig { .. })));
    }
}
