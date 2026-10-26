//! The server: listeners, workers, the door, drain, and shutdown.

mod engine;
mod source;

use std::any::TypeId;
use std::fmt;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::control::ControlLine;
use crate::driver::DriverKind;
use crate::error::{CloseReason, ConfigReason, KillReason, NetError, RefusalCause};
use crate::events::{EventSink, NoopSink};
use crate::gate::Gate;
use crate::id::{ConnectionId, WorkerId};
use crate::limits::Limits;
use crate::opts::{ListenOptions, LocalOptions};
use crate::proxy::ProxyMode;
use crate::session::SessionFactory;
use crate::tcp::{ListenerInfo, TcpConnection};
use crate::time::Clock;
use crate::tls::ErasedAcceptor;
use crate::tls::{NoTls, TlsAcceptor};
use crate::trusted::TrustedProxies;

pub(crate) use engine::Shared;

/// Whether the server is accepting.
///
/// ```
/// assert_ne!(net_io::DoorState::Open, net_io::DoorState::Closed);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DoorState {
    /// Accepting new connections.
    Open,
    /// Not accepting; listening sockets stay open.
    Closed,
}

/// What a drain did.
///
/// ```
/// let r = net_io::DrainReport { graceful: 3, killed: 1, took: std::time::Duration::from_millis(40) };
/// assert_eq!(r.graceful + r.killed, 4);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrainReport {
    /// Connections that finished before the deadline.
    pub graceful: u32,
    /// Connections killed at the deadline.
    pub killed: u32,
    /// How long the drain took.
    pub took: Duration,
}

/// Counters summed over the workers.
///
/// ```no_run
/// let server = net_io::serve("127.0.0.1:0", |_c| Ok(()))?;
/// let stats = server.stats();
/// println!("{} open, {} accepted", stats.open, stats.accepted);
/// # Ok::<(), net_io::NetError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Connections open now.
    pub open: u64,
    /// Connections accepted.
    pub accepted: u64,
    /// Connections refused.
    pub refused: u64,
    /// Connections closed.
    pub closed: u64,
    /// Bytes received.
    pub bytes_in: u64,
    /// Bytes sent.
    pub bytes_out: u64,
    /// Writes the gate denied.
    pub egress_denied: u64,
    /// Connections killed.
    pub killed: u64,
    /// Connections closed for the minimum rate.
    pub slow_peers: u64,
    /// Connections closed by a timeout.
    pub timeouts: u64,
    /// Times the process ran out of descriptors.
    pub descriptor_pressure: u64,
    /// Completions for connections that had closed.
    pub stale_completions: u64,
    /// Sessions that panicked.
    pub session_panics: u64,
    refused_by: [u64; RefusalCause::COUNT],
    closed_by: [u64; CloseReason::COUNT],
}

impl Stats {
    /// Refusals with this cause (gate codes summed).
    #[must_use]
    pub fn refused_for(&self, cause: RefusalCause) -> u64 {
        self.refused_by[cause.index()]
    }

    /// Closes with this reason's variant (inner values ignored).
    #[must_use]
    pub fn closed_for(&self, reason: CloseReason) -> u64 {
        self.closed_by[reason.index()]
    }

    /// Every close reason with a non-zero count, one entry per variant (inner
    /// values are not kept: `Killed` carries reason 0, `Io` class `Other(0)`).
    ///
    /// ```no_run
    /// let server = net_io::serve("127.0.0.1:0", |_c| Ok(()))?;
    /// for (reason, n) in server.stats().closes() {
    ///     println!("{}: {n}", reason.as_str());
    /// }
    /// # Ok::<(), net_io::NetError>(())
    /// ```
    pub fn closes(&self) -> impl Iterator<Item = (CloseReason, u64)> + '_ {
        CloseReason::BY_INDEX
            .iter()
            .zip(self.closed_by.iter())
            .filter(|(_, n)| **n > 0)
            .map(|(r, n)| (*r, *n))
    }

    /// Every refusal cause with a non-zero count (gate codes summed under `Gate(0)`).
    pub fn refusals(&self) -> impl Iterator<Item = (RefusalCause, u64)> + '_ {
        RefusalCause::BY_INDEX
            .iter()
            .zip(self.refused_by.iter())
            .filter(|(_, n)| **n > 0)
            .map(|(r, n)| (*r, *n))
    }
}

/// One listener of a server.
///
/// ```
/// use net_io::{ListenerSpec, Limits};
/// let spec = ListenerSpec::tcp("127.0.0.1:0")
///     .name("admin")
///     .limits(Limits::builder().max_per_listener(10).build()?);
/// # let _ = spec;
/// # Ok::<(), net_io::NetError>(())
/// ```
#[must_use]
#[derive(Debug)]
pub struct ListenerSpec {
    pub(crate) addrs: Result<Vec<SocketAddr>, String>,
    pub(crate) options: Option<ListenOptions>,
    pub(crate) name: Option<String>,
    pub(crate) limits: Limits,
    pub(crate) proxy: ProxyMode,
    pub(crate) trusted: Option<Arc<TrustedProxies>>,
    pub(crate) tls: bool,
    pub(crate) unix: Option<(PathBuf, LocalOptions)>,
}

impl ListenerSpec {
    /// A TCP listener on `addr` (resolved now; a failure is reported by `build`).
    pub fn tcp<A: ToSocketAddrs>(addr: A) -> ListenerSpec {
        ListenerSpec {
            addrs: addr
                .to_socket_addrs()
                .map(|i| i.collect())
                .map_err(|e| e.to_string()),
            options: None,
            name: None,
            limits: Limits::default(),
            proxy: ProxyMode::Off,
            trusted: None,
            tls: false,
            unix: None,
        }
    }

    /// A TCP listener with explicit options (their backlog wins over the limits').
    pub fn tcp_with<A: ToSocketAddrs>(addr: A, options: ListenOptions) -> ListenerSpec {
        ListenerSpec {
            options: Some(options),
            ..ListenerSpec::tcp(addr)
        }
    }

    /// A Unix domain socket listener at `path` (feature `local`, Unix; Windows
    /// AF_UNIX arrives in `0.5.0`). The socket file gets `options`' mode and
    /// owner before it listens, and is removed at shutdown if it is still the
    /// file this server created. Connections carry `Transport::Unix`, the peer's
    /// credentials, and no IP address: the per-source cap does not apply, and a
    /// `BlockingHandler` receives them as a `TcpConnection` whose `peer_addr` is
    /// unspecified. With `proxy`, every peer is trusted: the socket file's
    /// permissions decide who may connect.
    ///
    /// ```
    /// use net_io::{ListenerSpec, LocalOptions};
    /// let spec = ListenerSpec::unix("/run/myapp/api.sock", LocalOptions::new().group_access(33));
    /// # let _ = spec;
    /// ```
    pub fn unix(path: impl Into<PathBuf>, options: LocalOptions) -> ListenerSpec {
        ListenerSpec {
            addrs: Ok(Vec::new()),
            options: None,
            name: None,
            limits: Limits::default(),
            proxy: ProxyMode::Off,
            trusted: None,
            tls: false,
            unix: Some((path.into(), options)),
        }
    }

    /// A name (up to 64 bytes) for events and hand-off.
    pub fn name(mut self, name: &str) -> ListenerSpec {
        self.name = Some(name.to_owned());
        self
    }

    /// Per-listener caps and deadlines; values set here override the server's.
    pub fn limits(mut self, limits: Limits) -> ListenerSpec {
        self.limits = limits;
        self
    }

    /// Requires a PROXY protocol header on every connection (feature `proxy`).
    /// Peers outside the trusted proxies are closed before any byte is read.
    ///
    /// ```
    /// use net_io::{ListenerSpec, ProxyMode, ProxyVersions};
    /// let spec = ListenerSpec::tcp("127.0.0.1:0").proxy(ProxyMode::Required { versions: ProxyVersions::Both });
    /// # let _ = spec;
    /// ```
    pub fn proxy(mut self, mode: ProxyMode) -> ListenerSpec {
        self.proxy = mode;
        self
    }

    /// Serves TLS on this listener through the builder's acceptor
    /// ([`ServerBuilder::tls`], feature `tls`).
    pub fn tls(mut self, on: bool) -> ListenerSpec {
        self.tls = on;
        self
    }

    /// The proxies trusted on this listener, instead of the server's list.
    pub fn trusted_proxies(mut self, proxies: TrustedProxies) -> ListenerSpec {
        self.trusted = Some(Arc::new(proxies));
        self
    }
}

/// What runs per connection; the unset state (no `build` exists for it).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoWork;

/// The unset gate (no `build` exists for it): name `AllowAll` to run without a gate.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoGate;

/// What `ServerBuilder::sessions` produces; programs never name it.
#[derive(Debug)]
pub struct Sessions<F> {
    pub(crate) factory: F,
}

/// What `ServerBuilder::handler` produces; programs never name it.
pub struct BlockingHandler<H> {
    pub(crate) handler: H,
}

impl<H> fmt::Debug for BlockingHandler<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BlockingHandler")
    }
}

pub(crate) mod sealed {
    pub trait Sealed {}
}

/// What runs per connection: [`Sessions`] or a [`BlockingHandler`]. Sealed.
pub trait Workload: sealed::Sealed + engine::Serve + Send + Sync + 'static {}

impl<F: SessionFactory> sealed::Sealed for Sessions<F> {}
impl<F: SessionFactory> Workload for Sessions<F> {}

impl<H> sealed::Sealed for BlockingHandler<H> where
    H: Fn(&mut TcpConnection) -> Result<(), NetError> + Send + Sync + 'static
{
}
impl<H> Workload for BlockingHandler<H> where
    H: Fn(&mut TcpConnection) -> Result<(), NetError> + Send + Sync + 'static
{
}

/// Builds a [`Server`]. A builder without a gate or without `sessions`/`handler`
/// has no `build` method: forgetting either is a compile error.
///
/// # Examples
///
/// ```no_run
/// use net_io::{AllowAll, DriverKind, Limits, ListenerSpec, ServerBuilder};
/// use std::time::{Duration, Instant};
///
/// let server = ServerBuilder::new()
///     .listener(ListenerSpec::tcp("0.0.0.0:8080").name("public"))
///     .listener(ListenerSpec::tcp("127.0.0.1:9090").name("admin"))
///     .driver(DriverKind::Blocking)
///     .workers(64)
///     .limits(Limits::builder().idle_timeout(Duration::from_secs(5)).build()?)
///     .handler(|conn| { conn.send_all(b"hello\n")?; Ok(()) })
///     .gate(AllowAll)
///     .build()?;              // listeners bound, workers started, door closed
/// // ... drop privileges here ...
/// server.open_door()?;
/// let report = server.shutdown(Instant::now() + Duration::from_secs(30));
/// println!("{report:?}");
/// # Ok::<(), net_io::NetError>(())
/// ```
#[must_use]
pub struct ServerBuilder<W = NoWork, G = NoGate, S = NoopSink, T = NoTls> {
    listeners: Vec<ListenerSpec>,
    driver: DriverKind,
    workers: Option<u16>,
    limits: Limits,
    work: W,
    gate: G,
    sink: S,
    tls: T,
    control: Option<Arc<dyn ControlLine>>,
    wipe: bool,
    clock: Option<Arc<dyn Clock>>,
    trusted: Option<Arc<TrustedProxies>>,
}

impl ServerBuilder {
    /// An empty builder.
    pub fn new() -> ServerBuilder {
        ServerBuilder {
            listeners: Vec::new(),
            driver: DriverKind::Auto,
            workers: None,
            limits: Limits::default(),
            work: NoWork,
            gate: NoGate,
            sink: NoopSink,
            tls: NoTls,
            control: None,
            wipe: true,
            clock: None,
            trusted: None,
        }
    }
}

impl Default for ServerBuilder {
    fn default() -> ServerBuilder {
        ServerBuilder::new()
    }
}

impl<W, G, S, T> ServerBuilder<W, G, S, T> {
    fn map<W2, G2, S2, T2>(
        self,
        f: impl FnOnce(W, G, S, T) -> (W2, G2, S2, T2),
    ) -> ServerBuilder<W2, G2, S2, T2> {
        let ServerBuilder {
            listeners,
            driver,
            workers,
            limits,
            work,
            gate,
            sink,
            tls,
            control,
            wipe,
            clock,
            trusted,
        } = self;
        let (work, gate, sink, tls) = f(work, gate, sink, tls);
        ServerBuilder {
            listeners,
            driver,
            workers,
            limits,
            work,
            gate,
            sink,
            tls,
            control,
            wipe,
            clock,
            trusted,
        }
    }

    /// The proxies whose PROXY headers are believed, for every listener that
    /// requires one and has no list of its own.
    pub fn trusted_proxies(mut self, proxies: TrustedProxies) -> Self {
        self.trusted = Some(Arc::new(proxies));
        self
    }

    /// Adds a listener (at most 64).
    pub fn listener(mut self, spec: ListenerSpec) -> Self {
        self.listeners.push(spec);
        self
    }

    /// The driver (default `Auto`).
    pub fn driver(mut self, kind: DriverKind) -> Self {
        self.driver = kind;
        self
    }

    /// Worker threads (default 128 on the blocking driver; 1 to 4,096).
    pub fn workers(mut self, n: u16) -> Self {
        self.workers = Some(n);
        self
    }

    /// The server's limits; unset values take the driver's defaults.
    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Runs a sans-IO session per connection.
    pub fn sessions<F: SessionFactory>(self, factory: F) -> ServerBuilder<Sessions<F>, G, S, T> {
        self.map(|_, g, s, t| (Sessions { factory }, g, s, t))
    }

    /// Runs a blocking handler per connection (on the blocking driver).
    pub fn handler<H>(self, handler: H) -> ServerBuilder<BlockingHandler<H>, G, S, T>
    where
        H: Fn(&mut TcpConnection) -> Result<(), NetError> + Send + Sync + 'static,
    {
        self.map(|_, g, s, t| (BlockingHandler { handler }, g, s, t))
    }

    /// The TLS engine for listeners with `ListenerSpec::tls(true)` (feature `tls`).
    pub fn tls<T2: TlsAcceptor>(self, acceptor: T2) -> ServerBuilder<W, G, S, T2> {
        self.map(|w, g, s, _| (w, g, s, acceptor))
    }

    /// The connection gate (required; `AllowAll` for none).
    pub fn gate<G2: Gate>(self, gate: G2) -> ServerBuilder<W, G2, S, T> {
        self.map(|w, _, s, t| (w, gate, s, t))
    }

    /// The event sink (default `NoopSink`).
    pub fn events<S2: EventSink>(self, sink: S2) -> ServerBuilder<W, G, S2, T> {
        self.map(|w, g, _, t| (w, g, sink, t))
    }

    /// The control line (default: none).
    pub fn control<C: ControlLine>(mut self, line: Arc<C>) -> Self {
        self.control = Some(line);
        self
    }

    /// Zero the used part of every buffer when it returns to a pool (default on).
    pub fn wipe_buffers(mut self, on: bool) -> Self {
        self.wipe = on;
        self
    }

    /// The clock deadlines read (tests inject a `ManualClock`).
    pub fn clock<K: Clock>(mut self, clock: Arc<K>) -> Self {
        self.clock = Some(clock);
        self
    }
}

impl<W, G, S, T> ServerBuilder<W, G, S, T>
where
    W: Workload,
    G: Gate,
    S: EventSink,
    T: TlsAcceptor,
{
    /// Validates everything, binds the listeners, starts the workers, and returns
    /// the server with the door **closed**.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` (`field` names the method), bind errors, `Unsupported` for a
    /// driver this version does not have.
    pub fn build(self) -> Result<Server, NetError> {
        let driver = match self.driver.resolve() {
            DriverKind::Blocking => DriverKind::Blocking,
            other => {
                return Err(NetError::Unsupported {
                    feature: match other {
                        DriverKind::Uring => "the io_uring driver (after 1.0.0)",
                        _ => "the reactor driver (0.5.0)",
                    },
                    platform: std::env::consts::OS,
                });
            }
        };
        if self.listeners.is_empty() {
            return Err(invalid("listener", ConfigReason::Missing));
        }
        if self.listeners.len() > 64 {
            return Err(invalid("listener", ConfigReason::TooLarge { max: 64 }));
        }
        let workers = self.workers.unwrap_or(128);
        if workers == 0 {
            return Err(invalid("workers", ConfigReason::Zero));
        }
        if workers > 4096 {
            return Err(invalid("workers", ConfigReason::TooLarge { max: 4096 }));
        }
        let mut listeners = self.listeners;
        let has_tls = TypeId::of::<T>() != TypeId::of::<NoTls>();
        for spec in &mut listeners {
            if spec.unix.is_some() && !cfg!(all(unix, feature = "local")) {
                return Err(NetError::Unsupported {
                    feature: if cfg!(unix) {
                        "Unix domain sockets (the `local` feature)"
                    } else {
                        "Unix domain sockets on Windows (0.5.0)"
                    },
                    platform: std::env::consts::OS,
                });
            }
            if spec.tls {
                if !cfg!(feature = "tls") {
                    return Err(NetError::Unsupported {
                        feature: "TLS (the `tls` feature)",
                        platform: std::env::consts::OS,
                    });
                }
                if !has_tls {
                    return Err(invalid("tls", ConfigReason::Missing));
                }
            }
            if spec.proxy != ProxyMode::Off {
                if !cfg!(feature = "proxy") {
                    return Err(NetError::Unsupported {
                        feature: "PROXY protocol (the `proxy` feature)",
                        platform: std::env::consts::OS,
                    });
                }
                // On a Unix socket the file's permissions decide who may connect.
                if spec.unix.is_none() {
                    let trusted = spec.trusted.clone().or_else(|| self.trusted.clone());
                    match trusted {
                        Some(t) if !t.is_empty() => spec.trusted = Some(t),
                        // Required without anyone to trust would refuse every connection.
                        _ => return Err(invalid("trusted_proxies", ConfigReason::Missing)),
                    }
                }
            }
        }
        let mut names = Vec::new();
        for spec in &listeners {
            if let Some(n) = &spec.name {
                if n.len() > 64 {
                    return Err(invalid("name", ConfigReason::TooLarge { max: 64 }));
                }
                if names.contains(n) {
                    return Err(invalid("name", ConfigReason::Inconsistent));
                }
                names.push(n.clone());
            }
        }
        // On the blocking driver an unset global cap is one connection per worker.
        let limits = if self.limits.max_connections().is_none() {
            self.limits
                .to_builder()
                .max_connections(u32::from(workers))
                .build()?
        } else {
            self.limits.clone()
        };
        limits.validate(workers, crate::sys::descriptor_limit())?;
        for spec in &listeners {
            limits.overlay(&spec.limits).validate(workers, None)?;
        }
        let tls: Option<Arc<dyn ErasedAcceptor>> = if has_tls {
            Some(Arc::new(self.tls))
        } else {
            None
        };
        engine::start(engine::Config {
            tls,
            listeners,
            driver,
            workers,
            limits,
            work: self.work,
            gate: self.gate,
            sink: self.sink,
            control: self.control,
            wipe: self.wipe,
            clock: self.clock,
        })
    }
}

fn invalid(field: &'static str, reason: ConfigReason) -> NetError {
    NetError::InvalidConfig { field, reason }
}

/// A running server. Dropping it stops it (with a drain), so keep it and call
/// [`Server::wait_for_stop`] to run until a stop is requested.
#[must_use = "dropping a Server stops it; call wait_for_stop() to run until a stop is requested"]
pub struct Server {
    pub(crate) shared: Arc<Shared>,
    pub(crate) threads: Vec<JoinHandle<()>>,
    pub(crate) listeners: Vec<ListenerInfo>,
    pub(crate) stopped: bool,
}

impl Server {
    /// Starts accepting on every listener; a second call is a no-op.
    ///
    /// # Errors
    ///
    /// `ShuttingDown` while draining or after shutdown; `ForkedChild`.
    pub fn open_door(&self) -> Result<(), NetError> {
        self.shared.open_door()
    }

    /// Stops accepting within one loop iteration; listening sockets stay open. Idempotent.
    pub fn close_door(&self) {
        self.shared.close_door();
    }

    /// Whether the server is accepting.
    #[must_use]
    pub fn door(&self) -> DoorState {
        self.shared.door()
    }

    /// Closes the door, tells sessions to finish, closes idle connections at once,
    /// waits for the rest until `deadline`, then kills them with `DrainDeadline`.
    pub fn drain(&self, deadline: Instant) -> DrainReport {
        self.shared.drain(deadline)
    }

    /// Drains, then closes the listening sockets and joins every thread.
    pub fn shutdown(mut self, deadline: Instant) -> DrainReport {
        self.stop(deadline)
    }

    /// Blocks until a stop is requested (`ServerHandle::request_stop`, or the
    /// control line moves to `Draining` or `Stopping`), then shuts down.
    pub fn wait_for_stop(mut self) -> DrainReport {
        let deadline = self.shared.wait_for_stop_request();
        self.stop(deadline)
    }

    fn stop(&mut self, deadline: Instant) -> DrainReport {
        if self.stopped {
            return DrainReport {
                graceful: 0,
                killed: 0,
                took: Duration::ZERO,
            };
        }
        self.stopped = true;
        let report = self.shared.drain(deadline);
        self.shared.stop_threads();
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
        report
    }

    /// A cloneable handle for other threads.
    #[must_use]
    pub fn handle(&self) -> ServerHandle {
        ServerHandle {
            shared: self.shared.clone(),
        }
    }

    /// Counters summed over the workers.
    #[must_use]
    pub fn stats(&self) -> Stats {
        self.shared.stats()
    }

    /// Facts about each listener.
    #[must_use]
    pub fn listeners(&self) -> &[ListenerInfo] {
        &self.listeners
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let deadline = Instant::now() + self.shared.drain_timeout;
        self.stop(deadline);
    }
}

impl fmt::Debug for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
            .field("listeners", &self.listeners)
            .field("door", &self.door())
            .finish()
    }
}

/// A cloneable handle to a running server, safe to use from any thread.
///
/// ```no_run
/// let server = net_io::serve("127.0.0.1:7000", |conn| { conn.send_all(b"hi\n")?; Ok(()) })?;
/// let handle = server.handle();
/// std::thread::spawn(move || {
///     // ... wait for a signal from the application's signal library ...
///     handle.request_stop();
/// });
/// let report = server.wait_for_stop();
/// println!("drained: {} graceful, {} killed in {:?}", report.graceful, report.killed, report.took);
/// # Ok::<(), net_io::NetError>(())
/// ```
#[derive(Clone)]
pub struct ServerHandle {
    pub(crate) shared: Arc<Shared>,
}

impl ServerHandle {
    /// Aborts the connection `id`; `false` if it already closed or belongs to another server.
    pub fn kill(&self, id: ConnectionId, reason: KillReason) -> bool {
        self.shared.kill(id, reason)
    }

    /// Stops accepting.
    pub fn close_door(&self) {
        self.shared.close_door();
    }

    /// Makes `Server::wait_for_stop` return after the drain. Does not block.
    pub fn request_stop(&self) {
        self.shared.request_stop(None);
    }

    /// Interrupts every worker's and acceptor's wait so a control-line change is seen at once.
    pub fn wake_all(&self) {
        self.shared.wake_all();
    }

    /// The completion queue of `worker`.
    #[must_use]
    pub fn completer(&self, worker: WorkerId) -> Option<crate::completer::Completer> {
        self.shared.completer(worker)
    }

    /// Counters summed over the workers.
    #[must_use]
    pub fn stats(&self) -> Stats {
        self.shared.stats()
    }

    /// Whether the server is accepting.
    #[must_use]
    pub fn door(&self) -> DoorState {
        self.shared.door()
    }
}

impl fmt::Debug for ServerHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerHandle")
            .field("door", &self.door())
            .finish()
    }
}

impl Stats {
    pub(crate) fn from_parts(
        mut base: Stats,
        refused_by: [u64; RefusalCause::COUNT],
        closed_by: [u64; CloseReason::COUNT],
    ) -> Stats {
        base.refused_by = refused_by;
        base.closed_by = closed_by;
        base
    }
}
