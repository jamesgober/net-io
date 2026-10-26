# net-io - API Reference

> Reference for every public item in `net-io`, with signatures, behaviour, errors, costs, and examples.
> **Current release: `0.2.0` (design lock; no functional code yet).** This document is the contract for `0.3.0` to `1.0.0`. Each item carries the version that ships it; items marked with a later version than the current release are specified here and not yet in the crate. Names and signatures do not change after `0.2.0` without a decision-log entry in [`../dev/PLAN.md`](../dev/PLAN.md).

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

## Table of contents

- [Conventions](#conventions)
  - [Grades, tiers, versions](#grades-tiers-versions)
  - [Costs](#costs)
  - [Errors and panics](#errors-and-panics)
  - [Platforms](#platforms)
  - [Feature flags](#feature-flags)
- [Tier 1 at a glance](#tier-1-at-a-glance)
- [Crate root](#crate-root)
  - [`VERSION`](#version)
  - [`listen`](#listen)
  - [`connect`](#connect)
  - [`serve`](#serve)
  - [`serve_sessions`](#serve_sessions)
  - [`listen_local`, `connect_local`](#listen_local-connect_local)
- [Errors](#errors)
  - [`NetError`](#neterror)
  - [`ErrorClass`](#errorclass)
  - [`CloseReason`](#closereason)
  - [`RefusalCause`, `LimitKind`, `TimeoutKind`, `KillReason`, `Direction`, `OsErrorClass`](#refusalcause-limitkind-timeoutkind-killreason-direction-oserrorclass)
  - [`ConfigReason`](#configreason)
- [Addresses](#addresses)
  - [`normalize`, `normalize_socket`](#normalize-normalize_socket)
  - [`Cidr`](#cidr)
  - [`PrefixKey`, `PrefixPolicy`](#prefixkey-prefixpolicy)
  - [`TrustedProxies`](#trustedproxies)
  - [`AddrError`](#addrerror)
- [Identity and connection facts](#identity-and-connection-facts)
  - [`ConnectionId`, `ListenerId`, `WorkerId`](#connectionid-listenerid-workerid)
  - [`Lane`, `GateTag`](#lane-gatetag)
  - [`ConnectionInfo`](#connectioninfo)
  - [`Transport`, `Origin`, `Endpoint`](#transport-origin-endpoint)
  - [`PeerCredentials`](#peercredentials)
- [Limits](#limits)
  - [`Limits`](#limits-1)
  - [`LimitsBuilder`](#limitsbuilder)
  - [Defaults and reasons](#defaults-and-reasons)
  - [`MinRate`, `Pressure`, `SizeClass`](#minrate-pressure-sizeclass)
- [TCP](#tcp)
  - [`TcpListener`](#tcplistener)
  - [`TcpConnection`](#tcpconnection)
  - [`ConnectOptions`](#connectoptions)
- [Socket options](#socket-options)
  - [`ListenOptions`](#listenoptions)
  - [`TcpOptions`, `Keepalive`, `Linger`](#tcpoptions-keepalive-linger)
  - [`SocketOptions`](#socketoptions)
  - [Option support by platform](#option-support-by-platform)
- [Sessions](#sessions)
  - [`Session`](#session)
  - [`SessionFactory`](#sessionfactory)
  - [`Step`, `Phase`](#step-phase)
  - [`SessionContext`](#sessioncontext)
  - [`Input`](#input)
  - [`Output`](#output)
- [Server](#server)
  - [`ServerBuilder`](#serverbuilder)
  - [`ListenerSpec`](#listenerspec)
  - [`Server`](#server-1)
  - [`ServerHandle`](#serverhandle)
  - [`AdoptSpec`, `DrainReport`, `Stats`, `ListenerInfo`, `DoorState`](#adoptspec-drainreport-stats-listenerinfo-doorstate)
- [Gate seam](#gate-seam)
  - [`Gate`](#gate)
  - [`AdmitStage`, `Admitted`, `Refusal`](#admitstage-admitted-refusal)
  - [`WriteCheck`, `Denial`](#writecheck-denial)
  - [`AllowAll`](#allowall)
  - [`KillHandle`](#killhandle)
- [Control line](#control-line)
- [Completer](#completer)
- [Events](#events)
- [Buffers](#buffers)
- [Time](#time)
- [Drivers](#drivers)
- [UDP](#udp)
- [Local sockets](#local-sockets)
  - [Unix domain sockets](#unix-domain-sockets)
  - [Windows named pipes](#windows-named-pipes)
  - [`LocalListener`, `LocalConnection`](#locallistener-localconnection)
- [PROXY protocol](#proxy-protocol)
- [TLS seam](#tls-seam)
- [Inherited listeners](#inherited-listeners)
- [Listener hand-off](#listener-hand-off)
- [Thread safety and sizes](#thread-safety-and-sizes)
- [Recipes](#recipes)
- [Consumer checklists](#consumer-checklists)
- [Names changed at the design lock](#names-changed-at-the-design-lock)

---

## Conventions

### Grades, tiers, versions

Every item carries three marks:

| Mark | Values |
|---|---|
| **Grade** | **P0** required (the job cannot be done without it), **P1** expected (what users of the best libraries of this kind expect), **P2** high value (enterprise, high traffic, security), **P3** nice to have (after 1.0 is acceptable) |
| **Tier** | **1**: free functions and one-line constructors for about 80% of uses, no builder and no type parameter to name. **2**: builders and configuration for the next 15%. **3**: the full surface for the last 5% and for other libraries |
| **Version** | the release that ships the item. Everything graded P0, P1, or P2 ships by `1.0.0`; P3 items are listed so the design leaves room for them |

### Costs

Every cost is a target. Numbers marked **[est.]** are estimates that a benchmark replaces at `0.6.0`; `docs/PERFORMANCE.md` (from `0.6.0`) holds the measured numbers with method and hardware. "System calls" counts user-kernel round trips, which net-io treats as a hot-path cost like allocations.

### Errors and panics

- Every fallible function returns `Result<_, NetError>` unless the item says otherwise.
- Every error enum and every extensible struct is `#[non_exhaustive]`. Match with a wildcard arm.
- Every error type (`NetError`, `AddrError`, `ProxyError`, `TlsError`, `InheritError`, `HandoffError`, `PostError`, `SwapError`, `OutputFull`) implements `Display` (what happened and what to do) and `std::error::Error`, so `?` works into `Box<dyn Error>`; `NetError` also converts from `io::Error` and `AddrError`.
- Library code never panics. A `Session`, `Gate`, or `EventSink` implementation that panics is caught at the boundary in `panic = "unwind"` builds: a gate panic counts as a refusal or denial (fail closed) and a session panic closes that connection with `CloseReason::SessionPanicked`. Under `panic = "abort"` the process exits; restarting it is the supervisor's job.
- Every public type is `Send` and `Sync` unless its section says otherwise; this is checked by `const` assertions in the crate.

### Platforms

| Platform | Minimum for the full feature set | Older systems |
|---|---|---|
| Linux | 4.18 (features above it are detected at run time: `EPOLLEXCLUSIVE` 4.5, `SO_INCOMING_CPU` set 4.4, `TCP_FASTOPEN_CONNECT` 4.11) | the missing feature returns `NetError::Unsupported` |
| macOS | 11 | `Unsupported` |
| Windows | 10 1809 / Server 2019 (AF_UNIX from 1803, `TCP_KEEPIDLE` and `TCP_KEEPINTVL` from 1709, `TCP_KEEPCNT` from 1703) | `Unsupported`; keepalive falls back to `SIO_KEEPALIVE_VALS` |
| FreeBSD | 13 (in CI from `0.5.0`) | `Unsupported` |

Targets with hand-written OS declarations: `x86_64` and `aarch64` on `linux-gnu`, `linux-musl`, `apple-darwin`, `unknown-freebsd`, `pc-windows-msvc`, `pc-windows-gnu`. On any other target the crate builds the blocking driver over `std` alone and returns `Unsupported` for options and features `std` lacks.

Items that exist on one platform family only carry `#[cfg(unix)]` or `#[cfg(windows)]` in their signature. Each such item has a documented counterpart or a documented reason why there is none (see `docs/PLATFORM-NOTES.md`, from `0.3.0`).

### Feature flags

| Feature | Default | Contents | Version |
|---|---|---|---|
| (none) | always | TCP, the blocking driver, limits, the gate seam, sessions, server, drain, events, control line, completer, addresses | `0.3.0` |
| `proxy` | on | PROXY protocol parser and server integration | `0.4.0` |
| `udp` | on | UDP socket, amplification guard, source budgets | `0.4.0` |
| `local` | on | Unix domain sockets, Windows named pipes, descriptor passing, listener hand-off | `0.4.0` |
| `tls` | on | the TLS seam traits and server integration (no TLS code) | `0.4.0` |
| `reactor` | on | epoll, kqueue, and IOCP drivers | `0.5.0` |
| `uring` | off | io_uring driver (Linux), falls back to epoll automatically | after `1.0.0` |
| `executor` | off | adapter so an executor's worker threads park inside the reactor | `0.8.0` |

Features are additive. `--no-default-features` builds TCP, the blocking driver, limits, hooks, and drain, and passes CI on its own. The crate has no runtime dependencies in any feature combination.

Features gate machinery, not vocabulary: the plain data types that always-built items refer to exist in every build (`ProxyMode`, `ProxyFacts`, `ProxyError`, `TlsInfo`, `TlsError`, `TlsAcceptor`, `NoTls`, `InheritError`, `HandoffError`, `ListenerHandle`, `Endpoint`), so `ConnectionInfo`, `ListenerInfo`, and `NetError` have the same shape in every build. What a feature adds is the code that fills them: the PROXY parser and its server integration (`proxy`), UDP sockets (`udp`), local sockets, descriptor passing, and hand-off (`local`), the TLS server integration (`tls`), the reactor (`reactor`). Without a feature, a builder call that needs it (`ListenerSpec::proxy(Required)`, `ListenerSpec::tls(true)`) fails `build` with `Unsupported { feature }`.

---

## Tier 1 at a glance

```rust,no_run
use net_io::NetError;

fn main() -> Result<(), NetError> {
    // An echo server: one handler call per connection on a bounded worker pool,
    // with every default limit (idle, read, write, minimum rate, caps) applied.
    let server = net_io::serve("127.0.0.1:7000", |conn| {
        let mut buf = [0u8; 4096];
        loop {
            let n = conn.recv(&mut buf)?;
            if n == 0 {
                return Ok(()); // the peer closed its side
            }
            conn.send_all(&buf[..n])?;
        }
    })?;

    // A client.
    let mut conn = net_io::connect("127.0.0.1:7000")?;
    conn.send_all(b"ping")?;
    let mut reply = [0u8; 4];
    conn.recv_exact(&mut reply)?;
    assert_eq!(&reply, b"ping");

    // Stop: close the door, drain open connections, join the workers.
    server.handle().request_stop();
    let report = server.wait_for_stop();
    println!("{} closed gracefully, {} killed", report.graceful, report.killed);
    Ok(())
}
```

| Want | Call |
|---|---|
| a TCP listener with safe defaults | [`net_io::listen(addr)`](#listen) |
| a TCP client with a 10 s connect timeout | [`net_io::connect(addr)`](#connect) |
| a server that runs a blocking handler per connection | [`net_io::serve(addr, handler)`](#serve) |
| a server that drives sans-IO sessions (protocol engines) | [`net_io::serve_sessions(addr, factory)`](#serve_sessions) |
| local IPC (Unix socket or Windows named pipe) | [`net_io::listen_local(name)`](#listen_local-connect_local), [`net_io::connect_local(name)`](#listen_local-connect_local) |
| the real client address behind a trusted proxy | [`ConnectionInfo::client_addr()`](#connectioninfo) |
| a CIDR test | [`Cidr::parse("10.0.0.0/8")?.contains(ip)`](#cidr) |

Everything else (several listeners, the gate, TLS, PROXY, events, hand-off) goes through [`ServerBuilder`](#serverbuilder) (Tier 2).

---

## Crate root

### `VERSION`

```rust
pub const VERSION: &str;
```

The crate version, populated by Cargo at build time. P0, Tier 1, `0.1.0`.

```rust
println!("net-io {}", net_io::VERSION);
```

### `listen`

```rust
pub fn listen<A: ToSocketAddrs>(addr: A) -> Result<TcpListener, NetError>;
```

Binds a TCP listener with safe defaults: backlog 1,024 (capped by the OS, the effective value is in `TcpListener::info()`); `SO_REUSEADDR` on Unix so a restart does not wait for `TIME_WAIT`; `SO_EXCLUSIVEADDRUSE` on Windows so no other process can bind the same port; `IPV6_V6ONLY` on for IPv6 addresses; close-on-exec. `addr` is resolved with `std::net::ToSocketAddrs` and the first address that binds wins.

| Grade | Tier | Version | Cost |
|---|---|---|---|
| P0 | 1 | `0.3.0` | one-time: 4 to 6 system calls |

Errors: `AddrInUse { addr }` (another process listens there; stop it, pick another port, or use [listener hand-off](#listener-hand-off) for restarts), `PermissionDenied` (a port below 1024 without privileges: bind before dropping privileges, or use a high port behind a reverse proxy), `AddrNotAvailable` (the address is not on this host, or IPv6 is disabled), `NoAddresses` (resolution returned nothing), `Bind { addr, source }` (any other bind failure, OS error attached).

```rust
let listener = net_io::listen("127.0.0.1:0")?;
let addr = listener.local_addr()?;
println!("listening on {addr}, backlog {:?}", listener.info().backlog);
# Ok::<(), net_io::NetError>(())
```

```rust,no_run
// Accept connections one at a time (no server, no worker pool).
let listener = net_io::listen("0.0.0.0:7000")?;
loop {
    let (mut conn, info) = listener.accept()?;
    println!("connection {} from {:?}", info.id, info.client_addr());
    conn.send_all(b"hello\n")?;
    conn.close()?;
}
# Ok::<(), net_io::NetError>(())
```

### `connect`

```rust
pub fn connect<A: ToSocketAddrs>(addr: A) -> Result<TcpConnection, NetError>;
```

Connects with a total timeout of 10 s across all resolved addresses (tried in order), `TCP_NODELAY` on, close-on-exec, and default limits on the returned connection (read and write deadlines 30 s). For other options use [`TcpConnection::connect_with`](#tcpconnection).

| Grade | Tier | Version | Cost |
|---|---|---|---|
| P0 | 1 | `0.3.0` | one round trip to the peer plus 3 to 4 system calls |

Errors: `ConnectTimeout { addr, after }`, `ConnectionRefused { addr }`, `HostUnreachable { addr }`, `NetworkUnreachable { addr }`, `NoAddresses`. When several addresses were tried, the error is the last one.

```rust,no_run
let mut conn = net_io::connect("example.com:80")?;
conn.send_all(b"HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")?;
let mut head = [0u8; 512];
let n = conn.recv(&mut head)?;
println!("{}", String::from_utf8_lossy(&head[..n]));
# Ok::<(), net_io::NetError>(())
```

### `serve`

```rust
pub fn serve<A, F>(addr: A, handler: F) -> Result<Server, NetError>
where
    A: ToSocketAddrs,
    F: Fn(&mut TcpConnection) -> Result<(), NetError> + Send + Sync + 'static;
```

Builds and starts a server on the blocking driver with one TCP listener, default limits ([blocking defaults](#defaults-and-reasons)), [`AllowAll`](#allowall) as the gate, and no event sink, then opens the door. The handler runs once per accepted connection on a pool worker; when it returns `Ok(())` the connection closes gracefully, when it returns `Err` it closes abortively and the error is reported as `CloseReason::SessionError`. Every read and write inside the handler honours the connection's deadlines and the minimum transfer rate, so a slow or silent peer cannot hold a worker longer than the limits allow.

The returned `Server` must be kept: dropping it stops the server (with a drain), so `net_io::serve(addr, handler)?;` on its own line starts and stops at once; the compiler warns about it (`#[must_use]`). Call `wait_for_stop()` to run until a stop is requested.

`serve` uses `AllowAll` on purpose so the simplest program runs; a server facing the internet should set a [`Gate`](#gate) through [`ServerBuilder`](#serverbuilder).

| Grade | Tier | Version | Cost |
|---|---|---|---|
| P0 | 1 | `0.3.0` | one-time start; per connection see `docs/PERFORMANCE.md` (from `0.6.0`) |

Errors: as [`listen`](#listen), plus `InvalidConfig` when the default worker count exceeds the process's descriptor limit (raise the limit or use `ServerBuilder::workers`).

```rust,no_run
use std::io::{BufRead, BufReader, Write};

// Handlers can use std::io traits: TcpConnection implements Read and Write.
let server = net_io::serve("127.0.0.1:7001", |conn| {
    let mut line = String::new();
    BufReader::new(&mut *conn).read_line(&mut line)?;
    conn.write_all(line.to_uppercase().as_bytes())?;
    Ok(())
})?;
server.wait_for_stop();
# Ok::<(), net_io::NetError>(())
```

### `serve_sessions`

```rust
pub fn serve_sessions<A, F>(addr: A, factory: F) -> Result<Server, NetError>
where
    A: ToSocketAddrs,
    F: SessionFactory;
```

Builds and starts a server that drives sans-IO [`Session`](#session)s: the protocol engine reacts to bytes and returns what to do next; net-io does all reads, writes, timers, and limits. The driver is the blocking pool in `0.3.0` and `0.4.0`, and from `0.5.0` the reactor where it is built and available. Gate `AllowAll`, default limits, door open on return.

Any `Fn(&ConnectionInfo) -> S + Send + Sync + 'static` where `S: Session` is a `SessionFactory`, so a closure works.

| Grade | Tier | Version | Cost |
|---|---|---|---|
| P0 | 1 | `0.3.0` | per connection see `docs/PERFORMANCE.md` (from `0.6.0`) |

```rust,no_run
use net_io::{Input, Session, SessionContext, Step};

struct Echo;

impl Session for Echo {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        // Copy as much as the output budget takes; what is left stays in `input`,
        // and net-io calls on_data again after the flush because the input changed.
        let taken = cx.output().push_partial(input.bytes());
        input.consume(taken);
        Step::Write
    }
}

let server = net_io::serve_sessions("127.0.0.1:7002", |_info: &net_io::ConnectionInfo| Echo)?;
server.wait_for_stop();
# Ok::<(), net_io::NetError>(())
```

### `listen_local`, `connect_local`

```rust
pub fn listen_local(name: &str) -> Result<LocalListener, NetError>;
pub fn connect_local(name: &str) -> Result<LocalConnection, NetError>;
```

Local IPC with one name on every OS: on Unix, a Unix domain socket at the path `name` with mode `0600` (owner only; name a group in [`LocalOptions`](#unix-domain-sockets) for `0660`); on Windows, the named pipe `\\.\pipe\<name>` with an owner-only security descriptor, remote clients rejected, and squatting detected. `connect_local` waits up to 10 s for a busy pipe.

| Grade | Tier | Version |
|---|---|---|
| P1 | 1 | `0.4.0` (Unix), `0.5.0` (Windows) |

Errors: `Bind`, `PathTooLong { max }`, `StaleSocketInUse { path }` (a live listener owns the path), `PermissionDenied`, `PipeNameInUse { name }` (another process created the pipe first: possible squatting; pick another name or find the other process), `NotFound`, `ConnectionRefused`, `ConnectTimeout`, `Unsupported`.

```rust,no_run
// Server side.
let listener = net_io::listen_local("/run/myapp/control.sock")?;
let (mut conn, info) = listener.accept()?;
println!("peer process {:?}", info.peer_credentials.and_then(|c| c.pid));
conn.send_all(b"ok\n")?;
# Ok::<(), net_io::NetError>(())
```

```rust,no_run
// Client side; on Windows the same call opens \\.\pipe\myapp-control.
let mut conn = net_io::connect_local(if cfg!(windows) { "myapp-control" } else { "/run/myapp/control.sock" })?;
conn.send_all(b"status\n")?;
# Ok::<(), net_io::NetError>(())
```

---

## Errors

### `NetError`

```rust
#[non_exhaustive]
#[derive(Debug)]
pub enum NetError {
    Bind { addr: SocketAddr, source: io::Error },
    AddrInUse { addr: SocketAddr },
    AddrNotAvailable { addr: SocketAddr },
    PermissionDenied { what: &'static str },
    NoAddresses,
    ConnectTimeout { addr: SocketAddr, after: Duration },
    ConnectionRefused { addr: SocketAddr },
    HostUnreachable { addr: SocketAddr },
    NetworkUnreachable { addr: SocketAddr },
    TimedOut { kind: TimeoutKind },
    ConnectionReset,
    BrokenPipe,
    Closed,
    Killed { reason: KillReason },
    EgressDenied { code: u16 },
    Refused { cause: RefusalCause },
    Limit { which: LimitKind },
    SlowPeer { direction: Direction },
    InvalidConfig { field: &'static str, reason: ConfigReason },
    Unsupported { feature: &'static str, platform: &'static str },
    PathTooLong { max: usize },
    StaleSocketInUse { path: PathBuf },
    PipeNameInUse { name: String },
    NotFound,
    FileTruncated { sent: u64 },
    Address(AddrError),
    Proxy(ProxyError),
    Tls(TlsError),
    Inherit(InheritError),
    Handoff(HandoffError),
    DriverSetup { driver: DriverKind, source: io::Error },
    DoorClosed,
    ShuttingDown,
    ForkedChild,
    Os { op: &'static str, source: io::Error },
}

impl NetError {
    pub fn class(&self) -> ErrorClass;
    pub fn is_retryable(&self) -> bool;
    pub fn os_error_code(&self) -> Option<i32>;
}
impl fmt::Display for NetError;
impl std::error::Error for NetError;      // source() returns the io::Error or the nested error
impl From<NetError> for io::Error;        // kind mapped; the NetError is kept as the source
impl From<io::Error> for NetError;        // Os { op: "io", source }, or the matching variant for timeouts, resets, broken pipes
impl From<AddrError> for NetError;        // Address(..)
```

The one error type of the crate. P0, Tier 1, `0.3.0` (variants for later features arrive with them).

| Variant | When | What to do |
|---|---|---|
| `Bind` | bind failed for a reason without its own variant | read the OS error in `source` |
| `AddrInUse` | another socket holds the address | stop the other process, choose another port, or use listener hand-off on restart |
| `AddrNotAvailable` | the address is not local, or IPv6 is disabled | bind an address this host owns |
| `PermissionDenied` | privileged port, socket file permissions, pipe security descriptor | bind before dropping privileges; check ownership |
| `NoAddresses` | name resolution gave no address | check the host name |
| `ConnectTimeout` | no answer within the connect deadline | check reachability; raise `ConnectOptions::timeout` |
| `ConnectionRefused` | nothing listens at the address | start the server or fix the port |
| `HostUnreachable`, `NetworkUnreachable` | routing failure | check the network |
| `TimedOut` | one of net-io's deadlines passed (`kind` says which) | the peer is too slow; raise the limit if the workload needs it |
| `ConnectionReset` | the peer sent RST | none; the connection is gone |
| `BrokenPipe` | write after the peer closed | none; the connection is gone |
| `Closed` | the connection was already closed by this side or the peer | stop using it |
| `Killed` | a `KillHandle` or `ServerHandle::kill` closed it | none; `reason` is the caller's code |
| `EgressDenied` | the gate denied a write | none; the connection was reset |
| `Refused` | `Server::adopt` or a client-side gate refused the connection | `cause` says why |
| `Limit` | a configured bound was hit (`which` says which) | raise the limit or shed load |
| `SlowPeer` | the minimum transfer rate was not met | none; this is the slowloris and slow-read defence |
| `InvalidConfig` | a builder or option value is out of range or inconsistent | `field` and `reason` name the value and the rule |
| `Unsupported` | the platform lacks the feature | `feature` and `platform` say which; see the platform table |
| `PathTooLong` | a Unix socket path exceeds the platform limit | use a shorter path (`max` bytes including the terminator) |
| `StaleSocketInUse` | a live listener owns the socket path, or the path is not a socket | stop that listener or choose another path |
| `PipeNameInUse` | another process created the named pipe first | possible squatting: choose another name or find the process |
| `NotFound` | no local endpoint with that name | start the server first |
| `FileTruncated` | a file shrank while `send_file` sent it (`sent` bytes left) | the connection was reset; send files that do not change while in flight |
| `Address` | an address, CIDR, or trusted-proxy list did not parse | see [`AddrError`](#addrerror) |
| `Proxy` | PROXY header invalid | see [`ProxyError`](#proxy-protocol) |
| `Tls` | the TLS engine failed | see [`TlsError`](#tls-seam) |
| `Inherit` | inherited descriptors failed verification | see [`InheritError`](#inherited-listeners) |
| `Handoff` | listener hand-off failed (nothing was adopted) | see [`HandoffError`](#listener-hand-off) |
| `DriverSetup` | the selected driver could not start | use `DriverKind::Auto` or the blocking driver |
| `DoorClosed` | an operation needs the door open | call `open_door` first |
| `ShuttingDown` | the server is draining or stopped | none |
| `ForkedChild` | a `Server` was used in a child process after `fork` | create servers after forking, never before |
| `Os` | any other OS failure | `op` names the call; `source` has the OS error |

`class()` sorts errors for policy: `Config` (fix the configuration), `Resource` (descriptors, memory, buffers: retry later), `Peer` (the other side misbehaved or left), `Timeout`, `Policy` (gate, limits, refusal), `Platform` (unsupported), `Bug` (a contract was broken by the caller). `is_retryable()` is true for `Resource` and for `ConnectTimeout` and `TimedOut { kind: Connect }`. `os_error_code()` returns the raw OS error number when one exists.

`From<io::Error> for NetError` lets handlers use `?` on `std::io` calls (`ErrorKind::TimedOut` becomes `TimedOut { kind: Read }`, `ConnectionReset`, `BrokenPipe`, and the rest `Os { op: "io", source }`). `From<NetError> for io::Error` maps `TimedOut` and `ConnectTimeout` to `ErrorKind::TimedOut`, `ConnectionReset` to `ConnectionReset`, `BrokenPipe` to `BrokenPipe`, `ConnectionRefused` to `ConnectionRefused`, `AddrInUse` to `AddrInUse`, `AddrNotAvailable` to `AddrNotAvailable`, `PermissionDenied` to `PermissionDenied`, `NotFound` to `NotFound`, `Unsupported` to `Unsupported`, `InvalidConfig` to `InvalidInput`, and everything else to `Other`, always with the `NetError` as the inner error.

```rust,no_run
use net_io::{ErrorClass, NetError};

match net_io::connect("127.0.0.1:9") {
    Ok(_) => {}
    Err(NetError::ConnectionRefused { addr }) => eprintln!("nothing listens on {addr}"),
    Err(e) if e.class() == ErrorClass::Timeout => eprintln!("slow network: {e}"),
    Err(e) => return Err(e),
}
# Ok::<(), NetError>(())
```

No secret ever appears in an error: TLS errors carry codes only, PROXY errors carry positions, and peer bytes are never copied into a message.

### `ErrorClass`

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorClass { Config, Resource, Peer, Timeout, Policy, Platform, Bug }
```

P1, Tier 2, `0.3.0`. See [`NetError::class`](#neterror).

### `CloseReason`

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CloseReason {
    PeerClosed, PeerReset,
    Idle, HandshakeTimeout, ReadTimeout, WriteTimeout, ExchangeDeadline, ParkDeadline,
    SlowPeer { direction: Direction },
    Refused(RefusalCause),
    ProxyUntrusted, ProxyMissing, ProxyInvalid,
    TlsFailed, HelloRefused,
    Killed(KillReason), EgressDenied(u16),
    Drained, DrainDeadline, Shed, Shutdown,
    SessionClosed, SessionError, SessionPanicked,
    Limit(LimitKind), Io(OsErrorClass),
}
impl CloseReason {
    pub fn as_str(&self) -> &'static str;   // stable snake_case name for logs: "slow_peer_in", "egress_denied"
    pub fn is_abortive(&self) -> bool;      // closed with RST
}
```

Every connection ends with exactly one `CloseReason`, delivered once to `Session::on_close`, `Gate::closed`, and the `Closed` event. P0, Tier 1, `0.3.0`. Eight bytes, `Copy`.

Close style per reason (decision D-032): **graceful** (flush within the write deadline, FIN, then a bounded linger that reads and discards up to 64 KiB for up to 2 s so unread input does not turn into an RST that destroys the last response) for `PeerClosed`, `Idle`, `Drained`, `SessionClosed`; **abortive** (`SO_LINGER` 0, RST, kernel resources freed at once) for everything else: kills, egress denials, refusals, timeouts, slow peers, limits, the drain deadline, PROXY and TLS failures, session errors and panics.

| Reason | Produced by |
|---|---|
| `PeerClosed` | the peer sent FIN and the session closed (default `on_peer_closed`) |
| `PeerReset` | the peer sent RST |
| `Idle` | no exchange started within the idle deadline |
| `HandshakeTimeout` | PROXY header and TLS handshake not done within the handshake deadline |
| `ReadTimeout`, `WriteTimeout` | no progress within the read or write deadline |
| `ExchangeDeadline` | the session's total deadline for the current exchange passed |
| `ParkDeadline` | a parked connection was not woken in time |
| `SlowPeer { direction }` | the minimum transfer rate was not met in that direction |
| `Refused(cause)` | refused at accept or by the session factory |
| `ProxyUntrusted` | a PROXY-required listener got a connection from a peer outside `TrustedProxies` |
| `ProxyMissing` | a trusted peer sent no PROXY header |
| `ProxyInvalid` | the header was malformed or over its size limit |
| `TlsFailed` | the TLS engine reported an error |
| `HelloRefused` | the TLS engine's hello hook refused the ClientHello |
| `Killed(reason)` | `KillHandle::kill` or `ServerHandle::kill` |
| `EgressDenied(code)` | `Gate::check` denied a write |
| `Drained` | the session finished after drain started |
| `DrainDeadline` | the session had not finished when the drain deadline passed |
| `Shed` | the control line shed this lane |
| `Shutdown` | the control line said `Stopping`, or `shutdown` ran |
| `SessionClosed` | the session returned `Step::Close` |
| `SessionError` | the session returned `Step::Abort` outside `on_timeout`, or a `serve` handler returned `Err` |
| `SessionPanicked` | the session panicked (unwind builds) |
| `Limit(which)` | a per-connection bound was hit (for example a full read buffer that the session never consumes) |
| `Io(class)` | the OS reported an error not covered above |

### `RefusalCause`, `LimitKind`, `TimeoutKind`, `KillReason`, `Direction`, `OsErrorClass`

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RefusalCause { GlobalCap, ListenerCap, SourceCap, LaneReserve, Gate(u16), Session, Busy, DoorClosed, Shed, Lockdown, Credentials }

#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LimitKind {
    Connections, PerListener, PerSource, BufferBudget, OutputBudget, CompletionQueue,
    ProxyHeader, AcceptBatch, ReadBuffer, Amplification, SourceBudget, Descriptors,
}

#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TimeoutKind { Handshake, Idle, Read, Write, Exchange, Park, Connect, Drain }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KillReason(pub u16);                 // codes belong to the caller

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction { In, Out }

#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OsErrorClass { Reset, Aborted, TimedOut, Refused, Unreachable, FileTruncated, Other(i32) }
```

P0, Tier 2, `0.3.0`. `RefusalCause::Gate(code)` carries the gate's refusal code; `Session` means the session factory refused; `Busy` means every worker of the blocking driver had a connection or one waiting for it (D-067). `OsErrorClass` carries the OS error number, never message text, so it is `Copy` and fits in events.

### `ConfigReason`

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigReason {
    Zero,                                   // zero where zero is meaningless
    TooLarge { max: u64 },
    TooSmall { min: u64 },
    AboveGlobal,                            // a per-listener cap above the global cap
    BelowTick,                              // a deadline shorter than one timer tick
    WindowBelowCheck,                       // min_rate.window < min_rate.check
    BudgetBelowWorkers { need: u64 },       // buffer budget below workers x largest class x 2
    DescriptorLimit { have: u64, need: u64 },
    Missing,                                // a required part is not set (gate, trusted proxies, session factory)
    NotListening,                           // an adopted socket is not a listening socket
    Inconsistent,                           // values that contradict each other (for example pressure.high <= pressure.low)
    Malformed,                              // a byte or character the value cannot hold (a NUL in a socket path)
}
```

P0, Tier 2, `0.3.0`. Carried by `NetError::InvalidConfig { field, reason }`; `field` is the builder method's name.

---

## Addresses

Module `addr`, re-exported at the crate root. Everything here works without the OS and is written against `core` only (checked in CI), so it can move to a `no_std` crate later without changes.

### `normalize`, `normalize_socket`

```rust
pub fn normalize(ip: IpAddr) -> IpAddr;
pub fn normalize_socket(addr: SocketAddr) -> SocketAddr;
```

An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) becomes the IPv4 address; nothing else is rewritten. Scope ids of link-local IPv6 addresses are kept; NAT64 (`64:ff9b::/96`) is not translated. net-io normalizes every peer at accept, so caps, bans, and logs agree on one form. P0, Tier 1, `0.3.0`, under 2 ns [est.].

```rust
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
let mapped = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 7).to_ipv6_mapped());
assert_eq!(net_io::normalize(mapped), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)));
assert_eq!(net_io::normalize(IpAddr::V6(Ipv6Addr::LOCALHOST)), IpAddr::V6(Ipv6Addr::LOCALHOST));
```

### `Cidr`

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Cidr { /* normalized network address + prefix length */ }

impl Cidr {
    pub fn new(ip: IpAddr, prefix: u8) -> Result<Cidr, AddrError>;         // host bits must be zero
    pub fn new_masked(ip: IpAddr, prefix: u8) -> Result<Cidr, AddrError>;  // clears host bits
    pub fn parse(text: &str) -> Result<Cidr, AddrError>;
    pub fn contains(&self, ip: IpAddr) -> bool;                             // normalizes ip first
    pub fn network(&self) -> IpAddr;
    pub fn prefix_len(&self) -> u8;
    pub fn is_ipv4(&self) -> bool;
}
impl FromStr for Cidr { type Err = AddrError; }
impl fmt::Display for Cidr;
```

A network block. `parse` accepts `"10.0.0.0/8"`, `"2001:db8::/32"`, and a bare address (`"192.0.2.7"` is `/32`, `"::1"` is `/128`). It accepts canonical text only: no leading zeros in IPv4 octets (no octal ambiguity), no zone ids, no whitespace. An IPv4-mapped IPv6 block is normalized to the IPv4 block. P0, Tier 1, `0.3.0`; `contains` under 3 ns [est.].

Errors: `Syntax { at }` (byte offset), `PrefixTooLong { max }` (above 32 or 128), `HostBitsSet` (use `new_masked` or fix the text), `Empty`.

```rust
use net_io::Cidr;
let office: Cidr = "203.0.113.0/24".parse()?;
assert!(office.contains("203.0.113.9".parse().unwrap()));
assert!(!office.contains("198.51.100.1".parse().unwrap()));
assert_eq!(office.to_string(), "203.0.113.0/24");
assert!(Cidr::parse("10.0.0.1/8").is_err());                            // host bits set
assert_eq!(Cidr::new_masked("10.0.0.1".parse().unwrap(), 8)?.to_string(), "10.0.0.0/8");
# Ok::<(), net_io::AddrError>(())
```

### `PrefixKey`, `PrefixPolicy`

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PrefixKey { /* family tag, 16 bytes, prefix length: 18 bytes */ }
impl PrefixKey {
    pub fn of(ip: IpAddr, policy: PrefixPolicy) -> PrefixKey;
    pub fn exact(ip: IpAddr) -> PrefixKey;          // /32 or /128
    pub fn network(&self) -> IpAddr;
    pub fn prefix_len(&self) -> u8;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PrefixPolicy { /* v4 and v6 prefix lengths */ }
impl PrefixPolicy {
    pub const HOST: PrefixPolicy;      // /32 and /128
    pub const DEFAULT: PrefixPolicy;   // /32 and /64
    pub const fn new(v4: u8, v6: u8) -> Result<PrefixPolicy, AddrError>;
    pub const fn v4(&self) -> u8;
    pub const fn v6(&self) -> u8;
}
impl Default for PrefixPolicy;         // DEFAULT
```

A fixed-size, `Copy` key for "this address at this prefix length", usable as a hash key. IPv6 hosts usually own a whole /64, so the default policy groups IPv6 at /64 and IPv4 at /32; IPv4 /24 and IPv6 /56 and /48 are available for wider grouping. The scope id of an IPv6 address is ignored. P0, Tier 2, `0.3.0`; `of` under 3 ns [est.].

```rust
use net_io::{PrefixKey, PrefixPolicy};
let a = PrefixKey::of("2001:db8:1:2::10".parse().unwrap(), PrefixPolicy::DEFAULT);
let b = PrefixKey::of("2001:db8:1:2:ffff::1".parse().unwrap(), PrefixPolicy::DEFAULT);
assert_eq!(a, b);                                   // same /64
let wide = PrefixPolicy::new(24, 48)?;
assert_eq!(PrefixKey::of("192.0.2.200".parse().unwrap(), wide).to_string(), "192.0.2.0/24");
# Ok::<(), net_io::AddrError>(())
```

`PrefixKey` also implements `Display` (CIDR text).

### `TrustedProxies`

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedProxies { /* sorted, deduplicated, at most 1,024 Cidr */ }
impl TrustedProxies {
    pub const MAX: usize = 1024;
    pub fn new(blocks: &[Cidr]) -> Result<TrustedProxies, AddrError>;
    pub fn parse(text: &str) -> Result<TrustedProxies, AddrError>;  // comma or whitespace separated
    pub fn none() -> TrustedProxies;
    pub fn loopback() -> TrustedProxies;                             // 127.0.0.0/8 and ::1/128
    pub fn contains(&self, ip: IpAddr) -> bool;
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn iter(&self) -> impl Iterator<Item = Cidr> + '_;
}
```

The one list of proxies whose claims about the client address are believed: PROXY headers here, and `X-Forwarded-For` / `Forwarded` in the web layer, which should use the same value. Keep it minimal: a trusted proxy can claim any client address. P0, Tier 1, `0.3.0` (moved from `0.4.0`, D-081: serve-net's 0.3 takes one for `X-Forwarded-For`); `contains` under 20 ns for 16 blocks [est.], no allocation. The lookup is a binary search over IPv4 and IPv6 blocks kept separately.

Errors: as `Cidr::parse`, plus `TooMany { max: 1024 }`.

```rust
use net_io::TrustedProxies;
let proxies = TrustedProxies::parse("10.0.0.0/8, 192.168.1.10 ::1")?;
assert!(proxies.contains("10.4.5.6".parse().unwrap()));
assert!(!proxies.contains("8.8.8.8".parse().unwrap()));
# Ok::<(), net_io::AddrError>(())
```

### `AddrError`

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddrError { Syntax { at: usize }, PrefixTooLong { max: u8 }, HostBitsSet, TooMany { max: usize }, Empty }
```

P0, Tier 2, `0.3.0`. Implements `Display` and `std::error::Error`.

---

## Identity and connection facts

### `ConnectionId`, `ListenerId`, `WorkerId`

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionId(NonZeroU64);
impl ConnectionId { pub const fn get(self) -> u64; pub const fn new(id: u64) -> Option<ConnectionId>; }   // new: for tests and conversions; None for 0
impl fmt::Display for ConnectionId;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ListenerId(u16);
impl ListenerId { pub const fn get(self) -> u16; }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WorkerId(u16);
impl WorkerId { pub const fn get(self) -> u16; pub const fn first() -> WorkerId; pub const fn for_testing(index: u16) -> WorkerId; }   // first: worker 0; for_testing: tests of per-worker state
```

`ConnectionId` is issued for every accepted, adopted, dialed-and-registered, or inherited connection; it is never zero and never reused within a process. Workers take blocks of 1,024 ids from one process-wide counter, so ids are ordered within a worker, not globally; at one million connections per second the counter lasts about 584,000 years. The block also tells `ServerHandle::kill` which worker owns an id. P0, Tier 1, `0.3.0`. `ListenerId` and `WorkerId` (P0, Tier 2) count from 0 within one server; at most 65,535 of each.

### `Lane`, `GateTag`

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Lane(pub u8);
impl Lane { pub const MOST_IMPORTANT: Lane = Lane(0); }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct GateTag(pub u64);
```

An opaque importance class the gate assigns at admission: lower is more important. net-io uses it only to shed lanes at or above a floor under load (`ControlState::Shed`) and for per-lane connection reservations (`LimitsBuilder::lane_reserve`, `0.6.0`). What a lane means belongs to the application. P1, Tier 2, `0.3.0`.

`GateTag` is an opaque value the gate returns at admission (`Admitted::tag`) and net-io stores in `ConnectionInfo::gate`. It lets a protocol engine name the connection to the gate (for example to open a per-request ticket) without being generic over the gate's type. A session can also mark the current response with a tag (`Output::begin_tagged_response(tag)`), which the gate sees in `WriteCheck::response`; on HTTP/2, or behind a proxy that pools many clients on one connection, that is how a check judges the right request. net-io never interprets either value. `AllowAll` returns `GateTag(0)`. P1, Tier 2, `0.3.0` (decision D-051).

### `ConnectionInfo`

```rust
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct ConnectionInfo {
    pub id: ConnectionId,
    pub listener: Option<ListenerId>,
    pub worker: WorkerId,
    pub transport: Transport,
    pub origin: Origin,
    pub local: Endpoint,
    pub peer: Endpoint,                          // normalized
    pub real_peer: Option<SocketAddr>,           // from a trusted PROXY header, normalized
    pub proxy: Option<Arc<ProxyFacts>>,          // ALPN, authority, unique id, SSL flags (fixed arrays, pooled)
    pub peer_credentials: Option<PeerCredentials>,  // local sockets
    pub tls: Option<Arc<TlsInfo>>,               // after the handshake (pooled)
    pub lane: Lane,
    pub gate: GateTag,                           // set by the gate at admission
    pub accepted_at: Instant,
}
impl ConnectionInfo {
    pub fn client_addr(&self) -> Option<SocketAddr>;                 // real_peer if set, else the IP peer
    pub fn client_key(&self, policy: PrefixPolicy) -> Option<PrefixKey>;
    pub fn socket_peer(&self) -> Option<SocketAddr>;                  // the socket peer, ignoring PROXY
    pub fn for_testing(peer: SocketAddr) -> ConnectionInfo;          // a fresh id, TCP, accepted now; fields are public to adjust
}
```

What net-io knows about one connection, built at accept and completed as the handshake reveals more. Building one never allocates after warm-up: Unix paths and pipe names are shared with the listener that owns them (`Arc`), and PROXY and TLS facts (fixed arrays inside) come from per-worker pools of `Arc`s that are reused when a connection closes, so the struct itself stays near 200 bytes and an idle connection fits the 512-byte target (decision D-061). `client_addr` is what gates, logs, and rate limits should use: it returns the PROXY-reported address only when that header came from a trusted proxy. P0, Tier 1, `0.3.0` (TCP fields, `client_addr`, `client_key`), `0.4.0` (`real_peer`, `proxy`, `peer_credentials`, `tls`). `for_testing` (P1, Tier 3, `0.3.0`) builds one that is attached to no socket, so gates and sessions can be unit-tested; its id comes from the same process counter, so it never collides with a real connection.

```rust,no_run
let listener = net_io::listen("0.0.0.0:7000")?;
let (_conn, info) = listener.accept()?;
let key = info.client_key(net_io::PrefixPolicy::DEFAULT);
println!("{} from {:?} (group {:?}) via {:?}", info.id, info.client_addr(), key, info.transport);
# Ok::<(), net_io::NetError>(())
```

### `Transport`, `Origin`, `Endpoint`

```rust
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Transport { Tcp, Udp, Unix, Pipe }

#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Origin { Accepted, Dialed, Adopted, Inherited }

#[non_exhaustive] #[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Endpoint {
    Ip(SocketAddr),
    Unix(Arc<UnixPath>),     // up to 108 bytes, fixed array, shared with the listener
    Pipe(Arc<PipeName>),     // up to 256 UTF-16 units, fixed array, shared with the listener
    Unnamed,                 // an unnamed Unix socket peer
}
impl Endpoint { pub fn socket_addr(&self) -> Option<SocketAddr>; }
impl fmt::Display for Endpoint { /* 127.0.0.1:80, the Unix path, the pipe name, or "unnamed" */ }
#[derive(Clone, Debug, PartialEq, Eq, Hash)] pub struct UnixPath { /* [u8; 108] + len */ }  impl UnixPath { pub fn as_bytes(&self) -> &[u8]; #[cfg(unix)] pub fn as_path(&self) -> &Path; }
#[derive(Clone, Debug, PartialEq, Eq, Hash)] pub struct PipeName { /* [u16; 256] + len */ } impl PipeName { pub fn as_wide(&self) -> &[u16]; pub fn to_string_lossy(&self) -> String; }
```

P0, Tier 2, `0.3.0` (`Ip`, `Tcp`, `Accepted`, `Dialed`), `0.4.0` (the rest).

### `PeerCredentials`

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PeerCredentials { pub pid: Option<u32>, pub uid: Option<u32>, pub gid: Option<u32> }
```

Who is on the other end of a local socket, read once at accept: `SO_PEERCRED` (Linux), `getpeereid` plus `LOCAL_PEERPID` (macOS), `getpeereid` and `LOCAL_PEERCRED` (FreeBSD), `SIO_AF_UNIX_GETPEERPID` (Windows AF_UNIX, pid only), `GetNamedPipeClientProcessId` (named pipes, pid only). A field the platform cannot report is `None`. P1, Tier 2, `0.4.0` (Unix), `0.5.0` (Windows).

---

## Limits

### `Limits`

```rust
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Limits { /* private: one optional value per row of the defaults table */ }

impl Limits {
    pub fn builder() -> LimitsBuilder;                         // every value unset
    pub fn reactor_defaults() -> Limits;                       // every value set to the reactor column
    pub fn blocking_defaults() -> Limits;                      // every value set to the blocking column
    pub fn to_builder(&self) -> LimitsBuilder;
    pub fn resolve(&self, driver: DriverKind) -> Limits;       // unset values filled from that driver's defaults
    pub fn validate(&self, workers: u16, descriptor_limit: Option<u64>) -> Result<(), NetError>;
    // One getter per value; None = not set here (the driver's default applies):
    pub fn max_connections(&self) -> Option<u32>;
    pub fn max_per_listener(&self) -> Option<u32>;
    pub fn max_per_source(&self) -> Option<(u32, PrefixPolicy)>;
    pub fn backlog(&self) -> Option<u32>;
    pub fn accept_batch(&self) -> Option<u16>;
    pub fn handshake_timeout(&self) -> Option<Duration>;
    pub fn idle_timeout(&self) -> Option<Duration>;
    pub fn read_timeout(&self) -> Option<Duration>;
    pub fn write_timeout(&self) -> Option<Duration>;
    pub fn park_timeout(&self) -> Option<Duration>;
    pub fn min_rate(&self) -> Option<MinRate>;
    pub fn proxy_header_max(&self) -> Option<u16>;
    pub fn read_class(&self) -> Option<(SizeClass, SizeClass)>;      // initial, maximum
    pub fn output_budget(&self) -> Option<u32>;
    pub fn completion_queue(&self) -> Option<u32>;
    pub fn buffer_budget(&self) -> Option<u64>;
    pub fn drain_timeout(&self) -> Option<Duration>;
    pub fn graceful_linger(&self) -> Option<(Duration, u32)>;
    pub fn refusal_bytes_max(&self) -> Option<u16>;
    pub fn tick(&self) -> Option<Duration>;
    pub fn pressure(&self) -> Option<Pressure>;
    pub fn lane_reserve(&self, lane: Lane) -> Option<u32>;
}
```

Every bound net-io enforces, in one value. A `Limits` records only what was set; everything left unset takes the defaults of the driver that runs the connection (table below), so `Limits::builder().max_connections(100).build()` means "my cap, the driver's defaults for the rest" whichever driver the server picks. `Limits::default()` is the same as an empty builder. A server takes one `Limits` and each listener may override values of it (`ListenerSpec::limits`); a client `TcpConnection` takes one through `set_limits`. Limits are checked before the resource is committed: a connection over a cap is refused before any byte is read, a header over its size before buffering, a buffer before allocation. P0, Tier 2, `0.3.0`.

`resolve` returns the effective values for a driver (every getter then returns `Some`); `validate` is what `ServerBuilder::build` runs on the resolved values (Tier 3 for code that checks limits ahead of time). `descriptor_limit` is the process's open-descriptor limit (`RLIMIT_NOFILE` soft limit on Unix, `None` on Windows, where socket handles do not come from a small table).

### `LimitsBuilder`

```rust
#[must_use]
#[derive(Clone, Debug, Default)]
pub struct LimitsBuilder { /* ... */ }
impl LimitsBuilder {
    pub fn max_connections(self, n: u32) -> Self;
    pub fn max_per_listener(self, n: u32) -> Self;
    pub fn max_per_source(self, n: u32, policy: PrefixPolicy) -> Self;
    pub fn backlog(self, n: u32) -> Self;
    pub fn accept_batch(self, n: u16) -> Self;
    pub fn handshake_timeout(self, d: Duration) -> Self;
    pub fn idle_timeout(self, d: Duration) -> Self;
    pub fn read_timeout(self, d: Duration) -> Self;
    pub fn write_timeout(self, d: Duration) -> Self;
    pub fn park_timeout(self, d: Duration) -> Self;
    pub fn min_rate(self, rate: MinRate) -> Self;
    pub fn proxy_header_max(self, v2_body_bytes: u16) -> Self;
    pub fn read_class(self, initial: SizeClass, max: SizeClass) -> Self;
    pub fn output_budget(self, bytes: u32) -> Self;
    pub fn completion_queue(self, n: u32) -> Self;             // rounded up to a power of two
    pub fn buffer_budget(self, bytes: u64) -> Self;
    pub fn drain_timeout(self, d: Duration) -> Self;
    pub fn graceful_linger(self, d: Duration, bytes: u32) -> Self;
    pub fn refusal_bytes_max(self, n: u16) -> Self;             // at most 512
    pub fn tick(self, d: Duration) -> Self;                     // 1 ms to 100 ms
    pub fn pressure(self, p: Pressure) -> Self;                 // P2, 0.6.0
    pub fn lane_reserve(self, lane: Lane, slots: u32) -> Self;  // P2, 0.6.0
    pub fn build(self) -> Result<Limits, NetError>;
}
```

P0, Tier 2, `0.3.0` (except `pressure` and `lane_reserve`). `build` checks the values that were set, alone and against each other, in the order of this table, and returns `InvalidConfig { field, reason }` for the first violation (`field` is the setter's name). The same checks run again in `ServerBuilder::build` on the values resolved for the driver, together with the checks that need the server (buffer budget against workers, caps against the descriptor limit).

| Rule | `reason` |
|---|---|
| `max_connections`, `backlog`, `accept_batch`, `max_per_source`, `completion_queue`, `output_budget` are zero | `Zero` |
| `max_per_listener > max_connections`, `max_per_source > max_connections` (both set) | `AboveGlobal` |
| any timeout below one `tick` | `BelowTick` |
| `min_rate.window < min_rate.check`, or `grace` or `check` zero while the rate is on | `WindowBelowCheck` / `Zero` |
| `read_class` maximum below its initial class | `Inconsistent` |
| `refusal_bytes_max > 512`, `proxy_header_max > 65,519`, `completion_queue > 1,048,576` | `TooLarge { max }` |
| `pressure.high <= pressure.low`, `factor` outside (0, 1] | `Inconsistent` |
| sum of `lane_reserve` above `max_connections` | `AboveGlobal` |

Defaults that depend on another value follow it: an unset `max_per_listener` equals `max_connections`, and an unset `max_per_source` is `min(default, max_connections)`, so setting only a small `max_connections` is always valid.

```rust
use net_io::{Limits, MinRate};
use std::time::Duration;

let limits = Limits::builder()
    .max_connections(20_000)
    .idle_timeout(Duration::from_secs(15))
    .min_rate(MinRate::new(512, Duration::from_secs(10)))
    .build()?;
assert_eq!(limits.max_connections(), Some(20_000));
assert_eq!(limits.read_timeout(), None); // the driver's default (30 s) applies
assert_eq!(limits.resolve(net_io::DriverKind::Blocking).read_timeout(), Some(Duration::from_secs(30)));
# Ok::<(), net_io::NetError>(())
```

```rust
use net_io::{ConfigReason, Limits, NetError};
let err = Limits::builder().max_connections(100).max_per_listener(200).build().unwrap_err();
assert!(matches!(err, NetError::InvalidConfig { field: "max_per_listener", reason: ConfigReason::AboveGlobal }));
assert!(Limits::builder().max_connections(100).build().is_ok()); // max_per_source follows it down
```

### Defaults and reasons

| Limit | Reactor | Blocking | Guards against | Reason for the value |
|---|---|---|---|---|
| `max_connections` | 10,000 | `workers` (128) | descriptor and memory exhaustion | fits the default `RLIMIT_NOFILE` of many servers (65,536 hard) with room for files; blocking: one connection per worker |
| `max_per_listener` | follows `max_connections` | same | one listener starving others | equal by default; lower it for admin listeners |
| `max_per_source` | 256 per IPv4 /32 or IPv6 /64, at most `max_connections` | 16, at most `max_connections` | one host taking every slot | browsers open 6 to 10 connections per host; 256 leaves room for NAT; blocking pools are small. Counted per listener (each listener applies its own value, D-085), over every open connection including one finishing a graceful close, so a client at the cap that reconnects at once can be refused until its last connection is closed; a load test from one host needs a higher cap |
| `backlog` | 1,024 | 1,024 | SYN bursts overflowing the accept queue | Linux caps it at `somaxconn` (4,096 since 5.4, 128 before) |
| `accept_batch` | 64 | 16 | one listener starving other work | bounds accept work per wake-up |
| `handshake_timeout` | 10 s | 10 s | PROXY or TLS that never finishes | a TLS handshake over a slow mobile link takes under 2 s; 10 s is generous |
| `idle_timeout` | 60 s | 5 s | parked keep-alive connections | browsers keep idle connections 60 s to 300 s; an idle blocking connection holds a whole worker |
| `read_timeout`, `write_timeout` | 30 s | 30 s | stalled sender or receiver | per operation; the minimum rate catches trickles sooner |
| `exchange` | none (set per exchange) | none | trickle inside every per-read timeout | only the protocol knows what an exchange is |
| `park_timeout` | 30 s | 30 s | offloaded work that never returns | longer than any password hash or database call should take |
| `min_rate` | 256 B/s over 10 s, after 5 s grace, checked every 1 s | same | slowloris (in), slow-read (out) | the same order as Apache `mod_reqtimeout`'s `MinRate=500`; active directions only |
| `proxy_header_max` (v2 body) | 1,024 B | same | oversized v2 TLV blocks | covers a UNIX address block (216 B), a 128 B unique id, ALPN, authority, and SSL sub-TLVs; up to 65,519 |
| PROXY v1 line | 107 B (fixed) | same | oversized v1 lines | the specification's maximum |
| `read_class` | 16 KiB, may grow to 64 KiB | same | memory per connection | a typical request head fits 16 KiB |
| `output_budget` | 64 KiB of pool memory per connection | same | memory per connection | static slices and file ranges do not count |
| `completion_queue` | 1,024 per worker | 1 per worker | offload floods | a blocking worker serves one connection |
| `buffer_budget` | 512 MiB | 64 MiB | total memory | at least `workers x 64 KiB x 2` (checked) |
| `drain_timeout` | 30 s | 30 s | hung shutdowns | matches common orchestrator grace periods |
| `graceful_linger` | 2 s, 64 KiB | same | RST on unread data at close | enough for the peer to see the last response |
| `refusal_bytes_max` | 512 B | same | refusals used as amplifiers | one canned status line and headers |
| `tick` | 1 ms | 10 ms | timer resolution | blocking reads re-arm `SO_RCVTIMEO` only when the target moves by more than a tick |

Per-address **rates** and bans are not net-io's: they belong to the gate. net-io keeps only the per-source **concurrency** cap (decision D-025), because it needs no policy, costs one table update per accept, and keeps a server safe when it runs without a gate.

### `MinRate`, `Pressure`, `SizeClass`

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MinRate { pub bytes_per_sec: u32, pub window: Duration, pub grace: Duration, pub check: Duration }
impl MinRate {
    pub const fn off() -> MinRate;
    pub const fn new(bytes_per_sec: u32, window: Duration) -> MinRate;   // grace 5 s, check 1 s
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Pressure { pub high: f32, pub low: f32, pub factor: f32 }
impl Default for Pressure;                                               // 0.8, 0.6, 0.25

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SizeClass(u32);
impl SizeClass {
    pub const SMALL: SizeClass;      // 4 KiB
    pub const MEDIUM: SizeClass;     // 16 KiB
    pub const LARGE: SizeClass;      // 64 KiB
    pub const fn new(bytes: u32) -> Result<SizeClass, NetError>;   // power of two, 1 KiB to 1 MiB
    pub const fn bytes(self) -> u32;
}
```

The minimum rate applies per direction while that direction is active (receiving an exchange, or output pending). After `grace`, the bytes moved over the last `window` must reach `bytes_per_sec x window`, or the connection closes with `SlowPeer { direction }`. A one-byte-every-few-seconds client passes any per-read timeout; it does not pass this. Cost: one add per IO completion and one wheel timer per active connection per second [est. under 50 ns per check]. P0, Tier 2, `0.3.0`.

`Pressure::default()` is high 0.8, low 0.6, factor 0.25. Adaptive deadlines (`Pressure`, P2, `0.6.0`): when open connections pass `high` of `max_connections`, the handshake and idle deadlines of new and idle connections are multiplied by `factor` (floor 1 s), and restored below `low`. No cost below the threshold.

---

## TCP

### `TcpListener`

```rust
pub struct TcpListener { /* owned socket, ListenerInfo */ }

impl TcpListener {
    pub fn bind<A: ToSocketAddrs>(addr: A) -> Result<TcpListener, NetError>;
    pub fn bind_with<A: ToSocketAddrs>(addr: A, options: ListenOptions) -> Result<TcpListener, NetError>;
    pub fn accept(&self) -> Result<(TcpConnection, ConnectionInfo), NetError>;
    pub fn accept_timeout(&self, timeout: Duration) -> Result<Option<(TcpConnection, ConnectionInfo)>, NetError>;
    pub fn info(&self) -> &ListenerInfo;
    pub fn local_addr(&self) -> Result<SocketAddr, NetError>;
    pub fn from_std(listener: std::net::TcpListener) -> Result<TcpListener, NetError>;
    pub fn into_std(self) -> std::net::TcpListener;
    pub fn try_clone(&self) -> Result<TcpListener, NetError>;
}
#[cfg(unix)]    impl From<TcpListener> for OwnedFd;      #[cfg(unix)]    impl TryFrom<OwnedFd> for TcpListener;
#[cfg(windows)] impl From<TcpListener> for OwnedSocket;  #[cfg(windows)] impl TryFrom<OwnedSocket> for TcpListener;
#[cfg(unix)]    impl AsFd for TcpListener;               #[cfg(windows)] impl AsSocket for TcpListener;
```

A listening TCP socket created by net-io (not by `std`), so options that must precede `bind` (reuse port, IPv6-only, buffer sizes) can be set.

| Item | Behaviour | Errors | Cost | Grade | Tier | Version |
|---|---|---|---|---|---|---|
| `bind` | as [`listen`](#listen) | as `listen` | one-time | P0 | 1 | `0.3.0` |
| `bind_with` | applies [`ListenOptions`](#listenoptions) in the order given there | `Unsupported` for an option the platform lacks (never silently ignored), `InvalidConfig` for an out-of-range value, bind errors | one-time | P0 | 2 | `0.3.0` |
| `accept` | blocks until a connection arrives; applies the per-connection options, normalizes the peer, issues a `ConnectionId`, builds `ConnectionInfo`; on descriptor exhaustion runs the reserve-descriptor routine (one pending connection is accepted and reset, then a backoff); retries `EINTR`; skips per-connection failures (`ECONNABORTED` and the like) | `Limit { which: Descriptors }` when exhaustion persists past one backoff step, `Os` | 1 system call plus options [est. 1 to 2 µs] | P0 | 1 | `0.3.0` |
| `accept_timeout` | `Ok(None)` when nothing arrived in time | as `accept` | +1 system call (`poll` / `WSAPoll`) | P1 | 2 | `0.3.0` |
| `info`, `local_addr` | | | none | P0 | 1 | `0.3.0` |
| `from_std`, `TryFrom<OwnedFd/OwnedSocket>` | adopt an existing socket after checking it is a listening stream socket (`SO_ACCEPTCONN`, `SO_TYPE`); sets close-on-exec | `InvalidConfig { field: "socket", reason: NotListening }` | 2 to 3 system calls | P1 | 3 | `0.3.0` |
| `into_std`, `From<TcpListener>` | give the socket up | | none | P1 | 3 | `0.3.0` |
| `try_clone` | duplicate the descriptor (close-on-exec) | `Os` | 1 system call | P2 | 3 | `0.3.0` |

`TcpListener::accept` does no admission: a plain listener has no gate. Admission, caps, and drain belong to the [server](#server).

```rust
use net_io::{ListenOptions, TcpListener};
let options = ListenOptions::new().backlog(4096).reuse_port(cfg!(target_os = "linux"));
let listener = TcpListener::bind_with("127.0.0.1:0", options)?;
println!("effective backlog {:?}", listener.info().backlog);
# Ok::<(), net_io::NetError>(())
```

```rust,no_run
use std::time::Duration;
let listener = net_io::listen("127.0.0.1:7000")?;
while let Some((conn, info)) = listener.accept_timeout(Duration::from_secs(1))? {
    println!("{} connected", info.id);
    conn.abort(); // refuse with RST
}
# Ok::<(), net_io::NetError>(())
```

### `TcpConnection`

```rust
pub struct TcpConnection { /* owned socket, ConnectionInfo, limits, rate counters, kill state */ }

impl TcpConnection {
    pub fn connect<A: ToSocketAddrs>(addr: A) -> Result<TcpConnection, NetError>;
    pub fn connect_with<A: ToSocketAddrs>(addr: A, options: ConnectOptions) -> Result<TcpConnection, NetError>;
    pub fn connect_host(host: &str, port: u16, options: ConnectOptions) -> Result<TcpConnection, NetError>;

    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize, NetError>;           // 0 = the peer closed its side
    pub fn recv_exact(&mut self, buf: &mut [u8]) -> Result<(), NetError>;
    pub fn recv_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> Result<usize, NetError>;
    pub fn peek(&self, buf: &mut [u8]) -> Result<usize, NetError>;
    pub fn send(&mut self, buf: &[u8]) -> Result<usize, NetError>;              // one system call, may be partial
    pub fn send_all(&mut self, buf: &[u8]) -> Result<(), NetError>;
    pub fn send_vectored(&mut self, bufs: &[IoSlice<'_>]) -> Result<usize, NetError>;
    pub fn send_all_vectored(&mut self, bufs: &mut [IoSlice<'_>]) -> Result<(), NetError>;
    pub fn send_file(&mut self, file: &File, offset: u64, len: u64) -> Result<u64, NetError>;

    pub fn shutdown(&mut self, how: Shutdown) -> Result<(), NetError>;
    pub fn close(self) -> Result<(), NetError>;                                  // graceful
    pub fn abort(self);                                                          // RST

    pub fn info(&self) -> &ConnectionInfo;
    pub fn id(&self) -> ConnectionId;
    pub fn peer_addr(&self) -> SocketAddr;
    pub fn local_addr(&self) -> SocketAddr;
    pub fn kill_handle(&self) -> KillHandle;
    pub fn set_limits(&mut self, limits: Limits);
    pub fn set_phase(&mut self, phase: Phase);
    pub fn set_exchange_deadline(&mut self, at: Option<Instant>);
    pub fn set_gate<G: Gate>(&mut self, gate: Arc<G>) -> Result<(), NetError>;
    pub fn options(&self) -> SocketOptions<'_>;
    pub fn take_error(&self) -> Result<Option<io::Error>, NetError>;
}
impl Read for TcpConnection;
impl Write for TcpConnection;            // flush() is a no-op: net-io buffers nothing on this path
impl Drop for TcpConnection;             // never blocks: FIN, then close without the linger; use close() for the full graceful close
#[cfg(unix)] impl AsFd for TcpConnection; #[cfg(windows)] impl AsSocket for TcpConnection;
```

A connected TCP socket that carries its own limits: every read honours the current phase's deadline (a connection from `accept` starts in `Idle` and waits for the first byte of an exchange under the idle timeout; a connection from `connect` starts in `Receiving` and reads under the read timeout), the exchange deadline, and the inbound minimum rate; every write honours the write deadline and the outbound minimum rate. It has one owner: there is no `Read` or `Write` for `&TcpConnection`, and other threads act on it only through its [`KillHandle`](#killhandle). `Send`, not `Sync`.

| Item | Behaviour | Errors | Cost | Grade | Tier | Version |
|---|---|---|---|---|---|---|
| `connect` | as [`connect`](#connect) | as `connect` | | P0 | 1 | `0.3.0` |
| `connect_with` | uses [`ConnectOptions`](#connectoptions) | as `connect` | | P0 | 2 | `0.3.0` |
| `connect_host` | resolves through `std::net::ToSocketAddrs`, tries addresses in order, per-attempt deadline = remaining total / remaining addresses (at least 1 s); Happy Eyeballs when `ConnectOptions::happy_eyeballs(true)` | `NoAddresses`, connect errors (the last one) | resolution plus one round trip | P1 (Happy Eyeballs P2) | 2 | `0.3.0` (Happy Eyeballs `0.5.0`) |
| `recv`, `recv_vectored` | retries `EINTR` with the remaining deadline; a zero-length `buf` returns `Ok(0)` without a system call (this is not end of stream; check `buf.len()`) | `TimedOut { kind }`, `SlowPeer { In }`, `ConnectionReset`, `Killed`, `Closed` | 1 system call; 2 when the deadline target moved by more than a tick | P0 (vectored P1) | 1 | `0.3.0` |
| `recv_exact` | loops until `buf` is full | as `recv`, plus `Closed` when the peer closes early | | P1 | 1 | `0.3.0` |
| `peek` | `MSG_PEEK` | as `recv` | 1 system call | P2 | 2 | `0.3.0` |
| `send` | gate check, then one system call; may write less than `buf` | `TimedOut`, `SlowPeer { Out }`, `BrokenPipe`, `ConnectionReset`, `EgressDenied`, `Killed` | gate check + 1 system call | P0 | 1 | `0.3.0` |
| `send_all` | loops from the exact offset until done, the deadline passes, or the gate denies; the gate check runs before each write (a retry after the socket was full is not checked again, D-074) | as `send` | 1 system call per chunk | P0 | 1 | `0.3.0` |
| `send_vectored`, `send_all_vectored` | up to 64 slices per system call; `send_all_vectored` advances the slices in place (no copy) | as `send` | 1 system call per 64 slices | P1 | 2 | `0.3.0` |
| `send_file` | `sendfile` (Linux, macOS, FreeBSD) or `TransmitFile` (Windows) in chunks, a gate check before each chunk; falls back to read-and-write internally where zero copy is unavailable | as `send`; `FileTruncated { sent }` when the file shrinks | zero copy where possible | P2 | 2 | `0.6.0` |
| `shutdown` | half-close: `Write` sends FIN and keeps reading; `Read` stops reading; repeated calls are no-ops | `Closed`, `Os` | 1 system call | P0 | 1 | `0.3.0` |
| `close` | graceful: FIN, then reads and discards up to 64 KiB for up to 2 s so unread input does not cause an RST that destroys the last response, then close | `TimedOut`, `Os` | flush plus linger | P0 | 1 | `0.3.0` |
| `abort` | `SO_LINGER {on, 0}` and close: RST, kernel resources freed at once | none surfaced | 2 system calls | P0 | 1 | `0.3.0` |
| `info`, `id`, `peer_addr`, `local_addr` | | | none | P0 | 1 | `0.3.0` |
| `kill_handle` | a handle other threads can use to abort this connection | | one `Arc` clone | P0 | 2 | `0.3.0` |
| `set_limits`, `set_phase`, `set_exchange_deadline` | change the deadlines that apply from the next operation | | none | P0 | 2 | `0.3.0` |
| `set_gate` | registers a dialed connection with a gate (`Gate::admit` with `AdmitStage::Dialed`); from then on `Gate::check` runs before every write and `Gate::closed` runs once at close; for back-channel and outbound connections that must be revocable like accepted ones | `Refused { cause }` when the gate refuses (the connection is then aborted) | one admission | P1 | 2 | `0.4.0` |
| `options` | live get and set of [socket options](#socketoptions) | | 1 system call per option | P1 | 3 | `0.3.0` |
| `take_error` | `SO_ERROR` | `Os` | 1 system call | P2 | 3 | `0.3.0` |
| `Read`, `Write` | through `recv` and `send_all`; the `io::Error` carries the `NetError` as its inner error | | as `recv` / `send` | P0 | 1 | `0.3.0` |

```rust,no_run
use net_io::{Limits, Phase};
use std::time::{Duration, Instant};

let mut conn = net_io::connect("127.0.0.1:7000")?;
conn.set_limits(Limits::builder().read_timeout(Duration::from_secs(5)).build()?);
conn.set_phase(Phase::Receiving);
conn.set_exchange_deadline(Some(Instant::now() + Duration::from_secs(20)));
let mut buf = [0u8; 1024];
let n = conn.recv(&mut buf)?;
# let _ = n;
# Ok::<(), net_io::NetError>(())
```

```rust,no_run
// Kill a connection from another thread: the blocked recv returns Killed at once.
use net_io::KillReason;
let mut conn = net_io::connect("127.0.0.1:7000")?;
let kill = conn.kill_handle();
std::thread::spawn(move || {
    std::thread::sleep(std::time::Duration::from_secs(1));
    kill.kill(KillReason(1));
});
let mut buf = [0u8; 16];
assert!(matches!(conn.recv(&mut buf), Err(net_io::NetError::Killed { .. })));
# Ok::<(), net_io::NetError>(())
```

### `ConnectOptions`

```rust
#[must_use]
#[derive(Clone, Debug)]
pub struct ConnectOptions { /* ... */ }
impl ConnectOptions {
    pub fn new() -> Self;                                  // timeout 10 s, nodelay on, no local bind, Happy Eyeballs off
    pub fn timeout(self, total: Duration) -> Self;
    pub fn local_addr(self, addr: SocketAddr) -> Self;     // bind before connect
    pub fn tcp_options(self, options: TcpOptions) -> Self;
    pub fn limits(self, limits: Limits) -> Self;
    pub fn happy_eyeballs(self, on: bool) -> Self;         // P2, 0.5.0
    pub fn attempt_delay(self, d: Duration) -> Self;       // P2, 0.5.0: 250 ms default, 100 ms to 2 s
}
impl Default for ConnectOptions;
```

P0, Tier 2, `0.3.0`. Happy Eyeballs (RFC 8305, simplified because `std` resolution returns both families at once): IPv6 first, families interleaved one address at a time, the next attempt starts `attempt_delay` after the previous one unless that one already failed, never two attempts within 10 ms, the first established connection wins, and the others are aborted.

```rust,no_run
use net_io::{ConnectOptions, TcpConnection};
use std::time::Duration;
let options = ConnectOptions::new().timeout(Duration::from_secs(3)).happy_eyeballs(true);
let conn = TcpConnection::connect_host("example.com", 443, options)?;
println!("connected to {}", conn.peer_addr());
# Ok::<(), net_io::NetError>(())
```

---

## Socket options

### `ListenOptions`

```rust
#[must_use]
#[derive(Clone, Debug)]
pub struct ListenOptions { /* ... */ }
impl ListenOptions {
    pub fn new() -> Self;
    pub fn backlog(self, n: u32) -> Self;
    pub fn reuse_address(self, on: bool) -> Self;         // Unix: SO_REUSEADDR. Windows: false = SO_EXCLUSIVEADDRUSE, true = SO_REUSEADDR
    pub fn reuse_port(self, on: bool) -> Self;            // SO_REUSEPORT
    pub fn ipv6_only(self, on: bool) -> Self;             // IPV6_V6ONLY
    pub fn send_buffer(self, bytes: u32) -> Self;
    pub fn receive_buffer(self, bytes: u32) -> Self;
    pub fn defer_accept(self, wait: Option<Duration>) -> Self;   // P2, 0.6.0
    pub fn fast_open(self, queue: Option<u32>) -> Self;          // P2, 0.6.0
    pub fn incoming_cpu(self, cpu: Option<u32>) -> Self;         // P2, 0.6.0
    pub fn tcp_options(self, options: TcpOptions) -> Self; // applied to every accepted socket
}
impl Default for ListenOptions;
```

Order of application at bind: create the socket (close-on-exec; non-blocking for the reactor; `SO_NOSIGPIPE` on macOS), reuse address or exclusive address use, reuse port, IPv6-only, incoming CPU, buffer sizes (before `listen`, so window scaling is negotiated), `bind`, defer accept, fast open, `listen(backlog)`. P0, Tier 2, `0.3.0` per option row below.

Options a listener passes to accepted sockets differ by OS. On Linux and Windows every option is inherited from the listener, so net-io does not set them again (one fewer system call per option per accept); on macOS and FreeBSD it applies `tcp_options` to each accepted socket explicitly (decision D-055; details in `docs/PLATFORM-NOTES.md` from `0.3.0`).

### `TcpOptions`, `Keepalive`, `Linger`

```rust
#[must_use]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TcpOptions {
    pub nodelay: Option<bool>,
    pub keepalive: Option<Keepalive>,
    pub linger: Option<Linger>,
    pub send_buffer: Option<u32>,
    pub receive_buffer: Option<u32>,
    pub user_timeout: Option<Duration>,     // P2, 0.6.0
    pub ttl: Option<u8>,                    // P2, 0.3.0
    pub notsent_lowat: Option<u32>,         // P3
    pub quickack: Option<bool>,             // P3
    pub dscp: Option<u8>,                   // P3, a hint
}
impl TcpOptions {
    pub fn new() -> Self;
    pub fn nodelay(self, on: bool) -> Self;
    pub fn keepalive(self, k: Keepalive) -> Self;
    pub fn linger(self, l: Linger) -> Self;
    pub fn send_buffer(self, bytes: u32) -> Self;
    pub fn receive_buffer(self, bytes: u32) -> Self;
    pub fn user_timeout(self, d: Duration) -> Self;
    pub fn ttl(self, hops: u8) -> Self;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Keepalive { pub idle: Duration, pub interval: Duration, pub count: u32 }
impl Keepalive { pub const DEFAULT: Keepalive; }      // 60 s, 10 s, 6

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Linger { Off, Abortive, Timeout(Duration) }
```

`None` leaves the OS default. P0, Tier 2, `0.3.0`.

### `SocketOptions`

```rust
pub struct SocketOptions<'a> { /* borrowed socket */ }
impl SocketOptions<'_> {
    pub fn nodelay(&self) -> Result<bool, NetError>;          pub fn set_nodelay(&self, on: bool) -> Result<(), NetError>;
    pub fn keepalive(&self) -> Result<Option<Keepalive>, NetError>; pub fn set_keepalive(&self, k: Option<Keepalive>) -> Result<(), NetError>;
    pub fn linger(&self) -> Result<Linger, NetError>;         pub fn set_linger(&self, l: Linger) -> Result<(), NetError>;
    pub fn send_buffer(&self) -> Result<u32, NetError>;       pub fn set_send_buffer(&self, bytes: u32) -> Result<u32, NetError>;
    pub fn receive_buffer(&self) -> Result<u32, NetError>;    pub fn set_receive_buffer(&self, bytes: u32) -> Result<u32, NetError>;
    pub fn ttl(&self) -> Result<u8, NetError>;                pub fn set_ttl(&self, hops: u8) -> Result<(), NetError>;
    pub fn user_timeout(&self) -> Result<Option<Duration>, NetError>; pub fn set_user_timeout(&self, d: Option<Duration>) -> Result<(), NetError>;
}
```

Live get and set on an open socket. Setters that the OS may adjust return the effective value (Linux doubles buffer sizes). P1, Tier 3, `0.3.0`.

```rust,no_run
use net_io::{Keepalive, Linger};
let conn = net_io::connect("127.0.0.1:7000")?;
conn.options().set_keepalive(Some(Keepalive::DEFAULT))?;
conn.options().set_linger(Linger::Abortive)?;
let effective = conn.options().set_receive_buffer(256 * 1024)?;
println!("receive buffer is {effective} bytes");
# Ok::<(), net_io::NetError>(())
```

### Option support by platform

Errors: `Unsupported { feature, platform }` (never silent, except options marked "hint"), `InvalidConfig` (for example a keepalive count above 255 on Windows), `Os`.

| Option | Linux | macOS | FreeBSD | Windows | Default | Grade | Version |
|---|---|---|---|---|---|---|---|
| `nodelay` | `TCP_NODELAY` | yes | yes | yes | on for accepted and dialed | P0 | `0.3.0` |
| keepalive on/off | `SO_KEEPALIVE` | yes | yes | yes | off | P0 | `0.3.0` |
| keepalive idle | `TCP_KEEPIDLE` | `TCP_KEEPALIVE` | `TCP_KEEPIDLE` | `TCP_KEEPIDLE` (1709+), else `SIO_KEEPALIVE_VALS` | 60 s when on | P1 | `0.3.0` |
| keepalive interval | `TCP_KEEPINTVL` | yes | yes | `TCP_KEEPINTVL` (1709+), else `SIO_KEEPALIVE_VALS` | 10 s | P1 | `0.3.0` |
| keepalive count | `TCP_KEEPCNT` | yes | yes | `TCP_KEEPCNT` (1703+, at most 255); older: `Unsupported` | 6 | P1 | `0.3.0` |
| `linger` | `SO_LINGER` | `SO_LINGER_SEC` (seconds) | `SO_LINGER` | `SO_LINGER` | off; abortive on kill | P0 | `0.3.0` |
| `send_buffer`, `receive_buffer` | `SO_SNDBUF`, `SO_RCVBUF` (doubled by the kernel; effective value reported) | yes | yes | yes | OS default | P1 | `0.3.0` |
| `reuse_address` | `SO_REUSEADDR` | yes | yes | `SO_EXCLUSIVEADDRUSE` by default (port hijack protection); `SO_REUSEADDR` only on request | Unix on, Windows exclusive | P0 | `0.3.0` |
| `reuse_port` | `SO_REUSEPORT` (load-balanced) | `SO_REUSEPORT` (not load-balanced) | `SO_REUSEPORT`, `SO_REUSEPORT_LB` (P3) | `Unsupported` | off | P1 | `0.3.0` |
| `ipv6_only` | `IPV6_V6ONLY` | yes | yes | yes | on (decision D-026) | P0 | `0.3.0` |
| `backlog` | capped by `somaxconn` (read once, effective value reported) | capped by `kern.ipc.somaxconn` | same | as given | 1,024 | P0 | `0.3.0` |
| `defer_accept` | `TCP_DEFER_ACCEPT` | `Unsupported` | accept filter (P3) | `Unsupported` | off | P2 | `0.6.0` |
| `fast_open` (server) | `TCP_FASTOPEN` | `TCP_FASTOPEN` | `TCP_FASTOPEN` | `TCP_FASTOPEN` (1607+) | off | P2 | `0.6.0` |
| `incoming_cpu` | `SO_INCOMING_CPU` (set 4.4+) | `Unsupported` | `Unsupported` | `Unsupported` | off | P2 | `0.6.0` |
| `user_timeout` | `TCP_USER_TIMEOUT` | `Unsupported` | `Unsupported` | `TCP_MAXRT` (seconds) | off | P2 | `0.6.0` |
| `ttl` | `IP_TTL` / `IPV6_UNICAST_HOPS` | yes | yes | yes | OS default | P2 | `0.3.0` |
| `notsent_lowat` | `TCP_NOTSENT_LOWAT` | yes | `Unsupported` | `Unsupported` | off | P3 | after `1.0.0` |
| `quickack` | `TCP_QUICKACK` (re-applied after reads, not sticky) | `Unsupported` | `Unsupported` | `Unsupported` | off | P3 | after `1.0.0` |
| `dscp` | `IP_TOS` / `IPV6_TCLASS` | yes | yes | hint (ignored without a QoS policy) | unset | P3 | after `1.0.0` |
| client fast open | `TCP_FASTOPEN_CONNECT` | `connectx` | `TCP_FASTOPEN` | `ConnectEx` with data | off | P3 | after `1.0.0` |
| no `SIGPIPE` | `MSG_NOSIGNAL` on every send | `SO_NOSIGPIPE` on every socket | `MSG_NOSIGNAL` | n/a | always | P0 | `0.3.0` |
| close-on-exec / not inheritable | `SOCK_CLOEXEC`, `accept4` | `FD_CLOEXEC` right after creation (a documented window) | `SOCK_CLOEXEC`, `accept4` | `WSA_FLAG_NO_HANDLE_INHERIT` | always | P0 | `0.3.0` |

---

## Sessions

A `Session` is a sans-IO protocol engine bound to one connection: net-io reads, calls the session with the bytes, and does what the session's [`Step`](#step-phase) says. The same session code runs on every driver. Sessions are called only on the worker that owns the connection, never concurrently.

### `Session`

```rust
pub trait Session: Send + 'static {
    fn on_open(&mut self, cx: &mut SessionContext<'_>) -> Step { let _ = cx; Step::Read }
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step;
    fn on_writable(&mut self, cx: &mut SessionContext<'_>) -> Step { let _ = cx; Step::Read }
    fn on_wake(&mut self, cx: &mut SessionContext<'_>, token: u32, value: u64) -> Step { let _ = (cx, token, value); Step::Abort }
    fn on_timeout(&mut self, cx: &mut SessionContext<'_>, which: TimeoutKind) -> Step { let _ = (cx, which); Step::Close }
    fn on_peer_closed(&mut self, cx: &mut SessionContext<'_>) -> Step { let _ = cx; Step::Close }
    fn on_denied(&mut self, code: u16, output: &mut Output) { let _ = (code, output); }
    fn on_close(&mut self, info: &ConnectionInfo, reason: CloseReason) { let _ = (info, reason); }
}
```

| Method | Called | Grade | Version |
|---|---|---|---|
| `on_open` | once, after admission and the handshake (PROXY, TLS) | P0 | `0.3.0` |
| `on_data` | when bytes arrived; `input` holds everything not yet consumed | P0 | `0.3.0` |
| `on_writable` | after a `Step::Write` flushed all pending output | P0 | `0.3.0` |
| `on_wake` | when another thread posted a completion for this connection through its [`Completer`](#completer) (after `Step::Park`) | P0 | `0.3.0` (blocking), `0.5.0` (reactor) |
| `on_timeout` | when a deadline passed that the session may handle (`Read`, `Write`, `Exchange`, `Park`, `Idle`). Returning `Close` or `Abort` closes with the timeout's own reason (`Idle`, `ReadTimeout`, `WriteTimeout`, `ExchangeDeadline`, `ParkDeadline`) and that reason's close style (graceful for `Idle`, abortive for the others); anything else re-arms with the same limits. The default returns `Close` | P0 | `0.3.0` |
| `on_peer_closed` | the peer sent FIN; the session may keep writing (half-close) | P1 | `0.3.0` |
| `on_denied` | the gate denied a write and no byte of the current response has left yet; write the protocol's refusal for `code` (for example a 403, a WebSocket close 1008, a database error frame) into `output`; net-io sends it with one bounded attempt and closes abortively | P0 | `0.3.0` |
| `on_close` | exactly once, with the one close reason | P0 | `0.3.0` |

Dispatch is static (each worker loop is compiled for the server's factory type), so a call costs a direct function call. A session that panics in an unwind build is closed with `SessionPanicked`; the worker continues.

### `SessionFactory`

```rust
pub trait SessionFactory: Send + Sync + 'static {
    type Session: Session;
    fn open(&self, info: &ConnectionInfo) -> Result<Self::Session, RefusalCause>;
}
impl<F, S> SessionFactory for F
where F: Fn(&ConnectionInfo) -> S + Send + Sync + 'static, S: Session
{ type Session = S; }
```

Creates one session per admitted connection. Returning `Err` closes the connection with `CloseReason::Refused(cause)` (for example the protocol cannot be served on this listener). A closure is a factory that never refuses. P0, Tier 3 (Tier 1 through the closure), `0.3.0`.

```rust
use net_io::{ConnectionInfo, Input, RefusalCause, Session, SessionContext, SessionFactory, Step};

struct Discard;
impl Session for Discard {
    fn on_data(&mut self, _cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let n = input.bytes().len();
        input.consume(n);
        Step::Read
    }
}

struct OnlyLoopback;
impl SessionFactory for OnlyLoopback {
    type Session = Discard;
    fn open(&self, info: &ConnectionInfo) -> Result<Discard, RefusalCause> {
        match info.client_addr() {
            Some(addr) if addr.ip().is_loopback() => Ok(Discard),
            _ => Err(RefusalCause::Session),
        }
    }
}
```

### `Step`, `Phase`

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Read,                                   // wait for more input; queued output is NOT sent (return Write first)
    Write,                                  // flush pending output, then on_writable
    Park { until: Option<Instant> },        // no reads, no idle timer, until a completion or the park deadline
    Close,                                  // graceful: flush, FIN, bounded linger
    Abort,                                  // RST now
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Phase { #[default] Idle, Receiving, Sending }
```

After `Step::Read`, net-io calls `on_data` again at once if the input changed since the last call (the session consumed bytes, or bytes arrived while it was writing); otherwise it waits for more bytes. So a session that consumed part of its input and returned `Write` sees the rest after the flush, and a session that consumed nothing and waits for more is not called in a loop.

`Phase` chooses which deadlines run (idle in `Idle`; read deadline, inbound rate, and exchange deadline in `Receiving`; write deadline, outbound rate, and exchange deadline in `Sending`). net-io moves `Idle` to `Receiving` itself when the first byte of a new exchange arrives, and back to `Idle` once a reply went out and no input is left over, so a session that never sets a phase still gets idle and read deadlines (D-065). Calling `set_phase` hands the phase to the session for the rest of the connection. `Park { until: None }` uses the park timeout. P0, Tier 3, `0.3.0`.

### `SessionContext`

```rust
pub struct SessionContext<'a> { /* worker-local */ }
impl SessionContext<'_> {
    pub fn info(&self) -> &ConnectionInfo;
    pub fn output(&mut self) -> &mut Output;
    pub fn now(&self) -> Instant;                         // the worker's clock, read once per loop iteration
    pub fn set_phase(&mut self, phase: Phase);
    pub fn set_exchange_deadline(&mut self, at: Option<Instant>);
    pub fn set_idle_timeout(&mut self, timeout: Option<Duration>);   // this connection, from its next idle wait; None: the limit again
    pub fn draining(&self) -> bool;                        // finish the current exchange, then close
    pub fn pressure(&self) -> f32;                         // 0.0 to 1.0; 1.0 under ControlState::Shed
    pub fn kill_handle(&self) -> KillHandle;
    pub fn completer(&self) -> Completer;                  // this worker's completion queue
    pub fn worker(&self) -> WorkerId;
    pub fn buffers(&mut self) -> &mut BufferPool;          // this worker's pool
    pub fn release(&mut self, buffer: Buffer);             // return a buffer taken by Input::swap (wiped)
    pub fn grow_input(&mut self, class: SizeClass) -> Result<(), NetError>;
}
```

Everything a session may touch, scoped to one call. `pressure` is the fraction of busy workers (blocking driver) or of `max_connections` in use (reactor); a protocol layer uses it to stop offering keep-alive above about 0.9. `grow_input` moves the unconsumed input into a larger buffer, up to the maximum read class (`LimitsBuilder::read_class`); above it the error is `Limit { which: ReadBuffer }`. `set_idle_timeout` overrides the idle timeout for this connection only (for example 2 s of keep-alive while the pool is over 75% busy), raised to at least one tick; `None` restores the listener's limit (D-081). Each method costs under 5 ns [est.]. P0 (`pressure`, `grow_input`, `set_idle_timeout` P1), Tier 3, `0.3.0`.

### `Input`

```rust
pub struct Input { /* the connection's Buffer + consumed offset */ }
impl Input {
    pub fn from_bytes(bytes: &[u8]) -> Input;                           // for tests of sessions (allocates)
    pub fn bytes(&self) -> &[u8];                                       // unconsumed bytes, borrowed from the read buffer
    pub fn consume(&mut self, n: usize);                                // saturates at the length
    pub fn is_full(&self) -> bool;
    pub fn class(&self) -> SizeClass;
    pub fn swap(&mut self, other: &mut Buffer) -> Result<(), SwapError>;
}
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwapError { ClassMismatch, NotEmpty, Busy }
```

A zero-copy view of what was read. A session consumes a prefix and leaves the rest for the next call; net-io compacts only when the free tail is under a quarter of the buffer (one `copy_within`, amortized). If the buffer is full and the session neither consumes nor grows it, the connection closes with `Limit(ReadBuffer)` instead of spinning. P0, Tier 3, `0.3.0`.

`swap` exchanges the connection's read buffer with an empty caller-owned `Buffer` of the same size class in O(1), under 5 ns [est.]: the bytes never move, the caller now owns them (for example a request body or a WebSocket message handed to another thread), and the connection reads into the buffer it was given. The caller returns the buffer later through `SessionContext::release` or any worker's `BufferPool`. Errors: `ClassMismatch`, `NotEmpty` (the incoming buffer has data), `Busy` (a driver operation holds the buffer; never true inside `on_data`).

```rust
use net_io::{Buffer, Input, Session, SessionContext, SizeClass, Step};

// Hand each full read buffer (16 KiB by default) to another owner without copying.
struct Blocks { spare: Option<Buffer>, ready: Vec<Buffer> }
impl Session for Blocks {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        if !input.is_full() {
            return Step::Read;
        }
        let mut spare = match self.spare.take().or_else(|| cx.buffers().take(input.class())) {
            Some(b) => b,
            None => return Step::Read, // budget spent: back-pressure, try again later
        };
        if input.swap(&mut spare).is_ok() {
            // `spare` now holds the bytes. Whoever processes `ready` returns each
            // buffer to a pool when done (BufferPool::put or SessionContext::release).
            self.ready.push(spare);
        }
        Step::Read
    }
}
# let _ = SizeClass::MEDIUM;
```

### `Output`

```rust
pub struct Output { /* bounded chunk queue */ }
impl Output {
    pub fn standalone(limit: u32) -> Output;                                     // for tests of sessions (allocates)
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), OutputFull>;              // all or nothing; copies into pool buffers
    pub fn push_partial(&mut self, bytes: &[u8]) -> usize;                       // as much as the budget allows; returns the count
    pub fn push_buffer(&mut self, buffer: Buffer) -> Result<(), OutputFull>;     // moves, no copy
    pub fn push_static(&mut self, bytes: &'static [u8]) -> Result<(), OutputFull>;
    pub fn push_file(&mut self, file: Arc<File>, offset: u64, len: u64) -> Result<(), OutputFull>;   // P2, 0.6.0
    pub fn begin_response(&mut self);
    pub fn begin_tagged_response(&mut self, tag: GateTag);      // the tag reaches the gate as WriteCheck::response
    pub fn end_response(&mut self);
    pub fn pending(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn wipe_all(&mut self);
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputFull;
```

What the session wants written, flushed when it returns `Step::Write` (or `Close`). Bounded by `Limits::output_budget` of pool memory per connection; `push_static` and file ranges do not count against it. On `OutputFull` the session returns `Step::Write`; after the flush it continues in `on_writable`, or in `on_data` if it left input unconsumed (see [`Step`](#step-phase)). Writes go out as vectored system calls of up to 64 chunks, each write preceded by the gate check (a retry after the socket was full sends only bytes the gate already approved, so a byte-counting gate counts them once; D-074). P0, Tier 3, `0.3.0`.

`begin_response` (or `begin_tagged_response`) and `end_response` mark response boundaries for the gate (`end_response` clears the tag): when the gate denies a write, the session's `on_denied` output is written only if no byte since the last `begin_response` has left; otherwise the connection is reset with no denial bytes mixed into a partial response. A session that never marks boundaries is treated as "started" after its first byte. Bytes already handed to the kernel cannot be recalled: responses that must be all-or-nothing are pushed in full before returning `Step::Write`. `wipe_all` overwrites every pending chunk net-io owns with zeroes and drops it.

---

## Server

A `Server` binds listeners, runs workers, and drives sessions under limits, a gate, the control line, and drain. The door (accepting) is separate from binding, so a process can bind privileged ports, drop privileges, and only then open the door.

### `ServerBuilder`

```rust
#[must_use]
pub struct ServerBuilder<W = NoWork, G = NoGate, S = NoopSink, T = NoTls> { /* ... */ }

impl ServerBuilder { pub fn new() -> ServerBuilder; }
impl<W, G, S, T> ServerBuilder<W, G, S, T> {
    pub fn listener(self, spec: ListenerSpec) -> Self;                   // repeatable, at most 64
    pub fn driver(self, kind: DriverKind) -> Self;                       // default Auto
    pub fn workers(self, n: u16) -> Self;                                // default: Blocking 128, Reactor = logical CPUs
    pub fn limits(self, limits: Limits) -> Self;
    pub fn sessions<F: SessionFactory>(self, factory: F) -> ServerBuilder<Sessions<F>, G, S, T>;
    pub fn handler<H>(self, handler: H) -> ServerBuilder<BlockingHandler<H>, G, S, T>
        where H: Fn(&mut TcpConnection) -> Result<(), NetError> + Send + Sync + 'static;
    pub fn gate<G2: Gate>(self, gate: G2) -> ServerBuilder<W, G2, S, T>;
    pub fn events<S2: EventSink>(self, sink: S2) -> ServerBuilder<W, G, S2, T>;
    pub fn tls<T2: TlsAcceptor>(self, acceptor: T2) -> ServerBuilder<W, G, S, T2>;
    pub fn trusted_proxies(self, proxies: TrustedProxies) -> Self;
    pub fn control<C: ControlLine>(self, line: Arc<C>) -> Self;
    pub fn placement(self, placement: Placement) -> Self;               // P2, 0.6.0: Off (default), PinPerCore, Explicit(Vec<usize>)
    pub fn wipe_buffers(self, on: bool) -> Self;                         // default true
    pub fn clock<K: Clock>(self, clock: Arc<K>) -> Self;                 // tests
    pub fn build(self) -> Result<Server, NetError>
        where W: Workload, G: Gate, S: EventSink, T: TlsAcceptor;
}

pub struct NoWork;   pub struct NoGate;                       // the unset states: `build` does not exist for them
pub struct Sessions<F> { /* the factory */ }                  // what `sessions` produces
pub struct BlockingHandler<H> { /* the handler */ }           // what `handler` produces
pub trait Workload: sealed::Sealed + Send + Sync + 'static {}  // implemented by Sessions<F> and BlockingHandler<H> only
```

A builder without a gate or without `sessions`/`handler` has no `build` method: forgetting either is a compile error that names the missing part (`the trait Gate is not implemented for NoGate`), not a run-time surprise. `build` validates everything else before it binds anything (limits resolved for the driver, caps against the descriptor limit, worker count, trusted proxies present when any listener requires PROXY, a TLS acceptor present when any listener has TLS on), then binds or adopts the listeners and starts the workers with the **door closed**. `Server` is not generic: the factory, gate, sink, and acceptor types live inside the workers, so the type a program holds stays `Server`.

| Item | Behaviour | Errors | Grade | Tier | Version |
|---|---|---|---|---|---|
| `new`, `listener`, `limits`, `sessions`, `handler`, `gate`, `events`, `build` | as above | `InvalidConfig` (`field` names the method), bind errors, `DriverSetup` | P0 | 2 | `0.3.0` |
| `driver` | `Auto` = the reactor where built and available, else blocking; an explicit kind that cannot start is an error | `DriverSetup` | P0 | 2 | `0.3.0` (reactor `0.5.0`) |
| `workers` | | `InvalidConfig` (0, or above 4,096) | P0 | 2 | `0.3.0` |
| `tls` | | | P0 | 2 | `0.4.0` |
| `trusted_proxies` | required when any listener has `ProxyMode::Required` | `InvalidConfig { field: "trusted_proxies", reason: Missing }` | P0 | 2 | `0.4.0` |
| `control` | | | P1 | 2 | `0.3.0` |
| `placement` | worker CPU placement | `Unsupported` on macOS for pinning | P2 | 2 | `0.6.0` |
| `wipe_buffers` | zero the used part of every buffer when it returns to a pool (on by default; turn off only for traffic that never carries secrets) | | P1 | 2 | `0.3.0` |
| `clock` | inject a [`ManualClock`](#time) | | P2 | 3 | `0.3.0` |

The gate is required: "no gate" is the visible choice `.gate(AllowAll)`, never a silent default (decision D-041).

`handler` and `sessions` are the two ways to say what runs per connection; the last one set wins. A blocking handler holds its worker for the whole connection, so `handler` runs on the blocking driver: `Auto` picks it, and an explicit `DriverKind::Reactor` fails `build` with `InvalidConfig { field: "driver", reason: Inconsistent }`. `Sessions<F>`, `BlockingHandler<H>`, `NoWork`, `NoGate`, and the sealed `Workload` trait exist only to make that compile-time check; programs never name them.

```rust,no_run
use net_io::{AllowAll, DriverKind, Limits, ListenerSpec, ServerBuilder};
use std::time::{Duration, Instant};

let server = ServerBuilder::new()
    .listener(ListenerSpec::tcp("0.0.0.0:8080").name("public"))
    .listener(ListenerSpec::tcp("127.0.0.1:9090").name("admin").lockdown_allowed(true))
    .driver(DriverKind::Blocking)
    .workers(64)
    .limits(Limits::builder().idle_timeout(Duration::from_secs(5)).build()?)
    .handler(|conn| { conn.send_all(b"hello\n")?; Ok(()) })
    .gate(AllowAll)
    .build()?;              // listeners bound, workers started, door closed
// ... drop privileges here ...
server.open_door()?;
let report = server.shutdown(Instant::now() + Duration::from_secs(30));
println!("{report:?}");
# Ok::<(), net_io::NetError>(())
```

### `ListenerSpec`

```rust
#[must_use]
pub struct ListenerSpec { /* source + options */ }
impl ListenerSpec {
    pub fn tcp<A: ToSocketAddrs>(addr: A) -> Self;                                  // resolved now; a failure is reported by build
    pub fn tcp_with<A: ToSocketAddrs>(addr: A, options: ListenOptions) -> Self;
    pub fn unix(path: impl Into<PathBuf>, options: LocalOptions) -> Self;          // P1, 0.4.0: see below
    #[cfg(windows)] pub fn pipe(name: &str, options: PipeOptions) -> Self;          // P1, 0.5.0
    pub fn adopt(listener: ListenerHandle) -> Self;                                 // P0, 0.4.0
    pub fn name(self, name: &str) -> Self;                                          // up to 64 bytes; events and hand-off
    pub fn proxy(self, mode: ProxyMode) -> Self;                                    // P0, 0.4.0
    pub fn tls(self, on: bool) -> Self;                                             // P0, 0.4.0
    pub fn limits(self, limits: Limits) -> Self;                                    // per-listener caps and deadlines
    pub fn lockdown_allowed(self, on: bool) -> Self;                                // P2, 0.6.0
}
```

One listener of a server. P0, Tier 2, `0.3.0` unless marked.

`unix` (feature `local`, Unix; Windows AF_UNIX in `0.5.0`, `Unsupported` until then) binds as `UnixListener::bind_with` at `build` and removes its file at shutdown only if it is still the one it created. Its connections carry `Transport::Unix`, the peer's credentials, and no IP address, so the per-source cap does not apply; `require_uid` refusals count as `RefusalCause::Credentials`. A `BlockingHandler` receives them as a `TcpConnection` (`info().transport` is `Unix`, `peer_addr` is unspecified, socket options fail). With `proxy`, every peer is trusted and no trusted list is needed: the socket file's mode decides who may connect (decision D-093). A name longer than 64 bytes, or a repeated name, fails `build` with `InvalidConfig { field: "name" }`.

### `Server`

```rust
#[must_use = "dropping a Server stops it; call wait_for_stop() to run until a stop is requested"]
pub struct Server { /* workers, listeners, door, handle */ }
impl Server {
    pub fn open_door(&self) -> Result<(), NetError>;
    pub fn close_door(&self);
    pub fn door(&self) -> DoorState;
    pub fn drain(&self, deadline: Instant) -> DrainReport;
    pub fn shutdown(self, deadline: Instant) -> DrainReport;
    pub fn wait_for_stop(self) -> DrainReport;
    pub fn release_listeners(&self) -> Result<Vec<ListenerHandle>, NetError>;
    pub fn adopt(&self, conn: TcpConnection, spec: AdoptSpec) -> Result<ConnectionId, NetError>;
    pub fn handle(&self) -> ServerHandle;
    pub fn stats(&self) -> Stats;
    pub fn listeners(&self) -> &[ListenerInfo];
}
impl Drop for Server;   // shutdown with the drain timeout as the deadline
```

| Item | Behaviour | Errors | Cost | Grade | Tier | Version |
|---|---|---|---|---|---|---|
| `open_door` | start accepting on every listener; a second call is a no-op; refused while draining | `ShuttingDown`, `ForkedChild` | NFR: accepting within 1 ms | P0 | 2 | `0.3.0` |
| `close_door` | stop accepting on every worker within one loop iteration; listening sockets stay open (the kernel backlog keeps new connections for the next process during a restart); idempotent | | under 1 ms p99 [est.] | P0 | 2 | `0.3.0` |
| `door` | `Open` or `Closed` | | one atomic load | P0 | 2 | `0.3.0` |
| `drain` | closes the door, tells every session to finish (`SessionContext::draining()`), closes idle connections at once, waits for the rest until `deadline`, then kills them with `DrainDeadline`; returns the counts | none (report) | 10,000 idle connections under 100 ms [est.] | P0 | 2 | `0.3.0` |
| `shutdown` | `drain`, then closes the listening sockets (except released ones) and joins every worker; afterwards no net-io thread runs and every descriptor net-io opened is closed | none (report) | | P0 | 2 | `0.3.0` |
| `wait_for_stop` | blocks the calling thread until a stop is requested (`ServerHandle::request_stop`, or the control line moves to `Draining` or `Stopping`), then shuts down with the drain deadline (the drain timeout or the control line's) | none (report) | zero CPU while waiting | P0 | 1 | `0.3.0` |
| `release_listeners` | owned duplicates of every listening socket, for [hand-off](#listener-hand-off); works while the door is open, so the new process can start accepting before this one stops (decision D-042); a later `shutdown` does not close the released sockets | `Os` | 1 system call per listener | P0 | 3 | `0.4.0` |
| `adopt` | registers a dialed connection exactly like an accepted one: new id, `Gate::admit` with `AdmitStage::Adopt`, the named listener's limits, sessions, kill handle, events | `Refused`, `Limit`, `ShuttingDown` | as accept | P1 | 3 | `0.4.0` |
| `handle` | a cloneable handle for other threads | | `Arc` clone | P0 | 2 | `0.3.0` |
| `stats` | sum of per-worker snapshots, each consistent (a worker's counters are read under a sequence lock, D-069) | | O(workers) | P1 | 2 | `0.3.0` |
| `listeners` | facts about each bound listener | | none | P0 | 2 | `0.3.0` |

A `Server` must not be used in a process created by `fork` after it was built: the cold calls (`open_door`, `adopt`, `shutdown`) check the process id and return `ForkedChild`.

### `ServerHandle`

```rust
#[derive(Clone)]
pub struct ServerHandle { /* shared door, control, worker queues */ }
impl ServerHandle {
    pub fn kill(&self, id: ConnectionId, reason: KillReason) -> bool;
    pub fn close_door(&self);
    pub fn request_stop(&self);
    pub fn wake_all(&self);
    pub fn completer(&self, worker: WorkerId) -> Option<Completer>;
    pub fn stats(&self) -> Stats;
    pub fn door(&self) -> DoorState;
}
```

`Send + Sync + Clone`, safe to call from any thread, including signal-handling threads. `kill` finds the owning worker from the id block, aborts the connection, and returns `false` if it was already closed or belongs to another server (under 1 µs to enqueue [est.]; the RST reaches the wire within 1 ms p99 [est.]). `request_stop` makes `Server::wait_for_stop` return after the drain; it does not block. `wake_all` interrupts every worker's wait so a control-line change is seen at once. P0 (`wake_all` P1), Tier 2, `0.3.0`.

```rust,no_run
// Ctrl-C style stop from another thread.
let server = net_io::serve("127.0.0.1:7000", |conn| { conn.send_all(b"hi\n")?; Ok(()) })?;
let handle = server.handle();
std::thread::spawn(move || {
    // ... wait for a signal from the application's signal library ...
    handle.request_stop();
});
let report = server.wait_for_stop();
println!("drained: {} graceful, {} killed in {:?}", report.graceful, report.killed, report.took);
# Ok::<(), net_io::NetError>(())
```

### `AdoptSpec`, `DrainReport`, `Stats`, `ListenerInfo`, `DoorState`

```rust
#[must_use]
pub struct AdoptSpec { /* listener name for limits, lane hint */ }
impl AdoptSpec { pub fn new(listener: &str) -> Self; pub fn lane(self, lane: Lane) -> Self; }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrainReport { pub graceful: u32, pub killed: u32, pub took: Duration }

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub open: u64, pub accepted: u64, pub refused: u64, pub closed: u64,
    pub bytes_in: u64, pub bytes_out: u64,
    pub egress_denied: u64, pub killed: u64, pub slow_peers: u64, pub timeouts: u64,
    pub descriptor_pressure: u64, pub stale_completions: u64, pub session_panics: u64,
}
impl Stats {
    pub fn refused_for(&self, cause: RefusalCause) -> u64;     // per cause (gate codes summed)
    pub fn closed_for(&self, reason: CloseReason) -> u64;      // per reason variant (inner values ignored)
    pub fn closes(&self) -> impl Iterator<Item = (CloseReason, u64)> + '_;      // non-zero counts, one per variant
    pub fn refusals(&self) -> impl Iterator<Item = (RefusalCause, u64)> + '_;
}

#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct ListenerInfo {
    pub id: ListenerId, pub name: Option<String>, pub local: Endpoint,
    pub backlog: Option<u32>,      // effective; None when it cannot be read (an adopted socket)
    pub transport: Transport, pub proxy: ProxyMode, pub tls: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DoorState { Open, Closed }
```

`Stats` counters are per-worker plain integers published as relaxed atomic snapshots once per loop iteration; no atomic touches the hot path. P0 (`Stats` P1), Tier 2, `0.3.0`. A `ListenerInfo` is built once at bind; its `name` is the only heap field and lives outside the hot path.

---

## Gate seam

The gate decides who may connect and whether bytes may still leave. net-io defines the trait and calls it at fixed points; a connection gate crate implements it (net-io never depends on the implementer). The two guarantees:

1. **No byte is read before the gate admits the connection.**
2. **No byte is written without passing the gate**: the gate is asked before every write (each `send`, each vectored write of a flush, each file chunk, each TLS ciphertext flush), and a retry after the socket was full sends only the bytes it approved. Even a handler that forgets every other checkpoint cannot send a byte on a revoked connection.

### `Gate`

```rust
pub trait Gate: Send + Sync + 'static {
    /// Per-connection state the gate keeps. net-io stores it beside the connection
    /// and passes it back on every call, so a check needs no lookup by id.
    type Ticket: Send + 'static;

    /// After accept and before any read (`Accept`), on `Server::adopt` (`Adopt`),
    /// or when a client connection gets a gate (`Dialed`).
    fn admit(&self, info: &ConnectionInfo, stage: AdmitStage) -> Result<Admitted<Self::Ticket>, Refusal>;

    /// After a trusted PROXY header revealed the real client (`info.real_peer` is set).
    fn readmit(&self, ticket: &mut Self::Ticket, info: &ConnectionInfo) -> Result<(), Refusal>;

    /// Before every write system call. The path where nothing is revoked should be one atomic load.
    fn check(&self, ticket: &mut Self::Ticket, write: &WriteCheck) -> Result<(), Denial>;

    /// Exactly once per admitted connection, after it closed, with its one close reason.
    fn closed(&self, ticket: Self::Ticket, info: &ConnectionInfo, reason: CloseReason) {
        let _ = (ticket, info, reason);
    }
}
```

| Method | net-io's reaction | Cost | Grade | Tier | Version |
|---|---|---|---|---|---|
| `admit` | `Ok`: the lane and the ticket are stored, the connection proceeds. `Err(refusal)`: closed abortively without reading; `Refusal::WithBytes` first writes its bytes with one non-blocking attempt (no retry) | hook cost plus under 20 ns [est.] | P0 | 3 | `0.3.0` (`Adopt`, `Dialed` `0.4.0`) |
| `readmit` | `Err`: closed abortively; the per-source cap moves from the proxy's address to the real client's before `readmit` runs | hook cost | P0 | 3 | `0.4.0` |
| `check` | `Err(Denial { code })`: every pending chunk net-io owns is overwritten with zeroes and dropped; if no byte of the current response has left, the session's `on_denied(code, ..)` output is written with one bounded attempt (the denial itself is not checked again); then abortive close with `EgressDenied(code)` | one call; with `AllowAll` it compiles to nothing; target under 2 ns with a one-atomic gate [est.] | P0 | 3 | `0.3.0` |
| `closed` | the ticket is given back with the reason (release counts, record strikes for `SlowPeer`, `ProxyInvalid`, `ProxyUntrusted`, `TlsFailed`, `HelloRefused`, timeouts) | hook cost | P0 | 3 | `0.3.0` |

Rules:

- **`readmit` has no default.** A gate that does not care about proxies writes `Ok(())` on purpose; a silent default would admit every real client behind a trusted proxy on the proxy's own verdict (decision D-060).
- **Fail closed.** A gate method that panics (unwind builds) counts as a refusal or a denial. Refusals and denials are abortive.
- **Static dispatch.** Each worker loop is compiled for the server's gate type, so the hooks are direct calls.
- **Where the checks run.** `admit` on the accepting worker (blocking driver: the accept thread) before the socket is registered for reading; `check` on the worker that writes; `closed` on the worker that closed the connection. A gate must be `Sync`.
- **Denial text belongs to the session**, which knows the protocol and its framing state (an HTTP response boundary, a WebSocket frame, a database frame). The gate gives only a code.
- **Ejecting idle connections** from a gate's own maintenance thread uses [`ServerHandle::kill`](#serverhandle) with the `ConnectionId` in `ConnectionInfo`.

```rust
use net_io::{Admitted, AdmitStage, CloseReason, ConnectionInfo, Denial, Gate, Lane, Refusal, WriteCheck};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// A gate with one global kill switch and a count of open connections.
struct Switch { revoked: AtomicBool, open: AtomicU64 }

impl Gate for Switch {
    type Ticket = ();

    fn admit(&self, info: &ConnectionInfo, _stage: AdmitStage) -> Result<Admitted<()>, Refusal> {
        if self.revoked.load(Ordering::Acquire) {
            return Err(Refusal::Reset { code: 1 });
        }
        let lane = if info.client_addr().is_some_and(|a| a.ip().is_loopback()) { Lane(0) } else { Lane(3) };
        self.open.fetch_add(1, Ordering::Relaxed);
        Ok(Admitted { lane, ticket: (), tag: net_io::GateTag(0) })
    }

    fn readmit(&self, _ticket: &mut (), _info: &ConnectionInfo) -> Result<(), Refusal> {
        Ok(())
    }

    fn check(&self, _ticket: &mut (), _write: &WriteCheck) -> Result<(), Denial> {
        if self.revoked.load(Ordering::Acquire) { Err(Denial { code: 503 }) } else { Ok(()) }
    }

    fn closed(&self, _ticket: (), _info: &ConnectionInfo, _reason: CloseReason) {
        self.open.fetch_sub(1, Ordering::Relaxed);
    }
}
# let _ = Arc::new(Switch { revoked: AtomicBool::new(false), open: AtomicU64::new(0) });
```

### `AdmitStage`, `Admitted`, `Refusal`

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AdmitStage { Accept, Adopt, Dialed }

#[derive(Debug)]
pub struct Admitted<T> { pub lane: Lane, pub ticket: T, pub tag: GateTag }

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Reset { code: u16 },
    WithBytes { code: u16, bytes: &'static [u8] },   // at most Limits::refusal_bytes_max (512)
}
```

`WithBytes` lets a gate answer a refused connection with a canned protocol reply (for example `HTTP/1.1 503` with `Retry-After`) straight from the accept path: one non-blocking write of at most 512 bytes, only on TCP after the handshake completed (so it cannot amplify a spoofed source), then RST. Longer bytes fail fast: the refusal is sent as `Reset` and a `LimitHit` event is emitted. The code appears in `RefusalCause::Gate(code)`, events, and stats. P0, Tier 3, `0.3.0`.

### `WriteCheck`, `Denial`

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteCheck {
    pub id: ConnectionId,
    pub lane: Lane,
    pub bytes: u32,                 // size of the chunk about to be written
    pub response_started: bool,     // a byte of the current response already left
    pub response: Option<GateTag>,  // the tag the session gave Output::begin_tagged_response
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Denial { pub code: u16 }

impl WriteCheck {
    pub fn new(id: ConnectionId, lane: Lane, bytes: u32, response_started: bool, response: Option<GateTag>) -> WriteCheck;   // for tests
}
```

P0, Tier 3, `0.3.0`. `WriteCheck::new` and `ConnectionInfo::for_testing` let a gate be unit-tested without a socket.

### `AllowAll`

```rust
#[derive(Clone, Copy, Debug, Default)]
pub struct AllowAll;
impl Gate for AllowAll { type Ticket = (); /* admits every connection in Lane(0) with GateTag(0), never denies */ }
```

The explicit "no gate". `ServerBuilder` requires a gate, so a server without one says `.gate(AllowAll)` in its code; the Tier 1 functions use it and their documentation says so. With `AllowAll` the checks compile to nothing. P0, Tier 2, `0.3.0`.

### `KillHandle`

```rust
#[derive(Clone)]
pub struct KillHandle { /* worker index, id, generation, shared command queue */ }
impl KillHandle {
    pub fn kill(&self, reason: KillReason) -> bool;   // false if the connection already closed
    pub fn id(&self) -> ConnectionId;
    pub fn is_open(&self) -> bool;                    // a snapshot; for diagnostics only
}
```

Aborts one connection from any thread: the closing flag is set with one compare-and-swap, the owning worker is woken (blocking driver: on Unix `shutdown` of the read side wakes a blocked receive and the worker's wake pipe wakes a stalled send; on Windows the waiter's wake socket; reactor: a command on the worker's queue), and the worker closes with RST and emits the one closed event. The killing thread never closes the descriptor itself, so it can never close a reused descriptor number. A kill racing a FIN, a timeout, or another kill produces one close with the reason that won the compare-and-swap; the others return `false`. `Send + Sync + Clone`. P0, Tier 2, `0.3.0`; under 1 µs to enqueue [est.].

---

## Control line

```rust
pub trait ControlLine: Send + Sync + 'static {
    fn epoch(&self) -> u64;                 // Acquire load; changes on every state change
    fn state(&self) -> ControlState;        // read only when the epoch moved
    fn deadline(&self) -> Option<Instant>;  // for Draining
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlState { Normal, Shed { from_lane: Lane }, Lockdown, Draining, Stopping }

#[derive(Clone, Copy, Debug, Default)]
pub struct NoControl;                       // epoch() is always 0

#[derive(Debug, Default)]
pub struct SimpleControl { /* AtomicU64 epoch, state, deadline */ }
impl SimpleControl {
    pub fn new() -> Self;
    pub fn set(&self, state: ControlState, deadline: Option<Instant>);
}
impl ControlLine for SimpleControl;
```

A process-wide signal that every worker reads with one atomic load at the top of each loop iteration, before each accept batch, and before each admission. P1, Tier 3 (`SimpleControl` Tier 2), `0.3.0`; about 1 ns per read [est.].

| State | net-io's reaction |
|---|---|
| `Normal` | none; undoes the reactions below |
| `Shed { from_lane }` | refuses new connections in `from_lane` and every less important lane (numbers at or above it; `RefusalCause::Shed`); closes idle connections in those lanes at once and busy ones at their next idle point (`CloseReason::Shed`); `SessionContext::pressure()` reports 1.0 so protocols stop keep-alive |
| `Lockdown` | refuses new connections on listeners not marked `lockdown_allowed`; existing connections are not touched |
| `Draining` | `close_door`, then `drain` with the line's deadline (or the drain timeout); the accept thread runs the drain, so it happens whether or not the program waits in `wait_for_stop` (D-075) |
| `Stopping` | kills every remaining connection with `Shutdown` |

`ServerHandle::wake_all` makes workers that sleep in the kernel see a change at once. Reactions are idempotent and epoch-gated: a line that moves `Normal`, `Shed`, `Normal` within one loop iteration is seen only in its final state.

```rust,no_run
use net_io::{AllowAll, ControlState, Lane, ListenerSpec, ServerBuilder, SimpleControl};
use std::sync::Arc;

let control = Arc::new(SimpleControl::new());
let server = ServerBuilder::new()
    .listener(ListenerSpec::tcp("0.0.0.0:8080"))
    .handler(|conn| { conn.send_all(b"ok\n")?; Ok(()) })
    .gate(AllowAll)
    .control(control.clone())
    .build()?;
server.open_door()?;
// Under overload: refuse everything but lanes 0 and 1.
control.set(ControlState::Shed { from_lane: Lane(2) }, None);
server.handle().wake_all();
# Ok::<(), net_io::NetError>(())
```

---

## Completer

```rust
#[derive(Clone)]
pub struct Completer { /* shared bounded ring, the worker's waker */ }
impl Completer {
    pub fn post(&self, connection: ConnectionId, token: u32, value: u64) -> Result<(), PostError>;
    pub fn worker(&self) -> WorkerId;
    pub fn capacity(&self) -> usize;
}
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PostError { Full, WrongWorker, ServerStopped }
```

A per-worker queue that other threads use to hand a result back to a connection that parked while slow work (a password hash, a database call) ran elsewhere. The session returns `Step::Park`, the connection stops reading (bytes wait in the kernel, the receive window slows the peer), and the worker serves others; when the other thread posts, the worker is woken and calls `Session::on_wake(token, value)`. P0, Tier 3, `0.3.0` (blocking), `0.5.0` (reactor).

- Bounded multi-producer, single-consumer ring (power-of-two capacity, `Limits::completion_queue`), with a sequence number per slot, no allocation, model-checked with loom.
- `post` never blocks: `Full` when the ring is full (the poster decides, for example answer 503), `WrongWorker` when the id belongs to another worker's id block, `ServerStopped` after shutdown.
- One wake per burst: the poster wakes the worker only when the ring goes from empty to non-empty.
- A completion for a connection that closed meanwhile is dropped and counted (`Event::StaleCompletion`); it can never reach another connection that reused the slot (generation check).
- The value is a `u64` (for example an index into the caller's own table), so there is nothing to allocate or drop.

Cost: under 50 ns per post; 1 to 5 µs to wake a sleeping worker; under 10 µs p99 from `post` to `on_wake` on an idle worker [est.].

```rust,no_run
use net_io::{Input, Session, SessionContext, Step};
use std::time::Instant;

const HASH_DONE: u32 = 1;

struct Login { waiting: bool }
impl Session for Login {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let n = input.bytes().len();
        input.consume(n);
        let completer = cx.completer();
        let id = cx.info().id;
        std::thread::spawn(move || {
            let verdict = 1u64; // ... an expensive hash ...
            let _ = completer.post(id, HASH_DONE, verdict);
        });
        self.waiting = true;
        Step::Park { until: Some(cx.now() + std::time::Duration::from_secs(5)) }
    }
    fn on_wake(&mut self, cx: &mut SessionContext<'_>, token: u32, value: u64) -> Step {
        if token == HASH_DONE && value == 1 {
            let _ = cx.output().push_static(b"welcome\n");
        }
        self.waiting = false;
        Step::Write
    }
}
# let _ = Instant::now();
```

---

## Events

```rust
pub trait EventSink: Send + Sync + 'static { fn event(&self, event: &Event); }

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopSink;
impl EventSink for NoopSink { #[inline(always)] fn event(&self, _: &Event) {} }

#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub enum Event {
    ListenerOpened { listener: ListenerId, local: Option<SocketAddr>, backlog: Option<u32> },
    DoorOpened,
    DoorClosed,
    Accepted { id: ConnectionId, peer: Option<SocketAddr>, listener: ListenerId },
    Refused { peer: Option<SocketAddr>, cause: RefusalCause },
    Admitted { id: ConnectionId, lane: Lane },
    ProxyResolved { id: ConnectionId, real_peer: SocketAddr },
    HandshakeDone { id: ConnectionId, took: Duration },
    LimitHit { id: Option<ConnectionId>, which: LimitKind },
    Killed { id: ConnectionId, reason: KillReason },
    EgressDenied { id: ConnectionId, code: u16 },
    Closed { id: ConnectionId, reason: CloseReason, bytes_in: u64, bytes_out: u64, lifetime: Duration },
    AcceptError { listener: ListenerId, class: OsErrorClass },
    DescriptorPressure { listener: ListenerId, backoff: Duration },
    ListenerFailed { listener: ListenerId, class: OsErrorClass },
    DrainStarted { open: u32 },
    DrainFinished { graceful: u32, killed: u32 },
    ControlReacted { state: ControlState },
    StaleCompletion { worker: WorkerId },
    SessionPanicked { id: ConnectionId },
    DriverFallback { wanted: DriverKind, using: DriverKind },
    Coalesced { kind: CoalescedKind, count: u32 },
}
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoalescedKind { Refused(RefusalCause), LimitHit(LimitKind) }
```

Typed, fixed-size events (at most 64 bytes, `Copy`, borrowing nothing) for logs, metrics, and detection. The sink is a type parameter of the builder (`ServerBuilder::events`), so `NoopSink`, the default, compiles to nothing and a real sink is one static call per event. Under a flood, `Refused` and `LimitHit` events above 1,000 per second per worker are folded into one `Coalesced` event per second with the count, so the sink cannot become the bottleneck. P0, Tier 3 (Tier 2 for implementers), `0.3.0`. The sink runs on worker threads: it should copy what it needs into its own queue and return.

```rust
use net_io::{CoalescedKind, Event, EventSink};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
struct Counts { closed: AtomicU64, refused: AtomicU64, limits: AtomicU64 }
impl EventSink for Counts {
    fn event(&self, event: &Event) {
        match event {
            Event::Closed { .. } => { self.closed.fetch_add(1, Ordering::Relaxed); }
            Event::Refused { .. } => { self.refused.fetch_add(1, Ordering::Relaxed); }
            Event::LimitHit { .. } => { self.limits.fetch_add(1, Ordering::Relaxed); }
            Event::Coalesced { kind: CoalescedKind::Refused(_), count } => { self.refused.fetch_add(u64::from(*count), Ordering::Relaxed); }
            Event::Coalesced { kind: CoalescedKind::LimitHit(_), count } => { self.limits.fetch_add(u64::from(*count), Ordering::Relaxed); }
            _ => {}
        }
    }
}
```

---

## Buffers

```rust
pub struct Buffer { /* boxed byte slice from a pool, length, size class */ }
impl Buffer {
    pub fn as_slice(&self) -> &[u8];          // the filled part
    pub fn as_mut_slice(&mut self) -> &mut [u8];
    pub fn spare(&mut self) -> &mut [u8];     // the unfilled tail
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn set_len(&mut self, n: usize);      // saturates at capacity
    pub fn capacity(&self) -> usize;
    pub fn class(&self) -> SizeClass;
    pub fn clear(&mut self);
}

pub struct BufferPool { /* per worker: one free list per size class */ }
impl BufferPool {
    pub fn standalone(bytes: u64) -> BufferPool;                      // its own budget, for use outside a server
    pub fn take(&mut self, class: SizeClass) -> Option<Buffer>;
    pub fn put(&mut self, buffer: Buffer);
    pub fn stats(&self) -> PoolStats;
}
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PoolStats { pub allocated: u64, pub free: u64, pub budget_left: u64, pub budget_refusals: u64 }
```

Every byte net-io reads lands in a pooled `Buffer`. Each worker owns a pool per size class (4, 16, and 64 KiB by default); a buffer is allocated on first need, never freed while the server runs, and returned to a pool on release. The sum of all buffers ever allocated by all workers is bounded by `Limits::buffer_budget`: when a pool is empty and the budget is spent, `take` returns `None`, the connection stops reading (the kernel's receive window then slows the peer), and `LimitHit { which: BufferBudget }` is emitted at most once per second per worker. Idle connections on the reactor hold no read buffer. P0, Tier 3, `0.3.0`; `take` and `put` under 10 ns plus the wipe [est.].

**Wipe on release** (default on, decision D-027): the used prefix of a buffer is overwritten with zeroes using writes the optimizer cannot remove before it returns to a pool, so request bytes (credentials, tokens) never leak into another connection. Cost 50 to 100 ns per 2 KiB [est.]. `ServerBuilder::wipe_buffers(false)` turns it off for traffic that carries no secrets.

**Ownership with asynchronous drivers:** a buffer given to the kernel (IOCP, io_uring) belongs to the operation until its completion is reaped, even when the connection is killed; no safe call can drop or reuse it earlier. A buffer returned to a different worker's pool is accepted and counted there.

---

## Time

```rust
pub trait Clock: Send + Sync + 'static { fn now(&self) -> Instant; }

#[derive(Clone, Copy, Debug, Default)]
pub struct MonotonicClock;                  // Instant::now()
impl Clock for MonotonicClock;

#[derive(Debug)]
pub struct ManualClock { /* starts at a fixed Instant */ }
impl ManualClock {
    pub fn new() -> Self;
    pub fn advance(&self, by: Duration);
    pub fn set(&self, at: Instant);         // never earlier than the current value
}
impl Clock for ManualClock;
```

All deadlines run on one hierarchical timing wheel per worker: 6 levels of 64 slots, tick `Limits::tick` (1 ms by default), covering about 2.2 years at 1 ms; later deadlines go to an overflow list re-examined when the top level wraps. Timer slots are part of each connection's record, so inserting and cancelling allocate nothing. Extending a deadline (every read resets the idle timer) only stores the new time; the wheel entry is moved only when it fires early. A timer never fires before its deadline; a clock that jumps forward (a resumed VM) fires every expired timer once, in order, at most 1,024 per loop iteration so IO is not starved. With no IO and no timer due, every net-io thread sleeps in the kernel: no periodic tick. P1 (`Clock`, `ManualClock`), Tier 3, `0.3.0`; insert and cancel under 20 ns, extend under 2 ns [est.].

```rust,no_run
use net_io::{AllowAll, ListenerSpec, ManualClock, ServerBuilder};
use std::sync::Arc;
use std::time::Duration;

// Deterministic timeout tests: time moves only when the test says so.
let clock = Arc::new(ManualClock::new());
let server = ServerBuilder::new()
    .listener(ListenerSpec::tcp("127.0.0.1:0"))
    .handler(|_conn| Ok(()))
    .gate(AllowAll)
    .clock(clock.clone())
    .build()?;
clock.advance(Duration::from_secs(61)); // every idle connection's deadline passes
server.handle().wake_all();
# Ok::<(), net_io::NetError>(())
```

---

## Drivers

```rust
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum DriverKind { Blocking, Reactor, Uring, #[default] Auto }
```

P0, Tier 2, `0.3.0`.

| | Blocking pool | Reactor | io_uring |
|---|---|---|---|
| Version | `0.3.0` | `0.5.0` | after `1.0.0` (P3, feature `uring`) |
| Threads | `workers` (default 128, 256 KiB stacks) plus one accept thread per listener | one per logical CPU by default, each with its own epoll, kqueue, or IOCP port | one per CPU, one ring each |
| Connections per worker | one at a time | thousands | thousands |
| Idle connection memory | a parked thread's stack pages | connection state only (target under 512 B), no read buffer (IOCP: zero-byte receives) | connection state, shared provided buffers |
| Best for | tens to low thousands of concurrent connections; shared hosting; development; CI; a first deployment behind a reverse proxy | thousands to hundreds of thousands, many idle keep-alive or WebSocket connections | highest throughput with large batches on Linux hosts that permit io_uring |

`Auto` picks the reactor where it is built and available, otherwise the blocking pool. `Uring` falls back to epoll when `io_uring_setup` fails (`EPERM`, `ENOSYS`, seccomp, `kernel.io_uring_disabled`) and emits `DriverFallback`; it is never the default (decision D-015).

The driver interface itself becomes public (Tier 3) at `0.5.0` so an executor adapter and future drivers can build on it. Its shape is fixed now; it is marked "unstable until 1.0" in rustdoc and frozen at `1.0.0` (decision D-029):

```rust
pub trait Driver: Send {
    fn kind(&self) -> DriverKind;
    fn register(&mut self, socket: BorrowedSocket<'_>, token: Token) -> Result<(), NetError>;
    fn submit(&mut self, operation: Operation) -> Result<(), Rejected>;   // Rejected gives the operation and its buffers back
    fn wait(&mut self, out: &mut Completions, timeout: Option<Duration>) -> Result<usize, NetError>;
    fn cancel(&mut self, token: Token, which: OperationKind) -> Result<(), NetError>;  // always followed by exactly one completion
    fn deregister(&mut self, token: Token) -> Result<(), NetError>;
    fn waker(&self) -> DriverWaker;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)] pub struct Token(pub u64);
#[non_exhaustive] pub enum Operation {
    Accept { listener: Token },
    Receive { token: Token, buffer: Buffer },
    ReceiveZero { token: Token },                              // IOCP readiness for idle connections
    Send { token: Token, chunks: SendChunks },
    SendFile { token: Token, file: Arc<File>, offset: u64, len: u32 },
    Connect { token: Token, addr: SocketAddr },
    Close { token: Token, abortive: bool },
    Nop { token: Token },
}
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum OperationKind { Accept, Receive, Send, SendFile, Connect, Close, Nop }
#[non_exhaustive] pub struct Completion { pub token: Token, pub kind: OperationKind, pub result: Result<usize, OsErrorClass>, pub buffer: Option<Buffer> }
pub struct Completions { /* fixed capacity, 256 entries; wait never allocates */ }
pub struct SendChunks { /* up to 64 chunks: pool buffers, &'static slices; taken from Output */ }
pub struct Rejected { pub operation: Operation }
#[derive(Clone)] pub struct DriverWaker { /* eventfd, EVFILT_USER, IOCP port, or parker */ }
impl DriverWaker { pub fn wake(&self); }
#[cfg(unix)] pub type BorrowedSocket<'a> = BorrowedFd<'a>;
#[cfg(windows)] pub type BorrowedSocket<'a> = std::os::windows::io::BorrowedSocket<'a>;
```

Completion-shaped (decision D-005): operations own their buffers until the completion returns them, which is what IOCP and io_uring need; epoll and kqueue adapt by doing the non-blocking call when readiness arrives. Cancellation always ends in exactly one completion. P2, Tier 3, `0.5.0`.

---

## UDP

Feature `udp`.

```rust
pub struct UdpSocket { /* owned socket, amplification guard, source budgets */ }
impl UdpSocket {
    pub fn bind<A: ToSocketAddrs>(addr: A) -> Result<UdpSocket, NetError>;
    pub fn bind_with<A: ToSocketAddrs>(addr: A, options: UdpOptions) -> Result<UdpSocket, NetError>;
    pub fn recv_from(&mut self, buf: &mut [u8]) -> Result<Datagram, NetError>;
    pub fn send_to(&mut self, buf: &[u8], to: SocketAddr) -> Result<usize, NetError>;
    pub fn connect(&mut self, to: SocketAddr) -> Result<(), NetError>;
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<Datagram, NetError>;
    pub fn send(&mut self, buf: &[u8]) -> Result<usize, NetError>;
    pub fn mark_verified(&mut self, peer: SocketAddr);
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<(), NetError>;
    pub fn local_addr(&self) -> Result<SocketAddr, NetError>;
    pub fn recv_batch(&mut self, bufs: &mut [DatagramBuffer]) -> Result<usize, NetError>;      // P2, 0.6.0
    pub fn send_batch(&mut self, datagrams: &[OutgoingDatagram<'_>]) -> Result<usize, NetError>; // P2, 0.6.0
    pub fn join_multicast(&self, group: IpAddr, interface: MulticastInterface) -> Result<(), NetError>; // P2, 0.6.0
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Datagram { pub len: usize, pub from: SocketAddr, pub truncated: bool, pub destination: Option<IpAddr> }

#[must_use]
#[derive(Clone, Debug)]
pub struct UdpOptions { /* ... */ }
impl UdpOptions {
    pub fn new() -> Self;
    pub fn amplification_factor(self, factor: u8) -> Self;     // 1 by default, at most 3
    pub fn source_budget(self, budget: UdpBudget) -> Self;
    pub fn global_budget(self, budget: UdpBudget) -> Self;
    pub fn source_table(self, entries: u32) -> Self;            // 65,536 by default
    pub fn packet_info(self, on: bool) -> Self;                 // P2, 0.6.0
    pub fn ipv6_only(self, on: bool) -> Self;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpBudget { pub datagrams_per_sec: u32, pub bytes_per_sec: u32, pub burst: u32 }

// P2, 0.6.0: batches and multicast
pub struct DatagramBuffer<'a> { pub buf: &'a mut [u8], pub datagram: Option<Datagram> }   // filled by recv_batch
pub struct OutgoingDatagram<'a> { pub bytes: &'a [u8], pub to: SocketAddr }
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MulticastInterface { Any, V4(Ipv4Addr), V6Index(u32) }

// P2, 0.6.0: datagram sessions on the reactor
pub trait UdpSession: Send + 'static {
    fn on_datagram(&mut self, cx: &mut UdpContext<'_>, from: SocketAddr, bytes: &[u8]);
}
pub struct UdpContext<'a> { /* send_to (guarded), mark_verified, now, worker */ }
impl UdpContext<'_> {
    pub fn send_to(&mut self, bytes: &[u8], to: SocketAddr) -> Result<usize, NetError>;
    pub fn mark_verified(&mut self, peer: SocketAddr);
    pub fn now(&self) -> Instant;
}
// ListenerSpec::udp(addr, options) with ServerBuilder::udp_sessions(factory) runs them on the reactor workers
```

UDP source addresses are trivially spoofed, so the socket protects others and itself by default:

| Item | Behaviour | Errors | Cost | Grade | Tier | Version |
|---|---|---|---|---|---|---|
| `bind`, `bind_with` | close-on-exec; peers normalized | bind errors | one-time | P1 | 1 / 2 | `0.4.0` |
| `recv_from`, `recv` | a datagram larger than `buf` is reported with `truncated: true` and its real length where the OS gives it (`MSG_TRUNC` on Linux, `WSAEMSGSIZE` on Windows), never as a silently cut datagram; a zero-length datagram is valid; datagrams from sources over their budget are read, dropped, and counted before returning; ICMP "port unreachable" reports (`ECONNREFUSED`, Windows `WSAECONNRESET`) never end the socket | `TimedOut`, `Os` | 1 system call plus the budget check [est. under 30 ns] | P1 | 1 | `0.4.0` |
| `send_to`, `send` | **no amplification**: to a peer not marked verified, the bytes sent never exceed `factor x` the bytes received from it within the window; otherwise `Limit { which: Amplification }` and nothing is sent | `Limit`, `Os` | 1 system call plus the guard | P1 | 1 | `0.4.0` |
| `connect` | fixes the peer; the kernel filters other sources | `Os` | one-time | P1 | 2 | `0.4.0` |
| `mark_verified` | the protocol proved the peer can receive (a cookie, a handshake); lifts the guard for it | | O(1) | P1 | 2 | `0.4.0` |
| source table | bounded (default 65,536 entries) with CLOCK eviction; when full, unknown sources share one small overflow budget (strangers lose first, verified peers keep their entries) | | O(1) | P1 | 2 | `0.4.0` |
| `recv_batch`, `send_batch` | `recvmmsg` / `sendmmsg` on Linux, a loop elsewhere | | 1 system call per batch on Linux | P2 | 3 | `0.6.0` |
| packet info (`destination`) | `IP_PKTINFO`, `IPV6_RECVPKTINFO` | `Unsupported` | ancillary data parse | P2 | 3 | `0.6.0` |
| `join_multicast` | IPv4 and IPv6 groups | `Os` | | P2 | 2 | `0.6.0` |
| `UdpSession`, `UdpContext`, `ListenerSpec::udp`, `ServerBuilder::udp_sessions` | datagrams driven like connections on the reactor: the same guard and budgets, the same events and drain | as `send_to` | per datagram: one dispatch | P2 | 3 | `0.6.0` |
| GSO, GRO | `UDP_SEGMENT`, `UDP_GRO` (Linux) | `Unsupported` | | P3 | 3 | after `1.0.0` |

The amplification factor defaults to 1 (decision D-034); a QUIC implementation sets 3 for its own handshake, as RFC 9000 allows.

```rust,no_run
let mut socket = net_io::UdpSocket::bind("0.0.0.0:5353")?;
let mut buf = [0u8; 1500];
loop {
    let datagram = socket.recv_from(&mut buf)?;
    if datagram.truncated {
        continue; // larger than we accept
    }
    // Replies are limited to the size of what the peer sent until it is verified.
    socket.send_to(&buf[..datagram.len], datagram.from)?;
}
# Ok::<(), net_io::NetError>(())
```

---

## Local sockets

Feature `local`.

### Unix domain sockets

```rust
pub struct UnixListener { /* path, owned socket, inode of the created file */ }
impl UnixListener {
    pub fn bind<P: AsRef<Path>>(path: P) -> Result<UnixListener, NetError>;
    pub fn bind_with<P: AsRef<Path>>(path: P, options: LocalOptions) -> Result<UnixListener, NetError>;
    pub fn bind_atomic<P: AsRef<Path>>(path: P, options: LocalOptions) -> Result<UnixListener, NetError>;
    #[cfg(target_os = "linux")]
    pub fn bind_abstract(name: &[u8], options: LocalOptions) -> Result<UnixListener, NetError>;   // P3
    pub fn accept(&self) -> Result<(UnixConnection, ConnectionInfo), NetError>;
    pub fn accept_timeout(&self, timeout: Duration) -> Result<Option<(UnixConnection, ConnectionInfo)>, NetError>;
    pub fn info(&self) -> &ListenerInfo;
    pub fn path(&self) -> Option<&Path>;                       // the final path (recorded, not read back: decision D-058)
}
impl Drop for UnixListener;   // removes its path only if it is still the file this listener created

pub struct UnixConnection { /* owned socket, ConnectionInfo, limits, kill state */ }
impl UnixConnection {
    pub fn connect<P: AsRef<Path>>(path: P) -> Result<UnixConnection, NetError>;
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize, NetError>;
    pub fn recv_exact(&mut self, buf: &mut [u8]) -> Result<(), NetError>;
    pub fn send(&mut self, buf: &[u8]) -> Result<usize, NetError>;
    pub fn send_all(&mut self, buf: &[u8]) -> Result<(), NetError>;
    pub fn shutdown(&mut self, how: Shutdown) -> Result<(), NetError>;
    pub fn close(self) -> Result<(), NetError>;
    pub fn abort(self);
    pub fn info(&self) -> &ConnectionInfo;
    pub fn id(&self) -> ConnectionId;
    pub fn kill_handle(&self) -> KillHandle;
    pub fn set_limits(&mut self, limits: Limits);
    pub fn set_phase(&mut self, phase: Phase);
    pub fn set_exchange_deadline(&mut self, at: Option<Instant>);
    pub fn peer_credentials(&self) -> Result<PeerCredentials, NetError>;
    #[cfg(unix)] pub fn send_descriptors(&mut self, body: &[u8], descriptors: &[BorrowedFd<'_>]) -> Result<(), NetError>;
    #[cfg(unix)] pub fn recv_descriptors(&mut self, body: &mut [u8], into: &mut Descriptors) -> Result<usize, NetError>;
}
#[cfg(unix)] pub struct Descriptors { /* fixed capacity 64 OwnedFd */ }
#[cfg(unix)] impl Descriptors { pub fn new() -> Self; pub fn len(&self) -> usize; pub fn is_empty(&self) -> bool; pub fn take(&mut self) -> impl Iterator<Item = OwnedFd> + '_; }
impl Read for UnixConnection; impl Write for UnixConnection; impl Drop for UnixConnection;   // as TcpConnection

#[must_use]
#[derive(Clone, Debug)]
pub struct LocalOptions { /* ... */ }
impl LocalOptions {
    pub fn new() -> Self;                       // mode 0o600, remove_stale true
    pub fn mode(self, mode: u32) -> Self;
    pub fn owner(self, uid: u32) -> Self;
    pub fn group(self, gid: u32) -> Self;       // sets the socket file's group; the mode stays 0o600
    pub fn group_access(self, gid: u32) -> Self; // group(gid) and mode 0o660: members of that group may connect
    pub fn remove_stale(self, on: bool) -> Self;
    pub fn require_uid(self, uid: u32) -> Self; // refuse peers with another uid (checked at accept)
    pub fn backlog(self, backlog: u32) -> Self; // default 1,024, capped by the OS
}
```

| Item | Behaviour | Errors | Grade | Tier | Version |
|---|---|---|---|---|---|
| `bind`, `bind_with` | path length checked (Linux 108 bytes, macOS and FreeBSD 104, including the terminator); a NUL byte in the path is refused (`InvalidConfig { field: "path", reason: Malformed }`); a stale socket file is removed only if `lstat` (no symlink following) says it is a socket and a connect to it is refused, while a live socket, a regular file, a directory, or a symbolic link is left alone and fails with `StaleSocketInUse`; then `bind`, `chmod` and `lchown` (when set) on the file the bind created (its device and inode checked before and after), and only then `listen`, so no connection is ever accepted under the umask's permissions (decision D-091). Cost [est.]: two to three `lstat`, one probe connect when a file exists, and the `chmod`, once per bind | `PathTooLong`, `StaleSocketInUse`, `PermissionDenied`, `NotFound` (no such directory), `InvalidConfig`, `Os` | P1 | 1 / 2 | `0.4.0` |
| `bind_atomic` | as `bind_with`, but bound under `.<name>.<pid>.<n>` in the same directory and renamed into place after `listen`, so the path never names a socket that refuses or has the wrong mode | as `bind` | P1 | 2 | `0.4.0` |
| `accept`, `accept_timeout` | the accept discipline of `TcpListener` (reserve descriptor, backoff); peer credentials read once (one `getsockopt`, under 1 µs [est.]) and stored in `ConnectionInfo`; `require_uid` closes a mismatched peer, or one whose uid the OS did not report, before any read, and accepting continues | `Limit { which: Descriptors }`, `Os` | P1 | 1 | `0.4.0` |
| `Drop` | unlinks the path only if `lstat` still shows the inode this listener created, never a replacement someone else bound | none (event) | P1 | 1 | `0.4.0` |
| `UnixConnection` IO | as `TcpConnection`: the same connection core, limits, deadlines, kill handle, and close behaviour (decision D-093) | as `TcpConnection` | P1 | 1 | `0.4.0` |
| `UnixConnection::connect` | blocking connect; a full backlog waits up to 10 s (`SO_SNDTIMEO`); no socket at the path and a socket nobody listens on are both `NotFound` (decision D-092) | `NotFound`, `PermissionDenied`, `TimedOut { kind: Connect }`, `PathTooLong` | P1 | 1 | `0.4.0` |
| `peer_credentials` | see [`PeerCredentials`](#peercredentials) | `Unsupported` | P1 | 2 | `0.4.0` (Windows `0.5.0`) |
| `send_descriptors`, `recv_descriptors` | `SCM_RIGHTS`, at most 64 descriptors per message, attached to the first byte of a non-empty body that is sent in full (one gate check for the body); received through the connection's normal read path (deadlines, kill, drain), close-on-exec (`MSG_CMSG_CLOEXEC` on Linux; on macOS `FD_CLOEXEC` right after the receive, so a `fork` plus `exec` on another thread in between can inherit one); a truncated control message (`MSG_CTRUNC`) closes every descriptor received and fails the connection, since its bytes can no longer be framed (decision D-094); on a TLS connection both are `Unsupported` | `Handoff(Truncated)`, `InvalidConfig` (empty body, more than 64), `Unsupported`, `Os` | P0 | 3 | `0.4.0` |
| Windows AF_UNIX | `UnixListener` and `UnixConnection` on Windows 10 1803+: stream sockets only, no descriptor passing; permissions are NTFS ACLs; the socket file is deleted with `DeleteFileW` before rebinding | `Unsupported` on older Windows | P2 | 2 | `0.5.0` |
| `bind_abstract` | Linux abstract namespace; refused unless `require_uid` is set, because no file permission protects it | `InvalidConfig { field: "require_uid", reason: Missing }` | P3 | 3 | after `1.0.0` |

The default mode is `0600` (decision D-024): only the owner can connect; `group_access` opens it to one group. Keep sockets in a private directory (`0750`) as well.

```rust,no_run
use net_io::{LocalOptions, UnixListener};
let options = LocalOptions::new().group_access(33).require_uid(1000);
let listener = UnixListener::bind_atomic("/run/myapp/api.sock", options)?;
let (mut conn, info) = listener.accept()?;
println!("uid {:?}", info.peer_credentials.and_then(|c| c.uid));
conn.send_all(b"ready\n")?;
# Ok::<(), net_io::NetError>(())
```

### Windows named pipes

```rust
#[cfg(windows)] pub struct PipeListener { /* name, security descriptor, next instance */ }
#[cfg(windows)] impl PipeListener {
    pub fn create(name: &str) -> Result<PipeListener, NetError>;                     // \\.\pipe\<name>
    pub fn create_with(name: &str, options: PipeOptions) -> Result<PipeListener, NetError>;
    pub fn accept(&self) -> Result<(PipeConnection, ConnectionInfo), NetError>;
}
#[cfg(windows)] pub struct PipeConnection { /* owned handle, ConnectionInfo, limits, kill state */ }
#[cfg(windows)] impl PipeConnection {
    pub fn connect(name: &str, timeout: Duration) -> Result<PipeConnection, NetError>;
    // recv, recv_exact, send, send_all, close, abort, info, id, kill_handle, set_limits, set_phase,
    // set_exchange_deadline: the same signatures as UnixConnection; Read, Write, Drop as TcpConnection
    pub fn client_pid(&self) -> Result<u32, NetError>;
}
#[cfg(windows)] #[must_use] #[derive(Clone, Debug)] pub struct PipeOptions { /* ... */ }
#[cfg(windows)] impl PipeOptions {
    pub fn new() -> Self;                                  // owner only, 255 instances
    pub fn max_instances(self, n: u8) -> Self;
    pub fn security(self, security: PipeSecurity) -> Self;
    pub fn buffer_sizes(self, inbound: u32, outbound: u32) -> Self;
}
#[cfg(windows)] #[non_exhaustive] #[derive(Clone, Debug)]
pub enum PipeSecurity { OwnerOnly, OwnerAndSystem, Sddl(String) }
```

| Item | Behaviour | Errors | Grade | Tier | Version |
|---|---|---|---|---|---|
| `create`, `create_with` | the first instance uses `FILE_FLAG_FIRST_PIPE_INSTANCE`, so if another process already owns the name the call fails instead of sharing it; `PIPE_REJECT_REMOTE_CLIENTS` always (not configurable); an owner-only security descriptor by default; a backslash in the name part is refused before any system call | `PipeNameInUse`, `PermissionDenied`, `InvalidConfig`, `Os` | P1 | 1 / 2 | `0.5.0` |
| `accept` | waits for a client (overlapped on the reactor), creates the next instance before returning so a client never finds none; a client that connected before the wait (`ERROR_PIPE_CONNECTED`) is a success | `Os` | P1 | 1 | `0.5.0` |
| `PipeConnection::connect` | `CreateFileW` with `SECURITY_SQOS_PRESENT \| SECURITY_IDENTIFICATION`, so the server can identify the client but not impersonate it beyond that; on `ERROR_PIPE_BUSY` waits with `WaitNamedPipeW` within `timeout` | `ConnectTimeout`, `NotFound`, `PermissionDenied` | P1 | 1 | `0.5.0` |
| `client_pid` | `GetNamedPipeClientProcessId` | `Os` | P1 | 2 | `0.5.0` |

### `LocalListener`, `LocalConnection`

```rust
#[non_exhaustive]
pub enum LocalListener { Unix(UnixListener), #[cfg(windows)] Pipe(PipeListener) }
impl LocalListener { pub fn accept(&self) -> Result<(LocalConnection, ConnectionInfo), NetError>; }

#[non_exhaustive]
pub enum LocalConnection { Unix(UnixConnection), #[cfg(windows)] Pipe(PipeConnection) }
impl LocalConnection {
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize, NetError>;
    pub fn recv_exact(&mut self, buf: &mut [u8]) -> Result<(), NetError>;
    pub fn send(&mut self, buf: &[u8]) -> Result<usize, NetError>;
    pub fn send_all(&mut self, buf: &[u8]) -> Result<(), NetError>;
    pub fn shutdown(&mut self, how: Shutdown) -> Result<(), NetError>;   // Unsupported for a pipe's read side
    pub fn close(self) -> Result<(), NetError>;
    pub fn abort(self);
    pub fn info(&self) -> &ConnectionInfo;
    pub fn kill_handle(&self) -> KillHandle;
    pub fn set_limits(&mut self, limits: Limits);
}
impl Read for LocalConnection; impl Write for LocalConnection;
```

What [`listen_local`](#listen_local-connect_local) and `connect_local` return: a named pipe on Windows (native, with ACLs and the client pid, on every supported Windows), a Unix socket elsewhere (decision D-043). P1, Tier 1, `0.4.0` / `0.5.0`.

---

## PROXY protocol

Feature `proxy`. The real client address when a trusted reverse proxy or load balancer (HAProxy, nginx, a cloud load balancer) sits in front.

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ProxyMode { #[default] Off, Required { versions: ProxyVersions } }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyVersions { V1, V2, Both }

pub struct ProxyParser { /* state, resume offset, limits */ }
impl ProxyParser {
    pub fn new(versions: ProxyVersions, v2_body_max: u16) -> ProxyParser;
    pub fn feed<'a>(&mut self, input: &'a [u8]) -> Result<ProxyProgress<'a>, ProxyError>;   // input = every byte received so far
}
#[derive(Debug)]
pub enum ProxyProgress<'a> { NeedMore { at_least: usize }, Done { header: ProxyHeader<'a>, consumed: usize } }

#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub struct ProxyHeader<'a> {
    pub version: u8,
    pub command: ProxyCommand,                 // Proxy | Local
    pub transport: ProxyTransport,             // Stream | Datagram | Unspecified
    pub source: Option<ProxyAddress<'a>>,      // None for LOCAL, UNKNOWN, UNSPEC
    pub destination: Option<ProxyAddress<'a>>,
    pub tlvs: Tlvs<'a>,                        // empty for v1
}
impl<'a> ProxyHeader<'a> {
    pub fn alpn(&self) -> Option<&'a [u8]>;
    pub fn authority(&self) -> Option<&'a str>;
    pub fn unique_id(&self) -> Option<&'a [u8]>;
    pub fn ssl(&self) -> Option<ProxySsl<'a>>;
    pub fn network_namespace(&self) -> Option<&'a [u8]>;
    pub fn crc_checked(&self) -> bool;
    pub fn to_facts(&self) -> ProxyFacts;
}
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum ProxyCommand { Proxy, Local }
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum ProxyTransport { Stream, Datagram, Unspecified }
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum ProxyAddress<'a> { Ip(SocketAddr), Unix(&'a [u8]) }
#[derive(Clone, Copy, Debug)] pub struct Tlvs<'a>; impl<'a> Iterator for Tlvs<'a> { type Item = Tlv<'a>; }
#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub struct Tlv<'a> { pub kind: u8, pub value: &'a [u8] }
#[non_exhaustive] #[derive(Clone, Copy, Debug)]
pub struct ProxySsl<'a> { pub client: u8, pub verified: bool, pub version: Option<&'a str>, pub common_name: Option<&'a str>,
                          pub cipher: Option<&'a str>, pub signature_algorithm: Option<&'a str>, pub key_algorithm: Option<&'a str> }
#[non_exhaustive] #[derive(Clone, Copy, Debug)]
pub struct ProxyFacts { /* ALPN up to 32 bytes, authority up to 255, unique id up to 128, SSL flags: fixed arrays */ }
impl ProxyFacts { pub fn alpn(&self) -> Option<&[u8]>; pub fn authority(&self) -> Option<&str>; pub fn unique_id(&self) -> Option<&[u8]>; pub fn ssl_client(&self) -> Option<u8>; }

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyError {
    OutputTooSmall { need: usize },             // encode: `out` cannot hold the header
    NotProxy,                                   // the first bytes match no allowed signature
    V1TooLong, V1Syntax { at: u8 }, V1BadAddress, V1BadPort,
    V2BadVersion, V2BadCommand, V2BadFamily, V2LengthTooLarge { declared: u16, max: u16 },
    V2AddressTooShort, V2TlvOverrun, V2CrcMismatch, V2UniqueIdTooLong, V2SslMalformed,
    FamilyMismatch,                             // for example TCP4 with an IPv6 literal
}

pub fn encode_v1(source: SocketAddr, destination: SocketAddr, out: &mut [u8]) -> Result<usize, ProxyError>;
pub fn encode_v2(command: ProxyCommand, source: Option<SocketAddr>, destination: Option<SocketAddr>,
                 tlvs: &[Tlv<'_>], with_crc: bool, out: &mut [u8]) -> Result<usize, ProxyError>;   // None = LOCAL / UNSPEC
```

Server behaviour (`ListenerSpec::proxy`), P0, Tier 2, `0.4.0`:

1. There is no "optional" mode: the PROXY specification says a receiver must be configured for it and must not guess whether a header is present. `Required { Both }` picks the version from the first byte (`P` or `0x0D`) on a listener that always expects a header.
2. **Trust before parsing.** A connection from a peer outside `TrustedProxies` on a `Required` listener is closed with `ProxyUntrusted` before any byte is read.
3. The header is read under the handshake deadline; a missing header (the trusted peer sent something else) closes with `ProxyMissing`, an invalid or oversized one with `ProxyInvalid`. The v2 length field is checked against `Limits::proxy_header_max` before waiting for the body.
4. Exactly one header is read; a second header is application data that reaches the protocol engine, which rejects it.
5. The real client is normalized, the per-source cap moves to it, `Gate::readmit` runs, `ConnectionInfo::real_peer` and `proxy` are set, and `ProxyResolved` is emitted.
6. v2 `LOCAL` (health checks from the proxy itself) keeps the socket's own addresses.

Parser (Tier 3): `feed` is a sans-IO state machine. Give it all bytes received so far; it resumes where it stopped, so a growing buffer costs O(new bytes), and it never reads past `consumed`, so the rest stays application data. v1 is strict: single spaces, decimal ports 0 to 65535 without sign or leading zeros, dotted-quad IPv4 without leading zeros, IPv6 text parsed by net-io's own parser so the accepted grammar is exactly the tested one, at most 107 bytes. v2: the 12-byte signature (it contains a zero byte, so it is never treated as a C string), version 2, `LOCAL` or `PROXY`, families `0x00`, `0x11`, `0x12`, `0x21`, `0x22`, `0x31`, `0x32`, address blocks of 12, 36, or 216 bytes, a bounds-checked TLV walk that must end exactly at the declared length, CRC32C (`0x03`) verified over the whole header with the checksum field zeroed, `NOOP` (`0x04`) skipped, unique id (`0x05`) at most 128 bytes, SSL (`0x20`) with sub-TLVs `0x21` to `0x25`, NETNS (`0x30`), and custom, experimental, and future types exposed as raw TLVs. Cost: v1 TCP4 under 100 ns, v2 IPv4 without TLVs under 50 ns, v2 with 5 TLVs and CRC32C under 300 ns [est.]; no allocation. CRC32C is in-house and table-driven (Castagnoli, reflected 0x82F63B78), tested with the RFC 3720 vectors.

| Item | Grade | Tier | Version |
|---|---|---|---|
| `ProxyMode`, `ProxyVersions`, server integration | P0 | 2 | `0.4.0` |
| `ProxyParser`, `ProxyProgress`, `ProxyHeader` and accessors, `Tlvs`, `Tlv`, `ProxyAddress`, `ProxyFacts` | P0 | 3 | `0.4.0` |
| `ProxySsl` | P2 | 3 | `0.4.0` |
| `ProxyError` | P0 | 2 | `0.4.0` |
| `encode_v1`, `encode_v2` (for a proxy that speaks PROXY to its backends) | P2 | 3 | `0.6.0` |

```rust
use net_io::{ProxyParser, ProxyProgress, ProxyVersions};
let mut parser = ProxyParser::new(ProxyVersions::Both, 1024);
let bytes = b"PROXY TCP4 192.0.2.1 198.51.100.2 51000 443\r\nGET / HTTP/1.1\r\n";
match parser.feed(bytes)? {
    ProxyProgress::Done { header, consumed } => {
        assert_eq!(&bytes[consumed..], b"GET / HTTP/1.1\r\n");
        println!("client {:?}", header.source);
    }
    ProxyProgress::NeedMore { at_least } => println!("need {at_least} more bytes"),
}
# Ok::<(), net_io::ProxyError>(())
```

```rust,no_run
// Behind HAProxy or nginx with `proxy_protocol on`.
use net_io::{AllowAll, ListenerSpec, ProxyMode, ProxyVersions, ServerBuilder, TrustedProxies};
let server = ServerBuilder::new()
    .listener(ListenerSpec::tcp("127.0.0.1:8080")
        .proxy(ProxyMode::Required { versions: ProxyVersions::Both }))
    .trusted_proxies(TrustedProxies::loopback())
    .handler(|conn| {
        let client = conn.info().client_addr();
        conn.send_all(format!("you are {client:?}\n").as_bytes())?;
        Ok(())
    })
    .gate(AllowAll)
    .build()?;
server.open_door()?;
server.wait_for_stop();
# Ok::<(), net_io::NetError>(())
```

---

## TLS seam

Feature `tls`. net-io carries no TLS code: a TLS engine implements these traits in its own crate (the planned adapter over rustls is `tls-net`). The seam is in place and sans-IO (decision D-019): ciphertext is decrypted inside the connection's own read buffer and plaintext is encrypted straight into net-io's output buffer, with no queue inside the engine and no extra buffer between them.

```rust
pub trait TlsAcceptor: Send + Sync + 'static {
    type Session: TlsSession;
    /// Called once per admitted connection, after PROXY and readmission, before any TLS byte is read.
    fn session(&self, info: &ConnectionInfo) -> Result<Self::Session, TlsError>;
}

pub trait TlsSession: Send + 'static {
    /// Ciphertext is in `input`; free space for records to send is `output`. Never blocks, never does IO.
    fn step<'i>(&mut self, input: &'i mut [u8], output: &mut [u8]) -> Result<TlsProgress<'i>, TlsError>;
    /// Encrypts `plaintext` into `output`; all records or none.
    fn encrypt(&mut self, plaintext: &[u8], output: &mut [u8]) -> Result<usize, TlsError>;
    /// Writes close_notify.
    fn close(&mut self, output: &mut [u8]) -> Result<usize, TlsError>;
    /// The peer's transport closed: was the TLS stream ended cleanly?
    fn on_transport_closed(&mut self) -> TlsCloseKind;
    /// SNI, ALPN, version, cipher; Some after HandshakeComplete.
    fn info(&self) -> Option<TlsInfo>;
    /// The smallest input buffer the session needs now (the largest handshake message being assembled).
    fn input_capacity_required(&self) -> usize;
}

#[must_use]
#[derive(Debug)]
pub struct TlsProgress<'i> { pub consumed: usize, pub written: usize, pub event: TlsEvent<'i> }

#[non_exhaustive]
#[derive(Debug)]
pub enum TlsEvent<'i> {
    NeedInput,              // read more ciphertext, append after the unconsumed bytes, call step again
    Transmit,               // `written` bytes at the start of `output` must be sent, all of them
    HandshakeComplete,      // once; info() is now Some
    Data(&'i [u8]),         // plaintext decrypted in place; call step again for more
    OutputFull,             // not enough room in `output`; flush and call again
    PeerClosed,             // close_notify received
    Closed,                 // both directions closed
}

#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsCloseKind { Clean, Unclean }

#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsError { pub kind: TlsFailure, pub code: u16, pub alert: Option<u8> }   // no secret material
impl TlsError { pub const fn new(kind: TlsFailure, code: u16, alert: Option<u8>) -> TlsError; }
#[non_exhaustive] #[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsFailure { Handshake, HelloRefused, Capacity, Protocol, OutputFull, State }

#[non_exhaustive] #[derive(Clone, Copy, Debug)]
pub struct TlsInfo { /* SNI up to 255 bytes, ALPN up to 32 bytes, version, cipher suite: fixed arrays */ }
impl TlsInfo {
    pub fn new(sni: Option<&str>, alpn: Option<&[u8]>, version: u16, cipher_suite: u16) -> Option<TlsInfo>;   // None if SNI > 255 or ALPN > 32 bytes
    pub fn sni(&self) -> Option<&str>; pub fn alpn(&self) -> Option<&[u8]>; pub fn version(&self) -> u16; pub fn cipher_suite(&self) -> u16;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoTls;                         // the builder's default; no listener may enable TLS with it
impl TlsAcceptor for NoTls { type Session = NoTlsSession; /* session() always fails */ }
pub enum NoTlsSession {}                  // uninhabited; impl TlsSession
```

How the server drives it (P0, Tier 3, `0.4.0`):

1. Order: accept, `Gate::admit`, PROXY header, `Gate::readmit`, `TlsAcceptor::session` (an acceptor at capacity refuses here, before reading), then `step` under the handshake deadline until `HandshakeComplete`; `info()` is copied into `ConnectionInfo::tls`.
2. **ClientHello inspection lives in the engine.** The engine parses the ClientHello from net-io's read buffer inside `step` and can refuse it (fingerprinting); net-io copies nothing. A refusal is `TlsError { kind: HelloRefused, .. }` and closes with `CloseReason::HelloRefused`; other errors close with `TlsFailed`. A ClientHello split into many tiny records is the engine's to bound; net-io's read buffer limit and handshake deadline bound it too.
3. `Data` slices are plaintext inside net-io's ciphertext buffer; net-io copies each one once into the reader's buffer (the session's input or a handler's `recv` buffer), so blocking handlers and sessions share one TLS path (D-089).
4. Outbound: the gate check runs once on the plaintext before `encrypt`, for exactly the bytes encrypted, and the ciphertext is sent within the same call; a denial is encrypted like any other output and followed by `close_notify`. `TcpConnection::peek` is `Unsupported` on a TLS connection.
5. Graceful close sends `close_notify`; abortive close does not. The read buffer grows (up to the maximum read class) when `input_capacity_required` exceeds it, for example for a large client certificate chain.
6. The engine's minimum buffer sizes are met by the default 16 KiB class with the 64 KiB growth limit (rustls needs at least 18,437 bytes for one full record; `input_capacity_required` says more when a handshake message spans several records).

| Item | Grade | Tier | Version |
|---|---|---|---|
| `TlsAcceptor`, `TlsSession`, `TlsProgress`, `TlsEvent`, `TlsCloseKind` | P0 | 3 | `0.4.0` |
| `TlsInfo`, `TlsError`, `TlsFailure`, `NoTls` | P0 | 2 | `0.4.0` |
| kTLS hand-off after the handshake | P3 | 3 | after `1.0.0` |

Cost: the seam adds no copy beyond the engine's own and one `copy_within` per plaintext record [est. under 100 ns per 16 KiB record].

```rust,no_run
// With a TLS adapter crate that implements TlsAcceptor (shown with a placeholder type).
# use net_io::*;
# struct MyTls; impl TlsAcceptor for MyTls { type Session = MySession; fn session(&self, _: &ConnectionInfo) -> Result<MySession, TlsError> { unimplemented!() } }
# struct MySession; impl TlsSession for MySession {
#   fn step<'i>(&mut self, _: &'i mut [u8], _: &mut [u8]) -> Result<TlsProgress<'i>, TlsError> { unimplemented!() }
#   fn encrypt(&mut self, _: &[u8], _: &mut [u8]) -> Result<usize, TlsError> { unimplemented!() }
#   fn close(&mut self, _: &mut [u8]) -> Result<usize, TlsError> { unimplemented!() }
#   fn on_transport_closed(&mut self) -> TlsCloseKind { TlsCloseKind::Unclean }
#   fn info(&self) -> Option<TlsInfo> { None }
#   fn input_capacity_required(&self) -> usize { 18_437 } }
let server = ServerBuilder::new()
    .listener(ListenerSpec::tcp("0.0.0.0:443").tls(true))
    .tls(MyTls)
    .handler(|conn| {
        let sni = conn.info().tls.as_ref().and_then(|t| t.sni().map(str::to_owned));
        conn.send_all(format!("hello {sni:?}\n").as_bytes())?;
        Ok(())
    })
    .gate(AllowAll)
    .build()?;
# Ok::<(), NetError>(())
```

---

## Inherited listeners

Feature `local` for the Unix parts. Cold paths: allocation is allowed here.

```rust
pub struct InheritedListener { pub name: Option<String>, pub handle: ListenerHandle }

pub fn systemd() -> Result<Vec<InheritedListener>, InheritError>;
pub fn systemd_named(name: &str) -> Result<Option<InheritedListener>, InheritError>;
#[cfg(unix)] pub fn fastcgi_listener() -> Result<Option<ListenerHandle>, InheritError>;

#[non_exhaustive]
#[derive(Debug)]
pub enum InheritError {
    BadCount, TooMany { max: u32 }, NotASocket { fd: i32 }, NotListening { fd: i32 }, WrongKind { fd: i32 },
    NamesMismatch, PidFdMismatch, Os(io::Error),
}
```

| Item | Behaviour | Grade | Tier | Version |
|---|---|---|---|---|
| `systemd` | socket activation: reads `LISTEN_PID` (must equal this process id, otherwise the variables were meant for another process and the result is an empty list), `LISTEN_FDS` (at most 64), `LISTEN_FDNAMES` (optional), and `LISTEN_PIDFDID` where present; descriptors start at 3; each is verified (a socket, listening, a known family and type) and set close-on-exec. The variables are left in the environment (decision D-036). Not systemd (no `LISTEN_PID`): `Ok(vec![])` | P1 | 1 | `0.4.0` |
| `systemd_named` | the one listener with that `LISTEN_FDNAMES` entry, or `None` | P1 | 1 | `0.4.0` |
| `fastcgi_listener` | FastCGI's convention (`FCGI_LISTENSOCK_FILENO`, as `mod_fcgid` starts a FastCGI server): descriptor 0 is adopted only if it is a socket, listening, and has no peer (`getpeername` fails with `ENOTCONN`); otherwise `None` (a terminal, a file, a pipe, a connected socket) | P1 | 1 | `0.4.0` |
| FastCGI on Windows | open decision OD-26: `0.6.0` if a Windows FastCGI deployment is planned; otherwise it is regraded P3 and moves after `1.0.0` | P2 | 2 | per OD-26 |

```rust,no_run
use net_io::{AllowAll, ListenerSpec, ServerBuilder};
let mut builder = ServerBuilder::new();
for inherited in net_io::systemd()? {
    builder = builder.listener(ListenerSpec::adopt(inherited.handle));
}
let server = builder.handler(|conn| { conn.send_all(b"hi\n")?; Ok(()) }).gate(AllowAll).build()?;
server.open_door()?;
server.wait_for_stop();
# Ok::<(), Box<dyn std::error::Error>>(())
```

---

## Listener hand-off

Feature `local`. A restart without a closed port: the old process gives its listening sockets to the new one, the new one opens its door, then the old one closes its door and drains. The kernel keeps queuing connections in the backlog throughout, so none is refused. Both processes may accept for a short overlap; each connection belongs to exactly one of them (decision D-042).

```rust
pub struct ListenerHandle { /* kind, name (up to 64 bytes), local endpoint, owned descriptor or socket */ }
impl ListenerHandle {
    pub fn kind(&self) -> Transport;
    pub fn name(&self) -> Option<&str>;
    pub fn local(&self) -> &Endpoint;
}
impl Drop for ListenerHandle;      // closes the descriptor

#[cfg(unix)] pub fn send_listeners(channel: &mut UnixConnection, listeners: &[&ListenerHandle]) -> Result<(), HandoffError>;
#[cfg(unix)] pub fn recv_listeners(channel: &mut UnixConnection, expect: &HandoffPeer, deadline: Instant) -> Result<Vec<ListenerHandle>, HandoffError>;

#[cfg(windows)] pub fn share_listeners(listeners: &[&ListenerHandle], target_pid: u32) -> Result<SharedListeners, HandoffError>;
#[cfg(windows)] pub struct SharedListeners { /* WSAPROTOCOL_INFOW blobs + manifest */ }
#[cfg(windows)] impl SharedListeners { pub fn write_to(self, pipe: &mut PipeConnection) -> Result<(), HandoffError>; }   // consumed: sent once
#[cfg(windows)] pub fn receive_shared(pipe: &mut PipeConnection, expect: &HandoffPeer, deadline: Instant) -> Result<Vec<ListenerHandle>, HandoffError>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HandoffPeer { pub uid: Option<u32>, pub pid: Option<u32> }   // uid None = this process's own uid

#[non_exhaustive]
#[derive(Debug)]
pub enum HandoffError {
    PeerMismatch, Truncated, CountMismatch, BadMagic, BadVersion, BadChecksum, TooMany { max: u8 },
    VerifyFailed { index: u8, why: &'static str }, Timeout, Os(io::Error),
}
```

| Item | Behaviour | Grade | Tier | Version |
|---|---|---|---|---|
| `ListenerHandle` | owned, move-only; dropping it closes the socket | P0 | 3 | `0.4.0` |
| `send_listeners`, `recv_listeners` | one `sendmsg` carrying up to 64 descriptors (`SCM_RIGHTS`) and a manifest: magic `NIOH`, version 1, count, per listener kind, name, local address, and an options digest, then a CRC32C. The receiver checks the sender's credentials against `expect` (default: same uid), receives close-on-exec, fails on a truncated control message, checks magic, version, checksum, and count, and verifies every descriptor (`SO_TYPE`, `SO_ACCEPTCONN`, `getsockname` equals the manifest address). Any failure closes every received descriptor and returns the error: all or nothing | P0 | 3 | `0.4.0` |
| `share_listeners`, `receive_shared` | Windows: `WSADuplicateSocketW` per socket for one target pid (each blob works once, in that process only), sent with a random nonce over a named pipe with an owner-only security descriptor; the receiver checks `GetNamedPipeClientProcessId`, refuses a nonce it already accepted, creates each socket with `WSASocketW(FROM_PROTOCOL_INFO, WSA_FLAG_OVERLAPPED)`, and verifies it | P0 | 3 | `0.5.0` |
| `HandoffPeer`, `HandoffError` | | P0 | 3 | `0.4.0` |

Keep the channel's socket in a private directory (`0700`). Cost: under 1 ms per hand-off [est.].

```rust,no_run
// Old process: give the listeners away, then drain.
# #[cfg(unix)] {
use net_io::{send_listeners, UnixConnection};
use std::time::{Duration, Instant};
# let server: net_io::Server = unimplemented!();
let mut channel = UnixConnection::connect("/run/myapp/handoff.sock")?;
let handles = server.release_listeners()?;           // the door stays open meanwhile
send_listeners(&mut channel, &handles.iter().collect::<Vec<_>>())?;
let mut ready = [0u8; 1];
channel.recv_exact(&mut ready)?;                      // the new process has opened its door
server.shutdown(Instant::now() + Duration::from_secs(30)); // close our door, drain, exit
# }
# Ok::<(), Box<dyn std::error::Error>>(())
```

```rust,no_run
// New process: receive, build, open the door.
# #[cfg(unix)] {
use net_io::{recv_listeners, AllowAll, HandoffPeer, ListenerSpec, ServerBuilder, UnixListener};
use std::time::{Duration, Instant};
let channel_listener = UnixListener::bind("/run/myapp/handoff.sock")?;
let (mut channel, _) = channel_listener.accept()?;
let handles = recv_listeners(&mut channel, &HandoffPeer::default(), Instant::now() + Duration::from_secs(5))?;
let mut builder = ServerBuilder::new();
for handle in handles {
    builder = builder.listener(ListenerSpec::adopt(handle));
}
let server = builder.handler(|conn| { conn.send_all(b"v2\n")?; Ok(()) }).gate(AllowAll).build()?;
server.open_door()?;
channel.send_all(b"1")?;                              // tell the old process to stop
# }
# Ok::<(), Box<dyn std::error::Error>>(())
```

On Windows, net-io never associates a listening socket with an I/O completion port, in any driver: once any process associates a listener, a process that receives it can never use it with its own port (decision D-016). Windows also does not make a `WSAPROTOCOL_INFOW` single use, so net-io does: each manifest carries a random nonce that `receive_shared` accepts once per process, and `SharedListeners::write_to` consumes the value (decision D-054).

---

## Thread safety and sizes

| Type | `Send` | `Sync` | Size target |
|---|---|---|---|
| `TcpListener`, `UnixListener`, `PipeListener`, `UdpSocket` | yes | yes (accept takes `&self`) | one socket plus a small info struct |
| `TcpConnection`, `UnixConnection`, `PipeConnection` | yes | no (one owner) | about 700 bytes with `ConnectionInfo` [est.] |
| `Server` | yes | yes | |
| `ServerHandle`, `KillHandle`, `Completer`, `DriverWaker` | yes | yes | one `Arc` plus a few words |
| `ConnectionInfo` | yes | yes | about 200 bytes; no allocation after warm-up |
| `ConnectionId`, `Lane`, `PrefixKey`, `Cidr`, `CloseReason`, `Event` | yes | yes | 8, 1, 18, 18, 4, at most 64 bytes |
| `Input`, `Output`, `Buffer`, `BufferPool` | yes | no (worker-local) | |
| `SessionContext` | no | no | borrowed for one call |

Every limit, deadline, and buffer is per connection or per worker; nothing global is mutable except two process-wide facts that are read-only after first use: the Windows Winsock start-up (reference counted, done once) and the connection-id block counter (one atomic, touched once per 1,024 ids per worker).

---

## Recipes

| Task | Recipe |
|---|---|
| Echo server in a few lines | [Tier 1 at a glance](#tier-1-at-a-glance) |
| Bind first, drop privileges, then accept | `ServerBuilder::build` (door closed), drop privileges, `Server::open_door` ([Server](#serverbuilder)) |
| Graceful shutdown on a signal | `ServerHandle::request_stop` from the signal thread, `Server::wait_for_stop` in `main` ([ServerHandle](#serverhandle)) |
| Behind a reverse proxy with the real client address | `ListenerSpec::proxy(Required)` plus `trusted_proxies` ([PROXY](#proxy-protocol)) |
| Same-host IPC | `listen_local` / `connect_local` ([Crate root](#listen_local-connect_local)) |
| Zero-downtime restart | `release_listeners`, `send_listeners`, `recv_listeners`, `ListenerSpec::adopt` ([Hand-off](#listener-hand-off)) |
| Socket activation | `net_io::systemd()` ([Inherited listeners](#inherited-listeners)) |
| Revoke a connection's output | a [`Gate`](#gate) whose `check` returns `Denial` |
| Kill one connection from anywhere | `ServerHandle::kill(id, reason)` |
| Slow work without holding a worker | `Step::Park`, then `Completer::post` from the other thread ([Completer](#completer)) |
| Hand a received body to another thread without copying | `Input::swap` ([Input](#input)) |
| Shed load by importance | `ControlState::Shed { from_lane }` ([Control line](#control-line)) |
| Logs and metrics | an [`EventSink`](#events) |
| Deterministic timeout tests | `ManualClock` ([Time](#time)) |
| UDP without becoming an amplifier | `UdpSocket` defaults ([UDP](#udp)) |

---

## Consumer checklists

### A connection gate (bouncer-io)

| Needs | net-io item |
|---|---|
| admission before any byte, with a per-connection ticket | `Gate::admit`, `Gate::Ticket`, `Admitted` |
| naming the connection and the current response to the gate from the protocol engine | `ConnectionInfo::gate`, `Output::begin_tagged_response(tag)`, `WriteCheck::response` |
| real client after a trusted PROXY header | `Gate::readmit`, `ConnectionInfo::real_peer`, `client_addr`, `client_key` |
| a check before every write without a lookup by id | `Gate::check(&mut Ticket, &WriteCheck)` |
| release and strikes at close | `Gate::closed(Ticket, &ConnectionInfo, CloseReason)` |
| eject from a maintenance thread | `ServerHandle::kill(ConnectionId, KillReason)` |
| ids, addresses, prefixes | `ConnectionId::get`, `normalize`, `Cidr`, `PrefixKey`, `PrefixPolicy`, `TrustedProxies` |
| a canned refusal reply | `Refusal::WithBytes` |
| dialed connections registered like accepted ones | `AdmitStage::Dialed` (`TcpConnection::set_gate`), `AdmitStage::Adopt` (`Server::adopt`) |

### A TLS adapter (tls-net)

| Needs | net-io item |
|---|---|
| per-connection session creation, refusal at capacity | `TlsAcceptor::session` |
| in-place decryption in net-io's read buffer | `TlsSession::step(&mut [u8], &mut [u8])`, `TlsEvent::Data` |
| ClientHello parsing and refusal inside the engine | `TlsFailure::HelloRefused` -> `CloseReason::HelloRefused` |
| buffer minimums | `TlsSession::input_capacity_required`, `Limits::read_class` |
| SNI and ALPN to the protocol layer | `TlsSession::info` -> `ConnectionInfo::tls` |

### A network service module (serve-net)

| Needs | net-io item |
|---|---|
| listeners per ingress mode | `ListenerSpec::{tcp, unix, pipe, adopt}`, `proxy`, `tls` |
| sessions over any driver | `Session`, `SessionFactory`, `Step`, `SessionContext` |
| keep-alive policy under load | `SessionContext::pressure`, `draining` |
| drain and restarts | `close_door`, `drain`, `shutdown`, `release_listeners`, `systemd`, `fastcgi_listener` |
| offloaded work | `Step::Park`, `Completer`, `Session::on_wake` |
| zero-copy request bodies and WebSocket messages | `Input::swap`, `Buffer`, `BufferPool` |
| refusal text | `Session::on_denied(code, &mut Output)` |
| the process-wide control signal | `ControlLine`, `ControlState` |

---

## Names changed at the design lock

Names follow the rule "plain words, no abbreviations" (decisions D-017, D-059). Earlier plans used the left column. Kept on purpose because they are the established word for the thing in Rust and in socket programming: `recv` and `send` (as in `std::net::UdpSocket`), `addr` (as in `SocketAddr`, `local_addr`), `nodelay`, `backlog`, `linger`, `keepalive`, `Cidr`, `Tlv`, and the door (`open_door`, `close_door`: accepting new connections, separate from binding).

| Earlier | Now |
|---|---|
| `TcpConn`, `UnixConn`, `PipeConn`, `LocalConn` | `TcpConnection`, `UnixConnection`, `PipeConnection`, `LocalConnection` |
| `ConnInfo` | `ConnectionInfo` |
| `ConnOptions` | `TcpOptions` |
| `Cx` | `SessionContext` |
| `InBuf`, `OutBuf`, `Buf`, `BufPool` | `Input`, `Output`, `Buffer`, `BufferPool` |
| `OutFull` | `OutputFull` |
| `LocalAddr` | `Endpoint` |
| `PeerCred` | `PeerCredentials` |
| `IoClass` | `OsErrorClass` |
| `SizeClass::{K4, K16, K64}` | `SizeClass::{SMALL, MEDIUM, LARGE}` |
| `Op`, `OpKind`, `Submit` | `Operation`, `OperationKind`, `Rejected` |
| `FdBuf`, `send_fds`, `recv_fds` | `Descriptors`, `send_descriptors`, `recv_descriptors` |
| `DatagramBuf`, `OutDatagram` | `DatagramBuffer`, `OutgoingDatagram` |
| `SslTlv`, `ProxyAddr`, `Progress` (PROXY) | `ProxySsl`, `ProxyAddress`, `ProxyProgress` |
| `Admission` + `Egress` traits, `AdmitVerdict`, `EgressVerdict`, `EgressContext` | one `Gate` trait with an associated `Ticket`; `Admitted`, `Denial`, `WriteCheck`; `GateTag` kept for protocol engines (D-051) |
| `TlsEngine`, `TlsFactory`, `HelloHook`, `HelloVerdict` | `TlsSession`, `TlsAcceptor`; the hello hook belongs to the engine |
| `Step::CloseAfterFlush` | `Step::Close` (always flushes) |
| `Limits::{handshake, idle, read, write, park, drain}` | `handshake_timeout`, `idle_timeout`, `read_timeout`, `write_timeout`, `park_timeout`, `drain_timeout` |
| `Session::denial`, `TlsSession::on_eof` | `Session::on_denied`, `TlsSession::on_transport_closed` |
| `ConnInfo::peer_ip`, `Endpoint::ip`, `NetError::os_code` | `socket_peer`, `socket_addr`, `os_error_code` |
| `UnixListener::bind_in_dir`, `ControlState::Shed { lane_floor }` | `bind_atomic`, `Shed { from_lane }` |
| `send_buffer`/`recv_buffer` options | `send_buffer`/`receive_buffer` |
| `Server<S: EventSink>` | `Server` (not generic) |
