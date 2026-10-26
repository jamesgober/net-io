<h1 align="center">
    <img width="90px" height="auto" src="https://raw.githubusercontent.com/jamesgober/jamesgober/main/media/icons/hexagon-3.svg" alt="Triple Hexagon">
    <br><b>CHANGELOG</b>
</h1>
<p>
  All notable changes to <code>net-io</code> will be documented in this file. The format is based on <a href="https://keepachangelog.com/en/1.1.0/">Keep a Changelog</a>,
  and this project adheres to <a href="https://semver.org/spec/v2.0.0.html/">Semantic Versioning</a>.
</p>

---

## [Unreleased]

---

## [0.4.0] - 2026-10-26

Edges: everything around the TCP core that a real deployment meets. Behind a
proxy, on a Unix socket, over UDP, started by systemd or a FastCGI manager,
and restarted without closing the port.

### Added

- PROXY protocol v1 and v2: `ProxyParser` (sans-IO, strict grammar, every
  TLV, CRC32C), `ProxyHeader`, `ProxyAddress`, `Tlv`, `Tlvs`, `ProxySsl`.
  On a server, `ListenerSpec::proxy` reads the header under the handshake
  deadline from trusted proxies only (an untrusted peer is closed before any
  byte is read), sets `ConnectionInfo::real_peer` and `proxy`, moves the
  per-source slot to the real client, and asks the gate again
  (`Gate::readmit`). `ListenerSpec::trusted_proxies` per listener.
- The TLS seam on listeners: `ServerBuilder::tls` and `ListenerSpec::tls`.
  Reads return plaintext, every write is checked by the gate once, and a
  graceful close sends `close_notify`.
- Unix domain sockets: `UnixListener` (`bind`, `bind_with`, `bind_atomic`,
  `accept`, `accept_timeout`), `UnixConnection`, `LocalOptions` (mode 0600 by
  default, owner, group, `require_uid`), peer credentials, descriptor
  passing (`send_descriptors`, `recv_descriptors`, `Descriptors`),
  `listen_local` and `connect_local`, and `ListenerSpec::unix` on servers.
  The socket file gets its mode before it listens; a stale file is removed
  only when nothing listens on it; a listener removes only the file it
  created.
- UDP: `UdpSocket` with truncation detection, per-source and global budgets
  (`UdpBudget`), a bounded source table, and the no-amplification guard
  (`mark_verified`, `amplification_factor`, `amplification_window`),
  `Datagram`, `UdpOptions`, `UdpStats`.
- Restarts: `systemd`, `systemd_named`, `fastcgi_listener`,
  `InheritedListener`, `ListenerHandle`, `ListenerSpec::adopt`,
  `Server::release_listeners`, `send_listeners` and `recv_listeners` (a
  checksummed manifest, credential checks, all or nothing), `HandoffPeer`.
- `Server::add_listener` and `Server::remove_listener` on a running server,
  with the `ListenerClosed` event.
- Back-channels: `Server::adopt` with `AdoptSpec`, and
  `TcpConnection::set_gate`.
- `monotonic_micros`, the clock systemd's `MONOTONIC_USEC` expects.
- `RefusalCause::Credentials`, `ConfigReason::Malformed`.
- Examples: `behind_proxy`, `unix_socket`, `handoff_restart`,
  `systemd_activation`, `fastcgi_detect`, `udp_echo`.
- `docs/SECURITY.md` (draft): the threat model and the threat table with each
  defence's cost and test.
- Fuzz targets for the PROXY parser, the hand-off manifest, the systemd
  environment, CIDR blocks, and trusted-proxy lists (`fuzz/`).

### Changed

- The per-source cap is counted per listener, sized from that listener's
  limits.
- The loom models build under `--cfg net_io_loom` instead of `--cfg loom`, so
  a downstream crate running its own loom models can build net-io.
- `Stats::closes` and `Stats::refusals` iterate the non-zero counters;
  `WorkerId::for_testing`.
- The gate's check covers only bytes it has not approved yet, so the tail of a
  partial send is never counted twice.

### Fixed

- A test that counted connections exactly could fail on a loaded host when
  the server refused a quick reconnect; it now checks bounds.

---

## [0.3.0] - 2026-10-26

TCP and the blocking driver: the first release with working code. Servers
and clients over TCP on Linux, macOS, and Windows (x86_64 and aarch64), with
every limit, the gate seam, sans-IO sessions, kill, and graceful drain.

### Added

- Tier 1: `listen`, `connect`, `serve` (a handler per connection on a pool
  worker), `serve_sessions` (a sans-IO session per connection).
- `TcpListener` and `TcpConnection`: every read under the current phase's
  deadline and the minimum inbound rate, every write under the write
  deadline and the minimum outbound rate, partial writes continued from the
  exact offset, `Read` and `Write`, a `KillHandle` usable from any thread.
  `ConnectOptions` with a total timeout across every resolved address.
- `ServerBuilder` and `Server`: TCP listeners with their own limits, the
  blocking driver (128 workers by default), the door (`open_door`,
  `close_door`), `drain`, `shutdown`, `wait_for_stop`, `ServerHandle`
  (`kill`, `request_stop`, `wake_all`, `completer`), and `Stats` with counts
  per refusal cause and per close reason.
- `Limits` and `LimitsBuilder`: global, per-listener, and per-source caps
  (sources grouped by `PrefixPolicy`), handshake, idle, read, write, park,
  and drain timeouts, `MinRate`, buffer and output budgets, read buffer size
  classes; unset values take the driver's defaults, validated at build
  against the process descriptor limit.
- `Session`, `SessionFactory`, `Step`, `Phase`, `Input` (with the O(1)
  `swap`), `Output`, `SessionContext`; `Completer` for work finished on
  other threads; `BufferPool` with wipe on release.
- The gate seam: `Gate` with admission before any byte is read and a check
  before every write, `Refusal`, `Denial`, `WriteCheck`, `AllowAll`.
- `ControlLine`, `SimpleControl`, `NoControl`: shed lanes, lockdown, drain,
  and stop, read with one atomic load per check.
- `EventSink` and `Event` with coalescing of refusal floods.
- `TrustedProxies`: the one list of proxies whose client-address claims are
  believed, with an allocation-free binary-search lookup (brought forward
  from `0.4.0` for serve-net).
- `SessionContext::set_idle_timeout`: a per-connection idle timeout, for
  example to shorten keep-alive while the worker pool is nearly full.
- `Cidr`, `PrefixKey`, `normalize`, and the error types (`NetError` with
  `class`, `is_retryable`, and `os_error_code`, `CloseReason`,
  `RefusalCause`, and the rest).
- Examples: `echo_blocking`, `echo_sessions`, `kill_and_drain`, `gate`.
- `docs/PERFORMANCE.md` with the 0.3 baselines, `docs/PLATFORM-NOTES.md`.

### Performance

- A keep-alive round trip on Linux is 2 system calls (one `recv`, one
  `send`) and 3 on macOS and Windows (a wait first; see the platform notes).
- No allocation per message after warm-up.
- 64-byte echo on one loopback connection is within 0.1 to 0.4 µs of a
  bare `std` echo per round trip.

### Security

- No byte is read before the gate admits a connection, and no byte leaves
  without passing the gate.
- Caps refuse before any read; a full worker pool refuses with `Busy`
  instead of queueing without bound.
- Out of descriptors, the acceptor sheds one pending connection with the
  reserve descriptor and backs off instead of spinning.
- Slowloris and slow readers are closed by the minimum transfer rate and the
  read and write deadlines.
- A kill never touches a descriptor the owner already closed (a guard bit
  held across the one system call).
- Accepted sockets are not inherited by child processes on any platform.

### Testing

- Socket integration tests for every limit, hook, and close reason, with
  exactly one closed event per connection, also over random interleavings
  of FIN, RST, kill, timeouts, and drain.
- Fault injection through a test-only OS shim, property tests, loom models,
  Miri, a counting allocator, and a descriptor leak test over 100,000
  connections.

---

## [0.2.0] - 2026-10-23

The design lock: the public API is written down in full and the design
behind it recorded. Still no functional code; `0.3.0` brings TCP with the
blocking driver.

### Added

- `docs/API.md`: every public item from `0.3.0` to `1.0.0` with its
  signature, behaviour, errors, cost target, grade, tier, the version that
  ships it, and examples. Tier 1 is `listen`, `connect`, `serve`,
  `serve_sessions`, `listen_local`, and `connect_local`.
- `dev/SYS-SURFACE.md`: the OS functions, constants, and structs the crate
  declares per platform, with the documentation each relies on.
- The gate seam: one `Gate` trait whose per-connection ticket is passed back
  on every check and returned at close with the close reason.
- The TLS seam: an in-place, sans-IO session (`TlsAcceptor`, `TlsSession`)
  that decrypts inside the connection's own read buffer.

### Changed

- `dev/PLAN.md` rewritten: requirements (FR-1 to FR-72, NFR-1 to NFR-20),
  architecture, the threat table with a test and a cost for each threat,
  performance targets, the edge-case list, platform spike results, and
  decisions D-013 to D-060.
- `dev/ROADMAP.md` rewritten to the portfolio's version table (0.6
  optimisation, 0.7 hardening, 0.8 alpha, 0.9 beta added; hardening moved
  from 0.9 to 0.7), with the reconciliation recorded.
- Names use full words (`TcpConnection`, `ConnectionInfo`,
  `SessionContext`, `Input`, `Output`, `Buffer`).
- Unix sockets default to mode `0600`; naming a group gives `0660`.
- `dev/PLAN.md` (earlier, unreleased): the security crates have names and
  repositories (`shield-sec`, `sentinel-sec`); decisions D-010 to D-012.

---

## [0.1.0] - 2026-10-13

The scaffold and the plan. No functional code yet.

### Added

- Crate manifest (edition 2024, MSRV 1.85, no dependencies), `Apache-2.0 OR MIT`
  license, README, REPS, CI (Linux, macOS, Windows on stable and 1.85; audit
  and deny), `deny.toml`, `clippy.toml`, `rustfmt.toml`, `.gitattributes`.
- `dev/PLAN.md`: purpose, the request path and the protocol-free rule, scope
  and where excluded work lives (QUIC in `quic-net`, DNS in `dns-net`, TLS
  through a seam), design principles, architecture (modules, connection
  lifecycle, gate and TLS seams, drivers, PROXY protocol, limits, drain, UDP,
  local sockets), deployment modes, security responsibilities, ecosystem and
  dependencies, testing, open decisions, and the decision log.
- `dev/DIRECTIVES.md` and `dev/ROADMAP.md`.

[Unreleased]: https://github.com/jamesgober/net-io/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/jamesgober/net-io/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/jamesgober/net-io/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jamesgober/net-io/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/net-io/releases/tag/v0.1.0
