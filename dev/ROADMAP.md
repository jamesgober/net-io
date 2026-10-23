# net-io - Roadmap

> Path from scaffold to a stable 1.0. Hard parts are front-loaded; each phase has hard exit criteria.
> Design and decisions: [`PLAN.md`](./PLAN.md). The public API, item by item with the version that ships it: [`../docs/API.md`](../docs/API.md).
>
> **Anti-deferral rule:** no listed hard task moves to a later phase unless this file records the move and the reason.
>
> **After every version:** the release routine (section "Release routine" below), then the next version starts.

## Reconciliation with the 0.1 roadmap (recorded 2026-10-23, D-013)

| 0.1 roadmap | Now | Change and reason |
|---|---|---|
| 0.1.0 Scaffold (done) | 0.1 | none |
| 0.2.0 Design lock | 0.2 | adds the platform spikes, the reconciled roadmap, and every open decision answered or escalated |
| 0.3.0 TCP and the blocking driver | 0.3 | kept; adds the `Session` interface, `Completer`, control line, reserve descriptor, per-source cap, and the fault-injection shim, because the first consumers need them and they are cheap now and expensive to retrofit |
| 0.4.0 Edges | 0.4 extended | kept; adds listener hand-off (Unix), `Server::adopt`, and the gate on dialed connections |
| 0.5.0 Reactor | 0.5 feature complete | kept; adds Windows hand-off, Happy Eyeballs, and "every P0 and P1 item done" |
| (none) | 0.6 optimisation | new, required by the portfolio standard: competitor benchmarks and the P2 performance items |
| 0.9.0 Hardening | 0.7 hardening | moved earlier, where the standard places it; 0.9 becomes beta |
| (none) | 0.8 alpha | new: integration with serve-net and a non-HTTP service |
| (none) | 0.9 beta and release candidates | new |
| 1.0.0 Stable | 1.0 | kept, including DIRECTIVES done item 10 (the web stack and one non-HTTP service end to end) |

No hard task moved later: io_uring was "later, Linux only" in the 0.1 plan and is now after 1.0 with a recorded reason (D-015).

---

## v0.1.0 - Scaffold (DONE, 2026-10-13)
- [x] Manifest, README, CHANGELOG, REPS, dual license, CI, deny, clippy, rustfmt, DIRECTIVES, ROADMAP, PLAN.

## v0.2.0 - Design lock (DONE, 2026-10-23)
Exit: James approves `docs/API.md`; every spike has a written result; CI green.
- [x] `docs/API.md`: every public item with signatures, behaviour, errors, cost, grade, tier, version, examples; final names (D-017); final defaults with reasons.
- [x] `dev/SYS-SURFACE.md`: the OS functions, constants, and structs per platform, with the documentation each relies on.
- [x] `dev/PLAN.md` rewritten from the specification; decisions D-013 to D-060 logged.
- [x] This roadmap rewritten.
- [x] Gate seam shape proposed to bouncer-io for both 0.2 locks (D-018).
- [x] TLS seam condition (X-2) checked against rustls 0.23.46: holds (D-019).
- [x] Spikes S-1 to S-6 run on Windows and Linux; results and decisions D-016, D-052 to D-058 in PLAN section 15.
- [x] James approved the API (2026-10-23). Open decisions O-1, O-2, OD-26 stay open; none blocks 0.3 or 0.4.
- [x] Release routine: 0.2.0 tagged, released, published (claims the crate name, D-048).

## v0.3.0 - Core: TCP and the blocking driver (DONE, 2026-10-23)
Exit: a TCP echo service runs on Linux, macOS, and Windows under the blocking driver with every limit, hook, and close reason covered by socket tests; the 20-line echo example builds and runs; no allocation after warm-up on the hot path (counting allocator); the descriptor leak test passes for 100,000 connections; the layout cross-check passes; a consumer can build a server skeleton against the published 0.3.

| Area | Items (`docs/API.md`) |
|---|---|
| Tier 1 | `listen`, `connect`, `serve`, `serve_sessions`, `VERSION` |
| Errors | `NetError` (TCP variants), `ErrorClass`, `CloseReason`, `RefusalCause`, `LimitKind`, `TimeoutKind`, `KillReason`, `Direction`, `OsErrorClass`, `ConfigReason` |
| Addresses | `normalize`, `normalize_socket`, `Cidr`, `PrefixKey`, `PrefixPolicy`, `AddrError` |
| Identity | `ConnectionId`, `ListenerId`, `WorkerId`, `Lane`, `GateTag`, `ConnectionInfo` (TCP fields, `client_addr`, `client_key`, `for_testing`), `Transport`, `Origin`, `Endpoint` (Ip) |
| Limits | `Limits`, `LimitsBuilder` (all but `pressure`, `lane_reserve`), `MinRate`, `SizeClass` |
| TCP | `TcpListener` (all), `TcpConnection` (all but `send_file`, `set_gate`), `ConnectOptions` (without Happy Eyeballs), `connect_host` |
| Options | option rows graded P0/P1 (and `ttl`) for 0.3; `ListenOptions`, `TcpOptions`, `Keepalive`, `Linger`, `SocketOptions` |
| Gate | `Gate` (`Accept`), `Admitted`, `Refusal`, `WriteCheck`, `Denial`, `AllowAll`, `KillHandle` |
| Sessions | `Session`, `SessionFactory`, `Step`, `Phase`, `SessionContext`, `Input` (with `swap`), `Output` (without `push_file`), `SwapError`, `OutputFull` |
| Server | `ServerBuilder` (TCP listeners, `handler`, `sessions`), `ListenerSpec::tcp`, `Server` (door, drain, shutdown, `wait_for_stop`, handle, stats), `ServerHandle`, `DrainReport`, `Stats`, `ListenerInfo`, `DoorState` |
| Control, events | `ControlLine`, `ControlState`, `NoControl`, `SimpleControl`, `EventSink`, `NoopSink`, `Event` (TCP events, coalescing) |
| Completer | `Completer`, `PostError` (blocking driver) |
| Buffers, time | `Buffer`, `BufferPool`, `PoolStats`, `Clock`, `MonotonicClock`, `ManualClock`, `DriverKind` |
| Internals | blocking driver, timing wheel, pools with wipe, reserve descriptor, per-source table, `sys` for Linux, macOS, Windows (TCP subset), fault-injection shim; crate root moves to `deny(unsafe_code)` with `sys` allowed (D-014) |
| Tests | unit, socket integration, hostile peers, shim, property, loom, Miri, allocation, leak, layout; edge cases 1-29, 32-49, 51-61, 106-132 that apply to TCP |
| Benchmarks | baselines for B-2, B-7, B-8, B-13, B-14 (no competitor gate yet) |
| Docs | `docs/PLATFORM-NOTES.md` draft; `examples/echo_blocking.rs`, `echo_sessions.rs`, `kill_and_drain.rs`, `gate.rs` |

Done:
- [x] Every 0.3 item in the table above, in `src/`, with unit tests beside the code.
- [x] Socket integration and hostile-peer tests (`tests/server.rs`, `tests/edge.rs`): caps, `Busy`, the door, kill, drain, idle and read timeouts, slowloris, a peer that never reads, panics.
- [x] Every close reason of the blocking driver produced on a real socket with exactly one `Closed` event (`tests/close_reasons.rs`), and the exactly-once rule over random interleavings (`tests/interleave.rs`).
- [x] Fault injection (`tests/shim.rs`, `cfg(net_io_shim)`): accept error classes, `EMFILE` with the reserve, short and zero-byte sends, `EINTR`, spurious `EAGAIN`, keepalive `ETIMEDOUT`, system calls per round trip.
- [x] Property tests (CIDR and prefix keys, output stream, rate check; D-076), loom models (kill guard, completer ring, id blocks), Miri on the pure modules, layout checks against `libc` and `windows-sys`.
- [x] No allocation in steady-state echo (`tests/alloc.rs`); no descriptor leak over 100,000 connections (`tests/leak.rs`, CI runs the full count).
- [x] Benchmark baselines B-2, B-7, B-13, B-14 in `docs/PERFORMANCE.md`; `docs/PLATFORM-NOTES.md` draft; examples `echo_blocking`, `echo_sessions`, `kill_and_drain`, `gate`.
- [x] Appendix A cases mapped to their tests in `dev/EDGE-CASES.md`.
- [x] Decisions D-062 to D-080 logged.

Moved to a later version (anti-deferral record):

| Item | To | Reason |
|---|---|---|
| Timing wheel; appendix A cases 53 to 60; benchmark B-8 | 0.5 | D-063: a blocking worker holds one connection with at most five deadlines, carried by `SO_RCVTIMEO` or the wait timeout; the wheel pays off on the reactor, where one worker holds thousands. Nothing in 0.3 needs it |
| FreeBSD build, std-only fallback for other targets | 0.5 | D-064: both need the kqueue path or a second blocking path; 0.3 stops at a clear compile error on other targets |
| Appendix A case 11 (reads pause when the buffer budget is spent) | 0.5 | the blocking driver takes each worker's buffers at warm-up and validates the budget at build, so it cannot run dry mid-connection; pausing one connection's reads is reactor behaviour |
| Benchmark B-2 goal (1.2x the std thread-per-connection server) | 0.6 | measured under load with the `compare/` harness from 0.6, where the competitor gate starts; the 0.3 baseline (one connection, loopback) is at parity within noise |

## v0.4.0 - Extended: edges
Exit: net-io runs behind Apache and nginx over TCP and over a Unix socket with the real client address from PROXY v1 and v2; serves TLS directly through tls-net; a listener hand-off between two processes under 1,000 connections per second refuses zero connections (Linux and macOS); systemd socket activation and FastCGI descriptor 0 work in emulated tests and on one real host each.

| Area | Items |
|---|---|
| PROXY | `ProxyMode`, `ProxyVersions`, `ProxyParser`, `ProxyProgress`, `ProxyHeader`, `Tlvs`, `Tlv`, `ProxyAddress`, `ProxySsl`, `ProxyFacts`, `ProxyError`, CRC32C, server integration, `Gate::readmit`, `ConnectionInfo::real_peer` |
| Trusted proxies | `TrustedProxies` |
| UDP | `UdpSocket` (bind, recv/send, connect, guard, budgets, `mark_verified`), `Datagram`, `UdpOptions`, `UdpBudget` (`UdpSession` at 0.6) |
| Unix sockets | `UnixListener`, `UnixConnection`, `LocalOptions`, `peer_credentials`, `send_descriptors`, `recv_descriptors`, `Descriptors`, `bind_atomic`, `listen_local` / `connect_local` on Unix, `ListenerSpec::unix` |
| TLS seam | `TlsAcceptor`, `TlsSession`, `TlsProgress`, `TlsEvent`, `TlsCloseKind`, `TlsInfo`, `TlsError`, `TlsFailure`, `NoTls`, server integration; tls-net built against 0.4 in its own repository |
| Restarts | `systemd`, `systemd_named`, `fastcgi_listener`, `InheritedListener`, `InheritError`, `ListenerHandle`, `send_listeners`, `recv_listeners`, `HandoffPeer`, `HandoffError`, `Server::release_listeners`, `ListenerSpec::adopt` |
| Back-channel | `Server::adopt`, `AdoptSpec`, `AdmitStage::{Adopt, Dialed}`, `TcpConnection::set_gate` |
| Tests | fuzz targets (PROXY, manifest, systemd environment, CIDR, trusted proxies); conformance vectors; cross-process tests; edge cases 13-17, 76-85, 90-104 |
| Docs | `docs/SECURITY.md` draft; examples `behind_proxy.rs`, `unix_socket.rs`, `handoff_restart.rs`, `systemd_activation.rs`, `fastcgi_detect.rs`, `udp_echo.rs` |

## v0.5.0 - Feature complete
Exit: 10,000 idle connections held on each OS with bounded memory, and throughput at or above the blocking driver for active connections; Windows hand-off refuses zero connections under load; every P0 and P1 item is in `docs/API.md` and tested.

| Area | Items |
|---|---|
| Reactor | epoll (Linux), kqueue (macOS, FreeBSD), IOCP (Windows) with zero-byte receives and one `WSAPoll` accept thread per listener (D-016); `DriverKind::Reactor`, `Auto`; accept distribution; `Completer` on the reactor; the timing wheel with appendix A cases 53 to 60 and B-8 (moved from 0.3, D-063); buffer-budget back-pressure (case 11) |
| Driver API | `Driver`, `Operation`, `OperationKind`, `Completion`, `Completions`, `Token`, `Rejected`, `DriverWaker` public (Tier 3, unstable until 1.0) |
| Windows local | AF_UNIX on Windows, `PipeListener`, `PipeConnection`, `PipeOptions`, `PipeSecurity`, `client_pid`, `listen_local` / `connect_local` on Windows, `ListenerSpec::pipe` |
| Windows hand-off | `share_listeners`, `SharedListeners`, `receive_shared` with the single-use nonce (D-054); listeners never associated with a completion port (D-016) |
| Outbound | Happy Eyeballs (`ConnectOptions::happy_eyeballs`, `attempt_delay`) |
| Platform | FreeBSD in CI (D-035); the std-only fallback for other targets (D-064); ASan and TSan jobs |
| Completeness | every P0 and P1 item shipped |
| Docs | `docs/ARCHITECTURE.md` draft; examples `named_pipe.rs`, `offload_completer.rs` |

## v0.6.0 - Optimisation
Exit: every benchmark meets the 1.2x gate against the best Rust competitor at equal or stronger security, or the miss is recorded with James's written decision; no regression over 5% between 0.5 and 0.6 baselines; every P2 item shipped or moved here with a reason.

Items: `compare/` harness; B-1 to B-14 in `docs/PERFORMANCE.md`; P2 items: `SO_REUSEPORT` per-worker listeners, `incoming_cpu`, `defer_accept`, server `fast_open`, `user_timeout`, `send_file` / `Output::push_file`, UDP `recv_batch` / `send_batch` (`DatagramBuffer`, `OutgoingDatagram`), packet info, multicast (`MulticastInterface`), `UdpSession` / `UdpContext` / `ListenerSpec::udp`, `Placement`, adaptive deadlines (`Pressure`), `lane_reserve`, `ListenerSpec::lockdown_allowed`, `encode_v1` / `encode_v2`, FastCGI on Windows if OD-26 says so.

## v0.7.0 - Hardening
Exit: zero open findings of severity medium or above; the soak shows no memory, descriptor, or handle growth and no stuck connection.

Items: continuous fuzzing of every target with no open crash; every threat in PLAN 8.2 has its attack test passing; full shim coverage (every `sys` call site with each error class); 24-hour soak with mixed normal and hostile peers on Linux, Windows, macOS; adversarial review of the whole crate with findings fixed test-first; `docs/SECURITY.md` final.

## v0.8.0 - Alpha
Exit: two consumers in daily use for two weeks without a net-io defect of severity medium or above.

Items: serve-net and a request pipeline run on net-io; one non-HTTP consumer (HiveDB network layer, raft-io, or rpc-io) runs on it; the executor adapter (feature `executor`, D-030) built and tested against the executor's published version; `docs/ARCHITECTURE.md` and `docs/PLATFORM-NOTES.md` drafts complete; API changes from integration recorded in PLAN.

## v0.9.0 - Beta and release candidates
Exit: no API change requested by consumers for the final release candidate; the audit checklist for `docs/STABILITY-1.0.md` complete except the sign-off.

Items: API freeze candidate; 72-hour soak; external review of every `sys` `unsafe` block against its `// SAFETY:` comment; all documentation final; `0.9.x` release candidates for consumers.

## v1.0.0 - Stable
Exit: DIRECTIVES done item 10 (the web stack and one non-HTTP service used the API end to end); the full audit passed and recorded in `docs/STABILITY-1.0.md`; **James's go/no-go** before the tag.

Items: API frozen until 2.0; MSRV frozen (a raise is a major change).

## After 1.0 (P3, additive)
io_uring driver (feature `uring`, D-015), NUMA-aware pools, UDP GSO/GRO, kTLS hand-off, `notsent_lowat`, `quickack`, client TCP Fast Open, Linux abstract sockets, FreeBSD accept filters and `SO_REUSEPORT_LB`, `SO_ATTACH_REUSEPORT_CBPF` steering, hardware CRC32C, a public `Wheel`, `dscp`.

---

## Release routine (after every version)

1. Finish the version: every item done; version bumped everywhere it appears (`Cargo.toml`, README install snippet, `docs/API.md`, rustdoc examples); `CHANGELOG.md` rolled; `docs/release/vX.Y.Z.md` written; README and `docs/API.md` checked against the build.
2. Local gate on Windows and WSL, stable and 1.85: fmt, clippy (default, all, no default features), tests, `cargo doc` (default and all features, `-D warnings`), `cargo package` in a fresh target directory; plus the unsafe-location grep, the layout cross-check, and loom on WSL.
3. Commit and push on a `feature/` branch with a pull request.
4. Wait for CI on every platform; fix in place if red; never cut a patch release for a red version.
5. Squash-merge; tag `vX.Y.Z` (lightweight) and push it.
6. `gh release create vX.Y.Z --title "vX.Y.Z - <Name>" --notes-file docs/release/vX.Y.Z.md`, pre-release for 0.x.
7. `cargo doc --no-deps` with default and all features under `RUSTDOCFLAGS=-D warnings`.
8. `cargo publish --dry-run`, then `cargo publish`.
9. Verify the version on crates.io and the docs.rs build.
