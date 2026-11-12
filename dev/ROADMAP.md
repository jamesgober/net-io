# net-io - Roadmap

> Path from scaffold to a stable 1.0. Hard parts are front-loaded; each phase has hard exit criteria.
> Design and decisions: [`PLAN.md`](./PLAN.md). The public API, item by item with the version that ships it: [`../docs/API.md`](../docs/API.md).
>
> **Anti-deferral rule:** no listed hard task moves to a later phase unless this file records the move and the reason.
>
> **After every version:** the release routine (section "Release routine" below), then the next version starts.
>
> **Nothing accepted mid-series becomes final silently.** Every accepted gap, deferred item, known issue, platform caveat, and missed target goes into the register at the end of this file when it is accepted. The pre-1.0 polish milestone (0.9.x) works through all of it, and whatever is still open goes into the 1.0 readiness note for James (D-102).

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

## v0.3.0 - Core: TCP and the blocking driver (DONE, 2026-10-26)
Exit: a TCP echo service runs on Linux, macOS, and Windows under the blocking driver with every limit, hook, and close reason covered by socket tests; the 20-line echo example builds and runs; no allocation after warm-up on the hot path (counting allocator); the descriptor leak test passes for 100,000 connections; the layout cross-check passes; a consumer can build a server skeleton against the published 0.3.

| Area | Items (`docs/API.md`) |
|---|---|
| Tier 1 | `listen`, `connect`, `serve`, `serve_sessions`, `VERSION` |
| Errors | `NetError` (TCP variants), `ErrorClass`, `CloseReason`, `RefusalCause`, `LimitKind`, `TimeoutKind`, `KillReason`, `Direction`, `OsErrorClass`, `ConfigReason` |
| Addresses | `normalize`, `normalize_socket`, `Cidr`, `PrefixKey`, `PrefixPolicy`, `AddrError`, `TrustedProxies` (moved from 0.4 for serve-net, D-081) |
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
- [x] Decisions D-062 to D-081 logged; `TrustedProxies` and `SessionContext::set_idle_timeout` added at serve-net's request (D-081).

Moved to a later version (anti-deferral record):

| Item | To | Reason |
|---|---|---|
| Timing wheel; appendix A cases 53 to 60; benchmark B-8 | 0.5 | D-063: a blocking worker holds one connection with at most five deadlines, carried by `SO_RCVTIMEO` or the wait timeout; the wheel pays off on the reactor, where one worker holds thousands. Nothing in 0.3 needs it |
| FreeBSD build, std-only fallback for other targets | 0.5 | D-064: both need the kqueue path or a second blocking path; 0.3 stops at a clear compile error on other targets |
| Appendix A case 11 (reads pause when the buffer budget is spent) | 0.5 | the blocking driver takes each worker's buffers at warm-up and validates the budget at build, so it cannot run dry mid-connection; pausing one connection's reads is reactor behaviour |
| Benchmark B-2 goal (1.2x the std thread-per-connection server) | 0.6 | measured under load with the `compare/` harness from 0.6, where the competitor gate starts; the 0.3 baseline (one connection, loopback) is at parity within noise |

## v0.4.0 - Extended: edges (DONE, 2026-10-29)
Exit: net-io runs behind Apache and nginx over TCP and over a Unix socket with the real client address from PROXY v1 and v2; serves TLS directly through tls-net; a listener hand-off between two processes under 1,000 connections per second refuses zero connections (Linux and macOS); systemd socket activation and FastCGI descriptor 0 work in emulated tests and on one real host each.

| Area | Items |
|---|---|
| PROXY | `ProxyMode`, `ProxyVersions`, `ProxyParser`, `ProxyProgress`, `ProxyHeader`, `Tlvs`, `Tlv`, `ProxyAddress`, `ProxySsl`, `ProxyFacts`, `ProxyError`, CRC32C, server integration, `Gate::readmit`, `ConnectionInfo::real_peer` |
| Trusted proxies | per-listener trusted proxies for PROXY (`TrustedProxies` itself shipped in 0.3, D-081) |
| UDP | `UdpSocket` (bind, recv/send, connect, guard, budgets, `mark_verified`), `Datagram`, `UdpOptions`, `UdpBudget` (`UdpSession` at 0.6) |
| Unix sockets | `UnixListener`, `UnixConnection`, `LocalOptions`, `peer_credentials`, `send_descriptors`, `recv_descriptors`, `Descriptors`, `bind_atomic`, `listen_local` / `connect_local` on Unix, `ListenerSpec::unix` |
| TLS seam | `TlsAcceptor`, `TlsSession`, `TlsProgress`, `TlsEvent`, `TlsCloseKind`, `TlsInfo`, `TlsError`, `TlsFailure`, `NoTls`, server integration; tls-net built against 0.4 in its own repository |
| Restarts | `systemd`, `systemd_named`, `fastcgi_listener`, `InheritedListener`, `InheritError`, `ListenerHandle`, `send_listeners`, `recv_listeners`, `HandoffPeer`, `HandoffError`, `Server::release_listeners`, `ListenerSpec::adopt`; `Server::add_listener` / `remove_listener` and the raw monotonic clock for `MONOTONIC_USEC` (serve-net 0.4 reload and systemd, D-081) |
| Back-channel | `Server::adopt`, `AdoptSpec`, `AdmitStage::{Adopt, Dialed}`, `TcpConnection::set_gate` |
| Tests | fuzz targets (PROXY, manifest, systemd environment, CIDR, trusted proxies); conformance vectors; cross-process tests; edge cases 13-17, 76-85, 90-104 |
| Docs | `docs/SECURITY.md` draft; examples `behind_proxy.rs`, `unix_socket.rs`, `handoff_restart.rs`, `systemd_activation.rs`, `fastcgi_detect.rs`, `udp_echo.rs` |

Done:
- [x] PROXY v1 and v2 (strict sans-IO parser, CRC32C, every TLV) and its server integration with per-listener trusted proxies, the handshake deadline, the source slot moved to the real client, and `Gate::readmit` (D-088).
- [x] The TLS seam on listeners: records decrypted in place, one gate check per plaintext write, `close_notify` on graceful closes (D-089, D-090).
- [x] Unix domain sockets: mode and owner set before `listen`, `bind_atomic`, stale-socket rules, peer credentials, `require_uid`, descriptor passing, `listen_local` / `connect_local`, server listeners (D-091 to D-095).
- [x] UDP with truncation detection, per-source and global budgets, a bounded source table, and the amplification guard (D-096).
- [x] Restarts: `add_listener` / `remove_listener` on a running server (D-097); systemd and FastCGI inheritance (D-098); listener hand-off with a checksummed manifest (D-099); `Server::adopt`, `TcpConnection::set_gate` (D-100); `monotonic_micros` (D-101).
- [x] Edge cases 13-17, 76-85, 90-103, 111, 112 mapped to tests in `dev/EDGE-CASES.md`.
- [x] Fuzz targets `proxy`, `manifest`, `systemd_env`, `cidr`, `trusted` (`fuzz/`; 60 s each locally without a finding, 30 s each in CI per push).
- [x] Cross-process tests: a hand-off between two processes under about 1,000 connections per second with zero refused connections (Linux and macOS in CI), systemd activation through `systemd-socket-activate`, a listener as a child's descriptor 0.
- [x] CI job running net-io behind HAProxy (PROXY v1 and v2) and nginx (v1), each over TCP and a Unix socket, checking the client address end to end.
- [x] `docs/SECURITY.md` draft with the threat table; the six examples; `docs/PLATFORM-NOTES.md` for the new transports.

Exit criteria, as met:

| Criterion | Status |
|---|---|
| Behind a proxy over TCP and a Unix socket with the real client address from PROXY v1 and v2 | HAProxy (v1, v2) and nginx (v1) in CI. Apache cannot be tested here: its `mod_proxy` does not send the PROXY protocol (`mod_remoteip` only receives it), so "behind Apache" means Apache in front over HTTP or `mod_fcgid` starting net-io, which the FastCGI test covers |
| Serves TLS directly through tls-net | net-io's side is tested with an engine in `tests/tls.rs`; building tls-net against the published 0.4 is tls-net's own release step in its repository |
| Hand-off between two processes under 1,000 connections per second refuses zero connections (Linux and macOS) | `cross_process::handoff_between_processes_refuses_nothing_under_load`, run by CI on both |
| systemd activation and FastCGI descriptor 0 in emulated tests and on one real host each | systemd: `systemd-socket-activate` on Linux (WSL2 and the CI runner). FastCGI: emulated exactly as `mod_fcgid` starts a server (the listening socket as the child's descriptor 0); no FastCGI manager was available on the build host |

Moved to a later version (anti-deferral record):

| Item | To | Reason |
|---|---|---|
| Edge cases 104, 105 (Windows hand-off) | 0.5 | they belong to the Windows hand-off, scheduled with named pipes |
| Hash-flooding chain test (threat T-22) | 0.7 | the per-source tables use `std`'s keyed SipHash; the chain-length attack test is part of the 0.7 hardening suite |

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

Done:
- [x] The timing wheel: six levels, lazy extension, tickless, never early; cases 53 to 60; B-8 (D-105).
- [x] The reactor on epoll, kqueue, and IOCP with sessions, PROXY, TLS, drain, kill, sheds, and `Completer` (D-103 to D-112).
- [x] `Driver` public, with `new_reactor_driver` (D-121).
- [x] Reads pause on an empty buffer budget, case 11 (D-111).
- [x] Windows: named pipes (D-113, D-114), AF_UNIX (D-115), the hand-off (D-116); cases 62 to 66, 68, 69, 86 to 89, 104, 105.
- [x] Happy Eyeballs (D-117); FreeBSD in CI (D-118); ASan and TSan jobs; every suite on the pool with `net_io_force_blocking` (D-120).
- [x] `docs/ARCHITECTURE.md` draft; examples `named_pipe`, `offload_completer`.

Exit criteria, as met:

| Criterion | Status |
|---|---|
| 10,000 idle connections held on each OS with bounded memory | `tests/idle.rs`: 1,730 bytes of heap each on Linux, 1,840 on Windows, no read buffers; the `idle` CI job runs it on Linux, macOS, and Windows. Kernel memory per socket is the OS's |
| Throughput at or above the blocking driver for active connections | Met: Windows 1.11x at 64 connections and 1.63x at 256; Linux on GitHub's runner 1.16x and 1.20x, with less CPU per round trip. On one connection the reactor is 0.97x the pool on Linux, one more system call. On a WSL2 guest under load 45 to 65 Linux was 0.25x: register R-20 |
| Windows hand-off refuses zero connections under load | `windows_handoff::handoff_between_processes_refuses_nothing_under_load`, in CI |
| Every P0 and P1 item in `docs/API.md` and tested | yes, except `send_file` and what the API marks for later |

Moved to a later version (anti-deferral record):

| Item | To | Reason |
|---|---|---|
| Std-only fallback for other targets | 0.6 | D-119: needs a cfg alias across about 70 sites and a CI run of its own; no consumer needs another target; the compile error says so |

## v0.6.0 - Optimisation
Exit: every benchmark meets the 1.2x gate against the best Rust competitor at equal or stronger security, or the miss is recorded with James's written decision; no regression over 5% between 0.5 and 0.6 baselines; every P2 item shipped or moved here with a reason.

Items: `compare/` harness; B-1 to B-14 in `docs/PERFORMANCE.md`; P2 items: `SO_REUSEPORT` per-worker listeners, `incoming_cpu`, `defer_accept`, server `fast_open`, `user_timeout`, `send_file` / `Output::push_file`, UDP `recv_batch` / `send_batch` (`DatagramBuffer`, `OutgoingDatagram`), packet info, multicast (`MulticastInterface`), `UdpSession` / `UdpContext` / `ListenerSpec::udp`, `Placement`, adaptive deadlines (`Pressure`), `lane_reserve`, `ListenerSpec::lockdown_allowed`, `encode_v1` / `encode_v2`, FastCGI on Windows if OD-26 says so.

Done:
- [x] Listener and socket options `defer_accept`, `fast_open`, `incoming_cpu`, `user_timeout` (D-122).
- [x] Files: `send_file`, `Output::push_file`, `sendfile` and `TransmitFile` (D-123, D-124).
- [x] UDP batches, packet info on Unix, multicast, `UdpSession` listeners (D-125 to D-127).
- [x] `Pressure`, `lane_reserve`, `lockdown_allowed`, `Placement`, `encode_v1` / `encode_v2` (D-128 to D-130).
- [x] Per-worker `SO_REUSEPORT` listeners on Linux (D-131); the std-only fallback moved after 1.0 (D-132).
- [x] `compare/` and B-1 to B-14 in `docs/PERFORMANCE.md` (D-133); `benches/lifecycle.rs`.
- [x] The 16 KiB stall found and fixed, with the test that would have caught it (D-134); kqueue's write filter only while asked (D-135).
- [x] The accept storm test T-19, bounded so it never empties the port range (D-136).

Exit criteria, as met:

| Criterion | Status |
|---|---|
| Every benchmark meets the 1.2x gate, or the miss is recorded with James's written decision | Missed, R-30: see `docs/PERFORMANCE.md`. James's decision (2026-11-04, D-139): accept the miss for 0.6.0; re-run the gate on a dedicated, quiet load machine at 0.9.x; before 1.0 the gate is met or the target is derived again with the reason written down |
| No regression over 5% between 0.5 and 0.6 | Met: `cargo bench --bench echo` from the v0.5.0 tag and from this branch, alternated three times on the build host. Medians: B-1 reactor +4% at 64 connections and +2% at 256, CPU per round trip -6% and +3%; B-2 p50 within 0.2 us on every stack (worst +1.4%). `docs/PERFORMANCE.md` |
| Every P2 item shipped or moved here with a reason | Shipped, except packet info on Windows (D-126) and FastCGI on Windows (OD-26, below) |

Moved to a later version (anti-deferral record):

| Item | To | Reason |
|---|---|---|
| Std-only fallback for other targets | after 1.0 | D-132 |
| Packet info on Windows | after 1.0, on request | D-126: needs `WSARecvMsg` through an extension pointer; no consumer asks |
| FastCGI on Windows | after 1.0 | OD-26, D-139: no Windows FastCGI deployment is planned |
| Physical-core pinning, open-loop generator, B-6 competitor row | 0.9.x | R-28, R-29, R-33 |

## v0.7.0 - Hardening
Exit: zero open findings of severity medium or above; the soak shows no memory, descriptor, or handle growth and no stuck connection.

Items: continuous fuzzing of every target with no open crash; every threat in PLAN 8.2 has its attack test passing; full shim coverage (every `sys` call site with each error class); 24-hour soak with mixed normal and hostile peers on Linux, Windows, macOS; adversarial review of the whole crate with findings fixed test-first; `docs/SECURITY.md` final.

A database consumer's transport needs, added 2026-11-04 (D-140). The two that are transport hardening land here; the third needs the executor adapter and lands with it in 0.8:
- **Bulk transfer that cannot starve small requests.** Files already go out by `sendfile` and `TransmitFile` (0.6). Measure a small request's p99 and p99.9 on a worker that also streams a file to a fast reader, bound what one connection sends per reactor turn, and add receiving into a file (`splice` on Linux, a copy elsewhere) for snapshot and log shipping.
- **An outbound client that survives its server.** Connect exists; add reconnect with backoff and jitter, a health probe that does not consume data, and a graceful client-side drain. Pooling stays in the pooling crates (PLAN section 3); the soak runs these through a small test pool while the server restarts and kills connections.
- **Tail latency through the `executor` adapter** (0.8): p99 and p99.9 measured through the adapter, beside the reactor's own numbers.

The plan for each item:

| Item | Plan |
|---|---|
| Fuzzing | every parser has a target (PROXY, CIDR, trusted lists, manifest, systemd environment) plus new stateful targets for the timing wheel, the rate counter, and the UDP source table against models; a scheduled CI workflow runs each target for longer than the per-push 30 s and keeps the corpus between runs |
| Threat tests | every row of `docs/SECURITY.md` names a passing test, or a later version with a reason |
| Shim coverage | a list of every `sys` call site, each with an injected error test, checked by a test that fails when a new site has none |
| Soak | `tests/soak.rs`, driven by `NET_IO_SOAK_SECS`: normal clients, big writers whose replies take several output buffers a flush (the 0.6.0 budget leak, D-169), slowloris and slow readers, floods at the cap, kills, and client reconnects through a test pool, sampling memory, descriptors or handles, and open connections; 24 hours on the build host's Windows and Linux. macOS runs on GitHub's hosted runner, whose jobs stop at 6 hours, so it runs 5.5 hours there per driver (`.github/workflows/soak.yml`, recorded with the result) |
| Review | six independent reviews of the crate (link and sessions, reactor and drivers, engine and admission, Unix `sys`, Windows `sys`, parsers and UDP); every finding fixed test-first or recorded with a reason |

Done:
- [x] Six independent reviews of the crate: 1 critical, 2 high, 24 medium, 33 low. Every critical, high, and medium finding fixed with a test that failed before it, or shown not to be a defect (D-143 to D-161); the lows fixed or entered in the register (R-34 to R-41).
- [x] Attack tests for every threat in `docs/SECURITY.md`, now final (T-1 to T-52).
- [x] Fuzzing: stateful targets `wheel`, `rate`, and `udp` (the UDP guard against a model, D-171; `rate` found D-153 at once); every target runs 30 s per push and 10 minutes nightly with the corpus kept.
- [x] Shim: the reactor's wait failing, a file stream giving way, the descriptor routine's reset.
- [x] A database consumer's needs: bulk files give way every 256 KiB (D-141); receiving into a file, by `splice` on Linux (D-170); `Backoff`, `connect_retry`, `probe`, `drain` (D-142); tail latency through the executor adapter scheduled with it in 0.8 (D-140).
- [x] `tests/soak.rs`: normal, pooled, big-writer, and hostile peers with memory, handle, and connection sampling.
- [x] 0.6.1 merged in: the output-buffer leak fix (D-169) and serve-net's requests 4 and 7.

## v0.8.0 - Alpha
Exit: two consumers in daily use for two weeks without a net-io defect of severity medium or above.

Items: bouncer-io's close requests (D-182): a flush-then-close after a denial or a refusal with bytes, bounded by `Limits::denial_linger`, and `close_after_flush` by connection id for its ejector, each with its cost in the release notes; serve-net and a request pipeline run on net-io; one non-HTTP consumer (a database's network layer, raft-io, or rpc-io) runs on it; the executor adapter (feature `executor`, D-030) built and tested against the executor's published version, with p99 and p99.9 measured through it beside the reactor's own (a database consumer's need, D-140); serve-net's open requests: a drain-start hook (`Session::on_drain`, so a WebSocket can send its 1001 Close before a drain closes it; both drivers' drain paths change), workers kept for a listener on the reactor (so an admin listener keeps a worker under a flood on the public one), and an answer, with a CI test, on two `Server`s sharing one listening socket in one process on Windows through `release_listeners` (register R-43); tls-net's handshake needs (D-180): one send for what a turn produced (tickets, response, and `close_notify` together, 4 sends a connection to 2; built, D-194), and per-worker listeners accepted in the worker's own loop (built, D-197), each measured against tokio-rustls for tls-net's 1.2x handshake target; `docs/ARCHITECTURE.md` and `docs/PLATFORM-NOTES.md` drafts complete (done for 0.8.0 on 2026-11-08: the per-worker accept, the three close shapes, the drain rules, TLS buffers, lost resets on the BSDs, Windows TIME_WAIT); API changes from integration recorded in PLAN.

## v0.9.0 - Beta and release candidates
Exit: no API change requested by consumers for the final release candidate; the audit checklist for `docs/STABILITY-1.0.md` complete except the sign-off.

Items: API freeze candidate; 72-hour soak; external review of every `sys` `unsafe` block against its `// SAFETY:` comment; all documentation final; `0.9.x` release candidates for consumers.

## v0.9.x - Pre-1.0 polish (before any 1.0 release candidate)
Exit: every entry in the register below is closed (fixed, measured and accepted with a reason, or moved after 1.0 with a reason); a fresh performance pass and a fresh security and edge-case review are recorded; the 1.0 readiness note for James is written. No `1.0.0-rc` is cut before this exit.

Standing rule from James: "make sure to go back and fix any issues / perf tune / etc before we get close to release."

Items:
- **Revisit the register.** Every accepted gap, deferred item, known issue, platform note, and missed target, one by one: fix it, or measure it and record why it stays (with the cost of fixing it), or move it after 1.0 with a reason. Nothing stays open by default.
- **Performance tuning pass.** Re-run every benchmark in `docs/PERFORMANCE.md` (B-1 to B-14) against the competitor harness on Linux, macOS, and Windows; profile the hot paths (accept, read, write, close, the gate check, the timing wheel); try to remove the extra system call per round trip on macOS and Windows; publish before and after numbers. A missed target is either met or written into the readiness note with its gap.
- **The 1.2x gate on a quiet machine (required, R-30, D-139, D-172).** Re-run `compare/` on the 32-thread build host in a quiet window, with the load generator and the server under test pinned to separate core sets (`Placement` for net-io, `taskset` or affinity masks for the generator and the other stacks), plus the hosted-runner numbers. Before 1.0 the gate is met, or the target is derived again from those numbers with the reason written down; the 0.6.0 acceptance does not carry to 1.0. A run with the generator on a separate machine is listed in the readiness note as an open item.
- **Security and edge-case review.** Re-run the threat table in `docs/SECURITY.md` (every attack test), every case in `dev/EDGE-CASES.md`, extended fuzzing of every target, and an adversarial read of every change since 0.7's review; findings fixed test-first.
- **Platform notes.** Every caveat in `docs/PLATFORM-NOTES.md` is checked again on current OS versions: still true, still needed, still the best available behaviour.
- **1.0 readiness note** (`docs/STABILITY-1.0.md`, section "Open at 1.0"): in plain English, every item still open, what it costs a user, and a recommendation, for James's go/no-go.

## v1.0.0 - Stable
Exit: DIRECTIVES done item 10 (the web stack and one non-HTTP service used the API end to end); the 0.9.x polish milestone done and its readiness note written; the full audit passed and recorded in `docs/STABILITY-1.0.md`; **James's go/no-go** before the tag.

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

---

## Register: accepted gaps, deferrals, known issues, missed targets

Every entry is revisited in the 0.9.x polish milestone. Add an entry in the same change that accepts the gap. Close an entry only with the change that fixes it, or with a measured reason in this table.

| # | Since | Kind | Item | Current state | Revisit |
|---|---|---|---|---|---|
| R-1 | 0.3 | missed target | macOS: 3 system calls per keep-alive round trip, against 2 on Linux (a `poll` before every receive, D-083) | measured; the Linux model does not hold on macOS | reactor (0.5) and the 0.9.x performance pass |
| R-2 | 0.3 | missed target | Windows: 3 system calls per round trip (`WSAPoll` before every receive, D-052) | measured; required by Microsoft's documented timeout semantics | IOCP reactor (0.5) and the 0.9.x performance pass |
| R-3 | 0.3 | closed | B-2 goal of 1.2x the std thread-per-connection server | 0.6 replaced it with the competitor gate: on CI, B-2 std is 1.07x tokio and net-io's reactor 0.94x to 1.01x; one connection on loopback measures the kernel. Carried by R-30 | closed into R-30 |
| R-4 | 0.3 | platform note | Windows send-buffer autotuning lets a peer that never reads absorb tens of MiB before the write timeout; operators must set `ListenOptions::send_buffer` | documented in `docs/PLATFORM-NOTES.md` | consider a bounded default for internet-facing listeners |
| R-5 | 0.3 | platform note | Windows: each worker's wake channel holds one loopback UDP port; many servers in one process can hit `WSAENOBUFS` | documented | reactor (0.5) wake mechanism |
| R-6 | 0.3 | deferred | timing wheel, appendix A cases 53 to 60, benchmark B-8, case 11 (reads pause on an empty budget), FreeBSD and the std-only fallback | all done in 0.5 except the fallback (D-119) | fallback at 0.6 |
| R-7 | 0.4 | platform note | macOS has no atomic close-on-exec for accepted, received, or inherited descriptors (a fork plus exec on another thread can inherit one) | documented | check current macOS for a race-free option |
| R-8 | 0.4 | platform note | a refusal that writes bytes is followed by RST; Windows discards unread bytes on RST, so a Windows peer may not see the refusal | documented; the RST is deliberate (threat T-44) | measure a FIN close under refusal floods; decide |
| R-9 | 0.4 | platform note | UDP truncation reports the copied length on macOS and Windows (the real length only on Linux) | documented | check `recvmsg` options on current OS versions |
| R-10 | 0.4 | accepted gap | a `BlockingHandler` receives Unix connections as a `TcpConnection` (`peer_addr` unspecified, socket options fail) (D-093) | documented | a connection type shared by every transport with the reactor API (0.5) |
| R-11 | 0.4 | accepted gap | an adopted Unix socket's file is never removed by the adopting process (D-098) | documented | find a safe identity check, or keep with the reason |
| R-12 | 0.4 | accepted gap | the hand-off manifest carries no options digest (D-099) | address check against `getsockname` instead | re-check during the security review |
| R-13 | 0.4 | missed criterion | "behind Apache": Apache's `mod_proxy` does not send the PROXY protocol; HAProxy and nginx are tested instead | recorded in the 0.4 exit table | confirm the Apache deployment shape with serve-net |
| R-14 | 0.4 | missed criterion | TLS served through tls-net was not built against 0.4 here; net-io's side is tested with a test engine | tls-net's release step | integration test with the published tls-net |
| R-15 | 0.4 | missed criterion | FastCGI descriptor 0 tested by emulating `mod_fcgid`, not under a real FastCGI manager | no manager on the build host | run under `mod_fcgid` or `spawn-fcgi` once |
| R-16 | 0.4 | deferred | hash-flooding chain test for the per-source tables (threat T-22) | `std` keyed SipHash in use | 0.7 hardening |
| R-17 | 0.4 | deferred | Windows hand-off, edge cases 104 and 105 | closed in 0.5 (D-116) | closed |
| R-18 | 0.5 | missed target | an idle reactor connection's state is 848 bytes on 64-bit Linux, against the 512-byte estimate (1,384 before limits and rate settings were shared and TLS state boxed) | B-5 on CI: 1,239 bytes of resident memory per idle connection at 10,000 (tokio 8,993, monoio 16,963, mio 88); B-6 on the build host: 511 bytes at 100,000. Boxing what is read only at the next event adds one allocation per connection and a pointer per event | retry at the 0.9 tuning pass with measured allocation cost |
| R-19 | 0.5 | closed | the reactor's accept path keeps one accept thread per listener | D-131: `ListenOptions::per_worker` gives each worker its own `SO_REUSEPORT` socket. Measured against B-1 on CI: 1.08x tokio, against 1.07x with the shared accept thread, so the default stays. The accept gap to mio (1.24x) is R-30 | closed |
| R-20 | 0.5 | open question | reactor throughput depends on the host. GitHub's runner at 0.6: 1.05x the pool at 64 connections and 1.25x at 256, with less CPU per round trip (13.6 us against 15.0); 0.5 on the same kind of runner was 1.16x and 1.20x. A WSL2 guest under load 45 to 65 was 0.25x | hypothesis: epoll wakes without the synchronous hint on kernels before 6.13, so on a busy host a worker waits for a CPU where a blocked thread would not. Not tested at 0.6: the test needs a dedicated Linux host, which this project does not have yet. Method: a dedicated host, then 6.13 or later, then a short poll before sleeping and `SO_INCOMING_CPU` placement (now built, D-131), each with its idle CPU cost | 0.9.x tuning pass |
| R-21 | 0.5 | missed target | B-8 on CI at 0.6: insert 22.4 and 30.9 ns, lazy extend 3.9 and 2.6 ns, cancel 5.5 and 4.7 ns on two runs; targets under 20, 2, and 20 ns. 0.5 on CI met all three (17.0, 1.5, 2.3) | `src/wheel.rs` has not changed since 0.5, so the spread is the runner; insert and lazy extend miss on slower runners | 0.9.x tuning pass, on a quiet host with pinned cores |
| R-22 | 0.5 | missed target | Windows reactor: 3.50 system calls per round trip at 0.6 (4 at 0.5; target 3): the zero-byte receive after an exchange | one idle buffer saved per connection; hypothesis: keep a real receive pending for a connection active in the last tick, cancelling on the idle timer, with its cost in pinned buffers | 0.9.x tuning pass |
| R-23 | 0.5 | accepted gap | pipe and Windows AF_UNIX listeners cannot be handed off; `release_listeners` reports `Unsupported` for them | a pipe has no socket to duplicate; a new process can create the next instance under the same name, which needs its own overlap design | revisit with a consumer |
| R-24 | 0.5 | closed | kqueue's write filter fired after ACKs: 3.05 to 3.13 system calls per round trip on macOS, against 3 | D-135: the filter exists only while a send or connect waits; macOS measures 3.00 on CI | closed |
| R-25 | 0.5 | accepted gap | a pipe on the reactor writes one chunk per system call (no gather) | not measured at 0.6: no pipe benchmark exists, and no consumer sends volume over a pipe; short sends are handled | 0.9.x tuning pass: build the pipe benchmark, then decide |
| R-26 | 0.5 | platform note | Windows AF_UNIX: a replaced socket file is removed by the old listener's `Drop` (no identity check; std has no stable file id) | documented | re-check with `GetFileInformationByHandle` at 0.9.x |
| R-27 | 0.5 | moved | std-only fallback for other targets (D-119) | D-132: moved after 1.0 as P3; without `poll`, `std` cannot wait on a socket and a wake together, which breaks the kill and deadline bounds | after 1.0 |
| R-28 | 0.6 | accepted gap | `Placement::PinPerCore` pins worker `n` to CPU `n`, which can put two workers on SMT siblings before every physical core has one (D-130) | needs a topology read per OS | 0.9.x tuning pass |
| R-29 | 0.6 | accepted gap | `compare/` is closed loop: its p99 understates latency under overload (D-133) | capacity is what the 1.2x gate compares | open-loop generator at the 0.9.x pass |
| R-30 | 0.6 | missed target | the 1.2x gate against the best Rust competitor. On CI (4 vCPUs shared with the generator): net-io's reactor 1.07x tokio on B-1, 0.94x on B-2, 0.88x to 0.94x on B-3, 0.92x on B-4; the best competitor is mio at 1.00x to 1.24x tokio. On the 32-thread build host B-4 is about 2x tokio and 0.84x to 0.95x mio | mio is the same kind of event loop with no limits, deadlines, gate, or wiping, so 1.2x over it is not reachable on this harness. Accepted for 0.6.0 only (D-139); not final | 0.9.x, required: re-run the gate on a dedicated, quiet load machine; before 1.0 it is met, or the target is derived again with the reason written down |
| R-31 | 0.6 | missed target | B-10 post to wake: p99 21 to 33 us on CI, target under 10 us | the post is a few nanoseconds; the rest is one OS wake of a sleeping thread on a VM, and the blocking driver pays it too (p99 26 to 29 us) | 0.9.x: measure on a dedicated host, then a short spin before sleeping, with its idle CPU cost |
| R-32 | 0.6 | known issue | B-4 server CPU per round trip: net-io 22.3 us against tokio 18.8 and mio 18.2 on CI; wiping explains about 1 us (21.3 without) | not profiled at 0.6: the runner has no `perf`, and the build host is loaded | 0.9.x profile of the 16 KiB path |
| R-33 | 0.6 | known issue | B-6 at 100,000 idle: no competitor row (the tokio echo stopped at 4,786 in that client, not investigated), and net-io used 20 ms of CPU per second while idle on the loaded build host (0.0 at 10,000 on CI) | CI's descriptor limit is 30,000, so B-6 runs only on the build host | 0.9.x on a dedicated host |
| R-34 | 0.7 | accepted gap | Windows: a socket accepted from a listener that was created inheritable outside net-io (`TcpListener::from_std`) is inheritable until `SetHandleInformation` runs, so a child spawned in that window can inherit it | accepted sockets take the listener's creation flags, and listeners net-io creates, std creates, or hand-off delivers are never inheritable (`src/sys/windows.rs::test_accepted_sockets_start_non_inheritable`); closing it for outside listeners needs `AcceptEx` on its own overlapped path, about 150 lines and one more system call per accept | 0.9.x: decide with a consumer that passes such a listener |
| R-35 | 0.7 | accepted gap | Windows hand-off: a handle value adopted through hand-off stays reserved until the process exits (D-157), so a later legitimate hand-off that reuses the value is refused and that socket leaks | fails closed; the fix is `ListenerHandle::into_parts` with the engine holding the adoption until the listener closes | 0.9.x |
| R-36 | 0.7 | known issue | Windows IOCP: a completion for a socket the driver already forgot passes the stored socket number back to Winsock (`SO_UPDATE_CONNECT_CONTEXT`, the error read); the number may belong to a new socket by then | the error read has no consumer, and the context update would hit a socket that is not connecting (it fails); the fix is a `Port::forget` called from `IocpDriver::deregister`, about 15 lines | 0.9.x tuning pass |
| R-37 | 0.7 | platform note | 32-bit targets: `send_file`'s copy path truncates a length over 4 GiB, and its 64 KiB copy buffer is allocated outside the buffer budget | no supported target is 32-bit (CI covers 64-bit Linux, macOS, Windows, FreeBSD); the buffer is one per call, freed at its end | 0.9.x: take the buffer from the worker's pool; 32-bit stays unsupported unless a consumer needs it |
| R-38 | 0.7 | accepted gap | a `KillHandle` kept past its connection kills the slot's later connection after 2^32 connections on that slot (the generation wraps) | needs a stale handle kept for a day of churn on one worker; the fix compares the handle's id with the slot's current one | 0.9.x |
| R-39 | 0.7 | known issue | hand-off of a link-local IPv6 listener always fails: the manifest drops the scope id, and the receiver's check compares it | fails closed; the fix changes the manifest format (a version bump) | 0.9.x, with the next manifest change |
| R-40 | 0.7 | platform note | `connect_with` and `connect_host` resolve the name before the connect timeout starts | `std`'s resolver (`getaddrinfo`) cannot be interrupted; documented on `ConnectOptions::timeout` | after 1.0, with a resolver of our own if a consumer needs bounded resolution |
| R-41 | 0.7 | known issue | the SCM_RIGHTS control buffer (2,064 bytes) is sized from macOS and FreeBSD's per-message limit of 2,048 bytes as documented in their headers, not measured there | `sys::unix::layout::test_truncated_control_message_closes_every_descriptor` sends as many descriptors as the kernel takes in one message and checks that every one is closed when the record is cut | confirmed 2026-11-06: it passes on macOS (stable and 1.85) and FreeBSD in CI on 702c2d1; closed |
| R-42 | 0.7 | missed target | the soak on macOS runs 5.5 hours, not 24: GitHub's hosted runners stop a job at 6 hours and no macOS machine is available locally | Linux and Windows run the full 24 hours on the build host | 0.9's 72-hour soak needs a macOS machine for the full length |
| R-43 | 0.7 | closed | Windows: two `Server`s in one process sharing a listening socket from `release_listeners` passed serve-net's restart test on a 24-core machine (199 of 200) and failed on GitHub's runner (a reset after 0 bytes, stalls) | Closed 2026-11-06 (D-187): not a sharing defect; the new server refused at its own caps (`GlobalCap` = workers, `SourceCap` = 16 per source on the blocking driver) while its workers started on a loaded host. A hand-off needs headroom on the new server; `tests/handoff_in_process.rs` runs the restart in CI on every system | 0.8 |
| R-44 | 0.8 | closed | Windows, blocking pool with 1,000 workers on a host at 100% CPU: in a burst of 500 connects, 22 clients stayed in `SYN_SENT` and failed with 10060 (ws-net on 0.6.2) | Not a net-io defect (closed 2026-11-06, agreed with ws-net). The real listen queue is 1,024 on both drivers, no admission took over 5 ms, nothing closed during the burst, and the stuck clients had no `SYN_RECEIVED` row with the listener idle: Windows dropped their SYNs before the queue because each four-tuple matched a server-side TIME_WAIT entry (120 s) on a host with about 12,000 loopback TIME_WAIT entries from other runs, including this repository's two Windows soaks at once. The worker-count split was the host's TIME_WAIT level moving between runs. Windows release soaks now run one driver at a time | 0.8 |
| R-45 | 0.8 | deferral | the executor adapter (feature `executor`, D-030) and the tail latency measured through it (D-140) | it must depend on the executor crate by published version, and `task-io` is not on crates.io (checked 2026-11-06), nor does it have a driver seam yet; a `path` or git dependency is not allowed (CI checks out each repository alone) | the first `task-io` release with a driver trait; until then the reactor's own p99 and p99.9 are what net-io reports |
| R-46 | 0.8 | known issue | Windows CI: `edge_129_kill_from_many_threads_closes_once` failed once at its connect with `WSAEADDRINUSE` (10048) in the no-default-features run on PR jamesgober/net-io#11, the third run of the whole suite in that job; the rerun passed | Not a net-io defect: the client ran out of ephemeral ports to TIME_WAIT entries from the job's earlier runs (as R-44 on the build host). `tests/common::client` now retries `AddrInUse` and `AddrNotAvailable` for up to 5 s, so a short shortage passes and a lasting one (a connection leak) still fails | 0.9.x: if it recurs with the retry, split the Windows test job by feature set |
| R-47 | 0.8 | closed | `tests/flush_close.rs::test_kill_ends_a_close_after_flush` on the Linux reactor: once, in a full suite run at load 110 on 32 cores (2026-11-08, at 6148f29), the connection had closed within 300 ms of `close_after_flush(.., 20 s)` instead of lingering | Fixed (D-202, 2026-11-11): a flush then close took the graceful close's idle shortcut on both drivers, so a connection still `Idle` with no input seen closed with no linger. The test sleeps 50 ms after its first write; at that load the worker had not yet run `on_data`, so the phase was still `Idle`. `test_a_close_after_flush_lingers_before_any_input` (a soft kill before any input) failed every run on b79502e on both Windows drivers, and on the reactor with only the reactor's half of the fix undone; it passes with the fix | closed in 0.8 |
| R-48 | 0.7.2 | deferred | the medium, low and note findings of the 2026-11-11 independent review of 0.7.1 (six, eleven and eight); 0.7.2 and 0.6.3 fix its critical and high ones (D-203 to D-207) | listed privately until each is fixed, so the list does not point at open defects before a release carries the fix; each fix gets its own decision row naming the finding, and this entry closes when the last one does | 0.8.0 |
| R-49 | 0.7.2 | known issue | a Unix socket bound through a private directory (D-207): a swap of that directory's entry before the bind can make the binder create an unused socket named `s` in a directory the swapper chose; no mode or owner is applied to it and it never listens | the swapper must already be able to rename entries in the socket's directory | 0.8: bind through `/proc/self/fd` on Linux and `bindat` on FreeBSD |
