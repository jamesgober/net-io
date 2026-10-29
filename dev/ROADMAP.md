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

## v0.9.x - Pre-1.0 polish (before any 1.0 release candidate)
Exit: every entry in the register below is closed (fixed, measured and accepted with a reason, or moved after 1.0 with a reason); a fresh performance pass and a fresh security and edge-case review are recorded; the 1.0 readiness note for James is written. No `1.0.0-rc` is cut before this exit.

Standing rule from James: "make sure to go back and fix any issues / perf tune / etc before we get close to release."

Items:
- **Revisit the register.** Every accepted gap, deferred item, known issue, platform note, and missed target, one by one: fix it, or measure it and record why it stays (with the cost of fixing it), or move it after 1.0 with a reason. Nothing stays open by default.
- **Performance tuning pass.** Re-run every benchmark in `docs/PERFORMANCE.md` (B-1 to B-14) against the competitor harness on Linux, macOS, and Windows; profile the hot paths (accept, read, write, close, the gate check, the timing wheel); try to remove the extra system call per round trip on macOS and Windows; publish before and after numbers. A missed target is either met or written into the readiness note with its gap.
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
| R-3 | 0.3 | missed target | B-2 goal of 1.2x the std thread-per-connection server | 0.3 baseline at parity within noise; goal moved to 0.6 | 0.6 harness, then 0.9.x |
| R-4 | 0.3 | platform note | Windows send-buffer autotuning lets a peer that never reads absorb tens of MiB before the write timeout; operators must set `ListenOptions::send_buffer` | documented in `docs/PLATFORM-NOTES.md` | consider a bounded default for internet-facing listeners |
| R-5 | 0.3 | platform note | Windows: each worker's wake channel holds one loopback UDP port; many servers in one process can hit `WSAENOBUFS` | documented | reactor (0.5) wake mechanism |
| R-6 | 0.3 | deferred | timing wheel, appendix A cases 53 to 60, benchmark B-8, case 11 (reads pause on an empty budget), FreeBSD and the std-only fallback | moved to 0.5 (D-063, D-064) | 0.5 |
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
| R-17 | 0.4 | deferred | Windows hand-off, edge cases 104 and 105 | scheduled | 0.5 |
