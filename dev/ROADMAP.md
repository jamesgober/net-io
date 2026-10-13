# net-io - Roadmap

> Path from scaffold to a stable 1.0. Hard parts are front-loaded; each phase has hard exit criteria.
> Design and decisions: [`PLAN.md`](./PLAN.md).
>
> **Anti-deferral rule:** no listed hard task moves to a later phase unless this file records the move and the reason.

## v0.1.0 - Scaffold (DONE, 2026-10-13)
Compiles, CI green, structure correct, no domain logic.
- [x] Manifest, README, CHANGELOG, REPS, dual license, CI, deny, clippy, rustfmt, DIRECTIVES, ROADMAP.
- [x] Project plan (`dev/PLAN.md`): scope, architecture, hooks, deployment modes, security responsibilities, ecosystem, decision log.

## v0.2.0 - Design lock
Exit: every public type, trait, and signature written down in `REPS.md`-style detail in `docs/API.md`, reviewed, and approved.
- [ ] Public API: `Addr`, `Cidr`, `PrefixKey`, `ConnectionId`, `ConnInfo`, `Limits`, `NetError`, `CloseReason`, listeners and connections per transport.
- [ ] Hook traits final: `Admission`, `Egress`, `KillHandle`, TLS seam, `EventSink`.
- [ ] Driver interface (completion-shaped) specified, with how epoll, kqueue, IOCP, and io_uring map onto it.
- [ ] `sys/` FFI surface listed per OS: every function, constant, and struct we declare, with its documentation reference.
- [ ] Limits and timeouts: defaults final (PLAN 5.7).
- [ ] Open decisions O-1 to O-3 answered.

## v0.3.0 - TCP and the blocking driver
Exit: a TCP echo service runs on all three OSes under the blocking driver with every limit, hook, and close reason covered by socket tests.
- [ ] Addresses, CIDR, prefix keys, IPv4-mapped normalization.
- [ ] `ConnectionId`, `ConnInfo`, lifecycle states, `CloseReason`.
- [ ] TCP listener, connection, connect; socket options through `sys/`.
- [ ] Blocking bounded worker pool with all timeouts and the minimum transfer rate.
- [ ] Admission and egress hooks called at the invariant points; `KillHandle` with abortive close.
- [ ] `EventSink` with a no-op default.
- [ ] `DrainController`.
- [ ] Hostile-peer test suite (slowloris, slow-read, half-open, floods at the cap); descriptor leak test.
- [ ] Benchmarks: accept rate, echo throughput, egress-check overhead.

## v0.4.0 - Edges
Exit: net-io runs behind Apache and nginx (TCP and Unix socket) with the real client address, and serves TLS directly through tls-net.
- [ ] PROXY protocol v1 and v2 (sans-IO), `TrustedProxies`, fail-closed when required and missing; property tests and fuzz targets.
- [ ] UDP socket with per-source budgets and the no-amplification rule.
- [ ] Unix domain sockets (Unix) with permissions and peer credentials.
- [ ] TLS seam, ClientHello capture, SNI/ALPN in `ConnInfo`, certificate reload; `tls-net` adapter crate.
- [ ] Inherited listeners (`LISTEN_FDS`) and listener hand-off.

## v0.5.0 - Reactor
Exit: 10,000 idle connections held on each OS with bounded memory, and throughput at or above the blocking driver for active ones.
- [ ] epoll (Linux), kqueue (macOS, FreeBSD), IOCP (Windows) behind the driver interface.
- [ ] Windows AF_UNIX and named pipes.
- [ ] FreeBSD in CI.

## v0.9.0 - Hardening
- [ ] Fuzzing for every parser; soak test (24 h, mixed hostile and normal peers); adversarial review with findings fixed test-first.

## v1.0.0 - Stable
- [ ] Frozen after the web stack and one non-HTTP service (HiveDB wire or raft-io) have used it end to end.
