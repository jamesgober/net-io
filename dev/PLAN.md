# net-io - Project Plan

> The design, strategy, and decision record for `net-io`. This is a living document: any design decision, idea, or open question about net-io that comes up anywhere (chat, review, a sibling crate) is written here or in [`ROADMAP.md`](./ROADMAP.md) before it is acted on, so nothing lives only in someone's memory.
>
> **Read order:** [`../REPS.md`](../REPS.md) (portfolio standard) &rarr; [`DIRECTIVES.md`](./DIRECTIVES.md) (engineering law for this crate) &rarr; **this file** &rarr; [`ROADMAP.md`](./ROADMAP.md) (phases and exit criteria) &rarr; [`../docs/API.md`](../docs/API.md) (the locked public API) &rarr; [`SYS-SURFACE.md`](./SYS-SURFACE.md) (every OS call, constant, and struct the crate declares).
>
> **Status:** `0.2.0` design lock. The public API is written in `docs/API.md`; this plan records the design behind it and every decision (section 14).

---

## Contents

1. [Purpose](#1-purpose)
2. [Where net-io sits](#2-where-net-io-sits)
3. [Scope](#3-scope)
4. [Design principles](#4-design-principles)
5. [Requirements](#5-requirements)
6. [Architecture](#6-architecture)
7. [Deployment modes](#7-deployment-modes)
8. [Security](#8-security)
9. [Performance](#9-performance)
10. [Ecosystem and dependencies](#10-ecosystem-and-dependencies)
11. [Testing and verification](#11-testing-and-verification)
12. [Open decisions](#12-open-decisions)
13. [Ideas parking lot](#13-ideas-parking-lot)
14. [Decision log](#14-decision-log)
15. [Spikes at the design lock](#15-spikes-at-the-design-lock)

Appendix A: [edge cases](#appendix-a-edge-cases)

---

## 1. Purpose

net-io is the entrance and the exit. Every byte that reaches one of our services arrives through it, and every byte a service sends leaves through it. It owns:

1. **Sockets and their options:** TCP, UDP, Unix domain sockets (Unix, and Windows through AF_UNIX), and Windows named pipes; every socket option a server needs, set through its own small FFI layer because `std` exposes few of them.
2. **The life of each connection:** accepted, admitted, handshaking, open, parked, draining, closed, with exactly one `CloseReason` per connection and a `ConnectionId` that is never reused inside a process.
3. **The limits that stop a peer from holding what it should not:** global, per-listener, and per-source connection caps; handshake, idle, read, write, and total deadlines; a minimum transfer rate against slowloris and slow-read; bounded buffers; bounded queues.
4. **The drivers that move the bytes:** a bounded blocking worker pool first (works everywhere, including shared hosting and CI), its own reactor second (epoll on Linux, kqueue on macOS and FreeBSD, IOCP on Windows), and io_uring later on Linux, all behind one completion-shaped driver interface.
5. **The seams other crates plug into without net-io depending on them:** a gate (admission at accept, a check before every write), a sans-IO TLS seam, an event sink, a control line, and a completion queue for work that left the connection's worker.
6. **Graceful drain and zero-downtime restarts:** a door that opens last and closes first, drain with a deadline, systemd socket activation, FastCGI descriptor-0 inheritance, and listener hand-off between processes by descriptor passing.
7. **The real client address behind a proxy:** PROXY protocol v1 and v2 parsed sans-IO, honoured only from configured trusted proxies.

It is written once and used by everything that listens on a port or dials one: the web stack, HiveDB's wire protocol, raft-io's transport, rpc-io over TCP, admin consoles, back-channel clients.

What it is not:

| Not | Why | Where it lives |
|---|---|---|
| an HTTP server or any protocol parser | protocol-free rule (2.2) | `http-net`, `ws-net`, `fcgi-net`, `wire-codec`, HiveDB wire |
| a TLS implementation | TLS is never written in-house (D-003, D-012) | `tls-net` (adapter over rustls) |
| a policy engine (bans, scores, rates per prefix) | policy belongs to the gate | `bouncer-io`, `sentinel-sec` |
| an async runtime or task scheduler | no rented runtime (D-004) | an executor crate, through a driver seam |
| a DNS resolver | `std::net::ToSocketAddrs` until a real resolver exists (D-002) | `dns-net` (later) |
| QUIC | its own transport with TLS 1.3 built in (D-002) | `quic-net` (later), on net-io's UDP socket |
| a signal handler | signals are translated by the signal library and decided by the application | `signal-mod`; net-io exposes `close_door`, `drain`, `shutdown`, `stop`, and the control line |
| a supervisor or watchdog | a separate process | the application's supervisor |
| a privilege dropper | a verified security control | `shield-sec`, called after net-io has bound the sockets |

---

## 2. Where net-io sits

### 2.1 The request path

Each stage rejects as early and as cheaply as it can. An IP ban costs nanoseconds; a password check costs milliseconds and a database lookup. A flood that the door can stop must never reach the expensive stages.

```
            inbound                                              outbound
  ┌───────────────────────┐                             ┌───────────────────────┐
  │ net-io: accept        │  socket, ConnectionId,      │ net-io: write         │
  │                       │  peer address, caps         │                       │
  ├───────────────────────┤                             ├───────────────────────┤
  │ bouncer-io: door      │  bans, budgets              │ bouncer-io: egress    │  Gate::check before
  │ (Gate::admit)         │  (before any byte is read)  │ (Gate::check)         │  every write
  ├───────────────────────┤                             ├───────────────────────┤
  │ PROXY header, then    │  real client, readmission   │ customs-sec: export   │  only declared data
  │ Gate::readmit         │                             │                       │  leaves
  ├───────────────────────┤                             ├───────────────────────┤
  │ TLS (tls-net adapter) │  handshake, fingerprint     │ handlers / services   │  bouncer checkpoints
  ├───────────────────────┤                             │                       │  between stages
  │ protocol engine       │  http-net / ws-net /        └───────────────────────┘
  │ (Session)             │  fcgi-net / HiveDB wire                 ▲
  ├───────────────────────┤                                         │
  │ customs-sec: head     │  declared size, type, route             │
  ├───────────────────────┤                                         │
  │ gate-net: authn       │  who are you (session/login)            │
  ├───────────────────────┤                                         │
  │ gate-sec: authz       │  may you do this                        │
  ├───────────────────────┤                                         │
  │ customs-sec: body     │  payload matches the contract ──────────┘
  └───────────────────────┘

  underneath everything: shield-sec (hardening)   watching everything: sentinel-sec (detection)
```

### 2.2 The protocol-free rule

A crate is **protocol-free** when it does its job without knowing the format of the messages crossing the wire. net-io moves bytes and knows who is connected; it never parses HTTP. The same is true of bouncer-io, gate-net, and session storage. Only thin adapters at the top know where a protocol keeps its credentials or how it phrases a refusal (in net-io's terms: the `Session` writes the denial text for a code the gate gives).

**Litmus test:** delete `http-net` from the workspace. Every protocol-free crate still compiles; only the web crates break.

### 2.3 Who uses it

| Consumer | What it needs from net-io |
|---|---|
| `serve-net` (network service module) | listeners per ingress mode, sessions over every driver, limits, drain, the gate seam, PROXY, the TLS seam |
| a private request pipeline built on `serve-net` | everything above, plus `Input::swap` for request bodies and WebSocket messages, the per-worker `Completer` for offloaded work, lanes at admission, the control line, door order, hand-off with a supervisor process, dialed back-channel connections registered like accepted ones |
| `bouncer-io` | implements `Gate`; uses `ServerHandle::kill`, `ConnectionInfo`, `ConnectionId`, `Cidr`, `PrefixKey`, `normalize` |
| `tls-net` | implements `TlsAcceptor` and `TlsSession` |
| `fetch-net`, `proxy-net`, `smtp-net`, back-channel clients | outbound connect with timeouts, socket options, the same limits, `set_gate` |
| HiveDB's network layer, `raft-io`, `rpc-io` | TCP listener and client, drain, limits, hand-off |
| `quic-net` (later) | UDP socket, batch IO, GSO/GRO, packet info |
| an executor crate | net-io implements its driver trait so workers park inside the reactor (feature `executor`, D-030) |

### 2.4 Dependency direction

```
 bouncer-io ──▶ net-io ◀── tls-net          (implementers depend on net-io; never the reverse: D-006)
 serve-net ──▶ net-io, bouncer-io, http-net
 net-io ──▶ (nothing at run time)          executor adapter: optional feature, D-030
```

---

## 3. Scope

### 3.1 In scope

| Area | Contents | Grade summary |
|---|---|---|
| TCP | listener, accepted connection, outbound connect (timeout, local bind, options), half-close, abortive close, vectored IO, peek | P0 |
| Socket options | `TCP_NODELAY`; keepalive with idle, interval, count; `SO_LINGER`; buffer sizes; `SO_REUSEADDR` / `SO_EXCLUSIVEADDRUSE`; `SO_REUSEPORT`; `IPV6_V6ONLY`; backlog; `TCP_DEFER_ACCEPT`; TCP Fast Open; `SO_INCOMING_CPU`; `TCP_USER_TIMEOUT` / `TCP_MAXRT`; `TCP_QUICKACK`; `TCP_NOTSENT_LOWAT`; TTL and DSCP | P0 to P3 per option (`docs/API.md`, option table) |
| UDP | bound socket, send and receive with source address, truncation detection, per-source budgets, no-amplification guard, batch IO, packet info, GSO/GRO | P1 (batch and offloads P2/P3) |
| Local sockets | Unix domain sockets on Unix and Windows (AF_UNIX, 1803+); Windows named pipes; permissions; stale socket handling; peer credentials | P1 (Windows AF_UNIX P2) |
| Addresses | normalization (IPv4-mapped IPv6 to IPv4), `Cidr`, `PrefixKey` (IPv4 /32 and /24, IPv6 /128, /64, /56, /48), `TrustedProxies`, endpoints | P0 |
| Identity | `ConnectionId`, `ListenerId`, `WorkerId`, `Lane`, `ConnectionInfo` | P0 |
| Lifecycle | states, `CloseReason`, exactly one closed event | P0 |
| Limits | caps; backlog; handshake, idle, read, write, total, park deadlines; minimum transfer rate; buffer and queue bounds; adaptive deadlines under pressure | P0 (adaptive P2) |
| Accept discipline | batched accept, reserve descriptor on `EMFILE`/`ENFILE`, accept pause with backoff, transient error classes | P0 |
| Drivers | blocking pool (0.3), reactor: epoll, kqueue, IOCP (0.5), io_uring (after 1.0, P3); one completion-shaped interface; per-worker completion queue | P0 (io_uring P3) |
| Buffers | per-worker pools in size classes, bounded total, zero-copy read views, O(1) buffer swap, wipe on release, vectored writes, `sendfile` / `TransmitFile` | P0 to P2 |
| Timers | hierarchical timing wheel per worker, lazy deadline extension, tickless idle | P0 |
| Server | door, drain with deadline, shutdown, wait/stop, adopt dialed connections, kill by id, stats, worker placement | P0 (placement P2, NUMA P3) |
| Hooks | `Gate`, `KillHandle`, `EventSink`, `ControlLine`, `Completer`, TLS seam | P0 |
| PROXY protocol | v1 and v2 parsing (TLVs, CRC32C, SSL sub-TLVs), off or required, trusted peers only, encoder for outbound | P0 parsing, P2 encoder |
| Restarts | systemd `LISTEN_FDS`, FastCGI descriptor 0, listener hand-off by descriptor passing, raw adoption | P0 hand-off, P1 inheritance |
| Outbound | connect with timeout, connect to a host name through `std` resolution, Happy Eyeballs (RFC 8305, simplified) | P0 connect, P2 Happy Eyeballs |
| Platform | Linux, macOS, Windows first class; FreeBSD for the reactor; close-on-exec everywhere; no `SIGPIPE` | P0 |

### 3.2 Out of scope, and where it goes

| Not in net-io | Goes to | Reason |
|---|---|---|
| QUIC, HTTP/3 | `quic-net` (later) | a large separate job; uses net-io's UDP, GSO/GRO, packet info |
| DNS resolution beyond `std` | `dns-net` (later) | net-io accepts resolved addresses; `connect_host` uses `std` |
| the TLS implementation | `tls-net` | net-io defines the seam; kTLS is a parking-lot idea |
| ban lists, per-prefix rates, strikes, revocation | `bouncer-io` | net-io provides the gate seam, kill by id, and only a per-source concurrency cap (D-025) |
| HTTP keep-alive policy, `Connection: close`, 503 bodies | protocol layer | net-io exposes `pressure`, `draining`, and the denial and refusal slots; it never formats them |
| request pipelines, what a lane means | the application | net-io carries an opaque `Lane(u8)` and the gate's ticket |
| offload pools | an executor or the application | net-io only provides the per-worker `Completer` |
| process lock, umask, open-file limit raise | `sys-lib` | net-io reads the limit and refuses a configuration that exceeds it |
| privilege drop | `shield-sec` | called after net-io binds and before `open_door` |
| signal handling | `signal-mod`, the application | |
| eBPF/XDP ban export | `bouncer-io` parking lot | net-io may later expose `SO_ATTACH_REUSEPORT_*` and a raw descriptor accessor (Tier 3) |
| connection pooling for clients | `pool-mod`, `fetch-net` | net-io supplies connections |
| compression, framing | `wire-codec`, protocol crates | |
| payload and contract validation | `customs-sec` | needs the protocol and the route |
| authentication, sessions, authorization | `gate-net`, `gate-sec` | identity is not transport |

---

## 4. Design principles

1. **Ours, not rented.** Zero runtime dependencies. OS calls `std` lacks go through our own minimal FFI declarations in `src/sys/` (D-014), not `libc`, `windows-sys`, `mio`, `socket2`, or `tokio`.
2. **Unsafe is fenced.** `unsafe` exists only inside `src/sys/`, every block carries a `// SAFETY:` comment, and everything outside `sys/` is `#![deny(unsafe_code)]`. Until `sys/` lands (0.3), the crate stays `#![forbid(unsafe_code)]`.
3. **Hooks, not dependencies.** net-io defines traits (gate, TLS, event sink, control line, clock); implementers depend on net-io, never the reverse.
4. **Everything is bounded.** Every buffer, queue, count, and wait has a limit, checked before the resource is committed.
5. **Fail closed.** When a hook errors or panics, or a limit cannot be evaluated, the connection is refused or closed, never waved through.
6. **Cross-platform for real.** Linux, macOS, and Windows first class on stable and MSRV in CI; FreeBSD from the reactor. Platform differences documented per feature, never hidden.
7. **Measured, not guessed.** No performance claim without a benchmark at realistic scale; system calls are a hot-path cost like allocations.
8. **Simple first.** Tier 1 (a free function, one line) covers the common uses; builders are Tier 2; the generic, allocation-free surface is Tier 3 (`docs/API.md`, conventions).

---

## 5. Requirements

Each requirement has an id that tests and roadmap items cite. "Must" means the version that introduces the item does not ship without it.

### 5.1 Functional

**Addresses and identity**

- **FR-1** Normalize every peer address at accept: an IPv4-mapped IPv6 address becomes the IPv4 address; scope ids are kept for link-local IPv6; nothing else is rewritten (NAT64 is not translated).
- **FR-2** Parse and match CIDR blocks for IPv4 and IPv6, rejecting host bits beyond the prefix unless the caller asks for masking.
- **FR-3** Produce prefix keys: IPv4 /32 and /24; IPv6 /128, /64, /56, /48; each a fixed-size `Copy` value usable as a hash key.
- **FR-4** `TrustedProxies`: an immutable set of at most 1,024 CIDR blocks with an allocation-free lookup.
- **FR-5** Issue a `ConnectionId` for every accepted, adopted, dialed-and-registered, or inherited connection; never reused within a process, never zero.
- **FR-6** Build a `ConnectionInfo` for every connection: local and peer endpoints, real peer (after PROXY), transport, origin, listener, worker, lane, accept instant, peer credentials (local sockets), TLS facts (after the handshake).

**TCP**

- **FR-7** Bind a TCP listener with options applied before `bind` (reuse address, exclusive address use on Windows, reuse port, IPv6-only) and before `listen` (backlog, defer accept, fast open queue).
- **FR-8** Accept in batches up to a configured count per wake-up; set non-blocking (reactor), close-on-exec, no-SIGPIPE, and the configured per-connection options on each accepted socket.
- **FR-9** Survive descriptor exhaustion at accept: on `EMFILE`/`ENFILE` (Windows `WSAEMFILE`, `WSAENOBUFS`), release the reserve descriptor, accept and reset one pending connection, reopen the reserve, emit `DescriptorPressure`, and pause accepting with exponential backoff (1 ms doubling to 1 s) instead of spinning.
- **FR-10** Treat `ECONNABORTED`, `EPROTO`, `EPERM`, `ENOPROTOOPT`, `EHOSTDOWN`, `ENONET`, `EHOSTUNREACH`, `EOPNOTSUPP`, `ENETUNREACH` from `accept` as per-connection failures (counted, accept continues); `ENOBUFS`/`ENOMEM` as pressure (pause); `EBADF`, `EINVAL`, `ENOTSOCK` as listener failure (listener closed, event, error).
- **FR-11** Connect outbound with a deadline, optional local bind, and options; report `ConnectTimeout`, `ConnectionRefused`, `HostUnreachable`, `NetworkUnreachable` distinctly.
- **FR-12** Read into caller or pooled buffers; write single and vectored buffers; continue partial writes from the exact offset until done, the deadline passes, or the gate denies.
- **FR-13** Half-close: `shutdown(Write)` sends FIN and keeps reading; `shutdown(Read)` stops reading.
- **FR-14** Abortive close: `SO_LINGER {on, 0}` and close (RST, resources freed at once); used by kill, gate denial, refusal, and the drain deadline.
- **FR-15** Graceful close: flush within the write deadline, FIN, read and discard inbound bytes for a bounded linger (2 s, 64 KiB), then close.

**Socket options**

- **FR-16** Set and get every option of the option table on every platform that supports it; elsewhere return `Unsupported { feature, platform }`, never silently ignore, unless the option is a documented hint.
- **FR-17** Report the effective value where the OS adjusts it (buffer sizes doubled on Linux; backlog capped by `somaxconn`).

**Limits and timeouts**

- **FR-18** Enforce global, per-listener, and per-source concurrency caps (keyed by `PrefixKey`, /32 and /64 by default) before any byte is read; the per-source table has capacity above the global cap, so it can never overflow.
- **FR-19** One handshake deadline covers the PROXY header and the TLS handshake together.
- **FR-20** Idle deadline while idle; read and write deadlines while bytes are expected or pending.
- **FR-21** A total deadline per exchange set by the session.
- **FR-22** A minimum transfer rate per direction while it is active: after a grace period, the bytes moved over a sliding window must reach the configured rate, or the connection closes with `SlowPeer { direction }`.
- **FR-23** Bound every buffer and queue: read buffer class per connection, output bytes per connection, completion queue per worker, accept batch, buffer budget.
- **FR-24** Under pressure, shrink handshake and idle deadlines by a configured factor (P2).
- **FR-25** Validate every limit at build time; reject zero, out-of-range, and inconsistent combinations with `InvalidConfig { field, reason }`.

**Gate**

- **FR-26** Call `Gate::admit` after accept and before any read; call `Gate::readmit` after a trusted PROXY header reveals the real peer; on refusal close abortively without reading, optionally after one non-blocking write of at most 512 refusal bytes.
- **FR-27** Store the lane and the ticket admission returns; pass the ticket to every later gate call and back to `Gate::closed` exactly once.
- **FR-28** Call `Gate::check` before every write system call (each chunk of a vectored or file send, each TLS flush); on denial overwrite all pending output with zeroes, write the session's denial if no byte of the current response has left, then close abortively.
- **FR-29** A `KillHandle` per connection, `Send + Sync + Clone`, closes the connection abortively from any thread, wakes any blocked or pending operation, and yields exactly one closed event; killing a closed connection returns `false`. `ServerHandle::kill` does the same by id.
- **FR-30** Typed, fixed-size events to an `EventSink` for listener, door, accept, refusal, admission, PROXY resolution, TLS completion, limit hits, kills, gate denials, close (reason, bytes, duration), accept errors, descriptor pressure, drain, control-line reactions, driver fallback.
- **FR-31** Read the `ControlLine` at every worker loop iteration and before every accept batch and admission; react to `Shed`, `Lockdown`, `Draining`, `Stopping` (6.12); wake every worker on demand.
- **FR-32** A `Completer` per worker: a bounded queue other threads use to post `(ConnectionId, token, value)` to the owning worker and wake it; a full queue returns `PostError::Full` and never blocks.

**Sessions and buffers**

- **FR-33** Drive a sans-IO `Session` per connection with the same code on every driver.
- **FR-34** Give `on_data` a zero-copy view of the bytes read; let the session consume a prefix, keep the rest, or swap the whole buffer with a caller-owned buffer of the same class in O(1).
- **FR-35** Let a session park its connection (no reads, no idle timer, a park deadline) until a completion arrives or the park deadline passes.
- **FR-36** Wipe the used part of every buffer when it returns to a pool, unless configured off.
- **FR-37** Send files with `sendfile` / `TransmitFile`, falling back to read-and-write where the platform or TLS prevents it, with a gate check before each chunk.

**Server, drain, restarts**

- **FR-38** Separate binding from accepting: `build` binds or adopts and starts workers with the door closed; `open_door` starts accepting; `close_door` stops accepting within one loop iteration while keeping the listening sockets open.
- **FR-39** Drain: after `close_door`, tell every session to finish, close idle connections at once, wait for the rest until the deadline, then kill the remainder with `DrainDeadline`; return a `DrainReport`.
- **FR-40** Shutdown: close the door, drain, close the listening sockets (unless released), join every worker; afterwards no net-io thread runs and every descriptor net-io opened is closed. `wait` blocks until a stop is requested, then shuts down.
- **FR-41** Release listeners for hand-off and send them to another process (`SCM_RIGHTS` on Unix; `WSADuplicateSocketW` blobs over an authenticated named pipe on Windows) with a versioned, checksummed manifest; the receiver verifies every socket and refuses all of them if any check fails.
- **FR-42** Inherit listeners from systemd (`LISTEN_PID`, `LISTEN_FDS`, `LISTEN_FDNAMES`, `LISTEN_PIDFDID`, descriptors from 3), validating the pid and each descriptor.
- **FR-43** Detect and adopt the FastCGI listening socket on descriptor 0 (Unix).
- **FR-44** Adopt an outbound connection into a running server so it is registered exactly like an accepted one (`AdmitStage::Adopt`).

**PROXY protocol**

- **FR-45** Parse PROXY v1 (at most 107 bytes) and v2 sans-IO from any split of the input, reporting how many bytes were consumed.
- **FR-46** Accept a header only on listeners configured `Required` and only from peers in `TrustedProxies`; never guess whether a header is present; an untrusted peer, a missing header, or an invalid header closes the connection with a distinct reason.
- **FR-47** Handle v2 `LOCAL`, `UNSPEC`, TCP and UDP over IPv4 and IPv6, and UNIX; verify CRC32C when present; expose ALPN, authority, unique id (at most 128 bytes), SSL sub-TLVs, and NETNS as borrowed views; skip unknown and `NOOP` TLVs within bounds.
- **FR-48** Encode v1 and v2 headers for outbound use (P2).

**UDP**

- **FR-49** Bind, send to, receive from, connect; report truncated datagrams instead of returning them silently cut.
- **FR-50** Per-source and global datagram and byte budgets with a bounded source table.
- **FR-51** No amplification: to a source not marked verified, bytes sent never exceed a configured factor (default 1) of bytes received from it within the window.
- **FR-52** Batch receive and send, packet info (P2); GSO/GRO (P3).

**Local sockets**

- **FR-53** Bind Unix sockets with a configured mode (default `0o600`, `0o660` when a group is named) and optional owner and group; refuse a path longer than the platform limit; remove a stale socket file only if `lstat` says socket and a connect to it is refused.
- **FR-54** Linux abstract names only with a mandatory peer uid check (P3).
- **FR-55** Report peer credentials on every platform that has them.
- **FR-56** Pass descriptors over Unix sockets with close-on-exec, detect control-message truncation, and close every descriptor of a failed exchange.
- **FR-57** Windows named pipes with an owner-only security descriptor by default, `PIPE_REJECT_REMOTE_CLIENTS`, and `FILE_FLAG_FIRST_PIPE_INSTANCE`; clients connect with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`.

**TLS seam**

- **FR-58** Drive a sans-IO TLS session in place: feed ciphertext in the connection's read buffer, take plaintext from the same buffer, encrypt into the output buffer; finish the handshake under the handshake deadline; send `close_notify` on graceful close.
- **FR-59** The engine inspects the ClientHello inside `step` and may refuse it; net-io closes such a connection with `HelloRefused` (D-019).
- **FR-60** Surface SNI, ALPN, version, and cipher suite in `ConnectionInfo` after the handshake.

**Platform and process**

- **FR-61** At build, read the open-descriptor limit and refuse a configuration whose caps plus reserves exceed it.
- **FR-62** Create every descriptor and handle close-on-exec / non-inheritable; where the OS has no atomic form (macOS), set it immediately after creation and document the window.
- **FR-63** Never raise `SIGPIPE`.
- **FR-64** Retry `EINTR` internally, recomputing the remaining deadline.
- **FR-65** Worker CPU placement and connection steering (P2); NUMA-aware pools (P3).

**Drivers and outbound**

- **FR-66** One completion-shaped driver interface: operations own their buffers until completion; cancellation always ends in exactly one completion.
- **FR-67** Blocking driver: bounded worker pool, one connection per worker, an accept thread per listener with a wake channel, a bounded hand-over queue; refuse when full.
- **FR-68** Reactor driver: one event loop per worker (epoll, kqueue, IOCP); idle connections hold no read buffer.
- **FR-69** io_uring driver (P3): Linux only, non-default feature, automatic fallback to epoll.
- **FR-70** An executor adapter so worker threads park inside the reactor (P2, feature `executor`).
- **FR-71** `connect_host` resolves through `std` (never on a reactor worker) and tries addresses in order with per-attempt and total deadlines.
- **FR-72** Happy Eyeballs, simplified for `std` resolution (P2).

### 5.2 Non-functional

- **NFR-1** Zero runtime dependencies: `cargo tree -e normal` shows only `net-io`.
- **NFR-2** `unsafe` only under `src/sys/`; every block with a `// SAFETY:` comment naming the invariant and the documentation it relies on; a CI grep fails the build otherwise.
- **NFR-3** No allocation on hot paths after warm-up (accept, admission, read, dispatch, gate check, write, timers, completion post), proven by a counting allocator.
- **NFR-4** Zero CPU when idle: no periodic tick; measured over 60 s idle.
- **NFR-5** Memory bounded by configuration, never by peer behaviour.
- **NFR-6** No panics reachable from library code.
- **NFR-7** Descriptor hygiene: counts return to baseline after 100,000 connections across every close path.
- **NFR-8** Exactly one closed event with one `CloseReason` per connection on every path, including kill races and shutdown.
- **NFR-9** At least 20% faster than the best Rust competitor at equal or stronger security on each benchmark of section 9, p99 included, measured and published; a regression over 5% blocks a change.
- **NFR-10** Linux, macOS, Windows first class on stable and MSRV in CI; FreeBSD from 0.5.
- **NFR-11** Deterministic tests: the wheel, limits, and session state machine run under an injectable clock; `sys` has a fault-injection shim in test builds (D-045).
- **NFR-12** The gate check adds one predictable branch and one hook call per write system call; under 2 ns with a one-atomic gate [est.].
- **NFR-13** Fail closed on every hook error and every unverifiable inherited or handed-off descriptor.
- **NFR-14** Every public item documented with a runnable example; `docs/API.md` lists every item.
- **NFR-15** MSRV 1.85 (edition 2024); newer OS features through `sys` (D-031).
- **NFR-16** Minimum platforms (D-037): Linux 4.18, macOS 11, Windows 10 1809 / Server 2019, FreeBSD 13 for the full feature set; older systems get `Unsupported`, never undefined behaviour.
- **NFR-17** Soak: 24 hours at 0.7 and 72 hours before 1.0 with no memory, descriptor, or handle growth and no stuck connection.
- **NFR-18** Fewer system calls per request than each competitor on the echo benchmark; counts published.
- **NFR-19** A kill from another thread puts RST on the wire within 1 ms p99 on an idle system [est.].
- **NFR-20** `close_door` stops new accepts within 1 ms p99 [est.].

### 5.3 Enterprise and distributed (standard 2.16)

net-io holds per-process connection state (sockets, timers, the per-source table) and no state that must survive the process or be shared between nodes. The "stateful" row applies to what a deployment needs from it across processes and nodes:

| Point | How net-io meets it |
|---|---|
| correct under concurrency and load | `Send`/`Sync` checked at compile time; no global mutable state except two documented read-only-after-start facts; loom models for every concurrency primitive; soak tests (NFR-17) |
| observable | `EventSink` (zero cost unused), `Stats` snapshots, `CloseReason::as_str` stable names, `NetError::class` and stable variant names |
| operable | every limit configurable with a safe default and validated (FR-25); overload refuses cleanly (caps, `Busy`, `Shed`, `PostError::Full`); limits and capacity numbers documented in `docs/API.md` and, from 0.6, `PERFORMANCE.md` |
| secure | section 8; fail closed; the gate check cannot be skipped |
| many processes, many nodes | no process-local assumption in the API: hand-off moves listeners between processes; `SO_REUSEPORT` groups and systemd activation let several processes share a port; the control line lets a cluster controller shed or drain every node; `ConnectionId` is unique per process and paired with a node id by the application when it leaves the process |
| partitions and clock skew | each node protects itself locally (caps, deadlines, the gate's local state); timers use the monotonic clock only, so wall-clock skew between nodes cannot fire or delay a deadline |
| idempotent under retries | `close_door`, `open_door`, `drain`, `kill`, `stop` are idempotent; a second hand-off receive of the same blobs fails closed |
| long-lived systems | semantic versioning, MSRV policy, deprecation before removal, `docs/STABILITY-1.0.md` at 1.0 |

---

## 6. Architecture

### 6.1 Module map

```
src/
  lib.rs              crate docs, lints, Tier 1 functions, re-exports, VERSION
  error.rs            NetError, ErrorClass, CloseReason, RefusalCause, LimitKind, TimeoutKind, ConfigReason
  addr.rs             normalize, Cidr, PrefixKey, PrefixPolicy, TrustedProxies, Endpoint
  id.rs               ConnectionId, ListenerId, WorkerId, id blocks
  info.rs             ConnectionInfo, Transport, Origin, PeerCredentials, Lane
  limits.rs           Limits, LimitsBuilder, defaults, validation, MinRate, Pressure, SizeClass
  opts/               ListenOptions, TcpOptions, Keepalive, Linger, SocketOptions, per-platform mapping
  tcp.rs              TcpListener, TcpConnection, ConnectOptions, connect_host, Happy Eyeballs (0.5)
  udp.rs              UdpSocket, amplification guard, source budgets, Datagram
  local/              unix.rs (Unix + Windows AF_UNIX), pipe.rs (named pipes), credentials.rs
  proxy/              v1.rs, v2.rs, tlv.rs, crc32c.rs, encode.rs, ProxyParser, ProxyHeader
  gate.rs             Gate, Admitted, Refusal, WriteCheck, Denial, AllowAll, KillHandle
  tls.rs              TlsAcceptor, TlsSession, TlsProgress, TlsEvent, TlsInfo, TlsError, NoTls
  events.rs           EventSink, Event, NoopSink
  control.rs          ControlLine, ControlState, NoControl, SimpleControl
  session.rs          Session, SessionFactory, SessionContext, Step, Phase, Input, Output
  server/             builder.rs, server.rs, door.rs, drain.rs, adopt.rs, stats.rs, placement.rs
  buf/                pool.rs (per-worker free lists per class), buffer.rs (Buffer, swap), wipe.rs
  time/               wheel.rs (hierarchical timing wheel), clock.rs (Clock, MonotonicClock, ManualClock)
  driver/             mod.rs (Driver, Operation, Completion, Token), blocking.rs, reactor/ (epoll, kqueue, iocp), uring.rs (P3), completer.rs
  inherit.rs          systemd, systemd_named, fastcgi_listener
  handoff.rs          ListenerHandle, manifest encode/decode, send/recv (Unix), share/receive (Windows)
  sys/                the only unsafe: unix/, linux/, bsd/, windows/, shim.rs (fault injection, test builds)
```

`pub(crate)` by default; the public surface is exactly `docs/API.md`.

### 6.2 Connection lifecycle

```
                      ┌──────────── refused (cap, gate, untrusted PROXY, hello refused) ─────────────┐
                      │                                                                              ▼
 accepted ──▶ admitted ──▶ handshaking ──▶ open ⇄ parked ──▶ draining ──▶ closing ──▶ closed (one CloseReason)
 (id, peer,    (lane,       (PROXY under     (Session     (offload      (no new      (flush,
  caps)         ticket)      handshake       phases:      in flight,    exchange)    FIN or RST)
                             deadline, TLS)  idle,        park
                                             receiving,   deadline)
                                             sending)
   any state ──── kill / gate denial / limit / error / drain deadline ──────────────────────────▶ closing (abortive)
```

| State | Timers armed | Reads | Writes | Exits |
|---|---|---|---|---|
| accepted | none (microseconds) | no | refusal bytes only | admitted, refused |
| admitted | handshake | PROXY header and TLS records only | TLS records | handshaking, refused, closing |
| handshaking | handshake | yes (bounded by header caps) | TLS records | open, closing |
| open, Idle | idle | yes | no pending output | Receiving, closing |
| open, Receiving | read, rate in, exchange | yes | allowed | Sending, Idle, parked, closing |
| open, Sending | write, rate out, exchange | optional | yes | Idle, Receiving, closing |
| parked | park, exchange | no (bytes stay in the kernel) | no | open (wake), closing |
| draining | drain (server) plus the phase's timers | until the exchange ends | yes | closing |
| closing | graceful linger (2 s) or none (abortive) | drain only, bounded | flush only | closed |

Rules: no byte is read before `Gate::admit` succeeds; net-io moves Idle to Receiving itself on the first byte of an exchange; exactly one transition into `closed`, guarded by one atomic state word per connection (compare-and-swap on a closing flag), so a kill racing a FIN produces one reason.

### 6.3 The `sys` layer

- Each platform module declares only what net-io calls: `extern "C"` on Unix (the C library is already linked by `std`), `extern "system"` on Windows with `ws2_32` and `kernel32` (and `advapi32` for security descriptors, `bcrypt` for randomness). `ConnectEx` and `TransmitFile` are loaded at run time through `WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER)`, so `mswsock` is never linked (`AcceptEx` is not used: D-016).
- Constants and layouts are declared per target: `x86_64` and `aarch64` on `linux-gnu`, `linux-musl`, `apple-darwin`, `unknown-freebsd`, `pc-windows-msvc`, `pc-windows-gnu`. Other targets compile the blocking driver over `std` only and return `Unsupported` for what `std` lacks (D-014).
- Every struct has a `const` size and alignment assertion; every constant, size, field offset, and function signature is cross-checked in CI against `libc` and `windows-sys`, which are **dev-dependencies only** (`tests/layout.rs`).
- `sys` exposes only safe functions over owned or borrowed handles (`OwnedFd`, `OwnedSocket`, and their borrowed forms); no raw pointer or raw descriptor crosses the boundary.
- Windows: `WSAStartup(2.2)` once through `std::sync::Once` (reference counted, so it coexists with `std`'s own call).
- The full list of functions, constants, and structs per OS, with the documentation each relies on, is frozen in [`SYS-SURFACE.md`](./SYS-SURFACE.md). Adding to it needs a decision-log entry.
- Lints: the crate root becomes `#![deny(unsafe_code)]` and `#![deny(unsafe_op_in_unsafe_fn)]` in 0.3; only `src/sys/mod.rs` has `#![allow(unsafe_code)]`; a CI grep fails if the token `unsafe` appears outside `src/sys/` (doc comments excluded).
- Miri runs on every module outside `sys` with the shim; `sys` itself is covered by loopback tests on every OS, the layout cross-check, and sanitizer runs on Linux nightly.

**Fault-injection shim (D-045).** In builds with `cfg(test)` or the custom cfg `net_io_shim` (set by CI through `RUSTFLAGS="--cfg net_io_shim"` for the integration tests that need it), every `sys` function goes through a dispatch point a test can program ("the 3rd `send` on socket X returns 7 bytes", "the next `accept` returns `EMFILE`", "every `recv` returns `EINTR` once"). It is a cfg, not a Cargo feature, so it can never appear in the published feature list or be enabled by a dependent; normal builds compile no dispatch at all. `Cargo.toml` declares the cfg in `[lints.rust] unexpected_cfgs` so it does not warn.

### 6.4 Drivers

Completion-shaped (D-005): IOCP and io_uring report "this operation finished, here is your buffer"; epoll and kqueue report readiness and adapt by doing the non-blocking call themselves. The reverse (readiness on Windows) needs the undocumented `\Device\Afd` path that mio uses; completion keeps every backend on documented interfaces. The `Driver` trait is in `docs/API.md` (public Tier 3 from 0.5, D-029). `Completions` is a fixed array (256), so `wait` never allocates.

| | Blocking pool | Reactor | io_uring |
|---|---|---|---|
| Version | 0.3 | 0.5 | after 1.0, P3, feature `uring` (D-015) |
| Threads | `workers` (128, 256 KiB stacks) + one accept thread per listener | one per logical CPU, each with its own epoll, kqueue, or IOCP port | one per CPU, one ring each |
| `submit` | Unix: blocking `recv` with the remaining deadline as `SO_RCVTIMEO`; sends with `MSG_DONTWAIT`, waiting in `poll` on `EAGAIN`. Windows: non-blocking socket, `WSAPoll` until ready, then the call (D-052). The completion is queued locally | readiness: edge-triggered interest, call when ready; IOCP: `WSARecv`/`WSASend` (accept: one `WSAPoll` thread per listener, D-016) | an SQE |
| `wait` | local completions; when parked, the worker's parker until a completer wake or the park deadline | `epoll_wait` / `kevent` / `GetQueuedCompletionStatusEx` with the wheel's next expiry | `io_uring_enter` with a timeout |
| Kill wake | Unix: `shutdown(SHUT_RD)` wakes a blocked `recv`, the worker's wake pipe wakes a stalled send; Windows: the waiter's wake socket wakes `WSAPoll` (D-052, D-053), then abortive close by the worker | command queue + `DriverWaker` | `IORING_OP_ASYNC_CANCEL` |

Comparison [est.] (section 9 replaces it with measurements): the blocking pool needs 2 system calls per small exchange and has the lowest single-connection latency but falls behind beyond a few hundred active connections; the reactor needs about 3 (the wait amortized) and holds thousands of idle connections with state only; io_uring was measured about 10% ahead of epoll at 1,000 connections with CPU mitigations on and behind without them (Alibaba/OpenAnolis), and its security record (60% of the kernel exploits submitted to Google's kCTF VRP used it; Docker's default seccomp profile blocks it; `kernel.io_uring_disabled` exists) argues against making it a default.

**Accept distribution.** Linux: one listening socket in every worker's epoll with `EPOLLEXCLUSIVE` (4.5+); option at 0.6: one `SO_REUSEPORT` listener per worker, steered by `SO_INCOMING_CPU`. macOS, FreeBSD: one acceptor per listener hands sockets to the least-loaded worker's bounded inbox. Windows: one accept thread per listener waits in `WSAPoll` on the listener and a wake socket and accepts without `AcceptEx`, because a listener must never be associated with a completion port (D-016); it hands each socket to the least-loaded worker, which associates the accepted socket with its own port. Blocking: one accept thread per listener; a bounded hand-over queue (capacity = idle workers); full means refuse with `Busy`.

**IOCP idle connections.** A pending `WSARecv` with a real buffer pins it while the peer is silent; the reactor posts zero-byte receives for idle connections and reads into a pool buffer when one completes (one extra system call per wake-up, one buffer saved per idle connection; measured at 0.5). `FILE_SKIP_COMPLETION_PORT_ON_SUCCESS` is set unless `WSAEnumProtocols` shows a provider without `XP1_IFS_HANDLES`.

**Executor seam.** An executor's own driver trait (a worker that would park asks for ready events with a timeout) is implemented by an optional adapter over the reactor (feature `executor`, D-030), so one thread serves tasks and sockets with no extra hop.

### 6.5 Blocking driver

```
 accept thread (per listener)                       workers (bounded pool, default 128)
   poll([listener, wake], timeout)                    loop:
   ├─ wake: check door / control line                   take (conn, info) from the hand-over queue (blocks, zero CPU)
   ├─ readable: accept up to accept_batch               session.on_open
   │    reserve-descriptor routine on EMFILE            loop on Step:
   │    caps (global, listener, source)                   Read  ─▶ recv(timeout = earliest of read/idle/exchange/rate check)
   │    Gate::admit (no read yet)                         Write ─▶ per chunk: control check, Gate::check, send
   │    hand-over queue try_push                          Park  ─▶ parker.wait(park deadline) until the Completer posts
   │      full ─▶ refuse (Busy), RST                      Close ─▶ graceful or abortive close, one closed event
   └─ repeat                                            return to the pool
```

- `poll` / `WSAPoll` on the listener plus a wake socket lets `close_door`, `shutdown`, and the control line interrupt the accept thread without closing the listener, which hand-off needs.
- Unix reads: blocking `recv` with `SO_RCVTIMEO`, set only when the target moves by more than one tick, so most reads are one system call. Unix sends: `MSG_DONTWAIT` first (usually one call); on `EAGAIN`, `poll` on the socket and the worker's wake pipe with the write deadline.
- Windows: Microsoft documents a socket whose blocking receive or send timed out as being in an indeterminate state. Spike S-2 saw no data lost after a timeout, but a lost or reordered byte in the middle of a stream would desynchronize the protocol framing, which is how request smuggling starts, so net-io does not rely on it: Windows sockets in the blocking driver are non-blocking, every wait is `WSAPoll` on the socket and the waiter's wake socket with the deadline, then the call. Cost: two system calls per read where Unix needs one [est. under 1 µs extra]; the production path on Windows is the IOCP reactor (D-052).
- The minimum rate on the blocking driver: the read timeout is capped at the rate-check interval (1 s) and the rate is checked on every return from `recv`.
- An idle keep-alive connection occupies a worker, so the default idle deadline is 5 s and `pressure()` reports the fraction of busy workers (D-028).

### 6.6 Buffers and memory

- **Size classes** 4, 16, 64 KiB by default (powers of two from 1 KiB to 1 MiB). Each worker owns a free list per class; buffers are allocated on first need and never freed while the server runs.
- **Budget:** the sum of all buffers ever allocated is bounded by `buffer_budget` (validated at least `workers x 64 KiB x 2`); when spent, `take` returns `None`, the connection stops reading (back-pressure through the kernel's receive window), and `LimitHit { BufferBudget }` is emitted at most once per second per worker.
- **Asynchronous drivers:** a buffer given to `Operation::Receive` belongs to the driver until its completion is reaped, even when the connection is killed; the kill path cancels and waits for the completion before returning the buffer (6.10).
- **Zero copy:** `on_data` receives `&mut Input`, a view into the connection's buffer; compaction happens only when the free tail is under a quarter (one `copy_within`, amortized).
- **Swap** (`Input::swap`): O(1) exchange with an empty caller-owned buffer of the same class; the bytes never move. For request bodies and WebSocket messages handed to another owner; the request head is copied by the protocol layer instead (cross-crate decision X-3).
- **Wipe on release** (D-027): volatile zeroing of the used prefix; 50 to 100 ns per 2 KiB [est.].
- **Output:** a bounded chunk queue (pool buffers, `&'static [u8]`, file ranges); 64 KiB of pool memory per connection; vectored writes of up to 64 chunks per call (below `IOV_MAX`).

### 6.7 Accept path and accept storms

Per wake-up, per listener, until `accept_batch` or `EAGAIN`: (1) control line check (one atomic load; door closed, `Draining`, or `Stopping` stops the batch and leaves the rest in the backlog); (2) `accept4` / `accept` with the FR-10 error classes; (3) caps, refusing with RST before any read; (4) id from the worker's block, normalized peer, `ConnectionInfo`; (5) `Gate::admit` (a panic counts as refusal); (6) per-connection options, only where the OS does not inherit them from the listener (spike S-4); (7) register with the driver and arm the handshake or idle deadline.

**Reserve descriptor.** Each Unix acceptor holds one spare descriptor (`/dev/null`). On `EMFILE`/`ENFILE`: close the spare, accept one connection, close it with RST, reopen the spare, emit `DescriptorPressure`, pause with backoff (1 ms doubling to 1 s, reset after one good batch, no CPU while paused). Best effort: another thread can take the freed slot (the caveat Twisted documents for the same technique); the backoff then applies. Windows socket handles do not come from a small per-process table; there the pause alone handles `WSAEMFILE` and `WSAENOBUFS`.

**Backlog.** Default 1,024; Linux caps it silently at `net.core.somaxconn` (4,096 since 5.4, 128 before), so net-io reads `/proc/sys/net/core/somaxconn` once and reports the effective value. SYN floods are the kernel's (SYN cookies), documented in `PLATFORM-NOTES.md`.

### 6.8 Limits

Defaults and the reason for each are in `docs/API.md` ("Defaults and reasons"). Design notes:

- **Per-source table** (D-025): open addressing over `(PrefixKey, count)` with capacity the next power of two above `2 x max_connections`, so live entries never exceed `max_connections` and the table never fills; backward-shift deletion, no tombstones; keyed hash with a per-process random key read once from the OS (no attacker-chosen collisions). On the reactor the table is shared and striped with compare-and-swap counts [measured at 0.5 against per-worker shards]. The 0.3 blocking driver uses 16 shards of std maps keyed by std's `RandomState` instead (D-062).
- **Minimum rate:** per direction, a ring of ten one-second counters; a wheel timer every second only while the direction is active.
- **Adaptive deadlines** (P2, 0.6): above `pressure.high` of `max_connections`, handshake and idle deadlines of new and idle connections are multiplied by `pressure.factor` (floor 1 s), restored below `pressure.low`.
- **Lane reservations** (P2, 0.6): slots reserved for lanes out of `max_connections`; a lane may use the shared slots or the reserve of any less important lane; a flood of unimportant connections cannot take the last descriptors needed for health checks.

### 6.9 Timers

One hierarchical timing wheel per worker (Varghese and Lauck, 1987): 6 levels of 64 slots, 1 ms tick (1 to 100 ms configurable), about 2.2 years at 1 ms, an overflow list beyond. Intrusive slots per connection (handshake, idle, read, write, exchange, park, rate), so insert and cancel allocate nothing. Lazy extension: a read that extends a deadline only stores the new deadline; the entry is re-inserted when it fires early. Never early; tickless (the driver's wait timeout is the next occupied slot, found with a 64-bit occupancy bitmap per level); saturating `u64` tick arithmetic; a forward jump fires every expired slot once, in order, at most 1,024 per iteration.

The wheel ships with the reactor in 0.5 (D-063). The blocking driver holds one connection per worker and computes its few deadlines from the connection's progress time; `SO_RCVTIMEO` (Unix) or the `WSAPoll` timeout (Windows) carries the nearest one.

### 6.10 Cancellation and kill

| Driver | Kill sequence |
|---|---|
| Blocking | compare-and-swap the closing flag; then wake the worker: Unix `shutdown(SHUT_RD)` on the connection (a blocked `recv` returns 0 at once, spike S-3; the worker checks the flag before treating 0 as end of stream) and one byte to the worker's wake pipe (a send waiting in `poll`); Windows one datagram to the waiter's wake socket (`WSAPoll` returns). The worker sees the flag, sets linger 0, closes, emits the event. The killing thread never closes the descriptor itself, and it touches the descriptor or wake channel only under the kill guard (D-053). |
| Reactor (epoll, kqueue) | push `Kill(id, reason)` on the owning worker's bounded command queue and wake it; the worker deregisters, sets linger 0, closes, emits. |
| IOCP | `CancelIoEx(socket, NULL)`, buffers stay owned, close only after **every** outstanding completion was dequeued (Microsoft documents three outcomes for a cancelled operation; the `OVERLAPPED` and buffer must live until it completes). |
| io_uring | `IORING_OP_ASYNC_CANCEL` by user data; buffers return after the original CQE and, for zero-copy sends, after the notification CQE. |

A `KillHandle` holds the worker index, the `ConnectionId`, a generation number, and the worker's command queue; a generation mismatch returns `false`.

**Kill guard (D-053).** A killer that makes a system call on the connection's socket or on a wake channel must never hit a descriptor the owner already closed and the OS reused. The connection's state word carries a `KILLING` bit: the killer sets it with the closing flag in one compare-and-swap (only if the connection is not already closed), makes its wake call, then clears it; the owner's close path waits until `KILLING` is clear before it closes the socket or unregisters its wake channel. The wait is bounded by one system call in the killer. Model-checked with loom (kill vs close vs FIN vs drain).

### 6.11 Gate seam (bouncer-io)

The shape agreed for both crates' 0.2 design locks (D-018; bouncer-io's open decision O-6, option (a)):

```rust
pub trait Gate: Send + Sync + 'static {
    type Ticket: Send + 'static;
    fn admit(&self, info: &ConnectionInfo, stage: AdmitStage) -> Result<Admitted<Self::Ticket>, Refusal>;
    fn readmit(&self, ticket: &mut Self::Ticket, info: &ConnectionInfo) -> Result<(), Refusal>;
    fn check(&self, ticket: &mut Self::Ticket, write: &WriteCheck) -> Result<(), Denial>;
    fn closed(&self, ticket: Self::Ticket, info: &ConnectionInfo, reason: CloseReason) { let _ = (ticket, info, reason); }
}
```

- The ticket is stored beside the connection and passed back on every call, so the check before a write is one load through the gate's own state (bouncer: one atomic epoch load), with no lookup by id.
- One trait instead of separate admission and egress traits: the same per-connection ticket serves both, and a server sets it with one call (`.gate(bouncer)`).
- `closed` gives the ticket back with the one close reason: the gate releases its counts and can turn `SlowPeer`, `ProxyInvalid`, `ProxyUntrusted`, `TlsFailed`, `HelloRefused`, and timeouts into strikes without parsing events.
- Denials carry a code; the connection's `Session` writes the protocol's denial for it, because only the session knows its framing state. The denial is written only on a clean response boundary (`Output::begin_response`); otherwise the connection is reset with no denial bytes (D-032).
- `GateTag` (D-051): the gate's opaque name for the connection, stored in `ConnectionInfo::gate` for protocol engines, and an optional per-response tag the session sets with `Output::begin_tagged_response`, passed to `check` as `WriteCheck::response`.
- With `AllowAll` (`Ticket = ()`, `GateTag(0)`), the checks compile to nothing.

What the transport cannot do, stated plainly: bytes already handed to the kernel cannot be recalled. Responses that must be all-or-nothing are pushed in full before they are written.

### 6.12 Control line

net-io's view of an application-wide urgent signal: one `Acquire` load of the epoch at the top of every worker loop, before every accept batch, and before every admission; the state is read only when the epoch moved. Reactions: `Shed { from_lane }` refuses new connections in that lane and every less important one and reports `pressure() == 1.0`; `Lockdown` refuses new connections on listeners not marked `lockdown_allowed`; `Draining` closes the door and drains; `Stopping` kills everything left with `Shutdown`. `ServerHandle::wake_all` reaches workers asleep in the kernel (eventfd, `EVFILT_USER`, `PostQueuedCompletionStatus`, the blocking pool's wake socket and parkers).

### 6.13 Completer

A bounded multi-producer single-consumer ring per worker (Vyukov-style, power-of-two capacity, a sequence number per slot), loom-tested. `post` on a full ring returns `Full`; a completion for a connection that closed meanwhile is dropped and counted (generation check); the poster wakes the worker only on the empty-to-non-empty transition. The value is a `u64`, so nothing is allocated or dropped.

### 6.14 PROXY protocol

Modes `Off` and `Required { V1 | V2 | Both }`; no optional mode (the specification forbids guessing). Trust is checked at accept from the socket address, before any read. The parser is a sans-IO state machine with a resume offset, borrowing TLV values from the caller's buffer; `to_facts` copies ALPN (32 bytes), authority (255), unique id (128), and SSL flags into fixed arrays inside `ConnectionInfo`. The v2 address-and-TLV cap is 1,024 bytes by default, configurable to 65,519 (D-040). After the parse: the real peer is normalized, the per-source cap moves to it, `Gate::readmit` runs. Strictness rules for v1 and v2 are in `docs/API.md`.

### 6.15 TLS seam

In place (D-019, cross-crate decision X-2): the engine's `step` decrypts in the connection's read buffer and returns plaintext as a range of it; `encrypt` writes records straight into net-io's output buffer. The condition X-2 set (rustls's unbuffered API reassembles a handshake message that spans several records inside the caller's buffer) holds: rustls 0.23.46's unbuffered path calls the handshake deframer's `coalesce`, which moves the fragments together in the caller's buffer (`src/conn/unbuffered.rs` -> `ConnectionCommon::deframe` in `src/conn.rs` -> `HandshakeDeframer::coalesce` in `src/msgs/deframer/handshake.rs`). Consequence: the input buffer must hold the largest handshake message being assembled, which the session reports through `input_capacity_required` and net-io meets by growing the read buffer up to `read_class_max`.

The ClientHello is parsed by the engine inside `step` from net-io's buffer (no copy); fingerprinting and refusal are the engine's hello hook (tls-net calls bouncer-io), surfaced to net-io as `TlsFailure::HelloRefused`. net-io's earlier plan to copy the hello into a per-worker scratch buffer and call its own hook is dropped (D-019): the engine already holds the parsed hello, and a second hook would mean a second parse.

Order: accept, admit, PROXY, readmit, `TlsAcceptor::session` (capacity refusal before reading), handshake under the handshake deadline, `info()` into `ConnectionInfo`, protocol chosen by ALPN. Outbound: gate check on plaintext before `encrypt` and before each ciphertext flush; denial encrypted, then `close_notify`, then reset.

### 6.16 Drain, door, shutdown, hand-off

```
 BOOT                                          SHUTDOWN                            RESTART
 build(): bind or adopt listeners,             close_door()  (first)              the supervisor or the old process
   start workers, door CLOSED                  drain(deadline)                      holds the listening socket
 [drop privileges]                               idle: close now                   new process: build() with listeners
 open_door()  (last)                             active: finish the exchange          received by hand-off ─▶ open_door()
                                                 deadline: kill (DrainDeadline)    old process: close_door()
                                               shutdown(): close listeners,          ─▶ drain(deadline) ─▶ exit
                                                 join workers                      the listening socket is never closed
```

- `close_door` sets the door word and wakes every acceptor (NFR-20). Connections in the kernel backlog stay there: the next process accepts them in a restart; `shutdown` resets them in a final stop.
- Overlap during a restart is allowed (D-042): both processes may accept for a moment; each connection belongs to one.
- **Unix manifest:** one `sendmsg`, up to 64 descriptors (`SCM_RIGHTS`; Linux's per-message limit is 253), body: magic `NIOH`, version 1, count, per listener kind, name (up to 64 bytes), local address, options digest, then CRC32C. The receiver uses `MSG_CMSG_CLOEXEC` where available, fails on `MSG_CTRUNC`, checks count, verifies each descriptor (`SO_TYPE`, `SO_ACCEPTCONN`, `getsockname` equals the manifest). Any failure closes all received descriptors (fail closed). The channel is a Unix socket in a `0700` directory; the receiver checks the sender's uid (default its own) and, if configured, pid.
- **Windows:** `WSADuplicateSocketW(listener, target_pid)` yields a `WSAPROTOCOL_INFOW` for one target process, sent over an owner-only named pipe; the receiver checks `GetNamedPipeClientProcessId` and calls `WSASocketW(FROM_PROTOCOL_INFO, WSA_FLAG_OVERLAPPED)`. Windows does not make the blob single use (spike S-1: a second use returns the same handle, a use after the sender closed returns a dead one), so net-io does: the manifest carries a 128-bit random nonce, `receive_shared` refuses a nonce it already accepted in this process, `SharedListeners::write_to` consumes the value so it cannot be sent twice, and every received socket is verified before use (D-054). Listeners are never associated with a completion port in any process, so a received listener works in the new process exactly as in the old one (D-016).

### 6.17 Inheritance

- **systemd** (FR-42): `LISTEN_PID` must equal this process (otherwise an empty list), `LISTEN_FDS` at most 64, `LISTEN_FDNAMES` optional, `LISTEN_PIDFDID` checked against the inode of this process's pidfd on Linux when present (systemd 259+). Descriptors from 3, each verified (`fstat` socket, `SO_ACCEPTCONN`, `SO_DOMAIN`, `SO_TYPE`) and set close-on-exec. The variables are not unset (D-036).
- **FastCGI** (FR-43): descriptor 0 must be a socket, listening, with `getpeername` failing with `ENOTCONN`; adopted as TCP or Unix by `SO_DOMAIN`. Windows: OD-26.

### 6.18 Outbound connections

`connect`: non-blocking connect, wait for writability within the deadline (blocking driver: `poll` on Unix, `WSAPoll` on Windows, D-056), then `SO_ERROR`. The Windows reactor uses `ConnectEx` (needs a bound socket). `connect_host`: `std` resolution off the worker, addresses in order, per-attempt deadline = remaining / remaining addresses (at least 1 s). Happy Eyeballs at 0.5 (D-044).

### 6.19 Placement (P2) and NUMA (P3)

`Placement::Off` (default), `PinPerCore` (physical cores before SMT siblings), `Explicit(cpus)`. Linux `sched_setaffinity` plus `SO_INCOMING_CPU` per-worker reuse-port listeners; Windows `SetThreadGroupAffinity` (processor groups above 64 CPUs); FreeBSD `cpuset_setaffinity`; macOS: `Unsupported` (D-037). NUMA (P3): one pool per node, first touch from the pinned thread.

### 6.20 Fork safety and signals

Every descriptor and handle is close-on-exec / non-inheritable; on macOS `socket` and `accept` have no atomic flag, so `FD_CLOEXEC` is set immediately after creation (a `fork` plus `exec` by another thread in that window can leak one descriptor; documented with the advice to start children before the server or use `posix_spawn` with `POSIX_SPAWN_CLOEXEC_DEFAULT`). net-io never forks; a `Server` records its creating pid and its cold calls return `ForkedChild` in a child. No signal handling; `SIGPIPE` is avoided on every write because a library cannot rely on the host's disposition. `EINTR` is retried with the remaining deadline.

### 6.21 Events, stats, ids

`EventSink` is a type parameter of the builder (D-033); `NoopSink` compiles away; events are `Copy`, at most 64 bytes, borrow nothing; `Refused` and `LimitHit` coalesce above 1,000 per second per worker. Stats are per-worker plain counters published as relaxed snapshots once per loop. `ConnectionId`s come from per-worker blocks of 1,024 taken with one `fetch_add` on a process-wide `AtomicU64`; a small block-to-worker map lets `ServerHandle::kill` find the owner.

---

## 7. Deployment modes

Our server never runs inside Apache or nginx. It runs beside them, in one of these modes. All of them hand the upper layers the same normalized connection, so nothing above the ingress adapter knows which mode is active.

| Mode | How | Who handles it |
|---|---|---|
| **Direct** | binds :80/:443 itself, TLS via tls-net | net-io + tls-net |
| **Reverse proxy, TCP** | Apache `ProxyPass` / nginx `proxy_pass` to `127.0.0.1:port`; real client via PROXY protocol or `X-Forwarded-For` from a trusted proxy | net-io (+ the web layer for headers, with the same `TrustedProxies`) |
| **Reverse proxy, Unix socket** | same, over a Unix socket; no port exposed | net-io local sockets |
| **FastCGI** | Apache `mod_fcgid` / `mod_proxy_fcgi`, nginx `fastcgi_pass` | fcgi-net (sans-IO) over net-io; descriptor 0 adoption (FR-43) |
| **CGI** | the web server runs our binary once per request | web layer adapter over stdin/stdout, last resort |
| **Socket activation** | systemd passes the listening sockets | `net_io::systemd()` |

**cPanel note.** On a cPanel server with WHM/root (VPS or dedicated), a long-running daemon behind Apache `ProxyPass` (or EA-Nginx) is fine. On shared cPanel hosting, a process that keeps a port open is usually not allowed and FastCGI is often the only real option (open decision O-2).

---

## 8. Security

### 8.1 Threat model

net-io is the first and last code every connection touches. Attackers range from scanners to botnets with residential proxies. net-io must stop, on its own, the attacks that are transport problems (every layer stands alone), and it must make the gate's enforcement impossible to skip. Assets: descriptors, memory, worker threads, CPU, the integrity of the client address, the guarantee that no byte leaves a revoked connection, listening sockets during restarts, local IPC endpoints.

Owned elsewhere: bans and rates (bouncer-io), content (customs-sec), identity (gates), floods larger than the link (upstream), SYN floods (kernel SYN cookies; documented).

### 8.2 Threats, defences, tests, costs

Every threat has an attack test that must fail to get through. Costs are [est.] until measured.

| # | Threat | Defence | Test | Cost |
|---|---|---|---|---|
| T-1 | connection flood exhausting descriptors | caps before any read; gate before any read | `test_accept_flood_at_cap_refuses_with_rst` | one table update per accept, under 50 ns |
| T-2 | descriptor exhaustion making accept spin or stall | reserve descriptor, accept backoff | shim `EMFILE`; real low `RLIMIT_NOFILE`; CPU near zero, backlog drains when descriptors return | one spare descriptor per acceptor |
| T-3 | slowloris | handshake and read deadlines, inbound minimum rate, exchange deadline | one byte every 900 ms; closed `SlowPeer { In }` by grace + window | one timer per active connection per second |
| T-4 | slow-read | write deadline, outbound minimum rate, output budget | zero receive window; closed `SlowPeer { Out }` or `WriteTimeout`; memory never above the budget | same |
| T-5 | idle keep-alive hoarding | idle deadline; adaptive deadlines (P2); blocking idle 5 s | 10,000 idle at 90% of cap; new clients admitted | none below pressure |
| T-6 | handshake that never finishes | one handshake deadline for PROXY and TLS | half a PROXY header, half a ClientHello | one timer |
| T-7 | memory exhaustion through many connections | idle connections hold no read buffer; budgets; back-pressure | 50,000 connections each sending 1 byte; RSS bounded | none |
| T-8 | oversized PROXY header | 107-byte v1 cap; v2 length checked before the body | v2 declaring 65,535 bytes closed at once | none |
| T-9 | spoofed client address via PROXY from an untrusted peer | trust checked at accept; untrusted peer on a Required listener closed before reading | valid header from a non-trusted address: `ProxyUntrusted` | one set lookup |
| T-10 | missing PROXY header behind a proxy | `Required` fails closed; no optional mode | trusted peer sends `GET /`: `ProxyMissing` | none |
| T-11 | PROXY header injected by a client through a proxy that does not strip it | exactly one header is read; a second is application data | second line never interpreted as PROXY | none |
| T-12 | PROXY v2 TLV bugs | bounds-checked walk, checked arithmetic, fuzzing, property tests | fuzz target `proxy_v2`; property: never panics, never reads past the length | none |
| T-13 | framing someone else through a forged address | as T-9; `client_key` uses `real_peer` only from a trusted header | as T-9 plus the gate's own test | none |
| T-14 | data leaving a revoked connection | gate check before every write system call; wipe; abortive close | revoke between two chunks; no byte of chunk 2 on the wire (loopback capture) | one hook call per write, under 2 ns |
| T-15 | partial response leaking before a denial | denial only on a clean boundary | revoke after the first byte of a streamed response: reset, no denial bytes mixed in | none |
| T-16 | residual request data in reused buffers | wipe on release (default on) | secret read on connection A is zeroes for connection B | 50-100 ns per 2 KiB |
| T-17 | kill races (double close, reused descriptor) | closing flag CAS; only the owner closes; generations | loom model kill vs FIN vs drain; 1 million racing kills | one CAS per close |
| T-18 | IOCP / io_uring use-after-free on cancellation | buffers owned until the completion is reaped | kill during pending `WSARecv` with a guard-page allocator; ASan for io_uring | none |
| T-19 | accept storm starving established connections | accept batch; `EPOLLEXCLUSIVE` | 50,000 connects per second while 1,000 echo; their p99 within 2x | none |
| T-20 | offload flood filling completion queues | bounded ring, `Full`, park deadline | 1 million posts to one worker; never above capacity | none |
| T-21 | event sink as a bottleneck | coalescing above 1,000 per second per worker | refusal flood; sink sees about 1,000 per second plus counts | one counter |
| T-22 | hash flooding the per-source table | keyed hash, random per-process key | addresses chosen for an unkeyed hash make no long chains | about 2 ns per hash |
| T-23 | Unix socket hijack or eavesdropping | default `0600`, private directory guidance, `bind_atomic`, `require_uid` | another uid connects to a `0600` socket and is refused | one `getsockopt` per accept |
| T-24 | stale-path deletion of a non-socket (symlink attack) | `lstat`, remove only a refusing socket | path is a symlink to an important file: `StaleSocketInUse`, target untouched | one `lstat` |
| T-25 | Linux abstract socket squatting | abstract names only with `require_uid` | another uid binds first; ours fails; a client of another uid refused | one `getsockopt` |
| T-26 | named-pipe squatting | `FILE_FLAG_FIRST_PIPE_INSTANCE`; owner-only descriptor | another process creates the pipe first: `PipeNameInUse` | none |
| T-27 | pipe client impersonated by a malicious server | `SECURITY_SQOS_PRESENT \| SECURITY_IDENTIFICATION` | test server impersonates: identification level only | none |
| T-28 | remote access to a local pipe | `PIPE_REJECT_REMOTE_CLIENTS` always | SMB connect when a lab exists; flag inspection otherwise | none |
| T-29 | hand-off channel abuse | `0700` directory, peer uid/pid, magic, version, CRC32C, per-descriptor verification, all or nothing | manifest from another uid; a regular file descriptor; truncated control data: all rejected, every descriptor closed | under 1 ms per hand-off |
| T-30 | Windows hand-off to the wrong process, or a replayed hand-off | `WSADuplicateSocketW` targets one pid; pipe client pid checked; net-io enforces single use with a manifest nonce (Windows does not, spike S-1); every received socket verified | replay the blob in another process: `WSASocketW` fails; replay it in the target process: refused by the nonce check | one table lookup per hand-off |
| T-31 | descriptor leak into child processes | close-on-exec everywhere | spawn a child and list its descriptors / handles | none (macOS window documented) |
| T-32 | `SIGPIPE` killing the process | `MSG_NOSIGNAL`, `SO_NOSIGPIPE` | a C host with default disposition writes to a reset connection and survives | none |
| T-33 | systemd variables meant for another process | `LISTEN_PID`, `LISTEN_PIDFDID`, per-descriptor checks | a child with inherited variables gets an empty list | none |
| T-34 | descriptor 0 not a listening socket under FastCGI | `SO_ACCEPTCONN` and `ENOTCONN` checks | terminal, file, connected socket: `None` | 3 system calls once |
| T-35 | UDP amplification | no-amplification guard (factor 1) until proof | small request from a spoofed source: replies never larger | under 30 ns per send |
| T-36 | UDP source flood and table exhaustion | per-source budgets, bounded table with eviction, shared overflow bucket | 1 million sources; memory bounded; verified peers keep budgets | under 30 ns per datagram |
| T-37 | truncated datagram treated as complete | truncation always reported | 70 KB into a 1 KB buffer: `truncated` | none |
| T-38 | port hijacking on Windows | `SO_EXCLUSIVEADDRUSE` by default | second process binds with `SO_REUSEADDR`: fails | none |
| T-39 | privileged port held while running as root | bind, then drop privileges, then `open_door` | integration test in shield-sec; net-io: `open_door` is separate | none |
| T-40 | `Server` used after `fork` | creator pid; `ForkedChild` | fork and call `open_door` in the child | one comparison |
| T-41 | io_uring kernel attack surface | off by default, feature-gated, automatic fallback | under Docker's default seccomp: epoll and a `DriverFallback` event | none |
| T-42 | timer storms caused by peers | lazy extension, intrusive slots, bounded expirations | 100,000 connections extending every millisecond; CPU per connection flat | none |
| T-43 | hello inspection bypassed by fragmenting the ClientHello | the engine reassembles within its bound; net-io's read buffer limit and handshake deadline bound it too | ClientHello in 1-byte records | bounded |
| T-44 | refusal path used for amplification | at most 512 bytes, one non-blocking attempt, TCP after the handshake only | SYN flood triggers no writes; completed connections get at most 512 bytes | one system call |
| T-45 | gate or session panic letting traffic through | a gate panic is refuse / deny; a session panic closes the connection | test hooks that panic | none |

### 8.3 What net-io does not cover

- Bytes already handed to the kernel cannot be recalled; all-or-nothing responses must be complete before they are written.
- SYN floods are the kernel's (SYN cookies); net-io cannot see half-open connections.
- Floods larger than the link need upstream help.
- A compromised trusted proxy can claim any client address; keep the list minimal.
- macOS: a descriptor can leak to a child created by another thread between `socket` / `accept` and `fcntl(FD_CLOEXEC)`.
- Policy (who is banned, which rate) is the gate's; net-io's per-source cap is a concurrency cap only.

### 8.4 Defence ideas per version (hypothesis, method, cost)

| Version | Idea | Hypothesis | Method | Expected cost |
|---|---|---|---|---|
| 0.3 | reserve descriptor plus accept backoff | descriptor exhaustion no longer makes the accept loop spin or stall | shim-injected `EMFILE`, real low `RLIMIT_NOFILE`, CPU measured during pressure | one descriptor per acceptor |
| 0.4 | hand-off manifest with CRC32C, peer check, per-descriptor verification | a local attacker cannot inject or steal listeners during a restart | hostile sender tests (other uid, wrong descriptor types, truncation) | under 1 ms per restart |
| 0.5 | zero-byte receives on IOCP for idle connections | memory under an idle-connection flood on Windows stays at state-only levels | 10,000 idle connections, RSS against 4 KiB posted receives | one extra system call per wake-up |
| 0.6 | adaptive deadlines under pressure | hoarding near the cap is cleared four times faster without hurting normal clients | load test at 90% of cap with 10% slow clients | none below the threshold |
| 0.7 | deterministic fault injection across the whole state machine | every partial-IO and error path is exercised on every OS | shim schedules covering every system call site, in CI | test time only |
| 0.8 | lane reservations at the connection level | health checks and admin access survive a flood of unimportant connections | flood with low-importance connections; important connects still succeed | one counter per lane |
| 0.9 | per-source handshake-failure counts handed to the gate as strikes (net-io counts, the gate decides) | scanners that fail PROXY or TLS repeatedly are banned within seconds | scanner simulation with a gate; `Gate::closed` carries the reasons | one counter per failure |
| 1.0 | `SO_ATTACH_REUSEPORT_CBPF` seam for kernel-side steering and drops | known-bad prefixes can be dropped before accept on Linux | prototype with the gate's prefix export; accept-path CPU under a flood | kernel side only |
| 0.2 (new) | ticket returned to the gate at close (`Gate::closed`) | the gate learns every transport-level misbehaviour (slow peer, bad PROXY, TLS failure) with its connection's ticket, so strikes need no event parsing and no lookup | bouncer-io integration test: a slowloris connection produces a strike on its ticket's keys | one hook call per close |

---

## 9. Performance

### 9.1 Targets

All targets are [est.] until the 0.6 measurement. "Best competitor" is the fastest Rust library on that benchmark at equal or stronger security (security-sensitive benchmarks give competitors equivalent limits in user code; the harness documents each configuration).

| Id | Benchmark | Metric | Target |
|---|---|---|---|
| B-1 | accept rate, 1 listener, connect-close clients | connections per second, p99 accept-to-admission | at least 1.2x the best competitor |
| B-2 | echo, 64 B, 1 connection | round trips per second, p50, p99 | at least 1.2x (blocking vs `std::net` threads; reactor vs tokio) |
| B-3 | echo, 64 B, 100 / 1,000 / 10,000 connections | throughput, p99, p99.9 | at least 1.2x tokio; within 10% of monoio/glommio on Linux at 0.6, at least equal by 1.0 |
| B-4 | echo, 16 KiB, 1,000 connections | bytes per second, CPU per GB | at least 1.2x |
| B-5 | idle connections | RSS per idle connection attributable to the library | under 512 B, at least 1.2x lower than tokio |
| B-6 | 100,000 idle (Linux), 10,000 (all OSes) | RSS, idle CPU | bounded by configuration; idle CPU near zero |
| B-7 | gate check overhead | ns per write, `AllowAll` and a one-atomic gate | under 1 ns and under 2 ns |
| B-8 | timer insert / cancel / lazy extend | ns per operation | under 20, under 20, under 2 |
| B-9 | PROXY v1 TCP4, v2 IPv4 without TLVs, v2 with 5 TLVs and CRC32C | ns per header | under 100, under 50, under 300 |
| B-10 | completer post-to-wake | µs from `post` to `on_wake` on an idle worker | under 10 µs p99 |
| B-11 | kill latency | µs from `kill` to RST on the wire | under 1 ms p99 |
| B-12 | drain of 10,000 idle connections | ms to `DrainReport` | under 100 ms |
| B-13 | system calls per echo round trip | count | at most 3 (reactor), 2 (blocking, Unix), 3 (blocking, Windows: D-052) |
| B-14 | allocations per connection after warm-up | count | 0 |

### 9.2 Competitors and harness

Rust: `std::net` thread per connection, `mio`, `tokio`, `monoio` and `glommio` (Linux, io_uring), `compio`. libuv and Seastar for context only. An unpublished `compare/` crate with its own `[workspace]` holds one echo and one accept server per competitor and an in-house open-loop load generator (coordinated-omission-free timing as in `wrk2`). criterion microbenchmarks in `benches/` for B-7 to B-10 and the pool. Reference hardware: Ryzen 9 9950X3D, Windows 11 and WSL2 Ubuntu; published Linux numbers from bare metal or labelled "WSL2". Method: fixed governor, disjoint pinned cores, 10 runs, median and spread, system calls per operation, allocations, RSS slope; every number names its commit, hardware, OS, kernel, and command line. Load benchmarks run before each release from 0.6; a regression over 5% blocks the release.

### 9.3 Where the speed comes from (hypotheses for 0.6)

1. No runtime layer: sessions are called directly by the worker loop, with no future, waker, or task queue between.
2. No allocation per connection or per IO after warm-up.
3. Lazy timer extension: no wheel operation per read.
4. Fewer system calls: `accept4` with flags, batched accepts, `SO_RCVTIMEO` only on change, vectored writes, one wake per completion burst.
5. Idle connections hold no buffers, so caches stay warm for active ones.
6. The gate, the sink, and the session factory are monomorphized; no-op versions compile away.
7. The gate ticket removes a per-write lookup (D-018).

If a hypothesis fails, the roadmap records it and the design changes; the 1.2x gate is not waived without James in writing.

---

## 10. Ecosystem and dependencies

### 10.1 net-io's own dependencies

- **Runtime:** none, in every feature combination (NFR-1, D-014).
- **Dev only:** `criterion`, `proptest`, `loom` (under `cfg(loom)`), and `libc` / `windows-sys` for the layout cross-check only. Competitor crates live in the unpublished `compare/` crate, never in net-io's graph.
- **REPS exception (D-047):** REPS says "MUST use tokio for async runtime". net-io uses no async runtime (D-004); the portfolio standard records that clause as a known mistake, and this plan records net-io's exception. Whether REPS itself changes portfolio-wide is James's open decision O-1.

### 10.2 Existing crates the stack reuses

| Crate | Role in the stack |
|---|---|
| `http-net` | HTTP/1.1 engine, sans-IO, no dependencies (0.6 published) |
| `parse-net` | shared grammar for the protocol crates |
| `ws-net` | WebSocket engine, sans-IO |
| `wire-codec` | binary framing for non-HTTP protocols |
| `rpc-io` | JSON-RPC 2.0 engine |
| `clock-lib` | monotonic time; an application can implement net-io's `Clock` over it in one line (D-038) |
| `crypt-io`, `key-vault` | cryptography and key storage (gate-net, sessions, tls-net) |
| `log-io`, `metrics-lib` | logging and metrics (implement `EventSink`) |
| `signal-mod` | OS signals, turned into `ServerHandle::request_stop` or the control line by the application |
| `sys-lib` | process guard, open-file limit, boot order (bind, drop privileges, open the door) |

### 10.3 Crates to build or finish

| Crate | Purpose |
|---|---|
| **net-io** | transport substrate (this crate) |
| **bouncer-io** | the door: ban memory, in-flight revocation, egress wipe-and-eject; implements `Gate` |
| **tls-net** | adapter from rustls to net-io's TLS seam; we do not write TLS (D-003) |
| **serve-net** | network service module on net-io: ingress modes, sessions, drain |
| **fcgi-net** | FastCGI engine, sans-IO |
| **customs-sec**, **gate-net**, **gate-sec**, **shield-sec**, **sentinel-sec**, **sandbox-sec** | security stack (each has its own plan) |
| **quic-net**, **dns-net** | later |

### 10.4 Dependency hygiene elsewhere

- `network-protocol` 1.4.0 overlaps net-io and carries about 28 third-party dependencies; net-io supersedes it. Two lessons taken: its Unix server removes an existing socket path unconditionally before binding (net-io removes only a stale socket: FR-53, T-24), and its named-pipe module claims a throughput advantage over loopback TCP without a benchmark (net-io measures before claiming).
- `service-kernel`, `proc-daemon`, `signal-mod`, `config-lib` depend on tokio or other third-party crates; tracked in their own plans.

---

## 11. Testing and verification

| Layer | What | Where | From |
|---|---|---|---|
| Unit | every function, every `Ok` and `Err` path | bottom of each file | 0.3 |
| Socket integration | real loopback sockets for every transport, option, limit, hook, close reason | `tests/` | 0.3 |
| Hostile peers | slowloris, slow-read, half-open, never-finishing handshakes, floods at the cap, PROXY attacks, kill races | `tests/server.rs`, `tests/edge.rs` (PROXY and handshakes from 0.4) | 0.3 |
| Fault injection | `sys` shim schedules (appendix A), system calls per round trip | `tests/shim.rs` (cfg `net_io_shim`); thread-scoped rules in unit tests | 0.3 |
| Property | PROXY parser (whole, split at every byte, byte by byte, arbitrary), CIDR and prefix keys, wheel against a sorted-list model, pool against a model, completer against a model, manifest round trip | seeded generator in `src/testing.rs` (D-076) | 0.3 / 0.4 |
| Fuzz | `proxy_v1`, `proxy_v2`, `proxy_any`, `handoff_manifest`, `systemd_env`, `cidr_parse`, `trusted_proxies_parse` | cargo-fuzz, corpus outside the repository | 0.4; continuous from 0.7 |
| Concurrency | loom: door word, closing flag, completer ring, id blocks, kill vs completion generation, wake-pending flag | `cfg(loom)` | 0.3 |
| Miri | non-`sys` modules with the shim | nightly CI | 0.3 |
| Sanitizers | ASan, TSan on the integration suite | Linux nightly CI | 0.5 |
| Allocation | counting allocator on every hot path after warm-up | `tests/alloc.rs` | 0.3 |
| Leak | 100,000 connections through every close path; descriptor and handle counts back to baseline | `tests/leak.rs` (`NET_IO_LEAK_CONNECTIONS`) | 0.3 |
| Layout | every `sys` constant, size, offset, and signature against `libc` / `windows-sys` | `#[cfg(test)]` beside the declarations in `src/sys/` | 0.3 |
| Conformance | PROXY specification examples; RFC 3720 CRC32C vectors; RFC 8305 timing with `ManualClock` | `tests/conformance_*.rs` | 0.4 / 0.5 |
| Cross-process | hand-off between two real processes; systemd emulation; FastCGI emulation | `tests/process_*.rs` | 0.4 |
| Soak | 24 h mixed normal and hostile traffic (0.7), 72 h (0.9) | release candidate box | 0.7, 0.9 |
| Benchmarks | section 9 | `benches/`, `compare/` | 0.6 |

Test names: `test_<subject>_<condition>_<expected>`. Every `CloseReason` variant has one integration test that produces it on a real socket and asserts exactly one `Closed` event with that reason, plus a property test that random interleavings of kill, FIN, RST, timeout, and drain always produce exactly one closed event.

---

## 12. Open decisions

James's calls. Each can be answered in one line. Technical decisions are in the log (section 14).

| Id | Question | Recommendation |
|---|---|---|
| O-1 | REPS says "MUST use tokio". net-io records an exception (D-047). Should the REPS rule itself change portfolio-wide to "no rented runtime"? | yes; the portfolio standard already calls the clause a known mistake, and every network crate follows the no-runtime rule |
| O-2 | Hosting: does the cPanel server have WHM/root, or is it shared hosting? | if shared, FastCGI moves into the first run of the web stack |
| OD-26 | FastCGI on Windows (`mod_fcgid` on Windows passes a named pipe, unverified): is a Windows FastCGI deployment planned? | only if one is planned: then P2 at 0.6; otherwise after 1.0 |

Closed at the design lock: O-3 (publish to claim the name) is settled by the release routine, which publishes 0.2.0 once James approves the API (D-048). O-5 (users core name) belongs to the gate crates' plans and moved there.

---

## 13. Ideas parking lot

Ideas worth keeping that are not scheduled. Each moves into the roadmap with a reason, or is dropped with a reason.

- **Kernel-level ban enforcement (Linux):** the gate pushes banned prefixes into an eBPF/XDP filter so banned traffic is dropped before it costs a system call. net-io's 1.0 idea (`SO_ATTACH_REUSEPORT_CBPF`) is the first step.
- **kTLS offload (Linux):** after the handshake, the kernel does record encryption (P3).
- **TCP Fast Open client side, `TCP_DEFER_ACCEPT`, FreeBSD accept filters:** fewer round trips; no worker woken until data arrives (P2/P3 in the option table).
- **Reverse-proxy client mode (`proxy-net`):** our own server forwarding to backends, using `encode_v1`/`encode_v2`.
- **HTTP/2 and HTTP/3 engines** on top of net-io and quic-net.
- **Connection fingerprint library:** ClientHello (JA4-style) and TCP-level fingerprints shared by bouncer-io and sentinel-sec.
- **Faster refused connects on Windows:** `SIO_TCP_INITIAL_RTO` with no SYN retransmissions reports a refused connect in under 0.5 ms instead of about 2 s (spike S-5), at the cost of retry behaviour on lossy networks; a candidate `ConnectOptions` setting.
- **Hardware CRC32C** (SSE4.2 `crc32`, ARMv8 CRC): only if the PROXY benchmark shows CRC is a measurable share (it is unlikely to be at 1 KiB headers).
- **A public timing wheel** (`Wheel`), if another crate needs one.

---

## 14. Decision log

| Id | Date | Decision | Reason |
|---|---|---|---|
| D-001 | 2026-10-13 | One crate for all transports (TCP, UDP, local), not `tcp-net` / `udp-net` | the driver, addresses, limits, timeouts, and drain are shared; splitting duplicates them or forces a third crate |
| D-002 | 2026-10-13 | QUIC goes to `quic-net`, DNS to `dns-net`, both later | QUIC builds TLS 1.3 into the transport (a large separate job); `std` covers DNS for now |
| D-003 | 2026-10-13 | TLS through a seam; rustls behind a separate `tls-net` adapter | keeps net-io dependency-free; TLS is the accepted third-party exception |
| D-004 | 2026-10-13 | No tokio, no async runtime; blocking pool first, own reactor second | ours, not rented; the sans-IO engines above work with either driver |
| D-005 | 2026-10-13 | Internal driver interface is completion-shaped | IOCP and io_uring are completion-based; readiness backends adapt cheaply, the reverse does not |
| D-006 | 2026-10-13 | net-io defines gate, TLS, and event traits; implementers depend on net-io, never the reverse | one-way dependencies; protocol-free rule |
| D-007 | 2026-10-13 | Mandatory gate check before every socket write, with wipe-and-replace and abortive close | no byte leaves a revoked connection even if a handler skips its checkpoints |
| D-008 | 2026-10-13 | Template aligned with http-net: edition 2024, MSRV 1.85, `Apache-2.0 OR MIT`, `dev/` committed and `.dev/` private | portfolio consistency |
| D-009 | 2026-10-13 | Naming: `gate-net` for authentication and sessions, `gate-sec` for authorization, `bouncer-io` for the door, `customs-sec` for contract inspection | James's naming |
| D-010 | 2026-10-13 | `shield-sec` and `sentinel-sec` (`sentinel` is taken) | public crate names in the `-sec` family |
| D-011 | 2026-10-13 | "Protocol parser" in the request path is a role, not a crate | each protocol keeps its own engine above the protocol-free layers |
| D-012 | 2026-10-13 | We never write our own TLS; `tls-net` stays a thin adapter | TLS safety comes from years of audits and side-channel work |
| D-013 | 2026-10-23 | The library specification written for the 0.2 design lock is adopted as the design contract; this plan, `ROADMAP.md`, and `docs/API.md` were rewritten from it | one contract for every later version; the specification extended the plan (drivers, sessions, completer, control line, hand-off, inheritance, limits defaults) and differed in a few places, each resolved below |
| D-014 | 2026-10-23 | OS access through our own `extern` declarations in `src/sys/` for x86_64 and aarch64 on linux-gnu, linux-musl, apple-darwin, unknown-freebsd, pc-windows-msvc, pc-windows-gnu; `libc` and `windows-sys` only as dev-dependencies for a CI layout cross-check (constants, sizes, offsets, signatures); other targets build the blocking driver over `std` and return `Unsupported` (was open decision OD-2) | zero runtime dependencies is the portfolio's rule; the surface is about 80 functions and 150 constants [est.], small enough to own (frozen in `SYS-SURFACE.md`); the cross-check removes the main risk, ABI drift; the cost is hand-maintained declarations, paid once per target |
| D-015 | 2026-10-23 | io_uring after 1.0 as P3 behind the non-default feature `uring`, with automatic fallback to epoll; never the default (was OD-4) | measured gains are workload-dependent (about +10% at 1,000 connections with mitigations on, a loss without them, per the Alibaba/OpenAnolis analysis) and its security record (kCTF VRP, Docker's seccomp profile, `io_uring_disabled`) argues against a default; the blocking pool and the reactor carry 0.3 to 1.0 |
| D-016 | 2026-10-23 | On Windows a listening socket is never associated with an I/O completion port, in any driver or process. The reactor accepts on Windows with one accept thread per listener (`WSAPoll` on the listener and a wake socket, then non-blocking `accept`); accepted sockets join the workers' IOCP ports. `AcceptEx` is not used for listeners; `NtSetInformationFile(FileReplaceCompletionInformation)` is rejected (was OD-5) | spike S-1: the association belongs to the shared kernel socket, so once any process associates a listener, a process that receives it by hand-off can never associate it (error 87, even after the first process closes), and its `AcceptEx` completions are delivered to the first process's port with a pointer from the wrong address space; a listener never associated works normally in the receiver. The native-API workaround redirects the old process's in-flight I/O. Accept rate is not the bottleneck on Windows deployments [est.]; at 0.6 `AcceptEx` may be offered for listeners that opt out of hand-off if a measurement shows it is worth a second path |
| D-017 | 2026-10-23 | Full-word names before anything is published: `TcpConnection`, `UnixConnection`, `PipeConnection`, `LocalConnection`, `ConnectionInfo`, `TcpOptions`, `SessionContext`, `Input`, `Output`, `Buffer`, `BufferPool`, `OutputFull`, `Endpoint`, `PeerCredentials`, `OsErrorClass`, `Operation`, `OperationKind`, `Rejected`, `Descriptors`, `DatagramBuffer`, `OutgoingDatagram`, `ProxySsl`, `ProxyAddress`, `ProxyProgress`; `SizeClass` constants `SMALL`, `MEDIUM`, `LARGE` (was OD-31; full table in `docs/API.md`) | the standard requires plain words without abbreviations; renaming is free before the first publish and expensive after; established socket vocabulary (`nodelay`, `backlog`, `linger`, `keepalive`, `Tlv`, `Cidr`) stays because it is the plain word for the thing |
| D-018 | 2026-10-23 | The gate seam is one trait, `Gate`, with an associated `Ticket` returned by `admit`, passed by `&mut` to `readmit` and `check`, and returned by value to `closed(ticket, info, reason)`; `check` returns `Result<(), Denial { code }>` and the connection's `Session::on_denied(code, output)` formats the refusal; `AllowAll` is the explicit no-gate. Agreed with bouncer-io for both 0.2 locks (its O-6, option (a)), with the additions in D-051 | the ticket removes a lookup by id on every write (bouncer measured the alternative at 5 to 10 ns per write [est.]); one trait means one builder call and no `Egress<Token = ...>` bound; `closed` gives the gate releases and strikes without parsing events; the session, not the gate, knows the protocol's framing state, which keeps the gate protocol-free |
| D-019 | 2026-10-23 | TLS seam in place, after tls-net's specification: `TlsAcceptor` (per-connection session) and `TlsSession::step(input, output)` with `TlsEvent::{NeedInput, Transmit, HandshakeComplete, Data, OutputFull, PeerClosed, Closed}`, `encrypt`, `close`, `on_transport_closed`, `info`, `input_capacity_required`. ClientHello inspection belongs to the engine; net-io drops its own hello capture and hook and maps `TlsFailure::HelloRefused` to `CloseReason::HelloRefused` | cross-crate decision X-2 (James, 2026-10-21), conditional on rustls reassembling multi-record handshake messages inside the caller's buffer: confirmed in rustls 0.23.46's source (section 6.15); no copy between engine and connection; the engine already parses the hello, so a second capture and hook would cost a copy and a second parse |
| D-020 | 2026-10-23 | `Server` is not generic; the factory, gate, sink, and acceptor types live in the worker loops | the type a program holds stays `Server` (simple API); nothing outside the workers needs those types |
| D-021 | 2026-10-23 | `Server::wait_for_stop` and `ServerHandle::request_stop` added | a Tier 1 program needs a one-line way to run until stopped and then drain; without it every user writes a parking loop |
| D-022 | 2026-10-23 | Any `Fn(&ConnectionInfo) -> S` is a `SessionFactory` (blanket impl) | `serve_sessions(addr, \|_\| Echo)` instead of a factory type for the common case |
| D-023 | 2026-10-23 | `Step::Close` always flushes, then FIN and the bounded linger; `Step::Abort` resets; `CloseAfterFlush` removed. Default `on_wake` returns `Abort`; default `on_timeout` returns `Close`, and a close from `on_timeout` carries the timeout's own reason and close style (amended by D-059) | one obvious way to close gracefully; an unexpected wake fails closed; a timeout keeps its own reason so logs and the gate see `Idle` or `ReadTimeout`, not a session error |
| D-024 | 2026-10-23 | Unix sockets default to mode `0600`; naming a group makes it `0660` (was OD-25, where the plan said `0660`) | fail closed: with no group named, `0660` would grant the process's primary group, which nobody chose; one call (`LocalOptions::group`) gives group access when it is wanted |
| D-025 | 2026-10-23 | A per-source concurrency cap lives in net-io (keyed by `PrefixKey`, table sized so it cannot overflow); rates and bans stay in the gate (was OD-8) | needs no policy, costs one table update per accept, and keeps a server safe without a gate |
| D-026 | 2026-10-23 | `ipv6_only` on by default (was OD-9) | an IPv6 listener is IPv6 only; dual-stack is explicit; no IPv4-mapped surprises in caps and bans |
| D-027 | 2026-10-23 | Wipe buffers on release by default; `wipe_buffers(false)` to turn off (was OD-10) | peer bytes may carry credentials; 50-100 ns per 2 KiB [est.] |
| D-028 | 2026-10-23 | Blocking-driver defaults: 128 workers, 256 KiB stacks, 5 s idle, `pressure()` = busy workers (was OD-11) | an idle connection holds a worker; revisit with the first consumer's measurements |
| D-029 | 2026-10-23 | The `Driver` trait becomes public Tier 3 at 0.5, marked unstable until 1.0, frozen at 1.0 (was OD-12) | an executor adapter and future drivers need it |
| D-030 | 2026-10-23 | The executor adapter is an optional, default-off feature `executor` in net-io, depending on the executor crate by published version (was OD-13) | one place for the adapter; never in the default build |
| D-031 | 2026-10-23 | MSRV stays 1.85; OS features newer than `std` 1.85 come through `sys` (was OD-14) | portfolio MSRV |
| D-032 | 2026-10-23 | Close style: RST for kill, gate denial, refusal, drain deadline, slow peer, limits, timeouts, PROXY and TLS failures, session errors; graceful for peer close, idle, drained, session close. A denial after part of a response left is a reset with no denial bytes (was OD-15, OD-16) | a stream cannot be repaired mid-response; RST frees kernel resources at once where the peer is misbehaving |
| D-033 | 2026-10-23 | `EventSink` is a type parameter of the builder, default `NoopSink` (was OD-17) | zero cost unused, one static call used |
| D-034 | 2026-10-23 | UDP amplification factor 1 by default, configurable up to 3 (was OD-18) | strict by default; QUIC sets 3 for its handshake per RFC 9000 |
| D-035 | 2026-10-23 | FreeBSD CI through a VM action on GitHub runners from 0.5; the action is chosen then (was OD-19) | no self-hosted runner to maintain |
| D-036 | 2026-10-23 | `LISTEN_*` variables are not unset after reading (was OD-20) | `remove_var` is `unsafe` in edition 2024 because it races other threads; the pid check already stops a child from using them |
| D-037 | 2026-10-23 | Minimum platforms: Linux 4.18 with run-time detection above it, macOS 11 (no hard CPU affinity: `Unsupported`), Windows 10 1809 / Server 2019, FreeBSD 13; io_uring (P3) needs Linux 6.1 [to confirm when built] (was OD-21, OD-22, OD-23) | covers RHEL 8, every supported macOS, and every Windows still in support; older systems get `Unsupported`, never undefined behaviour |
| D-038 | 2026-10-23 | net-io has its own minimal `Clock` trait (was OD-24) | no first-party dependency for one method; an application adapts `clock-lib` in one line |
| D-039 | 2026-10-23 | No `no_std` core crate now; the OS-free modules (PROXY, CIDR, prefix keys, CRC32C, wheel) stay `core`-clean, checked in CI (was OD-27) | split only when a second consumer needs them without the OS parts |
| D-040 | 2026-10-23 | PROXY v2 address-and-TLV cap 1,024 bytes by default, configurable up to 65,519 (was OD-28; the plan said 4 KiB) | covers a UNIX address block, a 128-byte unique id, ALPN, authority, and SSL sub-TLVs with room to spare; smaller is cheaper to bound |
| D-041 | 2026-10-23 | `ServerBuilder::build` requires a gate; `AllowAll` must be named; Tier 1 `serve` and `serve_sessions` use `AllowAll` and say so (was OD-29) | "no gate" is a visible choice in code, never a silent default |
| D-042 | 2026-10-23 | During a hand-off both processes may accept for a short overlap (was OD-30) | no refused connection during a restart; each connection still belongs to one process |
| D-043 | 2026-10-23 | `listen_local` and `connect_local` use a named pipe on Windows; AF_UNIX on Windows stays available through `UnixListener` (was OD-7) | native, ACLs, the client pid, every supported Windows |
| D-044 | 2026-10-23 | Happy Eyeballs at 0.5 (P2), simplified for `std` resolution, behind `ConnectOptions::happy_eyeballs(true)`, default off; the Resolution Delay arrives with `dns-net` (was OD-6) | `std` returns both families at once, so the rest of RFC 8305 applies as written |
| D-045 | 2026-10-23 | The fault-injection shim is compiled under `cfg(test)` or the custom cfg `net_io_shim`, never as a Cargo feature | a cfg cannot appear in the published feature list or be enabled by a dependent; normal builds contain no dispatch |
| D-046 | 2026-10-23 | Windows randomness for the per-source hash key through `BCryptGenRandom` with `BCRYPT_USE_SYSTEM_PREFERRED_RNG`; Linux and FreeBSD `getrandom`, macOS `getentropy` | documented interfaces only (`ProcessPrng` is what `std` uses but is not documented for direct use). Not needed by the blocking driver: D-062 |
| D-047 | 2026-10-23 | net-io records the REPS "MUST use tokio" clause as an approved exception (portfolio standard 2.8) | no async runtime in this crate (D-004); the portfolio-wide REPS change stays James's open decision O-1 |
| D-048 | 2026-10-23 | The crate name is claimed by publishing 0.2.0 in the release routine after James approves the API; 0.1.0 is not published separately (closes O-3) | the release routine publishes every completed version; a separate scaffold publish adds nothing |
| D-049 | 2026-10-23 | `TcpConnection::set_gate` registers dialed connections with a gate (`AdmitStage::Dialed`), replacing the earlier `set_egress` | dialed back-channel connections must be revocable like accepted ones, which needs the same ticket and the same close notification |
| D-050 | 2026-10-23 | `Refusal::WithBytes` bytes are `&'static`, at most 512, written once without retry and only on TCP after the handshake | canned replies need no allocation; the bound and the single attempt keep the refusal path from becoming an amplifier or a blocking point |
| D-051 | 2026-10-23 | Keep an opaque `GateTag(u64)`: returned in `Admitted::tag`, stored in `ConnectionInfo::gate`; and a per-response tag the session sets with `Output::begin_tagged_response(tag)`, seen by the gate as `WriteCheck::response` and cleared by `end_response` (requested by bouncer-io) | a protocol engine must name the connection to the gate (to open request tickets) without being generic over the gate type; on HTTP/2, or a proxy pooling many clients on one connection, only the request's own tag lets a write check judge the right request; cost: 8 bytes per connection and one field load per check |
| D-052 | 2026-10-23 | Blocking-driver waits per platform. Unix: blocking `recv` with `SO_RCVTIMEO`; sends with `MSG_DONTWAIT`, then `poll` on the socket and the worker's wake pipe on `EAGAIN`. Windows: `SO_RCVTIMEO`/`SO_SNDTIMEO` are never used; sockets are non-blocking and every wait is `WSAPoll` on the socket and the waiter's wake socket. Wake channels: one per worker (a pipe on Unix, a loopback UDP socket connected to itself on Windows), and for connections used outside a server one per calling thread, created on first use | keeps one system call per read on Unix; on Windows the documented "indeterminate state" after a timeout (spike S-2 saw no loss, but a lost byte mid-stream is a framing desync) is avoided at the cost of one extra system call per read; kills wake stalled sends at once on both (NFR-19); the wake channels are counted in the descriptor-limit check (FR-61) |
| D-053 | 2026-10-23 | Kill guard: the state word's `KILLING` bit keeps the owner from closing a socket or dropping a wake channel while a killer's wake call on it is in flight | a killer's `shutdown` or wake write on a descriptor the owner already closed could hit a reused descriptor number; the guard costs one compare-and-swap per kill and a bounded wait on close only when a kill is in flight |
| D-054 | 2026-10-23 | Windows hand-off is made single use by net-io: a 128-bit random nonce per manifest, refused on reuse in the receiving process; `SharedListeners::write_to(self, ..)` consumes the value | spike S-1: Windows returns the same socket for a reused `WSAPROTOCOL_INFOW` and a dead one for a blob used after the sender closed |
| D-055 | 2026-10-23 | Per-connection options: not re-applied on Linux and on Windows (every tested option is inherited from the listener with plain `accept`, spike S-4); applied explicitly to each accepted socket on macOS and FreeBSD until their CI tests show inheritance; a CI test asserts inheritance on Linux and Windows so a platform change is caught | fewer system calls per accept where the OS already does the work; no unverified assumption elsewhere |
| D-056 | 2026-10-23 | Windows connect completion through `WSAPoll`; `select` is dropped from the OS surface | spike S-5: `WSAPoll` reported every refused connect (`POLLWRNORM \| POLLERR \| POLLHUP`, `SO_ERROR` 10061) on Windows 10.0.26200; the older reports of missed refusals did not reproduce; the CI runners re-check it in the 0.3 tests and `select` returns only if one of them misses. Windows reports a refused loopback connect after about 2 s (SYN retries); shortening it (`SIO_TCP_INITIAL_RTO`) changes retry behaviour on lossy networks and goes to the parking lot |
| D-057 | 2026-10-23 | net-io never calls `shutdown` on a listening socket; accept threads are woken only through their wake channel | spike S-3: on Linux, `shutdown(SHUT_RD)` on a listener wakes `accept` with `EINVAL` and disables the listener for good (new connects are refused), which would break hand-off |
| D-058 | 2026-10-23 | `UnixListener::bind_atomic` (bind under a temporary name, then `rename` into place) confirmed on Linux; the listener records its final path itself | spike S-6: `rename` was atomic on ext4 and tmpfs (about 14 million connects racing 4,500 renames over a stale socket file never saw `ENOENT`), the old name gives `ENOENT` after the rename, and `getsockname` still reports the temporary name; macOS and FreeBSD are checked by the 0.4 CI test |
| D-059 | 2026-10-23 | Changes from an independent review of `docs/API.md` before approval. Names: `Limits` timeouts end in `_timeout`; `Server::wait_for_stop` and `ServerHandle::request_stop`; `Session::on_denied`; `TlsSession::on_transport_closed`; `ConnectionInfo::socket_peer`, `Endpoint::socket_addr`, `NetError::os_error_code`; `UnixListener::bind_atomic`; `LocalOptions::group_access`; `ControlState::Shed { from_lane }`; `TcpOptions` (was `ConnectionOptions`, too close to `ConnectOptions`); `receive_buffer`. Kept on purpose: `recv`/`send`, `addr`, the door. Behaviour: `Limits` records only what was set and the driver's defaults fill the rest (`resolve`), with dependent defaults following `max_connections`; a builder without a gate or a workload has no `build` (compile error naming the missing part, sealed `Workload`); `Server` is `#[must_use]`; `release_listeners` works with the door open so hand-off can overlap (D-042); `NetError` gains `From<io::Error>`, `From<AddrError>`, `FileTruncated`, `Address`, and loses `attempts`; every error type implements `Error`; `Output::push_partial`, and after `Step::Read` net-io calls `on_data` again when the input changed; dropping a connection never blocks; `begin_tagged_response` replaces `begin_response(Some(..))`; constructors for implementers and tests (`TlsError::new`, `TlsInfo::new`, `ConnectionInfo::for_testing`, `ConnectionId::new`, `WriteCheck::new`); `encode_v2` takes parts instead of a parsed header; data types that always-built items refer to are compiled in every feature set; `UdpSession`, `SendChunks`, the batch and multicast types, and per-cause `Stats` declared; `client_addr` and `client_key` move to 0.3 | the review found examples that did not compile, a seam that could not be implemented outside the crate, an API order that contradicted D-042, defaults that changed with a Cargo feature instead of the driver, and names a reader could not decode; the simplified-API rule (standard 2.10) makes each of these a defect |
| D-060 | 2026-10-23 | `Gate::readmit` has no default implementation | a default `Ok(())` would let a gate that never thought about proxies admit every real client behind a trusted proxy on the proxy's verdict; writing one line is the visible choice |
| D-061 | 2026-10-23 | `Endpoint::Unix` and `Endpoint::Pipe` hold `Arc<UnixPath>` / `Arc<PipeName>` shared with the listener; `ConnectionInfo::proxy` and `::tls` are `Option<Arc<ProxyFacts>>` / `Option<Arc<TlsInfo>>` drawn from per-worker pools and returned when the connection closes | with the facts inline, `ConnectionInfo` measured about 1.8 KB (two endpoints sized for a 256-unit pipe name, 420 bytes of PROXY TLV copies, 290 bytes of TLS facts), which alone breaks the 512-byte idle-connection target (B-5); shared and pooled, it is near 200 bytes and still allocates nothing after warm-up |
| D-062 | 2026-10-23 | Per-source table on the blocking driver: 16 shards of `Mutex<HashMap<PrefixKey, u32>>` with std's `RandomState` (SipHash keyed from OS randomness once per process), sized from `max_connections` at build | the accept path is one thread per listener and a close is one lock per connection, so a shard lock costs tens of nanoseconds uncontended; std's keyed hash gives the "no attacker-chosen collisions" property without new FFI (`getrandom` / `BCryptGenRandom` leave the 0.3 OS surface); the open-addressing table with striped compare-and-swap counts is measured against shards on the reactor in 0.5 |
| D-063 | 2026-10-23 | The timing wheel ships with the reactor in 0.5, not in 0.3 | a blocking worker holds one connection with at most five deadlines, all computed from its progress time and carried by `SO_RCVTIMEO` or the wait timeout; a wheel pays off only where one worker holds thousands of connections. Edge cases 53 to 60 and benchmark B-8 move with it (roadmap record) |
| D-064 | 2026-10-23 | FreeBSD and the std-only fallback arrive in 0.5; 0.3 builds on Linux, macOS, and Windows (x86_64, aarch64) and names the rest in a `compile_error!` | both need the reactor's kqueue path or a second blocking path without our FFI; a clear compile error beats a silent partial build |
| D-065 | 2026-10-23 | When net-io chooses the phase (an accepted connection whose owner never called `set_phase`), a reply returns the connection to `Idle` once no input is left over; `set_phase` turns this off; dialed connections never get it | the API promises that a session which never sets a phase still gets idle and read deadlines; without the return, a keep-alive session sat on the 30 s read timeout forever and a drain could not see it as idle |
| D-066 | 2026-10-23 | A graceful close skips the linger when the connection is idle and a zero-timeout poll shows nothing unread | the linger protects unread request bytes from turning the close into a reset; an idle connection has none, and lingering made a drain of idle connections wait out `graceful_linger` (2 s). Cost: one poll per idle close |
| D-067 | 2026-10-23 | The blocking hand-over refuses with `Busy` when queued plus busy connections reach the worker count; a worker counts as busy from the moment it takes a job (under the queue lock) until its close | the first rule ("queue length at least the idle workers") counted idle workers from zero, so a fresh server refused its first connection, and a worker about to look for work counted as busy. Cost: one atomic load under the existing lock |
| D-068 | 2026-10-23 | A session that closes after the peer's FIN (the default `on_peer_closed`) closes with `PeerClosed`, not `SessionClosed` | appendix A case 1; the peer ended the connection |
| D-069 | 2026-10-23 | Per-worker counters sit behind a single-writer sequence lock; `stats()` sums consistent per-worker snapshots | appendix A case 132: a reader could see a close's `bytes_out` without its `bytes_in`. Cost: two stores per close for the worker (its counter updates became plain load and store, cheaper than the read-modify-writes they replace); a reader retries a torn read |
| D-070 | 2026-10-23 | An accepted connection whose peer address is unspecified or has port 0 is reset at once and counted as an `AcceptError` | appendix A case 47: nothing to key caps or the gate on |
| D-071 | 2026-10-23 | The fault-injection shim gains thread-scoped rules (unit tests run in parallel threads), the `Reserve` and `RecvTimeout` call sites, and per-site call counters; integration tests reach it through a `#[doc(hidden)] pub mod __shim` that exists only under `cfg(net_io_shim)` | a global rule in one unit test could be consumed by another test's socket call; the counters measure system calls per round trip (B-13) without strace; the hidden module is never in a normal build and is not part of the API |
| D-072 | 2026-10-23 | The minimum-rate check requires `bytes_per_sec` over the time its buckets actually cover (the full older buckets plus the elapsed part of the current one, never more than the time since activation), not over the whole window | found by the property test: with a window of few buckets, right after a bucket boundary the check demanded a full window of bytes from a window of history and flagged a peer sending at twice the rate |
| D-073 | 2026-10-23 | Unix reads, including the wait for the next exchange, are one blocking `recv` under `SO_RCVTIMEO`; a drain closes idle connections through the kill slot: the owner marks the idle wait, the drain shuts the read side under the D-053 guard and wakes it, and the owner closes with `Drained`. The drain repeats this pass every 10 ms for connections that finish an exchange during it | B-13 asks for 2 system calls per round trip on Unix; polling before each idle read made it 3. Measured after the change: 2.00 on Linux, 3.00 on Windows (D-052), counted at net-io's call sites. A reply in progress still goes out (writes are untouched). Cost: two atomic read-modify-writes per idle read |
| D-074 | 2026-10-23 | The gate is asked once per write call, before its first system call, not again after `WouldBlock`; the zero-byte-send rule (appendix A case 19) covers the vectored path too | a retry sends the bytes the gate already approved, and a gate that counts bytes would count them twice; every new write call (each flush step) is still checked first, so cases 25 to 27 hold. The vectored path used to wait forever on a send that moved 0 bytes |
| D-075 | 2026-10-23 | The control line's reactions run in the accept thread: `Draining` closes the door and drains with the line's deadline (or the drain timeout); `Stopping` closes the door and kills every connection with `Shutdown`; `Shed { from_lane }` closes idle connections in shed lanes at once (`CloseReason::Shed`) and sessions in those lanes close at their next idle point | before, the reactions took effect only if the program was blocked in `wait_for_stop`, and `CloseReason::Shed` was never produced, against the API table |
| D-076 | 2026-10-23 | Property tests use an in-crate seeded generator (xorshift64*) instead of proptest | no new dev-dependency, and every failure reproduces from its seed; the properties (CIDR and prefix keys against integer masks, the output stream against a model, the rate check against fast and silent peers) need generation, not shrinking. Revisit for the PROXY parser in 0.4, where shrinking helps |
| D-077 | 2026-10-23 | `Endpoint` implements `Display` (`127.0.0.1:80`, the Unix path, the pipe name, or `unnamed`) | printing a listener's address was not possible without matching on the variant |
| D-078 | 2026-10-23 | Windows: an accepted socket gets `SetHandleInformation(.., HANDLE_FLAG_INHERIT, 0)` | std's `accept` does not clear inheritance on Windows, so a child process started by the application would inherit every client socket |
| D-079 | 2026-10-23 | Benchmark baselines in 0.3 use a plain harness (`harness = false`), medians over rotated rounds; criterion arrives with the 0.6 microbenchmarks | a baseline needs round trips per second and percentiles, not statistics machinery; rotating the order over 7 rounds and taking medians keeps scheduler placement on a multi-die CPU from moving a single number by 2x |
| D-080 | 2026-10-23 | A receive error of kind `TimedOut` closes the connection with `Io(TimedOut)`; only `WouldBlock` means "try again" | an expired `SO_RCVTIMEO` reads as `WouldBlock` on Unix and Windows sockets are non-blocking, so `TimedOut` can only be the kernel giving up on the connection (keepalive probes, appendix A case 8); retrying it looped until net-io's own deadline and reported the wrong reason |
| D-081 | 2026-10-23 | Requests from serve-net: `TrustedProxies` moves from 0.4 to 0.3, and `SessionContext::set_idle_timeout(Option<Duration>)` is added in 0.3 (this connection only, from its next idle wait, at least one tick; `None` restores the limit). Scheduled for 0.4: `Server::add_listener` / `remove_listener` (door closed until opened; removal closes that listener's door and drains its connections), trusted proxies per listener for PROXY, and the raw monotonic clock in microseconds for systemd `MONOTONIC_USEC` | serve-net 0.3's `http_behind_proxy` takes a `TrustedProxies` and the stack has one source of truth for trusted proxies; `TrustedProxies` is pure address code with no OS dependence. serve-net shortens keep-alive under pool pressure (its FR-58). The other three are needed by serve-net 0.4 (reload, systemd) and belong with the PROXY and systemd work |
| D-082 | 2026-10-26 | macOS listener check (`TcpListener::from_std`): when `SO_ACCEPTCONN` answers `ENOPROTOOPT`, a socket counts as listening if it has no peer (`getpeername` gives `ENOTCONN`) and is bound to a port | macOS does not answer `SO_ACCEPTCONN` (CI on macOS 15); `SO_LISTENQLIMIT` is not in `libc`, so its value cannot be cross-checked (SYS-SURFACE rule 4). A bound socket that never listened passes the check and fails at its first `accept` with `EINVAL`, a listener failure |

---

## 15. Spikes at the design lock

Throwaway programs outside the crate, run on the reference box (Windows 11 and WSL2 Ubuntu) on 2026-10-23. macOS and FreeBSD are not available locally; where a spike asks about them, the 0.3 (macOS) and 0.5 (FreeBSD) CI integration tests decide, and the design has a fallback for each.

Windows 11 build 10.0.26200.9711; WSL2 kernel 6.6.87.2 (Ubuntu 24.04.4). Each observation was repeated at least three times with the same result.

| Spike | Question | Result | Decision |
|---|---|---|---|
| S-1 | Can a process that receives a listening socket by `WSADuplicateSocketW` associate it with its own IOCP port? | Only if no process associated it before. If the sender had associated it, the receiver's `CreateIoCompletionPort` fails with error 87, also after the sender closes its socket and port, and the receiver's `AcceptEx` completions arrive on the **sender's** port with the sender's key. A listener never associated works normally in the receiver (association and `AcceptEx`). `NtSetInformationFile(FileReplaceCompletionInformation)` moves the association but also redirects the sender's I/O. A `WSAPROTOCOL_INFOW` used twice returns the same handle; used after the sender closed, a dead handle (later calls fail with 10038). | D-016, D-054 |
| S-2 | Windows: is a socket usable after an `SO_RCVTIMEO` timeout, and what wakes a blocked `recv`? | After the timeout (10060) the socket stayed usable and 256 KiB sent afterwards arrived intact. `CancelIoEx` from another thread wakes a blocked `recv` at once with 10004 (`WSAEINTR`) and leaves the socket usable. `shutdown(SD_RECEIVE)` and `shutdown(SD_BOTH)` do not wake it. | D-052 (timeouts not relied on); `CancelIoEx` kept for the IOCP reactor |
| S-3 | Linux: does `shutdown` wake a blocked `recv` or `accept`? | `shutdown(SHUT_RD)` and `SHUT_RDWR` wake a blocked `recv`, which returns 0 (indistinguishable from end of stream without the closing flag). On a listener, `shutdown(SHUT_RD)` wakes `accept` with `EINVAL` and disables the listener for good (new connects get `ECONNREFUSED`). | D-052, D-057 |
| S-4 | Which options set on a listener are inherited by accepted sockets? | Linux and Windows plain `accept`: all tested options inherited (`TCP_NODELAY`, `SO_KEEPALIVE`, keepalive idle, `SO_RCVBUF`, `SO_SNDBUF`, `SO_LINGER`, `IP_TTL`). Windows `AcceptEx`: TCP-level options early, `SO_RCVBUF`, `SO_SNDBUF`, `SO_LINGER` only after `SO_UPDATE_ACCEPT_CONTEXT`. | D-055 |
| S-5 | Windows: does `WSAPoll` report a refused non-blocking connect? | Yes, every time (`POLLWRNORM \| POLLERR \| POLLHUP`, `SO_ERROR` 10061), after about 2.03 to 2.07 s (Windows retries the SYN). `select` reports it in the exception set only. `SIO_TCP_INITIAL_RTO` with no SYN retransmissions cuts the refusal to under 0.5 ms. | D-056 |
| S-6 | Linux: is renaming a bound Unix socket into place atomic? | Yes on ext4 and tmpfs: connects to the final name reach the same listener, the temporary name gives `ENOENT`, and about 14 million connects racing 4,500 renames over a stale socket file never saw `ENOENT`. `getsockname` keeps reporting the temporary name. | D-058 |

macOS and FreeBSD: S-3 (`shutdown` waking `recv`), S-4 (inheritance), and S-6 (rename) are checked by integration tests in CI at 0.3 (macOS) and 0.5 (FreeBSD); the design does not depend on the answer (the kill also writes the wake pipe; options are applied explicitly there; `bind_atomic` falls back to `bind` then `chmod` with the private-directory requirement if a test shows `rename` is not atomic).

---

## Appendix A: edge cases

Every item has a test by the version that ships the feature it concerns.

**Reads.** 1. `recv` returns 0 in Idle: `on_peer_closed`, default `PeerClosed`. 2. `recv` returns 0 in Receiving (truncated request): `on_peer_closed`; the session decides. 3. Partial reads at every split of a request (property test, every byte boundary). 4. The buffer is full and the session consumed nothing: `Input::is_full`; consume or grow, else `Limit(ReadBuffer)`, never a spin. 5. `EINTR`: retried with the remaining deadline. 6. Spurious `EAGAIN` after a readiness event: re-arm. 7. `ECONNRESET`: `PeerReset`. 8. `ETIMEDOUT` from keepalive probes: `Io(TimedOut)`, distinct from our deadlines. 9. Data after our `shutdown(Read)`: never delivered. 10. Data while parked stays in the kernel; read after wake. 11. Buffer budget exhausted: reading pauses and resumes; no error to the peer. 12. Zero-length buffer to `recv`: `Ok(0)` without a system call, documented as not end of stream. 13. 107 bytes without CRLF: `V1TooLong`. 14. v2 signature split across 12 segments: waits, then succeeds. 15. PROXY header and application data in one segment: `consumed` leaves the rest. 16. A second PROXY header is application data. 17. First byte of a PROXY header, then silence: handshake deadline.

**Writes.** 18. Partial writes continue from the exact offset (shim: every split). 19. `send` returns 0 for a non-empty buffer: treated as `WouldBlock` once, an error the second time. 20. `EAGAIN`: wait for writability within the write deadline. 21. `EPIPE`: `BrokenPipe`, no signal. 22. `ECONNRESET` mid-write: `PeerReset`; output wiped and released. 23. Write deadline with output pending: `WriteTimeout`, abortive. 24. Vectored write accepted partly into the third slice: slices advanced in place. 25. More than 64 chunks: several system calls, each after a gate check. 26. Gate denial between two chunks of one response: no denial, RST. 27. Gate denial before the first byte: denial written once (at most 512 bytes), then RST. 28. Denial while the denial is being written: not checked again; the write budget bounds it. 29. Output budget full: `OutputFull`, `Step::Write`. 30. `sendfile` short, `EAGAIN`, or the file shrinks: stop, `Io(FileTruncated)`. 31. TLS ciphertext larger than the remaining budget: flushed in pieces under the same budget.

**Close.** 32. Peer FIN with our output pending: finish writing, then close. 33. Peer RST while we write: `PeerReset`. 34. Graceful close with unread input: linger up to 2 s / 64 KiB, then close. 35. `SO_LINGER {1, 0}` produces RST on every OS (packet check where possible). 36. Kill during graceful linger: abortive at once. 37. Peer half-closes and keeps reading a streamed response: allowed. 38. `shutdown(Write)` twice: no-op. 39. Closing after the peer closed: no error.

**Accept.** 40. `EMFILE` with the reserve available: one accepted and reset, backoff starts. 41. Reserve cannot be reopened: backoff continues, reserve retried each step. 42. `ENFILE`: same routine. 43. `ECONNABORTED`: counted, continue. 44. `EPERM` (Linux firewall): counted, continue. 45. `ENOBUFS` / `ENOMEM`: pause. 46. `EBADF` / `EINVAL`: listener failed, event, no spin. 47. Peer address unspecified after accept: close quietly, count. 48. 10,000 connections in the backlog when the door opens: batches interleaved with IO. 49. Door closed with 500 in the backlog: they stay for the next process or are reset by `shutdown`. 50. Accept on a handed-off listener: effective backlog reported as unknown where it cannot be read. 51. IPv4-mapped peer on a dual-stack listener: normalized before caps and the gate. 52. IPv6 scope id: kept; the prefix key ignores it.

**Timers.** 53. Deadline exactly at the current tick: fires this tick. 54. Deadline in the past: next tick. 55. Beyond 64^6 ticks: overflow list, fires correctly across the wrap. 56. 100,000 timers in one slot: at most 1,024 per iteration, IO interleaved. 57. Deadline extended a million times: one entry, fires once. 58. Cancelled after firing but before processing: ignored (generation). 59. Clock jumps an hour: every expired timer once, in order, bounded per iteration. 60. Frozen clock: nothing fires, no spin. 61. Tick 100 ms with a 50 ms deadline: rejected at build.

**IOCP.** 62. `CancelIoEx` returns `ERROR_NOT_FOUND`: success. 63. Operation succeeds after the cancel: processed, bytes discarded, close proceeds. 64. Completion for a reused slot: generation mismatch, buffer returned, dropped. 65. Error packet with a null `OVERLAPPED`: driver shutdown path. 66. A client resets between the accept thread's `accept` and the worker's port association: the association or first receive fails, counted, closed quietly. 67. An accepted socket is associated with exactly one worker's port, never the listener (asserted). 68. Zero-byte receive completes and the peer had closed: the following `recv` returns 0. 69. Skip-completion-port mode on immediate success: processed inline; the flag-off path tested by forcing it off. 70. A socket associated with another worker's port: impossible by construction; tested.

**io_uring (P3).** 71. `io_uring_setup` `EPERM`: epoll fallback, event. 72. CQ overflow impossible by sizing; checked each loop. 73. Multishot accept ends: re-armed. 74. Zero-copy send: buffer released after the notification CQE. 75. Cancel of a completed operation: exactly one completion.

**Unix sockets and descriptor passing.** 76. Path exactly at the maximum: accepted; one more byte: `PathTooLong`. 77. NUL in the path: rejected. 78. Stale socket file: removed, bind succeeds. 79. Live listener on the path: `StaleSocketInUse`, file untouched. 80. Regular file, directory, symlink: not removed, error. 81. `MSG_CTRUNC`: every descriptor closed, `Truncated`. 82. Descriptors with a truncated or bad-checksum body: all closed. 83. More descriptors than declared: all closed, `CountMismatch`. 84. Peer credentials unavailable: `None`, and `require_uid` refuses. 85. Our path replaced by someone else's socket: `Drop` does not unlink it.

**Named pipes.** 86. All instances busy: `WaitNamedPipeW` within the timeout. 87. Next instance created before hand-over: never "no instance". 88. Client gone before `ConnectNamedPipe` completes: `ERROR_NO_DATA` handled; `ERROR_PIPE_CONNECTED` is success. 89. Backslash in the name part: rejected before the system call.

**UDP.** 90. Datagram larger than the buffer: `truncated`. 91. Zero-length datagram: valid, not end of stream. 92. ICMP port unreachable (`ECONNREFUSED`, Windows `WSAECONNRESET`): never fatal to the socket (Windows `SIO_UDP_CONNRESET` checked at 0.4). 93. Source table full: strangers share the overflow budget; verified peers keep entries. 94. Factor 1 and a 1-byte request: a 2-byte reply refused until `mark_verified`.

**Hand-off and inheritance.** 95. `LISTEN_FDS=0`: empty list. 96. `LISTEN_FDS` non-numeric, negative, or above 64: `BadCount` / `TooMany`. 97. No `LISTEN_PID`: empty list. 98. Names count differs: `NamesMismatch`. 99. Descriptor 3 closed or a regular file: `NotASocket`. 100. A connected socket: `NotListening`. 101. FastCGI descriptor 0 is `/dev/null`, a TTY, a pipe, a connected socket: `None`. 102. Receiver timeout: `Timeout`, nothing adopted. 103. Sender dies mid-send: nothing adopted. 104. Windows blob used twice in the target process: refused by the nonce check before `WSASocketW` (Windows itself would hand back the same socket). 105. A listener received on Windows is never associated with a completion port (asserted; D-016).

**Server lifecycle.** 106. `open_door` twice: no-op. 107. `close_door` before `open_door`: no-op. 108. `drain` with nothing open: returns at once. 109. `drain` deadline already passed: kills at once. 110. `shutdown` takes `self`, so a session cannot call it; `ServerHandle::request_stop` from a session thread is safe. 111. `adopt` while draining: `ShuttingDown`. 112. `release_listeners` with the door open: duplicates returned while this process keeps accepting (D-042); `shutdown` afterwards does not close them. 113. `kill` with an id from another server or a closed connection: `false`. 114. Control line `Normal` -> `Shed` -> `Normal` in one iteration: only the final state, idempotent. 115. `Draining` without a deadline: the drain timeout. 116. More workers than CPUs: allowed; placement wraps. 117. `post` after shutdown: `ServerStopped`. 118. Session panics in `on_data` (unwind): `SessionPanicked`, worker continues, buffers returned, one closed event.

**Configuration.** 119. Zero caps, workers, backlog, batch: `InvalidConfig`. 120. Per-listener above global: `InvalidConfig`. 121. Caps plus reserves above `RLIMIT_NOFILE`: `InvalidConfig` with have and need. 122. `ProxyMode::Required` without trusted proxies: `InvalidConfig`. 123. 1,025 trusted blocks: `TooMany`. 124. `Cidr::parse("10.0.0.1/8")`: `HostBitsSet`; `new_masked` accepts. 125. `/33`: `PrefixTooLong`. 126. Address in use: `AddrInUse` with advice. 127. Port below 1024 without privileges: `PermissionDenied` with advice. 128. IPv6 address with IPv6 disabled: `AddrNotAvailable`.

**Cross-thread.** 129. Kill from 64 threads at once: one close, one event, 63 `false`. 130. Kill racing `Step::Close`: one close. 131. Post racing close: delivered before close or counted stale, never delivered elsewhere. 132. `stats()` while workers run: consistent per-worker snapshots, no torn counter.
