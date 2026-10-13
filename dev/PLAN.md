# net-io - Project Plan

> The design, strategy, and decision record for `net-io`. This is a living document: any design decision, idea, or open question about net-io that comes up anywhere (chat, review, a sibling crate) is written here or in [`ROADMAP.md`](./ROADMAP.md) before it is acted on, so nothing lives only in someone's memory.
>
> **Read order:** [`../REPS.md`](../REPS.md) (portfolio standard) &rarr; [`DIRECTIVES.md`](./DIRECTIVES.md) (engineering law for this crate) &rarr; **this file** &rarr; [`ROADMAP.md`](./ROADMAP.md) (phases and exit criteria).
>
> **Status:** scaffold, `0.1.0`. Design lock is `0.2.0`.

---

## Contents

1. [Purpose](#1-purpose)
2. [Where net-io sits](#2-where-net-io-sits)
3. [Scope](#3-scope)
4. [Design principles](#4-design-principles)
5. [Architecture](#5-architecture)
6. [Deployment modes](#6-deployment-modes)
7. [Security responsibilities](#7-security-responsibilities)
8. [Ecosystem and dependencies](#8-ecosystem-and-dependencies)
9. [Phases](#9-phases)
10. [Testing and verification](#10-testing-and-verification)
11. [Open decisions](#11-open-decisions)
12. [Ideas parking lot](#12-ideas-parking-lot)
13. [Decision log](#13-decision-log)

---

## 1. Purpose

net-io is the entrance and the exit. Every byte that reaches one of our services arrives through it, and every byte a service sends leaves through it. It owns:

- the sockets (TCP, UDP, Unix domain sockets, Windows named pipes) and their options,
- the life of each connection, from accept to close,
- the limits and timeouts that stop a peer from holding resources it should not hold,
- graceful drain and zero-downtime restarts,
- learning the real client address when running behind a proxy (PROXY protocol),
- the seams that TLS and the connection gate (`bouncer-io`) plug into.

It is written once and used by everything that listens on a port: the web stack, HiveDB's wire protocol, raft-io's transport, rpc-io over TCP, admin consoles, and anything we build later.

---

## 2. Where net-io sits

### 2.1 The request path

Each stage rejects as early and as cheaply as it can. An IP ban costs nanoseconds; a password check costs milliseconds and a database lookup. A flood that the door can stop must never reach the expensive stages.

```
            inbound                                              outbound
  ┌───────────────────────┐                             ┌───────────────────────┐
  │ net-io: accept        │  socket, ConnectionId,      │ net-io: write         │
  │                       │  peer address, limits       │                       │
  ├───────────────────────┤                             ├───────────────────────┤
  │ bouncer-io: door      │  ban list, caps, rates      │ bouncer-io: egress    │  last check before
  │                       │  (before any byte is read)  │                       │  bytes leave
  ├───────────────────────┤                             ├───────────────────────┤
  │ TLS (tls-net adapter) │  handshake, fingerprint     │ customs-sec: export   │  only declared data
  ├───────────────────────┤                             │                       │  leaves
  │ protocol engine       │  http-net / ws-net /        ├───────────────────────┤
  │                       │  fcgi-net / HiveDB wire     │ handlers / services   │  bouncer checkpoints
  ├───────────────────────┤                             │                       │  between stages
  │ customs-sec: head     │  declared size, type, route ├───────────────────────┘
  ├───────────────────────┤                                         ▲
  │ gate-net: authn       │  who are you (session/login)            │
  ├───────────────────────┤                                         │
  │ gate-sec: authz       │  may you do this                        │
  ├───────────────────────┤                                         │
  │ customs-sec: body     │  payload matches the contract ──────────┘
  └───────────────────────┘

  underneath everything: shield-sec (hardening)   watching everything: sentinel-sec (detection)
  spine for everything: service-kernel (lifecycle, workers, events, health, shutdown)
```

Customs runs twice on the way in on purpose: the head check is cheap and runs before authentication; the body is only read and parsed for a caller who is already authenticated and authorized for that route (public routes such as login have their own contract).

### 2.2 The protocol-free rule

A crate is **protocol-free** when it does its job without knowing the format of the messages crossing the wire. net-io moves bytes and knows who is connected; it never parses HTTP. The same is true of bouncer-io (it decides on addresses, counts, rates, and revocations), gate-net (credentials in, identity out), and session storage (an opaque token in, a session out). Only thin adapters at the top know where a protocol keeps its credentials or how it phrases a refusal.

**Litmus test:** delete `http-net` from the workspace. Every protocol-free crate still compiles; only the web crates break.

Why it matters:

1. **Written once.** Every service reuses the same transport, gate, auth, and sessions.
2. **Dependencies point one way.** Lower layers never import upper ones. HiveDB never pulls in an HTTP parser to log a user in.
3. **Ingress modes are cheap.** Direct, reverse proxy, Unix socket, FastCGI, and CGI differ only at the top; everything below is shared.
4. **Security.** The gate rejects before any parser runs, so a parser bug cannot be reached by traffic that was already refused.
5. **Testing.** Each layer is testable on its own, without sockets or fake requests.

---

## 3. Scope

### 3.1 In scope

| Piece | What it covers | Why it is here |
|---|---|---|
| **TCP** | listener, accepted connection, outbound connect, half-close, shutdown | web, HiveDB wire, Raft, RPC |
| **UDP** | bound socket, send/recv with source address, per-source budgets | discovery and gossip (Swarm), syslog and metrics, DNS, game servers; the base QUIC will need later |
| **Local sockets** | Unix domain sockets (Unix, and Windows 10 1803+ via AF_UNIX), Windows named pipes | reverse proxy over a socket, same-host IPC between our own services |
| **Socket options** | `TCP_NODELAY`, keepalive (idle/interval/count), `SO_REUSEADDR`, `SO_REUSEPORT`, `IPV6_V6ONLY`, buffer sizes, linger | `std::net` exposes few of these; servers need all of them |
| **Addresses** | parsing, IPv4-mapped IPv6 normalization, CIDR matching, prefix keys (IPv4 /32, IPv6 /64) | one canonical address type every layer agrees on; the gate bans by prefix |
| **Connection identity** | `ConnectionId` (unique per process, never reused), `ConnInfo` (local, peer, real peer after PROXY, transport, accept time) | the handle every later layer refers to, including bouncer revocations |
| **Lifecycle** | accepted, admitted, handshaking, open, draining, closed, with a close reason | so every layer and every log line agrees on what happened |
| **Limits and timeouts** | global connection cap, accept backlog, handshake, idle, read, write, and total deadlines, minimum transfer rate, bounded buffers | slowloris, slow-read, and memory exhaustion are transport problems |
| **Drivers** | blocking bounded worker pool (first), own readiness/completion reactor (second) | see [5.4](#54-drivers) |
| **Graceful drain** | stop accepting, finish open work within a deadline, then close | deploys and shutdown without dropped requests |
| **Inherited sockets** | systemd `LISTEN_FDS`, handing a listener to a replacement process | zero-downtime restarts and binding privileged ports before dropping privileges |
| **PROXY protocol** | v1 (text) and v2 (binary) parsing, sans-IO, accepted only from trusted proxy addresses | real client address behind Apache, nginx, HAProxy, load balancers |
| **Trusted proxies** | one `TrustedProxies` list (CIDRs) | the single source of truth; the web layer uses the same list for `X-Forwarded-For` |
| **TLS seam** | traits a TLS engine implements; access to the raw ClientHello | TLS without a TLS dependency in this crate; fingerprinting for the gate |
| **Gate seam** | admission hook at accept, egress hook before every write, kill handle per connection | how bouncer-io enforces without net-io depending on it |
| **Events** | an event sink trait (opened, admitted, refused, limit hit, closed with reason) | logs, metrics, service-kernel, and sentinel-sec subscribe without net-io depending on them |

### 3.2 Out of scope, and where it goes

| Not in net-io | Goes to | Reason |
|---|---|---|
| QUIC | `quic-net` (later) | QUIC runs on UDP but builds TLS 1.3 into the transport itself: its own loss recovery, congestion control, streams, and connection migration. A large job that deserves its own crate. net-io's UDP socket is its base. |
| DNS resolution | `std` for now, `dns-net` (later) | `std::net::ToSocketAddrs` covers it today. A real resolver (caching, DNSSEC awareness, async-friendly, no libc resolver blocking) becomes its own crate. |
| The TLS implementation | `tls-net` (adapter over rustls) | We do not write TLS. It plugs in through the seam, keeping net-io dependency-free. |
| Any protocol parsing | `http-net`, `ws-net`, `fcgi-net`, `wire-codec`, HiveDB wire | protocol-free rule |
| Ban lists, rate policy, revocation | `bouncer-io` | net-io provides the hooks and the kill handle; policy lives in the gate |
| Payload and contract validation | `customs-sec` | needs to know the protocol and the route |
| Authentication, sessions, authorization | `gate-net`, `gate-sec` | identity is not transport |
| Async/await runtime | none (see D-004) | net-io has its own drivers; no rented runtime |

---

## 4. Design principles

1. **Ours, not rented.** Zero runtime dependencies. Socket calls the standard library lacks are made through our own minimal FFI declarations, not the `libc`, `windows-sys`, `mio`, `socket2`, or `tokio` crates.
2. **Unsafe is fenced.** `unsafe` exists only inside `sys/` (per-OS FFI), every block carries a `// SAFETY:` comment, and everything outside `sys/` is `#![deny(unsafe_code)]`. Until `sys/` lands, the crate stays `#![forbid(unsafe_code)]`.
3. **Hooks, not dependencies.** net-io defines traits (gate, TLS, event sink); bouncer-io, tls-net, log-io, metrics, and service-kernel implement them. net-io never imports them.
4. **Everything is bounded.** Every buffer, queue, count, and wait has a limit, and each limit is checked before the resource is committed.
5. **Fail closed.** When a hook errors or a limit cannot be evaluated, the connection is refused or closed, never waved through.
6. **Cross-platform for real.** Linux, macOS, and Windows are first-class, verified in CI on stable and MSRV. FreeBSD is a goal. Platform differences are documented per feature, never hidden.
7. **Measured, not guessed.** No performance claim without a benchmark at realistic scale.

---

## 5. Architecture

### 5.1 Module map (planned)

```
src/
  lib.rs          crate docs, re-exports, Tier-1 entry points
  error.rs        NetError (#[non_exhaustive]), close reasons
  addr.rs         Addr, Cidr, PrefixKey, IPv4-mapped normalization
  id.rs           ConnectionId (monotonic u64, never reused in a process)
  info.rs         ConnInfo: local, peer, real peer, transport, timestamps
  limits.rs       Limits and timeouts, with defaults and validation
  opts.rs         socket options (portable surface over sys/)
  tcp.rs          TcpListener, TcpConn, connect
  udp.rs          UdpSocket, per-source budgets
  local.rs        UnixListener/UnixConn (Unix + Windows AF_UNIX), named pipes (Windows)
  proxy.rs        PROXY protocol v1/v2, sans-IO, TrustedProxies
  gate.rs         Admission and Egress traits, KillHandle
  tls.rs          TLS seam traits, ClientHello capture
  events.rs       EventSink trait and event types
  drain.rs        DrainController: stop accepting, deadline, force close
  inherit.rs      LISTEN_FDS and listener hand-off
  driver/
    blocking.rs   bounded worker pool over std::net
    reactor/      epoll (Linux), kqueue (macOS/BSD), IOCP (Windows)
  sys/
    unix.rs       FFI declarations and wrappers (the only unsafe)
    windows.rs    FFI declarations and wrappers (the only unsafe)
```

### 5.2 Connection lifecycle

```
 accepted ──▶ admitted ──▶ handshaking ──▶ open ──▶ draining ──▶ closed
     │            │              │           │          │
     └─ refused ◀─┘              └───────────┴──────────┴──▶ closed (reason)
```

- **accepted:** the OS handed us a socket. We have a `ConnectionId` and the peer address. Nothing has been read.
- **admitted:** the admission hook (bouncer) said yes. If it said no, the socket is closed without reading a byte.
- **handshaking:** PROXY header (if expected from this peer) and TLS handshake, both under the handshake timeout. The real peer address from PROXY is re-checked by the admission hook.
- **open:** application bytes flow, under the idle, read, write, and minimum-rate limits.
- **draining:** no new requests; in-flight work finishes until the drain deadline.
- **closed:** always with a `CloseReason` (peer closed, idle, timeout, limit, refused, killed, drained, error), emitted as an event.

### 5.3 The gate seam (bouncer-io hooks)

net-io defines three things and calls them at fixed points. bouncer-io implements them.

| Hook | Called | Can do |
|---|---|---|
| `Admission::admit(&ConnInfo)` | right after accept, again after the PROXY header reveals the real peer | allow, or refuse (closed before any byte is read) |
| `Egress::check(ConnectionId, ...)` | before every write to the socket, and per chunk when streaming | allow, or deny: the pending output is wiped (overwritten, not just dropped), replaced with the denial bytes the protocol adapter provides, then the connection is killed |
| `KillHandle::kill(reason)` | any time, from any thread | abortive close (`SO_LINGER` 0 so resources are freed at once), wakes any blocked read or write, emits a closed event |

The egress check is the guarantee that matters most: even if a handler forgets every checkpoint, no byte leaves a revoked connection. The hot path when nothing is revoked is a single atomic load and compare.

What the transport cannot do, stated plainly: bytes already flushed to the socket cannot be recalled. For responses that must be all-or-nothing, the protocol layer uses buffered (not streamed) mode so the egress check sees the whole response before any of it leaves.

### 5.4 Drivers

| Driver | Phase | Model | Use |
|---|---|---|---|
| **Blocking pool** | first | `std::net` sockets, a bounded worker pool, one connection per worker at a time, timeouts on every read and write | works everywhere: shared hosting, Windows dev boxes, CI. Enough for a first deployment. |
| **Reactor** | second | our own event loop: `epoll` on Linux, `kqueue` on macOS and BSD, IOCP on Windows | thousands of idle keep-alive and WebSocket connections without a thread each |
| **io_uring** | later, Linux only | completion queue | highest throughput on Linux; shares knowledge with store-io's io_uring work |

The internal driver interface is completion-shaped ("this read finished with these bytes"). Readiness backends (epoll, kqueue) adapt to it easily; IOCP and io_uring are completion-based natively. Designing around readiness and bolting IOCP on later is the classic mistake; we avoid it from day one.

The protocol engines above are sans-IO (`http-net`, `ws-net`), so swapping drivers never touches them.

### 5.5 TLS seam

- The seam is sans-IO: the TLS engine is fed ciphertext from the socket and returns plaintext, and the reverse on the way out. rustls already exposes this shape (`read_tls` / `process_new_packets` / `write_tls`), so `tls-net` is a thin adapter.
- net-io captures the raw ClientHello before the engine consumes it, so the gate can fingerprint clients (cipher and extension order identify tooling regardless of what the client claims to be).
- SNI and ALPN are surfaced in `ConnInfo` after the handshake, so one listener can serve several certificates and route HTTP/1.1, HTTP/2 (later), and other protocols.
- Certificate reload without restart (new handshakes use the new certificate; open connections keep theirs).

### 5.6 PROXY protocol and trusted proxies

- v1 (text, `PROXY TCP4 ...\r\n`) and v2 (binary, with TLVs) parsed sans-IO, with a hard size bound and a handshake deadline.
- Accepted only from peers in `TrustedProxies`. A PROXY header from anyone else closes the connection; otherwise any client could claim any address, evade bans, or frame someone else.
- When a trusted proxy is expected and the header is missing, the connection is refused (fail closed).
- The same `TrustedProxies` list is what the web layer consults before believing `X-Forwarded-For` / `Forwarded`, so there is one source of truth.

### 5.7 Limits and timeouts (proposed defaults, finalized at 0.2.0)

| Limit | Proposed default | Guards against |
|---|---|---|
| global open connections | 10,000 (reactor), worker count (blocking) | descriptor and memory exhaustion |
| accept backlog | 1,024 | SYN bursts overflowing the kernel queue |
| handshake deadline (PROXY + TLS) | 10 s | connections that never finish the handshake |
| idle timeout | 60 s | parked keep-alive connections |
| read / write timeout | 30 s each | stalled peers |
| minimum transfer rate | 256 B/s averaged over 10 s | slowloris (slow send) and slow-read |
| total deadline per exchange | set by the protocol layer, enforced here | trickle attacks inside every per-read timeout |
| PROXY header size | v1: 107 B (the spec maximum); v2: 16 B fixed part plus at most 4 KiB of addresses and TLVs | oversized or never-ending headers |
| per-connection buffer | 64 KiB read, 64 KiB write | memory exhaustion by many connections |
| drain deadline | 30 s | hung shutdowns |

Per-IP and per-prefix caps live in bouncer-io, which sees every admission.

### 5.8 Drain and restarts

- `DrainController` stops accepting, signals the protocol layer to finish in-flight work (HTTP: `Connection: close` on the next response), and force-kills what remains at the deadline.
- Listener hand-off: a new process inherits the listening sockets (systemd `LISTEN_FDS` on Linux, descriptor passing over a Unix socket, handle duplication on Windows), starts accepting, and the old process drains. No port is ever closed during a deploy.
- Bind privileged ports (80, 443) first, then drop privileges (shield-sec) before reading any untrusted byte.

### 5.9 UDP specifics

- No connections, so no accept-time admission; the gate checks per datagram (cheaply, by source prefix).
- Source addresses on UDP are trivially spoofed. Rules that follow from that:
  - never ban or score a source address that has not proven it can receive (a protocol-level cookie or handshake does that; net-io exposes the hook),
  - never send more bytes to an unverified source than it sent us (no amplification),
  - per-source and global datagram and byte budgets.

### 5.10 Local sockets

- Unix domain sockets on Unix, and on Windows through AF_UNIX (Windows 10 1803+), which `std` does not expose, hence our own `sys/`.
- Windows named pipes as the native Windows IPC option.
- Socket file permissions set at bind (0660 by default, owner and group configurable), stale socket file removal only if it is a socket and nothing is listening.
- Peer credentials (`SO_PEERCRED` / `getpeereid` / `GetNamedPipeClientProcessId`) surfaced in `ConnInfo`, so a local service can verify which process or user connected.

### 5.11 Errors and observability

- `NetError` is `#[non_exhaustive]`, with one variant per distinct failure and the OS error kept as a source.
- `CloseReason` on every close.
- `EventSink` receives typed events. A no-op sink costs nothing; log-io, metrics-lib, service-kernel's event bus, and sentinel-sec each implement it without net-io depending on them.

---

## 6. Deployment modes

Our server never runs inside Apache or nginx. It runs beside them, in one of these modes. All of them hand the upper layers the same normalized request, so nothing above the ingress adapter knows which mode is active.

| Mode | How | Who handles it | First run |
|---|---|---|---|
| **Direct** | binds :80/:443 itself, TLS via tls-net | net-io + tls-net | working |
| **Reverse proxy, TCP** | Apache `ProxyPass` / nginx `proxy_pass` to `127.0.0.1:port`; real client address via PROXY protocol or `X-Forwarded-For` from a trusted proxy | net-io (+ web layer for headers) | working |
| **Reverse proxy, Unix socket** | same, over a Unix socket; no port exposed | net-io local sockets | working on Unix |
| **FastCGI** | Apache `mod_fcgid` / `mod_proxy_fcgi`, nginx `fastcgi_pass` | fcgi-net (new, sans-IO) over net-io | stub, unless hosting requires it (see 11) |
| **CGI** | the web server runs our binary once per request | web layer adapter over stdin/stdout | stub, last resort |

**cPanel note.** On a cPanel server with WHM/root (VPS or dedicated), a long-running daemon behind Apache `ProxyPass` (or EA-Nginx) is fine. On shared cPanel hosting, a process that keeps a port open is usually not allowed and FastCGI is often the only real option. That decides whether FastCGI is a stub or a first-run requirement.

---

## 7. Security responsibilities

net-io is the first and last thing every connection touches, so it owns these guarantees itself:

| Threat | net-io's defence |
|---|---|
| connection floods, descriptor exhaustion | global cap, backlog bound, admission before any read |
| slowloris, slow-read, trickle | handshake deadline, read/write timeouts, minimum transfer rate, total deadline |
| memory exhaustion | bounded buffers per connection, bounded totals |
| spoofed client address | PROXY and forwarded headers trusted only from `TrustedProxies`; fail closed when missing |
| UDP spoofing and amplification | no trust before proof of reachability, no amplification, per-source budgets |
| data leaving a revoked connection | mandatory egress check before every write; wipe and replace; abortive close |
| local socket hijack | socket file permissions, peer credentials |
| privilege | bind first, then drop privileges (with shield-sec) |
| descriptor leaks | every close path tested; leak tests in CI |

Policy (who is banned, how scores work, what counts as suspicious) belongs to bouncer-io and sentinel-sec; see their own plans.

---

## 8. Ecosystem and dependencies

### 8.1 net-io's own dependencies

- **Runtime:** none.
- **Dev only:** `criterion` (benchmarks) and `proptest` (property tests), added when the first test that needs them lands.

### 8.2 Existing crates the stack reuses

| Crate | Version | Role in the stack |
|---|---|---|
| `http-net` | 0.2.0 | HTTP/1.1 engine, sans-IO, strict RFC 9112, no deps |
| `ws-net` | 0.2.0 | WebSocket engine, sans-IO |
| `wire-codec` | 1.0.0 | binary framing for non-HTTP protocols |
| `pack-io` | 1.0.1 | binary serialization with schema evolution |
| `rpc-io` | 0.2.0 | JSON-RPC 2.0 engine |
| `rate-net`, `better-bucket` | 1.0.0 | rate limiting; not used by bouncer-io until they drop their third-party dependencies (bouncer-io O-1) |
| `clock-lib` | 1.0.0 | monotonic time, mockable for deterministic timeout tests |
| `id-forge` | | request and session ids |
| `crypt-io`, `key-vault` | 1.1.0 | hashing, AEAD, Argon2id, key storage (gate-net, sessions) |
| `mod-rand` | 1.0.0 | OS-backed randomness for tokens |
| `cache-mod`, `pool-mod` | 1.0.0 | session cache, connection pools |
| `audit-trail` | | tamper-evident record of every security action |
| `log-io`, `metrics-lib` | 1.0.0 | logging and metrics (implement `EventSink`) |
| `service-kernel` | 0.1.0 | lifecycle, supervised workers, events, health, shutdown |
| `signal-mod` | 1.0.0 | OS signals for drain |
| `jsonx-lib` | | strict JSON for customs-sec |
| `path-lib` | 0.1.0 | hardened path joining (uploads, static files) |
| `unicode-lang` | | normalization and identifier checks in customs-sec |
| `sandbox-sec` | stub | process sandboxing mechanisms under shield-sec |

### 8.3 Crates to build or finish

Each crate below that has a repository carries its own `dev/PLAN.md`; this table only places it in the stack.

| Crate | Status | Purpose |
|---|---|---|
| **net-io** | this crate | transport substrate |
| **bouncer-io** | repo, plan written | the door: ban memory, in-flight revocation, egress wipe-and-eject |
| **customs-sec** | repo, plan written | contract inspection, inbound and outbound |
| **gate-net** | repo, plan written | authentication and sessions (protocol-free) |
| **gate-sec** | repo, plan written | authorization: permissions and policy |
| **shield-sec** | repo (private), plan written | hardening, inner firewalls, data protection, containment |
| **sentinel-sec** | repo (private), plan written | detection, patrol, risk scoring; enforces through bouncer-io and shield-sec |
| **sandbox-sec** | repo, plan written | sandbox mechanisms under shield-sec |
| **tls-net** | new | adapter from rustls to net-io's TLS seam; we do not write TLS (D-003) |
| **fcgi-net** | new | FastCGI engine, sans-IO |
| form crate (name open) | new | `x-www-form-urlencoded` and streaming multipart parsing with budgets |
| users core (name open) | new | user records; consumes and bridges gate-net and gate-sec |
| web layer | new | router, handlers, middleware, ingress adapters, static files, render hand-off (a third-party render crate at first, loosely coupled, replaced by our own) |
| **quic-net** | later | QUIC on net-io's UDP |
| **dns-net** | later | resolver |

The full deliverables map for the web and service stack, including the smaller supporting crates (URL handling, compression, encodings, SMTP, jobs), is kept in the portfolio's private strategy notes.

Names checked as free on crates.io on 2026-10-13: gate-net, gate-sec, customs-sec, shield-sec, sentinel-sec, tls-net, fcgi-net, quic-net, dns-net, bouncer-net. `sentinel` is taken.

### 8.4 Dependency hygiene elsewhere

These conflict with "ours, not rented" and are tracked here so they are not forgotten:

- `network-protocol` 1.4.0 overlaps net-io and carries about 28 third-party dependencies (tokio, dashmap, zstd, rustls, ...). net-io supersedes it.
- `service-kernel`, `proc-daemon`, `signal-mod`, and `config-lib` depend on tokio and other third-party crates. service-kernel's own plan keeps tokio out of its public types, which makes a later swap possible.
- The portfolio `REPS.md` says "MUST use tokio for async runtime". net-io does not use async/await or tokio (D-004). See open decision O-1.

---

## 9. Phases

Summary only; exit criteria live in [`ROADMAP.md`](./ROADMAP.md).

| Version | Name | Delivers |
|---|---|---|
| 0.1.0 | Scaffold | repository, template, this plan |
| 0.2.0 | Design lock | public API written down (types and signatures), `sys/` FFI surface listed per OS, hook traits final |
| 0.3.0 | TCP + blocking driver | addresses, ids, `ConnInfo`, limits, TCP listener and connection, socket options, blocking pool, gate and event hooks, drain, close reasons |
| 0.4.0 | Edges | PROXY v1/v2 + `TrustedProxies`, UDP, Unix sockets, TLS seam (+ tls-net), inherited listeners |
| 0.5.0 | Reactor | epoll, kqueue, IOCP; Windows AF_UNIX and named pipes |
| 0.9.0 | Hardening | fuzzing, soak, leak tests, adversarial review |
| 1.0.0 | Stable | frozen after the web stack and one non-HTTP service have used it end to end |

---

## 10. Testing and verification

- **Unit and doc tests** for every public item.
- **Socket tests** on real loopback sockets: accept, refuse, kill, drain, every timeout firing, every close reason.
- **Hostile peers:** slowloris, slow-read, half-open, handshake that never finishes, PROXY header from an untrusted peer, oversized PROXY header, connection floods at the cap.
- **Property tests** for the PROXY parser (whole, split, byte at a time, arbitrary bytes) and for address and CIDR logic.
- **Fuzz targets** for every parser (PROXY v1, v2).
- **Leak tests:** open and close 100k connections; descriptor and handle counts return to baseline.
- **Cross-platform CI:** Linux, macOS, Windows on stable and MSRV 1.85; FreeBSD when the reactor lands.
- **Benchmarks** with criterion: accept rate, echo throughput, idle-connection memory, egress-check overhead.

---

## 11. Open decisions

These are James's calls. Each is written so it can be answered with one line.

| Id | Question | Recommendation |
|---|---|---|
| O-1 | REPS says "MUST use tokio". net-io uses its own drivers and no async runtime. Keep REPS as is and record net-io as an exception, or change the REPS rule portfolio-wide to "no rented runtime"? | change REPS portfolio-wide, since http-net and ws-net already follow the no-runtime rule |
| O-2 | Hosting: does the cPanel server have WHM/root, or is it shared hosting? | if shared, FastCGI moves into the first run |
| O-3 | Publish `0.1.0` to crates.io now to claim the `net-io` name? | yes; the name is free today |
| O-5 | Name for the users core that bridges gate-net and gate-sec. | open |

---

## 12. Ideas parking lot

Ideas worth keeping that are not scheduled yet. Each moves into the roadmap with a reason, or is dropped with a reason.

- **Kernel-level ban enforcement (Linux):** bouncer-io pushes banned prefixes into an eBPF/XDP filter so banned traffic is dropped by the kernel before it costs us a syscall. The strongest answer to floods from known-bad sources.
- **`SO_REUSEPORT` sharded accept:** one listener per core, kernel load-balances.
- **kTLS offload (Linux):** after the handshake, the kernel does record encryption.
- **TCP Fast Open and `TCP_DEFER_ACCEPT`:** fewer round trips; no worker woken until data arrives.
- **Reverse-proxy client mode (`proxy-net`):** our own server forwarding to backends, for the "all options" goal.
- **HTTP/2 and HTTP/3 engines** on top of net-io and quic-net.
- **Connection fingerprint library:** ClientHello (JA4-style) and TCP-level fingerprints shared by bouncer-io and sentinel-sec.

---

## 13. Decision log

| Id | Date | Decision | Reason |
|---|---|---|---|
| D-001 | 2026-10-13 | One crate for all transports (TCP, UDP, local), not `tcp-net` / `udp-net` | the driver, addresses, limits, timeouts, and drain are shared; splitting duplicates them or forces a third crate |
| D-002 | 2026-10-13 | QUIC goes to `quic-net`, DNS to `dns-net`, both later | QUIC builds TLS 1.3 into the transport (a large separate job); `std` covers DNS for now |
| D-003 | 2026-10-13 | TLS through a seam; rustls behind a separate `tls-net` adapter | keeps net-io dependency-free; TLS is the accepted third-party exception |
| D-004 | 2026-10-13 | No tokio, no async runtime; blocking pool first, own reactor second | ours, not rented; the sans-IO engines above work with either driver |
| D-005 | 2026-10-13 | Internal driver interface is completion-shaped | IOCP and io_uring are completion-based; readiness backends adapt cheaply, the reverse does not |
| D-006 | 2026-10-13 | net-io defines gate, TLS, and event traits; implementers depend on net-io, never the reverse | one-way dependencies; protocol-free rule |
| D-007 | 2026-10-13 | Mandatory egress check before every socket write, with wipe-and-replace and abortive close | no byte leaves a revoked connection even if a handler skips its checkpoints |
| D-008 | 2026-10-13 | Template aligned with http-net: edition 2024, MSRV 1.85, `Apache-2.0 OR MIT`, `dev/` committed and `.dev/` private | portfolio consistency; the old scaffold (edition 2021, MSRV 1.75, Apache only) was never published |
| D-009 | 2026-10-13 | Naming: `gate-net` for authentication and sessions, `gate-sec` for authorization, `bouncer-io` for the door, `customs-sec` for contract inspection | James's naming; network gate = who you are, security gate = what you may do |
| D-010 | 2026-10-13 | `shield-sec` (was "hive-shield") and `sentinel-sec` (resolves O-4; `sentinel` is taken) | public crate names in the `-sec` family |
| D-011 | 2026-10-13 | "Protocol parser" in the request path is a role, not a crate: `http-net`, `ws-net`, `fcgi-net`, `rpc-io`, and each service's own wire format fill it | each protocol keeps its own engine above the protocol-free layers |
| D-012 | 2026-10-13 | We never write our own TLS; `tls-net` stays a thin adapter | TLS safety comes from years of audits, constant-time code, and side-channel work; a home-made TLS would be the weakest link in a security-first stack |
