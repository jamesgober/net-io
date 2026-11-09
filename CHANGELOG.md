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

### Added

- Flush-then-close (D-182): after a denial whose bytes went out, the connection
  stops reading, sends what is queued, sends FIN, and discards input until the
  peer's EOF or `Limits::denial_linger` (default 100 ms; zero keeps the immediate
  reset). `Limits::denial_linger_max` caps how many connections linger at once
  (default a sixteenth of `max_connections`); past it a denial resets as before.
  On Windows this stops the formatted denial being lost to an abortive close.
- `ServerHandle::close_after_flush(id, reason, within)`: a soft kill. The session's
  queued output goes out within the bound, then the connection closes the same
  way. A later `kill` upgrades it to a reset.
- `Session::on_drain(cx) -> Step` (D-183): called once when a drain reaches a
  connection between exchanges. The default, `Close`, keeps the old behaviour; any
  other step keeps the connection until the session closes it or the drain
  deadline passes.
- `ListenerSpec::workers(n)` (D-186): on the reactor a listener gets workers of its
  own, so an admin listener keeps answering while the shared workers are busy.
- `Limits::first_request_grace` (D-189, default 1 s): a drain does not close a
  connection that was just accepted and has sent nothing yet, so a client that
  connected as the drain began still gets its first request answered.

### Changed

- A connection whose session wrote while it was idle (a reply in `on_open`, a push
  between exchanges) now lingers on a graceful close instead of closing at once,
  so a request already crossing the reply no longer turns the close into a reset
  that discards the reply (D-192).
- TLS on the reactor (D-194): the records a TLS engine writes as its handshake ends
  (session tickets) leave with the session's first reply, and a reply before
  `Step::Close` carries `close_notify` in the same send. A full exchange with a
  closing reply goes from 4 sends to 2. Held records go out at once whenever a
  turn ends without a reply.
- Per-worker listeners on the reactor (D-197): each worker accepts on its own
  socket in its own event loop, with no accept thread and no wake between threads
  for each connection. The gate's `admit` for these listeners runs on the worker.
  `remove_listener` still returns only once the group's sockets are closed.
- A graceful close on the reactor that needs no linger no longer calls `shutdown`
  before `close`: the close sends the FIN itself, one system call fewer (D-198).

### Fixed

- A refusal now shows in `Stats` by the time the client sees it; it was counted
  just after the socket closed (D-199).

## [0.7.1] - 2026-11-08

### Fixed

- On the reactor, an idle TLS connection kept its session's output, with up to
  four spare 16 KiB buffers from its last reply, charged to the shared buffer
  budget. Enough warm idle TLS connections spent the budget, and other
  connections' pushes then failed (`OutputFull`, `Limit(BufferBudget)`). The
  output and the session's input now go back as a plaintext connection's do
  (D-200; found by tls-net). Affects 0.7.0; on 0.6 such a connection held its
  128 KiB of TLS buffers as well.

## [0.7.0] - 2026-11-08

Hardening: an adversarial review of the whole crate with every finding of medium
severity or above fixed, attack tests for every threat, continuous fuzzing, a
soak, and a database consumer's transport needs.

### Security

- A session that wrote more than one 16 KiB output buffer per flush spent the
  shared buffer budget within seconds, after which other connections stalled and
  the session spun its worker; any client asking for a large reply could cause it.
  Outputs reuse their pool's buffers now, and a push the spent budget refuses
  closes the connection with `Limit(BufferBudget)` (also in 0.6.1).
- On the reactor, bytes read with a PROXY header on a TLS listener reached the
  session as plaintext after the handshake. They go to the TLS engine now
  (also in 0.6.1).
- A gate denial on a TLS connection was written in the clear between records. It
  is an encrypted record now, sent once.
- A panic in a TLS engine or an event sink cost a worker its connections, their
  cap slots, and every later drain. Both run behind panic boundaries, and each
  worker has a last boundary that closes and accounts for what a panic left.
- Released buffers were wiped only up to their current length, so a consumed
  request or decrypted TLS plaintext could reach the next owner. The wipe covers
  everything the buffer held since its last wipe.
- TLS records with no plaintext, or records the engine sends on its own, could
  keep a connection past its idle deadline or its minimum rate, and a handshake
  flight drained a byte at a time held a pool worker past the handshake deadline.
- A listener's own `max_connections` replaced the server's cap; it is refused at
  build now (use `max_per_listener`).
- Windows: a pipe listener with no open instance claims its name again instead of
  joining a pipe another user created under it; clients can check who serves a
  pipe (`PipeConnection::server_pid`, `server_owner_sid`); hand-off refuses a
  socket the process already owns, closes every socket of a failed message, and
  makes received sockets non-inheritable; binding an AF_UNIX path no longer
  deletes a reparse point that is not a socket file.
- Unix: a cut `SCM_RIGHTS` message closes every descriptor it carried; FreeBSD
  sets close-on-exec atomically; systemd and FastCGI descriptors with
  close-on-exec set are not taken (an in-place re-exec).
- UDP: verification is per address and port and expires (`verification_lifetime`,
  60 s), in its own bounded table; a dropped datagram no longer keeps its source
  in the table.
- The public `Driver` holds each registered socket until `deregister`, so a
  dropped socket's number cannot be reused by a connection that then gets another
  connection's bytes.

### Added

- `Backoff`, `TcpConnection::connect_retry`, `probe` (`Health`), and `drain`
  (`Drained`): reconnecting with backoff and jitter, a health check that consumes
  nothing, and a client-side drain.
- `TcpConnection::recv_file`: receives into a file at an offset, by `splice` on
  Linux and by copying elsewhere, under the usual read limits.
- `PipeConnection::server_pid` and `server_owner_sid`.
- `UdpOptions::verification_lifetime`, `UdpOptions::verified_table`,
  `UdpSocket::forget_verified`, `UdpContext::forget_verified`.
- `SharedSocket`, the socket type `Driver::register` takes.
- `descriptor_limit()`: the soft descriptor limit, for placing a cap under it.
- `TlsInfo::with_peer_spki_sha256` and `peer_spki_sha256`: the SHA-256 of a
  verified client certificate's public key, which a TLS engine sets so a session
  can map a mutual-TLS peer to a principal.
- Fuzz targets `wheel`, `rate`, and `udp`, a nightly fuzz workflow, and `tests/soak.rs`.

### Changed

- The reactor sends at most 256 KiB of file between two looks at the OS, in
  256 KiB pieces, so a stream to a fast reader cannot hold off the worker's other
  connections.
- `Driver::register` takes a `SharedSocket`; `BorrowedSocket` is no longer public.
- Timeouts over a year and `max_connections` over 2^20 are refused at build;
  durations at call sites are held to a year.
- `Accepted` and `Admitted` come from the worker that takes the connection, so
  they always precede its `Closed`; one drain emits one `DrainFinished`.
- UDP verification expires and is per port: protocols call `mark_verified` on each
  proof. `amplification_window` is at most an hour.
- A sub-second `Linger::Timeout` rounds up to one second on every OS.

### Fixed

- `TcpConnection::connect_retry` gave up at once on two errors that pass: a
  reset during the connect (a server refusing at its cap) and, on Windows, every
  ephemeral port in use or in TIME_WAIT (10048, 10055); both are retried under
  the backoff now, and a reset during the connect reads as `ConnectionReset`.
  A `local_addr` this host does not have still ends it at once. Found by the 0.7
  soak's pooled client.
- A session that survived a timeout with part of a message held could panic a
  reactor worker (also in 0.6.1).
- The accept batch admitted connections after the door closed; a stop during a
  drain waited for the drain's deadline.
- On the reactor: a paused reader whose wait moved on never resumed; a failed OS
  wait abandoned every connection; a post could lose its wake; a flush behind the
  TLS engine's records lost its timer; a linger that began with a receive out
  never read; idle PROXY connections kept their handshake buffer.
- The minimum rate required nothing at low rates or with a window under twice its
  check interval (found by the new `rate` fuzz target).
- Smaller fixes: drains and sheds could hit a worker's next connection; a flood's
  coalesced tail waited for the next refusal; a persistent accept error spun the
  accept thread; an invalid lane reservation could be hidden by a later one; a
  pipe listener whose name was taken paused instead of failing.
- Windows: a process whose threads ended after using a `TcpConnection` could
  freeze entirely, every thread start and exit waiting: the thread's wake socket
  was closed by a thread-local destructor, under the loader lock. A thread's wake
  now goes to a list of spares for the next thread instead (also in 0.6.2).
- The reactor gave every short connection to its first worker: with all loads at
  0, the least-loaded choice always took worker 0. Ties now go round the workers.
- Windows: a backlog past 200 was silently cut to 200 pending connections, so a
  server whose accept thread fell behind dropped SYNs and clients waited about
  21 s to fail. It is asked for as `SOMAXCONN_HINT` now (also in 0.6.2).
- On the Linux pool a drain could close a handler in the middle of an exchange:
  it shut the read side of a connection whose next request had already arrived,
  and the rest of that request read as end of stream. A drain now leaves such a
  connection to answer first (also in 0.6.2).
- The Windows reactor held a graceful close to the full linger (2 s) when the
  peer reset after reading its reply, as a TLS client that skips `close_notify`
  does, so connections, buffers, and cap slots piled up under short connections.
  A reset now ends the linger (also in 0.6.2).
- A drain could still close a connection in the middle of an exchange when it
  landed just as the connection's request arrived: it is now the connection's
  own thread that decides, through its wake channel, on every system (the Linux
  pool waits before an idle-phase receive for this).
- A connection an accept thread was admitting as a drain began could be closed
  unread by the stop that followed (a reset after 0 bytes, seen in the Windows
  hand-off test). A drain now waits for admissions in progress.
- Idle TLS connections on the reactor kept two 64 KiB buffers each until they
  closed, so the default budget capped a server at about 4,096 TLS connections,
  and idle TLS peers could spend the budget every connection draws from. They
  give the buffers back while they wait, as plaintext connections do.
- Everything fixed in 0.6.1: posts reach connections waiting for input, an idle
  trim releases buffers with a receive out, a stop ends lingers, and a drain
  answers a request that already arrived.

---

## [0.6.2] - 2026-11-06

Fixes for Windows (a deadlock, a backlog cut to 200, and reset closes held for
the whole linger), for the reactor running every short connection on one
worker, and for a drain that could cut a request short on Linux. No API change.

### Fixed

- The Windows reactor held a graceful close to the full linger (2 s) when the
  peer reset after reading its reply, as a TLS client that skips `close_notify`
  does, so connections, buffers, and cap slots piled up under short
  connections. A reset now ends the linger.
- A drain could close a connection in the middle of an exchange: it shut the
  read side of a connection whose next request had already arrived (or arrived
  as the drain looked), and the rest of that request read as end of stream. The
  connection's own thread now decides, through its wake channel, on every
  system; the Linux pool waits before an idle-phase receive for this.
- A connection an accept thread was admitting as a drain began could be closed
  unread by the stop that followed (a reset after 0 bytes, seen in a Windows
  hand-off between two processes). A drain now waits for admissions in
  progress.
- Windows: a backlog past 200 was silently cut to 200 pending connections (the
  default 1,024 included), so a server whose accept thread fell behind on a busy
  host dropped SYNs and those clients waited about 21 s to fail (found by
  ws-net). It is asked for as `SOMAXCONN_HINT` now, up to 65,535, and
  `ListenerInfo::backlog` reports what Windows applies.

- The reactor gave every short connection to its first worker: with all loads at
  0, the least-loaded choice always took worker 0, so one core served a whole
  handshake or request-per-connection load (found by tls-net, at about half of
  the throughput the other workers could add). Ties now go round the workers.

- Windows: a process whose threads ended after using a `TcpConnection` could
  freeze entirely, every thread start and exit waiting. A thread's wake socket
  was closed by its thread-local destructor, which runs under the loader lock,
  and that deadlocked against a thread loading a Winsock extension (the IOCP
  driver and `TransmitFile` do). A thread's wake now goes to a list of spares
  for the next thread instead. Affects 0.3.0 to 0.6.1 on Windows; seen as the
  library tests hanging in about 1 run in 14.

---

## [0.6.1] - 2026-11-04

A patch for serve-net's requests 4 and 7 and three defects found by the 0.7
review. No API change.

### Security

- A session that wrote more than one 16 KiB output buffer per flush (a large
  reply, a stream, a WebSocket echo) charged the shared buffer budget anew on every
  flush: the output's spare buffers went to the worker's pool and were never taken
  back. With the default budget (512 MiB on the reactor) it ran out within seconds,
  after which other connections could get no buffer and stalled, and a session whose
  push then took nothing was called back at once for ever, spinning the worker. Any
  client that asks for a large reply could cause it. An output now reuses the pool's
  buffers before charging the budget, and a flush with nothing queued because the
  budget refused it closes that connection with `Limit(BufferBudget)`. Affects 0.6.0
  on both drivers (found by ws-net's soak).
- On the reactor, bytes that arrived with a PROXY header on a TLS listener reached
  the session as if they had been decrypted, once the handshake finished: a client
  (or anyone between it and a proxy in TCP mode) could put bytes in front of the
  real ClientHello and have them read as the TLS peer's. They now go to the TLS
  engine, which refuses them. A ClientHello sent in the same segment as the header
  no longer stalls the handshake. Affects 0.5.0 and 0.6.0 with sessions on the
  reactor behind PROXY with TLS; the blocking pool was not affected.
- A session that survived a read timeout while part of a message waited in its
  buffer could make a reactor worker panic, closing every connection on that worker
  without its closed event. The input now knows when a receive holds its buffer.

### Fixed

- A `Completer::post` now reaches a connection that waits for input, not only a
  parked one, on both drivers, so a WebSocket can be written to from another thread
  (serve-net request 7). A post that arrives while the session is busy is delivered
  at its next wait. On the blocking driver on Linux, a connection whose session took
  a completer waits with one `poll` before each receive so the post can wake it.
- A session step that ends in `Step::Read` while a receive is already out (a
  survived idle timeout, a wake) gives back its idle buffers, as a fresh wait does:
  a trimmed idle connection holds about 1.8 KB, not 4.9 KB (serve-net request 4).
- With an injected clock on the reactor, `Server::shutdown` waited for ever on a
  connection that had closed gracefully and was lingering: a stop or a deadline
  kill now ends a linger, as a single kill already did.
- An accept batch checks the door, a drain, a stop, and the control line before each
  accept, so no connection is admitted after the door closed (serve-net's drain race).
- A drain no longer closes a connection whose next request has already arrived: it
  is answered first, then closed (the drain race's second window).

---

## [0.6.0] - 2026-11-04

Optimisation: the P2 options, files and UDP batches on both drivers, the
competitor harness, and the benchmarks B-1 to B-14 with their numbers.

### Added

- Listener and socket options: `ListenOptions::defer_accept`, `fast_open`,
  `incoming_cpu`, and `user_timeout`. An option the OS lacks fails with
  `Unsupported`. Fast open is off by default: its first data can be replayed.
- `ListenOptions::per_worker` (Linux): one `SO_REUSEPORT` socket and accept
  thread per reactor worker, each feeding its own worker.
- Files: `TcpConnection::send_file` and `Output::push_file`, by `sendfile` on
  Unix and `TransmitFile` on the Windows reactor, reading in pieces where those
  do not apply. The gate checks every MiB. A file that ends early fails the
  connection with `FileTruncated` and the count sent.
- UDP: `recv_batch` and `send_batch` with `DatagramBuffer` and
  `OutgoingDatagram` (`recvmmsg` and `sendmmsg` on Linux), packet info on Unix
  (`UdpOptions::packet_info`), `join_multicast` with `MulticastInterface`, and
  `UdpSession`, `UdpContext`, `ListenerSpec::udp`, and
  `ServerBuilder::udp_sessions` for UDP on a server.
- Adaptive deadlines (`Pressure`): handshake and idle deadlines shrink as the
  server fills, with hysteresis.
- `Limits::lane_reserve`: slots kept for the lanes before a given lane.
- `ListenerSpec::lockdown_allowed`, `Placement` for worker pinning, and the
  PROXY encoders `encode_v1` and `encode_v2`.
- `compare/`: an unpublished harness that runs one load generator against
  `std`, `mio`, `tokio`, `monoio`, and both net-io drivers.
- `benches/lifecycle.rs`: PROXY parsing, post to wake, kill to reset, and drain.

### Changed

- The reactor reads the clock once per turn, not once per event.
- On kqueue the write filter exists only while a send or connect waits, so an
  ACK no longer wakes the loop: 3 system calls per round trip on macOS.
- Parsing a PROXY v1 line tries the other address family only to name an error:
  87 ns per header, from 345.

### Security

- The reactor did not apply the minimum transfer rate to a peer that sent more
  often than the check interval (1 s by default): each arrival moved the check
  later, so a client sending one byte every 40 ms after an opening burst kept its
  connection for as long as it kept sending (slowloris). The rate is now checked
  on every arrival and every send completion. The blocking pool was not affected.
  Affects 0.5.0 with the reactor, the default driver for sessions, and 0.5.0 is
  yanked from crates.io for this reason; lockfiles that already name it still
  build.

### Fixed

- `Server::drain` on the reactor could report a connection it killed at the
  deadline as neither killed nor graceful: the drain could finish between the
  connection's release and its count.
- A buffer moved into an `Output` with `push_buffer` was never handed back, so an
  echo that swapped its input allocated 16 KiB per round trip and ran at a
  fiftieth of the copying echo's rate. An output now keeps one spare and returns
  the rest to the pool when a send completes.

---

## [0.5.0] - 2026-11-02

Feature complete: the reactor on every platform, and Windows as a full peer of
Unix for local sockets and restarts.

### Added

- The reactor: one event loop per worker on epoll (Linux), kqueue (macOS,
  FreeBSD), and I/O completion ports (Windows). `DriverKind::Auto` now picks it
  for sessions; a `BlockingHandler` stays on the pool. Sessions, PROXY, TLS,
  drain, kill, control-line sheds, and `Completer` all run on it.
- The timing wheel: six levels, lazy extension, tickless, never early.
- `new_reactor_driver` and the public `Driver` interface (Tier 3, unstable until
  1.0): register, submit, wait, cancel, deregister, a waker, and operations that
  own their buffers until the completion hands them back.
- Windows named pipes: `PipeListener`, `PipeConnection`, `PipeOptions`,
  `PipeSecurity`, `ListenerSpec::pipe`, and `listen_local` / `connect_local` on
  Windows. Owner-only by default, remote clients always rejected, a name another
  process took is an error, and pipes have the limits, deadlines, kill handle,
  and gate of a socket on both drivers.
- AF_UNIX on Windows: `UnixListener`, `UnixConnection`, `ListenerSpec::unix`.
- The Windows hand-off: `share_listeners`, `SharedListeners`, `receive_shared`,
  with a nonce that makes each hand-off work once.
- Happy Eyeballs: `ConnectOptions::happy_eyeballs` and `attempt_delay`.
- FreeBSD, tested in a VM in CI.
- `docs/ARCHITECTURE.md`, and the examples `named_pipe` and `offload_completer`.

### Changed

- An idle reactor connection holds no buffer, in any phase: an empty input goes
  back to the pool. `Limits` and rate settings are shared between connections,
  and TLS state is boxed, so a connection's state is 848 bytes.
- An empty buffer budget pauses a reactor connection's reads instead of closing
  it: TCP pushes back on the peer, and the read deadline keeps running. Setting
  up a PROXY or TLS handshake on an empty budget still closes with
  `Limit(BufferBudget)`, since nothing has been accepted yet.
- `Operation::Close { abortive }` is honoured on every driver.
- A kill cancels overlapped IO on Windows.

### Fixed

- `descriptor_limit` no longer takes an unlimited macOS or FreeBSD descriptor limit
  for a number.

---

## [0.4.0] - 2026-10-29

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

[Unreleased]: https://github.com/jamesgober/net-io/compare/v0.7.1...HEAD
[0.7.1]: https://github.com/jamesgober/net-io/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/jamesgober/net-io/compare/v0.6.2...v0.7.0
[0.6.2]: https://github.com/jamesgober/net-io/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/jamesgober/net-io/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/jamesgober/net-io/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/jamesgober/net-io/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/jamesgober/net-io/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/jamesgober/net-io/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jamesgober/net-io/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/net-io/releases/tag/v0.1.0
