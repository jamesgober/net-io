# net-io - Platform notes

What differs between operating systems, what net-io does about it, and what an operator should know. Covers 0.4.0: TCP, Unix domain sockets, UDP, the PROXY protocol, the TLS seam, inheritance, and hand-off on the blocking driver; named pipes, the Windows hand-off, and the reactor follow in 0.5.

## Every platform

- **One worker per open connection.** The blocking driver serves each connection on a pool thread (128 by default, 256 KiB stacks). An idle keep-alive connection holds its worker, which is why the default idle timeout is 5 s. `max_connections` defaults to the worker count; the reactor (0.5) lifts this.
- **Busy means busy.** When every worker has a connection or one waiting for it, a new connection is refused with RST (`RefusalCause::Busy`) instead of queueing without bound.
- **Descriptors.** At build, net-io checks that `max_connections + 2 x workers + 32` descriptors fit under the process limit (`RLIMIT_NOFILE` on Unix) and refuses the configuration otherwise, naming what it has and needs.
- **The door.** `close_door` stops accepting but keeps the listening sockets open: new connections wait in the kernel's backlog for the next process (hand-off, 0.4) or until `shutdown` closes the listener, which resets them.
- **PROXY behind a proxy.** A listener with `ProxyMode::Required` closes a peer outside its trusted proxies before reading a byte. On a Unix listener every peer that can open the socket file is trusted, so the file's mode is the boundary. HAProxy (v1 and v2) and nginx (v1) are tested in CI over TCP and Unix sockets; Apache's `mod_proxy` does not send the PROXY protocol (`mod_remoteip` only receives it).
- **UDP.** Every datagram is charged to its source address's budget before `recv_from` returns it, and replies to a source that has not been marked verified never exceed what it sent (factor 1 by default). Sources are keyed by IP address, not port. A full source table (65,536 by default, about 130 bytes each) evicts unverified entries; strangers that still find no room share one overflow budget and get no send allowance.
- **Closing.** A graceful close sends FIN and, if the peer may still have unread request bytes in flight, reads and discards up to 64 KiB for up to 2 s so the reply is not destroyed by a reset. An idle connection with nothing unread closes at once. Kills, timeouts in the middle of an exchange, and refusals close with RST (linger 0).

## Linux

- **Backlog.** The kernel silently caps `listen`'s backlog at `net.core.somaxconn` (4,096 since 5.4, 128 before). net-io reads `/proc/sys/net/core/somaxconn` and reports the effective value in `ListenerInfo::backlog`. Raise the sysctl for large accept bursts.
- **SYN floods** are the kernel's job (SYN cookies, `net.ipv4.tcp_syncookies`); net-io sees only completed handshakes.
- **No SIGPIPE.** Sends use `MSG_NOSIGNAL`, so a peer that disappears mid-write is `PeerReset`, never a signal.
- **Two system calls per exchange.** A keep-alive round trip is one blocking `recv` (its timeout set with `SO_RCVTIMEO` only when the deadline moves by more than one tick) and one `send` with `MSG_DONTWAIT`.
- **Kill and drain** shut the read side of the connection (`shutdown(SHUT_RD)`), which wakes a blocked `recv` at once; a reply already being written still goes out. net-io never calls `shutdown` on a listening socket: on Linux that disables the listener for good (decision D-057).
- **Port reuse.** `SO_REUSEADDR` is on by default for listeners (restart without waiting for `TIME_WAIT`); `SO_REUSEPORT` is opt-in.
- **Many short client connections** from one host can exhaust the ephemeral port range with `TIME_WAIT` entries on the side that closes first; this is the kernel's design, not a leak.

- **Unix sockets.** A listener's socket file gets its mode (0600 by default) and owner before the socket listens, so nothing connects under the umask's permissions. Paths are limited to 107 bytes. A stale socket file is removed only if nothing listens on it; anything else at the path (a live socket, a file, a directory, a symbolic link) is left alone and the bind fails. Peer credentials come from `SO_PEERCRED` (pid, uid, gid).
- **Inheritance.** systemd socket activation is tested with systemd's own `systemd-socket-activate`; `LISTEN_PIDFDID` (systemd 259 and Linux 6.9 or later) is checked against this process's pidfd.
- **Descriptor passing** receives with `MSG_CMSG_CLOEXEC`, so a passed descriptor is close-on-exec from the moment it arrives.

## macOS

- **No SIGPIPE.** Each socket gets `SO_NOSIGPIPE` at creation.
- **Waits.** Sockets stay non-blocking and every receive waits in `poll` first, as on Windows (decision D-083): a send with `MSG_DONTWAIT` on a blocking socket was seen to block on a full buffer, and `setsockopt` fails with `EINVAL` once a connection has ended, so the Linux model (blocking `recv` under `SO_RCVTIMEO`) does not hold. A keep-alive round trip is three system calls.
- **Backlog.** Capped by `kern.ipc.somaxconn`; the effective value is not readable per listener, so `ListenerInfo::backlog` is `None`.
- **Linger** uses `SO_LINGER_SEC` (seconds), not `SO_LINGER`.
- **`TcpListener::from_std`** cannot ask macOS whether a socket listens (`SO_ACCEPTCONN` is not answered), so it accepts a stream socket that is bound and has no peer; a socket that was bound but never listened then fails at its first `accept`.
- **`shutdown(SHUT_RD)`** discards data already received and any that arrives later; a drain or kill therefore never delivers more input to the session (Linux delivers what was already queued).

- **Unix sockets.** Paths are limited to 103 bytes. Peer credentials come from `getpeereid` (uid, gid) and `LOCAL_PEERPID` (pid).
- **Close-on-exec window.** macOS has no atomic close-on-exec for accepted, received (descriptor passing), or inherited descriptors: net-io sets `FD_CLOEXEC` right after the call, so a `fork` plus `exec` on another thread in between can inherit one.
- **UDP truncation.** A datagram larger than the buffer is reported `truncated` with the length that was copied; the real length is not available (Linux reports it).

## Windows

- **Waits.** Microsoft documents a socket whose blocking receive or send timed out as being in an indeterminate state, so net-io never relies on `SO_RCVTIMEO`: every socket in the blocking driver is non-blocking and every wait is `WSAPoll` on the socket and the worker's wake channel (decision D-052). A keep-alive round trip is therefore three system calls (`WSAPoll`, `recv`, `send`).
- **Wake channels.** Each worker's wake channel is a loopback UDP socket connected to itself, which holds one ephemeral port. With 128 workers that is 128 ports per server; many servers in one process (a test suite starting dozens of default servers at once) can run out of buffer space (`WSAENOBUFS`). Size `workers` to the load.
- **Exclusive binding.** Listeners use `SO_EXCLUSIVEADDRUSE` by default, so another process cannot bind the same port over net-io's listener. `SO_REUSEPORT` does not exist; asking for it is `Unsupported`.
- **Slow readers and send buffers.** Windows autotunes socket send buffers. On loopback a peer that never read absorbed 32 MiB before a send stalled, so the write timeout and the outbound rate check never fired. Internet-facing listeners on Windows should set `ListenOptions::send_buffer` (for example 256 KiB): then a peer that stops reading is detected within the write timeout, and the kernel memory one slow reader can pin is bounded.
- **Inheritance.** Listening and dialed sockets are created non-inheritable (`WSA_FLAG_NO_HANDLE_INHERIT`); accepted sockets are made non-inheritable after `accept` (decision D-078), so a child process the application starts does not keep client connections open.
- **Kill and drain** wake the owner through its wake channel (there is no safe equivalent of shutting only the read side under a blocked receive); the owner closes.
- **Local sockets.** Unix domain sockets (AF_UNIX) and named pipes arrive in 0.5: `listen_local` and `connect_local` return `Unsupported` until then, and a server listener built with `ListenerSpec::unix` fails `build` the same way.
- **UDP.** `SIO_UDP_CONNRESET` is switched off on every UDP socket, so an ICMP "port unreachable" for an earlier send never fails the next receive. UDP sockets are bound with `SO_EXCLUSIVEADDRUSE`. A truncated datagram (`WSAEMSGSIZE`) reports the length copied.
- **Hand-off and inheritance.** The Windows hand-off (`share_listeners`) arrives in 0.5; `systemd` returns an empty list, and FastCGI's descriptor 0 convention is Unix only (open decision OD-26).
- **IOCP.** Listeners are never associated with a completion port (decision D-016), so a listener can be handed to another process; the 0.5 reactor uses IOCP for connections only.

## Targets

0.4 builds on Linux, macOS, and Windows for x86_64 and aarch64, with net-io's own declarations of the OS calls it needs (`dev/SYS-SURFACE.md` lists them). FreeBSD and a std-only fallback for other targets arrive in 0.5; until then other targets stop at a compile error that says so.
