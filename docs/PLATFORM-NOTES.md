# net-io - Platform notes

What differs between operating systems, what net-io does about it, and what an operator should know. Draft for 0.3.0 (TCP and the blocking driver); later versions add Unix sockets, UDP, named pipes, hand-off, and the reactor.

## Every platform

- **One worker per open connection.** The blocking driver serves each connection on a pool thread (128 by default, 256 KiB stacks). An idle keep-alive connection holds its worker, which is why the default idle timeout is 5 s. `max_connections` defaults to the worker count; the reactor (0.5) lifts this.
- **Busy means busy.** When every worker has a connection or one waiting for it, a new connection is refused with RST (`RefusalCause::Busy`) instead of queueing without bound.
- **Descriptors.** At build, net-io checks that `max_connections + 2 x workers + 32` descriptors fit under the process limit (`RLIMIT_NOFILE` on Unix) and refuses the configuration otherwise, naming what it has and needs.
- **The door.** `close_door` stops accepting but keeps the listening sockets open: new connections wait in the kernel's backlog for the next process (hand-off, 0.4) or until `shutdown` closes the listener, which resets them.
- **Closing.** A graceful close sends FIN and, if the peer may still have unread request bytes in flight, reads and discards up to 64 KiB for up to 2 s so the reply is not destroyed by a reset. An idle connection with nothing unread closes at once. Kills, timeouts in the middle of an exchange, and refusals close with RST (linger 0).

## Linux

- **Backlog.** The kernel silently caps `listen`'s backlog at `net.core.somaxconn` (4,096 since 5.4, 128 before). net-io reads `/proc/sys/net/core/somaxconn` and reports the effective value in `ListenerInfo::backlog`. Raise the sysctl for large accept bursts.
- **SYN floods** are the kernel's job (SYN cookies, `net.ipv4.tcp_syncookies`); net-io sees only completed handshakes.
- **No SIGPIPE.** Sends use `MSG_NOSIGNAL`, so a peer that disappears mid-write is `PeerReset`, never a signal.
- **Two system calls per exchange.** A keep-alive round trip is one blocking `recv` (its timeout set with `SO_RCVTIMEO` only when the deadline moves by more than one tick) and one `send` with `MSG_DONTWAIT`.
- **Kill and drain** shut the read side of the connection (`shutdown(SHUT_RD)`), which wakes a blocked `recv` at once; a reply already being written still goes out. net-io never calls `shutdown` on a listening socket: on Linux that disables the listener for good (decision D-057).
- **Port reuse.** `SO_REUSEADDR` is on by default for listeners (restart without waiting for `TIME_WAIT`); `SO_REUSEPORT` is opt-in.
- **Many short client connections** from one host can exhaust the ephemeral port range with `TIME_WAIT` entries on the side that closes first; this is the kernel's design, not a leak.

## macOS

- **No SIGPIPE.** Each socket gets `SO_NOSIGPIPE` at creation.
- **Accepted sockets** inherit the listener's non-blocking flag on macOS; net-io clears it so the blocking driver's reads block under their timeout.
- **Backlog.** Capped by `kern.ipc.somaxconn`; the effective value is not readable per listener, so `ListenerInfo::backlog` is `None`.
- **Linger** uses `SO_LINGER_SEC` (seconds), not `SO_LINGER`.
- **`TcpListener::from_std`** cannot ask macOS whether a socket listens (`SO_ACCEPTCONN` is not answered), so it accepts a stream socket that is bound and has no peer; a socket that was bound but never listened then fails at its first `accept`.
- **`shutdown(SHUT_RD)`** discards data already received and any that arrives later; a drain or kill therefore never delivers more input to the session (Linux delivers what was already queued).

## Windows

- **Waits.** Microsoft documents a socket whose blocking receive or send timed out as being in an indeterminate state, so net-io never relies on `SO_RCVTIMEO`: every socket in the blocking driver is non-blocking and every wait is `WSAPoll` on the socket and the worker's wake channel (decision D-052). A keep-alive round trip is therefore three system calls (`WSAPoll`, `recv`, `send`).
- **Wake channels.** Each worker's wake channel is a loopback UDP socket connected to itself, which holds one ephemeral port. With 128 workers that is 128 ports per server; many servers in one process (a test suite starting dozens of default servers at once) can run out of buffer space (`WSAENOBUFS`). Size `workers` to the load.
- **Exclusive binding.** Listeners use `SO_EXCLUSIVEADDRUSE` by default, so another process cannot bind the same port over net-io's listener. `SO_REUSEPORT` does not exist; asking for it is `Unsupported`.
- **Slow readers and send buffers.** Windows autotunes socket send buffers. On loopback a peer that never read absorbed 32 MiB before a send stalled, so the write timeout and the outbound rate check never fired. Internet-facing listeners on Windows should set `ListenOptions::send_buffer` (for example 256 KiB): then a peer that stops reading is detected within the write timeout, and the kernel memory one slow reader can pin is bounded.
- **Inheritance.** Listening and dialed sockets are created non-inheritable (`WSA_FLAG_NO_HANDLE_INHERIT`); accepted sockets are made non-inheritable after `accept` (decision D-078), so a child process the application starts does not keep client connections open.
- **Kill and drain** wake the owner through its wake channel (there is no safe equivalent of shutting only the read side under a blocked receive); the owner closes.
- **IOCP.** Listeners are never associated with a completion port (decision D-016), so a listener can be handed to another process; the 0.5 reactor uses IOCP for connections only.

## Targets

0.3 builds on Linux, macOS, and Windows for x86_64 and aarch64, with net-io's own declarations of the OS calls it needs (`dev/SYS-SURFACE.md` lists them). FreeBSD and a std-only fallback for other targets arrive in 0.5; until then other targets stop at a compile error that says so.
