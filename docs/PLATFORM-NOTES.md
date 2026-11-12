# net-io - Platform notes

What differs between operating systems, what net-io does about it, and what an operator should know. Covers 0.6.0.

## Every platform

- **Two drivers.** Sessions run on the reactor by default: one thread per CPU, each with its own epoll, kqueue, or completion port, and a default cap of 10,000 connections (or what the descriptor limit allows). A `BlockingHandler` always runs on the pool. Accepts stay on one thread per listener on both drivers, and a new connection goes to the least-loaded worker, or is refused as `Busy` when that worker's inbox of 4,096 is full.
- **One worker per open connection.** The blocking driver serves each connection on a pool thread (128 by default, 256 KiB stacks). An idle keep-alive connection holds its worker, which is why the default idle timeout is 5 s. `max_connections` defaults to the worker count; the reactor (0.5) lifts this.
- **Busy means busy.** When every worker has a connection or one waiting for it, a new connection is refused with RST (`RefusalCause::Busy`) instead of queueing without bound.
- **Descriptors.** At build, net-io checks that `max_connections + 2 x workers + 32` descriptors fit under the process limit (`RLIMIT_NOFILE` on Unix) and refuses the configuration otherwise, naming what it has and needs.
- **The door.** `close_door` stops accepting but keeps the listening sockets open: new connections wait in the kernel's backlog for the next process (hand-off, 0.4) or until `shutdown` closes the listener, which resets them.
- **PROXY behind a proxy.** A listener with `ProxyMode::Required` closes a peer outside its trusted proxies before reading a byte. On a Unix listener every peer that can open the socket file is trusted, so the file's mode is the boundary. HAProxy (v1 and v2) and nginx (v1) are tested in CI over TCP and Unix sockets; Apache's `mod_proxy` does not send the PROXY protocol (`mod_remoteip` only receives it).
- **UDP.** Every datagram is charged to its source address's budget before `recv_from` returns it, and replies to a source that has not been marked verified never exceed what it sent (factor 1 by default). Sources are keyed by IP address, not port. A full source table (65,536 by default, about 130 bytes each) evicts unverified entries; strangers that still find no room share one overflow budget and get no send allowance.
- **Files.** `send_file` and `push_file` use `sendfile` on Unix and `TransmitFile` on the Windows reactor. TLS, named pipes, and Unix sockets off Linux read a piece at a time on the worker, as does a held `TcpConnection` on Windows, so a slow disk holds that worker. A file must not shrink while in flight: the connection is reset with `Io(FileTruncated)`.
- **Closing.** A graceful close sends FIN and, if the peer may still have unread request bytes in flight, reads and discards up to 64 KiB for up to 2 s so the reply is not destroyed by a reset. An idle connection with nothing unread closes at once. Kills, timeouts in the middle of an exchange, and refusals close with RST (linger 0).

## Linux

- **Backlog.** The kernel silently caps `listen`'s backlog at `net.core.somaxconn` (4,096 since 5.4, 128 before). net-io reads `/proc/sys/net/core/somaxconn` and reports the effective value in `ListenerInfo::backlog`. Raise the sysctl for large accept bursts.
- **SYN floods** are the kernel's job (SYN cookies, `net.ipv4.tcp_syncookies`); net-io sees only completed handshakes.
- **No SIGPIPE.** Sends use `MSG_NOSIGNAL`, so a peer that disappears mid-write is `PeerReset`, never a signal.
- **Three system calls per exchange on the blocking pool.** A keep-alive round trip is one `poll` on the socket and the worker's wake channel before the exchange's first receive, one `recv`, and one `send` with `MSG_DONTWAIT`; receives inside an exchange block under `SO_RCVTIMEO` (set only when the deadline moves by more than one tick). Before 0.6.2 the first receive blocked too (two calls), and a drain had to shut the read side to reach it, which could cut short a request that arrived as the drain looked (D-178).
- **Kill** shuts the read side of the connection (`shutdown(SHUT_RD)`), which wakes a blocked `recv` at once; a reply already being written still goes out. A **drain** reaches the worker through its wake channel, and the worker closes the connection at its wait, or first answers a request that already arrived. net-io never calls `shutdown` on a listening socket: on Linux that disables the listener for good (decision D-057).
- **Port reuse.** `SO_REUSEADDR` is on by default for listeners (restart without waiting for `TIME_WAIT`); `SO_REUSEPORT` is opt-in.
- **Many short client connections** from one host can exhaust the ephemeral port range with `TIME_WAIT` entries on the side that closes first; this is the kernel's design, not a leak.

- **Unix sockets.** A listener's socket file gets its mode (0600 by default) and owner before the socket listens, so nothing connects under the umask's permissions, and never through a path another user can change: in a directory others can write to, the socket is made in a private directory and moved into place, and a directory writable by every user without the sticky bit is refused. Paths are limited to 107 bytes (in a directory others can write to, the directory's path plus 15). A stale socket file is removed only if nothing listens on it; anything else at the path (a live socket, a file, a directory, a symbolic link) is left alone and the bind fails. Peer credentials come from `SO_PEERCRED` (pid, uid, gid).
- **Inheritance.** systemd socket activation is tested with systemd's own `systemd-socket-activate`; `LISTEN_PIDFDID` (systemd 259 and Linux 6.9 or later) is checked against this process's pidfd.
- **Descriptor passing** receives with `MSG_CMSG_CLOEXEC`, so a passed descriptor is close-on-exec from the moment it arrives.

- **Fast open** needs `net.ipv4.tcp_fastopen` to include the server bit (2). A client's first data can be replayed by the network: turn it on only for requests that are safe to run twice.
- **`per_worker`** builds a `SO_REUSEPORT` group, so the kernel's hash decides the balance, and with `ServerBuilder::placement` each socket takes what its worker's CPU received. Closing one socket of a group resets the connections queued on it, so such a listener cannot be handed off.
- **Batches.** `recv_batch` and `send_batch` are `recvmmsg` and `sendmmsg`; elsewhere they are a loop that flips the socket non-blocking and back.

## macOS

- **No SIGPIPE.** Each socket gets `SO_NOSIGPIPE` at creation.
- **Waits.** Sockets stay non-blocking and every receive waits in `poll` first, as on Windows (decision D-083): a send with `MSG_DONTWAIT` on a blocking socket was seen to block on a full buffer, and `setsockopt` fails with `EINVAL` once a connection has ended, so the Linux model (blocking `recv` under `SO_RCVTIMEO`) does not hold. A keep-alive round trip is three system calls.
- **Backlog.** Capped by `kern.ipc.somaxconn`; the effective value is not readable per listener, so `ListenerInfo::backlog` is `None`.
- **Linger** uses `SO_LINGER_SEC` (seconds), not `SO_LINGER`.
- **Placement** does not exist: `ServerBuilder::placement` is `Unsupported`.
- **Write wake-ups.** kqueue's write filter fires now and then after an ACK, an empty wake about once in twenty exchanges.
- **`TcpListener::from_std`** cannot ask macOS whether a socket listens (`SO_ACCEPTCONN` is not answered), so it accepts a stream socket that is bound and has no peer; a socket that was bound but never listened then fails at its first `accept`.
- **`shutdown(SHUT_RD)`** discards data already received and any that arrives later; a drain or kill therefore never delivers more input to the session (Linux delivers what was already queued).

- **Unix sockets.** Paths are limited to 103 bytes. Peer credentials come from `getpeereid` (uid, gid) and `LOCAL_PEERPID` (pid).
- **Close-on-exec window.** macOS has no atomic close-on-exec for accepted, received (descriptor passing), or inherited descriptors: net-io sets `FD_CLOEXEC` right after the call, so a `fork` plus `exec` on another thread in between can inherit one.
- **UDP truncation.** A datagram larger than the buffer is reported `truncated` with the length that was copied; the real length is not available (Linux reports it).

## FreeBSD

- **Same model as macOS.** Sockets stay non-blocking, every receive on the blocking pool waits in `poll` first, and the reactor uses kqueue with `EV_CLEAR`. Each socket gets `SO_NOSIGPIPE`.
- **Peer credentials.** `getpeereid` gives the uid and gid, and `LOCAL_PEERCRED` the pid.
- **Fast open** needs `net.inet.tcp.fastopen.server_enable`.
- **Close-on-exec.** As on macOS, descriptors get `FD_CLOEXEC` right after the call.

## Windows

- **The reactor** runs on an I/O completion port per worker. A receive that finds no bytes pends, and an idle connection waits with a zero-byte receive, so it pins no memory. That adds one system call per exchange: wait, receive, send, zero-byte receive. A call that finishes at once completes without a trip through the port (`FILE_SKIP_COMPLETION_PORT_ON_SUCCESS`, unless a layered provider without real handles is installed).
- **Backlog.** A plain `listen` backlog is capped at 200 pending connections; net-io asks for one past 200 as `SOMAXCONN_HINT`, which Windows holds to 65,535, and reports that value in `ListenerInfo::backlog`. Before 0.6.2 a server whose accept thread fell behind on a loaded host dropped SYNs past the 200th, and those clients waited about 21 s for a timeout.
- **UDP packet info** is `Unsupported`; it needs `WSARecvMsg`, and no consumer has asked.
- **`user_timeout`** is `TCP_MAXRT`, in whole seconds.
- **Pending sends** pin the output's pages in the kernel until the peer takes them. The output budget bounds this per connection, and the write deadline cancels it.
- **Waits.** Microsoft documents a socket whose blocking receive or send timed out as being in an indeterminate state, so net-io never relies on `SO_RCVTIMEO`: every socket in the blocking driver is non-blocking and every wait is `WSAPoll` on the socket and the worker's wake channel (decision D-052). A keep-alive round trip is therefore three system calls (`WSAPoll`, `recv`, `send`).
- **Wake channels.** Each worker's wake channel is a loopback UDP socket connected to itself, which holds one ephemeral port. With 128 workers that is 128 ports per server; many servers in one process (a test suite starting dozens of default servers at once) can run out of buffer space (`WSAENOBUFS`). Size `workers` to the load.
- **Exclusive binding.** Listeners use `SO_EXCLUSIVEADDRUSE` by default, so another process cannot bind the same port over net-io's listener. `SO_REUSEPORT` does not exist; asking for it is `Unsupported`.
- **Slow readers and send buffers.** Windows autotunes socket send buffers. On loopback a peer that never read absorbed 32 MiB before a send stalled, so the write timeout and the outbound rate check never fired. Internet-facing listeners on Windows should set `ListenOptions::send_buffer` (for example 256 KiB): then a peer that stops reading is detected within the write timeout, and the kernel memory one slow reader can pin is bounded.
- **Inheritance.** Listening and dialed sockets are created non-inheritable (`WSA_FLAG_NO_HANDLE_INHERIT`); accepted sockets are made non-inheritable after `accept` (decision D-078), so a child process the application starts does not keep client connections open.
- **Refusal bytes.** A refusal that writes bytes (`Refusal::WithBytes`) sends them once and then resets the connection. Windows discards data its receiver has not read yet when the reset arrives, so a Windows peer may see only part of the refusal, or none of it. The connection is refused either way.
- **Kill and drain** wake the owner through its wake channel, and a kill cancels the connection's overlapped IO with `CancelIoEx`; the owner closes.
- **Named pipes** are what `listen_local` and `connect_local` use: `\\\\.\\pipe\\<name>`. Remote clients are always rejected, the default security descriptor lets in the current user alone, and the first instance claims the name, so `PipeNameInUse` can mean another process is squatting on it. A pipe has no half-close: `Shutdown::Write` does nothing the peer can see, and a graceful close skips the linger, since Windows keeps written bytes readable after a close. A client gets `client_pid`, and the server sees it in `ConnectionInfo`. The server can identify a client and cannot impersonate it (`SECURITY_IDENTIFICATION`).
- **AF_UNIX** (Windows 10 1803 and later) runs on both drivers. The directory's NTFS ACL decides who connects: mode, owner, group, and `require_uid` in `LocalOptions` are refused with `Unsupported`, not ignored. `bind_atomic` and descriptor passing do not exist here, and the peer's pid is the only credential.
- **UDP.** `SIO_UDP_CONNRESET` is switched off on every UDP socket, so an ICMP "port unreachable" for an earlier send never fails the next receive. UDP sockets are bound with `SO_EXCLUSIVEADDRUSE`. A truncated datagram (`WSAEMSGSIZE`) reports the length copied.
- **Hand-off and inheritance.** `share_listeners` describes TCP listeners for one target process, and `receive_shared` takes them over a pipe; each hand-off works once. Pipes and AF_UNIX listeners cannot be handed off. `systemd` returns an empty list, and FastCGI's descriptor 0 convention is Unix only (open decision OD-26).
- **IOCP.** Listeners are never associated with a completion port (decision D-016), so a listener can be handed to another process. `new_reactor_driver` refuses to register one, and `Operation::Accept` is refused: accept from a thread of your own.

## Targets

0.5 builds on Linux, macOS, FreeBSD, and Windows for x86_64 and aarch64, with net-io's own declarations of the OS calls it needs (`dev/SYS-SURFACE.md` lists them). Other targets stop at a compile error that says so.
