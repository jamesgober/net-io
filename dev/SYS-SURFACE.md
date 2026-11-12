# net-io - OS surface

> Every operating-system function, constant, and struct that `src/sys/` declares, per platform, with the documentation it relies on and the version that first needs it. Frozen at the `0.2.0` design lock (decision D-014 in [`PLAN.md`](./PLAN.md)); adding an item needs a decision-log entry. Values of constants and layouts of structs are not written here: they are declared per target in `src/sys/` and cross-checked against `libc` and `windows-sys` (dev-dependencies only) by the layout tests next to the declarations (`#[cfg(test)]` in each `src/sys/` file), which are the authority if this list and the code ever disagree. Those tests run on the targets CI runs tests on; a cross build checks only the `const` size and alignment assertions (rule 2).
>
> Targets with hand-written declarations: `x86_64` and `aarch64` on `unknown-linux-gnu`, `unknown-linux-musl`, `apple-darwin`, `unknown-freebsd`, `pc-windows-msvc`, `pc-windows-gnu`. Every other target builds the blocking driver over `std` alone and returns `Unsupported` for anything below.

Documentation references:

- **Linux:** the man-pages project, `https://man7.org/linux/man-pages/man2/<name>.2.html` (section 2) and `man7/<name>.7.html` (section 7).
- **FreeBSD:** `https://man.freebsd.org/cgi/man.cgi?query=<name>&sektion=<n>`.
- **macOS:** the system's own `man <n> <name>` pages (xnu, BSD-derived); where macOS differs from FreeBSD the row says so.
- **Windows:** Microsoft Learn, `https://learn.microsoft.com/en-us/windows/win32/api/<header>/nf-<header>-<name in lowercase>` for functions and `.../ns-<header>-<name>` for structs; socket options at `https://learn.microsoft.com/en-us/windows/win32/winsock/sol-socket-socket-options`, `.../ipproto-tcp-socket-options`, `.../ipproto-ip-socket-options`, `.../ipproto-ipv6-socket-options`.

## 0.3.0 as built

The 0.3 blocking driver declares less than the lists below allow: `std` already makes most socket calls safely, so net-io declares only what `std` cannot do. Everything else on the lists keeps its version and arrives when a feature needs it (rule 5).

| Platform | Declared in `src/sys/` (0.3) | Done through `std` instead |
|---|---|---|
| Linux, macOS | `socket`, `bind`, `listen`, `connect` (options before bind and a non-blocking connect), `setsockopt`, `getsockopt`, `send` (as `c_send`, for `MSG_DONTWAIT \| MSG_NOSIGNAL`), `sendmsg` (vectored sends with the same flags), `poll`, `shutdown` (the kill and drain wake, D-053, D-073), `getrlimit`, `fcntl` (every Unix: `F_GETFD` and `F_SETFD` for close-on-exec on inherited descriptors, and on macOS after `socket`) | `accept` (`accept4` with `SOCK_CLOEXEC` on Linux), `recv`, `getsockname`, `getpeername`, `close`, `SO_RCVTIMEO` (`set_read_timeout`); the wake channel is a `UnixDatagram` pair instead of `pipe`; the reserve descriptor is `File::open("/dev/null")` |
| Windows | `WSAStartup`, `WSASocketW` (overlapped, not inheritable), `bind`, `listen`, `connect`, `setsockopt`, `getsockopt`, `WSAPoll`, `WSAGetLastError`, `SetHandleInformation` (accepted sockets, D-078) | `accept`, `recv`, `send`, `WSASend` (`write_vectored`), `ioctlsocket` (`set_nonblocking`), `closesocket`; the wake channel is a loopback UDP socket connected to itself |

Not in 0.3: `getrandom`, `getentropy`, `BCryptGenRandom` (the per-source table keys std's `RandomState`, D-062), `pipe`/`pipe2`, `open`, `getpid`, `WSAIoctl`, `GetCurrentProcessId`. The layout checks of rule 2 to 4 live next to the declarations (`src/sys/unix.rs` and `src/sys/windows.rs`, `#[cfg(test)]`), not in `tests/layout.rs`, because the declarations are private to the crate.

---

## 1. Unix (Linux, macOS, FreeBSD)

Linked from the C library that `std` already links. All declared `extern "C"`.

| Function | Purpose | Reference | Version |
|---|---|---|---|
| `socket` | create sockets (Linux and FreeBSD with `SOCK_CLOEXEC`; macOS sets `FD_CLOEXEC` after; non-blocking mode is set afterwards where it is wanted) | `socket(2)` | 0.3 |
| `bind`, `listen`, `connect` | | `bind(2)`, `listen(2)`, `connect(2)` | 0.3 |
| `accept` | macOS accept (then `fcntl`) | `accept(2)` | 0.3 |
| `getsockname`, `getpeername` | endpoints | `getsockname(2)`, `getpeername(2)` | 0.3 |
| `setsockopt`, `getsockopt` | every option | `setsockopt(2)`, `getsockopt(2)` | 0.3 |
| `recv`, `send`, `recvfrom`, `sendto` | IO (`MSG_NOSIGNAL` on Linux; on macOS and FreeBSD every socket net-io creates or accepts has `SO_NOSIGPIPE`) | `recv(2)`, `send(2)` | 0.3 (`*from`/`*to` 0.4) |
| `readv`, `writev` | vectored IO (not declared: every Unix writes vectors with `sendmsg`, and reads go through `std`) | `readv(2)`, `writev(2)` | 0.3 |
| `sendmsg`, `recvmsg` | vectored writes with flags; `SCM_RIGHTS`; UDP truncation and packet info | `sendmsg(2)`, `recvmsg(2)`, `unix(7)`, `cmsg(3)` | 0.3 (ancillary data 0.4) |
| `shutdown`, `close` | | `shutdown(2)`, `close(2)` | 0.3 |
| `fcntl` | `F_GETFL`, `F_SETFL` (`O_NONBLOCK`), `F_GETFD`, `F_SETFD` (`FD_CLOEXEC`), `F_DUPFD_CLOEXEC` | `fcntl(2)` | 0.3 |
| `poll` | blocking driver: accept thread, connect completion, `accept_timeout` | `poll(2)` | 0.3 |
| `pipe` (macOS) / `pipe2` (Linux, FreeBSD) | blocking driver's wake channel | `pipe(2)` | 0.3 |
| `getrlimit` | `RLIMIT_NOFILE` (FR-61) | `getrlimit(2)` | 0.3 |
| `open` | the reserve descriptor (`/dev/null`, `O_RDONLY \| O_CLOEXEC`) | `open(2)` | 0.3 |
| `fstat`, `lstat` | inherited descriptors are sockets; stale socket paths (no symlink following) | `stat(2)` | 0.4 |
| `chmod`, `chown`, `unlink`, `rename` | Unix socket files (through `std`; from 0.7.2 only `unlink` is still used, the rest is done by the `*at` calls below) | `chmod(2)`, `chown(2)`, `unlink(2)`, `rename(2)` | 0.4 |
| `fchmodat`, `fchownat`, `renameat`, `linkat`, `unlinkat` | a Unix socket file's mode, owner, and final name, set by name relative to an open directory nobody else can change (the socket's own, or a private one made next to it), never through a path; the directories are opened with `std` (`O_DIRECTORY`, `O_NOFOLLOW` as custom flags) and checked with `std`'s metadata | `fchmodat(2)`, `fchownat(2)`, `renameat(2)`, `linkat(2)`, `unlinkat(2)` | 0.7.2 |
| `getpid` | `LISTEN_PID`, fork detection | `getpid(2)` | 0.3 |
| `sendfile` | file sends (Linux `sendfile(out, in, off, n)`; macOS and FreeBSD have different signatures, declared per OS). A count of 0 never reaches it: macOS and FreeBSD read 0 as "to the end of the file" | `sendfile(2)` | 0.6 |
| `geteuid` | the expected peer uid of a hand-off | `geteuid(2)` | 0.4 |
| `clock_gettime` | `CLOCK_MONOTONIC` for `monotonic_micros` | `clock_gettime(2)` | 0.4 |

### 1.1 Linux only

| Function | Purpose | Reference | Version |
|---|---|---|---|
| `accept4` | `SOCK_CLOEXEC \| SOCK_NONBLOCK` atomically | `accept4(2)` | 0.3 |
| `getrandom` | per-process hash key (D-046) | `getrandom(2)` | 0.3 |
| `epoll_create1`, `epoll_ctl`, `epoll_wait` | reactor (`EPOLL_CLOEXEC`, `EPOLLET`, `EPOLLEXCLUSIVE`) | `epoll_create(2)`, `epoll_ctl(2)`, `epoll_wait(2)` | 0.5 |
| `eventfd` | reactor waker (`EFD_CLOEXEC \| EFD_NONBLOCK`) | `eventfd(2)` | 0.5 |
| `recvmmsg`, `sendmmsg` | UDP batches | `recvmmsg(2)`, `sendmmsg(2)` | 0.6 |
| `sched_setaffinity` | placement (P2) | `sched_setaffinity(2)` | 0.6 |
| `pidfd_open` (through `syscall`) | `LISTEN_PIDFDID` check (systemd 259+) | `pidfd_open(2)` | 0.4 |
| `splice`, `pipe2` | `recv_file`: socket to pipe to file (`SPLICE_F_MOVE`; the pipe with `O_CLOEXEC`) | `splice(2)`, `pipe2(2)` | 0.7 |
| `pthread_sigmask`, `sigpending`, `sigtimedwait` | no SIGPIPE from `sendfile`, which takes no `MSG_NOSIGNAL`: SIGPIPE is blocked on the calling thread for the call, and one the call raised is taken (zero timeout) before it is unblocked | `pthread_sigmask(3)`, `sigpending(2)`, `sigtimedwait(2)` | 0.8 |
| `syscall` | `pidfd_open` and the io_uring calls, which have no C library wrappers in older glibc and musl | `syscall(2)` | 0.4 |
| `io_uring_setup`, `io_uring_enter`, `io_uring_register` (through `syscall`), `mmap`, `munmap` | io_uring driver (P3) | `io_uring_setup(2)`, `io_uring_enter(2)`, `io_uring_register(2)`, `mmap(2)` | after 1.0 |

`/proc/sys/net/core/somaxconn` is read with `std::fs`, not declared.

### 1.2 macOS and FreeBSD (BSD family)

| Function | Platforms | Purpose | Reference | Version |
|---|---|---|---|---|
| `kqueue`, `kevent` | both | reactor (`EVFILT_READ`, `EVFILT_WRITE`, `EVFILT_USER`, `EV_CLEAR`) | `kqueue(2)` | 0.5 |
| `getpeereid` | both | peer uid and gid | `getpeereid(3)` | 0.4 |
| `getentropy` | macOS | hash key | macOS `getentropy(2)` | 0.3 |
| `getrandom` | FreeBSD | hash key | `getrandom(2)` | 0.3 |
| `accept4` | FreeBSD | as Linux | `accept(2)` | 0.3 |
| `cpuset_setaffinity` | FreeBSD | placement (P2) | `cpuset_setaffinity(2)` | 0.6 |

---

## 2. Unix constants

Declared per target; values from the target's system headers, cross-checked in CI.

| Group | Constants | Platforms |
|---|---|---|
| families, types, protocols | `AF_INET`, `AF_INET6`, `AF_UNIX`, `SOCK_STREAM`, `SOCK_DGRAM`, `IPPROTO_TCP`, `IPPROTO_UDP`, `IPPROTO_IP`, `IPPROTO_IPV6` | all |
| creation flags | `SOCK_CLOEXEC` (`SOCK_NONBLOCK` is not used) | Linux, FreeBSD |
| socket level | `SOL_SOCKET`, `SO_REUSEADDR`, `SO_REUSEPORT`, `SO_KEEPALIVE`, `SO_LINGER`, `SO_SNDBUF`, `SO_RCVBUF`, `SO_RCVTIMEO`, `SO_SNDTIMEO`, `SO_ERROR`, `SO_TYPE`, `SO_ACCEPTCONN`, `SO_DOMAIN` | all (`SO_DOMAIN` Linux and FreeBSD; macOS reads the family from `getsockname`) |
| socket level, one OS | `SO_NOSIGPIPE`, `SO_LINGER_SEC` (macOS); `SO_INCOMING_CPU`, `SO_PEERCRED` (Linux); `SO_REUSEPORT_LB` (FreeBSD, P3) | as listed |
| TCP | `TCP_NODELAY`, `TCP_KEEPINTVL`, `TCP_KEEPCNT`, `TCP_FASTOPEN` | all |
| TCP keepalive idle | `TCP_KEEPIDLE` (Linux, FreeBSD), `TCP_KEEPALIVE` (macOS) | as listed |
| TCP, Linux | `TCP_DEFER_ACCEPT`, `TCP_USER_TIMEOUT`, `TCP_QUICKACK`, `TCP_NOTSENT_LOWAT`, `TCP_FASTOPEN_CONNECT` | Linux (`TCP_NOTSENT_LOWAT` also macOS) |
| IP | `IP_TTL`, `IP_TOS`, `IP_PKTINFO` (Linux) / `IP_RECVDSTADDR` (BSD), `IP_ADD_MEMBERSHIP`, `IPV6_V6ONLY`, `IPV6_UNICAST_HOPS`, `IPV6_TCLASS`, `IPV6_RECVPKTINFO`, `IPV6_PKTINFO`, `IPV6_JOIN_GROUP` / `IPV6_ADD_MEMBERSHIP` | all, names per OS |
| UDP, Linux | `UDP_SEGMENT`, `UDP_GRO` (P3) | Linux |
| local credentials | `SOL_LOCAL`, `LOCAL_PEERPID` (macOS); `LOCAL_PEERCRED` (FreeBSD) | as listed |
| message flags | `MSG_NOSIGNAL` (Linux; macOS and FreeBSD use `SO_NOSIGPIPE`), `MSG_PEEK`, `MSG_TRUNC`, `MSG_CTRUNC`, `MSG_CMSG_CLOEXEC` (Linux, FreeBSD), `MSG_DONTWAIT`, `MSG_WAITFORONE` (Linux) | as listed |
| ancillary data | `SCM_RIGHTS` | all |
| shutdown | `SHUT_RD`, `SHUT_WR`, `SHUT_RDWR` | all |
| fcntl | `F_GETFL`, `F_SETFL`, `F_GETFD`, `F_SETFD`, `F_DUPFD_CLOEXEC`, `FD_CLOEXEC`, `O_NONBLOCK`, `O_CLOEXEC`, `O_RDONLY` | all |
| splice | `SPLICE_F_MOVE` | Linux |
| signals | `SIGPIPE`, `SIG_BLOCK`, `SIG_UNBLOCK` | Linux |
| open flags | `O_DIRECTORY`, `O_NOFOLLOW` (0.7.2; values differ between Linux x86_64 and aarch64) | all |
| `*at` flags | `AT_SYMLINK_NOFOLLOW`, `AT_REMOVEDIR` (0.7.2) | all, values per OS |
| poll | `POLLIN`, `POLLOUT`, `POLLERR`, `POLLHUP`, `POLLNVAL` | all |
| limits | `RLIMIT_NOFILE`, `RLIM_INFINITY` | all |
| stat | `S_IFMT`, `S_IFSOCK` | all |
| epoll | `EPOLL_CLOEXEC`, `EPOLL_CTL_ADD`, `EPOLL_CTL_MOD`, `EPOLL_CTL_DEL`, `EPOLLIN`, `EPOLLOUT`, `EPOLLERR`, `EPOLLHUP`, `EPOLLRDHUP`, `EPOLLET`, `EPOLLEXCLUSIVE`; `EFD_CLOEXEC`, `EFD_NONBLOCK` | Linux |
| kqueue | `EVFILT_READ`, `EVFILT_WRITE`, `EVFILT_USER`, `EV_ADD`, `EV_DELETE`, `EV_ENABLE`, `EV_DISABLE`, `EV_DISPATCH`, `EV_CLEAR`, `EV_EOF`, `EV_ERROR`, `NOTE_TRIGGER` | macOS, FreeBSD |
| CPU sets | `CPU_LEVEL_WHICH`, `CPU_WHICH_TID` | FreeBSD |
| clocks | `CLOCK_MONOTONIC` | all, values per OS |
| error numbers | `EINTR`, `EAGAIN`, `EWOULDBLOCK`, `EINPROGRESS`, `EALREADY`, `EISCONN`, `EMFILE`, `ENFILE`, `ENOBUFS`, `ENOMEM`, `ECONNABORTED`, `EPROTO`, `EPERM`, `ENOPROTOOPT`, `EHOSTDOWN`, `ENONET` (Linux), `EHOSTUNREACH`, `ENETUNREACH`, `EOPNOTSUPP`, `EBADF`, `EINVAL`, `ENOTSOCK`, `ENOTCONN`, `ECONNRESET`, `ECONNREFUSED`, `EPIPE`, `ETIMEDOUT`, `EADDRINUSE`, `EADDRNOTAVAIL`, `EACCES`, `ENOENT`, `ENAMETOOLONG`, `ENOSYS` | all, values per OS (read back through `io::Error::raw_os_error`) |
| random | `GRND_NONBLOCK` is not used (blocking until seeded is correct at start-up) | |

## 3. Unix structs

| Struct | Used for | Platforms |
|---|---|---|
| `sockaddr`, `sockaddr_in`, `sockaddr_in6`, `sockaddr_un`, `sockaddr_storage`, `in_addr`, `in6_addr` | addresses (BSD layouts have `sin_len`) | all |
| `socklen_t`, `sa_family_t`, `mode_t` | type aliases (`mode_t` 32 bits on Linux, 16 on macOS and FreeBSD; 0.7.2) | all |
| `linger` | `SO_LINGER` | all |
| `timeval` | `SO_RCVTIMEO`, `SO_SNDTIMEO` | all |
| `iovec`, `msghdr`, `cmsghdr` (plus the `CMSG_*` arithmetic written as `const fn`s) | vectored IO, ancillary data | all |
| `pollfd` | `poll` | all |
| `rlimit` | `getrlimit` | all |
| `timespec` | `clock_gettime`, `kevent` timeouts | all |
| `stat` | `fstat`, `lstat` (only `st_mode`, `st_ino`, `st_dev` are read; the full layout is declared and checked) | all |
| `ucred` | `SO_PEERCRED` | Linux |
| `xucred` | `LOCAL_PEERCRED` | FreeBSD |
| `in_pktinfo`, `in6_pktinfo`, `ip_mreq`, `ipv6_mreq` | packet info, multicast | all (names per OS) |
| `epoll_event` (packed on x86_64) | epoll | Linux |
| `kevent` | kqueue | macOS, FreeBSD |
| `mmsghdr` | batches | Linux |
| `cpu_set_t`, `cpuset_t` | placement | Linux, FreeBSD |
| `sigset_t` (1,024 bits on glibc and musl) | `pthread_sigmask`, `sigpending`, `sigtimedwait` | Linux |
| `io_uring_params`, `io_uring_sqe`, `io_uring_cqe`, ring offsets | io_uring (P3) | Linux |

---

## 4. Windows

Declared `extern "system"`. `ws2_32` for Winsock, `kernel32` for handles and IOCP, `advapi32` for security descriptors, `bcrypt` for randomness. `ConnectEx` and `TransmitFile` are not linked: their pointers come from `WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER)` with the documented GUIDs `WSAID_CONNECTEX` and `WSAID_TRANSMITFILE`.

| Function | Library | Purpose | Reference (header) | Version |
|---|---|---|---|---|
| `WSAStartup`, `WSACleanup` | ws2_32 | once through `std::sync::Once` | winsock2 | 0.3 |
| `WSASocketW` | ws2_32 | create (`WSA_FLAG_OVERLAPPED \| WSA_FLAG_NO_HANDLE_INHERIT`; `FROM_PROTOCOL_INFO` for hand-off) | winsock2 | 0.3 |
| `bind`, `listen`, `connect`, `accept`, `getsockname`, `getpeername`, `shutdown`, `closesocket` | ws2_32 | | winsock2 | 0.3 |
| `setsockopt`, `getsockopt`, `ioctlsocket` (`FIONBIO`) | ws2_32 | options, non-blocking mode | winsock2 | 0.3 |
| `recv`, `send`, `recvfrom`, `sendto` | ws2_32 | blocking driver IO | winsock2 | 0.3 (`*from`/`*to` 0.4) |
| `WSARecv`, `WSASend`, `WSARecvFrom`, `WSASendTo` | ws2_32 | vectored and overlapped IO | winsock2 | 0.3 (overlapped 0.5) |
| `WSAPoll` | ws2_32 | every wait in the blocking driver, the accept threads, connect completion (D-052, D-056) | winsock2 | 0.3 |
| `WSAIoctl` | ws2_32 | extension pointers, `SIO_KEEPALIVE_VALS`, `SIO_AF_UNIX_GETPEERPID`, `SIO_UDP_CONNRESET`, `SIO_BASE_HANDLE` | winsock2 | 0.3 |
| `WSAGetLastError` | ws2_32 | error codes | winsock2 | 0.3 |
| `WSADuplicateSocketW` | ws2_32 | hand-off | winsock2 | 0.5 |
| `WSAEnumProtocolsW` | ws2_32 | detect providers without `XP1_IFS_HANDLES` before enabling skip-on-success | winsock2 | 0.5 |
| `WSAGetOverlappedResult` | ws2_32 | overlapped results | winsock2 | 0.5 |
| `ConnectEx`, `TransmitFile` | (pointer) | IOCP connect; file sends. `AcceptEx` and `GetAcceptExSockaddrs` are not used: listeners are never associated with a completion port (D-016) | mswsock | 0.5 (`TransmitFile` 0.6) |
| `CreateIoCompletionPort`, `GetQueuedCompletionStatusEx`, `PostQueuedCompletionStatus` | kernel32 | IOCP | ioapiset | 0.5 |
| `CancelIoEx` | kernel32 | kill and deadlines on IOCP | ioapiset | 0.5 |
| `SetFileCompletionNotificationModes` | kernel32 | `FILE_SKIP_COMPLETION_PORT_ON_SUCCESS`, `FILE_SKIP_SET_EVENT_ON_HANDLE` | winbase | 0.5 |
| `SetHandleInformation` | kernel32 | clear `HANDLE_FLAG_INHERIT` on handles not created non-inheritable | handleapi | 0.3 |
| `GetHandleInformation` | kernel32 | a socket made from a hand-off description must still be inheritable (the sender's fresh duplicate) before it is taken; tests: an accepted or received socket is not inheritable | handleapi | 0.7 (outside tests 0.7.2) |
| `CloseHandle` | kernel32 | | handleapi | 0.3 |
| `GetCurrentProcessId` | kernel32 | fork-equivalent checks, hand-off target | processthreadsapi | 0.3 |
| `CreateEventW`, `SetEvent`, `WaitForSingleObject` | kernel32 | overlapped pipe connect in the blocking driver | synchapi | 0.5 |
| `CreateNamedPipeW`, `ConnectNamedPipe`, `DisconnectNamedPipe`, `WaitNamedPipeW`, `GetNamedPipeClientProcessId`, `GetNamedPipeServerProcessId` | kernel32 | named pipes | namedpipeapi, winbase | 0.5 |
| `GetOverlappedResult`, `WaitForMultipleObjects`, `GetCurrentProcess` | kernel32 | overlapped pipe IO, waits, the token query | ioapiset, synchapi, processthreadsapi | 0.5 |
| `OpenProcessToken`, `GetTokenInformation`, `ConvertSidToStringSidW` | advapi32 | the current user's SID for an owner-only pipe (D-114) | processthreadsapi, securitybaseapi, sddl | 0.5 |
| `OpenProcess`, `GetProcessTimes` | kernel32 | a hand-off sender's user and start time, checked before anything is read | processthreadsapi | 0.7.2 |
| `GetSecurityInfo` | advapi32 | the owner of a connected pipe, for `PipeConnection::server_owner_sid` | aclapi | 0.7 |
| `CreateFileW`, `ReadFile`, `WriteFile`, `FlushFileBuffers` | kernel32 | pipe clients and IO | fileapi | 0.5 |
| `DeleteFileW`, `GetFileAttributesW` | kernel32 | AF_UNIX socket files | fileapi | 0.5 |
| `GetFileInformationByHandleEx` | kernel32 | the reparse tag of a stale socket path (`FileAttributeTagInfo`) | winbase | 0.7 |
| `LocalFree` | kernel32 | security descriptor from SDDL | winbase | 0.5 |
| `ConvertStringSecurityDescriptorToSecurityDescriptorW` | advapi32 | pipe security from SDDL | sddl | 0.5 |
| `BCryptGenRandom` | bcrypt | hash key (`BCRYPT_USE_SYSTEM_PREFERRED_RNG`, D-046) | bcrypt | 0.3 |
| `SetThreadGroupAffinity`, `GetActiveProcessorCount` | kernel32 | placement (P2) | processtopologyapi, winbase | 0.6 |

### 4.1 Windows constants

| Group | Constants |
|---|---|
| families, types, protocols | `AF_INET`, `AF_INET6`, `AF_UNIX`, `SOCK_STREAM`, `SOCK_DGRAM`, `IPPROTO_TCP`, `IPPROTO_UDP`, `IPPROTO_IP`, `IPPROTO_IPV6` |
| creation | `WSA_FLAG_OVERLAPPED`, `WSA_FLAG_NO_HANDLE_INHERIT`, `FROM_PROTOCOL_INFO`, `INVALID_SOCKET`, `SOCKET_ERROR` |
| socket level | `SOL_SOCKET`, `SO_REUSEADDR`, `SO_EXCLUSIVEADDRUSE`, `SO_KEEPALIVE`, `SO_LINGER`, `SO_SNDBUF`, `SO_RCVBUF`, `SO_RCVTIMEO`, `SO_SNDTIMEO`, `SO_ERROR`, `SO_TYPE`, `SO_ACCEPTCONN`, `SO_PROTOCOL_INFOW`, `SO_UPDATE_CONNECT_CONTEXT` |
| TCP | `TCP_NODELAY`, `TCP_KEEPIDLE`, `TCP_KEEPINTVL`, `TCP_KEEPCNT`, `TCP_FASTOPEN`, `TCP_MAXRT` |
| IP | `IP_TTL`, `IP_TOS`, `IP_PKTINFO`, `IP_ADD_MEMBERSHIP`, `IPV6_V6ONLY`, `IPV6_UNICAST_HOPS`, `IPV6_PKTINFO`, `IPV6_ADD_MEMBERSHIP` |
| ioctl codes | `FIONBIO`, `SIO_GET_EXTENSION_FUNCTION_POINTER`, `SIO_KEEPALIVE_VALS`, `SIO_AF_UNIX_GETPEERPID`, `SIO_UDP_CONNRESET`, `SIO_BASE_HANDLE` |
| extension GUIDs | `WSAID_CONNECTEX`, `WSAID_TRANSMITFILE` |
| shutdown | `SD_RECEIVE`, `SD_SEND`, `SD_BOTH` |
| poll | `POLLRDNORM`, `POLLWRNORM`, `POLLERR`, `POLLHUP`, `POLLNVAL` |
| messages | `MSG_PEEK`, `MSG_TRUNC`, `MSG_PARTIAL` |
| pipes | `PIPE_ACCESS_DUPLEX`, `FILE_FLAG_OVERLAPPED`, `FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_TYPE_BYTE`, `PIPE_READMODE_BYTE`, `PIPE_WAIT`, `PIPE_REJECT_REMOTE_CLIENTS`, `PIPE_UNLIMITED_INSTANCES`, `NMPWAIT_USE_DEFAULT_WAIT`, `SECURITY_SQOS_PRESENT`, `SECURITY_IDENTIFICATION`, `GENERIC_READ`, `GENERIC_WRITE`, `OPEN_EXISTING`, `SDDL_REVISION_1` |
| processes | `PROCESS_QUERY_LIMITED_INFORMATION` (0.7.2) |
| handles, IOCP | `INVALID_HANDLE_VALUE`, `HANDLE_FLAG_INHERIT`, `FILE_SKIP_COMPLETION_PORT_ON_SUCCESS`, `FILE_SKIP_SET_EVENT_ON_HANDLE`, `INFINITE`, `WAIT_OBJECT_0`, `WAIT_TIMEOUT`, `XP1_IFS_HANDLES` |
| random | `BCRYPT_USE_SYSTEM_PREFERRED_RNG` |
| errors | `WSAEINTR`, `WSAEWOULDBLOCK`, `WSAEINPROGRESS`, `WSAEALREADY`, `WSAEMFILE`, `WSAENOBUFS`, `WSAECONNABORTED`, `WSAECONNRESET`, `WSAECONNREFUSED`, `WSAETIMEDOUT`, `WSAEADDRINUSE`, `WSAEADDRNOTAVAIL`, `WSAEACCES`, `WSAENOTCONN`, `WSAENOTSOCK`, `WSAEINVAL`, `WSAEMSGSIZE`, `WSAESHUTDOWN`, `WSAENETUNREACH`, `WSAEHOSTUNREACH`, `WSAEAFNOSUPPORT`, `WSA_IO_PENDING`, `WSA_OPERATION_ABORTED`, `ERROR_PIPE_BUSY`, `ERROR_PIPE_CONNECTED`, `ERROR_NO_DATA`, `ERROR_ACCESS_DENIED`, `ERROR_FILE_NOT_FOUND`, `ERROR_NOT_FOUND`, `ERROR_NETNAME_DELETED`, `ERROR_OPERATION_ABORTED`, `ERROR_IO_PENDING`, `ERROR_SEM_TIMEOUT` |

### 4.2 Windows structs

| Struct | Used for |
|---|---|
| `WSADATA` | `WSAStartup` |
| `SOCKADDR`, `SOCKADDR_IN`, `SOCKADDR_IN6`, `SOCKADDR_UN` (`afunix.h`, path 108), `SOCKADDR_STORAGE`, `IN_ADDR`, `IN6_ADDR` | addresses |
| `LINGER` (`u16` fields) | `SO_LINGER` |
| `WSABUF`, `WSAMSG`, `WSACMSGHDR` | vectored and ancillary IO |
| `WSAPOLLFD` | `WSAPoll` |
| `WSAPROTOCOL_INFOW`, `WSAPROTOCOLCHAIN`, `GUID` | hand-off, provider enumeration, extension pointers |
| `tcp_keepalive` | `SIO_KEEPALIVE_VALS` |
| `OVERLAPPED`, `OVERLAPPED_ENTRY` | IOCP |
| `FILETIME` | `GetProcessTimes` (0.7.2) |
| `SECURITY_ATTRIBUTES` | pipes |
| `TRANSMIT_FILE_BUFFERS` | `TransmitFile` (not used: null) |
| `IN_PKTINFO`, `IN6_PKTINFO`, `IP_MREQ`, `IPV6_MREQ` | packet info, multicast |
| `GROUP_AFFINITY` | placement |
| `FILE_ATTRIBUTE_TAG_INFO` | the reparse tag of a socket path |

---

## 5. Rules for this surface

1. Every declaration has a `// SAFETY:`-commented safe wrapper in the same platform module; no raw pointer or raw descriptor crosses `src/sys/`.
2. Every struct has a `const` assertion of size and alignment for each declared target, and a layout test against `libc` / `windows-sys`: the size, and the offset of every field net-io reads or writes. The `const` assertions are checked on every build for the target, including a cross-compiled one; the layout tests run only where the tests run.
3. Every function signature is checked by a layout test next to its declaration: net-io's function and the dev-dependency's are each assigned to a function pointer type, so a different count, order, or type of an argument or the result fails to compile. Where net-io's declaration takes a pointer to its own struct (or an untyped address for a `sockaddr`), the dev-dependency's function is assigned to the same shape with its own struct in that place, and the pair of structs is compared under rule 2. Where the C libraries disagree on signedness of an argument of the same size (glibc's `getrlimit` resource, musl's `recvmmsg` and `sendmmsg` flags, macOS's `clockid_t`), the check uses the library's own type for that argument.
4. Every constant is compared with the dev-dependency's value. A value the dev-dependency does not export is compared with an equal one it does (macOS `IP_RECVPKTINFO` with `IP_PKTINFO`) or exercised by a test that uses it.
5. A function needed by a later version is declared in that version, not earlier (no unused unsafe surface), but it must already be on this list.

## 0.5.0 as built

Added: epoll (`epoll_create1`, `epoll_ctl`, `epoll_wait`, `eventfd`) on Linux; `kqueue`, `kevent` with `EVFILT_READ`, `EVFILT_WRITE`, `EVFILT_USER` on macOS and FreeBSD; on Windows every IOCP, pipe, AF_UNIX, and hand-off row above, except `FlushFileBuffers`, `DeleteFileW`, and `GetFileAttributesW`, which `std` covers. `SIO_AF_UNIX_GETPEERPID` is `0x58000100`. `FreeBSD` constants that differ from macOS: `AF_INET6` 28, `CLOCK_MONOTONIC` 4, `SO_NOSIGPIPE` 0x0800, linger through `SO_LINGER` in seconds, `TCP_KEEPIDLE` 256, `TCP_KEEPINTVL` 512, `TCP_KEEPCNT` 1024, `EPROTO` 92, `EOPNOTSUPP` 45, `EVFILT_USER` -11, `CMSG` alignment of `size_t`. `struct kevent` on FreeBSD has the four-word `ext` array. Each is checked against `libc` or `windows-sys` by a layout test.

## 0.6.0 as built

Added: `sendfile` (three signatures: Linux, macOS, FreeBSD), `recvmmsg`, `sendmmsg`, `sched_setaffinity`, `cpuset_setaffinity`; `TCP_DEFER_ACCEPT` 9, `TCP_USER_TIMEOUT` 18, `TCP_FASTOPEN` 23 (0x105 on macOS, 1025 on FreeBSD), `SO_INCOMING_CPU` 49, `MSG_WAITFORONE` 0x10000, `IP_PKTINFO` and `IPV6_RECVPKTINFO` with their per-OS values, FreeBSD `IP_RECVDSTADDR` 7; on Windows `TransmitFile` (pointer), `GetActiveProcessorGroupCount`, `GetActiveProcessorCount`, `GetCurrentThread`, `SetThreadGroupAffinity`, `TCP_MAXRT` 5, `TCP_FASTOPEN` 15. Each constant has a layout test against `libc` or `windows-sys`, except the per-OS packet-info values on macOS and FreeBSD, which `test_packet_info_reports_the_destination` exercises.

## 0.7.0 as built

Added on Windows: `GetSecurityInfo` with `SE_KERNEL_OBJECT` 6 and `OWNER_SECURITY_INFORMATION` 1 (it returns its error code rather than setting the thread's last error); `GetFileInformationByHandleEx` with `FileAttributeTagInfo` 9 and the struct `FILE_ATTRIBUTE_TAG_INFO`, on a file opened through `std`'s `OpenOptionsExt` with `FILE_READ_ATTRIBUTES` 0x80, `FILE_FLAG_OPEN_REPARSE_POINT` 0x00200000, and `FILE_FLAG_BACKUP_SEMANTICS` 0x02000000; `IO_REPARSE_TAG_AF_UNIX` 0x80000023; `TokenOwner` 4 (tests); `GetHandleInformation` (tests). `SetHandleInformation` now also clears `HANDLE_FLAG_INHERIT` on a socket made from a `WSAPROTOCOL_INFOW`: `WSA_FLAG_NO_HANDLE_INHERIT` does not reach such a socket. `FILE_FLAG_FIRST_PIPE_INSTANCE` is now passed whenever the listener holds no instance of its name, not only for the first. Each constant and the struct have a layout test against `windows-sys`, except `SE_KERNEL_OBJECT` and `IO_REPARSE_TAG_AF_UNIX`, whose windows-sys features are not enabled: `test_owner_sid_is_the_creators_default_owner` exercises the first, and `test_layout_socket_files_match_windows_sys` reads the second back from a socket file.

On Unix: the list above now names every item `src/sys/` declares: `geteuid`, `clock_gettime`, `timespec`, `EV_DISPATCH`, and FreeBSD's `CPU_LEVEL_WHICH` and `CPU_WHICH_TID` were declared before they were listed. FreeBSD now creates sockets with `SOCK_CLOEXEC` (`0x10000000`) and receives descriptors with `MSG_CMSG_CLOEXEC` (`0x00040000`), as Linux does; only macOS sets close-on-exec in a second step. Every struct has its `const` size and alignment assertion, including `cmsghdr`, `ucred`, `xucred`, `sockaddr_un`, `mmsghdr`, `timespec`, `epoll_event`, and `kevent`. The batch calls pass `IoSlice` and `IoSliceMut` as `struct iovec`, never a tuple.

## 0.7.2 as built

Added on Windows: `OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION` 0x1000, `GetProcessTimes` and the struct `FILETIME` (a hand-off sender's user SID, through the existing token calls, and its start time); `GetHandleInformation` outside tests (a socket made from a `WSAPROTOCOL_INFOW` is taken only while it is inheritable). Every overlapped call on a pipe sets the low bit of `OVERLAPPED.hEvent`, so it queues no completion packet. The constant and the struct have layout tests against `windows-sys`. The Unix additions are listed in sections 1 and 2.

## 0.8.0 review fixes

On Unix: `pthread_sigmask`, `sigpending`, and `sigtimedwait` with `sigset_t`, `SIGPIPE`, `SIG_BLOCK`, and `SIG_UNBLOCK` (Linux), so that `sendfile`, which takes no flags, raises no SIGPIPE; `EINTR`, `EPIPE`, `EALREADY`, and `EISCONN` are now classified (a blocking Unix connect that a signal interrupts goes on; a non-blocking connect that reports `EINTR` is in progress). `splice`, `pipe2`, and `SPLICE_F_MOVE` (0.7, `recv_file`) were declared before they were listed. FreeBSD's `CPU_LEVEL_WHICH` and `CPU_WHICH_TID` moved into the constants module so that the layout test can compare them. The layout tests now check every Unix function signature against `libc` (rule 3), the offsets of `msghdr`'s `msg_iov`, `msg_control`, and `msg_controllen`, `mmsghdr`'s `msg_len`, every field of `ucred`, `xucred`'s `cr_uid`, `cr_groups`, and `cr_pid`, and the constants `MSG_WAITFORONE`, `IP_PKTINFO` / `IP_RECVPKTINFO` / `IP_RECVDSTADDR` and `IPV6_RECVPKTINFO` / `IPV6_PKTINFO` with the packet-info address offset per OS, FreeBSD's `SOCK_CLOEXEC` and `MSG_CMSG_CLOEXEC`, and the bit `sigset_t` keeps each signal at. The earlier text of this file said `SOCK_NONBLOCK` was used at creation and that FreeBSD sends with `MSG_NOSIGNAL`; neither was true (FreeBSD sockets carry `SO_NOSIGPIPE`, as on macOS), and both rows are corrected above.
