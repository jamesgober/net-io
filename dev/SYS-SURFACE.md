# net-io - OS surface

> Every operating-system function, constant, and struct that `src/sys/` declares, per platform, with the documentation it relies on and the version that first needs it. Frozen at the `0.2.0` design lock (decision D-014 in [`PLAN.md`](./PLAN.md)); adding an item needs a decision-log entry. Values of constants and layouts of structs are not written here: they are declared per target in `src/sys/` and cross-checked against `libc` and `windows-sys` (dev-dependencies only) by `tests/layout.rs` in CI, which is the authority if this list and the code ever disagree.
>
> Targets with hand-written declarations: `x86_64` and `aarch64` on `unknown-linux-gnu`, `unknown-linux-musl`, `apple-darwin`, `unknown-freebsd`, `pc-windows-msvc`, `pc-windows-gnu`. Every other target builds the blocking driver over `std` alone and returns `Unsupported` for anything below.

Documentation references:

- **Linux:** the man-pages project, `https://man7.org/linux/man-pages/man2/<name>.2.html` (section 2) and `man7/<name>.7.html` (section 7).
- **FreeBSD:** `https://man.freebsd.org/cgi/man.cgi?query=<name>&sektion=<n>`.
- **macOS:** the system's own `man <n> <name>` pages (xnu, BSD-derived); where macOS differs from FreeBSD the row says so.
- **Windows:** Microsoft Learn, `https://learn.microsoft.com/en-us/windows/win32/api/<header>/nf-<header>-<name in lowercase>` for functions and `.../ns-<header>-<name>` for structs; socket options at `https://learn.microsoft.com/en-us/windows/win32/winsock/sol-socket-socket-options`, `.../ipproto-tcp-socket-options`, `.../ipproto-ip-socket-options`, `.../ipproto-ipv6-socket-options`.

---

## 1. Unix (Linux, macOS, FreeBSD)

Linked from the C library that `std` already links. All declared `extern "C"`.

| Function | Purpose | Reference | Version |
|---|---|---|---|
| `socket` | create sockets (Linux and FreeBSD with `SOCK_CLOEXEC \| SOCK_NONBLOCK`) | `socket(2)` | 0.3 |
| `bind`, `listen`, `connect` | | `bind(2)`, `listen(2)`, `connect(2)` | 0.3 |
| `accept` | macOS accept (then `fcntl`) | `accept(2)` | 0.3 |
| `getsockname`, `getpeername` | endpoints | `getsockname(2)`, `getpeername(2)` | 0.3 |
| `setsockopt`, `getsockopt` | every option | `setsockopt(2)`, `getsockopt(2)` | 0.3 |
| `recv`, `send`, `recvfrom`, `sendto` | IO (`MSG_NOSIGNAL` on Linux and FreeBSD) | `recv(2)`, `send(2)` | 0.3 (`*from`/`*to` 0.4) |
| `readv`, `writev` | vectored IO (macOS writes; Linux and FreeBSD use `sendmsg` for `MSG_NOSIGNAL`) | `readv(2)`, `writev(2)` | 0.3 |
| `sendmsg`, `recvmsg` | vectored writes with flags; `SCM_RIGHTS`; UDP truncation and packet info | `sendmsg(2)`, `recvmsg(2)`, `unix(7)`, `cmsg(3)` | 0.3 (ancillary data 0.4) |
| `shutdown`, `close` | | `shutdown(2)`, `close(2)` | 0.3 |
| `fcntl` | `F_GETFL`, `F_SETFL` (`O_NONBLOCK`), `F_GETFD`, `F_SETFD` (`FD_CLOEXEC`), `F_DUPFD_CLOEXEC` | `fcntl(2)` | 0.3 |
| `poll` | blocking driver: accept thread, connect completion, `accept_timeout` | `poll(2)` | 0.3 |
| `pipe` (macOS) / `pipe2` (Linux, FreeBSD) | blocking driver's wake channel | `pipe(2)` | 0.3 |
| `getrlimit` | `RLIMIT_NOFILE` (FR-61) | `getrlimit(2)` | 0.3 |
| `open` | the reserve descriptor (`/dev/null`, `O_RDONLY \| O_CLOEXEC`) | `open(2)` | 0.3 |
| `fstat`, `lstat` | inherited descriptors are sockets; stale socket paths (no symlink following) | `stat(2)` | 0.4 |
| `chmod`, `chown`, `unlink`, `rename` | Unix socket files | `chmod(2)`, `chown(2)`, `unlink(2)`, `rename(2)` | 0.4 |
| `getpid` | `LISTEN_PID`, fork detection | `getpid(2)` | 0.3 |
| `sendfile` | file sends (Linux `sendfile(out, in, off, n)`; macOS and FreeBSD have different signatures, declared per OS) | `sendfile(2)` | 0.6 |

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
| creation flags | `SOCK_CLOEXEC`, `SOCK_NONBLOCK` | Linux, FreeBSD |
| socket level | `SOL_SOCKET`, `SO_REUSEADDR`, `SO_REUSEPORT`, `SO_KEEPALIVE`, `SO_LINGER`, `SO_SNDBUF`, `SO_RCVBUF`, `SO_RCVTIMEO`, `SO_SNDTIMEO`, `SO_ERROR`, `SO_TYPE`, `SO_ACCEPTCONN`, `SO_DOMAIN` | all (`SO_DOMAIN` Linux and FreeBSD; macOS reads the family from `getsockname`) |
| socket level, one OS | `SO_NOSIGPIPE`, `SO_LINGER_SEC` (macOS); `SO_INCOMING_CPU`, `SO_PEERCRED` (Linux); `SO_REUSEPORT_LB` (FreeBSD, P3) | as listed |
| TCP | `TCP_NODELAY`, `TCP_KEEPINTVL`, `TCP_KEEPCNT`, `TCP_FASTOPEN` | all |
| TCP keepalive idle | `TCP_KEEPIDLE` (Linux, FreeBSD), `TCP_KEEPALIVE` (macOS) | as listed |
| TCP, Linux | `TCP_DEFER_ACCEPT`, `TCP_USER_TIMEOUT`, `TCP_QUICKACK`, `TCP_NOTSENT_LOWAT`, `TCP_FASTOPEN_CONNECT` | Linux (`TCP_NOTSENT_LOWAT` also macOS) |
| IP | `IP_TTL`, `IP_TOS`, `IP_PKTINFO` (Linux) / `IP_RECVDSTADDR` (BSD), `IP_ADD_MEMBERSHIP`, `IPV6_V6ONLY`, `IPV6_UNICAST_HOPS`, `IPV6_TCLASS`, `IPV6_RECVPKTINFO`, `IPV6_PKTINFO`, `IPV6_JOIN_GROUP` / `IPV6_ADD_MEMBERSHIP` | all, names per OS |
| UDP, Linux | `UDP_SEGMENT`, `UDP_GRO` (P3) | Linux |
| local credentials | `SOL_LOCAL`, `LOCAL_PEERPID` (macOS); `LOCAL_PEERCRED` (FreeBSD) | as listed |
| message flags | `MSG_NOSIGNAL` (Linux, FreeBSD), `MSG_PEEK`, `MSG_TRUNC`, `MSG_CTRUNC`, `MSG_CMSG_CLOEXEC` (Linux, FreeBSD), `MSG_DONTWAIT` | as listed |
| ancillary data | `SCM_RIGHTS` | all |
| shutdown | `SHUT_RD`, `SHUT_WR`, `SHUT_RDWR` | all |
| fcntl | `F_GETFL`, `F_SETFL`, `F_GETFD`, `F_SETFD`, `F_DUPFD_CLOEXEC`, `FD_CLOEXEC`, `O_NONBLOCK`, `O_CLOEXEC`, `O_RDONLY` | all |
| poll | `POLLIN`, `POLLOUT`, `POLLERR`, `POLLHUP`, `POLLNVAL` | all |
| limits | `RLIMIT_NOFILE`, `RLIM_INFINITY` | all |
| stat | `S_IFMT`, `S_IFSOCK` | all |
| epoll | `EPOLL_CLOEXEC`, `EPOLL_CTL_ADD`, `EPOLL_CTL_MOD`, `EPOLL_CTL_DEL`, `EPOLLIN`, `EPOLLOUT`, `EPOLLERR`, `EPOLLHUP`, `EPOLLRDHUP`, `EPOLLET`, `EPOLLEXCLUSIVE`; `EFD_CLOEXEC`, `EFD_NONBLOCK` | Linux |
| kqueue | `EVFILT_READ`, `EVFILT_WRITE`, `EVFILT_USER`, `EV_ADD`, `EV_DELETE`, `EV_ENABLE`, `EV_DISABLE`, `EV_CLEAR`, `EV_EOF`, `EV_ERROR`, `NOTE_TRIGGER` | macOS, FreeBSD |
| error numbers | `EINTR`, `EAGAIN`, `EWOULDBLOCK`, `EINPROGRESS`, `EALREADY`, `EMFILE`, `ENFILE`, `ENOBUFS`, `ENOMEM`, `ECONNABORTED`, `EPROTO`, `EPERM`, `ENOPROTOOPT`, `EHOSTDOWN`, `ENONET` (Linux), `EHOSTUNREACH`, `ENETUNREACH`, `EOPNOTSUPP`, `EBADF`, `EINVAL`, `ENOTSOCK`, `ENOTCONN`, `ECONNRESET`, `ECONNREFUSED`, `EPIPE`, `ETIMEDOUT`, `EADDRINUSE`, `EADDRNOTAVAIL`, `EACCES`, `ENOENT`, `ENAMETOOLONG`, `ENOSYS` | all, values per OS (read back through `io::Error::raw_os_error`) |
| random | `GRND_NONBLOCK` is not used (blocking until seeded is correct at start-up) | |

## 3. Unix structs

| Struct | Used for | Platforms |
|---|---|---|
| `sockaddr`, `sockaddr_in`, `sockaddr_in6`, `sockaddr_un`, `sockaddr_storage`, `in_addr`, `in6_addr` | addresses (BSD layouts have `sin_len`) | all |
| `socklen_t`, `sa_family_t` | type aliases | all |
| `linger` | `SO_LINGER` | all |
| `timeval` | `SO_RCVTIMEO`, `SO_SNDTIMEO` | all |
| `iovec`, `msghdr`, `cmsghdr` (plus the `CMSG_*` arithmetic written as `const fn`s) | vectored IO, ancillary data | all |
| `pollfd` | `poll` | all |
| `rlimit` | `getrlimit` | all |
| `stat` | `fstat`, `lstat` (only `st_mode`, `st_ino`, `st_dev` are read; the full layout is declared and checked) | all |
| `ucred` | `SO_PEERCRED` | Linux |
| `xucred` | `LOCAL_PEERCRED` | FreeBSD |
| `in_pktinfo`, `in6_pktinfo`, `ip_mreq`, `ipv6_mreq` | packet info, multicast | all (names per OS) |
| `epoll_event` (packed on x86_64) | epoll | Linux |
| `kevent` | kqueue | macOS, FreeBSD |
| `mmsghdr` | batches | Linux |
| `cpu_set_t`, `cpuset_t` | placement | Linux, FreeBSD |
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
| `CloseHandle` | kernel32 | | handleapi | 0.3 |
| `GetCurrentProcessId` | kernel32 | fork-equivalent checks, hand-off target | processthreadsapi | 0.3 |
| `CreateEventW`, `SetEvent`, `WaitForSingleObject` | kernel32 | overlapped pipe connect in the blocking driver | synchapi | 0.5 |
| `CreateNamedPipeW`, `ConnectNamedPipe`, `DisconnectNamedPipe`, `WaitNamedPipeW`, `GetNamedPipeClientProcessId` | kernel32 | named pipes | namedpipeapi, winbase | 0.5 |
| `CreateFileW`, `ReadFile`, `WriteFile`, `FlushFileBuffers` | kernel32 | pipe clients and IO | fileapi | 0.5 |
| `DeleteFileW`, `GetFileAttributesW` | kernel32 | AF_UNIX socket files | fileapi | 0.5 |
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
| `SECURITY_ATTRIBUTES` | pipes |
| `TRANSMIT_FILE_BUFFERS` | `TransmitFile` (not used: null) |
| `IN_PKTINFO`, `IN6_PKTINFO`, `IP_MREQ`, `IPV6_MREQ` | packet info, multicast |
| `GROUP_AFFINITY` | placement |

---

## 5. Rules for this surface

1. Every declaration has a `// SAFETY:`-commented safe wrapper in the same platform module; no raw pointer or raw descriptor crosses `src/sys/`.
2. Every struct has a `const` assertion of size and alignment for each declared target, and a layout test (field offsets) against `libc` / `windows-sys`.
3. Every function signature is checked in `tests/layout.rs` by assigning the dev-dependency's function to a pointer of net-io's declared type (a mismatch fails to compile).
4. Every constant is compared with the dev-dependency's value.
5. A function needed by a later version is declared in that version, not earlier (no unused unsafe surface), but it must already be on this list.
