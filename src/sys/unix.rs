//! Linux and macOS (x86_64, aarch64).
//!
//! Declarations come from the platforms' system headers; every constant,
//! struct layout, and function signature is checked against `libc` by the
//! `layout` tests at the bottom of this file. References: the Linux
//! man-pages project (`socket(7)`, `tcp(7)`, `ipv6(7)`, `poll(2)`, `send(2)`,
//! `getrlimit(2)`, `fcntl(2)`) and the macOS man pages of the same names.

use std::ffi::{c_int, c_short, c_void};
use std::io::{self, IoSlice};
use std::mem::size_of;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::time::Duration;

use super::{Interest, Ready, poll_millis, retry_interrupted};

type SockLen = u32;

#[cfg(target_os = "linux")]
type Nfds = std::ffi::c_ulong;
#[cfg(not(target_os = "linux"))]
type Nfds = std::ffi::c_uint;

// ---- constants -------------------------------------------------------------

/// Error numbers net-io classifies (`errno(3)`).
#[cfg(target_os = "linux")]
pub(crate) mod errno {
    pub const EPERM: i32 = 1;
    pub const EBADF: i32 = 9;
    pub const ENOMEM: i32 = 12;
    pub const EACCES: i32 = 13;
    pub const EINVAL: i32 = 22;
    pub const ENFILE: i32 = 23;
    pub const EMFILE: i32 = 24;
    pub const ENONET: i32 = 64;
    pub const EPROTO: i32 = 71;
    pub const ENOTSOCK: i32 = 88;
    pub const ENOPROTOOPT: i32 = 92;
    pub const EOPNOTSUPP: i32 = 95;
    pub const EADDRINUSE: i32 = 98;
    pub const EADDRNOTAVAIL: i32 = 99;
    pub const ENETUNREACH: i32 = 101;
    pub const ECONNABORTED: i32 = 103;
    pub const ENOBUFS: i32 = 105;
    pub const ETIMEDOUT: i32 = 110;
    pub const ECONNREFUSED: i32 = 111;
    pub const EHOSTDOWN: i32 = 112;
    pub const EHOSTUNREACH: i32 = 113;
}

/// Error numbers net-io classifies (`intro(2)` on macOS, `errno(2)` on FreeBSD).
#[cfg(not(target_os = "linux"))]
pub(crate) mod errno {
    pub const EPERM: i32 = 1;
    pub const EBADF: i32 = 9;
    pub const ENOMEM: i32 = 12;
    pub const EACCES: i32 = 13;
    pub const EINVAL: i32 = 22;
    pub const ENFILE: i32 = 23;
    pub const EMFILE: i32 = 24;
    pub const ENOTSOCK: i32 = 38;
    pub const ENOPROTOOPT: i32 = 42;
    pub const ENOTCONN: i32 = 57;
    pub const EADDRINUSE: i32 = 48;
    pub const EADDRNOTAVAIL: i32 = 49;
    pub const ENETUNREACH: i32 = 51;
    pub const ECONNABORTED: i32 = 53;
    pub const ENOBUFS: i32 = 55;
    pub const ETIMEDOUT: i32 = 60;
    pub const ECONNREFUSED: i32 = 61;
    pub const EHOSTDOWN: i32 = 64;
    pub const EHOSTUNREACH: i32 = 65;
    #[cfg(target_os = "macos")]
    pub const EPROTO: i32 = 100;
    #[cfg(target_os = "freebsd")]
    pub const EPROTO: i32 = 92;
    #[cfg(target_os = "macos")]
    pub const EOPNOTSUPP: i32 = 102;
    #[cfg(target_os = "freebsd")]
    pub const EOPNOTSUPP: i32 = 45;
    /// No ENONET on these systems; a value no error carries.
    pub const ENONET: i32 = -1;
}

/// How an `accept` failure is handled (FR-9, FR-10).
pub(crate) fn classify_accept(e: &io::Error) -> super::AcceptFailure {
    use super::AcceptFailure as F;
    use errno::*;
    match e.raw_os_error() {
        Some(EMFILE | ENFILE) => F::Descriptors,
        Some(ENOBUFS | ENOMEM) => F::Pressure,
        Some(EBADF | EINVAL | ENOTSOCK) => F::ListenerFailed,
        // The pending-network errors `accept(2)` says to treat as a retry, and an
        // aborted handshake: the one connection failed, the listener is fine.
        Some(
            ECONNABORTED | EPROTO | ENOPROTOOPT | ENONET | EOPNOTSUPP | EHOSTDOWN | EHOSTUNREACH
            | ENETUNREACH,
        ) => F::PerConnection,
        _ => F::PerConnection,
    }
}

/// Maps a bind or connect error to its own variant.
pub(crate) fn classify_addr_error(e: &io::Error) -> super::AddrFailure {
    use super::AddrFailure as F;
    use errno::*;
    match e.raw_os_error() {
        Some(EADDRINUSE) => F::InUse,
        Some(EADDRNOTAVAIL) => F::NotAvailable,
        Some(EACCES | EPERM) => F::Permission,
        Some(ECONNREFUSED) => F::Refused,
        Some(EHOSTUNREACH | EHOSTDOWN) => F::HostUnreachable,
        Some(ENETUNREACH) => F::NetworkUnreachable,
        Some(ETIMEDOUT) => F::TimedOut,
        _ => F::Other,
    }
}

#[cfg(target_os = "linux")]
mod c {
    use std::ffi::{c_int, c_short};
    #[cfg(feature = "local")]
    pub const AF_UNIX: c_int = 1;
    pub const AF_INET: c_int = 2;
    pub const AF_INET6: c_int = 10;
    pub const AF_UNIX_FAMILY: c_int = 1;
    pub const F_GETFD: c_int = 1;
    pub const F_SETFD: c_int = 2;
    pub const FD_CLOEXEC: c_int = 1;
    pub const CLOCK_MONOTONIC: c_int = 1;
    pub const SYS_PIDFD_OPEN: std::ffi::c_long = 434;
    pub const SOCK_STREAM: c_int = 1;
    #[cfg(feature = "udp")]
    pub const SOCK_DGRAM: c_int = 2;
    #[cfg(feature = "udp")]
    pub const MSG_TRUNC: c_int = 0x20;
    #[cfg(feature = "udp")]
    pub const MSG_WAITFORONE: c_int = 0x10000;
    #[cfg(feature = "udp")]
    pub const IP_RECVPKTINFO: c_int = 8;
    #[cfg(feature = "udp")]
    pub const IP_PKTINFO_TYPE: c_int = 8;
    #[cfg(feature = "udp")]
    pub const PKTINFO_ADDR_AT: usize = 8;
    #[cfg(feature = "udp")]
    pub const IPV6_RECVPKTINFO: c_int = 49;
    #[cfg(feature = "udp")]
    pub const IPV6_PKTINFO_TYPE: c_int = 50;
    pub const SOCK_CLOEXEC: c_int = 0o2_000_000;
    pub const SOL_SOCKET: c_int = 1;
    pub const SO_REUSEADDR: c_int = 2;
    pub const SO_TYPE: c_int = 3;
    pub const SO_ERROR: c_int = 4;
    pub const SO_SNDBUF: c_int = 7;
    pub const SO_RCVBUF: c_int = 8;
    pub const SO_KEEPALIVE: c_int = 9;
    pub const SO_LINGER: c_int = 13;
    pub const SO_REUSEPORT: c_int = 15;
    pub const SO_ACCEPTCONN: c_int = 30;
    pub const IPPROTO_IP: c_int = 0;
    pub const IPPROTO_TCP: c_int = 6;
    pub const IPPROTO_IPV6: c_int = 41;
    pub const IP_TTL: c_int = 2;
    pub const IPV6_UNICAST_HOPS: c_int = 16;
    pub const IPV6_V6ONLY: c_int = 26;
    pub const TCP_NODELAY: c_int = 1;
    pub const SO_INCOMING_CPU: c_int = 49;
    pub const TCP_DEFER_ACCEPT: c_int = 9;
    pub const TCP_USER_TIMEOUT: c_int = 18;
    pub const TCP_FASTOPEN: c_int = 23;
    pub const TCP_KEEPIDLE: c_int = 4;
    pub const TCP_KEEPINTVL: c_int = 5;
    pub const TCP_KEEPCNT: c_int = 6;
    pub const MSG_DONTWAIT: c_int = 0x40;
    pub const MSG_NOSIGNAL: c_int = 0x4000;
    pub const POLLIN: c_short = 0x1;
    pub const POLLOUT: c_short = 0x4;
    pub const POLLERR: c_short = 0x8;
    pub const POLLHUP: c_short = 0x10;
    pub const POLLNVAL: c_short = 0x20;
    pub const SHUT_RD: c_int = 0;
    pub const RLIMIT_NOFILE: c_int = 7;
    pub const EINPROGRESS: c_int = 115;
    #[cfg(feature = "local")]
    pub const SO_PEERCRED: c_int = 17;
    #[cfg(feature = "local")]
    pub const SCM_RIGHTS: c_int = 1;
    #[cfg(feature = "local")]
    pub const MSG_CTRUNC: c_int = 0x8;
    #[cfg(feature = "local")]
    pub const MSG_CMSG_CLOEXEC: c_int = 0x4000_0000;
}

#[cfg(not(target_os = "linux"))]
mod c {
    use std::ffi::{c_int, c_short};
    #[cfg(feature = "local")]
    pub const AF_UNIX: c_int = 1;
    pub const AF_INET: c_int = 2;
    #[cfg(target_os = "macos")]
    pub const AF_INET6: c_int = 30;
    #[cfg(target_os = "freebsd")]
    pub const AF_INET6: c_int = 28;
    pub const AF_UNIX_FAMILY: c_int = 1;
    pub const F_GETFD: c_int = 1;
    #[cfg(target_os = "macos")]
    pub const CLOCK_MONOTONIC: c_int = 6;
    #[cfg(target_os = "freebsd")]
    pub const CLOCK_MONOTONIC: c_int = 4;
    pub const SOCK_STREAM: c_int = 1;
    /// FreeBSD 10 and later; macOS has no atomic flag.
    #[cfg(target_os = "freebsd")]
    pub const SOCK_CLOEXEC: c_int = 0x1000_0000;
    #[cfg(feature = "udp")]
    pub const SOCK_DGRAM: c_int = 2;
    #[cfg(feature = "udp")]
    pub const MSG_TRUNC: c_int = 0x10;
    #[cfg(all(feature = "udp", target_os = "macos"))]
    pub const IP_RECVPKTINFO: c_int = 26;
    #[cfg(all(feature = "udp", target_os = "macos"))]
    pub const IP_PKTINFO_TYPE: c_int = 26;
    #[cfg(all(feature = "udp", target_os = "macos"))]
    pub const PKTINFO_ADDR_AT: usize = 8;
    /// `IP_RECVDSTADDR`: FreeBSD's record is the address alone.
    #[cfg(all(feature = "udp", target_os = "freebsd"))]
    pub const IP_RECVPKTINFO: c_int = 7;
    #[cfg(all(feature = "udp", target_os = "freebsd"))]
    pub const IP_PKTINFO_TYPE: c_int = 7;
    #[cfg(all(feature = "udp", target_os = "freebsd"))]
    pub const PKTINFO_ADDR_AT: usize = 0;
    #[cfg(all(feature = "udp", target_os = "macos"))]
    pub const IPV6_RECVPKTINFO: c_int = 61;
    #[cfg(all(feature = "udp", target_os = "freebsd"))]
    pub const IPV6_RECVPKTINFO: c_int = 36;
    #[cfg(feature = "udp")]
    pub const IPV6_PKTINFO_TYPE: c_int = 46;
    pub const SOL_SOCKET: c_int = 0xffff;
    pub const SO_ACCEPTCONN: c_int = 0x2;
    pub const SO_REUSEADDR: c_int = 0x4;
    pub const SO_KEEPALIVE: c_int = 0x8;
    pub const SO_REUSEPORT: c_int = 0x200;
    pub const SO_SNDBUF: c_int = 0x1001;
    pub const SO_RCVBUF: c_int = 0x1002;
    pub const SO_ERROR: c_int = 0x1007;
    pub const SO_TYPE: c_int = 0x1008;
    #[cfg(target_os = "macos")]
    pub const SO_NOSIGPIPE: c_int = 0x1022;
    #[cfg(target_os = "freebsd")]
    pub const SO_NOSIGPIPE: c_int = 0x0800;
    #[cfg(target_os = "macos")]
    pub const SO_LINGER_SEC: c_int = 0x1080;
    /// FreeBSD's `SO_LINGER` is in seconds already.
    #[cfg(target_os = "freebsd")]
    pub const SO_LINGER_SEC: c_int = 0x80;
    pub const IPPROTO_IP: c_int = 0;
    pub const IPPROTO_TCP: c_int = 6;
    pub const IPPROTO_IPV6: c_int = 41;
    pub const IP_TTL: c_int = 4;
    pub const IPV6_UNICAST_HOPS: c_int = 4;
    pub const IPV6_V6ONLY: c_int = 27;
    pub const TCP_NODELAY: c_int = 0x1;
    #[cfg(target_os = "macos")]
    pub const TCP_FASTOPEN: c_int = 0x105;
    #[cfg(target_os = "freebsd")]
    pub const TCP_FASTOPEN: c_int = 1025;
    #[cfg(target_os = "macos")]
    pub const TCP_KEEPALIVE: c_int = 0x10;
    #[cfg(target_os = "macos")]
    pub const TCP_KEEPINTVL: c_int = 0x101;
    #[cfg(target_os = "macos")]
    pub const TCP_KEEPCNT: c_int = 0x102;
    /// `TCP_KEEPIDLE`.
    #[cfg(target_os = "freebsd")]
    pub const TCP_KEEPALIVE: c_int = 256;
    #[cfg(target_os = "freebsd")]
    pub const TCP_KEEPINTVL: c_int = 512;
    #[cfg(target_os = "freebsd")]
    pub const TCP_KEEPCNT: c_int = 1024;
    pub const MSG_DONTWAIT: c_int = 0x80;
    pub const POLLIN: c_short = 0x1;
    pub const POLLOUT: c_short = 0x4;
    pub const POLLERR: c_short = 0x8;
    pub const POLLHUP: c_short = 0x10;
    pub const POLLNVAL: c_short = 0x20;
    pub const SHUT_RD: c_int = 0;
    pub const RLIMIT_NOFILE: c_int = 8;
    pub const F_SETFD: c_int = 2;
    pub const FD_CLOEXEC: c_int = 1;
    pub const EINPROGRESS: c_int = 36;
    #[cfg(feature = "local")]
    pub const SCM_RIGHTS: c_int = 1;
    #[cfg(feature = "local")]
    pub const MSG_CTRUNC: c_int = 0x20;
    /// FreeBSD 10 and later; macOS has no atomic flag.
    #[cfg(all(feature = "local", target_os = "freebsd"))]
    pub const MSG_CMSG_CLOEXEC: c_int = 0x0004_0000;
    #[cfg(all(feature = "local", not(target_os = "linux")))]
    pub const SOL_LOCAL: c_int = 0;
    #[cfg(all(feature = "local", target_os = "macos"))]
    pub const LOCAL_PEERPID: c_int = 0x002;
    #[cfg(all(feature = "local", target_os = "freebsd"))]
    pub const LOCAL_PEERCRED: c_int = 1;
}

// ---- structs ---------------------------------------------------------------

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrIn6 {
    sin6_family: u16,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    sin6_scope_id: u32,
}

#[cfg(not(target_os = "linux"))]
#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrIn {
    sin_len: u8,
    sin_family: u8,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

#[cfg(not(target_os = "linux"))]
#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrIn6 {
    sin6_len: u8,
    sin6_family: u8,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    sin6_scope_id: u32,
}

/// `struct msghdr` (only `msg_iov` and `msg_iovlen` are used; no name, no control data).
#[cfg(target_os = "linux")]
#[repr(C)]
struct MsgHdr {
    msg_name: *mut c_void,
    msg_namelen: u32,
    msg_iov: *const IoSlice<'static>,
    msg_iovlen: usize,
    msg_control: *mut c_void,
    msg_controllen: usize,
    msg_flags: c_int,
}

#[cfg(not(target_os = "linux"))]
#[repr(C)]
struct MsgHdr {
    msg_name: *mut c_void,
    msg_namelen: u32,
    msg_iov: *const IoSlice<'static>,
    msg_iovlen: c_int,
    msg_control: *mut c_void,
    msg_controllen: u32,
    msg_flags: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Linger {
    l_onoff: c_int,
    l_linger: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PollFd {
    fd: c_int,
    events: c_short,
    revents: c_short,
}

/// `struct timespec` (64-bit targets: both fields 64 bits).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Rlimit {
    rlim_cur: u64,
    rlim_max: u64,
}

const _: () = assert!(size_of::<SockaddrIn>() == 16);
const _: () = assert!(size_of::<SockaddrIn6>() == 28);
const _: () = assert!(size_of::<Linger>() == 8);
const _: () = assert!(size_of::<PollFd>() == 8);
const _: () = assert!(size_of::<Rlimit>() == 16);
const _: () = assert!(size_of::<Timespec>() == 16 && align_of::<Timespec>() == 8);
#[cfg(target_os = "linux")]
const _: () = assert!(size_of::<MsgHdr>() == 56);
#[cfg(not(target_os = "linux"))]
const _: () = assert!(size_of::<MsgHdr>() == 48);
#[cfg(all(feature = "udp", target_os = "linux"))]
const _: () = assert!(size_of::<MmsgHdr>() == 64 && align_of::<MmsgHdr>() == 8);
#[cfg(all(any(feature = "local", feature = "udp"), target_os = "linux"))]
const _: () = assert!(size_of::<CmsgHdr>() == 16 && align_of::<CmsgHdr>() == 8);
#[cfg(all(any(feature = "local", feature = "udp"), not(target_os = "linux")))]
const _: () = assert!(size_of::<CmsgHdr>() == 12 && align_of::<CmsgHdr>() == 4);
#[cfg(all(feature = "local", target_os = "linux"))]
const _: () = assert!(size_of::<Ucred>() == 12 && align_of::<Ucred>() == 4);
#[cfg(all(feature = "local", target_os = "freebsd"))]
const _: () = assert!(size_of::<Xucred>() == 88 && align_of::<Xucred>() == 8);
#[cfg(all(feature = "local", target_os = "linux"))]
const _: () = assert!(size_of::<SockaddrUn>() == 110 && align_of::<SockaddrUn>() == 2);
#[cfg(all(feature = "local", not(target_os = "linux")))]
const _: () = assert!(size_of::<SockaddrUn>() == 106 && align_of::<SockaddrUn>() == 1);

unsafe extern "C" {
    fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
    fn bind(fd: c_int, addr: *const c_void, len: SockLen) -> c_int;
    fn listen(fd: c_int, backlog: c_int) -> c_int;
    fn connect(fd: c_int, addr: *const c_void, len: SockLen) -> c_int;
    fn setsockopt(
        fd: c_int,
        level: c_int,
        name: c_int,
        value: *const c_void,
        len: SockLen,
    ) -> c_int;
    fn getsockopt(
        fd: c_int,
        level: c_int,
        name: c_int,
        value: *mut c_void,
        len: *mut SockLen,
    ) -> c_int;
    #[link_name = "send"]
    fn c_send(fd: c_int, buf: *const c_void, len: usize, flags: c_int) -> isize;
    fn sendmsg(fd: c_int, msg: *const MsgHdr, flags: c_int) -> isize;
    fn poll(fds: *mut PollFd, nfds: Nfds, timeout: c_int) -> c_int;
    fn shutdown(fd: c_int, how: c_int) -> c_int;
    fn getrlimit(resource: c_int, rlim: *mut Rlimit) -> c_int;
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    fn getsockname(fd: c_int, addr: *mut c_void, len: *mut SockLen) -> c_int;
    fn getpeername(fd: c_int, addr: *mut c_void, len: *mut SockLen) -> c_int;
    #[cfg(target_os = "linux")]
    fn sched_setaffinity(pid: c_int, size: usize, mask: *const u64) -> c_int;
    #[cfg(target_os = "freebsd")]
    fn cpuset_setaffinity(
        level: c_int,
        which: c_int,
        id: i64,
        size: usize,
        mask: *const u64,
    ) -> c_int;
    #[cfg(target_os = "linux")]
    fn sendfile(out: c_int, file: c_int, offset: *mut i64, count: usize) -> isize;
    #[cfg(target_os = "macos")]
    fn sendfile(
        file: c_int,
        sock: c_int,
        offset: i64,
        len: *mut i64,
        headers: *mut c_void,
        flags: c_int,
    ) -> c_int;
    #[cfg(target_os = "freebsd")]
    fn sendfile(
        file: c_int,
        sock: c_int,
        offset: i64,
        count: usize,
        headers: *mut c_void,
        sent: *mut i64,
        flags: c_int,
    ) -> c_int;
    #[cfg(feature = "local")]
    fn geteuid() -> u32;
    fn clock_gettime(clock: c_int, ts: *mut Timespec) -> c_int;
    #[cfg(target_os = "linux")]
    fn syscall(num: std::ffi::c_long, ...) -> std::ffi::c_long;
    #[cfg(any(feature = "local", feature = "udp"))]
    fn recvmsg(fd: c_int, msg: *mut MsgHdr, flags: c_int) -> isize;
    #[cfg(all(feature = "udp", target_os = "linux"))]
    fn recvmmsg(
        fd: c_int,
        msgs: *mut MmsgHdr,
        count: std::ffi::c_uint,
        flags: c_int,
        timeout: *mut c_void,
    ) -> c_int;
    #[cfg(all(feature = "udp", target_os = "linux"))]
    fn sendmmsg(fd: c_int, msgs: *mut MmsgHdr, count: std::ffi::c_uint, flags: c_int) -> c_int;
    #[cfg(all(feature = "udp", target_os = "linux"))]
    fn recvfrom(
        fd: c_int,
        buf: *mut c_void,
        len: usize,
        flags: c_int,
        addr: *mut c_void,
        addr_len: *mut SockLen,
    ) -> isize;
    #[cfg(all(feature = "local", not(target_os = "linux")))]
    fn getpeereid(fd: c_int, euid: *mut u32, egid: *mut u32) -> c_int;
}

/// A borrowed socket handle.
pub(crate) type Sock<'a> = BorrowedFd<'a>;
/// A raw socket handle (used only inside the kill guard).
pub(crate) type RawSock = RawFd;
/// An owned socket handle.
pub(crate) type OwnedSock = OwnedFd;

/// Types whose socket handle this layer can borrow.
pub(crate) trait AsSock {
    fn sock(&self) -> Sock<'_>;
}

impl<T: AsFd> AsSock for T {
    fn sock(&self) -> Sock<'_> {
        self.as_fd()
    }
}

pub(crate) fn raw_of(sock: Sock<'_>) -> RawSock {
    sock.as_raw_fd()
}

fn cvt(ret: c_int) -> io::Result<c_int> {
    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

fn set_int(sock: Sock<'_>, level: c_int, name: c_int, value: c_int) -> io::Result<()> {
    // SAFETY: `sock` is a borrowed, open descriptor for the duration of the call
    // (the borrow keeps its owner alive); `value` is a live c_int and the length
    // passed is its size, as setsockopt(2) requires for integer options.
    let ret = unsafe {
        setsockopt(
            sock.as_raw_fd(),
            level,
            name,
            (&raw const value).cast::<c_void>(),
            size_of::<c_int>() as SockLen,
        )
    };
    cvt(ret).map(drop)
}

fn get_int(sock: Sock<'_>, level: c_int, name: c_int) -> io::Result<c_int> {
    let mut value: c_int = 0;
    let mut len = size_of::<c_int>() as SockLen;
    // SAFETY: `sock` is open for the call; `value` and `len` are live locals and
    // `len` holds the size of `value`, as getsockopt(2) requires.
    let ret = unsafe {
        getsockopt(
            sock.as_raw_fd(),
            level,
            name,
            (&raw mut value).cast::<c_void>(),
            &raw mut len,
        )
    };
    cvt(ret).map(|_| value)
}

/// Encodes a socket address into a buffer large enough for either family.
fn encode_addr(addr: SocketAddr, out: &mut [u8; 28]) -> SockLen {
    match addr {
        SocketAddr::V4(a) => {
            let sa = SockaddrIn {
                #[cfg(not(target_os = "linux"))]
                sin_len: size_of::<SockaddrIn>() as u8,
                #[cfg(not(target_os = "linux"))]
                sin_family: c::AF_INET as u8,
                #[cfg(target_os = "linux")]
                sin_family: c::AF_INET as u16,
                sin_port: a.port().to_be(),
                sin_addr: u32::from_ne_bytes(a.ip().octets()),
                sin_zero: [0; 8],
            };
            // SAFETY: `SockaddrIn` is `repr(C)`, `Copy`, has no padding (16 bytes of
            // fields), and `out` has room for it; reading its bytes is defined.
            let bytes: [u8; 16] = unsafe { std::mem::transmute(sa) };
            out[..16].copy_from_slice(&bytes);
            16
        }
        SocketAddr::V6(a) => {
            let sa = SockaddrIn6 {
                #[cfg(not(target_os = "linux"))]
                sin6_len: size_of::<SockaddrIn6>() as u8,
                #[cfg(not(target_os = "linux"))]
                sin6_family: c::AF_INET6 as u8,
                #[cfg(target_os = "linux")]
                sin6_family: c::AF_INET6 as u16,
                sin6_port: a.port().to_be(),
                sin6_flowinfo: a.flowinfo().to_be(),
                sin6_addr: a.ip().octets(),
                sin6_scope_id: a.scope_id(),
            };
            // SAFETY: `SockaddrIn6` is `repr(C)`, `Copy`, 28 bytes with no padding.
            let bytes: [u8; 28] = unsafe { std::mem::transmute(sa) };
            out.copy_from_slice(&bytes);
            28
        }
    }
}

/// Room for any socket address the kernel returns (`sockaddr_storage`).
#[repr(C, align(8))]
struct AddrBuf([u8; 128]);

/// Decodes an IPv4 or IPv6 socket address written by the kernel.
fn decode_addr(b: &[u8; 128], len: SockLen) -> Option<SocketAddr> {
    #[cfg(target_os = "linux")]
    let family = c_int::from(u16::from_ne_bytes([b[0], b[1]]));
    #[cfg(not(target_os = "linux"))]
    let family = c_int::from(b[1]);
    let port = u16::from_be_bytes([b[2], b[3]]);
    if family == c::AF_INET && len as usize >= 16 {
        let ip = std::net::Ipv4Addr::new(b[4], b[5], b[6], b[7]);
        Some(SocketAddr::from((ip, port)))
    } else if family == c::AF_INET6 && len as usize >= 28 {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&b[8..24]);
        let flow = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
        let scope = u32::from_ne_bytes([b[24], b[25], b[26], b[27]]);
        Some(SocketAddr::V6(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::from(octets),
            port,
            flow,
            scope,
        )))
    } else {
        None
    }
}

/// A new UDP socket: close-on-exec.
#[cfg(feature = "udp")]
fn udp_socket(v6: bool) -> io::Result<OwnedFd> {
    #[cfg(any(test, net_io_shim))]
    super::shim::check(super::shim::Op::Socket)?;
    let domain = if v6 { c::AF_INET6 } else { c::AF_INET };
    #[cfg(not(target_os = "macos"))]
    let ty = c::SOCK_DGRAM | c::SOCK_CLOEXEC;
    #[cfg(target_os = "macos")]
    let ty = c::SOCK_DGRAM;
    // SAFETY: socket(2) takes plain integers and returns a new descriptor or -1.
    let fd = cvt(unsafe { socket(domain, ty, 0) })?;
    // SAFETY: `fd` was just returned by socket(2), is open, and is owned by no one else.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    #[cfg(target_os = "macos")]
    {
        // SAFETY: as in `tcp_socket`.
        cvt(unsafe { fcntl(owned.as_raw_fd(), c::F_SETFD, c::FD_CLOEXEC) })?;
    }
    Ok(owned)
}

/// `struct mmsghdr`: one message of a batch.
#[cfg(all(feature = "udp", target_os = "linux"))]
#[repr(C)]
struct MmsgHdr {
    hdr: MsgHdr,
    len: std::ffi::c_uint,
}

/// The most messages one batch system call carries.
#[cfg(all(feature = "udp", target_os = "linux"))]
pub(crate) const BATCH_MAX: usize = 64;

/// One datagram of a received batch.
#[cfg(all(feature = "udp", target_os = "linux"))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct Incoming {
    pub len: usize,
    pub from: SocketAddr,
    pub truncated: bool,
}

/// Fills `bufs` from one `recvmmsg`: it waits for the first datagram, then takes what
/// is ready. Returns how many arrived; `out` holds them in order. A datagram the
/// kernel gave no address for is skipped by the caller through `None`.
#[cfg(all(feature = "udp", target_os = "linux"))]
pub(crate) fn udp_recv_many(
    sock: Sock<'_>,
    bufs: &mut [&mut [u8]],
    out: &mut [Option<Incoming>],
) -> io::Result<usize> {
    #[repr(C, align(8))]
    struct Addrs([[u8; 128]; BATCH_MAX]);
    let count = bufs.len().min(out.len()).min(BATCH_MAX);
    let mut addrs = Addrs([[0; 128]; BATCH_MAX]);
    let mut iovs: [io::IoSliceMut<'_>; BATCH_MAX] =
        std::array::from_fn(|_| io::IoSliceMut::new(&mut []));
    for (iov, buf) in iovs.iter_mut().zip(bufs.iter_mut()).take(count) {
        *iov = io::IoSliceMut::new(buf);
    }
    // SAFETY: an all-zero `mmsghdr` is valid: null pointers and zero lengths.
    let mut msgs: [MmsgHdr; BATCH_MAX] = unsafe { std::mem::zeroed() };
    for i in 0..count {
        msgs[i].hdr.msg_name = addrs.0[i].as_mut_ptr().cast();
        msgs[i].hdr.msg_namelen = 128;
        msgs[i].hdr.msg_iov = (&raw const iovs[i]).cast();
        msgs[i].hdr.msg_iovlen = 1;
    }
    // SAFETY: the first `count` messages point at live `iovs`, `addrs`, and at buffers
    // writable for their lengths; `IoSliceMut` is ABI-compatible with `struct iovec`.
    let n = cvt(unsafe {
        recvmmsg(
            sock.as_raw_fd(),
            msgs.as_mut_ptr(),
            count as std::ffi::c_uint,
            c::MSG_WAITFORONE | c::MSG_TRUNC,
            std::ptr::null_mut(),
        )
    })?;
    let n = n.unsigned_abs() as usize;
    for i in 0..n {
        let len = msgs[i].len as usize;
        out[i] = decode_addr(&addrs.0[i], msgs[i].hdr.msg_namelen).map(|from| Incoming {
            len,
            from,
            truncated: msgs[i].hdr.msg_flags & c::MSG_TRUNC != 0,
        });
    }
    Ok(n)
}

/// Sends the first of `datagrams` (at most [`BATCH_MAX`]) in one `sendmmsg`; returns how
/// many went.
#[cfg(all(feature = "udp", target_os = "linux"))]
pub(crate) fn udp_send_many(
    sock: Sock<'_>,
    datagrams: &[(&[u8], SocketAddr)],
) -> io::Result<usize> {
    let count = datagrams.len().min(BATCH_MAX);
    let mut addrs = [[0u8; 28]; BATCH_MAX];
    let mut iovs = [IoSlice::new(&[]); BATCH_MAX];
    // SAFETY: an all-zero `mmsghdr` is valid: null pointers and zero lengths.
    let mut msgs: [MmsgHdr; BATCH_MAX] = unsafe { std::mem::zeroed() };
    for i in 0..count {
        let (bytes, to) = datagrams[i];
        let len = encode_addr(to, &mut addrs[i]);
        iovs[i] = IoSlice::new(bytes);
        msgs[i].hdr.msg_name = addrs[i].as_mut_ptr().cast();
        msgs[i].hdr.msg_namelen = len;
        msgs[i].hdr.msg_iov = (&raw const iovs[i]).cast();
        msgs[i].hdr.msg_iovlen = 1;
    }
    // SAFETY: as in `udp_recv_many`; the kernel only reads what these messages point at.
    let n = cvt(unsafe {
        sendmmsg(
            sock.as_raw_fd(),
            msgs.as_mut_ptr(),
            count as std::ffi::c_uint,
            c::MSG_NOSIGNAL,
        )
    })?;
    Ok(n.unsigned_abs() as usize)
}

/// Asks for each datagram's destination address.
#[cfg(feature = "udp")]
pub(crate) fn udp_packet_info(sock: Sock<'_>, v6: bool) -> io::Result<()> {
    if v6 {
        set_int(sock, c::IPPROTO_IPV6, c::IPV6_RECVPKTINFO, 1)
    } else {
        set_int(sock, c::IPPROTO_IP, c::IP_RECVPKTINFO, 1)
    }
}

/// One datagram with the address it was sent to: as [`udp_recv_from`], through
/// `recvmsg` and its ancillary data.
#[cfg(feature = "udp")]
pub(crate) fn udp_recv_with_destination(
    sock: Sock<'_>,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, bool, Option<std::net::IpAddr>)> {
    #[repr(C, align(8))]
    struct Control([u8; 128]);
    let mut addr = AddrBuf([0; 128]);
    let mut control = Control([0; 128]);
    let mut iov = [io::IoSliceMut::new(buf)];
    let mut msg = MsgHdr {
        msg_name: addr.0.as_mut_ptr().cast::<c_void>(),
        msg_namelen: 128,
        msg_iov: iov.as_mut_ptr().cast::<IoSlice<'static>>(),
        msg_iovlen: 1,
        msg_control: control.0.as_mut_ptr().cast::<c_void>(),
        msg_controllen: 128,
        msg_flags: 0,
    };
    #[cfg(target_os = "linux")]
    let flags = c::MSG_TRUNC;
    #[cfg(not(target_os = "linux"))]
    let flags = 0;
    // SAFETY: `msg` points at `addr`, `control`, and one iovec over `buf`; all live for
    // the call; `sock` is open.
    let n = unsafe { recvmsg(sock.as_raw_fd(), &raw mut msg, flags) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let from = decode_addr(&addr.0, msg.msg_namelen)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    #[allow(clippy::unnecessary_cast)] // u32 off Linux
    let used = (msg.msg_controllen as usize).min(control.0.len());
    let destination = destination_in(&control.0[..used]);
    Ok((
        n.unsigned_abs(),
        from,
        msg.msg_flags & c::MSG_TRUNC != 0,
        destination,
    ))
}

/// Walks the control messages for a packet-info record. Lengths are the kernel's, and
/// checked against the bytes it reported.
#[cfg(feature = "udp")]
fn destination_in(control: &[u8]) -> Option<std::net::IpAddr> {
    let mut at = 0;
    while at + size_of::<CmsgHdr>() <= control.len() {
        let word =
            |o: usize| -> Option<[u8; 4]> { control.get(at + o..at + o + 4)?.try_into().ok() };
        // On Linux `cmsg_len` is a `size_t`, whose low half comes first on these targets.
        let len = u32::from_ne_bytes(word(0)?) as usize;
        let level = i32::from_ne_bytes(word(CMSG_LEVEL_AT)?);
        let ty = i32::from_ne_bytes(word(CMSG_LEVEL_AT + 4)?);
        if len < size_of::<CmsgHdr>() {
            return None;
        }
        let data = control.get(at + cmsg_align_any(size_of::<CmsgHdr>())..at + len)?;
        if level == c::IPPROTO_IP && ty == c::IP_PKTINFO_TYPE {
            let octets: [u8; 4] = data
                .get(c::PKTINFO_ADDR_AT..c::PKTINFO_ADDR_AT + 4)?
                .try_into()
                .ok()?;
            return Some(std::net::IpAddr::from(octets));
        }
        if level == c::IPPROTO_IPV6 && ty == c::IPV6_PKTINFO_TYPE {
            let octets: [u8; 16] = data.get(..16)?.try_into().ok()?;
            return Some(std::net::IpAddr::from(octets));
        }
        at += cmsg_align_any(len);
    }
    None
}

#[cfg(feature = "udp")]
const CMSG_LEVEL_AT: usize = size_of::<CmsgHdr>() - 8;

#[cfg(feature = "udp")]
const fn cmsg_align_any(n: usize) -> usize {
    let to = if cfg!(target_os = "macos") {
        4
    } else {
        size_of::<usize>()
    };
    (n + to - 1) & !(to - 1)
}

/// Creates and binds a UDP socket; `IPV6_V6ONLY` as asked for IPv6 addresses.
/// No `SO_REUSEADDR`: another socket must not share the port.
#[cfg(feature = "udp")]
pub(crate) fn udp_bind(addr: SocketAddr, ipv6_only: bool) -> io::Result<std::net::UdpSocket> {
    let fd = udp_socket(addr.is_ipv6())?;
    if addr.is_ipv6() {
        set_int(
            fd.as_fd(),
            c::IPPROTO_IPV6,
            c::IPV6_V6ONLY,
            c_int::from(ipv6_only),
        )?;
    }
    bind_to(fd.as_fd(), addr)?;
    Ok(std::net::UdpSocket::from(fd))
}

/// One datagram: its length, its source, and whether it was cut to fit `buf`.
/// On Linux a truncated datagram reports its real length (`MSG_TRUNC`); on macOS
/// the length copied.
#[cfg(feature = "udp")]
pub(crate) fn udp_recv_from(
    sock: Sock<'_>,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, bool)> {
    #[cfg(any(test, net_io_shim))]
    let buf = match super::shim::io(super::shim::Op::Recv, buf.len())? {
        Some(n) => &mut buf[..n],
        None => buf,
    };
    let mut addr = AddrBuf([0; 128]);
    let mut addr_len = 128 as SockLen;
    #[cfg(target_os = "linux")]
    let (n, truncated) = {
        // SAFETY: `buf` is writable for `buf.len()` bytes and `addr` for
        // `addr_len`; both live for the call; `sock` is open.
        let n = unsafe {
            recvfrom(
                sock.as_raw_fd(),
                buf.as_mut_ptr().cast::<c_void>(),
                buf.len(),
                c::MSG_TRUNC,
                addr.0.as_mut_ptr().cast::<c_void>(),
                &raw mut addr_len,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n.unsigned_abs();
        (n, n > buf.len())
    };
    #[cfg(not(target_os = "linux"))]
    let (n, truncated) = {
        let mut iov = [io::IoSliceMut::new(buf)];
        let mut msg = MsgHdr {
            msg_name: addr.0.as_mut_ptr().cast::<c_void>(),
            msg_namelen: addr_len,
            msg_iov: iov.as_mut_ptr().cast::<IoSlice<'static>>(),
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        // SAFETY: `msg` points at `addr` (128 bytes) and one iovec over `buf`;
        // all live for the call; `sock` is open.
        let n = unsafe { recvmsg(sock.as_raw_fd(), &raw mut msg, 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        addr_len = msg.msg_namelen;
        (n.unsigned_abs(), msg.msg_flags & c::MSG_TRUNC != 0)
    };
    match decode_addr(&addr.0, addr_len) {
        Some(from) => Ok((n, from, truncated)),
        None => Err(io::Error::from(io::ErrorKind::InvalidData)),
    }
}

/// A new TCP socket for `addr`'s family: close-on-exec (atomically with
/// `SOCK_CLOEXEC` on Linux and FreeBSD), and on macOS and FreeBSD with
/// `SO_NOSIGPIPE` so a write to a closed peer never raises `SIGPIPE`.
pub(crate) fn tcp_socket(v6: bool) -> io::Result<OwnedFd> {
    #[cfg(any(test, net_io_shim))]
    super::shim::check(super::shim::Op::Socket)?;
    let domain = if v6 { c::AF_INET6 } else { c::AF_INET };
    #[cfg(not(target_os = "macos"))]
    let ty = c::SOCK_STREAM | c::SOCK_CLOEXEC;
    #[cfg(target_os = "macos")]
    let ty = c::SOCK_STREAM;
    // SAFETY: socket(2) takes plain integers and returns a new descriptor or -1.
    let fd = cvt(unsafe { socket(domain, ty, 0) })?;
    // SAFETY: `fd` was just returned by socket(2), is open, and is owned by no one else.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    #[cfg(target_os = "macos")]
    {
        // SAFETY: `owned` is an open descriptor; F_SETFD with FD_CLOEXEC is fcntl(2)'s
        // documented way to set close-on-exec. macOS has no atomic flag, so a fork plus
        // exec on another thread between socket(2) and here could inherit it (documented).
        cvt(unsafe { fcntl(owned.as_raw_fd(), c::F_SETFD, c::FD_CLOEXEC) })?;
    }
    #[cfg(not(target_os = "linux"))]
    set_int(owned.as_fd(), c::SOL_SOCKET, c::SO_NOSIGPIPE, 1)?;
    Ok(owned)
}

/// Options set on a listening socket before `bind` and `listen`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ListenParams {
    pub reuse_address: bool,
    pub reuse_port: bool,
    pub ipv6_only: bool,
    pub send_buffer: Option<u32>,
    pub receive_buffer: Option<u32>,
    pub backlog: u32,
    pub defer_accept: Option<Duration>,
    pub fast_open: Option<u32>,
    pub incoming_cpu: Option<u32>,
}

/// Creates, configures, binds, and listens, in the order `docs/API.md` gives.
pub(crate) fn tcp_listener(addr: SocketAddr, p: &ListenParams) -> io::Result<TcpListener> {
    let fd = tcp_socket(addr.is_ipv6())?;
    if p.reuse_address {
        set_int(fd.as_fd(), c::SOL_SOCKET, c::SO_REUSEADDR, 1)?;
    }
    if p.reuse_port {
        set_int(fd.as_fd(), c::SOL_SOCKET, c::SO_REUSEPORT, 1)?;
    }
    if addr.is_ipv6() {
        set_int(
            fd.as_fd(),
            c::IPPROTO_IPV6,
            c::IPV6_V6ONLY,
            c_int::from(p.ipv6_only),
        )?;
    }
    if let Some(n) = p.send_buffer {
        set_int(fd.as_fd(), c::SOL_SOCKET, c::SO_SNDBUF, clamp_int(n))?;
    }
    if let Some(n) = p.receive_buffer {
        set_int(fd.as_fd(), c::SOL_SOCKET, c::SO_RCVBUF, clamp_int(n))?;
    }
    set_incoming_cpu(fd.as_fd(), p.incoming_cpu)?;
    bind_to(fd.as_fd(), addr)?;
    // SAFETY: `fd` is an open, bound stream socket; listen(2) takes an int backlog.
    cvt(unsafe { listen(fd.as_raw_fd(), clamp_int(p.backlog)) })?;
    set_defer_accept(fd.as_fd(), p.defer_accept)?;
    if let Some(queue) = p.fast_open {
        set_fast_open(fd.as_fd(), queue)?;
    }
    let listener = TcpListener::from(fd);
    // Listeners are always non-blocking: accepts wait in poll with a wake channel.
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// One `sendfile` on a non-blocking socket: `WouldBlock` when the buffer is full, `0`
/// when the file has nothing at `offset`.
pub(crate) fn send_file(
    sock: Sock<'_>,
    file: &std::fs::File,
    offset: u64,
    len: usize,
) -> io::Result<usize> {
    let raw_file = file.as_raw_fd();
    let start = i64::try_from(offset).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    retry_interrupted(|| {
        #[cfg(any(test, net_io_shim))]
        let len = match super::shim::io(super::shim::Op::Send, len)? {
            Some(n) => n,
            None => len,
        };
        #[cfg(target_os = "linux")]
        {
            let mut at = start;
            // SAFETY: both descriptors are open for the call, and `at` is a live local.
            let n = unsafe { sendfile(sock.as_raw_fd(), raw_file, &raw mut at, len) };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n.unsigned_abs())
            }
        }
        #[cfg(target_os = "macos")]
        {
            let mut moved = len as i64;
            // SAFETY: both descriptors are open for the call; no headers; `moved` is a
            // live local that the call reads as the count and writes as the result.
            let ret = unsafe {
                sendfile(
                    raw_file,
                    sock.as_raw_fd(),
                    start,
                    &raw mut moved,
                    std::ptr::null_mut(),
                    0,
                )
            };
            sendfile_result(ret, moved)
        }
        #[cfg(target_os = "freebsd")]
        {
            let mut moved = 0i64;
            // SAFETY: both descriptors are open for the call; no headers; `moved` is a
            // live local written during the call.
            let ret = unsafe {
                sendfile(
                    raw_file,
                    sock.as_raw_fd(),
                    start,
                    len,
                    std::ptr::null_mut(),
                    &raw mut moved,
                    0,
                )
            };
            sendfile_result(ret, moved)
        }
    })
}

/// On the BSDs a call that stopped at a full buffer fails and still reports its bytes.
#[cfg(not(target_os = "linux"))]
fn sendfile_result(ret: c_int, moved: i64) -> io::Result<usize> {
    if ret == 0 || moved > 0 {
        return Ok(moved.unsigned_abs() as usize);
    }
    Err(io::Error::last_os_error())
}

/// Whether `sendfile` turned this file or socket down, as opposed to failing: the
/// bytes can still go by reading and writing.
pub(crate) fn send_file_refused(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(errno::EINVAL | errno::EOPNOTSUPP | errno::ENOTSOCK)
    ) || e.kind() == io::ErrorKind::Unsupported
}

/// Bytes of `file` at `offset`, leaving its position alone.
pub(crate) fn read_file_at(file: &std::fs::File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(file, buf, offset)
}

/// Whether this OS can pin a thread.
pub(crate) const CAN_PIN: bool = cfg!(any(target_os = "linux", target_os = "freebsd"));

/// `cpu` as a `cpu_set_t` or `cpuset_t` (1,024 CPUs on Linux, 256 on FreeBSD).
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn cpu_mask(cpu: usize) -> io::Result<[u64; 16]> {
    let mut mask = [0u64; 16];
    let word = mask
        .get_mut(cpu / 64)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    *word = 1 << (cpu % 64);
    Ok(mask)
}

/// Pins the calling thread to `cpu`.
#[cfg(target_os = "linux")]
pub(crate) fn pin_current_thread(cpu: usize) -> io::Result<()> {
    let mask = cpu_mask(cpu)?;
    // SAFETY: pid 0 means the calling thread; `mask` is live for its stated size.
    cvt(unsafe { sched_setaffinity(0, size_of_val(&mask), mask.as_ptr()) }).map(drop)
}

/// Pins the calling thread to `cpu`.
#[cfg(target_os = "freebsd")]
pub(crate) fn pin_current_thread(cpu: usize) -> io::Result<()> {
    const CPU_LEVEL_WHICH: c_int = 3;
    const CPU_WHICH_TID: c_int = 1;
    let mask = cpu_mask(cpu)?;
    // SAFETY: id -1 means the calling thread; `mask` is live, and 32 bytes is `cpuset_t`.
    cvt(unsafe { cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, 32, mask.as_ptr()) })
        .map(drop)
}

/// macOS has no affinity call; `build` refuses a placement there.
#[cfg(target_os = "macos")]
pub(crate) fn pin_current_thread(_cpu: usize) -> io::Result<()> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// `SO_INCOMING_CPU`: connections to a reuse-port group go to the listener on the
/// CPU that received them.
#[cfg(target_os = "linux")]
fn set_incoming_cpu(sock: Sock<'_>, cpu: Option<u32>) -> io::Result<()> {
    match cpu {
        Some(cpu) => set_int(sock, c::SOL_SOCKET, c::SO_INCOMING_CPU, clamp_int(cpu)),
        None => Ok(()),
    }
}

#[cfg(not(target_os = "linux"))]
fn set_incoming_cpu(_sock: Sock<'_>, cpu: Option<u32>) -> io::Result<()> {
    match cpu {
        Some(_) => Err(io::Error::from(io::ErrorKind::Unsupported)),
        None => Ok(()),
    }
}

/// `TCP_DEFER_ACCEPT`: `accept` returns once bytes arrive, or after `wait`.
#[cfg(target_os = "linux")]
fn set_defer_accept(sock: Sock<'_>, wait: Option<Duration>) -> io::Result<()> {
    match wait {
        Some(d) => set_int(sock, c::IPPROTO_TCP, c::TCP_DEFER_ACCEPT, secs(d)),
        None => Ok(()),
    }
}

#[cfg(not(target_os = "linux"))]
fn set_defer_accept(_sock: Sock<'_>, wait: Option<Duration>) -> io::Result<()> {
    match wait {
        Some(_) => Err(io::Error::from(io::ErrorKind::Unsupported)),
        None => Ok(()),
    }
}

/// Server fast open: a queue length on Linux, on or off on the BSDs.
fn set_fast_open(sock: Sock<'_>, queue: u32) -> io::Result<()> {
    let value = if cfg!(target_os = "linux") {
        clamp_int(queue)
    } else {
        c_int::from(queue != 0)
    };
    set_int(sock, c::IPPROTO_TCP, c::TCP_FASTOPEN, value)
}

/// `TCP_USER_TIMEOUT`: how long sent bytes may stay unacknowledged.
#[cfg(target_os = "linux")]
pub(crate) fn set_user_timeout(sock: Sock<'_>, timeout: Duration) -> io::Result<()> {
    let ms = c_int::try_from(timeout.as_millis()).unwrap_or(c_int::MAX);
    set_int(sock, c::IPPROTO_TCP, c::TCP_USER_TIMEOUT, ms)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn set_user_timeout(_sock: Sock<'_>, _timeout: Duration) -> io::Result<()> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// Binds `sock` to `addr`.
pub(crate) fn bind_to(sock: Sock<'_>, addr: SocketAddr) -> io::Result<()> {
    let mut buf = [0u8; 28];
    let len = encode_addr(addr, &mut buf);
    // SAFETY: `buf` holds a valid sockaddr of `len` bytes for the socket's family
    // and lives for the call; `sock` is open.
    cvt(unsafe { bind(sock.as_raw_fd(), buf.as_ptr().cast::<c_void>(), len) }).map(drop)
}

/// Starts a non-blocking connect. `Ok(true)` when it is in progress, `Ok(false)` when done.
pub(crate) fn connect_start(sock: Sock<'_>, addr: SocketAddr) -> io::Result<bool> {
    #[cfg(any(test, net_io_shim))]
    super::shim::check(super::shim::Op::Connect)?;
    let mut buf = [0u8; 28];
    let len = encode_addr(addr, &mut buf);
    // SAFETY: as in `bind_to`; the socket is non-blocking, so connect(2) returns at once.
    let ret = unsafe { connect(sock.as_raw_fd(), buf.as_ptr().cast::<c_void>(), len) };
    if ret == 0 {
        return Ok(false);
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(c::EINPROGRESS) {
        Ok(true)
    } else {
        Err(err)
    }
}

/// The pending error of a socket (`SO_ERROR`), cleared by reading it.
pub(crate) fn take_error(sock: Sock<'_>) -> io::Result<Option<io::Error>> {
    let code = get_int(sock, c::SOL_SOCKET, c::SO_ERROR)?;
    Ok((code != 0).then(|| io::Error::from_raw_os_error(code)))
}

/// Whether `sock` is a listening stream socket.
///
/// macOS answers `SO_ACCEPTCONN` with `ENOPROTOOPT`; there a socket counts as
/// listening when it has no peer (`getpeername` gives `ENOTCONN`) and is bound to
/// a port. A bound socket that never called `listen` passes too; its first
/// `accept` then fails with `EINVAL`, which is a listener failure.
pub(crate) fn is_listening_stream(sock: Sock<'_>) -> io::Result<bool> {
    let stream = get_int(sock, c::SOL_SOCKET, c::SO_TYPE)? == c::SOCK_STREAM;
    let listening = match get_int(sock, c::SOL_SOCKET, c::SO_ACCEPTCONN) {
        Ok(v) => v != 0,
        #[cfg(not(target_os = "linux"))]
        Err(e) if e.raw_os_error() == Some(errno::ENOPROTOOPT) => bound_without_peer(sock)?,
        Err(e) => return Err(e),
    };
    Ok(listening && stream)
}

/// Whether `sock` is bound to a port and has no peer (the macOS listener check).
#[cfg(not(target_os = "linux"))]
fn bound_without_peer(sock: Sock<'_>) -> io::Result<bool> {
    // SAFETY: `sock` is open for the call; `ManuallyDrop` keeps this temporary
    // `TcpStream` from closing a descriptor it does not own.
    let s = std::mem::ManuallyDrop::new(unsafe { TcpStream::from_raw_fd(sock.as_raw_fd()) });
    match s.peer_addr() {
        Ok(_) => return Ok(false),
        Err(e) if e.raw_os_error() == Some(errno::ENOTCONN) => {}
        Err(e) => return Err(e),
    }
    Ok(s.local_addr()?.port() != 0)
}

/// Identifies a socket handed to this process: a listening stream socket, TCP
/// (IPv4 or IPv6) or Unix, and the address it is bound to.
pub(crate) fn listener_kind(sock: Sock<'_>) -> Result<super::SockKind, super::KindError> {
    use super::{KindError, SockKind};
    let ty = match get_int(sock, c::SOL_SOCKET, c::SO_TYPE) {
        Ok(t) => t,
        Err(e) if matches!(e.raw_os_error(), Some(errno::ENOTSOCK | errno::EBADF)) => {
            return Err(KindError::NotASocket);
        }
        Err(e) => return Err(KindError::Os(e)),
    };
    if ty != c::SOCK_STREAM {
        return Err(KindError::WrongKind);
    }
    let mut addr = AddrBuf([0; 128]);
    let mut len = 128 as SockLen;
    // SAFETY: `addr` is writable for `len` bytes and lives for the call; `sock` is open.
    cvt(unsafe {
        getsockname(
            sock.as_raw_fd(),
            addr.0.as_mut_ptr().cast::<c_void>(),
            &raw mut len,
        )
    })
    .map_err(KindError::Os)?;
    #[cfg(target_os = "linux")]
    let family = c_int::from(u16::from_ne_bytes([addr.0[0], addr.0[1]]));
    #[cfg(not(target_os = "linux"))]
    let family = c_int::from(addr.0[1]);
    let kind = if family == c::AF_UNIX_FAMILY {
        let end = (len as usize).min(addr.0.len());
        let path = addr.0.get(2..end).unwrap_or(&[]);
        // Up to the terminator; an abstract name (leading NUL) counts as unnamed.
        let path = path.split(|&b| b == 0).next().unwrap_or(&[]);
        SockKind::Unix(path.to_vec())
    } else {
        match decode_addr(&addr.0, len) {
            Some(a) => SockKind::Tcp(a),
            None => return Err(KindError::WrongKind),
        }
    };
    let listening = match get_int(sock, c::SOL_SOCKET, c::SO_ACCEPTCONN) {
        Ok(v) => v != 0,
        // macOS: no SO_ACCEPTCONN; a bound socket without a peer counts (as in
        // `is_listening_stream`).
        Err(e) if e.raw_os_error() == Some(errno::ENOPROTOOPT) => {
            let bound = match &kind {
                SockKind::Tcp(a) => a.port() != 0,
                SockKind::Unix(p) => !p.is_empty(),
            };
            bound && !has_peer(sock).map_err(KindError::Os)?
        }
        Err(e) => return Err(KindError::Os(e)),
    };
    if !listening {
        return Err(KindError::NotListening);
    }
    Ok(kind)
}

/// Whether `sock` is connected (`getpeername` succeeds; `ENOTCONN` means no peer).
pub(crate) fn has_peer(sock: Sock<'_>) -> io::Result<bool> {
    let mut addr = AddrBuf([0; 128]);
    let mut len = 128 as SockLen;
    // SAFETY: as in `listener_kind`.
    let ret = unsafe {
        getpeername(
            sock.as_raw_fd(),
            addr.0.as_mut_ptr().cast::<c_void>(),
            &raw mut len,
        )
    };
    if ret == 0 {
        return Ok(true);
    }
    let e = io::Error::last_os_error();
    if e.kind() == io::ErrorKind::NotConnected {
        Ok(false)
    } else {
        Err(e)
    }
}

/// Identifies a descriptor this process was given by number (systemd, FastCGI):
/// checks it is open first, then as [`listener_kind`].
pub(crate) fn inherited_kind(fd: RawFd) -> Result<super::SockKind, super::KindError> {
    // SAFETY: F_GETFD only reads the descriptor's flags; on a closed number it
    // fails with EBADF and touches nothing.
    if unsafe { fcntl(fd, c::F_GETFD) } == -1 {
        return Err(super::KindError::NotASocket);
    }
    // SAFETY: the descriptor is open (checked above) and stays open for this
    // call: only `claim_inherited` takes ownership of inherited descriptors.
    listener_kind(unsafe { BorrowedFd::borrow_raw(fd) })
}

/// Takes ownership of an inherited descriptor and sets close-on-exec. The caller
/// (`inherit`) does this once per descriptor per process, under its lock, after
/// `inherited_kind` verified it; nothing else in net-io owns these numbers.
pub(crate) fn claim_inherited(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: see above: the descriptor is open and has no other owner in net-io.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: `owned` is open; F_SETFD with FD_CLOEXEC is fcntl(2)'s documented use.
    cvt(unsafe { fcntl(owned.as_raw_fd(), c::F_SETFD, c::FD_CLOEXEC) })?;
    Ok(owned)
}

/// `CLOCK_MONOTONIC` in microseconds.
pub(crate) fn monotonic_micros() -> u64 {
    let mut ts = Timespec::default();
    // SAFETY: `ts` is a live, correctly sized timespec; CLOCK_MONOTONIC always exists.
    let _ = unsafe { clock_gettime(c::CLOCK_MONOTONIC, &raw mut ts) };
    (ts.tv_sec.max(0) as u64)
        .saturating_mul(1_000_000)
        .saturating_add((ts.tv_nsec.max(0) as u64) / 1_000)
}

/// This process's effective user id.
#[cfg(feature = "local")]
pub(crate) fn effective_uid() -> u32 {
    // SAFETY: geteuid(2) takes no arguments and cannot fail.
    unsafe { geteuid() }
}

/// The inode of this process's pidfd, which systemd passes as `LISTEN_PIDFDID`
/// (Linux 6.9 and later).
#[cfg(target_os = "linux")]
pub(crate) fn pidfd_inode() -> io::Result<u64> {
    use std::os::unix::fs::MetadataExt;
    let pid = std::ffi::c_long::from(std::process::id() as i32);
    // SAFETY: pidfd_open(2) takes a pid and flags (0) and returns a new descriptor or -1.
    let fd = unsafe { syscall(c::SYS_PIDFD_OPEN, pid, 0 as std::ffi::c_long) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = RawFd::try_from(fd).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    // SAFETY: `fd` was just returned by pidfd_open, is open, and is owned by no one else.
    let file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    Ok(file.metadata()?.ino())
}

/// Places a duplicate of `sock` at descriptor number `target` (tests only).
#[cfg(test)]
pub(crate) fn dup_to(sock: Sock<'_>, target: RawFd) -> io::Result<()> {
    unsafe extern "C" {
        fn dup2(old: c_int, new: c_int) -> c_int;
    }
    // SAFETY: dup2 takes two descriptor numbers; `sock` is open, `target` is a
    // number the test reserved.
    cvt(unsafe { dup2(sock.as_raw_fd(), target) }).map(drop)
}

/// Closes descriptor number `fd` (tests only).
#[cfg(test)]
pub(crate) fn close_number(fd: RawFd) {
    // SAFETY: `fd` was placed by `dup_to` and has no owner.
    drop(unsafe { OwnedFd::from_raw_fd(fd) });
}

/// Accepts one connection. On Linux `std` uses `accept4(SOCK_CLOEXEC)` and the
/// socket is blocking; on macOS `std` sets close-on-exec after `accept`, this adds
/// `SO_NOSIGPIPE`, and the socket stays non-blocking (D-083).
pub(crate) fn accept(listener: &TcpListener) -> io::Result<(TcpStream, SocketAddr)> {
    #[cfg(any(test, net_io_shim))]
    super::shim::check(super::shim::Op::Accept)?;
    let (stream, peer) = listener.accept()?;
    #[cfg(not(target_os = "linux"))]
    {
        // A connection the peer already reset makes these fail (`EINVAL` on
        // macOS); that is this connection's failure, never the listener's.
        let setup = set_int(stream.as_fd(), c::SOL_SOCKET, c::SO_NOSIGPIPE, 1)
            .and_then(|()| stream.set_nonblocking(true));
        if setup.is_err() {
            return Err(io::Error::from_raw_os_error(errno::ECONNABORTED));
        }
    }
    Ok((stream, peer))
}

/// Configures a dialed stream (created non-blocking for the connect) for
/// net-io's IO model on this OS: on Linux, blocking reads with a receive timeout
/// and sends that never block (`MSG_DONTWAIT`); on macOS it stays non-blocking.
pub(crate) fn prepare_dialed(stream: &TcpStream) -> io::Result<()> {
    if WAIT_BEFORE_RECV {
        Ok(())
    } else {
        stream.set_nonblocking(false)
    }
}

/// Whether reads wait in `poll` first on a non-blocking socket, or block in `recv`
/// with a receive timeout. Linux blocks (2 system calls per exchange). macOS
/// waits first, like Windows (D-083): a send there blocked on a full buffer
/// despite `MSG_DONTWAIT`, and `setsockopt` fails with `EINVAL` once the
/// connection has ended, so per-read `SO_RCVTIMEO` updates are not usable.
pub(crate) const WAIT_BEFORE_RECV: bool = cfg!(not(target_os = "linux"));

/// One receive. On Linux it blocks until bytes arrive, the receive timeout passes
/// (`WouldBlock`), the peer closes (0), or a kill shuts the read side (0); on
/// macOS the socket is non-blocking and the caller waited first.
pub(crate) fn recv(stream: &super::Stream, buf: &mut [u8]) -> io::Result<usize> {
    retry_interrupted(|| {
        #[cfg(any(test, net_io_shim))]
        let buf = match super::shim::io(super::shim::Op::Recv, buf.len())? {
            Some(n) => &mut buf[..n],
            None => &mut *buf,
        };
        stream.read(buf)
    })
}

/// Sets the receive timeout used by `recv` (`None` = wait forever).
pub(crate) fn set_recv_timeout(
    stream: &super::Stream,
    timeout: Option<Duration>,
) -> io::Result<()> {
    #[cfg(any(test, net_io_shim))]
    super::shim::check(super::shim::Op::RecvTimeout)?;
    // std rejects a zero duration; the caller never passes one, but be safe.
    stream.set_read_timeout(timeout.map(|d| d.max(Duration::from_millis(1))))
}

/// One send that never blocks: `WouldBlock` when the socket buffer is full.
pub(crate) fn send(stream: &super::Stream, buf: &[u8]) -> io::Result<usize> {
    retry_interrupted(|| {
        #[cfg(any(test, net_io_shim))]
        let buf = match super::shim::io(super::shim::Op::Send, buf.len())? {
            Some(n) => &buf[..n],
            None => buf,
        };
        send_once(stream.sock(), buf)
    })
}

/// One `send` system call with net-io's flags.
fn send_once(sock: Sock<'_>, buf: &[u8]) -> io::Result<usize> {
    #[cfg(target_os = "linux")]
    let flags = c::MSG_DONTWAIT | c::MSG_NOSIGNAL;
    #[cfg(not(target_os = "linux"))]
    let flags = c::MSG_DONTWAIT;
    {
        // SAFETY: `stream` is open for the call; `buf` is a live slice of `buf.len()`
        // bytes. MSG_NOSIGNAL (Linux) and SO_NOSIGPIPE (set at creation on macOS)
        // keep a closed peer from raising SIGPIPE.
        let n = unsafe {
            c_send(
                sock.as_raw_fd(),
                buf.as_ptr().cast::<c_void>(),
                buf.len(),
                flags,
            )
        };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n.unsigned_abs())
        }
    }
}

/// The largest number of slices passed to one vectored send (below `IOV_MAX`).
pub(crate) const MAX_SLICES: usize = 64;

/// One vectored send that never blocks (at most [`MAX_SLICES`] slices).
pub(crate) fn send_vectored(stream: &super::Stream, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
    send_vectored_sock(stream.sock(), bufs)
}

/// As [`send_vectored`], on a borrowed socket.
pub(crate) fn send_vectored_sock(sock: Sock<'_>, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
    let bufs = &bufs[..bufs.len().min(MAX_SLICES)];
    #[cfg(target_os = "linux")]
    let flags = c::MSG_DONTWAIT | c::MSG_NOSIGNAL;
    #[cfg(not(target_os = "linux"))]
    let flags = c::MSG_DONTWAIT;
    retry_interrupted(|| {
        #[cfg(any(test, net_io_shim))]
        if let Some(n) = super::shim::io(super::shim::Op::Send, bufs.iter().map(|b| b.len()).sum())?
        {
            // A short write: send only the first `n` bytes of the first slice that has them.
            let first = bufs
                .iter()
                .find(|b| !b.is_empty())
                .map_or(&[][..], |b| &b[..]);
            // Straight to the system call: this send already took its fault.
            return send_once(sock, &first[..n.min(first.len())]);
        }
        let msg = MsgHdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: bufs.as_ptr().cast::<IoSlice<'static>>(),
            #[cfg(target_os = "linux")]
            msg_iovlen: bufs.len(),
            #[cfg(not(target_os = "linux"))]
            msg_iovlen: bufs.len() as c_int,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        // SAFETY: `IoSlice` is documented as ABI-compatible with `struct iovec` on Unix;
        // `bufs` (at most 64 slices) and the bytes they point to live for the call;
        // `msg` carries no name and no control data. MSG_DONTWAIT keeps the call from blocking.
        let n = unsafe { sendmsg(sock.as_raw_fd(), &raw const msg, flags) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n.unsigned_abs())
        }
    })
}

/// Waits until `sock` is ready for `interest`, `wake` fires, or `timeout` passes.
pub(crate) fn wait(
    sock: Sock<'_>,
    interest: Interest,
    wake: Option<&Wake>,
    timeout: Option<Duration>,
) -> io::Result<Ready> {
    #[cfg(any(test, net_io_shim))]
    super::shim::check(super::shim::Op::Wait)?;
    let events = match interest {
        Interest::Read => c::POLLIN,
        Interest::Write => c::POLLOUT,
    };
    let mut fds = [
        PollFd {
            fd: sock.as_raw_fd(),
            events,
            revents: 0,
        },
        PollFd {
            fd: wake.map_or(-1, |w| w.rx.as_raw_fd()),
            events: c::POLLIN,
            revents: 0,
        },
    ];
    let nfds: Nfds = if wake.is_some() { 2 } else { 1 };
    let ms = poll_millis(timeout);
    // SAFETY: `fds` is a live array of `nfds` initialized pollfd structs whose
    // descriptors are open for the call (borrowed `sock`, and `wake.rx` owned by `wake`).
    let n = retry_interrupted(|| cvt(unsafe { poll(fds.as_mut_ptr(), nfds, ms) }))?;
    if n == 0 {
        return Ok(Ready::TimedOut);
    }
    if fds[1].revents != 0 {
        if let Some(w) = wake {
            w.drain();
        }
        return Ok(Ready::Woken);
    }
    // POLLERR, POLLHUP, and POLLNVAL also count as ready: the next call reports the error.
    let _ready = fds[0].revents & (events | c::POLLERR | c::POLLHUP | c::POLLNVAL);
    Ok(Ready::Socket)
}

/// Waits on the wake channel alone (or until `timeout`). `true` when woken.
pub(crate) fn wait_wake(wake: &Wake, timeout: Option<Duration>) -> io::Result<bool> {
    let mut fds = [PollFd {
        fd: wake.rx.as_raw_fd(),
        events: c::POLLIN,
        revents: 0,
    }];
    let ms = poll_millis(timeout);
    // SAFETY: `fds` holds one initialized pollfd whose descriptor `wake` owns for the call.
    let n = retry_interrupted(|| cvt(unsafe { poll(fds.as_mut_ptr(), 1, ms) }))?;
    if n > 0 {
        wake.drain();
    }
    Ok(n > 0)
}

/// Waits until any of `socks` (at most 64) can write or has failed; bit `i` of the
/// result stands for `socks[i]`, and 0 means the timeout passed.
pub(crate) fn wait_writable(socks: &[Sock<'_>], timeout: Duration) -> io::Result<u64> {
    let mut fds: Vec<PollFd> = socks
        .iter()
        .map(|s| PollFd {
            fd: s.as_raw_fd(),
            events: c::POLLOUT,
            revents: 0,
        })
        .collect();
    let ms = poll_millis(Some(timeout));
    // SAFETY: `fds` is a live slice of initialized pollfd structs whose descriptors are
    // open for the call (borrowed in `socks`).
    retry_interrupted(|| cvt(unsafe { poll(fds.as_mut_ptr(), fds.len() as Nfds, ms) }))?;
    Ok(fds
        .iter()
        .enumerate()
        .filter(|(_, f)| f.revents != 0)
        .fold(0, |mask, (i, _)| mask | (1 << i)))
}

/// Shuts the read side of a raw socket. Used only by the kill guard.
///
/// # Safety
///
/// `raw` must be an open descriptor for the whole call; the kill guard ensures
/// its owner does not close it while a kill is in flight.
pub(crate) unsafe fn shutdown_read_raw(raw: RawSock) {
    // SAFETY: the caller guarantees `raw` is open; shutdown(2) on an open socket
    // has no memory effects. The result is ignored: a socket the peer already
    // closed reports ENOTCONN, which is fine for a wake-up.
    let _ = unsafe { shutdown(raw, c::SHUT_RD) };
}

fn clamp_int(n: u32) -> c_int {
    c_int::try_from(n).unwrap_or(c_int::MAX)
}

/// Linger: `None` = off, `Some(0)` = abortive (RST on close), `Some(d)` = wait up to `d`.
pub(crate) fn set_linger(sock: Sock<'_>, linger: Option<Duration>) -> io::Result<()> {
    let value = Linger {
        l_onoff: c_int::from(linger.is_some()),
        l_linger: linger.map_or(0, |d| c_int::try_from(d.as_secs()).unwrap_or(c_int::MAX)),
    };
    #[cfg(target_os = "linux")]
    let name = c::SO_LINGER;
    #[cfg(not(target_os = "linux"))]
    let name = c::SO_LINGER_SEC;
    // SAFETY: `value` is a live repr(C) linger struct and the length is its size.
    let ret = unsafe {
        setsockopt(
            sock.as_raw_fd(),
            c::SOL_SOCKET,
            name,
            (&raw const value).cast::<c_void>(),
            size_of::<Linger>() as SockLen,
        )
    };
    cvt(ret).map(drop)
}

/// The linger setting (`None` = off).
pub(crate) fn linger(sock: Sock<'_>) -> io::Result<Option<Duration>> {
    let mut value = Linger {
        l_onoff: 0,
        l_linger: 0,
    };
    let mut len = size_of::<Linger>() as SockLen;
    #[cfg(target_os = "linux")]
    let name = c::SO_LINGER;
    #[cfg(not(target_os = "linux"))]
    let name = c::SO_LINGER_SEC;
    // SAFETY: `value` and `len` are live locals; `len` holds the struct's size.
    let ret = unsafe {
        getsockopt(
            sock.as_raw_fd(),
            c::SOL_SOCKET,
            name,
            (&raw mut value).cast::<c_void>(),
            &raw mut len,
        )
    };
    cvt(ret)?;
    Ok((value.l_onoff != 0)
        .then(|| Duration::from_secs(u64::try_from(value.l_linger).unwrap_or(0))))
}

/// Keepalive: `None` = off; otherwise idle, interval, count.
pub(crate) fn set_keepalive(
    sock: Sock<'_>,
    keepalive: Option<(Duration, Duration, u32)>,
) -> io::Result<()> {
    match keepalive {
        None => set_int(sock, c::SOL_SOCKET, c::SO_KEEPALIVE, 0),
        Some((idle, interval, count)) => {
            set_int(sock, c::SOL_SOCKET, c::SO_KEEPALIVE, 1)?;
            #[cfg(target_os = "linux")]
            set_int(sock, c::IPPROTO_TCP, c::TCP_KEEPIDLE, secs(idle))?;
            #[cfg(not(target_os = "linux"))]
            set_int(sock, c::IPPROTO_TCP, c::TCP_KEEPALIVE, secs(idle))?;
            set_int(sock, c::IPPROTO_TCP, c::TCP_KEEPINTVL, secs(interval))?;
            set_int(sock, c::IPPROTO_TCP, c::TCP_KEEPCNT, clamp_int(count))
        }
    }
}

/// The keepalive setting.
pub(crate) fn keepalive(sock: Sock<'_>) -> io::Result<Option<(Duration, Duration, u32)>> {
    if get_int(sock, c::SOL_SOCKET, c::SO_KEEPALIVE)? == 0 {
        return Ok(None);
    }
    #[cfg(target_os = "linux")]
    let idle = get_int(sock, c::IPPROTO_TCP, c::TCP_KEEPIDLE)?;
    #[cfg(not(target_os = "linux"))]
    let idle = get_int(sock, c::IPPROTO_TCP, c::TCP_KEEPALIVE)?;
    let interval = get_int(sock, c::IPPROTO_TCP, c::TCP_KEEPINTVL)?;
    let count = get_int(sock, c::IPPROTO_TCP, c::TCP_KEEPCNT)?;
    Ok(Some((
        Duration::from_secs(u64::try_from(idle).unwrap_or(0)),
        Duration::from_secs(u64::try_from(interval).unwrap_or(0)),
        u32::try_from(count).unwrap_or(0),
    )))
}

fn secs(d: Duration) -> c_int {
    c_int::try_from(d.as_secs().max(1)).unwrap_or(c_int::MAX)
}

/// Sets `SO_SNDBUF` and returns the effective value (Linux doubles it).
pub(crate) fn set_send_buffer(sock: Sock<'_>, bytes: u32) -> io::Result<u32> {
    set_int(sock, c::SOL_SOCKET, c::SO_SNDBUF, clamp_int(bytes))?;
    send_buffer(sock)
}

/// The effective `SO_SNDBUF`.
pub(crate) fn send_buffer(sock: Sock<'_>) -> io::Result<u32> {
    Ok(u32::try_from(get_int(sock, c::SOL_SOCKET, c::SO_SNDBUF)?).unwrap_or(0))
}

/// Sets `SO_RCVBUF` and returns the effective value (Linux doubles it).
pub(crate) fn set_receive_buffer(sock: Sock<'_>, bytes: u32) -> io::Result<u32> {
    set_int(sock, c::SOL_SOCKET, c::SO_RCVBUF, clamp_int(bytes))?;
    receive_buffer(sock)
}

/// The effective `SO_RCVBUF`.
pub(crate) fn receive_buffer(sock: Sock<'_>) -> io::Result<u32> {
    Ok(u32::try_from(get_int(sock, c::SOL_SOCKET, c::SO_RCVBUF)?).unwrap_or(0))
}

/// `TCP_NODELAY`.
pub(crate) fn set_nodelay(sock: Sock<'_>, on: bool) -> io::Result<()> {
    set_int(sock, c::IPPROTO_TCP, c::TCP_NODELAY, c_int::from(on))
}

/// `TCP_NODELAY`.
pub(crate) fn nodelay(sock: Sock<'_>) -> io::Result<bool> {
    Ok(get_int(sock, c::IPPROTO_TCP, c::TCP_NODELAY)? != 0)
}

/// `IP_TTL` or `IPV6_UNICAST_HOPS`.
pub(crate) fn set_ttl(sock: Sock<'_>, v6: bool, hops: u8) -> io::Result<()> {
    if v6 {
        set_int(
            sock,
            c::IPPROTO_IPV6,
            c::IPV6_UNICAST_HOPS,
            c_int::from(hops),
        )
    } else {
        set_int(sock, c::IPPROTO_IP, c::IP_TTL, c_int::from(hops))
    }
}

/// `IP_TTL` or `IPV6_UNICAST_HOPS`.
pub(crate) fn ttl(sock: Sock<'_>, v6: bool) -> io::Result<u8> {
    let v = if v6 {
        get_int(sock, c::IPPROTO_IPV6, c::IPV6_UNICAST_HOPS)?
    } else {
        get_int(sock, c::IPPROTO_IP, c::IP_TTL)?
    };
    Ok(u8::try_from(v).unwrap_or(u8::MAX))
}

/// The process's soft open-descriptor limit; `None` when unlimited.
pub(crate) fn descriptor_limit() -> Option<u64> {
    let mut r = Rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `r` is a live rlimit struct; getrlimit(2) writes it and returns 0, or -1.
    let ret = unsafe { getrlimit(c::RLIMIT_NOFILE, &raw mut r) };
    if ret != 0 || r.rlim_cur >= i64::MAX as u64 {
        None
    } else {
        Some(r.rlim_cur)
    }
}

/// A wake-up channel: a datagram socket pair. Waits include its receive end, and
/// `wake` sends one byte to end them.
#[derive(Debug)]
pub(crate) struct Wake {
    tx: UnixDatagram,
    rx: UnixDatagram,
    thread: std::sync::OnceLock<std::thread::Thread>,
}

impl Wake {
    pub(crate) fn new() -> io::Result<Wake> {
        let (tx, rx) = UnixDatagram::pair()?;
        tx.set_nonblocking(true)?;
        rx.set_nonblocking(true)?;
        Ok(Wake {
            tx,
            rx,
            thread: std::sync::OnceLock::new(),
        })
    }

    /// Also unpark this thread on every wake (a worker parked without a socket).
    pub(crate) fn bind_thread(&self, thread: std::thread::Thread) {
        let _ = self.thread.set(thread);
    }

    /// Ends the current or next wait that includes this channel. Never blocks.
    pub(crate) fn wake(&self) {
        // A full queue already holds a wake-up; nothing else can go wrong that matters here.
        let _ = self.tx.send(&[1]);
        if let Some(t) = self.thread.get() {
            t.unpark();
        }
    }

    fn drain(&self) {
        let mut buf = [0u8; 64];
        while matches!(self.rx.recv(&mut buf), Ok(n) if n > 0) {}
    }
}

// ---- local sockets (feature `local`) ----------------------------------------

/// `struct ucred` (`unix(7)`), for `SO_PEERCRED`.
#[cfg(all(feature = "local", target_os = "linux"))]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Ucred {
    pid: i32,
    uid: u32,
    gid: u32,
}

/// `struct cmsghdr` (`cmsg(3)`): Linux uses `size_t` for the length.
#[cfg(all(any(feature = "local", feature = "udp"), target_os = "linux"))]
#[repr(C)]
struct CmsgHdr {
    cmsg_len: usize,
    cmsg_level: c_int,
    cmsg_type: c_int,
}

/// `struct cmsghdr` on macOS: `socklen_t` for the length.
#[cfg(all(any(feature = "local", feature = "udp"), not(target_os = "linux")))]
#[repr(C)]
struct CmsgHdr {
    cmsg_len: u32,
    cmsg_level: c_int,
    cmsg_type: c_int,
}

/// `CMSG_ALIGN`: to 4 bytes on macOS, to `size_t` elsewhere.
#[cfg(feature = "local")]
const CMSG_ALIGN_TO: usize = if cfg!(target_os = "macos") {
    4
} else {
    size_of::<usize>()
};

#[cfg(feature = "local")]
const fn cmsg_align(n: usize) -> usize {
    (n + CMSG_ALIGN_TO - 1) & !(CMSG_ALIGN_TO - 1)
}

/// `CMSG_SPACE(n)`.
#[cfg(feature = "local")]
const fn cmsg_space(n: usize) -> usize {
    cmsg_align(size_of::<CmsgHdr>()) + cmsg_align(n)
}

/// `CMSG_LEN(n)`.
#[cfg(feature = "local")]
const fn cmsg_len(n: usize) -> usize {
    cmsg_align(size_of::<CmsgHdr>()) + n
}

/// The most descriptors one message carries.
#[cfg(feature = "local")]
pub(crate) const MAX_FDS: usize = 64;

/// Control-message space for [`MAX_FDS`] descriptors, aligned for `cmsghdr`.
#[cfg(feature = "local")]
#[repr(C, align(8))]
struct CmsgBuf([u8; cmsg_space(4 * MAX_FDS)]);

/// Control-message space a receive offers: room for 512 descriptors, more than
/// one message can carry (Linux caps it at 253, `SCM_MAX_FD`; macOS and FreeBSD
/// cap the control data at `MCLBYTES`, 2,048 bytes [to confirm on each]). A
/// message never comes back cut short, so macOS and FreeBSD, which install every
/// descriptor before copying, never install one whose number is lost.
#[cfg(feature = "local")]
const RECV_CONTROL: usize = cmsg_space(4 * 512);

#[cfg(feature = "local")]
#[repr(C, align(8))]
struct RecvBuf([u8; RECV_CONTROL]);

/// Sends `body` (not empty) with `fds` attached (`SCM_RIGHTS`, at most
/// [`MAX_FDS`]); never blocks. Returns the bytes of `body` sent; the descriptors
/// travel with the first byte.
#[cfg(feature = "local")]
pub(crate) fn send_with_fds(
    stream: &super::Stream,
    body: &[u8],
    fds: &[BorrowedFd<'_>],
) -> io::Result<usize> {
    if body.is_empty() || fds.len() > MAX_FDS {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let mut control = CmsgBuf([0; cmsg_space(4 * MAX_FDS)]);
    let data_len = 4 * fds.len();
    let space = if fds.is_empty() {
        0
    } else {
        cmsg_space(data_len)
    };
    if !fds.is_empty() {
        let hdr = cmsg_align(size_of::<CmsgHdr>());
        let len = cmsg_len(data_len);
        #[cfg(target_os = "linux")]
        control.0[..size_of::<usize>()].copy_from_slice(&len.to_ne_bytes());
        #[cfg(not(target_os = "linux"))]
        control.0[..4].copy_from_slice(&(len as u32).to_ne_bytes());
        let level_at = size_of::<CmsgHdr>() - 2 * size_of::<c_int>();
        control.0[level_at..level_at + 4].copy_from_slice(&c::SOL_SOCKET.to_ne_bytes());
        control.0[level_at + 4..level_at + 8].copy_from_slice(&c::SCM_RIGHTS.to_ne_bytes());
        for (i, fd) in fds.iter().enumerate() {
            let at = hdr + 4 * i;
            control.0[at..at + 4].copy_from_slice(&fd.as_raw_fd().to_ne_bytes());
        }
    }
    let iov = [IoSlice::new(body)];
    let msg = MsgHdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: iov.as_ptr().cast::<IoSlice<'static>>(),
        #[cfg(target_os = "linux")]
        msg_iovlen: 1,
        #[cfg(not(target_os = "linux"))]
        msg_iovlen: 1,
        msg_control: if space == 0 {
            std::ptr::null_mut()
        } else {
            control.0.as_mut_ptr().cast::<c_void>()
        },
        #[cfg(target_os = "linux")]
        msg_controllen: space,
        #[cfg(not(target_os = "linux"))]
        msg_controllen: space as u32,
        msg_flags: 0,
    };
    #[cfg(target_os = "linux")]
    let flags = c::MSG_DONTWAIT | c::MSG_NOSIGNAL;
    #[cfg(not(target_os = "linux"))]
    let flags = c::MSG_DONTWAIT;
    retry_interrupted(|| {
        // SAFETY: `iov` (one slice of `body`) and `control` (a cmsghdr with `fds.len()`
        // open descriptors, `space` bytes) live for the call; `msg` points only at them.
        let n = unsafe { sendmsg(stream.sock().as_raw_fd(), &raw const msg, flags) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n.unsigned_abs())
        }
    })
}

/// What [`recv_with_fds`] got.
#[cfg(feature = "local")]
pub(crate) struct Received {
    /// Bytes of body.
    pub(crate) bytes: usize,
    /// Descriptors stored into the caller's array.
    pub(crate) fds: usize,
    /// The control data did not fit, or carried more than [`MAX_FDS`]
    /// descriptors: every descriptor received was closed.
    pub(crate) truncated: bool,
}

/// Receives into `body` and stores attached descriptors (close-on-exec) into
/// `into` from index 0. Like [`recv`]: on Linux it blocks under the receive
/// timeout, on macOS the socket is non-blocking and the caller waited first.
/// On a truncated control message, or one with more than [`MAX_FDS`]
/// descriptors, every descriptor received is closed and `truncated` is set.
#[cfg(feature = "local")]
pub(crate) fn recv_with_fds(
    stream: &super::Stream,
    body: &mut [u8],
    into: &mut [Option<OwnedFd>; MAX_FDS],
) -> io::Result<Received> {
    let mut control = RecvBuf([0; RECV_CONTROL]);
    let mut iov = [io::IoSliceMut::new(body)];
    let mut msg = MsgHdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: iov.as_mut_ptr().cast::<IoSlice<'static>>(),
        #[cfg(target_os = "linux")]
        msg_iovlen: 1,
        #[cfg(not(target_os = "linux"))]
        msg_iovlen: 1,
        msg_control: control.0.as_mut_ptr().cast::<c_void>(),
        #[cfg(target_os = "linux")]
        msg_controllen: control.0.len(),
        #[cfg(not(target_os = "linux"))]
        msg_controllen: control.0.len() as u32,
        msg_flags: 0,
    };
    #[cfg(not(target_os = "macos"))]
    let flags = c::MSG_CMSG_CLOEXEC;
    #[cfg(target_os = "macos")]
    let flags = 0;
    let n = retry_interrupted(|| {
        // SAFETY: `iov` (`IoSliceMut`, ABI-compatible with `struct iovec`) covers
        // `body`; `control` is `msg_controllen` bytes; both live for the call.
        let n = unsafe { recvmsg(stream.sock().as_raw_fd(), &raw mut msg, flags) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n.unsigned_abs())
        }
    })?;
    #[cfg(target_os = "linux")]
    let used = msg.msg_controllen.min(control.0.len());
    #[cfg(not(target_os = "linux"))]
    let used = (msg.msg_controllen as usize).min(control.0.len());
    let truncated = msg.msg_flags & c::MSG_CTRUNC != 0;
    // SAFETY: `control[..used]` is what recvmsg(2) just wrote: every SCM_RIGHTS
    // record in it names descriptors the kernel installed in this process for this
    // call, which nothing else owns.
    let (fds, refused) = unsafe { take_fds(&control.0[..used], truncated, into) };
    Ok(Received {
        bytes: n,
        fds,
        truncated: truncated || refused,
    })
}

/// Moves the descriptors of the `SCM_RIGHTS` records in `control` into `into`
/// from index 0 and returns how many, and whether they were refused: a record
/// cut short, or more than [`MAX_FDS`] descriptors. When `truncated` or refused,
/// every descriptor found is closed instead and the count is 0.
///
/// macOS and FreeBSD install every descriptor of a message before they copy the
/// control data out, and copy a record that does not fit only in part, keeping
/// its original `cmsg_len`. The descriptors whose numbers reached the buffer are
/// closed here; any whose numbers did not would be beyond reach, which is why
/// the receive buffer holds more than a message can carry (Linux installs only
/// what fits, and rewrites `cmsg_len` to match).
///
/// # Safety
///
/// Every descriptor number in an `SCM_RIGHTS` record of `control` must be open
/// and owned by no one else: the kernel's report of a `recvmsg` call.
#[cfg(feature = "local")]
unsafe fn take_fds(
    control: &[u8],
    truncated: bool,
    into: &mut [Option<OwnedFd>; MAX_FDS],
) -> (usize, bool) {
    let used = control.len();
    let hdr = cmsg_align(size_of::<CmsgHdr>());
    let level_at = size_of::<CmsgHdr>() - 2 * size_of::<c_int>();
    let word = |at: usize| -> [u8; 4] {
        control
            .get(at..at + 4)
            .and_then(|b| b.try_into().ok())
            .unwrap_or([0xFF; 4])
    };
    let mut count = 0;
    let mut cut = false;
    let mut over = false;
    let mut off = 0;
    while off + size_of::<CmsgHdr>() <= used {
        #[cfg(target_os = "linux")]
        let len = control
            .get(off..off + size_of::<usize>())
            .and_then(|b| b.try_into().ok())
            .map_or(0, usize::from_ne_bytes);
        #[cfg(not(target_os = "linux"))]
        let len = u32::from_ne_bytes(word(off)) as usize;
        let level = c_int::from_ne_bytes(word(off + level_at));
        let kind = c_int::from_ne_bytes(word(off + level_at + 4));
        if len < hdr {
            break;
        }
        let end = off.saturating_add(len).min(used);
        cut |= end < off.saturating_add(len);
        if level == c::SOL_SOCKET && kind == c::SCM_RIGHTS {
            for at in (off + hdr..end).step_by(4).take_while(|at| at + 4 <= end) {
                let raw = RawFd::from_ne_bytes(word(at));
                if raw < 0 {
                    continue;
                }
                // SAFETY: the caller's contract: the kernel installed `raw` in this
                // process for this call, and nothing else owns it.
                let owned = unsafe { OwnedFd::from_raw_fd(raw) };
                #[cfg(target_os = "macos")]
                {
                    // SAFETY: `owned` is open; F_SETFD with FD_CLOEXEC takes an int.
                    // macOS has no MSG_CMSG_CLOEXEC, so this is a second step.
                    unsafe { fcntl(owned.as_raw_fd(), c::F_SETFD, c::FD_CLOEXEC) };
                }
                over |= count == MAX_FDS;
                if !over && !truncated && !cut {
                    into[count] = Some(owned);
                    count += 1;
                }
                // Otherwise `owned` drops here and the descriptor is closed.
            }
        }
        if cut {
            break;
        }
        off += cmsg_align(len);
    }
    if truncated || cut || over {
        for slot in into.iter_mut().take(count) {
            *slot = None;
        }
        count = 0;
    }
    (count, cut || over)
}

/// The peer's process id (where the OS says), user id, and group id.
#[cfg(all(feature = "local", target_os = "linux"))]
pub(crate) fn peer_credentials(sock: Sock<'_>) -> io::Result<(Option<u32>, u32, u32)> {
    let mut cred = Ucred::default();
    let mut len = size_of::<Ucred>() as SockLen;
    // SAFETY: `sock` is open; `cred` and `len` are live locals and `len` holds the
    // size of `cred`, as `unix(7)` describes for SO_PEERCRED.
    let ret = unsafe {
        getsockopt(
            sock.as_raw_fd(),
            c::SOL_SOCKET,
            c::SO_PEERCRED,
            (&raw mut cred).cast::<c_void>(),
            &raw mut len,
        )
    };
    cvt(ret)?;
    Ok((
        u32::try_from(cred.pid).ok().filter(|&p| p > 0),
        cred.uid,
        cred.gid,
    ))
}

/// The peer's process id (where the OS says), user id, and group id.
#[cfg(all(feature = "local", not(target_os = "linux")))]
pub(crate) fn peer_credentials(sock: Sock<'_>) -> io::Result<(Option<u32>, u32, u32)> {
    let mut uid = 0u32;
    let mut gid = 0u32;
    // SAFETY: `sock` is open; `uid` and `gid` are live locals getpeereid(3) writes.
    cvt(unsafe { getpeereid(sock.as_raw_fd(), &raw mut uid, &raw mut gid) })?;
    #[cfg(target_os = "macos")]
    let pid = get_int(sock, c::SOL_LOCAL, c::LOCAL_PEERPID)
        .ok()
        .and_then(|p| u32::try_from(p).ok());
    #[cfg(target_os = "freebsd")]
    let pid = peer_pid(sock);
    Ok((pid, uid, gid))
}

/// `struct xucred` (`unix(4)` on FreeBSD), for `LOCAL_PEERCRED`. `cr_pid` shares a
/// pointer-sized union, and FreeBSD fills it from 13.
#[cfg(all(feature = "local", target_os = "freebsd"))]
#[repr(C)]
struct Xucred {
    cr_version: u32,
    cr_uid: u32,
    cr_ngroups: i16,
    cr_groups: [u32; 16],
    cr_pid: usize,
}

/// The process at the other end of a Unix socket; only FreeBSD's credentials carry it.
#[cfg(all(feature = "local", target_os = "freebsd"))]
fn peer_pid(sock: Sock<'_>) -> Option<u32> {
    let mut cred = Xucred {
        cr_version: 0,
        cr_uid: 0,
        cr_ngroups: 0,
        cr_groups: [0; 16],
        cr_pid: 0,
    };
    let mut len = size_of::<Xucred>() as SockLen;
    // SAFETY: `sock` is open; `cred` is writable for `len` bytes and lives for the call.
    let ret = unsafe {
        getsockopt(
            sock.as_raw_fd(),
            c::SOL_LOCAL,
            c::LOCAL_PEERCRED,
            (&raw mut cred).cast::<c_void>(),
            &raw mut len,
        )
    };
    if ret != 0 {
        return None;
    }
    // The low half of the union, on these little-endian targets.
    u32::try_from(cred.cr_pid as u32 as i32)
        .ok()
        .filter(|p| *p != 0)
}

/// `struct sockaddr_un` (`unix(7)`).
#[cfg(all(feature = "local", target_os = "linux"))]
#[repr(C)]
struct SockaddrUn {
    sun_family: u16,
    sun_path: [u8; 108],
}

/// `struct sockaddr_un` on macOS.
#[cfg(all(feature = "local", not(target_os = "linux")))]
#[repr(C)]
struct SockaddrUn {
    sun_len: u8,
    sun_family: u8,
    sun_path: [u8; 104],
}

/// The size of `sun_path`: the longest Unix socket path plus its terminator.
#[cfg(all(feature = "local", target_os = "linux"))]
pub(crate) const UNIX_PATH_MAX: usize = 108;
/// The size of `sun_path`: the longest Unix socket path plus its terminator.
#[cfg(all(feature = "local", not(target_os = "linux")))]
pub(crate) const UNIX_PATH_MAX: usize = 104;

/// Encodes a filesystem path (no NUL byte, shorter than [`UNIX_PATH_MAX`]).
#[cfg(feature = "local")]
fn encode_unix(path: &[u8]) -> io::Result<(SockaddrUn, SockLen)> {
    if path.is_empty() || path.len() >= UNIX_PATH_MAX || path.contains(&0) {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let mut sa = SockaddrUn {
        #[cfg(not(target_os = "linux"))]
        sun_len: 0,
        #[cfg(not(target_os = "linux"))]
        sun_family: c::AF_UNIX as u8,
        #[cfg(target_os = "linux")]
        sun_family: c::AF_UNIX as u16,
        sun_path: [0; UNIX_PATH_MAX],
    };
    sa.sun_path[..path.len()].copy_from_slice(path);
    let len = std::mem::offset_of!(SockaddrUn, sun_path) + path.len() + 1;
    #[cfg(not(target_os = "linux"))]
    {
        sa.sun_len = len as u8;
    }
    Ok((sa, len as SockLen))
}

/// A new Unix stream socket: close-on-exec (as in `tcp_socket`), and on macOS
/// and FreeBSD with `SO_NOSIGPIPE`.
#[cfg(feature = "local")]
pub(crate) fn unix_socket() -> io::Result<OwnedFd> {
    #[cfg(any(test, net_io_shim))]
    super::shim::check(super::shim::Op::Socket)?;
    #[cfg(not(target_os = "macos"))]
    let ty = c::SOCK_STREAM | c::SOCK_CLOEXEC;
    #[cfg(target_os = "macos")]
    let ty = c::SOCK_STREAM;
    // SAFETY: socket(2) takes plain integers and returns a new descriptor or -1.
    let fd = cvt(unsafe { socket(c::AF_UNIX, ty, 0) })?;
    // SAFETY: `fd` was just returned by socket(2), is open, and is owned by no one else.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    #[cfg(target_os = "macos")]
    {
        // SAFETY: as in `tcp_socket`.
        cvt(unsafe { fcntl(owned.as_raw_fd(), c::F_SETFD, c::FD_CLOEXEC) })?;
    }
    #[cfg(not(target_os = "linux"))]
    set_int(owned.as_fd(), c::SOL_SOCKET, c::SO_NOSIGPIPE, 1)?;
    Ok(owned)
}

/// Binds a Unix socket to `path`; the file appears with the umask's permissions,
/// and nothing can connect until [`unix_listen`].
#[cfg(feature = "local")]
pub(crate) fn unix_bind(sock: Sock<'_>, path: &[u8]) -> io::Result<()> {
    let (sa, len) = encode_unix(path)?;
    // SAFETY: `sa` is a valid sockaddr_un of `len` bytes that lives for the call;
    // `sock` is open.
    cvt(unsafe { bind(sock.as_raw_fd(), (&raw const sa).cast::<c_void>(), len) }).map(drop)
}

/// Starts listening on a bound Unix socket.
#[cfg(feature = "local")]
pub(crate) fn unix_listen(sock: Sock<'_>, backlog: u32) -> io::Result<()> {
    // SAFETY: `sock` is an open, bound stream socket; listen(2) takes an int backlog.
    cvt(unsafe { listen(sock.as_raw_fd(), clamp_int(backlog)) }).map(drop)
}

/// Connects a blocking Unix socket to `path`. On Linux a full backlog makes this
/// wait up to the socket's send timeout (`SO_SNDTIMEO`).
#[cfg(feature = "local")]
pub(crate) fn unix_connect(sock: Sock<'_>, path: &[u8]) -> io::Result<()> {
    #[cfg(any(test, net_io_shim))]
    super::shim::check(super::shim::Op::Connect)?;
    let (sa, len) = encode_unix(path)?;
    // SAFETY: as in `unix_bind`.
    cvt(unsafe { connect(sock.as_raw_fd(), (&raw const sa).cast::<c_void>(), len) }).map(drop)
}

/// Accepts one Unix connection from a non-blocking listener and sets it up for
/// net-io's IO model on this OS (as [`accept`] does for TCP).
#[cfg(feature = "local")]
pub(crate) fn accept_unix(
    listener: &std::os::unix::net::UnixListener,
) -> io::Result<std::os::unix::net::UnixStream> {
    #[cfg(any(test, net_io_shim))]
    super::shim::check(super::shim::Op::Accept)?;
    let (stream, _) = listener.accept()?;
    #[cfg(target_os = "linux")]
    stream.set_nonblocking(false)?;
    #[cfg(not(target_os = "linux"))]
    {
        let setup = set_int(stream.as_fd(), c::SOL_SOCKET, c::SO_NOSIGPIPE, 1)
            .and_then(|()| stream.set_nonblocking(true));
        if setup.is_err() {
            return Err(io::Error::from_raw_os_error(errno::ECONNABORTED));
        }
    }
    Ok(stream)
}

#[cfg(test)]
mod layout {
    //! Cross-checks the declarations above against `libc` (a dev-dependency).
    use super::*;

    #[test]
    fn test_layout_constants_match_libc() {
        assert_eq!(c::AF_INET, libc::AF_INET);
        assert_eq!(c::AF_INET6, libc::AF_INET6);
        assert_eq!(c::SOCK_STREAM, libc::SOCK_STREAM);
        assert_eq!(c::SOL_SOCKET, libc::SOL_SOCKET);
        assert_eq!(c::SO_REUSEADDR, libc::SO_REUSEADDR);
        assert_eq!(c::SO_REUSEPORT, libc::SO_REUSEPORT);
        assert_eq!(c::SO_TYPE, libc::SO_TYPE);
        assert_eq!(c::SO_ERROR, libc::SO_ERROR);
        assert_eq!(c::SO_SNDBUF, libc::SO_SNDBUF);
        assert_eq!(c::SO_RCVBUF, libc::SO_RCVBUF);
        assert_eq!(c::SO_KEEPALIVE, libc::SO_KEEPALIVE);
        assert_eq!(c::SO_ACCEPTCONN, libc::SO_ACCEPTCONN);
        assert_eq!(c::IPPROTO_IP, libc::IPPROTO_IP);
        assert_eq!(c::IPPROTO_TCP, libc::IPPROTO_TCP);
        assert_eq!(c::IPPROTO_IPV6, libc::IPPROTO_IPV6);
        assert_eq!(c::IP_TTL, libc::IP_TTL);
        assert_eq!(c::IPV6_UNICAST_HOPS, libc::IPV6_UNICAST_HOPS);
        assert_eq!(c::IPV6_V6ONLY, libc::IPV6_V6ONLY);
        assert_eq!(c::TCP_NODELAY, libc::TCP_NODELAY);
        assert_eq!(c::TCP_KEEPINTVL, libc::TCP_KEEPINTVL);
        assert_eq!(c::TCP_KEEPCNT, libc::TCP_KEEPCNT);
        assert_eq!(c::TCP_FASTOPEN, libc::TCP_FASTOPEN);
        #[cfg(target_os = "linux")]
        {
            assert_eq!(c::SO_INCOMING_CPU, libc::SO_INCOMING_CPU);
            assert_eq!(c::TCP_DEFER_ACCEPT, libc::TCP_DEFER_ACCEPT);
            assert_eq!(c::TCP_USER_TIMEOUT, libc::TCP_USER_TIMEOUT);
        }
        assert_eq!(c::MSG_DONTWAIT, libc::MSG_DONTWAIT);
        assert_eq!(c::POLLIN, libc::POLLIN);
        assert_eq!(c::POLLOUT, libc::POLLOUT);
        assert_eq!(c::POLLERR, libc::POLLERR);
        assert_eq!(c::POLLHUP, libc::POLLHUP);
        assert_eq!(c::POLLNVAL, libc::POLLNVAL);
        assert_eq!(c::SHUT_RD, libc::SHUT_RD);
        assert_eq!(c::RLIMIT_NOFILE as i64, libc::RLIMIT_NOFILE as i64);
        assert_eq!(c::EINPROGRESS, libc::EINPROGRESS);
        #[cfg(target_os = "linux")]
        {
            assert_eq!(c::SOCK_CLOEXEC, libc::SOCK_CLOEXEC);
            assert_eq!(c::SO_LINGER, libc::SO_LINGER);
            assert_eq!(c::TCP_KEEPIDLE, libc::TCP_KEEPIDLE);
            assert_eq!(c::MSG_NOSIGNAL, libc::MSG_NOSIGNAL);
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(c::SO_NOSIGPIPE, libc::SO_NOSIGPIPE);
            #[cfg(target_os = "macos")]
            {
                assert_eq!(c::SO_LINGER_SEC, libc::SO_LINGER_SEC);
                assert_eq!(c::TCP_KEEPALIVE, libc::TCP_KEEPALIVE);
            }
            #[cfg(target_os = "freebsd")]
            {
                assert_eq!(c::SO_LINGER_SEC, libc::SO_LINGER);
                assert_eq!(c::TCP_KEEPALIVE, libc::TCP_KEEPIDLE);
            }
            assert_eq!(c::F_SETFD, libc::F_SETFD);
            assert_eq!(c::FD_CLOEXEC, libc::FD_CLOEXEC);
        }
    }

    #[test]
    fn test_layout_errno_match_libc() {
        use errno::*;
        assert_eq!(EPERM, libc::EPERM);
        assert_eq!(EBADF, libc::EBADF);
        assert_eq!(ENOMEM, libc::ENOMEM);
        assert_eq!(EACCES, libc::EACCES);
        assert_eq!(EINVAL, libc::EINVAL);
        assert_eq!(ENFILE, libc::ENFILE);
        assert_eq!(EMFILE, libc::EMFILE);
        assert_eq!(EPROTO, libc::EPROTO);
        assert_eq!(ENOTSOCK, libc::ENOTSOCK);
        assert_eq!(ENOPROTOOPT, libc::ENOPROTOOPT);
        #[cfg(not(target_os = "linux"))]
        assert_eq!(ENOTCONN, libc::ENOTCONN);
        assert_eq!(EOPNOTSUPP, libc::EOPNOTSUPP);
        assert_eq!(EADDRINUSE, libc::EADDRINUSE);
        assert_eq!(EADDRNOTAVAIL, libc::EADDRNOTAVAIL);
        assert_eq!(ENETUNREACH, libc::ENETUNREACH);
        assert_eq!(ECONNABORTED, libc::ECONNABORTED);
        assert_eq!(ENOBUFS, libc::ENOBUFS);
        assert_eq!(ETIMEDOUT, libc::ETIMEDOUT);
        assert_eq!(ECONNREFUSED, libc::ECONNREFUSED);
        assert_eq!(EHOSTDOWN, libc::EHOSTDOWN);
        assert_eq!(EHOSTUNREACH, libc::EHOSTUNREACH);
        #[cfg(target_os = "linux")]
        assert_eq!(ENONET, libc::ENONET);
    }

    #[test]
    fn test_layout_structs_match_libc() {
        assert_eq!(size_of::<SockaddrIn>(), size_of::<libc::sockaddr_in>());
        assert_eq!(size_of::<SockaddrIn6>(), size_of::<libc::sockaddr_in6>());
        assert_eq!(size_of::<Linger>(), size_of::<libc::linger>());
        assert_eq!(size_of::<PollFd>(), size_of::<libc::pollfd>());
        assert_eq!(size_of::<Rlimit>(), size_of::<libc::rlimit>());
        assert_eq!(size_of::<Nfds>(), size_of::<libc::nfds_t>());
        assert_eq!(size_of::<SockLen>(), size_of::<libc::socklen_t>());
        assert_eq!(size_of::<MsgHdr>(), size_of::<libc::msghdr>());
        assert_eq!(
            std::mem::offset_of!(MsgHdr, msg_iovlen),
            std::mem::offset_of!(libc::msghdr, msg_iovlen)
        );
        assert_eq!(
            std::mem::offset_of!(MsgHdr, msg_flags),
            std::mem::offset_of!(libc::msghdr, msg_flags)
        );
        assert_eq!(size_of::<IoSlice<'_>>(), size_of::<libc::iovec>());
        assert_eq!(
            std::mem::offset_of!(SockaddrIn6, sin6_addr),
            std::mem::offset_of!(libc::sockaddr_in6, sin6_addr)
        );
        assert_eq!(
            std::mem::offset_of!(SockaddrIn6, sin6_scope_id),
            std::mem::offset_of!(libc::sockaddr_in6, sin6_scope_id)
        );
        assert_eq!(
            std::mem::offset_of!(SockaddrIn, sin_addr),
            std::mem::offset_of!(libc::sockaddr_in, sin_addr)
        );
        assert_eq!(
            std::mem::offset_of!(PollFd, revents),
            std::mem::offset_of!(libc::pollfd, revents)
        );
    }

    #[cfg(feature = "local")]
    #[test]
    fn test_layout_local_matches_libc() {
        assert_eq!(c::AF_UNIX, libc::AF_UNIX);
        assert_eq!(c::SCM_RIGHTS, libc::SCM_RIGHTS);
        assert_eq!(c::MSG_CTRUNC, libc::MSG_CTRUNC);
        #[cfg(target_os = "linux")]
        {
            assert_eq!(c::SO_PEERCRED, libc::SO_PEERCRED);
            assert_eq!(c::MSG_CMSG_CLOEXEC, libc::MSG_CMSG_CLOEXEC);
            assert_eq!(size_of::<Ucred>(), size_of::<libc::ucred>());
            assert_eq!(
                std::mem::offset_of!(Ucred, uid),
                std::mem::offset_of!(libc::ucred, uid)
            );
        }
        #[cfg(target_os = "macos")]
        {
            assert_eq!(c::SOL_LOCAL, libc::SOL_LOCAL);
            assert_eq!(c::LOCAL_PEERPID, libc::LOCAL_PEERPID);
        }
        #[cfg(target_os = "freebsd")]
        {
            assert_eq!(size_of::<Xucred>(), size_of::<libc::xucred>());
            assert_eq!(c::SOL_LOCAL, libc::SOL_LOCAL);
            assert_eq!(c::LOCAL_PEERCRED, libc::LOCAL_PEERCRED);
        }
        assert_eq!(size_of::<CmsgHdr>(), size_of::<libc::cmsghdr>());
        assert_eq!(
            std::mem::offset_of!(CmsgHdr, cmsg_level),
            std::mem::offset_of!(libc::cmsghdr, cmsg_level)
        );
        assert_eq!(size_of::<SockaddrUn>(), size_of::<libc::sockaddr_un>());
        assert_eq!(
            std::mem::offset_of!(SockaddrUn, sun_path),
            std::mem::offset_of!(libc::sockaddr_un, sun_path)
        );
        for n in [0usize, 4, 8, 12, 4 * MAX_FDS] {
            #[allow(unused_unsafe)]
            // SAFETY: CMSG_SPACE and CMSG_LEN are arithmetic on their argument.
            let (space, len) = unsafe { (libc::CMSG_SPACE(n as u32), libc::CMSG_LEN(n as u32)) };
            assert_eq!(cmsg_space(n), space as usize, "CMSG_SPACE({n})");
            assert_eq!(cmsg_len(n), len as usize, "CMSG_LEN({n})");
        }
    }

    #[cfg(feature = "local")]
    #[test]
    fn test_descriptors_cross_a_socket_pair() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        let (a, b) = UnixStream::pair().unwrap();
        let (a, b) = (super::super::Stream::Unix(a), super::super::Stream::Unix(b));
        let (mut x, y) = UnixStream::pair().unwrap();
        assert_eq!(send_with_fds(&a, b"fd", &[y.as_fd()]).unwrap(), 2);
        drop(y);
        let mut slots: [Option<OwnedFd>; MAX_FDS] = [const { None }; MAX_FDS];
        let mut body = [0u8; 8];
        let got = recv_with_fds(&b, &mut body, &mut slots).unwrap();
        assert_eq!((got.bytes, got.fds, got.truncated), (2, 1, false));
        assert_eq!(&body[..2], b"fd");
        let fd = slots[0].take().unwrap();
        #[cfg(target_os = "linux")]
        {
            // SAFETY: fcntl(F_GETFD) on an open descriptor.
            let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
            assert_eq!(
                flags & libc::FD_CLOEXEC,
                libc::FD_CLOEXEC,
                "received close-on-exec"
            );
        }
        let mut y = UnixStream::from(fd);
        y.write_all(b"via").unwrap();
        let mut out = [0u8; 3];
        x.read_exact(&mut out).unwrap();
        assert_eq!(&out, b"via");
        // No descriptors, and the limits.
        assert_eq!(send_with_fds(&a, b"x", &[]).unwrap(), 1);
        let got = recv_with_fds(&b, &mut body, &mut slots).unwrap();
        assert_eq!((got.bytes, got.fds), (1, 0));
        assert!(send_with_fds(&a, b"", &[x.as_fd()]).is_err());
        let many = vec![x.as_fd(); MAX_FDS + 1];
        assert!(send_with_fds(&a, b"x", &many).is_err());
    }

    /// Edge case 81: more descriptors than net-io takes from one message
    /// ([`MAX_FDS`]) is refused like `MSG_CTRUNC`: every descriptor that arrived
    /// is closed, none leak. (The receive buffer holds more than Linux sends in
    /// one message, so the kernel never cuts it; a cut record is covered by
    /// `test_cut_record_closes_the_descriptors_it_holds`.)
    #[cfg(all(feature = "local", target_os = "linux"))]
    #[test]
    fn test_truncated_control_message_closes_every_descriptor() {
        use std::os::unix::net::UnixStream;
        let (a, b) = UnixStream::pair().unwrap();
        let (x, mut y) = UnixStream::pair().unwrap();
        let count = MAX_FDS + 6;
        let fds = vec![x.as_raw_fd(); count];
        let data_len = 4 * count;
        // SAFETY: CMSG_SPACE and CMSG_LEN are arithmetic on their argument.
        let (space, len) = unsafe {
            (
                libc::CMSG_SPACE(data_len as u32),
                libc::CMSG_LEN(data_len as u32),
            )
        };
        let mut control = vec![0u64; (space as usize).div_ceil(8)];
        let body = [7u8; 3];
        let mut iov = libc::iovec {
            iov_base: body.as_ptr() as *mut c_void,
            iov_len: body.len(),
        };
        // SAFETY: a zeroed msghdr is valid; every pointer set below points at a
        // live local of the stated length, and the cmsg macros stay inside `control`.
        unsafe {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &raw mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast::<c_void>();
            msg.msg_controllen = space as usize;
            let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = len as usize;
            std::ptr::copy_nonoverlapping(
                fds.as_ptr().cast::<u8>(),
                libc::CMSG_DATA(cmsg),
                data_len,
            );
            assert_eq!(libc::sendmsg(a.as_raw_fd(), &raw const msg, 0), 3);
        }
        // The message holds the only other copies of `x`.
        drop(x);
        let b = super::super::Stream::Unix(b);
        let mut slots: [Option<OwnedFd>; MAX_FDS] = [const { None }; MAX_FDS];
        let mut out = [0u8; 8];
        let got = recv_with_fds(&b, &mut out, &mut slots).unwrap();
        assert!(got.truncated);
        assert_eq!((got.bytes, got.fds), (3, 0));
        assert!(slots.iter().all(Option::is_none));
        // `y` reads end of stream only once every copy of `x` is closed.
        y.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut one = [0u8; 1];
        assert_eq!(
            std::io::Read::read(&mut y, &mut one).unwrap(),
            0,
            "a copy leaked"
        );
    }

    /// What macOS and FreeBSD hand back when a message carries more descriptors
    /// than the buffer holds: one record, cut short, with its original `cmsg_len`.
    /// The descriptors whose numbers arrived are closed, none kept.
    #[cfg(feature = "local")]
    #[test]
    fn test_cut_record_closes_the_descriptors_it_holds() {
        use std::os::fd::IntoRawFd;
        use std::os::unix::net::UnixStream;
        let (x, mut y) = UnixStream::pair().unwrap();
        let hdr = cmsg_align(size_of::<CmsgHdr>());
        let level_at = size_of::<CmsgHdr>() - 2 * size_of::<c_int>();
        let mut control = CmsgBuf([0; cmsg_space(4 * MAX_FDS)]);
        let claimed = cmsg_len(4 * 10);
        #[cfg(target_os = "linux")]
        control.0[..size_of::<usize>()].copy_from_slice(&claimed.to_ne_bytes());
        #[cfg(not(target_os = "linux"))]
        control.0[..4].copy_from_slice(&(claimed as u32).to_ne_bytes());
        control.0[level_at..level_at + 4].copy_from_slice(&c::SOL_SOCKET.to_ne_bytes());
        control.0[level_at + 4..level_at + 8].copy_from_slice(&c::SCM_RIGHTS.to_ne_bytes());
        for i in 0..3 {
            let raw = x.try_clone().unwrap().into_raw_fd();
            control.0[hdr + 4 * i..hdr + 4 * i + 4].copy_from_slice(&raw.to_ne_bytes());
        }
        // Three whole numbers and half of a fourth reached the buffer.
        let used = hdr + 4 * 3 + 2;
        let mut slots: [Option<OwnedFd>; MAX_FDS] = [const { None }; MAX_FDS];
        // SAFETY: the three numbers are open copies of `x` that nothing owns.
        let (count, cut) = unsafe { take_fds(&control.0[..used], true, &mut slots) };
        assert_eq!((count, cut), (0, true));
        assert!(slots.iter().all(Option::is_none));
        drop(x);
        y.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut one = [0u8; 1];
        assert_eq!(
            std::io::Read::read(&mut y, &mut one).unwrap(),
            0,
            "a copy leaked"
        );
    }

    #[cfg(feature = "local")]
    #[test]
    fn test_peer_credentials_of_a_pair() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let (pid, uid, gid) = peer_credentials(a.as_fd()).unwrap();
        // SAFETY: getuid and getgid cannot fail.
        let (me, group) = unsafe { (libc::getuid(), libc::getgid()) };
        assert_eq!((uid, gid), (me, group));
        assert_eq!(pid, Some(std::process::id()));
    }

    #[cfg(feature = "local")]
    #[test]
    fn test_unix_bind_listen_connect_accept() {
        let dir = std::env::temp_dir().join(format!("net-io-sys-{}", std::process::id()));
        let _ = std::fs::create_dir(&dir);
        let path = dir.join("s.sock");
        let _ = std::fs::remove_file(&path);
        let p = path.as_os_str().as_encoded_bytes();
        let l = unix_socket().unwrap();
        unix_bind(l.as_fd(), p).unwrap();
        // Bound but not listening: a connect is refused.
        let c = unix_socket().unwrap();
        assert!(unix_connect(c.as_fd(), p).is_err());
        unix_listen(l.as_fd(), 8).unwrap();
        let l = std::os::unix::net::UnixListener::from(l);
        l.set_nonblocking(true).unwrap();
        let c = unix_socket().unwrap();
        unix_connect(c.as_fd(), p).unwrap();
        let s = accept_unix(&l).unwrap();
        assert!(peer_credentials(s.as_fd()).is_ok());
        assert!(encode_unix(&[b'a'; UNIX_PATH_MAX]).is_err());
        assert!(encode_unix(&[b'a'; UNIX_PATH_MAX - 1]).is_ok());
        assert!(encode_unix(b"a\0b").is_err());
        assert!(encode_unix(b"").is_err());
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[cfg(feature = "udp")]
    #[test]
    fn test_layout_udp_matches_libc() {
        assert_eq!(c::SOCK_DGRAM, libc::SOCK_DGRAM);
        assert_eq!(c::MSG_TRUNC, libc::MSG_TRUNC);
        assert!(size_of::<AddrBuf>() >= size_of::<libc::sockaddr_storage>());
    }

    #[cfg(feature = "udp")]
    #[test]
    fn test_udp_recv_reports_truncation_and_source() {
        let a = udp_bind("127.0.0.1:0".parse().unwrap(), true).unwrap();
        let b = udp_bind("[::1]:0".parse().unwrap(), true).unwrap();
        let to = a.local_addr().unwrap();
        let src = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        src.send_to(&[1u8; 100], to).unwrap();
        let mut small = [0u8; 10];
        let (n, from, truncated) = udp_recv_from(a.as_fd(), &mut small).unwrap();
        assert!(truncated);
        assert_eq!(from, src.local_addr().unwrap());
        #[cfg(target_os = "linux")]
        assert_eq!(n, 100);
        #[cfg(not(target_os = "linux"))]
        assert_eq!(n, 10);
        let src6 = std::net::UdpSocket::bind("[::1]:0").unwrap();
        src6.send_to(&[], b.local_addr().unwrap()).unwrap();
        let (n, from, truncated) = udp_recv_from(b.as_fd(), &mut small).unwrap();
        assert_eq!((n, truncated), (0, false));
        assert_eq!(from, src6.local_addr().unwrap());
    }

    #[test]
    fn test_monotonic_micros_matches_libc() {
        assert_eq!(i64::from(c::CLOCK_MONOTONIC), libc::CLOCK_MONOTONIC as i64);
        assert_eq!(size_of::<Timespec>(), size_of::<libc::timespec>());
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let ours = monotonic_micros();
        // SAFETY: a live timespec.
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut ts) };
        let theirs = ts.tv_sec as u64 * 1_000_000 + ts.tv_nsec as u64 / 1_000;
        assert!(theirs >= ours && theirs - ours < 1_000_000);
    }

    #[test]
    fn test_layout_inherit_matches_libc() {
        assert_eq!(c::AF_UNIX_FAMILY, libc::AF_UNIX);
        assert_eq!(c::F_GETFD, libc::F_GETFD);
        #[cfg(target_os = "linux")]
        {
            assert_eq!(c::F_SETFD, libc::F_SETFD);
            assert_eq!(c::FD_CLOEXEC, libc::FD_CLOEXEC);
            assert_eq!(c::SYS_PIDFD_OPEN, libc::SYS_pidfd_open);
        }
        let _: unsafe extern "C" fn(c_int, *mut c_void, *mut SockLen) -> c_int = getsockname;
        #[cfg(feature = "local")]
        {
            let _: unsafe extern "C" fn() -> u32 = geteuid;
            // SAFETY: geteuid cannot fail.
            assert_eq!(effective_uid(), unsafe { libc::geteuid() });
        }
    }

    #[test]
    fn test_listener_kind_tells_listeners_apart() {
        use super::super::{KindError, SockKind};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        assert_eq!(
            listener_kind(l.as_fd()).unwrap(),
            SockKind::Tcp(l.local_addr().unwrap())
        );
        let c = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        assert!(matches!(
            listener_kind(c.as_fd()),
            Err(KindError::NotListening)
        ));
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(matches!(
            listener_kind(u.as_fd()),
            Err(KindError::WrongKind)
        ));
        let f = std::fs::File::open("/dev/null").unwrap();
        assert!(matches!(
            listener_kind(f.as_fd()),
            Err(KindError::NotASocket)
        ));
        let dir = std::env::temp_dir().join(format!("nio-kind-{}", std::process::id()));
        let _ = std::fs::create_dir(&dir);
        let path = dir.join("k.sock");
        let _ = std::fs::remove_file(&path);
        let ul = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert_eq!(
            listener_kind(ul.as_fd()).unwrap(),
            SockKind::Unix(path.as_os_str().as_encoded_bytes().to_vec())
        );
        drop(ul);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
        assert!(matches!(inherited_kind(-1), Err(KindError::NotASocket)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_pidfd_inode_is_stable() {
        match pidfd_inode() {
            Ok(a) => assert_eq!(a, pidfd_inode().unwrap()),
            // Kernels before 5.3 have no pidfd_open.
            Err(e) => assert_eq!(e.raw_os_error(), Some(libc::ENOSYS)),
        }
    }

    #[test]
    fn test_layout_signatures_match_libc() {
        // A mismatch in argument or return types fails to compile.
        let _: unsafe extern "C" fn(c_int, c_int, c_int) -> c_int = socket;
        let _: unsafe extern "C" fn(c_int, c_int, c_int) -> c_int = libc::socket;
        let _: unsafe extern "C" fn(c_int, c_int) -> c_int = listen;
        let _: unsafe extern "C" fn(c_int, c_int) -> c_int = libc::listen;
        let _: unsafe extern "C" fn(c_int, c_int) -> c_int = shutdown;
        let _: unsafe extern "C" fn(c_int, c_int) -> c_int = libc::shutdown;
        let _: unsafe extern "C" fn(c_int, *const c_void, usize, c_int) -> isize = c_send;
        let _: unsafe extern "C" fn(c_int, *const c_void, usize, c_int) -> isize = libc::send;
    }

    #[test]
    fn test_encode_addr_round_trips_through_std() {
        let mut buf = [0u8; 28];
        let len = encode_addr("127.0.0.1:8080".parse().unwrap(), &mut buf);
        assert_eq!(len, 16);
        // SAFETY (test): `buf` holds a sockaddr_in written by encode_addr.
        let sa: libc::sockaddr_in = unsafe { std::ptr::read_unaligned(buf.as_ptr().cast()) };
        assert_eq!(u16::from_be(sa.sin_port), 8080);
        assert_eq!(sa.sin_addr.s_addr.to_ne_bytes(), [127, 0, 0, 1]);
    }

    #[test]
    fn test_descriptor_limit_reads_rlimit() {
        // SAFETY (test): getrlimit writes the struct.
        let mut r = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut r) };
        let expected = if r.rlim_cur == libc::RLIM_INFINITY {
            None
        } else {
            #[allow(clippy::unnecessary_cast)] // i64 on FreeBSD
            Some(r.rlim_cur as u64)
        };
        assert_eq!(descriptor_limit(), expected);
    }

    #[test]
    fn test_wake_ends_wait() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let w = Wake::new().unwrap();
        w.wake();
        let r = wait(
            l.as_fd(),
            Interest::Read,
            Some(&w),
            Some(Duration::from_secs(5)),
        )
        .unwrap();
        assert_eq!(r, Ready::Woken);
        let r = wait(
            l.as_fd(),
            Interest::Read,
            Some(&w),
            Some(Duration::from_millis(10)),
        )
        .unwrap();
        assert_eq!(r, Ready::TimedOut);
    }

    #[test]
    fn test_listener_options_and_listening_check() {
        let p = ListenParams {
            reuse_address: true,
            reuse_port: false,
            ipv6_only: true,
            send_buffer: Some(64 * 1024),
            receive_buffer: None,
            backlog: 16,
            defer_accept: None,
            fast_open: None,
            incoming_cpu: None,
        };
        let l = tcp_listener("127.0.0.1:0".parse().unwrap(), &p).unwrap();
        assert!(is_listening_stream(l.as_fd()).unwrap());
        let s = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        assert!(!is_listening_stream(s.as_fd()).unwrap());
    }

    #[test]
    fn test_linger_and_keepalive_round_trip() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let s = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        set_linger(s.as_fd(), Some(Duration::ZERO)).unwrap();
        assert_eq!(linger(s.as_fd()).unwrap(), Some(Duration::ZERO));
        set_linger(s.as_fd(), None).unwrap();
        assert_eq!(linger(s.as_fd()).unwrap(), None);
        set_keepalive(
            s.as_fd(),
            Some((Duration::from_secs(30), Duration::from_secs(5), 4)),
        )
        .unwrap();
        assert_eq!(
            keepalive(s.as_fd()).unwrap(),
            Some((Duration::from_secs(30), Duration::from_secs(5), 4))
        );
        set_nodelay(s.as_fd(), true).unwrap();
        assert!(nodelay(s.as_fd()).unwrap());
        set_ttl(s.as_fd(), false, 33).unwrap();
        assert_eq!(ttl(s.as_fd(), false).unwrap(), 33);
    }
}
