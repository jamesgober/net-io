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
#[cfg(target_os = "macos")]
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

/// Error numbers net-io classifies (`intro(2)` on macOS).
#[cfg(target_os = "macos")]
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
    pub const EPROTO: i32 = 100;
    pub const EOPNOTSUPP: i32 = 102;
    /// macOS has no ENONET; a value no error carries.
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
    pub const SOCK_STREAM: c_int = 1;
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

#[cfg(target_os = "macos")]
mod c {
    use std::ffi::{c_int, c_short};
    #[cfg(feature = "local")]
    pub const AF_UNIX: c_int = 1;
    pub const AF_INET: c_int = 2;
    pub const AF_INET6: c_int = 30;
    pub const SOCK_STREAM: c_int = 1;
    pub const SOL_SOCKET: c_int = 0xffff;
    pub const SO_ACCEPTCONN: c_int = 0x2;
    pub const SO_REUSEADDR: c_int = 0x4;
    pub const SO_KEEPALIVE: c_int = 0x8;
    pub const SO_REUSEPORT: c_int = 0x200;
    pub const SO_SNDBUF: c_int = 0x1001;
    pub const SO_RCVBUF: c_int = 0x1002;
    pub const SO_ERROR: c_int = 0x1007;
    pub const SO_TYPE: c_int = 0x1008;
    pub const SO_NOSIGPIPE: c_int = 0x1022;
    pub const SO_LINGER_SEC: c_int = 0x1080;
    pub const IPPROTO_IP: c_int = 0;
    pub const IPPROTO_TCP: c_int = 6;
    pub const IPPROTO_IPV6: c_int = 41;
    pub const IP_TTL: c_int = 4;
    pub const IPV6_UNICAST_HOPS: c_int = 4;
    pub const IPV6_V6ONLY: c_int = 27;
    pub const TCP_NODELAY: c_int = 0x1;
    pub const TCP_KEEPALIVE: c_int = 0x10;
    pub const TCP_KEEPINTVL: c_int = 0x101;
    pub const TCP_KEEPCNT: c_int = 0x102;
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
    #[cfg(feature = "local")]
    pub const SOL_LOCAL: c_int = 0;
    #[cfg(feature = "local")]
    pub const LOCAL_PEERPID: c_int = 0x002;
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

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrIn {
    sin_len: u8,
    sin_family: u8,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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
#[cfg(target_os = "linux")]
const _: () = assert!(size_of::<MsgHdr>() == 56);
#[cfg(target_os = "macos")]
const _: () = assert!(size_of::<MsgHdr>() == 48);

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
    #[cfg(target_os = "macos")]
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    #[cfg(feature = "local")]
    fn recvmsg(fd: c_int, msg: *mut MsgHdr, flags: c_int) -> isize;
    #[cfg(all(feature = "local", target_os = "macos"))]
    fn getpeereid(fd: c_int, euid: *mut u32, egid: *mut u32) -> c_int;
}

/// A borrowed socket handle.
pub(crate) type Sock<'a> = BorrowedFd<'a>;
/// A raw socket handle (used only inside the kill guard).
pub(crate) type RawSock = RawFd;

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
                #[cfg(target_os = "macos")]
                sin_len: size_of::<SockaddrIn>() as u8,
                #[cfg(target_os = "macos")]
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
                #[cfg(target_os = "macos")]
                sin6_len: size_of::<SockaddrIn6>() as u8,
                #[cfg(target_os = "macos")]
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

/// A new TCP socket for `addr`'s family: close-on-exec, and on macOS with
/// `SO_NOSIGPIPE` so a write to a closed peer never raises `SIGPIPE`.
pub(crate) fn tcp_socket(v6: bool) -> io::Result<OwnedFd> {
    #[cfg(any(test, net_io_shim))]
    super::shim::check(super::shim::Op::Socket)?;
    let domain = if v6 { c::AF_INET6 } else { c::AF_INET };
    #[cfg(target_os = "linux")]
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
        set_int(owned.as_fd(), c::SOL_SOCKET, c::SO_NOSIGPIPE, 1)?;
    }
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
    bind_to(fd.as_fd(), addr)?;
    // SAFETY: `fd` is an open, bound stream socket; listen(2) takes an int backlog.
    cvt(unsafe { listen(fd.as_raw_fd(), clamp_int(p.backlog)) })?;
    let listener = TcpListener::from(fd);
    // Listeners are always non-blocking: accepts wait in poll with a wake channel.
    listener.set_nonblocking(true)?;
    Ok(listener)
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
        #[cfg(target_os = "macos")]
        Err(e) if e.raw_os_error() == Some(errno::ENOPROTOOPT) => bound_without_peer(sock)?,
        Err(e) => return Err(e),
    };
    Ok(listening && stream)
}

/// Whether `sock` is bound to a port and has no peer (the macOS listener check).
#[cfg(target_os = "macos")]
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

/// Accepts one connection. On Linux `std` uses `accept4(SOCK_CLOEXEC)` and the
/// socket is blocking; on macOS `std` sets close-on-exec after `accept`, this adds
/// `SO_NOSIGPIPE`, and the socket stays non-blocking (D-083).
pub(crate) fn accept(listener: &TcpListener) -> io::Result<(TcpStream, SocketAddr)> {
    #[cfg(any(test, net_io_shim))]
    super::shim::check(super::shim::Op::Accept)?;
    let (stream, peer) = listener.accept()?;
    #[cfg(target_os = "macos")]
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
pub(crate) const WAIT_BEFORE_RECV: bool = cfg!(target_os = "macos");

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
        send_once(stream, buf)
    })
}

/// One `send` system call with net-io's flags.
fn send_once(stream: &super::Stream, buf: &[u8]) -> io::Result<usize> {
    #[cfg(target_os = "linux")]
    let flags = c::MSG_DONTWAIT | c::MSG_NOSIGNAL;
    #[cfg(target_os = "macos")]
    let flags = c::MSG_DONTWAIT;
    {
        // SAFETY: `stream` is open for the call; `buf` is a live slice of `buf.len()`
        // bytes. MSG_NOSIGNAL (Linux) and SO_NOSIGPIPE (set at creation on macOS)
        // keep a closed peer from raising SIGPIPE.
        let n = unsafe {
            c_send(
                stream.sock().as_raw_fd(),
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
    let bufs = &bufs[..bufs.len().min(MAX_SLICES)];
    #[cfg(target_os = "linux")]
    let flags = c::MSG_DONTWAIT | c::MSG_NOSIGNAL;
    #[cfg(target_os = "macos")]
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
            return send_once(stream, &first[..n.min(first.len())]);
        }
        let msg = MsgHdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: bufs.as_ptr().cast::<IoSlice<'static>>(),
            #[cfg(target_os = "linux")]
            msg_iovlen: bufs.len(),
            #[cfg(target_os = "macos")]
            msg_iovlen: bufs.len() as c_int,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        // SAFETY: `IoSlice` is documented as ABI-compatible with `struct iovec` on Unix;
        // `bufs` (at most 64 slices) and the bytes they point to live for the call;
        // `msg` carries no name and no control data. MSG_DONTWAIT keeps the call from blocking.
        let n = unsafe { sendmsg(stream.sock().as_raw_fd(), &raw const msg, flags) };
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
    #[cfg(target_os = "macos")]
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
    #[cfg(target_os = "macos")]
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
            #[cfg(target_os = "macos")]
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
    #[cfg(target_os = "macos")]
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
    if ret != 0 || r.rlim_cur == u64::MAX {
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
#[cfg(all(feature = "local", target_os = "linux"))]
#[repr(C)]
struct CmsgHdr {
    cmsg_len: usize,
    cmsg_level: c_int,
    cmsg_type: c_int,
}

/// `struct cmsghdr` on macOS: `socklen_t` for the length.
#[cfg(all(feature = "local", target_os = "macos"))]
#[repr(C)]
struct CmsgHdr {
    cmsg_len: u32,
    cmsg_level: c_int,
    cmsg_type: c_int,
}

/// `CMSG_ALIGN`: to `size_t` on Linux, to 4 bytes on macOS.
#[cfg(feature = "local")]
const CMSG_ALIGN_TO: usize = if cfg!(target_os = "linux") {
    size_of::<usize>()
} else {
    4
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
        #[cfg(target_os = "macos")]
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
        #[cfg(target_os = "macos")]
        msg_iovlen: 1,
        msg_control: if space == 0 {
            std::ptr::null_mut()
        } else {
            control.0.as_mut_ptr().cast::<c_void>()
        },
        #[cfg(target_os = "linux")]
        msg_controllen: space,
        #[cfg(target_os = "macos")]
        msg_controllen: space as u32,
        msg_flags: 0,
    };
    #[cfg(target_os = "linux")]
    let flags = c::MSG_DONTWAIT | c::MSG_NOSIGNAL;
    #[cfg(target_os = "macos")]
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
    /// The control data did not fit: every descriptor received was closed.
    pub(crate) truncated: bool,
}

/// Receives into `body` and stores attached descriptors (close-on-exec) into
/// `into` from index 0. Like [`recv`]: on Linux it blocks under the receive
/// timeout, on macOS the socket is non-blocking and the caller waited first.
/// On a truncated control message every descriptor received is closed and
/// `truncated` is set.
#[cfg(feature = "local")]
pub(crate) fn recv_with_fds(
    stream: &super::Stream,
    body: &mut [u8],
    into: &mut [Option<OwnedFd>; MAX_FDS],
) -> io::Result<Received> {
    let mut control = CmsgBuf([0; cmsg_space(4 * MAX_FDS)]);
    let mut iov = [io::IoSliceMut::new(body)];
    let mut msg = MsgHdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: iov.as_mut_ptr().cast::<IoSlice<'static>>(),
        #[cfg(target_os = "linux")]
        msg_iovlen: 1,
        #[cfg(target_os = "macos")]
        msg_iovlen: 1,
        msg_control: control.0.as_mut_ptr().cast::<c_void>(),
        #[cfg(target_os = "linux")]
        msg_controllen: control.0.len(),
        #[cfg(target_os = "macos")]
        msg_controllen: control.0.len() as u32,
        msg_flags: 0,
    };
    #[cfg(target_os = "linux")]
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
    let used = (msg.msg_controllen as usize).min(control.0.len());
    let truncated = msg.msg_flags & c::MSG_CTRUNC != 0;
    let hdr = cmsg_align(size_of::<CmsgHdr>());
    let level_at = size_of::<CmsgHdr>() - 2 * size_of::<c_int>();
    let mut count = 0;
    let mut off = 0;
    while off + size_of::<CmsgHdr>() <= used {
        let bytes = &control.0[off..used];
        #[cfg(target_os = "linux")]
        let len = usize::from_ne_bytes(
            bytes[..size_of::<usize>()]
                .try_into()
                .unwrap_or([0; size_of::<usize>()]),
        );
        #[cfg(target_os = "macos")]
        let len = u32::from_ne_bytes(bytes[..4].try_into().unwrap_or([0; 4])) as usize;
        let level =
            c_int::from_ne_bytes(bytes[level_at..level_at + 4].try_into().unwrap_or([0; 4]));
        let kind = c_int::from_ne_bytes(
            bytes[level_at + 4..level_at + 8]
                .try_into()
                .unwrap_or([0; 4]),
        );
        if len < hdr || off + len > used {
            break;
        }
        if level == c::SOL_SOCKET && kind == c::SCM_RIGHTS {
            for i in 0..(len - hdr) / 4 {
                let at = off + hdr + 4 * i;
                let raw =
                    RawFd::from_ne_bytes(control.0[at..at + 4].try_into().unwrap_or([0xFF; 4]));
                if raw < 0 {
                    continue;
                }
                // SAFETY: the kernel just installed `raw` in this process for us
                // (SCM_RIGHTS); nothing else owns it.
                let owned = unsafe { OwnedFd::from_raw_fd(raw) };
                #[cfg(target_os = "macos")]
                {
                    // SAFETY: `owned` is open; F_SETFD with FD_CLOEXEC takes an int.
                    unsafe { fcntl(owned.as_raw_fd(), c::F_SETFD, c::FD_CLOEXEC) };
                }
                if count < MAX_FDS && !truncated {
                    into[count] = Some(owned);
                    count += 1;
                }
                // Otherwise `owned` drops here and the descriptor is closed.
            }
        }
        off += cmsg_align(len);
    }
    if truncated {
        for slot in into.iter_mut().take(count) {
            *slot = None;
        }
        count = 0;
    }
    Ok(Received {
        bytes: n,
        fds: count,
        truncated,
    })
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
#[cfg(all(feature = "local", target_os = "macos"))]
pub(crate) fn peer_credentials(sock: Sock<'_>) -> io::Result<(Option<u32>, u32, u32)> {
    let mut uid = 0u32;
    let mut gid = 0u32;
    // SAFETY: `sock` is open; `uid` and `gid` are live locals getpeereid(3) writes.
    cvt(unsafe { getpeereid(sock.as_raw_fd(), &raw mut uid, &raw mut gid) })?;
    let pid = get_int(sock, c::SOL_LOCAL, c::LOCAL_PEERPID)
        .ok()
        .and_then(|p| u32::try_from(p).ok());
    Ok((pid, uid, gid))
}

/// `struct sockaddr_un` (`unix(7)`).
#[cfg(all(feature = "local", target_os = "linux"))]
#[repr(C)]
struct SockaddrUn {
    sun_family: u16,
    sun_path: [u8; 108],
}

/// `struct sockaddr_un` on macOS.
#[cfg(all(feature = "local", target_os = "macos"))]
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
#[cfg(all(feature = "local", target_os = "macos"))]
pub(crate) const UNIX_PATH_MAX: usize = 104;

/// Encodes a filesystem path (no NUL byte, shorter than [`UNIX_PATH_MAX`]).
#[cfg(feature = "local")]
fn encode_unix(path: &[u8]) -> io::Result<(SockaddrUn, SockLen)> {
    if path.is_empty() || path.len() >= UNIX_PATH_MAX || path.contains(&0) {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let mut sa = SockaddrUn {
        #[cfg(target_os = "macos")]
        sun_len: 0,
        #[cfg(target_os = "macos")]
        sun_family: c::AF_UNIX as u8,
        #[cfg(target_os = "linux")]
        sun_family: c::AF_UNIX as u16,
        sun_path: [0; UNIX_PATH_MAX],
    };
    sa.sun_path[..path.len()].copy_from_slice(path);
    let len = std::mem::offset_of!(SockaddrUn, sun_path) + path.len() + 1;
    #[cfg(target_os = "macos")]
    {
        sa.sun_len = len as u8;
    }
    Ok((sa, len as SockLen))
}

/// A new Unix stream socket: close-on-exec, and on macOS with `SO_NOSIGPIPE`.
#[cfg(feature = "local")]
pub(crate) fn unix_socket() -> io::Result<OwnedFd> {
    #[cfg(any(test, net_io_shim))]
    super::shim::check(super::shim::Op::Socket)?;
    #[cfg(target_os = "linux")]
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
        set_int(owned.as_fd(), c::SOL_SOCKET, c::SO_NOSIGPIPE, 1)?;
    }
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
    #[cfg(target_os = "macos")]
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
        #[cfg(target_os = "macos")]
        {
            assert_eq!(c::SO_NOSIGPIPE, libc::SO_NOSIGPIPE);
            assert_eq!(c::SO_LINGER_SEC, libc::SO_LINGER_SEC);
            assert_eq!(c::TCP_KEEPALIVE, libc::TCP_KEEPALIVE);
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
        #[cfg(target_os = "macos")]
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

    /// Edge case 81: more descriptors than the receive buffer holds sets
    /// `MSG_CTRUNC`; every descriptor that arrived is closed, none leak.
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
            Some(r.rlim_cur)
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
