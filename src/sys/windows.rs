//! Windows (x86_64, aarch64; MSVC and GNU).
//!
//! Declarations come from the Windows SDK headers (`winsock2.h`, `ws2def.h`,
//! `ws2ipdef.h`, `mstcpip.h`, `handleapi.h`); every constant, struct layout,
//! and function signature is checked against `windows-sys` by the `layout`
//! tests at the bottom of this file. Reference: Microsoft Learn, Winsock
//! functions and `SOL_SOCKET` / `IPPROTO_TCP` / `IPPROTO_IPV6` socket options.
//!
//! Sockets in net-io's blocking driver are non-blocking on Windows and every
//! wait is `WSAPoll` with a wake socket: a socket whose blocking receive or send
//! timed out is documented as being in an indeterminate state (decision D-052).

use std::ffi::c_void;
use std::io::{self, IoSlice};
use std::mem::size_of;
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::windows::io::{
    AsRawHandle, AsRawSocket, AsSocket, BorrowedSocket, FromRawHandle, FromRawSocket, OwnedHandle,
    OwnedSocket, RawSocket,
};
use std::sync::Once;
use std::time::Duration;

use super::{Interest, Ready, poll_millis, retry_interrupted};

pub(super) type Socket = usize;

/// Winsock error codes net-io classifies.
pub(crate) mod errno {
    pub const WSAEBADF: i32 = 10009;
    pub const WSAEACCES: i32 = 10013;
    pub const WSAEINVAL: i32 = 10022;
    pub const WSAEMFILE: i32 = 10024;
    pub const WSAENOTSOCK: i32 = 10038;
    pub const WSAEADDRINUSE: i32 = 10048;
    pub const WSAEADDRNOTAVAIL: i32 = 10049;
    pub const WSAENETUNREACH: i32 = 10051;
    pub const WSAENOBUFS: i32 = 10055;
    pub const WSAETIMEDOUT: i32 = 10060;
    pub const WSAECONNREFUSED: i32 = 10061;
    pub const WSAEHOSTUNREACH: i32 = 10065;
    #[cfg(feature = "udp")]
    pub const WSAEMSGSIZE: i32 = 10040;
}

/// How an `accept` failure is handled (FR-9, FR-10). Socket handles do not come
/// from a small table on Windows, so exhaustion is handled with the pause alone.
pub(crate) fn classify_accept(e: &io::Error) -> super::AcceptFailure {
    use super::AcceptFailure as F;
    use errno::*;
    match e.raw_os_error() {
        Some(WSAEMFILE | WSAENOBUFS) => F::Pressure,
        Some(WSAEBADF | WSAEINVAL | WSAENOTSOCK) => F::ListenerFailed,
        _ => F::PerConnection,
    }
}

/// Maps a bind or connect error to its own variant.
pub(crate) fn classify_addr_error(e: &io::Error) -> super::AddrFailure {
    use super::AddrFailure as F;
    use errno::*;
    match e.raw_os_error() {
        Some(WSAEADDRINUSE) => F::InUse,
        Some(WSAEADDRNOTAVAIL) => F::NotAvailable,
        Some(WSAEACCES) => F::Permission,
        Some(WSAECONNREFUSED) => F::Refused,
        Some(WSAEHOSTUNREACH) => F::HostUnreachable,
        Some(WSAENETUNREACH) => F::NetworkUnreachable,
        Some(WSAETIMEDOUT) => F::TimedOut,
        _ => F::Other,
    }
}

pub(super) mod c {
    #[cfg(feature = "local")]
    pub const AF_UNIX: i32 = 1;
    pub const AF_INET: i32 = 2;
    pub const AF_INET6: i32 = 23;
    pub const SOCK_STREAM: i32 = 1;
    #[cfg(feature = "udp")]
    pub const SOCK_DGRAM: i32 = 2;
    #[cfg(feature = "udp")]
    pub const IPPROTO_UDP: i32 = 17;
    #[cfg(feature = "udp")]
    pub const SIO_UDP_CONNRESET: u32 = 0x9800_000C;
    pub const IPPROTO_IP: i32 = 0;
    pub const IPPROTO_TCP: i32 = 6;
    pub const IPPROTO_IPV6: i32 = 41;
    pub const SOL_SOCKET: i32 = 0xffff;
    pub const SO_ACCEPTCONN: i32 = 0x2;
    pub const SO_REUSEADDR: i32 = 0x4;
    pub const SO_EXCLUSIVEADDRUSE: i32 = !SO_REUSEADDR;
    pub const SO_KEEPALIVE: i32 = 0x8;
    pub const SO_LINGER: i32 = 0x80;
    pub const SO_SNDBUF: i32 = 0x1001;
    pub const SO_RCVBUF: i32 = 0x1002;
    pub const SO_ERROR: i32 = 0x1007;
    pub const SO_TYPE: i32 = 0x1008;
    pub const TCP_NODELAY: i32 = 0x1;
    pub const TCP_KEEPIDLE: i32 = 3;
    pub const TCP_MAXRT: i32 = 5;
    pub const TCP_FASTOPEN: i32 = 15;
    pub const TCP_KEEPCNT: i32 = 16;
    pub const TCP_KEEPINTVL: i32 = 17;
    pub const IP_TTL: i32 = 4;
    pub const IPV6_UNICAST_HOPS: i32 = 4;
    pub const IPV6_V6ONLY: i32 = 27;
    pub const POLLRDNORM: i16 = 0x100;
    pub const POLLWRNORM: i16 = 0x10;
    pub const WSA_FLAG_OVERLAPPED: u32 = 0x01;
    pub const WSA_FLAG_NO_HANDLE_INHERIT: u32 = 0x80;
    pub const HANDLE_FLAG_INHERIT: u32 = 0x1;
    pub const INVALID_SOCKET: usize = !0;
    pub const SOCKET_ERROR: i32 = -1;
    pub const WSAEINTR: i32 = 10004;
    pub const WSAEWOULDBLOCK: i32 = 10035;
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrIn6 {
    sin6_family: u16,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    sin6_scope_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Linger {
    l_onoff: u16,
    l_linger: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct WsaPollFd {
    fd: Socket,
    events: i16,
    revents: i16,
}

#[repr(C)]
struct WsaData {
    w_version: u16,
    w_high_version: u16,
    i_max_sockets: u16,
    i_max_udp_dg: u16,
    lp_vendor_info: *mut u8,
    sz_description: [u8; 257],
    sz_system_status: [u8; 129],
}

/// `OVERLAPPED`. The kernel writes `internal` and `internal_high`.
#[cfg(any(feature = "reactor", feature = "local"))]
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct Overlapped {
    pub(super) internal: usize,
    pub(super) internal_high: usize,
    pub(super) offset: u32,
    pub(super) offset_high: u32,
    pub(super) event: usize,
}

/// `WSAPROTOCOL_INFOW`.
#[cfg(any(feature = "reactor", feature = "local"))]
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct WsaProtocolInfo {
    pub(super) service_flags1: u32,
    service_flags2: u32,
    service_flags3: u32,
    service_flags4: u32,
    provider_flags: u32,
    provider_id: [u8; 16],
    catalog_entry_id: u32,
    chain_len: i32,
    chain: [u32; 7],
    version: i32,
    address_family: i32,
    max_sockaddr: i32,
    min_sockaddr: i32,
    socket_type: i32,
    pub(super) i_protocol: i32,
    protocol_max_offset: i32,
    network_byte_order: i32,
    security_scheme: i32,
    message_size: u32,
    provider_reserved: u32,
    protocol: [u16; 256],
}

const _: () = assert!(size_of::<SockaddrIn>() == 16);
#[cfg(any(feature = "reactor", feature = "local"))]
const _: () = assert!(size_of::<WsaProtocolInfo>() == 628);
const _: () = assert!(size_of::<SockaddrIn6>() == 28);
const _: () = assert!(size_of::<Linger>() == 4);
const _: () = assert!(size_of::<WsaPollFd>() == 16);
const _: () = assert!(size_of::<WsaData>() == 408);

#[link(name = "ws2_32")]
unsafe extern "system" {
    fn WSAStartup(version: u16, data: *mut WsaData) -> i32;
    fn WSASocketW(
        af: i32,
        ty: i32,
        protocol: i32,
        info: *mut c_void,
        group: u32,
        flags: u32,
    ) -> Socket;
    fn bind(s: Socket, name: *const c_void, len: i32) -> i32;
    fn listen(s: Socket, backlog: i32) -> i32;
    fn connect(s: Socket, name: *const c_void, len: i32) -> i32;
    #[cfg(feature = "local")]
    #[link_name = "accept"]
    fn accept_raw(s: Socket, name: *mut c_void, len: *mut i32) -> Socket;
    fn setsockopt(s: Socket, level: i32, name: i32, value: *const u8, len: i32) -> i32;
    fn getsockopt(s: Socket, level: i32, name: i32, value: *mut u8, len: *mut i32) -> i32;
    fn WSAPoll(fds: *mut WsaPollFd, nfds: u32, timeout: i32) -> i32;
    fn WSAGetLastError() -> i32;
    #[cfg(feature = "local")]
    fn WSADuplicateSocketW(s: Socket, pid: u32, info: *mut WsaProtocolInfo) -> i32;
    #[cfg(feature = "udp")]
    fn recvfrom(
        s: Socket,
        buf: *mut u8,
        len: i32,
        flags: i32,
        from: *mut c_void,
        from_len: *mut i32,
    ) -> i32;
    #[cfg(any(feature = "udp", feature = "local"))]
    fn WSAIoctl(
        s: Socket,
        code: u32,
        in_buf: *const c_void,
        in_len: u32,
        out_buf: *mut c_void,
        out_len: u32,
        returned: *mut u32,
        overlapped: *mut c_void,
        completion: *mut c_void,
    ) -> i32;
}

#[cfg(feature = "local")]
#[link(name = "bcrypt")]
unsafe extern "system" {
    fn BCryptGenRandom(algorithm: *mut c_void, buffer: *mut u8, len: u32, flags: u32) -> i32;
}

#[cfg(feature = "local")]
const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 2;
#[cfg(feature = "local")]
const FROM_PROTOCOL_INFO: i32 = -1;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn SetHandleInformation(handle: *mut c_void, mask: u32, flags: u32) -> i32;
    fn GetActiveProcessorGroupCount() -> u16;
    fn GetActiveProcessorCount(group: u16) -> u32;
    fn GetCurrentThread() -> *mut c_void;
    fn SetThreadGroupAffinity(
        thread: *mut c_void,
        affinity: *const GroupAffinity,
        previous: *mut GroupAffinity,
    ) -> i32;
    fn CreateEventW(
        attributes: *const c_void,
        manual: i32,
        initial: i32,
        name: *const u16,
    ) -> *mut c_void;
    fn SetEvent(event: *mut c_void) -> i32;
    pub(super) fn CancelIoEx(file: *mut c_void, overlapped: *mut c_void) -> i32;
    fn QueryPerformanceCounter(count: *mut i64) -> i32;
    fn QueryPerformanceFrequency(frequency: *mut i64) -> i32;
}

/// The performance counter in microseconds.
pub(crate) fn monotonic_micros() -> u64 {
    let (mut count, mut freq) = (0i64, 0i64);
    // SAFETY: both calls write one i64 through a live pointer; neither fails on
    // Windows XP and later.
    unsafe {
        QueryPerformanceCounter(&raw mut count);
        QueryPerformanceFrequency(&raw mut freq);
    }
    let (count, freq) = (count.max(0) as u128, freq.max(1) as u128);
    (count * 1_000_000 / freq) as u64
}

/// A borrowed socket handle.
pub(crate) type Sock<'a> = BorrowedSocket<'a>;
/// A raw socket handle.
pub(crate) type RawSock = RawSocket;
/// An owned socket handle.
pub(crate) type OwnedSock = OwnedSocket;

/// Types whose socket handle this layer can borrow.
pub(crate) trait AsSock {
    fn sock(&self) -> Sock<'_>;
}

impl<T: AsSocket> AsSock for T {
    fn sock(&self) -> Sock<'_> {
        self.as_socket()
    }
}

/// A socket number as a borrowed socket.
///
/// # Safety
///
/// `s` is open for as long as the result is used.
#[cfg(feature = "reactor")]
pub(super) unsafe fn borrow(s: Socket) -> Sock<'static> {
    // SAFETY: by this function's contract.
    unsafe { BorrowedSocket::borrow_raw(s as RawSocket) }
}

/// Sets a socket-level option that takes no value.
///
/// # Safety
///
/// None beyond passing a number: a stale socket fails the call.
#[cfg(feature = "reactor")]
pub(super) unsafe fn setsockopt_empty(s: Socket, name: i32) -> io::Result<()> {
    // SAFETY: a null value of length 0 is what these options take.
    cvt(unsafe { setsockopt(s, c::SOL_SOCKET, name, std::ptr::null(), 0) }).map(drop)
}

pub(crate) fn raw_of(sock: Sock<'_>) -> RawSock {
    sock.as_raw_socket()
}

pub(super) fn raw(sock: Sock<'_>) -> Socket {
    // RawSocket is u64; SOCKET is pointer-sized, and both targets here are 64-bit.
    sock.as_raw_socket() as Socket
}

fn last_error() -> io::Error {
    // SAFETY: WSAGetLastError reads this thread's last Winsock error; no arguments.
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}

fn cvt(ret: i32) -> io::Result<i32> {
    if ret == c::SOCKET_ERROR {
        Err(last_error())
    } else {
        Ok(ret)
    }
}

static STARTUP: Once = Once::new();

/// Winsock must be started before the first socket call. `WSAStartup` is
/// reference counted, so this coexists with the standard library's own call.
pub(super) fn startup() {
    STARTUP.call_once(|| {
        // SAFETY: WsaData is plain data; zeroed is a valid starting value that
        // WSAStartup overwrites. Version 2.2 is requested as Microsoft documents.
        let mut data: WsaData = unsafe { std::mem::zeroed() };
        // SAFETY: `data` is a live, correctly sized WSADATA.
        let _ = unsafe { WSAStartup(0x0202, &raw mut data) };
    });
}

fn set_int(sock: Sock<'_>, level: i32, name: i32, value: i32) -> io::Result<()> {
    // SAFETY: `sock` is open for the call; `value` is a live i32 and the length
    // passed is its size, as setsockopt requires for integer and DWORD options.
    let ret = unsafe {
        setsockopt(
            raw(sock),
            level,
            name,
            (&raw const value).cast::<u8>(),
            size_of::<i32>() as i32,
        )
    };
    cvt(ret).map(drop)
}

fn get_int(sock: Sock<'_>, level: i32, name: i32) -> io::Result<i32> {
    let mut value: i32 = 0;
    let mut len = size_of::<i32>() as i32;
    // SAFETY: `value` and `len` are live locals; `len` holds the size of `value`.
    let ret = unsafe {
        getsockopt(
            raw(sock),
            level,
            name,
            (&raw mut value).cast::<u8>(),
            &raw mut len,
        )
    };
    cvt(ret).map(|_| value)
}

pub(super) fn encode_addr(addr: SocketAddr, out: &mut [u8; 28]) -> i32 {
    match addr {
        SocketAddr::V4(a) => {
            let sa = SockaddrIn {
                sin_family: c::AF_INET as u16,
                sin_port: a.port().to_be(),
                sin_addr: u32::from_ne_bytes(a.ip().octets()),
                sin_zero: [0; 8],
            };
            // SAFETY: `SockaddrIn` is repr(C), Copy, 16 bytes without padding.
            let bytes: [u8; 16] = unsafe { std::mem::transmute(sa) };
            out[..16].copy_from_slice(&bytes);
            16
        }
        SocketAddr::V6(a) => {
            let sa = SockaddrIn6 {
                sin6_family: c::AF_INET6 as u16,
                sin6_port: a.port().to_be(),
                sin6_flowinfo: a.flowinfo().to_be(),
                sin6_addr: a.ip().octets(),
                sin6_scope_id: a.scope_id(),
            };
            // SAFETY: `SockaddrIn6` is repr(C), Copy, 28 bytes without padding.
            let bytes: [u8; 28] = unsafe { std::mem::transmute(sa) };
            out.copy_from_slice(&bytes);
            28
        }
    }
}

/// Room for any socket address Winsock returns (`SOCKADDR_STORAGE`).
#[cfg(feature = "udp")]
#[repr(C, align(8))]
struct AddrBuf([u8; 128]);

/// Decodes an IPv4 or IPv6 socket address written by Winsock.
#[cfg(feature = "udp")]
fn decode_addr(b: &[u8; 128], len: i32) -> Option<SocketAddr> {
    let family = i32::from(u16::from_ne_bytes([b[0], b[1]]));
    let port = u16::from_be_bytes([b[2], b[3]]);
    if family == c::AF_INET && len >= 16 {
        let ip = std::net::Ipv4Addr::new(b[4], b[5], b[6], b[7]);
        Some(SocketAddr::from((ip, port)))
    } else if family == c::AF_INET6 && len >= 28 {
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

/// Creates and binds a UDP socket: not inheritable, `SO_EXCLUSIVEADDRUSE` so no
/// other process can bind the port, `IPV6_V6ONLY` as asked, and ICMP "port
/// unreachable" reports switched off (`SIO_UDP_CONNRESET`), which would
/// otherwise fail the next receive of an unconnected socket.
#[cfg(feature = "udp")]
pub(crate) fn udp_bind(addr: SocketAddr, ipv6_only: bool) -> io::Result<std::net::UdpSocket> {
    #[cfg(any(test, net_io_shim))]
    super::shim::check(super::shim::Op::Socket)?;
    startup();
    let af = if addr.is_ipv6() {
        c::AF_INET6
    } else {
        c::AF_INET
    };
    // SAFETY: as in `tcp_socket`.
    let s = unsafe {
        WSASocketW(
            af,
            c::SOCK_DGRAM,
            c::IPPROTO_UDP,
            std::ptr::null_mut(),
            0,
            c::WSA_FLAG_OVERLAPPED | c::WSA_FLAG_NO_HANDLE_INHERIT,
        )
    };
    if s == c::INVALID_SOCKET {
        return Err(last_error());
    }
    // SAFETY: `s` was just created by WSASocketW, is open, and is owned by no one else.
    let owned = unsafe { OwnedSocket::from_raw_socket(s as RawSocket) };
    set_int(owned.as_socket(), c::SOL_SOCKET, c::SO_EXCLUSIVEADDRUSE, 1)?;
    if addr.is_ipv6() {
        set_int(
            owned.as_socket(),
            c::IPPROTO_IPV6,
            c::IPV6_V6ONLY,
            i32::from(ipv6_only),
        )?;
    }
    let off: i32 = 0;
    let mut returned = 0u32;
    // SAFETY: SIO_UDP_CONNRESET takes a BOOL input and no output; `off` and
    // `returned` are live locals; no overlapped IO.
    cvt(unsafe {
        WSAIoctl(
            raw(owned.as_socket()),
            c::SIO_UDP_CONNRESET,
            (&raw const off).cast::<c_void>(),
            size_of::<i32>() as u32,
            std::ptr::null_mut(),
            0,
            &raw mut returned,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    })?;
    bind_to(owned.as_socket(), addr)?;
    Ok(std::net::UdpSocket::from(owned))
}

/// One datagram: its length, its source, and whether it was cut to fit `buf`
/// (`WSAEMSGSIZE`; the length is then the bytes copied).
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
    let mut addr_len = 128i32;
    let len = i32::try_from(buf.len()).unwrap_or(i32::MAX);
    // SAFETY: `buf` is writable for `len` bytes and `addr` for `addr_len`; both
    // live for the call; `sock` is open.
    let n = unsafe {
        recvfrom(
            raw(sock),
            buf.as_mut_ptr(),
            len,
            0,
            addr.0.as_mut_ptr().cast::<c_void>(),
            &raw mut addr_len,
        )
    };
    let (n, truncated) = if n == c::SOCKET_ERROR {
        let e = last_error();
        if e.raw_os_error() != Some(errno::WSAEMSGSIZE) {
            return Err(e);
        }
        (len.unsigned_abs() as usize, true)
    } else {
        (n.unsigned_abs() as usize, false)
    };
    match decode_addr(&addr.0, addr_len) {
        Some(from) => Ok((n, from, truncated)),
        None => Err(io::Error::from(io::ErrorKind::InvalidData)),
    }
}

/// A new TCP socket: overlapped (needed for completion ports and for hand-off
/// receivers) and not inheritable by child processes.
pub(crate) fn tcp_socket(v6: bool) -> io::Result<OwnedSocket> {
    #[cfg(any(test, net_io_shim))]
    super::shim::check(super::shim::Op::Socket)?;
    startup();
    let af = if v6 { c::AF_INET6 } else { c::AF_INET };
    // SAFETY: WSASocketW with a null protocol-info pointer creates a new socket
    // from the plain integer arguments; it returns INVALID_SOCKET on failure.
    let s = unsafe {
        WSASocketW(
            af,
            c::SOCK_STREAM,
            c::IPPROTO_TCP,
            std::ptr::null_mut(),
            0,
            c::WSA_FLAG_OVERLAPPED | c::WSA_FLAG_NO_HANDLE_INHERIT,
        )
    };
    if s == c::INVALID_SOCKET {
        return Err(last_error());
    }
    // SAFETY: `s` was just created by WSASocketW, is open, and is owned by no one else.
    Ok(unsafe { OwnedSocket::from_raw_socket(s as RawSocket) })
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

/// Creates, configures, binds, and listens. Without `reuse_address`, the socket
/// uses `SO_EXCLUSIVEADDRUSE`, so no other process can bind the same port.
pub(crate) fn tcp_listener(addr: SocketAddr, p: &ListenParams) -> io::Result<TcpListener> {
    if p.reuse_port {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SO_REUSEPORT does not exist on Windows",
        ));
    }
    if p.defer_accept.is_some() || p.incoming_cpu.is_some() {
        return Err(io::Error::from(io::ErrorKind::Unsupported));
    }
    let s = tcp_socket(addr.is_ipv6())?;
    if p.reuse_address {
        set_int(s.as_socket(), c::SOL_SOCKET, c::SO_REUSEADDR, 1)?;
    } else {
        set_int(s.as_socket(), c::SOL_SOCKET, c::SO_EXCLUSIVEADDRUSE, 1)?;
    }
    if addr.is_ipv6() {
        set_int(
            s.as_socket(),
            c::IPPROTO_IPV6,
            c::IPV6_V6ONLY,
            i32::from(p.ipv6_only),
        )?;
    }
    if let Some(n) = p.send_buffer {
        set_int(s.as_socket(), c::SOL_SOCKET, c::SO_SNDBUF, clamp_int(n))?;
    }
    if let Some(n) = p.receive_buffer {
        set_int(s.as_socket(), c::SOL_SOCKET, c::SO_RCVBUF, clamp_int(n))?;
    }
    bind_to(s.as_socket(), addr)?;
    // SAFETY: `s` is an open, bound stream socket.
    cvt(unsafe { listen(raw(s.as_socket()), clamp_int(p.backlog)) })?;
    if p.fast_open.is_some() {
        set_int(s.as_socket(), c::IPPROTO_TCP, c::TCP_FASTOPEN, 1)?;
    }
    let listener = TcpListener::from(s);
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Whether a file send was turned down, so the bytes must go by reading and writing.
pub(crate) fn send_file_refused(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::Unsupported
}

/// Bytes of `file` at `offset`. Windows moves the file's position, which no net-io
/// path relies on.
pub(crate) fn read_file_at(file: &std::fs::File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(file, buf, offset)
}

/// Whether this OS can pin a thread.
pub(crate) const CAN_PIN: bool = true;

/// `GROUP_AFFINITY`.
#[repr(C)]
struct GroupAffinity {
    mask: usize,
    group: u16,
    reserved: [u16; 3],
}

/// Pins the calling thread to the `cpu`th processor, counting across processor groups.
pub(crate) fn pin_current_thread(cpu: usize) -> io::Result<()> {
    let mut left = cpu;
    // SAFETY: takes no pointers.
    let groups = unsafe { GetActiveProcessorGroupCount() };
    for group in 0..groups {
        // SAFETY: takes no pointers.
        let in_group = unsafe { GetActiveProcessorCount(group) } as usize;
        if left < in_group {
            let affinity = GroupAffinity {
                mask: 1usize << left,
                group,
                reserved: [0; 3],
            };
            // SAFETY: the pseudo handle needs no closing; `affinity` lives for the call,
            // and the previous-affinity pointer may be null.
            let ok = unsafe {
                SetThreadGroupAffinity(
                    GetCurrentThread(),
                    &raw const affinity,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            return Ok(());
        }
        left -= in_group;
    }
    Err(io::Error::from(io::ErrorKind::InvalidInput))
}

/// `TCP_MAXRT`: how long sent bytes may stay unacknowledged, in whole seconds.
pub(crate) fn set_user_timeout(sock: Sock<'_>, timeout: Duration) -> io::Result<()> {
    set_int(sock, c::IPPROTO_TCP, c::TCP_MAXRT, secs(timeout).max(1))
}

/// Binds `sock` to `addr`.
pub(crate) fn bind_to(sock: Sock<'_>, addr: SocketAddr) -> io::Result<()> {
    let mut buf = [0u8; 28];
    let len = encode_addr(addr, &mut buf);
    // SAFETY: `buf` holds a valid SOCKADDR of `len` bytes and lives for the call.
    cvt(unsafe { bind(raw(sock), buf.as_ptr().cast::<c_void>(), len) }).map(drop)
}

/// Starts a non-blocking connect. `Ok(true)` when it is in progress.
pub(crate) fn connect_start(sock: Sock<'_>, addr: SocketAddr) -> io::Result<bool> {
    #[cfg(any(test, net_io_shim))]
    super::shim::check(super::shim::Op::Connect)?;
    let mut buf = [0u8; 28];
    let len = encode_addr(addr, &mut buf);
    // SAFETY: as in `bind_to`; the socket is non-blocking, so connect returns at once.
    let ret = unsafe { connect(raw(sock), buf.as_ptr().cast::<c_void>(), len) };
    if ret == 0 {
        return Ok(false);
    }
    let err = last_error();
    if err.raw_os_error() == Some(c::WSAEWOULDBLOCK) {
        Ok(true)
    } else {
        Err(err)
    }
}

/// The pending error of a socket (`SO_ERROR`).
pub(crate) fn take_error(sock: Sock<'_>) -> io::Result<Option<io::Error>> {
    let code = get_int(sock, c::SOL_SOCKET, c::SO_ERROR)?;
    Ok((code != 0).then(|| io::Error::from_raw_os_error(code)))
}

/// Whether `sock` is a listening stream socket.
pub(crate) fn is_listening_stream(sock: Sock<'_>) -> io::Result<bool> {
    let listening = get_int(sock, c::SOL_SOCKET, c::SO_ACCEPTCONN)? != 0;
    let stream = get_int(sock, c::SOL_SOCKET, c::SO_TYPE)? == c::SOCK_STREAM;
    Ok(listening && stream)
}

/// Identifies a socket handed to this process: a listening TCP stream socket
/// and the address it is bound to.
pub(crate) fn listener_kind(sock: Sock<'_>) -> Result<super::SockKind, super::KindError> {
    use super::{KindError, SockKind};
    let ty = match get_int(sock, c::SOL_SOCKET, c::SO_TYPE) {
        Ok(t) => t,
        Err(e) if e.raw_os_error() == Some(errno::WSAENOTSOCK) => {
            return Err(KindError::NotASocket);
        }
        Err(e) => return Err(KindError::Os(e)),
    };
    if ty != c::SOCK_STREAM {
        return Err(KindError::WrongKind);
    }
    if get_int(sock, c::SOL_SOCKET, c::SO_ACCEPTCONN).map_err(KindError::Os)? == 0 {
        return Err(KindError::NotListening);
    }
    // SAFETY: the socket is open for the call; `ManuallyDrop` keeps this
    // temporary `TcpListener` from closing a socket it does not own.
    let view =
        std::mem::ManuallyDrop::new(unsafe { TcpListener::from_raw_socket(sock.as_raw_socket()) });
    match view.local_addr() {
        Ok(a) => Ok(SockKind::Tcp(a)),
        Err(e) if e.kind() == io::ErrorKind::InvalidInput => Err(KindError::WrongKind),
        Err(e) => Err(KindError::Os(e)),
    }
}

/// Accepts one connection and makes it non-inheritable (std's `accept` does not).
pub(crate) fn accept(listener: &TcpListener) -> io::Result<(TcpStream, SocketAddr)> {
    #[cfg(any(test, net_io_shim))]
    super::shim::check(super::shim::Op::Accept)?;
    let (stream, peer) = listener.accept()?;
    // SAFETY: the handle is the accepted socket, open for the call; clearing
    // HANDLE_FLAG_INHERIT is SetHandleInformation's documented use.
    let ok = unsafe {
        SetHandleInformation(
            stream.as_raw_socket() as *mut c_void,
            c::HANDLE_FLAG_INHERIT,
            0,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    stream.set_nonblocking(true)?;
    Ok((stream, peer))
}

/// Configures a dialed stream for net-io's Windows IO model: non-blocking,
/// every wait in `WSAPoll` (already non-blocking from the connect).
pub(crate) fn prepare_dialed(_stream: &TcpStream) -> io::Result<()> {
    Ok(())
}

/// Whether reads wait in `WSAPoll` first (Windows) or block in `recv` (Unix).
pub(crate) const WAIT_BEFORE_RECV: bool = true;

/// One receive on a non-blocking socket: `WouldBlock` when nothing is there.
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

/// Not used on Windows: waits carry the timeout instead.
pub(crate) fn set_recv_timeout(
    _stream: &super::Stream,
    _timeout: Option<Duration>,
) -> io::Result<()> {
    Ok(())
}

/// One send on a non-blocking socket: `WouldBlock` when the buffer is full.
pub(crate) fn send(stream: &super::Stream, buf: &[u8]) -> io::Result<usize> {
    retry_interrupted(|| {
        #[cfg(any(test, net_io_shim))]
        let buf = match super::shim::io(super::shim::Op::Send, buf.len())? {
            Some(n) => &buf[..n],
            None => buf,
        };
        stream.write(buf)
    })
}

/// The largest number of slices passed to one vectored send.
pub(crate) const MAX_SLICES: usize = 64;

/// One vectored send on a non-blocking socket (`WSASend` through std).
pub(crate) fn send_vectored(stream: &super::Stream, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
    let bufs = &bufs[..bufs.len().min(MAX_SLICES)];
    retry_interrupted(|| {
        #[cfg(any(test, net_io_shim))]
        if let Some(n) = super::shim::io(super::shim::Op::Send, bufs.iter().map(|b| b.len()).sum())?
        {
            let first = bufs
                .iter()
                .find(|b| !b.is_empty())
                .map_or(&[][..], |b| &b[..]);
            return stream.write(&first[..n.min(first.len())]);
        }
        stream.write_vectored(bufs)
    })
}

/// The longest AF_UNIX path, terminator included.
#[cfg(feature = "local")]
pub(crate) const UNIX_PATH_MAX: usize = 108;

#[cfg(feature = "local")]
const SIO_AF_UNIX_GETPEERPID: u32 = 0x5800_0100;

/// A `sockaddr_un`, and its length.
#[cfg(feature = "local")]
fn unix_addr(path: &[u8]) -> io::Result<([u8; 2 + UNIX_PATH_MAX], i32)> {
    if path.is_empty() || path.len() >= UNIX_PATH_MAX || path.contains(&0) {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let mut addr = [0u8; 2 + UNIX_PATH_MAX];
    addr[..2].copy_from_slice(&1u16.to_ne_bytes());
    addr[2..2 + path.len()].copy_from_slice(path);
    Ok((addr, (2 + path.len() + 1) as i32))
}

/// A new AF_UNIX stream socket.
#[cfg(feature = "local")]
pub(crate) fn unix_socket() -> io::Result<OwnedSocket> {
    startup();
    // SAFETY: a null protocol-info pointer creates a socket from the plain integers.
    let s = unsafe {
        WSASocketW(
            c::AF_UNIX,
            c::SOCK_STREAM,
            0,
            std::ptr::null_mut(),
            0,
            c::WSA_FLAG_OVERLAPPED | c::WSA_FLAG_NO_HANDLE_INHERIT,
        )
    };
    if s == c::INVALID_SOCKET {
        return Err(last_error());
    }
    // SAFETY: `s` was just created, is open, and is owned by no one else.
    Ok(unsafe { OwnedSocket::from_raw_socket(s as RawSocket) })
}

/// Binds and listens; the path names a new socket file.
#[cfg(feature = "local")]
pub(crate) fn unix_bind(sock: Sock<'_>, path: &[u8], backlog: u32) -> io::Result<()> {
    let (addr, len) = unix_addr(path)?;
    // SAFETY: `addr` holds a valid SOCKADDR_UN of `len` bytes and lives for the call.
    cvt(unsafe { bind(raw(sock), addr.as_ptr().cast(), len) })?;
    // SAFETY: `sock` is an open, bound stream socket.
    cvt(unsafe { listen(raw(sock), clamp_int(backlog)) })?;
    Ok(())
}

/// Connects to the socket at `path`.
#[cfg(feature = "local")]
pub(crate) fn unix_connect(sock: Sock<'_>, path: &[u8]) -> io::Result<()> {
    let (addr, len) = unix_addr(path)?;
    // SAFETY: as in `unix_bind`.
    cvt(unsafe { connect(raw(sock), addr.as_ptr().cast(), len) }).map(drop)
}

/// One accept on a non-blocking AF_UNIX listener. std's `accept` cannot decode the
/// peer's address, so this asks for none. Sockets start inheritable here.
#[cfg(feature = "local")]
pub(crate) fn unix_accept(listener: Sock<'_>) -> io::Result<OwnedSocket> {
    #[cfg(any(test, net_io_shim))]
    super::shim::check(super::shim::Op::Accept)?;
    // SAFETY: `listener` is open; no address is asked for.
    let s = unsafe { accept_raw(raw(listener), std::ptr::null_mut(), std::ptr::null_mut()) };
    if s == c::INVALID_SOCKET {
        return Err(last_error());
    }
    // SAFETY: `s` was just accepted, is open, and is owned by no one else.
    let owned = unsafe { OwnedSocket::from_raw_socket(s as RawSocket) };
    // SAFETY: the handle is open; clearing the flag is the call's documented use.
    let ok = unsafe { SetHandleInformation(s as *mut c_void, c::HANDLE_FLAG_INHERIT, 0) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(owned)
}

/// The process at the other end of an AF_UNIX connection.
#[cfg(feature = "local")]
pub(crate) fn unix_peer_pid(sock: Sock<'_>) -> io::Result<u32> {
    let (mut pid, mut returned) = (0u32, 0u32);
    // SAFETY: `pid` is writable for the stated length; no overlapped operation.
    cvt(unsafe {
        WSAIoctl(
            raw(sock),
            SIO_AF_UNIX_GETPEERPID,
            std::ptr::null(),
            0,
            (&raw mut pid).cast(),
            size_of::<u32>() as u32,
            &raw mut returned,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    })?;
    Ok(pid)
}

/// How many bytes describe a socket for another process (`WSAPROTOCOL_INFOW`).
#[cfg(feature = "local")]
pub(crate) const SHARED_SOCKET: usize = size_of::<WsaProtocolInfo>();

/// Describes `sock` for the process `pid`; the description works there alone.
#[cfg(feature = "local")]
pub(crate) fn share_socket(sock: Sock<'_>, pid: u32) -> io::Result<[u8; SHARED_SOCKET]> {
    let mut out = [0u8; SHARED_SOCKET];
    let mut info = std::mem::MaybeUninit::<WsaProtocolInfo>::zeroed();
    // SAFETY: `info` is writable for its size, and `sock` is open for the call.
    cvt(unsafe { WSADuplicateSocketW(raw(sock), pid, info.as_mut_ptr()) })?;
    // SAFETY: the call filled it, and every field is plain data.
    let bytes = unsafe { std::slice::from_raw_parts(info.as_ptr().cast::<u8>(), SHARED_SOCKET) };
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Sockets made from descriptions and still owned in this process, by handle value.
/// Windows hands back the socket it made before when a description is used again,
/// and the provider-reserved field could name any socket here, so a value on this
/// list is refused rather than given a second owner (two closes of one handle).
#[cfg(feature = "local")]
static ADOPTED: std::sync::Mutex<Vec<RawSocket>> = std::sync::Mutex::new(Vec::new());

#[cfg(feature = "local")]
fn adopted() -> std::sync::MutexGuard<'static, Vec<RawSocket>> {
    ADOPTED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A socket's place on the adopted list. Kept after the socket, so dropping both
/// closes the socket first and then frees its value.
#[cfg(feature = "local")]
#[derive(Debug)]
pub(crate) struct Adoption(RawSocket);

#[cfg(feature = "local")]
impl Adoption {
    /// The socket moves to an owner that does not carry this: its value stays
    /// taken for the life of the process, so a later description that names it
    /// is refused even after that owner closes it (a reused value fails closed).
    pub(crate) fn keep_for_good(self) {
        std::mem::forget(self);
    }
}

#[cfg(feature = "local")]
impl Drop for Adoption {
    fn drop(&mut self) {
        let mut list = adopted();
        if let Some(at) = list.iter().position(|&s| s == self.0) {
            list.swap_remove(at);
        }
    }
}

/// The socket a description from [`share_socket`] names, not inheritable.
/// `AlreadyExists` when it names a socket this process already owns through an
/// earlier description: that one keeps its single owner, and nothing is closed.
#[cfg(feature = "local")]
pub(crate) fn socket_from_shared(
    blob: &[u8; SHARED_SOCKET],
) -> io::Result<(OwnedSocket, Adoption)> {
    startup();
    let mut info = std::mem::MaybeUninit::<WsaProtocolInfo>::uninit();
    // SAFETY: `info` has room for the bytes, and any bytes are a valid WsaProtocolInfo.
    unsafe {
        std::ptr::copy_nonoverlapping(blob.as_ptr(), info.as_mut_ptr().cast::<u8>(), SHARED_SOCKET);
    }
    // SAFETY: the structure is live for the call; the kernel checks what it holds.
    let s = unsafe {
        WSASocketW(
            FROM_PROTOCOL_INFO,
            FROM_PROTOCOL_INFO,
            FROM_PROTOCOL_INFO,
            info.as_mut_ptr().cast(),
            0,
            c::WSA_FLAG_OVERLAPPED | c::WSA_FLAG_NO_HANDLE_INHERIT,
        )
    };
    if s == c::INVALID_SOCKET {
        return Err(last_error());
    }
    let mut list = adopted();
    if list.contains(&(s as RawSocket)) {
        return Err(io::Error::from(io::ErrorKind::AlreadyExists));
    }
    list.push(s as RawSocket);
    drop(list);
    let adoption = Adoption(s as RawSocket);
    // SAFETY: `s` is open and was not on the list, so this call made it: nothing
    // else in the process owns it.
    let sock = unsafe { OwnedSocket::from_raw_socket(s as RawSocket) };
    // The flag passed above does not reach a socket made from a description (the
    // sender's duplicate is inheritable), so it is cleared here.
    // SAFETY: the handle is open; clearing the flag is the call's documented use.
    if unsafe { SetHandleInformation(s as *mut c_void, c::HANDLE_FLAG_INHERIT, 0) } == 0 {
        let e = io::Error::last_os_error();
        drop((sock, adoption));
        return Err(e);
    }
    Ok((sock, adoption))
}

#[cfg(test)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetHandleInformation(handle: *mut c_void, flags: *mut u32) -> i32;
}

/// Whether a process this one starts with handle inheritance would get `sock`.
#[cfg(test)]
pub(crate) fn is_inheritable(sock: Sock<'_>) -> io::Result<bool> {
    let mut flags = 0u32;
    // SAFETY: the socket is open for the call; `flags` is written during it.
    if unsafe { GetHandleInformation(raw(sock) as *mut c_void, &raw mut flags) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(flags & c::HANDLE_FLAG_INHERIT != 0)
}

/// Bytes from the OS's preferred random source.
#[cfg(feature = "local")]
pub(crate) fn random_bytes(out: &mut [u8]) -> io::Result<()> {
    // SAFETY: `out` is writable for its length; a null algorithm with this flag means
    // the system's preferred source.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            out.as_mut_ptr(),
            u32::try_from(out.len()).unwrap_or(u32::MAX),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(io::Error::other("BCryptGenRandom failed"));
    }
    Ok(())
}

/// Waits until any of `socks` (at most 64) can write or has failed; bit `i` of the
/// result stands for `socks[i]`, and 0 means the timeout passed. `WSAPoll` reports a
/// refused connect through `POLLERR` and `POLLHUP`, which every call watches.
pub(crate) fn wait_writable(socks: &[Sock<'_>], timeout: Duration) -> io::Result<u64> {
    let mut fds: Vec<WsaPollFd> = socks
        .iter()
        .map(|s| WsaPollFd {
            fd: raw(*s),
            events: c::POLLWRNORM,
            revents: 0,
        })
        .collect();
    let ms = poll_millis(Some(timeout));
    // SAFETY: `fds` is a live slice of initialized WSAPOLLFD structs whose sockets are
    // open for the call (borrowed in `socks`).
    retry_interrupted(|| cvt(unsafe { WSAPoll(fds.as_mut_ptr(), fds.len() as u32, ms) }))?;
    Ok(fds
        .iter()
        .enumerate()
        .filter(|(_, f)| f.revents != 0)
        .fold(0, |mask, (i, _)| mask | (1 << i)))
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
        Interest::Read => c::POLLRDNORM,
        Interest::Write => c::POLLWRNORM,
    };
    let mut fds = [
        WsaPollFd {
            fd: raw(sock),
            events,
            revents: 0,
        },
        WsaPollFd {
            fd: wake.map_or(c::INVALID_SOCKET, |w| w.socket.as_raw_socket() as Socket),
            events: c::POLLRDNORM,
            revents: 0,
        },
    ];
    let nfds: u32 = if wake.is_some() { 2 } else { 1 };
    let ms = poll_millis(timeout);
    // SAFETY: `fds` is a live array of `nfds` initialized WSAPOLLFD structs whose
    // sockets are open for the call.
    let n = match retry_interrupted(|| cvt(unsafe { WSAPoll(fds.as_mut_ptr(), nfds, ms) })) {
        Ok(n) => n,
        // A kill's `CancelIoEx` ended the wait; the kill flag says why.
        Err(e) if e.raw_os_error() == Some(c::WSAEINTR) => return Ok(Ready::Woken),
        Err(e) => return Err(e),
    };
    if n == 0 {
        return Ok(Ready::TimedOut);
    }
    if fds[1].revents != 0 {
        if let Some(w) = wake {
            w.drain();
        }
        return Ok(Ready::Woken);
    }
    Ok(Ready::Socket)
}

/// Waits on the wake channel alone (or until `timeout`). `true` when woken.
pub(crate) fn wait_wake(wake: &Wake, timeout: Option<Duration>) -> io::Result<bool> {
    let mut fds = [WsaPollFd {
        fd: wake.socket.as_raw_socket() as Socket,
        events: c::POLLRDNORM,
        revents: 0,
    }];
    let ms = poll_millis(timeout);
    // SAFETY: `fds` holds one initialized WSAPOLLFD whose socket `wake` owns for the call.
    let n = retry_interrupted(|| cvt(unsafe { WSAPoll(fds.as_mut_ptr(), 1, ms) }))?;
    if n > 0 {
        wake.drain();
    }
    Ok(n > 0)
}

/// Not used on Windows: `shutdown` does not wake a blocked receive there (spike S-2),
/// and net-io's Windows waits use wake sockets instead.
///
/// # Safety
///
/// `raw` must be an open socket for the call.
pub(crate) unsafe fn shutdown_read_raw(raw: RawSock) {
    // Not found is the usual answer: only a pipe's or a reactor's IO is overlapped.
    // SAFETY: `raw` is open, by this function's contract; null means all operations.
    let _ = unsafe { CancelIoEx(raw as usize as *mut c_void, std::ptr::null_mut()) };
}

fn clamp_int(n: u32) -> i32 {
    i32::try_from(n).unwrap_or(i32::MAX)
}

/// Linger: `None` = off, `Some(0)` = abortive, `Some(d)` = wait up to `d` seconds.
pub(crate) fn set_linger(sock: Sock<'_>, linger: Option<Duration>) -> io::Result<()> {
    let value = Linger {
        l_onoff: u16::from(linger.is_some()),
        l_linger: linger.map_or(0, |d| u16::try_from(d.as_secs()).unwrap_or(u16::MAX)),
    };
    // SAFETY: `value` is a live repr(C) LINGER and the length is its size.
    let ret = unsafe {
        setsockopt(
            raw(sock),
            c::SOL_SOCKET,
            c::SO_LINGER,
            (&raw const value).cast::<u8>(),
            size_of::<Linger>() as i32,
        )
    };
    cvt(ret).map(drop)
}

/// The linger setting.
pub(crate) fn linger(sock: Sock<'_>) -> io::Result<Option<Duration>> {
    let mut value = Linger {
        l_onoff: 0,
        l_linger: 0,
    };
    let mut len = size_of::<Linger>() as i32;
    // SAFETY: `value` and `len` are live locals; `len` holds the struct's size.
    let ret = unsafe {
        getsockopt(
            raw(sock),
            c::SOL_SOCKET,
            c::SO_LINGER,
            (&raw mut value).cast::<u8>(),
            &raw mut len,
        )
    };
    cvt(ret)?;
    Ok((value.l_onoff != 0).then(|| Duration::from_secs(u64::from(value.l_linger))))
}

/// Keepalive (Windows 10 1709+ for idle and interval, 1703+ for count).
pub(crate) fn set_keepalive(
    sock: Sock<'_>,
    keepalive: Option<(Duration, Duration, u32)>,
) -> io::Result<()> {
    match keepalive {
        None => set_int(sock, c::SOL_SOCKET, c::SO_KEEPALIVE, 0),
        Some((idle, interval, count)) => {
            set_int(sock, c::SOL_SOCKET, c::SO_KEEPALIVE, 1)?;
            set_int(sock, c::IPPROTO_TCP, c::TCP_KEEPIDLE, secs(idle))?;
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
    let idle = get_int(sock, c::IPPROTO_TCP, c::TCP_KEEPIDLE)?;
    let interval = get_int(sock, c::IPPROTO_TCP, c::TCP_KEEPINTVL)?;
    let count = get_int(sock, c::IPPROTO_TCP, c::TCP_KEEPCNT)?;
    Ok(Some((
        Duration::from_secs(u64::try_from(idle).unwrap_or(0)),
        Duration::from_secs(u64::try_from(interval).unwrap_or(0)),
        u32::try_from(count).unwrap_or(0),
    )))
}

fn secs(d: Duration) -> i32 {
    i32::try_from(d.as_secs().max(1)).unwrap_or(i32::MAX)
}

/// Sets `SO_SNDBUF` and returns the effective value.
pub(crate) fn set_send_buffer(sock: Sock<'_>, bytes: u32) -> io::Result<u32> {
    set_int(sock, c::SOL_SOCKET, c::SO_SNDBUF, clamp_int(bytes))?;
    send_buffer(sock)
}

/// The effective `SO_SNDBUF`.
pub(crate) fn send_buffer(sock: Sock<'_>) -> io::Result<u32> {
    Ok(u32::try_from(get_int(sock, c::SOL_SOCKET, c::SO_SNDBUF)?).unwrap_or(0))
}

/// Sets `SO_RCVBUF` and returns the effective value.
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
    set_int(sock, c::IPPROTO_TCP, c::TCP_NODELAY, i32::from(on))
}

/// `TCP_NODELAY`.
pub(crate) fn nodelay(sock: Sock<'_>) -> io::Result<bool> {
    Ok(get_int(sock, c::IPPROTO_TCP, c::TCP_NODELAY)? != 0)
}

/// `IP_TTL` or `IPV6_UNICAST_HOPS`.
pub(crate) fn set_ttl(sock: Sock<'_>, v6: bool, hops: u8) -> io::Result<()> {
    if v6 {
        set_int(sock, c::IPPROTO_IPV6, c::IPV6_UNICAST_HOPS, i32::from(hops))
    } else {
        set_int(sock, c::IPPROTO_IP, c::IP_TTL, i32::from(hops))
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

/// Socket handles are not drawn from a small per-process table on Windows.
pub(crate) fn descriptor_limit() -> Option<u64> {
    None
}

/// A wake-up channel: a loopback UDP socket connected to itself, and an event for
/// the waits that cannot take a socket (named pipes).
#[derive(Debug)]
pub(crate) struct Wake {
    socket: UdpSocket,
    event: OwnedHandle,
    thread: std::sync::OnceLock<std::thread::Thread>,
}

impl Wake {
    pub(crate) fn new() -> io::Result<Wake> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.connect(socket.local_addr()?)?;
        socket.set_nonblocking(true)?;
        // SAFETY: no attributes, no name; an auto-reset event, not signaled.
        let raw = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Wake {
            socket,
            // SAFETY: `raw` was just returned, is open, and has no other owner.
            event: unsafe { OwnedHandle::from_raw_handle(raw) },
            thread: std::sync::OnceLock::new(),
        })
    }

    /// Also unpark this thread on every wake (a worker parked without a socket).
    pub(crate) fn bind_thread(&self, thread: std::thread::Thread) {
        let _ = self.thread.set(thread);
    }

    /// Ends the current or next wait that includes this channel. Never blocks.
    pub(crate) fn wake(&self) {
        let _ = self.socket.send(&[1]);
        // SAFETY: the event is open while `self` lives.
        let _ = unsafe { SetEvent(self.event.as_raw_handle()) };
        if let Some(t) = self.thread.get() {
            t.unpark();
        }
    }

    fn drain(&self) {
        let mut buf = [0u8; 64];
        while self.socket.recv(&mut buf).is_ok() {}
    }

    /// The event a wait on a pipe includes.
    #[cfg(feature = "local")]
    pub(super) fn event_raw(&self) -> *mut c_void {
        self.event.as_raw_handle()
    }

    /// Consumes a wake seen through the event.
    #[cfg(feature = "local")]
    pub(super) fn take(&self) {
        self.drain();
    }
}

#[cfg(test)]
mod layout {
    //! Cross-checks the declarations above against `windows-sys` (a dev-dependency).
    use super::*;
    use windows_sys::Win32::Foundation as wf;
    use windows_sys::Win32::Networking::WinSock as ws;

    #[test]
    fn test_layout_constants_match_windows_sys() {
        assert_eq!(c::AF_INET as i64, ws::AF_INET as i64);
        assert_eq!(c::AF_INET6 as i64, ws::AF_INET6 as i64);
        assert_eq!(c::SOCK_STREAM as i64, ws::SOCK_STREAM as i64);
        assert_eq!(c::IPPROTO_IP as i64, ws::IPPROTO_IP as i64);
        assert_eq!(c::IPPROTO_TCP as i64, ws::IPPROTO_TCP as i64);
        assert_eq!(c::IPPROTO_IPV6 as i64, ws::IPPROTO_IPV6 as i64);
        assert_eq!(c::SOL_SOCKET as i64, ws::SOL_SOCKET as i64);
        assert_eq!(c::SO_ACCEPTCONN as i64, ws::SO_ACCEPTCONN as i64);
        assert_eq!(c::SO_REUSEADDR as i64, ws::SO_REUSEADDR as i64);
        assert_eq!(
            c::SO_EXCLUSIVEADDRUSE as i64,
            ws::SO_EXCLUSIVEADDRUSE as i64
        );
        assert_eq!(c::SO_KEEPALIVE as i64, ws::SO_KEEPALIVE as i64);
        assert_eq!(c::SO_LINGER as i64, ws::SO_LINGER as i64);
        assert_eq!(c::SO_SNDBUF as i64, ws::SO_SNDBUF as i64);
        assert_eq!(c::SO_RCVBUF as i64, ws::SO_RCVBUF as i64);
        assert_eq!(c::SO_ERROR as i64, ws::SO_ERROR as i64);
        assert_eq!(c::SO_TYPE as i64, ws::SO_TYPE as i64);
        assert_eq!(c::TCP_NODELAY as i64, ws::TCP_NODELAY as i64);
        assert_eq!(c::TCP_KEEPIDLE as i64, ws::TCP_KEEPIDLE as i64);
        assert_eq!(c::TCP_KEEPCNT as i64, ws::TCP_KEEPCNT as i64);
        assert_eq!(c::TCP_KEEPINTVL as i64, ws::TCP_KEEPINTVL as i64);
        assert_eq!(c::IP_TTL as i64, ws::IP_TTL as i64);
        assert_eq!(c::IPV6_UNICAST_HOPS as i64, ws::IPV6_UNICAST_HOPS as i64);
        assert_eq!(c::IPV6_V6ONLY as i64, ws::IPV6_V6ONLY as i64);
        assert_eq!(c::POLLRDNORM as i64, ws::POLLRDNORM as i64);
        assert_eq!(c::POLLWRNORM as i64, ws::POLLWRNORM as i64);
        assert_eq!(
            c::WSA_FLAG_OVERLAPPED as i64,
            ws::WSA_FLAG_OVERLAPPED as i64
        );
        assert_eq!(
            c::WSA_FLAG_NO_HANDLE_INHERIT as i64,
            ws::WSA_FLAG_NO_HANDLE_INHERIT as i64
        );
        assert_eq!(
            c::HANDLE_FLAG_INHERIT as i64,
            wf::HANDLE_FLAG_INHERIT as i64
        );
        assert_eq!(c::INVALID_SOCKET, ws::INVALID_SOCKET);
        assert_eq!(c::SOCKET_ERROR as i64, ws::SOCKET_ERROR as i64);
        assert_eq!(c::WSAEWOULDBLOCK as i64, ws::WSAEWOULDBLOCK as i64);
    }

    #[test]
    fn test_layout_errno_match_windows_sys() {
        use errno::*;
        assert_eq!(WSAEBADF as i64, ws::WSAEBADF as i64);
        assert_eq!(WSAEACCES as i64, ws::WSAEACCES as i64);
        assert_eq!(WSAEINVAL as i64, ws::WSAEINVAL as i64);
        assert_eq!(WSAEMFILE as i64, ws::WSAEMFILE as i64);
        assert_eq!(WSAENOTSOCK as i64, ws::WSAENOTSOCK as i64);
        assert_eq!(WSAEADDRINUSE as i64, ws::WSAEADDRINUSE as i64);
        assert_eq!(WSAEADDRNOTAVAIL as i64, ws::WSAEADDRNOTAVAIL as i64);
        assert_eq!(WSAENETUNREACH as i64, ws::WSAENETUNREACH as i64);
        assert_eq!(WSAENOBUFS as i64, ws::WSAENOBUFS as i64);
        assert_eq!(WSAETIMEDOUT as i64, ws::WSAETIMEDOUT as i64);
        assert_eq!(WSAECONNREFUSED as i64, ws::WSAECONNREFUSED as i64);
        assert_eq!(WSAEHOSTUNREACH as i64, ws::WSAEHOSTUNREACH as i64);
    }

    #[test]
    fn test_layout_structs_match_windows_sys() {
        assert_eq!(size_of::<SockaddrIn>(), size_of::<ws::SOCKADDR_IN>());
        assert_eq!(size_of::<SockaddrIn6>(), size_of::<ws::SOCKADDR_IN6>());
        assert_eq!(size_of::<Linger>(), size_of::<ws::LINGER>());
        assert_eq!(size_of::<WsaPollFd>(), size_of::<ws::WSAPOLLFD>());
        assert_eq!(size_of::<WsaData>(), size_of::<ws::WSADATA>());
        assert_eq!(
            std::mem::offset_of!(WsaPollFd, revents),
            std::mem::offset_of!(ws::WSAPOLLFD, revents)
        );
        assert_eq!(
            std::mem::offset_of!(WsaData, lp_vendor_info),
            std::mem::offset_of!(ws::WSADATA, lpVendorInfo)
        );
        assert_eq!(
            std::mem::offset_of!(SockaddrIn6, sin6_scope_id),
            std::mem::offset_of!(ws::SOCKADDR_IN6, Anonymous)
        );
    }

    #[cfg(feature = "udp")]
    #[test]
    fn test_layout_udp_matches_windows_sys() {
        assert_eq!(c::SOCK_DGRAM as i64, ws::SOCK_DGRAM as i64);
        assert_eq!(c::IPPROTO_UDP as i64, ws::IPPROTO_UDP as i64);
        assert_eq!(c::SIO_UDP_CONNRESET as i64, ws::SIO_UDP_CONNRESET as i64);
        assert_eq!(errno::WSAEMSGSIZE as i64, ws::WSAEMSGSIZE as i64);
        assert!(size_of::<AddrBuf>() >= size_of::<ws::SOCKADDR_STORAGE>());
    }

    #[cfg(feature = "udp")]
    #[test]
    fn test_udp_recv_reports_truncation_and_source() {
        let a = udp_bind("127.0.0.1:0".parse().unwrap(), true).unwrap();
        let b = udp_bind("[::1]:0".parse().unwrap(), true).unwrap();
        let src = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        src.send_to(&[1u8; 100], a.local_addr().unwrap()).unwrap();
        let mut small = [0u8; 10];
        let (n, from, truncated) = udp_recv_from(a.as_socket(), &mut small).unwrap();
        assert!(truncated);
        assert_eq!(n, 10);
        assert_eq!(from, src.local_addr().unwrap());
        let src6 = std::net::UdpSocket::bind("[::1]:0").unwrap();
        src6.send_to(&[], b.local_addr().unwrap()).unwrap();
        let (n, from, truncated) = udp_recv_from(b.as_socket(), &mut small).unwrap();
        assert_eq!((n, truncated), (0, false));
        assert_eq!(from, src6.local_addr().unwrap());
    }

    #[test]
    fn test_layout_signatures_match_windows_sys() {
        let _: unsafe extern "system" fn(Socket, i32) -> i32 = listen;
        let _: unsafe extern "system" fn(ws::SOCKET, i32) -> i32 = ws::listen;
        let _: unsafe extern "system" fn() -> i32 = WSAGetLastError;
        let _: unsafe extern "system" fn() -> ws::WSA_ERROR = ws::WSAGetLastError;
        let _: unsafe extern "system" fn(*mut WsaPollFd, u32, i32) -> i32 = WSAPoll;
        let _: unsafe extern "system" fn(*mut ws::WSAPOLLFD, u32, i32) -> i32 = ws::WSAPoll;
    }

    #[test]
    fn test_wake_ends_wait() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let w = Wake::new().unwrap();
        w.wake();
        assert_eq!(
            wait(
                l.as_socket(),
                Interest::Read,
                Some(&w),
                Some(Duration::from_secs(5))
            )
            .unwrap(),
            Ready::Woken
        );
        assert_eq!(
            wait(
                l.as_socket(),
                Interest::Read,
                Some(&w),
                Some(Duration::from_millis(10))
            )
            .unwrap(),
            Ready::TimedOut
        );
    }

    #[test]
    fn test_listener_exclusive_by_default() {
        let p = ListenParams {
            reuse_address: false,
            reuse_port: false,
            ipv6_only: true,
            send_buffer: None,
            receive_buffer: None,
            backlog: 16,
            defer_accept: None,
            fast_open: None,
            incoming_cpu: None,
        };
        let l = tcp_listener("127.0.0.1:0".parse().unwrap(), &p).unwrap();
        assert!(is_listening_stream(l.as_socket()).unwrap());
        assert_eq!(
            get_int(l.as_socket(), c::SOL_SOCKET, c::SO_EXCLUSIVEADDRUSE).unwrap(),
            1
        );
        let second = tcp_listener(l.local_addr().unwrap(), &p);
        assert!(second.is_err());
    }

    #[test]
    fn test_linger_and_keepalive_round_trip() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let s = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        set_linger(s.as_socket(), Some(Duration::ZERO)).unwrap();
        assert_eq!(linger(s.as_socket()).unwrap(), Some(Duration::ZERO));
        set_keepalive(
            s.as_socket(),
            Some((Duration::from_secs(30), Duration::from_secs(5), 4)),
        )
        .unwrap();
        assert_eq!(
            keepalive(s.as_socket()).unwrap(),
            Some((Duration::from_secs(30), Duration::from_secs(5), 4))
        );
        set_ttl(s.as_socket(), false, 33).unwrap();
        assert_eq!(ttl(s.as_socket(), false).unwrap(), 33);
    }
}
