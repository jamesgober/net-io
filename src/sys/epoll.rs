//! Readiness on Linux: edge-triggered epoll and an eventfd for wake-ups.
//!
//! References: `epoll(7)`, `epoll_ctl(2)`, `epoll_wait(2)`, `eventfd(2)`.
//! Layout and constants are checked against `libc` by the tests below.

use std::ffi::{c_int, c_void};
use std::fs::File;
use std::io::{self, IoSlice, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::{Sock, poll_millis};

const EPOLL_CLOEXEC: c_int = 0o2_000_000;
const EPOLL_CTL_ADD: c_int = 1;
const EPOLL_CTL_DEL: c_int = 2;
const EPOLLIN: u32 = 0x001;
const EPOLLOUT: u32 = 0x004;
const EPOLLERR: u32 = 0x008;
const EPOLLHUP: u32 = 0x010;
const EPOLLRDHUP: u32 = 0x2000;
const EPOLLET: u32 = 1 << 31;
const EFD_CLOEXEC: c_int = 0o2_000_000;
const EFD_NONBLOCK: c_int = 0o4_000;
const MSG_DONTWAIT: c_int = 0x40;

/// `struct epoll_event`: packed on x86_64, naturally aligned elsewhere.
#[repr(C)]
#[cfg_attr(target_arch = "x86_64", repr(packed))]
#[derive(Clone, Copy)]
struct EpollEvent {
    events: u32,
    data: u64,
}

unsafe extern "C" {
    fn epoll_create1(flags: c_int) -> c_int;
    fn epoll_ctl(epfd: c_int, op: c_int, fd: c_int, event: *mut EpollEvent) -> c_int;
    fn epoll_wait(epfd: c_int, events: *mut EpollEvent, max: c_int, timeout: c_int) -> c_int;
    fn eventfd(init: u32, flags: c_int) -> c_int;
    fn recv(fd: c_int, buf: *mut c_void, len: usize, flags: c_int) -> isize;
}

/// The key the wake channel reports under; no token uses it.
pub(crate) const WAKE_KEY: u64 = u64::MAX;
/// How many events one wait returns.
pub(crate) const EVENTS: usize = 256;

fn cvt(ret: c_int) -> io::Result<c_int> {
    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// One readiness report.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PollEvent {
    pub(crate) key: u64,
    pub(crate) readable: bool,
    pub(crate) writable: bool,
}

/// A registered socket: opaque, used only between `register` and `deregister`,
/// while the caller keeps the socket open (the `Driver` contract).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Registered(RawFd);

impl Registered {
    /// One receive that never blocks.
    pub(crate) fn recv(self, buf: &mut [u8]) -> io::Result<usize> {
        #[cfg(any(test, net_io_shim))]
        let buf = match super::shim::io(super::shim::Op::Recv, buf.len())? {
            Some(n) => &mut buf[..n],
            None => buf,
        };
        // SAFETY: `buf` is writable for its length and lives for the call. The
        // descriptor is open by the `Driver` contract; a stale number can only
        // make recv(2) fail or read another socket's bytes into `buf`.
        let n = unsafe {
            recv(
                self.0,
                buf.as_mut_ptr().cast::<c_void>(),
                buf.len(),
                MSG_DONTWAIT,
            )
        };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n.unsigned_abs())
        }
    }

    fn sock(self) -> Sock<'static> {
        // SAFETY: open between `register` and `deregister` by the `Driver` contract.
        unsafe { std::os::fd::BorrowedFd::borrow_raw(self.0) }
    }

    /// One vectored send that never blocks.
    pub(crate) fn send_vectored(self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        super::send_vectored_sock(self.sock(), bufs)
    }

    pub(crate) fn connect_start(self, addr: std::net::SocketAddr) -> io::Result<bool> {
        super::connect_start(self.sock(), addr)
    }

    pub(crate) fn take_error(self) -> io::Result<Option<io::Error>> {
        super::take_error(self.sock())
    }
}

/// The epoll instance of one worker.
#[derive(Debug)]
pub(crate) struct Poller {
    epoll: OwnedFd,
    wake: Arc<PollWaker>,
    buf: Box<[EpollEventBox; EVENTS]>,
}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct EpollEventBox(EpollEvent);

impl std::fmt::Debug for EpollEventBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EpollEvent")
    }
}

/// Wakes a worker's wait from any thread; repeated wakes before the worker runs
/// cost one atomic load.
#[derive(Debug)]
pub(crate) struct PollWaker {
    event: File,
    pending: AtomicBool,
}

impl PollWaker {
    pub(crate) fn wake(&self) {
        if !self.pending.swap(true, Ordering::AcqRel) {
            let _ = (&self.event).write(&1u64.to_ne_bytes());
        }
    }
}

impl Poller {
    pub(crate) fn new() -> io::Result<Poller> {
        // SAFETY: plain integer arguments; a new descriptor or -1.
        let fd = cvt(unsafe { epoll_create1(EPOLL_CLOEXEC) })?;
        // SAFETY: `fd` was just returned, is open, and has no other owner.
        let epoll = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: as above.
        let ev = cvt(unsafe { eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK) })?;
        // SAFETY: as above.
        let event = File::from(unsafe { OwnedFd::from_raw_fd(ev) });
        let mut reg = EpollEvent {
            events: EPOLLIN,
            data: WAKE_KEY,
        };
        // SAFETY: both descriptors are open; `reg` is a live epoll_event.
        cvt(unsafe { epoll_ctl(fd, EPOLL_CTL_ADD, event.as_raw_fd(), &raw mut reg) })?;
        Ok(Poller {
            epoll,
            wake: Arc::new(PollWaker {
                event,
                pending: AtomicBool::new(false),
            }),
            buf: Box::new([EpollEventBox(EpollEvent { events: 0, data: 0 }); EVENTS]),
        })
    }

    pub(crate) fn waker(&self) -> Arc<PollWaker> {
        self.wake.clone()
    }

    /// Registers a socket under `key` for both directions, edge-triggered.
    pub(crate) fn add(&self, sock: Sock<'_>, key: u64) -> io::Result<Registered> {
        let raw = sock.as_raw_fd();
        let mut reg = EpollEvent {
            events: EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET,
            data: key,
        };
        // SAFETY: both descriptors are open; `reg` is a live epoll_event.
        cvt(unsafe { epoll_ctl(self.epoll.as_raw_fd(), EPOLL_CTL_ADD, raw, &raw mut reg) })?;
        Ok(Registered(raw))
    }

    pub(crate) fn remove(&self, reg: Registered) -> io::Result<()> {
        let mut unused = EpollEvent { events: 0, data: 0 };
        // SAFETY: the epoll descriptor is open; the event argument is ignored for
        // DEL on current kernels and must be non-null on kernels before 2.6.9.
        cvt(unsafe {
            epoll_ctl(
                self.epoll.as_raw_fd(),
                EPOLL_CTL_DEL,
                reg.0,
                &raw mut unused,
            )
        })
        .map(drop)
    }

    /// Waits and calls `f` for each report. Interrupted waits report nothing.
    pub(crate) fn wait(
        &mut self,
        timeout: Option<Duration>,
        mut f: impl FnMut(PollEvent),
    ) -> io::Result<()> {
        // SAFETY: `buf` holds EVENTS entries and lives for the call; EpollEventBox
        // is transparent over EpollEvent.
        let n = unsafe {
            epoll_wait(
                self.epoll.as_raw_fd(),
                self.buf.as_mut_ptr().cast::<EpollEvent>(),
                EVENTS as c_int,
                poll_millis(timeout),
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                return Ok(());
            }
            return Err(e);
        }
        for i in 0..n as usize {
            let EpollEventBox(ev) = self.buf[i];
            let (events, key) = (ev.events, ev.data);
            if key == WAKE_KEY {
                self.wake.pending.store(false, Ordering::Release);
                let mut scratch = [0u8; 8];
                let _ = (&self.wake.event).read(&mut scratch);
                continue;
            }
            f(PollEvent {
                key,
                readable: events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR) != 0,
                writable: events & (EPOLLOUT | EPOLLHUP | EPOLLERR) != 0,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};
    use std::os::fd::AsFd;

    #[test]
    fn test_layout_matches_libc() {
        assert_eq!(size_of::<EpollEvent>(), size_of::<libc::epoll_event>());
        assert_eq!(offset_of!(EpollEvent, data), {
            // libc's field is named u64.
            let e = libc::epoll_event { events: 0, u64: 0 };
            let base = (&raw const e) as usize;
            (&raw const e.u64) as usize - base
        });
        assert_eq!(EPOLL_CLOEXEC, libc::EPOLL_CLOEXEC);
        assert_eq!(EPOLL_CTL_ADD, libc::EPOLL_CTL_ADD);
        assert_eq!(EPOLL_CTL_DEL, libc::EPOLL_CTL_DEL);
        assert_eq!(EPOLLIN, libc::EPOLLIN as u32);
        assert_eq!(EPOLLOUT, libc::EPOLLOUT as u32);
        assert_eq!(EPOLLERR, libc::EPOLLERR as u32);
        assert_eq!(EPOLLHUP, libc::EPOLLHUP as u32);
        assert_eq!(EPOLLRDHUP, libc::EPOLLRDHUP as u32);
        assert_eq!(EPOLLET, libc::EPOLLET as u32);
        assert_eq!(EFD_CLOEXEC, libc::EFD_CLOEXEC);
        assert_eq!(EFD_NONBLOCK, libc::EFD_NONBLOCK);
        assert_eq!(MSG_DONTWAIT, libc::MSG_DONTWAIT);
    }

    #[test]
    fn test_edges_and_waker() {
        let mut p = Poller::new().unwrap();
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let c = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (s, _) = l.accept().unwrap();
        s.set_nonblocking(true).unwrap();
        let reg = p.add(s.as_fd(), 7).unwrap();
        let mut seen = Vec::new();
        p.wait(Some(Duration::from_secs(1)), |e| seen.push(e))
            .unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].key, 7);
        assert!(seen[0].writable && !seen[0].readable);
        seen.clear();
        (&c).write_all(b"hi").unwrap();
        p.wait(Some(Duration::from_secs(1)), |e| seen.push(e))
            .unwrap();
        assert!(seen[0].readable);
        let mut b = [0u8; 8];
        assert_eq!(reg.recv(&mut b).unwrap(), 2);
        assert_eq!(
            reg.recv(&mut b).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let w = p.waker();
        w.wake();
        w.wake();
        seen.clear();
        p.wait(Some(Duration::from_secs(1)), |e| seen.push(e))
            .unwrap();
        assert!(seen.is_empty(), "the wake reports nothing");
        p.remove(reg).unwrap();
    }
}
