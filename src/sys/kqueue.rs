//! Readiness on macOS and FreeBSD: kqueue with `EV_CLEAR` (edge-triggered) and
//! `EVFILT_USER` for wake-ups.
//!
//! A socket's write filter exists only while a send or connect waits: registered
//! for good, it fires now and then after an ACK and wakes the worker for nothing.
//! Adding the filter looks at the socket, so a send that blocked just before the
//! buffer drained still gets its event.
//!
//! References: `kqueue(2)` and `kevent(2)` in the macOS and FreeBSD man pages.
//! Layout and constants are checked against `libc` by the tests below.

use std::ffi::{c_int, c_void};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::{PollEvent, Registered, Sock, WAKE_KEY};

const EVFILT_READ: i16 = -1;
const EVFILT_WRITE: i16 = -2;
#[cfg(target_os = "macos")]
const EVFILT_USER: i16 = -10;
#[cfg(target_os = "freebsd")]
const EVFILT_USER: i16 = -11;
const EV_ADD: u16 = 0x0001;
const EV_DELETE: u16 = 0x0002;
const EV_CLEAR: u16 = 0x0020;
const EV_DISPATCH: u16 = 0x0080;
const EV_EOF: u16 = 0x8000;
const EV_ERROR: u16 = 0x4000;
const NOTE_TRIGGER: u32 = 0x0100_0000;

/// `struct kevent`.
#[repr(C)]
#[derive(Clone, Copy)]
struct Kevent {
    ident: usize,
    filter: i16,
    flags: u16,
    fflags: u32,
    data: isize,
    udata: *mut c_void,
    #[cfg(target_os = "freebsd")]
    ext: [u64; 4],
}

/// `struct timespec`.
#[repr(C)]
#[derive(Clone, Copy)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

unsafe extern "C" {
    fn kqueue() -> c_int;
    fn kevent(
        kq: c_int,
        changes: *const Kevent,
        nchanges: c_int,
        events: *mut Kevent,
        nevents: c_int,
        timeout: *const Timespec,
    ) -> c_int;
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
}

const F_SETFD: c_int = 2;
const FD_CLOEXEC: c_int = 1;
/// The `ident` of the wake event.
const WAKE_IDENT: usize = 1;
/// How many events one wait returns.
const EVENTS: usize = 256;

fn cvt(ret: c_int) -> io::Result<c_int> {
    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

fn change(ident: usize, filter: i16, flags: u16, fflags: u32, key: u64) -> Kevent {
    Kevent {
        ident,
        filter,
        flags,
        fflags,
        data: 0,
        udata: key as usize as *mut c_void,
        #[cfg(target_os = "freebsd")]
        ext: [0; 4],
    }
}

/// Wakes a worker's wait from any thread; repeated wakes before the worker runs
/// cost one atomic load.
#[derive(Debug)]
pub(crate) struct PollWaker {
    kq: Arc<OwnedFd>,
    pending: AtomicBool,
}

impl PollWaker {
    pub(crate) fn wake(&self) {
        if !self.pending.swap(true, Ordering::AcqRel) {
            let ev = change(WAKE_IDENT, EVFILT_USER, 0, NOTE_TRIGGER, WAKE_KEY);
            // SAFETY: `kq` is open; one live change, no events asked for, a zero
            // timeout pointer is not read because nothing waits.
            let _ = unsafe {
                kevent(
                    self.kq.as_raw_fd(),
                    &raw const ev,
                    1,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                )
            };
        }
    }
}

/// The kqueue of one worker.
pub(crate) struct Poller {
    kq: Arc<OwnedFd>,
    wake: Arc<PollWaker>,
    buf: Box<[Kevent; EVENTS]>,
}

// SAFETY: the raw `udata` pointers in `buf` are plain numbers (token keys), never
// dereferenced; the kqueue descriptor may be used from any thread.
unsafe impl Send for Poller {}

impl std::fmt::Debug for Poller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Poller").finish_non_exhaustive()
    }
}

/// Asks a poller for one write event on a socket.
#[derive(Clone, Copy, Debug)]
pub(crate) struct WriteArm {
    kq: c_int,
}

impl WriteArm {
    /// The next report that `reg` can take bytes, under `key`, once.
    ///
    /// A failure here is the kernel out of memory for a filter: the send waits, and
    /// its write deadline ends the connection.
    pub(crate) fn arm(self, reg: Registered, key: u64) {
        let flags = EV_ADD | EV_CLEAR | EV_DISPATCH;
        let changes = [change(reg.raw() as usize, EVFILT_WRITE, flags, 0, key)];
        // SAFETY: `kq` outlives the driver that holds this and `reg` is registered;
        // one live change, no events asked for.
        let _ = unsafe {
            kevent(
                self.kq,
                changes.as_ptr(),
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };
    }
}

impl Poller {
    pub(crate) fn new() -> io::Result<Poller> {
        // SAFETY: no arguments; a new descriptor or -1.
        let fd = cvt(unsafe { kqueue() })?;
        // SAFETY: `fd` was just returned, is open, and has no other owner.
        let kq = Arc::new(unsafe { OwnedFd::from_raw_fd(fd) });
        // SAFETY: `kq` is open; F_SETFD with FD_CLOEXEC takes an int.
        cvt(unsafe { fcntl(kq.as_raw_fd(), F_SETFD, FD_CLOEXEC) })?;
        let wake = change(WAKE_IDENT, EVFILT_USER, EV_ADD | EV_CLEAR, 0, WAKE_KEY);
        // SAFETY: as in `PollWaker::wake`.
        cvt(unsafe {
            kevent(
                kq.as_raw_fd(),
                &raw const wake,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        })?;
        Ok(Poller {
            wake: Arc::new(PollWaker {
                kq: kq.clone(),
                pending: AtomicBool::new(false),
            }),
            kq,
            buf: Box::new([change(0, 0, 0, 0, 0); EVENTS]),
        })
    }

    pub(crate) fn waker(&self) -> Arc<PollWaker> {
        self.wake.clone()
    }

    /// Registers a socket under `key` for reading, edge-triggered. Writing waits
    /// through [`WriteArm`].
    pub(crate) fn add(&self, sock: Sock<'_>, key: u64) -> io::Result<Registered> {
        let raw = sock.as_raw_fd();
        let changes = [change(raw as usize, EVFILT_READ, EV_ADD | EV_CLEAR, 0, key)];
        // SAFETY: `kq` and `raw` are open; one live change, no events asked for.
        cvt(unsafe {
            kevent(
                self.kq.as_raw_fd(),
                changes.as_ptr(),
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        })?;
        Ok(Registered::new(raw))
    }

    /// What asks for one write event; usable while a wait is delivering events.
    pub(crate) fn write_arm(&self) -> WriteArm {
        WriteArm {
            kq: self.kq.as_raw_fd(),
        }
    }

    /// Unregisters a socket. Its write filter may never have existed, so it goes last.
    pub(crate) fn remove(&self, reg: Registered) -> io::Result<()> {
        let raw = reg.raw();
        let changes = [
            change(raw as usize, EVFILT_READ, EV_DELETE, 0, 0),
            change(raw as usize, EVFILT_WRITE, EV_DELETE, 0, 0),
        ];
        // SAFETY: as in `add`. A filter that is already gone reports an error
        // the caller has no use for.
        let _ = unsafe {
            kevent(
                self.kq.as_raw_fd(),
                changes.as_ptr(),
                2,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };
        Ok(())
    }

    /// Waits and calls `f` for each report. Interrupted waits report nothing.
    pub(crate) fn wait(
        &mut self,
        timeout: Option<Duration>,
        mut f: impl FnMut(PollEvent),
    ) -> io::Result<()> {
        #[cfg(any(test, net_io_shim))]
        super::shim::check(super::shim::Op::Wait)?;
        let ts = timeout.map(|d| Timespec {
            tv_sec: i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: i64::from(d.subsec_nanos()),
        });
        let ts_ptr = ts
            .as_ref()
            .map_or(std::ptr::null(), |t| t as *const Timespec);
        // SAFETY: `buf` holds EVENTS entries and `ts` lives for the call.
        let n = unsafe {
            kevent(
                self.kq.as_raw_fd(),
                std::ptr::null(),
                0,
                self.buf.as_mut_ptr(),
                EVENTS as c_int,
                ts_ptr,
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
            let ev = self.buf[i];
            let key = ev.udata as usize as u64;
            if ev.filter == EVFILT_USER || key == WAKE_KEY {
                self.wake.pending.store(false, Ordering::Release);
                continue;
            }
            let failed = ev.flags & EV_ERROR != 0;
            let hangup = ev.flags & EV_EOF != 0 || failed;
            f(PollEvent {
                key,
                readable: ev.filter == EVFILT_READ || failed,
                writable: ev.filter == EVFILT_WRITE || failed,
                hangup: hangup && ev.filter == EVFILT_READ,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::mem::{offset_of, size_of};
    use std::os::fd::AsFd;

    #[test]
    fn test_layout_matches_libc() {
        assert_eq!(size_of::<Kevent>(), size_of::<libc::kevent>());
        assert_eq!(offset_of!(Kevent, udata), offset_of!(libc::kevent, udata));
        assert_eq!(offset_of!(Kevent, data), offset_of!(libc::kevent, data));
        assert_eq!(EVFILT_READ, libc::EVFILT_READ);
        assert_eq!(EVFILT_WRITE, libc::EVFILT_WRITE);
        assert_eq!(EVFILT_USER, libc::EVFILT_USER);
        assert_eq!(EV_ADD, libc::EV_ADD);
        assert_eq!(EV_DELETE, libc::EV_DELETE);
        assert_eq!(EV_CLEAR, libc::EV_CLEAR);
        assert_eq!(EV_DISPATCH, libc::EV_DISPATCH);
        assert_eq!(EV_EOF, libc::EV_EOF);
        assert_eq!(EV_ERROR, libc::EV_ERROR);
        assert_eq!(NOTE_TRIGGER, libc::NOTE_TRIGGER);
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
        assert!(seen.iter().any(|e| e.key == 7 && e.writable));
        seen.clear();
        (&c).write_all(b"hi").unwrap();
        p.wait(Some(Duration::from_secs(1)), |e| seen.push(e))
            .unwrap();
        assert!(seen.iter().any(|e| e.readable));
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
