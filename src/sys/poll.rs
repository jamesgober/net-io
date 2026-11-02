//! What epoll and kqueue share: a readiness report and a registered socket.

use std::ffi::{c_int, c_void};
use std::io::{self, IoSlice};
use std::os::fd::RawFd;

use super::Sock;

/// The key the wake channel reports under; no token uses it.
pub(crate) const WAKE_KEY: u64 = u64::MAX;

const MSG_DONTWAIT: c_int = if cfg!(target_os = "linux") {
    0x40
} else {
    0x80
};

unsafe extern "C" {
    fn recv(fd: c_int, buf: *mut c_void, len: usize, flags: c_int) -> isize;
}

/// One readiness report.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PollEvent {
    pub(crate) key: u64,
    pub(crate) readable: bool,
    pub(crate) writable: bool,
    /// The peer hung up (or the socket failed): no later edge will come.
    pub(crate) hangup: bool,
}

/// A registered socket: opaque, used only between `register` and `deregister`,
/// while the caller keeps the socket open (the `Driver` contract).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Registered(RawFd);

impl Registered {
    pub(crate) fn new(raw: RawFd) -> Registered {
        Registered(raw)
    }

    pub(crate) fn raw(self) -> RawFd {
        self.0
    }

    fn sock(self) -> Sock<'static> {
        // SAFETY: open between `register` and `deregister` by the `Driver` contract.
        unsafe { std::os::fd::BorrowedFd::borrow_raw(self.0) }
    }

    /// A reset instead of a FIN at close.
    pub(crate) fn set_abortive(self) {
        let _ = super::set_linger(self.sock(), Some(std::time::Duration::ZERO));
    }

    /// One receive that never blocks.
    pub(crate) fn recv(self, buf: &mut [u8]) -> io::Result<usize> {
        super::retry_interrupted(|| {
            #[cfg(any(test, net_io_shim))]
            let room = match super::shim::io(super::shim::Op::Recv, buf.len())? {
                Some(n) => n,
                None => buf.len(),
            };
            #[cfg(not(any(test, net_io_shim)))]
            let room = buf.len();
            // SAFETY: `buf` is writable for `room` bytes and lives for the call. The
            // descriptor is open by the `Driver` contract; a stale number can only
            // make recv(2) fail or read another socket's bytes into `buf`.
            let n = unsafe {
                recv(
                    self.0,
                    buf.as_mut_ptr().cast::<c_void>(),
                    room,
                    MSG_DONTWAIT,
                )
            };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n.unsigned_abs())
            }
        })
    }

    /// One vectored send that never blocks.
    pub(crate) fn send_vectored(self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        super::retry_interrupted(|| super::send_vectored_sock(self.sock(), bufs))
    }

    pub(crate) fn connect_start(self, addr: std::net::SocketAddr) -> io::Result<bool> {
        super::connect_start(self.sock(), addr)
    }

    pub(crate) fn take_error(self) -> io::Result<Option<io::Error>> {
        super::take_error(self.sock())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flags_match_libc() {
        assert_eq!(MSG_DONTWAIT, libc::MSG_DONTWAIT);
    }
}
