//! The only place in the crate that may use `unsafe`: calls into the operating
//! system that `std` does not expose.
//!
//! Every function here is safe to call and takes owned or borrowed handles; no
//! raw pointer or raw descriptor leaves this module. Every OS function,
//! constant, and struct declared below is listed in `dev/SYS-SURFACE.md`, and
//! the declarations are cross-checked against `libc` and `windows-sys`
//! (dev-dependencies only) by the `layout` tests in each platform module.
//!
//! Most socket work goes through `std` itself (creation of accepted sockets,
//! reads, writes, read timeouts, shutdown); this layer adds options that must
//! be set before `bind`, linger and keepalive tuning, waits on several sockets,
//! non-blocking sends on Unix, handle inheritance on Windows, and the
//! descriptor limit.

#![allow(unsafe_code)]

#[cfg(not(any(
    all(
        any(target_os = "linux", target_os = "macos"),
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(windows, any(target_arch = "x86_64", target_arch = "aarch64")),
)))]
compile_error!(
    "net-io 0.3 declares its OS surface for x86_64 and aarch64 on Linux, macOS, and Windows; \
     FreeBSD and the std-only fallback for other targets arrive in 0.5"
);

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub(crate) use unix::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::*;

mod kill;

use std::io::{self, IoSlice, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::Duration;

/// A connected stream socket: TCP, or a Unix domain socket (feature `local`).
#[derive(Debug)]
pub(crate) enum Stream {
    Tcp(TcpStream),
    #[cfg(all(unix, feature = "local"))]
    Unix(std::os::unix::net::UnixStream),
}

impl Stream {
    pub(crate) fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(s) => (&mut &*s).read(buf),
            #[cfg(all(unix, feature = "local"))]
            Stream::Unix(s) => (&mut &*s).read(buf),
        }
    }

    #[cfg_attr(unix, allow(dead_code))]
    pub(crate) fn write(&self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(s) => (&mut &*s).write(buf),
            #[cfg(all(unix, feature = "local"))]
            Stream::Unix(s) => (&mut &*s).write(buf),
        }
    }

    #[cfg_attr(unix, allow(dead_code))]
    pub(crate) fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        match self {
            Stream::Tcp(s) => (&mut &*s).write_vectored(bufs),
            #[cfg(all(unix, feature = "local"))]
            Stream::Unix(s) => (&mut &*s).write_vectored(bufs),
        }
    }

    #[cfg_attr(windows, allow(dead_code))]
    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Stream::Tcp(s) => s.set_read_timeout(timeout),
            #[cfg(all(unix, feature = "local"))]
            Stream::Unix(s) => s.set_read_timeout(timeout),
        }
    }

    pub(crate) fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        match self {
            Stream::Tcp(s) => s.shutdown(how),
            #[cfg(all(unix, feature = "local"))]
            Stream::Unix(s) => s.shutdown(how),
        }
    }

    /// The TCP stream, when this is one.
    pub(crate) fn tcp(&self) -> Option<&TcpStream> {
        match self {
            Stream::Tcp(s) => Some(s),
            #[cfg(all(unix, feature = "local"))]
            Stream::Unix(_) => None,
        }
    }

    /// Bytes waiting, without consuming them (TCP only).
    pub(crate) fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.peek(buf),
            #[cfg(all(unix, feature = "local"))]
            Stream::Unix(_) => Err(io::Error::from(io::ErrorKind::Unsupported)),
        }
    }
}

#[cfg(unix)]
impl std::os::fd::AsFd for Stream {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        match self {
            Stream::Tcp(s) => s.as_fd(),
            #[cfg(feature = "local")]
            Stream::Unix(s) => s.as_fd(),
        }
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsSocket for Stream {
    fn as_socket(&self) -> std::os::windows::io::BorrowedSocket<'_> {
        match self {
            Stream::Tcp(s) => s.as_socket(),
        }
    }
}
pub(crate) use kill::KillSlot;

#[cfg(any(test, net_io_shim))]
pub(crate) mod shim;

/// What a wait is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Interest {
    /// Bytes to read (or end of stream, or an error).
    Read,
    /// Room to write (or an error).
    Write,
}

/// How a wait ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ready {
    /// The socket is ready for the interest (or has an error to report).
    Socket,
    /// The wake channel fired.
    Woken,
    /// The timeout passed.
    TimedOut,
}

/// How an `accept` failure is handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AcceptFailure {
    /// Only this connection failed; count it and keep accepting.
    PerConnection,
    /// Out of descriptors: run the reserve-descriptor routine and back off.
    /// (Windows reports exhaustion as pressure: handles do not come from a small table.)
    #[cfg_attr(windows, allow(dead_code))]
    Descriptors,
    /// Out of buffers or memory: back off.
    Pressure,
    /// The listener itself is broken: close it.
    ListenerFailed,
}

/// The kind of a bind or connect failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AddrFailure {
    InUse,
    NotAvailable,
    Permission,
    Refused,
    HostUnreachable,
    NetworkUnreachable,
    TimedOut,
    Other,
}

/// Converts a timeout to the millisecond argument of `poll` / `WSAPoll`
/// (rounded up, so a wait never ends early; `-1` for no timeout).
pub(crate) fn poll_millis(timeout: Option<Duration>) -> i32 {
    match timeout {
        None => -1,
        Some(d) => {
            let ms = d
                .as_millis()
                .saturating_add(u128::from(d.subsec_nanos() % 1_000_000 != 0));
            i32::try_from(ms).unwrap_or(i32::MAX)
        }
    }
}

/// Retries an operation that failed with `EINTR`.
pub(crate) fn retry_interrupted<T>(mut op: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    loop {
        match op() {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            other => return other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poll_millis_rounds_up_and_caps() {
        assert_eq!(poll_millis(None), -1);
        assert_eq!(poll_millis(Some(Duration::from_millis(5))), 5);
        assert_eq!(poll_millis(Some(Duration::from_micros(1))), 1);
        assert_eq!(poll_millis(Some(Duration::from_secs(u64::MAX))), i32::MAX);
        assert_eq!(poll_millis(Some(Duration::ZERO)), 0);
    }

    #[test]
    fn test_retry_interrupted_retries_then_returns() {
        let mut n = 0;
        let r = retry_interrupted(|| {
            n += 1;
            if n < 3 {
                Err(io::Error::from(io::ErrorKind::Interrupted))
            } else {
                Ok(n)
            }
        });
        assert_eq!(r.unwrap(), 3);
    }
}
