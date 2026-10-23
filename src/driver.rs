//! Driver selection.
//!
//! The blocking pool ships in `0.3.0`; the reactor (epoll, kqueue, IOCP) in
//! `0.5.0`; io_uring after `1.0.0`. The `Driver` trait itself becomes public at
//! `0.5.0`.

/// Which driver moves the bytes.
///
/// `Auto` picks the reactor where it is built and available, otherwise the
/// blocking pool.
///
/// # Examples
///
/// ```
/// assert_eq!(net_io::DriverKind::default(), net_io::DriverKind::Auto);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum DriverKind {
    /// A bounded pool of threads, one connection per thread.
    Blocking,
    /// One event loop per worker (epoll, kqueue, IOCP); from `0.5.0`.
    Reactor,
    /// io_uring on Linux; after `1.0.0`.
    Uring,
    /// The reactor where available, otherwise the blocking pool.
    #[default]
    Auto,
}

impl DriverKind {
    /// The driver `Auto` resolves to in this build.
    pub(crate) fn resolve(self) -> DriverKind {
        match self {
            // The reactor arrives in 0.5.0; until then everything runs on the blocking pool.
            DriverKind::Auto => DriverKind::Blocking,
            other => other,
        }
    }
}
