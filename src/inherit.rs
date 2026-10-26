//! Inherited listeners (systemd socket activation, FastCGI descriptor 0).
//!
//! The functions arrive in `0.4.0`; the error type exists in every build.

use std::fmt;
use std::io;

/// Why inherited descriptors were refused.
///
/// ```
/// assert_eq!(net_io::InheritError::BadCount.to_string(), "LISTEN_FDS is not a valid count");
/// ```
#[non_exhaustive]
#[derive(Debug)]
pub enum InheritError {
    /// `LISTEN_FDS` is not a non-negative number.
    BadCount,
    /// More descriptors than allowed.
    TooMany {
        /// The maximum.
        max: u32,
    },
    /// The descriptor is not a socket.
    NotASocket {
        /// The descriptor.
        fd: i32,
    },
    /// The socket is not listening.
    NotListening {
        /// The descriptor.
        fd: i32,
    },
    /// The socket's family or type is not one net-io serves.
    WrongKind {
        /// The descriptor.
        fd: i32,
    },
    /// `LISTEN_FDNAMES` does not match `LISTEN_FDS`.
    NamesMismatch,
    /// `LISTEN_PIDFDID` does not match this process.
    PidFdMismatch,
    /// An OS call failed.
    Os(io::Error),
}

impl fmt::Display for InheritError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InheritError::BadCount => f.write_str("LISTEN_FDS is not a valid count"),
            InheritError::TooMany { max } => write!(f, "more than {max} inherited descriptors"),
            InheritError::NotASocket { fd } => write!(f, "descriptor {fd} is not a socket"),
            InheritError::NotListening { fd } => {
                write!(f, "descriptor {fd} is not a listening socket")
            }
            InheritError::WrongKind { fd } => {
                write!(f, "descriptor {fd} is not a TCP or Unix stream socket")
            }
            InheritError::NamesMismatch => f.write_str("LISTEN_FDNAMES does not match LISTEN_FDS"),
            InheritError::PidFdMismatch => {
                f.write_str("LISTEN_PIDFDID does not match this process")
            }
            InheritError::Os(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for InheritError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            InheritError::Os(e) => Some(e),
            _ => None,
        }
    }
}
