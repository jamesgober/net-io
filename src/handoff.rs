//! Listener hand-off between processes.
//!
//! The functions arrive in `0.4.0` (Unix) and `0.5.0` (Windows); the error type
//! exists in every build.

use std::fmt;
use std::io;

/// Why a listener hand-off failed. Nothing is adopted on any error.
///
/// ```
/// assert_eq!(net_io::HandoffError::BadChecksum.to_string(), "the hand-off manifest checksum does not match");
/// ```
#[non_exhaustive]
#[derive(Debug)]
pub enum HandoffError {
    /// The sender is not the expected process or user.
    PeerMismatch,
    /// The control message was truncated.
    Truncated,
    /// The descriptor count does not match the manifest.
    CountMismatch,
    /// The manifest does not start with the expected magic.
    BadMagic,
    /// The manifest version is unknown.
    BadVersion,
    /// The manifest checksum does not match.
    BadChecksum,
    /// More listeners than one hand-off carries.
    TooMany {
        /// The maximum.
        max: u8,
    },
    /// A received socket failed verification.
    VerifyFailed {
        /// Its position in the manifest.
        index: u8,
        /// Which check failed.
        why: &'static str,
    },
    /// The hand-off did not finish in time.
    Timeout,
    /// An OS call failed.
    Os(io::Error),
}

impl fmt::Display for HandoffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandoffError::PeerMismatch => {
                f.write_str("the hand-off sender is not the expected process or user")
            }
            HandoffError::Truncated => f.write_str("the hand-off message was truncated"),
            HandoffError::CountMismatch => {
                f.write_str("the descriptor count does not match the manifest")
            }
            HandoffError::BadMagic => f.write_str("not a hand-off manifest"),
            HandoffError::BadVersion => f.write_str("unknown hand-off manifest version"),
            HandoffError::BadChecksum => {
                f.write_str("the hand-off manifest checksum does not match")
            }
            HandoffError::TooMany { max } => write!(f, "more than {max} listeners in one hand-off"),
            HandoffError::VerifyFailed { index, why } => {
                write!(f, "received listener {index} failed: {why}")
            }
            HandoffError::Timeout => f.write_str("the hand-off did not finish in time"),
            HandoffError::Os(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for HandoffError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HandoffError::Os(e) => Some(e),
            _ => None,
        }
    }
}
