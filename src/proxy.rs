//! PROXY protocol vocabulary.
//!
//! The parser (`proxy_parse`) and the server integration are behind the `proxy`
//! feature; the types the rest of the crate refers to exist in every build.

use std::fmt;

/// Whether a listener expects a PROXY protocol header.
///
/// There is no optional mode: the PROXY specification says a receiver must be
/// configured for the protocol and must not guess whether a header is present.
///
/// # Examples
///
/// ```
/// use net_io::{ProxyMode, ProxyVersions};
/// assert_eq!(ProxyMode::default(), ProxyMode::Off);
/// let mode = ProxyMode::Required { versions: ProxyVersions::Both };
/// assert_ne!(mode, ProxyMode::Off);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ProxyMode {
    /// No header is expected.
    #[default]
    Off,
    /// Every connection must start with a header from a trusted proxy.
    Required {
        /// Which versions are accepted.
        versions: ProxyVersions,
    },
}

/// Which PROXY protocol versions a listener accepts.
///
/// ```
/// assert_ne!(net_io::ProxyVersions::V1, net_io::ProxyVersions::V2);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyVersions {
    /// The text version.
    V1,
    /// The binary version.
    V2,
    /// Either, chosen by the first byte.
    Both,
}

/// Facts copied from a trusted PROXY header into fixed arrays.
///
/// ```
/// let facts = net_io::ProxyFacts::default();
/// assert!(facts.alpn().is_none());
/// ```
#[derive(Clone, Copy)]
pub struct ProxyFacts {
    alpn: [u8; 32],
    alpn_len: u8,
    authority: [u8; 255],
    authority_len: u8,
    unique_id: [u8; 128],
    unique_id_len: u8,
    ssl_client: Option<u8>,
}

impl Default for ProxyFacts {
    fn default() -> ProxyFacts {
        ProxyFacts {
            alpn: [0; 32],
            alpn_len: 0,
            authority: [0; 255],
            authority_len: 0,
            unique_id: [0; 128],
            unique_id_len: 0,
            ssl_client: None,
        }
    }
}

impl ProxyFacts {
    /// Copies the facts into fixed arrays; a value longer than its array is left out.
    #[cfg_attr(not(feature = "proxy"), allow(dead_code))]
    pub(crate) fn from_parts(
        alpn: Option<&[u8]>,
        authority: Option<&str>,
        unique_id: Option<&[u8]>,
        ssl_client: Option<u8>,
    ) -> ProxyFacts {
        let mut f = ProxyFacts {
            ssl_client,
            ..ProxyFacts::default()
        };
        if let Some(a) = alpn.filter(|a| a.len() <= f.alpn.len()) {
            f.alpn[..a.len()].copy_from_slice(a);
            f.alpn_len = a.len() as u8;
        }
        if let Some(a) = authority.filter(|a| a.len() <= f.authority.len()) {
            f.authority[..a.len()].copy_from_slice(a.as_bytes());
            f.authority_len = a.len() as u8;
        }
        if let Some(u) = unique_id.filter(|u| u.len() <= f.unique_id.len()) {
            f.unique_id[..u.len()].copy_from_slice(u);
            f.unique_id_len = u.len() as u8;
        }
        f
    }

    /// The ALPN protocol the proxy negotiated with the client.
    #[must_use]
    pub fn alpn(&self) -> Option<&[u8]> {
        (self.alpn_len > 0).then(|| &self.alpn[..usize::from(self.alpn_len)])
    }

    /// The authority (host name) the client asked the proxy for.
    #[must_use]
    pub fn authority(&self) -> Option<&str> {
        if self.authority_len == 0 {
            return None;
        }
        std::str::from_utf8(&self.authority[..usize::from(self.authority_len)]).ok()
    }

    /// The proxy's unique connection id.
    #[must_use]
    pub fn unique_id(&self) -> Option<&[u8]> {
        (self.unique_id_len > 0).then(|| &self.unique_id[..usize::from(self.unique_id_len)])
    }

    /// The SSL client flags the proxy reported.
    #[must_use]
    pub fn ssl_client(&self) -> Option<u8> {
        self.ssl_client
    }
}

impl fmt::Debug for ProxyFacts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyFacts")
            .field("alpn", &self.alpn().map(String::from_utf8_lossy))
            .field("authority", &self.authority())
            .field("unique_id_len", &self.unique_id_len)
            .field("ssl_client", &self.ssl_client)
            .finish()
    }
}

/// Why a PROXY header was refused.
///
/// ```
/// assert_eq!(net_io::ProxyError::V1TooLong.to_string(), "v1 header longer than 107 bytes");
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyError {
    /// `encode`: the output buffer cannot hold the header.
    OutputTooSmall {
        /// Bytes needed.
        need: usize,
    },
    /// The first bytes match no allowed signature.
    NotProxy,
    /// A v1 line longer than 107 bytes.
    V1TooLong,
    /// A v1 line that does not follow the grammar.
    V1Syntax {
        /// Byte offset of the problem.
        at: u8,
    },
    /// A v1 address that does not parse.
    V1BadAddress,
    /// A v1 port that does not parse.
    V1BadPort,
    /// A v2 version nibble other than 2.
    V2BadVersion,
    /// A v2 command other than LOCAL or PROXY.
    V2BadCommand,
    /// A v2 family and transport byte not in the specification.
    V2BadFamily,
    /// A v2 length above the configured maximum.
    V2LengthTooLarge {
        /// The declared length.
        declared: u16,
        /// The maximum.
        max: u16,
    },
    /// A v2 address block shorter than its family needs.
    V2AddressTooShort,
    /// A v2 TLV that runs past the declared length.
    V2TlvOverrun,
    /// A v2 CRC32C TLV that does not match.
    V2CrcMismatch,
    /// A v2 unique id longer than 128 bytes.
    V2UniqueIdTooLong,
    /// A v2 SSL TLV that does not parse.
    V2SslMalformed,
    /// Addresses of a different family than the header declares.
    FamilyMismatch,
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyError::OutputTooSmall { need } => {
                write!(f, "output buffer too small ({need} bytes needed)")
            }
            ProxyError::NotProxy => f.write_str("the connection did not start with a PROXY header"),
            ProxyError::V1TooLong => f.write_str("v1 header longer than 107 bytes"),
            ProxyError::V1Syntax { at } => write!(f, "v1 header syntax error at byte {at}"),
            ProxyError::V1BadAddress => f.write_str("v1 header with an invalid address"),
            ProxyError::V1BadPort => f.write_str("v1 header with an invalid port"),
            ProxyError::V2BadVersion => f.write_str("v2 header with an unknown version"),
            ProxyError::V2BadCommand => f.write_str("v2 header with an unknown command"),
            ProxyError::V2BadFamily => f.write_str("v2 header with an unknown address family"),
            ProxyError::V2LengthTooLarge { declared, max } => {
                write!(
                    f,
                    "v2 header declares {declared} bytes, above the maximum of {max}"
                )
            }
            ProxyError::V2AddressTooShort => {
                f.write_str("v2 address block too short for its family")
            }
            ProxyError::V2TlvOverrun => f.write_str("v2 TLV runs past the declared length"),
            ProxyError::V2CrcMismatch => f.write_str("v2 header checksum does not match"),
            ProxyError::V2UniqueIdTooLong => f.write_str("v2 unique id longer than 128 bytes"),
            ProxyError::V2SslMalformed => f.write_str("v2 SSL TLV is malformed"),
            ProxyError::FamilyMismatch => f.write_str("addresses do not match the declared family"),
        }
    }
}

impl std::error::Error for ProxyError {}
