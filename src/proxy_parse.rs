//! The PROXY protocol parser (versions 1 and 2): a sans-IO state machine.
//!
//! Give [`ProxyParser::feed`] every byte received so far; it resumes where it
//! stopped and never reads past the end of the header, so the bytes after
//! `consumed` stay application data. The grammar follows the HAProxy PROXY
//! protocol specification; the v1 text is parsed strictly (single spaces, no
//! leading zeros, addresses parsed by this module's own grammar).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str;

use crate::crc32c::Crc32c;
use crate::proxy::{ProxyError, ProxyFacts, ProxyVersions};

const V1_PREFIX: &[u8] = b"PROXY ";
const V1_MAX: usize = 107;
const V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];
const V2_FIXED: usize = 16;

const TLV_ALPN: u8 = 0x01;
const TLV_AUTHORITY: u8 = 0x02;
const TLV_CRC32C: u8 = 0x03;
const TLV_NOOP: u8 = 0x04;
const TLV_UNIQUE_ID: u8 = 0x05;
const TLV_SSL: u8 = 0x20;
const SSL_VERSION: u8 = 0x21;
const SSL_CN: u8 = 0x22;
const SSL_CIPHER: u8 = 0x23;
const SSL_SIG_ALG: u8 = 0x24;
const SSL_KEY_ALG: u8 = 0x25;
const TLV_NETNS: u8 = 0x30;
const UNIQUE_ID_MAX: usize = 128;

/// Which version the parser is reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Undecided,
    V1,
    V2,
}

/// A sans-IO PROXY header parser for one connection.
///
/// # Examples
///
/// ```
/// use net_io::{ProxyParser, ProxyProgress, ProxyVersions};
/// let mut parser = ProxyParser::new(ProxyVersions::Both, 1024);
/// let bytes = b"PROXY TCP4 192.0.2.1 198.51.100.2 51000 443\r\nGET / HTTP/1.1\r\n";
/// match parser.feed(bytes)? {
///     ProxyProgress::Done { header, consumed } => {
///         assert_eq!(&bytes[consumed..], b"GET / HTTP/1.1\r\n");
///         assert_eq!(header.source.unwrap().to_string(), "192.0.2.1:51000");
///     }
///     ProxyProgress::NeedMore { .. } => unreachable!(),
/// }
/// # Ok::<(), net_io::ProxyError>(())
/// ```
#[derive(Clone, Debug)]
pub struct ProxyParser {
    versions: ProxyVersions,
    v2_body_max: u16,
    kind: Kind,
    /// v1: bytes already searched for the line end.
    scanned: usize,
}

/// What [`ProxyParser::feed`] found.
#[derive(Debug)]
pub enum ProxyProgress<'a> {
    /// The header is incomplete: feed again with at least this many more bytes.
    NeedMore {
        /// The fewest additional bytes that can make progress.
        at_least: usize,
    },
    /// A complete header; the bytes from `consumed` on are application data.
    Done {
        /// The header, borrowing from the input.
        header: ProxyHeader<'a>,
        /// The header's length in bytes.
        consumed: usize,
    },
}

/// A parsed PROXY header, borrowing from the bytes it was parsed from.
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub struct ProxyHeader<'a> {
    /// 1 or 2.
    pub version: u8,
    /// `Proxy`, or `Local` (a connection made by the proxy itself, such as a
    /// health check: keep the socket's own addresses).
    pub command: ProxyCommand,
    /// The transport of the proxied connection.
    pub transport: ProxyTransport,
    /// The real client; `None` for `LOCAL`, v1 `UNKNOWN`, and v2 `UNSPEC`.
    pub source: Option<ProxyAddress<'a>>,
    /// The address the client connected to; `None` as for `source`.
    pub destination: Option<ProxyAddress<'a>>,
    /// The v2 TLVs (empty for v1); `NOOP` entries are skipped.
    pub tlvs: Tlvs<'a>,
    crc_checked: bool,
}

/// The PROXY command.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyCommand {
    /// A proxied connection.
    Proxy,
    /// A connection made by the proxy itself.
    Local,
}

/// The transport of the proxied connection.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyTransport {
    /// A stream (TCP, or a Unix stream socket).
    Stream,
    /// Datagrams.
    Datagram,
    /// Not given.
    Unspecified,
}

/// An address in a PROXY header.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyAddress<'a> {
    /// An IP address and port.
    Ip(SocketAddr),
    /// A Unix socket path (v2 only), with trailing zero bytes removed.
    Unix(&'a [u8]),
}

impl ProxyAddress<'_> {
    /// The IP socket address, if this is one.
    #[must_use]
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            ProxyAddress::Ip(a) => Some(*a),
            ProxyAddress::Unix(_) => None,
        }
    }
}

impl std::fmt::Display for ProxyAddress<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyAddress::Ip(a) => write!(f, "{a}"),
            ProxyAddress::Unix(p) => write!(f, "{}", String::from_utf8_lossy(p)),
        }
    }
}

/// One v2 TLV.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// The type byte.
    pub kind: u8,
    /// The value.
    pub value: &'a [u8],
}

/// The TLVs of a v2 header, already checked to fit the declared length.
#[derive(Clone, Copy, Debug)]
pub struct Tlvs<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Tlvs<'a> {
    type Item = Tlv<'a>;

    fn next(&mut self) -> Option<Tlv<'a>> {
        loop {
            let (tlv, rest) = split_tlv(self.rest)?;
            self.rest = rest;
            if tlv.kind != TLV_NOOP {
                return Some(tlv);
            }
        }
    }
}

/// The SSL facts a proxy that terminated TLS reports (v2 TLV `0x20`).
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub struct ProxySsl<'a> {
    /// The client flags: bit 0 SSL, bit 1 a client certificate on this
    /// connection, bit 2 one in the session.
    pub client: u8,
    /// Whether the client certificate was verified (`verify` field 0).
    pub verified: bool,
    /// The TLS version, such as `TLSv1.3`.
    pub version: Option<&'a str>,
    /// The client certificate's common name.
    pub common_name: Option<&'a str>,
    /// The cipher.
    pub cipher: Option<&'a str>,
    /// The certificate's signature algorithm.
    pub signature_algorithm: Option<&'a str>,
    /// The certificate's key algorithm.
    pub key_algorithm: Option<&'a str>,
}

impl<'a> ProxyHeader<'a> {
    fn find(&self, kind: u8) -> Option<&'a [u8]> {
        let mut tlvs = self.tlvs;
        tlvs.find(|t| t.kind == kind).map(|t| t.value)
    }

    /// The ALPN protocol the proxy negotiated with the client (TLV `0x01`).
    #[must_use]
    pub fn alpn(&self) -> Option<&'a [u8]> {
        self.find(TLV_ALPN)
    }

    /// The authority (host name) the client asked for (TLV `0x02`), if UTF-8.
    #[must_use]
    pub fn authority(&self) -> Option<&'a str> {
        self.find(TLV_AUTHORITY)
            .and_then(|v| str::from_utf8(v).ok())
    }

    /// The proxy's unique connection id (TLV `0x05`, at most 128 bytes).
    #[must_use]
    pub fn unique_id(&self) -> Option<&'a [u8]> {
        self.find(TLV_UNIQUE_ID)
    }

    /// The SSL facts (TLV `0x20`).
    #[must_use]
    pub fn ssl(&self) -> Option<ProxySsl<'a>> {
        let v = self.find(TLV_SSL)?;
        let client = v[0];
        let verify = u32::from_be_bytes([v[1], v[2], v[3], v[4]]);
        let mut ssl = ProxySsl {
            client,
            verified: verify == 0,
            version: None,
            common_name: None,
            cipher: None,
            signature_algorithm: None,
            key_algorithm: None,
        };
        let mut rest = &v[5..];
        while let Some((sub, more)) = split_tlv(rest) {
            let text = str::from_utf8(sub.value).ok();
            match sub.kind {
                SSL_VERSION => ssl.version = text,
                SSL_CN => ssl.common_name = text,
                SSL_CIPHER => ssl.cipher = text,
                SSL_SIG_ALG => ssl.signature_algorithm = text,
                SSL_KEY_ALG => ssl.key_algorithm = text,
                _ => {}
            }
            rest = more;
        }
        Some(ssl)
    }

    /// The network namespace (TLV `0x30`).
    #[must_use]
    pub fn network_namespace(&self) -> Option<&'a [u8]> {
        self.find(TLV_NETNS)
    }

    /// Whether a CRC32C TLV was present and matched.
    #[must_use]
    pub fn crc_checked(&self) -> bool {
        self.crc_checked
    }

    /// The facts net-io keeps after the header's bytes are gone (fixed arrays;
    /// a value longer than its array is left out).
    #[must_use]
    pub fn to_facts(&self) -> ProxyFacts {
        ProxyFacts::from_parts(
            self.alpn(),
            self.authority(),
            self.unique_id(),
            self.ssl().map(|s| s.client),
        )
    }
}

impl ProxyParser {
    /// A parser accepting `versions`, refusing a v2 header whose body (after the
    /// 16 fixed bytes) is longer than `v2_body_max`.
    #[must_use]
    pub fn new(versions: ProxyVersions, v2_body_max: u16) -> ProxyParser {
        ProxyParser {
            versions,
            v2_body_max,
            kind: Kind::Undecided,
            scanned: 0,
        }
    }

    /// Parses from `input`, which holds every byte received so far.
    ///
    /// # Errors
    ///
    /// [`ProxyError`]: the bytes are not an allowed header, or are malformed.
    pub fn feed<'a>(&mut self, input: &'a [u8]) -> Result<ProxyProgress<'a>, ProxyError> {
        if self.kind == Kind::Undecided {
            let Some(&first) = input.first() else {
                return Ok(ProxyProgress::NeedMore { at_least: 1 });
            };
            let v1 = matches!(self.versions, ProxyVersions::V1 | ProxyVersions::Both);
            let v2 = matches!(self.versions, ProxyVersions::V2 | ProxyVersions::Both);
            self.kind = match first {
                b'P' if v1 => Kind::V1,
                0x0D if v2 => Kind::V2,
                _ => return Err(ProxyError::NotProxy),
            };
        }
        match self.kind {
            Kind::V1 => self.feed_v1(input),
            _ => self.feed_v2(input),
        }
    }

    fn feed_v1<'a>(&mut self, input: &'a [u8]) -> Result<ProxyProgress<'a>, ProxyError> {
        let n = input.len().min(V1_PREFIX.len());
        if input[..n] != V1_PREFIX[..n] {
            return Err(ProxyError::NotProxy);
        }
        let limit = input.len().min(V1_MAX);
        let start = self.scanned.min(limit);
        let Some(lf) = input[start..limit].iter().position(|&b| b == b'\n') else {
            if input.len() >= V1_MAX {
                return Err(ProxyError::V1TooLong);
            }
            self.scanned = limit;
            return Ok(ProxyProgress::NeedMore { at_least: 1 });
        };
        let lf = start + lf;
        if lf == 0 || input[lf - 1] != b'\r' {
            return Err(ProxyError::V1Syntax { at: offset(lf) });
        }
        let header = parse_v1_line(&input[..lf - 1])?;
        Ok(ProxyProgress::Done {
            header,
            consumed: lf + 1,
        })
    }

    fn feed_v2<'a>(&mut self, input: &'a [u8]) -> Result<ProxyProgress<'a>, ProxyError> {
        let n = input.len().min(V2_SIGNATURE.len());
        if input[..n] != V2_SIGNATURE[..n] {
            return Err(ProxyError::NotProxy);
        }
        if input.len() < V2_FIXED {
            return Ok(ProxyProgress::NeedMore {
                at_least: V2_FIXED - input.len(),
            });
        }
        let version = input[12] >> 4;
        if version != 2 {
            return Err(ProxyError::V2BadVersion);
        }
        let command = match input[12] & 0x0F {
            0x0 => ProxyCommand::Local,
            0x1 => ProxyCommand::Proxy,
            _ => return Err(ProxyError::V2BadCommand),
        };
        let family = input[13];
        let (address_len, transport) = match family {
            0x00 => (0, ProxyTransport::Unspecified),
            0x11 => (12, ProxyTransport::Stream),
            0x12 => (12, ProxyTransport::Datagram),
            0x21 => (36, ProxyTransport::Stream),
            0x22 => (36, ProxyTransport::Datagram),
            0x31 => (216, ProxyTransport::Stream),
            0x32 => (216, ProxyTransport::Datagram),
            _ => return Err(ProxyError::V2BadFamily),
        };
        let declared = u16::from_be_bytes([input[14], input[15]]);
        if declared > self.v2_body_max {
            return Err(ProxyError::V2LengthTooLarge {
                declared,
                max: self.v2_body_max,
            });
        }
        let total = V2_FIXED + usize::from(declared);
        if input.len() < total {
            return Ok(ProxyProgress::NeedMore {
                at_least: total - input.len(),
            });
        }
        let header = &input[..total];
        let body = &header[V2_FIXED..];
        if body.len() < address_len {
            return Err(ProxyError::V2AddressTooShort);
        }
        let (source, destination) = if command == ProxyCommand::Proxy {
            v2_addresses(family >> 4, &body[..address_len])
        } else {
            (None, None)
        };
        let tlv_bytes = &body[address_len..];
        let crc_checked = check_tlvs(header, V2_FIXED + address_len)?;
        Ok(ProxyProgress::Done {
            header: ProxyHeader {
                version: 2,
                command,
                transport,
                source,
                destination,
                tlvs: Tlvs { rest: tlv_bytes },
                crc_checked,
            },
            consumed: total,
        })
    }
}

/// A byte offset within a v1 line, which is at most 107 bytes.
fn offset(at: usize) -> u8 {
    u8::try_from(at).unwrap_or(u8::MAX)
}

/// One TLV from the front of `bytes`, or `None` when fewer than a whole TLV remain.
fn split_tlv(bytes: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    if bytes.len() < 3 {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([bytes[1], bytes[2]]));
    let value = bytes.get(3..3 + len)?;
    Some((
        Tlv {
            kind: bytes[0],
            value,
        },
        &bytes[3 + len..],
    ))
}

/// Walks every TLV of `header` (starting at `start`) and checks it ends exactly
/// at the declared length; verifies CRC32C, the unique id, and the SSL TLV.
/// Returns whether a checksum was verified.
fn check_tlvs(header: &[u8], start: usize) -> Result<bool, ProxyError> {
    let mut pos = start;
    let mut crc_checked = false;
    while pos < header.len() {
        let rest = &header[pos..];
        let Some((tlv, _)) = split_tlv(rest) else {
            return Err(ProxyError::V2TlvOverrun);
        };
        let value_at = pos + 3;
        match tlv.kind {
            TLV_CRC32C => {
                if tlv.value.len() != 4 {
                    return Err(ProxyError::V2CrcMismatch);
                }
                let expected =
                    u32::from_be_bytes([tlv.value[0], tlv.value[1], tlv.value[2], tlv.value[3]]);
                let mut c = Crc32c::new();
                c.update(&header[..value_at]);
                c.update(&[0; 4]);
                c.update(&header[value_at + 4..]);
                if c.finish() != expected {
                    return Err(ProxyError::V2CrcMismatch);
                }
                crc_checked = true;
            }
            TLV_UNIQUE_ID if tlv.value.len() > UNIQUE_ID_MAX => {
                return Err(ProxyError::V2UniqueIdTooLong);
            }
            TLV_SSL => check_ssl(tlv.value)?,
            _ => {}
        }
        pos = value_at + tlv.value.len();
    }
    Ok(crc_checked)
}

fn check_ssl(value: &[u8]) -> Result<(), ProxyError> {
    if value.len() < 5 {
        return Err(ProxyError::V2SslMalformed);
    }
    let mut rest = &value[5..];
    while !rest.is_empty() {
        match split_tlv(rest) {
            Some((_, more)) => rest = more,
            None => return Err(ProxyError::V2SslMalformed),
        }
    }
    Ok(())
}

fn v2_addresses(family: u8, block: &[u8]) -> (Option<ProxyAddress<'_>>, Option<ProxyAddress<'_>>) {
    let port = |b: &[u8]| u16::from_be_bytes([b[0], b[1]]);
    match family {
        0x1 => {
            let src = Ipv4Addr::new(block[0], block[1], block[2], block[3]);
            let dst = Ipv4Addr::new(block[4], block[5], block[6], block[7]);
            (
                Some(ProxyAddress::Ip(SocketAddr::new(
                    IpAddr::V4(src),
                    port(&block[8..]),
                ))),
                Some(ProxyAddress::Ip(SocketAddr::new(
                    IpAddr::V4(dst),
                    port(&block[10..]),
                ))),
            )
        }
        0x2 => {
            let mut s = [0u8; 16];
            let mut d = [0u8; 16];
            s.copy_from_slice(&block[..16]);
            d.copy_from_slice(&block[16..32]);
            (
                Some(ProxyAddress::Ip(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(s)),
                    port(&block[32..]),
                ))),
                Some(ProxyAddress::Ip(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(d)),
                    port(&block[34..]),
                ))),
            )
        }
        0x3 => (
            Some(ProxyAddress::Unix(trim_zeros(&block[..108]))),
            Some(ProxyAddress::Unix(trim_zeros(&block[108..216]))),
        ),
        _ => (None, None),
    }
}

fn trim_zeros(path: &[u8]) -> &[u8] {
    let end = path.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    &path[..end]
}

/// Parses a v1 line without its CRLF.
fn parse_v1_line(line: &[u8]) -> Result<ProxyHeader<'static>, ProxyError> {
    let rest = &line[V1_PREFIX.len()..];
    let base = V1_PREFIX.len();
    let empty = Tlvs { rest: &[] };
    if let Some(after) = rest.strip_prefix(b"UNKNOWN") {
        // The receiver ignores everything after UNKNOWN on the line.
        if after.is_empty() || after[0] == b' ' {
            return Ok(ProxyHeader {
                version: 1,
                command: ProxyCommand::Proxy,
                transport: ProxyTransport::Unspecified,
                source: None,
                destination: None,
                tlvs: empty,
                crc_checked: false,
            });
        }
        return Err(ProxyError::V1Syntax {
            at: offset(base + 7),
        });
    }
    let mut fields = [&[][..]; 5];
    let mut count = 0;
    let mut at = base;
    for field in rest.split(|&b| b == b' ') {
        if field.is_empty() || count == 5 {
            return Err(ProxyError::V1Syntax { at: offset(at) });
        }
        fields[count] = field;
        count += 1;
        at += field.len() + 1;
    }
    if count != 5 {
        return Err(ProxyError::V1Syntax {
            at: offset(line.len()),
        });
    }
    let v6 = match fields[0] {
        b"TCP4" => false,
        b"TCP6" => true,
        _ => return Err(ProxyError::V1Syntax { at: offset(base) }),
    };
    let address = |text: &[u8]| -> Result<IpAddr, ProxyError> {
        let (mine, other) = if v6 {
            (
                parse_ipv6(text).map(IpAddr::V6),
                parse_ipv4(text).map(IpAddr::V4),
            )
        } else {
            (
                parse_ipv4(text).map(IpAddr::V4),
                parse_ipv6(text).map(IpAddr::V6),
            )
        };
        match (mine, other) {
            (Some(ip), _) => Ok(ip),
            (None, Some(_)) => Err(ProxyError::FamilyMismatch),
            (None, None) => Err(ProxyError::V1BadAddress),
        }
    };
    let src = address(fields[1])?;
    let dst = address(fields[2])?;
    let sport = parse_port(fields[3]).ok_or(ProxyError::V1BadPort)?;
    let dport = parse_port(fields[4]).ok_or(ProxyError::V1BadPort)?;
    Ok(ProxyHeader {
        version: 1,
        command: ProxyCommand::Proxy,
        transport: ProxyTransport::Stream,
        source: Some(ProxyAddress::Ip(SocketAddr::new(src, sport))),
        destination: Some(ProxyAddress::Ip(SocketAddr::new(dst, dport))),
        tlvs: empty,
        crc_checked: false,
    })
}

/// A decimal port, 0 to 65535, no sign and no leading zeros.
fn parse_port(text: &[u8]) -> Option<u16> {
    decimal(text, 5).and_then(|v| u16::try_from(v).ok())
}

/// Decimal digits only, at most `max_digits`, no leading zero unless the value is 0.
fn decimal(text: &[u8], max_digits: usize) -> Option<u32> {
    if text.is_empty() || text.len() > max_digits || (text.len() > 1 && text[0] == b'0') {
        return None;
    }
    text.iter().try_fold(0u32, |acc, &b| {
        b.is_ascii_digit().then(|| acc * 10 + u32::from(b - b'0'))
    })
}

/// A dotted-quad IPv4 address: four decimal octets, no leading zeros.
fn parse_ipv4(text: &[u8]) -> Option<Ipv4Addr> {
    let mut octets = [0u8; 4];
    let mut n = 0;
    for part in text.split(|&b| b == b'.') {
        if n == 4 {
            return None;
        }
        octets[n] = u8::try_from(decimal(part, 3)?).ok()?;
        n += 1;
    }
    (n == 4).then(|| Ipv4Addr::from(octets))
}

/// An IPv6 address in RFC 4291 text form: eight groups of one to four hex
/// digits, at most one `::`, optionally ending in a dotted-quad IPv4 address.
/// No zone index.
fn parse_ipv6(text: &[u8]) -> Option<Ipv6Addr> {
    let (head, tail, compressed) = match find_double_colon(text) {
        Some(i) => (&text[..i], &text[i + 2..], true),
        None => (text, &[][..], false),
    };
    if compressed && find_double_colon(tail).is_some() {
        return None;
    }
    let mut groups = [0u16; 8];
    // Groups before `::` (or all of them, when there is no `::`).
    let front = groups_into(head, &mut groups, 0, !compressed)?;
    if !compressed {
        return (front == 8).then(|| Ipv6Addr::from(groups));
    }
    let mut back = [0u16; 8];
    let n_back = groups_into(tail, &mut back, 0, true)?;
    if front + n_back > 7 {
        return None;
    }
    groups[8 - n_back..].copy_from_slice(&back[..n_back]);
    Some(Ipv6Addr::from(groups))
}

fn find_double_colon(text: &[u8]) -> Option<usize> {
    text.windows(2).position(|w| w == b"::")
}

/// Parses `:`-separated groups of `text` into `out` from index `at`; an IPv4
/// tail (two groups) is allowed when `last` says this part ends the address.
/// Returns the next free index.
fn groups_into(text: &[u8], out: &mut [u16; 8], mut at: usize, last: bool) -> Option<usize> {
    if text.is_empty() {
        return Some(at);
    }
    let mut parts = text.split(|&b| b == b':').peekable();
    while let Some(part) = parts.next() {
        let is_last = parts.peek().is_none();
        if is_last && last && part.contains(&b'.') {
            let v4 = parse_ipv4(part)?.octets();
            if at + 2 > 8 {
                return None;
            }
            out[at] = u16::from_be_bytes([v4[0], v4[1]]);
            out[at + 1] = u16::from_be_bytes([v4[2], v4[3]]);
            at += 2;
            continue;
        }
        if part.is_empty() || part.len() > 4 || at >= 8 {
            return None;
        }
        let mut v = 0u16;
        for &b in part {
            let d = (b as char).to_digit(16)?;
            v = (v << 4) | u16::try_from(d).ok()?;
        }
        out[at] = v;
        at += 1;
    }
    Some(at)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn done(p: &mut ProxyParser, bytes: &[u8]) -> (ProxyHeader<'static>, usize) {
        let bytes: &'static [u8] = Box::leak(bytes.to_vec().into_boxed_slice());
        match p.feed(bytes).unwrap() {
            ProxyProgress::Done { header, consumed } => (header, consumed),
            ProxyProgress::NeedMore { at_least } => panic!("need {at_least} more"),
        }
    }

    fn v1(line: &str) -> Result<ProxyHeader<'static>, ProxyError> {
        let bytes: &'static [u8] = Box::leak(line.as_bytes().to_vec().into_boxed_slice());
        match ProxyParser::new(ProxyVersions::Both, 1024).feed(bytes)? {
            ProxyProgress::Done { header, .. } => Ok(header),
            ProxyProgress::NeedMore { .. } => panic!("incomplete: {line:?}"),
        }
    }

    /// Builds a v2 header: command, family, address block, TLVs; optionally a CRC.
    fn v2(command: u8, family: u8, block: &[u8], tlvs: &[(u8, &[u8])], crc: bool) -> Vec<u8> {
        let mut body = block.to_vec();
        for (kind, value) in tlvs {
            body.push(*kind);
            body.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
            body.extend_from_slice(value);
        }
        let crc_at = if crc {
            body.extend_from_slice(&[TLV_CRC32C, 0, 4, 0, 0, 0, 0]);
            Some(V2_FIXED + body.len() - 4)
        } else {
            None
        };
        let mut h = V2_SIGNATURE.to_vec();
        h.push(0x20 | command);
        h.push(family);
        h.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        h.extend_from_slice(&body);
        if let Some(at) = crc_at {
            let sum = crate::crc32c::crc32c(&h);
            h[at..at + 4].copy_from_slice(&sum.to_be_bytes());
        }
        h
    }

    fn ipv4_block() -> Vec<u8> {
        let mut b = vec![192, 0, 2, 1, 198, 51, 100, 2];
        b.extend_from_slice(&51000u16.to_be_bytes());
        b.extend_from_slice(&443u16.to_be_bytes());
        b
    }

    #[test]
    fn test_v1_tcp4_and_rest_is_data() {
        let mut p = ProxyParser::new(ProxyVersions::Both, 1024);
        let (h, consumed) = done(
            &mut p,
            b"PROXY TCP4 192.0.2.1 198.51.100.2 51000 443\r\nGET",
        );
        assert_eq!(h.version, 1);
        assert_eq!(
            h.source,
            Some(ProxyAddress::Ip("192.0.2.1:51000".parse().unwrap()))
        );
        assert_eq!(
            h.destination,
            Some(ProxyAddress::Ip("198.51.100.2:443".parse().unwrap()))
        );
        assert_eq!(consumed, 45);
    }

    #[test]
    fn test_v1_tcp6_unknown_and_mapped() {
        let h = v1("PROXY TCP6 2001:db8::1 ::ffff:192.0.2.1 1 65535\r\n").unwrap();
        assert_eq!(h.source.unwrap().to_string(), "[2001:db8::1]:1");
        let h = v1("PROXY UNKNOWN\r\n").unwrap();
        assert!(h.source.is_none());
        let h = v1("PROXY UNKNOWN anything at all 1 2\r\n").unwrap();
        assert_eq!(h.transport, ProxyTransport::Unspecified);
    }

    #[test]
    fn test_v1_strict_grammar() {
        use ProxyError::*;
        let bad = [
            ("PROXY TCP4  192.0.2.1 198.51.100.2 1 2\r\n", "double space"),
            (
                "PROXY TCP4 192.0.2.1 198.51.100.2 1 2 \r\n",
                "trailing space",
            ),
            ("PROXY TCP4 192.0.2.1 198.51.100.2 1\r\n", "missing port"),
            ("PROXY TCP5 192.0.2.1 198.51.100.2 1 2\r\n", "protocol"),
            ("PROXY UNKNOWNX\r\n", "unknown suffix"),
        ];
        for (line, why) in bad {
            assert!(
                matches!(v1(line), Err(V1Syntax { .. })),
                "{why}: {:?}",
                v1(line)
            );
        }
        assert_eq!(
            v1("PROXY TCP4 192.0.2.01 198.51.100.2 1 2\r\n").unwrap_err(),
            V1BadAddress
        );
        assert_eq!(
            v1("PROXY TCP4 256.0.2.1 198.51.100.2 1 2\r\n").unwrap_err(),
            V1BadAddress
        );
        assert_eq!(
            v1("PROXY TCP4 192.0.2.1 198.51.100.2 01 2\r\n").unwrap_err(),
            V1BadPort
        );
        assert_eq!(
            v1("PROXY TCP4 192.0.2.1 198.51.100.2 +1 2\r\n").unwrap_err(),
            V1BadPort
        );
        assert_eq!(
            v1("PROXY TCP4 192.0.2.1 198.51.100.2 65536 2\r\n").unwrap_err(),
            V1BadPort
        );
        assert_eq!(
            v1("PROXY TCP4 2001:db8::1 198.51.100.2 1 2\r\n").unwrap_err(),
            FamilyMismatch
        );
        assert_eq!(
            v1("PROXY TCP6 192.0.2.1 ::1 1 2\r\n").unwrap_err(),
            FamilyMismatch
        );
        assert!(matches!(
            ProxyParser::new(ProxyVersions::Both, 1024).feed(b"PROXY TCP4 1.2.3.4 1.2.3.4 1 2\n"),
            Err(V1Syntax { .. })
        ));
    }

    /// Edge case 13: 107 bytes without a line end.
    #[test]
    fn test_v1_too_long() {
        let mut line = b"PROXY UNKNOWN ".to_vec();
        line.resize(107, b'x');
        let r = ProxyParser::new(ProxyVersions::V1, 1024).feed(&line);
        assert_eq!(r.unwrap_err(), ProxyError::V1TooLong);
        let mut ok = b"PROXY UNKNOWN ".to_vec();
        ok.resize(105, b'x');
        ok.extend_from_slice(b"\r\n");
        assert!(matches!(
            ProxyParser::new(ProxyVersions::V1, 1024).feed(&ok),
            Ok(ProxyProgress::Done { consumed: 107, .. })
        ));
    }

    #[test]
    fn test_not_proxy_and_version_filters() {
        let mut p = ProxyParser::new(ProxyVersions::Both, 1024);
        assert_eq!(p.feed(b"GET / HTTP/1.1").unwrap_err(), ProxyError::NotProxy);
        assert_eq!(
            ProxyParser::new(ProxyVersions::Both, 1024)
                .feed(b"PROXX")
                .unwrap_err(),
            ProxyError::NotProxy
        );
        let v2h = v2(1, 0x11, &ipv4_block(), &[], false);
        assert_eq!(
            ProxyParser::new(ProxyVersions::V1, 1024)
                .feed(&v2h)
                .unwrap_err(),
            ProxyError::NotProxy
        );
        assert_eq!(
            ProxyParser::new(ProxyVersions::V2, 1024)
                .feed(b"PROXY TCP4")
                .unwrap_err(),
            ProxyError::NotProxy
        );
    }

    #[test]
    fn test_v2_ipv4_tlvs_and_crc() {
        let h = v2(
            1,
            0x11,
            &ipv4_block(),
            &[
                (TLV_ALPN, b"h2"),
                (TLV_NOOP, b"pad"),
                (TLV_AUTHORITY, b"example.com"),
                (TLV_UNIQUE_ID, b"id-1"),
                (
                    TLV_SSL,
                    &[
                        0x07,
                        0,
                        0,
                        0,
                        0,
                        SSL_VERSION,
                        0,
                        7,
                        b'T',
                        b'L',
                        b'S',
                        b'v',
                        b'1',
                        b'.',
                        b'3',
                        SSL_CN,
                        0,
                        3,
                        b'b',
                        b'o',
                        b'b',
                    ],
                ),
                (0xE0, b"custom"),
            ],
            true,
        );
        let mut p = ProxyParser::new(ProxyVersions::Both, 1024);
        let (header, consumed) = done(&mut p, &h);
        assert_eq!(consumed, h.len());
        assert_eq!(header.command, ProxyCommand::Proxy);
        assert_eq!(header.source.unwrap().to_string(), "192.0.2.1:51000");
        assert_eq!(header.alpn(), Some(&b"h2"[..]));
        assert_eq!(header.authority(), Some("example.com"));
        assert_eq!(header.unique_id(), Some(&b"id-1"[..]));
        assert!(header.crc_checked());
        let ssl = header.ssl().unwrap();
        assert_eq!(
            (ssl.client, ssl.verified, ssl.version, ssl.common_name),
            (7, true, Some("TLSv1.3"), Some("bob"))
        );
        assert!({ header.tlvs }.all(|t| t.kind != TLV_NOOP), "NOOP skipped");
        assert!({ header.tlvs }.any(|t| t.kind == 0xE0 && t.value == b"custom"));
        let facts = header.to_facts();
        assert_eq!(facts.alpn(), Some(&b"h2"[..]));
        assert_eq!(facts.authority(), Some("example.com"));
        assert_eq!(facts.ssl_client(), Some(7));
    }

    #[test]
    fn test_v2_ipv6_unix_local_unspec() {
        let mut block = vec![0u8; 36];
        block[15] = 1;
        block[31] = 2;
        block[32..34].copy_from_slice(&80u16.to_be_bytes());
        let h = v2(1, 0x21, &block, &[], false);
        let (hd, _) = done(&mut ProxyParser::new(ProxyVersions::V2, 1024), &h);
        assert_eq!(hd.source.unwrap().to_string(), "[::1]:80");
        let mut unix = vec![0u8; 216];
        unix[..9].copy_from_slice(b"/run/a.sk");
        let h = v2(1, 0x31, &unix, &[], false);
        let (hd, _) = done(&mut ProxyParser::new(ProxyVersions::V2, 1024), &h);
        assert_eq!(hd.source, Some(ProxyAddress::Unix(b"/run/a.sk")));
        let h = v2(0, 0x11, &ipv4_block(), &[], false);
        let (hd, _) = done(&mut ProxyParser::new(ProxyVersions::V2, 1024), &h);
        assert_eq!((hd.command, hd.source), (ProxyCommand::Local, None));
        let h = v2(1, 0x00, &[], &[], false);
        let (hd, _) = done(&mut ProxyParser::new(ProxyVersions::V2, 1024), &h);
        assert_eq!(
            (hd.transport, hd.source),
            (ProxyTransport::Unspecified, None)
        );
    }

    #[test]
    fn test_v2_errors() {
        use ProxyError::*;
        let feed = |h: &[u8]| ProxyParser::new(ProxyVersions::V2, 64).feed(h).map(|_| ());
        let mut h = v2(1, 0x11, &ipv4_block(), &[], false);
        h[12] = 0x11;
        assert_eq!(feed(&h).unwrap_err(), V2BadVersion);
        let mut h = v2(1, 0x11, &ipv4_block(), &[], false);
        h[12] = 0x22;
        assert_eq!(feed(&h).unwrap_err(), V2BadCommand);
        let mut h = v2(1, 0x11, &ipv4_block(), &[], false);
        h[13] = 0x13;
        assert_eq!(feed(&h).unwrap_err(), V2BadFamily);
        let big = v2(1, 0x11, &ipv4_block(), &[(0xE0, &[0u8; 100])], false);
        assert_eq!(
            feed(&big).unwrap_err(),
            V2LengthTooLarge {
                declared: 115,
                max: 64
            }
        );
        let short = v2(1, 0x21, &[0u8; 20], &[], false);
        assert_eq!(feed(&short).unwrap_err(), V2AddressTooShort);
        let mut over = v2(1, 0x11, &ipv4_block(), &[(0xE0, b"abc")], false);
        let n = over.len();
        over[n - 4] = 9; // TLV length runs past the end
        assert_eq!(feed(&over).unwrap_err(), V2TlvOverrun);
        let mut crc = v2(1, 0x11, &ipv4_block(), &[(TLV_ALPN, b"h2")], true);
        let n = crc.len();
        crc[n - 1] ^= 1;
        assert_eq!(feed(&crc).unwrap_err(), V2CrcMismatch);
        let long_id = vec![b'i'; 129];
        let h = v2(1, 0x11, &ipv4_block(), &[(TLV_UNIQUE_ID, &long_id)], false);
        assert_eq!(
            ProxyParser::new(ProxyVersions::V2, 1024)
                .feed(&h)
                .map(|_| ())
                .unwrap_err(),
            V2UniqueIdTooLong
        );
        let h = v2(1, 0x11, &ipv4_block(), &[(TLV_SSL, &[1, 0, 0])], false);
        assert_eq!(feed(&h).unwrap_err(), V2SslMalformed);
    }

    /// Edge case 14: a v2 header split across 12 segments.
    #[test]
    fn test_v2_split_into_segments_waits_then_succeeds() {
        let mut h = v2(
            1,
            0x11,
            &ipv4_block(),
            &[(TLV_AUTHORITY, b"a.example")],
            true,
        );
        h.extend_from_slice(b"DATA");
        let total = h.len() - 4;
        let mut p = ProxyParser::new(ProxyVersions::Both, 1024);
        let step = h.len().div_ceil(12);
        let mut have = 0;
        loop {
            have = (have + step).min(h.len());
            match p.feed(&h[..have]).unwrap() {
                ProxyProgress::NeedMore { at_least } => assert!(at_least > 0 && have < h.len()),
                ProxyProgress::Done { consumed, .. } => {
                    assert_eq!(consumed, total);
                    break;
                }
            }
        }
    }

    /// Edge cases 15 and 16: the header and data in one segment, and a second
    /// header is application data.
    #[test]
    fn test_second_header_is_data() {
        let two = b"PROXY UNKNOWN\r\nPROXY UNKNOWN\r\n";
        let mut p = ProxyParser::new(ProxyVersions::V1, 1024);
        let (_, consumed) = done(&mut p, two);
        assert_eq!(&two[consumed..], b"PROXY UNKNOWN\r\n");
    }

    /// Property: every split of a valid header gives the same result as the whole.
    #[test]
    fn prop_every_split_point_agrees() {
        let headers: Vec<Vec<u8>> = vec![
            b"PROXY TCP6 2001:db8:0:0:1:0:0:1 ::ffff:10.0.0.1 1024 8080\r\n".to_vec(),
            v2(
                1,
                0x11,
                &ipv4_block(),
                &[(TLV_ALPN, b"http/1.1"), (TLV_UNIQUE_ID, b"u")],
                true,
            ),
        ];
        for h in headers {
            for split in 0..h.len() {
                let mut p = ProxyParser::new(ProxyVersions::Both, 1024);
                if split > 0 {
                    assert!(
                        matches!(p.feed(&h[..split]).unwrap(), ProxyProgress::NeedMore { .. }),
                        "split {split}"
                    );
                }
                match p.feed(&h).unwrap() {
                    ProxyProgress::Done { consumed, .. } => assert_eq!(consumed, h.len()),
                    ProxyProgress::NeedMore { .. } => {
                        panic!("whole header incomplete at split {split}")
                    }
                }
            }
        }
    }

    /// Property: random bytes never panic, and a header is never longer than the input.
    #[test]
    fn prop_random_input_never_panics() {
        use crate::testing::Gen;
        let mut g = Gen::new(0x9F0C_7E11);
        for _ in 0..if cfg!(miri) { 200 } else { 50_000 } {
            let len = g.below(300) as usize;
            let mut bytes: Vec<u8> = (0..len).map(|_| g.next_u64() as u8).collect();
            match g.below(3) {
                0 if len >= 12 => bytes[..12].copy_from_slice(&V2_SIGNATURE),
                1 if len >= 6 => bytes[..6].copy_from_slice(V1_PREFIX),
                _ => {}
            }
            let mut p = ProxyParser::new(ProxyVersions::Both, u16::MAX);
            if let Ok(ProxyProgress::Done { consumed, header }) = p.feed(&bytes) {
                assert!(consumed <= bytes.len());
                let _ = (header.alpn(), header.ssl(), header.tlvs.count());
            }
        }
    }

    /// Property: the IPv6 grammar accepts only what std accepts, with the same value,
    /// and accepts every address std prints.
    #[test]
    fn prop_ipv6_grammar_matches_std() {
        use crate::testing::Gen;
        let mut g = Gen::new(0x1FE6_0001);
        let alphabet = b"0123456789abcdefABCDEF:.";
        for _ in 0..if cfg!(miri) { 200 } else { 100_000 } {
            let len = 1 + g.below(40) as usize;
            let text: Vec<u8> = (0..len)
                .map(|_| alphabet[g.below(alphabet.len() as u64) as usize])
                .collect();
            if let Some(ours) = parse_ipv6(&text) {
                let s = str::from_utf8(&text).unwrap();
                assert_eq!(s.parse::<Ipv6Addr>().ok(), Some(ours), "{s}");
            }
        }
        for _ in 0..if cfg!(miri) { 200 } else { 20_000 } {
            let mut b = [0u8; 16];
            for x in &mut b {
                // Runs of zeros, so `::` forms appear.
                *x = if g.chance(2) { 0 } else { g.next_u64() as u8 };
            }
            let a = Ipv6Addr::from(b);
            assert_eq!(parse_ipv6(a.to_string().as_bytes()), Some(a), "{a}");
        }
        for (s, ok) in [
            ("::", true),
            ("::1", true),
            ("1::", true),
            ("1:2:3:4:5:6:7:8", true),
            ("1:2:3:4:5:6:7::", true),
            ("1:2:3:4:5:6:1.2.3.4", true),
            (":1", false),
            ("1:", false),
            ("1:::2", false),
            ("1::2::3", false),
            ("1:2:3:4:5:6:7:8:9", false),
            ("12345::", false),
            ("::1.2.3", false),
            ("fe80::1%eth0", false),
        ] {
            assert_eq!(parse_ipv6(s.as_bytes()).is_some(), ok, "{s}");
        }
    }

    #[test]
    fn test_ipv4_grammar() {
        for (s, ok) in [
            ("0.0.0.0", true),
            ("255.255.255.255", true),
            ("1.2.3.04", false),
            ("1.2.3", false),
            ("1.2.3.4.5", false),
            ("1.2.3.256", false),
            ("1..3.4", false),
            (" 1.2.3.4", false),
        ] {
            assert_eq!(parse_ipv4(s.as_bytes()).is_some(), ok, "{s}");
        }
    }
}
