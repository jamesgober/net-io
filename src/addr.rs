//! Addresses: normalization, CIDR blocks, and prefix keys.
//!
//! Nothing here touches the OS; it is written against `core` types so it can
//! move to a `no_std` crate later without changes.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;

/// Turns an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) into the IPv4 address.
///
/// Nothing else is rewritten: scope ids are kept, and NAT64 (`64:ff9b::/96`)
/// is not translated. net-io normalizes every peer at accept, so caps, gates,
/// and logs agree on one form.
///
/// # Examples
///
/// ```
/// use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
/// let mapped = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 7).to_ipv6_mapped());
/// assert_eq!(net_io::normalize(mapped), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)));
/// assert_eq!(net_io::normalize(IpAddr::V6(Ipv6Addr::LOCALHOST)), IpAddr::V6(Ipv6Addr::LOCALHOST));
/// ```
#[inline]
#[must_use]
pub fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// [`normalize`] for a socket address; the port is kept.
///
/// # Examples
///
/// ```
/// let addr: std::net::SocketAddr = "[::ffff:10.0.0.1]:80".parse().unwrap();
/// assert_eq!(net_io::normalize_socket(addr).to_string(), "10.0.0.1:80");
/// ```
#[inline]
#[must_use]
pub fn normalize_socket(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::V4(SocketAddrV4::new(v4, v6.port())),
            None => SocketAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// An error parsing or building an address value.
///
/// # Examples
///
/// ```
/// use net_io::{AddrError, Cidr};
/// assert_eq!(Cidr::parse("10.0.0.1/8"), Err(AddrError::HostBitsSet));
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddrError {
    /// The text is not an address or block; `at` is the byte offset where it went wrong.
    Syntax {
        /// Byte offset of the problem.
        at: usize,
    },
    /// The prefix length is above the family's maximum.
    PrefixTooLong {
        /// 32 or 128.
        max: u8,
    },
    /// Bits beyond the prefix are set; use the masked constructor or fix the text.
    HostBitsSet,
    /// More entries than allowed.
    TooMany {
        /// The maximum.
        max: usize,
    },
    /// The text is empty.
    Empty,
}

impl fmt::Display for AddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddrError::Syntax { at } => write!(f, "not an address or CIDR block (at byte {at})"),
            AddrError::PrefixTooLong { max } => write!(f, "prefix length above {max}"),
            AddrError::HostBitsSet => f.write_str(
                "bits beyond the prefix are set; write the network address or use new_masked",
            ),
            AddrError::TooMany { max } => write!(f, "more than {max} entries"),
            AddrError::Empty => f.write_str("empty address text"),
        }
    }
}

impl std::error::Error for AddrError {}

/// Network bits of `ip` at `prefix`, as 16 big-endian bytes (IPv4 in the first 4).
fn masked_bytes(ip: IpAddr, prefix: u8) -> [u8; 16] {
    let mut out = [0u8; 16];
    let (bytes, total): ([u8; 16], u8) = match ip {
        IpAddr::V4(v4) => {
            let mut b = [0u8; 16];
            b[..4].copy_from_slice(&v4.octets());
            (b, 32)
        }
        IpAddr::V6(v6) => (v6.octets(), 128),
    };
    let prefix = prefix.min(total);
    let full = usize::from(prefix / 8);
    out[..full].copy_from_slice(&bytes[..full]);
    let rem = prefix % 8;
    if rem != 0 && full < 16 {
        out[full] = bytes[full] & (0xFFu8 << (8 - rem));
    }
    out
}

fn ip_from_bytes(v4: bool, bytes: &[u8; 16]) -> IpAddr {
    if v4 {
        IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    } else {
        IpAddr::V6(Ipv6Addr::from(*bytes))
    }
}

fn max_prefix(ip: IpAddr) -> u8 {
    if ip.is_ipv4() { 32 } else { 128 }
}

/// A network block: a normalized network address and a prefix length.
///
/// # Examples
///
/// ```
/// use net_io::Cidr;
/// let office: Cidr = "203.0.113.0/24".parse()?;
/// assert!(office.contains("203.0.113.9".parse().unwrap()));
/// assert!(!office.contains("198.51.100.1".parse().unwrap()));
/// assert_eq!(office.to_string(), "203.0.113.0/24");
/// assert!(Cidr::parse("10.0.0.1/8").is_err());
/// assert_eq!(Cidr::new_masked("10.0.0.1".parse().unwrap(), 8)?.to_string(), "10.0.0.0/8");
/// # Ok::<(), net_io::AddrError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// A block whose host bits must be zero.
    ///
    /// # Errors
    ///
    /// [`AddrError::PrefixTooLong`], [`AddrError::HostBitsSet`].
    ///
    /// ```
    /// let block = net_io::Cidr::new("10.0.0.0".parse().unwrap(), 8)?;
    /// assert_eq!(block.prefix_len(), 8);
    /// # Ok::<(), net_io::AddrError>(())
    /// ```
    pub fn new(ip: IpAddr, prefix: u8) -> Result<Cidr, AddrError> {
        let ip = normalize(ip);
        let max = max_prefix(ip);
        if prefix > max {
            return Err(AddrError::PrefixTooLong { max });
        }
        let masked = masked_bytes(ip, prefix);
        let network = ip_from_bytes(ip.is_ipv4(), &masked);
        if network != ip {
            return Err(AddrError::HostBitsSet);
        }
        Ok(Cidr { network, prefix })
    }

    /// A block that clears host bits instead of refusing them.
    ///
    /// # Errors
    ///
    /// [`AddrError::PrefixTooLong`].
    ///
    /// ```
    /// let block = net_io::Cidr::new_masked("192.0.2.77".parse().unwrap(), 24)?;
    /// assert_eq!(block.to_string(), "192.0.2.0/24");
    /// # Ok::<(), net_io::AddrError>(())
    /// ```
    pub fn new_masked(ip: IpAddr, prefix: u8) -> Result<Cidr, AddrError> {
        let ip = normalize(ip);
        let max = max_prefix(ip);
        if prefix > max {
            return Err(AddrError::PrefixTooLong { max });
        }
        let masked = masked_bytes(ip, prefix);
        Ok(Cidr {
            network: ip_from_bytes(ip.is_ipv4(), &masked),
            prefix,
        })
    }

    /// Parses `"10.0.0.0/8"`, `"2001:db8::/32"`, or a bare address (`/32` or `/128`).
    ///
    /// Canonical text only: no leading zeros in IPv4 octets, no zone ids, no whitespace.
    ///
    /// # Errors
    ///
    /// [`AddrError::Empty`], [`AddrError::Syntax`], [`AddrError::PrefixTooLong`],
    /// [`AddrError::HostBitsSet`].
    ///
    /// ```
    /// let block = net_io::Cidr::parse("::1")?;
    /// assert_eq!(block.prefix_len(), 128);
    /// # Ok::<(), net_io::AddrError>(())
    /// ```
    pub fn parse(text: &str) -> Result<Cidr, AddrError> {
        if text.is_empty() {
            return Err(AddrError::Empty);
        }
        let (addr_text, prefix_text) = match text.find('/') {
            Some(slash) => (&text[..slash], Some((slash, &text[slash + 1..]))),
            None => (text, None),
        };
        let ip = IpAddr::from_str(addr_text).map_err(|_| AddrError::Syntax { at: 0 })?;
        let prefix = match prefix_text {
            None => max_prefix(normalize(ip)),
            Some((slash, p)) => parse_prefix(p).ok_or(AddrError::Syntax { at: slash + 1 })?,
        };
        // A mapped IPv6 block keeps its meaning only if the prefix covers the ::ffff:0:0/96 part.
        let (ip, prefix) = match ip {
            IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some() && prefix_text.is_some() => {
                if prefix < 96 {
                    return Err(AddrError::Syntax { at: 0 });
                }
                (ip, prefix - 96)
            }
            _ => (ip, prefix),
        };
        Cidr::new(ip, prefix)
    }

    /// Whether the block contains `ip` (normalized first).
    ///
    /// ```
    /// let block = net_io::Cidr::parse("10.0.0.0/8")?;
    /// assert!(block.contains("::ffff:10.1.2.3".parse().unwrap()));
    /// # Ok::<(), net_io::AddrError>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = normalize(ip);
        if ip.is_ipv4() != self.network.is_ipv4() {
            return false;
        }
        ip_from_bytes(ip.is_ipv4(), &masked_bytes(ip, self.prefix)) == self.network
    }

    /// The network address.
    ///
    /// ```
    /// let block = net_io::Cidr::parse("10.0.0.0/8")?;
    /// assert_eq!(block.network().to_string(), "10.0.0.0");
    /// # Ok::<(), net_io::AddrError>(())
    /// ```
    #[must_use]
    pub fn network(&self) -> IpAddr {
        self.network
    }

    /// The prefix length.
    ///
    /// ```
    /// assert_eq!(net_io::Cidr::parse("10.0.0.0/8")?.prefix_len(), 8);
    /// # Ok::<(), net_io::AddrError>(())
    /// ```
    #[must_use]
    pub fn prefix_len(&self) -> u8 {
        self.prefix
    }

    /// Whether this is an IPv4 block.
    ///
    /// ```
    /// assert!(net_io::Cidr::parse("10.0.0.0/8")?.is_ipv4());
    /// # Ok::<(), net_io::AddrError>(())
    /// ```
    #[must_use]
    pub fn is_ipv4(&self) -> bool {
        self.network.is_ipv4()
    }
}

fn parse_prefix(text: &str) -> Option<u8> {
    if text.is_empty() || text.len() > 3 || (text.len() > 1 && text.starts_with('0')) {
        return None;
    }
    let mut value: u16 = 0;
    for b in text.bytes() {
        if !b.is_ascii_digit() {
            return None;
        }
        value = value * 10 + u16::from(b - b'0');
    }
    u8::try_from(value).ok()
}

impl FromStr for Cidr {
    type Err = AddrError;
    fn from_str(s: &str) -> Result<Cidr, AddrError> {
        Cidr::parse(s)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

/// The prefix lengths used to group addresses.
///
/// IPv6 hosts usually own a whole /64, so the default groups IPv6 at /64 and
/// IPv4 at /32.
///
/// # Examples
///
/// ```
/// use net_io::PrefixPolicy;
/// assert_eq!(PrefixPolicy::DEFAULT.v6(), 64);
/// assert!(PrefixPolicy::new(33, 64).is_err());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PrefixPolicy {
    v4: u8,
    v6: u8,
}

impl PrefixPolicy {
    /// Every address on its own: /32 and /128.
    pub const HOST: PrefixPolicy = PrefixPolicy { v4: 32, v6: 128 };
    /// /32 for IPv4 and /64 for IPv6.
    pub const DEFAULT: PrefixPolicy = PrefixPolicy { v4: 32, v6: 64 };

    /// A policy with the given lengths.
    ///
    /// # Errors
    ///
    /// [`AddrError::PrefixTooLong`] above 32 or 128.
    ///
    /// ```
    /// let wide = net_io::PrefixPolicy::new(24, 48)?;
    /// assert_eq!(wide.v4(), 24);
    /// # Ok::<(), net_io::AddrError>(())
    /// ```
    pub const fn new(v4: u8, v6: u8) -> Result<PrefixPolicy, AddrError> {
        if v4 > 32 {
            return Err(AddrError::PrefixTooLong { max: 32 });
        }
        if v6 > 128 {
            return Err(AddrError::PrefixTooLong { max: 128 });
        }
        Ok(PrefixPolicy { v4, v6 })
    }

    /// The IPv4 prefix length.
    #[must_use]
    pub const fn v4(&self) -> u8 {
        self.v4
    }

    /// The IPv6 prefix length.
    #[must_use]
    pub const fn v6(&self) -> u8 {
        self.v6
    }
}

impl Default for PrefixPolicy {
    fn default() -> PrefixPolicy {
        PrefixPolicy::DEFAULT
    }
}

/// "This address at this prefix length" as a fixed-size `Copy` hash key.
///
/// # Examples
///
/// ```
/// use net_io::{PrefixKey, PrefixPolicy};
/// let a = PrefixKey::of("2001:db8:1:2::10".parse().unwrap(), PrefixPolicy::DEFAULT);
/// let b = PrefixKey::of("2001:db8:1:2:ffff::1".parse().unwrap(), PrefixPolicy::DEFAULT);
/// assert_eq!(a, b);
/// let wide = PrefixPolicy::new(24, 48)?;
/// assert_eq!(PrefixKey::of("192.0.2.200".parse().unwrap(), wide).to_string(), "192.0.2.0/24");
/// # Ok::<(), net_io::AddrError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PrefixKey {
    family: u8,
    bytes: [u8; 16],
    len: u8,
}

impl PrefixKey {
    /// The key of `ip` under `policy` (normalized first; scope ids ignored).
    #[inline]
    #[must_use]
    pub fn of(ip: IpAddr, policy: PrefixPolicy) -> PrefixKey {
        let ip = normalize(ip);
        let len = if ip.is_ipv4() { policy.v4 } else { policy.v6 };
        PrefixKey {
            family: if ip.is_ipv4() { 4 } else { 6 },
            bytes: masked_bytes(ip, len),
            len,
        }
    }

    /// The key of the single address (/32 or /128).
    ///
    /// ```
    /// let key = net_io::PrefixKey::exact("10.0.0.1".parse().unwrap());
    /// assert_eq!(key.prefix_len(), 32);
    /// ```
    #[must_use]
    pub fn exact(ip: IpAddr) -> PrefixKey {
        PrefixKey::of(ip, PrefixPolicy::HOST)
    }

    /// The network address of the key.
    ///
    /// ```
    /// let key = net_io::PrefixKey::of("10.1.2.3".parse().unwrap(), net_io::PrefixPolicy::new(8, 64)?);
    /// assert_eq!(key.network().to_string(), "10.0.0.0");
    /// # Ok::<(), net_io::AddrError>(())
    /// ```
    #[must_use]
    pub fn network(&self) -> IpAddr {
        ip_from_bytes(self.family == 4, &self.bytes)
    }

    /// The prefix length of the key.
    #[must_use]
    pub fn prefix_len(&self) -> u8 {
        self.len
    }
}

impl fmt::Display for PrefixKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network(), self.len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn test_normalize_mapped_v6_becomes_v4() {
        assert_eq!(normalize(ip("::ffff:1.2.3.4")), ip("1.2.3.4"));
    }

    #[test]
    fn test_normalize_nat64_untouched() {
        assert_eq!(normalize(ip("64:ff9b::102:304")), ip("64:ff9b::102:304"));
    }

    #[test]
    fn test_normalize_socket_keeps_port_and_scope() {
        let a: SocketAddr = "[fe80::1%3]:80".parse().unwrap();
        assert_eq!(normalize_socket(a), a);
    }

    #[test]
    fn test_cidr_parse_valid_forms() {
        assert_eq!(Cidr::parse("10.0.0.0/8").unwrap().to_string(), "10.0.0.0/8");
        assert_eq!(
            Cidr::parse("2001:db8::/32").unwrap().to_string(),
            "2001:db8::/32"
        );
        assert_eq!(Cidr::parse("192.0.2.7").unwrap().prefix_len(), 32);
        assert_eq!(Cidr::parse("0.0.0.0/0").unwrap().prefix_len(), 0);
    }

    #[test]
    fn test_cidr_parse_rejects_bad_text() {
        assert_eq!(Cidr::parse(""), Err(AddrError::Empty));
        assert!(matches!(
            Cidr::parse("10.0.0.0/"),
            Err(AddrError::Syntax { .. })
        ));
        assert!(matches!(
            Cidr::parse("10.0.0.0/08"),
            Err(AddrError::Syntax { .. })
        ));
        assert!(matches!(
            Cidr::parse("10.0.0.0/+8"),
            Err(AddrError::Syntax { .. })
        ));
        assert!(matches!(
            Cidr::parse("010.0.0.0/8"),
            Err(AddrError::Syntax { .. })
        ));
        assert!(matches!(
            Cidr::parse(" 10.0.0.0/8"),
            Err(AddrError::Syntax { .. })
        ));
        assert!(matches!(
            Cidr::parse("fe80::1%3/64"),
            Err(AddrError::Syntax { .. })
        ));
        assert_eq!(
            Cidr::parse("10.0.0.0/33"),
            Err(AddrError::PrefixTooLong { max: 32 })
        );
        assert_eq!(
            Cidr::parse("::/129"),
            Err(AddrError::PrefixTooLong { max: 128 })
        );
        assert_eq!(Cidr::parse("10.0.0.1/8"), Err(AddrError::HostBitsSet));
    }

    #[test]
    fn test_cidr_mapped_block_normalizes_to_v4() {
        let c = Cidr::parse("::ffff:10.0.0.0/104").unwrap();
        assert_eq!(c.to_string(), "10.0.0.0/8");
        assert!(matches!(
            Cidr::parse("::ffff:10.0.0.0/64"),
            Err(AddrError::Syntax { .. })
        ));
    }

    #[test]
    fn test_cidr_contains_boundaries() {
        let c = Cidr::parse("192.0.2.0/31").unwrap();
        assert!(c.contains(ip("192.0.2.0")));
        assert!(c.contains(ip("192.0.2.1")));
        assert!(!c.contains(ip("192.0.2.2")));
        assert!(!c.contains(ip("::1")));
        let all = Cidr::parse("::/0").unwrap();
        assert!(all.contains(ip("2001:db8::1")));
        assert!(!all.contains(ip("1.1.1.1")));
    }

    #[test]
    fn test_cidr_new_masked_clears_bits() {
        let c = Cidr::new_masked(ip("2001:db8:ffff::1"), 33).unwrap();
        assert_eq!(c.to_string(), "2001:db8:8000::/33");
    }

    #[test]
    fn test_prefix_key_groups_by_policy() {
        let p = PrefixPolicy::new(24, 56).unwrap();
        assert_eq!(
            PrefixKey::of(ip("1.2.3.4"), p),
            PrefixKey::of(ip("1.2.3.200"), p)
        );
        assert_ne!(
            PrefixKey::of(ip("1.2.3.4"), p),
            PrefixKey::of(ip("1.2.4.4"), p)
        );
        assert_eq!(
            PrefixKey::of(ip("2001:db8:0:ff12::1"), p).to_string(),
            "2001:db8:0:ff00::/56"
        );
    }

    #[test]
    fn test_prefix_key_v4_and_v6_never_equal() {
        let p = PrefixPolicy::new(0, 0).unwrap();
        assert_ne!(PrefixKey::of(ip("0.0.0.0"), p), PrefixKey::of(ip("::"), p));
    }

    #[test]
    fn test_prefix_key_mapped_equals_v4() {
        assert_eq!(
            PrefixKey::exact(ip("::ffff:9.9.9.9")),
            PrefixKey::exact(ip("9.9.9.9"))
        );
    }

    #[test]
    fn test_prefix_key_size_is_eighteen_bytes() {
        assert_eq!(std::mem::size_of::<PrefixKey>(), 18);
    }

    #[test]
    fn test_policy_bounds() {
        assert!(PrefixPolicy::new(32, 128).is_ok());
        assert_eq!(
            PrefixPolicy::new(0, 129),
            Err(AddrError::PrefixTooLong { max: 128 })
        );
    }

    /// Property: `Cidr::contains` and `PrefixKey` grouping agree with integer masks.
    #[test]
    fn prop_cidr_and_prefix_key_match_integer_masks() {
        use crate::testing::Gen;
        let mut g = Gen::new(0xADD2_0001);
        for _ in 0..if cfg!(miri) { 200 } else { 20_000 } {
            if g.chance(2) {
                let net = g.next_u64() as u32;
                let p = g.below(33) as u32;
                let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
                // Half the probes share the prefix, so both answers are exercised.
                let ip = if g.chance(2) {
                    (net & mask) | (g.next_u64() as u32 & !mask)
                } else {
                    g.next_u64() as u32
                };
                let (net_ip, probe) = (
                    IpAddr::from(std::net::Ipv4Addr::from(net)),
                    IpAddr::from(std::net::Ipv4Addr::from(ip)),
                );
                let block = Cidr::new_masked(net_ip, p as u8).unwrap();
                let inside = ip & mask == net & mask;
                assert_eq!(block.contains(probe), inside, "{block} {probe}");
                let policy = PrefixPolicy::new(p as u8, 64).unwrap();
                assert_eq!(
                    PrefixKey::of(probe, policy) == PrefixKey::of(net_ip, policy),
                    inside
                );
            } else {
                let net = (u128::from(g.next_u64()) << 64) | u128::from(g.next_u64());
                // Keep clear of the IPv4-mapped block, which normalizes to IPv4.
                let net = net | (1u128 << 127);
                let p = g.below(129) as u32;
                let mask = if p == 0 { 0 } else { u128::MAX << (128 - p) };
                let rand =
                    (u128::from(g.next_u64()) << 64) | u128::from(g.next_u64()) | (1u128 << 127);
                let ip = if g.chance(2) {
                    (net & mask) | (rand & !mask)
                } else {
                    rand
                };
                let (net_ip, probe) = (
                    IpAddr::from(std::net::Ipv6Addr::from(net)),
                    IpAddr::from(std::net::Ipv6Addr::from(ip)),
                );
                let block = Cidr::new_masked(net_ip, p as u8).unwrap();
                let inside = ip & mask == net & mask;
                assert_eq!(block.contains(probe), inside, "{block} {probe}");
                let policy = PrefixPolicy::new(32, p as u8).unwrap();
                assert_eq!(
                    PrefixKey::of(probe, policy) == PrefixKey::of(net_ip, policy),
                    inside
                );
            }
        }
    }
}
