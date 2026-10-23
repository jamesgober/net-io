//! The one list of proxies whose claims about the client address are believed.

use std::net::IpAddr;

use crate::addr::{AddrError, Cidr, normalize};

/// The proxies whose claims about the client address are believed: PROXY
/// headers here, and `X-Forwarded-For` / `Forwarded` in the web layer, which
/// should use the same value. Keep it minimal: a trusted proxy can claim any
/// client address.
///
/// Sorted, deduplicated, at most [`TrustedProxies::MAX`] blocks. `contains` is a
/// binary search over the blocks merged into disjoint ranges, IPv4 and IPv6 kept
/// apart; it allocates nothing.
///
/// # Examples
///
/// ```
/// use net_io::TrustedProxies;
/// let proxies = TrustedProxies::parse("10.0.0.0/8, 192.168.1.10 ::1")?;
/// assert!(proxies.contains("10.4.5.6".parse().unwrap()));
/// assert!(!proxies.contains("8.8.8.8".parse().unwrap()));
/// # Ok::<(), net_io::AddrError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedProxies {
    blocks: Vec<Cidr>,
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl TrustedProxies {
    /// The most blocks a list holds.
    pub const MAX: usize = 1024;

    /// A list of these blocks (duplicates removed).
    ///
    /// # Errors
    ///
    /// [`AddrError::TooMany`] above [`TrustedProxies::MAX`] blocks.
    ///
    /// ```
    /// use net_io::{Cidr, TrustedProxies};
    /// let p = TrustedProxies::new(&[Cidr::parse("10.0.0.0/8")?, Cidr::parse("10.0.0.0/8")?])?;
    /// assert_eq!(p.len(), 1);
    /// # Ok::<(), net_io::AddrError>(())
    /// ```
    pub fn new(blocks: &[Cidr]) -> Result<TrustedProxies, AddrError> {
        if blocks.len() > Self::MAX {
            return Err(AddrError::TooMany { max: Self::MAX });
        }
        let mut sorted = blocks.to_vec();
        sorted.sort_by_key(|c| sort_key(*c));
        sorted.dedup();
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for c in &sorted {
            match c.network() {
                IpAddr::V4(a) => {
                    let start = u32::from(a);
                    let span = if c.prefix_len() == 0 {
                        u32::MAX
                    } else {
                        (1u32 << (32 - u32::from(c.prefix_len()))) - 1
                    };
                    v4.push((start, start | span));
                }
                IpAddr::V6(a) => {
                    let start = u128::from(a);
                    let span = if c.prefix_len() == 0 {
                        u128::MAX
                    } else {
                        (1u128 << (128 - u32::from(c.prefix_len()))) - 1
                    };
                    v6.push((start, start | span));
                }
            }
        }
        Ok(TrustedProxies {
            blocks: sorted,
            v4: merge(v4),
            v6: merge(v6),
        })
    }

    /// Parses blocks or addresses separated by commas or whitespace (a bare
    /// address is a /32 or /128).
    ///
    /// # Errors
    ///
    /// As [`Cidr::parse`] (with `Syntax { at }` counted from the start of `text`),
    /// [`AddrError::Empty`] when there is no entry, [`AddrError::TooMany`].
    ///
    /// ```
    /// let p = net_io::TrustedProxies::parse("127.0.0.1, ::1")?;
    /// assert_eq!(p.len(), 2);
    /// assert!(net_io::TrustedProxies::parse("10.0.0.1/8").is_err()); // host bits set
    /// # Ok::<(), net_io::AddrError>(())
    /// ```
    pub fn parse(text: &str) -> Result<TrustedProxies, AddrError> {
        let mut blocks = Vec::new();
        let mut start = None;
        for (i, ch) in text
            .char_indices()
            .chain(std::iter::once((text.len(), ' ')))
        {
            let separator = ch == ',' || ch.is_whitespace();
            match (start, separator) {
                (None, false) => start = Some(i),
                (Some(s), true) => {
                    if blocks.len() == Self::MAX {
                        return Err(AddrError::TooMany { max: Self::MAX });
                    }
                    let block = Cidr::parse(&text[s..i]).map_err(|e| match e {
                        AddrError::Syntax { at } => AddrError::Syntax { at: s + at },
                        other => other,
                    })?;
                    blocks.push(block);
                    start = None;
                }
                _ => {}
            }
        }
        if blocks.is_empty() {
            return Err(AddrError::Empty);
        }
        TrustedProxies::new(&blocks)
    }

    /// Trusts nobody.
    ///
    /// ```
    /// assert!(net_io::TrustedProxies::none().is_empty());
    /// ```
    #[must_use]
    pub fn none() -> TrustedProxies {
        TrustedProxies {
            blocks: Vec::new(),
            v4: Vec::new(),
            v6: Vec::new(),
        }
    }

    /// `127.0.0.0/8` and `::1/128`: a proxy on the same host.
    ///
    /// ```
    /// assert!(net_io::TrustedProxies::loopback().contains("127.0.0.1".parse().unwrap()));
    /// ```
    #[must_use]
    pub fn loopback() -> TrustedProxies {
        let blocks = [
            Cidr::new(IpAddr::from([127, 0, 0, 0]), 8),
            Cidr::new(IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 1]), 128),
        ];
        let blocks: Vec<Cidr> = blocks.into_iter().flatten().collect();
        TrustedProxies::new(&blocks).unwrap_or_else(|_| TrustedProxies::none())
    }

    /// Whether `ip` (normalized first, so an IPv4-mapped address matches IPv4
    /// blocks) belongs to a trusted proxy. No allocation.
    ///
    /// ```
    /// let p = net_io::TrustedProxies::parse("10.0.0.0/8")?;
    /// assert!(p.contains("::ffff:10.1.2.3".parse().unwrap()));
    /// # Ok::<(), net_io::AddrError>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match normalize(ip) {
            IpAddr::V4(a) => in_ranges(&self.v4, u32::from(a)),
            IpAddr::V6(a) => in_ranges(&self.v6, u128::from(a)),
        }
    }

    /// The number of blocks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Whether the list is empty (trusts nobody).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// The blocks, sorted (IPv4 first, then by network and prefix).
    pub fn iter(&self) -> impl Iterator<Item = Cidr> + '_ {
        self.blocks.iter().copied()
    }
}

fn sort_key(c: Cidr) -> (u8, u128, u8) {
    match c.network() {
        IpAddr::V4(a) => (4, u128::from(u32::from(a)), c.prefix_len()),
        IpAddr::V6(a) => (6, u128::from(a), c.prefix_len()),
    }
}

/// Sorted, inclusive ranges merged so they are disjoint and not adjacent.
fn merge<T: Copy + Ord + Step>(mut ranges: Vec<(T, T)>) -> Vec<(T, T)> {
    ranges.sort_unstable();
    let mut out: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match out.last_mut() {
            Some(last) if start <= last.1.next_or_max() => last.1 = last.1.max(end),
            _ => out.push((start, end)),
        }
    }
    out.shrink_to_fit();
    out
}

fn in_ranges<T: Copy + Ord>(ranges: &[(T, T)], x: T) -> bool {
    // The last range starting at or before `x`.
    let i = ranges.partition_point(|r| r.0 <= x);
    i > 0 && x <= ranges[i - 1].1
}

/// The successor of a range end, saturating, for merging adjacent ranges.
trait Step {
    fn next_or_max(self) -> Self;
}

impl Step for u32 {
    fn next_or_max(self) -> Self {
        self.saturating_add(1)
    }
}

impl Step for u128 {
    fn next_or_max(self) -> Self {
        self.saturating_add(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn test_trusted_parse_mixed_separators_and_bare_addresses() {
        let p = TrustedProxies::parse(" 10.0.0.0/8,192.168.1.10\t::1 ,, 2001:db8::/32 ").unwrap();
        assert_eq!(p.len(), 4);
        assert!(p.contains(ip("10.255.255.255")));
        assert!(p.contains(ip("192.168.1.10")));
        assert!(!p.contains(ip("192.168.1.11")));
        assert!(p.contains(ip("::1")));
        assert!(p.contains(ip("2001:db8:ffff::1")));
        assert!(!p.contains(ip("2001:db9::1")));
        assert!(!p.contains(ip("11.0.0.0")));
    }

    #[test]
    fn test_trusted_parse_errors() {
        assert_eq!(TrustedProxies::parse(" , "), Err(AddrError::Empty));
        assert_eq!(
            TrustedProxies::parse("10.0.0.0/8, nope"),
            Err(AddrError::Syntax { at: 12 })
        );
        assert_eq!(
            TrustedProxies::parse("10.0.0.1/8"),
            Err(AddrError::HostBitsSet)
        );
        let many: String = (0..1025u32)
            .map(|i| format!("10.{}.{}.0/24 ", i / 256, i % 256))
            .collect();
        assert_eq!(
            TrustedProxies::parse(&many),
            Err(AddrError::TooMany { max: 1024 })
        );
    }

    #[test]
    fn test_trusted_nested_and_adjacent_blocks_merge() {
        let p = TrustedProxies::parse("10.0.0.0/8 10.1.0.0/16 11.0.0.0/8 0.0.0.0/1").unwrap();
        assert_eq!(p.len(), 4, "iter keeps every distinct block");
        assert_eq!(
            p.v4,
            vec![(0, u32::from(std::net::Ipv4Addr::new(127, 255, 255, 255)))]
        );
        assert!(p.contains(ip("11.200.0.1")));
        assert!(!p.contains(ip("128.0.0.0")));
    }

    #[test]
    fn test_trusted_whole_space_and_none() {
        let all = TrustedProxies::parse("0.0.0.0/0 ::/0").unwrap();
        assert!(all.contains(ip("255.255.255.255")));
        assert!(all.contains(ip("ffff::1")));
        let none = TrustedProxies::none();
        assert!(!none.contains(ip("127.0.0.1")));
        let lo = TrustedProxies::loopback();
        assert_eq!(lo.len(), 2);
        assert!(lo.contains(ip("127.9.9.9")) && lo.contains(ip("::1")) && !lo.contains(ip("::2")));
    }

    /// Property: `contains` agrees with checking every block one by one.
    #[test]
    fn prop_trusted_contains_matches_a_linear_scan() {
        use crate::testing::Gen;
        let mut g = Gen::new(0x7275_5354);
        for _ in 0..if cfg!(miri) { 20 } else { 2000 } {
            let n = 1 + g.below(12) as usize;
            let blocks: Vec<Cidr> = (0..n)
                .map(|_| {
                    let a = std::net::Ipv4Addr::from(g.next_u64() as u32 & 0x0F0F_FFFF);
                    Cidr::new_masked(IpAddr::V4(a), 8 + g.below(25) as u8).unwrap()
                })
                .collect();
            let p = TrustedProxies::new(&blocks).unwrap();
            for _ in 0..50 {
                let probe = IpAddr::V4(std::net::Ipv4Addr::from(g.next_u64() as u32 & 0x0F0F_FFFF));
                assert_eq!(
                    p.contains(probe),
                    blocks.iter().any(|b| b.contains(probe)),
                    "{blocks:?} {probe}"
                );
            }
        }
    }
}
