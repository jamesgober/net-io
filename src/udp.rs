//! UDP: a bound socket that reports truncated datagrams, budgets sources, and
//! never amplifies (FR-49 to FR-51).
//!
//! UDP source addresses are trivially spoofed, so the guard sits between the
//! socket and the caller: every datagram is charged to its source's budget
//! (and the global one) before it is returned, and every send to a source that
//! has not proved it can receive is limited to `factor` times what it sent us.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV6, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::addr::normalize;
use crate::error::{ConfigReason, LimitKind, NetError, TimeoutKind};
use crate::sys::{self, AsSock};

/// Rates for one budget: datagrams and bytes per second, and how many datagrams
/// may arrive at once. The byte bucket holds one second of bytes.
///
/// ```
/// let budget = net_io::UdpBudget { datagrams_per_sec: 100, bytes_per_sec: 150_000, burst: 20 };
/// # let _ = budget;
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpBudget {
    /// Datagrams per second, sustained.
    pub datagrams_per_sec: u32,
    /// Bytes per second, sustained.
    pub bytes_per_sec: u32,
    /// Datagrams that may arrive at once (the datagram bucket's depth).
    pub burst: u32,
}

impl UdpBudget {
    /// The default per-source budget: 1,000 datagrams and 1 MB per second,
    /// bursts of 100.
    pub const SOURCE_DEFAULT: UdpBudget = UdpBudget {
        datagrams_per_sec: 1_000,
        bytes_per_sec: 1_000_000,
        burst: 100,
    };
}

/// Options for [`UdpSocket::bind_with`].
///
/// ```
/// use net_io::{UdpBudget, UdpOptions};
/// let options = UdpOptions::new()
///     .amplification_factor(3) // a QUIC handshake (RFC 9000)
///     .global_budget(UdpBudget { datagrams_per_sec: 50_000, bytes_per_sec: 60_000_000, burst: 5_000 });
/// # let _ = options;
/// ```
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpOptions {
    factor: u8,
    window: Duration,
    source: UdpBudget,
    global: Option<UdpBudget>,
    table: u32,
    ipv6_only: bool,
    packet_info: bool,
}

impl Default for UdpOptions {
    fn default() -> UdpOptions {
        UdpOptions::new()
    }
}

impl UdpOptions {
    /// Factor 1, a 10 s window, [`UdpBudget::SOURCE_DEFAULT`] per source, no
    /// global budget, 65,536 sources, IPv6-only for IPv6 addresses.
    pub fn new() -> UdpOptions {
        UdpOptions {
            factor: 1,
            window: Duration::from_secs(10),
            source: UdpBudget::SOURCE_DEFAULT,
            global: None,
            table: 65_536,
            ipv6_only: true,
            packet_info: false,
        }
    }

    /// How many times the bytes received from an unverified source may be sent
    /// back to it (1 by default, at most 3; decision D-034).
    pub fn amplification_factor(mut self, factor: u8) -> UdpOptions {
        self.factor = factor;
        self
    }

    /// How long received bytes count toward a source's send allowance (10 s by
    /// default, at least 1 s). The allowance spans the current and the previous
    /// window, so a reply just after a window boundary is not refused.
    pub fn amplification_window(mut self, window: Duration) -> UdpOptions {
        self.window = window;
        self
    }

    /// The budget of each source address.
    pub fn source_budget(mut self, budget: UdpBudget) -> UdpOptions {
        self.source = budget;
        self
    }

    /// A budget for the whole socket (none by default).
    pub fn global_budget(mut self, budget: UdpBudget) -> UdpOptions {
        self.global = Some(budget);
        self
    }

    /// How many sources are tracked (65,536 by default, about 130 bytes each).
    pub fn source_table(mut self, entries: u32) -> UdpOptions {
        self.table = entries;
        self
    }

    /// `IPV6_V6ONLY` for an IPv6 address (on by default). Off, an IPv6 socket also
    /// receives IPv4; sources are reported as IPv4 and replies to them work.
    /// Reports each datagram's destination address in [`Datagram::destination`], for a
    /// socket bound to a wildcard that must answer from the address it was asked on.
    /// One `recvmsg` per datagram instead of `recvfrom`. Unix only: `bind_with` fails
    /// with `Unsupported` on Windows, and `recv_batch` does not fill it.
    pub fn packet_info(mut self, on: bool) -> UdpOptions {
        self.packet_info = on;
        self
    }

    /// `IPV6_V6ONLY` for IPv6 addresses (on by default).
    pub fn ipv6_only(mut self, on: bool) -> UdpOptions {
        self.ipv6_only = on;
        self
    }

    fn validate(&self) -> Result<(), NetError> {
        let invalid = |field, reason| Err(NetError::InvalidConfig { field, reason });
        if self.factor == 0 {
            return invalid("amplification_factor", ConfigReason::Zero);
        }
        if self.factor > 3 {
            return invalid("amplification_factor", ConfigReason::TooLarge { max: 3 });
        }
        if self.window < Duration::from_secs(1) {
            return invalid("amplification_window", ConfigReason::TooSmall { min: 1 });
        }
        if self.table == 0 {
            return invalid("source_table", ConfigReason::Zero);
        }
        for (field, b) in [
            ("source_budget", Some(self.source)),
            ("global_budget", self.global),
        ] {
            if let Some(b) = b {
                if b.datagrams_per_sec == 0 || b.bytes_per_sec == 0 || b.burst == 0 {
                    return invalid(field, ConfigReason::Zero);
                }
            }
        }
        Ok(())
    }
}

/// One received datagram.
///
/// ```
/// let d = net_io::Datagram { len: 3, from: "127.0.0.1:9".parse().unwrap(), truncated: false, destination: None };
/// assert!(!d.truncated);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Datagram {
    /// Its length. When `truncated`: the real length on Linux, the bytes copied
    /// (the buffer's length) elsewhere; never index the buffer with it then.
    pub len: usize,
    /// Its source, normalized.
    pub from: SocketAddr,
    /// It did not fit the buffer and was cut.
    pub truncated: bool,
    /// The local address it was sent to (packet info, `0.6.0`; always `None` before).
    pub destination: Option<IpAddr>,
}

/// Counters of one socket since it was bound.
///
/// ```
/// let s = net_io::UdpSocket::bind("127.0.0.1:0")?.stats();
/// assert_eq!(s.received, 0);
/// # Ok::<(), net_io::NetError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UdpStats {
    /// Datagrams returned to the caller.
    pub received: u64,
    /// Datagrams sent.
    pub sent: u64,
    /// Datagrams read and dropped because their source or the socket was over budget.
    pub dropped: u64,
    /// Sends refused by the amplification guard.
    pub refused: u64,
    /// Datagrams returned truncated.
    pub truncated: u64,
    /// ICMP error reports read from the socket and ignored.
    pub icmp_errors: u64,
    /// Datagrams from sources that found the table full (the shared overflow budget).
    pub overflow: u64,
    /// Sources tracked now.
    pub sources: u32,
}

/// A token bucket in micro-tokens: one token per datagram, one per byte.
#[derive(Clone, Copy, Debug)]
struct Bucket {
    datagrams: u64,
    bytes: u64,
    at: Instant,
}

const MICRO: u64 = 1_000_000;

impl Bucket {
    fn full(budget: &UdpBudget, now: Instant) -> Bucket {
        Bucket {
            datagrams: u64::from(budget.burst) * MICRO,
            bytes: u64::from(budget.bytes_per_sec) * MICRO,
            at: now,
        }
    }

    /// Refills for the time passed and takes one datagram of `len` bytes.
    fn take(&mut self, budget: &UdpBudget, len: usize, now: Instant) -> bool {
        // Micro-tokens per microsecond equal tokens per second; a gap of more
        // than 1,000 s refills the buckets completely anyway.
        let us = now
            .saturating_duration_since(self.at)
            .as_micros()
            .min(1_000_000_000) as u64;
        self.at = now;
        let cap_d = u64::from(budget.burst) * MICRO;
        let cap_b = u64::from(budget.bytes_per_sec) * MICRO;
        self.datagrams = (self.datagrams + us * u64::from(budget.datagrams_per_sec)).min(cap_d);
        self.bytes = (self.bytes + us * u64::from(budget.bytes_per_sec)).min(cap_b);
        let need_b = (len as u64).saturating_mul(MICRO);
        if self.datagrams >= MICRO && self.bytes >= need_b {
            self.datagrams -= MICRO;
            self.bytes -= need_b;
            true
        } else {
            false
        }
    }
}

/// What the guard knows about one source address.
#[derive(Clone, Copy, Debug)]
struct Entry {
    ip: IpAddr,
    bucket: Bucket,
    received: [u64; 2],
    sent: [u64; 2],
    window_at: Instant,
    verified: bool,
    referenced: bool,
}

impl Entry {
    fn new(ip: IpAddr, budget: &UdpBudget, now: Instant) -> Entry {
        Entry {
            ip,
            bucket: Bucket::full(budget, now),
            received: [0; 2],
            sent: [0; 2],
            window_at: now,
            verified: false,
            referenced: true,
        }
    }

    /// Index 0 is the current window, 1 the previous one.
    fn roll(&mut self, window: Duration, now: Instant) {
        let gone = now.saturating_duration_since(self.window_at);
        if gone >= window * 2 {
            self.received = [0; 2];
            self.sent = [0; 2];
            self.window_at = now;
        } else if gone >= window {
            self.received = [0, self.received[0]];
            self.sent = [0, self.sent[0]];
            self.window_at += window;
        }
    }
}

/// How many entries one insertion may look at before it gives up and uses the
/// overflow budget.
const SWEEP: usize = 64;

/// The source table: a bounded map with CLOCK eviction of unverified entries.
#[derive(Debug)]
struct Guard {
    index: HashMap<IpAddr, u32>,
    slots: Vec<Entry>,
    hand: usize,
    overflow: Bucket,
    global: Option<Bucket>,
    options: UdpOptions,
}

impl Guard {
    fn new(options: UdpOptions, now: Instant) -> Guard {
        Guard {
            index: HashMap::new(),
            slots: Vec::new(),
            hand: 0,
            overflow: Bucket::full(&options.source, now),
            global: options.global.map(|g| Bucket::full(&g, now)),
            options,
        }
    }

    fn find(&mut self, ip: IpAddr) -> Option<usize> {
        let i = *self.index.get(&ip)? as usize;
        self.slots[i].referenced = true;
        Some(i)
    }

    /// Finds or makes room for `ip`. `force` (verification) may evict a
    /// recently used unverified entry; plain traffic may not.
    fn slot(&mut self, ip: IpAddr, now: Instant, force: bool) -> Option<usize> {
        if let Some(i) = self.find(ip) {
            return Some(i);
        }
        let entry = Entry::new(ip, &self.options.source, now);
        if self.slots.len() < self.options.table as usize {
            self.slots.push(entry);
            let i = self.slots.len() - 1;
            self.index.insert(ip, i as u32);
            return Some(i);
        }
        let n = self.slots.len();
        let looks = if force { 2 * n } else { SWEEP.min(2 * n) };
        for _ in 0..looks {
            let i = self.hand;
            self.hand = (self.hand + 1) % n;
            let e = &mut self.slots[i];
            if e.verified {
                continue;
            }
            if e.referenced {
                e.referenced = false;
                continue;
            }
            self.index.remove(&e.ip);
            *e = entry;
            self.index.insert(ip, i as u32);
            return Some(i);
        }
        None
    }

    /// Charges a received datagram; `false` drops it. `overflow` is set when the
    /// source found no room in the table.
    fn admit(&mut self, ip: IpAddr, len: usize, now: Instant, overflow: &mut bool) -> bool {
        let source = self.options.source;
        let ok = match self.slot(ip, now, false) {
            Some(i) => {
                let window = self.options.window;
                let e = &mut self.slots[i];
                if e.bucket.take(&source, len, now) {
                    e.roll(window, now);
                    e.received[0] += len as u64;
                    true
                } else {
                    false
                }
            }
            None => {
                *overflow = true;
                self.overflow.take(&source, len, now)
            }
        };
        if !ok {
            return false;
        }
        match (&mut self.global, &self.options.global) {
            (Some(bucket), Some(budget)) => bucket.take(budget, len, now),
            _ => true,
        }
    }

    /// Whether `len` bytes may go to `ip` now.
    fn may_send(&mut self, ip: IpAddr, len: usize, now: Instant) -> bool {
        let Some(i) = self.find(ip) else {
            return len == 0;
        };
        let window = self.options.window;
        let factor = u64::from(self.options.factor);
        let e = &mut self.slots[i];
        if e.verified {
            return true;
        }
        e.roll(window, now);
        let allowed = factor * (e.received[0] + e.received[1]);
        e.sent[0] + e.sent[1] + len as u64 <= allowed
    }

    fn sent(&mut self, ip: IpAddr, len: usize) {
        if let Some(&i) = self.index.get(&ip) {
            self.slots[i as usize].sent[0] += len as u64;
        }
    }

    fn verify(&mut self, ip: IpAddr, now: Instant) {
        if let Some(i) = self.slot(ip, now, true) {
            self.slots[i].verified = true;
        }
    }
}

/// A UDP socket with the guard in front of it.
///
/// ```no_run
/// let mut socket = net_io::UdpSocket::bind("0.0.0.0:5353")?;
/// let mut buf = [0u8; 1500];
/// loop {
///     let datagram = socket.recv_from(&mut buf)?;
///     if datagram.truncated {
///         continue; // larger than we accept
///     }
///     // Replies are limited to the size of what the peer sent until it is verified.
///     socket.send_to(&buf[..datagram.len], datagram.from)?;
/// }
/// # Ok::<(), net_io::NetError>(())
/// ```
#[derive(Debug)]
pub struct UdpSocket {
    inner: std::net::UdpSocket,
    guard: Guard,
    read_timeout: Option<Duration>,
    peer: Option<SocketAddr>,
    v6: bool,
    #[cfg_attr(windows, allow(dead_code))]
    packet_info: bool,
    stats: UdpStats,
}

/// A receive buffer of a batch; [`UdpSocket::recv_batch`] fills `datagram`.
///
/// ```
/// let mut bytes = [0u8; 1500];
/// let slot = net_io::DatagramBuffer::new(&mut bytes);
/// assert!(slot.datagram.is_none());
/// ```
#[derive(Debug)]
pub struct DatagramBuffer<'a> {
    /// Where the bytes land.
    pub buf: &'a mut [u8],
    /// What arrived; `None` for a slot not filled, or dropped over budget.
    pub datagram: Option<Datagram>,
}

impl<'a> DatagramBuffer<'a> {
    /// An empty slot over `buf`.
    #[must_use]
    pub fn new(buf: &'a mut [u8]) -> DatagramBuffer<'a> {
        DatagramBuffer {
            buf,
            datagram: None,
        }
    }
}

/// One datagram of a batch to send.
///
/// ```
/// let d = net_io::OutgoingDatagram { bytes: b"hi", to: "127.0.0.1:9".parse().unwrap() };
/// assert_eq!(d.bytes.len(), 2);
/// ```
#[derive(Clone, Copy, Debug)]
pub struct OutgoingDatagram<'a> {
    /// The bytes.
    pub bytes: &'a [u8],
    /// The destination.
    pub to: SocketAddr,
}

/// Which interface joins a multicast group.
///
/// ```
/// let any = net_io::MulticastInterface::Any;
/// # let _ = any;
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MulticastInterface {
    /// The one the OS picks.
    Any,
    /// The IPv4 interface with this address.
    V4(Ipv4Addr),
    /// The IPv6 interface with this index.
    V6Index(u32),
}

impl UdpSocket {
    /// Binds with [`UdpOptions::new`]. The first resolved address that binds wins.
    ///
    /// # Errors
    ///
    /// `AddrInUse`, `AddrNotAvailable`, `PermissionDenied`, `NoAddresses`, `Bind`.
    pub fn bind<A: ToSocketAddrs>(addr: A) -> Result<UdpSocket, NetError> {
        UdpSocket::bind_with(addr, UdpOptions::new())
    }

    /// Binds with `options`.
    ///
    /// # Errors
    ///
    /// As [`UdpSocket::bind`]; `InvalidConfig` for an option out of range.
    pub fn bind_with<A: ToSocketAddrs>(
        addr: A,
        options: UdpOptions,
    ) -> Result<UdpSocket, NetError> {
        options.validate()?;
        let addrs: Vec<SocketAddr> = addr
            .to_socket_addrs()
            .map_err(|e| NetError::Os {
                op: "resolve",
                source: e,
            })?
            .collect();
        let mut last = NetError::NoAddresses;
        if options.packet_info && !cfg!(unix) {
            return Err(NetError::Unsupported {
                feature: "UDP packet info",
                platform: std::env::consts::OS,
            });
        }
        let packet_info = options.packet_info;
        for a in addrs {
            match sys::udp_bind(a, options.ipv6_only) {
                Ok(inner) => {
                    #[cfg(unix)]
                    if packet_info {
                        sys::udp_packet_info(inner.sock(), a.is_ipv6())
                            .map_err(|e| NetError::from_os("setsockopt", e))?;
                    }
                    return Ok(UdpSocket {
                        inner,
                        guard: Guard::new(options, Instant::now()),
                        read_timeout: None,
                        peer: None,
                        v6: a.is_ipv6(),
                        packet_info,
                        stats: UdpStats::default(),
                    });
                }
                Err(e) => last = crate::tcp::bind_error(a, e),
            }
        }
        Err(last)
    }

    /// Receives one datagram within the budgets. Datagrams over budget are read,
    /// dropped, and counted; ICMP error reports are counted and never end the
    /// socket. Under a flood the call returns within twice the read timeout.
    ///
    /// # Errors
    ///
    /// `TimedOut { kind: Read }` (only with a read timeout), `Os`.
    pub fn recv_from(&mut self, buf: &mut [u8]) -> Result<Datagram, NetError> {
        let deadline = self.read_timeout.map(|t| Instant::now() + t);
        loop {
            let (len, from, truncated, destination) = match self.recv_one(buf) {
                Ok(got) => got,
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                        return Err(NetError::TimedOut {
                            kind: TimeoutKind::Read,
                        });
                    }
                    io::ErrorKind::Interrupted => continue,
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset => {
                        // An ICMP report about an earlier send: never fatal (edge case 92).
                        self.stats.icmp_errors += 1;
                        if past(deadline) {
                            return Err(NetError::TimedOut {
                                kind: TimeoutKind::Read,
                            });
                        }
                        continue;
                    }
                    _ => return Err(NetError::from_os("recvfrom", e)),
                },
            };
            let from = crate::addr::normalize_socket(from);
            if !self.admit(from, len, truncated) {
                if past(deadline) {
                    return Err(NetError::TimedOut {
                        kind: TimeoutKind::Read,
                    });
                }
                continue;
            }
            return Ok(Datagram {
                len,
                from,
                truncated,
                destination,
            });
        }
    }

    fn recv_one(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, bool, Option<IpAddr>)> {
        #[cfg(unix)]
        if self.packet_info {
            return sys::udp_recv_with_destination(self.inner.sock(), buf);
        }
        let (len, from, truncated) = sys::udp_recv_from(self.inner.sock(), buf)?;
        Ok((len, from, truncated, None))
    }

    /// Charges a datagram to its source and counts it.
    fn admit(&mut self, from: SocketAddr, len: usize, truncated: bool) -> bool {
        let mut overflow = false;
        let admitted = self
            .guard
            .admit(from.ip(), len, Instant::now(), &mut overflow);
        if overflow {
            self.stats.overflow += 1;
        }
        if !admitted {
            self.stats.dropped += 1;
            return false;
        }
        self.stats.received += 1;
        if truncated {
            self.stats.truncated += 1;
        }
        true
    }

    /// Waits for a datagram, then takes what else is ready, up to `slots.len()`
    /// (64 at most). Each datagram passes the budgets as in [`UdpSocket::recv_from`]:
    /// one that does not leaves its slot's `datagram` at `None`, so walk every slot.
    /// One system call on Linux (`recvmmsg`), a loop elsewhere. Returns how many
    /// slots hold a datagram. Packet info is not reported here.
    ///
    /// # Errors
    ///
    /// As [`UdpSocket::recv_from`].
    pub fn recv_batch(&mut self, slots: &mut [DatagramBuffer<'_>]) -> Result<usize, NetError> {
        for slot in slots.iter_mut() {
            slot.datagram = None;
        }
        if slots.is_empty() {
            return Ok(0);
        }
        self.recv_many(slots)
    }

    #[cfg(target_os = "linux")]
    fn recv_many(&mut self, slots: &mut [DatagramBuffer<'_>]) -> Result<usize, NetError> {
        let count = slots.len().min(sys::BATCH_MAX);
        let mut got = [None; sys::BATCH_MAX];
        let n = loop {
            let received = {
                let mut bufs: [&mut [u8]; sys::BATCH_MAX] = std::array::from_fn(|_| &mut [][..]);
                for (b, slot) in bufs.iter_mut().zip(slots.iter_mut()).take(count) {
                    *b = &mut *slot.buf;
                }
                sys::udp_recv_many(self.inner.sock(), &mut bufs[..count], &mut got)
            };
            match received {
                Ok(n) => break n,
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                        return Err(NetError::TimedOut {
                            kind: TimeoutKind::Read,
                        });
                    }
                    io::ErrorKind::Interrupted => {}
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset => {
                        self.stats.icmp_errors += 1;
                    }
                    _ => return Err(NetError::from_os("recvmmsg", e)),
                },
            }
        };
        let mut filled = 0;
        for (slot, r) in slots.iter_mut().zip(got.iter()).take(n) {
            let Some(r) = r else { continue };
            let from = crate::addr::normalize_socket(r.from);
            if self.admit(from, r.len, r.truncated) {
                slot.datagram = Some(Datagram {
                    len: r.len,
                    from,
                    truncated: r.truncated,
                    destination: None,
                });
                filled += 1;
            }
        }
        Ok(filled)
    }

    #[cfg(not(target_os = "linux"))]
    fn recv_many(&mut self, slots: &mut [DatagramBuffer<'_>]) -> Result<usize, NetError> {
        let (first, rest) = match slots.split_first_mut() {
            Some(parts) => parts,
            None => return Ok(0),
        };
        first.datagram = Some(self.recv_from(first.buf)?);
        let mut filled = 1;
        self.inner
            .set_nonblocking(true)
            .map_err(|e| NetError::from_os("ioctl", e))?;
        for slot in rest.iter_mut().take(63) {
            match self.recv_from(slot.buf) {
                Ok(d) => {
                    slot.datagram = Some(d);
                    filled += 1;
                }
                Err(_) => break,
            }
        }
        self.inner
            .set_nonblocking(false)
            .map_err(|e| NetError::from_os("ioctl", e))?;
        Ok(filled)
    }

    /// Sends from the front of `datagrams`, each under the guard of
    /// [`UdpSocket::send_to`], until one is refused or the OS takes no more. One system
    /// call per 64 on Linux (`sendmmsg`), a loop elsewhere. Returns how many went.
    ///
    /// # Errors
    ///
    /// `Limit { which: Amplification }` when the first is refused, `Os`.
    pub fn send_batch(&mut self, datagrams: &[OutgoingDatagram<'_>]) -> Result<usize, NetError> {
        let mut sent = 0;
        while sent < datagrams.len() {
            match self.send_some(&datagrams[sent..]) {
                Ok(0) => break,
                Ok(n) => sent += n,
                Err(e) if sent == 0 => return Err(e),
                Err(_) => break,
            }
        }
        Ok(sent)
    }

    /// The guard's prefix of `datagrams`. Charged before the send, so a short send
    /// leaves the peer's allowance smaller, never larger.
    fn charge(&mut self, datagrams: &[OutgoingDatagram<'_>]) -> Result<usize, NetError> {
        let now = Instant::now();
        let mut allowed = 0;
        for d in datagrams.iter().take(64) {
            let ip = normalize(d.to.ip());
            if !self.guard.may_send(ip, d.bytes.len(), now) {
                self.stats.refused += 1;
                break;
            }
            self.guard.sent(ip, d.bytes.len());
            allowed += 1;
        }
        if allowed == 0 && !datagrams.is_empty() {
            return Err(NetError::Limit {
                which: LimitKind::Amplification,
            });
        }
        Ok(allowed)
    }

    #[cfg(target_os = "linux")]
    fn send_some(&mut self, datagrams: &[OutgoingDatagram<'_>]) -> Result<usize, NetError> {
        let allowed = self.charge(datagrams)?;
        let mut wire = [(&[][..], SocketAddr::from(([0, 0, 0, 0], 0))); sys::BATCH_MAX];
        for (w, d) in wire.iter_mut().zip(datagrams.iter().take(allowed)) {
            *w = (d.bytes, self.wire(d.to));
        }
        let n = sys::udp_send_many(self.inner.sock(), &wire[..allowed])
            .map_err(|e| NetError::from_os("sendmmsg", e))?;
        self.stats.sent += n as u64;
        Ok(n)
    }

    #[cfg(not(target_os = "linux"))]
    fn send_some(&mut self, datagrams: &[OutgoingDatagram<'_>]) -> Result<usize, NetError> {
        let allowed = self.charge(datagrams)?;
        let mut n = 0;
        for d in &datagrams[..allowed] {
            let wire = self.wire(d.to);
            if let Err(e) = self.inner.send_to(d.bytes, wire) {
                if n == 0 {
                    return Err(NetError::from_os("sendto", e));
                }
                break;
            }
            self.stats.sent += 1;
            n += 1;
        }
        Ok(n)
    }

    /// Joins a multicast group. Datagrams to the group then pass the same budgets as
    /// any other; a reply to a group member is still under the amplification guard.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` when the interface's family is not the group's, `Os`.
    pub fn join_multicast(
        &self,
        group: IpAddr,
        interface: MulticastInterface,
    ) -> Result<(), NetError> {
        let result = match (group, interface) {
            (IpAddr::V4(g), MulticastInterface::Any) => {
                self.inner.join_multicast_v4(&g, &Ipv4Addr::UNSPECIFIED)
            }
            (IpAddr::V4(g), MulticastInterface::V4(i)) => self.inner.join_multicast_v4(&g, &i),
            (IpAddr::V6(g), MulticastInterface::Any) => self.inner.join_multicast_v6(&g, 0),
            (IpAddr::V6(g), MulticastInterface::V6Index(i)) => self.inner.join_multicast_v6(&g, i),
            _ => {
                return Err(NetError::InvalidConfig {
                    field: "interface",
                    reason: ConfigReason::Inconsistent,
                });
            }
        };
        result.map_err(|e| NetError::from_os("setsockopt", e))
    }

    /// Receives from the connected peer (see [`UdpSocket::connect`]).
    ///
    /// # Errors
    ///
    /// As [`UdpSocket::recv_from`].
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<Datagram, NetError> {
        self.recv_from(buf)
    }

    /// Sends one datagram. To a source not marked verified, the bytes sent within
    /// the window never exceed `factor` times the bytes received from it; a
    /// source never heard from gets nothing (an empty datagram aside).
    ///
    /// # Errors
    ///
    /// `Limit { which: Amplification }` (nothing was sent), `Os`.
    pub fn send_to(&mut self, buf: &[u8], to: SocketAddr) -> Result<usize, NetError> {
        let ip = normalize(to.ip());
        if !self.guard.may_send(ip, buf.len(), Instant::now()) {
            self.stats.refused += 1;
            return Err(NetError::Limit {
                which: LimitKind::Amplification,
            });
        }
        let wire = self.wire(to);
        let n = self
            .inner
            .send_to(buf, wire)
            .map_err(|e| NetError::from_os("sendto", e))?;
        self.guard.sent(ip, n);
        self.stats.sent += 1;
        Ok(n)
    }

    /// Sends to the connected peer, under the same guard as [`UdpSocket::send_to`].
    ///
    /// # Errors
    ///
    /// `Closed` when not connected; as [`UdpSocket::send_to`].
    pub fn send(&mut self, buf: &[u8]) -> Result<usize, NetError> {
        let peer = self.peer.ok_or(NetError::Closed)?;
        let ip = normalize(peer.ip());
        if !self.guard.may_send(ip, buf.len(), Instant::now()) {
            self.stats.refused += 1;
            return Err(NetError::Limit {
                which: LimitKind::Amplification,
            });
        }
        let n = self
            .inner
            .send(buf)
            .map_err(|e| NetError::from_os("send", e))?;
        self.guard.sent(ip, n);
        self.stats.sent += 1;
        Ok(n)
    }

    /// Fixes the peer: the kernel drops datagrams from other sources, and
    /// [`UdpSocket::send`] goes to it.
    ///
    /// # Errors
    ///
    /// `Os`.
    pub fn connect(&mut self, to: SocketAddr) -> Result<(), NetError> {
        self.inner
            .connect(self.wire(to))
            .map_err(|e| NetError::from_os("connect", e))?;
        self.peer = Some(to);
        Ok(())
    }

    /// The protocol proved `peer` can receive (a cookie, a handshake): the guard
    /// no longer limits sends to it, and its table entry is kept.
    pub fn mark_verified(&mut self, peer: SocketAddr) {
        self.guard.verify(normalize(peer.ip()), Instant::now());
    }

    /// How long a receive waits (`None`: forever, the default).
    ///
    /// # Errors
    ///
    /// `InvalidConfig` for a zero duration, `Os`.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<(), NetError> {
        if timeout == Some(Duration::ZERO) {
            return Err(NetError::InvalidConfig {
                field: "read_timeout",
                reason: ConfigReason::Zero,
            });
        }
        self.inner
            .set_read_timeout(timeout)
            .map_err(|e| NetError::from_os("setsockopt", e))?;
        self.read_timeout = timeout;
        Ok(())
    }

    /// Receives never wait: a server's thread waits in `poll` with its wake channel.
    pub(crate) fn set_nonblocking(&self) -> Result<(), NetError> {
        self.inner
            .set_nonblocking(true)
            .map_err(|e| NetError::from_os("ioctl", e))
    }

    pub(crate) fn raw_sock(&self) -> sys::Sock<'_> {
        self.inner.sock()
    }

    /// The bound address.
    ///
    /// # Errors
    ///
    /// `Os` when `getsockname` fails.
    pub fn local_addr(&self) -> Result<SocketAddr, NetError> {
        self.inner
            .local_addr()
            .map_err(|e| NetError::from_os("getsockname", e))
    }

    /// Counters since the socket was bound.
    #[must_use]
    pub fn stats(&self) -> UdpStats {
        UdpStats {
            sources: self.guard.slots.len() as u32,
            ..self.stats
        }
    }

    /// An IPv4 destination on an IPv6 socket goes out as its IPv4-mapped form.
    fn wire(&self, to: SocketAddr) -> SocketAddr {
        match to {
            SocketAddr::V4(a) if self.v6 => {
                SocketAddr::V6(SocketAddrV6::new(a.ip().to_ipv6_mapped(), a.port(), 0, 0))
            }
            other => other,
        }
    }
}

/// A datagram protocol run by a server: one per UDP listener, called on that listener's
/// thread, so it needs no locks of its own. Budgets and the amplification guard apply
/// before it sees a datagram and on every reply.
///
/// ```
/// use std::net::SocketAddr;
/// use net_io::{UdpContext, UdpSession};
/// struct Echo;
/// impl UdpSession for Echo {
///     fn on_datagram(&mut self, cx: &mut UdpContext<'_>, from: SocketAddr, bytes: &[u8]) {
///         let _ = cx.send_to(bytes, from);
///     }
/// }
/// ```
pub trait UdpSession: Send + 'static {
    /// One datagram that passed its budgets.
    fn on_datagram(&mut self, cx: &mut UdpContext<'_>, from: SocketAddr, bytes: &[u8]);
}

/// What a [`UdpSession`] may do during a call.
#[derive(Debug)]
pub struct UdpContext<'a> {
    pub(crate) socket: &'a mut UdpSocket,
}

impl UdpContext<'_> {
    /// Sends a datagram under the guard of [`UdpSocket::send_to`].
    ///
    /// # Errors
    ///
    /// As [`UdpSocket::send_to`].
    pub fn send_to(&mut self, bytes: &[u8], to: SocketAddr) -> Result<usize, NetError> {
        self.socket.send_to(bytes, to)
    }

    /// As [`UdpSocket::mark_verified`].
    pub fn mark_verified(&mut self, peer: SocketAddr) {
        self.socket.mark_verified(peer);
    }

    /// The time.
    #[must_use]
    pub fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Makes the [`UdpSession`] of each UDP listener; any
/// `Fn(&ListenerInfo) -> impl UdpSession` is one.
pub trait UdpSessionFactory: Send + Sync + 'static {
    /// The session for this listener.
    fn open(&self, listener: &crate::tcp::ListenerInfo) -> Box<dyn UdpSession>;
}

impl<F, S> UdpSessionFactory for F
where
    F: Fn(&crate::tcp::ListenerInfo) -> S + Send + Sync + 'static,
    S: UdpSession,
{
    fn open(&self, listener: &crate::tcp::ListenerInfo) -> Box<dyn UdpSession> {
        Box::new(self(listener))
    }
}

fn past(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|d| Instant::now() >= d)
}

#[cfg(unix)]
impl std::os::fd::AsFd for UdpSocket {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsSocket for UdpSocket {
    fn as_socket(&self) -> std::os::windows::io::BorrowedSocket<'_> {
        self.inner.as_socket()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, n])
    }

    #[test]
    fn test_bucket_refills_at_its_rate() {
        let b = UdpBudget {
            datagrams_per_sec: 10,
            bytes_per_sec: 1_000,
            burst: 2,
        };
        let t = Instant::now();
        let mut bucket = Bucket::full(&b, t);
        assert!(bucket.take(&b, 100, t));
        assert!(bucket.take(&b, 100, t));
        assert!(!bucket.take(&b, 100, t), "burst used up");
        // 100 ms refills one datagram.
        assert!(bucket.take(&b, 100, t + Duration::from_millis(100)));
        // Bytes: the bucket holds one second; 1,001 bytes never pass.
        assert!(!bucket.take(&b, 1_001, t + Duration::from_secs(5)));
    }

    #[test]
    fn test_amplification_factor_one_until_verified() {
        // Edge case 94: a 1-byte request, a 2-byte reply refused until verified.
        let t = Instant::now();
        let mut g = Guard::new(UdpOptions::new(), t);
        let mut o = false;
        assert!(!g.may_send(ip(1), 1, t), "never heard from");
        assert!(g.may_send(ip(1), 0, t));
        assert!(g.admit(ip(1), 1, t, &mut o));
        assert!(!g.may_send(ip(1), 2, t));
        assert!(g.may_send(ip(1), 1, t));
        g.sent(ip(1), 1);
        assert!(!g.may_send(ip(1), 1, t), "the allowance is spent");
        g.verify(ip(1), t);
        assert!(g.may_send(ip(1), 10_000, t));
    }

    #[test]
    fn test_amplification_factor_three_and_the_window() {
        let t = Instant::now();
        let w = Duration::from_secs(10);
        let mut g = Guard::new(UdpOptions::new().amplification_factor(3), t);
        let mut o = false;
        assert!(g.admit(ip(1), 100, t, &mut o));
        assert!(g.may_send(ip(1), 300, t));
        assert!(!g.may_send(ip(1), 301, t));
        // Just after the window edge the previous window still counts.
        assert!(g.may_send(ip(1), 300, t + w + Duration::from_millis(1)));
        // Two windows later it is gone.
        assert!(!g.may_send(ip(1), 1, t + 3 * w));
    }

    #[test]
    fn test_source_budget_drops_and_others_pass() {
        let t = Instant::now();
        let budget = UdpBudget {
            datagrams_per_sec: 1,
            bytes_per_sec: 10_000,
            burst: 3,
        };
        let mut g = Guard::new(UdpOptions::new().source_budget(budget), t);
        let mut o = false;
        let passed = (0..10).filter(|_| g.admit(ip(1), 10, t, &mut o)).count();
        assert_eq!(passed, 3);
        assert!(
            g.admit(ip(2), 10, t, &mut o),
            "another source has its own budget"
        );
        assert!(!o);
    }

    #[test]
    fn test_global_budget_caps_every_source() {
        let t = Instant::now();
        let global = UdpBudget {
            datagrams_per_sec: 1,
            bytes_per_sec: 10_000,
            burst: 4,
        };
        let mut g = Guard::new(UdpOptions::new().global_budget(global), t);
        let mut o = false;
        let passed = (1..=10).filter(|&n| g.admit(ip(n), 10, t, &mut o)).count();
        assert_eq!(passed, 4);
    }

    #[test]
    fn test_full_table_evicts_strangers_and_keeps_verified() {
        // Edge case 93.
        let t = Instant::now();
        let mut g = Guard::new(UdpOptions::new().source_table(4), t);
        let mut o = false;
        for n in 1..=4 {
            assert!(g.admit(ip(n), 10, t, &mut o));
        }
        g.verify(ip(1), t);
        g.verify(ip(2), t);
        // Recently used entries survive one pass of the hand; the next newcomer
        // takes an unverified one.
        assert!(g.admit(ip(5), 10, t, &mut o));
        assert!(!o, "an unverified entry was evicted");
        assert!(g.index.contains_key(&ip(1)) && g.index.contains_key(&ip(2)));
        assert_eq!(g.slots.len(), 4);
        // Fill with verified peers: strangers share the overflow budget.
        for n in [3, 4, 5] {
            if g.index.contains_key(&ip(n)) {
                g.verify(ip(n), t);
            }
        }
        for n in 6..=7 {
            g.verify(ip(n), t);
        }
        let mut o = false;
        assert!(g.admit(ip(9), 10, t, &mut o));
        assert!(o, "no room: the overflow budget");
        assert!(
            !g.may_send(ip(9), 1, t),
            "an overflow stranger gets no allowance"
        );
        assert!(
            g.index.contains_key(&ip(1)),
            "verified peers keep their entries"
        );
    }

    #[test]
    fn test_options_validate() {
        let bad = |o: UdpOptions| matches!(o.validate(), Err(NetError::InvalidConfig { .. }));
        assert!(bad(UdpOptions::new().amplification_factor(0)));
        assert!(bad(UdpOptions::new().amplification_factor(4)));
        assert!(bad(
            UdpOptions::new().amplification_window(Duration::from_millis(500))
        ));
        assert!(bad(UdpOptions::new().source_table(0)));
        assert!(bad(UdpOptions::new().source_budget(UdpBudget {
            datagrams_per_sec: 0,
            bytes_per_sec: 1,
            burst: 1
        })));
        assert!(UdpOptions::new().validate().is_ok());
        assert_eq!(UdpOptions::default(), UdpOptions::new());
    }

    #[test]
    fn test_echo_truncation_and_zero_length() {
        let mut s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let to = s.local_addr().unwrap();
        let c = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.send_to(b"hello", to).unwrap();
        let mut buf = [0u8; 64];
        let d = s.recv_from(&mut buf).unwrap();
        assert_eq!(
            (d.len, d.truncated, d.from),
            (5, false, c.local_addr().unwrap())
        );
        assert_eq!(s.send_to(&buf[..5], d.from).unwrap(), 5);
        let mut back = [0u8; 8];
        assert_eq!(c.recv(&mut back).unwrap(), 5);
        assert!(matches!(
            s.send_to(b"x", d.from),
            Err(NetError::Limit {
                which: LimitKind::Amplification
            })
        ));
        // Edge cases 90 and 91.
        c.send_to(&[7u8; 100], to).unwrap();
        let mut small = [0u8; 10];
        let d = s.recv_from(&mut small).unwrap();
        assert!(d.truncated);
        c.send_to(&[], to).unwrap();
        let d = s.recv_from(&mut buf).unwrap();
        assert_eq!((d.len, d.truncated), (0, false));
        let st = s.stats();
        assert_eq!(
            (st.received, st.sent, st.refused, st.truncated),
            (3, 1, 1, 1)
        );
        assert_eq!(st.sources, 1);
    }

    #[test]
    fn test_icmp_reports_never_end_the_socket() {
        // Edge case 92: an injected "connection reset" and a real port-unreachable.
        use crate::sys::shim::{Fault, Op, clear_here, program_here};
        let mut s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let closed = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let gone = closed.local_addr().unwrap();
        drop(closed);
        s.connect(gone).unwrap();
        s.mark_verified(gone);
        s.send(b"anyone?").unwrap();
        program_here(Op::Recv, 0, 1, Fault::Kind(io::ErrorKind::ConnectionReset));
        let mut buf = [0u8; 16];
        assert!(matches!(
            s.recv(&mut buf),
            Err(NetError::TimedOut {
                kind: TimeoutKind::Read
            })
        ));
        clear_here();
        assert!(s.stats().icmp_errors >= 1);
        // Still usable.
        let mut t = UdpSocket::bind("127.0.0.1:0").unwrap();
        t.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let c = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        c.send_to(b"ok", t.local_addr().unwrap()).unwrap();
        assert_eq!(t.recv_from(&mut buf).unwrap().len, 2);
    }

    #[test]
    fn test_dual_stack_replies_to_ipv4_sources() {
        let Ok(mut s) = UdpSocket::bind_with("[::]:0", UdpOptions::new().ipv6_only(false)) else {
            return; // no IPv6 on this host
        };
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let port = s.local_addr().unwrap().port();
        let c = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.send_to(b"v4", ("127.0.0.1", port)).unwrap();
        let mut buf = [0u8; 8];
        let d = s.recv_from(&mut buf).unwrap();
        assert!(d.from.is_ipv4(), "normalized: {}", d.from);
        s.send_to(b"ok", d.from).unwrap();
        assert_eq!(c.recv(&mut buf).unwrap(), 2);
    }

    fn verified_pair() -> (UdpSocket, UdpSocket) {
        let mut a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (aa, ba) = (a.local_addr().unwrap(), b.local_addr().unwrap());
        a.mark_verified(ba);
        b.mark_verified(aa);
        a.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        b.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        (a, b)
    }

    #[test]
    fn test_batches_cross_in_one_call_each() {
        let (mut a, mut b) = verified_pair();
        let to = b.local_addr().unwrap();
        let bodies: Vec<Vec<u8>> = (0..10u8).map(|i| vec![i; 1 + usize::from(i)]).collect();
        let out: Vec<_> = bodies
            .iter()
            .map(|b| OutgoingDatagram { bytes: b, to })
            .collect();
        assert_eq!(a.send_batch(&out).unwrap(), 10);
        std::thread::sleep(Duration::from_millis(50));
        let mut store = vec![[0u8; 64]; 16];
        let mut seen = 0;
        while seen < 10 {
            let mut slots: Vec<_> = store.iter_mut().map(|b| DatagramBuffer::new(b)).collect();
            let n = b.recv_batch(&mut slots).unwrap();
            assert!(n > 0);
            for slot in &slots {
                if let Some(d) = slot.datagram {
                    assert_eq!(d.from, a.local_addr().unwrap());
                    assert_eq!(&slot.buf[..d.len], &bodies[seen][..]);
                    seen += 1;
                }
            }
        }
        assert_eq!(a.stats().sent, 10);
        assert_eq!(b.stats().received, 10);
    }

    /// An unverified peer's allowance holds across a batch: what got through is what
    /// the guard allows, and a batch cannot spend it twice.
    #[test]
    fn test_batch_send_stays_under_the_guard() {
        let mut server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let to = client.local_addr().unwrap();
        client
            .send_to(&[0u8; 100], server.local_addr().unwrap())
            .unwrap();
        let mut buf = [0u8; 200];
        server.recv_from(&mut buf).unwrap();
        let big = [1u8; 40];
        let out = [OutgoingDatagram { bytes: &big, to }; 4];
        assert_eq!(
            server.send_batch(&out).unwrap(),
            2,
            "100 bytes of allowance"
        );
        assert!(matches!(
            server.send_batch(&out),
            Err(NetError::Limit {
                which: LimitKind::Amplification
            })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn test_packet_info_reports_the_destination() {
        let mut server =
            UdpSocket::bind_with("0.0.0.0:0", UdpOptions::new().packet_info(true)).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let port = server.local_addr().unwrap().port();
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        client.send_to(b"hi", ("127.0.0.1", port)).unwrap();
        let mut buf = [0u8; 16];
        let d = server.recv_from(&mut buf).unwrap();
        assert_eq!(d.len, 2);
        assert_eq!(d.destination, Some("127.0.0.1".parse().unwrap()));
    }

    #[cfg(windows)]
    #[test]
    fn test_packet_info_is_refused_on_windows() {
        assert!(matches!(
            UdpSocket::bind_with("127.0.0.1:0", UdpOptions::new().packet_info(true)),
            Err(NetError::Unsupported { .. })
        ));
    }

    #[test]
    fn test_multicast_join_checks_the_family() {
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        let group: IpAddr = "239.1.2.3".parse().unwrap();
        assert!(matches!(
            socket.join_multicast(group, MulticastInterface::V6Index(1)),
            Err(NetError::InvalidConfig { .. })
        ));
        // A host without a multicast route refuses; a broken family check would not.
        let _ = socket.join_multicast(group, MulticastInterface::Any);
    }
}
