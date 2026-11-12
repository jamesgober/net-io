//! UDP: a bound socket that reports truncated datagrams, budgets sources, and
//! never amplifies (FR-49 to FR-51).
//!
//! UDP source addresses are trivially spoofed, so the guard sits between the
//! socket and the caller: every datagram is charged to its source's budget
//! (and the global one) before it is returned, and every send to a source that
//! has not proved it can receive is limited to `factor` times what it sent us.
//! Budgets are kept per source prefix (an IPv6 host usually owns a whole /64);
//! the send allowance is kept per exact address, since that is what a reply hits.

use std::collections::HashMap;
use std::hash::Hash;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV6, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::addr::{PrefixKey, PrefixPolicy, normalize};
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

    /// The default budget of a whole socket: 100,000 datagrams and 150 MB per
    /// second (100,000 full-size 1,500-byte datagrams, 1.2 Gbit/s), bursts of
    /// 10,000 (a tenth of a second). One listener is one thread, which handles
    /// on the order of 100,000 datagrams a second once its session does any work
    /// (an estimate, not a measurement), so a server below that never meets this
    /// budget; one that expects more sets its own with
    /// [`UdpOptions::global_budget`].
    pub const GLOBAL_DEFAULT: UdpBudget = UdpBudget {
        datagrams_per_sec: 100_000,
        bytes_per_sec: 150_000_000,
        burst: 10_000,
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
    first: u32,
    prefix: PrefixPolicy,
    global: UdpBudget,
    table: u32,
    verified_for: Duration,
    verified_table: u32,
    ipv6_only: bool,
    packet_info: bool,
}

impl Default for UdpOptions {
    fn default() -> UdpOptions {
        UdpOptions::new()
    }
}

impl UdpOptions {
    /// Factor 1, a 10 s window, [`UdpBudget::SOURCE_DEFAULT`] per source prefix
    /// (/32 for IPv4, /64 for IPv6) with a first burst of 16,
    /// [`UdpBudget::GLOBAL_DEFAULT`] for the socket, 65,536 sources, verification
    /// for 60 s and up to 65,536 verified peers, IPv6-only for IPv6 addresses.
    pub fn new() -> UdpOptions {
        UdpOptions {
            factor: 1,
            window: Duration::from_secs(10),
            source: UdpBudget::SOURCE_DEFAULT,
            first: 16,
            prefix: PrefixPolicy::DEFAULT,
            global: UdpBudget::GLOBAL_DEFAULT,
            table: 65_536,
            verified_for: Duration::from_secs(60),
            verified_table: 65_536,
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
    /// default, at least 1 s, at most 1 hour). The allowance spans the current and
    /// the previous window, so a reply just after a window boundary is not refused.
    pub fn amplification_window(mut self, window: Duration) -> UdpOptions {
        self.window = window;
        self
    }

    /// How long one [`UdpSocket::mark_verified`] lasts (60 s by default, at least
    /// 1 s, at most 1 day). Each call starts it again, so a protocol that proves
    /// its peer on every authenticated datagram never sees it lapse; a peer that
    /// went away stops being an unlimited target once it does.
    pub fn verification_lifetime(mut self, lifetime: Duration) -> UdpOptions {
        self.verified_for = lifetime;
        self
    }

    /// How many verified peers (address and port) are held (65,536 by default,
    /// about 100 bytes each). Past that, a new verification takes the place of
    /// one that lapsed or was least recently verified; that peer is limited
    /// again until it is verified again.
    pub fn verified_table(mut self, entries: u32) -> UdpOptions {
        self.verified_table = entries;
        self
    }

    /// The budget of each source (each prefix of [`UdpOptions::source_prefix`]).
    pub fn source_budget(mut self, budget: UdpBudget) -> UdpOptions {
        self.source = budget;
        self
    }

    /// How addresses are grouped into sources for the budgets
    /// ([`PrefixPolicy::DEFAULT`]: /32 for IPv4 and /64 for IPv6, as the TCP
    /// per-source cap groups them; [`PrefixPolicy::HOST`] budgets every address
    /// on its own). An IPv6 host usually owns a whole /64 and can send from any
    /// address in it, so a budget per address would give it millions. The send
    /// allowance and verification stay per address whatever the policy.
    pub fn source_prefix(mut self, policy: PrefixPolicy) -> UdpOptions {
        self.prefix = policy;
        self
    }

    /// How many datagrams a source not in the table may send at once (16 by
    /// default, never more than the source budget's burst). Its bucket then fills
    /// to the full burst at the budget's rate, so a source that keeps sending sees
    /// no difference after a moment, while a spoofer that rotates sources, or
    /// pushes its own entry out of a full table, gets this much per entry instead
    /// of a full burst.
    pub fn new_source_burst(mut self, datagrams: u32) -> UdpOptions {
        self.first = datagrams;
        self
    }

    /// The budget of the whole socket ([`UdpBudget::GLOBAL_DEFAULT`] by
    /// default): what all sources together may send, so a flood from many
    /// sources, spoofed or not, reaches the caller at this rate at most.
    pub fn global_budget(mut self, budget: UdpBudget) -> UdpOptions {
        self.global = budget;
        self
    }

    /// How many sources are tracked (65,536 by default): budgets per source
    /// prefix and send allowances per address, each table bounded by this,
    /// about 200 bytes per source in all (12.5 MiB for a full default table).
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
        if self.window > Duration::from_secs(MAX_WINDOW_SECS) {
            return invalid(
                "amplification_window",
                ConfigReason::TooLarge {
                    max: MAX_WINDOW_SECS,
                },
            );
        }
        if self.verified_for < Duration::from_secs(1) {
            return invalid("verification_lifetime", ConfigReason::TooSmall { min: 1 });
        }
        if self.verified_for > Duration::from_secs(MAX_VERIFIED_SECS) {
            return invalid(
                "verification_lifetime",
                ConfigReason::TooLarge {
                    max: MAX_VERIFIED_SECS,
                },
            );
        }
        if self.table == 0 {
            return invalid("source_table", ConfigReason::Zero);
        }
        if self.verified_table == 0 {
            return invalid("verified_table", ConfigReason::Zero);
        }
        if self.first == 0 {
            return invalid("new_source_burst", ConfigReason::Zero);
        }
        for (field, b) in [
            ("source_budget", self.source),
            ("global_budget", self.global),
        ] {
            if b.datagrams_per_sec == 0 || b.bytes_per_sec == 0 || b.burst == 0 {
                return invalid(field, ConfigReason::Zero);
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
    /// Sources (prefixes of [`UdpOptions::source_prefix`]) with a budget now.
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

    /// A bucket for a source new to the table: `first` datagrams (at most the
    /// burst) and the same share of the byte bucket.
    fn starting(budget: &UdpBudget, first: u32, now: Instant) -> Bucket {
        let burst = u64::from(budget.burst.max(1));
        let first = u64::from(first.min(budget.burst));
        Bucket {
            datagrams: first * MICRO,
            bytes: u64::from(budget.bytes_per_sec) * first / burst * MICRO,
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

/// The send allowance of one source address: bytes received from it and sent to
/// it, over the current and the previous window.
#[derive(Clone, Copy, Debug)]
struct Allowance {
    received: [u64; 2],
    sent: [u64; 2],
    window_at: Instant,
}

impl Allowance {
    fn new(now: Instant) -> Allowance {
        Allowance {
            received: [0; 2],
            sent: [0; 2],
            window_at: now,
        }
    }

    /// Index 0 is the current window, 1 the previous one.
    fn roll(&mut self, window: Duration, now: Instant) {
        let gone = now.saturating_duration_since(self.window_at);
        if gone >= window.saturating_mul(2) {
            self.received = [0; 2];
            self.sent = [0; 2];
            self.window_at = now;
        } else if gone >= window {
            self.received = [0, self.received[0]];
            self.sent = [0, self.sent[0]];
            self.window_at = self.window_at.checked_add(window).unwrap_or(now);
        }
    }
}

/// A peer the application verified: its address and port, until a deadline.
#[derive(Clone, Copy, Debug)]
struct Proof {
    key: PeerKey,
    until: Instant,
    /// Set by a verification, cleared by the hand.
    referenced: bool,
}

/// A verified peer: the normalized IP and the port. Flow label and scope are not
/// part of it.
type PeerKey = (IpAddr, u16);

fn peer_key(peer: SocketAddr) -> PeerKey {
    (normalize(peer.ip()), peer.port())
}

/// How many entries one insertion may look at before it gives up and uses the
/// overflow budget.
const SWEEP: usize = 64;

/// How far the hand moves for each datagram from a source already in a full
/// table. Above 1, so a spoofer that touches each of its entries once per
/// revolution cannot keep them all recently used.
const TURN: usize = 2;

/// The longest amplification window (1 hour).
const MAX_WINDOW_SECS: u64 = 3_600;

/// The longest verification lifetime (1 day).
const MAX_VERIFIED_SECS: u64 = 86_400;

/// A bounded map with CLOCK eviction: a hash index over a slab, a hand, and a
/// recently-used bit per entry.
#[derive(Debug)]
struct Clock<K, V> {
    index: HashMap<K, u32>,
    slots: Vec<Slot<K, V>>,
    hand: usize,
    cap: usize,
}

#[derive(Clone, Copy, Debug)]
struct Slot<K, V> {
    key: K,
    value: V,
    /// Set by an admitted datagram, cleared by the hand.
    referenced: bool,
}

impl<K: Copy + Eq + Hash, V> Clock<K, V> {
    fn new(cap: u32) -> Clock<K, V> {
        Clock {
            index: HashMap::new(),
            slots: Vec::new(),
            hand: 0,
            cap: cap as usize,
        }
    }

    fn get(&self, key: &K) -> Option<usize> {
        self.index.get(key).map(|&i| i as usize)
    }

    /// Finds `key`, or makes room for it holding `value`; the flag says it was
    /// already there. A newcomer takes the first entry the hand finds not
    /// recently used, within [`SWEEP`] looks; `None` when there is none.
    fn find_or_insert(&mut self, key: K, value: V) -> Option<(usize, bool)> {
        if let Some(i) = self.get(&key) {
            return Some((i, true));
        }
        if self.slots.len() < self.cap {
            self.slots.push(Slot {
                key,
                value,
                referenced: false,
            });
            let i = self.slots.len() - 1;
            self.index.insert(key, i as u32);
            return Some((i, false));
        }
        let n = self.slots.len();
        for _ in 0..SWEEP.min(2 * n) {
            let i = self.hand;
            self.hand = (self.hand + 1) % n;
            let s = &mut self.slots[i];
            if s.referenced {
                s.referenced = false;
                continue;
            }
            self.index.remove(&s.key);
            *s = Slot {
                key,
                value,
                referenced: false,
            };
            self.index.insert(key, i as u32);
            return Some((i, false));
        }
        None
    }

    /// While the table is full, moves the hand [`TURN`] entries: the sources'
    /// own traffic ages the table, not only newcomers.
    fn turn(&mut self) {
        let n = self.slots.len();
        if n < self.cap || n == 0 {
            return;
        }
        for _ in 0..TURN {
            self.slots[self.hand].referenced = false;
            self.hand = (self.hand + 1) % n;
        }
    }
}

/// The budgets of source prefixes and the send allowances of source addresses,
/// both bounded maps with CLOCK eviction, and the table of verified peers,
/// bounded the same way.
#[derive(Debug)]
struct Guard {
    budgets: Clock<PrefixKey, Bucket>,
    allowances: Clock<IpAddr, Allowance>,
    proofs: HashMap<PeerKey, u32>,
    proved: Vec<Proof>,
    proof_hand: usize,
    overflow: Bucket,
    global: Bucket,
    options: UdpOptions,
}

impl Guard {
    fn new(options: UdpOptions, now: Instant) -> Guard {
        Guard {
            budgets: Clock::new(options.table),
            allowances: Clock::new(options.table),
            proofs: HashMap::new(),
            proved: Vec::new(),
            proof_hand: 0,
            overflow: Bucket::full(&options.source, now),
            global: Bucket::full(&options.global, now),
            options,
        }
    }

    /// Charges a received datagram from `ip` (normalized); `false` drops it.
    /// `overflow` is set when its prefix found no room in the table. Only an
    /// admitted datagram marks its entries recently used and counts toward the
    /// send allowance of its address.
    fn admit(&mut self, ip: IpAddr, len: usize, now: Instant, overflow: &mut bool) -> bool {
        let source = self.options.source;
        let key = PrefixKey::of(ip, self.options.prefix);
        let fresh = Bucket::starting(&source, self.options.first, now);
        let at = match self.budgets.find_or_insert(key, fresh) {
            Some((i, known)) => {
                if known {
                    self.budgets.turn();
                }
                if !self.budgets.slots[i].value.take(&source, len, now) {
                    return false;
                }
                Some(i)
            }
            None => {
                *overflow = true;
                if !self.overflow.take(&source, len, now) {
                    return false;
                }
                None
            }
        };
        if !self.global.take(&self.options.global, len, now) {
            return false;
        }
        // A prefix with no room shares the overflow budget, and its addresses get
        // no send allowance: strangers in a full table could otherwise pool one.
        let Some(i) = at else { return true };
        self.budgets.slots[i].referenced = true;
        if let Some((j, known)) = self.allowances.find_or_insert(ip, Allowance::new(now)) {
            if known {
                self.allowances.turn();
            }
            let window = self.options.window;
            let s = &mut self.allowances.slots[j];
            s.referenced = true;
            s.value.roll(window, now);
            s.value.received[0] = s.value.received[0].saturating_add(len as u64);
        }
        true
    }

    /// Whether `len` bytes may go to `to` now. A verified peer is not limited; to
    /// anyone else the bytes are charged against the allowance of its IP, so a
    /// short send leaves it smaller, never larger.
    fn charge(&mut self, to: SocketAddr, len: usize, now: Instant) -> bool {
        if self.is_verified(to, now) {
            return true;
        }
        let Some(i) = self.allowances.get(&normalize(to.ip())) else {
            return len == 0;
        };
        let window = self.options.window;
        let factor = u64::from(self.options.factor);
        let e = &mut self.allowances.slots[i].value;
        e.roll(window, now);
        let allowed = factor.saturating_mul(e.received[0].saturating_add(e.received[1]));
        let total = e.sent[0]
            .saturating_add(e.sent[1])
            .saturating_add(len as u64);
        if total > allowed {
            return false;
        }
        e.sent[0] = e.sent[0].saturating_add(len as u64);
        true
    }

    fn is_verified(&self, peer: SocketAddr, now: Instant) -> bool {
        self.proofs
            .get(&peer_key(peer))
            .is_some_and(|&i| now < self.proved[i as usize].until)
    }

    /// Verifies `peer` for the lifetime from `now`. A full table gives the place
    /// of a lapsed or not recently verified peer, or failing that within one
    /// sweep, of the peer under the hand: a verification always lands.
    fn verify(&mut self, peer: SocketAddr, now: Instant) {
        let key = peer_key(peer);
        let until = now.checked_add(self.options.verified_for).unwrap_or(now);
        if let Some(&i) = self.proofs.get(&key) {
            let p = &mut self.proved[i as usize];
            p.until = until;
            p.referenced = true;
            return;
        }
        let proof = Proof {
            key,
            until,
            referenced: true,
        };
        if self.proved.len() < self.options.verified_table as usize {
            self.proved.push(proof);
            self.proofs.insert(key, (self.proved.len() - 1) as u32);
            return;
        }
        let n = self.proved.len();
        let mut found = None;
        for _ in 0..SWEEP.min(2 * n) {
            let i = self.proof_hand;
            self.proof_hand = (i + 1) % n;
            let p = &mut self.proved[i];
            if now >= p.until || !p.referenced {
                found = Some(i);
                break;
            }
            p.referenced = false;
        }
        let at = found.unwrap_or_else(|| {
            let i = self.proof_hand;
            self.proof_hand = (i + 1) % n;
            i
        });
        let old = self.proved[at].key;
        self.proofs.remove(&old);
        self.proved[at] = proof;
        self.proofs.insert(key, at as u32);
    }

    /// Ends `peer`'s verification now.
    fn forget(&mut self, peer: SocketAddr, now: Instant) {
        if let Some(&i) = self.proofs.get(&peer_key(peer)) {
            let p = &mut self.proved[i as usize];
            p.until = now;
            p.referenced = false;
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
    /// Set by the server's loop: receives never wait, and one gives up after
    /// [`DROP_TURN`] datagrams it dropped. Atomic only so that setting it takes
    /// `&self`; one thread owns the socket.
    nonblocking: AtomicBool,
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
                        nonblocking: AtomicBool::new(false),
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
    /// dropped, and counted; ICMP error reports about earlier sends (port, host,
    /// or network unreachable, time exceeded, a parameter problem) are counted and
    /// never end the socket. Under a flood the call returns within twice the read
    /// timeout.
    ///
    /// # Errors
    ///
    /// `TimedOut { kind: Read }` (only with a read timeout), `Os`.
    pub fn recv_from(&mut self, buf: &mut [u8]) -> Result<Datagram, NetError> {
        let bounded = self.nonblocking.load(Ordering::Relaxed);
        self.recv_bounded(buf, bounded)
    }

    /// As [`UdpSocket::recv_from`]; `bounded` (a socket that never waits) also
    /// returns `TimedOut` after [`DROP_TURN`] datagrams dropped or reports skipped,
    /// as if nothing were ready, so a flood over budget cannot hold the caller's
    /// loop away from its other checks.
    fn recv_bounded(&mut self, buf: &mut [u8], bounded: bool) -> Result<Datagram, NetError> {
        let timed_out = || {
            Err(NetError::TimedOut {
                kind: TimeoutKind::Read,
            })
        };
        // A timeout past the clock's range has no deadline.
        let deadline = self
            .read_timeout
            .and_then(|t| Instant::now().checked_add(t));
        let mut skipped = 0u32;
        loop {
            let (len, from, truncated, destination) = match self.recv_one(buf) {
                Ok(got) => got,
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => return timed_out(),
                    io::ErrorKind::Interrupted => continue,
                    _ if icmp_report(&e) => {
                        // About an earlier send: never fatal (edge case 92).
                        self.stats.icmp_errors += 1;
                        skipped += 1;
                        if past(deadline) || (bounded && skipped >= DROP_TURN) {
                            return timed_out();
                        }
                        continue;
                    }
                    _ => return Err(NetError::from_os("recvfrom", e)),
                },
            };
            let from = crate::addr::normalize_socket(from);
            if !self.admit(from, len, truncated) {
                skipped += 1;
                if past(deadline) || (bounded && skipped >= DROP_TURN) {
                    return timed_out();
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
                    _ if icmp_report(&e) => self.stats.icmp_errors += 1,
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
        // The rest is what is ready now: the socket stops waiting for them, and
        // goes back to the mode it was in.
        let waits = !self.nonblocking.load(Ordering::Relaxed);
        if waits {
            self.inner
                .set_nonblocking(true)
                .map_err(|e| NetError::from_os("ioctl", e))?;
        }
        for slot in rest.iter_mut().take(63) {
            match self.recv_bounded(slot.buf, true) {
                Ok(d) => {
                    slot.datagram = Some(d);
                    filled += 1;
                }
                Err(_) => break,
            }
        }
        if waits {
            self.inner
                .set_nonblocking(false)
                .map_err(|e| NetError::from_os("ioctl", e))?;
        }
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
            if !self.guard.charge(d.to, d.bytes.len(), now) {
                self.stats.refused += 1;
                break;
            }
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

    /// Sends one datagram. To an address and port not marked verified, the bytes
    /// sent within the window never exceed `factor` times the bytes received
    /// from its IP; a source never heard from gets nothing (an empty datagram
    /// aside). The bytes are charged before the send.
    ///
    /// # Errors
    ///
    /// `Limit { which: Amplification }` (nothing was sent), `Os`.
    pub fn send_to(&mut self, buf: &[u8], to: SocketAddr) -> Result<usize, NetError> {
        if !self.guard.charge(to, buf.len(), Instant::now()) {
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
        if !self.guard.charge(peer, buf.len(), Instant::now()) {
            self.stats.refused += 1;
            return Err(NetError::Limit {
                which: LimitKind::Amplification,
            });
        }
        let n = self
            .inner
            .send(buf)
            .map_err(|e| NetError::from_os("send", e))?;
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

    /// The protocol proved `peer` can receive at this address and port (a cookie,
    /// a handshake, an authenticated datagram): the guard does not limit sends to
    /// it for the verification lifetime (60 s by default), counted from the latest
    /// call. Call it again each time the protocol proves the peer again; a raw
    /// datagram from the address never extends it, since anyone can forge one.
    /// Other ports of the same IP stay limited: a new port is a new path.
    pub fn mark_verified(&mut self, peer: SocketAddr) {
        self.guard.verify(peer, Instant::now());
    }

    /// The protocol is done with `peer` (its connection closed): sends to it are
    /// limited again from now, without waiting for the lifetime to run out.
    pub fn forget_verified(&mut self, peer: SocketAddr) {
        self.guard.forget(peer, Instant::now());
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
            .map_err(|e| NetError::from_os("ioctl", e))?;
        self.nonblocking.store(true, Ordering::Relaxed);
        Ok(())
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
            sources: self.guard.budgets.slots.len() as u32,
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

    /// As [`UdpSocket::forget_verified`].
    pub fn forget_verified(&mut self, peer: SocketAddr) {
        self.socket.forget_verified(peer);
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

/// Datagrams a receive that never waits drops over budget (or ICMP reports it
/// skips) before it reports nothing ready. The server's loop then waits in `poll`
/// again, which returns at once while datagrams are queued: under a flood that is
/// one more system call per 64 dropped (an estimated 2% of the cost of reading
/// them), and the loop reaches its stop and drain checks in between.
const DROP_TURN: u32 = 64;

/// Whether a receive error is an ICMP report about an earlier send rather than a
/// fault of this socket: port, host, or network unreachable, and on some systems
/// host down, protocol unreachable, a parameter problem, or (Windows) time
/// exceeded. Only numbers a receive gives for no other reason are here, so a
/// lasting fault is never skipped as a report.
fn icmp_report(e: &io::Error) -> bool {
    use io::ErrorKind as K;
    if matches!(
        e.kind(),
        K::ConnectionRefused | K::ConnectionReset | K::HostUnreachable | K::NetworkUnreachable
    ) {
        return true;
    }
    #[cfg(unix)]
    {
        use sys::errno::{EHOSTDOWN, ENONET, ENOPROTOOPT, EPROTO};
        matches!(
            e.raw_os_error(),
            Some(EHOSTDOWN | ENONET | ENOPROTOOPT | EPROTO)
        )
    }
    #[cfg(windows)]
    {
        e.raw_os_error() == Some(sys::errno::WSAENETRESET)
    }
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

/// The fuzz target `udp`: arbitrary datagrams, sends, verifications, and clock
/// steps against the guard, under three prefix policies. It checks that the
/// tables stay consistent and within their bounds, that an allowance has its
/// prefix's budget beside it unless the budget table is full, that no peer is verified that a model says is not, that an
/// unverified peer is never sent more than the factor times what the guard holds
/// as received from it, and that the global budget admits no more than its burst
/// plus its rate.
#[cfg(any(fuzzing, test))]
pub(crate) fn fuzz_udp(data: &[u8]) {
    let Some((head, ops)) = data.split_first_chunk::<5>() else {
        return;
    };
    let global = UdpBudget {
        datagrams_per_sec: u32::from(head[3]) + 1,
        bytes_per_sec: u32::from(head[3]) * 64 + 64,
        burst: u32::from(head[4] % 16) + 1,
    };
    let options = UdpOptions::new()
        .source_table(u32::from(head[0] % 16) + 1)
        .verified_table(u32::from(head[1] % 8) + 1)
        .amplification_factor(head[2] % 3 + 1)
        .amplification_window(Duration::from_secs(u64::from(head[2] >> 2) % 8 + 1))
        .verification_lifetime(Duration::from_secs(u64::from(head[4] >> 4) + 1))
        .source_budget(UdpBudget {
            datagrams_per_sec: 20,
            bytes_per_sec: 4_000,
            burst: 4,
        })
        .new_source_burst(u32::from(head[2] >> 5) + 1)
        .source_prefix(match (head[1] >> 3) & 3 {
            1 => PrefixPolicy::HOST,
            2 => PrefixPolicy::new(24, 48).unwrap_or(PrefixPolicy::DEFAULT),
            _ => PrefixPolicy::DEFAULT,
        })
        .global_budget(global);
    if options.validate().is_err() {
        return;
    }
    let start = Instant::now();
    let mut now = start;
    let mut guard = Guard::new(options.clone(), now);
    // The model: when each peer's verification ends, if it is verified.
    let mut proven: HashMap<PeerKey, Instant> = HashMap::new();
    let mut admitted = 0u64;
    for op in ops.chunks(4) {
        let n = op.get(1).copied().unwrap_or(0);
        // Mapped and plain forms of the same IPv4 address, and IPv6 addresses.
        let host = match n % 3 {
            0 => IpAddr::from([10, 0, 0, n >> 2]),
            1 => IpAddr::V6(std::net::Ipv4Addr::new(10, 0, 0, n >> 2).to_ipv6_mapped()),
            _ => IpAddr::from([0xfd00, 0, 0, 0, 0, 0, 0, u16::from(n >> 2)]),
        };
        let peer = SocketAddr::new(host, u16::from(op.get(2).copied().unwrap_or(0) % 4));
        let arg = usize::from(op.get(3).copied().unwrap_or(0)) * 8;
        match op[0] % 6 {
            0 => {
                let mut overflow = false;
                let from = crate::addr::normalize_socket(peer);
                if guard.admit(from.ip(), arg, now, &mut overflow) {
                    admitted += 1;
                }
            }
            1 => {
                let verified = guard.is_verified(peer, now);
                let sent = guard.charge(peer, arg, now);
                if sent && !verified && arg > 0 {
                    let i = guard.allowances.index[&normalize(peer.ip())] as usize;
                    let e = &guard.allowances.slots[i].value;
                    let allowed = u64::from(options.factor)
                        .saturating_mul(e.received[0].saturating_add(e.received[1]));
                    assert!(
                        e.sent[0].saturating_add(e.sent[1]) <= allowed,
                        "sent past the factor"
                    );
                }
            }
            2 => {
                guard.verify(peer, now);
                proven.insert(peer_key(peer), now + options.verified_for);
            }
            3 => {
                guard.forget(peer, now);
                proven.remove(&peer_key(peer));
            }
            4 => now += Duration::from_millis(arg as u64 * 13),
            _ => {
                let model = proven.get(&peer_key(peer)).is_some_and(|&t| now < t);
                assert!(
                    model || !guard.is_verified(peer, now),
                    "verified without a live proof"
                );
            }
        }
        assert_eq!(guard.budgets.index.len(), guard.budgets.slots.len());
        assert!(guard.budgets.slots.len() <= options.table as usize);
        for (key, &i) in &guard.budgets.index {
            assert_eq!(
                guard.budgets.slots[i as usize].key, *key,
                "index points elsewhere"
            );
        }
        assert_eq!(guard.allowances.index.len(), guard.allowances.slots.len());
        assert!(guard.allowances.slots.len() <= options.table as usize);
        for (ip, &i) in &guard.allowances.index {
            assert_eq!(
                guard.allowances.slots[i as usize].key, *ip,
                "index points elsewhere"
            );
            assert!(
                guard
                    .budgets
                    .index
                    .contains_key(&PrefixKey::of(*ip, options.prefix))
                    || guard.budgets.slots.len() == options.table as usize,
                "an allowance with no budget in a table with room"
            );
        }
        assert_eq!(guard.proofs.len(), guard.proved.len());
        assert!(guard.proved.len() <= options.verified_table as usize);
        for (key, &i) in &guard.proofs {
            assert_eq!(guard.proved[i as usize].key, *key, "proof points elsewhere");
        }
        let elapsed = now.saturating_duration_since(start).as_secs_f64();
        let most = f64::from(global.burst) + f64::from(global.datagrams_per_sec) * elapsed + 1.0;
        assert!(
            admitted as f64 <= most,
            "{admitted} admitted, at most {most}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, n])
    }

    /// The fuzz target's checks on pseudo-random input, so they run in every test
    /// build and not only under cargo-fuzz.
    #[test]
    fn test_guard_holds_under_random_operations() {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..2_000 {
            let len = 5 + (x % 400) as usize;
            let data: Vec<u8> = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    x as u8
                })
                .collect();
            fuzz_udp(&data);
        }
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

    fn at(n: u8, port: u16) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, n], port))
    }

    #[test]
    fn test_amplification_factor_one_until_verified() {
        // Edge case 94: a 1-byte request, a 2-byte reply refused until verified.
        let t = Instant::now();
        let mut g = Guard::new(UdpOptions::new(), t);
        let mut o = false;
        let a = at(1, 1_000);
        assert!(!g.charge(a, 1, t), "never heard from");
        assert!(g.charge(a, 0, t));
        assert!(g.admit(ip(1), 1, t, &mut o));
        assert!(!g.charge(a, 2, t));
        assert!(g.charge(a, 1, t));
        assert!(!g.charge(a, 1, t), "the allowance is spent");
        g.verify(a, t);
        assert!(g.charge(a, 10_000, t));
        assert!(
            !g.charge(at(1, 2_000), 1, t),
            "another port is not verified, and the IP's allowance is spent"
        );
    }

    #[test]
    fn test_amplification_factor_three_and_the_window() {
        let t = Instant::now();
        let w = Duration::from_secs(10);
        let mut g = Guard::new(UdpOptions::new().amplification_factor(3), t);
        let mut o = false;
        assert!(g.admit(ip(1), 100, t, &mut o));
        assert!(!g.charge(at(1, 9), 301, t));
        assert!(g.charge(at(1, 9), 300, t));
        assert!(!g.charge(at(1, 9), 1, t));
        // Just after the window edge the previous window still counts.
        assert!(g.admit(ip(2), 100, t, &mut o));
        assert!(g.charge(at(2, 9), 300, t + w + Duration::from_millis(1)));
        // Two windows later it is gone.
        assert!(g.admit(ip(3), 100, t, &mut o));
        assert!(!g.charge(at(3, 9), 1, t + 3 * w));
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
    fn test_full_table_evicts_strangers() {
        // Edge case 93.
        let t = Instant::now();
        let mut g = Guard::new(UdpOptions::new().source_table(4), t);
        let mut o = false;
        for n in 1..=4 {
            assert!(g.admit(ip(n), 10, t, &mut o));
        }
        // Recently used entries survive one pass of the hand; the newcomer takes
        // the first entry it then finds.
        assert!(g.admit(ip(5), 10, t, &mut o));
        assert!(!o, "an entry was evicted");
        assert!(g.budgets.index.contains_key(&PrefixKey::exact(ip(5))));
        assert_eq!(g.budgets.slots.len(), 4);
    }

    #[test]
    fn test_overflow_strangers_get_nothing_and_verified_peers_stay_answered() {
        let t = Instant::now();
        let mut g = Guard::new(UdpOptions::new().source_table(64), t);
        let mut o = false;
        let source = |n: u8| IpAddr::from([10, 0, 1, n]);
        for n in 0..64u8 {
            assert!(g.admit(source(n), 10, t, &mut o));
        }
        let peer = SocketAddr::from((source(0), 7));
        g.verify(peer, t);
        assert!(g.admit(ip(200), 10, t, &mut o));
        assert!(o, "no room: the overflow budget");
        assert!(
            !g.charge(at(200, 9), 1, t),
            "an overflow stranger gets no allowance"
        );
        assert!(g.charge(peer, 10_000, t), "verification needs no entry");
    }

    /// Verification proves one address and port, for its lifetime from the
    /// latest proof, and ends early when the application says so.
    #[test]
    fn test_verification_is_per_port_and_expires() {
        let t = Instant::now();
        let s = Duration::from_secs;
        let mut g = Guard::new(UdpOptions::new(), t);
        let a = at(1, 1_000);
        g.verify(a, t);
        assert!(g.charge(a, 10_000, t));
        assert!(!g.charge(at(1, 2_000), 1, t), "another port is a new path");
        assert!(g.charge(a, 10_000, t + s(59)));
        assert!(!g.charge(a, 1, t + s(61)), "the proof lapsed");
        g.verify(a, t + s(61));
        g.verify(a, t + s(100));
        assert!(
            g.charge(a, 10_000, t + s(159)),
            "a new proof starts it again"
        );
        g.forget(a, t + s(150));
        assert!(!g.charge(a, 1, t + s(151)));
        // IPv4-mapped and plain IPv4 are one peer.
        let mapped = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped(), 3_000));
        g.verify(mapped, t);
        assert!(g.charge(at(1, 3_000), 10_000, t));
    }

    /// The verified table is bounded; a full one gives up a lapsed peer first,
    /// then one not recently verified.
    #[test]
    fn test_verified_table_is_bounded() {
        let t = Instant::now();
        let s = Duration::from_secs;
        let mut g = Guard::new(UdpOptions::new().verified_table(2), t);
        g.verify(at(1, 1), t);
        g.verify(at(2, 1), t);
        g.verify(at(3, 1), t);
        assert_eq!(g.proved.len(), 2);
        assert!(!g.is_verified(at(1, 1), t));
        assert!(g.is_verified(at(2, 1), t) && g.is_verified(at(3, 1), t));
        let mut g = Guard::new(
            UdpOptions::new()
                .verified_table(2)
                .verification_lifetime(s(1)),
            t,
        );
        g.verify(at(1, 1), t);
        g.verify(at(2, 1), t + s(2));
        g.verify(at(3, 1), t + s(2));
        assert!(g.is_verified(at(2, 1), t + s(2)), "the lapsed one went");
        assert!(g.is_verified(at(3, 1), t + s(2)));
    }

    /// Verified peers never lock newcomers out of the table.
    #[test]
    fn test_verified_peers_leave_room_for_newcomers() {
        let t = Instant::now();
        let mut g = Guard::new(UdpOptions::new().source_table(4), t);
        let mut o = false;
        for n in 1..=4 {
            assert!(g.admit(ip(n), 10, t, &mut o));
            g.verify(at(n, 1), t);
        }
        let later = t + Duration::from_millis(10);
        assert!(g.admit(ip(9), 100, later, &mut o));
        assert!(!o, "a newcomer finds a slot");
        assert!(g.charge(at(9, 1), 100, later), "and its allowance");
    }

    /// A datagram dropped over budget does not keep its entry recently used.
    #[test]
    fn test_dropped_datagrams_do_not_keep_entries() {
        let t = Instant::now();
        let budget = UdpBudget {
            datagrams_per_sec: 1,
            bytes_per_sec: 10_000,
            burst: 1,
        };
        let options = UdpOptions::new().source_table(64).source_budget(budget);
        let mut g = Guard::new(options, t);
        let mut o = false;
        for n in 0..64u8 {
            assert!(g.admit(IpAddr::from([10, 0, 1, n]), 10, t, &mut o));
        }
        // A newcomer's sweep clears every bit and finds nothing.
        assert!(g.admit(ip(200), 10, t, &mut o));
        assert!(o);
        // Every source sends again at once and is dropped over its budget.
        for n in 0..64u8 {
            assert!(!g.admit(IpAddr::from([10, 0, 1, n]), 10, t, &mut o));
        }
        let mut o = false;
        assert!(g.admit(ip(201), 10, t, &mut o));
        assert!(!o, "the dropped traffic did not keep the table full");
    }

    /// A full table's own traffic turns the hand, so a spoofer touching every
    /// entry once per revolution cannot hold every slot.
    #[test]
    fn test_full_table_traffic_turns_the_hand() {
        let t = Instant::now();
        let mut g = Guard::new(UdpOptions::new().source_table(64), t);
        let mut o = false;
        for n in 0..64u8 {
            assert!(g.admit(IpAddr::from([10, 0, 1, n]), 10, t, &mut o));
        }
        assert!(g.admit(ip(200), 10, t, &mut o));
        assert!(o, "every entry was recently used");
        // The spoofer touches each entry once, admitted.
        let later = t + Duration::from_secs(1);
        for n in 0..64u8 {
            assert!(g.admit(IpAddr::from([10, 0, 1, n]), 10, later, &mut o));
        }
        let mut o = false;
        assert!(g.admit(ip(201), 10, later, &mut o));
        assert!(!o, "a newcomer finds a slot");
    }

    /// A window, lifetime, or read timeout too large for the clock is refused or
    /// clamped, never a panic.
    #[test]
    fn test_huge_durations_never_panic() {
        for options in [
            UdpOptions::new().amplification_window(Duration::MAX),
            UdpOptions::new().amplification_window(Duration::from_secs(3_601)),
            UdpOptions::new().verification_lifetime(Duration::MAX),
            UdpOptions::new().verification_lifetime(Duration::from_millis(999)),
            UdpOptions::new().verified_table(0),
        ] {
            assert!(matches!(
                options.validate(),
                Err(NetError::InvalidConfig { .. })
            ));
        }
        // The guard itself saturates, validated or not.
        let t = Instant::now();
        let options = UdpOptions::new()
            .amplification_window(Duration::MAX)
            .verification_lifetime(Duration::MAX);
        let mut g = Guard::new(options, t);
        let mut o = false;
        assert!(g.admit(ip(1), 10, t, &mut o));
        assert!(g.charge(at(1, 1), 10, t + Duration::from_secs(1)));
        g.verify(at(1, 1), t);
        let mut s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_read_timeout(Some(Duration::MAX)).unwrap();
        let c = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        c.send_to(b"hi", s.local_addr().unwrap()).unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(s.recv_from(&mut buf).unwrap().len, 2);
    }

    /// A verified address does not verify another port of the same IP, through
    /// the socket.
    #[test]
    fn test_verified_port_does_not_cover_the_ip() {
        let mut server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        a.send_to(b"hello", server.local_addr().unwrap()).unwrap();
        let mut buf = [0u8; 16];
        let d = server.recv_from(&mut buf).unwrap();
        server.mark_verified(d.from);
        assert_eq!(server.send_to(&[1u8; 1_000], d.from).unwrap(), 1_000);
        assert!(matches!(
            server.send_to(&[1u8; 1_000], b.local_addr().unwrap()),
            Err(NetError::Limit {
                which: LimitKind::Amplification
            })
        ));
        server.forget_verified(d.from);
        assert!(server.send_to(&[1u8; 1_000], d.from).is_err());
        assert_eq!(server.send_to(&[1u8; 5], d.from).unwrap(), 5);
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
        assert!(bad(UdpOptions::new().new_source_burst(0)));
        assert!(bad(UdpOptions::new().global_budget(UdpBudget {
            datagrams_per_sec: 1,
            bytes_per_sec: 1,
            burst: 0
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

    /// One IPv6 /64 is one source by default: a host that rotates its interface
    /// id gets no budget per address, and another /64 keeps its own.
    #[test]
    fn test_one_slash64_shares_one_budget() {
        let t = Instant::now();
        let budget = UdpBudget {
            datagrams_per_sec: 1,
            bytes_per_sec: 1_000_000,
            burst: 3,
        };
        let mut g = Guard::new(UdpOptions::new().source_budget(budget), t);
        let mut o = false;
        let mut admitted = 0;
        for host in 0..1_000u16 {
            let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, host + 1));
            for _ in 0..10 {
                if g.admit(ip, 100, t, &mut o) {
                    admitted += 1;
                }
            }
        }
        assert!(admitted <= 3, "{admitted} admitted from one /64");
        let other = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 3, 0, 0, 0, 1));
        assert!(g.admit(other, 100, t, &mut o), "another /64 has its own");
        assert!(!o);
    }

    /// `PrefixPolicy::HOST` budgets every address on its own, and a first burst
    /// larger than the budget's burst is cut to it.
    #[test]
    fn test_source_prefix_and_first_burst_are_options() {
        let t = Instant::now();
        let budget = UdpBudget {
            datagrams_per_sec: 1,
            bytes_per_sec: 1_000_000,
            burst: 3,
        };
        let options = UdpOptions::new()
            .source_budget(budget)
            .source_prefix(PrefixPolicy::HOST)
            .new_source_burst(50);
        let mut g = Guard::new(options, t);
        let mut o = false;
        let mut admitted = 0;
        for host in 1..=10u16 {
            let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, host));
            admitted += (0..10).filter(|_| g.admit(ip, 100, t, &mut o)).count();
        }
        assert_eq!(admitted, 30, "three per address");
        let wide = PrefixPolicy::new(24, 48).unwrap();
        let mut g = Guard::new(UdpOptions::new().source_prefix(wide).new_source_burst(2), t);
        let n = (1..=20u8)
            .filter(|&n| g.admit(IpAddr::from([192, 0, 2, n]), 10, t, &mut o))
            .count();
        assert_eq!(n, 2, "one /24, a first burst of two");
    }

    /// The send allowance stays with the exact address that sent, even when its
    /// budget is shared with the rest of its /64.
    #[test]
    fn test_send_allowance_stays_per_address_within_a_prefix() {
        let t = Instant::now();
        let mut g = Guard::new(UdpOptions::new(), t);
        let mut o = false;
        let a = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let b = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
        assert!(g.admit(a, 100, t, &mut o));
        assert!(
            !g.charge(SocketAddr::new(b, 9), 1, t),
            "a neighbour in the /64 never sent"
        );
        assert!(g.charge(SocketAddr::new(a, 9), 100, t));
        assert!(!g.charge(SocketAddr::new(a, 9), 1, t));
    }

    /// With the default options a flood of new sources at one instant reaches the
    /// caller only up to the default global burst.
    #[test]
    fn test_default_options_cap_a_flood_of_new_sources() {
        let t = Instant::now();
        let mut g = Guard::new(UdpOptions::new(), t);
        let mut o = false;
        let admitted = (0..300_000u32)
            .filter(|n| {
                let ip = IpAddr::from((0x0A00_0000u32 + n).to_be_bytes());
                g.admit(ip, 512, t, &mut o)
            })
            .count();
        assert!(admitted <= 10_000, "{admitted} of 300,000 admitted");
    }

    /// A source new to the table starts with a small burst, and its bucket fills
    /// to the full burst at its rate.
    #[test]
    fn test_a_new_source_starts_with_a_small_burst() {
        let t = Instant::now();
        let mut g = Guard::new(UdpOptions::new(), t);
        let mut o = false;
        let first = (0..200).filter(|_| g.admit(ip(1), 10, t, &mut o)).count();
        assert_eq!(first, 16);
        let later = t + Duration::from_secs(1);
        let then = (0..200)
            .filter(|_| g.admit(ip(1), 10, later, &mut o))
            .count();
        assert_eq!(then, 100, "the full burst after a second");
    }

    /// A non-blocking receive (the server's loop) returns after a bounded number
    /// of datagrams dropped over budget instead of reading the whole queue.
    #[test]
    fn test_a_non_blocking_receive_returns_after_a_bounded_number_of_drops() {
        let budget = UdpBudget {
            datagrams_per_sec: 1,
            bytes_per_sec: 1_000_000,
            burst: 1,
        };
        let mut s =
            UdpSocket::bind_with("127.0.0.1:0", UdpOptions::new().source_budget(budget)).unwrap();
        let to = s.local_addr().unwrap();
        let c = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        for _ in 0..200 {
            c.send_to(b"x", to).unwrap();
        }
        std::thread::sleep(Duration::from_millis(100));
        s.set_nonblocking().unwrap();
        let mut buf = [0u8; 8];
        assert!(s.recv_from(&mut buf).is_ok(), "the burst");
        assert!(matches!(
            s.recv_from(&mut buf),
            Err(NetError::TimedOut {
                kind: TimeoutKind::Read
            })
        ));
        assert_eq!(s.stats().dropped, 64, "one call read the whole queue");
        assert!(s.recv_from(&mut buf).is_err());
        assert!(s.stats().dropped > 64, "the next call goes on");
    }

    /// Unreachable reports and the other errors an ICMP message leaves on a
    /// socket are counted and skipped like a refused port.
    #[test]
    fn test_other_icmp_reports_never_end_the_socket() {
        use crate::sys::shim::{Fault, Op, clear_here, program_here};
        let mut s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut faults = vec![
            Fault::Kind(io::ErrorKind::HostUnreachable),
            Fault::Kind(io::ErrorKind::NetworkUnreachable),
        ];
        #[cfg(unix)]
        faults.extend([
            Fault::Os(sys::errno::EHOSTDOWN),
            Fault::Os(sys::errno::ENOPROTOOPT),
            Fault::Os(sys::errno::EPROTO),
        ]);
        // WSAENETRESET: a "time exceeded" report.
        #[cfg(windows)]
        faults.push(Fault::Os(sys::errno::WSAENETRESET));
        let n = faults.len() as u64;
        let mut buf = [0u8; 16];
        for fault in faults {
            program_here(Op::Recv, 0, 1, fault);
            let got = s.recv_from(&mut buf);
            clear_here();
            assert!(
                matches!(
                    got,
                    Err(NetError::TimedOut {
                        kind: TimeoutKind::Read
                    })
                ),
                "{got:?}"
            );
        }
        assert_eq!(s.stats().icmp_errors, n);
    }

    /// A batch receive leaves a non-blocking socket non-blocking.
    #[test]
    fn test_a_batch_receive_keeps_the_socket_mode() {
        let (mut a, mut b) = verified_pair();
        b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        b.set_nonblocking().unwrap();
        a.send_to(b"one", b.local_addr().unwrap()).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        let mut store = [[0u8; 16]; 4];
        let mut slots: Vec<_> = store.iter_mut().map(|b| DatagramBuffer::new(b)).collect();
        assert_eq!(b.recv_batch(&mut slots).unwrap(), 1);
        let started = Instant::now();
        let mut buf = [0u8; 16];
        assert!(b.recv_from(&mut buf).is_err());
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "the receive waited {:?}: the batch left the socket blocking",
            started.elapsed()
        );
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
