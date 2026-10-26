//! Every bound net-io enforces, in one value.

use std::time::Duration;

use crate::addr::PrefixPolicy;
use crate::driver::DriverKind;
use crate::error::{ConfigReason, NetError};
use crate::info::Lane;

/// Lanes that can hold a connection reservation (0 to 7).
const RESERVED_LANES: usize = 8;

/// A minimum transfer rate, checked per direction while that direction is active.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// let rate = net_io::MinRate::new(512, Duration::from_secs(10));
/// assert_eq!(rate.grace, Duration::from_secs(5));
/// assert!(net_io::MinRate::off().is_off());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MinRate {
    /// Bytes per second the peer must reach over the window.
    pub bytes_per_sec: u32,
    /// The sliding window.
    pub window: Duration,
    /// How long after a direction becomes active the check starts.
    pub grace: Duration,
    /// How often the rate is checked.
    pub check: Duration,
}

impl MinRate {
    /// No minimum rate.
    #[must_use]
    pub const fn off() -> MinRate {
        MinRate {
            bytes_per_sec: 0,
            window: Duration::from_secs(10),
            grace: Duration::from_secs(5),
            check: Duration::from_secs(1),
        }
    }

    /// `bytes_per_sec` over `window`, after a 5 s grace, checked every second.
    #[must_use]
    pub const fn new(bytes_per_sec: u32, window: Duration) -> MinRate {
        MinRate {
            bytes_per_sec,
            window,
            grace: Duration::from_secs(5),
            check: Duration::from_secs(1),
        }
    }

    /// Whether the rate check is off.
    #[must_use]
    pub const fn is_off(&self) -> bool {
        self.bytes_per_sec == 0
    }
}

/// Adaptive deadlines under pressure (applied from `0.6.0`).
///
/// ```
/// let p = net_io::Pressure::default();
/// assert!(p.high > p.low);
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Pressure {
    /// Fraction of `max_connections` above which deadlines shrink.
    pub high: f32,
    /// Fraction below which they return to normal.
    pub low: f32,
    /// The multiplier applied to handshake and idle timeouts.
    pub factor: f32,
}

impl Default for Pressure {
    fn default() -> Pressure {
        Pressure {
            high: 0.8,
            low: 0.6,
            factor: 0.25,
        }
    }
}

/// A buffer size class: a power of two from 1 KiB to 1 MiB.
///
/// ```
/// use net_io::SizeClass;
/// assert_eq!(SizeClass::MEDIUM.bytes(), 16 * 1024);
/// assert!(SizeClass::new(3000).is_err());
/// assert_eq!(SizeClass::new(2048).unwrap().bytes(), 2048);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SizeClass(u32);

impl SizeClass {
    /// 4 KiB.
    pub const SMALL: SizeClass = SizeClass(4 * 1024);
    /// 16 KiB.
    pub const MEDIUM: SizeClass = SizeClass(16 * 1024);
    /// 64 KiB.
    pub const LARGE: SizeClass = SizeClass(64 * 1024);

    /// A class of `bytes`.
    ///
    /// # Errors
    ///
    /// `InvalidConfig { field: "size_class" }` unless `bytes` is a power of two from 1 KiB to 1 MiB.
    pub const fn new(bytes: u32) -> Result<SizeClass, NetError> {
        if !bytes.is_power_of_two() {
            return Err(NetError::InvalidConfig {
                field: "size_class",
                reason: ConfigReason::Inconsistent,
            });
        }
        if bytes < 1024 {
            return Err(NetError::InvalidConfig {
                field: "size_class",
                reason: ConfigReason::TooSmall { min: 1024 },
            });
        }
        if bytes > 1024 * 1024 {
            return Err(NetError::InvalidConfig {
                field: "size_class",
                reason: ConfigReason::TooLarge { max: 1024 * 1024 },
            });
        }
        Ok(SizeClass(bytes))
    }

    /// The size in bytes.
    #[must_use]
    pub const fn bytes(self) -> u32 {
        self.0
    }
}

/// Every bound net-io enforces. Unset values take the defaults of the driver
/// that runs the connection.
///
/// # Examples
///
/// ```
/// use net_io::{DriverKind, Limits, MinRate};
/// use std::time::Duration;
///
/// let limits = Limits::builder()
///     .max_connections(20_000)
///     .idle_timeout(Duration::from_secs(15))
///     .min_rate(MinRate::new(512, Duration::from_secs(10)))
///     .build()?;
/// assert_eq!(limits.max_connections(), Some(20_000));
/// assert_eq!(limits.read_timeout(), None);
/// assert_eq!(limits.resolve(DriverKind::Blocking).read_timeout(), Some(Duration::from_secs(30)));
/// # Ok::<(), net_io::NetError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Limits {
    max_connections: Option<u32>,
    max_per_listener: Option<u32>,
    max_per_source: Option<(u32, PrefixPolicy)>,
    backlog: Option<u32>,
    accept_batch: Option<u16>,
    handshake_timeout: Option<Duration>,
    idle_timeout: Option<Duration>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    park_timeout: Option<Duration>,
    min_rate: Option<MinRate>,
    proxy_header_max: Option<u16>,
    read_class: Option<(SizeClass, SizeClass)>,
    output_budget: Option<u32>,
    completion_queue: Option<u32>,
    buffer_budget: Option<u64>,
    drain_timeout: Option<Duration>,
    graceful_linger: Option<(Duration, u32)>,
    refusal_bytes_max: Option<u16>,
    tick: Option<Duration>,
    pressure: Option<Pressure>,
    lane_reserve: [Option<u32>; RESERVED_LANES],
}

/// The resolved values a running connection uses.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Effective {
    pub max_connections: u32,
    pub max_per_listener: u32,
    pub max_per_source: u32,
    pub source_policy: PrefixPolicy,
    pub backlog: u32,
    pub accept_batch: u16,
    pub handshake_timeout: Duration,
    pub idle_timeout: Duration,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    pub park_timeout: Duration,
    pub min_rate: MinRate,
    pub proxy_header_max: u16,
    pub read_class: SizeClass,
    pub read_class_max: SizeClass,
    pub output_budget: u32,
    pub completion_queue: u32,
    pub buffer_budget: u64,
    pub drain_timeout: Duration,
    pub graceful_linger: Duration,
    pub graceful_linger_bytes: u32,
    pub refusal_bytes_max: u16,
    pub tick: Duration,
}

impl Effective {
    /// The defaults of `driver` (blocking, or the reactor).
    pub(crate) fn defaults(driver: DriverKind) -> Effective {
        let blocking = driver.resolve() == DriverKind::Blocking;
        let max_connections = if blocking { 128 } else { 10_000 };
        Effective {
            max_connections,
            max_per_listener: max_connections,
            max_per_source: if blocking { 16 } else { 256 },
            source_policy: PrefixPolicy::DEFAULT,
            backlog: 1024,
            accept_batch: if blocking { 16 } else { 64 },
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(if blocking { 5 } else { 60 }),
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            park_timeout: Duration::from_secs(30),
            min_rate: MinRate::new(256, Duration::from_secs(10)),
            proxy_header_max: 1024,
            read_class: SizeClass::MEDIUM,
            read_class_max: SizeClass::LARGE,
            output_budget: 64 * 1024,
            completion_queue: if blocking { 1 } else { 1024 },
            buffer_budget: if blocking { 64 << 20 } else { 512 << 20 },
            drain_timeout: Duration::from_secs(30),
            graceful_linger: Duration::from_secs(2),
            graceful_linger_bytes: 64 * 1024,
            refusal_bytes_max: 512,
            tick: Duration::from_millis(if blocking { 10 } else { 1 }),
        }
    }
}

impl Limits {
    /// A builder with every value unset.
    ///
    /// ```
    /// let limits = net_io::Limits::builder().max_connections(100).build()?;
    /// assert_eq!(limits.max_per_source(), None);
    /// # Ok::<(), net_io::NetError>(())
    /// ```
    pub fn builder() -> LimitsBuilder {
        LimitsBuilder::default()
    }

    /// Every value set to the reactor's defaults.
    ///
    /// ```
    /// assert_eq!(net_io::Limits::reactor_defaults().max_connections(), Some(10_000));
    /// ```
    #[must_use]
    pub fn reactor_defaults() -> Limits {
        Limits::from_effective(&Effective::defaults(DriverKind::Reactor))
    }

    /// Every value set to the blocking driver's defaults.
    ///
    /// ```
    /// assert_eq!(net_io::Limits::blocking_defaults().idle_timeout(), Some(std::time::Duration::from_secs(5)));
    /// ```
    #[must_use]
    pub fn blocking_defaults() -> Limits {
        Limits::from_effective(&Effective::defaults(DriverKind::Blocking))
    }

    /// A builder starting from these values.
    ///
    /// Every value carried over counts as set, so lowering `max_connections`
    /// below a carried-over `max_per_listener` fails validation. Start from
    /// [`Limits::builder`] to let dependent values follow `max_connections`.
    ///
    /// ```
    /// let limits = net_io::Limits::blocking_defaults().to_builder().max_connections(256).build()?;
    /// assert_eq!(limits.max_connections(), Some(256));
    /// # Ok::<(), net_io::NetError>(())
    /// ```
    pub fn to_builder(&self) -> LimitsBuilder {
        LimitsBuilder {
            limits: self.clone(),
        }
    }

    /// These limits with unset values filled from `driver`'s defaults.
    ///
    /// ```
    /// let limits = net_io::Limits::builder().max_connections(10).build()?;
    /// let resolved = limits.resolve(net_io::DriverKind::Blocking);
    /// assert_eq!(resolved.max_per_source().map(|(n, _)| n), Some(10));
    /// # Ok::<(), net_io::NetError>(())
    /// ```
    #[must_use]
    pub fn resolve(&self, driver: DriverKind) -> Limits {
        let mut out = Limits::from_effective(&self.effective(driver));
        out.pressure = self.pressure;
        out.lane_reserve = self.lane_reserve;
        out
    }

    /// Checks the resolved values against each other, the worker count, and the
    /// process's descriptor limit.
    ///
    /// # Errors
    ///
    /// `InvalidConfig { field, reason }` for the first rule broken.
    ///
    /// ```
    /// let limits = net_io::Limits::builder().max_connections(1_000_000).build()?;
    /// assert!(limits.validate(4, Some(1024)).is_err());
    /// # Ok::<(), net_io::NetError>(())
    /// ```
    pub fn validate(&self, workers: u16, descriptor_limit: Option<u64>) -> Result<(), NetError> {
        // Rules that need only the values themselves.
        LimitsBuilder {
            limits: self.clone(),
        }
        .check()?;
        let e = self.effective(DriverKind::Blocking);
        let need_budget = u64::from(workers)
            .saturating_mul(u64::from(e.read_class_max.bytes()))
            .saturating_mul(2);
        if e.buffer_budget < need_budget {
            return Err(invalid(
                "buffer_budget",
                ConfigReason::BudgetBelowWorkers { need: need_budget },
            ));
        }
        if let Some(have) = descriptor_limit {
            let need = descriptors_needed(e.max_connections, workers);
            if need > have {
                return Err(invalid(
                    "max_connections",
                    ConfigReason::DescriptorLimit { have, need },
                ));
            }
        }
        Ok(())
    }

    /// The resolved values for `driver`.
    pub(crate) fn effective(&self, driver: DriverKind) -> Effective {
        let d = Effective::defaults(driver);
        let max_connections = self.max_connections.unwrap_or(d.max_connections);
        let (max_per_source, source_policy) = self
            .max_per_source
            .unwrap_or((d.max_per_source.min(max_connections), d.source_policy));
        let (read_class, read_class_max) =
            self.read_class.unwrap_or((d.read_class, d.read_class_max));
        let (graceful_linger, graceful_linger_bytes) = self
            .graceful_linger
            .unwrap_or((d.graceful_linger, d.graceful_linger_bytes));
        Effective {
            max_connections,
            max_per_listener: self.max_per_listener.unwrap_or(max_connections),
            max_per_source,
            source_policy,
            backlog: self.backlog.unwrap_or(d.backlog),
            accept_batch: self.accept_batch.unwrap_or(d.accept_batch),
            handshake_timeout: self.handshake_timeout.unwrap_or(d.handshake_timeout),
            idle_timeout: self.idle_timeout.unwrap_or(d.idle_timeout),
            read_timeout: self.read_timeout.unwrap_or(d.read_timeout),
            write_timeout: self.write_timeout.unwrap_or(d.write_timeout),
            park_timeout: self.park_timeout.unwrap_or(d.park_timeout),
            min_rate: self.min_rate.unwrap_or(d.min_rate),
            proxy_header_max: self.proxy_header_max.unwrap_or(d.proxy_header_max),
            read_class,
            read_class_max,
            output_budget: self.output_budget.unwrap_or(d.output_budget),
            completion_queue: self.completion_queue.unwrap_or(d.completion_queue),
            buffer_budget: self.buffer_budget.unwrap_or(d.buffer_budget),
            drain_timeout: self.drain_timeout.unwrap_or(d.drain_timeout),
            graceful_linger,
            graceful_linger_bytes,
            refusal_bytes_max: self.refusal_bytes_max.unwrap_or(d.refusal_bytes_max),
            tick: self.tick.unwrap_or(d.tick),
        }
    }

    /// Values from `other` where it sets them, otherwise from `self` (listener overrides).
    pub(crate) fn overlay(&self, other: &Limits) -> Limits {
        macro_rules! pick {
            ($($f:ident),*) => { Limits { $($f: other.$f.or(self.$f),)* lane_reserve: {
                let mut r = self.lane_reserve;
                for (i, v) in other.lane_reserve.iter().enumerate() { if v.is_some() { r[i] = *v; } }
                r
            } } };
        }
        pick!(
            max_connections,
            max_per_listener,
            max_per_source,
            backlog,
            accept_batch,
            handshake_timeout,
            idle_timeout,
            read_timeout,
            write_timeout,
            park_timeout,
            min_rate,
            proxy_header_max,
            read_class,
            output_budget,
            completion_queue,
            buffer_budget,
            drain_timeout,
            graceful_linger,
            refusal_bytes_max,
            tick,
            pressure
        )
    }

    fn from_effective(e: &Effective) -> Limits {
        Limits {
            max_connections: Some(e.max_connections),
            max_per_listener: Some(e.max_per_listener),
            max_per_source: Some((e.max_per_source, e.source_policy)),
            backlog: Some(e.backlog),
            accept_batch: Some(e.accept_batch),
            handshake_timeout: Some(e.handshake_timeout),
            idle_timeout: Some(e.idle_timeout),
            read_timeout: Some(e.read_timeout),
            write_timeout: Some(e.write_timeout),
            park_timeout: Some(e.park_timeout),
            min_rate: Some(e.min_rate),
            proxy_header_max: Some(e.proxy_header_max),
            read_class: Some((e.read_class, e.read_class_max)),
            output_budget: Some(e.output_budget),
            completion_queue: Some(e.completion_queue),
            buffer_budget: Some(e.buffer_budget),
            drain_timeout: Some(e.drain_timeout),
            graceful_linger: Some((e.graceful_linger, e.graceful_linger_bytes)),
            refusal_bytes_max: Some(e.refusal_bytes_max),
            tick: Some(e.tick),
            pressure: None,
            lane_reserve: [None; RESERVED_LANES],
        }
    }

    /// The global connection cap.
    #[must_use]
    pub fn max_connections(&self) -> Option<u32> {
        self.max_connections
    }
    /// The per-listener connection cap.
    #[must_use]
    pub fn max_per_listener(&self) -> Option<u32> {
        self.max_per_listener
    }
    /// The per-source concurrency cap and how sources are grouped. Each listener
    /// applies its own value to its own connections. Every open connection counts,
    /// including one finishing a graceful close, so a client at the cap that
    /// reconnects at once can be refused until its last connection is closed.
    #[must_use]
    pub fn max_per_source(&self) -> Option<(u32, PrefixPolicy)> {
        self.max_per_source
    }
    /// The listen backlog.
    #[must_use]
    pub fn backlog(&self) -> Option<u32> {
        self.backlog
    }
    /// Connections accepted per wake-up.
    #[must_use]
    pub fn accept_batch(&self) -> Option<u16> {
        self.accept_batch
    }
    /// Time for the PROXY header and TLS handshake together.
    #[must_use]
    pub fn handshake_timeout(&self) -> Option<Duration> {
        self.handshake_timeout
    }
    /// Time to wait for the next exchange.
    #[must_use]
    pub fn idle_timeout(&self) -> Option<Duration> {
        self.idle_timeout
    }
    /// Time to wait for bytes during an exchange.
    #[must_use]
    pub fn read_timeout(&self) -> Option<Duration> {
        self.read_timeout
    }
    /// Time to wait for the peer to take bytes.
    #[must_use]
    pub fn write_timeout(&self) -> Option<Duration> {
        self.write_timeout
    }
    /// Time a parked connection may wait for its completion.
    #[must_use]
    pub fn park_timeout(&self) -> Option<Duration> {
        self.park_timeout
    }
    /// The minimum transfer rate.
    #[must_use]
    pub fn min_rate(&self) -> Option<MinRate> {
        self.min_rate
    }
    /// The PROXY v2 address-and-TLV cap.
    #[must_use]
    pub fn proxy_header_max(&self) -> Option<u16> {
        self.proxy_header_max
    }
    /// The initial and maximum read buffer class.
    #[must_use]
    pub fn read_class(&self) -> Option<(SizeClass, SizeClass)> {
        self.read_class
    }
    /// Pool memory a connection's output may hold.
    #[must_use]
    pub fn output_budget(&self) -> Option<u32> {
        self.output_budget
    }
    /// A worker's completion queue length.
    #[must_use]
    pub fn completion_queue(&self) -> Option<u32> {
        self.completion_queue
    }
    /// Total bytes of buffers all workers may allocate.
    #[must_use]
    pub fn buffer_budget(&self) -> Option<u64> {
        self.buffer_budget
    }
    /// The drain deadline.
    #[must_use]
    pub fn drain_timeout(&self) -> Option<Duration> {
        self.drain_timeout
    }
    /// The graceful-close linger: time and bytes read and discarded.
    #[must_use]
    pub fn graceful_linger(&self) -> Option<(Duration, u32)> {
        self.graceful_linger
    }
    /// The largest refusal reply.
    #[must_use]
    pub fn refusal_bytes_max(&self) -> Option<u16> {
        self.refusal_bytes_max
    }
    /// The timer resolution.
    #[must_use]
    pub fn tick(&self) -> Option<Duration> {
        self.tick
    }
    /// Adaptive deadlines under pressure.
    #[must_use]
    pub fn pressure(&self) -> Option<Pressure> {
        self.pressure
    }
    /// The connection slots reserved for `lane` (lanes 0 to 7).
    #[must_use]
    pub fn lane_reserve(&self, lane: Lane) -> Option<u32> {
        self.lane_reserve
            .get(usize::from(lane.0))
            .copied()
            .flatten()
    }
}

/// Descriptors a configuration needs: connections, two wake descriptors per
/// worker, and a fixed reserve for listeners and the spare descriptor.
pub(crate) fn descriptors_needed(max_connections: u32, workers: u16) -> u64 {
    u64::from(max_connections) + 2 * u64::from(workers) + 32
}

fn invalid(field: &'static str, reason: ConfigReason) -> NetError {
    NetError::InvalidConfig { field, reason }
}

/// Builds [`Limits`]; every setter is optional.
///
/// ```
/// use net_io::{ConfigReason, Limits, NetError};
/// let err = Limits::builder().max_connections(100).max_per_listener(200).build().unwrap_err();
/// assert!(matches!(err, NetError::InvalidConfig { field: "max_per_listener", reason: ConfigReason::AboveGlobal }));
/// assert!(Limits::builder().max_connections(100).build().is_ok());
/// ```
#[must_use]
#[derive(Clone, Debug, Default)]
pub struct LimitsBuilder {
    limits: Limits,
}

macro_rules! setter {
    ($(#[$m:meta])* $name:ident, $t:ty) => {
        $(#[$m])*
        pub fn $name(mut self, value: $t) -> Self {
            self.limits.$name = Some(value);
            self
        }
    };
}

impl LimitsBuilder {
    setter!(/// The global connection cap.
        max_connections, u32);
    setter!(/// The per-listener connection cap.
        max_per_listener, u32);
    setter!(/// The listen backlog.
        backlog, u32);
    setter!(/// Connections accepted per wake-up.
        accept_batch, u16);
    setter!(/// Time for the PROXY header and TLS handshake together.
        handshake_timeout, Duration);
    setter!(/// Time to wait for the next exchange.
        idle_timeout, Duration);
    setter!(/// Time to wait for bytes during an exchange.
        read_timeout, Duration);
    setter!(/// Time to wait for the peer to take bytes.
        write_timeout, Duration);
    setter!(/// Time a parked connection may wait for its completion.
        park_timeout, Duration);
    setter!(/// The minimum transfer rate ([`MinRate::off`] to disable).
        min_rate, MinRate);
    setter!(/// Pool memory a connection's output may hold.
        output_budget, u32);
    setter!(/// Total bytes of buffers all workers may allocate.
        buffer_budget, u64);
    setter!(/// The drain deadline.
        drain_timeout, Duration);
    setter!(/// The largest refusal reply (at most 512).
        refusal_bytes_max, u16);
    setter!(/// The timer resolution (1 ms to 100 ms).
        tick, Duration);
    setter!(/// Adaptive deadlines under pressure (applied from `0.6.0`).
        pressure, Pressure);

    /// The per-source concurrency cap and how sources are grouped.
    pub fn max_per_source(mut self, n: u32, policy: PrefixPolicy) -> Self {
        self.limits.max_per_source = Some((n, policy));
        self
    }

    /// The PROXY v2 address-and-TLV cap (up to 65,519).
    pub fn proxy_header_max(mut self, v2_body_bytes: u16) -> Self {
        self.limits.proxy_header_max = Some(v2_body_bytes);
        self
    }

    /// The initial read buffer class and the largest a session may grow it to.
    pub fn read_class(mut self, initial: SizeClass, max: SizeClass) -> Self {
        self.limits.read_class = Some((initial, max));
        self
    }

    /// A worker's completion queue length, rounded up to a power of two.
    pub fn completion_queue(mut self, n: u32) -> Self {
        self.limits.completion_queue = Some(n);
        self
    }

    /// The graceful-close linger: time and bytes read and discarded.
    pub fn graceful_linger(mut self, time: Duration, bytes: u32) -> Self {
        self.limits.graceful_linger = Some((time, bytes));
        self
    }

    /// Connection slots reserved for `lane` (lanes 0 to 7; applied from `0.6.0`).
    pub fn lane_reserve(mut self, lane: Lane, slots: u32) -> Self {
        match self.limits.lane_reserve.get_mut(usize::from(lane.0)) {
            Some(slot) => *slot = Some(slots),
            // Rejected by `build` (field "lane_reserve").
            None => self.limits.lane_reserve[RESERVED_LANES - 1] = Some(u32::MAX),
        }
        self
    }

    /// Checks the values that were set and returns the limits.
    ///
    /// # Errors
    ///
    /// `InvalidConfig { field, reason }` for the first rule broken, in the order
    /// documented in `docs/API.md`.
    pub fn build(self) -> Result<Limits, NetError> {
        self.check()?;
        let mut limits = self.limits;
        if let Some(n) = limits.completion_queue {
            limits.completion_queue = Some(n.next_power_of_two());
        }
        Ok(limits)
    }

    fn check(&self) -> Result<(), NetError> {
        let l = &self.limits;
        // Zero where zero is meaningless.
        let zeros: [(&'static str, bool); 6] = [
            ("max_connections", l.max_connections == Some(0)),
            ("backlog", l.backlog == Some(0)),
            ("accept_batch", l.accept_batch == Some(0)),
            ("max_per_source", matches!(l.max_per_source, Some((0, _)))),
            ("completion_queue", l.completion_queue == Some(0)),
            ("output_budget", l.output_budget == Some(0)),
        ];
        for (field, zero) in zeros {
            if zero {
                return Err(invalid(field, ConfigReason::Zero));
            }
        }
        if let Some(max) = l.max_connections {
            if l.max_per_listener.is_some_and(|n| n > max) {
                return Err(invalid("max_per_listener", ConfigReason::AboveGlobal));
            }
            if l.max_per_source.is_some_and(|(n, _)| n > max) {
                return Err(invalid("max_per_source", ConfigReason::AboveGlobal));
            }
        }
        if let Some(tick) = l.tick {
            if tick < Duration::from_millis(1) {
                return Err(invalid("tick", ConfigReason::TooSmall { min: 1 }));
            }
            if tick > Duration::from_millis(100) {
                return Err(invalid("tick", ConfigReason::TooLarge { max: 100 }));
            }
        }
        let tick = l.tick.unwrap_or(Duration::from_millis(1));
        let timeouts: [(&'static str, Option<Duration>); 6] = [
            ("handshake_timeout", l.handshake_timeout),
            ("idle_timeout", l.idle_timeout),
            ("read_timeout", l.read_timeout),
            ("write_timeout", l.write_timeout),
            ("park_timeout", l.park_timeout),
            ("drain_timeout", l.drain_timeout),
        ];
        for (field, value) in timeouts {
            if value.is_some_and(|d| d < tick) {
                return Err(invalid(field, ConfigReason::BelowTick));
            }
        }
        if let Some(rate) = l.min_rate {
            if !rate.is_off() {
                if rate.check.is_zero() || rate.grace.is_zero() {
                    return Err(invalid("min_rate", ConfigReason::Zero));
                }
                if rate.window < rate.check {
                    return Err(invalid("min_rate", ConfigReason::WindowBelowCheck));
                }
            }
        }
        if let Some((initial, max)) = l.read_class {
            if max < initial {
                return Err(invalid("read_class", ConfigReason::Inconsistent));
            }
        }
        if l.refusal_bytes_max.is_some_and(|n| n > 512) {
            return Err(invalid(
                "refusal_bytes_max",
                ConfigReason::TooLarge { max: 512 },
            ));
        }
        if l.proxy_header_max.is_some_and(|n| n > 65_519) {
            return Err(invalid(
                "proxy_header_max",
                ConfigReason::TooLarge { max: 65_519 },
            ));
        }
        if l.completion_queue.is_some_and(|n| n > 1 << 20) {
            return Err(invalid(
                "completion_queue",
                ConfigReason::TooLarge { max: 1 << 20 },
            ));
        }
        if let Some(p) = l.pressure {
            let factor_ok = p.factor > 0.0 && p.factor <= 1.0;
            let ordered = p.high.partial_cmp(&p.low) == Some(std::cmp::Ordering::Greater);
            if !ordered
                || !factor_ok
                || !(0.0..=1.0).contains(&p.high)
                || !(0.0..=1.0).contains(&p.low)
            {
                return Err(invalid("pressure", ConfigReason::Inconsistent));
            }
        }
        if l.lane_reserve[RESERVED_LANES - 1] == Some(u32::MAX) {
            return Err(invalid("lane_reserve", ConfigReason::TooLarge { max: 7 }));
        }
        let reserved: u64 = l.lane_reserve.iter().flatten().map(|n| u64::from(*n)).sum();
        if let Some(max) = l.max_connections {
            if reserved > u64::from(max) {
                return Err(invalid("lane_reserve", ConfigReason::AboveGlobal));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unset_values_take_driver_defaults() {
        let l = Limits::builder().build().unwrap();
        assert_eq!(
            l.effective(DriverKind::Blocking).idle_timeout,
            Duration::from_secs(5)
        );
        assert_eq!(
            l.effective(DriverKind::Reactor).idle_timeout,
            Duration::from_secs(60)
        );
    }

    #[test]
    fn test_dependent_defaults_follow_max_connections() {
        let l = Limits::builder().max_connections(10).build().unwrap();
        let e = l.effective(DriverKind::Reactor);
        assert_eq!(e.max_per_listener, 10);
        assert_eq!(e.max_per_source, 10);
    }

    #[test]
    fn test_zero_values_rejected() {
        for b in [
            Limits::builder().max_connections(0),
            Limits::builder().backlog(0),
            Limits::builder().accept_batch(0),
            Limits::builder().max_per_source(0, PrefixPolicy::DEFAULT),
            Limits::builder().completion_queue(0),
            Limits::builder().output_budget(0),
        ] {
            assert!(matches!(
                b.build(),
                Err(NetError::InvalidConfig {
                    reason: ConfigReason::Zero,
                    ..
                })
            ));
        }
    }

    #[test]
    fn test_timeout_below_tick_rejected() {
        let err = Limits::builder()
            .tick(Duration::from_millis(100))
            .read_timeout(Duration::from_millis(50))
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            NetError::InvalidConfig {
                field: "read_timeout",
                reason: ConfigReason::BelowTick
            }
        ));
    }

    #[test]
    fn test_min_rate_window_below_check_rejected() {
        let rate = MinRate {
            bytes_per_sec: 10,
            window: Duration::from_millis(500),
            grace: Duration::from_secs(1),
            check: Duration::from_secs(1),
        };
        assert!(matches!(
            Limits::builder().min_rate(rate).build(),
            Err(NetError::InvalidConfig {
                reason: ConfigReason::WindowBelowCheck,
                ..
            })
        ));
        assert!(Limits::builder().min_rate(MinRate::off()).build().is_ok());
    }

    #[test]
    fn test_bounds_too_large() {
        assert!(Limits::builder().refusal_bytes_max(513).build().is_err());
        assert!(Limits::builder().refusal_bytes_max(512).build().is_ok());
        assert!(Limits::builder().proxy_header_max(65_520).build().is_err());
        assert!(
            Limits::builder()
                .completion_queue((1 << 20) + 1)
                .build()
                .is_err()
        );
    }

    #[test]
    fn test_completion_queue_rounded_to_power_of_two() {
        let l = Limits::builder().completion_queue(1000).build().unwrap();
        assert_eq!(l.completion_queue(), Some(1024));
    }

    #[test]
    fn test_pressure_and_lane_reserve_validation() {
        let bad = Pressure {
            high: 0.5,
            low: 0.6,
            factor: 0.5,
        };
        assert!(Limits::builder().pressure(bad).build().is_err());
        assert!(Limits::builder().lane_reserve(Lane(8), 1).build().is_err());
        assert!(
            Limits::builder()
                .max_connections(10)
                .lane_reserve(Lane(0), 6)
                .lane_reserve(Lane(1), 5)
                .build()
                .is_err()
        );
    }

    #[test]
    fn test_validate_descriptor_limit_and_budget() {
        let l = Limits::builder().max_connections(1000).build().unwrap();
        assert!(matches!(
            l.validate(4, Some(500)),
            Err(NetError::InvalidConfig {
                reason: ConfigReason::DescriptorLimit { have: 500, .. },
                ..
            })
        ));
        assert!(l.validate(4, Some(100_000)).is_ok());
        let small = Limits::builder().buffer_budget(1024).build().unwrap();
        assert!(matches!(
            small.validate(4, None),
            Err(NetError::InvalidConfig {
                reason: ConfigReason::BudgetBelowWorkers { .. },
                ..
            })
        ));
    }

    #[test]
    fn test_overlay_takes_listener_values() {
        let base = Limits::builder()
            .max_connections(100)
            .idle_timeout(Duration::from_secs(9))
            .build()
            .unwrap();
        let over = Limits::builder()
            .idle_timeout(Duration::from_secs(1))
            .build()
            .unwrap();
        let merged = base.overlay(&over);
        assert_eq!(merged.max_connections(), Some(100));
        assert_eq!(merged.idle_timeout(), Some(Duration::from_secs(1)));
    }

    #[test]
    fn test_resolve_sets_every_value() {
        let r = Limits::default().resolve(DriverKind::Blocking);
        assert!(
            r.max_connections().is_some() && r.tick().is_some() && r.graceful_linger().is_some()
        );
    }
}
