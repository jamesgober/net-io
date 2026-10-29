//! Socket options: before bind, per accepted or dialed connection, and live.

use std::time::Duration;

use crate::error::NetError;
use crate::sys::{self, AsSock};

/// Keepalive probes: idle time before the first, interval between them, and count.
///
/// ```
/// let k = net_io::Keepalive::DEFAULT;
/// assert_eq!(k.count, 6);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Keepalive {
    /// Idle time before the first probe.
    pub idle: Duration,
    /// Time between probes.
    pub interval: Duration,
    /// Probes before the connection is dropped.
    pub count: u32,
}

impl Keepalive {
    /// 60 s, 10 s, 6.
    pub const DEFAULT: Keepalive = Keepalive {
        idle: Duration::from_secs(60),
        interval: Duration::from_secs(10),
        count: 6,
    };
}

/// What happens to unsent data at close.
///
/// ```
/// assert_ne!(net_io::Linger::Off, net_io::Linger::Abortive);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Linger {
    /// The OS default: close returns at once, the kernel sends what it can.
    Off,
    /// RST on close; kernel resources are freed at once.
    Abortive,
    /// Close waits up to this long for unsent data.
    Timeout(Duration),
}

impl Linger {
    fn to_sys(self) -> Option<Duration> {
        match self {
            Linger::Off => None,
            Linger::Abortive => Some(Duration::ZERO),
            Linger::Timeout(d) => Some(d),
        }
    }
}

/// Options applied to each accepted or dialed TCP connection. `None` leaves the OS default.
///
/// ```
/// use net_io::{Keepalive, TcpOptions};
/// let opts = TcpOptions::new().nodelay(true).keepalive(Keepalive::DEFAULT);
/// assert_eq!(opts.nodelay, Some(true));
/// ```
#[must_use]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpOptions {
    /// `TCP_NODELAY`.
    pub nodelay: Option<bool>,
    /// Keepalive probes.
    pub keepalive: Option<Keepalive>,
    /// Linger at close.
    pub linger: Option<Linger>,
    /// `SO_SNDBUF`.
    pub send_buffer: Option<u32>,
    /// `SO_RCVBUF`.
    pub receive_buffer: Option<u32>,
    /// Hop limit (`IP_TTL` / `IPV6_UNICAST_HOPS`).
    pub ttl: Option<u8>,
}

impl TcpOptions {
    /// Every option at the OS default.
    pub fn new() -> TcpOptions {
        TcpOptions::default()
    }

    /// `TCP_NODELAY`.
    pub fn nodelay(mut self, on: bool) -> TcpOptions {
        self.nodelay = Some(on);
        self
    }

    /// Keepalive probes.
    pub fn keepalive(mut self, k: Keepalive) -> TcpOptions {
        self.keepalive = Some(k);
        self
    }

    /// Linger at close.
    pub fn linger(mut self, l: Linger) -> TcpOptions {
        self.linger = Some(l);
        self
    }

    /// `SO_SNDBUF`.
    pub fn send_buffer(mut self, bytes: u32) -> TcpOptions {
        self.send_buffer = Some(bytes);
        self
    }

    /// `SO_RCVBUF`.
    pub fn receive_buffer(mut self, bytes: u32) -> TcpOptions {
        self.receive_buffer = Some(bytes);
        self
    }

    /// Hop limit.
    pub fn ttl(mut self, hops: u8) -> TcpOptions {
        self.ttl = Some(hops);
        self
    }

    /// Applies the options that are set to `stream`.
    pub(crate) fn apply<S: AsSock>(&self, socket: &S, v6: bool) -> Result<(), NetError> {
        let sock = socket.sock();
        let os = |op: &'static str| move |e| NetError::from_os(op, e);
        if let Some(on) = self.nodelay {
            sys::set_nodelay(sock, on).map_err(os("TCP_NODELAY"))?;
        }
        if let Some(k) = self.keepalive {
            check_keepalive(&k)?;
            sys::set_keepalive(sock, Some((k.idle, k.interval, k.count)))
                .map_err(os("keepalive"))?;
        }
        if let Some(l) = self.linger {
            sys::set_linger(sock, l.to_sys()).map_err(os("SO_LINGER"))?;
        }
        if let Some(n) = self.send_buffer {
            sys::set_send_buffer(sock, n).map_err(os("SO_SNDBUF"))?;
        }
        if let Some(n) = self.receive_buffer {
            sys::set_receive_buffer(sock, n).map_err(os("SO_RCVBUF"))?;
        }
        if let Some(h) = self.ttl {
            sys::set_ttl(sock, v6, h).map_err(os("IP_TTL"))?;
        }
        Ok(())
    }

    /// Whether any option is set.
    pub(crate) fn is_empty(&self) -> bool {
        *self == TcpOptions::default()
    }
}

fn check_keepalive(k: &Keepalive) -> Result<(), NetError> {
    if cfg!(windows) && k.count > 255 {
        return Err(NetError::InvalidConfig {
            field: "keepalive",
            reason: crate::error::ConfigReason::TooLarge { max: 255 },
        });
    }
    if k.idle.is_zero() || k.interval.is_zero() || k.count == 0 {
        return Err(NetError::InvalidConfig {
            field: "keepalive",
            reason: crate::error::ConfigReason::Zero,
        });
    }
    Ok(())
}

/// Options set on a listening socket before `bind` and `listen`.
///
/// ```
/// use net_io::{ListenOptions, TcpListener};
/// let options = ListenOptions::new().backlog(4096).reuse_port(cfg!(target_os = "linux"));
/// let listener = TcpListener::bind_with("127.0.0.1:0", options)?;
/// println!("effective backlog {:?}", listener.info().backlog);
/// # Ok::<(), net_io::NetError>(())
/// ```
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenOptions {
    pub(crate) backlog: u32,
    pub(crate) reuse_address: bool,
    pub(crate) reuse_port: bool,
    pub(crate) ipv6_only: bool,
    pub(crate) send_buffer: Option<u32>,
    pub(crate) receive_buffer: Option<u32>,
    pub(crate) tcp: TcpOptions,
}

impl Default for ListenOptions {
    fn default() -> ListenOptions {
        ListenOptions {
            backlog: 1024,
            reuse_address: cfg!(unix),
            reuse_port: false,
            ipv6_only: true,
            send_buffer: None,
            receive_buffer: None,
            tcp: TcpOptions::new().nodelay(true),
        }
    }
}

impl ListenOptions {
    /// Backlog 1,024; reuse address on Unix, exclusive address use on Windows;
    /// IPv6-only; `TCP_NODELAY` on accepted sockets.
    pub fn new() -> ListenOptions {
        ListenOptions::default()
    }

    /// The listen backlog (capped by the OS; the effective value is in `ListenerInfo`).
    pub fn backlog(mut self, n: u32) -> ListenOptions {
        self.backlog = n;
        self
    }

    /// Unix: `SO_REUSEADDR`. Windows: `false` = `SO_EXCLUSIVEADDRUSE`, `true` = `SO_REUSEADDR`.
    pub fn reuse_address(mut self, on: bool) -> ListenOptions {
        self.reuse_address = on;
        self
    }

    /// `SO_REUSEPORT` (`Unsupported` on Windows).
    pub fn reuse_port(mut self, on: bool) -> ListenOptions {
        self.reuse_port = on;
        self
    }

    /// `IPV6_V6ONLY` for IPv6 addresses (on by default; decision D-026).
    pub fn ipv6_only(mut self, on: bool) -> ListenOptions {
        self.ipv6_only = on;
        self
    }

    /// `SO_SNDBUF` on the listener (before `listen`).
    pub fn send_buffer(mut self, bytes: u32) -> ListenOptions {
        self.send_buffer = Some(bytes);
        self
    }

    /// `SO_RCVBUF` on the listener (before `listen`, so window scaling is negotiated).
    pub fn receive_buffer(mut self, bytes: u32) -> ListenOptions {
        self.receive_buffer = Some(bytes);
        self
    }

    /// Options applied to every accepted socket.
    pub fn tcp_options(mut self, options: TcpOptions) -> ListenOptions {
        self.tcp = options;
        self
    }

    pub(crate) fn params(&self) -> sys::ListenParams {
        sys::ListenParams {
            reuse_address: self.reuse_address,
            reuse_port: self.reuse_port,
            ipv6_only: self.ipv6_only,
            send_buffer: self.send_buffer,
            receive_buffer: self.receive_buffer,
            backlog: self.backlog,
        }
    }
}

/// Live get and set on an open socket.
///
/// ```no_run
/// use net_io::{Keepalive, Linger};
/// let conn = net_io::connect("127.0.0.1:7000")?;
/// conn.options().set_keepalive(Some(Keepalive::DEFAULT))?;
/// conn.options().set_linger(Linger::Abortive)?;
/// let effective = conn.options().set_receive_buffer(256 * 1024)?;
/// println!("receive buffer is {effective} bytes");
/// # Ok::<(), net_io::NetError>(())
/// ```
#[derive(Debug)]
pub struct SocketOptions<'a> {
    pub(crate) sock: sys::Sock<'a>,
    pub(crate) v6: bool,
}

fn os(op: &'static str) -> impl Fn(std::io::Error) -> NetError {
    move |e| NetError::from_os(op, e)
}

impl SocketOptions<'_> {
    /// `TCP_NODELAY`.
    ///
    /// # Errors
    ///
    /// `Os` when the OS call fails.
    pub fn nodelay(&self) -> Result<bool, NetError> {
        sys::nodelay(self.sock).map_err(os("TCP_NODELAY"))
    }

    /// Sets `TCP_NODELAY`.
    ///
    /// # Errors
    ///
    /// `Os` when the OS call fails.
    pub fn set_nodelay(&self, on: bool) -> Result<(), NetError> {
        sys::set_nodelay(self.sock, on).map_err(os("TCP_NODELAY"))
    }

    /// Keepalive probes (`None` = off).
    ///
    /// # Errors
    ///
    /// `Os` when the OS call fails.
    pub fn keepalive(&self) -> Result<Option<Keepalive>, NetError> {
        Ok(sys::keepalive(self.sock)
            .map_err(os("keepalive"))?
            .map(|(idle, interval, count)| Keepalive {
                idle,
                interval,
                count,
            }))
    }

    /// Sets keepalive probes (`None` = off).
    ///
    /// # Errors
    ///
    /// `InvalidConfig` for a zero value or a count above 255 on Windows; `Os`.
    pub fn set_keepalive(&self, k: Option<Keepalive>) -> Result<(), NetError> {
        if let Some(k) = &k {
            check_keepalive(k)?;
        }
        sys::set_keepalive(self.sock, k.map(|k| (k.idle, k.interval, k.count)))
            .map_err(os("keepalive"))
    }

    /// Linger at close.
    ///
    /// # Errors
    ///
    /// `Os` when the OS call fails.
    pub fn linger(&self) -> Result<Linger, NetError> {
        Ok(match sys::linger(self.sock).map_err(os("SO_LINGER"))? {
            None => Linger::Off,
            Some(d) if d.is_zero() => Linger::Abortive,
            Some(d) => Linger::Timeout(d),
        })
    }

    /// Sets linger at close.
    ///
    /// # Errors
    ///
    /// `Os` when the OS call fails.
    pub fn set_linger(&self, l: Linger) -> Result<(), NetError> {
        sys::set_linger(self.sock, l.to_sys()).map_err(os("SO_LINGER"))
    }

    /// The effective `SO_SNDBUF`.
    ///
    /// # Errors
    ///
    /// `Os` when the OS call fails.
    pub fn send_buffer(&self) -> Result<u32, NetError> {
        sys::send_buffer(self.sock).map_err(os("SO_SNDBUF"))
    }

    /// Sets `SO_SNDBUF` and returns the effective value (Linux doubles it).
    ///
    /// # Errors
    ///
    /// `Os` when the OS call fails.
    pub fn set_send_buffer(&self, bytes: u32) -> Result<u32, NetError> {
        sys::set_send_buffer(self.sock, bytes).map_err(os("SO_SNDBUF"))
    }

    /// The effective `SO_RCVBUF`.
    ///
    /// # Errors
    ///
    /// `Os` when the OS call fails.
    pub fn receive_buffer(&self) -> Result<u32, NetError> {
        sys::receive_buffer(self.sock).map_err(os("SO_RCVBUF"))
    }

    /// Sets `SO_RCVBUF` and returns the effective value (Linux doubles it).
    ///
    /// # Errors
    ///
    /// `Os` when the OS call fails.
    pub fn set_receive_buffer(&self, bytes: u32) -> Result<u32, NetError> {
        sys::set_receive_buffer(self.sock, bytes).map_err(os("SO_RCVBUF"))
    }

    /// The hop limit.
    ///
    /// # Errors
    ///
    /// `Os` when the OS call fails.
    pub fn ttl(&self) -> Result<u8, NetError> {
        sys::ttl(self.sock, self.v6).map_err(os("IP_TTL"))
    }

    /// Sets the hop limit.
    ///
    /// # Errors
    ///
    /// `Os` when the OS call fails.
    pub fn set_ttl(&self, hops: u8) -> Result<(), NetError> {
        sys::set_ttl(self.sock, self.v6, hops).map_err(os("IP_TTL"))
    }
}

/// Options for a Unix socket listener. The defaults: mode `0600` (only the
/// owner may connect, decision D-024), stale socket files removed, backlog 1,024.
///
/// ```
/// let options = net_io::LocalOptions::new().group_access(33).require_uid(1000);
/// # let _ = options;
/// ```
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalOptions {
    pub(crate) mode: u32,
    pub(crate) owner: Option<u32>,
    pub(crate) group: Option<u32>,
    pub(crate) remove_stale: bool,
    pub(crate) require_uid: Option<u32>,
    pub(crate) backlog: u32,
}

impl Default for LocalOptions {
    fn default() -> LocalOptions {
        LocalOptions::new()
    }
}

impl LocalOptions {
    /// Mode `0600`, stale socket files removed, backlog 1,024.
    pub fn new() -> LocalOptions {
        LocalOptions {
            mode: 0o600,
            owner: None,
            group: None,
            remove_stale: true,
            require_uid: None,
            backlog: 1024,
        }
    }

    /// The socket file's permission bits (only the low 9 bits are used).
    pub fn mode(mut self, mode: u32) -> LocalOptions {
        self.mode = mode & 0o777;
        self
    }

    /// The socket file's owner (needs the privilege to change owners).
    pub fn owner(mut self, uid: u32) -> LocalOptions {
        self.owner = Some(uid);
        self
    }

    /// The socket file's group; the mode is unchanged.
    pub fn group(mut self, gid: u32) -> LocalOptions {
        self.group = Some(gid);
        self
    }

    /// The socket file's group and mode `0660`: members of `gid` may connect.
    pub fn group_access(mut self, gid: u32) -> LocalOptions {
        self.group = Some(gid);
        self.mode = 0o660;
        self
    }

    /// Whether a socket file nobody listens on is removed before binding
    /// (default on). A live listener's file, or anything that is not a socket,
    /// is never removed.
    pub fn remove_stale(mut self, on: bool) -> LocalOptions {
        self.remove_stale = on;
        self
    }

    /// Refuses peers whose user id is not `uid`, at accept, before any read.
    pub fn require_uid(mut self, uid: u32) -> LocalOptions {
        self.require_uid = Some(uid);
        self
    }

    /// The listen backlog (capped by the OS).
    pub fn backlog(mut self, backlog: u32) -> LocalOptions {
        self.backlog = backlog;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_options_builders() {
        let o = LocalOptions::new();
        assert_eq!((o.mode, o.remove_stale, o.backlog), (0o600, true, 1024));
        let o = o
            .group_access(7)
            .owner(3)
            .require_uid(9)
            .mode(0o1777)
            .backlog(5);
        assert_eq!(o.mode, 0o777);
        assert_eq!(
            (o.group, o.owner, o.require_uid),
            (Some(7), Some(3), Some(9))
        );
        assert_eq!(LocalOptions::default(), LocalOptions::new());
    }

    #[test]
    fn test_keepalive_zero_rejected() {
        let k = Keepalive {
            idle: Duration::ZERO,
            interval: Duration::from_secs(1),
            count: 1,
        };
        assert!(check_keepalive(&k).is_err());
        assert!(check_keepalive(&Keepalive::DEFAULT).is_ok());
    }

    #[test]
    fn test_listen_defaults() {
        let o = ListenOptions::new();
        assert_eq!(o.backlog, 1024);
        assert!(o.ipv6_only);
        assert_eq!(o.reuse_address, cfg!(unix));
        assert_eq!(o.tcp.nodelay, Some(true));
    }

    #[test]
    fn test_tcp_options_is_empty() {
        assert!(TcpOptions::new().is_empty());
        assert!(!TcpOptions::new().ttl(5).is_empty());
    }
}
