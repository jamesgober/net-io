//! What net-io knows about one connection.

use std::fmt;
use std::net::SocketAddr;
#[cfg(unix)]
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use crate::addr::{PrefixKey, PrefixPolicy};
use crate::id::{ConnectionId, ListenerId, WorkerId};
use crate::proxy::ProxyFacts;
use crate::tls::TlsInfo;

/// An opaque importance class the gate assigns at admission; lower is more important.
///
/// net-io uses it only to shed lanes under load and for per-lane reservations.
///
/// # Examples
///
/// ```
/// use net_io::Lane;
/// assert!(Lane::MOST_IMPORTANT < Lane(3));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Lane(pub u8);

impl Lane {
    /// Lane 0.
    pub const MOST_IMPORTANT: Lane = Lane(0);
}

/// An opaque value the gate returns at admission, stored in [`ConnectionInfo::gate`].
///
/// It lets a protocol engine name the connection to the gate without being
/// generic over the gate's type. net-io never interprets it.
///
/// # Examples
///
/// ```
/// let tag = net_io::GateTag(17);
/// assert_eq!(tag.0, 17);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct GateTag(pub u64);

/// The kind of socket a connection uses.
///
/// ```
/// assert_ne!(net_io::Transport::Tcp, net_io::Transport::Unix);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Transport {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// A Unix domain socket.
    Unix,
    /// A Windows named pipe.
    Pipe,
}

/// How a connection came to exist.
///
/// ```
/// assert_ne!(net_io::Origin::Accepted, net_io::Origin::Dialed);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Origin {
    /// Accepted by a listener.
    Accepted,
    /// Dialed by this process.
    Dialed,
    /// Dialed and then adopted into a server.
    Adopted,
    /// Inherited from another process.
    Inherited,
}

/// A Unix socket path in a fixed array (up to 108 bytes).
///
/// ```
/// let path = net_io::UnixPath::new(b"/run/app.sock").unwrap();
/// assert_eq!(path.as_bytes(), b"/run/app.sock");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnixPath {
    bytes: [u8; 108],
    len: u8,
}

impl UnixPath {
    /// The largest path this type holds.
    pub const MAX: usize = 108;

    /// A path from bytes; `None` when longer than [`UnixPath::MAX`].
    #[must_use]
    pub fn new(bytes: &[u8]) -> Option<UnixPath> {
        if bytes.len() > Self::MAX {
            return None;
        }
        let mut out = [0u8; 108];
        out[..bytes.len()].copy_from_slice(bytes);
        Some(UnixPath {
            bytes: out,
            len: u8::try_from(bytes.len()).ok()?,
        })
    }

    /// The path bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// The path as a `Path`.
    ///
    /// ```
    /// # #[cfg(unix)] {
    /// let path = net_io::UnixPath::new(b"/tmp/x").unwrap();
    /// assert_eq!(path.as_path(), std::path::Path::new("/tmp/x"));
    /// # }
    /// ```
    #[cfg(unix)]
    #[must_use]
    pub fn as_path(&self) -> &Path {
        use std::os::unix::ffi::OsStrExt;
        Path::new(std::ffi::OsStr::from_bytes(self.as_bytes()))
    }
}

impl std::fmt::Debug for UnixPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UnixPath({:?})",
            String::from_utf8_lossy(self.as_bytes())
        )
    }
}

/// A Windows pipe name in a fixed array (up to 256 UTF-16 units).
///
/// ```
/// let name = net_io::PipeName::new("myapp").unwrap();
/// assert_eq!(name.to_string_lossy(), "myapp");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PipeName {
    units: [u16; 256],
    len: u16,
}

impl PipeName {
    /// The longest name this type holds, in UTF-16 units.
    pub const MAX: usize = 256;

    /// A name from text; `None` when longer than [`PipeName::MAX`] units.
    #[must_use]
    pub fn new(name: &str) -> Option<PipeName> {
        let mut units = [0u16; 256];
        let mut len = 0usize;
        for u in name.encode_utf16() {
            if len == Self::MAX {
                return None;
            }
            units[len] = u;
            len += 1;
        }
        Some(PipeName {
            units,
            len: u16::try_from(len).ok()?,
        })
    }

    /// The name as UTF-16 units.
    #[must_use]
    pub fn as_wide(&self) -> &[u16] {
        &self.units[..usize::from(self.len)]
    }

    /// The name as text, with invalid units replaced.
    #[must_use]
    pub fn to_string_lossy(&self) -> String {
        String::from_utf16_lossy(self.as_wide())
    }
}

impl std::fmt::Debug for PipeName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PipeName({:?})", self.to_string_lossy())
    }
}

/// One end of a connection.
///
/// ```
/// let end = net_io::Endpoint::Ip("127.0.0.1:80".parse().unwrap());
/// assert_eq!(end.socket_addr().unwrap().port(), 80);
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Endpoint {
    /// An IP socket address.
    Ip(SocketAddr),
    /// A Unix socket path (shared with the listener that owns it).
    Unix(Arc<UnixPath>),
    /// A Windows pipe name (shared with the listener that owns it).
    Pipe(Arc<PipeName>),
    /// An unnamed Unix socket peer.
    Unnamed,
}

/// The address as text: `127.0.0.1:80`, a Unix path, a pipe name, or `unnamed`.
///
/// ```
/// let e = net_io::Endpoint::Ip("127.0.0.1:80".parse().unwrap());
/// assert_eq!(e.to_string(), "127.0.0.1:80");
/// ```
impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Endpoint::Ip(a) => write!(f, "{a}"),
            Endpoint::Unix(p) => write!(f, "{}", String::from_utf8_lossy(p.as_bytes())),
            Endpoint::Pipe(p) => {
                for c in char::decode_utf16(p.as_wide().iter().copied()) {
                    write!(f, "{}", c.unwrap_or(char::REPLACEMENT_CHARACTER))?;
                }
                Ok(())
            }
            Endpoint::Unnamed => f.write_str("unnamed"),
        }
    }
}

impl Endpoint {
    /// The socket address, for IP endpoints.
    #[must_use]
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Endpoint::Ip(a) => Some(*a),
            _ => None,
        }
    }
}

/// Who is on the other end of a local socket. A field the platform cannot report is `None`.
///
/// ```
/// let creds = net_io::PeerCredentials { pid: Some(1), uid: None, gid: None };
/// assert_eq!(creds.pid, Some(1));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PeerCredentials {
    /// The peer's process id.
    pub pid: Option<u32>,
    /// The peer's user id.
    pub uid: Option<u32>,
    /// The peer's group id.
    pub gid: Option<u32>,
}

/// What net-io knows about one connection, built at accept and completed as the
/// handshake reveals more. It holds no heap memory.
///
/// # Examples
///
/// ```
/// let info = net_io::ConnectionInfo::for_testing("192.0.2.1:5000".parse().unwrap());
/// assert_eq!(info.client_addr().unwrap().port(), 5000);
/// let key = info.client_key(net_io::PrefixPolicy::DEFAULT).unwrap();
/// assert_eq!(key.to_string(), "192.0.2.1/32");
/// ```
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct ConnectionInfo {
    /// The connection's id.
    pub id: ConnectionId,
    /// The listener that accepted it, if any.
    pub listener: Option<ListenerId>,
    /// The worker that owns it.
    pub worker: WorkerId,
    /// The kind of socket.
    pub transport: Transport,
    /// How it came to exist.
    pub origin: Origin,
    /// Our end.
    pub local: Endpoint,
    /// The socket peer, normalized.
    pub peer: Endpoint,
    /// The real client from a trusted PROXY header, normalized.
    pub real_peer: Option<SocketAddr>,
    /// Facts copied from a trusted PROXY header (pooled per worker, no allocation after warm-up).
    pub proxy: Option<Arc<ProxyFacts>>,
    /// Who is on the other end of a local socket.
    pub peer_credentials: Option<PeerCredentials>,
    /// TLS facts after the handshake (pooled per worker, no allocation after warm-up).
    pub tls: Option<Arc<TlsInfo>>,
    /// The lane the gate assigned.
    pub lane: Lane,
    /// The gate's tag for this connection.
    pub gate: GateTag,
    /// When the connection was accepted or dialed.
    pub accepted_at: Instant,
}

impl ConnectionInfo {
    /// The client address: the real peer from a trusted PROXY header when set,
    /// otherwise the IP peer.
    #[inline]
    #[must_use]
    pub fn client_addr(&self) -> Option<SocketAddr> {
        self.real_peer.or_else(|| self.peer.socket_addr())
    }

    /// The client address grouped under `policy`.
    #[must_use]
    pub fn client_key(&self, policy: PrefixPolicy) -> Option<PrefixKey> {
        self.client_addr().map(|a| PrefixKey::of(a.ip(), policy))
    }

    /// The socket peer, ignoring any PROXY header.
    #[must_use]
    pub fn socket_peer(&self) -> Option<SocketAddr> {
        self.peer.socket_addr()
    }

    /// A connection fact set attached to no socket, for testing gates and sessions.
    ///
    /// The id comes from the process counter, so it never collides with a real
    /// connection. Fields are public to adjust.
    #[must_use]
    pub fn for_testing(peer: SocketAddr) -> ConnectionInfo {
        let local = if peer.is_ipv4() {
            SocketAddr::from(([127, 0, 0, 1], 0))
        } else {
            SocketAddr::from(([0u16, 0, 0, 0, 0, 0, 0, 1], 0))
        };
        ConnectionInfo::new_tcp(
            crate::id::issue_single(),
            None,
            WorkerId(0),
            Origin::Accepted,
            local,
            crate::addr::normalize_socket(peer),
            Instant::now(),
        )
    }

    pub(crate) fn new_tcp(
        id: ConnectionId,
        listener: Option<ListenerId>,
        worker: WorkerId,
        origin: Origin,
        local: SocketAddr,
        peer: SocketAddr,
        at: Instant,
    ) -> ConnectionInfo {
        ConnectionInfo {
            id,
            listener,
            worker,
            transport: Transport::Tcp,
            origin,
            local: Endpoint::Ip(local),
            peer: Endpoint::Ip(peer),
            real_peer: None,
            proxy: None,
            peer_credentials: None,
            tls: None,
            lane: Lane::MOST_IMPORTANT,
            gate: GateTag(0),
            accepted_at: at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_addr_prefers_real_peer() {
        let mut info = ConnectionInfo::for_testing("10.0.0.1:1".parse().unwrap());
        assert_eq!(info.client_addr().unwrap().ip().to_string(), "10.0.0.1");
        info.real_peer = Some("203.0.113.5:9".parse().unwrap());
        assert_eq!(info.client_addr().unwrap().ip().to_string(), "203.0.113.5");
        assert_eq!(info.socket_peer().unwrap().ip().to_string(), "10.0.0.1");
    }

    #[test]
    fn test_for_testing_normalizes_mapped_peer() {
        let info = ConnectionInfo::for_testing("[::ffff:1.2.3.4]:80".parse().unwrap());
        assert_eq!(info.socket_peer().unwrap().to_string(), "1.2.3.4:80");
    }

    #[test]
    fn test_unix_path_bounds() {
        assert!(UnixPath::new(&[b'a'; 108]).is_some());
        assert!(UnixPath::new(&[b'a'; 109]).is_none());
    }

    #[test]
    fn test_pipe_name_bounds() {
        assert!(PipeName::new(&"a".repeat(256)).is_some());
        assert!(PipeName::new(&"a".repeat(257)).is_none());
    }

    #[test]
    fn test_connection_info_size_fits_idle_budget() {
        // Stored once per connection; the idle-connection target is 512 bytes of net-io state.
        assert!(
            std::mem::size_of::<ConnectionInfo>() <= 256,
            "{}",
            std::mem::size_of::<ConnectionInfo>()
        );
    }
}
