//! Listener hand-off between processes, and the owned listener handle that
//! inheritance, hand-off, and `Server::release_listeners` produce.
//!
//! `send_listeners` and `recv_listeners` are Unix (feature `local`); Windows
//! follows in `0.5.0`. `ListenerHandle` and the error type exist in every build.
//!
//! Manifest, version 1 (big-endian integers):
//!
//! ```text
//!  "NIOH" | version 1 | count | total length (u16, all bytes including the CRC)
//!  per listener: kind (1 TCP, 2 Unix) | name length (at most 64) | name
//!                | address length (u16) | address (TCP: family 4 or 6, IP, port;
//!                  Unix: the path bytes)
//!  CRC32C of everything before it (u32)
//! ```

// The manifest is read and written only by the Unix hand-off functions.
#![cfg_attr(not(all(unix, feature = "local")), allow(dead_code))]

use std::fmt;
use std::io;
#[cfg(unix)]
use std::sync::Arc;

#[cfg(unix)]
use crate::info::UnixPath;
use crate::info::{Endpoint, Transport};
use crate::sys::{self, KindError, SockKind};

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

/// An owned listening socket with what is known about it: its kind, an
/// optional name (up to 64 bytes), and its local endpoint. Dropping it closes
/// the socket. Made by [`crate::systemd`], hand-off, and
/// `Server::release_listeners`; used by `ListenerSpec::adopt`.
pub struct ListenerHandle {
    kind: Transport,
    name: Option<String>,
    local: Endpoint,
    sock: sys::OwnedSock,
}

impl ListenerHandle {
    /// Verifies `sock` (a listening stream socket of a family net-io serves) and
    /// records its endpoint.
    pub(crate) fn verified(
        sock: sys::OwnedSock,
        name: Option<String>,
    ) -> Result<ListenerHandle, KindError> {
        let kind = sys::listener_kind(sys::AsSock::sock(&sock))?;
        let (kind, local) = endpoint_of(kind)?;
        Ok(ListenerHandle {
            kind,
            name,
            local,
            sock,
        })
    }

    pub(crate) fn new(
        kind: Transport,
        name: Option<String>,
        local: Endpoint,
        sock: sys::OwnedSock,
    ) -> ListenerHandle {
        ListenerHandle {
            kind,
            name,
            local,
            sock,
        }
    }

    pub(crate) fn into_sock(self) -> sys::OwnedSock {
        self.sock
    }

    /// TCP or Unix.
    #[must_use]
    pub fn kind(&self) -> Transport {
        self.kind
    }

    /// The name it was given (systemd's `LISTEN_FDNAMES`, a listener's name).
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// The address it is bound to.
    #[must_use]
    pub fn local(&self) -> &Endpoint {
        &self.local
    }
}

/// The transport and endpoint of a verified socket.
fn endpoint_of(kind: SockKind) -> Result<(Transport, Endpoint), KindError> {
    match kind {
        SockKind::Tcp(a) => Ok((Transport::Tcp, Endpoint::Ip(a))),
        #[cfg(unix)]
        SockKind::Unix(path) => {
            if !cfg!(feature = "local") {
                return Err(KindError::WrongKind);
            }
            let local = UnixPath::new(&path)
                .filter(|_| !path.is_empty())
                .map_or(Endpoint::Unnamed, |p| Endpoint::Unix(Arc::new(p)));
            Ok((Transport::Unix, local))
        }
    }
}

impl fmt::Debug for ListenerHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListenerHandle")
            .field("kind", &self.kind)
            .field("name", &self.name)
            .field("local", &self.local)
            .finish()
    }
}

#[cfg(unix)]
impl std::os::fd::AsFd for ListenerHandle {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.sock.as_fd()
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsSocket for ListenerHandle {
    fn as_socket(&self) -> std::os::windows::io::BorrowedSocket<'_> {
        self.sock.as_socket()
    }
}

/// Whom `recv_listeners` accepts listeners from. `uid: None` means this
/// process's own effective user id; `pid: None` accepts any process of that user.
///
/// ```
/// let only_parent = net_io::HandoffPeer { uid: None, pid: Some(1234) };
/// # let _ = only_parent;
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HandoffPeer {
    /// The sender's user id (`None`: ours).
    pub uid: Option<u32>,
    /// The sender's process id (`None`: any).
    pub pid: Option<u32>,
}

const MAGIC: [u8; 4] = *b"NIOH";
const VERSION: u8 = 1;
const HEADER: usize = 8;
/// The most listeners one hand-off carries (one `SCM_RIGHTS` message).
const MAX_LISTENERS: usize = 64;
/// The longest name carried; longer names are cut at a character boundary.
const MAX_NAME: usize = 64;

/// One listener as the manifest describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Record {
    kind: SockKind,
    name: Option<String>,
}

/// Encodes the manifest for `records`.
fn encode(records: &[Record]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + records.len() * 96 + 4);
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(records.len() as u8);
    out.extend_from_slice(&[0, 0]); // total length, filled in below
    for r in records {
        let mut name = r.name.as_deref().unwrap_or("");
        if name.len() > MAX_NAME {
            let mut cut = MAX_NAME;
            while !name.is_char_boundary(cut) {
                cut -= 1;
            }
            name = &name[..cut];
        }
        let mut addr = Vec::with_capacity(32);
        let kind = match &r.kind {
            SockKind::Tcp(a) => {
                match a.ip() {
                    std::net::IpAddr::V4(ip) => {
                        addr.push(4);
                        addr.extend_from_slice(&ip.octets());
                    }
                    std::net::IpAddr::V6(ip) => {
                        addr.push(6);
                        addr.extend_from_slice(&ip.octets());
                    }
                }
                addr.extend_from_slice(&a.port().to_be_bytes());
                1u8
            }
            #[cfg(unix)]
            SockKind::Unix(path) => {
                addr.extend_from_slice(path);
                2u8
            }
        };
        out.push(kind);
        out.push(name.len() as u8);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(addr.len() as u16).to_be_bytes());
        out.extend_from_slice(&addr);
    }
    let total = (out.len() + 4) as u16;
    out[6..8].copy_from_slice(&total.to_be_bytes());
    let mut crc = crate::crc32c::Crc32c::new();
    crc.update(&out);
    out.extend_from_slice(&crc.finish().to_be_bytes());
    out
}

/// Checks the header: magic, version, count, total length.
fn parse_header(h: &[u8; HEADER]) -> Result<(usize, usize), HandoffError> {
    if h[..4] != MAGIC {
        return Err(HandoffError::BadMagic);
    }
    if h[4] != VERSION {
        return Err(HandoffError::BadVersion);
    }
    let count = usize::from(h[5]);
    if count > MAX_LISTENERS {
        return Err(HandoffError::TooMany {
            max: MAX_LISTENERS as u8,
        });
    }
    let total = usize::from(u16::from_be_bytes([h[6], h[7]]));
    if total < HEADER + 4 {
        return Err(HandoffError::Truncated);
    }
    Ok((count, total))
}

/// Parses a whole manifest (header included).
fn decode(bytes: &[u8]) -> Result<Vec<Record>, HandoffError> {
    let header: &[u8; HEADER] = bytes
        .get(..HEADER)
        .and_then(|h| h.try_into().ok())
        .ok_or(HandoffError::Truncated)?;
    let (count, total) = parse_header(header)?;
    if bytes.len() != total {
        return Err(HandoffError::Truncated);
    }
    let (body, sum) = bytes.split_at(total - 4);
    let mut crc = crate::crc32c::Crc32c::new();
    crc.update(body);
    if crc.finish().to_be_bytes() != sum {
        return Err(HandoffError::BadChecksum);
    }
    let mut at = HEADER;
    let mut take = |n: usize| -> Result<&[u8], HandoffError> {
        let s = body.get(at..at + n).ok_or(HandoffError::Truncated)?;
        at += n;
        Ok(s)
    };
    let mut records = Vec::with_capacity(count);
    for i in 0..count {
        let bad = |why| HandoffError::VerifyFailed {
            index: i as u8,
            why,
        };
        let kind = take(1)?[0];
        let name_len = usize::from(take(1)?[0]);
        if name_len > MAX_NAME {
            return Err(bad("name longer than 64 bytes"));
        }
        let name = std::str::from_utf8(take(name_len)?)
            .map_err(|_| bad("name is not UTF-8"))?
            .to_owned();
        let addr_len = take(2)?;
        let addr_len = usize::from(u16::from_be_bytes([addr_len[0], addr_len[1]]));
        let addr = take(addr_len)?;
        let kind = match (kind, addr) {
            (1, [4, a, b, c, d, p0, p1]) => SockKind::Tcp(std::net::SocketAddr::from((
                [*a, *b, *c, *d],
                u16::from_be_bytes([*p0, *p1]),
            ))),
            (1, [6, rest @ ..]) if rest.len() == 18 => {
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&rest[..16]);
                SockKind::Tcp(std::net::SocketAddr::from((
                    ip,
                    u16::from_be_bytes([rest[16], rest[17]]),
                )))
            }
            #[cfg(unix)]
            (2, path) => SockKind::Unix(path.to_vec()),
            _ => return Err(bad("unknown kind or malformed address")),
        };
        records.push(Record {
            kind,
            name: (!name.is_empty()).then_some(name),
        });
    }
    if at != body.len() {
        return Err(HandoffError::Truncated);
    }
    Ok(records)
}

/// The fuzz target's entry: decoding never panics, and an accepted manifest
/// encodes back to the same bytes.
#[cfg(fuzzing)]
pub(crate) fn fuzz_manifest(data: &[u8]) {
    if let Ok(records) = decode(data) {
        assert_eq!(encode(&records), data);
    }
}

/// Sends `listeners` over `channel` in one message: the manifest and every
/// socket (`SCM_RIGHTS`). The listeners stay open here; the receiver gets its
/// own copies. At most 64.
///
/// # Errors
///
/// `TooMany`, `Timeout`, `Os`.
#[cfg(all(unix, feature = "local"))]
pub fn send_listeners(
    channel: &mut crate::local::UnixConnection,
    listeners: &[&ListenerHandle],
) -> Result<(), HandoffError> {
    use std::os::fd::AsFd;
    if listeners.len() > MAX_LISTENERS {
        return Err(HandoffError::TooMany {
            max: MAX_LISTENERS as u8,
        });
    }
    let mut records = Vec::with_capacity(listeners.len());
    for (i, l) in listeners.iter().enumerate() {
        let kind = sys::listener_kind(l.as_fd()).map_err(|e| HandoffError::VerifyFailed {
            index: i as u8,
            why: why(&e),
        })?;
        records.push(Record {
            kind,
            name: l.name.clone(),
        });
    }
    let manifest = encode(&records);
    let fds: Vec<_> = listeners.iter().map(|l| l.as_fd()).collect();
    channel
        .send_descriptors(&manifest, &fds)
        .map_err(handoff_error)
}

/// Receives listeners from `channel`. The sender's credentials must match
/// `expect` (by default: the same user); the message must be complete, intact
/// (magic, version, CRC32C), carry exactly as many sockets as it lists, and
/// every socket must be a listener bound to the address the manifest names.
/// All or nothing: on any error every received socket is closed.
///
/// # Errors
///
/// `PeerMismatch`, `Timeout` (nothing arrived by `deadline`), `Truncated` (the
/// sender closed mid-message or the control data was cut), `BadMagic`,
/// `BadVersion`, `BadChecksum`, `CountMismatch`, `TooMany`, `VerifyFailed`, `Os`.
#[cfg(all(unix, feature = "local"))]
pub fn recv_listeners(
    channel: &mut crate::local::UnixConnection,
    expect: &HandoffPeer,
    deadline: std::time::Instant,
) -> Result<Vec<ListenerHandle>, HandoffError> {
    use crate::local::Descriptors;
    let creds = channel
        .peer_credentials()
        .map_err(|_| HandoffError::PeerMismatch)?;
    let uid = expect.uid.unwrap_or_else(sys::effective_uid);
    if creds.uid != Some(uid) || expect.pid.is_some_and(|p| creds.pid != Some(p)) {
        return Err(HandoffError::PeerMismatch);
    }
    channel.set_phase(crate::session::Phase::Receiving);
    channel.set_exchange_deadline(Some(deadline));
    let result = receive(channel);
    channel.set_exchange_deadline(None);
    let (records, mut fds): (Vec<Record>, Descriptors) = result?;
    if fds.len() != records.len() {
        return Err(HandoffError::CountMismatch);
    }
    let mut handles = Vec::with_capacity(records.len());
    for (i, (record, fd)) in records.into_iter().zip(fds.take()).enumerate() {
        let index = i as u8;
        let got = sys::listener_kind(std::os::fd::AsFd::as_fd(&fd)).map_err(|e| {
            HandoffError::VerifyFailed {
                index,
                why: why(&e),
            }
        })?;
        if got != record.kind {
            return Err(HandoffError::VerifyFailed {
                index,
                why: "bound to another address than the manifest says",
            });
        }
        let (kind, local) = endpoint_of(got).map_err(|e| HandoffError::VerifyFailed {
            index,
            why: why(&e),
        })?;
        handles.push(ListenerHandle::new(kind, record.name, local, fd));
    }
    Ok(handles)
}

/// Reads the manifest and its descriptors.
#[cfg(all(unix, feature = "local"))]
fn receive(
    channel: &mut crate::local::UnixConnection,
) -> Result<(Vec<Record>, crate::local::Descriptors), HandoffError> {
    use crate::local::Descriptors;
    let mut fds = Descriptors::new();
    let mut header = [0u8; HEADER];
    let mut got = 0;
    while got < HEADER {
        // The descriptors travel with the first byte; a later read must bring none.
        let mut extra = Descriptors::new();
        let into = if got == 0 { &mut fds } else { &mut extra };
        let n = channel
            .recv_descriptors(&mut header[got..], into)
            .map_err(handoff_error)?;
        if n == 0 {
            return Err(HandoffError::Truncated);
        }
        if !extra.is_empty() {
            return Err(HandoffError::CountMismatch);
        }
        got += n;
    }
    let (_, total) = parse_header(&header)?;
    let mut manifest = vec![0u8; total];
    manifest[..HEADER].copy_from_slice(&header);
    let mut at = HEADER;
    while at < total {
        let mut extra = Descriptors::new();
        let n = channel
            .recv_descriptors(&mut manifest[at..], &mut extra)
            .map_err(handoff_error)?;
        if n == 0 {
            return Err(HandoffError::Truncated);
        }
        if !extra.is_empty() {
            return Err(HandoffError::CountMismatch);
        }
        at += n;
    }
    let records = decode(&manifest)?;
    Ok((records, fds))
}

#[cfg(all(unix, feature = "local"))]
fn handoff_error(e: crate::error::NetError) -> HandoffError {
    use crate::error::NetError;
    match e {
        NetError::TimedOut { .. } => HandoffError::Timeout,
        NetError::Handoff(h) => h,
        NetError::Closed => HandoffError::Truncated,
        other => HandoffError::Os(io::Error::from(other)),
    }
}

fn why(e: &KindError) -> &'static str {
    match e {
        KindError::NotASocket => "not a socket",
        KindError::NotListening => "not listening",
        KindError::WrongKind => "not a TCP or Unix stream listener",
        KindError::Os(_) => "could not be inspected",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn records() -> Vec<Record> {
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut v = vec![
            Record {
                kind: SockKind::Tcp("127.0.0.1:8080".parse().unwrap()),
                name: Some("web".into()),
            },
            Record {
                kind: SockKind::Tcp("[2001:db8::1]:443".parse().unwrap()),
                name: None,
            },
        ];
        #[cfg(unix)]
        v.push(Record {
            kind: SockKind::Unix(b"/run/app/api.sock".to_vec()),
            name: Some("api".into()),
        });
        v
    }

    #[test]
    fn test_manifest_round_trips() {
        let r = records();
        assert_eq!(decode(&encode(&r)).unwrap(), r);
        assert_eq!(decode(&encode(&[])).unwrap(), Vec::new());
    }

    #[test]
    fn test_manifest_rejects_damage() {
        let good = encode(&records());
        let mut m = good.clone();
        m[0] = b'X';
        assert!(matches!(decode(&m), Err(HandoffError::BadMagic)));
        let mut m = good.clone();
        m[4] = 2;
        assert!(matches!(decode(&m), Err(HandoffError::BadVersion)));
        let mut m = good.clone();
        let mid = m.len() / 2;
        m[mid] ^= 1;
        assert!(matches!(decode(&m), Err(HandoffError::BadChecksum)));
        assert!(matches!(
            decode(&good[..good.len() - 1]),
            Err(HandoffError::Truncated)
        ));
        let mut m = good.clone();
        m[5] = 65;
        assert!(matches!(decode(&m), Err(HandoffError::TooMany { max: 64 })));
        assert!(matches!(decode(&good[..3]), Err(HandoffError::Truncated)));
    }

    #[test]
    fn test_long_names_are_cut_at_a_character_boundary() {
        let r = [Record {
            kind: SockKind::Tcp("127.0.0.1:1".parse().unwrap()),
            name: Some("é".repeat(40)),
        }];
        let back = decode(&encode(&r)).unwrap();
        let name = back[0].name.clone().unwrap();
        assert_eq!(name.len(), 64);
        assert!(name.chars().all(|c| c == 'é'));
    }

    /// A connected channel pair in a fresh directory: (sender, receiver).
    #[cfg(all(unix, feature = "local"))]
    fn channel(
        tag: &str,
    ) -> (
        crate::local::UnixConnection,
        crate::local::UnixConnection,
        std::path::PathBuf,
    ) {
        let dir = std::env::temp_dir().join(format!("nio-ho-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let l = crate::local::UnixListener::bind(dir.join("c.sock")).unwrap();
        let tx = crate::local::UnixConnection::connect(dir.join("c.sock")).unwrap();
        let (rx, _) = l.accept().unwrap();
        (tx, rx, dir)
    }

    #[cfg(all(unix, feature = "local"))]
    #[test]
    fn test_count_mismatch_truncation_timeout_and_peer() {
        use std::os::fd::AsFd;
        use std::time::{Duration, Instant};
        let soon = || Instant::now() + Duration::from_secs(5);
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let r = Record {
            kind: SockKind::Tcp(l.local_addr().unwrap()),
            name: None,
        };
        // Edge case 83: the manifest lists two, one socket came.
        let (mut tx, mut rx, d1) = channel("count");
        tx.send_descriptors(&encode(&[r.clone(), r.clone()]), &[l.as_fd()])
            .unwrap();
        assert!(matches!(
            recv_listeners(&mut rx, &HandoffPeer::default(), soon()),
            Err(HandoffError::CountMismatch)
        ));
        // Edge case 103: the sender dies mid-message: nothing adopted.
        let (mut tx, mut rx, d2) = channel("dies");
        let m = encode(std::slice::from_ref(&r));
        tx.send_descriptors(&m[..m.len() / 2], &[l.as_fd()])
            .unwrap();
        drop(tx);
        assert!(matches!(
            recv_listeners(&mut rx, &HandoffPeer::default(), soon()),
            Err(HandoffError::Truncated)
        ));
        // Edge case 102: nothing arrives in time.
        let (_tx, mut rx, d3) = channel("timeout");
        let started = Instant::now();
        assert!(matches!(
            recv_listeners(
                &mut rx,
                &HandoffPeer::default(),
                Instant::now() + Duration::from_millis(200)
            ),
            Err(HandoffError::Timeout)
        ));
        assert!(started.elapsed() < Duration::from_secs(3));
        // The wrong sender.
        let (_tx, mut rx, d4) = channel("peer");
        let other = HandoffPeer {
            uid: Some(sys::effective_uid().wrapping_add(1)),
            pid: None,
        };
        assert!(matches!(
            recv_listeners(&mut rx, &other, soon()),
            Err(HandoffError::PeerMismatch)
        ));
        let wrong_pid = HandoffPeer {
            uid: None,
            pid: Some(1),
        };
        assert!(matches!(
            recv_listeners(&mut rx, &wrong_pid, soon()),
            Err(HandoffError::PeerMismatch)
        ));
        for d in [d1, d2, d3, d4] {
            let _ = std::fs::remove_dir_all(d);
        }
    }

    /// A socket bound elsewhere than the manifest says is refused.
    #[cfg(all(unix, feature = "local"))]
    #[test]
    fn test_address_must_match_the_manifest() {
        use std::os::fd::AsFd;
        use std::time::{Duration, Instant};
        let a = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let b = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let (mut tx, mut rx, dir) = channel("addr");
        let lie = Record {
            kind: SockKind::Tcp(b.local_addr().unwrap()),
            name: None,
        };
        tx.send_descriptors(&encode(&[lie]), &[a.as_fd()]).unwrap();
        assert!(matches!(
            recv_listeners(
                &mut rx,
                &HandoffPeer::default(),
                Instant::now() + Duration::from_secs(5)
            ),
            Err(HandoffError::VerifyFailed { index: 0, .. })
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_handle_verifies_its_socket() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let h = ListenerHandle::verified(sys::OwnedSock::from(l), Some("x".into())).unwrap();
        assert_eq!(h.kind(), Transport::Tcp);
        assert_eq!(h.local().socket_addr(), Some(addr));
        assert_eq!(h.name(), Some("x"));
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(matches!(
            ListenerHandle::verified(sys::OwnedSock::from(u), None),
            Err(KindError::WrongKind)
        ));
    }
}
