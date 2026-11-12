//! Listener hand-off between processes, and the owned listener handle that
//! inheritance, hand-off, and `Server::release_listeners` produce.
//!
//! `send_listeners` and `recv_listeners` are Unix (feature `local`);
//! `share_listeners` and `receive_shared` are their Windows counterparts. A
//! `ListenerHandle` and the error type exist in every build.
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
//!
//! On Windows the manifest is followed by a 16-byte nonce, one 628-byte
//! `WSAPROTOCOL_INFOW` per listener, and a CRC32C of those.

// The manifest is read and written only by the hand-off functions.
#![cfg_attr(not(feature = "local"), allow(dead_code))]

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
    /// After `sock`, so the socket closes before its value is freed.
    #[cfg(all(windows, feature = "local"))]
    adopted: Option<sys::Adoption>,
}

impl ListenerHandle {
    /// Verifies `sock` (a listening stream socket of a family net-io serves) and
    /// records its endpoint.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn verified(
        sock: sys::OwnedSock,
        name: Option<String>,
    ) -> Result<ListenerHandle, KindError> {
        let kind = sys::listener_kind(sys::AsSock::sock(&sock))?;
        let (kind, local) = endpoint_of(kind)?;
        Ok(ListenerHandle::new(kind, name, local, sock))
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
            #[cfg(all(windows, feature = "local"))]
            adopted: None,
        }
    }

    pub(crate) fn into_sock(self) -> sys::OwnedSock {
        #[cfg(all(windows, feature = "local"))]
        if let Some(adoption) = self.adopted {
            adoption.keep_for_good();
        }
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

#[cfg(feature = "local")]
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

/// Listeners described for one process, ready to go over a pipe once.
///
/// ```no_run
/// use net_io::{PipeConnection, share_listeners};
/// # fn f(handles: Vec<net_io::ListenerHandle>, pid: u32, mut pipe: PipeConnection)
/// #     -> Result<(), net_io::HandoffError> {
/// let shared = share_listeners(&handles.iter().collect::<Vec<_>>(), pid)?;
/// shared.write_to(&mut pipe)?;
/// # Ok(())
/// # }
/// ```
#[cfg(all(windows, feature = "local"))]
#[cfg_attr(docsrs, doc(cfg(windows)))]
pub struct SharedListeners {
    frame: Vec<u8>,
}

#[cfg(all(windows, feature = "local"))]
impl std::fmt::Debug for SharedListeners {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedListeners").finish_non_exhaustive()
    }
}

#[cfg(all(windows, feature = "local"))]
const NONCE: usize = 16;

/// Nonces this process has accepted. Windows lets a description be used twice and
/// returns the same socket; this makes it once.
#[cfg(all(windows, feature = "local"))]
static ACCEPTED: std::sync::Mutex<Vec<[u8; NONCE]>> = std::sync::Mutex::new(Vec::new());

/// Describes `listeners` for the process `target_pid`. Each description works in that
/// process alone. Send them over a pipe with an owner-only security descriptor, which
/// is what [`PipeListener::create`](crate::PipeListener::create) makes.
///
/// # Errors
///
/// `TooMany`, `VerifyFailed`, `Os`.
#[cfg(all(windows, feature = "local"))]
#[cfg_attr(docsrs, doc(cfg(windows)))]
pub fn share_listeners(
    listeners: &[&ListenerHandle],
    target_pid: u32,
) -> Result<SharedListeners, HandoffError> {
    use std::os::windows::io::AsSocket;
    if listeners.len() > MAX_LISTENERS {
        return Err(HandoffError::TooMany {
            max: MAX_LISTENERS as u8,
        });
    }
    let mut records = Vec::with_capacity(listeners.len());
    let mut tail = vec![0u8; NONCE];
    sys::random_bytes(&mut tail).map_err(HandoffError::Os)?;
    for (i, l) in listeners.iter().enumerate() {
        let kind = sys::listener_kind(l.as_socket()).map_err(|e| HandoffError::VerifyFailed {
            index: i as u8,
            why: why(&e),
        })?;
        records.push(Record {
            kind,
            name: l.name.clone(),
        });
        let blob = sys::share_socket(l.as_socket(), target_pid).map_err(HandoffError::Os)?;
        tail.extend_from_slice(&blob);
    }
    let mut crc = crate::crc32c::Crc32c::new();
    crc.update(&tail);
    let check = crc.finish().to_be_bytes();
    let mut frame = encode(&records);
    frame.extend_from_slice(&tail);
    frame.extend_from_slice(&check);
    Ok(SharedListeners { frame })
}

#[cfg(all(windows, feature = "local"))]
impl SharedListeners {
    /// Sends the listeners; consumed, so they go once.
    ///
    /// # Errors
    ///
    /// `Timeout`, `Truncated`, `Os`.
    pub fn write_to(self, pipe: &mut crate::pipe::PipeConnection) -> Result<(), HandoffError> {
        pipe.send_all(&self.frame).map_err(handoff_error)
    }
}

/// Receives listeners sent with [`SharedListeners::write_to`]. The process at the
/// far end of the pipe must run as the same user as this one, must have started
/// before the pipe connected, and must be `expect.pid` when that is set; it is
/// checked before anything is read. This holds whichever end created the pipe:
/// when this process dialed, the pipe's security descriptor is the other side's,
/// so it does not decide who sends. `expect.uid` has no meaning on Windows. The
/// message must be intact and never seen before, and every socket a listener bound
/// to the address the manifest names. All or nothing: on any error every received
/// socket is closed, also those listed after the one that failed. A description
/// that names a socket this process already owns (the same one twice, one from an
/// earlier hand-off, or one this process made or adopted any other way) is
/// refused and that socket is left as it was, so no socket gets two owners and
/// none is closed. Received sockets are not inheritable.
///
/// Windows makes each socket in this process when the sender describes it, so a
/// message that arrives damaged (`Truncated`, `BadChecksum`, or a bad manifest)
/// leaves the sockets it described open here, unclaimed, until this process
/// exits: their descriptions cannot be trusted enough to claim them. Only a
/// process of the same user can cause that; set `expect.pid` to narrow it to the
/// one expected sender.
///
/// # Errors
///
/// `PeerMismatch`, `Timeout`, `Truncated`, `BadMagic`, `BadVersion`, `BadChecksum`,
/// `TooMany`, `VerifyFailed` (also for a message accepted before), `Os`.
#[cfg(all(windows, feature = "local"))]
#[cfg_attr(docsrs, doc(cfg(windows)))]
pub fn receive_shared(
    pipe: &mut crate::pipe::PipeConnection,
    expect: &HandoffPeer,
    deadline: std::time::Instant,
) -> Result<Vec<ListenerHandle>, HandoffError> {
    let peer = pipe.peer_pid().map_err(|_| HandoffError::PeerMismatch)?;
    if expect.pid.is_some_and(|p| p != peer) {
        return Err(HandoffError::PeerMismatch);
    }
    if !same_user_sender(peer, pipe.info().accepted_at) {
        return Err(HandoffError::PeerMismatch);
    }
    pipe.set_phase(crate::session::Phase::Receiving);
    pipe.set_exchange_deadline(Some(deadline));
    let result = read_shared(pipe);
    pipe.set_exchange_deadline(None);
    let (records, tail) = result?;
    let (nonce, blobs) = tail.split_at(NONCE);
    let nonce: [u8; NONCE] = nonce.try_into().map_err(|_| HandoffError::Truncated)?;
    adopt_shared(records, nonce, blobs)
}

/// Whether process `pid` runs as this process's user and started before the pipe
/// connected at `connected` (so it is not a later process that took the number
/// of a sender that has exited). A process this one may not query fails.
#[cfg(all(windows, feature = "local"))]
fn same_user_sender(pid: u32, connected: std::time::Instant) -> bool {
    // System clock adjustments move both readings; a second of slack keeps one of
    // them from refusing a real sender.
    const SLACK: std::time::Duration = std::time::Duration::from_secs(1);
    let Ok(ours) = sys::current_user_sid() else {
        return false;
    };
    let Ok((theirs, started)) = sys::process_user_and_start(pid) else {
        return false;
    };
    let Some(latest) = filetime_at(connected).and_then(|t| t.checked_add(ticks(SLACK)))
    else {
        return false;
    };
    theirs == ours && started <= latest
}

/// `at` on the system clock, in `FILETIME` units (100 ns since 1601).
#[cfg(all(windows, feature = "local"))]
fn filetime_at(at: std::time::Instant) -> Option<u64> {
    /// 1601 to 1970 in 100 ns units.
    const EPOCH: u64 = 116_444_736_000_000_000;
    let ago = std::time::Instant::now().checked_duration_since(at)?;
    let then = std::time::SystemTime::now()
        .checked_sub(ago)?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    ticks(then).checked_add(EPOCH)
}

#[cfg(all(windows, feature = "local"))]
fn ticks(d: std::time::Duration) -> u64 {
    u64::try_from(d.as_nanos() / 100).unwrap_or(u64::MAX)
}

#[cfg(all(windows, feature = "local"))]
fn read_shared(
    pipe: &mut crate::pipe::PipeConnection,
) -> Result<(Vec<Record>, Vec<u8>), HandoffError> {
    let mut header = [0u8; HEADER];
    pipe.recv_exact(&mut header).map_err(handoff_error)?;
    let (count, total) = parse_header(&header)?;
    let mut manifest = vec![0u8; total];
    manifest[..HEADER].copy_from_slice(&header);
    pipe.recv_exact(&mut manifest[HEADER..])
        .map_err(handoff_error)?;
    let records = decode(&manifest)?;
    let mut tail = vec![0u8; NONCE + count * sys::SHARED_SOCKET + 4];
    pipe.recv_exact(&mut tail).map_err(handoff_error)?;
    let check_at = tail.len() - 4;
    let mut crc = crate::crc32c::Crc32c::new();
    crc.update(&tail[..check_at]);
    if crc.finish().to_be_bytes() != tail[check_at..] {
        return Err(HandoffError::BadChecksum);
    }
    tail.truncate(check_at);
    Ok((records, tail))
}

#[cfg(all(windows, feature = "local"))]
fn adopt_shared(
    records: Vec<Record>,
    nonce: [u8; NONCE],
    blobs: &[u8],
) -> Result<Vec<ListenerHandle>, HandoffError> {
    {
        let mut seen = ACCEPTED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if seen.contains(&nonce) {
            return Err(HandoffError::VerifyFailed {
                index: 0,
                why: "this hand-off was already accepted",
            });
        }
        seen.push(nonce);
    }
    // Every description is claimed before anything is checked: Windows made the
    // duplicate in this process when the sender described it, so one never turned
    // into a socket here stays open with no owner. A failure below drops them all.
    let mut claimed = Vec::with_capacity(records.len());
    let mut failed = None;
    for (i, blob) in blobs.chunks_exact(sys::SHARED_SOCKET).enumerate() {
        let index = i as u8;
        let got = <&[u8; sys::SHARED_SOCKET]>::try_from(blob)
            .map_err(|_| HandoffError::Truncated)
            .and_then(|blob| {
                sys::socket_from_shared(blob).map_err(|e| match e.kind() {
                    io::ErrorKind::AlreadyExists => HandoffError::VerifyFailed {
                        index,
                        why: "names a socket this process already owns",
                    },
                    _ => HandoffError::Os(e),
                })
            });
        match got {
            Ok(sock) => claimed.push(sock),
            Err(e) => {
                failed.get_or_insert(e);
            }
        }
    }
    if let Some(e) = failed {
        return Err(e);
    }
    if claimed.len() != records.len() {
        return Err(HandoffError::CountMismatch);
    }
    let mut handles = Vec::with_capacity(records.len());
    for (i, (record, (sock, adoption))) in records.into_iter().zip(claimed).enumerate() {
        let index = i as u8;
        let got = sys::listener_kind(sys::AsSock::sock(&sock)).map_err(|e| {
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
        let mut handle = ListenerHandle::new(kind, record.name, local, sock);
        handle.adopted = Some(adoption);
        handles.push(handle);
    }
    Ok(handles)
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

    /// Edge case 104: the same message twice is refused before any `WSASocketW`.
    #[cfg(all(windows, feature = "local"))]
    #[test]
    fn test_a_hand_off_works_once() {
        use std::net::TcpListener as Std;
        use std::time::{Duration, Instant};
        let std = Std::bind("127.0.0.1:0").unwrap();
        let addr = std.local_addr().unwrap();
        let handle =
            ListenerHandle::verified(sys::OwnedSock::from(std), Some("a".to_owned())).unwrap();
        let name = format!("net-io-handoff-{}", std::process::id());
        let listener = crate::pipe::PipeListener::create(&name).unwrap();
        let mut tx = crate::pipe::PipeConnection::connect(&name, Duration::from_secs(1)).unwrap();
        let (mut rx, _) = listener.accept().unwrap();
        let shared = share_listeners(&[&handle], std::process::id()).unwrap();
        let frame = shared.frame.clone();
        tx.send_all(&frame).unwrap();
        tx.send_all(&frame).unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        let peer = HandoffPeer {
            uid: None,
            pid: Some(std::process::id()),
        };
        let got = receive_shared(&mut rx, &peer, until).unwrap();
        assert_eq!(got[0].name(), Some("a"));
        assert_eq!(got[0].local().socket_addr(), Some(addr));
        assert!(matches!(
            receive_shared(&mut rx, &peer, until),
            Err(HandoffError::VerifyFailed { .. })
        ));
    }

    #[cfg(all(windows, feature = "local"))]
    #[test]
    fn test_wrong_peer_and_bad_checksum() {
        use std::net::TcpListener as Std;
        use std::time::{Duration, Instant};
        let std = Std::bind("127.0.0.1:0").unwrap();
        let handle = ListenerHandle::verified(sys::OwnedSock::from(std), None).unwrap();
        let name = format!("net-io-handoff-b-{}", std::process::id());
        let listener = crate::pipe::PipeListener::create(&name).unwrap();
        let mut tx = crate::pipe::PipeConnection::connect(&name, Duration::from_secs(1)).unwrap();
        let (mut rx, _) = listener.accept().unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        let wrong = HandoffPeer {
            uid: None,
            pid: Some(1),
        };
        assert!(matches!(
            receive_shared(&mut rx, &wrong, until),
            Err(HandoffError::PeerMismatch)
        ));
        let mut frame = share_listeners(&[&handle], std::process::id())
            .unwrap()
            .frame;
        let last = frame.len() - 1;
        frame[last] ^= 1;
        tx.send_all(&frame).unwrap();
        assert!(matches!(
            receive_shared(&mut rx, &HandoffPeer::default(), until),
            Err(HandoffError::BadChecksum)
        ));
    }

    /// A pipe pair for one test, (sender, receiver).
    #[cfg(all(windows, feature = "local"))]
    fn pipe_pair(tag: &str) -> (crate::pipe::PipeConnection, crate::pipe::PipeConnection) {
        use std::time::Duration;
        let name = format!("net-io-handoff-{tag}-{}", std::process::id());
        let listener = crate::pipe::PipeListener::create(&name).unwrap();
        let tx = crate::pipe::PipeConnection::connect(&name, Duration::from_secs(1)).unwrap();
        let (rx, _) = listener.accept().unwrap();
        (tx, rx)
    }

    /// A frame as `share_listeners` builds it, from any records and descriptions.
    #[cfg(all(windows, feature = "local"))]
    fn frame(records: &[Record], blobs: &[[u8; sys::SHARED_SOCKET]]) -> Vec<u8> {
        let mut tail = vec![0u8; NONCE];
        sys::random_bytes(&mut tail).unwrap();
        for b in blobs {
            tail.extend_from_slice(b);
        }
        let mut crc = crate::crc32c::Crc32c::new();
        crc.update(&tail);
        let mut out = encode(records);
        out.extend_from_slice(&tail);
        out.extend_from_slice(&crc.finish().to_be_bytes());
        out
    }

    #[cfg(all(windows, feature = "local"))]
    fn tcp_record(addr: std::net::SocketAddr) -> Record {
        Record {
            kind: SockKind::Tcp(addr),
            name: None,
        }
    }

    /// The sockets a failed hand-off received, also those after the one that
    /// failed, are closed: none keeps listening here.
    #[cfg(all(windows, feature = "local"))]
    #[test]
    fn test_a_failed_hand_off_leaves_no_socket_open() {
        use std::net::{TcpListener as Std, TcpStream};
        use std::os::windows::io::AsSocket;
        use std::time::{Duration, Instant};
        let (a, b) = (
            Std::bind("127.0.0.1:0").unwrap(),
            Std::bind("127.0.0.1:0").unwrap(),
        );
        let addr_b = b.local_addr().unwrap();
        let me = std::process::id();
        let blobs = [
            sys::share_socket(a.as_socket(), me).unwrap(),
            sys::share_socket(b.as_socket(), me).unwrap(),
        ];
        // The first record names the wrong address.
        let records = [tcp_record(addr_b), tcp_record(addr_b)];
        let (mut tx, mut rx) = pipe_pair("leak");
        tx.send_all(&frame(&records, &blobs)).unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        assert!(matches!(
            receive_shared(&mut rx, &HandoffPeer::default(), until),
            Err(HandoffError::VerifyFailed { index: 0, .. })
        ));
        drop((a, b));
        assert!(
            TcpStream::connect_timeout(&addr_b, Duration::from_secs(1)).is_err(),
            "the second socket still listens in this process"
        );
    }

    /// Fails the test without closing handles that may have two owners.
    #[cfg(all(windows, feature = "local"))]
    fn refused(got: Result<Vec<ListenerHandle>, HandoffError>) -> HandoffError {
        match got {
            Ok(handles) => {
                std::mem::forget(handles);
                panic!("one socket was adopted twice");
            }
            Err(e) => e,
        }
    }

    /// One description twice in a frame, or again in a later frame with a fresh
    /// nonce, would give one socket two owners: refused.
    #[cfg(all(windows, feature = "local"))]
    #[test]
    fn test_a_socket_is_never_adopted_twice() {
        use std::net::TcpListener as Std;
        use std::os::windows::io::AsSocket;
        use std::time::{Duration, Instant};
        let a = Std::bind("127.0.0.1:0").unwrap();
        let addr = a.local_addr().unwrap();
        let me = std::process::id();
        let until = Instant::now() + Duration::from_secs(5);
        let (mut tx, mut rx) = pipe_pair("twice");

        let blob = sys::share_socket(a.as_socket(), me).unwrap();
        let records = [tcp_record(addr), tcp_record(addr)];
        tx.send_all(&frame(&records, &[blob, blob])).unwrap();
        assert!(matches!(
            refused(receive_shared(&mut rx, &HandoffPeer::default(), until)),
            HandoffError::VerifyFailed { index: 1, .. }
        ));

        let blob = sys::share_socket(a.as_socket(), me).unwrap();
        tx.send_all(&frame(&records[..1], &[blob])).unwrap();
        let first = receive_shared(&mut rx, &HandoffPeer::default(), until).unwrap();
        tx.send_all(&frame(&records[..1], &[blob])).unwrap();
        assert!(matches!(
            refused(receive_shared(&mut rx, &HandoffPeer::default(), until)),
            HandoffError::VerifyFailed { index: 0, .. }
        ));
        // Once that socket is closed, a new description of the listener works.
        drop(first);
        let blob = sys::share_socket(a.as_socket(), me).unwrap();
        tx.send_all(&frame(&records[..1], &[blob])).unwrap();
        let again = receive_shared(&mut rx, &HandoffPeer::default(), until).unwrap();
        assert_eq!(again[0].local().socket_addr(), Some(addr));
    }

    /// A received listener is not inherited by processes this one starts.
    #[cfg(all(windows, feature = "local"))]
    #[test]
    fn test_received_sockets_are_not_inheritable() {
        use std::net::TcpListener as Std;
        use std::os::windows::io::AsSocket;
        use std::time::{Duration, Instant};
        let a = Std::bind("127.0.0.1:0").unwrap();
        let addr = a.local_addr().unwrap();
        let (mut tx, mut rx) = pipe_pair("inherit");
        let blob = sys::share_socket(a.as_socket(), std::process::id()).unwrap();
        tx.send_all(&frame(&[tcp_record(addr)], &[blob])).unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        let got = receive_shared(&mut rx, &HandoffPeer::default(), until).unwrap();
        assert!(!sys::is_inheritable(got[0].as_socket()).unwrap());
    }

    /// A description from `share_socket` with the handle value it names here
    /// changed to `to`.
    #[cfg(all(windows, feature = "local"))]
    fn naming(to: usize) -> [u8; sys::SHARED_SOCKET] {
        use std::os::windows::io::AsSocket;
        let decoy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut blob = sys::share_socket(decoy.as_socket(), std::process::id()).unwrap();
        // `dwProviderReserved`: the socket's handle value in the receiving process.
        blob[112..116].copy_from_slice(&u32::try_from(to).unwrap().to_ne_bytes());
        blob
    }

    /// A description that names a socket this process made itself is refused, and
    /// that socket is neither taken nor closed.
    #[cfg(all(windows, feature = "local"))]
    #[test]
    fn test_a_description_naming_a_socket_owned_here_is_refused() {
        use std::os::windows::io::AsRawSocket;
        let victim = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let raw = usize::try_from(victim.as_raw_socket()).unwrap();
        match sys::socket_from_shared(&naming(raw)) {
            Ok((sock, adoption)) => {
                let same = sock.as_raw_socket() == victim.as_raw_socket();
                std::mem::forget((sock, adoption));
                panic!("adopted a socket owned here (same handle: {same})");
            }
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::AlreadyExists),
        }
        let addr = victim.local_addr().unwrap();
        let _c = std::net::TcpStream::connect(addr).expect("the socket still listens");
        assert!(victim.accept().is_ok());
    }

    /// Through `receive_shared`: a frame that names the receiver's own listener at
    /// its real address is refused, and one whose check would fail does not close
    /// that listener.
    #[cfg(all(windows, feature = "local"))]
    #[test]
    fn test_a_forged_hand_off_neither_adopts_nor_closes_a_listener_here() {
        use std::os::windows::io::AsRawSocket;
        use std::time::{Duration, Instant};
        let victim = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = victim.local_addr().unwrap();
        let raw = usize::try_from(victim.as_raw_socket()).unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        let (mut tx, mut rx) = pipe_pair("forged");
        tx.send_all(&frame(&[tcp_record(addr)], &[naming(raw)]))
            .unwrap();
        assert!(matches!(
            refused(receive_shared(&mut rx, &HandoffPeer::default(), until)),
            HandoffError::VerifyFailed { index: 0, .. }
        ));
        let wrong: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        tx.send_all(&frame(&[tcp_record(wrong)], &[naming(raw)]))
            .unwrap();
        assert!(receive_shared(&mut rx, &HandoffPeer::default(), until).is_err());
        let _c = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2))
            .expect("the listener survived");
        assert!(victim.accept().is_ok());
    }

    /// Descriptions naming handles that are not sockets (a file, the channel's own
    /// pipe) leave those handles working.
    #[cfg(all(windows, feature = "local"))]
    #[test]
    fn test_a_forged_hand_off_leaves_other_handles_alone() {
        use std::io::{Read, Seek};
        use std::os::windows::io::AsRawHandle;
        use std::time::{Duration, Instant};
        let mut file = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
        let (mut tx, mut rx) = pipe_pair("others");
        let channel = rx.raw_handle() as usize;
        let any: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let blobs = [naming(file.as_raw_handle() as usize), naming(channel)];
        tx.send_all(&frame(&[tcp_record(any), tcp_record(any)], &blobs))
            .unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        assert!(receive_shared(&mut rx, &HandoffPeer::default(), until).is_err());
        let mut buf = [0u8; 2];
        file.rewind().unwrap();
        assert!(file.read(&mut buf).is_ok(), "the file was closed");
        tx.send_all(b"hi").unwrap();
        rx.recv_exact(&mut buf).expect("the channel was closed");
        assert_eq!(&buf, b"hi");
    }

    /// The sender must run as this user and must have started before the pipe
    /// connected.
    #[cfg(all(windows, feature = "local"))]
    #[test]
    fn test_only_a_sender_of_this_user_that_was_already_running_is_accepted() {
        use std::time::{Duration, Instant};
        assert!(same_user_sender(std::process::id(), Instant::now()));
        // The system process runs as another account.
        assert!(!same_user_sender(4, Instant::now()));
        // A process that started after the pipe connected took a number that
        // belonged to someone else.
        let connected = Instant::now().checked_sub(Duration::from_secs(10)).unwrap();
        let mut child = std::process::Command::new("cmd")
            .args(["/C", "ping", "-n", "3", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let later = same_user_sender(child.id(), connected);
        let _ = child.kill();
        let _ = child.wait();
        assert!(!later, "a process started after the connection was accepted");
    }

    #[cfg(all(windows, feature = "local"))]
    #[test]
    fn test_nothing_arrives_by_the_deadline() {
        use std::time::{Duration, Instant};
        let name = format!("net-io-handoff-c-{}", std::process::id());
        let listener = crate::pipe::PipeListener::create(&name).unwrap();
        let _tx = crate::pipe::PipeConnection::connect(&name, Duration::from_secs(1)).unwrap();
        let (mut rx, _) = listener.accept().unwrap();
        let until = Instant::now() + Duration::from_millis(50);
        assert!(matches!(
            receive_shared(&mut rx, &HandoffPeer::default(), until),
            Err(HandoffError::Timeout)
        ));
    }
}
