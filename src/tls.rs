//! The TLS seam: traits a TLS engine implements in its own crate.
//!
//! net-io carries no TLS code. The seam is in place and sans-IO: ciphertext is
//! decrypted inside the connection's own read buffer and plaintext is encrypted
//! straight into net-io's output buffer. The server integration arrives in
//! `0.4.0` behind the `tls` feature; the traits exist in every build.

use std::fmt;

use crate::info::ConnectionInfo;

/// Creates one [`TlsSession`] per admitted connection.
///
/// # Examples
///
/// ```
/// use net_io::{ConnectionInfo, NoTls, TlsAcceptor};
/// let info = ConnectionInfo::for_testing("127.0.0.1:1".parse().unwrap());
/// assert!(NoTls.session(&info).is_err());
/// ```
pub trait TlsAcceptor: Send + Sync + 'static {
    /// The per-connection session type.
    type Session: TlsSession;

    /// Called once per admitted connection, after PROXY and readmission, before any TLS byte is read.
    ///
    /// # Errors
    ///
    /// A [`TlsError`] refuses the connection (for example an acceptor at capacity).
    fn session(&self, info: &ConnectionInfo) -> Result<Self::Session, TlsError>;
}

/// One connection's TLS state machine. Never blocks, never does IO.
///
/// See `docs/API.md` (TLS seam) for how the server drives it.
pub trait TlsSession: Send + 'static {
    /// Ciphertext is in `input`; free space for records to send is `output`.
    ///
    /// # Errors
    ///
    /// A [`TlsError`]; `TlsFailure::HelloRefused` closes the connection with
    /// `CloseReason::HelloRefused`, anything else with `TlsFailed`.
    fn step<'i>(
        &mut self,
        input: &'i mut [u8],
        output: &mut [u8],
    ) -> Result<TlsProgress<'i>, TlsError>;

    /// Encrypts `plaintext` into `output`: all records or none.
    ///
    /// # Errors
    ///
    /// `TlsFailure::OutputFull` when `output` cannot hold every record.
    fn encrypt(&mut self, plaintext: &[u8], output: &mut [u8]) -> Result<usize, TlsError>;

    /// Writes `close_notify` into `output`.
    ///
    /// # Errors
    ///
    /// `TlsFailure::OutputFull` or `TlsFailure::State`.
    fn close(&mut self, output: &mut [u8]) -> Result<usize, TlsError>;

    /// The peer's transport closed: was the TLS stream ended cleanly?
    fn on_transport_closed(&mut self) -> TlsCloseKind;

    /// SNI, ALPN, version, and cipher suite; `Some` after the handshake.
    fn info(&self) -> Option<TlsInfo>;

    /// The smallest input buffer the session needs now.
    fn input_capacity_required(&self) -> usize;
}

/// What one [`TlsSession::step`] did.
#[must_use]
#[derive(Debug)]
pub struct TlsProgress<'i> {
    /// Input bytes the engine consumed.
    pub consumed: usize,
    /// Bytes the engine wrote at the start of `output`.
    pub written: usize,
    /// What the caller does next.
    pub event: TlsEvent<'i>,
}

/// The next thing the driver does after a step.
#[non_exhaustive]
#[derive(Debug)]
pub enum TlsEvent<'i> {
    /// Read more ciphertext, append it after the unconsumed bytes, call `step` again.
    NeedInput,
    /// Send the `written` bytes at the start of `output`, all of them.
    Transmit,
    /// The handshake finished; `info()` is now `Some`.
    HandshakeComplete,
    /// Plaintext decrypted in place; call `step` again for more.
    Data(&'i [u8]),
    /// Not enough room in `output`; flush and call again.
    OutputFull,
    /// `close_notify` was received.
    PeerClosed,
    /// Both directions are closed.
    Closed,
}

/// Whether a TLS stream ended with `close_notify`.
///
/// ```
/// assert_ne!(net_io::TlsCloseKind::Clean, net_io::TlsCloseKind::Unclean);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsCloseKind {
    /// `close_notify` was seen.
    Clean,
    /// The transport closed without it.
    Unclean,
}

/// What failed in a TLS engine.
///
/// ```
/// assert_ne!(net_io::TlsFailure::Handshake, net_io::TlsFailure::HelloRefused);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsFailure {
    /// The handshake failed.
    Handshake,
    /// The engine's hello hook refused the ClientHello.
    HelloRefused,
    /// The acceptor is at capacity.
    Capacity,
    /// The peer broke the protocol.
    Protocol,
    /// The output buffer is too small.
    OutputFull,
    /// The call is not valid in the session's state.
    State,
}

/// A TLS engine error: codes only, never secret material.
///
/// ```
/// use net_io::{TlsError, TlsFailure};
/// let e = TlsError::new(TlsFailure::HelloRefused, 3, None);
/// assert_eq!(e.kind, TlsFailure::HelloRefused);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsError {
    /// What failed.
    pub kind: TlsFailure,
    /// The engine's own code.
    pub code: u16,
    /// The TLS alert sent or received, if any.
    pub alert: Option<u8>,
}

impl TlsError {
    /// Builds an error.
    #[must_use]
    pub const fn new(kind: TlsFailure, code: u16, alert: Option<u8>) -> TlsError {
        TlsError { kind, code, alert }
    }
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} (engine code {}", self.kind, self.code)?;
        if let Some(alert) = self.alert {
            write!(f, ", alert {alert}")?;
        }
        f.write_str(")")
    }
}

impl std::error::Error for TlsError {}

/// TLS facts after the handshake, in fixed arrays.
///
/// ```
/// let info = net_io::TlsInfo::new(Some("example.com"), Some(b"h2"), 0x0304, 0x1301).unwrap();
/// assert_eq!(info.sni(), Some("example.com"));
/// assert!(net_io::TlsInfo::new(Some(&"a".repeat(256)), None, 0, 0).is_none());
/// ```
#[non_exhaustive]
#[derive(Clone, Copy)]
pub struct TlsInfo {
    sni: [u8; 255],
    sni_len: u8,
    alpn: [u8; 32],
    alpn_len: u8,
    version: u16,
    cipher_suite: u16,
}

impl TlsInfo {
    /// Builds the facts; `None` if the SNI is longer than 255 bytes or the ALPN longer than 32.
    #[must_use]
    pub fn new(
        sni: Option<&str>,
        alpn: Option<&[u8]>,
        version: u16,
        cipher_suite: u16,
    ) -> Option<TlsInfo> {
        let sni = sni.unwrap_or("").as_bytes();
        let alpn = alpn.unwrap_or(&[]);
        if sni.len() > 255 || alpn.len() > 32 {
            return None;
        }
        let mut info = TlsInfo {
            sni: [0; 255],
            sni_len: u8::try_from(sni.len()).ok()?,
            alpn: [0; 32],
            alpn_len: u8::try_from(alpn.len()).ok()?,
            version,
            cipher_suite,
        };
        info.sni[..sni.len()].copy_from_slice(sni);
        info.alpn[..alpn.len()].copy_from_slice(alpn);
        Some(info)
    }

    /// The server name the client asked for.
    #[must_use]
    pub fn sni(&self) -> Option<&str> {
        if self.sni_len == 0 {
            return None;
        }
        std::str::from_utf8(&self.sni[..usize::from(self.sni_len)]).ok()
    }

    /// The negotiated application protocol.
    #[must_use]
    pub fn alpn(&self) -> Option<&[u8]> {
        (self.alpn_len > 0).then(|| &self.alpn[..usize::from(self.alpn_len)])
    }

    /// The protocol version code (for example `0x0304` for TLS 1.3).
    #[must_use]
    pub fn version(&self) -> u16 {
        self.version
    }

    /// The cipher suite code.
    #[must_use]
    pub fn cipher_suite(&self) -> u16 {
        self.cipher_suite
    }
}

impl fmt::Debug for TlsInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsInfo")
            .field("sni", &self.sni())
            .field("alpn", &self.alpn().map(String::from_utf8_lossy))
            .field("version", &format_args!("{:#06x}", self.version))
            .field("cipher_suite", &format_args!("{:#06x}", self.cipher_suite))
            .finish()
    }
}

/// The builder's default acceptor: no listener may enable TLS with it.
///
/// ```
/// use net_io::{ConnectionInfo, NoTls, TlsAcceptor};
/// let info = ConnectionInfo::for_testing("127.0.0.1:1".parse().unwrap());
/// assert!(NoTls.session(&info).is_err());
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct NoTls;

/// The session type of [`NoTls`]; it has no values.
#[derive(Debug)]
pub enum NoTlsSession {}

impl TlsAcceptor for NoTls {
    type Session = NoTlsSession;
    fn session(&self, _info: &ConnectionInfo) -> Result<NoTlsSession, TlsError> {
        Err(TlsError::new(TlsFailure::State, 0, None))
    }
}

impl TlsSession for NoTlsSession {
    fn step<'i>(
        &mut self,
        _input: &'i mut [u8],
        _output: &mut [u8],
    ) -> Result<TlsProgress<'i>, TlsError> {
        match *self {}
    }
    fn encrypt(&mut self, _plaintext: &[u8], _output: &mut [u8]) -> Result<usize, TlsError> {
        match *self {}
    }
    fn close(&mut self, _output: &mut [u8]) -> Result<usize, TlsError> {
        match *self {}
    }
    fn on_transport_closed(&mut self) -> TlsCloseKind {
        match *self {}
    }
    fn info(&self) -> Option<TlsInfo> {
        match *self {}
    }
    fn input_capacity_required(&self) -> usize {
        match *self {}
    }
}
