//! # net_io
//!
//! The network IO substrate for the `-net` and `-io` crates: the entrance
//! and exit every service shares. It owns listeners and sockets (TCP, UDP,
//! Unix domain sockets, Windows named pipes), the lifecycle of each
//! connection, the limits and timeouts that keep a peer from pinning the
//! server, graceful drain, the PROXY protocol for running behind a reverse
//! proxy, and the seams that TLS and the connection gate plug into.
//!
//! It is protocol-free. It moves bytes and knows who is on the other end of
//! a connection; it does not know whether those bytes are HTTP, a database
//! wire protocol, or Raft messages. Protocol engines such as `http-net` and
//! `ws-net` sit on top of it.
//!
//! ## Status
//!
//! Design lock (`0.2.0`). No functional code yet. The public API is locked in
//! `docs/API.md`, the design and its decisions in `dev/PLAN.md`, and the
//! milestone schedule in `dev/ROADMAP.md` (all in the
//! [repository](https://github.com/jamesgober/net-io)). `0.3.0` brings TCP
//! with the blocking driver.

#![doc(html_root_url = "https://docs.rs/net-io")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Crate version string, populated by Cargo at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_matches_manifest() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert_eq!(VERSION.split('.').count(), 3, "expected MAJOR.MINOR.PATCH");
    }
}
