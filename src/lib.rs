//! Purpose-built network IO substrate for Rust. TCP / QUIC listeners, connection lifecycle, framing-over-stream, session state, request multiplexing, backpressure, timeouts. Built for enterprise-grade high-throughput servers (HiveDB and friends).
//!
//! # Status
//!
//! This crate is in early scaffolding. The public API is not yet
//! defined. See [the repository](https://github.com/jamesgober/net-io)
//! and `.dev/ROADMAP.md` for the milestone plan.

#![doc(html_root_url = "https://docs.rs/net-io")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Crate version string, populated by Cargo at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
