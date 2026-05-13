<h1 align="center">
    <strong>net-io</strong>
    <br>
    <sup><sub>HIGH-PERFORMANCE NETWORK IO FOR RUST</sub></sup>
</h1>

<p align="center">
    <a href="https://crates.io/crates/net-io"><img alt="crates.io" src="https://img.shields.io/crates/v/net-io.svg"></a>
    <a href="https://crates.io/crates/net-io"><img alt="downloads" src="https://img.shields.io/crates/d/net-io.svg"></a>
    <a href="https://docs.rs/net-io"><img alt="docs.rs" src="https://docs.rs/net-io/badge.svg"></a>
    <a href="https://github.com/jamesgober/net-io/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/jamesgober/net-io/actions/workflows/ci.yml/badge.svg"></a>
</p>

<p align="center">
    Server-grade TCP and QUIC transport with session lifecycle, framing, multiplexing, and backpressure built in.
</p>

---

## Status

Status: CONSIDERING - placeholder repo to claim the crates.io name. Active design work begins after HiveDB single-node API stabilizes. See `.dev/ROADMAP.md`.

This repository is published primarily to reserve the crate name and
to establish the project scaffolding. Implementation work proceeds on
the schedule documented in `.dev/ROADMAP.md`.

## What it does

Purpose-built network IO substrate for Rust. TCP / QUIC listeners, connection lifecycle, framing-over-stream, session state, request multiplexing, backpressure, timeouts. Built for enterprise-grade high-throughput servers (HiveDB and friends).

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE)
for the full text.

Copyright (C) 2026 James Gober.
