<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <b>net-io</b>
    <br>
    <sub><sup>NETWORK IO SUBSTRATE</sup></sub>
</h1>

<div align="center">
    <a href="https://crates.io/crates/net-io"><img alt="Crates.io" src="https://img.shields.io/crates/v/net-io"></a>
    <a href="https://crates.io/crates/net-io"><img alt="Downloads" src="https://img.shields.io/crates/d/net-io?color=%230099ff"></a>
    <a href="https://docs.rs/net-io"><img alt="docs.rs" src="https://img.shields.io/docsrs/net-io"></a>
    <a href="https://github.com/jamesgober/net-io/actions"><img alt="CI" src="https://github.com/jamesgober/net-io/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.85%2B-blue"></a>
</div>

<br>

<div align="left">
    <p>
        <strong>net-io</strong> is the entrance and exit for network services: listeners and sockets for TCP, UDP, Unix domain sockets, and Windows named pipes; the life of each connection from accept to close; the limits and timeouts that stop a peer from holding what it should not; graceful drain and zero-downtime restarts; the PROXY protocol for running behind Apache, nginx, or a load balancer; and the seams that TLS and a connection gate plug into.
    </p>
    <p>
        It is protocol-free. It moves bytes and knows who is on the other end; it never parses HTTP or any other application protocol. Protocol engines such as <a href="https://github.com/jamesgober/http-net"><code>http-net</code></a> and <a href="https://github.com/jamesgober/ws-net"><code>ws-net</code></a> sit on top, so the same transport serves a web stack, a database wire protocol, or a consensus transport.
    </p>
    <br>
    <hr>
    <p>
        <strong>MSRV is 1.85+</strong> (Rust 2024 edition). No dependencies: OS calls the standard library does not expose go through the crate's own fenced FFI layer.
    </p>
    <blockquote>
        <strong>Status: scaffold (<code>0.1.0</code>).</strong> No functional code yet. The design is written down in <a href="./dev/PLAN.md"><code>dev/PLAN.md</code></a> and the schedule in <a href="./dev/ROADMAP.md"><code>dev/ROADMAP.md</code></a>; the public API is locked in <code>0.2.0</code>.
    </blockquote>
</div>

<hr>
<br>

## What it will do

| Area | Planned |
|---|---|
| Transports | TCP, UDP, Unix domain sockets (Unix and Windows), Windows named pipes |
| Socket options | `TCP_NODELAY`, keepalive tuning, `SO_REUSEADDR`, `SO_REUSEPORT`, `IPV6_V6ONLY`, buffer sizes, linger |
| Connections | a never-reused `ConnectionId`, `ConnInfo` (local, peer, real peer, transport, timestamps), lifecycle states, a `CloseReason` on every close |
| Limits | global connection cap, accept backlog, handshake, idle, read, write, and total deadlines, minimum transfer rate, bounded buffers |
| Drivers | a bounded blocking worker pool first; its own reactor (epoll, kqueue, IOCP) second |
| Behind a proxy | PROXY protocol v1 and v2, honoured only from configured trusted proxies |
| Restarts | graceful drain; inherited listeners (`LISTEN_FDS`) and listener hand-off |
| Seams | admission and egress hooks with a kill handle for a connection gate; a sans-IO TLS seam with ClientHello capture; an event sink for logs and metrics |

<br>

## What is not here

- **QUIC:** it runs on UDP but builds TLS 1.3 into the transport itself, so it gets its own crate later (`quic-net`) on top of this one's UDP socket.
- **DNS resolution:** `std` covers it for now; a real resolver becomes its own crate later (`dns-net`).
- **A TLS implementation:** TLS plugs in through the seam from a separate adapter crate, which keeps this crate dependency-free.
- **Application protocols, ban policy, authentication:** these live in the crates above it.

<hr>
<br>

## Contributing

See <a href="./dev/DIRECTIVES.md"><code>dev/DIRECTIVES.md</code></a> for engineering standards and the definition of done. Before a PR: `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-features` must be clean.

<br>

<div id="license">
    <h2>License</h2>
    <p>Licensed under either of</p>
    <ul>
        <li><b>Apache License, Version 2.0</b> &mdash; <a href="./LICENSE-APACHE">LICENSE-APACHE</a></li>
        <li><b>MIT License</b> &mdash; <a href="./LICENSE-MIT">LICENSE-MIT</a></li>
    </ul>
    <p>at your option.</p>
</div>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
