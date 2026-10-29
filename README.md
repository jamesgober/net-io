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
        <strong>Status: <code>0.4.0</code>, the edges.</strong> TCP, Unix domain sockets, and UDP on the blocking driver, the PROXY protocol, the TLS seam on listeners, systemd and FastCGI inheritance, and listener hand-off between processes. Pre-1.0: the API in <a href="./docs/API.md"><code>docs/API.md</code></a> is locked, and each item says the version that ships it. The reactor and Windows named pipes arrive in <code>0.5.0</code> (<a href="./dev/ROADMAP.md"><code>dev/ROADMAP.md</code></a>).
    </blockquote>
</div>

<hr>
<br>

## What it does

| Area | In `0.4.0` | Later |
|---|---|---|
| Transports | TCP; Unix domain sockets with peer credentials and descriptor passing; UDP with budgets and an amplification guard | Windows named pipes and AF_UNIX (`0.5.0`) |
| Drivers | a bounded blocking worker pool: 2 system calls per keep-alive round trip on Linux (3 on macOS and Windows), no allocation after warm-up | its own reactor on epoll, kqueue, and IOCP (`0.5.0`) |
| Limits | global, per-listener, and per-source caps; idle, read, write, exchange, and park deadlines; a minimum transfer rate against slowloris and slow readers; bounded buffers | adaptive deadlines and lane reservations (`0.6.0`) |
| Lifecycle | the door, graceful drain with a deadline, kill from any thread, one `CloseReason` and one closed event per connection, a control line (shed, lockdown, drain, stop); listeners added and removed while running; systemd and FastCGI inheritance; listener hand-off between processes (Unix) | the Windows hand-off (`0.5.0`) |
| Seams | the gate (admission before any byte is read, a check before every write, also for adopted and dialed connections), sans-IO sessions, an event sink, a completion queue for offloaded work; the PROXY protocol from trusted proxies; the TLS seam on listeners | adaptive deadlines and lane reservations (`0.6.0`) |

The full plan:

| Area | Planned |
|---|---|
| Transports | TCP, UDP, Unix domain sockets (Unix and Windows), Windows named pipes |
| Socket options | `TCP_NODELAY`, keepalive tuning, linger, buffer sizes, `SO_REUSEADDR` / `SO_EXCLUSIVEADDRUSE`, `SO_REUSEPORT`, `IPV6_V6ONLY`, and the server options `std` does not expose |
| Connections | a never-reused `ConnectionId`, `ConnectionInfo` (endpoints, real client behind a trusted proxy, transport, TLS facts), one `CloseReason` on every close |
| Limits | global, per-listener, and per-source caps; handshake, idle, read, write, and total deadlines; a minimum transfer rate against slowloris and slow-read; bounded buffers and queues |
| Drivers | a bounded blocking worker pool (`0.3.0`); its own reactor on epoll, kqueue, and IOCP (`0.5.0`); one completion-shaped interface |
| Sessions | sans-IO protocol engines driven the same way on every driver, with zero-copy input and an O(1) buffer hand-off |
| Behind a proxy | PROXY protocol v1 and v2, honoured only from configured trusted proxies |
| Restarts | a door that opens last and closes first, graceful drain, systemd socket activation, FastCGI descriptor 0, listener hand-off between processes |
| Seams | a gate (admission before any byte is read, a check before every write, kill from any thread), a sans-IO TLS seam, an event sink, a control line, a completion queue for offloaded work |

## Use

```toml
[dependencies]
net-io = "0.3"
```

The simplest server (the full API is in [`docs/API.md`](./docs/API.md); `examples/` has a sans-IO session, kill and drain, and a gate):

```rust
fn main() -> Result<(), net_io::NetError> {
    // Echo server on a bounded worker pool with every default limit applied.
    let server = net_io::serve("127.0.0.1:7000", |conn| {
        let mut buf = [0u8; 4096];
        loop {
            let n = conn.recv(&mut buf)?;
            if n == 0 {
                return Ok(());
            }
            conn.send_all(&buf[..n])?;
        }
    })?;
    server.wait_for_stop(); // runs until server.handle().request_stop(), then drains
    Ok(())
}
```

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
        <li><b>Apache License, Version 2.0</b>: <a href="./LICENSE-APACHE">LICENSE-APACHE</a></li>
        <li><b>MIT License</b>: <a href="./LICENSE-MIT">LICENSE-MIT</a></li>
    </ul>
    <p>at your option.</p>
</div>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
