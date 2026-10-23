<h1 align="center">
    <img width="90px" height="auto" src="https://raw.githubusercontent.com/jamesgober/jamesgober/main/media/icons/hexagon-3.svg" alt="Triple Hexagon">
    <br><b>CHANGELOG</b>
</h1>
<p>
  All notable changes to <code>net-io</code> will be documented in this file. The format is based on <a href="https://keepachangelog.com/en/1.1.0/">Keep a Changelog</a>,
  and this project adheres to <a href="https://semver.org/spec/v2.0.0.html/">Semantic Versioning</a>.
</p>

---

## [Unreleased]

---

## [0.2.0] - 2026-10-23

The design lock: the public API is written down in full and the design
behind it recorded. Still no functional code; `0.3.0` brings TCP with the
blocking driver.

### Added

- `docs/API.md`: every public item from `0.3.0` to `1.0.0` with its
  signature, behaviour, errors, cost target, grade, tier, the version that
  ships it, and examples. Tier 1 is `listen`, `connect`, `serve`,
  `serve_sessions`, `listen_local`, and `connect_local`.
- `dev/SYS-SURFACE.md`: the OS functions, constants, and structs the crate
  declares per platform, with the documentation each relies on.
- The gate seam: one `Gate` trait whose per-connection ticket is passed back
  on every check and returned at close with the close reason.
- The TLS seam: an in-place, sans-IO session (`TlsAcceptor`, `TlsSession`)
  that decrypts inside the connection's own read buffer.

### Changed

- `dev/PLAN.md` rewritten: requirements (FR-1 to FR-72, NFR-1 to NFR-20),
  architecture, the threat table with a test and a cost for each threat,
  performance targets, the edge-case list, platform spike results, and
  decisions D-013 to D-060.
- `dev/ROADMAP.md` rewritten to the portfolio's version table (0.6
  optimisation, 0.7 hardening, 0.8 alpha, 0.9 beta added; hardening moved
  from 0.9 to 0.7), with the reconciliation recorded.
- Names use full words (`TcpConnection`, `ConnectionInfo`,
  `SessionContext`, `Input`, `Output`, `Buffer`).
- Unix sockets default to mode `0600`; naming a group gives `0660`.
- `dev/PLAN.md` (earlier, unreleased): the security crates have names and
  repositories (`shield-sec`, `sentinel-sec`); decisions D-010 to D-012.

---

## [0.1.0] - 2026-10-13

The scaffold and the plan. No functional code yet.

### Added

- Crate manifest (edition 2024, MSRV 1.85, no dependencies), `Apache-2.0 OR MIT`
  license, README, REPS, CI (Linux, macOS, Windows on stable and 1.85; audit
  and deny), `deny.toml`, `clippy.toml`, `rustfmt.toml`, `.gitattributes`.
- `dev/PLAN.md`: purpose, the request path and the protocol-free rule, scope
  and where excluded work lives (QUIC in `quic-net`, DNS in `dns-net`, TLS
  through a seam), design principles, architecture (modules, connection
  lifecycle, gate and TLS seams, drivers, PROXY protocol, limits, drain, UDP,
  local sockets), deployment modes, security responsibilities, ecosystem and
  dependencies, testing, open decisions, and the decision log.
- `dev/DIRECTIVES.md` and `dev/ROADMAP.md`.

[Unreleased]: https://github.com/jamesgober/net-io/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/jamesgober/net-io/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/net-io/releases/tag/v0.1.0
