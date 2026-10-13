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

### Changed

- `dev/PLAN.md`: the security crates now have names and repositories
  (`shield-sec`, `sentinel-sec`); the stack table records which crates have
  their own plans and adds the form crate; decisions D-010 (names), D-011
  (the protocol-parser role), and D-012 (no home-made TLS); `rate-net` and
  `better-bucket` are not used by bouncer-io until they are dependency-free.

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

[Unreleased]: https://github.com/jamesgober/net-io/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jamesgober/net-io/releases/tag/v0.1.0
