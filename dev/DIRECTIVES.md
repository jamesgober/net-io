# net-io &mdash; Engineering Directives

> Engineering standards and the definition of done for this project. Read alongside `REPS.md` (root, authoritative), [`PLAN.md`](./PLAN.md) (design and decisions), and [`ROADMAP.md`](./ROADMAP.md) (current phase). If anything here conflicts with `REPS.md`, `REPS.md` wins, except where `PLAN.md` records an approved exception.

---

## 0. Philosophy

This library is built and maintained to a production standard and treated as a flagship piece of work. Plan the full path, then build one verified step at a time. "Good enough" is treated as a defect. It is the transport substrate of the owner's `-io` and `-net` domains: every service that listens on a port goes through it, so a flaw here is a flaw everywhere.

---

## 1. What this is

net-io owns sockets, connection lifecycle, limits and timeouts, drain, the PROXY protocol, and the seams for TLS, the connection gate, and observability. It does not parse application protocols, implement TLS, decide policy (who is banned), or run an async runtime. See `PLAN.md` section 3 for the full in/out list and where each excluded piece lives.

---

## 2. Engineering law (non-negotiable)

- **Ours, not rented.** No third-party runtime dependency. OS calls `std` lacks go through our own FFI declarations in `sys/`. Dev-only test tooling (`criterion`, `proptest`) is allowed.
- **Protocol-free.** Nothing in this crate knows the format of the bytes it carries. Hooks are traits defined here and implemented elsewhere; this crate never depends on its implementers.
- **Unsafe is fenced.** `unsafe` only inside `sys/`, every block with a `// SAFETY:` comment stating the invariants, how they are established, and the platform contract (man page or Microsoft documentation) it relies on. Everything else is `#![deny(unsafe_code)]`. Until `sys/` exists the crate is `#![forbid(unsafe_code)]`.
- **Hostile-input hardening.** Every peer may be adversarial: explicit budgets for bytes, time, and counts, checked before the resource is committed; no reachable panics; fail closed.
- **Performance.** Peak is the baseline: allocation-free hot paths, no lock on the accept or write path that a lock-free design can avoid, no "faster" claim without `criterion` numbers at realistic scale.
- **Cross-platform.** Linux, macOS, and Windows are first-class, verified by CI on stable and MSRV 1.85. Platform differences are documented per feature.
- **Error handling.** Every fallible path returns `Result`; errors are `#[non_exhaustive]`, carry the OS error as a source, and say what to do.
- **Production-ready.** `#![deny(missing_docs)]`; no `unwrap`/`expect`/`todo!`/`dbg!`/printing in library code; every public item has rustdoc with a runnable example; every claim in the docs maps to a test.

---

## 3. Definition of done

1. Compiles clean on Linux/macOS/Windows, stable and MSRV 1.85.
2. `fmt`, `clippy -D warnings` (all targets, all/no-default features), `test --all-features`, `cargo doc -D warnings` clean.
3. `cargo audit` + `cargo deny check` pass.
4. No `unwrap`/`expect`/`todo!`/`dbg!` in shipping code.
5. A Tier-1 API exists and headlines the docs.
6. Property tests cover every section-4 invariant; a fuzz target exists for every parser.
7. Hot-path changes carry benchmarks; no regression over 5%.
8. `README.md`, `docs/API.md`, and `CHANGELOG.md` updated; the matching `docs/release/vX.Y.Z.md` written before the tag.
9. `PLAN.md` decision log updated for every design decision made during the work.
10. v1.0.0 only after the web stack and one non-HTTP service have used the API end to end.

---

## 4. Project-specific invariants

- No byte is read from a connection before the admission hook has allowed it.
- No byte is written to a connection without passing the egress hook; a denied write never leaves partial output on the wire.
- Every connection ends with exactly one closed event carrying a `CloseReason`.
- A PROXY header is honoured only from a peer in `TrustedProxies`; when one is required and missing, the connection is refused.
- Every buffer, queue, and wait is bounded; limits are checked before allocation.
- Descriptor and handle counts return to baseline after every connection closes, on every close path.
- `ConnectionId`s are never reused within a process.

---

## 5. Writing style

- Plain, specific, human prose in every shipping file. No marketing voice.
- Banned in shipping files: "comprehensive", "robust", "seamless", "leverage", and the em-dash character (U+2014) in prose.
- Commits: imperative present tense, descriptive subject line.
