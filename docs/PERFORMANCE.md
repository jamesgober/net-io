# net-io - Performance

The targets and the method are in the project plan (section 9). This file records measured numbers, each with its commit, hardware, OS, and command line. Until 0.6 these are baselines: there is no competitor gate yet.

## 0.3.0 baselines (blocking driver)

Hardware: AMD Ryzen 9 9950X3D (16 cores, 32 threads, two dies). Linux numbers from WSL2 (kernel 6.6.87.2-microsoft-standard-WSL2), labelled as such; Windows 11 numbers for comparison. Rust 1.99.0 (WSL2), release profile. Commit `1fce41e` on the 0.3 branch.

### B-2: echo, 64 B, one connection

`cargo bench --bench echo`: one client thread, one round trip at a time, 20,000 round trips per run, 7 runs in rotated order, medians.

| Stack (WSL2) | Round trips/s | p50 | p99 |
|---|---|---|---|
| std, thread per connection | 82,793 | 7.6 µs | 39.6 µs |
| net-io blocking handler | 73,380 | 7.7 µs | 40.9 µs |
| net-io sessions, `AllowAll` | 79,373 | 8.0 µs | 40.9 µs |
| net-io sessions, one-atomic gate | 61,135 | 8.0 µs | 44.7 µs |

Reading: per round trip, net-io is within 0.1 to 0.4 µs of a bare std echo while enforcing its deadlines, the inbound rate check, the kill guard, and the gate seam. Throughput medians move by up to 20% between runs on WSL2 (the same build gave std 58,979 and net-io 80,882 in an earlier run); p50 latency is the stable figure. On Windows 11 the p50 of every stack is 13 to 16 µs when the client and server threads share a die and 28 to 39 µs when they do not, so single Windows runs differ by 2x in either direction; the medians over rotated runs agree within noise.

The plan's B-2 goal (at least 1.2x the std thread-per-connection server) is a 0.6 target, measured under load with the `compare/` harness; a single connection on loopback mostly measures the kernel.

### B-7: gate check overhead

The difference in p50 between sessions with `AllowAll` (no check: the gate is skipped by type) and a gate that does one atomic add per write: -27 ns on WSL2, below the run-to-run noise of about 200 ns. The check is one dynamic call and one `catch_unwind` per write call; a nanosecond-level figure needs the 0.6 microbenchmark.

### B-8: timers

Not measured: the timing wheel ships with the reactor in 0.5 (decision D-063).

### B-13: system calls per echo round trip

Counted at net-io's own call sites by the fault-injection shim (`tests/shim.rs::test_system_calls_per_echo_round_trip`, run in CI on every platform):

| Platform | Target | Measured (blocking handler, sessions) |
|---|---|---|
| Linux (WSL2) | 2 | 2.00, 2.00 (one `recv`, one `send`) |
| Windows 11 | 3 | 3.00, 3.00 (`WSAPoll`, `recv`, `send`; D-052) |

### B-14: allocations per connection after warm-up

0 for the steady-state echo (`tests/alloc.rs`, a counting global allocator, 1,000 round trips on an established connection after 50 warm-up exchanges, Windows and Linux).

### Descriptor leak

100,000 connections through the sessions and blocking-handler servers, every one closed by the client with RST: no descriptor left over, and dropping the servers returns the process to its starting count (`NET_IO_LEAK_CONNECTIONS=100000 cargo test --release --test leak`, 43 s on WSL2).
