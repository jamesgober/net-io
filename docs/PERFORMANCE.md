# net-io - Performance

The targets and the method are in the project plan (section 9). This file records measured numbers, each with its commit, hardware, OS, and command line. Until 0.6 these are baselines: there is no competitor gate yet.

## 0.5.0: the reactor

Hardware as below. The machine was shared with other builds during these runs (load average 45 to 65 on 32 threads), so read ratios, not absolutes; `cargo bench --bench echo` also runs in CI as a job that does not gate, on a quiet runner.

### B-1: echo, 64 B, many connections

Eight client threads share the connections, so the load generator does not take the CPU from a reactor's fewer threads (one client thread per connection measures the scheduler). Medians of 7 runs.

| OS | Connections | Blocking pool | Reactor | Ratio |
|---|---|---|---|---|
| Windows 11 | 64 | 190,419 | 211,486 | 1.11x |
| Windows 11 | 256 | 172,058 | 281,037 | 1.63x |
| Linux (WSL2) | 64 | 185,617 | 47,332 | 0.25x |
| Linux (WSL2) | 256 | 122,049 | 25,838 | 0.21x |

Reading: Windows meets the 0.5 exit criterion. Linux does not, on this machine. CPU per round trip, client and server together: 11 us on the pool, 17 us on the reactor with 4 workers, 31 us with 32. The time goes to waking a worker: the pool's thread is woken synchronously, on the CPU of the thread that wrote, while epoll on this kernel (6.6) wakes without that hint, so the worker queues on a busy CPU behind the other builds and runs on a cold cache. Register R-20 holds the plan.

### B-2: echo, 64 B, one connection

| Stack | Linux (WSL2) | Windows 11 |
|---|---|---|
| std, thread per connection | 90,618 rt/s, p50 7.5 us | |
| blocking handler | 94,086 rt/s, p50 7.4 us | |
| sessions on the pool | 83,923 rt/s, p50 7.8 us | 26,479 rt/s, p50 29.7 us |
| sessions on the reactor | 81,662 rt/s, p50 8.5 us | 40,798 rt/s, p50 16.0 us |

Reading: on Linux the reactor adds 0.7 us per round trip, one `epoll_wait`. On Windows it is nearly twice the pool's rate, because the pool waits in `WSAPoll` before every receive (D-052).

### B-8: timers

`cargo test --release --lib bench_wheel -- --ignored --nocapture`, one million timers.

| Operation | Target | Linux (WSL2) | Windows 11 |
|---|---|---|---|
| insert | under 20 ns | 29.9 ns | 25.7 ns |
| lazy extend | under 2 ns | 4.7 ns | 3.9 ns |
| cancel | under 20 ns | 5.7 ns | 5.1 ns |

Insert and extend miss their targets (register R-21); a connection extends its one timer once per read, so neither shows in B-2.

### B-13: system calls per echo round trip, reactor

| Platform | Target | Measured |
|---|---|---|
| Linux (WSL2) | 3 | 3.00 (`epoll_wait`, `recv`, `send`) |
| macOS, FreeBSD (CI) | 3 | asserted at most 3 |
| Windows 11 | 3 | asserted at most 4: the zero-byte receive is one more (register R-22) |

### Idle connections

10,000 connections, `tests/idle.rs` (`NET_IO_IDLE_CONNECTIONS=10000`), live heap through a tracking allocator, kernel memory not counted: 1,730 bytes each on Linux, 1,840 on Windows, with no read buffer. That is the connection's state (848 bytes in the slab), its kill slot, its table entry, and on Windows its operation block.

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

### B-13: system calls per echo round trip

Counted at net-io's own call sites by the fault-injection shim (`tests/shim.rs::test_system_calls_per_echo_round_trip`, run in CI on every platform):

| Platform | Target | Measured (blocking handler, sessions) |
|---|---|---|
| Linux (WSL2) | 2 | 2.00, 2.00 (one `recv`, one `send`) |
| Windows 11 | 3 | 3.00, 3.00 (`WSAPoll`, `recv`, `send`; D-052) |
| macOS (CI) | 3 | asserted at most 3 (`poll`, `recv`, `send`; D-083) |

### B-14: allocations per connection after warm-up

0 for the steady-state echo (`tests/alloc.rs`, a counting global allocator, 1,000 round trips on an established connection after 50 warm-up exchanges, Windows and Linux).

### Descriptor leak

100,000 connections through the sessions and blocking-handler servers, every one closed by the client with RST: no descriptor left over, and dropping the servers returns the process to its starting count (`NET_IO_LEAK_CONNECTIONS=100000 cargo test --release --test leak`, 43 s on WSL2).
