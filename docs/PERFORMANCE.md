# net-io - Performance

The targets and the method are in the project plan (section 9). This file records measured numbers, each with its commit, hardware, OS, and command line.

## 0.6.0: against other stacks

### Method

`compare/` is an unpublished crate (D-133). Every stack runs the same echo in its own process: `std` (a thread per connection), `mio`, `tokio` (multi-threaded runtime), `monoio` (io_uring), and net-io on both drivers, with the default limits, deadlines, and buffer wiping on. One load generator drives all of them: client threads, each with its share of the connections, each connection with one message in flight (closed loop). It reports round trips per second, latency percentiles, and server CPU per round trip from `/proc`. Each shape runs 3 s after a warm-up. CI runs it on every change (`Against other stacks`, not a gate) on GitHub's `ubuntu-latest`: 4 vCPUs, which the generator shares with the server. That host is small, and its speed varies from one run to the next (the same reactor B-1 bench gave 163,611 and 269,468 round trips per second on two runs a few hours apart), so compare stacks within one run, not runs with each other.

Closed loop measures capacity. Its p99 understates latency under overload (coordinated omission); an open-loop generator is register R-29.

### The table

Run 41537050560 (commit `421a22c`), round trips per second unless marked, ratio against tokio. The run before it (41526262144, commit `64c23d2`, a faster runner) is in brackets where it differs by 0.05x or more.

| Shape | std | mio | tokio | monoio | net-io pool | net-io reactor |
|---|---|---|---|---|---|---|
| B-1 accepts/s, connect and close | 0.88x | 1.24x | 12,884 | 1.28x | 1.13x | 1.07x |
| B-2 one connection, 64 B | 1.07x | 1.02x | 28,927 | 0.98x | 1.01x | 0.94x [1.01x] |
| B-3 100 connections, 64 B | 0.72x | 1.04x | 190,576 | 0.92x | 0.64x | 0.94x [1.04x] |
| B-3 1,000 connections, 64 B | 0.65x | 1.00x | 197,205 | 0.88x | 0.56x | 0.94x |
| B-3 10,000 connections, 64 B | | 1.03x | 127,194 | 0.85x | | 0.88x [0.98x] |
| B-4 1,000 connections, 16 KiB | 0.69x | 1.01x | 121,317 | 0.91x | 0.65x | 0.92x [0.87x] |

Server CPU per round trip in the same run, B-3 at 1,000 connections: tokio 11.4 us, mio 11.5, net-io 13.0, monoio 13.6. B-4: mio 18.2, tokio 18.8, net-io 22.3. Tail latency at 1,000 connections, p99 / p99.9: tokio 8.4 / 11.9 ms, net-io 11.2 / 13.7 ms.

Two variants of net-io run beside it, each changing one thing:

- `net-io-no-wipe` turns off zeroing of released buffers: B-4 0.96x, against 0.92x with wiping, so wiping costs about 4% at 16 KiB, which matches its measured cost (127 ns per 16 KiB buffer, `bench_wipe`). It stays on by default (threat T-1).
- `net-io-per-worker` uses `SO_REUSEPORT` listeners per worker (D-131): B-1 1.08x against 1.07x, no difference on this host. The likely reason, not yet tested, is that the generator's connects on the same four vCPUs set the rate, not the accept path.

On the build host (32 threads, loaded with other builds, so ratios only), B-4 after the fix below: 100 connections, net-io 572,862, tokio 251,476, mio 605,499, monoio 550,970, the pool 735,208; 1,000 connections, net-io 484,831, tokio 285,030, mio 579,834, monoio 444,120, the pool 829,993. With threads to spare the pool is fastest and the reactor is about 2x tokio; on four vCPUs shared with the client, the pool's thread per connection is the slowest.

Reading: on the CI host net-io's reactor is within 0.88x to 1.07x of tokio, and raw `mio`, an event loop with no limits, deadlines, gate, or wiping, is within 1.00x to 1.24x. The plan's gate of 1.2x the best competitor is not met on this harness, and could not be: the best competitor is `mio` itself, the same kind of event loop without the limits, deadlines, gate, and wiping net-io enforces. The gate decision is in `dev/ROADMAP.md`.

### The 16 KiB stall (D-134)

The first B-4 run gave 11,002 round trips per second, against 560,235 for the copying echo, and the rate did not grow with workers (24,241 on one, 25,130 on two). The echo moves its input buffer into the output (`push_buffer`). The output kept every buffer it was given and never handed one back, so each round trip took a fresh 16 KiB buffer from the allocator, with about five page faults, and the faults serialized in the kernel. An output now keeps one spare and gives the rest back to the worker's pool as each send completes. `tests/alloc.rs` now runs on every driver and on the moved-buffer path; before the fix it counted 1,005 allocations in 1,000 round trips.

### B-5 and B-6: idle connections

Connections that sent one message and went quiet, resident memory of the server process per connection after they settle, kernel socket memory not included (it is the same for every stack):

| Stack | 10,000 idle (CI) | Idle CPU |
|---|---|---|
| mio | 88 B | 0.0 ms/s |
| net-io reactor | 1,239 B | 0.0 ms/s |
| tokio | 8,993 B | 0.0 ms/s |
| monoio | 16,963 B | 0.0 ms/s |

`mio` keeps nothing per connection but the socket. net-io keeps its 848-byte connection state, a kill slot, and a table entry (register R-18). tokio and monoio keep a task and its buffer.

B-6, 100,000 idle on the build host (descriptor limit 300,000; CI's limit is 30,000, so CI skips it): net-io held 100,000 at 511 bytes each, with 20 ms of CPU per second while idle, on a host loaded with other builds; the cause is not yet measured (CI shows 0.0 at 10,000). The tokio echo in the same client stopped at 4,786 connections; that is not investigated, so no competitor row is given (register).

### Against 0.5.0

`cargo bench --bench echo` built from the `v0.5.0` tag and from the 0.6 branch, run alternately three times on the build host (load average 110 to 118, so throughput moves by up to 2x between runs; p50 latency is the stable figure). Medians of the three:

| Benchmark | 0.5.0 | 0.6.0 | Change |
|---|---|---|---|
| B-1 reactor, 64 connections | 55,894 rt/s, 30.8 us CPU | 58,106 rt/s, 28.9 us CPU | +4%, CPU -6% |
| B-1 reactor, 256 connections | 34,291 rt/s, 42.9 us CPU | 35,017 rt/s, 44.3 us CPU | +2%, CPU +3% |
| B-1 pool, 64 connections | 255,621 rt/s | 295,370 rt/s | +16% |
| B-2 blocking handler, p50 | 7.1 us | 6.9 us | -0.2 us |
| B-2 sessions on the reactor, p50 | 7.8 us | 7.7 us | -0.1 us |
| B-2 sessions on the pool, p50 | 7.0 us | 7.1 us | +0.1 us |

No benchmark regressed by more than 5%. The reactor's low rate against the pool on this host is register R-20.

### B-9 to B-12: the lifecycle

`cargo bench --bench lifecycle` (CI, run 41537050560; the earlier run in brackets).

| Benchmark | Target | Measured |
|---|---|---|
| B-9 PROXY v1, TCP4 | under 100 ns | 96.8 ns [86.8] |
| B-9 PROXY v2, IPv4, no TLVs | under 50 ns | 14.7 ns [18.3] |
| B-9 PROXY v2, 5 TLVs and CRC32C | under 300 ns | 219.0 ns [224.3] |
| B-10 post to wake, reactor, p50 / p99 | p99 under 10 us | 12.9 / 32.9 us [13.5 / 21.3] |
| B-11 kill to reset, reactor, p50 / p99 | p99 under 1 ms | 35.8 / 62.6 us [41.1 / 77.0] |
| B-11 floor: a plain close that resets | | 15.0 / 33.0 us |
| B-12 drain 10,000 idle connections | under 100 ms | 64.5 ms [98.5] |

B-10 misses: the post itself is a few nanoseconds, and the rest is one OS wake of a sleeping thread on a virtual machine, which the blocking driver pays too (12.3 / 25.8 us). Register.

### B-8: timers

| Operation | Target | CI, run 41537050560 | CI, run 41526262144 |
|---|---|---|---|
| insert | under 20 ns | 22.4 ns | 30.9 ns |
| lazy extend | under 2 ns | 3.9 ns | 2.6 ns |
| cancel | under 20 ns | 5.5 ns | 4.7 ns |

The 0.5 run met all three (17.0, 1.5, 2.3 ns). The code has not changed since; the spread is the host. Register R-21.

### B-13: system calls per echo round trip

Counted by the fault-injection shim on CI (`tests/shim.rs`).

| Platform | Target | Blocking handler | Reactor sessions | 16 KiB message |
|---|---|---|---|---|
| Linux | 2 / 3 | 2.00 | 3.00 | 4.00 |
| macOS | 3 / 3 | 3.00 | 3.00 (3.05 to 3.13 in 0.5; D-135 closes R-24) | 4.00 |
| Windows | 3 / 3 | 3.00 | 3.50 (4 in 0.5; register R-22) | 3.87 |

A 16 KiB message fills the read buffer, so readiness cannot say the socket is empty: one more receive finds it so.

### B-14: allocations

0 per round trip after warm-up on every driver, for the copying echo and the moved-buffer echo (`tests/alloc.rs`).

### Security costs, measured

| Measure | Cost |
|---|---|
| Wiping a released buffer (T-1) | 21.5 ns per 2 KiB, 127 ns per 16 KiB; about 4% of B-4 |
| Per-source table, acquire and release (T-16, T-22) | 342.8 ns on the loaded build host; an upper bound |
| Gate check per write (B-7) | below the noise of the benchmark (-708 ns difference, noise about 200 ns) |

## 0.5.0: the reactor

Two machines. The build host (hardware as below) was shared with other builds during these runs, load average 45 to 65 on 32 threads, so read its ratios, not its absolutes. GitHub's `ubuntu-latest` runner is small and quiet; `cargo bench --bench echo` runs there in CI on every change, as a job that does not gate.

### B-1: echo, 64 B, many connections

Eight client threads share the connections, so the load generator does not take the CPU from a reactor's fewer threads (one client thread per connection measures the scheduler). Medians of 7 runs.

| OS | Connections | Blocking pool | Reactor | Ratio |
|---|---|---|---|---|
| Windows 11 | 64 | 190,419 | 211,486 | 1.11x |
| Windows 11 | 256 | 172,058 | 281,037 | 1.63x |
| Linux (GitHub runner) | 64 | 211,353 | 244,417 | 1.16x |
| Linux (GitHub runner) | 256 | 218,828 | 262,033 | 1.20x |
| Linux (WSL2, loaded) | 64 | 185,617 | 47,332 | 0.25x |
| Linux (WSL2, loaded) | 256 | 122,049 | 25,838 | 0.21x |

Reading: the reactor is ahead on Windows and on a quiet Linux host, where it also spends less CPU per round trip, client and server together: 15 us against 18 at 64 connections. On the loaded host it was far behind, at 31 us against 11 with 32 workers, and 17 us with 4. The likely cause is waking a worker: the pool's thread wakes on the CPU of the thread that wrote, while epoll on that kernel (6.6) has no such hint, so the worker queues on a CPU busy with other work and runs on a cold cache. That is a hypothesis; register R-20 holds the way to test it.

### B-2: echo, 64 B, one connection

| Stack | Linux (WSL2) | Windows 11 |
|---|---|---|
| std, thread per connection | 90,618 rt/s, p50 7.5 us | |
| blocking handler | 94,086 rt/s, p50 7.4 us | |
| sessions on the pool | 83,923 rt/s, p50 7.8 us | 26,479 rt/s, p50 29.7 us |
| sessions on the reactor | 81,662 rt/s, p50 8.5 us | 40,798 rt/s, p50 16.0 us |

On the GitHub runner: pool 45,218 rt/s (p50 21.5 us), reactor 43,670 rt/s (p50 22.5 us).

Reading: on Linux the reactor adds about 1 us per round trip, one `epoll_wait`. On Windows it is nearly twice the pool's rate, because the pool waits in `WSAPoll` before every receive (D-052).

### B-8: timers

`cargo test --release --lib bench_wheel -- --ignored --nocapture`, one million timers.

| Operation | Target | GitHub runner | Linux (WSL2, loaded) | Windows 11 (loaded) |
|---|---|---|---|---|
| insert | under 20 ns | 17.0 ns | 29.9 ns | 25.7 ns |
| lazy extend | under 2 ns | 1.5 ns | 4.7 ns | 3.9 ns |
| cancel | under 20 ns | 2.3 ns | 5.7 ns | 5.1 ns |

### B-13: system calls per echo round trip, reactor

| Platform | Target | Measured |
|---|---|---|
| Linux (WSL2) | 3 | 3.00 (`epoll_wait`, `recv`, `send`) |
| macOS (CI) | 3 | 3.05: the write filter fires now and then after an ACK (register R-24) |
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
