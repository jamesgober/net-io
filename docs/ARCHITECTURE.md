# net-io - Architecture

How the crate fits together, as of 0.8.0. It is checked again for 1.0. `docs/API.md` is the contract, and `dev/PLAN.md` holds the reasoning and the decision log.

## Layers

| Layer | Files | What it does |
|---|---|---|
| OS surface | `src/sys/` | Every `unsafe` block in the crate: socket calls `std` does not expose, epoll, kqueue, IOCP, named pipes, the kill guard, the fault-injection shim |
| Connection core | `src/link.rs` | One connection whatever its transport: limits, deadlines, rate checks, the gate, TLS, the close sequence |
| Drivers | `src/driver/` | The completion-shaped `Driver` interface; `ready.rs` adapts epoll and kqueue, `iocp.rs` is the Windows backend |
| Server | `src/server/` | Listeners, admission, the blocking pool (`engine.rs`), the reactor (`reactor.rs`), drain, kill, the control line |
| Connections you hold | `src/tcp.rs`, `src/local.rs`, `src/local_windows.rs`, `src/pipe.rs`, `src/udp.rs` | Public wrappers around the core |
| Sessions and pure logic | `src/session.rs`, `src/proxy_parse.rs`, `src/wheel.rs`, `src/rate.rs`, `src/limits.rs`, `src/buf.rs` | No IO; most run under Miri |

## A connection's path

1. **Accept.** One thread per listener accepts, on both drivers, because Windows must never associate a listener with a completion port (D-016) and one path is simpler than two. It runs the caps, the lockdown, the gate, the lane reserve, and the shed, in that order; a refused connection costs no worker, and it is counted before the peer can see the refusal (D-199). A listener with `ListenOptions::per_worker` on the Linux reactor has no accept thread: each worker accepts on its own socket of a `SO_REUSEPORT` group in its own event loop, through the same admission code (D-197).
2. **Hand-over.** The pool takes jobs from one bounded queue. The reactor picks the least-loaded worker in the listener's range (its own workers with `ListenerSpec::workers`, D-186, the shared ones otherwise), scanning from a start that moves on by one each connection and stopping at the first idle worker (D-174), puts the job in that worker's bounded inbox (4,096), and wakes it. A full inbox refuses with `Busy`. A worker that accepted for itself takes its inbox in the same turn, with no wake.
3. **Start.** The worker gives the connection a slab entry, registers it with its driver, and runs the PROXY and TLS handshakes as state machines on the loop.
4. **Exchange.** The session sees input and returns a `Step`; net-io reads, writes, and enforces deadlines around it. The same `Session` runs on both drivers.
5. **Close.** Exactly one `CloseReason`, one closed event, and one gate `close` per connection. The socket closes only after every operation on it came back.

A close takes one of three shapes:

| Shape | When | On the wire |
|---|---|---|
| Graceful | `Step::Close`, a drain, an idle timeout between exchanges | queued bytes, `close_notify` on TLS, FIN; then a linger that reads and discards input for up to 2 s and 64 KiB, only when input may still arrive (mid-exchange, the socket readable, or the session wrote while idle with no request to answer, D-192, D-201). Without a linger the reactor closes at once and the kernel sends the FIN behind what is queued (D-198) |
| Flush then close | a denial whose bytes went out, `ServerHandle::close_after_flush` | no more input, queued bytes, FIN, reads discarded until the peer's EOF or `Limits::denial_linger` (D-182) |
| Abortive | a kill, a timeout mid-exchange, a refusal without bytes | RST (linger 0) |

A drain closes a connection between exchanges only when nothing waits in its socket, after `Session::on_drain` (D-183) and outside `Limits::first_request_grace` of its accept (D-189). The owner decides at its own wait, reached through its wake channel (D-178), so a request that already arrived is read and answered first. The drain is not over while an accept is between its door check and its hand-over (D-179).

## The reactor

Each worker owns its driver, a slab of connections, a timing wheel, a buffer pool, and pools of outputs and kill slots. Nothing on the data path is shared between workers: a worker borrows the shared state rather than holding a reference count, per-worker state sits on cache lines of its own, and a worker writes to shared state only when a connection opens or closes.

```text
loop:
    inbox, commands, kills, posted completions, expired timers
    wait on the driver (the OS, up to the next timer)
    for each completion: run the connection's state machine
    repeat for what finished at once, up to 16 rounds, without the OS
```

The driver is the reactor's real interface (D-005). On epoll and kqueue, `ReadyDriver` remembers readiness per direction, because the OS reports edges, and makes the call as soon as it can; a send tries first, since a socket is nearly always writable. On Windows the operation goes to the kernel. Either way the reactor sees one completion per operation, carrying the buffers back.

An idle connection holds no buffer. It waits with `ReceiveZero`; when that completes the worker takes a pool buffer and receives. When the session consumed everything, the buffer goes back. A connection whose read finds the buffer budget spent pauses on a list, oldest first, and TCP pushes back on its peer.

An output keeps up to four spare buffers between sends, so a session that moves its input to its output with `Input::swap` and `push_buffer` allocates nothing, however long it runs; it takes the buffers its worker's pool already holds before it charges the budget (D-169). When a connection goes idle its spares go back to the pool (D-164).

A TLS connection keeps two more buffers, the engine's ciphertext in and out (64 KiB each by default). Idle between exchanges with nothing in them, it gives both back along with its input and output and waits with a zero-byte receive as a plaintext connection does (D-181, D-200); it takes a pair again when bytes arrive, before a flush, and before a graceful close so `close_notify` can go out. The records the engine writes as its handshake ends (the tickets) wait at the front of the output when the client's request is already in, and leave with the first reply; a reply before `Step::Close` carries `close_notify` in the same buffer, so a full exchange with a closing reply is two sends (D-194).

A connection has one timer, at its nearest deadline. Moving it is lazy: the wheel keeps the entry where it is and looks again when it fires, so an exchange costs one comparison. The clock is read once per trip through the OS, however many connections a turn touches.

Accepting takes one thread per listener. A per-worker group (Linux) is part of the loop instead: the worker arms `Operation::Accept` on its own socket while no connection waits, accepts up to `accept_batch` when it fires, and queues a `Nop` to come back for the rest, so a backlog cannot hold the worker past one batch a round. A closed door or a drain parks the socket, looked at each turn; descriptor pressure pauses it until a deadline the wait honours. Listeners added or removed at run time move an epoch the workers compare each turn, and `remove_listener` returns only when every worker has dropped its socket (D-197). A file in an output travels as its own operation: `sendfile` on Unix, `TransmitFile` on IOCP, with the gate checking 1 MiB at a time. TLS, pipes, and Unix sockets read the file into buffers instead.

A UDP listener is a thread of its own, not a reactor worker. The thread owns the socket, so the amplification guard stays lock-free and a `UdpSession` needs no synchronization; the door, stop, and drain apply as they do on TCP.

## Ownership on Windows

An operation lives in a heap block that starts with its `OVERLAPPED` and owns its buffers. `Box::into_raw` gives the block to the kernel; the dequeued packet gives it back. A call that finishes at once in skip mode never leaves. Nothing else frees a block, so a cancelled receive cannot write into a reused buffer (T-18). `CancelIoEx` asks; the block comes back when the kernel says so, with a result or `Aborted`.

## Kill

A kill can come from any thread at any time. `close_after_flush` is a soft kill: a `SOFT` bit beside `KILLED` ends reads and lets queued sends go on until its bound, then closes as a flush then close; a `kill` afterwards upgrades it to a reset (D-182).

`KillSlot` keeps the connection's state word; its `KILLING` bit stops the owner from closing the socket while a kill makes a system call on it, so a kill never reaches a reused descriptor (D-053). On the pool the kill wakes the blocked thread (`shutdown` of the read side on Unix, the wake channel and `CancelIoEx` on Windows). On the reactor it puts the connection's index on the worker's list and wakes the loop.

## Named pipes

A pipe has no readiness, so `PipeStream` gives the core what it expects from a non-blocking socket: overlapped reads and writes against an internal buffer, `WouldBlock` while the kernel holds it, and a wait on the operation's event and the wake channel's. On the reactor those buffers never exist: the completion port reads and writes directly, with the same `Op` blocks as a socket.

## Testing

| Tool | What it covers |
|---|---|
| The shim (`net_io_shim`) | Injects faults at each `sys` call site and counts system calls |
| `net_io_force_blocking` | Runs every suite on the blocking pool, now that `Auto` means the reactor |
| Loom, Miri | The kill guard; the pure modules |
| AddressSanitizer, ThreadSanitizer | The session and driver suites on Linux |
| Fuzzing | Every parser of untrusted bytes |
| Cross-process tests | Hand-off under load, systemd activation, FastCGI descriptor 0 |
| Soak (`tests/soak.rs`) | Normal, pooled, and hostile peers for 24 hours per driver before each release, sampling memory, handles, and connections (D-162); on macOS and FreeBSD a reset the client's stack dropped is counted, not failed (D-193) |
| `tests/accept_on_worker.rs` | Per-worker accept: no accept threads, the door, run-time add and remove, the control line, a dropped server (D-197) |
