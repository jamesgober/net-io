# net-io - Architecture

How the crate fits together, as of 0.5.0. Draft: it becomes final at 0.8. `docs/API.md` is the contract, and `dev/PLAN.md` holds the reasoning and the decision log.

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

1. **Accept.** One thread per listener accepts, on both drivers, because Windows must never associate a listener with a completion port (D-016) and one path is simpler than two. It runs the caps and the gate; a refused connection costs no worker.
2. **Hand-over.** The pool takes jobs from one bounded queue. The reactor picks the least-loaded worker and puts the job in that worker's bounded inbox, then wakes it. A full inbox refuses with `Busy`.
3. **Start.** The worker gives the connection a slab entry, registers it with its driver, and runs the PROXY and TLS handshakes as state machines on the loop.
4. **Exchange.** The session sees input and returns a `Step`; net-io reads, writes, and enforces deadlines around it. The same `Session` runs on both drivers.
5. **Close.** Exactly one `CloseReason`, one closed event, and one gate `close` per connection. The socket closes only after every operation on it came back.

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

An output keeps one free buffer between sends and gives the rest to the worker's pool the moment a send completes, so a session that moves its input to its output with `Input::swap` and `push_buffer` allocates nothing, however long it runs.

A connection has one timer, at its nearest deadline. Moving it is lazy: the wheel keeps the entry where it is and looks again when it fires, so an exchange costs one comparison. The clock is read once per trip through the OS, however many connections a turn touches.

Accepting takes one thread per listener, or with `ListenOptions::per_worker` on Linux one `SO_REUSEPORT` socket and thread per worker, each feeding its own worker. A file in an output travels as its own operation: `sendfile` on Unix, `TransmitFile` on IOCP, with the gate checking 1 MiB at a time. TLS, pipes, and Unix sockets read the file into buffers instead.

A UDP listener is a thread of its own, not a reactor worker. The thread owns the socket, so the amplification guard stays lock-free and a `UdpSession` needs no synchronization; the door, stop, and drain apply as they do on TCP.

## Ownership on Windows

An operation lives in a heap block that starts with its `OVERLAPPED` and owns its buffers. `Box::into_raw` gives the block to the kernel; the dequeued packet gives it back. A call that finishes at once in skip mode never leaves. Nothing else frees a block, so a cancelled receive cannot write into a reused buffer (T-18). `CancelIoEx` asks; the block comes back when the kernel says so, with a result or `Aborted`.

## Kill

A kill can come from any thread at any time. `KillSlot` keeps the connection's state word; its `KILLING` bit stops the owner from closing the socket while a kill makes a system call on it, so a kill never reaches a reused descriptor (D-053). On the pool the kill wakes the blocked thread (`shutdown` of the read side on Unix, the wake channel and `CancelIoEx` on Windows). On the reactor it puts the connection's index on the worker's list and wakes the loop.

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
