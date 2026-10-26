//! Edge cases from the plan's appendix A that apply to TCP and the blocking driver.
//! Each test names its case numbers; `dev/EDGE-CASES.md` maps every case to its test.

mod common;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use common::{addr, client, closed_by_server, eventually, round_trip};
use net_io::{
    AdmitStage, Admitted, AllowAll, CloseReason, ConnectionId, ConnectionInfo, ControlState,
    Denial, DriverKind, Gate, GateTag, Input, KillReason, Lane, Limits, ListenOptions,
    ListenerSpec, NetError, Output, Phase, PostError, Refusal, ServerBuilder, ServerHandle,
    Session, SessionContext, SimpleControl, SizeClass, Step, TcpConnection, WriteCheck,
};

const WAIT: Duration = Duration::from_secs(5);

fn limits(f: impl FnOnce(net_io::LimitsBuilder) -> net_io::LimitsBuilder) -> Limits {
    f(Limits::builder()).build().expect("limits")
}

/// Echoes complete lines; a partial line keeps the exchange open.
struct Lines;

impl Session for Lines {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let Some(end) = input.bytes().iter().position(|&b| b == b'\n') else {
            cx.set_phase(Phase::Receiving);
            return Step::Read;
        };
        let taken = cx.output().push_partial(&input.bytes()[..=end]);
        input.consume(taken);
        if taken == end + 1 {
            cx.set_phase(Phase::Idle);
        }
        Step::Write
    }
}

/// Tests run in parallel: small pools keep the process's socket count low.
/// A `Lines` factory whose sessions report their first bytes.
fn signalled_lines() -> (
    impl Fn(&ConnectionInfo) -> Signalled + Send + Sync + 'static,
    mpsc::Receiver<()>,
) {
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    (
        move |_: &ConnectionInfo| Signalled(tx.lock().ok().map(|t| t.clone())),
        rx,
    )
}

/// `Lines` that sends one signal on its first bytes.
struct Signalled(Option<mpsc::Sender<()>>);

impl Session for Signalled {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let step = Lines.on_data(cx, input);
        if let Some(tx) = self.0.take() {
            let _ = tx.send(());
        }
        step
    }
}

/// `serve_sessions` with 4 workers: tests run in parallel, and on Windows every
/// worker's wake channel holds a loopback port.
fn small_sessions<F: net_io::SessionFactory>(factory: F) -> Result<net_io::Server, NetError> {
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .workers(4)
        .sessions(factory)
        .gate(AllowAll)
        .build()?;
    server.open_door()?;
    Ok(server)
}

/// `serve` with 4 workers (see `small_sessions`).
fn small_blocking<H>(handler: H) -> Result<net_io::Server, NetError>
where
    H: Fn(&mut TcpConnection) -> Result<(), NetError> + Send + Sync + 'static,
{
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .workers(4)
        .handler(handler)
        .gate(AllowAll)
        .build()?;
    server.open_door()?;
    Ok(server)
}

/// Tests run in parallel: small pools keep the process's socket count low.
fn lines_server() -> net_io::Server {
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .workers(4)
        .sessions(|_: &ConnectionInfo| Lines)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    server
}

/// A session built from closures, so each test states only what it needs.
struct Custom<D, C> {
    data: D,
    peer_closed: C,
}

impl<D, C> Session for Custom<D, C>
where
    D: FnMut(&mut SessionContext<'_>, &mut Input) -> Step + Send + 'static,
    C: FnMut(&mut SessionContext<'_>) -> Step + Send + 'static,
{
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        (self.data)(cx, input)
    }
    fn on_peer_closed(&mut self, cx: &mut SessionContext<'_>) -> Step {
        (self.peer_closed)(cx)
    }
}

// ---- reads -------------------------------------------------------------------

#[test]
fn edge_01_eof_in_idle_is_peer_closed() {
    let server = lines_server();
    let c = client(addr(&server));
    drop(c);
    assert!(
        eventually(WAIT, || server.stats().closed_for(CloseReason::PeerClosed)
            == 1),
        "{:?}",
        server.stats()
    );
}

#[test]
fn edge_02_37_eof_mid_request_reaches_the_session_which_may_still_write() {
    // The peer half-closes in the middle of a line; the session answers and closes.
    let server = small_sessions(|_: &ConnectionInfo| Custom {
        data: |cx: &mut SessionContext<'_>, input: &mut Input| {
            cx.set_phase(Phase::Receiving);
            let n = input.bytes().len();
            input.consume(n);
            Step::Read
        },
        peer_closed: |cx: &mut SessionContext<'_>| {
            let _ = cx.output().push(b"truncated\n");
            Step::Close
        },
    })
    .expect("serve");
    let mut c = client(addr(&server));
    c.write_all(b"half a req").expect("write");
    c.shutdown(Shutdown::Write).expect("half-close");
    let mut reply = String::new();
    c.read_to_string(&mut reply).expect("read");
    assert_eq!(reply, "truncated\n");
}

#[test]
fn edge_03_partial_reads_at_every_split() {
    let server = lines_server();
    let request = b"a request line of some length\n";
    for split in 1..request.len() {
        let mut c = client(addr(&server));
        c.write_all(&request[..split]).expect("write");
        c.flush().expect("flush");
        std::thread::sleep(Duration::from_millis(2));
        c.write_all(&request[split..]).expect("write");
        let mut back = vec![0u8; request.len()];
        c.read_exact(&mut back).expect("read");
        assert_eq!(&back, request, "split at {split}");
    }
}

#[test]
fn edge_04_full_buffer_with_nothing_consumed_is_a_limit_not_a_spin() {
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .limits(limits(|b| b.read_class(SizeClass::SMALL, SizeClass::SMALL)))
        .sessions(|_: &ConnectionInfo| Lines)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let mut c = client(addr(&server));
    let _ = c.write_all(&[b'x'; 8192]);
    assert!(closed_by_server(&mut c));
    assert!(eventually(WAIT, || {
        server
            .stats()
            .closed_for(CloseReason::Limit(net_io::LimitKind::ReadBuffer))
            == 1
    }));
}

#[test]
fn edge_07_33_peer_reset_is_peer_reset() {
    let server = lines_server();
    let a = addr(&server);
    let mut conn = net_io::connect(a).expect("connect");
    conn.send_all(b"partial").expect("send");
    std::thread::sleep(Duration::from_millis(50));
    conn.abort();
    assert!(eventually(WAIT, || server
        .stats()
        .closed_for(CloseReason::PeerReset)
        == 1));
}

#[test]
fn edge_10_bytes_sent_while_parked_are_read_after_the_wake() {
    let (tx, rx) = mpsc::channel::<(net_io::Completer, ConnectionId)>();
    let tx = Mutex::new(tx);
    struct Parker {
        tx: Option<mpsc::Sender<(net_io::Completer, ConnectionId)>>,
        waited: bool,
    }
    impl Session for Parker {
        fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
            if !self.waited {
                if let Some(tx) = self.tx.take() {
                    let _ = tx.send((cx.completer(), cx.info().id));
                }
                return Step::Park { until: None };
            }
            let taken = cx.output().push_partial(input.bytes());
            input.consume(taken);
            Step::Write
        }
        fn on_wake(&mut self, cx: &mut SessionContext<'_>, token: u32, value: u64) -> Step {
            self.waited = true;
            let _ = cx
                .output()
                .push(format!("woken {token} {value}:").as_bytes());
            Step::Write
        }
    }
    let server = small_sessions(move |_: &ConnectionInfo| Parker {
        tx: tx.lock().ok().map(|t| t.clone()),
        waited: false,
    })
    .expect("serve");
    let mut c = client(addr(&server));
    c.write_all(b"first").expect("write");
    let (completer, id) = rx.recv_timeout(WAIT).expect("parked");
    c.write_all(b"second").expect("write");
    std::thread::sleep(Duration::from_millis(50));
    completer.post(id, 7, 42).expect("post");
    // The wake reply, then the echo of everything that waited in the kernel.
    let mut got = Vec::new();
    let want = b"woken 7 42:firstsecond";
    let end = Instant::now() + WAIT;
    while got.len() < want.len() && Instant::now() < end {
        let mut buf = [0u8; 64];
        let n = c.read(&mut buf).expect("read");
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(&got, want);
    // Edge case 131: a post for a connection that is not this worker's is refused, never delivered elsewhere.
    drop(c);
    assert!(eventually(WAIT, || server.stats().closed == 1));
    assert_eq!(completer.post(id, 1, 1), Err(PostError::WrongWorker));
}

#[test]
fn edge_12_zero_length_receive_returns_at_once() {
    let listener = net_io::listen("127.0.0.1:0").expect("listen");
    let a = listener.local_addr().expect("addr");
    let _peer = std::thread::spawn(move || {
        let s = TcpStream::connect(a).expect("connect");
        std::thread::sleep(Duration::from_millis(500));
        drop(s);
    });
    let (mut conn, _info) = listener.accept().expect("accept");
    let start = Instant::now();
    assert_eq!(conn.recv(&mut []).expect("recv"), 0);
    assert!(
        start.elapsed() < Duration::from_millis(100),
        "no wait for data"
    );
}

// ---- writes ------------------------------------------------------------------

/// Answers any byte with `total` bytes of `b'r'`, as one response.
struct Respond {
    total: usize,
    sent: usize,
}

static R_BLOCK: [u8; 64 * 1024] = [b'r'; 64 * 1024];

impl Respond {
    fn fill(&mut self, cx: &mut SessionContext<'_>) -> Step {
        while self.sent < self.total {
            let n = (self.total - self.sent).min(R_BLOCK.len());
            if cx.output().push_static(&R_BLOCK[..n]).is_err() {
                break;
            }
            self.sent += n;
        }
        if self.sent >= self.total {
            cx.output().end_response();
            return Step::Close;
        }
        Step::Write
    }
}

impl Session for Respond {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let n = input.bytes().len();
        input.consume(n);
        if self.sent == 0 {
            cx.output().begin_response();
        }
        self.fill(cx)
    }
    fn on_writable(&mut self, cx: &mut SessionContext<'_>) -> Step {
        self.fill(cx)
    }
    fn on_peer_closed(&mut self, cx: &mut SessionContext<'_>) -> Step {
        // Edge case 32: the peer's FIN does not stop a response in progress.
        if self.sent > 0 && self.sent < self.total {
            return self.fill(cx);
        }
        Step::Close
    }
    fn on_denied(&mut self, code: u16, output: &mut Output) {
        let _ = output.push(format!("denied {code}\n").as_bytes());
    }
}

/// A gate that counts checks and denies from the `deny_from`-th check on.
struct Counting {
    checks: Arc<AtomicU32>,
    deny_from: u32,
}

impl Gate for Counting {
    type Ticket = ();
    fn admit(&self, _info: &ConnectionInfo, _stage: AdmitStage) -> Result<Admitted<()>, Refusal> {
        Ok(Admitted {
            lane: Lane(0),
            ticket: (),
            tag: GateTag(0),
        })
    }
    fn readmit(&self, _ticket: &mut (), _info: &ConnectionInfo) -> Result<(), Refusal> {
        Ok(())
    }
    fn check(&self, _ticket: &mut (), _write: &WriteCheck) -> Result<(), Denial> {
        let n = self.checks.fetch_add(1, Ordering::SeqCst) + 1;
        if n >= self.deny_from {
            return Err(Denial { code: 9 });
        }
        Ok(())
    }
}

fn respond_server(
    total: usize,
    deny_from: u32,
    send_buffer: Option<u32>,
) -> (net_io::Server, Arc<AtomicU32>) {
    let checks = Arc::new(AtomicU32::new(0));
    let mut options = ListenOptions::new();
    if let Some(b) = send_buffer {
        options = options.send_buffer(b);
    }
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp_with("127.0.0.1:0", options))
        .sessions(move |_: &ConnectionInfo| Respond { total, sent: 0 })
        .gate(Counting {
            checks: checks.clone(),
            deny_from,
        })
        .build()
        .expect("build");
    server.open_door().expect("open");
    (server, checks)
}

#[test]
fn edge_25_32_large_response_after_peer_fin_uses_several_checked_sends() {
    let total = 8 << 20;
    let (server, checks) = respond_server(total, u32::MAX, Some(64 * 1024));
    let mut c = client(addr(&server));
    c.write_all(b"go").expect("write");
    c.shutdown(Shutdown::Write).expect("half-close");
    let mut got = Vec::with_capacity(total);
    c.read_to_end(&mut got).expect("read");
    assert_eq!(got.len(), total, "the whole response arrives after our FIN");
    assert!(
        checks.load(Ordering::SeqCst) >= 2,
        "one gate check per system call"
    );
}

#[test]
fn edge_27_28_denial_before_the_first_byte_is_written_once() {
    let (server, checks) = respond_server(1000, 1, None);
    let mut c = client(addr(&server));
    c.write_all(b"go").expect("write");
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    assert_eq!(got, b"denied 9\n");
    assert_eq!(
        checks.load(Ordering::SeqCst),
        1,
        "the denial itself is not checked"
    );
    assert!(eventually(WAIT, || server
        .stats()
        .closed_for(CloseReason::EgressDenied(0))
        == 1));
    assert_eq!(server.stats().egress_denied, 1);
}

#[test]
fn edge_26_denial_inside_a_response_resets_without_a_denial() {
    let total = 16 << 20;
    let (server, _checks) = respond_server(total, 2, Some(64 * 1024));
    let mut c = client(addr(&server));
    c.write_all(b"go").expect("write");
    std::thread::sleep(Duration::from_millis(100));
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    assert!(got.len() < total, "the response was cut");
    assert!(
        got.iter().all(|&b| b == b'r'),
        "no denial bytes after a started response"
    );
    assert!(eventually(WAIT, || server
        .stats()
        .closed_for(CloseReason::EgressDenied(0))
        == 1));
}

#[test]
fn edge_21_22_peer_gone_mid_write_is_peer_reset_without_a_signal() {
    let (server, _checks) = respond_server(64 << 20, u32::MAX, Some(64 * 1024));
    let mut c = client(addr(&server));
    c.write_all(b"go").expect("write");
    let mut some = [0u8; 4096];
    c.read_exact(&mut some).expect("read");
    drop(c);
    // On Linux a SIGPIPE would end this process; sends use MSG_NOSIGNAL.
    assert!(eventually(WAIT, || server
        .stats()
        .closed_for(CloseReason::PeerReset)
        == 1));
}

// ---- close -------------------------------------------------------------------

#[test]
fn edge_34_close_with_unread_input_lingers_so_the_reply_arrives() {
    let server = small_sessions(|_: &ConnectionInfo| Custom {
        data: |cx: &mut SessionContext<'_>, input: &mut Input| {
            // Answer the first line and close without reading the rest.
            if input.bytes().contains(&b'\n') {
                let _ = cx.output().push(b"bye\n");
                return Step::Close;
            }
            Step::Read
        },
        peer_closed: |_cx: &mut SessionContext<'_>| Step::Close,
    })
    .expect("serve");
    let mut c = client(addr(&server));
    let mut req = b"first\n".to_vec();
    req.extend_from_slice(&[b'x'; 32 * 1024]);
    c.write_all(&req).expect("write");
    let mut reply = [0u8; 4];
    c.read_exact(&mut reply)
        .expect("the reply is not destroyed by a reset");
    assert_eq!(&reply, b"bye\n");
}

#[test]
fn edge_35_abort_sends_a_reset() {
    let server = small_blocking(|conn: &mut TcpConnection| {
        let mut b = [0u8; 8];
        let _ = conn.recv(&mut b)?;
        Err(NetError::Closed)
    })
    .expect("serve");
    let mut c = client(addr(&server));
    c.write_all(b"x").expect("write");
    let mut b = [0u8; 8];
    let r = c.read(&mut b);
    assert!(
        matches!(&r, Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset),
        "an abortive close is a reset: {r:?}"
    );
}

#[test]
fn edge_36_kill_during_the_linger_closes_at_once() {
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let server = small_sessions(move |_: &ConnectionInfo| {
        let tx = tx.lock().ok().map(|t| t.clone());
        Custom {
            data: move |cx: &mut SessionContext<'_>, _input: &mut Input| {
                if let Some(tx) = &tx {
                    let _ = tx.send(cx.info().id);
                }
                Step::Close
            },
            peer_closed: |_cx: &mut SessionContext<'_>| Step::Close,
        }
    })
    .expect("serve");
    let mut c = client(addr(&server));
    // Unread input, and no FIN: the graceful close lingers.
    c.write_all(&[b'x'; 1024]).expect("write");
    let id = rx.recv_timeout(WAIT).expect("id");
    std::thread::sleep(Duration::from_millis(100));
    let start = Instant::now();
    assert!(server.handle().kill(id, KillReason(3)));
    assert!(eventually(WAIT, || server.stats().closed == 1));
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "the linger did not hold the kill"
    );
    assert_eq!(server.stats().killed, 1);
}

#[test]
fn edge_38_39_shutdown_twice_and_close_after_the_peer_closed() {
    let listener = net_io::listen("127.0.0.1:0").expect("listen");
    let a = listener.local_addr().expect("addr");
    let peer = std::thread::spawn(move || {
        let mut s = TcpStream::connect(a).expect("connect");
        let mut b = Vec::new();
        let _ = s.read_to_end(&mut b);
    });
    let (mut conn, _info) = listener.accept().expect("accept");
    conn.shutdown(Shutdown::Write).expect("first");
    conn.shutdown(Shutdown::Write).expect("second is a no-op");
    peer.join().expect("peer");
    let mut b = [0u8; 4];
    assert_eq!(conn.recv(&mut b).expect("eof"), 0);
    conn.close().expect("close after the peer closed");
}

// ---- accept ------------------------------------------------------------------

#[test]
fn edge_48_burst_in_the_backlog_does_not_stall_open_connections() {
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp_with(
            "127.0.0.1:0",
            ListenOptions::new().backlog(1024),
        ))
        .workers(4)
        .limits(limits(|b| b.idle_timeout(Duration::from_secs(60))))
        .sessions(|_: &ConnectionInfo| Lines)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let mut steady = client(addr(&server));
    assert_eq!(round_trip(&mut steady, b"before\n"), b"before\n");
    server.close_door();
    let a = addr(&server);
    let started = Instant::now();
    // Below macOS's default `kern.ipc.somaxconn` (128): connects beyond the backlog
    // stall in SYN retries instead of queueing.
    let burst: Vec<_> = (0..100)
        .filter_map(|_| TcpStream::connect(a).ok())
        .collect();
    eprintln!(
        "{} connects into the backlog took {:?}",
        burst.len(),
        started.elapsed()
    );
    server.open_door().expect("open");
    let start = Instant::now();
    assert_eq!(round_trip(&mut steady, b"during\n"), b"during\n");
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "IO waited for the accept burst"
    );
    let n = burst.len() as u64;
    assert!(eventually(WAIT, || {
        let s = server.stats();
        s.accepted + s.refused > n
    }));
}

#[test]
fn edge_49_backlog_is_reset_by_shutdown() {
    let server = lines_server();
    server.close_door();
    let mut waiting: Vec<_> = (0..20).map(|_| client(addr(&server))).collect();
    let _ = server.shutdown(Instant::now());
    for c in &mut waiting {
        assert!(closed_by_server(c));
    }
}

#[test]
fn edge_51_mapped_peer_is_normalized_before_the_gate() {
    let seen = Arc::new(Mutex::new(None));
    struct Record(Arc<Mutex<Option<std::net::SocketAddr>>>);
    impl Gate for Record {
        type Ticket = ();
        fn admit(
            &self,
            info: &ConnectionInfo,
            _stage: AdmitStage,
        ) -> Result<Admitted<()>, Refusal> {
            if let Ok(mut s) = self.0.lock() {
                *s = info.client_addr();
            }
            Ok(Admitted {
                lane: Lane(0),
                ticket: (),
                tag: GateTag(0),
            })
        }
        fn readmit(&self, _t: &mut (), _i: &ConnectionInfo) -> Result<(), Refusal> {
            Ok(())
        }
        fn check(&self, _t: &mut (), _w: &WriteCheck) -> Result<(), Denial> {
            Ok(())
        }
    }
    let built = ServerBuilder::new()
        .listener(ListenerSpec::tcp_with(
            "[::]:0",
            ListenOptions::new().ipv6_only(false),
        ))
        .sessions(|_: &ConnectionInfo| Lines)
        .gate(Record(seen.clone()))
        .build();
    let Ok(server) = built else {
        return; // No IPv6 on this host.
    };
    server.open_door().expect("open");
    let port = addr(&server).port();
    let mut c = client(std::net::SocketAddr::from(([127, 0, 0, 1], port)));
    assert_eq!(round_trip(&mut c, b"hi\n"), b"hi\n");
    let peer = seen.lock().expect("lock").expect("admitted");
    assert!(peer.is_ipv4(), "mapped address normalized: {peer}");
}

// ---- server lifecycle ----------------------------------------------------------

#[test]
fn edge_106_107_door_calls_are_idempotent() {
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .sessions(|_: &ConnectionInfo| Lines)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.close_door();
    server.open_door().expect("open");
    server.open_door().expect("second open is a no-op");
    let mut c = client(addr(&server));
    assert_eq!(round_trip(&mut c, b"ok\n"), b"ok\n");
}

#[test]
fn edge_108_drain_with_nothing_open_returns_at_once() {
    let server = lines_server();
    let start = Instant::now();
    let report = server.drain(Instant::now() + Duration::from_secs(10));
    assert!(start.elapsed() < Duration::from_millis(500));
    assert_eq!((report.graceful, report.killed), (0, 0));
}

#[test]
fn edge_109_drain_deadline_in_the_past_kills_at_once() {
    let (factory, seen) = signalled_lines();
    let server = small_sessions(factory).expect("serve");
    let mut c = client(addr(&server));
    c.write_all(b"no newline yet").expect("write");
    seen.recv_timeout(WAIT).expect("read by the session");
    let report = server.shutdown(Instant::now() - Duration::from_secs(1));
    // The drain itself; joining the worker threads afterwards is not part of it.
    assert!(
        report.took < Duration::from_millis(500),
        "{:?}",
        report.took
    );
    assert_eq!(report.killed, 1);
}

#[test]
fn edge_110_request_stop_from_a_session_is_safe() {
    let handle: Arc<OnceLock<ServerHandle>> = Arc::new(OnceLock::new());
    let h = handle.clone();
    let server = small_sessions(move |_: &ConnectionInfo| {
        let h = h.clone();
        Custom {
            data: move |_cx: &mut SessionContext<'_>, _input: &mut Input| {
                if let Some(h) = h.get() {
                    h.request_stop();
                }
                Step::Close
            },
            peer_closed: |_cx: &mut SessionContext<'_>| Step::Close,
        }
    })
    .expect("serve");
    let _ = handle.set(server.handle());
    let mut c = client(addr(&server));
    c.write_all(b"stop").expect("write");
    let report = server.wait_for_stop();
    assert!(report.graceful + report.killed <= 1);
}

#[test]
fn edge_113_kill_with_a_foreign_or_closed_id_is_false() {
    let a = lines_server();
    let b = lines_server();
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let server = small_blocking(move |conn: &mut TcpConnection| {
        let _ = tx.lock().map(|t| t.send(conn.id()));
        Ok(())
    })
    .expect("serve");
    let _c = client(addr(&server));
    let id = rx.recv_timeout(WAIT).expect("id");
    assert!(eventually(WAIT, || server.stats().closed == 1));
    assert!(!server.handle().kill(id, KillReason(1)), "closed");
    assert!(!a.handle().kill(id, KillReason(1)), "another server");
    drop(b);
}

#[test]
fn edge_115_draining_without_a_deadline_uses_the_drain_timeout() {
    let (factory, seen) = signalled_lines();
    let line = Arc::new(SimpleControl::new());
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .limits(limits(|b| b.drain_timeout(Duration::from_millis(300))))
        .sessions(factory)
        .gate(AllowAll)
        .control(line.clone())
        .build()
        .expect("build");
    server.open_door().expect("open");
    let mut c = client(addr(&server));
    c.write_all(b"mid-line").expect("write");
    seen.recv_timeout(WAIT).expect("read by the session");
    let start = Instant::now();
    line.set(ControlState::Draining, None);
    server.handle().wake_all();
    let report = server.wait_for_stop();
    let took = start.elapsed();
    assert!(
        took >= Duration::from_millis(250) && took < Duration::from_secs(3),
        "{took:?}"
    );
    assert_eq!(report.killed, 1);
}

#[test]
fn edge_116_more_workers_than_cpus() {
    let cpus = std::thread::available_parallelism().map_or(4, |n| n.get());
    let workers = u16::try_from(cpus * 4).unwrap_or(u16::MAX).min(512);
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .driver(DriverKind::Blocking)
        .workers(workers)
        .sessions(|_: &ConnectionInfo| Lines)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let mut c = client(addr(&server));
    assert_eq!(round_trip(&mut c, b"ok\n"), b"ok\n");
}

#[test]
fn edge_117_post_after_shutdown_is_server_stopped() {
    let server = lines_server();
    let completer = server
        .handle()
        .completer(net_io::WorkerId::first())
        .expect("completer");
    let mut c = client(addr(&server));
    assert_eq!(round_trip(&mut c, b"x\n"), b"x\n");
    let id = net_io::ConnectionId::new(1).expect("id");
    let _ = server.shutdown(Instant::now());
    assert_eq!(completer.post(id, 0, 0), Err(PostError::ServerStopped));
}

// ---- configuration -------------------------------------------------------------

#[test]
fn edge_119_120_bad_caps_fail_at_build() {
    let zero = Limits::builder().max_connections(0).build();
    assert!(matches!(zero, Err(NetError::InvalidConfig { .. })));
    let above = Limits::builder()
        .max_connections(10)
        .max_per_listener(11)
        .build();
    assert!(matches!(above, Err(NetError::InvalidConfig { .. })));
    let workers = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .workers(0)
        .sessions(|_: &ConnectionInfo| Lines)
        .gate(AllowAll)
        .build();
    assert!(matches!(workers, Err(NetError::InvalidConfig { .. })));
}

#[test]
fn edge_126_address_in_use() {
    let first = net_io::listen("127.0.0.1:0").expect("listen");
    let a = first.local_addr().expect("addr");
    let second = net_io::listen(a);
    assert!(
        matches!(second, Err(NetError::AddrInUse { .. })),
        "{second:?}"
    );
}

#[test]
fn edge_127_low_port_without_privileges() {
    match net_io::listen("127.0.0.1:1") {
        // Privileged, or the OS has no such rule (Windows, some containers).
        Ok(_) => {}
        Err(e) => assert!(
            matches!(
                e,
                NetError::PermissionDenied { .. } | NetError::AddrInUse { .. }
            ),
            "{e:?}"
        ),
    }
}

// ---- cross-thread ----------------------------------------------------------------

#[test]
fn edge_129_kill_from_many_threads_closes_once() {
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let server = small_blocking(move |conn: &mut TcpConnection| {
        let _ = tx.lock().map(|t| t.send(conn.id()));
        let mut b = [0u8; 8];
        let _ = conn.recv(&mut b)?;
        Ok(())
    })
    .expect("serve");
    let _c = client(addr(&server));
    let id = rx.recv_timeout(WAIT).expect("id");
    let handle = server.handle();
    let wins: u32 = std::thread::scope(|s| {
        let threads: Vec<_> = (0..64)
            .map(|_| s.spawn(|| u32::from(handle.kill(id, KillReason(2)))))
            .collect();
        threads.into_iter().map(|t| t.join().unwrap_or(0)).sum()
    });
    assert_eq!(wins, 1);
    assert!(eventually(WAIT, || server.stats().closed == 1));
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(server.stats().closed, 1);
    assert_eq!(server.stats().killed, 1);
}

#[test]
fn edge_132_stats_while_workers_run() {
    // Headroom: a client's next connection may arrive before its last one is counted closed.
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .workers(16)
        .sessions(|_: &ConnectionInfo| Lines)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let a = addr(&server);
    let clients: Vec<_> = (0..4)
        .map(|_| {
            std::thread::spawn(move || {
                for _ in 0..50 {
                    let mut c = client(a);
                    assert_eq!(round_trip(&mut c, b"x\n"), b"x\n");
                }
            })
        })
        .collect();
    let mut last = 0;
    while clients.iter().any(|c| !c.is_finished()) {
        let s = server.stats();
        assert!(s.closed >= last, "counters never go back");
        assert!(
            s.bytes_out <= s.bytes_in,
            "echo never sends more than it read"
        );
        last = s.closed;
    }
    for c in clients {
        c.join().expect("client");
    }
    assert!(eventually(WAIT, || server.stats().closed == 200));
}
