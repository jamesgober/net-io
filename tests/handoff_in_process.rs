//! Two servers in one process on one listening socket from `release_listeners`, as a
//! supervisor restarts a service in place (register R-43, serve-net's restart test):
//! under load the new server starts, the old one closes its door and drains, and no
//! connection is refused, reset, or left unanswered.
//!
//! Each server has headroom over the load (64 workers, and a per-source cap to
//! match): the blocking driver's caps are one connection per worker and 16 per
//! source by default, and a new server whose workers start slowly on a loaded host
//! refuses at those caps with a reset, which is what R-43 turned out to be.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use net_io::{
    AllowAll, ConnectionInfo, DriverKind, Input, Limits, ListenerHandle, ListenerSpec,
    PrefixPolicy, Server, ServerBuilder, Session, SessionContext, Step, TcpConnection,
};

const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n";

/// A client-side shortage of local ports (a shared host's TIME_WAIT), not a refusal.
fn out_of_ports(e: &std::io::Error) -> bool {
    let codes: &[i32] = if cfg!(windows) {
        &[10048, 10049, 10055]
    } else {
        &[98, 99, 48, 49]
    };
    e.raw_os_error().is_some_and(|c| codes.contains(&c))
}

/// One request on a new connection, written before the reply is read as an HTTP
/// client does: the server's word, or what went wrong.
fn one_request(addr: SocketAddr) -> Result<(), String> {
    let mut tries = 0;
    let mut s = loop {
        match TcpStream::connect(addr) {
            Ok(s) => break s,
            Err(e) if out_of_ports(&e) && tries < 100 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(format!("connect: {e}")),
        }
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
    s.write_all(REQUEST).map_err(|e| format!("write: {e}"))?;
    let mut got = Vec::new();
    match s.read_to_end(&mut got) {
        Ok(_) if got == b"old" || got == b"new" => Ok(()),
        Ok(_) => Err(format!("reply: {got:?}")),
        Err(e) => Err(format!("read after {} bytes: {e}", got.len())),
    }
}

/// Answers one whole request with its server's word, then closes.
struct Reply(&'static [u8]);

impl Session for Reply {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        if !input.bytes().windows(4).any(|w| w == b"\r\n\r\n") {
            return Step::Read;
        }
        let n = input.bytes().len();
        input.consume(n);
        let _ = cx.output().push_partial(self.0);
        Step::Close
    }
}

/// Two handles on one listening socket, as a supervisor holds it.
fn shared_socket() -> (SocketAddr, ListenerHandle, ListenerHandle) {
    let holder = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .handler(|_c: &mut TcpConnection| Ok(()))
        .gate(AllowAll)
        .build()
        .expect("holder");
    let addr = holder.listeners()[0].local.socket_addr().expect("tcp");
    let first = holder
        .release_listeners()
        .expect("release")
        .pop()
        .expect("one");
    let second = holder
        .release_listeners()
        .expect("release")
        .pop()
        .expect("two");
    let _ = holder.shutdown(Instant::now());
    (addr, first, second)
}

fn serve(handle: ListenerHandle, word: &'static [u8]) -> Server {
    let server = ServerBuilder::new()
        .listener(ListenerSpec::adopt(handle))
        .driver(DriverKind::Blocking)
        .workers(64)
        .limits(
            Limits::builder()
                .max_per_source(64, PrefixPolicy::DEFAULT)
                .build()
                .expect("limits"),
        )
        .sessions(move |_: &ConnectionInfo| Reply(word))
        .gate(AllowAll)
        .build()
        .expect("serve");
    server.open_door().expect("open");
    server
}

/// Four clients, each making one request after another until `stop`: when each
/// began, and how it ended.
type Log = Arc<Mutex<Vec<(Instant, Result<(), String>)>>>;

fn clients(
    addr: SocketAddr,
    stop: &Arc<AtomicBool>,
    log: &Log,
) -> Vec<std::thread::JoinHandle<()>> {
    (0..4)
        .map(|_| {
            let (stop, log) = (stop.clone(), log.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let begun = Instant::now();
                    let r = one_request(addr);
                    log.lock().expect("lock").push((begun, r));
                }
            })
        })
        .collect()
}

#[test]
fn test_restart_in_process_refuses_and_resets_nothing() {
    let (addr, first, second) = shared_socket();
    let old = serve(first, b"old");
    let stop = Arc::new(AtomicBool::new(false));
    let log: Log = Arc::default();
    let running = clients(addr, &stop, &log);
    std::thread::sleep(Duration::from_millis(100));
    // The new server starts on the same socket, then the old one leaves.
    let new = serve(second, b"new");
    std::thread::sleep(Duration::from_millis(50));
    old.close_door();
    let report = old.shutdown(Instant::now() + Duration::from_secs(5));
    assert_eq!(report.killed, 0, "{report:?}");
    std::thread::sleep(Duration::from_millis(100));
    stop.store(true, Ordering::Relaxed);
    for c in running {
        c.join().expect("client");
    }
    let log = log.lock().expect("lock");
    assert!(log.iter().any(|(_, r)| r.is_ok()));
    let failed: Vec<_> = log.iter().filter_map(|(_, r)| r.as_ref().err()).collect();
    assert!(failed.is_empty(), "failed in the restart: {failed:?}");
    let _ = new.shutdown(Instant::now() + Duration::from_secs(2));
}

/// The old server dies (dropped at once, no drain) before the new one starts: for a
/// moment only the supervisor's handle holds the socket, and connections wait in its
/// backlog with their requests. Every request begun after the drop is answered by
/// the new server (serve-net's kill before the new server starts).
#[test]
fn test_a_server_dropped_before_the_new_one_starts_leaves_nothing_unanswered() {
    let (addr, first, second) = shared_socket();
    let old = serve(first, b"old");
    let stop = Arc::new(AtomicBool::new(false));
    let log: Log = Arc::default();
    let running = clients(addr, &stop, &log);
    std::thread::sleep(Duration::from_millis(100));
    let _ = old.shutdown(Instant::now());
    let dropped = Instant::now();
    std::thread::sleep(Duration::from_millis(50));
    let new = serve(second, b"new");
    // Until a request begun after the drop is served, not for a fixed time: on a
    // loaded host the first ones can take longer than any short window.
    let until = Instant::now() + Duration::from_secs(30);
    std::thread::sleep(Duration::from_millis(300));
    while Instant::now() < until
        && !log
            .lock()
            .expect("lock")
            .iter()
            .any(|(begun, r)| *begun > dropped && r.is_ok())
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    stop.store(true, Ordering::Relaxed);
    for c in running {
        c.join().expect("client");
    }
    let log = log.lock().expect("lock");
    let late: Vec<_> = log
        .iter()
        .filter(|(begun, r)| *begun > dropped && r.is_err())
        .map(|(begun, r)| (begun.duration_since(dropped), r))
        .collect();
    assert!(late.is_empty(), "failed after the drop: {late:?}");
    let served = log
        .iter()
        .filter(|(begun, r)| *begun > dropped && r.is_ok())
        .count();
    assert!(served > 0, "nothing served after the drop");
    let _ = new.shutdown(Instant::now() + Duration::from_secs(2));
}
