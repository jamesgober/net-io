//! Two servers in one process on one listening socket from `release_listeners`, as a
//! supervisor restarts a service in place (register R-43, serve-net's restart test):
//! under load the new server starts, the old one closes its door and drains, and no
//! connection is refused, reset, or left unanswered.
//!
//! Each server has headroom over the load (64 workers, and a per-source cap to
//! match): the blocking driver's caps are one connection per worker and 16 per
//! source by default, and a new server whose workers start slowly on a loaded host
//! refuses at those caps with a reset, which is what R-43 turned out to be.

use std::io::Read;
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use net_io::{
    AllowAll, DriverKind, Limits, ListenerHandle, ListenerSpec, NetError, PrefixPolicy, Server,
    ServerBuilder, TcpConnection,
};

/// A client-side shortage of local ports (a shared host's TIME_WAIT), not a refusal.
fn out_of_ports(e: &std::io::Error) -> bool {
    let codes: &[i32] = if cfg!(windows) {
        &[10048, 10049, 10055]
    } else {
        &[98, 99, 48, 49]
    };
    e.raw_os_error().is_some_and(|c| codes.contains(&c))
}

/// One connection: the server's word, or what went wrong.
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
    let mut got = Vec::new();
    match s.read_to_end(&mut got) {
        Ok(_) if got == b"old" || got == b"new" => Ok(()),
        Ok(_) => Err(format!("reply: {got:?}")),
        Err(e) => Err(format!("read after {} bytes: {e}", got.len())),
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
        .handler(move |c: &mut TcpConnection| -> Result<(), NetError> { c.send_all(word) })
        .gate(AllowAll)
        .build()
        .expect("serve");
    server.open_door().expect("open");
    server
}

#[test]
fn test_restart_in_process_refuses_and_resets_nothing() {
    let (addr, first, second) = shared_socket();
    let old = serve(first, b"old");
    let stop = Arc::new(AtomicBool::new(false));
    let served = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(Mutex::new(Vec::new()));
    let clients: Vec<_> = (0..4)
        .map(|_| {
            let (stop, served, failed) = (stop.clone(), served.clone(), failed.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match one_request(addr) {
                        Ok(()) => {
                            served.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => failed.lock().expect("lock").push(e),
                    }
                }
            })
        })
        .collect();
    std::thread::sleep(Duration::from_millis(100));
    // The new server starts on the same socket, then the old one leaves.
    let new = serve(second, b"new");
    std::thread::sleep(Duration::from_millis(50));
    old.close_door();
    let report = old.shutdown(Instant::now() + Duration::from_secs(5));
    assert_eq!(report.killed, 0, "{report:?}");
    std::thread::sleep(Duration::from_millis(100));
    stop.store(true, Ordering::Relaxed);
    for c in clients {
        c.join().expect("client");
    }
    assert!(served.load(Ordering::Relaxed) > 0);
    let failed = failed.lock().expect("lock");
    assert!(failed.is_empty(), "failed in the restart: {failed:?}");
    let _ = new.shutdown(Instant::now() + Duration::from_secs(2));
}
