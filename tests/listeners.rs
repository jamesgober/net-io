//! Listeners on a running server: `add_listener` (door closed until opened) and
//! `remove_listener` (socket closed at once, its connections drained).

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{addr, client, eventually};
use net_io::{
    AllowAll, CloseReason, ConfigReason, Event, EventSink, ListenerId, ListenerSpec, NetError,
    Phase, ServerBuilder, TcpConnection,
};

const WAIT: Duration = Duration::from_secs(5);

#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<Event>>>);

impl EventSink for Recorder {
    fn event(&self, event: &Event) {
        if let Ok(mut v) = self.0.lock() {
            v.push(*event);
        }
    }
}

impl Recorder {
    fn has(&self, f: impl Fn(&Event) -> bool) -> bool {
        self.0.lock().map(|v| v.iter().any(f)).unwrap_or(false)
    }
}

/// Greets with the listener's id, then echoes until the peer closes. A client
/// that sends `b` first makes the connection busy (`Receiving`) for the rest.
fn greet(conn: &mut TcpConnection) -> Result<(), NetError> {
    let id = conn.info().listener.map_or(u16::MAX, |l| l.get());
    conn.send_all(format!("{id}\n").as_bytes())?;
    let mut buf = [0u8; 64];
    loop {
        let n = conn.recv(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        if buf[0] == b'b' {
            conn.set_phase(Phase::Receiving);
        }
        conn.send_all(&buf[..n])?;
    }
}

fn line(s: &mut TcpStream) -> String {
    let mut out = Vec::new();
    let mut b = [0u8; 1];
    while s.read(&mut b).expect("read") == 1 && b[0] != b'\n' {
        out.push(b[0]);
    }
    String::from_utf8(out).expect("utf-8")
}

fn local(server: &net_io::Server, id: ListenerId) -> SocketAddr {
    server
        .listeners()
        .iter()
        .find(|l| l.id == id)
        .and_then(|l| l.local.socket_addr())
        .expect("listener")
}

#[test]
fn added_listener_waits_for_open_door() {
    let rec = Recorder::default();
    let mut server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0").name("first"))
        .workers(4)
        .handler(greet)
        .gate(AllowAll)
        .events(rec.clone())
        .build()
        .expect("build");
    server.open_door().expect("open");
    let id = server
        .add_listener(ListenerSpec::tcp("127.0.0.1:0").name("second"))
        .expect("add");
    assert_eq!(id.get(), 1);
    assert_eq!(server.listeners().len(), 2);
    assert!(rec.has(|e| matches!(e, Event::ListenerOpened { listener, .. } if *listener == id)));
    // The kernel queues the connection, but nothing accepts it yet.
    let mut c = client(local(&server, id));
    c.set_read_timeout(Some(Duration::from_millis(300)))
        .expect("timeout");
    let mut b = [0u8; 1];
    assert!(c.read(&mut b).is_err(), "door closed: no greeting");
    server.open_door().expect("open again");
    c.set_read_timeout(Some(WAIT)).expect("timeout");
    assert_eq!(line(&mut c), "1");
    // The first listener kept serving.
    let mut first = client(addr(&server));
    assert_eq!(line(&mut first), "0");
    // A taken name is refused.
    assert!(matches!(
        server.add_listener(ListenerSpec::tcp("127.0.0.1:0").name("first")),
        Err(NetError::InvalidConfig {
            field: "name",
            reason: ConfigReason::Inconsistent
        })
    ));
}

#[test]
fn removed_listener_closes_and_drains_only_its_connections() {
    let rec = Recorder::default();
    let mut server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .workers(4)
        .handler(greet)
        .gate(AllowAll)
        .events(rec.clone())
        .build()
        .expect("build");
    server.open_door().expect("open");
    let second = server.listeners()[1].id;
    let second_addr = local(&server, second);
    // On the first listener: one connection that must survive.
    let mut keep = client(addr(&server));
    assert_eq!(line(&mut keep), "0");
    // On the second: one idle connection, one busy in an exchange.
    let mut idle = client(second_addr);
    assert_eq!(line(&mut idle), "1");
    let mut busy = client(second_addr);
    assert_eq!(line(&mut busy), "1");
    busy.write_all(b"b").expect("busy");
    let mut echo = [0u8; 1];
    busy.read_exact(&mut echo).expect("echo");

    let report = server
        .remove_listener(second, Instant::now() + Duration::from_millis(300))
        .expect("remove");
    assert_eq!((report.graceful, report.killed), (1, 1), "{report:?}");
    assert!(rec.has(|e| matches!(e, Event::ListenerClosed { listener } if *listener == second)));
    assert!(rec.has(|e| matches!(
        e,
        Event::Closed {
            reason: CloseReason::DrainDeadline,
            ..
        }
    )));
    assert_eq!(server.listeners().len(), 1);
    // Its socket is closed: nothing accepts there any more.
    assert!(TcpStream::connect(second_addr).is_err());
    // The other listener's connection was not touched.
    keep.write_all(b"x").expect("write");
    keep.read_exact(&mut echo).expect("still served");
    assert_eq!(&echo, b"x");
    assert!(matches!(
        server.remove_listener(second, Instant::now()),
        Err(NetError::InvalidConfig {
            field: "listener",
            ..
        })
    ));
    drop(keep);
    assert!(eventually(WAIT, || server.stats().open == 0));
}

#[test]
fn listener_ids_are_not_reused() {
    let mut server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .workers(2)
        .handler(greet)
        .gate(AllowAll)
        .build()
        .expect("build");
    let a = server
        .add_listener(ListenerSpec::tcp("127.0.0.1:0"))
        .expect("add");
    server.remove_listener(a, Instant::now()).expect("remove");
    let b = server
        .add_listener(ListenerSpec::tcp("127.0.0.1:0"))
        .expect("add");
    assert_ne!(a, b);
    server.open_door().expect("open");
    let mut c = client(local(&server, b));
    assert_eq!(line(&mut c), b.get().to_string());
}
