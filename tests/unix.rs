//! Unix domain socket listeners on a server: credentials, `require_uid`, PROXY
//! without a trusted list, and the socket file's life.

#![cfg(all(unix, feature = "local"))]

mod common;

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::eventually;
use net_io::{
    AllowAll, ConnectionInfo, Endpoint, Input, ListenerSpec, LocalOptions, NetError, ProxyMode,
    ProxyVersions, RefusalCause, ServerBuilder, Session, SessionContext, Step, TcpConnection,
    Transport, UnixConnection, UnixListener,
};

const WAIT: Duration = Duration::from_secs(5);

/// A fresh private directory under the temp dir.
fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("nio-t-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir(&d).expect("dir");
    d
}

fn my_uid(d: &std::path::Path) -> u32 {
    std::fs::metadata(d).expect("stat").uid()
}

/// Writes what net-io knows about the peer, then echoes one read.
fn whoami(conn: &mut TcpConnection) -> Result<(), NetError> {
    let info = conn.info();
    let line = format!(
        "{:?} {:?} {:?}\n",
        info.transport,
        info.client_addr(),
        info.peer_credentials.and_then(|c| c.uid)
    );
    conn.send_all(line.as_bytes())?;
    let mut buf = [0u8; 64];
    let n = conn.recv(&mut buf)?;
    conn.send_all(&buf[..n])?;
    Ok(())
}

fn read_line(c: &mut UnixConnection) -> String {
    let mut out = Vec::new();
    let mut b = [0u8; 1];
    while c.recv(&mut b).expect("recv") == 1 {
        if b[0] == b'\n' {
            break;
        }
        out.push(b[0]);
    }
    String::from_utf8(out).expect("utf-8")
}

#[test]
fn unix_listener_serves_a_handler_with_credentials() {
    let d = dir("handler");
    let path = d.join("api.sock");
    let server = ServerBuilder::new()
        .listener(ListenerSpec::unix(&path, LocalOptions::new().mode(0o660)).name("api"))
        .workers(2)
        .handler(whoami)
        .gate(AllowAll)
        .build()
        .expect("build");
    let info = &server.listeners()[0];
    assert_eq!(info.transport, Transport::Unix);
    assert!(matches!(info.local, Endpoint::Unix(_)));
    let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
    assert_eq!(mode, 0o660);
    server.open_door().expect("open");
    let mut c = UnixConnection::connect(&path).expect("connect");
    let line = read_line(&mut c);
    assert_eq!(line, format!("Unix None Some({})", my_uid(&d)));
    c.send_all(b"ping").expect("send");
    let mut back = [0u8; 4];
    c.recv_exact(&mut back).expect("echo");
    assert_eq!(&back, b"ping");
    drop(c);
    assert!(eventually(WAIT, || server.stats().closed == 1));
    let _ = server.shutdown(Instant::now() + WAIT);
    assert!(!path.exists(), "the server removed its socket file");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn unix_listener_refuses_other_users_with_credentials_cause() {
    let d = dir("uid");
    let path = d.join("s.sock");
    let other = my_uid(&d).wrapping_add(1);
    let server = ServerBuilder::new()
        .listener(ListenerSpec::unix(
            &path,
            LocalOptions::new().require_uid(other),
        ))
        .workers(2)
        .handler(whoami)
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let mut c = UnixConnection::connect(&path).expect("connect");
    let mut b = [0u8; 8];
    assert!(matches!(
        c.recv(&mut b),
        Ok(0) | Err(NetError::ConnectionReset)
    ));
    assert!(eventually(WAIT, || server.stats().refused == 1));
    let stats = server.stats();
    let by_credentials = stats
        .refusals()
        .find(|(cause, _)| *cause == RefusalCause::Credentials)
        .map(|(_, n)| n);
    assert_eq!(by_credentials, Some(1));
    assert_eq!(stats.accepted, 0);
    let _ = server.shutdown(Instant::now() + WAIT);
    let _ = std::fs::remove_dir_all(&d);
}

/// Records the real client a session saw.
struct Seen(Arc<Mutex<Option<ConnectionInfo>>>);

impl Session for Seen {
    fn on_data(&mut self, ctx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        if let Ok(mut s) = self.0.lock() {
            *s = Some(ctx.info().clone());
        }
        let n = input.bytes().len();
        input.consume(n);
        Step::Close
    }
}

#[test]
fn unix_listener_proxy_needs_no_trusted_list() {
    let d = dir("proxy");
    let path = d.join("s.sock");
    let seen = Arc::new(Mutex::new(None));
    let s2 = seen.clone();
    let server = ServerBuilder::new()
        .listener(
            ListenerSpec::unix(&path, LocalOptions::new()).proxy(ProxyMode::Required {
                versions: ProxyVersions::Both,
            }),
        )
        .workers(2)
        .sessions(move |_: &ConnectionInfo| Seen(s2.clone()))
        .gate(AllowAll)
        .build()
        .expect("build without trusted proxies");
    server.open_door().expect("open");
    let mut c = UnixConnection::connect(&path).expect("connect");
    c.send_all(b"PROXY TCP4 203.0.113.5 10.0.0.1 40000 443\r\nhello")
        .expect("send");
    assert!(eventually(WAIT, || seen
        .lock()
        .map(|s| s.is_some())
        .unwrap_or(false)));
    let info = seen.lock().expect("lock").clone().expect("info");
    assert_eq!(info.transport, Transport::Unix);
    assert_eq!(
        info.client_addr(),
        Some("203.0.113.5:40000".parse().expect("addr"))
    );
    assert!(info.peer_credentials.is_some());
    let _ = server.shutdown(Instant::now() + WAIT);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn unix_listener_on_a_live_path_fails_build() {
    let d = dir("live");
    let path = d.join("s.sock");
    let live = UnixListener::bind(&path).expect("bind");
    let built = ServerBuilder::new()
        .listener(ListenerSpec::unix(&path, LocalOptions::new()))
        .workers(1)
        .handler(whoami)
        .gate(AllowAll)
        .build();
    assert!(matches!(built, Err(NetError::StaleSocketInUse { .. })));
    drop(live);
    let _ = std::fs::remove_dir_all(&d);
}
