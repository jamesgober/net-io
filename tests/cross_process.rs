//! Tests that need a second process: the test binary runs itself again as the
//! child (the `child_*` tests, ignored unless a parent starts them with
//! `NET_IO_CHILD` set).
//!
//! - A listener hand-off between two processes under about 1,000 connections
//!   per second refuses no connection (the 0.4 exit criterion).
//! - systemd socket activation through systemd's own `systemd-socket-activate`
//!   (where it is installed).
//! - FastCGI: a listening socket as the child's descriptor 0, as `mod_fcgid`
//!   starts a FastCGI server.

#![cfg(all(unix, feature = "local"))]

use std::io::Read;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use net_io::{
    AllowAll, HandoffPeer, ListenerSpec, NetError, ServerBuilder, TcpConnection, UnixConnection,
    UnixListener, recv_listeners, send_listeners,
};

const WAIT: Duration = Duration::from_secs(10);

fn says(word: &'static [u8]) -> impl Fn(&mut TcpConnection) -> Result<(), NetError> {
    move |conn| conn.send_all(word)
}

/// Starts this test binary again, running only the child test `name`.
fn child(name: &str, role: &str, env: &[(&str, String)]) -> Command {
    let exe = std::env::current_exe().expect("test binary");
    let mut cmd = Command::new(exe);
    cmd.args([
        "--exact",
        name,
        "--ignored",
        "--nocapture",
        "--test-threads",
        "1",
    ])
    .env("NET_IO_CHILD", role);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd
}

fn role() -> Option<String> {
    std::env::var("NET_IO_CHILD").ok()
}

fn wait_ok(mut c: Child) {
    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(status) = c.try_wait().expect("wait") {
            assert!(status.success(), "child failed: {status}");
            return;
        }
        if Instant::now() > deadline {
            let _ = c.kill();
            panic!("child did not finish");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Connects (retrying while the child starts) and reads everything.
fn fetch(addr: SocketAddr) -> Vec<u8> {
    let deadline = Instant::now() + WAIT;
    loop {
        match TcpStream::connect(addr) {
            Ok(mut s) => {
                s.set_read_timeout(Some(WAIT)).expect("timeout");
                let mut out = Vec::new();
                let _ = s.read_to_end(&mut out);
                return out;
            }
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => panic!("connect: {e}"),
        }
    }
}

fn free_port() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    l.local_addr().expect("addr")
}

fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("nio-xp-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir(&d).expect("dir");
    d
}

// ---- hand-off under load -----------------------------------------------------

#[test]
fn handoff_between_processes_refuses_nothing_under_load() {
    let dir = temp_dir("handoff");
    let channel_path = dir.join("handoff.sock");
    let old = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0").name("web"))
        .workers(8)
        .handler(says(b"A"))
        .gate(AllowAll)
        .build()
        .expect("old");
    old.open_door().expect("open");
    let addr = old.listeners()[0].local.socket_addr().expect("tcp");

    // About 1,000 connections per second from before the hand-off until after
    // the old server stopped; every one must be served by one of the two.
    let stop = Arc::new(AtomicBool::new(false));
    let (failed, by_a, by_b) = (
        Arc::new(AtomicU32::new(0)),
        Arc::new(AtomicU32::new(0)),
        Arc::new(AtomicU32::new(0)),
    );
    let load = {
        let (stop, failed, by_a, by_b) = (stop.clone(), failed.clone(), by_a.clone(), by_b.clone());
        std::thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                let got = TcpStream::connect(addr).ok().map(|mut s| {
                    let _ = s.set_read_timeout(Some(WAIT));
                    let mut out = Vec::new();
                    let _ = s.read_to_end(&mut out);
                    out
                });
                match got.as_deref() {
                    Some(b"A") => by_a.fetch_add(1, Ordering::AcqRel),
                    Some(b"B") => by_b.fetch_add(1, Ordering::AcqRel),
                    _ => failed.fetch_add(1, Ordering::AcqRel),
                };
                std::thread::sleep(Duration::from_millis(1));
            }
        })
    };
    std::thread::sleep(Duration::from_millis(300));

    let new = child(
        "child_handoff_receiver",
        "handoff",
        &[("NET_IO_CHANNEL", channel_path.display().to_string())],
    )
    .stdin(Stdio::null())
    .spawn()
    .expect("spawn");
    let deadline = Instant::now() + WAIT;
    let mut channel = loop {
        match UnixConnection::connect(&channel_path) {
            Ok(c) => break c,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => panic!("channel: {e}"),
        }
    };
    let handles = old.release_listeners().expect("release");
    send_listeners(&mut channel, &handles.iter().collect::<Vec<_>>()).expect("send");
    drop(handles);
    let mut ready = [0u8; 1];
    channel
        .recv_exact(&mut ready)
        .expect("the new process opened its door");
    let report = old.shutdown(Instant::now() + WAIT);
    std::thread::sleep(Duration::from_millis(300));
    stop.store(true, Ordering::Release);
    load.join().expect("load");
    channel.send_all(b"x").expect("stop the child");
    wait_ok(new);

    let (a, b, f) = (
        by_a.load(Ordering::Acquire),
        by_b.load(Ordering::Acquire),
        failed.load(Ordering::Acquire),
    );
    assert_eq!(f, 0, "refused or broken connections (A {a}, B {b})");
    assert!(a > 0 && b > 0, "both processes served (A {a}, B {b})");
    assert_eq!(report.killed, 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore = "started by handoff_between_processes_refuses_nothing_under_load"]
fn child_handoff_receiver() {
    if role().as_deref() != Some("handoff") {
        return;
    }
    let path = std::env::var("NET_IO_CHANNEL").expect("channel path");
    let channel_listener = UnixListener::bind(&path).expect("bind channel");
    let (mut channel, _) = channel_listener.accept().expect("accept");
    let handles = recv_listeners(&mut channel, &HandoffPeer::default(), Instant::now() + WAIT)
        .expect("receive");
    let mut builder = ServerBuilder::new();
    for h in handles {
        builder = builder.listener(ListenerSpec::adopt(h));
    }
    let server = builder
        .workers(8)
        .handler(says(b"B"))
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    channel.send_all(b"1").expect("ready");
    let mut stop = [0u8; 1];
    channel.recv_exact(&mut stop).expect("stop");
    let _ = server.shutdown(Instant::now() + WAIT);
}

// ---- systemd socket activation ---------------------------------------------------

#[test]
fn systemd_socket_activation_with_the_real_tool() {
    let Some(tool) = [
        "/usr/bin/systemd-socket-activate",
        "/bin/systemd-socket-activate",
    ]
    .into_iter()
    .find(|p| std::path::Path::new(p).exists()) else {
        eprintln!("systemd-socket-activate is not installed; skipped");
        return;
    };
    let exe = std::env::current_exe().expect("test binary");
    // The port is chosen by binding port 0 and releasing it, so another test
    // running in parallel can take it before the tool binds. Connect only after
    // the tool says it listens; if its bind failed, try another port.
    for _ in 0..5 {
        let addr = free_port();
        let mut c = Command::new(tool)
            .arg(format!("--listen={addr}"))
            .arg("--fdname=web")
            .arg("--setenv=NET_IO_CHILD=systemd")
            .arg(&exe)
            .args(["--exact", "child_systemd", "--ignored", "--nocapture"])
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn");
        if !listening(&mut c) {
            let _ = c.kill();
            let _ = c.wait();
            continue;
        }
        assert_eq!(fetch(addr), b"systemd web");
        wait_ok(c);
        return;
    }
    panic!("systemd-socket-activate never listened");
}

/// Waits for `systemd-socket-activate` to report "Listening on" on its stderr
/// (false when it exits or reports anything else first). Its stderr, which the
/// child shares, keeps being copied to this test's stderr afterwards.
fn listening(c: &mut Child) -> bool {
    use std::io::BufRead;
    let Some(stderr) = c.stderr.take() else {
        return false;
    };
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut told = false;
        for line in std::io::BufReader::new(stderr).lines() {
            let Ok(line) = line else { break };
            eprintln!("{line}");
            if !told {
                let _ = tx.send(line.starts_with("Listening on"));
                told = true;
            }
        }
        if !told {
            let _ = tx.send(false);
        }
    });
    rx.recv_timeout(WAIT).unwrap_or(false)
}

#[test]
#[ignore = "started by systemd_socket_activation_with_the_real_tool"]
fn child_systemd() {
    if role().as_deref() != Some("systemd") {
        return;
    }
    let mut list = net_io::systemd().expect("inherited");
    assert_eq!(list.len(), 1);
    let inherited = list.pop().expect("one");
    assert_eq!(inherited.name.as_deref(), Some("web"));
    assert!(net_io::systemd().expect("again").is_empty(), "taken once");
    let server = ServerBuilder::new()
        .listener(ListenerSpec::adopt(inherited.handle))
        .workers(1)
        .handler(|conn: &mut TcpConnection| {
            let name = conn.info().listener.map(|_| "web").unwrap_or("none");
            conn.send_all(format!("systemd {name}").as_bytes())
        })
        .gate(AllowAll)
        .build()
        .expect("build");
    assert_eq!(server.listeners()[0].name.as_deref(), Some("web"));
    server.open_door().expect("open");
    let deadline = Instant::now() + WAIT;
    while server.stats().closed == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = server.shutdown(Instant::now() + WAIT);
}

// ---- FastCGI descriptor 0 ---------------------------------------------------------

#[test]
fn fastcgi_listener_on_descriptor_zero() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let c = child("child_fastcgi", "fastcgi", &[])
        .stdin(Stdio::from(OwnedFd::from(listener)))
        .spawn()
        .expect("spawn");
    assert_eq!(fetch(addr), b"fastcgi");
    wait_ok(c);
}

#[test]
#[ignore = "started by fastcgi_listener_on_descriptor_zero"]
fn child_fastcgi() {
    if role().as_deref() != Some("fastcgi") {
        return;
    }
    let handle = net_io::fastcgi_listener()
        .expect("inspect")
        .expect("descriptor 0 is a listener");
    assert!(
        net_io::fastcgi_listener().expect("again").is_none(),
        "taken once"
    );
    let server = ServerBuilder::new()
        .listener(ListenerSpec::adopt(handle))
        .workers(1)
        .handler(says(b"fastcgi"))
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let deadline = Instant::now() + WAIT;
    while server.stats().closed == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = server.shutdown(Instant::now() + WAIT);
}

#[test]
fn fastcgi_listener_is_none_for_a_pipe_or_terminal() {
    // This process's descriptor 0 under the test harness: not a listening socket.
    assert!(net_io::fastcgi_listener().expect("inspect").is_none());
}
