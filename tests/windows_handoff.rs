//! The Windows hand-off between two processes: the test binary runs itself again
//! as the receiver. Under about 1,000 connections per second, no connection is
//! refused (the 0.5 exit criterion).

#![cfg(all(windows, feature = "local"))]

use std::io::Read;
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use net_io::{
    AllowAll, DriverKind, HandoffPeer, ListenerSpec, NetError, PipeConnection, PipeListener,
    ServerBuilder, TcpConnection, receive_shared, share_listeners,
};

const WAIT: Duration = Duration::from_secs(20);

fn says(word: &'static [u8]) -> impl Fn(&mut TcpConnection) -> Result<(), NetError> {
    move |conn| conn.send_all(word)
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

#[test]
fn handoff_between_processes_refuses_nothing_under_load() {
    let pipe = format!("net-io-handoff-test-{}", std::process::id());
    let channel_listener = PipeListener::create(&pipe).expect("channel");
    let old = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0").name("web"))
        .driver(DriverKind::Blocking)
        .workers(8)
        .handler(says(b"A"))
        .gate(AllowAll)
        .build()
        .expect("old");
    old.open_door().expect("open");
    let addr = old.listeners()[0].local.socket_addr().expect("tcp");

    let stop = Arc::new(AtomicBool::new(false));
    // What each failure was, for the report.
    let why = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let (failed, by_a, by_b) = (
        Arc::new(AtomicU32::new(0)),
        Arc::new(AtomicU32::new(0)),
        Arc::new(AtomicU32::new(0)),
    );
    let load = {
        let (stop, failed, by_a, by_b) = (stop.clone(), failed.clone(), by_a.clone(), by_b.clone());
        let why = why.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                let got = TcpStream::connect(addr)
                    .map_err(|e| format!("connect: {e}"))
                    .and_then(|mut s| {
                        let _ = s.set_read_timeout(Some(WAIT));
                        let mut out = Vec::new();
                        match s.read_to_end(&mut out) {
                            Ok(_) => Ok(out),
                            Err(e) => Err(format!("read after {:?}: {e}", out)),
                        }
                    });
                match got.as_deref() {
                    Ok(b"A") => by_a.fetch_add(1, Ordering::AcqRel),
                    Ok(b"B") => by_b.fetch_add(1, Ordering::AcqRel),
                    other => {
                        let at = by_a.load(Ordering::Acquire) + by_b.load(Ordering::Acquire);
                        if let Ok(mut w) = why.lock() {
                            w.push(format!("after {at}: {other:?}"));
                        }
                        failed.fetch_add(1, Ordering::AcqRel)
                    }
                };
                std::thread::sleep(Duration::from_millis(1));
            }
        })
    };
    std::thread::sleep(Duration::from_millis(300));

    let exe = std::env::current_exe().expect("test binary");
    let new = Command::new(exe)
        .args([
            "--exact",
            "child_handoff_receiver",
            "--ignored",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env("NET_IO_CHILD_PIPE", &pipe)
        .env("NET_IO_PARENT", std::process::id().to_string())
        .stdin(Stdio::null())
        .spawn()
        .expect("spawn");
    let target = new.id();
    let (mut channel, info) = channel_listener.accept().expect("channel");
    assert_eq!(
        info.peer_credentials.and_then(|c| c.pid),
        Some(target),
        "the expected process is on the pipe"
    );
    let handles = old.release_listeners().expect("release");
    share_listeners(&handles.iter().collect::<Vec<_>>(), target)
        .expect("share")
        .write_to(&mut channel)
        .expect("send");
    let mut ready = [0u8; 1];
    channel
        .recv_exact(&mut ready)
        .expect("the new process opened its door");
    drop(handles);
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
    assert_eq!(
        f,
        0,
        "refused or broken connections (A {a}, B {b}): {:?}",
        why.lock().map(|w| w.clone()).unwrap_or_default()
    );
    assert!(a > 0 && b > 0, "both processes served (A {a}, B {b})");
    assert_eq!(report.killed, 0);
}

#[test]
#[ignore = "started by handoff_between_processes_refuses_nothing_under_load"]
fn child_handoff_receiver() {
    let Ok(pipe) = std::env::var("NET_IO_CHILD_PIPE") else {
        return;
    };
    let parent: u32 = std::env::var("NET_IO_PARENT")
        .expect("parent")
        .parse()
        .expect("pid");
    let mut channel = PipeConnection::connect(&pipe, WAIT).expect("connect");
    let expect = HandoffPeer {
        uid: None,
        pid: Some(parent),
    };
    let handles = receive_shared(&mut channel, &expect, Instant::now() + WAIT).expect("receive");
    let mut builder = ServerBuilder::new();
    for h in handles {
        builder = builder.listener(ListenerSpec::adopt(h));
    }
    let server = builder
        .driver(DriverKind::Blocking)
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
