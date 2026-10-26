//! A restart without a closed port: one server releases its listeners, a second
//! receives them over a Unix socket, opens its door, and the first stops.

#![cfg(all(unix, feature = "local"))]

use std::io::Read;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use net_io::{
    AllowAll, HandoffPeer, ListenerSpec, LocalOptions, NetError, ServerBuilder, TcpConnection,
    Transport, UnixConnection, UnixListener, recv_listeners, send_listeners,
};

const WAIT: Duration = Duration::from_secs(5);

fn says(word: &'static [u8]) -> impl Fn(&mut TcpConnection) -> Result<(), NetError> {
    move |conn| conn.send_all(word)
}

fn read_all<R: Read>(mut r: R) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = r.read_to_end(&mut out);
    out
}

#[test]
fn listeners_move_to_a_new_server_without_closing() {
    let dir = std::env::temp_dir().join(format!("nio-restart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).expect("dir");
    let api = dir.join("api.sock");
    let old = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0").name("web"))
        .listener(ListenerSpec::unix(&api, LocalOptions::new()).name("api"))
        .workers(2)
        .handler(says(b"old"))
        .gate(AllowAll)
        .build()
        .expect("old");
    old.open_door().expect("open");
    let web = old.listeners()[0].local.socket_addr().expect("tcp");

    // The new process's side: a private channel, then receive and serve.
    let channel_path = dir.join("handoff.sock");
    let channel_listener = UnixListener::bind(&channel_path).expect("channel");
    let new_side = std::thread::spawn(move || {
        let (mut channel, _) = channel_listener.accept().expect("accept");
        let handles = recv_listeners(&mut channel, &HandoffPeer::default(), Instant::now() + WAIT)
            .expect("receive");
        assert_eq!(handles.len(), 2);
        assert_eq!(handles[0].kind(), Transport::Tcp);
        assert_eq!(handles[0].name(), Some("web"));
        assert_eq!(handles[1].kind(), Transport::Unix);
        let mut builder = ServerBuilder::new();
        for h in handles {
            builder = builder.listener(ListenerSpec::adopt(h));
        }
        let new = builder
            .workers(2)
            .handler(says(b"new"))
            .gate(AllowAll)
            .build()
            .expect("new");
        assert_eq!(new.listeners()[0].name.as_deref(), Some("web"));
        new.open_door().expect("open new");
        channel.send_all(b"1").expect("ready");
        new
    });

    // The old process's side.
    let mut channel = UnixConnection::connect(&channel_path).expect("connect");
    let handles = old.release_listeners().expect("release");
    send_listeners(&mut channel, &handles.iter().collect::<Vec<_>>()).expect("send");
    drop(handles);
    let mut ready = [0u8; 1];
    channel.recv_exact(&mut ready).expect("ready");
    let report = old.shutdown(Instant::now() + WAIT);
    assert_eq!(report.killed, 0);
    let new = new_side.join().expect("new side");

    // Both listeners still accept, now in the new server; the socket file stayed.
    for _ in 0..3 {
        let c = std::net::TcpStream::connect(web).expect("tcp still open");
        assert_eq!(read_all(c), b"new");
    }
    assert!(api.exists(), "the released socket file was not removed");
    let u = UnixStream::connect(&api).expect("unix still open");
    assert_eq!(read_all(u), b"new");
    drop(new);
    let _ = std::fs::remove_dir_all(&dir);
}
