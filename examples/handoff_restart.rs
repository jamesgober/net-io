//! A restart without a closed port: the running process gives its listening
//! socket to its replacement, which opens its door before the old one stops.
//! Connections keep being accepted throughout.
//!
//! ```text
//! cargo run --example handoff_restart -- old 127.0.0.1:7003 /tmp/net-io-handoff.sock
//! # later, in another terminal (the replacement):
//! cargo run --example handoff_restart -- new /tmp/net-io-handoff.sock
//! ```
//!
//! The old process serves "old" and watches for the replacement's channel
//! socket; once it appears, it releases its listeners, sends them, waits for the
//! replacement to say it is ready, and drains. The replacement serves "new"
//! until it is stopped. Keep the channel socket in a private directory: only
//! the same user may send listeners (`HandoffPeer::default()`).

#[cfg(all(unix, feature = "local"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::time::{Duration, Instant};

    use net_io::{
        AllowAll, HandoffPeer, ListenerSpec, ServerBuilder, UnixConnection, UnixListener,
        recv_listeners, send_listeners,
    };

    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("old") => {
            let addr = args.get(1).map_or("127.0.0.1:7003", String::as_str);
            let channel = args
                .get(2)
                .map_or("/tmp/net-io-handoff.sock", String::as_str);
            let server = ServerBuilder::new()
                .listener(ListenerSpec::tcp(addr).name("web"))
                .handler(|conn| conn.send_all(b"old\n"))
                .gate(AllowAll)
                .build()?;
            server.open_door()?;
            println!("old: serving on {addr}; start the replacement with `new {channel}`");
            // Wait for the replacement's channel.
            let mut conn = loop {
                if let Ok(c) = UnixConnection::connect(channel) {
                    break c;
                }
                std::thread::sleep(Duration::from_millis(200));
            };
            let handles = server.release_listeners()?;
            send_listeners(&mut conn, &handles.iter().collect::<Vec<_>>())?;
            let mut ready = [0u8; 1];
            conn.recv_exact(&mut ready)?;
            let report = server.shutdown(Instant::now() + Duration::from_secs(30));
            println!("old: handed off and drained: {report:?}");
        }
        Some("new") => {
            let channel = args
                .get(1)
                .map_or("/tmp/net-io-handoff.sock", String::as_str);
            let channel_listener = UnixListener::bind(channel)?;
            let (mut conn, _) = channel_listener.accept()?;
            let handles = recv_listeners(
                &mut conn,
                &HandoffPeer::default(),
                Instant::now() + Duration::from_secs(10),
            )?;
            let mut builder = ServerBuilder::new();
            for h in handles {
                println!("new: received {:?} on {}", h.name(), h.local());
                builder = builder.listener(ListenerSpec::adopt(h));
            }
            let server = builder
                .handler(|conn| conn.send_all(b"new\n"))
                .gate(AllowAll)
                .build()?;
            server.open_door()?;
            conn.send_all(b"1")?;
            println!("new: serving; stop it with Ctrl-C");
            let report = server.wait_for_stop();
            println!("new: stopped: {report:?}");
        }
        _ => eprintln!("usage: handoff_restart old <addr> <channel> | new <channel>"),
    }
    Ok(())
}

#[cfg(not(all(unix, feature = "local")))]
fn main() {
    eprintln!("the Unix hand-off needs Unix and the `local` feature (Windows: 0.5.0)");
}
