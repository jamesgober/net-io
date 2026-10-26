//! systemd socket activation: serve on the sockets systemd passed, or bind a
//! fallback address when started by hand.
//!
//! ```text
//! cargo build --example systemd_activation
//! systemd-socket-activate -l 127.0.0.1:7004 --fdname=web target/debug/examples/systemd_activation
//! ```
//!
//! In a unit, pair a `.socket` unit (`ListenStream=7004`, `FileDescriptorName=web`)
//! with this program as the service. `LISTEN_PID` must name this process,
//! otherwise the variables were meant for another and nothing is inherited.
//! `monotonic_micros` gives the clock systemd's `MONOTONIC_USEC` expects.

use net_io::{AllowAll, ListenerSpec, ServerBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let inherited = net_io::systemd()?;
    let mut builder = ServerBuilder::new();
    if inherited.is_empty() {
        let fallback = std::env::args()
            .nth(1)
            .unwrap_or_else(|| "127.0.0.1:7004".to_string());
        println!("not socket-activated; binding {fallback}");
        builder = builder.listener(ListenerSpec::tcp(fallback.as_str()));
    }
    for l in inherited {
        println!("inherited {:?} on {}", l.name, l.handle.local());
        builder = builder.listener(ListenerSpec::adopt(l.handle));
    }
    let server = builder
        .handler(|conn| conn.send_all(b"hello from a socket-activated service\n"))
        .gate(AllowAll)
        .build()?;
    server.open_door()?;
    println!("ready at MONOTONIC_USEC={}", net_io::monotonic_micros());
    let report = server.wait_for_stop();
    println!("stopped: {report:?}");
    Ok(())
}
