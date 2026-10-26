//! Started by a FastCGI process manager (Apache `mod_fcgid`, `spawn-fcgi`)?
//! Then descriptor 0 is the listening socket to serve; otherwise bind an
//! address. This example only detects and accepts: the FastCGI protocol itself
//! is fcgi-net's job.
//!
//! ```text
//! cargo run --example fastcgi_detect -- 127.0.0.1:7005
//! ```

#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use net_io::{AllowAll, ListenerSpec, ServerBuilder};

    let spec = match net_io::fastcgi_listener()? {
        Some(handle) => {
            println!("started by a FastCGI manager; serving {}", handle.local());
            ListenerSpec::adopt(handle)
        }
        None => {
            let addr = std::env::args()
                .nth(1)
                .unwrap_or_else(|| "127.0.0.1:7005".to_string());
            println!("descriptor 0 is not a listening socket; binding {addr}");
            ListenerSpec::tcp(addr.as_str())
        }
    };
    let server = ServerBuilder::new()
        .listener(spec)
        .handler(|conn| conn.send_all(b"accepted\n"))
        .gate(AllowAll)
        .build()?;
    server.open_door()?;
    let report = server.wait_for_stop();
    println!("stopped: {report:?}");
    Ok(())
}

#[cfg(not(unix))]
fn main() {
    eprintln!("the FastCGI descriptor 0 convention is Unix only (Windows: open decision OD-26)");
}
