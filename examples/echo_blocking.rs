//! A blocking echo server: one handler call per connection, on a pool worker.
//!
//! ```text
//! cargo run --example echo_blocking -- 127.0.0.1:7001
//! ```
//!
//! Try it with `nc 127.0.0.1 7001`. Every read and write runs under the default
//! limits: a 5 s idle timeout between exchanges, 30 s read and write timeouts
//! inside one, and a minimum transfer rate.

use net_io::{NetError, TcpConnection};

fn echo(conn: &mut TcpConnection) -> Result<(), NetError> {
    let mut buf = [0u8; 4096];
    loop {
        let n = conn.recv(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        conn.send_all(&buf[..n])?;
    }
}

fn main() -> Result<(), NetError> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:7001".to_string());
    let server = net_io::serve(addr.as_str(), echo)?;
    for l in server.listeners() {
        println!("echo (blocking) listening on {}", l.local);
    }
    let report = server.wait_for_stop();
    println!("stopped: {report:?}");
    Ok(())
}
