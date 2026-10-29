//! A UDP echo server behind the guard: every datagram is charged to its
//! source's budget first, and replies to a source that has not proved it can
//! receive are never larger than what it sent (no amplification).
//!
//! ```text
//! cargo run --example udp_echo -- 127.0.0.1:7006
//! ```
//!
//! Try it with `nc -u 127.0.0.1 7006`. Truncated datagrams (larger than the
//! 1,500-byte buffer) are reported and skipped, never echoed cut.

use std::time::Duration;

use net_io::{LimitKind, NetError, UdpSocket};

fn main() -> Result<(), NetError> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:7006".to_string());
    let mut socket = UdpSocket::bind(addr.as_str())?;
    socket.set_read_timeout(Some(Duration::from_secs(30)))?;
    println!("udp echo on {}", socket.local_addr()?);
    let mut buf = [0u8; 1500];
    loop {
        let datagram = match socket.recv_from(&mut buf) {
            Ok(d) => d,
            Err(NetError::TimedOut { .. }) => {
                println!("quiet for 30 s: {:?}", socket.stats());
                continue;
            }
            Err(e) => return Err(e),
        };
        if datagram.truncated {
            println!("{} sent more than 1,500 bytes; skipped", datagram.from);
            continue;
        }
        match socket.send_to(&buf[..datagram.len], datagram.from) {
            Ok(_) => {}
            Err(NetError::Limit {
                which: LimitKind::Amplification,
            }) => println!(
                "{}: reply refused by the amplification guard",
                datagram.from
            ),
            Err(e) => return Err(e),
        }
    }
}
