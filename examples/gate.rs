//! A connection gate: admission before any byte is read, and a check before every write.
//!
//! ```text
//! cargo run --example gate
//! ```
//!
//! Runs on its own and exits. The gate admits at most two connections per
//! client address (a third gets a one-line refusal), and denies any write once a
//! connection has sent 64 bytes. A real deployment plugs in its own gate, such
//! as a firewall or rate limiter; net-io only defines the trait.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::sync::Mutex;
use std::time::Duration;

use net_io::{
    AdmitStage, Admitted, CloseReason, ConnectionInfo, Denial, Gate, GateTag, Lane, ListenerSpec,
    NetError, Refusal, ServerBuilder, TcpConnection, WriteCheck,
};

const PER_ADDRESS: u32 = 2;
const BYTES_PER_CONNECTION: u64 = 64;

#[derive(Default)]
struct PerAddress {
    open: Mutex<HashMap<IpAddr, u32>>,
}

/// The gate's state for one connection.
struct Ticket {
    ip: IpAddr,
    sent: u64,
}

impl Gate for PerAddress {
    type Ticket = Ticket;

    fn admit(
        &self,
        info: &ConnectionInfo,
        _stage: AdmitStage,
    ) -> Result<Admitted<Ticket>, Refusal> {
        // Unix sockets and pipes have no IP; this gate refuses them.
        let ip = info.client_addr().ok_or(Refusal::Reset { code: 4 })?.ip();
        let mut open = self.open.lock().map_err(|_| Refusal::Reset { code: 1 })?;
        let n = open.entry(ip).or_insert(0);
        if *n >= PER_ADDRESS {
            return Err(Refusal::WithBytes {
                code: 2,
                bytes: b"too many connections\n",
            });
        }
        *n += 1;
        Ok(Admitted {
            lane: Lane(0),
            ticket: Ticket { ip, sent: 0 },
            tag: GateTag(0),
        })
    }

    fn readmit(&self, _ticket: &mut Ticket, _info: &ConnectionInfo) -> Result<(), Refusal> {
        Ok(())
    }

    fn check(&self, ticket: &mut Ticket, write: &WriteCheck) -> Result<(), Denial> {
        ticket.sent += u64::from(write.bytes);
        if ticket.sent > BYTES_PER_CONNECTION {
            return Err(Denial { code: 3 });
        }
        Ok(())
    }

    fn closed(&self, ticket: Ticket, info: &ConnectionInfo, reason: CloseReason) {
        if let Ok(mut open) = self.open.lock() {
            if let Some(n) = open.get_mut(&ticket.ip) {
                *n = n.saturating_sub(1);
            }
        }
        println!("  {} closed: {}", info.id, reason.as_str());
    }
}

fn echo(conn: &mut TcpConnection) -> Result<(), NetError> {
    let mut buf = [0u8; 256];
    loop {
        let n = conn.recv(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        conn.send_all(&buf[..n])?;
    }
}

fn main() -> Result<(), NetError> {
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .workers(4)
        .handler(echo)
        .gate(PerAddress::default())
        .build()?;
    server.open_door()?;
    let addr = server.listeners()[0]
        .local
        .socket_addr()
        .ok_or(NetError::Closed)?;

    let mut a = TcpStream::connect(addr)?;
    let _b = TcpStream::connect(addr)?;
    std::thread::sleep(Duration::from_millis(50));
    let mut c = TcpStream::connect(addr)?;
    c.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut refusal = String::new();
    let _ = c.read_to_string(&mut refusal);
    println!("third connection: {:?}", refusal.trim_end());

    a.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut echoed = [0u8; 40];
    a.write_all(&[b'x'; 40])?;
    a.read_exact(&mut echoed)?;
    println!("first 40 bytes echoed");
    a.write_all(&[b'y'; 40])?;
    let mut rest = Vec::new();
    let r = a.read_to_end(&mut rest);
    println!(
        "next 40 bytes: write denied by the gate, connection closed ({} bytes, {:?})",
        rest.len(),
        r.err().map(|e| e.kind())
    );

    // The worker counts the close right after the reset; give it a moment.
    let until = std::time::Instant::now() + Duration::from_secs(2);
    while server.stats().egress_denied == 0 && std::time::Instant::now() < until {
        std::thread::sleep(Duration::from_millis(5));
    }
    let stats = server.stats();
    println!(
        "refused {}, egress denied {}",
        stats.refused, stats.egress_denied
    );
    Ok(())
}
