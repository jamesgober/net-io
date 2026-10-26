//! Killing one connection from another thread, then draining the server.
//!
//! ```text
//! cargo run --example kill_and_drain
//! ```
//!
//! Runs on its own and exits: it starts a server, connects three clients, kills
//! one by id, then drains with a deadline. Idle connections close at once; a
//! connection in the middle of an exchange is killed when the deadline passes.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use net_io::{
    CloseReason, ConnectionId, ConnectionInfo, Input, KillReason, NetError, Phase, Session,
    SessionContext, Step,
};

/// Echoes complete lines; a partial line keeps the exchange open.
struct Lines {
    opened: Option<mpsc::Sender<ConnectionId>>,
}

impl Session for Lines {
    fn on_open(&mut self, cx: &mut SessionContext<'_>) -> Step {
        if let Some(tx) = self.opened.take() {
            let _ = tx.send(cx.info().id);
        }
        Step::Read
    }

    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        match input.bytes().iter().position(|&b| b == b'\n') {
            Some(end) => {
                let taken = cx.output().push_partial(&input.bytes()[..=end]);
                input.consume(taken);
                cx.set_phase(Phase::Idle);
                Step::Write
            }
            None => {
                cx.set_phase(Phase::Receiving);
                Step::Read
            }
        }
    }

    fn on_close(&mut self, info: &ConnectionInfo, reason: CloseReason) {
        println!("  {} closed: {}", info.id, reason.as_str());
    }
}

fn main() -> Result<(), NetError> {
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let server = net_io::serve_sessions("127.0.0.1:0", move |_: &ConnectionInfo| Lines {
        opened: tx.lock().ok().map(|t| t.clone()),
    })?;
    let addr = server.listeners()[0]
        .local
        .socket_addr()
        .ok_or(NetError::Closed)?;

    // Three clients: one to kill, one idle, one stuck in the middle of a line.
    let mut clients = Vec::new();
    let mut ids = Vec::new();
    for _ in 0..3 {
        let c = TcpStream::connect(addr)?;
        ids.push(
            rx.recv_timeout(Duration::from_secs(5))
                .map_err(|_| NetError::Closed)?,
        );
        clients.push(c);
    }
    clients[1].write_all(b"hello\n")?;
    let mut echo = [0u8; 6];
    clients[1].read_exact(&mut echo)?;
    clients[2].write_all(b"half a li")?;
    std::thread::sleep(Duration::from_millis(50));

    println!("killing {}", ids[0]);
    let handle = server.handle();
    let killed = handle.kill(ids[0], KillReason(1));
    println!("  kill delivered: {killed}");
    std::thread::sleep(Duration::from_millis(50));

    println!("draining with a 300 ms deadline");
    let start = Instant::now();
    let report = server.shutdown(Instant::now() + Duration::from_millis(300));
    println!(
        "drained in {:?}: {} graceful, {} killed at the deadline",
        start.elapsed(),
        report.graceful,
        report.killed
    );
    Ok(())
}
