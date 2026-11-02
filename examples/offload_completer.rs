//! A session parks while a worker thread of your own does slow work, and a
//! [`Completer`](net_io::Completer) brings the result back to the event loop.
//!
//! Run with `cargo run --example offload_completer`.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use net_io::{
    ConnectionId, ConnectionInfo, Input, NetError, ServerHandle, Session, SessionContext, Step,
};

/// What goes to the offload thread: who asked, and the number to work on.
struct Job {
    done: net_io::Completer,
    conn: ConnectionId,
    value: u64,
}

struct Doubler {
    jobs: mpsc::Sender<Job>,
}

impl Session for Doubler {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let Some(end) = input.bytes().iter().position(|b| *b == b'\n') else {
            return Step::Read;
        };
        let value = std::str::from_utf8(&input.bytes()[..end])
            .ok()
            .and_then(|t| t.trim().parse().ok())
            .unwrap_or(0);
        input.consume(end + 1);
        let job = Job {
            done: cx.completer(),
            conn: cx.info().id,
            value,
        };
        if self.jobs.send(job).is_err() {
            return Step::Close;
        }
        // The worker goes on with other connections; `on_wake` continues this one.
        Step::Park {
            until: Some(Instant::now() + Duration::from_secs(5)),
        }
    }

    fn on_wake(&mut self, cx: &mut SessionContext<'_>, _token: u32, value: u64) -> Step {
        let _ = cx.output().push(format!("{value}\n").as_bytes());
        Step::Write
    }
}

fn main() -> Result<(), NetError> {
    let (tx, rx) = mpsc::channel::<Job>();
    thread::spawn(move || {
        for job in rx {
            thread::sleep(Duration::from_millis(20));
            let _ = job.done.post(job.conn, 0, job.value * 2);
        }
    });
    let server = net_io::serve_sessions("127.0.0.1:0", move |_: &ConnectionInfo| Doubler {
        jobs: tx.clone(),
    })?;
    let addr = server.listeners()[0].local.socket_addr().expect("tcp");
    let handle: ServerHandle = server.handle();
    let mut client = TcpStream::connect(addr).expect("connect");
    client.write_all(b"21\n").expect("write");
    let mut reply = [0u8; 3];
    client.read_exact(&mut reply).expect("read");
    println!("21 doubled is {}", String::from_utf8_lossy(&reply).trim());
    handle.request_stop();
    Ok(())
}
