//! Helpers shared by the integration tests.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use net_io::Server;

/// The address of a server's first listener.
pub fn addr(server: &Server) -> SocketAddr {
    server.listeners()[0]
        .local
        .socket_addr()
        .expect("ip listener")
}

/// A plain std client with a 5 s timeout, so a broken test fails instead of hanging.
pub fn client(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    s.set_nodelay(true).expect("nodelay");
    s
}

/// Sends `msg` and reads back exactly as many bytes.
pub fn round_trip(s: &mut TcpStream, msg: &[u8]) -> Vec<u8> {
    s.write_all(msg).expect("write");
    let mut back = vec![0u8; msg.len()];
    s.read_exact(&mut back).expect("read");
    back
}

/// Reads until the server closes; `true` when it closed (EOF or reset) within 5 s.
pub fn closed_by_server(s: &mut TcpStream) -> bool {
    let mut buf = [0u8; 256];
    loop {
        match s.read(&mut buf) {
            Ok(0) => return true,
            Ok(_) => {}
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return false;
            }
            Err(_) => return true,
        }
    }
}

/// Polls `f` until it holds or `limit` passes.
pub fn eventually(limit: Duration, mut f: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + limit;
    while Instant::now() < end {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    f()
}

/// Connects a client the server is expected to refuse; `true` when it was refused
/// (a reset during connect, or EOF or reset on the first read within 5 s).
pub fn refused(addr: SocketAddr) -> bool {
    match TcpStream::connect(addr) {
        Err(_) => true,
        Ok(mut s) => {
            s.set_read_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
            closed_by_server(&mut s)
        }
    }
}
