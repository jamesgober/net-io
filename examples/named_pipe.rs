//! A control channel on a Windows named pipe, with the same connection API as a
//! socket. Only this user can open it, and remote clients are always rejected.
//!
//! Run with `cargo run --example named_pipe`.

#[cfg(windows)]
fn main() -> Result<(), net_io::NetError> {
    use std::time::Duration;

    use net_io::{PipeConnection, PipeListener};

    let name = format!("net-io-example-{}", std::process::id());
    let listener = PipeListener::create(&name)?;
    let client = {
        let name = name.clone();
        std::thread::spawn(move || -> Result<String, net_io::NetError> {
            let mut conn = PipeConnection::connect(&name, Duration::from_secs(5))?;
            conn.send_all(b"status\n")?;
            let mut reply = [0u8; 3];
            conn.recv_exact(&mut reply)?;
            Ok(String::from_utf8_lossy(&reply).into_owned())
        })
    };
    let (mut conn, info) = listener.accept()?;
    println!(
        "client process {:?}",
        info.peer_credentials.and_then(|c| c.pid)
    );
    let mut line = [0u8; 7];
    conn.recv_exact(&mut line)?;
    conn.send_all(b"ok\n")?;
    let reply = client.join().expect("client")?;
    println!("client read {:?}", reply.trim());
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    println!("named pipes are a Windows feature; see the unix_socket example");
}
