//! A Unix domain socket server and client in one run: the server's socket file
//! is mode 0600 (only this user may connect), the server sees the client's
//! process and user ids, and the file is removed when the listener drops.
//!
//! ```text
//! cargo run --example unix_socket
//! ```

#[cfg(unix)]
fn main() -> Result<(), net_io::NetError> {
    use net_io::{LocalOptions, NetError, UnixConnection, UnixListener};

    let dir = std::env::temp_dir().join(format!("net-io-example-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| NetError::Os {
        op: "mkdir",
        source: e,
    })?;
    let path = dir.join("api.sock");
    // bind_atomic: the path appears only once the socket listens with its mode.
    let listener = UnixListener::bind_atomic(&path, LocalOptions::new())?;
    println!("listening on {}", path.display());

    let client_path = path.clone();
    let client = std::thread::spawn(move || -> Result<String, NetError> {
        let mut conn = UnixConnection::connect(&client_path)?;
        conn.send_all(b"status\n")?;
        let mut reply = [0u8; 64];
        let n = conn.recv(&mut reply)?;
        Ok(String::from_utf8_lossy(&reply[..n]).into_owned())
    });

    let (mut conn, info) = listener.accept()?;
    let who = info.peer_credentials;
    println!(
        "peer: pid {:?}, uid {:?}, gid {:?}",
        who.and_then(|c| c.pid),
        who.and_then(|c| c.uid),
        who.and_then(|c| c.gid)
    );
    let mut request = [0u8; 64];
    let n = conn.recv(&mut request)?;
    println!("request: {:?}", String::from_utf8_lossy(&request[..n]));
    conn.send_all(b"ready\n")?;
    conn.close()?;
    match client.join() {
        Ok(reply) => println!("client got: {:?}", reply?),
        Err(_) => eprintln!("the client thread panicked"),
    }
    drop(listener);
    println!("socket file removed: {}", !path.exists());
    let _ = std::fs::remove_dir(&dir);
    Ok(())
}

#[cfg(not(unix))]
fn main() {
    eprintln!("Unix domain sockets on Windows arrive in net-io 0.5.0");
}
