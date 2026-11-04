//! The outbound client: health probes, drain, and reconnecting with backoff.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use net_io::{Backoff, ConnectOptions, Health, NetError, TcpConnection};

fn listener() -> (TcpListener, SocketAddr) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let at = l.local_addr().expect("addr");
    (l, at)
}

fn eventually_health(conn: &mut TcpConnection, want: Health) -> Result<Health, NetError> {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let h = conn.probe()?;
        if h == want || Instant::now() > until {
            return Ok(h);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn test_probe_sees_open_readable_and_peer_closed_without_consuming() {
    let (l, at) = listener();
    let mut conn = TcpConnection::connect(at).expect("connect");
    let (mut server, _) = l.accept().expect("accept");
    assert_eq!(conn.probe().expect("probe"), Health::Open);
    server.write_all(b"hello").expect("write");
    assert_eq!(
        eventually_health(&mut conn, Health::Readable).expect("probe"),
        Health::Readable
    );
    // Nothing was consumed.
    let mut buf = [0u8; 5];
    conn.recv_exact(&mut buf).expect("recv");
    assert_eq!(&buf, b"hello");
    assert_eq!(conn.probe().expect("probe"), Health::Open);
    server.shutdown(Shutdown::Write).expect("fin");
    assert_eq!(
        eventually_health(&mut conn, Health::PeerClosed).expect("probe"),
        Health::PeerClosed
    );
}

#[test]
fn test_probe_reports_a_reset() {
    let l = net_io::TcpListener::bind("127.0.0.1:0").expect("bind");
    let at = l.local_addr().expect("addr");
    let mut conn = TcpConnection::connect(at).expect("connect");
    let (server, _) = l.accept().expect("accept");
    server.abort();
    let until = Instant::now() + Duration::from_secs(5);
    let result = loop {
        match conn.probe() {
            Ok(Health::Open) if Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(5));
            }
            other => break other,
        }
    };
    assert!(
        matches!(result, Err(NetError::ConnectionReset)),
        "{result:?}"
    );
}

#[test]
fn test_drain_waits_for_the_peers_fin() {
    let (l, at) = listener();
    let conn = TcpConnection::connect(at).expect("connect");
    let (mut server, _) = l.accept().expect("accept");
    let peer = std::thread::spawn(move || {
        // A reply still in flight when the client drains, then the server's own FIN
        // once it sees the client's.
        server.write_all(&[9u8; 10_000]).expect("write");
        let mut rest = Vec::new();
        server.read_to_end(&mut rest).expect("read");
        server.shutdown(Shutdown::Write).expect("fin");
        rest.len()
    });
    let started = Instant::now();
    let d = conn.drain(Duration::from_secs(5));
    assert!(d.peer_closed, "{d:?}");
    assert_eq!(d.discarded, 10_000);
    assert!(started.elapsed() < Duration::from_secs(4));
    assert_eq!(peer.join().expect("peer"), 0);
}

#[test]
fn test_drain_gives_up_at_its_deadline() {
    let (l, at) = listener();
    let conn = TcpConnection::connect(at).expect("connect");
    let (server, _) = l.accept().expect("accept");
    let started = Instant::now();
    let d = conn.drain(Duration::from_millis(300));
    let took = started.elapsed();
    assert!(!d.peer_closed, "{d:?}");
    assert!(
        took >= Duration::from_millis(250) && took < Duration::from_secs(3),
        "{took:?}"
    );
    drop(server);
}

#[test]
fn test_connect_retry_finds_a_server_that_comes_back() {
    // A port that was free a moment ago, with nobody on it yet.
    let at = {
        let (l, at) = listener();
        drop(l);
        at
    };
    let back = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(400));
        let l = TcpListener::bind(at).expect("rebind");
        let (mut s, _) = l.accept().expect("accept");
        s.write_all(b"up").expect("write");
        s
    });
    let mut backoff = Backoff::new()
        .first(Duration::from_millis(20))
        .max(Duration::from_millis(100))
        .give_up_after(Duration::from_secs(20));
    let options = ConnectOptions::new().timeout(Duration::from_secs(2));
    let mut conn = TcpConnection::connect_retry(at, options, &mut backoff).expect("reconnect");
    let mut buf = [0u8; 2];
    conn.recv_exact(&mut buf).expect("recv");
    assert_eq!(&buf, b"up");
    // Windows retries a refused SYN for about 2 s (spike S-5), so there the first
    // attempt can outlast the outage.
    if cfg!(not(windows)) {
        assert!(backoff.attempt() >= 1, "{}", backoff.attempt());
    }
    drop(back.join().expect("server"));
}

#[test]
fn test_connect_retry_stops_when_the_backoff_is_spent() {
    let at = {
        let (l, at) = listener();
        drop(l);
        at
    };
    let mut backoff = Backoff::new()
        .first(Duration::from_millis(10))
        .jitter(false)
        .attempts(2);
    let result = TcpConnection::connect_retry(at, ConnectOptions::new(), &mut backoff);
    assert!(result.is_err(), "{:?}", result.map(|c| c.peer_addr()));
    assert_eq!(backoff.attempt(), 2);
}

#[test]
fn test_connect_retry_returns_a_configuration_error_at_once() {
    let (_l, at) = listener();
    // A local address this host does not have.
    let options = ConnectOptions::new().local_addr("192.0.2.1:0".parse().expect("addr"));
    let mut backoff = Backoff::new();
    let result = TcpConnection::connect_retry(at, options, &mut backoff);
    assert!(result.is_err());
    assert_eq!(backoff.attempt(), 0);
    let _ = TcpStream::connect(at);
}
