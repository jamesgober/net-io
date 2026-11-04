//! UDP listeners on a server.

#![cfg(feature = "udp")]

mod common;

use std::net::{SocketAddr, UdpSocket as StdUdp};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use common::eventually;
use net_io::{
    AllowAll, ConnectionInfo, Input, ListenerInfo, ListenerSpec, NetError, ServerBuilder, Session,
    SessionContext, Step, UdpContext, UdpOptions, UdpSession,
};

const WAIT: Duration = Duration::from_secs(5);

/// Echoes, and verifies a peer that says `ok`.
struct Echo(Arc<AtomicU32>);

impl UdpSession for Echo {
    fn on_datagram(&mut self, cx: &mut UdpContext<'_>, from: SocketAddr, bytes: &[u8]) {
        self.0.fetch_add(1, Ordering::SeqCst);
        if bytes == b"ok" {
            cx.mark_verified(from);
        }
        if bytes == b"boom" {
            panic!("a session bug");
        }
        assert!(cx.now() <= Instant::now());
        let _ = cx.send_to(bytes, from);
    }
}

fn client(to: SocketAddr) -> StdUdp {
    let c = StdUdp::bind("127.0.0.1:0").expect("bind");
    c.connect(to).expect("connect");
    c.set_read_timeout(Some(WAIT)).expect("timeout");
    c
}

fn udp_addr(server: &net_io::Server) -> SocketAddr {
    server.listeners()[0].local.socket_addr().expect("ip")
}

#[test]
fn test_udp_only_server_echoes_and_survives_a_panic() {
    let seen = Arc::new(AtomicU32::new(0));
    let count = seen.clone();
    let server = ServerBuilder::new()
        .listener(ListenerSpec::udp("127.0.0.1:0", UdpOptions::new()))
        .udp_sessions(move |_: &ListenerInfo| Echo(count.clone()))
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let c = client(udp_addr(&server));
    let mut back = [0u8; 16];
    c.send(b"hello").expect("send");
    let n = c.recv(&mut back).expect("echo");
    assert_eq!(&back[..n], b"hello");
    c.send(b"boom").expect("send");
    assert!(eventually(WAIT, || seen.load(Ordering::SeqCst) == 2));
    c.send(b"again").expect("send");
    let n = c.recv(&mut back).expect("echo");
    assert_eq!(&back[..n], b"again");
}

/// The guard stands on a server: a reply never outgrows what the source sent.
#[test]
fn test_door_and_guard() {
    struct Amplify;
    impl UdpSession for Amplify {
        fn on_datagram(&mut self, cx: &mut UdpContext<'_>, from: SocketAddr, _: &[u8]) {
            let refused = cx.send_to(&[1u8; 500], from).is_err();
            let _ = cx.send_to(&[u8::from(refused)], from);
        }
    }
    let server = ServerBuilder::new()
        .listener(ListenerSpec::udp("127.0.0.1:0", UdpOptions::new()))
        .udp_sessions(|_: &ListenerInfo| Amplify)
        .gate(AllowAll)
        .build()
        .expect("build");
    let c = client(udp_addr(&server));
    c.send(b"x").expect("send");
    // The door is closed: the datagram waits.
    c.set_read_timeout(Some(Duration::from_millis(100)))
        .expect("timeout");
    let mut back = [0u8; 600];
    assert!(c.recv(&mut back).is_err());
    server.open_door().expect("open");
    c.set_read_timeout(Some(WAIT)).expect("timeout");
    assert_eq!(c.recv(&mut back).expect("one byte"), 1);
    assert_eq!(back[0], 1, "the 500-byte reply was refused");
}

struct Tcp;

impl Session for Tcp {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let taken = cx.output().push_partial(input.bytes());
        input.consume(taken);
        Step::Write
    }
}

#[test]
fn test_udp_beside_tcp_stops_with_the_server() {
    let seen = Arc::new(AtomicU32::new(0));
    let count = seen.clone();
    let server = ServerBuilder::new()
        .listener(ListenerSpec::udp("127.0.0.1:0", UdpOptions::new()))
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .sessions(|_: &ConnectionInfo| Tcp)
        .udp_sessions(move |_: &ListenerInfo| Echo(count.clone()))
        .gate(AllowAll)
        .build()
        .expect("build");
    server.open_door().expect("open");
    let c = client(udp_addr(&server));
    c.send(b"ok").expect("send");
    let mut back = [0u8; 4];
    assert_eq!(c.recv(&mut back).expect("echo"), 2);
    let started = Instant::now();
    drop(server);
    assert!(started.elapsed() < WAIT);
}

#[test]
fn test_mismatched_listeners_fail_build() {
    let no_factory = ServerBuilder::new()
        .listener(ListenerSpec::udp("127.0.0.1:0", UdpOptions::new()))
        .sessions(|_: &ConnectionInfo| Tcp)
        .gate(AllowAll)
        .build();
    assert!(matches!(no_factory, Err(NetError::InvalidConfig { .. })));
    let tcp_on_udp_only = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .udp_sessions(|_: &ListenerInfo| Echo(Arc::new(AtomicU32::new(0))))
        .gate(AllowAll)
        .build();
    assert!(matches!(
        tcp_on_udp_only,
        Err(NetError::InvalidConfig { .. })
    ));
}
