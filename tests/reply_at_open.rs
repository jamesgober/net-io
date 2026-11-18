//! A reply written at open, before the first read, then a close (serve-net's busy
//! refusal at its soft cap): the client's request is already on its way, and a
//! close that skips the linger answers it with a reset, after which Windows
//! discards the reply the client already holds (D-192).

mod common;

use std::io::{Read, Write};
use std::time::Duration;

use common::{DRIVERS, addr, client};
use net_io::{
    AllowAll, ConnectionInfo, Input, ListenerSpec, ServerBuilder, Session, SessionContext, Step,
};

const REFUSAL: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";

struct Refuse;

impl Session for Refuse {
    fn on_open(&mut self, cx: &mut SessionContext<'_>) -> Step {
        let _ = cx.output().push(REFUSAL);
        Step::Close
    }

    fn on_data(&mut self, _: &mut SessionContext<'_>, _: &mut Input) -> Step {
        Step::Close
    }
}

#[test]
fn test_a_reply_at_open_survives_the_request_already_sent() {
    for &driver in DRIVERS {
        let server = ServerBuilder::new()
            .listener(ListenerSpec::tcp("127.0.0.1:0"))
            .driver(driver)
            .workers(4)
            .sessions(|_: &ConnectionInfo| Refuse)
            .gate(AllowAll)
            .build()
            .expect("build");
        server.open_door().expect("open");
        for round in 0..40 {
            let mut c = client(addr(&server));
            c.set_read_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
            // The request goes out after the server's close, as a client's does when
            // the reply and the close cross it on the way.
            std::thread::sleep(Duration::from_millis(30));
            c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                .expect("request");
            let mut got = Vec::new();
            let result = c.read_to_end(&mut got);
            assert!(
                got.starts_with(REFUSAL),
                "{driver:?} round {round}: {result:?}, got {} bytes",
                got.len()
            );
        }
    }
}
