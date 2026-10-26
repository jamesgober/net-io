//! Property: random interleavings of FIN, RST, kill, timeouts, and a final drain
//! give every admitted connection exactly one `Closed` event.

mod common;

use std::collections::HashMap;
use std::io::Write;
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{addr, eventually};
use net_io::{
    AllowAll, ConnectionInfo, Event, EventSink, Input, KillReason, Limits, ListenerSpec, Phase,
    ServerBuilder, Session, SessionContext, Step,
};

/// Admitted ids in order, and closes per id.
type Book = (Vec<u64>, HashMap<u64, u32>);

#[derive(Clone, Default)]
struct Ledger(Arc<Mutex<Book>>);

impl EventSink for Ledger {
    fn event(&self, event: &Event) {
        let Ok(mut l) = self.0.lock() else { return };
        match event {
            Event::Admitted { id, .. } => l.0.push(id.get()),
            Event::Closed { id, .. } => *l.1.entry(id.get()).or_insert(0) += 1,
            _ => {}
        }
    }
}

/// Echoes complete lines; a partial line keeps the exchange open.
struct Lines;

impl Session for Lines {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let Some(end) = input.bytes().iter().position(|&b| b == b'\n') else {
            cx.set_phase(Phase::Receiving);
            return Step::Read;
        };
        let taken = cx.output().push_partial(&input.bytes()[..=end]);
        input.consume(taken);
        cx.set_phase(Phase::Idle);
        Step::Write
    }
}

/// xorshift64*, seeded: a failure reproduces.
struct Gen(u64);

impl Gen {
    fn below(&mut self, n: u64) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D) % n
    }
}

#[test]
fn prop_every_connection_closes_exactly_once() {
    let ledger = Ledger::default();
    let limits = Limits::builder()
        .idle_timeout(Duration::from_millis(60))
        .read_timeout(Duration::from_millis(60))
        .build()
        .expect("limits");
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .workers(64)
        .limits(limits)
        .sessions(|_: &ConnectionInfo| Lines)
        .gate(AllowAll)
        .events(ledger.clone())
        .build()
        .expect("build");
    server.open_door().expect("open");
    let a = addr(&server);
    let handle = server.handle();
    let mut g = Gen(0x1D7E_51EA);
    let mut clients = Vec::new();
    for round in 0..240u64 {
        let action = g.below(6);
        let wait = Duration::from_millis(g.below(30));
        let send = g.below(3);
        clients.push(std::thread::spawn(move || {
            if action == 1 {
                // RST: net-io's abort closes with linger 0.
                let Ok(mut conn) = net_io::connect(a) else {
                    return;
                };
                if send > 0 {
                    let _ = conn.send_all(b"partial");
                }
                std::thread::sleep(wait);
                conn.abort();
                return;
            }
            let Ok(mut s) = TcpStream::connect(a) else {
                return;
            };
            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            match send {
                0 => {}
                1 => {
                    let _ = s.write_all(b"partial");
                }
                _ => {
                    let _ = s.write_all(b"line\n");
                }
            }
            std::thread::sleep(wait);
            match action {
                // FIN, then wait for the server's close.
                0 => {
                    let _ = s.shutdown(std::net::Shutdown::Write);
                    let mut b = Vec::new();
                    let _ = std::io::Read::read_to_end(&mut s, &mut b);
                }
                // Stay until a timeout, a kill, or the drain closes it.
                _ => {
                    let mut b = [0u8; 64];
                    while matches!(std::io::Read::read(&mut s, &mut b), Ok(n) if n > 0) {}
                }
            }
        }));
        // Kill a random admitted connection now and then (may already be closed).
        if round % 3 == 0 {
            let ids = ledger.0.lock().map(|l| l.0.clone()).unwrap_or_default();
            if !ids.is_empty() {
                let id = ids[g.below(ids.len() as u64) as usize];
                if let Some(id) = net_io::ConnectionId::new(id) {
                    let _ = handle.kill(id, KillReason(9));
                }
            }
        }
        std::thread::sleep(Duration::from_millis(g.below(5)));
    }
    let report = server.drain(Instant::now() + Duration::from_millis(200));
    for c in clients {
        let _ = c.join();
    }
    let all_closed = || {
        ledger
            .0
            .lock()
            .map(|l| l.0.iter().all(|id| l.1.get(id).is_some_and(|&n| n >= 1)))
            .unwrap_or(false)
    };
    assert!(
        eventually(Duration::from_secs(5), all_closed),
        "some connection never closed"
    );
    let (admitted, closes) = ledger
        .0
        .lock()
        .map(|l| (l.0.clone(), l.1.clone()))
        .expect("lock");
    assert!(admitted.len() > 40, "too few admitted: {}", admitted.len());
    for id in &admitted {
        assert_eq!(
            closes.get(id),
            Some(&1),
            "connection {id} closed {:?} times",
            closes.get(id)
        );
    }
    assert_eq!(closes.len(), admitted.len(), "a close without an admission");
    let stats = server.stats();
    assert_eq!(stats.closed, admitted.len() as u64);
    assert_eq!(stats.open, 0);
    let _ = report;
}
