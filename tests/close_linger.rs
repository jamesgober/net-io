//! When a graceful close lingers, and what a drain reports when its deadline ends
//! a linger (D-201).
//!
//! A reply the session wrote after it set `Idle` for the exchange it answered is
//! an answer, not news the peer did not ask for: the connection takes the idle
//! shortcut and a drain closes it at once (D-192 kept it for that case). And a
//! drain whose deadline cuts a linger short reports the close as it was, on
//! both drivers.

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{DRIVERS, addr, client, eventually, round_trip};
use net_io::{
    AllowAll, CloseReason, ConnectionInfo, DriverKind, Event, EventSink, Input, Limits,
    ListenerSpec, Phase, Server, ServerBuilder, Session, SessionContext, Step,
};

#[derive(Clone, Default)]
struct Closes(Arc<Mutex<Vec<CloseReason>>>);

impl EventSink for Closes {
    fn event(&self, event: &Event) {
        if let Event::Closed { reason, .. } = event {
            if let Ok(mut v) = self.0.lock() {
                v.push(*reason);
            }
        }
    }
}

impl Closes {
    fn all(&self) -> Vec<CloseReason> {
        self.0.lock().map(|v| v.clone()).unwrap_or_default()
    }
}

/// Answers each complete line, setting `Idle` before it writes the reply, as a
/// session that ends its exchange in `on_data` does.
struct IdleThenReply;

impl Session for IdleThenReply {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let Some(end) = input.bytes().iter().position(|&b| b == b'\n') else {
            cx.set_phase(Phase::Receiving);
            return Step::Read;
        };
        cx.set_phase(Phase::Idle);
        let taken = cx.output().push_partial(&input.bytes()[..=end]);
        input.consume(taken);
        Step::Write
    }
}

/// Closes in the middle of an exchange, so the close lingers for input still on
/// its way.
struct CloseMidExchange;

impl Session for CloseMidExchange {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        input.consume(input.bytes().len());
        cx.set_phase(Phase::Receiving);
        Step::Close
    }
}

fn server<S: Session + 'static>(driver: DriverKind, closes: &Closes, make: fn() -> S) -> Server {
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .driver(driver)
        .workers(2)
        .limits(
            Limits::builder()
                .graceful_linger(Duration::from_secs(4), 64 * 1024)
                .build()
                .expect("limits"),
        )
        .sessions(move |_: &ConnectionInfo| make())
        .gate(AllowAll)
        .events(closes.clone())
        .build()
        .expect("build");
    server.open_door().expect("open");
    server
}

#[test]
fn test_a_drain_closes_an_answered_connection_without_the_linger() {
    for &driver in DRIVERS {
        let closes = Closes::default();
        let s = server(driver, &closes, || IdleThenReply);
        let mut c = client(addr(&s));
        assert_eq!(round_trip(&mut c, b"x\n"), b"x\n");
        // The client stays open and silent: a linger would wait out its 4 s bound.
        let report = s.drain(Instant::now() + Duration::from_secs(8));
        assert_eq!(
            (report.graceful, report.killed),
            (1, 0),
            "{driver:?}: {report:?}"
        );
        assert!(
            report.took < Duration::from_secs(2),
            "{driver:?}: the drain waited out a linger: {report:?}"
        );
        assert!(
            eventually(Duration::from_secs(5), || !closes.all().is_empty()),
            "{driver:?}: no close"
        );
        assert_eq!(closes.all(), [CloseReason::Drained], "{driver:?}");
        drop(c);
    }
}

#[test]
fn test_a_drain_deadline_that_ends_a_linger_keeps_the_close_reason() {
    for &driver in DRIVERS {
        let closes = Closes::default();
        let s = server(driver, &closes, || CloseMidExchange);
        let mut c = client(addr(&s));
        c.write_all(b"part").expect("write");
        // The session closes and its close lingers (4 s) for the rest of the request.
        assert!(
            eventually(Duration::from_secs(5), || s.stats().open == 1) && closes.all().is_empty(),
            "{driver:?}: the connection did not stay open in its linger"
        );
        // Time for the request to reach the session and its close to start lingering.
        std::thread::sleep(Duration::from_millis(300));
        let report = s.drain(Instant::now() + Duration::from_millis(200));
        assert!(
            report.took < Duration::from_secs(2),
            "{driver:?}: the deadline did not end the linger: {report:?}"
        );
        assert!(
            eventually(Duration::from_secs(5), || !closes.all().is_empty()),
            "{driver:?}: no close"
        );
        let all = closes.all();
        assert_eq!(all.len(), 1, "{driver:?}: {all:?}");
        assert!(
            !all[0].is_abortive(),
            "{driver:?}: a linger the drain ended closed as {:?}",
            all[0]
        );
        assert_eq!(
            (report.graceful, report.killed),
            (1, 0),
            "{driver:?}: {report:?}"
        );
        drop(c);
    }
}
