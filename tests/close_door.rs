//! `close_door` and an admission already under way: when `close_door` returns, no
//! connection is admitted after it. A gate that holds one admission open stands in
//! for anything between the accept thread's door check and the hand-over (the
//! accept call itself, the caps, the gate). Every test runs on both drivers.

mod common;

use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{DRIVERS, addr, client, eventually};
use net_io::{
    AdmitStage, Admitted, ConnectionInfo, Denial, DoorState, DriverKind, Gate, GateTag, Input,
    Lane, ListenerSpec, Refusal, Server, ServerBuilder, ServerHandle, Session, SessionContext,
    Step, WriteCheck,
};

const WAIT: Duration = Duration::from_secs(5);

struct Echo;

impl Session for Echo {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let taken = cx.output().push_partial(input.bytes());
        input.consume(taken);
        Step::Write
    }
}

/// Holds the first admission until the test lets it go.
struct Hold {
    entered: Mutex<Option<mpsc::Sender<()>>>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl Gate for Hold {
    type Ticket = ();
    fn admit(&self, _info: &ConnectionInfo, _stage: AdmitStage) -> Result<Admitted<()>, Refusal> {
        let first = self.entered.lock().map(|mut e| e.take()).ok().flatten();
        if let Some(tx) = first {
            let _ = tx.send(());
            if let Ok(rx) = self.release.lock() {
                let _ = rx.recv_timeout(WAIT);
            }
        }
        Ok(Admitted {
            lane: Lane(0),
            ticket: (),
            tag: GateTag(0),
        })
    }
    fn readmit(&self, _t: &mut (), _i: &ConnectionInfo) -> Result<(), Refusal> {
        Ok(())
    }
    fn check(&self, _t: &mut (), _w: &WriteCheck) -> Result<(), Denial> {
        Ok(())
    }
}

fn held(driver: DriverKind) -> (Server, mpsc::Receiver<()>, mpsc::Sender<()>) {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp("127.0.0.1:0"))
        .driver(driver)
        .sessions(|_: &ConnectionInfo| Echo)
        .gate(Hold {
            entered: Mutex::new(Some(entered_tx)),
            release: Mutex::new(release_rx),
        })
        .build()
        .expect("build");
    server.open_door().expect("open");
    (server, entered_rx, release_tx)
}

#[test]
fn close_door_admits_nothing_after_it_returns() {
    for &driver in DRIVERS {
        let (server, entered, release) = held(driver);
        let server = Arc::new(server);
        let _c = client(addr(&server));
        entered.recv_timeout(WAIT).expect("admission under way");

        let closer = {
            let server = server.clone();
            std::thread::spawn(move || {
                server.close_door();
                (Instant::now(), server.stats().accepted)
            })
        };
        // Long enough for a `close_door` that does not wait to have returned.
        std::thread::sleep(Duration::from_millis(200));
        let released = Instant::now();
        release.send(()).expect("release");
        let (returned, accepted_at_return) = closer.join().expect("closer");

        assert!(
            returned >= released,
            "{driver:?}: close_door returned while an admission was under way"
        );
        // Nothing moves after it returned.
        std::thread::sleep(Duration::from_millis(200));
        let s = server.stats();
        assert_eq!(
            s.accepted, accepted_at_return,
            "{driver:?}: a connection was admitted after close_door returned"
        );
        assert_eq!(s.accepted + s.refused, 1, "{driver:?}: {s:?}");
    }
}

#[test]
fn close_door_from_inside_the_gate_does_not_wait_for_itself() {
    struct Closer(Arc<Mutex<Option<ServerHandle>>>);
    impl Gate for Closer {
        type Ticket = ();
        fn admit(
            &self,
            _info: &ConnectionInfo,
            _stage: AdmitStage,
        ) -> Result<Admitted<()>, Refusal> {
            let handle = self.0.lock().ok().and_then(|h| h.clone());
            if let Some(h) = handle {
                h.close_door();
            }
            Ok(Admitted {
                lane: Lane(0),
                ticket: (),
                tag: GateTag(0),
            })
        }
        fn readmit(&self, _t: &mut (), _i: &ConnectionInfo) -> Result<(), Refusal> {
            Ok(())
        }
        fn check(&self, _t: &mut (), _w: &WriteCheck) -> Result<(), Denial> {
            Ok(())
        }
    }
    for &driver in DRIVERS {
        let slot = Arc::new(Mutex::new(None));
        let server = ServerBuilder::new()
            .listener(ListenerSpec::tcp("127.0.0.1:0"))
            .driver(driver)
            .sessions(|_: &ConnectionInfo| Echo)
            .gate(Closer(slot.clone()))
            .build()
            .expect("build");
        if let Ok(mut s) = slot.lock() {
            *s = Some(server.handle());
        }
        server.open_door().expect("open");
        let _c = client(addr(&server));
        assert!(
            eventually(WAIT, || server.stats().accepted == 1),
            "{driver:?}: the admission that closed the door finished"
        );
        assert_eq!(server.door(), DoorState::Closed, "{driver:?}");
    }
}
