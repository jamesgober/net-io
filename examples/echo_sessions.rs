//! A line echo written as a sans-IO session: net-io reads and writes, the session
//! only decides what to send.
//!
//! ```text
//! cargo run --example echo_sessions -- 127.0.0.1:7002
//! ```
//!
//! Each complete line comes back upper-cased. A line longer than the input
//! buffer closes the connection (`CloseReason::Limit`).

use std::time::Duration;

use net_io::{
    AllowAll, CloseReason, ConnectionInfo, Input, Limits, ListenerSpec, NetError, Phase,
    ServerBuilder, Session, SessionContext, Step,
};

struct Upper;

impl Session for Upper {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let Some(end) = input.bytes().iter().position(|&b| b == b'\n') else {
            // Part of a line: keep reading under the read timeout and minimum rate.
            cx.set_phase(Phase::Receiving);
            return Step::Read;
        };
        let line = input.bytes()[..=end].to_ascii_uppercase();
        if cx.output().push(&line).is_err() {
            // Output full: flush first; net-io calls on_data again with the same input.
            return Step::Write;
        }
        input.consume(end + 1);
        // The exchange is over: wait for the next line under the idle timeout.
        cx.set_phase(Phase::Idle);
        Step::Write
    }

    fn on_close(&mut self, info: &ConnectionInfo, reason: CloseReason) {
        println!("{} from {} closed: {}", info.id, info.peer, reason.as_str());
    }
}

fn main() -> Result<(), NetError> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:7002".to_string());
    let limits = Limits::builder()
        .idle_timeout(Duration::from_secs(30))
        .read_timeout(Duration::from_secs(10))
        .build()?;
    let server = ServerBuilder::new()
        .listener(ListenerSpec::tcp(addr.as_str()).name("echo"))
        .workers(16)
        .limits(limits)
        .sessions(|_: &ConnectionInfo| Upper)
        .gate(AllowAll)
        .build()?;
    server.open_door()?;
    for l in server.listeners() {
        println!("echo (sessions) listening on {}", l.local);
    }
    let report = server.wait_for_stop();
    println!("stopped: {report:?}");
    Ok(())
}
