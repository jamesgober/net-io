//! Threat T-40: a `Server` used in a child after `fork` refuses its cold calls
//! (`ForkedChild`) instead of sharing the parent's sockets and threads.

#![cfg(unix)]

mod common;

use net_io::{
    AllowAll, ConnectionInfo, Input, NetError, ServerBuilder, Session, SessionContext, Step,
};

struct Echo;

impl Session for Echo {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let taken = cx.output().push_partial(input.bytes());
        input.consume(taken);
        Step::Write
    }
}

#[test]
fn test_server_in_a_forked_child_refuses_cold_calls() {
    let server = ServerBuilder::new()
        .listener(net_io::ListenerSpec::tcp("127.0.0.1:0"))
        .sessions(|_: &ConnectionInfo| Echo)
        .gate(AllowAll)
        .build()
        .expect("build");
    // SAFETY: the child calls only `open_door` (a pid comparison before anything
    // else, no allocation) and `_exit`; it never touches locks other threads held.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        let code = match server.open_door() {
            Err(NetError::ForkedChild) => 0,
            _ => 1,
        };
        // SAFETY: `_exit` skips the parent's destructors and atexit handlers.
        unsafe { libc::_exit(code) };
    }
    let mut status = 0;
    // SAFETY: waits for the child this test created.
    let waited = unsafe { libc::waitpid(pid, &raw mut status, 0) };
    assert_eq!(waited, pid);
    assert!(libc::WIFEXITED(status), "child did not exit: {status}");
    assert_eq!(libc::WEXITSTATUS(status), 0, "the child was not refused");
    // The parent's server is untouched.
    server.open_door().expect("parent opens");
    let mut c = common::client(common::addr(&server));
    assert_eq!(common::round_trip(&mut c, b"still mine"), b"still mine");
}
