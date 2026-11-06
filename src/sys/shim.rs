//! Fault injection for tests (decision D-045).
//!
//! Compiled only under `cfg(test)` or the custom cfg `net_io_shim`, never as a
//! Cargo feature. Each `sys` call site asks the shim first; a test programs
//! rules such as "the 3rd `send` returns 7 bytes" or "the next `accept` fails
//! with `EMFILE`". With no rule programmed the check is one atomic load.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// A `sys` call site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Op {
    /// Socket creation.
    Socket,
    /// Outbound connect.
    Connect,
    /// Accept.
    Accept,
    /// Receive.
    Recv,
    /// Send.
    Send,
    /// A wait (`poll` / `WSAPoll`).
    Wait,
    /// Reopening the spare descriptor of the `EMFILE` routine.
    Reserve,
    /// Setting the receive timeout (`SO_RCVTIMEO`).
    RecvTimeout,
    /// Binding a socket to an address.
    Bind,
    /// `listen` on a bound socket.
    Listen,
    /// Setting an integer socket option (`setsockopt`).
    SetOption,
    /// Registering a socket with a driver (`epoll_ctl`, `kevent`, a completion port).
    Register,
}

const OPS: usize = 12;

/// Every site, for the test that each one has a call site and an injected-error test.
#[cfg(test)]
const ALL: [Op; OPS] = [
    Op::Socket,
    Op::Connect,
    Op::Accept,
    Op::Recv,
    Op::Send,
    Op::Wait,
    Op::Reserve,
    Op::RecvTimeout,
    Op::Bind,
    Op::Listen,
    Op::SetOption,
    Op::Register,
];

/// What a matching call does instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Fault {
    /// Fail with this OS error number.
    Os(i32),
    /// Fail with this error kind.
    Kind(io::ErrorKind),
    /// Move at most this many bytes (`Recv`, `Send`).
    Short(usize),
    /// Fail with `Interrupted` (the caller retries).
    Interrupt,
}

#[derive(Debug)]
struct Rule {
    op: Op,
    skip: u32,
    times: u32,
    fault: Fault,
    /// Only calls from this thread match (unit tests run in parallel threads).
    thread: Option<std::thread::ThreadId>,
}

static ACTIVE: AtomicBool = AtomicBool::new(false);
static COUNTING: AtomicBool = AtomicBool::new(false);
static COUNTS: [AtomicU64; OPS] = [const { AtomicU64::new(0) }; OPS];

/// Counts calls per site from now on (system calls per operation, B-13).
#[allow(dead_code)]
pub fn start_counting() {
    for c in &COUNTS {
        c.store(0, Ordering::SeqCst);
    }
    COUNTING.store(true, Ordering::SeqCst);
}

/// Stops counting.
#[allow(dead_code)]
pub fn stop_counting() {
    COUNTING.store(false, Ordering::SeqCst);
}

/// Calls of `op` while counting.
#[allow(dead_code)]
pub fn counted(op: Op) -> u64 {
    COUNTS[op as usize].load(Ordering::SeqCst)
}

#[inline]
fn tally(op: Op) {
    if COUNTING.load(Ordering::Relaxed) {
        COUNTS[op as usize].fetch_add(1, Ordering::Relaxed);
    }
}
static RULES: Mutex<Vec<Rule>> = Mutex::new(Vec::new());

fn rules() -> MutexGuard<'static, Vec<Rule>> {
    RULES.lock().unwrap_or_else(PoisonError::into_inner)
}

/// After `skip` matching calls pass untouched, the next `times` calls of `op` get `fault`.
#[allow(dead_code)]
pub fn program(op: Op, skip: u32, times: u32, fault: Fault) {
    rules().push(Rule {
        op,
        skip,
        times,
        fault,
        thread: None,
    });
    ACTIVE.store(true, Ordering::SeqCst);
}

/// As [`program`], matching only calls made by the calling thread.
#[allow(dead_code)]
pub(crate) fn program_here(op: Op, skip: u32, times: u32, fault: Fault) {
    let thread = Some(std::thread::current().id());
    rules().push(Rule {
        op,
        skip,
        times,
        fault,
        thread,
    });
    ACTIVE.store(true, Ordering::SeqCst);
}

/// Removes the calling thread's rules.
#[allow(dead_code)]
pub(crate) fn clear_here() {
    let me = std::thread::current().id();
    rules().retain(|r| r.thread != Some(me));
}

/// Removes every rule.
#[allow(dead_code)]
pub fn clear() {
    rules().clear();
    ACTIVE.store(false, Ordering::SeqCst);
}

fn take(op: Op) -> Option<Fault> {
    if !ACTIVE.load(Ordering::Relaxed) {
        return None;
    }
    let me = std::thread::current().id();
    let mut rules = rules();
    let rule = rules
        .iter_mut()
        .find(|r| r.op == op && r.times > 0 && r.thread.is_none_or(|t| t == me))?;
    if rule.skip > 0 {
        rule.skip -= 1;
        return None;
    }
    rule.times -= 1;
    Some(rule.fault)
}

fn to_error(fault: Fault) -> Option<io::Error> {
    match fault {
        Fault::Os(code) => Some(io::Error::from_raw_os_error(code)),
        Fault::Kind(kind) => Some(io::Error::from(kind)),
        Fault::Interrupt => Some(io::Error::from(io::ErrorKind::Interrupted)),
        Fault::Short(_) => None,
    }
}

/// For calls that move no bytes: an injected error, if any.
pub(crate) fn check(op: Op) -> io::Result<()> {
    tally(op);
    match take(op).and_then(to_error) {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// For calls that move bytes: an injected error, or a cap on the length.
pub(crate) fn io(op: Op, len: usize) -> io::Result<Option<usize>> {
    tally(op);
    match take(op) {
        None => Ok(None),
        Some(Fault::Short(n)) => Ok(Some(n.min(len))),
        Some(other) => match to_error(other) {
            Some(e) => Err(e),
            None => Ok(None),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every site the shim knows is wired into `sys` and has a test that injects an
    /// error there; a new site without both fails here.
    #[test]
    fn test_every_site_is_called_and_tested() {
        let sys = [
            include_str!("unix.rs"),
            include_str!("windows.rs"),
            include_str!("epoll.rs"),
            include_str!("kqueue.rs"),
            include_str!("iocp.rs"),
            include_str!("poll.rs"),
            include_str!("../accept.rs"),
        ]
        .concat();
        let tests = [
            include_str!("../../tests/shim.rs"),
            include_str!("../accept.rs"),
            include_str!("../udp.rs"),
            include_str!("shim.rs"),
        ]
        .concat();
        for op in ALL {
            let name = format!("Op::{op:?}");
            let called = sys.matches(&format!("shim::{name}")).count()
                + sys.matches(&format!("shim::Op::{op:?})")).count();
            assert!(called > 0, "{name} has no call site in sys");
            let injected = tests.matches(&format!("{name}, ")).count();
            assert!(injected > 0, "{name} has no injected-error test");
        }
    }

    #[test]
    fn test_shim_skip_then_fault_then_pass() {
        program_here(Op::Accept, 1, 1, Fault::Kind(io::ErrorKind::OutOfMemory));
        assert!(check(Op::Accept).is_ok());
        assert!(check(Op::Accept).is_err());
        assert!(check(Op::Accept).is_ok());
        clear_here();
    }

    #[test]
    fn test_shim_short_caps_length() {
        program_here(Op::Send, 0, 1, Fault::Short(7));
        assert_eq!(io(Op::Send, 100).unwrap(), Some(7));
        assert_eq!(io(Op::Send, 100).unwrap(), None);
        clear_here();
    }

    #[test]
    fn test_shim_rules_of_other_threads_do_not_match() {
        program_here(Op::Recv, 0, 1, Fault::Interrupt);
        let other = std::thread::spawn(|| io(Op::Recv, 10).map_err(|e| e.kind()));
        assert_eq!(other.join().unwrap(), Ok(None));
        assert!(io(Op::Recv, 10).is_err());
        clear_here();
    }
}
