//! Inherited listeners: systemd socket activation and FastCGI's descriptor 0.
//!
//! Inherited descriptors are verified before net-io takes them, taken once per
//! process (a second call gets what is left, never a second owner of the same
//! number), and set close-on-exec. The `LISTEN_*` variables are left in the
//! environment (decision D-036): the pid check already keeps a child from
//! using them.

use std::fmt;
use std::io;
use std::sync::{Mutex, PoisonError};

use crate::handoff::ListenerHandle;
#[cfg(unix)]
use crate::sys::KindError;

/// Why inherited descriptors were refused.
///
/// ```
/// assert_eq!(net_io::InheritError::BadCount.to_string(), "LISTEN_FDS is not a valid count");
/// ```
#[non_exhaustive]
#[derive(Debug)]
pub enum InheritError {
    /// `LISTEN_FDS` is not a non-negative number.
    BadCount,
    /// More descriptors than allowed.
    TooMany {
        /// The maximum.
        max: u32,
    },
    /// The descriptor is not a socket.
    NotASocket {
        /// The descriptor.
        fd: i32,
    },
    /// The socket is not listening.
    NotListening {
        /// The descriptor.
        fd: i32,
    },
    /// The socket's family or type is not one net-io serves.
    WrongKind {
        /// The descriptor.
        fd: i32,
    },
    /// `LISTEN_FDNAMES` does not match `LISTEN_FDS`.
    NamesMismatch,
    /// `LISTEN_PIDFDID` does not match this process.
    PidFdMismatch,
    /// An OS call failed.
    Os(io::Error),
}

impl fmt::Display for InheritError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InheritError::BadCount => f.write_str("LISTEN_FDS is not a valid count"),
            InheritError::TooMany { max } => write!(f, "more than {max} inherited descriptors"),
            InheritError::NotASocket { fd } => write!(f, "descriptor {fd} is not a socket"),
            InheritError::NotListening { fd } => {
                write!(f, "descriptor {fd} is not a listening socket")
            }
            InheritError::WrongKind { fd } => {
                write!(f, "descriptor {fd} is not a TCP or Unix stream socket")
            }
            InheritError::NamesMismatch => f.write_str("LISTEN_FDNAMES does not match LISTEN_FDS"),
            InheritError::PidFdMismatch => {
                f.write_str("LISTEN_PIDFDID does not match this process")
            }
            InheritError::Os(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for InheritError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            InheritError::Os(e) => Some(e),
            _ => None,
        }
    }
}

/// A listener systemd passed to this process, with its `LISTEN_FDNAMES` name.
#[derive(Debug)]
pub struct InheritedListener {
    /// Its name from `LISTEN_FDNAMES`, when systemd gave names.
    pub name: Option<String>,
    /// The socket.
    pub handle: ListenerHandle,
}

/// The most descriptors systemd may pass (FR-42).
#[cfg(unix)]
const MAX_FDS: u32 = 64;
/// systemd's first passed descriptor (`SD_LISTEN_FDS_START`).
#[cfg(unix)]
const FIRST_FD: i32 = 3;

/// What systemd passed, taken once per process.
struct Taken {
    read: bool,
    left: Vec<InheritedListener>,
}

static SYSTEMD: Mutex<Taken> = Mutex::new(Taken {
    read: false,
    left: Vec::new(),
});

/// The listeners systemd passed to this process (socket activation). Reads
/// `LISTEN_PID` (it must name this process, otherwise the variables were meant
/// for another and the list is empty), `LISTEN_PIDFDID` where present (Linux:
/// must match this process's pidfd), `LISTEN_FDS` (at most 64), and
/// `LISTEN_FDNAMES`. Every descriptor from 3 is verified (a socket, listening,
/// TCP or Unix stream) before any is taken. Not started by systemd: an empty
/// list. A second call returns what earlier calls (including
/// [`systemd_named`]) left.
///
/// # Errors
///
/// `BadCount`, `TooMany`, `NamesMismatch`, `PidFdMismatch`, `NotASocket`,
/// `NotListening`, `WrongKind`, `Os`; nothing is taken on an error.
///
/// ```no_run
/// use net_io::{AllowAll, ListenerSpec, ServerBuilder};
/// let mut builder = ServerBuilder::new();
/// for inherited in net_io::systemd()? {
///     builder = builder.listener(ListenerSpec::adopt(inherited.handle));
/// }
/// let server = builder.handler(|conn| { conn.send_all(b"hi\n")?; Ok(()) }).gate(AllowAll).build()?;
/// server.open_door()?;
/// server.wait_for_stop();
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn systemd() -> Result<Vec<InheritedListener>, InheritError> {
    let mut taken = SYSTEMD.lock().unwrap_or_else(PoisonError::into_inner);
    read_once(&mut taken)?;
    Ok(std::mem::take(&mut taken.left))
}

/// The one listener systemd passed under `name` (`LISTEN_FDNAMES`), or `None`.
/// The others stay for later calls.
///
/// # Errors
///
/// As [`systemd`].
pub fn systemd_named(name: &str) -> Result<Option<InheritedListener>, InheritError> {
    let mut taken = SYSTEMD.lock().unwrap_or_else(PoisonError::into_inner);
    read_once(&mut taken)?;
    Ok(taken
        .left
        .iter()
        .position(|l| l.name.as_deref() == Some(name))
        .map(|i| taken.left.remove(i)))
}

fn read_once(taken: &mut Taken) -> Result<(), InheritError> {
    if taken.read {
        return Ok(());
    }
    #[cfg(unix)]
    {
        let env = |k: &str| std::env::var(k).ok();
        taken.left = from_systemd(&env, std::process::id(), FIRST_FD)?;
    }
    taken.read = true;
    Ok(())
}

/// The systemd protocol over `env`, with descriptors from `first` (3 outside tests).
#[cfg(unix)]
fn from_systemd(
    env: &dyn Fn(&str) -> Option<String>,
    pid: u32,
    first: i32,
) -> Result<Vec<InheritedListener>, InheritError> {
    // Not for this process (or not systemd at all): nothing inherited.
    match env("LISTEN_PID").and_then(|p| p.trim().parse::<u32>().ok()) {
        Some(p) if p == pid => {}
        _ => return Ok(Vec::new()),
    }
    #[cfg(target_os = "linux")]
    if let Some(want) = env("LISTEN_PIDFDID") {
        let want: u64 = want
            .trim()
            .parse()
            .map_err(|_| InheritError::PidFdMismatch)?;
        if crate::sys::pidfd_inode().map_err(InheritError::Os)? != want {
            return Err(InheritError::PidFdMismatch);
        }
    }
    let Some(count) = env("LISTEN_FDS") else {
        return Ok(Vec::new());
    };
    let count: u32 = count.trim().parse().map_err(|_| InheritError::BadCount)?;
    if count > MAX_FDS {
        return Err(InheritError::TooMany { max: MAX_FDS });
    }
    let names: Option<Vec<String>> =
        env("LISTEN_FDNAMES").map(|n| n.split(':').map(str::to_owned).collect());
    if names.as_ref().is_some_and(|n| n.len() != count as usize) {
        return Err(InheritError::NamesMismatch);
    }
    // Verify every descriptor before taking any.
    let fds: Vec<i32> = (0..count as i32).map(|i| first + i).collect();
    for &fd in &fds {
        crate::sys::inherited_kind(fd).map_err(|e| kind_error(e, fd))?;
    }
    let mut out = Vec::with_capacity(fds.len());
    for (i, fd) in fds.into_iter().enumerate() {
        let owned = crate::sys::claim_inherited(fd).map_err(InheritError::Os)?;
        let name = names
            .as_ref()
            .and_then(|n| n.get(i))
            .filter(|n| !n.is_empty())
            .cloned();
        let handle =
            ListenerHandle::verified(owned, name.clone()).map_err(|e| kind_error(e, fd))?;
        out.push(InheritedListener { name, handle });
    }
    Ok(out)
}

/// The fuzz target's entry: `LISTEN_FDS`, `LISTEN_FDNAMES`, and
/// `LISTEN_PIDFDID` from `data` (split at NUL), descriptors looked for from
/// 1,000,000 (never open), so nothing real is touched.
#[cfg(all(fuzzing, unix))]
pub(crate) fn fuzz_systemd_env(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let mut parts = text.split('\0');
    let pid = std::process::id();
    let (fds, names, pidfd) = (parts.next(), parts.next(), parts.next());
    let env = |k: &str| match k {
        "LISTEN_PID" => Some(pid.to_string()),
        "LISTEN_FDS" => fds.map(str::to_owned),
        "LISTEN_FDNAMES" => names.map(str::to_owned),
        "LISTEN_PIDFDID" => pidfd.map(str::to_owned),
        _ => None,
    };
    if let Ok(list) = from_systemd(&env, pid, 1_000_000) {
        assert!(list.is_empty(), "no descriptor is open up there");
    }
}

#[cfg(all(fuzzing, not(unix)))]
pub(crate) fn fuzz_systemd_env(_data: &[u8]) {}

#[cfg(unix)]
fn kind_error(e: KindError, fd: i32) -> InheritError {
    match e {
        KindError::NotASocket => InheritError::NotASocket { fd },
        KindError::NotListening => InheritError::NotListening { fd },
        KindError::WrongKind => InheritError::WrongKind { fd },
        KindError::Os(e) => InheritError::Os(e),
    }
}

#[cfg(unix)]
static FASTCGI: Mutex<bool> = Mutex::new(false);

/// FastCGI's listening socket (`FCGI_LISTENSOCK_FILENO`, as `mod_fcgid` starts a
/// FastCGI server): descriptor 0 is taken only if it is a socket, listening,
/// and has no peer; otherwise `None` (a terminal, a file, a pipe, a connected
/// socket). Taken once per process: later calls return `None`.
///
/// # Errors
///
/// `Os` when an OS call fails unexpectedly.
///
/// ```no_run
/// if let Some(handle) = net_io::fastcgi_listener()? {
///     println!("started by a FastCGI manager on {}", handle.local());
/// }
/// # Ok::<(), net_io::InheritError>(())
/// ```
#[cfg(unix)]
pub fn fastcgi_listener() -> Result<Option<ListenerHandle>, InheritError> {
    let mut taken = FASTCGI.lock().unwrap_or_else(PoisonError::into_inner);
    if *taken {
        return Ok(None);
    }
    let got = fastcgi_from(0)?;
    if got.is_some() {
        *taken = true;
    }
    Ok(got)
}

#[cfg(unix)]
fn fastcgi_from(fd: i32) -> Result<Option<ListenerHandle>, InheritError> {
    match crate::sys::inherited_kind(fd) {
        Ok(_) => {}
        Err(KindError::Os(e)) => return Err(InheritError::Os(e)),
        Err(_) => return Ok(None),
    }
    // A listener has no peer: `inherited_kind` refused a connected socket (on
    // macOS by `getpeername`), so descriptor 0 is taken only when it is ours.
    let owned = crate::sys::claim_inherited(fd).map_err(InheritError::Os)?;
    ListenerHandle::verified(owned, None)
        .map(Some)
        .map_err(|e| kind_error(e, fd))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::os::fd::AsFd;

    fn env(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |k| map.get(k).cloned()
    }

    /// Places listeners at `base`, `base + 1`, ... like systemd at 3.
    fn place(base: i32, n: usize) -> Vec<std::net::TcpListener> {
        (0..n)
            .map(|i| {
                let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                crate::sys::dup_to(l.as_fd(), base + i as i32).unwrap();
                l
            })
            .collect()
    }

    #[test]
    fn test_systemd_protocol() {
        let me = std::process::id();
        let pid = me.to_string();
        // Edge cases 95 and 97: nothing for us.
        assert!(from_systemd(&env(&[]), me, 900).unwrap().is_empty());
        assert!(
            from_systemd(&env(&[("LISTEN_PID", "1"), ("LISTEN_FDS", "1")]), me, 900)
                .unwrap()
                .is_empty()
        );
        assert!(
            from_systemd(&env(&[("LISTEN_PID", &pid), ("LISTEN_FDS", "0")]), me, 900)
                .unwrap()
                .is_empty()
        );
        // Edge case 96.
        for bad in ["x", "-1", ""] {
            assert!(matches!(
                from_systemd(&env(&[("LISTEN_PID", &pid), ("LISTEN_FDS", bad)]), me, 900),
                Err(InheritError::BadCount)
            ));
        }
        assert!(matches!(
            from_systemd(&env(&[("LISTEN_PID", &pid), ("LISTEN_FDS", "65")]), me, 900),
            Err(InheritError::TooMany { max: 64 })
        ));
        // Edge case 98.
        assert!(matches!(
            from_systemd(
                &env(&[
                    ("LISTEN_PID", &pid),
                    ("LISTEN_FDS", "2"),
                    ("LISTEN_FDNAMES", "a")
                ]),
                me,
                900
            ),
            Err(InheritError::NamesMismatch)
        ));
        // Edge case 99: a closed number and a regular file.
        assert!(matches!(
            from_systemd(&env(&[("LISTEN_PID", &pid), ("LISTEN_FDS", "1")]), me, 990),
            Err(InheritError::NotASocket { fd: 990 })
        ));
        let file = std::fs::File::open("/dev/null").unwrap();
        crate::sys::dup_to(file.as_fd(), 991).unwrap();
        assert!(matches!(
            from_systemd(&env(&[("LISTEN_PID", &pid), ("LISTEN_FDS", "1")]), me, 991),
            Err(InheritError::NotASocket { fd: 991 })
        ));
        crate::sys::close_number(991);
    }

    #[test]
    fn test_systemd_takes_verified_listeners_with_names() {
        let me = std::process::id();
        let pid = me.to_string();
        let ls = place(910, 2);
        let got = from_systemd(
            &env(&[
                ("LISTEN_PID", &pid),
                ("LISTEN_FDS", "2"),
                ("LISTEN_FDNAMES", "web:"),
            ]),
            me,
            910,
        )
        .unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].name.as_deref(), Some("web"));
        assert_eq!(got[1].name, None, "an empty name is no name");
        assert_eq!(
            got[0].handle.local().socket_addr(),
            Some(ls[0].local_addr().unwrap())
        );
        // Edge case 100: a connected socket is refused, and nothing is taken.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let c = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        crate::sys::dup_to(c.as_fd(), 920).unwrap();
        assert!(matches!(
            from_systemd(&env(&[("LISTEN_PID", &pid), ("LISTEN_FDS", "1")]), me, 920),
            Err(InheritError::NotListening { fd: 920 })
        ));
        crate::sys::close_number(920);
    }

    #[test]
    fn test_fastcgi_descriptor_checks() {
        // Edge case 101: a file, a connected socket: None; a listener: taken.
        let file = std::fs::File::open("/dev/null").unwrap();
        crate::sys::dup_to(file.as_fd(), 930).unwrap();
        assert!(fastcgi_from(930).unwrap().is_none());
        crate::sys::close_number(930);
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let c = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        crate::sys::dup_to(c.as_fd(), 931).unwrap();
        assert!(fastcgi_from(931).unwrap().is_none());
        crate::sys::close_number(931);
        crate::sys::dup_to(l.as_fd(), 932).unwrap();
        let h = fastcgi_from(932).unwrap().unwrap();
        assert_eq!(h.local().socket_addr(), Some(l.local_addr().unwrap()));
        assert!(fastcgi_from(-1).unwrap().is_none());
    }
}
