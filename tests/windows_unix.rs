//! AF_UNIX on Windows, standalone and under a server on both drivers.

#![cfg(all(windows, feature = "local"))]

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use common::eventually;
use net_io::{
    AllowAll, CloseReason, ConnectionInfo, DriverKind, Input, ListenerSpec, LocalOptions, NetError,
    ServerBuilder, Session, SessionContext, Step, Transport, UnixConnection, UnixListener,
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

fn path() -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("nio-{}-{n}.sock", std::process::id()))
}

#[test]
fn test_round_trip_and_peer_process() {
    let p = path();
    let listener = UnixListener::bind(&p).expect("bind");
    let mut client = UnixConnection::connect(&p).expect("connect");
    let (mut server, info) = listener.accept().expect("accept");
    assert_eq!(info.transport, Transport::Unix);
    let me = std::process::id();
    assert_eq!(info.peer_credentials.and_then(|c| c.pid), Some(me));
    assert_eq!(client.peer_credentials().expect("creds").pid, Some(me));
    client.send_all(b"ping").expect("send");
    let mut back = [0u8; 4];
    server.recv_exact(&mut back).expect("recv");
    assert_eq!(&back, b"ping");
    drop(server);
    assert_eq!(client.recv(&mut back).expect("eof"), 0);
    drop(listener);
    assert!(!p.exists(), "the socket file went with the listener");
}

#[test]
fn test_live_socket_and_other_files_stay() {
    let p = path();
    let live = UnixListener::bind(&p).expect("bind");
    assert!(matches!(
        UnixListener::bind(&p),
        Err(NetError::StaleSocketInUse { .. })
    ));
    drop(live);

    let file = path();
    std::fs::write(&file, b"keep me").expect("write");
    assert!(matches!(
        UnixListener::bind(&file),
        Err(NetError::StaleSocketInUse { .. })
    ));
    assert_eq!(std::fs::read(&file).expect("read"), b"keep me");
    std::fs::remove_file(&file).expect("remove");
}

/// Makes `path` a reparse point with a third-party tag, as a cloud or backup
/// product would (no privilege needed for a file this user owns).
fn make_foreign_reparse_point(path: &std::path::Path) {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem as fs;
    const FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(fs::FILE_FLAG_OPEN_REPARSE_POINT | fs::FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .expect("open");
    // REPARSE_GUID_DATA_BUFFER: tag, data length, reserved, GUID, then the data.
    let mut buf = [0u8; 24 + 4];
    buf[..4].copy_from_slice(&0x0000_1234u32.to_le_bytes());
    buf[4..6].copy_from_slice(&4u16.to_le_bytes());
    buf[8..24].copy_from_slice(&[7u8; 16]);
    let mut returned = 0u32;
    // SAFETY: the handle is open; `buf` is a complete buffer of the length given.
    let ok = unsafe {
        windows_sys::Win32::System::IO::DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_SET_REPARSE_POINT,
            buf.as_ptr().cast(),
            buf.len() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    assert_ne!(ok, 0, "{}", std::io::Error::last_os_error());
}

/// A reparse point that is not an AF_UNIX socket (a cloud placeholder, an app
/// alias, anything with another tag) is never taken for a stale socket file.
#[test]
fn test_other_reparse_points_stay() {
    let p = path();
    std::fs::write(&p, b"").expect("write");
    make_foreign_reparse_point(&p);
    let got = UnixListener::bind(&p).map(drop);
    let _ = std::fs::remove_file(&p);
    assert!(
        matches!(got, Err(NetError::StaleSocketInUse { .. })),
        "bind deleted a reparse point that is not a socket file: {got:?}"
    );
}

/// A process that died left its socket file: the next bind replaces it.
#[test]
fn test_stale_socket_file_is_replaced() {
    let p = path();
    let status = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", "child_leaves_a_socket_file", "--ignored"])
        .env("NET_IO_CHILD_SOCKET", &p)
        .status()
        .expect("spawn");
    assert_eq!(status.code(), Some(0));
    assert!(p.exists(), "the file outlived its process");
    let listener = UnixListener::bind(&p).expect("the stale file is replaced");
    let _client = UnixConnection::connect(&p).expect("connect");
    let _ = listener.accept().expect("accept");
}

#[test]
#[ignore = "started by test_stale_socket_file_is_replaced"]
fn child_leaves_a_socket_file() {
    let Ok(p) = std::env::var("NET_IO_CHILD_SOCKET") else {
        return;
    };
    let listener = UnixListener::bind(p).expect("bind");
    std::mem::forget(listener);
    std::process::exit(0);
}

#[test]
fn test_options_that_do_not_apply_are_refused() {
    assert!(matches!(
        UnixListener::bind_with(path(), LocalOptions::new().mode(0o660)),
        Err(NetError::Unsupported { .. })
    ));
    assert!(matches!(
        UnixListener::bind_with(path(), LocalOptions::new().require_uid(1000)),
        Err(NetError::Unsupported { .. })
    ));
    assert!(matches!(
        UnixConnection::connect(path()),
        Err(NetError::NotFound)
    ));
    let long = "a".repeat(200);
    assert!(matches!(
        UnixListener::bind(&long),
        Err(NetError::PathTooLong { .. })
    ));
}

#[test]
fn test_under_a_server_on_both_drivers() {
    for driver in [DriverKind::Blocking, DriverKind::Reactor] {
        let p = path();
        let server = ServerBuilder::new()
            .listener(ListenerSpec::unix(&p, LocalOptions::new()))
            .driver(driver)
            .workers(2)
            .sessions(|info: &ConnectionInfo| {
                assert_eq!(info.transport, Transport::Unix);
                assert!(info.peer_credentials.and_then(|c| c.pid).is_some());
                Echo
            })
            .gate(AllowAll)
            .build()
            .expect("build");
        server.open_door().expect("open");
        let mut c = UnixConnection::connect(&p).expect("connect");
        let body = vec![5u8; 256 * 1024];
        let mut back = vec![0u8; 16 * 1024];
        for chunk in body.chunks(back.len()) {
            c.send_all(chunk).expect("send");
            c.recv_exact(&mut back[..chunk.len()]).expect("recv");
            assert_eq!(&back[..chunk.len()], chunk, "{driver:?}");
        }
        drop(c);
        assert!(
            eventually(WAIT, || server.stats().closed == 1),
            "{driver:?}: {:?}",
            server.stats()
        );
        assert_eq!(server.stats().closed_for(CloseReason::PeerClosed), 1);
    }
}
