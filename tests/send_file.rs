//! Files on every path: a held connection, sessions on both drivers, and TLS-free
//! truncation.

mod common;

use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use common::{DRIVERS, addr, eventually};
use net_io::{
    AdmitStage, Admitted, AllowAll, CloseReason, ConnectionInfo, Denial, Gate, GateTag, Input,
    Lane, ListenerSpec, NetError, OsErrorClass, Refusal, ServerBuilder, Session, SessionContext,
    Step, TcpListener, WriteCheck,
};

const WAIT: Duration = Duration::from_secs(10);

/// A temporary file of `len` patterned bytes, removed on drop.
struct Temp(PathBuf);

impl Temp {
    fn new(len: usize) -> Temp {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("nio-file-{}-{n}", std::process::id()));
        let body: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, body).expect("write");
        Temp(path)
    }

    fn open(&self) -> File {
        File::open(&self.0).expect("open")
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn expected(offset: usize, len: usize) -> Vec<u8> {
    (offset..offset + len).map(|i| (i % 251) as u8).collect()
}

#[test]
fn test_send_file_on_a_connection() {
    let temp = Temp::new(3 << 20);
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let at = l.local_addr().expect("addr");
    let reader = std::thread::spawn(move || {
        let mut c = TcpStream::connect(at).expect("connect");
        let mut all = Vec::new();
        c.read_to_end(&mut all).expect("read");
        all
    });
    let (mut conn, _) = l.accept().expect("accept");
    let file = temp.open();
    let sent = conn.send_file(&file, 100, (3 << 20) - 100).expect("send");
    assert_eq!(sent, (3 << 20) - 100);
    conn.close().expect("close");
    assert_eq!(
        reader.join().expect("reader"),
        expected(100, (3 << 20) - 100)
    );
}

#[test]
fn test_file_that_ends_early_is_an_error_with_the_count() {
    let temp = Temp::new(1000);
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let at = l.local_addr().expect("addr");
    let reader = std::thread::spawn(move || {
        // The reset can arrive before `connect` returns, and Linux then reports it there.
        let Ok(mut c) = TcpStream::connect(at) else {
            return 0;
        };
        let mut all = Vec::new();
        let _ = c.read_to_end(&mut all);
        all.len()
    });
    let (mut conn, _) = l.accept().expect("accept");
    let file = temp.open();
    let result = conn.send_file(&file, 0, 5000);
    assert!(
        matches!(result, Err(NetError::FileTruncated { .. })),
        "{result:?}"
    );
    drop(conn);
    assert!(reader.join().expect("reader") <= 1000);
}

/// A session that answers any input with a header, a file, and a trailer.
struct Serve {
    file: Arc<File>,
    len: u64,
    done: bool,
}

impl Session for Serve {
    fn on_data(&mut self, cx: &mut SessionContext<'_>, input: &mut Input) -> Step {
        let all = input.bytes().len();
        input.consume(all);
        if !self.done {
            self.done = true;
            cx.output().push(b"head").expect("push");
            cx.output()
                .push_file(self.file.clone(), 0, self.len)
                .expect("push");
            cx.output().push_static(b"tail").expect("push");
        }
        Step::Close
    }
}

fn expected_reply(len: usize) -> Vec<u8> {
    let mut all = b"head".to_vec();
    all.extend(expected(0, len));
    all.extend_from_slice(b"tail");
    all
}

#[test]
fn test_push_file_on_both_drivers() {
    for &driver in DRIVERS {
        // Past one operation's 1 MiB, so the chunks and the partial sends show.
        let len = (5 << 20) / 2;
        let temp = Temp::new(len);
        let file = Arc::new(temp.open());
        let server = ServerBuilder::new()
            .listener(ListenerSpec::tcp("127.0.0.1:0"))
            .driver(driver)
            .workers(2)
            .sessions(move |_: &ConnectionInfo| Serve {
                file: file.clone(),
                len: len as u64,
                done: false,
            })
            .gate(AllowAll)
            .build()
            .expect("build");
        server.open_door().expect("open");
        let mut c = TcpStream::connect(addr(&server)).expect("connect");
        c.write_all(b"go").expect("write");
        let mut all = Vec::new();
        c.read_to_end(&mut all).expect("read");
        assert_eq!(all, expected_reply(len), "{driver:?}");
    }
}

#[test]
fn test_push_file_that_ends_early_resets_on_both_drivers() {
    for &driver in DRIVERS {
        let temp = Temp::new(1000);
        let file = Arc::new(temp.open());
        let server = ServerBuilder::new()
            .listener(ListenerSpec::tcp("127.0.0.1:0"))
            .driver(driver)
            .workers(2)
            .sessions(move |_: &ConnectionInfo| Serve {
                file: file.clone(),
                len: 5000,
                done: false,
            })
            .gate(AllowAll)
            .build()
            .expect("build");
        server.open_door().expect("open");
        let mut c = TcpStream::connect(addr(&server)).expect("connect");
        c.write_all(b"go").expect("write");
        let mut all = Vec::new();
        let _ = c.read_to_end(&mut all);
        assert!(
            eventually(WAIT, || server
                .stats()
                .closed_for(CloseReason::Io(OsErrorClass::FileTruncated))
                == 1),
            "{driver:?}: {:?}",
            server.stats()
        );
    }
}

/// Counts what the gate approved.
#[derive(Clone, Default)]
struct Counting(Arc<AtomicU64>);

impl Gate for Counting {
    type Ticket = ();
    fn admit(&self, _: &ConnectionInfo, _: AdmitStage) -> Result<Admitted<()>, Refusal> {
        Ok(Admitted {
            lane: Lane::MOST_IMPORTANT,
            ticket: (),
            tag: GateTag(0),
        })
    }
    fn readmit(&self, _: &mut (), _: &ConnectionInfo) -> Result<(), Refusal> {
        Ok(())
    }
    fn check(&self, _: &mut (), write: &WriteCheck) -> Result<(), Denial> {
        self.0.fetch_add(u64::from(write.bytes), Ordering::SeqCst);
        Ok(())
    }
}

/// A byte-counting gate sees each file byte once, whatever the partial sends do.
#[test]
fn test_gate_counts_file_bytes_once_on_both_drivers() {
    for &driver in DRIVERS {
        let len = 2 << 20;
        let temp = Temp::new(len);
        let file = Arc::new(temp.open());
        let gate = Counting::default();
        let counted = gate.0.clone();
        let server = ServerBuilder::new()
            .listener(ListenerSpec::tcp("127.0.0.1:0"))
            .driver(driver)
            .workers(2)
            .sessions(move |_: &ConnectionInfo| Serve {
                file: file.clone(),
                len: len as u64,
                done: false,
            })
            .gate(gate)
            .build()
            .expect("build");
        server.open_door().expect("open");
        let mut c = TcpStream::connect(addr(&server)).expect("connect");
        c.write_all(b"go").expect("write");
        let mut all = Vec::new();
        c.read_to_end(&mut all).expect("read");
        assert_eq!(all.len(), len + 8, "{driver:?}");
        assert_eq!(counted.load(Ordering::SeqCst), len as u64 + 8, "{driver:?}");
    }
}
