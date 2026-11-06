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

/// An empty file for `recv_file` to fill, removed on drop.
fn out_file(temp: &mut Option<Temp>, append: bool) -> File {
    let t = Temp::new(if append { 10 } else { 0 });
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(!append)
        .append(append)
        .open(&t.0)
        .expect("open");
    *temp = Some(t);
    file
}

/// A peer that sends `body`, then `tail`, then closes.
fn sender(body: usize, tail: &'static [u8]) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let at = l.local_addr().expect("addr");
    let t = std::thread::spawn(move || {
        let (mut c, _) = l.accept().expect("accept");
        c.write_all(&expected(0, body)).expect("body");
        c.write_all(tail).expect("tail");
    });
    (at, t)
}

#[test]
fn test_recv_file_takes_exactly_len_and_leaves_the_rest() {
    let (at, peer) = sender(3 << 20, b"tail");
    let mut conn = net_io::connect(at).expect("connect");
    let mut temp = None;
    let file = out_file(&mut temp, false);
    let got = conn.recv_file(&file, 50, 3 << 20).expect("recv_file");
    assert_eq!(got, 3 << 20);
    // Nothing past `len` went into the file: the tail is still on the connection.
    let mut tail = [0u8; 4];
    conn.recv_exact(&mut tail).expect("tail");
    assert_eq!(&tail, b"tail");
    peer.join().expect("peer");
    let written = std::fs::read(&temp.as_ref().expect("temp").0).expect("read");
    assert_eq!(written.len(), 50 + (3 << 20));
    assert!(written[..50].iter().all(|&b| b == 0));
    assert!(written[50..] == expected(0, 3 << 20)[..], "file differs");
}

#[test]
fn test_recv_file_stops_at_the_peers_close() {
    let (at, peer) = sender(1 << 20, b"");
    let mut conn = net_io::connect(at).expect("connect");
    let mut temp = None;
    let file = out_file(&mut temp, false);
    let got = conn.recv_file(&file, 0, 64 << 20).expect("recv_file");
    assert_eq!(got, 1 << 20);
    peer.join().expect("peer");
    let written = std::fs::read(&temp.as_ref().expect("temp").0).expect("read");
    assert!(written == expected(0, 1 << 20), "file differs");
}

#[test]
fn test_recv_file_honours_the_read_timeout() {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let at = l.local_addr().expect("addr");
    let limits = net_io::Limits::builder()
        .read_timeout(Duration::from_millis(300))
        .build()
        .expect("limits");
    let mut conn =
        net_io::TcpConnection::connect_with(at, net_io::ConnectOptions::new().limits(limits))
            .expect("connect");
    let (silent, _) = l.accept().expect("accept");
    let mut temp = None;
    let file = out_file(&mut temp, false);
    let started = std::time::Instant::now();
    let err = conn.recv_file(&file, 0, 1 << 20).unwrap_err();
    assert!(matches!(err, NetError::TimedOut { .. }), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
    drop(silent);
}

/// Linux: `splice` turns down a file opened for appending after the bytes reached
/// the pipe; they are copied out of it, and none is lost.
#[cfg(target_os = "linux")]
#[test]
fn test_recv_file_into_a_file_splice_refuses_loses_nothing() {
    let (at, peer) = sender(1 << 20, b"");
    let mut conn = net_io::connect(at).expect("connect");
    let mut temp = None;
    let file = out_file(&mut temp, true);
    let got = conn.recv_file(&file, 0, 1 << 20).expect("recv_file");
    assert_eq!(got, 1 << 20);
    peer.join().expect("peer");
    let written = std::fs::read(&temp.as_ref().expect("temp").0).expect("read");
    assert_eq!(written.len(), 10 + (1 << 20));
    assert!(written[10..] == expected(0, 1 << 20)[..], "file differs");
}

/// `recv_file` against a `recv` and a positioned write per 64 KiB, 1 GiB each over
/// loopback; prints both rates. Run with `--ignored --nocapture` in release.
#[cfg(unix)]
#[test]
#[ignore = "a benchmark"]
fn bench_recv_file() {
    const TOTAL: u64 = 1 << 30;
    fn feed() -> std::net::SocketAddr {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let at = l.local_addr().expect("addr");
        std::thread::spawn(move || {
            let (mut c, _) = l.accept().expect("accept");
            let block = vec![b'x'; 1 << 20];
            for _ in 0..(TOTAL >> 20) {
                c.write_all(&block).expect("write");
            }
        });
        at
    }
    for round in 0..3 {
        let mut temp = None;
        let file = out_file(&mut temp, false);
        let mut conn = net_io::connect(feed()).expect("connect");
        let started = std::time::Instant::now();
        assert_eq!(conn.recv_file(&file, 0, TOTAL).expect("recv_file"), TOTAL);
        let spliced = started.elapsed();
        let mut temp2 = None;
        let file2 = out_file(&mut temp2, false);
        let mut conn = net_io::connect(feed()).expect("connect");
        let mut buf = vec![0u8; 64 << 10];
        let started = std::time::Instant::now();
        let mut got = 0u64;
        while got < TOTAL {
            let n = conn.recv(&mut buf).expect("recv");
            std::os::unix::fs::FileExt::write_all_at(&file2, &buf[..n], got).expect("write");
            got += n as u64;
        }
        let copied = started.elapsed();
        let rate = |d: Duration| TOTAL as f64 / d.as_secs_f64() / f64::from(1 << 30);
        println!(
            "round {round}: recv_file {:.2} GiB/s, recv and write {:.2} GiB/s",
            rate(spliced),
            rate(copied)
        );
    }
}
