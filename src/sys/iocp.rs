//! Windows: I/O completion ports.
//!
//! An operation lives in a heap block that starts with its `OVERLAPPED` and owns
//! its buffers. Starting it hands the block to the kernel; the packet dequeued
//! later hands it back. Nothing else frees it, so a buffer the kernel may still
//! write to cannot be reused, whatever happened to the connection (T-18).
//!
//! Listeners never come here (D-016): an association belongs to the shared kernel
//! socket and would follow a listener into a process that receives it.
//!
//! References: Microsoft Learn, `CreateIoCompletionPort`,
//! `GetQueuedCompletionStatusEx`, `CancelIoEx`,
//! `SetFileCompletionNotificationModes`, `WSARecv`, `WSASend`, `ConnectEx`.
//! Layouts and constants are checked against `windows-sys` by the tests below.

use std::ffi::c_void;
use std::io::{self, IoSlice};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::windows::{self as win, Overlapped, Socket, WsaProtocolInfo, c};
use super::{MAX_SLICES, Sock};
use crate::buf::Buffer;
use crate::driver::SendChunks;

type Handle = *mut c_void;

const INFINITE: u32 = 0xFFFF_FFFF;
const WAIT_TIMEOUT: i32 = 258;
const ERROR_OPERATION_ABORTED: i32 = 995;
const WSA_IO_PENDING: i32 = 997;
const ERROR_NOT_FOUND: i32 = 1168;
const FILE_SKIP_COMPLETION_PORT_ON_SUCCESS: u8 = 1;
const FILE_SKIP_SET_EVENT_ON_HANDLE: u8 = 2;
const SO_UPDATE_CONNECT_CONTEXT: i32 = 0x7010;
const SIO_GET_EXTENSION_FUNCTION_POINTER: u32 = 0xC800_0006;
const XP1_IFS_HANDLES: u32 = 0x0002_0000;
const ERROR_BROKEN_PIPE: i32 = 109;
const WSAEINVAL: i32 = 10022;
const WSAENOBUFS: i32 = 10055;
/// `WSAID_CONNECTEX`, by its fields.
const WSAID_CONNECTEX: Guid = Guid {
    data1: 0x25a2_07b9,
    data2: 0xddf3,
    data3: 0x4660,
    data4: [0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e],
};

/// `WSAID_TRANSMITFILE`, by its fields.
const WSAID_TRANSMITFILE: Guid = Guid {
    data1: 0xb536_7df0,
    data2: 0xcbac,
    data3: 0x11cf,
    data4: [0x95, 0xca, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92],
};

/// How many packets one wait removes.
const ENTRIES: usize = 256;
/// The key of a wake packet; sockets use 0.
const WAKE_KEY: usize = usize::MAX;

/// `OVERLAPPED_ENTRY`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct OverlappedEntry {
    key: usize,
    overlapped: usize,
    internal: usize,
    bytes: u32,
}

/// `WSABUF`; `IoSlice` has the same layout.
#[repr(C)]
#[derive(Clone, Copy)]
struct WsaBuf {
    len: u32,
    buf: *mut u8,
}

/// `GUID`.
#[repr(C)]
#[derive(Clone, Copy)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

type TransmitFile = unsafe extern "system" fn(
    s: Socket,
    file: Handle,
    bytes: u32,
    per_send: u32,
    overlapped: *mut Overlapped,
    buffers: *mut c_void,
    flags: u32,
) -> i32;

type ConnectEx = unsafe extern "system" fn(
    s: Socket,
    name: *const c_void,
    name_len: i32,
    send_buf: *const c_void,
    send_len: u32,
    sent: *mut u32,
    overlapped: *mut Overlapped,
) -> i32;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateIoCompletionPort(file: Handle, port: Handle, key: usize, threads: u32) -> Handle;
    fn GetQueuedCompletionStatusEx(
        port: Handle,
        entries: *mut OverlappedEntry,
        count: u32,
        removed: *mut u32,
        milliseconds: u32,
        alertable: i32,
    ) -> i32;
    fn PostQueuedCompletionStatus(
        port: Handle,
        bytes: u32,
        key: usize,
        overlapped: *mut Overlapped,
    ) -> i32;
    fn SetFileCompletionNotificationModes(file: Handle, flags: u8) -> i32;
    fn ReadFile(
        file: Handle,
        buffer: *mut u8,
        len: u32,
        read: *mut u32,
        overlapped: *mut Overlapped,
    ) -> i32;
    fn WriteFile(
        file: Handle,
        buffer: *const u8,
        len: u32,
        written: *mut u32,
        overlapped: *mut Overlapped,
    ) -> i32;
    fn GetOverlappedResult(
        file: Handle,
        overlapped: *const Overlapped,
        transferred: *mut u32,
        wait: i32,
    ) -> i32;
}

#[link(name = "ws2_32")]
unsafe extern "system" {
    fn WSARecv(
        s: Socket,
        buffers: *const WsaBuf,
        count: u32,
        received: *mut u32,
        flags: *mut u32,
        overlapped: *mut Overlapped,
        completion: *mut c_void,
    ) -> i32;
    fn WSASend(
        s: Socket,
        buffers: *const WsaBuf,
        count: u32,
        sent: *mut u32,
        flags: u32,
        overlapped: *mut Overlapped,
        completion: *mut c_void,
    ) -> i32;
    fn WSAGetOverlappedResult(
        s: Socket,
        overlapped: *const Overlapped,
        transferred: *mut u32,
        wait: i32,
        flags: *mut u32,
    ) -> i32;
    fn WSAEnumProtocolsW(
        protocols: *const i32,
        buffer: *mut WsaProtocolInfo,
        length: *mut u32,
    ) -> i32;
    fn WSAIoctl(
        s: Socket,
        code: u32,
        in_buf: *const c_void,
        in_len: u32,
        out_buf: *mut c_void,
        out_len: u32,
        returned: *mut u32,
        overlapped: *mut c_void,
        completion: *mut c_void,
    ) -> i32;
    fn WSAGetLastError() -> i32;
}

/// Which operation finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpKind {
    Receive,
    Send,
    SendFile,
    Connect,
}

/// One operation. Boxed, and owned by the kernel from the start of the call
/// until its packet is dequeued.
#[repr(C)]
struct Op {
    overlapped: Overlapped,
    token: u64,
    socket: Socket,
    kind: OpKind,
    pipe: bool,
    buffer: Option<Buffer>,
    chunks: Option<SendChunks>,
    file: Option<Arc<std::fs::File>>,
    addr: [u8; 28],
}

/// An operation that finished, with its buffers.
#[derive(Debug)]
pub(crate) struct Finished {
    pub(crate) token: u64,
    pub(crate) kind: OpKind,
    pub(crate) result: io::Result<usize>,
    pub(crate) buffer: Option<Buffer>,
    pub(crate) chunks: Option<SendChunks>,
}

/// What starting an operation did.
#[derive(Debug)]
pub(crate) enum Started {
    /// In the kernel; a packet will finish it.
    Pending(InFlight),
    /// Finished in the call: no packet comes.
    Done(Finished),
}

/// Names an operation in the kernel, for [`Port::cancel`] only: a number the
/// kernel compares, never read here.
#[derive(Clone, Copy, Debug)]
pub(crate) struct InFlight(usize);

/// A socket on a port.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Associated {
    socket: Socket,
    /// A call that succeeds at once queues no packet.
    skip: bool,
    /// A named pipe's handle: `ReadFile` and `WriteFile` instead of Winsock.
    pipe: bool,
}

impl Associated {
    /// A reset instead of a FIN at close.
    pub(crate) fn set_abortive(self) {
        if self.pipe {
            return;
        }
        // SAFETY: open between `register` and `deregister` by the `Driver` contract.
        let sock = unsafe { win::borrow(self.socket) };
        let _ = super::set_linger(sock, Some(Duration::ZERO));
    }
}

/// Wakes a worker's wait from any thread; repeated wakes before the worker runs
/// cost one atomic load.
#[derive(Debug)]
pub(crate) struct PollWaker {
    port: Arc<OwnedHandle>,
    pending: AtomicBool,
}

impl PollWaker {
    pub(crate) fn wake(&self) {
        if !self.pending.swap(true, Ordering::AcqRel) {
            // SAFETY: the port is open while this `Arc` lives; a packet with a null
            // `OVERLAPPED` is the wake.
            let _ = unsafe {
                PostQueuedCompletionStatus(
                    self.port.as_raw_handle(),
                    0,
                    WAKE_KEY,
                    std::ptr::null_mut(),
                )
            };
        }
    }
}

/// The completion port of one worker.
pub(crate) struct Port {
    port: Arc<OwnedHandle>,
    wake: Arc<PollWaker>,
    entries: Box<[OverlappedEntry; ENTRIES]>,
    /// Finished operations, for reuse: an idle connection keeps one in the kernel.
    /// Boxed because the kernel holds them by address.
    #[allow(clippy::vec_box)]
    free: Vec<Box<Op>>,
    outstanding: usize,
    /// Whether every provider gives real handles, so the skip mode is sound.
    skip: bool,
    connect_ex: Option<ConnectEx>,
    transmit_file: Option<TransmitFile>,
}

impl std::fmt::Debug for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Port")
            .field("outstanding", &self.outstanding)
            .field("skip", &self.skip)
            .finish_non_exhaustive()
    }
}

/// Whether every TCP provider hands out real handles. A layered provider that
/// does not cannot use `FILE_SKIP_COMPLETION_PORT_ON_SUCCESS`.
fn ifs_providers() -> bool {
    win::startup();
    let mut list: Vec<WsaProtocolInfo> = Vec::with_capacity(32);
    loop {
        let mut bytes = u32::try_from(list.capacity() * size_of::<WsaProtocolInfo>()).unwrap_or(0);
        // SAFETY: `list` has room for `bytes` bytes; a null protocol list means all.
        let n = unsafe { WSAEnumProtocolsW(std::ptr::null(), list.as_mut_ptr(), &raw mut bytes) };
        if n >= 0 {
            // SAFETY: the call wrote `n` entries.
            unsafe { list.set_len(n.unsigned_abs() as usize) };
            return list
                .iter()
                .filter(|p| p.i_protocol == c::IPPROTO_TCP)
                .all(|p| p.service_flags1 & XP1_IFS_HANDLES != 0);
        }
        // SAFETY: reads this thread's last Winsock error.
        if unsafe { WSAGetLastError() } != WSAENOBUFS {
            return false;
        }
        list.reserve(bytes as usize / size_of::<WsaProtocolInfo>() + 1);
    }
}

impl Port {
    pub(crate) fn new() -> io::Result<Port> {
        Port::with_skip(ifs_providers())
    }

    /// `skip`: whether sockets use `FILE_SKIP_COMPLETION_PORT_ON_SUCCESS`.
    pub(crate) fn with_skip(skip: bool) -> io::Result<Port> {
        // SAFETY: an invalid file handle and a null port create a new port.
        let raw = unsafe { CreateIoCompletionPort(-1isize as Handle, std::ptr::null_mut(), 0, 1) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` was just returned, is open, and has no other owner.
        let port = Arc::new(unsafe { OwnedHandle::from_raw_handle(raw) });
        Ok(Port {
            wake: Arc::new(PollWaker {
                port: port.clone(),
                pending: AtomicBool::new(false),
            }),
            port,
            entries: Box::new([OverlappedEntry::default(); ENTRIES]),
            free: Vec::new(),
            outstanding: 0,
            skip,
            connect_ex: None,
            transmit_file: None,
        })
    }

    pub(crate) fn waker(&self) -> Arc<PollWaker> {
        self.wake.clone()
    }

    /// Puts a connected or connecting socket on this port. A listener is refused
    /// (D-016).
    pub(crate) fn associate(&self, sock: Sock<'_>) -> io::Result<Associated> {
        #[cfg(any(test, net_io_shim))]
        super::shim::check(super::shim::Op::Register)?;
        if super::is_listening_stream(sock)? {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let socket = win::raw(sock);
        // SAFETY: `socket` is open for the call and `port` is a completion port.
        let ret =
            unsafe { CreateIoCompletionPort(socket as Handle, self.port.as_raw_handle(), 0, 0) };
        if ret.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: as above; the flags are documented for sockets.
        let skip = self.skip
            && unsafe {
                SetFileCompletionNotificationModes(
                    socket as Handle,
                    FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE,
                )
            } != 0;
        Ok(Associated {
            socket,
            skip,
            pipe: false,
        })
    }

    /// Puts a named pipe on this port.
    #[cfg(feature = "local")]
    pub(crate) fn associate_pipe(
        &self,
        handle: std::os::windows::io::RawHandle,
    ) -> io::Result<Associated> {
        // SAFETY: `handle` is open for the call and `port` is a completion port.
        let ret = unsafe { CreateIoCompletionPort(handle, self.port.as_raw_handle(), 0, 0) };
        if ret.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: as above; the flags are documented for any file handle.
        let skip = self.skip
            && unsafe {
                SetFileCompletionNotificationModes(
                    handle,
                    FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE,
                )
            } != 0;
        Ok(Associated {
            socket: handle as Socket,
            skip,
            pipe: true,
        })
    }

    fn op(&mut self, on: Associated, token: u64, kind: OpKind) -> Box<Op> {
        let mut op = self.free.pop().unwrap_or_else(|| {
            Box::new(Op {
                overlapped: Overlapped::default(),
                token: 0,
                socket: 0,
                kind,
                pipe: false,
                buffer: None,
                chunks: None,
                file: None,
                addr: [0; 28],
            })
        });
        op.overlapped = Overlapped::default();
        op.token = token;
        op.socket = on.socket;
        op.kind = kind;
        op.pipe = on.pipe;
        op
    }

    /// The operation is back from the kernel (or never went there).
    ///
    /// # Safety
    ///
    /// `raw` came from `Box::into_raw` in this file and no kernel call holds it:
    /// its call failed, succeeded without queueing a packet, or its packet was
    /// dequeued.
    unsafe fn reclaim(&mut self, raw: *mut Op, result: io::Result<usize>) -> Finished {
        // SAFETY: by this function's contract.
        let mut op = unsafe { Box::from_raw(raw) };
        // A pipe reports the end of stream as an error.
        let result = match result {
            Err(e) if e.raw_os_error() == Some(ERROR_BROKEN_PIPE) && op.kind == OpKind::Receive => {
                Ok(0)
            }
            other => other,
        };
        if op.kind == OpKind::Connect && result.is_ok() {
            // SAFETY: an option that takes no value; a closed socket makes it fail.
            let _ = unsafe { win::setsockopt_empty(op.socket, SO_UPDATE_CONNECT_CONTEXT) };
        }
        let done = Finished {
            token: op.token,
            kind: op.kind,
            result,
            buffer: op.buffer.take(),
            chunks: op.chunks.take(),
        };
        op.file = None;
        self.free.push(op);
        done
    }

    /// What a start call returned decides who owns the operation now.
    ///
    /// # Safety
    ///
    /// `raw` came from `Box::into_raw`, and the call that took it returned `ret`
    /// on this thread just now.
    unsafe fn started(&mut self, on: Associated, raw: *mut Op, ret: i32, moved: u32) -> Started {
        if ret == 0 {
            if on.skip {
                // SAFETY: no packet is queued for a call that succeeded at once in
                // skip mode, so nothing else holds `raw`.
                return Started::Done(unsafe { self.reclaim(raw, Ok(moved as usize)) });
            }
        } else {
            // SAFETY: reads this thread's last Winsock error.
            let code = unsafe { WSAGetLastError() };
            if code != WSA_IO_PENDING {
                let e = io::Error::from_raw_os_error(code);
                // SAFETY: the call failed, so the kernel never took `raw`.
                return Started::Done(unsafe { self.reclaim(raw, Err(e)) });
            }
        }
        self.outstanding += 1;
        Started::Pending(InFlight(raw as usize))
    }

    /// Receives into `buffer`'s spare room, or, without one, waits for bytes.
    pub(crate) fn receive(
        &mut self,
        on: Associated,
        token: u64,
        buffer: Option<Buffer>,
    ) -> Started {
        let mut op = self.op(on, token, OpKind::Receive);
        op.buffer = buffer;
        #[cfg(any(test, net_io_shim))]
        let limit = {
            let room = op.buffer.as_mut().map_or(0, |b| b.spare().len());
            match super::retry_interrupted(|| super::shim::io(super::shim::Op::Recv, room)) {
                Ok(limit) => limit,
                Err(e) => {
                    let raw = Box::into_raw(op);
                    // SAFETY: `raw` never reached the kernel.
                    return Started::Done(unsafe { self.reclaim(raw, Err(e)) });
                }
            }
        };
        let raw = Box::into_raw(op);
        let mut moved = 0u32;
        // SAFETY: `raw` is live and its buffer's bytes stay put until it is reclaimed;
        // the kernel copies the `WSABUF` during the call. `moved` is written only for
        // an immediate success, and only this thread dequeues, so it cannot race the
        // packet Microsoft's note on that parameter warns about.
        let ret = unsafe {
            let (buf, len) = (*raw)
                .buffer
                .as_mut()
                .map_or((std::ptr::null_mut(), 0), |b| {
                    let spare = b.spare();
                    (spare.as_mut_ptr(), spare.len())
                });
            #[cfg(any(test, net_io_shim))]
            let len = limit.unwrap_or(len);
            let wsa = WsaBuf {
                len: u32::try_from(len).unwrap_or(u32::MAX),
                buf,
            };
            let mut flags = 0u32;
            if on.pipe {
                // The kernel writes nothing for length 0, but wants a pointer.
                let buf = if buf.is_null() {
                    std::ptr::NonNull::<u8>::dangling().as_ptr()
                } else {
                    buf
                };
                win_ret(ReadFile(
                    on.socket as Handle,
                    buf,
                    wsa.len,
                    &raw mut moved,
                    &raw mut (*raw).overlapped,
                ))
            } else {
                WSARecv(
                    on.socket,
                    &raw const wsa,
                    1,
                    &raw mut moved,
                    &raw mut flags,
                    &raw mut (*raw).overlapped,
                    std::ptr::null_mut(),
                )
            }
        };
        // SAFETY: `ret` is the result of the call above.
        unsafe { self.started(on, raw, ret, moved) }
    }

    /// Sends what `chunks` holds.
    pub(crate) fn send(&mut self, on: Associated, token: u64, chunks: SendChunks) -> Started {
        let mut op = self.op(on, token, OpKind::Send);
        op.chunks = Some(chunks);
        #[cfg(any(test, net_io_shim))]
        let limit = {
            let total = op.chunks.as_ref().map_or(0, SendChunks::pending);
            match super::retry_interrupted(|| super::shim::io(super::shim::Op::Send, total)) {
                Ok(limit) => limit,
                Err(e) => {
                    let raw = Box::into_raw(op);
                    // SAFETY: `raw` never reached the kernel.
                    return Started::Done(unsafe { self.reclaim(raw, Err(e)) });
                }
            }
        };
        let raw = Box::into_raw(op);
        let mut slices = [IoSlice::new(&[]); MAX_SLICES];
        let mut moved = 0u32;
        // SAFETY: `raw` is live. The chunks stay in it, and their bytes stay put, until
        // it is reclaimed. `IoSlice` is ABI-compatible with `WSABUF`, and the kernel
        // copies the array during the call.
        let ret = unsafe {
            let n = (*raw).chunks.as_ref().map_or(0, |c| c.slices(&mut slices));
            #[cfg(any(test, net_io_shim))]
            let n = match limit {
                Some(len) => {
                    let first = slices[0];
                    slices[0] = IoSlice::new(std::slice::from_raw_parts(
                        first.as_ptr(),
                        len.min(first.len()),
                    ));
                    1
                }
                None => n,
            };
            if on.pipe {
                // No gather on a pipe: one slice per call, and the reactor sends the rest.
                let first = slices[..n].iter().find(|s| !s.is_empty()).copied();
                let first = first.unwrap_or(slices[0]);
                win_ret(WriteFile(
                    on.socket as Handle,
                    first.as_ptr(),
                    u32::try_from(first.len()).unwrap_or(u32::MAX),
                    &raw mut moved,
                    &raw mut (*raw).overlapped,
                ))
            } else {
                WSASend(
                    on.socket,
                    slices.as_ptr().cast(),
                    n as u32,
                    &raw mut moved,
                    0,
                    &raw mut (*raw).overlapped,
                    std::ptr::null_mut(),
                )
            }
        };
        // SAFETY: `ret` is the result of the call above.
        unsafe { self.started(on, raw, ret, moved) }
    }

    /// The `TransmitFile` of this provider, looked up once per port.
    fn transmit_file(&mut self, sock: Sock<'_>) -> io::Result<TransmitFile> {
        if let Some(f) = self.transmit_file {
            return Ok(f);
        }
        let guid = WSAID_TRANSMITFILE;
        let mut f: Option<TransmitFile> = None;
        let mut returned = 0u32;
        // SAFETY: as in `connect_ex`.
        let ret = unsafe {
            WSAIoctl(
                win::raw(sock),
                SIO_GET_EXTENSION_FUNCTION_POINTER,
                (&raw const guid).cast(),
                size_of::<Guid>() as u32,
                (&raw mut f).cast(),
                size_of::<Option<TransmitFile>>() as u32,
                &raw mut returned,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ret != 0 {
            // SAFETY: reads this thread's last Winsock error.
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
        }
        self.transmit_file = f;
        f.ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))
    }

    /// Sends `len` bytes of `file` from `offset`, zero copy. The operation holds the
    /// file until it ends.
    pub(crate) fn send_file(
        &mut self,
        on: Associated,
        token: u64,
        file: Arc<std::fs::File>,
        offset: u64,
        len: u32,
    ) -> io::Result<Started> {
        // SAFETY: open between `register` and `deregister` by the `Driver` contract.
        let sock = unsafe { win::borrow(on.socket) };
        let transmit = self.transmit_file(sock)?;
        let mut op = self.op(on, token, OpKind::SendFile);
        op.overlapped.offset = offset as u32;
        op.overlapped.offset_high = (offset >> 32) as u32;
        let handle = file.as_raw_handle();
        op.file = Some(file);
        let raw = Box::into_raw(op);
        // SAFETY: `raw` is live and holds the file until it is reclaimed, so `handle`
        // stays open during the operation. No head or tail buffers.
        let ok = unsafe {
            transmit(
                on.socket,
                handle,
                len,
                0,
                &raw mut (*raw).overlapped,
                std::ptr::null_mut(),
                0,
            )
        };
        // A success sent all `len` bytes: asking past the end of the file (one that
        // shrank) fails with `WSAEINVAL` instead of sending less
        // (`test_send_file_past_the_end_fails`).
        // SAFETY: the return value is mapped as in `connect`, right after the call.
        Ok(unsafe { self.started(on, raw, win_ret(ok), len) })
    }

    /// The `ConnectEx` of this provider, looked up once per port.
    fn connect_ex(&mut self, sock: Sock<'_>) -> io::Result<ConnectEx> {
        if let Some(f) = self.connect_ex {
            return Ok(f);
        }
        let guid = WSAID_CONNECTEX;
        let mut f: Option<ConnectEx> = None;
        let mut returned = 0u32;
        // SAFETY: the code takes a GUID in and writes one function pointer, and `f`
        // is `Option` of a function pointer, which has that size.
        let ret = unsafe {
            WSAIoctl(
                win::raw(sock),
                SIO_GET_EXTENSION_FUNCTION_POINTER,
                (&raw const guid).cast(),
                size_of::<Guid>() as u32,
                (&raw mut f).cast(),
                size_of::<Option<ConnectEx>>() as u32,
                &raw mut returned,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ret != 0 {
            // SAFETY: reads this thread's last Winsock error.
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
        }
        self.connect_ex = f;
        f.ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))
    }

    /// Connects `sock`, which `ConnectEx` needs bound; an unbound one is bound here.
    pub(crate) fn connect(
        &mut self,
        on: Associated,
        token: u64,
        addr: SocketAddr,
    ) -> io::Result<Started> {
        // SAFETY: open between `register` and `deregister` by the `Driver` contract.
        let sock = unsafe { win::borrow(on.socket) };
        let any: IpAddr = if addr.is_ipv4() {
            Ipv4Addr::UNSPECIFIED.into()
        } else {
            Ipv6Addr::UNSPECIFIED.into()
        };
        match super::bind_to(sock, SocketAddr::new(any, 0)) {
            Err(e) if e.raw_os_error() != Some(WSAEINVAL) => return Err(e),
            _ => {}
        }
        let connect_ex = self.connect_ex(sock)?;
        let mut op = self.op(on, token, OpKind::Connect);
        let len = win::encode_addr(addr, &mut op.addr);
        let raw = Box::into_raw(op);
        // SAFETY: `raw` is live, so the address stays put during the operation. No data
        // goes with the connect.
        let ok = unsafe {
            connect_ex(
                on.socket,
                (&raw const (*raw).addr).cast(),
                len,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                &raw mut (*raw).overlapped,
            )
        };
        // SAFETY: the return values are mapped to the Winsock convention `started`
        // reads, and the call above just ran on this thread.
        Ok(unsafe { self.started(on, raw, win_ret(ok), 0) })
    }

    /// Asks the kernel to end an operation; it still finishes exactly once.
    pub(crate) fn cancel(&self, on: Associated, op: InFlight) -> io::Result<()> {
        // SAFETY: the pointer is only compared; `socket` is open by the `Driver`
        // contract.
        let ok = unsafe { win::CancelIoEx(on.socket as Handle, op.0 as *mut c_void) };
        if ok != 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        // Already finished: its packet is on the way (edge case 62).
        if e.raw_os_error() == Some(ERROR_NOT_FOUND) {
            return Ok(());
        }
        Err(e)
    }

    /// Waits, then calls `f` for each finished operation.
    pub(crate) fn wait(
        &mut self,
        timeout: Option<Duration>,
        mut f: impl FnMut(Finished),
    ) -> io::Result<()> {
        let ms = timeout.map_or(INFINITE, |d| {
            u32::try_from(d.as_micros().div_ceil(1_000))
                .unwrap_or(u32::MAX)
                .min(INFINITE - 1)
        });
        #[cfg(any(test, net_io_shim))]
        super::shim::check(super::shim::Op::Wait)?;
        let mut removed = 0u32;
        // SAFETY: `entries` holds ENTRIES items; the port is open.
        let ok = unsafe {
            GetQueuedCompletionStatusEx(
                self.port.as_raw_handle(),
                self.entries.as_mut_ptr(),
                ENTRIES as u32,
                &raw mut removed,
                ms,
                0,
            )
        };
        if ok == 0 {
            let e = io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(WAIT_TIMEOUT) => Ok(()),
                _ => Err(e),
            };
        }
        for i in 0..removed as usize {
            let entry = self.entries[i];
            if entry.overlapped == 0 {
                // The wake: read before the worker looks at its inbox, so a wake
                // after that look posts a new packet. No operation has a null
                // `OVERLAPPED` (edge case 65).
                self.wake.pending.store(false, Ordering::Release);
                continue;
            }
            let raw = entry.overlapped as *mut Op;
            self.outstanding -= 1;
            // SAFETY: a dequeued packet's `OVERLAPPED` is the start of an `Op` that
            // came from `Box::into_raw` here, and the kernel is done with it.
            let status = unsafe { (*raw).overlapped.internal } as u32;
            let result = if status < 0x8000_0000 {
                Ok(entry.bytes as usize)
            } else {
                // SAFETY: as above.
                Err(unsafe { op_error(raw) })
            };
            // SAFETY: the packet was dequeued.
            f(unsafe { self.reclaim(raw, result) });
        }
        Ok(())
    }
}

/// A `BOOL` result in the Winsock convention; the error stays in the same slot
/// (`WSAGetLastError` reads `GetLastError`).
fn win_ret(ok: i32) -> i32 {
    if ok != 0 { 0 } else { -1 }
}

/// The error of a failed operation.
///
/// # Safety
///
/// `raw` is a live `Op` whose packet was dequeued.
unsafe fn op_error(raw: *const Op) -> io::Error {
    let (mut bytes, mut flags) = (0u32, 0u32);
    // SAFETY: by this function's contract; a closed socket reports its own error, which
    // nobody reads because the connection is gone.
    unsafe {
        if (*raw).pipe {
            GetOverlappedResult(
                (*raw).socket as Handle,
                &raw const (*raw).overlapped,
                &raw mut bytes,
                0,
            );
            return io::Error::from_raw_os_error(WSAGetLastError());
        }
        WSAGetOverlappedResult(
            (*raw).socket,
            &raw const (*raw).overlapped,
            &raw mut bytes,
            0,
            &raw mut flags,
        );
        io::Error::from_raw_os_error(WSAGetLastError())
    }
}

/// Whether `e` is a cancelled operation (std files it under `TimedOut`).
pub(crate) fn is_aborted(e: &io::Error) -> bool {
    e.raw_os_error() == Some(ERROR_OPERATION_ABORTED)
}

impl Drop for Port {
    fn drop(&mut self) {
        // The kernel writes into an operation until its packet arrives. The driver
        // cancelled everything; what is still out after a second stays allocated.
        for _ in 0..10 {
            if self.outstanding == 0 {
                return;
            }
            let _ = self.wait(Some(Duration::from_millis(100)), drop);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, offset_of};
    use windows_sys::Win32::Networking::WinSock as ws;
    use windows_sys::Win32::System::IO as wio;

    /// `TransmitFile` sends all it was asked for or fails: asking past the end of
    /// the file is `WSAEINVAL`, never a short count, so a success reports the
    /// length asked for.
    #[test]
    fn test_send_file_past_the_end_fails() {
        use std::io::{Read, Write};
        use std::os::windows::io::AsSocket;
        let path = std::env::temp_dir().join(format!("net-io-iocp-{}", std::process::id()));
        std::fs::File::create(&path)
            .unwrap()
            .write_all(&[3u8; 100])
            .unwrap();
        let file = Arc::new(std::fs::File::open(&path).unwrap());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peer = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let mut port = Port::with_skip(true).unwrap();
        let on = port.associate(stream.as_socket()).unwrap();
        let mut send = |len| match port.send_file(on, 7, file.clone(), 0, len).unwrap() {
            Started::Done(f) => f.result,
            Started::Pending(_) => {
                let mut got = None;
                while got.is_none() {
                    port.wait(Some(Duration::from_secs(5)), |f| got = Some(f))
                        .unwrap();
                }
                got.unwrap().result
            }
        };
        assert_eq!(send(100).unwrap(), 100);
        assert_eq!(send(101).unwrap_err().raw_os_error(), Some(WSAEINVAL));
        let mut back = [0u8; 100];
        peer.read_exact(&mut back).unwrap();
        drop((stream, port));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_layout_matches_windows_sys() {
        assert_eq!(size_of::<Overlapped>(), size_of::<wio::OVERLAPPED>());
        assert_eq!(align_of::<Overlapped>(), align_of::<wio::OVERLAPPED>());
        assert_eq!(
            offset_of!(Overlapped, event),
            offset_of!(wio::OVERLAPPED, hEvent)
        );
        assert_eq!(
            size_of::<OverlappedEntry>(),
            size_of::<wio::OVERLAPPED_ENTRY>()
        );
        assert_eq!(
            offset_of!(OverlappedEntry, bytes),
            offset_of!(wio::OVERLAPPED_ENTRY, dwNumberOfBytesTransferred)
        );
        assert_eq!(size_of::<IoSlice<'_>>(), size_of::<ws::WSABUF>());
        assert_eq!(size_of::<WsaBuf>(), size_of::<ws::WSABUF>());
        assert_eq!(offset_of!(WsaBuf, buf), offset_of!(ws::WSABUF, buf));
        assert_eq!(offset_of!(Op, overlapped), 0);
        assert_eq!(WSA_IO_PENDING, ws::WSA_IO_PENDING);
        assert_eq!(WSAENOBUFS, ws::WSAENOBUFS);
        assert_eq!(WSAEINVAL, ws::WSAEINVAL);
        assert_eq!(SO_UPDATE_CONNECT_CONTEXT, ws::SO_UPDATE_CONNECT_CONTEXT);
        assert_eq!(
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            ws::SIO_GET_EXTENSION_FUNCTION_POINTER
        );
        assert_eq!(XP1_IFS_HANDLES, ws::XP1_IFS_HANDLES);
        assert_eq!(WSAID_CONNECTEX.data1, ws::WSAID_CONNECTEX.data1);
        assert_eq!(WSAID_CONNECTEX.data4, ws::WSAID_CONNECTEX.data4);
        assert_eq!(
            u32::from(FILE_SKIP_COMPLETION_PORT_ON_SUCCESS),
            windows_sys::Win32::System::WindowsProgramming::FILE_SKIP_COMPLETION_PORT_ON_SUCCESS
        );
    }
}
