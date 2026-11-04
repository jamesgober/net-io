//! Windows named pipes.
//!
//! A pipe has no readiness and cannot join `WSAPoll`, so `PipeStream` gives the
//! connection core what it expects from a non-blocking socket: `read` and `write`
//! run overlapped against an internal buffer and report `WouldBlock` while the
//! kernel still holds it, and `wait` waits on the operation's event and the wake
//! channel's. Those buffers appear on first use; the reactor reads and writes
//! through its completion port and never allocates them.
//!
//! Every operation's `OVERLAPPED` and buffer live in one box, released only after
//! the operation has ended (`Drop`). A kill cancels through `CancelIoEx`.
//!
//! References: Microsoft Learn, "Named Pipes", `CreateNamedPipeW`,
//! `ConnectNamedPipe`, `CreateFileW`, `WaitNamedPipeW`, `GetOverlappedResult`,
//! `ConvertStringSecurityDescriptorToSecurityDescriptorW`. Constants and layouts
//! are checked against `windows-sys` by the tests below.

use std::ffi::c_void;
use std::io::{self, IoSlice};
use std::mem::ManuallyDrop;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use super::windows::{CancelIoEx, Overlapped, Wake};
use super::{Interest, Ready, Sock, poll_millis};

type Handle = *mut c_void;

const PIPE_ACCESS_DUPLEX: u32 = 3;
const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
const PIPE_TYPE_BYTE: u32 = 0;
const PIPE_READMODE_BYTE: u32 = 0;
const PIPE_WAIT: u32 = 0;
const PIPE_REJECT_REMOTE_CLIENTS: u32 = 8;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const OPEN_EXISTING: u32 = 3;
const SECURITY_SQOS_PRESENT: u32 = 0x0010_0000;
/// `SECURITY_IDENTIFICATION`: the impersonation level, 1, shifted into place.
const SECURITY_IDENTIFICATION: u32 = 1 << 16;
const SDDL_REVISION_1: u32 = 1;
const TOKEN_QUERY: u32 = 8;
const TOKEN_USER_CLASS: i32 = 1;
#[cfg(test)]
const TOKEN_OWNER_CLASS: i32 = 4;
/// `SE_KERNEL_OBJECT`: a handle to any kernel object, a pipe included.
const SE_KERNEL_OBJECT: i32 = 6;
const OWNER_SECURITY_INFORMATION: u32 = 1;
const WAIT_TIMEOUT: u32 = 258;
const WAIT_FAILED: u32 = 0xFFFF_FFFF;
const INFINITE: u32 = 0xFFFF_FFFF;

const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_ACCESS_DENIED: i32 = 5;
const ERROR_BROKEN_PIPE: i32 = 109;
const ERROR_SEM_TIMEOUT: i32 = 121;
const ERROR_PIPE_BUSY: i32 = 231;
const ERROR_NO_DATA: i32 = 232;
const ERROR_PIPE_CONNECTED: i32 = 535;
const ERROR_OPERATION_ABORTED: i32 = 995;
const ERROR_IO_INCOMPLETE: i32 = 996;
const ERROR_IO_PENDING: i32 = 997;

/// The bytes one direction keeps in user space.
const BUFFER: usize = 16 * 1024;
/// How long a close waits for bytes still in flight.
const CLOSE_FLUSH_MS: u32 = 1_000;

#[repr(C)]
struct SecurityAttributes {
    length: u32,
    descriptor: *mut c_void,
    inherit: i32,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateNamedPipeW(
        name: *const u16,
        open_mode: u32,
        pipe_mode: u32,
        max_instances: u32,
        out_size: u32,
        in_size: u32,
        default_timeout: u32,
        attributes: *const SecurityAttributes,
    ) -> Handle;
    fn ConnectNamedPipe(pipe: Handle, overlapped: *mut Overlapped) -> i32;
    fn DisconnectNamedPipe(pipe: Handle) -> i32;
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        attributes: *const SecurityAttributes,
        disposition: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
    fn WaitNamedPipeW(name: *const u16, timeout: u32) -> i32;
    fn GetNamedPipeClientProcessId(pipe: Handle, pid: *mut u32) -> i32;
    fn GetNamedPipeServerProcessId(pipe: Handle, pid: *mut u32) -> i32;
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
    fn CreateEventW(
        attributes: *const c_void,
        manual: i32,
        initial: i32,
        name: *const u16,
    ) -> Handle;
    fn WaitForMultipleObjects(count: u32, handles: *const Handle, all: i32, ms: u32) -> u32;
    fn WaitForSingleObject(handle: Handle, ms: u32) -> u32;
    fn GetCurrentProcess() -> Handle;
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    fn GetTokenInformation(
        token: Handle,
        class: i32,
        info: *mut c_void,
        len: u32,
        returned: *mut u32,
    ) -> i32;
    fn ConvertSidToStringSidW(sid: *mut c_void, text: *mut *mut u16) -> i32;
    fn GetSecurityInfo(
        handle: Handle,
        object: i32,
        info: u32,
        owner: *mut *mut c_void,
        group: *mut *mut c_void,
        dacl: *mut *mut c_void,
        sacl: *mut *mut c_void,
        descriptor: *mut *mut c_void,
    ) -> u32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text: *const u16,
        revision: u32,
        descriptor: *mut *mut c_void,
        size: *mut u32,
    ) -> i32;
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `\\.\pipe\<name>`, terminated.
pub(crate) fn pipe_path(name: &str) -> Vec<u16> {
    wide(&format!(r"\\.\pipe\{name}"))
}

fn is_invalid(h: Handle) -> bool {
    h.is_null() || h as isize == -1
}

fn event() -> io::Result<OwnedHandle> {
    // SAFETY: no attributes, no name; a manual-reset event, not signaled.
    let raw = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` was just returned, is open, and has no other owner.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

/// The result of an operation that may still run: `None` while it does.
///
/// # Safety
///
/// `overlapped` belongs to an operation started on `file`, and both are live.
unsafe fn result_of(file: Handle, overlapped: *const Overlapped) -> io::Result<Option<usize>> {
    let mut moved = 0u32;
    // SAFETY: by this function's contract; `moved` is written during the call.
    let ok = unsafe { GetOverlappedResult(file, overlapped, &raw mut moved, 0) };
    if ok != 0 {
        return Ok(Some(moved as usize));
    }
    let e = io::Error::last_os_error();
    match e.raw_os_error() {
        Some(ERROR_IO_INCOMPLETE) => Ok(None),
        _ => Err(e),
    }
}

/// One direction of a stream.
struct Side {
    overlapped: Overlapped,
    event: OwnedHandle,
    pending: bool,
    buf: Box<[u8]>,
    at: usize,
    len: usize,
    eof: bool,
}

impl Side {
    fn new() -> io::Result<Side> {
        Ok(Side {
            overlapped: Overlapped::default(),
            event: event()?,
            pending: false,
            buf: vec![0; BUFFER].into_boxed_slice(),
            at: 0,
            len: 0,
            eof: false,
        })
    }

    fn arm(&mut self) -> *mut Overlapped {
        self.overlapped = Overlapped {
            event: self.event.as_raw_handle() as usize,
            ..Overlapped::default()
        };
        &raw mut self.overlapped
    }
}

/// Both directions, boxed: the kernel holds their addresses.
struct Sides {
    read: Side,
    write: Side,
}

/// The instances of one pipe name this process holds: the spare and every server
/// end in use. A pipe exists while one of its instances is open, so while `live` is
/// above zero the name is ours. At zero another process may have created the name
/// since, and a new instance made without `FILE_FLAG_FIRST_PIPE_INSTANCE` would join
/// that pipe, with its security descriptor. Instances are made and closed under
/// this lock, so `live` never counts one that is already closed.
#[derive(Default)]
struct Instances {
    spare: Option<OwnedHandle>,
    live: usize,
}

type Held = Arc<Mutex<Instances>>;

fn hold(held: &Held) -> MutexGuard<'_, Instances> {
    held.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Instances {
    /// Closes an instance this process made.
    fn close(&mut self, handle: OwnedHandle) {
        drop(handle);
        self.live = self.live.saturating_sub(1);
    }

    /// Keeps `handle` as the spare, or closes it when there is one already.
    fn keep(&mut self, handle: OwnedHandle) {
        if self.spare.is_none() {
            self.spare = Some(handle);
        } else {
            self.close(handle);
        }
    }
}

/// A connected pipe, either end.
pub(crate) struct PipeStream {
    /// Closed in `Drop`, after the IO has ended, under the server's lock for a
    /// server end.
    handle: ManuallyDrop<OwnedHandle>,
    /// The server's instance count, for a server end.
    instances: Option<Held>,
    sides: Mutex<Option<Box<Sides>>>,
    abortive: AtomicBool,
}

impl std::fmt::Debug for PipeStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeStream")
            .field("handle", &self.handle)
            .finish_non_exhaustive()
    }
}

impl PipeStream {
    /// A client end.
    pub(crate) fn new(handle: OwnedHandle) -> PipeStream {
        PipeStream {
            handle: ManuallyDrop::new(handle),
            instances: None,
            sides: Mutex::new(None),
            abortive: AtomicBool::new(false),
        }
    }

    /// A server end, counted among `instances` until it closes.
    fn server_end(handle: OwnedHandle, instances: Held) -> PipeStream {
        PipeStream {
            handle: ManuallyDrop::new(handle),
            instances: Some(instances),
            sides: Mutex::new(None),
            abortive: AtomicBool::new(false),
        }
    }

    pub(crate) fn raw(&self) -> RawHandle {
        self.handle.as_raw_handle()
    }

    /// The handle's number in a socket's clothing, for the code that keeps one
    /// number per connection. Winsock answers `WSAENOTSOCK` to it, so socket options
    /// fail cleanly; IO and waits never take this path.
    pub(crate) fn as_sock(&self) -> Sock<'_> {
        // SAFETY: the number stays valid as long as `self`, and is never -1.
        unsafe { Sock::borrow_raw(self.handle.as_raw_handle() as u64) }
    }

    fn with<T>(&self, f: impl FnOnce(&mut Sides) -> io::Result<T>) -> io::Result<T> {
        let mut guard = self.sides.lock().unwrap_or_else(PoisonError::into_inner);
        if guard.is_none() {
            *guard = Some(Box::new(Sides {
                read: Side::new()?,
                write: Side::new()?,
            }));
        }
        match guard.as_mut() {
            Some(sides) => f(sides),
            None => Err(io::Error::from(io::ErrorKind::OutOfMemory)),
        }
    }

    fn start_read(&self, s: &mut Side) -> io::Result<()> {
        let overlapped = s.arm();
        // SAFETY: `s` lives in the box, which outlives the operation (`Drop`); the
        // handle is open.
        let ok = unsafe {
            ReadFile(
                self.raw(),
                s.buf.as_mut_ptr(),
                BUFFER as u32,
                std::ptr::null_mut(),
                overlapped,
            )
        };
        if ok != 0 {
            s.pending = true;
            return Ok(());
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(ERROR_IO_PENDING) => {
                s.pending = true;
                Ok(())
            }
            Some(ERROR_BROKEN_PIPE) => {
                s.eof = true;
                Ok(())
            }
            _ => Err(e),
        }
    }

    /// Bytes read earlier, or `WouldBlock` with a read under way.
    pub(crate) fn read(&self, out: &mut [u8]) -> io::Result<usize> {
        self.with(|sides| {
            let s = &mut sides.read;
            loop {
                if s.at < s.len {
                    let n = (s.len - s.at).min(out.len());
                    out[..n].copy_from_slice(&s.buf[s.at..s.at + n]);
                    s.at += n;
                    return Ok(n);
                }
                if s.eof {
                    return Ok(0);
                }
                if !s.pending {
                    self.start_read(s)?;
                    continue;
                }
                // SAFETY: the operation was started on this handle and lives in `s`.
                match unsafe { result_of(self.raw(), &raw const s.overlapped) } {
                    Ok(None) => return Err(io::Error::from(io::ErrorKind::WouldBlock)),
                    Ok(Some(n)) => {
                        s.pending = false;
                        s.at = 0;
                        s.len = n;
                    }
                    Err(e) => {
                        s.pending = false;
                        match e.raw_os_error() {
                            Some(ERROR_BROKEN_PIPE) => s.eof = true,
                            // A kill cancelled it: the caller looks at the kill flag.
                            Some(ERROR_OPERATION_ABORTED) => {
                                return Err(io::Error::from(io::ErrorKind::WouldBlock));
                            }
                            _ => return Err(e),
                        }
                    }
                }
            }
        })
    }

    /// Copies up to one buffer's worth and starts writing it; like a socket's send
    /// buffer, a failure of those bytes surfaces on the next call. `WouldBlock` while
    /// the previous write runs.
    pub(crate) fn write(&self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        self.with(|sides| {
            let s = &mut sides.write;
            if s.pending {
                // SAFETY: the operation was started on this handle and lives in `s`.
                match unsafe { result_of(self.raw(), &raw const s.overlapped) } {
                    Ok(None) => return Err(io::Error::from(io::ErrorKind::WouldBlock)),
                    Ok(Some(_)) => s.pending = false,
                    Err(e) => {
                        s.pending = false;
                        return Err(e);
                    }
                }
            }
            let n = data.len().min(BUFFER);
            s.buf[..n].copy_from_slice(&data[..n]);
            let overlapped = s.arm();
            // SAFETY: as in `start_read`.
            let ok = unsafe {
                WriteFile(
                    self.raw(),
                    s.buf.as_ptr(),
                    n as u32,
                    std::ptr::null_mut(),
                    overlapped,
                )
            };
            if ok == 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() != Some(ERROR_IO_PENDING) {
                    return Err(e);
                }
            }
            s.pending = true;
            Ok(n)
        })
    }

    pub(crate) fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        match bufs.iter().find(|b| !b.is_empty()) {
            Some(b) => self.write(b),
            None => Ok(0),
        }
    }

    /// Waits for `interest`, the wake channel, or the timeout.
    pub(crate) fn wait(
        &self,
        interest: Interest,
        wake: Option<&Wake>,
        timeout: Option<Duration>,
    ) -> io::Result<Ready> {
        let event = self.with(|sides| match interest {
            Interest::Read => {
                let s = &mut sides.read;
                if !s.pending && s.at >= s.len && !s.eof {
                    self.start_read(s)?;
                }
                if !s.pending {
                    return Ok(None);
                }
                Ok(Some(s.event.as_raw_handle()))
            }
            Interest::Write => {
                let s = &sides.write;
                Ok(s.pending.then(|| s.event.as_raw_handle()))
            }
        })?;
        let Some(event) = event else {
            return Ok(Ready::Socket);
        };
        wait_for(event, wake, timeout)
    }

    /// Unread bytes are dropped at close, and nothing waits for a flush.
    pub(crate) fn set_abortive(&self) {
        self.abortive.store(true, Ordering::Relaxed);
    }

    /// The process that created the pipe's server end.
    pub(crate) fn server_pid(&self) -> io::Result<u32> {
        let mut pid = 0u32;
        // SAFETY: the handle is open; `pid` is written during the call.
        if unsafe { GetNamedPipeServerProcessId(self.raw(), &raw mut pid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(pid)
    }

    /// The owner of the pipe's security descriptor, as a string SID: the account
    /// (or, for an elevated administrator, the group) that created its first
    /// instance. Read from the handle, so it describes the pipe this end is
    /// connected to.
    pub(crate) fn owner_sid(&self) -> io::Result<String> {
        let mut owner: *mut c_void = std::ptr::null_mut();
        let mut descriptor: *mut c_void = std::ptr::null_mut();
        // SAFETY: the handle is open; `owner` and `descriptor` are written during the
        // call, and `owner` points into `descriptor`, which is freed below.
        let status = unsafe {
            GetSecurityInfo(
                self.raw(),
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &raw mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &raw mut descriptor,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let text = if owner.is_null() {
            Err(io::Error::from(io::ErrorKind::NotFound))
        } else {
            // SAFETY: `owner` points to a SID inside `descriptor`, still allocated.
            unsafe { sid_string(owner) }
        };
        // SAFETY: the call says to free the descriptor so.
        let _ = unsafe { LocalFree(descriptor) };
        text
    }

    /// The process that opened the pipe's client end.
    pub(crate) fn client_pid(&self) -> io::Result<u32> {
        let mut pid = 0u32;
        // SAFETY: the handle is open; `pid` is written during the call.
        if unsafe { GetNamedPipeClientProcessId(self.raw(), &raw mut pid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(pid)
    }
}

impl Drop for PipeStream {
    fn drop(&mut self) {
        self.settle();
        // SAFETY: the handle is taken once, here, and nothing uses it after.
        let handle = unsafe { ManuallyDrop::take(&mut self.handle) };
        match &self.instances {
            Some(held) => hold(held).close(handle),
            None => drop(handle),
        }
    }
}

impl PipeStream {
    /// Ends the IO still under way, so the box can go.
    fn settle(&mut self) {
        let sides = self
            .sides
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let Some(sides) = sides else { return };
        let raw = self.handle.as_raw_handle();
        // Closing a pipe keeps what is already in it readable, so only a write the
        // kernel has not taken yet needs a moment.
        if sides.write.pending && !self.abortive.load(Ordering::Relaxed) {
            // SAFETY: the event is open; the wait is bounded.
            let _ =
                unsafe { WaitForSingleObject(sides.write.event.as_raw_handle(), CLOSE_FLUSH_MS) };
        }
        if sides.read.pending || sides.write.pending {
            // SAFETY: the handle is open; a null `OVERLAPPED` means all of its operations.
            let _ = unsafe { CancelIoEx(raw, std::ptr::null_mut()) };
            for s in [&sides.read, &sides.write] {
                if s.pending {
                    let mut moved = 0u32;
                    // SAFETY: the operation was started on this handle; this waits for
                    // its end, so the box is released after the kernel lets go of it.
                    let _ = unsafe {
                        GetOverlappedResult(raw, &raw const s.overlapped, &raw mut moved, 1)
                    };
                }
            }
        }
    }
}

fn wait_for(event: RawHandle, wake: Option<&Wake>, timeout: Option<Duration>) -> io::Result<Ready> {
    let handles = [event, wake.map_or(std::ptr::null_mut(), Wake::event_raw)];
    let count = if wake.is_some() { 2 } else { 1 };
    let ms = match poll_millis(timeout) {
        n if n < 0 => INFINITE,
        n => n.unsigned_abs(),
    };
    // SAFETY: `count` handles are open for the call.
    let ret = unsafe { WaitForMultipleObjects(count, handles.as_ptr(), 0, ms) };
    match ret {
        0 => Ok(Ready::Socket),
        1 => {
            if let Some(w) = wake {
                w.take();
            }
            Ok(Ready::Woken)
        }
        WAIT_TIMEOUT => Ok(Ready::TimedOut),
        WAIT_FAILED => Err(io::Error::last_os_error()),
        _ => Err(io::Error::other("unexpected wait result")),
    }
}

/// A security descriptor from SDDL text.
pub(crate) struct Descriptor(usize);

impl Descriptor {
    pub(crate) fn from_sddl(text: &str) -> io::Result<Descriptor> {
        let text = wide(text);
        let mut out: *mut c_void = std::ptr::null_mut();
        // SAFETY: `text` is terminated; `out` is written during the call.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &raw mut out,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Descriptor(out as usize))
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: the memory came from the conversion above, which says to free it so.
        let _ = unsafe { LocalFree(self.0 as *mut c_void) };
    }
}

/// A SID as text (`S-1-5-18`).
///
/// # Safety
///
/// `sid` points to a valid SID for the call.
unsafe fn sid_string(sid: *mut c_void) -> io::Result<String> {
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid` is valid by this function's contract; `text` is written.
    if unsafe { ConvertSidToStringSidW(sid, &raw mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut len = 0;
    // SAFETY: the string is terminated, per the conversion's contract.
    let out = unsafe {
        while *text.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(text, len))
    };
    // SAFETY: the conversion says to free it so.
    let _ = unsafe { LocalFree(text.cast()) };
    Ok(out)
}

/// A SID from this process's token: `TokenUser` or `TokenOwner`, whose structures
/// both start with the SID pointer.
fn token_sid(class: i32) -> io::Result<String> {
    let mut token: Handle = std::ptr::null_mut();
    // SAFETY: the current-process pseudo handle needs no closing; `token` is written.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `token` was just returned, is open, and has no other owner.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    // The structure and its SID, aligned for the pointer it starts with.
    let mut info = [0usize; 32];
    let mut returned = 0u32;
    // SAFETY: `info` has room for the stated length; it is written during the call.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            class,
            info.as_mut_ptr().cast(),
            size_of_val(&info) as u32,
            &raw mut returned,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the first word points to the SID, inside `info`, as the call filled it.
    unsafe { sid_string(info[0] as *mut c_void) }
}

/// This process's default owner for new objects, which a pipe it creates gets.
#[cfg(test)]
pub(crate) fn token_owner_sid() -> io::Result<String> {
    token_sid(TOKEN_OWNER_CLASS)
}

/// The SDDL that lets only the current user in (and the system, when asked).
pub(crate) fn owner_sddl(system: bool) -> io::Result<String> {
    let user = token_sid(TOKEN_USER_CLASS)?;
    let mut sddl = format!("D:P(A;;GA;;;{user})");
    if system {
        sddl.push_str("(A;;GA;;;SY)");
    }
    Ok(sddl)
}

/// What every instance of a pipe is created with.
pub(crate) struct PipeParams {
    pub(crate) max_instances: u8,
    pub(crate) inbound: u32,
    pub(crate) outbound: u32,
}

/// The server side of a pipe name.
pub(crate) struct PipeServer {
    path: Vec<u16>,
    descriptor: Descriptor,
    params: PipeParams,
    instances: Held,
}

impl std::fmt::Debug for PipeServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeServer").finish_non_exhaustive()
    }
}

impl Drop for PipeServer {
    fn drop(&mut self) {
        let mut held = hold(&self.instances);
        if let Some(spare) = held.spare.take() {
            held.close(spare);
        }
    }
}

/// The error for a name another process holds.
fn name_taken(e: io::Error) -> io::Error {
    io::Error::new(io::ErrorKind::AddrInUse, e)
}

impl PipeServer {
    /// Creates the first instance, which fails if the name is taken: another process
    /// that made it first owns it.
    pub(crate) fn create(
        name: &str,
        params: PipeParams,
        descriptor: Descriptor,
    ) -> io::Result<PipeServer> {
        let server = PipeServer {
            path: pipe_path(name),
            descriptor,
            params,
            instances: Held::default(),
        };
        {
            let mut held = hold(&server.instances);
            let first = server.instance(&mut held)?;
            held.spare = Some(first);
        }
        Ok(server)
    }

    /// A new instance, made under the lock. With no instance held it claims the name
    /// (`FILE_FLAG_FIRST_PIPE_INSTANCE`), and `ERROR_ACCESS_DENIED` or
    /// `ERROR_PIPE_BUSY` then mean another process owns it: `AddrInUse`.
    fn instance(&self, held: &mut Instances) -> io::Result<OwnedHandle> {
        let attributes = SecurityAttributes {
            length: size_of::<SecurityAttributes>() as u32,
            descriptor: self.descriptor.0 as *mut c_void,
            inherit: 0,
        };
        let first = held.live == 0;
        let open_mode = PIPE_ACCESS_DUPLEX
            | FILE_FLAG_OVERLAPPED
            | if first {
                FILE_FLAG_FIRST_PIPE_INSTANCE
            } else {
                0
            };
        // SAFETY: `path` is terminated; `attributes` and its descriptor live for the call.
        let raw = unsafe {
            CreateNamedPipeW(
                self.path.as_ptr(),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                u32::from(self.params.max_instances),
                self.params.outbound,
                self.params.inbound,
                0,
                &raw const attributes,
            )
        };
        if is_invalid(raw) {
            let e = io::Error::last_os_error();
            return Err(match e.raw_os_error() {
                Some(ERROR_ACCESS_DENIED | ERROR_PIPE_BUSY) if first => name_taken(e),
                _ => e,
            });
        }
        held.live += 1;
        // SAFETY: `raw` was just returned, is open, and has no other owner.
        Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
    }

    /// Waits for a client; `None` when `wake` fired first. The next instance exists
    /// before this returns, so a client never finds none, unless the instance cap is
    /// reached (with `max_instances(1)`, always): the name is then free once the
    /// connections close, and the next accept claims it again.
    pub(crate) fn accept(&self, wake: Option<&Wake>) -> io::Result<Option<PipeStream>> {
        loop {
            let handle = {
                let mut held = hold(&self.instances);
                match held.spare.take() {
                    Some(h) => h,
                    None => self.instance(&mut held)?,
                }
            };
            match self.connect(&handle, wake) {
                Ok(true) => {
                    let mut held = hold(&self.instances);
                    // `handle` is open, so this joins our own pipe.
                    if held.spare.is_none() {
                        if let Ok(next) = self.instance(&mut held) {
                            held.spare = Some(next);
                        }
                    }
                    drop(held);
                    return Ok(Some(PipeStream::server_end(handle, self.instances.clone())));
                }
                Ok(false) => {
                    hold(&self.instances).keep(handle);
                    return Ok(None);
                }
                // The client came and went before the call: this instance is spent.
                Err(e) if e.raw_os_error() == Some(ERROR_NO_DATA) => {
                    // SAFETY: the handle is open.
                    let _ = unsafe { DisconnectNamedPipe(handle.as_raw_handle()) };
                    hold(&self.instances).keep(handle);
                }
                Err(e) => {
                    // Keep the name: a fresh instance replaces this one while it is
                    // still open, and when none can be made this one stays.
                    let mut held = hold(&self.instances);
                    match self.instance(&mut held) {
                        Ok(next) => {
                            held.close(handle);
                            held.keep(next);
                        }
                        Err(_) => {
                            // SAFETY: the handle is open.
                            let _ = unsafe { DisconnectNamedPipe(handle.as_raw_handle()) };
                            held.keep(handle);
                        }
                    }
                    return Err(e);
                }
            }
        }
    }

    /// `true` once a client is connected to `handle`, `false` when `wake` fired.
    fn connect(&self, handle: &OwnedHandle, wake: Option<&Wake>) -> io::Result<bool> {
        let raw = handle.as_raw_handle();
        let ev = event()?;
        let mut overlapped = Overlapped {
            event: ev.as_raw_handle() as usize,
            ..Overlapped::default()
        };
        // SAFETY: `overlapped` and `ev` outlive the operation: every path below waits
        // for its end before returning.
        if unsafe { ConnectNamedPipe(raw, &raw mut overlapped) } != 0 {
            return Ok(true);
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(ERROR_PIPE_CONNECTED) => return Ok(true),
            Some(ERROR_IO_PENDING) => {}
            _ => return Err(e),
        }
        let ready = wait_for(ev.as_raw_handle(), wake, None);
        if !matches!(ready, Ok(Ready::Socket)) {
            // SAFETY: the operation lives in `overlapped`, on this handle.
            let _ = unsafe { CancelIoEx(raw, (&raw mut overlapped).cast()) };
        }
        let mut moved = 0u32;
        // SAFETY: as above; this waits for the operation's end.
        let ok = unsafe { GetOverlappedResult(raw, &raw const overlapped, &raw mut moved, 1) };
        if ok != 0 {
            return Ok(true);
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(ERROR_OPERATION_ABORTED) => Ok(false),
            _ => Err(e),
        }
    }
}

/// Opens the client end: the server may identify this process, and no more. Waits
/// for a free instance up to `timeout`.
pub(crate) fn pipe_connect(name: &str, timeout: Duration) -> io::Result<PipeStream> {
    let path = pipe_path(name);
    let deadline = Instant::now() + timeout;
    loop {
        // SAFETY: `path` is terminated; no attributes, no template.
        let raw = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                std::ptr::null_mut(),
            )
        };
        if !is_invalid(raw) {
            // SAFETY: `raw` was just returned, is open, and has no other owner.
            return Ok(PipeStream::new(unsafe {
                OwnedHandle::from_raw_handle(raw)
            }));
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(ERROR_PIPE_BUSY) {
            return Err(e);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        let ms = u32::try_from(left.as_millis())
            .unwrap_or(u32::MAX - 1)
            .max(1);
        // SAFETY: `path` is terminated. A failure is looked at by the next open.
        if unsafe { WaitNamedPipeW(path.as_ptr(), ms) } == 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(ERROR_SEM_TIMEOUT) {
                return Err(io::Error::from(io::ErrorKind::TimedOut));
            }
        }
    }
}

/// Whether `e` from a pipe open says nobody serves the name.
pub(crate) fn is_no_pipe(e: &io::Error) -> bool {
    e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND)
}

/// Whether `e` from creating or accepting on a pipe says another process owns the
/// name.
pub(crate) fn is_name_taken(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::AddrInUse
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation as wf;
    use windows_sys::Win32::Security as sec;
    use windows_sys::Win32::Storage::FileSystem as fs;
    use windows_sys::Win32::System::Pipes as pipes;

    #[test]
    fn test_constants_match_windows_sys() {
        assert_eq!(PIPE_ACCESS_DUPLEX, fs::PIPE_ACCESS_DUPLEX);
        assert_eq!(FILE_FLAG_OVERLAPPED, fs::FILE_FLAG_OVERLAPPED);
        assert_eq!(
            FILE_FLAG_FIRST_PIPE_INSTANCE,
            fs::FILE_FLAG_FIRST_PIPE_INSTANCE
        );
        assert_eq!(PIPE_TYPE_BYTE, pipes::PIPE_TYPE_BYTE);
        assert_eq!(PIPE_READMODE_BYTE, pipes::PIPE_READMODE_BYTE);
        assert_eq!(PIPE_WAIT, pipes::PIPE_WAIT);
        assert_eq!(
            PIPE_REJECT_REMOTE_CLIENTS,
            pipes::PIPE_REJECT_REMOTE_CLIENTS
        );
        assert_eq!(GENERIC_READ, wf::GENERIC_READ);
        assert_eq!(GENERIC_WRITE, wf::GENERIC_WRITE);
        assert_eq!(OPEN_EXISTING, fs::OPEN_EXISTING);
        assert_eq!(SECURITY_SQOS_PRESENT, fs::SECURITY_SQOS_PRESENT);
        assert_eq!(SECURITY_IDENTIFICATION, fs::SECURITY_IDENTIFICATION);
        assert_eq!(TOKEN_QUERY, sec::TOKEN_QUERY);
        assert_eq!(TOKEN_USER_CLASS, sec::TokenUser);
        assert_eq!(TOKEN_OWNER_CLASS, sec::TokenOwner);
        assert_eq!(OWNER_SECURITY_INFORMATION, sec::OWNER_SECURITY_INFORMATION);
        assert_eq!(WAIT_TIMEOUT, wf::WAIT_TIMEOUT);
        assert_eq!(WAIT_FAILED, wf::WAIT_FAILED);
        assert_eq!(ERROR_FILE_NOT_FOUND as u32, wf::ERROR_FILE_NOT_FOUND);
        assert_eq!(ERROR_ACCESS_DENIED as u32, wf::ERROR_ACCESS_DENIED);
        assert_eq!(ERROR_BROKEN_PIPE as u32, wf::ERROR_BROKEN_PIPE);
        assert_eq!(ERROR_SEM_TIMEOUT as u32, wf::ERROR_SEM_TIMEOUT);
        assert_eq!(ERROR_PIPE_BUSY as u32, wf::ERROR_PIPE_BUSY);
        assert_eq!(ERROR_NO_DATA as u32, wf::ERROR_NO_DATA);
        assert_eq!(ERROR_PIPE_CONNECTED as u32, wf::ERROR_PIPE_CONNECTED);
        assert_eq!(ERROR_OPERATION_ABORTED as u32, wf::ERROR_OPERATION_ABORTED);
        assert_eq!(ERROR_IO_INCOMPLETE as u32, wf::ERROR_IO_INCOMPLETE);
        assert_eq!(ERROR_IO_PENDING as u32, wf::ERROR_IO_PENDING);
        assert_eq!(
            size_of::<SecurityAttributes>(),
            size_of::<sec::SECURITY_ATTRIBUTES>()
        );
    }

    /// The owner a client reads is the creator's default owner for new objects.
    #[test]
    fn test_owner_sid_is_the_creators_default_owner() {
        let name = format!("net-io-sys-owner-{}", std::process::id());
        let params = PipeParams {
            max_instances: 1,
            inbound: 4096,
            outbound: 4096,
        };
        let sddl = owner_sddl(false).unwrap();
        let server =
            PipeServer::create(&name, params, Descriptor::from_sddl(&sddl).unwrap()).unwrap();
        let client = pipe_connect(&name, Duration::from_secs(1)).unwrap();
        let expected = token_owner_sid().unwrap();
        assert_eq!(client.owner_sid().unwrap(), expected);
        let accepted = server.accept(None).unwrap().unwrap();
        assert_eq!(accepted.owner_sid().unwrap(), expected);
    }

    /// A drain closes an idle connection, but a reply its owner already handed over
    /// (a write still under way) goes out whole.
    #[test]
    fn test_drain_leaves_a_pending_write_alone() {
        let name = format!("net-io-sys-drain-{}", std::process::id());
        let params = PipeParams {
            max_instances: 1,
            inbound: 1024,
            outbound: 1024,
        };
        let sddl = owner_sddl(false).unwrap();
        let server =
            PipeServer::create(&name, params, Descriptor::from_sddl(&sddl).unwrap()).unwrap();
        let client = pipe_connect(&name, Duration::from_secs(1)).unwrap();
        let stream = server.accept(None).unwrap().unwrap();
        // More than the pipe holds: the write stays in the kernel until read.
        assert_eq!(stream.write(&[5u8; BUFFER]).unwrap(), BUFFER);
        let slot = crate::sys::KillSlot::new();
        let generation = slot.install(stream.as_sock());
        slot.set_wake(Some(Arc::new(Wake::new().unwrap())));
        slot.set_idle(true);
        assert!(slot.drain_idle(generation));
        let (mut got, mut buf) = (0, [0u8; 4096]);
        let until = Instant::now() + Duration::from_secs(2);
        while got < BUFFER && Instant::now() < until {
            match client.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    client
                        .wait(Interest::Read, None, Some(Duration::from_millis(100)))
                        .unwrap();
                }
                Err(e) => panic!("{e}"),
            }
        }
        assert_eq!(got, BUFFER, "the drain cut the reply short");
    }

    #[test]
    fn test_owner_sddl_parses() {
        let text = owner_sddl(true).unwrap();
        assert!(text.starts_with("D:P(A;;GA;;;S-1-"), "{text}");
        assert!(text.ends_with("(A;;GA;;;SY)"));
        Descriptor::from_sddl(&text).unwrap();
    }
}
