//! Windows named-pipe transport (change x1-apps-all-platforms, task 1.3; design.md decisions 1-2).
//!
//! The pipes are tokio's (`tokio::net::windows::named_pipe`, chosen in spike 1.1) driven by one
//! private background runtime, so the [`Transport`] and [`Listener`] traits stay blocking like the
//! Unix ones. Callers must not use them from inside an async runtime thread.
//!
//! Access control, in depth:
//! - every pipe instance carries the protected DACL `D:P(A;;GA;;;<current user SID>)`, so only the
//!   current OS user (and nobody through inheritance) can open it; remote clients are rejected;
//! - the first instance is created with `FILE_FLAG_FIRST_PIPE_INSTANCE`, so `bind` fails when
//!   another process (possibly another user's squatter) already owns the name;
//! - the server checks the connected client's token user SID and closes a foreign peer before
//!   reading anything; the client checks the server's SID the same way against pipe squatting.
//!
//! The peer is identified via its process id (`GetNamedPipe{Client,Server}ProcessId`), then that
//! process's token. The DACL is the primary control; the SID check is the second one.

#![allow(unsafe_code)] // FFI to the Win32 security API; each block has a SAFETY note.

use super::{Listener, Transport, pipe_name, user_only_sddl};
use std::ffi::c_void;
use std::future::Future;
use std::io::{self, Read, Write};
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, PipeMode, ServerOptions,
};
use tokio::runtime::Runtime;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_PIPE_BUSY, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    EqualSid, GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// How long `connect` retries while every server instance is busy.
const BUSY_RETRY: Duration = Duration::from_secs(5);

/// The private runtime that drives pipe I/O for the blocking API. One worker thread drives the
/// I/O and timer drivers; blocking callers wait in `Handle::block_on`.
fn runtime() -> io::Result<&'static Runtime> {
    static RT: OnceLock<Runtime> = OnceLock::new();
    if let Some(rt) = RT.get() {
        return Ok(rt);
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("ls-ipc-pipe")
        .enable_all()
        .build()?;
    // A racing thread may have set it first; then ours is dropped (not inside a runtime here).
    let _ = RT.set(rt);
    Ok(RT.get().expect("set above"))
}

/// Run `f` to completion on the pipe runtime, failing with `TimedOut` after `limit`.
fn block_on<T>(f: impl Future<Output = io::Result<T>>, limit: Option<Duration>) -> io::Result<T> {
    let rt = runtime()?;
    match limit {
        None => rt.handle().block_on(f),
        Some(d) => rt.handle().block_on(async move {
            tokio::time::timeout(d, f)
                .await
                .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
        }),
    }
}

// ---- Win32 security helpers ---------------------------------------------------------------

/// An owned kernel handle, closed on drop.
struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the handle was returned open by OpenProcess/OpenProcessToken and is closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// A `TOKEN_USER` buffer; the SID it points to lives inside the same buffer.
struct TokenUserBuf(Vec<u64>); // u64 for the alignment TOKEN_USER needs

impl TokenUserBuf {
    fn sid(&self) -> *mut c_void {
        // SAFETY: the buffer was filled by GetTokenInformation(TokenUser) and is at least
        // size_of::<TOKEN_USER>() and suitably aligned (checked in `of_process`).
        unsafe { (*(self.0.as_ptr() as *const TOKEN_USER)).User.Sid }
    }

    /// The token user of process `process` (a handle with PROCESS_QUERY_LIMITED_INFORMATION).
    fn of_process(process: HANDLE) -> io::Result<Self> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: `process` is a valid process handle; `token` is a valid out pointer.
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = OwnedHandle(token);
        let mut len = 0u32;
        // SAFETY: size query with a null buffer; fails with ERROR_INSUFFICIENT_BUFFER and sets len.
        unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut len) };
        if (len as usize) < std::mem::size_of::<TOKEN_USER>() {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        // SAFETY: `buf` is writable for at least `len` bytes and 8-byte aligned.
        let ok = unsafe {
            GetTokenInformation(token.0, TokenUser, buf.as_mut_ptr().cast(), len, &mut len)
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(TokenUserBuf(buf))
    }

    /// The token user of the current process.
    fn current() -> io::Result<Self> {
        // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no closing.
        Self::of_process(unsafe { GetCurrentProcess() })
    }

    /// The token user of process `pid`.
    fn of_pid(pid: u32) -> io::Result<Self> {
        // SAFETY: plain call; a null result is an error.
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h.is_null() {
            return Err(io::Error::last_os_error());
        }
        let h = OwnedHandle(h);
        Self::of_process(h.0)
    }

    fn same_user(&self, other: &Self) -> bool {
        // SAFETY: both SIDs are valid, inside live TOKEN_USER buffers.
        unsafe { EqualSid(self.sid(), other.sid()) != 0 }
    }

    /// The SID in string form (`S-1-5-21-...`), for the SDDL. Not secret.
    fn sid_string(&self) -> io::Result<String> {
        let mut s: *mut u16 = std::ptr::null_mut();
        // SAFETY: valid SID; `s` receives a LocalAlloc'd NUL-terminated string freed below.
        if unsafe { ConvertSidToStringSidW(self.sid(), &mut s) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `s` is NUL-terminated per the API contract.
        let len = (0..).take_while(|&i| unsafe { *s.add(i) } != 0).count();
        // SAFETY: `s` is valid for `len` u16s.
        let out = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(s, len) });
        // SAFETY: allocated by ConvertSidToStringSidW with LocalAlloc.
        unsafe { LocalFree(s.cast()) };
        Ok(out)
    }
}

/// A self-relative security descriptor parsed from SDDL, freed on drop.
struct SecurityDescriptor(PSECURITY_DESCRIPTOR);
// SAFETY: the descriptor is an immutable LocalAlloc'd block owned by this value alone.
unsafe impl Send for SecurityDescriptor {}
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated; `sd` receives a LocalAlloc'd descriptor.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(SecurityDescriptor(sd))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe { LocalFree(self.0) };
    }
}

/// The OS user of the process on the other end of `pipe`.
fn peer_user(pipe: &impl AsRawHandle, server_side: bool) -> io::Result<TokenUserBuf> {
    let h = pipe.as_raw_handle() as HANDLE;
    let mut pid = 0u32;
    // SAFETY: `h` is a live pipe handle owned by `pipe`; `pid` is a valid out pointer.
    let ok = unsafe {
        if server_side {
            GetNamedPipeClientProcessId(h, &mut pid)
        } else {
            GetNamedPipeServerProcessId(h, &mut pid)
        }
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    TokenUserBuf::of_pid(pid)
}

fn foreign_peer() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "named pipe peer runs as another OS user",
    )
}

// ---- Stream -------------------------------------------------------------------------------

enum Pipe {
    Server(NamedPipeServer),
    Client(NamedPipeClient),
}

impl Pipe {
    async fn readable(&self) -> io::Result<()> {
        match self {
            Pipe::Server(p) => p.readable().await,
            Pipe::Client(p) => p.readable().await,
        }
    }
    async fn writable(&self) -> io::Result<()> {
        match self {
            Pipe::Server(p) => p.writable().await,
            Pipe::Client(p) => p.writable().await,
        }
    }
    fn try_read(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Pipe::Server(p) => p.try_read(buf),
            Pipe::Client(p) => p.try_read(buf),
        }
    }
    fn try_write(&self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Pipe::Server(p) => p.try_write(buf),
            Pipe::Client(p) => p.try_write(buf),
        }
    }
}

struct Inner {
    pipe: Pipe,
    read_timeout: Mutex<Option<Duration>>,
    write_timeout: Mutex<Option<Duration>>,
}

/// One end of a connected named pipe whose peer runs as the current OS user. Clones share the
/// connection and its timeouts, like a cloned Unix socket.
pub struct PipeStream(Arc<Inner>);

impl PipeStream {
    fn new(pipe: Pipe) -> Self {
        PipeStream(Arc::new(Inner {
            pipe,
            read_timeout: Mutex::new(None),
            write_timeout: Mutex::new(None),
        }))
    }
    fn timeout(m: &Mutex<Option<Duration>>) -> Option<Duration> {
        *m.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn check_timeout(d: Option<Duration>) -> io::Result<()> {
    // Same contract as UnixStream::set_read_timeout: a zero duration is an error.
    if d == Some(Duration::ZERO) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot set a 0 duration timeout",
        ));
    }
    Ok(())
}

impl Read for PipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let inner = &*self.0;
        let r = block_on(
            async {
                loop {
                    inner.pipe.readable().await?;
                    match inner.pipe.try_read(buf) {
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                        r => return r,
                    }
                }
            },
            Self::timeout(&inner.read_timeout),
        );
        match r {
            // The peer closed its end: end of stream, as on a Unix socket.
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(0),
            r => r,
        }
    }
}

impl Write for PipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let inner = &*self.0;
        block_on(
            async {
                loop {
                    inner.pipe.writable().await?;
                    match inner.pipe.try_write(buf) {
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                        r => return r,
                    }
                }
            },
            Self::timeout(&inner.write_timeout),
        )
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Transport for PipeStream {
    /// Open the pipe for `path` (see [`pipe_name`]) and refuse a server of another OS user.
    fn connect(path: &Path) -> io::Result<Self> {
        let name = pipe_name(path)?;
        let rt = runtime()?;
        let _ctx = rt.enter(); // pipes register with the runtime's I/O driver
        let deadline = std::time::Instant::now() + BUSY_RETRY;
        let client = loop {
            // Default security QoS: SECURITY_IDENTIFICATION, so the server cannot impersonate us.
            match ClientOptions::new().pipe_mode(PipeMode::Byte).open(&name) {
                Ok(c) => break c,
                Err(e)
                    if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return Err(e),
            }
        };
        if !peer_user(&client, false)?.same_user(&TokenUserBuf::current()?) {
            return Err(foreign_peer()); // dropping `client` closes it unread
        }
        Ok(PipeStream::new(Pipe::Client(client)))
    }
    fn try_clone(&self) -> io::Result<Self> {
        Ok(PipeStream(self.0.clone()))
    }
    fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        check_timeout(d)?;
        *self
            .0
            .read_timeout
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = d;
        Ok(())
    }
    fn set_write_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        check_timeout(d)?;
        *self
            .0
            .write_timeout
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = d;
        Ok(())
    }
}

// ---- Listener -----------------------------------------------------------------------------

/// A named-pipe endpoint for the current OS user. Holds the next unconnected instance; each
/// `accept` connects it, creates its successor and hands out the connected one.
pub struct PipeListener {
    name: String,
    me: TokenUserBuf,
    sd: SecurityDescriptor,
    next: Mutex<NamedPipeServer>,
}

impl PipeListener {
    fn instance(&self, first: bool) -> io::Result<NamedPipeServer> {
        create_instance(&self.name, &self.sd, first)
    }
}

/// Create one pipe instance with the current-user-only DACL.
fn create_instance(
    name: &str,
    sd: &SecurityDescriptor,
    first: bool,
) -> io::Result<NamedPipeServer> {
    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    let rt = runtime()?;
    let _ctx = rt.enter();
    // SAFETY: `sa` and the descriptor it points to outlive the call; CreateNamedPipeW copies
    // the descriptor into the kernel object.
    unsafe {
        ServerOptions::new()
            .pipe_mode(PipeMode::Byte)
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(name, (&mut sa as *mut SECURITY_ATTRIBUTES).cast())
    }
}

impl Listener for PipeListener {
    type Stream = PipeStream;

    /// Create the first instance of the pipe for `path`; fails if the name is already taken.
    fn bind(path: &Path) -> io::Result<Self> {
        let name = pipe_name(path)?;
        let me = TokenUserBuf::current()?;
        let sd = SecurityDescriptor::from_sddl(&user_only_sddl(&me.sid_string()?))?;
        let first = create_instance(&name, &sd, true)?;
        Ok(PipeListener {
            name,
            me,
            sd,
            next: Mutex::new(first),
        })
    }

    /// Wait for the next client of the current OS user. A client of another user (which the
    /// DACL should already stop) is disconnected unread and the wait continues.
    fn accept(&self) -> io::Result<PipeStream> {
        let mut next = self.next.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            block_on(next.connect(), None)?;
            let fresh = self.instance(false)?;
            let connected = std::mem::replace(&mut *next, fresh);
            match peer_user(&connected, true) {
                Ok(u) if u.same_user(&self.me) => {
                    return Ok(PipeStream::new(Pipe::Server(connected)));
                }
                // Foreign or unidentifiable peer: drop (close) it without reading.
                _ => drop(connected),
            }
        }
    }
}
