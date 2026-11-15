//! Kernel-backed process identity: socket peers, parent chains, executable digests, fd passing.
//! (design: openspec/changes/m3-daemon-sessions/design.md D2, D3; docs/v6-review.md §1.5)
//!
//! A process is named by [`ProcId`] = (pid, start time). The start time makes a recycled PID
//! distinguishable; on Linux a pidfd additionally pins the process while we read its /proc entry.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

/// pid plus kernel start time (Linux: clock ticks since boot; macOS: microseconds since epoch).
/// Only compared for equality and ordering on the same machine and boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcId {
    pub pid: u32,
    pub start: u64,
}

/// A process as read from the kernel right now.
#[derive(Debug, Clone, Copy)]
pub struct ProcInfo {
    pub id: ProcId,
    pub ppid: u32,
    pub uid: u32,
}

/// Executable identity a binary is pinned by: SHA-256 of the file on Linux, the code directory
/// hash (cdhash) on macOS, where the kernel enforces it page by page while the process runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Digest {
    Sha256([u8; 32]),
    CdHash([u8; 20]),
}

impl Digest {
    pub fn hex(&self) -> String {
        let b: &[u8] = match self {
            Digest::Sha256(b) => b,
            Digest::CdHash(b) => b,
        };
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}

/// The process on the other end of a connected Unix socket, as the kernel reports it.
pub struct Peer {
    pub uid: u32,
    pub id: ProcId,
    /// Executable path at attestation time (for audit messages only, never for trust).
    pub exe: PathBuf,
    #[cfg(target_os = "linux")]
    pidfd: Option<OwnedFd>,
    /// The executable inode the peer runs, its identity, and its SHA-256 (computed lazily).
    #[cfg(target_os = "linux")]
    exe_file: std::fs::File,
    #[cfg(target_os = "linux")]
    exe_id: Option<FileId>,
    #[cfg(target_os = "linux")]
    exe_hash: std::sync::OnceLock<Option<[u8; 32]>>,
    #[cfg(target_os = "macos")]
    code: Option<security_framework::os::macos::code_signing::SecCode>,
}

impl Peer {
    /// True when the peer is still the same live process it was at connect time.
    pub fn alive(&self) -> bool {
        #[cfg(target_os = "linux")]
        if let Some(fd) = &self.pidfd {
            return linux::pidfd_alive(fd.as_raw_fd());
        }
        info(self.id.pid).is_ok_and(|i| i.id == self.id)
    }

    /// True when the peer's running code is the binary pinned by `d`.
    pub fn runs(&self, d: &Digest) -> bool {
        match d {
            #[cfg(target_os = "linux")]
            Digest::Sha256(h) => self.exe_sha256().as_ref() == Some(h),
            #[cfg(target_os = "macos")]
            Digest::CdHash(h) => self
                .code
                .as_ref()
                .is_some_and(|c| macos::code_has_cdhash(c, h)),
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }

    /// True when the peer runs the pinned binary. On Linux, when the peer's executable is the
    /// very inode pinned, unchanged since (same dev/inode/size/mtime/ctime; ctime cannot be set
    /// by the user, and Linux refuses writes to a running executable), the hash is skipped.
    pub fn runs_pin(&self, p: &Pin) -> bool {
        #[cfg(target_os = "linux")]
        if p.id.is_some() && self.exe_id == p.id {
            return true;
        }
        self.runs(&p.digest)
    }

    #[cfg(target_os = "linux")]
    fn exe_sha256(&self) -> Option<[u8; 32]> {
        *self.exe_hash.get_or_init(|| {
            use std::io::Seek;
            let mut f = &self.exe_file;
            f.rewind().ok()?;
            sha256_reader(f).ok()
        })
    }

    /// Kernel identity of the process connected on `s`. Errors when the kernel cannot say.
    pub fn of(s: &UnixStream) -> io::Result<Peer> {
        #[cfg(target_os = "linux")]
        return linux::peer(s.as_raw_fd());
        #[cfg(target_os = "macos")]
        return macos::peer(s.as_raw_fd());
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = s;
            Err(io::Error::other(
                "peer attestation is not supported on this OS",
            ))
        }
    }
}

/// Current pid, parent and start time of `pid`.
pub fn info(pid: u32) -> io::Result<ProcInfo> {
    #[cfg(target_os = "linux")]
    return linux::stat(&format!("/proc/{pid}/stat"), pid);
    #[cfg(target_os = "macos")]
    return macos::info(pid);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        Err(io::Error::other("unsupported OS"))
    }
}

/// Identity of a just-spawned child or of this process.
pub fn id_of(pid: u32) -> io::Result<ProcId> {
    info(pid).map(|i| i.id)
}

/// True when `p` is one of `roots` or a descendant of one, walking the live parent chain from
/// the kernel. Never cached: the chain is re-read on each call. Fails closed: an unreadable hop,
/// a recycled PID (a parent younger than its child) or a reparented orphan all return false.
pub fn descends_from(p: ProcId, roots: &[ProcId]) -> bool {
    let Ok(mut cur) = info(p.pid) else {
        return false;
    };
    if cur.id != p {
        return false;
    }
    for _ in 0..4096 {
        if roots.contains(&cur.id) {
            return true;
        }
        if cur.ppid <= 1 {
            return false;
        }
        let Ok(parent) = hop(cur.ppid) else {
            return false;
        };
        if parent.id.start > cur.id.start {
            return false; // ppid was recycled by a younger process
        }
        // The child must still name this parent after we read it (no reparenting in between).
        match info(cur.id.pid) {
            Ok(again) if again.id == cur.id && again.ppid == parent.id.pid => {}
            _ => return false,
        }
        cur = parent;
    }
    false
}

/// One hop of the walk. On Linux the pidfd pins the process while its stat is read.
fn hop(pid: u32) -> io::Result<ProcInfo> {
    #[cfg(target_os = "linux")]
    {
        let fd = linux::pidfd_open(pid).ok();
        let i = info(pid)?;
        if let Some(fd) = fd
            && !linux::pidfd_alive(fd.as_raw_fd())
        {
            return Err(io::Error::other("process exited during check"));
        }
        Ok(i)
    }
    #[cfg(not(target_os = "linux"))]
    info(pid)
}

/// File identity used to skip re-hashing an unchanged pinned binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileId {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl FileId {
    fn of(m: &std::fs::Metadata) -> FileId {
        use std::os::unix::fs::MetadataExt;
        FileId {
            dev: m.dev(),
            ino: m.ino(),
            size: m.size(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
        }
    }
}

/// A pinned binary: its digest, plus its file identity when that is stable.
#[derive(Debug, Clone)]
pub struct Pin {
    pub digest: Digest,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))] // macOS validates the cdhash live
    id: Option<FileId>,
}

/// Pin the binary at `path`. The identity is kept only if the file did not change while it
/// was being hashed.
pub fn pin(path: &std::path::Path) -> io::Result<Pin> {
    let before = std::fs::metadata(path).map(|m| FileId::of(&m)).ok();
    let digest = file_digest(path)?;
    let after = std::fs::metadata(path).map(|m| FileId::of(&m)).ok();
    Ok(Pin {
        digest,
        id: before.filter(|b| Some(*b) == after),
    })
}

/// Digest that pins the binary at `path` (see [`Digest`]).
pub fn file_digest(path: &std::path::Path) -> io::Result<Digest> {
    #[cfg(target_os = "macos")]
    return macho::cdhash(&std::fs::read(path)?)
        .map(Digest::CdHash)
        .ok_or_else(|| io::Error::other("binary has no code signature (cdhash)"));
    #[cfg(not(target_os = "macos"))]
    sha256_reader(std::fs::File::open(path)?).map(Digest::Sha256)
}

#[cfg(not(target_os = "macos"))]
fn sha256_reader(mut r: impl io::Read) -> io::Result<[u8; 32]> {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match r.read(&mut buf)? {
            0 => return Ok(h.finalize().into()),
            n => h.update(&buf[..n]),
        }
    }
}

/// True when the kernel exposes pidfds (Linux ≥ 5.3). Doctor warns otherwise.
pub fn has_pidfd() -> bool {
    #[cfg(target_os = "linux")]
    return linux::pidfd_open(std::process::id()).is_ok();
    #[cfg(not(target_os = "linux"))]
    false
}

/// Send `fds` with a one-byte payload over `s` (SCM_RIGHTS).
pub fn send_fds(s: &UnixStream, fds: &[RawFd]) -> io::Result<()> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let payload = std::mem::size_of_val(fds) as u32;
    // SAFETY: CMSG_SPACE is a pure size computation.
    let space = unsafe { libc::CMSG_SPACE(payload) } as usize;
    let mut cbuf = vec![0u64; space.div_ceil(8)]; // u64 for cmsghdr alignment
    // SAFETY: msghdr is plain data; zeroed is a valid empty header we fill below.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr().cast();
    msg.msg_controllen = space as _;
    // SAFETY: msg_control points at `space` bytes we own, enough for one header plus `payload`
    // bytes (CMSG_SPACE); CMSG_FIRSTHDR/CMSG_DATA stay inside that buffer, and `fds` is copied
    // with its exact length.
    unsafe {
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(payload) as _;
        std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(c).cast::<RawFd>(), fds.len());
    }
    // macOS refuses (EMSGSIZE/ENOBUFS) instead of blocking while the socket buffer still holds
    // a frame the peer has not read yet, so retry until it drains.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        // SAFETY: msg and everything it points to are live for the duration of the call.
        if unsafe { libc::sendmsg(s.as_raw_fd(), &msg, 0) } == 1 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        let full = matches!(
            e.raw_os_error(),
            Some(libc::EMSGSIZE | libc::ENOBUFS | libc::EAGAIN | libc::EINTR)
        );
        if !full || std::time::Instant::now() >= deadline {
            return Err(e);
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// Receive up to `max` fds sent with [`send_fds`]. Each returned fd is owned (closed on drop).
pub fn recv_fds(s: &UnixStream, max: usize) -> io::Result<Vec<OwnedFd>> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let payload = (max * std::mem::size_of::<RawFd>()) as u32;
    // SAFETY: pure size computation.
    let space = unsafe { libc::CMSG_SPACE(payload) } as usize;
    let mut cbuf = vec![0u64; space.div_ceil(8)];
    // SAFETY: zeroed msghdr is valid; filled below.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr().cast();
    msg.msg_controllen = space as _;
    #[cfg(target_os = "linux")]
    let flags = libc::MSG_CMSG_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = 0;
    // SAFETY: buffers are live and sized as declared in msg.
    let n = unsafe { libc::recvmsg(s.as_raw_fd(), &mut msg, flags) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    let mut out = Vec::new();
    // SAFETY: we walk the control messages the kernel wrote into our buffer with the CMSG
    // macros, which never step past msg_controllen; each SCM_RIGHTS fd is a new descriptor
    // installed in this process, so taking ownership of it is sound.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(c).cast::<RawFd>();
                let count = ((*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize)
                    / std::mem::size_of::<RawFd>();
                for i in 0..count {
                    let fd = data.add(i).read_unaligned();
                    #[cfg(not(target_os = "linux"))]
                    libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                    out.push(OwnedFd::from_raw_fd(fd));
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::other("too many file descriptors received"));
    }
    Ok(out)
}

/// macOS: refuse debugger attach (PT_DENY_ATTACH). Linux: covered by PR_SET_DUMPABLE=0 in
/// [`crate::disable_core_dumps`]. Best effort.
pub fn deny_debugger_attach() {
    #[cfg(target_os = "macos")]
    // SAFETY: ptrace(PT_DENY_ATTACH) takes no pointers and only flags this process.
    unsafe {
        libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    const SO_PEERPIDFD: libc::c_int = 77;

    pub fn pidfd_open(pid: u32) -> io::Result<OwnedFd> {
        // SAFETY: pidfd_open takes a pid and flags and returns a new fd or -1.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the syscall returned a fresh descriptor we now own.
        Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
    }

    pub fn pidfd_alive(fd: RawFd) -> bool {
        // SAFETY: signal 0 only checks existence; a null siginfo is allowed.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd,
                0,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            ) == 0
        }
    }

    /// Parse /proc/<pid>/stat: ppid is field 4, starttime field 22. The comm field may contain
    /// spaces and parentheses, so fields are counted after the last ')'.
    pub fn stat(path: &str, pid: u32) -> io::Result<ProcInfo> {
        use std::os::unix::fs::MetadataExt;
        let s = std::fs::read_to_string(path)?;
        let uid = std::fs::metadata(path)?.uid();
        let rest = s
            .rfind(')')
            .map(|i| &s[i + 1..])
            .ok_or_else(|| io::Error::other("bad stat"))?;
        let f: Vec<&str> = rest.split_whitespace().collect();
        let num = |i: usize| -> io::Result<u64> {
            f.get(i)
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| io::Error::other("bad stat"))
        };
        // f[0] is field 3 (state), so field N is f[N-3].
        Ok(ProcInfo {
            id: ProcId {
                pid,
                start: num(19)?,
            },
            ppid: num(1)? as u32,
            uid,
        })
    }

    fn getsockopt<T>(fd: RawFd, opt: libc::c_int, v: &mut T) -> io::Result<()> {
        let mut len = std::mem::size_of::<T>() as libc::socklen_t;
        // SAFETY: v is a live, writable T and len is its exact size.
        if unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, opt, (v as *mut T).cast(), &mut len) }
            != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn peer(sock: RawFd) -> io::Result<Peer> {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        getsockopt(sock, libc::SO_PEERCRED, &mut cred)?;
        let pid = cred.pid as u32;
        // Kernel ≥ 6.5 hands us the connecting process's pidfd; otherwise open one now.
        let mut raw: RawFd = -1;
        let pidfd = match getsockopt(sock, SO_PEERPIDFD, &mut raw) {
            // SAFETY: the kernel installed a new pidfd for us.
            Ok(()) if raw >= 0 => Some(unsafe { OwnedFd::from_raw_fd(raw) }),
            _ => pidfd_open(pid).ok(),
        };
        // Open the /proc entry, then prove (pidfd alive, or same start time) it is still our peer.
        let dir = std::fs::File::open(format!("/proc/{pid}"))?;
        let at = format!("/proc/self/fd/{}", dir.as_raw_fd());
        let i = stat(&format!("{at}/stat"), pid)?;
        let exe = std::fs::read_link(format!("{at}/exe"))?;
        // /proc/<pid>/exe opens the inode actually mapped, even if the path was replaced since.
        let exe_file = std::fs::File::open(format!("{at}/exe"))?;
        let still = match &pidfd {
            Some(fd) => pidfd_alive(fd.as_raw_fd()),
            None => super::info(pid).is_ok_and(|j| j.id == i.id),
        };
        if !still {
            return Err(io::Error::other("peer exited during attestation"));
        }
        Ok(Peer {
            uid: cred.uid,
            id: i.id,
            exe,
            pidfd,
            exe_id: exe_file.metadata().ok().map(|m| FileId::of(&m)),
            exe_file,
            exe_hash: std::sync::OnceLock::new(),
        })
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use core_foundation::base::TCFType;
    use core_foundation::data::CFData;
    use security_framework::os::macos::code_signing::{
        Flags, GuestAttributes, SecCode, SecRequirement,
    };

    pub fn info(pid: u32) -> io::Result<ProcInfo> {
        // SAFETY: proc_bsdinfo is plain data.
        let mut bi: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        // SAFETY: proc_pidinfo writes at most `size` bytes into `bi`, which we own.
        let n = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut bi as *mut libc::proc_bsdinfo).cast(),
                size,
            )
        };
        if n != size {
            return Err(io::Error::last_os_error());
        }
        Ok(ProcInfo {
            id: ProcId {
                pid,
                start: bi.pbi_start_tvsec * 1_000_000 + bi.pbi_start_tvusec,
            },
            ppid: bi.pbi_ppid,
            uid: bi.pbi_uid,
        })
    }

    fn pid_path(pid: u32) -> io::Result<PathBuf> {
        use std::os::unix::ffi::OsStringExt;
        let mut buf = vec![0u8; 4 * 1024]; // PROC_PIDPATHINFO_MAXSIZE
        // SAFETY: proc_pidpath writes at most buf.len() bytes into buf.
        let n = unsafe {
            libc::proc_pidpath(
                pid as libc::c_int,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
            )
        };
        if n <= 0 {
            return Err(io::Error::last_os_error());
        }
        buf.truncate(n as usize);
        Ok(PathBuf::from(std::ffi::OsString::from_vec(buf)))
    }

    pub fn peer(sock: RawFd) -> io::Result<Peer> {
        let mut token = [0u32; 8]; // audit_token_t
        let mut len = std::mem::size_of_val(&token) as libc::socklen_t;
        // SAFETY: token is a writable 32-byte buffer and len is its size.
        if unsafe {
            libc::getsockopt(
                sock,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERTOKEN,
                token.as_mut_ptr().cast(),
                &mut len,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let (uid, pid) = (token[1], token[5]);
        let bytes: Vec<u8> = token.iter().flat_map(|v| v.to_ne_bytes()).collect();
        let data = CFData::from_buffer(&bytes);
        let mut attrs = GuestAttributes::new();
        attrs.set_audit_token(data.as_concrete_TypeRef());
        // The audit token carries the pid version, so this names exactly the connecting process
        // (not whatever later reuses its pid); validity checks fail once that process is gone.
        let code = SecCode::copy_guest_with_attribues(None, &attrs, Flags::NONE).ok();
        let i = info(pid)?;
        Ok(Peer {
            uid,
            id: i.id,
            exe: pid_path(pid).unwrap_or_default(),
            code,
        })
    }

    /// Dynamic check by the kernel's code-signing layer: the running code is intact and its
    /// cdhash is `h`.
    pub fn code_has_cdhash(c: &SecCode, h: &[u8; 20]) -> bool {
        let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
        let Ok(req) = format!("cdhash H\"{hex}\"").parse::<SecRequirement>() else {
            return false;
        };
        c.check_validity(Flags::NONE, &req).is_ok()
    }
}

#[cfg(target_os = "macos")]
mod macho {
    //! Minimal Mach-O reader: the cdhash of a thin 64-bit binary's primary code directory.
    use sha2::{Digest, Sha256};

    const MH_MAGIC_64: u32 = 0xfeed_facf;
    const LC_CODE_SIGNATURE: u32 = 0x1d;
    const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
    const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
    const CS_HASHTYPE_SHA256: u8 = 2;

    fn le(b: &[u8], o: usize) -> Option<u32> {
        Some(u32::from_le_bytes(
            b.get(o..o.checked_add(4)?)?.try_into().ok()?,
        ))
    }
    fn be(b: &[u8], o: usize) -> Option<u32> {
        Some(u32::from_be_bytes(
            b.get(o..o.checked_add(4)?)?.try_into().ok()?,
        ))
    }

    pub fn cdhash(f: &[u8]) -> Option<[u8; 20]> {
        if le(f, 0)? != MH_MAGIC_64 {
            return None; // fat or 32-bit binaries are not produced by our builds
        }
        let ncmds = le(f, 16)? as usize;
        let mut off = 32usize;
        let mut sig = None;
        for _ in 0..ncmds {
            let (cmd, size) = (le(f, off)?, le(f, off + 4)? as usize);
            if cmd == LC_CODE_SIGNATURE {
                sig = Some((le(f, off + 8)? as usize, le(f, off + 12)? as usize));
            }
            off = off.checked_add(size.max(8))?;
        }
        let (so, sl) = sig?;
        let sb = f.get(so..so.checked_add(sl)?)?;
        if be(sb, 0)? != CSMAGIC_EMBEDDED_SIGNATURE {
            return None;
        }
        for i in 0..be(sb, 8)? as usize {
            let (typ, bo) = (be(sb, 12 + 8 * i)?, be(sb, 16 + 8 * i)? as usize);
            if typ != 0 {
                continue; // slot 0 = primary CodeDirectory
            }
            if be(sb, bo)? != CSMAGIC_CODEDIRECTORY {
                return None;
            }
            let cd = sb.get(bo..bo.checked_add(be(sb, bo + 4)? as usize)?)?;
            // CodeDirectory layout: hashType is the byte at offset 37.
            if *cd.get(37)? != CS_HASHTYPE_SHA256 {
                return None;
            }
            return Sha256::digest(cd)[..20].try_into().ok();
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `smith run` writes a large frame and passes its stdio right after; the peer may not have
    /// read the frame yet (macOS then refuses the fd message instead of blocking).
    #[test]
    fn send_fds_waits_for_a_full_buffer_to_drain() {
        use std::io::{Read, Write};
        let (mut a, mut b) = UnixStream::pair().unwrap();
        const BIG: usize = 256 << 10;
        let w = std::thread::spawn(move || {
            a.write_all(&vec![7u8; BIG]).unwrap();
            send_fds(&a, &[0]).map(|_| a)
        });
        std::thread::sleep(std::time::Duration::from_millis(100));
        let mut buf = vec![0u8; BIG];
        b.read_exact(&mut buf).unwrap();
        let got = recv_fds(&b, 3).unwrap();
        assert_eq!(got.len(), 1);
        w.join()
            .unwrap()
            .expect("send_fds succeeds once the buffer drains");
    }

    #[test]
    fn self_identity_is_stable_and_descends_from_itself() {
        let me = id_of(std::process::id()).unwrap();
        assert_eq!(me, id_of(std::process::id()).unwrap());
        assert!(descends_from(me, &[me]));
    }

    #[test]
    fn child_descends_from_parent_but_not_the_reverse() {
        let me = id_of(std::process::id()).unwrap();
        let mut c = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .unwrap();
        let child = id_of(c.id()).unwrap();
        assert!(descends_from(child, &[me]));
        assert!(!descends_from(me, &[child]));
        // The same pid with a different start time is a different process.
        let fake = ProcId {
            pid: me.pid,
            start: me.start + 1,
        };
        assert!(!descends_from(child, &[fake]));
        c.kill().unwrap();
        c.wait().unwrap();
        assert!(
            !descends_from(child, &[me]),
            "a dead process never descends"
        );
    }

    #[test]
    fn peer_over_socketpair_is_this_process() {
        let (a, _b) = UnixStream::pair().unwrap();
        let p = Peer::of(&a).unwrap();
        assert_eq!(p.id, id_of(std::process::id()).unwrap());
        assert_eq!(p.uid, crate::current_uid());
        assert!(p.alive());
    }

    #[test]
    fn peer_runs_its_own_binary_digest_only() {
        let (a, _b) = UnixStream::pair().unwrap();
        let p = Peer::of(&a).unwrap();
        let Ok(d) = file_digest(&std::env::current_exe().unwrap()) else {
            return; // unsigned macOS x86_64 test binary: nothing to pin
        };
        assert!(p.runs(&d), "own digest {}", d.hex());
        let other = match d {
            Digest::Sha256(mut h) => {
                h[0] ^= 1;
                Digest::Sha256(h)
            }
            Digest::CdHash(mut h) => {
                h[0] ^= 1;
                Digest::CdHash(h)
            }
        };
        assert!(!p.runs(&other));
    }

    #[test]
    fn pin_matches_own_binary_and_not_a_changed_copy() {
        let (a, _b) = UnixStream::pair().unwrap();
        let p = Peer::of(&a).unwrap();
        let exe = std::env::current_exe().unwrap();
        let Ok(own) = pin(&exe) else { return };
        assert!(p.runs_pin(&own));
        let dir = std::env::temp_dir().join(format!("ls-pin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let copy = dir.join("bin");
        let mut b = std::fs::read(&exe).unwrap();
        // A different file (new inode) with different content never matches by identity.
        let n = b.len() / 2;
        b[n] ^= 0xff;
        std::fs::write(&copy, &b).unwrap();
        if let Ok(other) = pin(&copy)
            && other.digest != own.digest
        {
            assert!(!p.runs_pin(&other));
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn fds_cross_a_socket() {
        use std::io::{Read, Write};
        let (a, b) = UnixStream::pair().unwrap();
        let (mut r, w) = UnixStream::pair().unwrap();
        send_fds(&a, &[w.as_raw_fd()]).unwrap();
        drop(w);
        let mut got = recv_fds(&b, 4).unwrap();
        assert_eq!(got.len(), 1);
        let mut f = std::fs::File::from(got.remove(0));
        f.write_all(b"hi").unwrap();
        drop(f);
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "hi");
    }
}
