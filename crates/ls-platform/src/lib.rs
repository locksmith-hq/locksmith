//! OS-specific code. The only crate allowed `unsafe`; every block states why it is sound.

#[cfg(unix)]
pub mod proc;
pub mod screen;

use std::io;

/// Disable core dumps for this process so decrypted memory never reaches disk.
/// On Linux also marks the process non-dumpable, which blocks same-user ptrace attach.
pub fn disable_core_dumps() -> io::Result<()> {
    #[cfg(unix)]
    {
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: setrlimit reads a valid, initialised rlimit struct we own.
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) } != 0 {
            return Err(io::Error::last_os_error());
        }
        #[cfg(target_os = "linux")]
        // SAFETY: prctl(PR_SET_DUMPABLE, 0) takes plain integer arguments.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Best-effort: keep `len` bytes at `ptr` out of swap. Returns false when the OS refuses
/// (e.g. RLIMIT_MEMLOCK exhausted); callers continue without the lock.
pub fn mlock(ptr: *const u8, len: usize) -> bool {
    #[cfg(unix)]
    {
        // SAFETY: mlock only changes paging attributes of the given range; it never
        // dereferences it. Callers pass a live allocation they own.
        unsafe { libc::mlock(ptr.cast(), len) == 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = (ptr, len);
        false
    }
}

/// Undo [`mlock`]. Safe to call on a range that was never locked.
pub fn munlock(ptr: *const u8, len: usize) {
    #[cfg(unix)]
    // SAFETY: as for mlock; munlock on an unlocked range is a harmless no-op.
    unsafe {
        libc::munlock(ptr.cast(), len);
    }
    #[cfg(not(unix))]
    let _ = (ptr, len);
}

/// Real user id of this process (unix). Used to verify vault file ownership.
#[cfg(unix)]
pub fn current_uid() -> u32 {
    // SAFETY: getuid has no arguments, cannot fail and touches no memory.
    unsafe { libc::getuid() }
}

/// Terminal put into raw mode on construction; the original settings are restored on drop.
#[cfg(unix)]
pub struct RawMode(libc::termios);

#[cfg(unix)]
impl RawMode {
    /// Raw mode on stdin. Errors when stdin is not a terminal.
    pub fn enable() -> io::Result<Self> {
        // SAFETY: termios is plain data; tcgetattr fills it for fd 0 and we check the result.
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(0, &mut t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let orig = RawMode(t);
        // SAFETY: cfmakeraw edits the struct we own; tcsetattr reads it.
        unsafe { libc::cfmakeraw(&mut t) };
        // SAFETY: fd 0 is our terminal and `t` is a fully initialised termios from tcgetattr.
        if unsafe { libc::tcsetattr(0, libc::TCSANOW, &t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(orig)
    }
}

#[cfg(unix)]
impl Drop for RawMode {
    fn drop(&mut self) {
        // SAFETY: restores the termios captured in `enable`; failure leaves nothing to undo.
        unsafe { libc::tcsetattr(0, libc::TCSANOW, &self.0) };
    }
}

/// (rows, cols) of the terminal on stdout, if it is one.
#[cfg(unix)]
pub fn term_size() -> Option<(u16, u16)> {
    // SAFETY: winsize is plain data; TIOCGWINSZ writes into it.
    let mut w: libc::winsize = unsafe { std::mem::zeroed() };
    (unsafe { libc::ioctl(1, libc::TIOCGWINSZ, &mut w) } == 0 && w.ws_row > 0)
        .then_some((w.ws_row, w.ws_col))
}

/// Send `sig` to process `pid` (best effort).
#[cfg(unix)]
pub fn kill(pid: u32, sig: i32) {
    // SAFETY: kill takes plain integers; a stale pid at worst signals nothing.
    unsafe { libc::kill(pid as libc::pid_t, sig) };
}

#[cfg(test)]
mod tests {
    #[test]
    fn core_dumps_disabled() {
        super::disable_core_dumps().unwrap();
        #[cfg(unix)]
        {
            let mut r = libc::rlimit {
                rlim_cur: 1,
                rlim_max: 1,
            };
            // SAFETY: getrlimit writes into the struct we own.
            assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut r) }, 0);
            assert_eq!(r.rlim_cur, 0);
        }
    }

    #[test]
    fn mlock_roundtrip_does_not_crash() {
        let buf = Box::new([0u8; 32]);
        let _locked = super::mlock(buf.as_ptr(), 32);
        super::munlock(buf.as_ptr(), 32);
    }
}
