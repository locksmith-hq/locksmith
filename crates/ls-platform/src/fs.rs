//! Owner-only files and directories on every OS.
//!
//! Unix: file mode 0600, directory mode 0700; "private" means no group or other bits
//! (`mode & 0o077 == 0`), exactly as before this module existed.
//!
//! Windows: the owner is set to the current user and the DACL is replaced by a protected one
//! with a single full-control entry for the current user's SID (`O:<sid>D:P(A;;FA;;;<sid>)`;
//! directories add `OICI` so new children inherit it). "Private" means the owner is the current
//! user (or SYSTEM / BUILTIN\Administrators, the root equivalents), the DACL is present, and no
//! entry that applies to the object itself grants any right to another SID. An entry type this
//! module does not understand counts as not private, so the checks fail closed.

use std::fs::File;
use std::io;
use std::path::Path;

/// Create `path` (and parents) and make the leaf directory private to the current user.
pub fn ensure_private_dir(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(path)?;
    set_private_dir(path)
}

/// Restrict an existing directory to the current user: chmod 0700 on Unix, a protected
/// current-user-only DACL (inherited by new children) on Windows.
pub fn set_private_dir(path: &Path) -> io::Result<()> {
    imp::set_private(path, true)
}

/// Restrict an existing file to the current user: chmod 0600 on Unix, a protected
/// current-user-only DACL on Windows.
pub fn set_private_file(path: &Path) -> io::Result<()> {
    imp::set_private(path, false)
}

/// True when no other user can access `path` (follows symlinks). Unix: no group/other mode bits.
/// Windows: see the module docs.
pub fn is_private(path: &Path) -> io::Result<bool> {
    imp::is_private(path)
}

/// True when `path` (followed through symlinks) is owned by the current user: the uid on Unix,
/// the owner SID on Windows.
pub fn is_owned_by_current_user(path: &Path) -> io::Result<bool> {
    imp::is_owned_by_current_user(path)
}

/// True when `path` is owned by the current user and no other user may modify it. Unix: owner
/// uid matches and no group/other write bit (`mode & 0o022 == 0`). Windows: owner SID matches and
/// no DACL entry grants a write, delete or permission-change right to another SID (SYSTEM and
/// BUILTIN\Administrators excepted, as root is on Unix).
pub fn is_writable_only_by_owner(path: &Path) -> io::Result<bool> {
    imp::is_writable_only_by_owner(path)
}

/// Mark a file executable (chmod 0755). Windows has no exec bit, so this is a no-op there.
pub fn set_executable(path: &Path) -> io::Result<()> {
    imp::set_executable(path)
}

/// The shell command that makes directory `path` private, for doctor remediation text.
pub fn private_dir_fix(path: &Path) -> String {
    if cfg!(windows) {
        format!(
            "icacls \"{}\" /inheritance:r /grant:r \"%USERNAME%:(OI)(CI)F\" (then remove any other entries it lists)",
            path.display()
        )
    } else {
        format!("chmod 700 '{}'", path.display())
    }
}

/// The shell command that makes file `path` private, for doctor remediation text.
pub fn private_file_fix(path: &Path) -> String {
    if cfg!(windows) {
        format!(
            "icacls \"{}\" /inheritance:r /grant:r \"%USERNAME%:F\" (then remove any other entries it lists)",
            path.display()
        )
    } else {
        format!("chmod 600 '{}'", path.display())
    }
}

/// Opens a file for writing that is private to the current user from the moment it is created:
/// mode 0600 on Unix, a protected current-user-only DACL passed to `CreateFileW` on Windows, so
/// there is no window in which another user could open it. As with a Unix create mode, an
/// existing file keeps its permissions; use [`set_private_file`] to change them.
#[derive(Clone, Copy, Debug, Default)]
pub struct PrivateFile {
    read: bool,
    truncate: bool,
    create_new: bool,
}

impl PrivateFile {
    /// Write access; create the file when missing, keep existing contents.
    pub fn new() -> Self {
        Self::default()
    }
    /// Also open for reading.
    pub fn read(mut self, yes: bool) -> Self {
        self.read = yes;
        self
    }
    /// Truncate an existing file to zero length.
    pub fn truncate(mut self, yes: bool) -> Self {
        self.truncate = yes;
        self
    }
    /// Fail with `AlreadyExists` when the file exists.
    pub fn create_new(mut self, yes: bool) -> Self {
        self.create_new = yes;
        self
    }
    pub fn open(&self, path: impl AsRef<Path>) -> io::Result<File> {
        imp::open_private(self, path.as_ref())
    }
}

#[cfg(unix)]
mod imp {
    use super::PrivateFile;
    use std::fs::{File, OpenOptions, Permissions};
    use std::io;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::Path;

    pub fn set_private(path: &Path, dir: bool) -> io::Result<()> {
        std::fs::set_permissions(
            path,
            Permissions::from_mode(if dir { 0o700 } else { 0o600 }),
        )
    }

    pub fn is_private(path: &Path) -> io::Result<bool> {
        Ok(std::fs::metadata(path)?.permissions().mode() & 0o077 == 0)
    }

    pub fn is_owned_by_current_user(path: &Path) -> io::Result<bool> {
        Ok(std::fs::metadata(path)?.uid() == crate::current_uid())
    }

    pub fn is_writable_only_by_owner(path: &Path) -> io::Result<bool> {
        let m = std::fs::metadata(path)?;
        Ok(m.uid() == crate::current_uid() && m.mode() & 0o022 == 0)
    }

    pub fn set_executable(path: &Path) -> io::Result<()> {
        std::fs::set_permissions(path, Permissions::from_mode(0o755))
    }

    pub fn open_private(o: &PrivateFile, path: &Path) -> io::Result<File> {
        let mut opts = OpenOptions::new();
        opts.write(true)
            .read(o.read)
            .truncate(o.truncate)
            .mode(0o600);
        if o.create_new {
            opts.create_new(true);
        } else {
            opts.create(true);
        }
        opts.open(path)
    }
}

#[cfg(windows)]
mod imp {
    use super::PrivateFile;
    use std::ffi::c_void;
    use std::fs::File;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{FromRawHandle, RawHandle};
    use std::path::Path;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GENERIC_ALL, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
        LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetTokenInformation,
        INHERIT_ONLY_ACE, IsWellKnownSid, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_ALWAYS, CREATE_NEW, CreateFileW, DELETE, FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL,
        FILE_DELETE_CHILD, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, OPEN_ALWAYS, WRITE_DAC, WRITE_OWNER,
    };
    use windows_sys::Win32::System::SystemServices::{
        ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// Rights that let a holder change the object, its permissions or (for a directory) its
    /// entries: the Windows counterpart of the Unix group/other write bits.
    const WRITE_RIGHTS: u32 = FILE_WRITE_DATA
        | FILE_APPEND_DATA
        | FILE_WRITE_EA
        | FILE_DELETE_CHILD
        | FILE_WRITE_ATTRIBUTES
        | DELETE
        | WRITE_DAC
        | WRITE_OWNER
        | GENERIC_WRITE
        | GENERIC_ALL;

    fn wide(p: &Path) -> Vec<u16> {
        p.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    fn win32(code: u32) -> io::Result<()> {
        if code == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(code as i32))
        }
    }

    /// Memory returned by an API that must be released with `LocalFree`.
    struct Local(*mut c_void);
    impl Drop for Local {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer came from an API documented to allocate with LocalAlloc
                // and is freed exactly once.
                unsafe { LocalFree(self.0) };
            }
        }
    }

    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: an open token handle from OpenProcessToken, closed once.
            unsafe { CloseHandle(self.0) };
        }
    }

    /// The current process's token user; the SID lives inside the buffer.
    struct UserSid(Vec<u64>); // u64 for the alignment TOKEN_USER needs

    impl UserSid {
        fn current() -> io::Result<Self> {
            let mut token: HANDLE = std::ptr::null_mut();
            // SAFETY: GetCurrentProcess returns a pseudo-handle; `token` is a valid out pointer.
            if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let token = Handle(token);
            let mut len = 0u32;
            // SAFETY: size query with a null buffer; it fails and sets `len`.
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
            Ok(UserSid(buf))
        }

        fn sid(&self) -> PSID {
            // SAFETY: the buffer holds a TOKEN_USER filled by GetTokenInformation (size and
            // alignment checked in `current`); its SID pointer points into the same buffer.
            unsafe { (*(self.0.as_ptr() as *const TOKEN_USER)).User.Sid }
        }

        /// `S-1-5-21-...` form, for SDDL.
        fn string(&self) -> io::Result<String> {
            let mut s: *mut u16 = std::ptr::null_mut();
            // SAFETY: the SID is valid for the life of `self`; `s` receives a LocalAlloc string.
            if unsafe { ConvertSidToStringSidW(self.sid(), &mut s) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let owned = Local(s.cast());
            // SAFETY: `s` is a NUL-terminated UTF-16 string allocated by the call above.
            let len = (0..).take_while(|&i| unsafe { *s.add(i) } != 0).count();
            // SAFETY: `len` u16s before the terminator are initialised.
            let out = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(s, len) });
            drop(owned);
            Ok(out)
        }

        fn is(&self, other: PSID) -> bool {
            // SAFETY: both SIDs are valid for the duration of the call.
            !other.is_null() && unsafe { EqualSid(self.sid(), other) } != 0
        }
    }

    /// SYSTEM and BUILTIN\Administrators: like root on Unix, they can reach any file anyway.
    fn is_root_equivalent(sid: PSID) -> bool {
        // SAFETY: `sid` is a valid SID for the duration of the call.
        !sid.is_null()
            && unsafe {
                IsWellKnownSid(sid, WinLocalSystemSid) != 0
                    || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
            }
    }

    /// A self-relative security descriptor: owner and a protected DACL for the current user only.
    fn private_descriptor(user: &UserSid, dir: bool) -> io::Result<Local> {
        let sid = user.string()?;
        let inherit = if dir { "OICI" } else { "" };
        let sddl = format!("O:{sid}D:P(A;{inherit};FA;;;{sid})");
        let w: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `w` is a NUL-terminated wide string; `sd` receives a LocalAlloc descriptor.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                w.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Local(sd))
    }

    pub fn set_private(path: &Path, dir: bool) -> io::Result<()> {
        let user = UserSid::current()?;
        let sd = private_descriptor(&user, dir)?;
        let (mut present, mut defaulted) = (0, 0);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut owner: PSID = std::ptr::null_mut();
        // SAFETY: `sd` is a valid descriptor; the out pointers point into it and stay valid
        // while `sd` lives.
        unsafe {
            if GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl, &mut defaulted) == 0
                || GetSecurityDescriptorOwner(sd.0, &mut owner, &mut defaulted) == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        if present == 0 || dacl.is_null() || owner.is_null() {
            return Err(io::Error::other(
                "private security descriptor has no DACL or owner",
            ));
        }
        let w = wide(path);
        // DACL first: the owner may always write the DACL, and the new entry grants the
        // WRITE_OWNER right that changing the owner below needs.
        // SAFETY: `w` is NUL-terminated; `dacl` is valid while `sd` lives.
        win32(unsafe {
            SetNamedSecurityInfoW(
                w.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null(),
            )
        })?;
        if !user.is(read(path)?.owner) {
            // SAFETY: as above; `owner` is valid while `sd` lives.
            win32(unsafe {
                SetNamedSecurityInfoW(
                    w.as_ptr(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION,
                    owner,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            })?;
        }
        Ok(())
    }

    /// Owner and DACL of a file or directory; both point into `_sd`.
    struct Security {
        _sd: Local,
        owner: PSID,
        dacl: *const ACL,
    }

    fn read(path: &Path) -> io::Result<Security> {
        let w = wide(path);
        let mut owner: PSID = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `w` is NUL-terminated; the out pointers are valid; `sd` receives a LocalAlloc
        // descriptor that owner and dacl point into.
        win32(unsafe {
            GetNamedSecurityInfoW(
                w.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut sd,
            )
        })?;
        Ok(Security {
            _sd: Local(sd),
            owner,
            dacl,
        })
    }

    /// Union of the rights the DACL grants to SIDs other than the current user and the root
    /// equivalents. A missing (NULL) DACL or an entry type not handled here yields all bits.
    fn rights_of_others(sec: &Security, user: &UserSid) -> io::Result<u32> {
        if sec.dacl.is_null() {
            return Ok(u32::MAX); // NULL DACL: everyone has full access
        }
        // SAFETY: a non-null DACL from GetNamedSecurityInfoW is a valid ACL inside `sec._sd`.
        let count = unsafe { (*sec.dacl).AceCount };
        let mut others = 0u32;
        for i in 0..u32::from(count) {
            let mut ace: *mut c_void = std::ptr::null_mut();
            // SAFETY: `i` < AceCount; `ace` receives a pointer into the ACL.
            if unsafe { GetAce(sec.dacl, i, &mut ace) } == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: every ACE starts with an ACE_HEADER.
            let header = unsafe { *(ace as *const ACE_HEADER) };
            if u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0 {
                continue; // applies to children only, grants nothing on this object
            }
            match u32::from(header.AceType) {
                ACCESS_DENIED_ACE_TYPE => {}
                ACCESS_ALLOWED_ACE_TYPE => {
                    let allowed = ace as *const ACCESS_ALLOWED_ACE;
                    // SAFETY: the type says this is an ACCESS_ALLOWED_ACE; its SID starts at
                    // SidStart and lies within AceSize.
                    let (mask, sid) = unsafe {
                        (
                            (*allowed).Mask,
                            std::ptr::addr_of!((*allowed).SidStart) as PSID,
                        )
                    };
                    if mask != 0 && !user.is(sid) && !is_root_equivalent(sid) {
                        others |= mask;
                    }
                }
                _ => return Ok(u32::MAX), // object/callback/conditional entries: fail closed
            }
        }
        Ok(others)
    }

    pub fn is_private(path: &Path) -> io::Result<bool> {
        let user = UserSid::current()?;
        let sec = read(path)?;
        if !user.is(sec.owner) && !is_root_equivalent(sec.owner) {
            return Ok(false);
        }
        Ok(rights_of_others(&sec, &user)? == 0)
    }

    pub fn is_owned_by_current_user(path: &Path) -> io::Result<bool> {
        Ok(UserSid::current()?.is(read(path)?.owner))
    }

    pub fn is_writable_only_by_owner(path: &Path) -> io::Result<bool> {
        let user = UserSid::current()?;
        let sec = read(path)?;
        Ok(user.is(sec.owner) && rights_of_others(&sec, &user)? & WRITE_RIGHTS == 0)
    }

    pub fn set_executable(path: &Path) -> io::Result<()> {
        let _ = path;
        Ok(())
    }

    pub fn open_private(o: &PrivateFile, path: &Path) -> io::Result<File> {
        let user = UserSid::current()?;
        let sd = private_descriptor(&user, false)?;
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        let access = GENERIC_WRITE | if o.read { GENERIC_READ } else { 0 };
        let disposition = if o.create_new {
            CREATE_NEW
        } else if o.truncate {
            CREATE_ALWAYS
        } else {
            OPEN_ALWAYS
        };
        let w = wide(path);
        // SAFETY: `w` is NUL-terminated; `sa` and the descriptor it points to outlive the call.
        let h = unsafe {
            CreateFileW(
                w.as_ptr(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                &sa,
                disposition,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `h` is a valid, owned, synchronous file handle; File takes ownership.
        Ok(unsafe { File::from_raw_handle(h as RawHandle) })
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use super::PrivateFile;
    use std::fs::File;
    use std::io;
    use std::path::Path;

    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "file privacy is not implemented on this OS",
        )
    }
    pub fn set_private(_: &Path, _: bool) -> io::Result<()> {
        Err(unsupported())
    }
    pub fn is_private(_: &Path) -> io::Result<bool> {
        Err(unsupported())
    }
    pub fn is_owned_by_current_user(_: &Path) -> io::Result<bool> {
        Err(unsupported())
    }
    pub fn is_writable_only_by_owner(_: &Path) -> io::Result<bool> {
        Err(unsupported())
    }
    pub fn set_executable(_: &Path) -> io::Result<()> {
        Ok(())
    }
    pub fn open_private(_: &PrivateFile, _: &Path) -> io::Result<File> {
        Err(unsupported())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Tmp(std::path::PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let p =
                std::env::temp_dir().join(format!("ls-platform-fs-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            Tmp(p)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn private_dir_and_file_round_trip() {
        use std::io::Write;
        let t = Tmp::new("rt");
        let dir = t.0.join("a/b");
        ensure_private_dir(&dir).unwrap();
        assert!(is_private(&dir).unwrap());
        assert!(is_owned_by_current_user(&dir).unwrap());
        assert!(is_writable_only_by_owner(&dir).unwrap());
        let f = dir.join("f");
        let mut h = PrivateFile::new().truncate(true).open(&f).unwrap();
        h.write_all(b"x").unwrap();
        drop(h);
        assert!(is_private(&f).unwrap());
        assert!(
            PrivateFile::new()
                .create_new(true)
                .open(&f)
                .unwrap_err()
                .kind()
                == io::ErrorKind::AlreadyExists
        );
        // Not truncated without `truncate`.
        drop(PrivateFile::new().open(&f).unwrap());
        assert_eq!(std::fs::read(&f).unwrap(), b"x");
        set_private_file(&f).unwrap();
        assert!(is_private(&f).unwrap());
    }

    #[test]
    fn missing_path_is_an_error() {
        let t = Tmp::new("missing");
        assert!(is_private(&t.0.join("nope")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn unix_modes_match_the_old_behaviour() {
        use std::os::unix::fs::PermissionsExt;
        let t = Tmp::new("modes");
        ensure_private_dir(&t.0).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&t.0), 0o700);
        let f = t.0.join("f");
        drop(PrivateFile::new().open(&f).unwrap());
        assert_eq!(mode(&f), 0o600);
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(!is_private(&f).unwrap());
        assert!(is_writable_only_by_owner(&f).unwrap());
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o620)).unwrap();
        assert!(!is_writable_only_by_owner(&f).unwrap());
        set_private_file(&f).unwrap();
        assert_eq!(mode(&f), 0o600);
        set_executable(&f).unwrap();
        assert_eq!(mode(&f), 0o755);
        std::fs::set_permissions(&t.0, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(!is_private(&t.0).unwrap());
        set_private_dir(&t.0).unwrap();
        assert_eq!(mode(&t.0), 0o700);
        assert!(private_dir_fix(&t.0).starts_with("chmod 700 "));
        assert!(private_file_fix(&f).starts_with("chmod 600 "));
    }
}
