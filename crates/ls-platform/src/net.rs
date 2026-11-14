//! Which local processes hold the client end of a loopback TCP connection.
//! Used to attribute a connection accepted on a loopback listener to a process.

use crate::proc::ProcId;
use std::io;
use std::net::{IpAddr, SocketAddr};

fn canon(a: SocketAddr) -> (IpAddr, u16) {
    (a.ip().to_canonical(), a.port())
}

/// Processes holding the client end of a loopback TCP connection: the socket whose local
/// address is `client` and whose remote address is `server` (as seen by the accepting side).
/// Fails closed: an error when the owner cannot be determined; an empty Vec is never returned
/// as success.
pub fn tcp_peer_owners(client: SocketAddr, server: SocketAddr) -> io::Result<Vec<ProcId>> {
    let (c, s) = (canon(client), canon(server));
    #[cfg(target_os = "linux")]
    let owners = linux::owners(c, s)?;
    #[cfg(target_os = "macos")]
    let owners = macos::owners(c, s)?;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (c, s);
        return Err(io::ErrorKind::Unsupported.into());
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if owners.is_empty() {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no visible process owns that TCP connection",
        ))
    } else {
        Ok(owners)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    /// Decode a /proc/net/tcp{,6} address: each 32-bit word is printed in host byte order.
    fn parse_addr(s: &str) -> Option<(IpAddr, u16)> {
        let (a, p) = s.split_once(':')?;
        let port = u16::from_str_radix(p, 16).ok()?;
        let mut bytes = Vec::with_capacity(16);
        if a.len() % 8 != 0 {
            return None;
        }
        for w in a.as_bytes().chunks(8) {
            let w = u32::from_str_radix(std::str::from_utf8(w).ok()?, 16).ok()?;
            bytes.extend_from_slice(&w.to_ne_bytes());
        }
        let ip = match bytes.len() {
            4 => IpAddr::from(<[u8; 4]>::try_from(bytes).ok()?),
            16 => IpAddr::from(<[u8; 16]>::try_from(bytes).ok()?).to_canonical(),
            _ => return None,
        };
        Some((ip, port))
    }

    /// Socket inodes of connections local=c, remote=s.
    fn inodes(c: (IpAddr, u16), s: (IpAddr, u16)) -> io::Result<Vec<u64>> {
        let mut out = Vec::new();
        let mut any = false;
        for f in ["/proc/net/tcp", "/proc/net/tcp6"] {
            let Ok(t) = std::fs::read_to_string(f) else {
                continue;
            };
            any = true;
            for l in t.lines().skip(1) {
                let f: Vec<&str> = l.split_whitespace().collect();
                // sl local rem st tx:rx tr:when retrnsmt uid timeout inode
                if f.len() > 9
                    && parse_addr(f[1]) == Some(c)
                    && parse_addr(f[2]) == Some(s)
                    && let Ok(i) = f[9].parse()
                {
                    out.push(i);
                }
            }
        }
        if !any {
            return Err(io::Error::other("cannot read /proc/net/tcp"));
        }
        Ok(out)
    }

    pub fn owners(c: (IpAddr, u16), s: (IpAddr, u16)) -> io::Result<Vec<ProcId>> {
        let want: Vec<String> = inodes(c, s)?
            .into_iter()
            .map(|i| format!("socket:[{i}]"))
            .collect();
        let mut out = Vec::new();
        if want.is_empty() {
            return Ok(out);
        }
        let me = crate::current_uid();
        for e in std::fs::read_dir("/proc")?.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
                continue;
            };
            // Only same-UID processes have readable fd tables anyway.
            if !e.metadata().is_ok_and(|m| m.uid() == me) {
                continue;
            }
            let Ok(fds) = std::fs::read_dir(e.path().join("fd")) else {
                continue; // unreadable or exited: skip
            };
            let hit = fds.flatten().any(|fd| {
                std::fs::read_link(fd.path())
                    .is_ok_and(|t| t.to_str().is_some_and(|t| want.iter().any(|w| w == t)))
            });
            if hit && let Ok(id) = crate::proc::id_of(pid) {
                out.push(id);
            }
        }
        Ok(out)
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;

    // Layout of `struct socket_fdinfo` from <sys/proc_info.h> (libc does not bind it):
    //   proc_fileinfo pfi (24 bytes) + socket_info psi (768 bytes) = 792.
    // Within psi: soi_kind (int) at 232, soi_proto union at 240. For SOCKINFO_TCP the union
    // starts with tcp_sockinfo.tcpsi_ini = in_sockinfo: insi_fport int @0, insi_lport int @4,
    // insi_vflag u8 @24, insi_faddr (16 bytes) @32, insi_laddr (16 bytes) @48. IPv4 addresses
    // sit in the last 4 bytes of the 16-byte address (in4in6_addr). Ports are network order.
    const PROC_PIDFDSOCKETINFO: libc::c_int = 3; // <sys/proc_info.h>
    const SOCKET_FDINFO_SIZE: usize = 792;
    const PSI: usize = 24;
    const SOI_KIND: usize = PSI + 232;
    const SOCKINFO_TCP: i32 = 2;
    const INI: usize = PSI + 240;
    const INI_IPV4: u8 = 1;

    fn rd<const N: usize>(b: &[u8], o: usize) -> [u8; N] {
        b[o..o + N].try_into().unwrap()
    }

    fn addr(b: &[u8], port_off: usize, addr_off: usize) -> (IpAddr, u16) {
        let port = u16::from_be(i32::from_ne_bytes(rd(b, INI + port_off)) as u16);
        let a: [u8; 16] = rd(b, INI + addr_off);
        let ip = if b[INI + 24] & INI_IPV4 != 0 {
            IpAddr::from([a[12], a[13], a[14], a[15]])
        } else {
            IpAddr::from(a).to_canonical()
        };
        (ip, port)
    }

    pub fn owners(c: (IpAddr, u16), s: (IpAddr, u16)) -> io::Result<Vec<ProcId>> {
        // SAFETY: with a null buffer proc_listallpids only returns the pid count.
        let n = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
        if n <= 0 {
            return Err(io::Error::last_os_error());
        }
        let mut pids = vec![0 as libc::pid_t; n as usize + 64];
        // SAFETY: the buffer is live and its byte size is passed.
        let n = unsafe {
            libc::proc_listallpids(
                pids.as_mut_ptr().cast(),
                std::mem::size_of_val(&pids[..]) as libc::c_int,
            )
        };
        if n <= 0 {
            return Err(io::Error::last_os_error());
        }
        pids.truncate(n as usize);
        let me = crate::current_uid();
        let sz = std::mem::size_of::<libc::proc_fdinfo>();
        let mut out = Vec::new();
        for pid in pids.into_iter().filter(|p| *p > 0) {
            let Ok(info) = crate::proc::info(pid as u32) else {
                continue;
            };
            if info.uid != me {
                continue;
            }
            // SAFETY: null buffer: returns the needed byte size.
            let need = unsafe {
                libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0)
            };
            if need <= 0 {
                continue;
            }
            // Room for fds opened since the size query.
            let mut fds = vec![
                libc::proc_fdinfo {
                    proc_fd: 0,
                    proc_fdtype: 0
                };
                need as usize / sz + 16
            ];
            // SAFETY: the buffer is live and its byte size is passed.
            let got = unsafe {
                libc::proc_pidinfo(
                    pid,
                    libc::PROC_PIDLISTFDS,
                    0,
                    fds.as_mut_ptr().cast(),
                    (fds.len() * sz) as libc::c_int,
                )
            };
            if got <= 0 {
                continue;
            }
            fds.truncate(got as usize / sz);
            let mut buf = [0u8; SOCKET_FDINFO_SIZE];
            let hit = fds
                .iter()
                .filter(|f| f.proc_fdtype == libc::PROX_FDTYPE_SOCKET as u32)
                .any(|f| {
                    // SAFETY: proc_pidfdinfo writes at most buf.len() bytes into buf.
                    let r = unsafe {
                        libc::proc_pidfdinfo(
                            pid,
                            f.proc_fd,
                            PROC_PIDFDSOCKETINFO,
                            buf.as_mut_ptr().cast(),
                            buf.len() as libc::c_int,
                        )
                    };
                    r as usize == SOCKET_FDINFO_SIZE
                        && i32::from_ne_bytes(rd(&buf, SOI_KIND)) == SOCKINFO_TCP
                        && addr(&buf, 4, 48) == c
                        && addr(&buf, 0, 32) == s
                });
            if hit {
                out.push(info.id);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proc::id_of;
    use std::net::{TcpListener, TcpStream};
    use std::process::{Command, Stdio};

    #[test]
    fn own_client_socket_resolves_to_this_process() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let server = l.local_addr().unwrap();
        let c = TcpStream::connect(server).unwrap();
        let (_s, client) = l.accept().unwrap();
        assert_eq!(c.local_addr().unwrap(), client);
        let me = id_of(std::process::id()).unwrap();
        assert!(tcp_peer_owners(client, server).unwrap().contains(&me));
    }

    #[test]
    fn child_client_socket_resolves_to_child_only() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let server = l.local_addr().unwrap();
        let mut child = Command::new("python3")
            .args([
                "-c",
                "import socket,sys,time;s=socket.create_connection(('127.0.0.1',int(sys.argv[1])));time.sleep(30)",
                &server.port().to_string(),
            ])
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let (_s, client) = l.accept().unwrap();
        let r = tcp_peer_owners(client, server);
        let (cid, me) = (
            id_of(child.id()).unwrap(),
            id_of(std::process::id()).unwrap(),
        );
        child.kill().unwrap();
        child.wait().unwrap();
        let owners = r.unwrap();
        assert!(owners.contains(&cid));
        assert!(!owners.contains(&me));
    }

    #[test]
    fn unknown_pair_is_an_error() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        assert!(tcp_peer_owners("127.0.0.1:1".parse().unwrap(), a).is_err());
    }
}
