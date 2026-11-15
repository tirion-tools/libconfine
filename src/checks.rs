//! Checks of layers the helper cannot create itself (the launcher's descriptor-only box) and of the
//! capability sets.

use super::{ConfineError, errno, errno_name};

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[repr(C)]
struct IfConf {
    len: libc::c_int,
    buf: *mut libc::c_void,
}

/// Effective, permitted, inheritable, bounding and ambient capability sets all empty (needs `capget`
/// and `prctl(PR_CAPBSET_READ | PR_CAP_AMBIENT)`).
pub fn capabilities_empty() -> Result<(), String> {
    let mut hdr = CapHeader {
        version: 0x2008_0522, // _LINUX_CAPABILITY_VERSION_3
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    // SAFETY: header and two data structs as capget(2) v3 expects.
    if unsafe { libc::syscall(libc::SYS_capget, &raw mut hdr, data.as_mut_ptr()) } != 0 {
        return Err(format!("capget: {}", errno_name(errno())));
    }
    if data
        .iter()
        .any(|d| d.effective != 0 || d.permitted != 0 || d.inheritable != 0)
    {
        return Err("capability sets not empty".into());
    }
    for cap in 0..64 {
        // SAFETY: integer-argument prctl.
        let bnd = unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) };
        if bnd < 0 {
            break;
        }
        // SAFETY: integer-argument prctl.
        let amb =
            unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_IS_SET, cap, 0, 0) };
        if bnd == 1 || amb == 1 {
            return Err(format!("capability {cap} in the bounding/ambient set"));
        }
    }
    Ok(())
}

/// The descriptor-only box a launcher builds: pid 1 with no parent in the namespace, an empty root,
/// no capabilities, and a network namespace with `lo` down, no IPv4 interface and no route.
pub fn descriptor_only_box() -> Result<(), ConfineError> {
    let b = |m: String| ConfineError::Box(m);
    // SAFETY: getters.
    let (pid, ppid) = unsafe { (libc::getpid(), libc::getppid()) };
    if pid != 1 || ppid != 0 {
        return Err(b(format!("pid {pid} ppid {ppid}; expected 1/0")));
    }
    let entries = root_entries().map_err(b)?;
    if entries != 0 {
        return Err(b(format!("/ has {entries} entries")));
    }
    capabilities_empty().map_err(b)?;
    network_isolated().map_err(b)
}

/// Entries of "/" other than "." and "..".
fn root_entries() -> Result<usize, String> {
    // SAFETY: NUL-terminated path.
    let root = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root < 0 {
        return Err(format!("open /: {}", errno_name(errno())));
    }
    let mut entries = 0usize;
    let mut buf = [0u8; 4096];
    loop {
        // SAFETY: `buf` is writable for its length.
        let n = unsafe { libc::syscall(libc::SYS_getdents64, root, buf.as_mut_ptr(), buf.len()) };
        if n <= 0 {
            break;
        }
        let n = n as usize;
        let mut off = 0usize;
        while off + 19 <= n {
            let reclen = usize::from(u16::from_ne_bytes([buf[off + 16], buf[off + 17]]));
            if reclen == 0 || off + reclen > n {
                break;
            }
            let name = &buf[off + 19..off + reclen];
            let name = &name[..name.iter().position(|&c| c == 0).unwrap_or(name.len())];
            if name != b"." && name != b".." {
                entries += 1;
            }
            off += reclen;
        }
    }
    // SAFETY: our descriptor.
    unsafe { libc::close(root) };
    Ok(entries)
}

/// Loopback down, no IPv4 interface, no route for IPv4 or IPv6. UDP connect() only does a route
/// lookup; nothing is sent.
fn network_isolated() -> Result<(), String> {
    // SAFETY: plain socket/ioctl/connect calls on our own descriptors with sized buffers.
    unsafe {
        let s = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if s < 0 {
            return Err(format!("socket: {}", errno_name(errno())));
        }
        let mut ifr: libc::ifreq = std::mem::zeroed();
        for (i, c) in b"lo\0".iter().enumerate() {
            ifr.ifr_name[i] = *c as libc::c_char;
        }
        let lo_flags = if libc::ioctl(s, libc::SIOCGIFFLAGS as _, &raw mut ifr) == 0 {
            i32::from(ifr.ifr_ifru.ifru_flags)
        } else {
            -1
        };
        let mut ifbuf = [0u8; 4096];
        let mut ifc = IfConf {
            len: ifbuf.len() as libc::c_int,
            buf: ifbuf.as_mut_ptr().cast(),
        };
        let ifaces = if libc::ioctl(s, libc::SIOCGIFCONF as _, &raw mut ifc) == 0 {
            ifc.len as usize / std::mem::size_of::<libc::ifreq>()
        } else {
            usize::MAX
        };
        // TEST-NET-1 and the IPv6 documentation prefix: never routable.
        let dst = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 9u16.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_be_bytes([192, 0, 2, 1]).to_be(),
            },
            sin_zero: [0; 8],
        };
        let r4 = libc::connect(
            s,
            (&raw const dst).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        libc::close(s);
        let s6 = libc::socket(libc::AF_INET6, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        let mut r6 = -1;
        if s6 >= 0 {
            let mut a: libc::sockaddr_in6 = std::mem::zeroed();
            a.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            a.sin6_port = 9u16.to_be();
            a.sin6_addr.s6_addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
            r6 = libc::connect(
                s6,
                (&raw const a).cast(),
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            );
            libc::close(s6);
        }
        let lo_up = lo_flags < 0 || lo_flags & libc::IFF_UP != 0;
        if lo_up || ifaces != 0 || r4 == 0 || r6 == 0 {
            return Err(format!(
                "network namespace: lo flags {lo_flags}, {ifaces} IPv4 interfaces, udp4 {r4}, udp6 {r6}"
            ));
        }
    }
    Ok(())
}
