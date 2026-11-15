//! Process layers applied before Landlock and seccomp: signals, descriptors, prctl flags, rlimits and
//! the musl pthread-key quirk.

use super::{ConfineError, errno, errno_name};

/// One resource limit; [`lower`] sets soft = hard = min(value, current hard limit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rlimit {
    pub resource: libc::c_int,
    pub value: u64,
    /// For messages, e.g. "RLIMIT_NOFILE".
    pub name: &'static str,
}

impl Rlimit {
    pub const fn new(resource: libc::c_int, value: u64, name: &'static str) -> Self {
        Self {
            resource,
            value,
            name,
        }
    }
}

/// Which optional process layers a policy wants.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Process {
    /// SIGXFSZ ignored, so a write past RLIMIT_FSIZE fails with EFBIG instead of killing.
    pub ignore_sigxfsz: bool,
    /// Every descriptor from this number up closed (close_range).
    pub close_fds_from: Option<u32>,
    /// pthread key 0 reserved ([`reserve_pthread_key_zero`]).
    pub reserve_pthread_key_zero: bool,
}

fn setup(what: &str) -> ConfineError {
    ConfineError::Setup(format!("{what}: {}", errno_name(errno())))
}

/// Applies `p`, then not dumpable and NO_NEW_PRIVS (both verified), then `rlimits`.
pub fn apply(p: &Process, rlimits: &[Rlimit]) -> Result<(), ConfineError> {
    if p.ignore_sigxfsz {
        // SAFETY: installs SIG_IGN; no handler code runs.
        unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_IGN) };
    }
    if let Some(fd) = p.close_fds_from {
        // SAFETY: closes descriptors of our own process only.
        if unsafe { libc::syscall(libc::SYS_close_range, fd, u32::MAX, 0u32) } != 0 {
            return Err(setup("close_range"));
        }
    }
    set_not_dumpable()?;
    set_no_new_privs()?;
    if p.reserve_pthread_key_zero {
        reserve_pthread_key_zero()?;
    }
    lower(rlimits)
}

/// PR_SET_DUMPABLE 0, verified with PR_GET_DUMPABLE.
pub fn set_not_dumpable() -> Result<(), ConfineError> {
    // SAFETY: prctl with integer arguments only.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(setup("PR_SET_DUMPABLE"));
    }
    // SAFETY: as above.
    let d = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
    if d != 0 {
        return Err(ConfineError::Setup(format!("PR_GET_DUMPABLE = {d}")));
    }
    Ok(())
}

/// PR_SET_NO_NEW_PRIVS 1, verified with PR_GET_NO_NEW_PRIVS.
pub fn set_no_new_privs() -> Result<(), ConfineError> {
    // SAFETY: prctl with integer arguments only.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(setup("PR_SET_NO_NEW_PRIVS"));
    }
    // SAFETY: as above.
    let n = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    if n != 1 {
        return Err(ConfineError::Setup(format!("PR_GET_NO_NEW_PRIVS = {n}")));
    }
    Ok(())
}

/// Lowers every limit in `rlimits` (never raises one).
pub fn lower(rlimits: &[Rlimit]) -> Result<(), ConfineError> {
    for r in rlimits {
        let mut cur = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `cur` is a valid rlimit out-parameter. (The resource type differs between glibc
        // and musl.)
        if unsafe { libc::getrlimit(r.resource as _, &mut cur) } != 0 {
            return Err(setup(&format!("getrlimit {}", r.name)));
        }
        let v = r.value.min(cur.rlim_max);
        let new = libc::rlimit {
            rlim_cur: v,
            rlim_max: v,
        };
        // SAFETY: `new` is a valid rlimit.
        if unsafe { libc::setrlimit(r.resource as _, &new) } != 0 {
            return Err(setup(&format!("setrlimit {}", r.name)));
        }
    }
    Ok(())
}

/// musl hands out pthread key 0 first, and std's `LazyKey` treats 0 as "unset": it creates a second
/// key and deletes key 0, and musl's `pthread_key_delete` blocks and restores signals
/// (rt_sigprocmask). Taking key 0 before lockdown keeps rt_sigprocmask out of the allowlist. No-op on
/// other C libraries.
pub fn reserve_pthread_key_zero() -> Result<(), ConfineError> {
    #[cfg(target_env = "musl")]
    {
        let mut k: libc::pthread_key_t = 0;
        // SAFETY: valid out-parameter, no destructor; the key is never deleted.
        let r = unsafe { libc::pthread_key_create(&mut k, None) };
        if r != 0 {
            return Err(ConfineError::Setup(format!(
                "pthread_key_create: {}",
                errno_name(r)
            )));
        }
    }
    Ok(())
}
