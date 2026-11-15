use std::fmt;

/// Why confinement failed; a helper exits instead of running with a layer missing.
#[derive(Debug)]
pub enum ConfineError {
    /// Process layers: prctl, rlimits, descriptors, probe fixtures.
    Setup(String),
    /// A layer only the launcher can create is missing ([`super::checks::descriptor_only_box`]).
    Box(String),
    Landlock(String),
    Seccomp(String),
    SelfCheck(String),
}

impl fmt::Display for ConfineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Setup(m) => write!(f, "confinement setup: {m}"),
            Self::Box(m) => write!(f, "launcher box check: {m}"),
            Self::Landlock(m) => write!(f, "landlock: {m}"),
            Self::Seccomp(m) => write!(f, "seccomp: {m}"),
            Self::SelfCheck(m) => write!(f, "self-check: {m}"),
        }
    }
}

impl std::error::Error for ConfineError {}

/// The calling thread's errno.
pub fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// The symbolic name of `e` ("ok" for 0, "errno<N>" for names not listed), as probe outcomes print it.
pub fn errno_name(e: i32) -> String {
    let n = match e {
        0 => "ok",
        libc::EACCES => "EACCES",
        libc::EPERM => "EPERM",
        libc::ENOENT => "ENOENT",
        libc::EROFS => "EROFS",
        libc::ENOSYS => "ENOSYS",
        libc::EXDEV => "EXDEV",
        libc::EINVAL => "EINVAL",
        libc::EBUSY => "EBUSY",
        libc::EBADF => "EBADF",
        libc::EAGAIN => "EAGAIN",
        libc::ESRCH => "ESRCH",
        libc::EEXIST => "EEXIST",
        libc::ENOTDIR => "ENOTDIR",
        libc::ENOTEMPTY => "ENOTEMPTY",
        libc::ENOEXEC => "ENOEXEC",
        libc::EFAULT => "EFAULT",
        libc::ENOMEM => "ENOMEM",
        libc::EMFILE => "EMFILE",
        libc::ENOTSOCK => "ENOTSOCK",
        libc::ENETUNREACH => "ENETUNREACH",
        libc::ECONNREFUSED => "ECONNREFUSED",
        libc::EADDRNOTAVAIL => "EADDRNOTAVAIL",
        libc::EAFNOSUPPORT => "EAFNOSUPPORT",
        _ => return format!("errno{e}"),
    };
    n.to_string()
}
