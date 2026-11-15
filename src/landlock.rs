//! The Landlock layer, through the `landlock` crate with a hard minimum ABI: every filesystem and
//! network right and every scope the running kernel's ABI knows is handled; only the given paths get
//! rights (none: deny-all).

use std::path::Path;

use ::landlock::{
    ABI, Access, AccessNet, BitFlags, CompatLevel, Compatible, PathBeneath, PathFd,
    RestrictSelfAttr, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope,
};

pub use ::landlock::AccessFs;

use super::{ConfineError, errno, errno_name};

/// The first ABI whose `restrict_self` can apply the domain to every thread (TSYNC).
pub const ABI_ALL_THREADS: i32 = 8;

/// A Landlock policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Landlock<'a> {
    /// Below this ABI the layer refuses.
    pub abi_floor: u32,
    /// Directories (or files) and the filesystem rights granted beneath them.
    pub paths: Vec<(&'a Path, BitFlags<AccessFs>)>,
    /// Apply the domain to every thread when the kernel can ([`ABI_ALL_THREADS`]).
    pub all_threads: bool,
    /// Verify afterwards that `open("/")` fails with EACCES (meaningful only without a rule on `/`).
    pub verify_root_denied: bool,
}

impl Landlock<'_> {
    /// Landlock with no rule at all.
    pub fn deny_all(abi_floor: u32) -> Self {
        Self {
            abi_floor,
            paths: vec![],
            all_threads: false,
            verify_root_denied: false,
        }
    }

    /// Restricts the calling thread (or process) and returns the kernel's ABI.
    pub fn restrict(&self) -> Result<i32, ConfineError> {
        let k = abi();
        if k < i64::from(self.abi_floor) {
            return Err(ConfineError::Landlock(format!(
                "ABI {k} < {} ({})",
                self.abi_floor,
                errno_name(errno())
            )));
        }
        let k = i32::try_from(k).map_err(|_| ConfineError::Landlock(format!("ABI {k}")))?;
        let abi = ABI::from(k);
        let e = |x: &dyn std::fmt::Display| ConfineError::Landlock(x.to_string());
        let mut created = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(abi))
            .map_err(|x| e(&x))?
            .handle_access(AccessNet::from_all(abi))
            .map_err(|x| e(&x))?
            .scope(Scope::from_all(abi))
            .map_err(|x| e(&x))?
            .create()
            .map_err(|x| e(&x))?;
        for &(path, access) in &self.paths {
            created = created
                .add_rule(PathBeneath::new(
                    PathFd::new(path).map_err(|x| e(&x))?,
                    access,
                ))
                .map_err(|x| e(&x))?;
        }
        if self.all_threads {
            created = created
                .all_threads(k >= ABI_ALL_THREADS)
                .map_err(|x| e(&x))?;
        }
        let status = created.restrict_self().map_err(|x| e(&x))?;
        if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
            return Err(ConfineError::Landlock(format!(
                "not fully enforced: {status:?}"
            )));
        }
        if self.verify_root_denied {
            verify_root_denied()?;
        }
        Ok(k)
    }
}

/// The running kernel's Landlock ABI (negative: unavailable, errno set).
fn abi() -> i64 {
    // SAFETY: the version query takes no attribute (NULL, 0).
    unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0usize,
            1u32, // LANDLOCK_CREATE_RULESET_VERSION
        )
    }
}

fn verify_root_denied() -> Result<(), ConfineError> {
    // SAFETY: open of a constant path; closed below.
    let fd = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd >= 0 {
        // SAFETY: our own descriptor.
        unsafe { libc::close(fd) };
        return Err(ConfineError::Landlock("open(/) still succeeds".into()));
    }
    if errno() != libc::EACCES {
        return Err(ConfineError::Landlock(format!(
            "open(/) = {}, expected EACCES",
            errno_name(errno())
        )));
    }
    Ok(())
}
