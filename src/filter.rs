//! The seccomp layer: an allowlist of syscall names plus argument rules, compiled by seccompiler into
//! one BPF program (default action and wrong architecture: KILL_PROCESS) and installed with seccomp(2)
//! (TSYNC on request).

use std::collections::BTreeMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

use super::{ConfineError, errno, errno_name, syscalls};

/// How many bytes of the argument a [`Cond`] compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Width {
    /// The low 32 bits (int, unsigned int, flags passed as int).
    Dword,
    /// All 64 bits.
    Qword,
}

/// One comparison on one syscall argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cond {
    /// Argument index, 0..=5.
    pub arg: u8,
    pub width: Width,
    /// `None`: the argument equals `value`; `Some(mask)`: `argument & mask == value`.
    pub mask: Option<u64>,
    pub value: u64,
}

impl Cond {
    /// The low 32 bits of argument `arg` equal `value`.
    pub const fn eq32(arg: u8, value: u64) -> Self {
        Self {
            arg,
            width: Width::Dword,
            mask: None,
            value,
        }
    }
    /// The 64-bit argument `arg` equals `value`.
    pub const fn eq64(arg: u8, value: u64) -> Self {
        Self {
            arg,
            width: Width::Qword,
            mask: None,
            value,
        }
    }
    /// The low 32 bits of argument `arg`, masked with `mask`, equal `value`.
    pub const fn masked32(arg: u8, mask: u64, value: u64) -> Self {
        Self {
            arg,
            width: Width::Dword,
            mask: Some(mask),
            value,
        }
    }
    /// The 64-bit argument `arg`, masked with `mask`, equals `value`.
    pub const fn masked64(arg: u8, mask: u64, value: u64) -> Self {
        Self {
            arg,
            width: Width::Qword,
            mask: Some(mask),
            value,
        }
    }
}

/// Argument rules of one allowlisted syscall: it is allowed when any alternative matches; an
/// alternative matches when all its conditions hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgRule<'a> {
    pub syscall: &'a str,
    pub any_of: Vec<Vec<Cond>>,
}

impl<'a> ArgRule<'a> {
    /// `syscall` allowed only when argument `arg` (low 32 bits) is one of `values`, in that order.
    pub fn one_of32(syscall: &'a str, arg: u8, values: &[u64]) -> Self {
        Self {
            syscall,
            any_of: values.iter().map(|&v| vec![Cond::eq32(arg, v)]).collect(),
        }
    }
}

fn condition(c: &Cond) -> Result<SeccompCondition, ConfineError> {
    let len = match c.width {
        Width::Dword => SeccompCmpArgLen::Dword,
        Width::Qword => SeccompCmpArgLen::Qword,
    };
    let op = c.mask.map_or(SeccompCmpOp::Eq, SeccompCmpOp::MaskedEq);
    SeccompCondition::new(c.arg, len, op, c.value).map_err(|e| ConfineError::Seccomp(e.to_string()))
}

/// Compiles `allowlist` (syscall names; each at most once) with `rules` (each naming a listed
/// syscall at most once) for x86_64.
pub fn compile<'a>(
    allowlist: impl IntoIterator<Item = &'a str>,
    rules: &[ArgRule<'_>],
) -> Result<BpfProgram, ConfineError> {
    let e = |x: &dyn std::fmt::Display| ConfineError::Seccomp(x.to_string());
    let mut map: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    let mut names = Vec::new();
    for name in allowlist {
        let nr = syscalls::number(name).ok_or_else(|| {
            ConfineError::Seccomp(format!("unknown syscall {name} in the allowlist"))
        })?;
        let mut matching = rules.iter().filter(|r| r.syscall == name);
        let alternatives = match (matching.next(), matching.next()) {
            (_, Some(_)) => {
                return Err(ConfineError::Seccomp(format!(
                    "{name} has more than one argument rule"
                )));
            }
            (Some(r), None) => r
                .any_of
                .iter()
                .map(|conds| {
                    let c = conds.iter().map(condition).collect::<Result<Vec<_>, _>>()?;
                    SeccompRule::new(c).map_err(|x| e(&x))
                })
                .collect::<Result<Vec<_>, _>>()?,
            (None, None) => vec![],
        };
        if map.insert(nr, alternatives).is_some() {
            return Err(ConfineError::Seccomp(format!("{name} listed twice")));
        }
        names.push(name);
    }
    if let Some(r) = rules.iter().find(|r| !names.contains(&r.syscall)) {
        return Err(ConfineError::Seccomp(format!(
            "argument rule for {}, which the allowlist does not list",
            r.syscall
        )));
    }
    SeccompFilter::new(
        map,
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        TargetArch::x86_64,
    )
    .map_err(|x| e(&x))?
    .try_into()
    .map_err(|x: seccompiler::BackendError| e(&x))
}

/// Installs `prog` on the calling thread (`all_threads`: on every thread, TSYNC) with seccomp(2), after
/// setting NO_NEW_PRIVS and checking that the process is not dumpable.
pub fn install(prog: &BpfProgram, all_threads: bool) -> Result<(), ConfineError> {
    // SAFETY: prctl with integer arguments only.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(ConfineError::Seccomp(format!(
            "PR_SET_NO_NEW_PRIVS: {}",
            errno_name(errno())
        )));
    }
    // SAFETY: getter prctls with integer arguments only (no filter of ours yet).
    let (nnp, dumpable) = unsafe {
        (
            libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0),
            libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0),
        )
    };
    if nnp != 1 || dumpable != 0 {
        return Err(ConfineError::SelfCheck(format!(
            "no_new_privs {nnp}, dumpable {dumpable}"
        )));
    }
    let len = u16::try_from(prog.len())
        .map_err(|_| ConfineError::Seccomp(format!("{} BPF instructions", prog.len())))?;
    let fprog = SockFprog {
        len,
        filter: prog.as_ptr(),
    };
    let flags: libc::c_ulong = if all_threads {
        SECCOMP_FILTER_FLAG_TSYNC
    } else {
        0
    };
    // SAFETY: `fprog` points at `prog`, which outlives the call; the kernel copies the program.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            flags,
            &raw const fprog,
        )
    };
    if rc != 0 {
        return Err(ConfineError::Seccomp(if rc < 0 {
            errno_name(errno())
        } else {
            format!("TSYNC failed for thread {rc}")
        }));
    }
    Ok(())
}

const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
const SECCOMP_FILTER_FLAG_TSYNC: libc::c_ulong = 1;

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const seccompiler::sock_filter,
}
