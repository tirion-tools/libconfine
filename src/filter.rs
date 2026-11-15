//! The seccomp layer: an allowlist of syscall names plus argument rules, compiled by seccompiler into
//! one BPF program (default action and wrong architecture: KILL_PROCESS) and installed with
//! `seccompiler::apply_filter` (TSYNC on request).

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

/// Installs `prog` on the calling thread (`all_threads`: on every thread, TSYNC). Requires
/// NO_NEW_PRIVS already set and the process not dumpable (checked first: after the filter the
/// getters may be denied).
pub fn install(prog: &BpfProgram, all_threads: bool) -> Result<(), ConfineError> {
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
    // apply_filter truncates the length to u16 silently.
    if u16::try_from(prog.len()).is_err() {
        return Err(ConfineError::Seccomp(format!(
            "{} BPF instructions",
            prog.len()
        )));
    }
    let r = if all_threads {
        seccompiler::apply_filter_all_threads(prog)
    } else {
        seccompiler::apply_filter(prog)
    };
    r.map_err(|x| {
        ConfineError::Seccomp(match x {
            seccompiler::Error::Prctl(io) => format!(
                "PR_SET_NO_NEW_PRIVS: {}",
                errno_name(io.raw_os_error().unwrap_or_else(errno))
            ),
            seccompiler::Error::Seccomp(io) => errno_name(io.raw_os_error().unwrap_or_else(errno)),
            seccompiler::Error::ThreadSync(tid) => format!("TSYNC failed for thread {tid}"),
            other => other.to_string(),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::super::bpf::{AUDIT_ARCH_I386, AUDIT_ARCH_X86_64, RET_ALLOW, RET_KILL_PROCESS, run};
    use super::*;
    use std::collections::BTreeSet;

    fn allowed(prog: &BpfProgram, args: [u64; 6]) -> BTreeSet<i64> {
        (0..1024i64)
            .filter(|&nr| run(prog, AUDIT_ARCH_X86_64, nr, args) == RET_ALLOW)
            .collect()
    }

    #[test]
    fn compiles_exactly_the_allowlist() {
        let list = ["read", "write", "exit_group", "getrandom", "capget"];
        let prog = compile(list, &[]).unwrap();
        let want: BTreeSet<i64> = list.iter().map(|n| syscalls::number(n).unwrap()).collect();
        assert_eq!(allowed(&prog, [0; 6]), want);
        assert_eq!(allowed(&prog, [u64::MAX; 6]), want);
    }

    #[test]
    fn argument_rules() {
        let rules = [
            ArgRule::one_of32("prctl", 0, &[1, 2]),
            ArgRule {
                syscall: "mmap",
                any_of: vec![vec![Cond::masked64(2, 4, 0), Cond::masked64(3, 1, 0)]],
            },
            ArgRule {
                syscall: "recvmsg",
                any_of: vec![vec![Cond::eq32(0, 3), Cond::masked32(2, 0x40, 0x40)]],
            },
            ArgRule {
                syscall: "clone",
                any_of: vec![vec![Cond::eq64(0, 1 << 40)]],
            },
        ];
        let prog = compile(["prctl", "mmap", "recvmsg", "clone", "write"], &rules).unwrap();
        let x = AUDIT_ARCH_X86_64;
        let at = |nr: i64, args: [u64; 6]| run(&prog, x, nr, args);
        assert_eq!(at(libc::SYS_prctl, [1, 0, 0, 0, 0, 0]), RET_ALLOW);
        assert_eq!(at(libc::SYS_prctl, [2, 9, 9, 9, 9, 9]), RET_ALLOW);
        assert_eq!(at(libc::SYS_prctl, [3, 0, 0, 0, 0, 0]), RET_KILL_PROCESS);
        // Dword: the high half is not compared.
        assert_eq!(
            at(libc::SYS_prctl, [(7 << 32) | 1, 0, 0, 0, 0, 0]),
            RET_ALLOW
        );
        assert_eq!(at(libc::SYS_mmap, [0, 4096, 3, 2, 0, 0]), RET_ALLOW);
        assert_eq!(at(libc::SYS_mmap, [0, 4096, 7, 2, 0, 0]), RET_KILL_PROCESS);
        assert_eq!(at(libc::SYS_mmap, [0, 4096, 3, 1, 0, 0]), RET_KILL_PROCESS);
        assert_eq!(at(libc::SYS_recvmsg, [3, 0, 0x41, 0, 0, 0]), RET_ALLOW);
        assert_eq!(
            at(libc::SYS_recvmsg, [4, 0, 0x40, 0, 0, 0]),
            RET_KILL_PROCESS
        );
        assert_eq!(
            at(libc::SYS_recvmsg, [3, 0, 0x01, 0, 0, 0]),
            RET_KILL_PROCESS
        );
        assert_eq!(at(libc::SYS_clone, [1 << 40, 0, 0, 0, 0, 0]), RET_ALLOW);
        assert_eq!(at(libc::SYS_clone, [0, 0, 0, 0, 0, 0]), RET_KILL_PROCESS);
        assert_eq!(at(libc::SYS_write, [9; 6]), RET_ALLOW);
        assert_eq!(at(libc::SYS_read, [0; 6]), RET_KILL_PROCESS);
        assert_eq!(
            run(&prog, x, libc::SYS_write | 0x4000_0000, [0; 6]),
            RET_KILL_PROCESS,
            "x32 ABI"
        );
        assert_eq!(
            run(&prog, AUDIT_ARCH_I386, 4 /* i386 write */, [0; 6]),
            RET_KILL_PROCESS,
            "foreign arch"
        );
    }

    #[test]
    fn refuses_bad_policies() {
        let msg = |r: Result<BpfProgram, ConfineError>| r.unwrap_err().to_string();
        assert_eq!(
            msg(compile(["read", "nosuch"], &[])),
            "seccomp: unknown syscall nosuch in the allowlist"
        );
        assert_eq!(
            msg(compile(["read", "read"], &[])),
            "seccomp: read listed twice"
        );
        assert_eq!(
            msg(compile(["read"], &[ArgRule::one_of32("write", 0, &[1])])),
            "seccomp: argument rule for write, which the allowlist does not list"
        );
        let twice = [
            ArgRule::one_of32("read", 0, &[0]),
            ArgRule::one_of32("read", 0, &[1]),
        ];
        assert_eq!(
            msg(compile(["read"], &twice)),
            "seccomp: read has more than one argument rule"
        );
    }
}
