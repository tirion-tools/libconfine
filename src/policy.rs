//! [`Policy`]: everything a helper's confinement needs, as data; [`enter`] applies it.

use std::fmt;

use seccompiler::BpfProgram;

use super::filter::{self, ArgRule};
use super::landlock::Landlock;
use super::process::{self, Process, Rlimit};
use super::{ConfineError, checks};

/// What the self-check after the filter verifies (each needs its getter on the allowlist).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SelfCheck {
    /// `PR_GET_SECCOMP == 2`.
    pub seccomp_mode: bool,
    /// `PR_GET_NO_NEW_PRIVS == 1` and `PR_GET_DUMPABLE == 0`.
    pub nnp_dumpable: bool,
    /// [`checks::capabilities_empty`].
    pub capabilities: bool,
}

/// A helper's confinement policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy<'a> {
    /// Allowed syscall names (e.g. [`super::allowlist::parse`] of a file), each once.
    pub allowlist: Vec<&'a str>,
    /// Argument rules of allowlisted syscalls; a syscall without one is allowed with any arguments.
    pub arg_rules: Vec<ArgRule<'a>>,
    /// Install the filter on every thread (TSYNC).
    pub tsync: bool,
    /// Lowered (never raised) during the process layers.
    pub rlimits: &'a [Rlimit],
    pub process: Process,
    /// Run [`checks::descriptor_only_box`] after the process layers.
    pub box_checks: bool,
    pub landlock: Landlock<'a>,
    pub self_check: SelfCheck,
}

/// What [`enter`] enforced and verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The kernel's Landlock ABI; the ruleset is fully enforced.
    pub landlock_abi: i32,
    /// Landlock path rules (0: deny-all).
    pub landlock_rules: usize,
    /// Syscalls in the allowlist.
    pub syscalls: usize,
    /// Instructions in the installed BPF program.
    pub bpf_insns: usize,
    /// PR_GET_SECCOMP after installation, when the self-check reads it.
    pub seccomp_mode: Option<i32>,
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "confined: landlock ABI {} fully enforced{}, seccomp KILL_PROCESS filter {} syscalls / {} BPF insns",
            self.landlock_abi,
            if self.landlock_rules == 0 {
                " (no rules)"
            } else {
                ""
            },
            self.syscalls,
            self.bpf_insns
        )?;
        if let Some(mode) = self.seccomp_mode {
            write!(f, ", mode {mode}")?;
        }
        Ok(())
    }
}

impl Policy<'_> {
    /// Compiles the allowlist and argument rules.
    pub fn filter(&self) -> Result<BpfProgram, ConfineError> {
        filter::compile(self.allowlist.iter().copied(), &self.arg_rules)
    }

    /// The process layers with `rlimits` (all of [`Policy::rlimits`] or a subset).
    pub fn process_layers(&self, rlimits: &[Rlimit]) -> Result<(), ConfineError> {
        process::apply(&self.process, rlimits)
    }

    /// Installs `prog` (from [`Policy::filter`]) on the calling thread, or every thread with TSYNC.
    pub fn install(&self, prog: &BpfProgram) -> Result<(), ConfineError> {
        filter::install(prog, self.tsync)
    }

    /// The self-check after [`Policy::install`].
    pub fn self_check(&self, landlock_abi: i32, prog: &BpfProgram) -> Result<Report, ConfineError> {
        let c = self.self_check;
        let mut seccomp_mode = None;
        let mut failed = false;
        let mut parts = Vec::new();
        if c.seccomp_mode {
            // SAFETY: getter prctl with integer arguments only.
            let mode = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
            failed |= mode != 2;
            parts.push(format!("seccomp mode {mode}"));
            seccomp_mode = Some(mode);
        }
        if c.nnp_dumpable {
            // SAFETY: getter prctls with integer arguments only.
            let (nnp, dumpable) = unsafe {
                (
                    libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0),
                    libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0),
                )
            };
            failed |= nnp != 1 || dumpable != 0;
            parts.push(format!("no_new_privs {nnp}, dumpable {dumpable}"));
        }
        if failed {
            return Err(ConfineError::SelfCheck(parts.join(", ")));
        }
        if c.capabilities {
            checks::capabilities_empty().map_err(ConfineError::SelfCheck)?;
        }
        Ok(Report {
            landlock_abi,
            landlock_rules: self.landlock.paths.len(),
            syscalls: self.allowlist.len(),
            bpf_insns: prog.len(),
            seccomp_mode,
        })
    }
}

/// Confines the calling process with `policy`: process layers, box checks, Landlock, the filter,
/// the self-check (module documentation of the crate). Call once, before any thread exists (unless
/// the policy uses TSYNC) and before reading input; on error the caller exits.
pub fn enter(policy: &Policy<'_>) -> Result<Report, ConfineError> {
    let prog = policy.filter()?;
    policy.process_layers(policy.rlimits)?;
    if policy.box_checks {
        checks::descriptor_only_box()?;
    }
    let abi = policy.landlock.restrict()?;
    policy.install(&prog)?;
    policy.self_check(abi, &prog)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(rules: usize, mode: Option<i32>) -> String {
        Report {
            landlock_abi: 6,
            landlock_rules: rules,
            syscalls: 12,
            bpf_insns: 99,
            seccomp_mode: mode,
        }
        .to_string()
    }

    #[test]
    fn report_lines() {
        assert_eq!(
            report(0, Some(2)),
            "confined: landlock ABI 6 fully enforced (no rules), seccomp KILL_PROCESS filter 12 syscalls / 99 BPF insns, mode 2"
        );
        assert_eq!(
            report(1, Some(2)),
            "confined: landlock ABI 6 fully enforced, seccomp KILL_PROCESS filter 12 syscalls / 99 BPF insns, mode 2"
        );
        assert_eq!(
            report(0, None),
            "confined: landlock ABI 6 fully enforced (no rules), seccomp KILL_PROCESS filter 12 syscalls / 99 BPF insns"
        );
    }

    #[test]
    fn policy_filter_uses_its_rules() {
        let p = Policy {
            allowlist: vec!["read", "exit_group"],
            arg_rules: vec![ArgRule::one_of32("read", 0, &[0])],
            tsync: false,
            rlimits: &[],
            process: Process::default(),
            box_checks: false,
            landlock: Landlock::deny_all(6),
            self_check: SelfCheck::default(),
        };
        let prog = p.filter().unwrap();
        use super::super::bpf::{AUDIT_ARCH_X86_64, RET_ALLOW, RET_KILL_PROCESS, run};
        assert_eq!(
            run(&prog, AUDIT_ARCH_X86_64, libc::SYS_read, [0; 6]),
            RET_ALLOW
        );
        assert_eq!(
            run(&prog, AUDIT_ARCH_X86_64, libc::SYS_read, [1, 0, 0, 0, 0, 0]),
            RET_KILL_PROCESS
        );
    }
}
