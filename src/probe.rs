//! Denial-matrix harness: escape probes run in forked children (a seccomp kill ends only the child),
//! each outcome compared with the expected set and printed on stderr as
//! `DENIAL <layers>/<probe> <outcome>` or `CONTROL <layers>/<probe> <outcome>` (expected outcome
//! exactly "ok"), `UNEXPECTED ...` for a mismatch and a final `DENIAL-MATRIX-DONE` line.

use std::io::Read;
use std::os::fd::FromRawFd;

use super::{errno, errno_name};

/// One row of a probe table: the layers it runs under (a label), its name and the outcomes that
/// count as expected ("ok", an errno name, "SIGSYS", "signal<n>", "exit<code>").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    pub layers: &'static str,
    pub name: &'static str,
    pub expect: &'static [&'static str],
}

impl Probe {
    pub const fn new(
        layers: &'static str,
        name: &'static str,
        expect: &'static [&'static str],
    ) -> Self {
        Self {
            layers,
            name,
            expect,
        }
    }
}

/// Counts of a denial-matrix run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Matrix {
    pub denials: usize,
    pub controls: usize,
    /// Probes whose outcome differed from the expected set (a denial that held with an unexpected
    /// errno counts here too).
    pub unexpected: usize,
}

impl Matrix {
    pub fn ok(&self) -> bool {
        self.unexpected == 0
    }

    /// Counts and prints one outcome.
    pub fn record(&mut self, layers: &str, name: &str, expect: &[&str], got: &str) {
        let control = expect == ["ok"];
        if control {
            self.controls += 1;
        } else {
            self.denials += 1;
        }
        eprintln!(
            "{} {layers}/{name} {got}",
            if control { "CONTROL" } else { "DENIAL" }
        );
        if !expect.contains(&got) {
            self.unexpected += 1;
            eprintln!(
                "UNEXPECTED {layers}/{name} got {got} want {}",
                expect.join("|")
            );
        }
    }

    /// Runs every row of `probes` through `run` and records its outcome.
    pub fn run_all(&mut self, probes: &[Probe], mut run: impl FnMut(&Probe) -> String) {
        for p in probes {
            let got = run(p);
            self.record(p.layers, p.name, p.expect, &got);
        }
    }

    /// Prints the `DENIAL-MATRIX-DONE` line and returns the counts.
    pub fn done(self) -> Self {
        eprintln!(
            "DENIAL-MATRIX-DONE denials={} controls={} unexpected={}",
            self.denials, self.controls, self.unexpected
        );
        self
    }
}

/// A probe's raw result as an outcome: "ok" for `rc >= 0`, else the errno name.
pub fn outcome(rc: i64) -> String {
    if rc < 0 {
        errno_name(errno())
    } else {
        "ok".to_string()
    }
}

/// Forks; the child runs `setup` (false: `_exit(78)`) and then `body`, and writes its outcome. Returns
/// that outcome, "SIGSYS" (killed by the filter), "signal<n>", or "exit<code>" when the child wrote
/// nothing. Call only while the process is single-threaded.
pub fn run_forked(setup: impl FnOnce() -> bool, body: impl FnOnce() -> String) -> String {
    let mut p = [0i32; 2];
    // SAFETY: `p` holds two descriptors.
    if unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return format!("pipe2 {}", errno_name(errno()));
    }
    // SAFETY: single-threaded (caller's contract); the child only runs `setup` and `body`, writes
    // one result and _exits.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // SAFETY: child side: own descriptors only, then _exit.
        unsafe {
            libc::close(p[0]);
            if !setup() {
                libc::_exit(78);
            }
            let out = body();
            libc::write(p[1], out.as_ptr().cast(), out.len());
            libc::_exit(0);
        }
    }
    // SAFETY: parent side: closes its copy of the write end.
    unsafe { libc::close(p[1]) };
    if pid < 0 {
        // SAFETY: closes the read end we own.
        unsafe { libc::close(p[0]) };
        return format!("fork {}", errno_name(errno()));
    }
    let mut out = String::new();
    // SAFETY: p[0] is ours; File takes ownership and closes it.
    let _ = unsafe { std::fs::File::from_raw_fd(p[0]) }.read_to_string(&mut out);
    let mut status = 0;
    // SAFETY: waits for our own child.
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if libc::WIFSIGNALED(status) {
        let sig = libc::WTERMSIG(status);
        return if sig == libc::SIGSYS {
            "SIGSYS".into()
        } else {
            format!("signal{sig}")
        };
    }
    if out.is_empty() {
        format!("exit{}", libc::WEXITSTATUS(status))
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts() {
        let mut m = Matrix::default();
        m.record("a", "denied", &["EPERM"], "EPERM");
        m.record("a", "control", &["ok"], "ok");
        m.record("a", "leak", &["SIGSYS"], "ok");
        assert_eq!(
            m.clone().done(),
            Matrix {
                denials: 2,
                controls: 1,
                unexpected: 1
            }
        );
        assert!(!m.ok());
    }

    #[test]
    fn forked_outcomes() {
        assert_eq!(run_forked(|| true, || "ok".into()), "ok");
        assert_eq!(run_forked(|| false, || "ok".into()), "exit78");
        assert_eq!(
            run_forked(
                || true,
                // SAFETY: ends the forked child.
                || unsafe { libc::_exit(3) }
            ),
            "exit3"
        );
        // No core file for the SIGSYS child.
        let no_core = || {
            let zero = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: valid rlimit.
            unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) == 0 }
        };
        assert_eq!(
            run_forked(
                no_core,
                // SAFETY: kills the forked child.
                || unsafe {
                    libc::raise(libc::SIGSYS);
                    libc::_exit(0)
                }
            ),
            "SIGSYS"
        );
        // SAFETY: close(-1) only fails.
        let rc = run_forked(|| true, || outcome(unsafe { libc::close(-1) }.into()));
        assert_eq!(rc, "EBADF");
    }
}
