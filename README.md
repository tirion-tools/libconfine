# libconfine

Fail-closed confinement for small Linux helper processes, in two parts:

- **`confine`** (Rust crate, `src/`): self-confinement of a single-threaded, statically linked helper, driven by a
  policy given as data. The helper calls it first thing in `main` and refuses to run if any layer is missing.
- **`confine_launcher`** (C++ static library, `launcher/`): a launcher that checks a fixed descriptor contract and
  starts the helper in an empty, namespaced box as the caller's own child.

Linux on x86_64 only. Neither part names a helper: every allowlist, argument rule, limit, path, mount point and probe
comes from the caller.

## Builds on

- **Landlock** (the Linux LSM) through the [`landlock`](https://crates.io/crates/landlock) crate (rust-landlock):
  rulesets, hard ABI requirements, `all_threads`.
- **seccomp-BPF** through [`seccompiler`](https://crates.io/crates/seccompiler) (rust-vmm): filter compilation and
  `apply_filter` / `apply_filter_all_threads`.
- **[libseccomp](https://github.com/seccomp/libseccomp)** in the launcher's dynamic-binary box (the helper is not
  ours to modify, so the filter is installed before `exec`).
- The launcher's box uses the same namespace, `pivot_root` and bind-mount techniques as
  [bubblewrap](https://github.com/containers/bubblewrap) and [minijail](https://github.com/google/minijail).

Fixes to those layers go upstream, not into this repository. A public syscall name → number table in seccompiler
(merged in rust-vmm/rust-vmm#103, not yet released) would replace `src/syscalls.rs`.

What it adds:

1. A **fail-closed self-confinement sequence** ([`confine::enter`]) for single-threaded, statically linked helpers:
   lower-only rlimits, non-dumpable and `NO_NEW_PRIVS` (both verified), then Landlock with every right and scope of
   the running kernel's ABI handled and a hard minimum ABI, then one KILL_PROCESS seccomp filter compiled from a
   frozen allowlist and its argument rules (plus, optionally, a few syscalls answered with a fixed errno in the same
   filter), then a self-check. It also handles the musl and Rust runtime quirks that
   would otherwise widen the filter: pthread key 0 reserved, `SIGXFSZ` ignored, an allocator that exits on
   allocation failure ([`confine::alloc::ExitOnOom`]).
2. **In-helper box checks** ([`confine::checks`]): the helper verifies the launcher's box itself (PID 1 with no
   parent, empty root, every capability set empty, a network namespace with `lo` down and no route).
3. A **denial-matrix harness** ([`confine::probe`]) that runs escape probes per layer in forked children and reports
   `DENIAL` / `CONTROL` outcomes, so the boundaries are tested rather than assumed.
4. A **launcher for descriptor-only boxes**: before any namespace exists it checks a fixed descriptor contract (fd 3
   a `SOCK_SEQPACKET` channel whose peer must be the parent, fd 4 the status pipe's write end, sealed memfd inputs, a
   private directory, nothing else open) and the credentials (no secure-exec, no root, no capabilities, no setuid or
   file capabilities on the launcher). The box has an empty read-only root, new user, mount, pid, ipc, net, uts and
   cgroup namespaces and no capabilities; the helper is exec'd from a pre-opened, owner- and mode-checked file with an
   empty environment, runs as PID 1 and is the caller's own child (`CLONE_PARENT`), so the caller can supervise it.

Related projects (choose them for general sandboxing; choose this when you need fixed-contract, descriptor-only
helpers that verify their own confinement):

- [extrasafe](https://github.com/boustrophedon/extrasafe): ergonomic in-process seccomp and Landlock rulesets.
- [birdcage](https://github.com/phylum-dev/birdcage): cross-platform file system and network sandbox (GPL-3.0).
- [hakoniwa](https://github.com/souk4711/hakoniwa): container-style isolation in Rust.
- [bubblewrap](https://github.com/containers/bubblewrap), [minijail](https://github.com/google/minijail),
  [nsjail](https://github.com/google/nsjail): general-purpose launchers.

## API

Rust (`confine`):

| Item | What |
|---|---|
| `Policy`, `enter(&Policy) -> Result<Report, ConfineError>` | the whole sequence; `Report` prints one `confined: ...` line |
| `allowlist::parse` | the allowlist file format: one syscall name per line, `#` comments |
| `filter`, `ArgRule`, `Failing` | the seccompiler filter (default and wrong architecture KILL_PROCESS), argument rules, and syscalls that fail with a fixed errno instead (a prologue in the same filter) |
| `landlock::Landlock` | deny-all or path rules at a minimum ABI |
| `process::{Process, Rlimit}` | the process layers |
| `checks` | descriptor-only box checks and the capability check |
| `probe::{Matrix, Probe}` | the denial-matrix harness |
| `bpf::run` | a BPF interpreter for testing filters without installing them |
| `alloc::ExitOnOom` | global allocator that writes a message and exits on allocation failure |

C++ (`confine_launcher`, namespace `confine`): `HelperPolicy` (`helper_policy.h`) is the policy schema; the caller owns
the table. `confine::lnx::launch(policy, options)` builds the box for static helpers and `launch_dynamic`
(`linux/dynamic_box.h`) for a dynamically linked one; `check_credentials` and `check_fds` are the contract checks.
Consumers `add_subdirectory(launcher)` and link `confine_launcher`; status lines are `R <reason>` (refused),
`F <step> <errno>` (failed in the box) and `P <pid>` (started), and every failure ends in exit 78.

## Security model

- **Fail closed.** Every layer is verified after it is applied; a missing layer is an error, never a warning. The
  helper exits instead of running with less confinement. The launcher exits 78 on any refusal.
- **Mechanism, not policy.** The crate and the launcher enforce exactly what the caller's policy says; reviewing that
  policy (the allowlist, the argument rules, the paths) is the caller's job. Allowlists are packaged data, not
  untrusted input.
- **Requirements.** Landlock at the policy's minimum ABI, seccomp, unprivileged user namespaces for the launcher.
  Below the minimum the helper refuses to start.
- **Limits.** x86_64 only. The helper must be single-threaded when it calls `enter` unless the policy asks for TSYNC.
  The launcher needs glibc 2.32 or later (`strerrorname_np`).

## Tests

- Rust unit tests in `src/` with synthetic policies: the filter allows exactly the allowlist, argument rules, x32 and
  foreign-architecture kills, refusal of unknown, duplicate and dangling names; the allowlist parser; the BPF
  interpreter; the syscall table; `Report` lines; `Matrix` counts and `run_forked` outcomes.
- `launcher/tests/contract_test.cc`: the invocation contract, accepted and refused cases, in forked children.

## Gates

Every check runs locally, in a pinned toolchain container (`tools/container/Dockerfile`: Rust 1.93.1 by digest, plus
cargo-deny 0.20.2, and CMake, Ninja and libseccomp at exact versions from a dated Debian snapshot):

```sh
tools/container.sh tools/gate.sh            # fmt, clippy, test, launcher, audit
tools/container.sh tools/gate.sh test       # one job
```

| Job | What |
|---|---|
| `fmt` | `cargo fmt --check` |
| `clippy` | `cargo clippy --locked --all-targets -D warnings` |
| `test` | `cargo test --locked` |
| `launcher` | the C++ library and the contract tests with `-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Werror`, then `ctest` |
| `audit` | `cargo deny check`: advisories, licences, bans, sources |

The crate parses no untrusted input, so there is no fuzz target. The library ships no binaries. Consumers pin a
commit. `.github/workflows/` mirrors the gate for when the repository is hosted.

## Contributing

This repository is not accepting contributions at this time: issues and pull requests are not accepted. Report
security vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md).

## Licence

MIT, see `LICENSE`. The launcher links libseccomp (LGPL-2.1) dynamically. Third-party material:
`THIRD-PARTY-NOTICES.md`.
