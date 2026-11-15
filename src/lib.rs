//! Self-confinement of a single-threaded (at entry), statically linked Linux helper, driven by a
//! caller-supplied [`Policy`]. Mechanism only: every allowlist, argument rule, limit, path and probe
//! comes from the caller.
//!
//! [`enter`] applies, in order and failing closed:
//!   1. process layers: optionally SIGXFSZ ignored and descriptors from N up closed; not dumpable,
//!      NO_NEW_PRIVS (both verified); optionally pthread key 0 reserved (musl); the rlimits lowered
//!      (never raised);
//!   2. optionally the descriptor-only box checks ([`checks::descriptor_only_box`]);
//!   3. Landlock through the `landlock` crate at a hard minimum ABI: every filesystem and network
//!      right and every scope of the running kernel's ABI handled, plus the policy's path rules;
//!   4. one seccompiler filter (default and wrong architecture KILL_PROCESS) compiled from the
//!      allowlist and its argument rules, installed with `seccompiler::apply_filter` (TSYNC when the
//!      policy asks);
//!   5. the policy's self-check, returning a [`Report`].
//!
//! The pieces are public as well, for denial-matrix drivers that apply the layers in a different
//! order around their probes ([`probe`]).
//!
//! Linux on x86_64 only; on other targets the crate is empty.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

pub mod alloc;
pub mod allowlist;
pub mod bpf;
pub mod checks;
mod error;
pub mod filter;
pub mod landlock;
pub mod policy;
pub mod probe;
pub mod process;
pub mod syscalls;

pub use error::{ConfineError, errno, errno_name};
pub use policy::{Policy, Report, SelfCheck, enter};
pub use probe::{Matrix, Probe};
