// Linux backend of the helper launcher: the invocation contract, new namespaces, an empty root, capabilities,
// NO_NEW_PRIVS and rlimits, then the helper exec'd as the caller's own child. Every failure ends in exit 78.
//
// Invocation contract: fd 3 a SOCK_SEQPACKET socketpair end created by the parent, fd 4 the write end of the
// status pipe ("R <reason>" refused, "F <step> <errno>" failed in the box, "P <pid>" the helper's pid), fd 5 per
// policy (HelperPolicy::extra_fd), nothing else open; Io::kMemfds also fd 0 the sealed request and fd 1 the
// empty response memfd.
#pragma once

#include <string>
#include <vector>

#include "helper_policy.h"

namespace confine::lnx {

inline constexpr int kExitRefused = 78;  // EX_CONFIG: "sandbox not supported on this system"
inline constexpr int kIpcFd = 3;
inline constexpr int kStatusFd = 4;
inline constexpr int kExtraFd = 5;

// The launcher's name in messages ("<name>: refusing: ..."); set once at start.
void set_program_name(const char* name);
const char* program_name();

// Refusal before any namespace exists: "R <reason>" on the status pipe (if fd 4 is one) and stderr.
[[noreturn]] void refuse(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

// AT_SECURE, differing real/effective ids, uid 0, any capability, a setuid/setgid/capability-carrying
// launcher file: refused.
void check_credentials();

// The invocation contract above for `policy`.
void check_fds(const HelperPolicy& policy);

struct LaunchOptions {
  std::string helper_dir;         // the packaged helper directory (compiled into the launcher)
  std::vector<std::string> argv;  // the helper's complete argv, argv[0] included
};

// Static helpers: builds the descriptor-only box (Filesystem::Kind::kNone) or the one-directory box
// (Filesystem::Kind::kDirectoryNoExec), clones the helper as the caller's child (CLONE_PARENT), writes
// "P <pid>" to the status pipe and returns 0; refuses (exit 78) any other policy shape. Dynamically linked
// helpers launch through launch_dynamic (linux/dynamic_box.h).
int launch(const HelperPolicy& policy, const LaunchOptions& options);

}  // namespace confine::lnx
