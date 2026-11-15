// The box for a dynamically linked helper the launcher confines itself (the helper cannot: e.g. a runtime
// that starts threads before main): the runtime libraries from a per-distribution manifest, the packaged
// files the caller passes, /dev/null, /dev/urandom and /proc bound into an empty root; Landlock on exactly
// those paths; a libseccomp KILL_PROCESS filter from an allowlist file plus the caller's argument rules.
#pragma once

#include <seccomp.h>

#include <cerrno>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "helper_policy.h"
#include "linux/backend.h"

namespace confine::lnx {

// One line of a library manifest: "<kind> <host path> [<path in the box>]", kind 'r' a file, 'd' a
// directory tree, 'x' a file with execute (the dynamic loader); '#' comments and blank lines ignored.
struct ManifestEntry {
  char kind;
  std::string host, dst;
};

// Reads (and closes) the manifest at `fd`; refuses a malformed, relative, '..'-carrying or empty one.
std::vector<ManifestEntry> load_manifest(int fd);

// Adds libseccomp rules, remembering any failure (EACCES, a rule identical to the default, is not one).
class SeccompRules {
 public:
  explicit SeccompRules(scmp_filter_ctx ctx) : ctx_(ctx) {}
  template <typename... Args>
  void add(uint32_t action, int nr, unsigned n, Args... args) {
    const int rc = seccomp_rule_add(ctx_, action, nr, n, args...);
    failed_ |= rc != 0 && rc != -EACCES;
  }
  bool failed() const { return failed_; }

 private:
  scmp_filter_ctx ctx_;
  bool failed_ = false;
};

// libseccomp's SCMP_A* macros are C99 compound literals; this is the same comparison in C++.
constexpr scmp_arg_cmp arg(unsigned index, scmp_compare op, scmp_datum_t a, scmp_datum_t b = 0) { return scmp_arg_cmp{index, op, a, b}; }

struct SeccompFile {
  std::span<const char* const> deny;          // EPERM; the allowlist file may never name these
  std::span<const char* const> arg_filtered;  // named in the file but allowed only by `rules`
  void (*rules)(SeccompRules&);               // the caller's argument rules
};

// Default and wrong architecture KILL_PROCESS; every syscall the allowlist file at `allow_fd` names (one
// per line, '#' comments) allowed unless arg-filtered; then `spec.rules`; then the deny list as EPERM.
// Refuses a denied or unknown name, an empty allowlist, or a rule libseccomp rejects.
scmp_filter_ctx build_seccomp(int allow_fd, const SeccompFile& spec);

// A packaged file the caller opened (open_packaged), re-opened in the box's mount namespace and bound
// read-only at `dst`; `landlock` rights on it (0: none of its own).
struct PassedFile {
  int fd;
  std::string label;  // failure steps "reopen_<label>", "bind_ro_<dst>"
  std::string dst;
  uint64_t landlock;
};

struct DynamicBox {
  std::vector<ManifestEntry> manifest;
  std::vector<PassedFile> files;                         // bound in order, after the manifest
  uint64_t directory_landlock;                           // Filesystem::Kind::kDirectoryNoExec: rights on it
  std::vector<std::string> empty_dirs;                   // created in the new root (e.g. a HOME)
  std::vector<std::pair<std::string, uint64_t>> landlock;  // further Landlock rules (path in the box, rights)
  scmp_filter_ctx seccomp;
  std::string exec_path;  // path in the box
  std::vector<std::string> argv;
  std::vector<std::string> env;
};

// Builds the box for `policy` (runtime_libraries; brokered sockets with the fd-5 directory at its mount
// point, or Io::kMemfds with neither), clones the helper as the caller's child and returns 0; refuses (exit
// 78) otherwise. fds in the helper: Io::kChannel 0 /dev/null, 1 and 2 the log, 3 the channel; Io::kMemfds 0
// the request, 1 the response, 2 the log.
int launch_dynamic(const HelperPolicy& policy, DynamicBox& box);

}  // namespace confine::lnx
