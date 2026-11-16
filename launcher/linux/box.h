// Building blocks shared by the Linux boxes (oneshot_box.cc, directory_box.cc, dynamic_box.cc): the new root under /tmp,
// bind mounts, re-opening passed descriptors inside the new mount namespace, capability drop, fd layout,
// rlimits and the clone into new namespaces with the caller as parent.
#pragma once

#include <string>
#include <vector>

#include "linux/backend.h"
#include "helper_policy.h"

namespace confine::lnx {

inline constexpr unsigned long kBindKeepDev = 1UL << 40;  // device-node binds must not get MS_NODEV
inline constexpr int kBindMissing = -2;                    // Binder::bind: optional source absent

struct Binder {
  std::string base;
  std::vector<std::string> bound_dirs;

  // Binds `host` at `dst` below `base` (MS_NOSUID, MS_NODEV unless kBindKeepDev, read-only unless
  // `writable`, plus the `extra` MS_* flags). > 0 errno, 0 bound, -1 already visible through an
  // earlier directory bind, kBindMissing `host` does not exist and `missing_ok` (nothing created).
  int bind(const std::string& host, const std::string& dst, bool writable, unsigned long extra, bool missing_ok = false);
};

int mkdir_p(const std::string& path);

// A descriptor opened before clone(CLONE_NEWNS) belongs to the caller's mount namespace; mount(MS_BIND)
// of it returns EINVAL. Re-opens the same path inside the new namespace and requires the same inode.
// Returns the new descriptor (*proc_path = its /proc/self/fd path) or -errno.
int reopen_here(int fd, std::string* proc_path);

int drop_caps();

// Moves fds to their contract positions without clobbering each other; closes everything above n-1.
// want[i] = source of target fd i; cloexec[i] marks targets closed by exec.
int arrange_fds(const int* want, const bool* cloexec, int n);

// The inode number of the caller's namespace `ns` ("0" if unreadable).
std::string ns_inode(const char* ns);

int landlock_abi();

// Refuses unless Landlock ABI >= 6 and seccomp KILL_PROCESS are available.
void require_kernel_floor();

// Child-side failure: "F <step> <errno>" on the status pipe, exit 78.
[[noreturn]] void child_fail(const char* step, int e);
void step(const char* name, int e);
int err(int rc);

// Child side, first step in the new mount namespace: mount propagation private (or child_fail).
void make_mounts_private();

// The policy's rlimits (zero for every resource it denies, the policy's caps for the others).
void apply_rlimits(const HelperPolicy& policy);

// clone(CLONE_PARENT | ns_flags): the child waits until the parent has written its id maps, then runs
// `child(ctx)`, which must exec or child_fail. The parent writes "P <pid>" on the status pipe, releases
// the child and returns 0; refuses (exit 78) otherwise.
using BoxMain = void (*)(void* ctx);
int spawn_box(unsigned long ns_flags, BoxMain child, void* ctx);

// The new root under /tmp becomes "/": pivot_root, detach the old root, remount read-only with `flags`.
void pivot_to_new_root(const std::string& base, unsigned long remount_flags);

// The helper's argv as execve wants it (pointers into `args`, NULL-terminated).
std::vector<char*> exec_argv(std::vector<std::string>& args);

// Descriptor-only helpers: oneshot_box.cc.
int launch_oneshot(const HelperPolicy& policy, const LaunchOptions& options);
// One read-write noexec directory: directory_box.cc.
int launch_directory(const HelperPolicy& policy, const LaunchOptions& options);

}  // namespace confine::lnx
