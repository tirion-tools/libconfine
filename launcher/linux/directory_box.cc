// The one-directory box for static helpers that own one directory: an empty read-only root whose only
// entry is Filesystem::mount_point, the caller's directory (fd 5) bind-mounted rw,noexec,nosuid,nodev; no
// /proc, no /dev; user, mount, pid, ipc, net, uts and cgroup namespaces; no capabilities; NO_NEW_PRIVS;
// rlimits; then execveat of the packaged binary with an empty environment. fds: 0 and 1 /dev/null, 2 the
// log, 3 the channel. The helper is expected to confine itself further (Landlock on the directory, seccomp).
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <string>
#include <string_view>
#include <vector>

#include "linux/backend.h"
#include "linux/box.h"
#include "linux/util.h"

namespace confine::lnx {
namespace {

struct DirectoryChild {
  const HelperPolicy* policy;
  std::string mount_point;
  int devnull_r;
  int devnull_w;
  int helper_fd;
  std::vector<std::string> args;
};

void child_directory(void* ctx) {
  DirectoryChild& a = *static_cast<DirectoryChild*>(ctx);
  make_mounts_private();
  // Re-open the directory in this mount namespace before the new root hides /tmp.
  std::string dir_path;
  const int rf = reopen_here(kExtraFd, &dir_path);
  step(("reopen_" + a.mount_point.substr(1)).c_str(), rf < 0 ? -rf : 0);
  Binder b{.base = "/tmp", .bound_dirs = {}};
  step("tmpfs_newroot",
       err(mount("tmpfs", b.base.c_str(), "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=0755,size=16k,nr_inodes=8")));
  const int r = b.bind(dir_path, a.mount_point, true, MS_NOEXEC);
  step(("bind_rw_noexec_" + a.mount_point).c_str(), r > 0 ? r : (r < 0 ? EEXIST : 0));
  pivot_to_new_root(b.base, MS_NOSUID | MS_NODEV | MS_NOEXEC);
  step("capdrop", drop_caps());
  step("no_new_privs", err(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)));
  apply_rlimits(*a.policy);
  // fds: 0 and 1 /dev/null, 2 the log, 3 IPC, 4 status (CLOEXEC: EOF = exec'd), 5 the helper binary
  // (CLOEXEC, executed through execveat); nothing else.
  const int want[6] = {a.devnull_r, a.devnull_w, 2, kIpcFd, kStatusFd, a.helper_fd};
  const bool cx[6] = {false, false, false, false, true, true};
  step("fd_layout", arrange_fds(want, cx, 6));
  std::vector<char*> argv = exec_argv(a.args);
  char* envp[] = {nullptr};
  syscall(SYS_execveat, kExtraFd, "", argv.data(), envp, AT_EMPTY_PATH);
  child_fail("execveat", errno);
}

}  // namespace

int launch_directory(const HelperPolicy& policy, const LaunchOptions& options) {
  const std::string_view mp = policy.filesystem.mount_point;
  if (mp.size() < 2 || mp[0] != '/' || mp.find('/', 1) != std::string_view::npos)
    refuse("mount point '%.*s' is not one absolute component", static_cast<int>(mp.size()), mp.data());
  const uid_t owner = launcher_owner();
  DirectoryChild a{};
  a.policy = &policy;
  a.mount_point = mp;
  a.helper_fd = open_packaged(options.helper_dir, std::string(policy.helper).c_str(), owner, true);
  require_kernel_floor();  // the helper enforces both itself; refuse here before any namespace exists
  a.args = options.argv;
  a.devnull_r = open("/dev/null", O_RDONLY | O_CLOEXEC);
  a.devnull_w = open("/dev/null", O_WRONLY | O_CLOEXEC);
  if (a.devnull_r < 0 || a.devnull_w < 0) refuse("open /dev/null: %s", errno_name(errno));
  return spawn_box(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWUTS | CLONE_NEWCGROUP,
                   child_directory, &a);
}

}  // namespace confine::lnx
