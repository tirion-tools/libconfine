// The descriptor-only box for static helpers that see no filesystem and talk only over descriptors: an empty
// read-only tmpfs root (no /proc, no /dev); user, mount, pid, ipc, net, uts and cgroup namespaces; no
// capabilities; NO_NEW_PRIVS; rlimits; then execveat of the packaged binary with an empty environment.
// fds: 0 and 1 /dev/null, 2 the log, 3 the SOCK_SEQPACKET channel, plus 5 for ExtraFd::Kind::kSealedMemfd
// (checked by contract.cc); Io::kMemfds: 0 the sealed request memfd, 1 the response memfd, no channel. The
// helper is expected to confine itself further (Landlock, seccomp) before reading input.
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
#include <vector>

#include "linux/backend.h"
#include "linux/box.h"
#include "linux/util.h"

namespace confine::lnx {
namespace {

struct OneshotChild {
  const HelperPolicy* policy;
  int devnull_r;
  int devnull_w;
  int helper_fd;
  bool extra_memfd;
  bool memfds;
  std::vector<std::string> args;
};

void child_oneshot(void* ctx) {
  OneshotChild& a = *static_cast<OneshotChild*>(ctx);
  make_mounts_private();
  const std::string base = "/tmp";
  step("tmpfs_newroot",
       err(mount("tmpfs", base.c_str(), "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=0555,size=4k,nr_inodes=4")));
  pivot_to_new_root(base, MS_NOSUID | MS_NODEV | MS_NOEXEC);
  step("capdrop", drop_caps());
  step("no_new_privs", err(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)));
  // fds: 0 and 1 /dev/null, 2 the log, 3 IPC, 4 status (CLOEXEC: EOF = exec'd), [5 the sealed memfd,] then
  // the helper binary (CLOEXEC, executed through execveat); nothing else.
  int n = 0;
  if (a.memfds) {
    // Io::kMemfds: 0 the request, 1 the response, 2 the log, 3 the helper binary (CLOEXEC), 4 status.
    const int want[5] = {0, 1, 2, a.helper_fd, kStatusFd};
    const bool cx[5] = {false, false, false, true, true};
    n = 5;
    step("fd_layout", arrange_fds(want, cx, n));
  } else {
    const int want[7] = {a.devnull_r, a.devnull_w, 2, kIpcFd, kStatusFd, a.extra_memfd ? kExtraFd : a.helper_fd, a.helper_fd};
    const bool cx[7] = {false, false, false, false, true, !a.extra_memfd, true};
    n = a.extra_memfd ? 7 : 6;
    step("fd_layout", arrange_fds(want, cx, n));
  }
  apply_rlimits(*a.policy);  // after the layout: arrange_fds parks copies at >= 100
  std::vector<char*> argv = exec_argv(a.args);
  char* envp[] = {nullptr};
  syscall(SYS_execveat, a.memfds ? 3 : n - 1, "", argv.data(), envp, AT_EMPTY_PATH);
  child_fail("execveat", errno);
}

}  // namespace

int launch_oneshot(const HelperPolicy& policy, const LaunchOptions& options) {
  const uid_t owner = launcher_owner();
  OneshotChild a{};
  a.policy = &policy;
  a.helper_fd = open_packaged(options.helper_dir, std::string(policy.helper).c_str(), owner, true);
  require_kernel_floor();  // the helper enforces both itself; refuse here before any namespace exists
  a.extra_memfd = policy.extra_fd.kind == ExtraFd::Kind::kSealedMemfd;
  a.memfds = policy.io == Io::kMemfds;
  a.args = options.argv;
  a.devnull_r = open("/dev/null", O_RDONLY | O_CLOEXEC);
  a.devnull_w = open("/dev/null", O_WRONLY | O_CLOEXEC);
  if (a.devnull_r < 0 || a.devnull_w < 0) refuse("open /dev/null: %s", errno_name(errno));
  return spawn_box(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWUTS | CLONE_NEWCGROUP,
                   child_oneshot, &a);
}

}  // namespace confine::lnx
