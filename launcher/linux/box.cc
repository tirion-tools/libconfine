// Building blocks shared by the Linux boxes: bind mounts into the new root, re-opened descriptors, capability
// drop, fd layout, rlimits, the clone with the caller as parent, and the dispatch of static policies.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "linux/box.h"

#include <fcntl.h>
#include <linux/capability.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "linux/util.h"

namespace confine::lnx {
namespace {

// ---------------------------------------------------------------- path helpers (new root under /tmp)

std::string normalize(const std::string& in) {
  std::vector<std::string> parts;
  size_t i = 0;
  while (i < in.size()) {
    while (i < in.size() && in[i] == '/') ++i;
    const size_t j = in.find('/', i);
    std::string s = in.substr(i, j == std::string::npos ? std::string::npos : j - i);
    i = j == std::string::npos ? in.size() : j;
    if (s.empty() || s == ".") continue;
    if (s == "..") {
      if (!parts.empty()) parts.pop_back();
      continue;
    }
    parts.push_back(std::move(s));
  }
  std::string out;
  for (const auto& p : parts) out += "/" + p;
  return out.empty() ? "/" : out;
}

// Recreates the symlink chain of `host` below `base` (so /lib64 -> usr/lib64 survives pivot_root) and
// returns the fully resolved host path in *resolved.
int materialize(const std::string& base, const std::string& host, std::string* resolved) {
  std::string rest = host;
  for (int depth = 0; depth < 40; ++depth) {
    std::string cur;
    size_t p = 0;
    bool restarted = false;
    while (p < rest.size()) {
      while (p < rest.size() && rest[p] == '/') ++p;
      if (p >= rest.size()) break;
      const size_t e = rest.find('/', p);
      const std::string comp = rest.substr(p, e == std::string::npos ? std::string::npos : e - p);
      std::string next = cur;
      next += '/';
      next += comp;
      struct stat st{};
      if (lstat(next.c_str(), &st) != 0) return errno;
      const std::string inbase = base + next;
      if (S_ISLNK(st.st_mode)) {
        char tgt[4096];
        const ssize_t l = readlink(next.c_str(), tgt, sizeof tgt - 1);
        if (l < 0) return errno;
        tgt[l] = 0;
        if (symlink(tgt, inbase.c_str()) != 0 && errno != EEXIST) return errno;
        const std::string tail = e == std::string::npos ? "" : rest.substr(e);
        std::string joined = tgt[0] == '/' ? std::string() : cur + '/';
        joined += tgt;
        joined += tail;
        rest = normalize(joined);
        restarted = true;
        break;
      }
      if (S_ISDIR(st.st_mode) && mkdir(inbase.c_str(), 0755) != 0 && errno != EEXIST) return errno;
      cur = next;
      p = e == std::string::npos ? rest.size() : e;
    }
    if (!restarted) {
      *resolved = cur.empty() ? "/" : cur;
      return 0;
    }
  }
  return ELOOP;
}

unsigned long locked_flags(const std::string& path) {
  struct statvfs v{};
  unsigned long f = 0;
  if (statvfs(path.c_str(), &v) != 0) return f;
  if ((v.f_flag & ST_NOSUID) != 0) f |= MS_NOSUID;
  if ((v.f_flag & ST_NODEV) != 0) f |= MS_NODEV;
  if ((v.f_flag & ST_NOEXEC) != 0) f |= MS_NOEXEC;
  if ((v.f_flag & ST_NOATIME) != 0) f |= MS_NOATIME;
  if ((v.f_flag & ST_NODIRATIME) != 0) f |= MS_NODIRATIME;
  if ((v.f_flag & ST_RELATIME) != 0) f |= MS_RELATIME;
  return f;
}

int write_text(const std::string& path, const std::string& text) {
  const int fd = open(path.c_str(), O_WRONLY | O_CLOEXEC);
  if (fd < 0) return errno;
  const ssize_t n = write(fd, text.data(), text.size());
  const int e = n == static_cast<ssize_t>(text.size()) ? 0 : (n < 0 ? errno : EIO);
  close(fd);
  return e;
}

}  // namespace

int mkdir_p(const std::string& path) {
  std::string cur;
  const std::string norm = normalize(path);
  size_t i = 1;
  while (i <= norm.size()) {
    const size_t j = norm.find('/', i);
    cur = norm.substr(0, j == std::string::npos ? norm.size() : j);
    if (mkdir(cur.c_str(), 0755) != 0 && errno != EEXIST) return errno;
    if (j == std::string::npos) break;
    i = j + 1;
  }
  return 0;
}

int Binder::bind(const std::string& host, const std::string& dst, bool writable, unsigned long extra, bool missing_ok) {
  const int src = open(host.c_str(), O_PATH | O_CLOEXEC);
  if (src < 0) return missing_ok && errno == ENOENT ? kBindMissing : errno;
  struct stat s{};
  fstat(src, &s);
  std::string resolved;
  int e = 0;
  if (host == dst) {
    e = materialize(base, host, &resolved);
  } else {
    resolved = normalize(dst);
    e = mkdir_p(base + resolved.substr(0, resolved.rfind('/')));
  }
  if (e != 0) {
    close(src);
    return e;
  }
  for (const auto& d : bound_dirs) {
    if (resolved.size() > d.size() && resolved.compare(0, d.size(), d) == 0 && resolved[d.size()] == '/') {
      close(src);
      return -1;
    }
  }
  const std::string target = base + resolved;
  if (S_ISDIR(s.st_mode)) {
    bound_dirs.push_back(resolved);
    if (mkdir(target.c_str(), 0755) != 0 && errno != EEXIST) e = errno;
  } else {
    const int t = open(target.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, 0644);
    if (t < 0) e = errno;
    else close(t);
  }
  const std::string srcpath = "/proc/self/fd/" + std::to_string(src);
  if (e == 0 && mount(srcpath.c_str(), target.c_str(), nullptr, MS_BIND | MS_REC, nullptr) != 0) e = errno;
  if (e == 0) {
    unsigned long fl = MS_BIND | MS_REMOUNT | MS_NOSUID | ((extra & kBindKeepDev) != 0 ? 0UL : static_cast<unsigned long>(MS_NODEV)) |
                       (extra & ~kBindKeepDev) | locked_flags(target);
    if (!writable) fl |= MS_RDONLY;
    if (mount(nullptr, target.c_str(), nullptr, fl, nullptr) != 0) e = errno;
  }
  close(src);
  return e;
}

int reopen_here(int fd, std::string* proc_path) {
  char path[4096];
  const std::string p = "/proc/self/fd/" + std::to_string(fd);
  const ssize_t n = readlink(p.c_str(), path, sizeof path - 1);
  if (n <= 0) return -errno;
  path[n] = 0;
  const int nfd = open(path, O_PATH | O_CLOEXEC | O_NOFOLLOW);
  if (nfd < 0) return -errno;
  struct stat a{};
  struct stat b{};
  if (fstat(fd, &a) != 0 || fstat(nfd, &b) != 0 || a.st_dev != b.st_dev || a.st_ino != b.st_ino) {
    close(nfd);
    return -ESTALE;
  }
  *proc_path = "/proc/self/fd/" + std::to_string(nfd);
  return nfd;
}

int landlock_abi() {
  const long v = syscall(SYS_landlock_create_ruleset, nullptr, 0, LANDLOCK_CREATE_RULESET_VERSION);
  return v < 0 ? -errno : static_cast<int>(v);
}

void require_kernel_floor() {
  const int abi = landlock_abi();
  if (abi < 6) refuse("Landlock ABI >= 6 unavailable (%d)", abi);
  uint32_t act = SECCOMP_RET_KILL_PROCESS;
  if (prctl(PR_GET_SECCOMP, 0, 0, 0, 0) < 0 || syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &act) != 0)
    refuse("seccomp-bpf unavailable");
}

// ---------------------------------------------------------------- process setup

int drop_caps() {
  for (int cap = 0; cap < 64; ++cap)
    if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0 && errno != EINVAL) return errno;
  if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0) return errno;
  __user_cap_header_struct hdr = {_LINUX_CAPABILITY_VERSION_3, 0};
  __user_cap_data_struct data[2] = {};
  return syscall(SYS_capset, &hdr, data) != 0 ? errno : 0;
}

// Moves fds to their contract positions without clobbering each other; closes everything above.
int arrange_fds(const int* want, const bool* cloexec, int n) {
  int hi[8];
  for (int i = 0; i < n; ++i) {
    hi[i] = want[i] >= 0 ? fcntl(want[i], F_DUPFD_CLOEXEC, 100) : -1;
    if (want[i] >= 0 && hi[i] < 0) return errno;
  }
  for (int i = 0; i < n; ++i)
    if (hi[i] >= 0 && dup3(hi[i], i, cloexec[i] ? O_CLOEXEC : 0) < 0) return errno;
  if (syscall(SYS_close_range, static_cast<unsigned>(n), ~0U, 0U) != 0) return errno;
  return 0;
}

std::string ns_inode(const char* ns) {
  char l[128];
  const std::string p = std::string("/proc/self/ns/") + ns;
  const ssize_t n = readlink(p.c_str(), l, sizeof l - 1);
  if (n < 0) return "0";
  l[n] = 0;
  const char* b = std::strchr(l, '[');
  const char* e = b != nullptr ? std::strchr(b, ']') : nullptr;
  return b != nullptr && e != nullptr ? std::string(b + 1, e) : "0";
}

[[noreturn]] void child_fail(const char* step, int e) {
  dprintf(kStatusFd, "F %s %s\n", step, errno_name(e));
  _exit(kExitRefused);
}

void step(const char* name, int e) {
  if (e != 0) child_fail(name, e);
}

int err(int rc) { return rc != 0 ? errno : 0; }

void make_mounts_private() {
  if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) == 0) return;
  const int e = errno;
  // With kernel.apparmor_restrict_unprivileged_userns=1 the new user namespace lands in Ubuntu's
  // unprivileged_userns profile and its first mount is refused; only an AppArmor profile for the launcher
  // (userns, sys_admin, mount), named after it, makes this work.
  if (e == EACCES)
    dprintf(2, "%s: mount in the new user namespace denied (EACCES): on an AppArmor host with "
               "kernel.apparmor_restrict_unprivileged_userns=1 the %s profile must be loaded\n",
            program_name(), program_name());
  child_fail("mount(/,MS_REC|MS_PRIVATE)", e);
}

void pivot_to_new_root(const std::string& base, unsigned long remount_flags) {
  step("chdir_newroot", err(chdir(base.c_str())));
  step("pivot_root", err(static_cast<int>(syscall(SYS_pivot_root, ".", "."))));
  step("umount_old_root", err(umount2(".", MNT_DETACH)));
  step("chdir_/", err(chdir("/")));
  step("remount_/_ro", err(mount(nullptr, "/", nullptr, MS_REMOUNT | MS_BIND | MS_RDONLY | remount_flags, nullptr)));
}

std::vector<char*> exec_argv(std::vector<std::string>& args) {
  std::vector<char*> argv;
  argv.reserve(args.size() + 1);
  for (auto& s : args) argv.push_back(s.data());
  argv.push_back(nullptr);
  return argv;
}

void apply_rlimits(const HelperPolicy& policy) {
  struct Rl {
    int res;
    bool limited;
    rlim_t value;
    const char* name;
  };
  const ResourceLimits& l = policy.limits;
  const Rl limits[] = {
      {RLIMIT_CORE, !policy.core_dumps, 0, "rlimit_core"},
      {RLIMIT_MEMLOCK, !policy.memory_lock, 0, "rlimit_memlock"},
      {RLIMIT_MSGQUEUE, !policy.message_queues, 0, "rlimit_msgqueue"},
      {RLIMIT_RTPRIO, !policy.realtime_priority, 0, "rlimit_rtprio"},
      {RLIMIT_NOFILE, l.open_files != 0, l.open_files, "rlimit_nofile"},
      {RLIMIT_AS, l.address_space != 0, l.address_space, "rlimit_as"},
      {RLIMIT_FSIZE, l.file_size != 0, l.file_size, "rlimit_fsize"},
      {RLIMIT_SIGPENDING, l.pending_signals != 0, l.pending_signals, "rlimit_sigpending"},
      {RLIMIT_CPU, l.cpu_seconds != 0, l.cpu_seconds, "rlimit_cpu"},
  };
  for (const Rl& r : limits) {
    if (!r.limited) continue;
    const rlimit v = {r.value, r.value};
    step(r.name, err(setrlimit(r.res, &v)));
  }
}

int spawn_box(unsigned long ns_flags, BoxMain child, void* ctx) {
  int syn[2];
  if (pipe2(syn, O_CLOEXEC) != 0) refuse("pipe2: %s", errno_name(errno));
  const unsigned long flags = SIGCHLD | CLONE_PARENT | ns_flags;
  const long pid = syscall(SYS_clone, flags, nullptr, nullptr, nullptr, 0);
  if (pid == 0) {
    close(syn[1]);
    prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
    char c = 0;
    step("wait_for_id_maps", read(syn[0], &c, 1) == 1 ? 0 : EIO);
    child(ctx);
    child_fail("box_main_returned", EINVAL);
  }
  if (pid < 0) refuse("cannot create sandbox namespaces: clone: %s", errno_name(errno));
  close(syn[0]);
  const std::string proc = "/proc/" + std::to_string(pid);
  const int e1 = write_text(proc + "/setgroups", "deny");
  const int e2 = write_text(proc + "/uid_map", std::to_string(getuid()) + " " + std::to_string(getuid()) + " 1");
  const int e3 = write_text(proc + "/gid_map", std::to_string(getgid()) + " " + std::to_string(getgid()) + " 1");
  const std::string line = "P " + std::to_string(pid) + "\n";
  write_all(kStatusFd, line.data(), line.size());
  if (e1 != 0 || e2 != 0 || e3 != 0) {
    kill(static_cast<pid_t>(pid), SIGKILL);  // the caller reaps it: it is the caller's child
    refuse("id maps: setgroups %s, uid_map %s, gid_map %s", errno_name(e1), errno_name(e2), errno_name(e3));
  }
  if (write(syn[1], "x", 1) != 1) {
    kill(static_cast<pid_t>(pid), SIGKILL);
    refuse("releasing the helper: %s", errno_name(errno));
  }
  return 0;
}

int launch(const HelperPolicy& policy, const LaunchOptions& options) {
  if (!policy.child_processes && !policy.descriptor_sending && !policy.runtime_libraries) {
    if (policy.network == Network::kNone && policy.filesystem.kind == Filesystem::Kind::kDirectoryNoExec &&
        policy.extra_fd.kind == ExtraFd::Kind::kDirectory)
      return launch_directory(policy, options);
    if (policy.filesystem.kind == Filesystem::Kind::kNone &&
        (policy.network == Network::kNone ? policy.extra_fd.kind == ExtraFd::Kind::kNone
                                          : policy.extra_fd.kind == ExtraFd::Kind::kSealedMemfd))
      return launch_oneshot(policy, options);
  }
  refuse("no Linux backend for this policy shape");
}

}  // namespace confine::lnx
