// The box for dynamically linked helpers (linux/dynamic_box.h).
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "linux/dynamic_box.h"

#include <fcntl.h>
#include <linux/landlock.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "linux/box.h"
#include "linux/util.h"

namespace confine::lnx {
namespace {

bool in(std::span<const char* const> list, std::string_view name) {
  for (std::string_view n : list)
    if (n == name) return true;
  return false;
}

// ---------------------------------------------------------------- Landlock (box paths, after pivot_root)

constexpr uint64_t kLlRead = LANDLOCK_ACCESS_FS_READ_FILE;
constexpr uint64_t kLlReadDir = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;

int ll_path(int rs, const char* path, uint64_t access) {
  const int fd = open(path, O_PATH | O_CLOEXEC);
  if (fd < 0) return errno;
  struct stat st{};
  fstat(fd, &st);
  if (!S_ISDIR(st.st_mode))
    access &= LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_TRUNCATE |
              LANDLOCK_ACCESS_FS_IOCTL_DEV;
  landlock_path_beneath_attr pb = {access, fd};
  const int e = syscall(SYS_landlock_add_rule, rs, LANDLOCK_RULE_PATH_BENEATH, &pb, 0) != 0 ? errno : 0;
  close(fd);
  return e;
}

// Every ABI-6 right handled; rules for the manifest, the dynamic loader, /proc, the two devices, the passed
// files, the directory and the caller's extra paths.
int apply_landlock(const DynamicBox& box, const std::string& ld_path, const std::string& directory) {
  if (landlock_abi() < 6) return EOPNOTSUPP;
  landlock_ruleset_attr attr{};
  attr.handled_access_fs = (LANDLOCK_ACCESS_FS_IOCTL_DEV << 1) - 1;
  attr.handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP;  // and no port rule at all
  attr.scoped = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL;
  const int rs = static_cast<int>(syscall(SYS_landlock_create_ruleset, &attr, sizeof attr, 0));
  if (rs < 0) return errno;
  int err = 0;
  for (const auto& [path, access] : manifest_landlock(box.manifest)) err |= ll_path(rs, path.c_str(), access);
  if (!ld_path.empty()) err |= ll_path(rs, ld_path.c_str(), kLlRead | LANDLOCK_ACCESS_FS_EXECUTE);
  err |= ll_path(rs, "/proc", kLlReadDir);
  err |= ll_path(rs, "/dev/null", kLlRead | LANDLOCK_ACCESS_FS_WRITE_FILE);
  err |= ll_path(rs, "/dev/urandom", kLlRead);
  for (const PassedFile& f : box.files)
    if (f.landlock != 0) err |= ll_path(rs, f.dst.c_str(), f.landlock);
  if (!directory.empty()) err |= ll_path(rs, directory.c_str(), box.directory_landlock);
  for (const auto& [path, access] : box.landlock) err |= ll_path(rs, path.c_str(), access);
  const int e = syscall(SYS_landlock_restrict_self, rs, 0) != 0 ? errno : 0;
  close(rs);
  return e != 0 ? e : (err != 0 ? EINVAL : 0);
}

// ---------------------------------------------------------------- the box

struct Child {
  const HelperPolicy* policy;
  DynamicBox* box;
  std::string directory;  // the mount point, or empty
  int devnull_r;
};

void child_dynamic(void* ctx) {
  Child& a = *static_cast<Child*>(ctx);
  DynamicBox& box = *a.box;
  const bool memfds = a.policy->io == Io::kMemfds;
  make_mounts_private();
  // Re-open the passed paths in this mount namespace before the new root hides /tmp (a directory may live there).
  std::vector<std::string> file_paths(box.files.size());
  for (size_t i = 0; i < box.files.size(); ++i) {
    const int rf = reopen_here(box.files[i].fd, &file_paths[i]);
    step(("reopen_" + box.files[i].label).c_str(), rf < 0 ? -rf : 0);
  }
  std::string directory_path;
  if (!a.directory.empty()) {
    const int rf = reopen_here(kExtraFd, &directory_path);
    step(("reopen_" + a.directory.substr(1)).c_str(), rf < 0 ? -rf : 0);
  }
  Binder b{.base = "/tmp", .bound_dirs = {}};
  step("tmpfs_newroot", err(mount("tmpfs", b.base.c_str(), "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755,size=4m")));
  int bind_err = 0;
  if (const int i = bind_manifest(b, box.manifest, &bind_err); i >= 0) {
    dprintf(kStatusFd, "F bind_manifest_entry:%s %s\n", box.manifest[i].host.c_str(), errno_name(bind_err));
    _exit(kExitRefused);
  }
  std::string ld;
  for (const ManifestEntry& e : box.manifest)
    if (e.kind == 'x') ld = e.dst;
  for (size_t i = 0; i < box.files.size(); ++i) {
    const int r = b.bind(file_paths[i], box.files[i].dst, false, 0);
    step(("bind_ro_" + box.files[i].dst).c_str(), r > 0 ? r : 0);
  }
  if (!a.directory.empty()) {
    const int r = b.bind(directory_path, a.directory, true, MS_NOEXEC);
    step(("bind_rw_noexec_" + a.directory).c_str(), r > 0 ? r : 0);
  }
  int r = b.bind("/dev/null", "/dev/null", true, MS_NOEXEC | kBindKeepDev);
  step("bind_/dev/null", r > 0 ? r : 0);
  r = b.bind("/dev/urandom", "/dev/urandom", false, MS_NOEXEC | kBindKeepDev);
  step("bind_/dev/urandom", r > 0 ? r : 0);
  for (const std::string& d : box.empty_dirs) step(("mkdir_" + d).c_str(), mkdir_p(b.base + d));
  step("mkdir_/proc", mkdir_p(b.base + "/proc"));
  step("mount_proc", err(mount("proc", (b.base + "/proc").c_str(), "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr)));
  pivot_to_new_root(b.base, MS_NOSUID | MS_NODEV);
  step("capdrop", drop_caps());
  step("no_new_privs", err(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)));
  step("landlock", apply_landlock(box, ld, a.directory));
  if (memfds) {
    // 0 the sealed request, 1 the response memfd, 2 the log, 4 status; no channel.
    const int want[5] = {0, 1, 2, -1, kStatusFd};
    const bool cx[5] = {false, false, false, false, true};
    step("fd_layout", arrange_fds(want, cx, 5));
    step("close_channel", err(close(kIpcFd)));
  } else {
    // 0 /dev/null, 1 and 2 the log, 3 IPC, 4 status (CLOEXEC: EOF = exec'd); nothing else.
    const int want[5] = {a.devnull_r, 2, 2, kIpcFd, kStatusFd};
    const bool cx[5] = {false, false, false, false, true};
    step("fd_layout", arrange_fds(want, cx, 5));
  }
  apply_rlimits(*a.policy);
  const int rc = seccomp_load(box.seccomp);
  step("seccomp_load", rc != 0 ? -rc : 0);
  std::vector<char*> argv = exec_argv(box.argv);
  std::vector<char*> envp = exec_argv(box.env);
  execve(box.exec_path.c_str(), argv.data(), envp.data());
  child_fail("execve", errno);
}

}  // namespace

int bind_manifest(Binder& b, std::vector<ManifestEntry>& manifest, int* err) {
  for (size_t i = 0; i < manifest.size(); ++i) {
    ManifestEntry& e = manifest[i];
    const int r = b.bind(e.host, e.dst, false, 0, e.kind == 'o');
    if (r == kBindMissing) continue;
    if (r > 0) {
      *err = r;
      return static_cast<int>(i);
    }
    e.bound = true;
  }
  return -1;
}

std::vector<std::pair<std::string, uint64_t>> manifest_landlock(const std::vector<ManifestEntry>& manifest) {
  std::vector<std::pair<std::string, uint64_t>> out;
  for (const ManifestEntry& e : manifest) {
    if (e.kind == 'o' && !e.bound) continue;
    out.emplace_back(e.dst, e.kind == 'd' ? kLlReadDir : e.kind == 'x' ? (kLlRead | LANDLOCK_ACCESS_FS_EXECUTE) : kLlRead);
  }
  return out;
}

std::vector<ManifestEntry> load_manifest(int fd) {
  FILE* f = fdopen(fd, "r");
  if (f == nullptr) refuse("manifest: %s", errno_name(errno));
  std::vector<ManifestEntry> out;
  char line[8300];
  while (std::fgets(line, sizeof line, f) != nullptr) {
    if (char* nl = std::strchr(line, '\n'); nl != nullptr) *nl = 0;
    if (line[0] == 0 || line[0] == '#') continue;
    if (std::strlen(line) < 3 || line[1] != ' ' || std::strchr("rdxo", line[0]) == nullptr) refuse("manifest line malformed: %s", line);
    char* host = line + 2;
    char* dst = std::strchr(host, ' ');
    if (dst != nullptr) *dst++ = 0;
    if (host[0] != '/' || (dst != nullptr && dst[0] != '/')) refuse("manifest entry is not absolute: %s", host);
    if (std::strstr(host, "/../") != nullptr || (dst != nullptr && std::strstr(dst, "/../") != nullptr)) refuse("manifest entry has '..': %s", host);
    out.push_back({line[0], host, dst != nullptr ? dst : host});
  }
  std::fclose(f);
  if (out.empty()) refuse("manifest is empty");
  return out;
}

scmp_filter_ctx build_seccomp(int allow_fd, const SeccompFile& spec) {
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
  if (ctx == nullptr) refuse("seccomp_init failed");
  bool fail = seccomp_attr_set(ctx, SCMP_FLTATR_ACT_BADARCH, SCMP_ACT_KILL_PROCESS) != 0;
  FILE* f = fdopen(allow_fd, "r");
  if (f == nullptr) refuse("seccomp allowlist: %s", errno_name(errno));
  char line[256];
  int allowed = 0;
  while (std::fgets(line, sizeof line, f) != nullptr) {
    for (char* c = line; *c != 0; ++c) {
      if (*c == '\n' || *c == '#' || *c == ' ' || *c == '\t') {
        *c = 0;
        break;
      }
    }
    if (line[0] == 0) continue;
    if (in(spec.deny, line)) refuse("seccomp allowlist names the denied syscall %s", line);
    const int nr = seccomp_syscall_resolve_name(line);
    if (nr == __NR_SCMP_ERROR) refuse("seccomp allowlist names unknown syscall %s", line);
    if (in(spec.arg_filtered, line)) continue;
    fail |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 0) != 0;
    ++allowed;
  }
  std::fclose(f);
  if (allowed == 0) refuse("seccomp allowlist is empty");
  SeccompRules rules(ctx);
  spec.rules(rules);
  for (const char* name : spec.deny) {
    const int nr = seccomp_syscall_resolve_name(name);
    if (nr == __NR_SCMP_ERROR) continue;
    rules.add(SCMP_ACT_ERRNO(EPERM), nr, 0);
  }
  if (fail || rules.failed()) refuse("seccomp policy build failed");
  return ctx;
}

int launch_dynamic(const HelperPolicy& policy, DynamicBox& box) {
  const bool directory = policy.network == Network::kBrokeredSockets && policy.filesystem.kind == Filesystem::Kind::kDirectoryNoExec &&
                         policy.extra_fd.kind == ExtraFd::Kind::kDirectory;
  const bool memfds = policy.io == Io::kMemfds && policy.network == Network::kNone &&
                      policy.filesystem.kind == Filesystem::Kind::kNone && policy.extra_fd.kind == ExtraFd::Kind::kNone;
  if (policy.child_processes || policy.descriptor_sending || !policy.runtime_libraries || !(directory || memfds))
    refuse("no Linux backend for this policy shape");
  const std::string_view mp = policy.filesystem.mount_point;
  if (directory && (mp.size() < 2 || mp[0] != '/' || mp.find('/', 1) != std::string_view::npos))
    refuse("mount point '%.*s' is not one absolute component", static_cast<int>(mp.size()), mp.data());
  Child a{};
  a.policy = &policy;
  a.box = &box;
  if (directory) a.directory = mp;
  a.devnull_r = open("/dev/null", O_RDONLY | O_CLOEXEC);
  if (a.devnull_r < 0) refuse("open /dev/null: %s", errno_name(errno));
  return spawn_box(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWNET, child_dynamic, &a);
}

}  // namespace confine::lnx
