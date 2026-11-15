// The launcher's invocation contract (linux/backend.h): refusals, credentials, descriptors, packaged files.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dirent.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "linux/backend.h"
#include "linux/util.h"

namespace confine::lnx {
namespace {

const char* g_program = "launcher";

// "4 MiB" for whole MiB, else "<n> bytes".
std::string size_text(uint64_t n) {
  constexpr uint64_t kMiB = 1ULL << 20;
  return n % kMiB == 0 && n != 0 ? std::to_string(n / kMiB) + " MiB" : std::to_string(n) + " bytes";
}

}  // namespace

void set_program_name(const char* name) { g_program = name; }
const char* program_name() { return g_program; }

void refuse(const char* fmt, ...) {  // NOLINT(cert-dcl50-cpp): printf-checked through the format attribute
  char msg[1024];
  va_list ap;
  va_start(ap, fmt);
  std::vsnprintf(msg, sizeof msg, fmt, ap);
  va_end(ap);
  struct stat st{};
  if (fstat(kStatusFd, &st) == 0 && S_ISFIFO(st.st_mode)) {
    const std::string line = std::string("R ") + msg + "\n";
    write_all(kStatusFd, line.data(), line.size());
  }
  dprintf(2, "%s: refusing: %s\n", g_program, msg);
  _exit(kExitRefused);
}

void check_credentials() {
  if (getauxval(AT_SECURE) != 0) refuse("secure-exec (setuid/setgid/file capabilities) is not supported");
  if (getuid() != geteuid() || getgid() != getegid()) refuse("real and effective ids differ");
  if (getuid() == 0) refuse("refusing to run as root");
  __user_cap_header_struct hdr = {_LINUX_CAPABILITY_VERSION_3, 0};
  __user_cap_data_struct d[2] = {};
  if (syscall(SYS_capget, &hdr, d) != 0) refuse("capget: %s", errno_name(errno));
  if ((d[0].effective | d[1].effective | d[0].permitted | d[1].permitted) != 0)
    refuse("launched with capabilities (effective %08x%08x)", d[1].effective, d[0].effective);
  for (int cap = 0; cap <= CAP_LAST_CAP; ++cap)
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0) == 1) refuse("ambient capability %d set", cap);
  struct stat self{};
  if (stat("/proc/self/exe", &self) != 0) refuse("stat /proc/self/exe: %s", errno_name(errno));
  if ((self.st_mode & (S_ISUID | S_ISGID)) != 0) refuse("the launcher file is setuid/setgid (mode %o)", self.st_mode & 07777);
  char x[64];
  if (getxattr("/proc/self/exe", "security.capability", x, sizeof x) >= 0) refuse("the launcher file carries file capabilities");
}

void check_fds(const HelperPolicy& policy) {
  struct stat st{};
  if (fstat(kIpcFd, &st) != 0 || !S_ISSOCK(st.st_mode)) refuse("fd 3 is not a socket");
  int v = 0;
  socklen_t l = sizeof v;
  if (getsockopt(kIpcFd, SOL_SOCKET, SO_DOMAIN, &v, &l) != 0 || v != AF_UNIX) refuse("fd 3 is not AF_UNIX");
  l = sizeof v;
  if (getsockopt(kIpcFd, SOL_SOCKET, SO_TYPE, &v, &l) != 0 || v != SOCK_SEQPACKET) refuse("fd 3 is not SOCK_SEQPACKET");
  ucred cr{};
  l = sizeof cr;
  if (getsockopt(kIpcFd, SOL_SOCKET, SO_PEERCRED, &cr, &l) != 0) refuse("SO_PEERCRED: %s", errno_name(errno));
  if (cr.pid != getppid()) refuse("fd 3 was not created by the parent process (peer pid %d, parent %d)", cr.pid, getppid());
  if (cr.uid != getuid()) refuse("fd 3 peer uid %u differs from ours", cr.uid);
  if (fstat(kStatusFd, &st) != 0 || !S_ISFIFO(st.st_mode)) refuse("fd 4 is not a pipe");
  const int fl = fcntl(kStatusFd, F_GETFL);
  if (fl < 0 || (fl & O_ACCMODE) != O_WRONLY) refuse("fd 4 is not the write end of a pipe");
  for (int fd = 0; fd <= 2; ++fd)
    if (fcntl(fd, F_GETFD) < 0) refuse("fd %d is not open", fd);
  if (policy.io == Io::kMemfds) {
    // fd 0: the request, a memfd sealed WRITE|GROW|SHRINK|SEAL, read from offset 0.
    constexpr int kSeals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    if (fstat(0, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 || static_cast<uint64_t>(st.st_size) > policy.request_max)
      refuse("fd 0 (request) is not a non-empty regular file of at most %llu bytes", static_cast<unsigned long long>(policy.request_max));
    if ((fcntl(0, F_GET_SEALS) & kSeals) != kSeals) refuse("fd 0 (request) is not a sealed memfd");
    if (lseek(0, 0, SEEK_CUR) != 0) refuse("fd 0 (request) is not at offset 0");
    // fd 1: the response, an empty writable memfd the helper may grow.
    const int seals = fcntl(1, F_GET_SEALS);
    if (fstat(1, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size != 0 || seals < 0 ||
        (seals & (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_FUTURE_WRITE)) != 0)
      refuse("fd 1 (response) is not an empty, growable memfd");
    const int fl1 = fcntl(1, F_GETFL);
    if (fl1 < 0 || (fl1 & O_ACCMODE) == O_RDONLY || (fl1 & O_APPEND) != 0) refuse("fd 1 (response) is not writable");
  }
  int last = kStatusFd;
  const ExtraFd& x = policy.extra_fd;
  const std::string name(x.name);
  switch (x.kind) {
    case ExtraFd::Kind::kNone: break;
    case ExtraFd::Kind::kDirectory:
      if (fstat(kExtraFd, &st) != 0 || !S_ISDIR(st.st_mode)) refuse("fd 5 (%s) is not a directory", name.c_str());
      if (st.st_uid != getuid() || (st.st_mode & 077) != 0)
        refuse("fd 5 (%s) must be owned by uid %u with mode 0700 (mode %o)", name.c_str(), getuid(), st.st_mode & 07777);
      last = kExtraFd;
      break;
    case ExtraFd::Kind::kSealedMemfd: {
      constexpr int kSeals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
      if (fstat(kExtraFd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 || static_cast<uint64_t>(st.st_size) > x.max_bytes)
        refuse("fd 5 (%s) is not a non-empty regular file of at most %s", name.c_str(), size_text(x.max_bytes).c_str());
      if ((fcntl(kExtraFd, F_GET_SEALS) & kSeals) != kSeals) refuse("fd 5 (%s) is not a sealed memfd", name.c_str());
      last = kExtraFd;
      break;
    }
  }
  DIR* d = opendir("/proc/self/fd");
  if (d == nullptr) refuse("opendir /proc/self/fd: %s", errno_name(errno));
  const int self_fd = dirfd(d);
  for (dirent* e = readdir(d); e != nullptr; e = readdir(d)) {
    if (e->d_name[0] == '.') continue;
    const int fd = static_cast<int>(std::strtol(e->d_name, nullptr, 10));
    if (fd == self_fd) continue;
    if (fd > last) {
      closedir(d);
      refuse("unexpected open descriptor %d", fd);
    }
  }
  closedir(d);
}

int open_packaged(const std::string& dir, const char* name, uid_t owner, bool want_exec) {
  const std::string path = dir + "/" + name;
  const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) refuse("open %s: %s", path.c_str(), errno_name(errno));
  struct stat st{};
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) refuse("%s is not a regular file", path.c_str());
  if (st.st_uid != owner) refuse("%s is owned by uid %u, not by the launcher's owner %u", path.c_str(), st.st_uid, owner);
  if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) refuse("%s is group/other writable (mode %o)", path.c_str(), st.st_mode & 07777);
  if ((st.st_mode & (S_ISUID | S_ISGID)) != 0) refuse("%s is setuid/setgid", path.c_str());
  if (want_exec && (st.st_mode & S_IXUSR) == 0) refuse("%s is not executable", path.c_str());
  struct stat ds{};
  if (stat(dir.c_str(), &ds) != 0 || ds.st_uid != owner || (ds.st_mode & (S_IWGRP | S_IWOTH)) != 0)
    refuse("%s must be owned by uid %u and not group/other writable", dir.c_str(), owner);
  return fd;
}

uid_t launcher_owner() {
  struct stat self{};
  if (stat("/proc/self/exe", &self) != 0) refuse("stat /proc/self/exe: %s", errno_name(errno));
  return self.st_uid;
}

}  // namespace confine::lnx
