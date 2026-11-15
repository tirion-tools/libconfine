// Small helpers shared by the Linux backend's translation units.
#pragma once

#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <string>

namespace confine::lnx {

inline const char* errno_name(int e) {
  if (e == 0) return "ok";
  const char* n = strerrorname_np(e);
  return n != nullptr ? n : "errno?";
}

inline void write_all(int fd, const char* p, size_t n) {
  while (n > 0) {
    const ssize_t w = write(fd, p, n);
    if (w <= 0) {
      if (w < 0 && errno == EINTR) continue;
      return;
    }
    p += w;
    n -= static_cast<size_t>(w);
  }
}

// A packaged file below `dir` (no symlinks) that only the launcher file's owner can have replaced.
int open_packaged(const std::string& dir, const char* name, uid_t owner, bool want_exec);
uid_t launcher_owner();

}  // namespace confine::lnx
