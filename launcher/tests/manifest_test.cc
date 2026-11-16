// Library-manifest tests (linux/dynamic_box.h): load_manifest's syntax and bind_manifest / manifest_landlock
// in a forked child that owns a user and mount namespace, binding into a tmpfs the way the dynamic box does.
// Kind 'o' (optional) is 'r' except that a missing host path is skipped and gets no Landlock rule.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <linux/landlock.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "linux/box.h"
#include "linux/dynamic_box.h"

namespace {

using confine::lnx::Binder;
using confine::lnx::bind_manifest;
using confine::lnx::kExitRefused;
using confine::lnx::load_manifest;
using confine::lnx::manifest_landlock;
using confine::lnx::ManifestEntry;

int g_failures = 0;
std::string g_dir;  // host fixtures: file, link (-> file), dangling (-> missing)

void check(bool ok, const char* name) {
  if (ok) {
    std::printf("ok   %s\n", name);
  } else {
    std::fprintf(stderr, "FAIL %s\n", name);
    ++g_failures;
  }
}

// Writes `text` to a memfd and parses it in a child (load_manifest refuses with exit 78).
int parse_exit(const char* text, std::vector<ManifestEntry>* out = nullptr) {
  int p[2];
  if (pipe(p) != 0) return -1;
  const pid_t pid = fork();
  if (pid == 0) {
    close(p[0]);
    const int fd = memfd_create("manifest", MFD_CLOEXEC);
    if (fd < 0 || write(fd, text, std::strlen(text)) < 0 || lseek(fd, 0, SEEK_SET) != 0) _exit(99);
    const std::vector<ManifestEntry> m = load_manifest(fd);
    for (const ManifestEntry& e : m) dprintf(p[1], "%c %s %s\n", e.kind, e.host.c_str(), e.dst.c_str());
    _exit(0);
  }
  close(p[1]);
  std::string got;
  char buf[512];
  for (ssize_t n; (n = read(p[0], buf, sizeof buf)) > 0;) got.append(buf, static_cast<size_t>(n));
  close(p[0]);
  int st = 0;
  waitpid(pid, &st, 0);
  if (out != nullptr)
    for (size_t at = 0; at < got.size();) {
      const size_t nl = got.find('\n', at);
      const std::string line = got.substr(at, nl - at);
      const size_t sp = line.find(' ', 2);
      out->push_back({line[0], line.substr(2, sp - 2), line.substr(sp + 1)});
      at = nl + 1;
    }
  return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

bool write_map(const char* path, const std::string& text) {
  const int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0) return false;
  const bool ok = write(fd, text.data(), text.size()) == static_cast<ssize_t>(text.size());
  close(fd);
  return ok;
}

// Runs `body` in a child with its own user (mapped to root) and mount namespace and a fresh tmpfs at /tmp,
// the base the dynamic box binds into. Returns the child's exit status (0: every expectation held).
int in_box(int (*body)()) {
  const pid_t pid = fork();
  if (pid == 0) {
    const uid_t uid = getuid();
    const gid_t gid = getgid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) _exit(98);
    if (!write_map("/proc/self/setgroups", "deny") || !write_map("/proc/self/uid_map", "0 " + std::to_string(uid) + " 1") ||
        !write_map("/proc/self/gid_map", "0 " + std::to_string(gid) + " 1"))
      _exit(98);
    if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0) _exit(98);
    if (mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755,size=1m") != 0) _exit(98);
    _exit(body());
  }
  int st = 0;
  waitpid(pid, &st, 0);
  return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

bool has_rule(const std::vector<std::pair<std::string, uint64_t>>& rules, const std::string& path, uint64_t access) {
  for (const auto& [p, a] : rules)
    if (p == path) return a == access;
  return false;
}

// The fixture paths, read by the bodies (set before any fork).
std::string g_file, g_link, g_dangling, g_missing;

int missing_optional() {
  Binder b{.base = "/tmp", .bound_dirs = {}};
  std::vector<ManifestEntry> m = {{'o', g_missing, g_missing}, {'r', g_file, g_file}};
  int err = 0;
  if (bind_manifest(b, m, &err) != -1) return 1;
  if (m[0].bound || !m[1].bound) return 2;
  struct stat st{};
  if (lstat(("/tmp" + g_missing).c_str(), &st) == 0) return 3;  // nothing created for it
  const auto rules = manifest_landlock(m);
  if (rules.size() != 1 || !has_rule(rules, g_file, LANDLOCK_ACCESS_FS_READ_FILE)) return 4;
  return 0;
}

int present_optional() {
  Binder b{.base = "/tmp", .bound_dirs = {}};
  std::vector<ManifestEntry> m = {{'o', g_file, g_file}};
  int err = 0;
  if (bind_manifest(b, m, &err) != -1 || !m[0].bound) return 1;
  const std::string in = "/tmp" + g_file;
  char buf[16] = {};
  const int fd = open(in.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0 || read(fd, buf, sizeof buf - 1) != 7 || std::strcmp(buf, "fixture") != 0) return 2;
  close(fd);
  if (open(in.c_str(), O_WRONLY | O_CLOEXEC) >= 0 || errno != EROFS) return 3;  // read-only bind
  if (!has_rule(manifest_landlock(m), g_file, LANDLOCK_ACCESS_FS_READ_FILE)) return 4;
  return 0;
}

int missing_required(char kind) {
  Binder b{.base = "/tmp", .bound_dirs = {}};
  std::vector<ManifestEntry> m = {{'r', g_file, g_file}, {kind, g_missing, g_missing}};
  int err = 0;
  return bind_manifest(b, m, &err) == 1 && err == ENOENT && !m[1].bound ? 0 : 1;
}
int missing_r() { return missing_required('r'); }
int missing_x() { return missing_required('x'); }
int missing_d() { return missing_required('d'); }

// A symlink entry: 'o' and 'r' give the same box (the link materialized, its target bound read-only).
int symlink_kind(char kind) {
  Binder b{.base = "/tmp", .bound_dirs = {}};
  std::vector<ManifestEntry> m = {{kind, g_link, g_link}};
  int err = 0;
  if (bind_manifest(b, m, &err) != -1 || !m[0].bound) return 1;
  struct stat st{};
  if (lstat(("/tmp" + g_link).c_str(), &st) != 0 || !S_ISLNK(st.st_mode)) return 2;
  if (stat(("/tmp" + g_file).c_str(), &st) != 0 || !S_ISREG(st.st_mode)) return 3;
  if (open(("/tmp" + g_link).c_str(), O_WRONLY | O_CLOEXEC) >= 0 || errno != EROFS) return 4;
  return 0;
}
int symlink_o() { return symlink_kind('o'); }
int symlink_r() { return symlink_kind('r'); }

// A dangling symlink is a missing host path: skipped for 'o', ENOENT for 'r'; nothing reaches the box for 'o'.
int dangling_o() {
  Binder b{.base = "/tmp", .bound_dirs = {}};
  std::vector<ManifestEntry> m = {{'o', g_dangling, g_dangling}};
  int err = 0;
  struct stat st{};
  return bind_manifest(b, m, &err) == -1 && !m[0].bound && lstat(("/tmp" + g_dangling).c_str(), &st) != 0 &&
                 manifest_landlock(m).empty()
             ? 0
             : 1;
}
int dangling_r() {
  Binder b{.base = "/tmp", .bound_dirs = {}};
  std::vector<ManifestEntry> m = {{'r', g_dangling, g_dangling}};
  int err = 0;
  return bind_manifest(b, m, &err) == 0 && err == ENOENT ? 0 : 1;
}

// A directory given as 'o': bound like 'r' would bind it (read-only, Landlock read-file only, no directory listing).
int directory_o() {
  Binder b{.base = "/tmp", .bound_dirs = {}};
  std::vector<ManifestEntry> m = {{'o', g_dir, g_dir}};
  int err = 0;
  if (bind_manifest(b, m, &err) != -1 || !m[0].bound) return 1;
  if (!has_rule(manifest_landlock(m), g_dir, LANDLOCK_ACCESS_FS_READ_FILE)) return 2;
  if (open(("/tmp" + g_dir + "/new").c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, 0644) >= 0 || errno != EROFS) return 3;
  return 0;
}

}  // namespace

int main() {
  confine::lnx::set_program_name("manifest_test");
  char tmpl[] = "/var/tmp/manifest_test.XXXXXX";  // not under /tmp, which the boxes replace
  if (mkdtemp(tmpl) == nullptr) {
    std::perror("mkdtemp");
    return 99;
  }
  g_dir = tmpl;
  g_file = g_dir + "/file";
  g_link = g_dir + "/link";
  g_dangling = g_dir + "/dangling";
  g_missing = g_dir + "/missing";
  const int fd = open(g_file.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
  if (fd < 0 || write(fd, "fixture", 7) != 7 || close(fd) != 0 || symlink("file", g_link.c_str()) != 0 ||
      symlink("missing", g_dangling.c_str()) != 0) {
    std::perror("fixtures");
    return 99;
  }

  std::vector<ManifestEntry> parsed;
  check(parse_exit("r /a\no /etc/localtime\nd /b /c\nx /lib64/ld\n", &parsed) == 0 && parsed.size() == 4 &&
            parsed[1].kind == 'o' && parsed[1].host == "/etc/localtime" && parsed[1].dst == "/etc/localtime",
        "manifest accepts kind o");
  check(parse_exit("q /a\n") == kExitRefused, "manifest refuses an unknown kind");
  check(parse_exit("o etc/localtime\n") == kExitRefused, "manifest refuses a relative o entry");
  check(parse_exit("o /etc/../etc/shadow\n") == kExitRefused, "manifest refuses an o entry with '..'");
  check(parse_exit("o /etc/localtime ../x\n") == kExitRefused, "manifest refuses a relative o destination");

  if (in_box(present_optional) == 98) {
    std::fprintf(stderr, "FAIL no unprivileged user namespace here (the box needs one)\n");
    return 1;
  }
  check(in_box(missing_optional) == 0, "missing o skipped: nothing created, no Landlock rule");
  check(in_box(present_optional) == 0, "present o bound read-only, unwritable, Landlock read-file");
  check(in_box(missing_r) == 0, "missing r refuses (ENOENT)");
  check(in_box(missing_x) == 0, "missing x refuses (ENOENT)");
  check(in_box(missing_d) == 0, "missing d refuses (ENOENT)");
  check(in_box(symlink_o) == 0 && in_box(symlink_r) == 0, "symlink o bound exactly like r");
  check(in_box(dangling_o) == 0, "dangling symlink o skipped");
  check(in_box(dangling_r) == 0, "dangling symlink r refuses");
  check(in_box(directory_o) == 0, "directory o bound read-only like r");

  unlink(g_dangling.c_str());
  unlink(g_link.c_str());
  unlink(g_file.c_str());
  rmdir(g_dir.c_str());
  if (g_failures != 0) std::fprintf(stderr, "%d case(s) failed\n", g_failures);
  return g_failures == 0 ? 0 : 1;
}
