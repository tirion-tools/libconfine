// Invocation-contract tests (linux/backend.h): each case forks a child that arranges its descriptors the
// way a caller would, then runs check_fds. A refusal is exit 78 with one "R <reason>" line on the status
// pipe; an accepted contract is exit 0 with nothing written.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>

#include "linux/backend.h"

namespace {

using confine::ExtraFd;
using confine::Filesystem;
using confine::HelperPolicy;
using confine::Io;
using confine::Network;

int g_failures = 0;

HelperPolicy channel_policy() {
  return HelperPolicy{"helper", "", Io::kChannel, 0, Network::kNone, Filesystem{Filesystem::Kind::kNone, ""},
                      ExtraFd{ExtraFd::Kind::kNone, "", 0}, false, false, false, false, false, false, false,
                      confine::ResourceLimits{}};
}

HelperPolicy memfd_policy() {
  HelperPolicy p = channel_policy();
  p.io = Io::kMemfds;
  p.request_max = 1024;
  return p;
}

[[noreturn]] void die(const char* what) {
  std::perror(what);
  _exit(99);
}

// fd `target` becomes a copy of `fd` (which is closed); never clobbers a descriptor in use below 100.
void place(int fd, int target) {
  const int high = fcntl(fd, F_DUPFD, 100);
  if (high < 0 || close(fd) != 0 || dup2(high, target) != target || close(high) != 0) die("place");
}

// A memfd holding `bytes` bytes at offset 0, sealed WRITE|GROW|SHRINK|SEAL when `sealed`.
int memfd(size_t bytes, bool sealed) {
  const int fd = memfd_create("test", MFD_ALLOW_SEALING | MFD_CLOEXEC);
  if (fd < 0) die("memfd_create");
  const std::string data(bytes, 'x');
  if (write(fd, data.data(), data.size()) != static_cast<ssize_t>(data.size()) || lseek(fd, 0, SEEK_SET) != 0)
    die("memfd write");
  if (sealed && fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) != 0) die("seal");
  return fd;
}

struct Outcome {
  int exit_code;  // -1 when killed by a signal
  std::string status_line;
};

// fd 3: a SEQPACKET socketpair end created by this (the parent) process; fd 4: the status pipe's write end;
// nothing open above fd 4. Then `arrange` adjusts that and check_fds(policy) runs.
Outcome run(const HelperPolicy& policy, void (*arrange)()) {
  int sv[2];
  int pp[2];
  if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) != 0 || pipe2(pp, O_CLOEXEC) != 0) die("setup");
  const pid_t pid = fork();
  if (pid < 0) die("fork");
  if (pid == 0) {
    close(sv[1]);
    close(pp[0]);
    place(sv[0], confine::lnx::kIpcFd);
    place(pp[1], confine::lnx::kStatusFd);
    if (close_range(5, ~0U, 0) != 0) die("close_range");
    if (arrange != nullptr) arrange();
    confine::lnx::check_fds(policy);
    _exit(0);
  }
  close(sv[0]);
  close(pp[1]);
  Outcome o{-1, {}};
  char buf[512];
  for (ssize_t n; (n = read(pp[0], buf, sizeof buf)) > 0;) o.status_line.append(buf, static_cast<size_t>(n));
  int st = 0;
  if (waitpid(pid, &st, 0) != pid) die("waitpid");
  close(sv[1]);
  close(pp[0]);
  if (WIFEXITED(st)) o.exit_code = WEXITSTATUS(st);
  return o;
}

void expect_accepted(const char* name, const HelperPolicy& policy, void (*arrange)()) {
  const Outcome o = run(policy, arrange);
  if (o.exit_code != 0 || !o.status_line.empty()) {
    std::fprintf(stderr, "FAIL %s: exit %d, status %s\n", name, o.exit_code, o.status_line.c_str());
    ++g_failures;
  } else {
    std::printf("ok   %s\n", name);
  }
}

// `reason` empty: refused without a status line (fd 4 is not a usable status pipe).
void expect_refused(const char* name, const HelperPolicy& policy, void (*arrange)(), std::string_view reason) {
  const Outcome o = run(policy, arrange);
  const std::string want = reason.empty() ? std::string() : "R " + std::string(reason);
  const bool line_ok = reason.empty() ? o.status_line.empty() : o.status_line.compare(0, want.size(), want) == 0;
  if (o.exit_code != confine::lnx::kExitRefused || !line_ok) {
    std::fprintf(stderr, "FAIL %s: exit %d, status \"%s\", want exit %d and \"%s...\"\n", name, o.exit_code,
                 o.status_line.c_str(), confine::lnx::kExitRefused, want.c_str());
    ++g_failures;
  } else {
    std::printf("ok   %s\n", name);
  }
}

void fd3_dev_null() { place(open("/dev/null", O_RDWR | O_CLOEXEC), 3); }
void fd3_stream_socket() {
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0) die("socketpair");
  place(sv[0], 3);
}
void fd3_own_socket() {  // created by the child itself, not by its parent
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) != 0) die("socketpair");
  place(sv[0], 3);
  close(sv[1]);
}
void fd4_read_end() {
  int pp[2];
  if (pipe2(pp, O_CLOEXEC) != 0) die("pipe2");
  place(pp[0], 4);
  close(pp[1]);
}
void extra_fd7() { place(open("/dev/null", O_RDONLY | O_CLOEXEC), 7); }
void memfds_ok() {
  place(memfd(16, true), 0);
  place(memfd(0, false), 1);
}
void memfds_unsealed_request() {
  place(memfd(16, false), 0);
  place(memfd(0, false), 1);
}
void memfds_oversized_request() {
  place(memfd(2048, true), 0);
  place(memfd(0, false), 1);
}
void memfds_sealed_response() {
  place(memfd(16, true), 0);
  place(memfd(0, true), 1);
}
void fd5_sealed_memfd() { place(memfd(64, true), 5); }
void fd5_big_memfd() { place(memfd(4096, true), 5); }
void fd5_open_directory() {
  char dir[] = "/tmp/confine-test-XXXXXX";
  if (mkdtemp(dir) == nullptr || chmod(dir, 0755) != 0) die("mkdtemp");
  place(open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC), 5);
  rmdir(dir);
}
void fd5_private_directory() {
  char dir[] = "/tmp/confine-test-XXXXXX";
  if (mkdtemp(dir) == nullptr) die("mkdtemp");  // mode 0700
  place(open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC), 5);
  rmdir(dir);
}

}  // namespace

int main() {
  confine::lnx::set_program_name("contract_test");
  const HelperPolicy channel = channel_policy();
  expect_accepted("channel contract", channel, nullptr);
  expect_refused("fd 3 not a socket", channel, fd3_dev_null, "fd 3 is not a socket");
  expect_refused("fd 3 a stream socket", channel, fd3_stream_socket, "fd 3 is not SOCK_SEQPACKET");
  expect_refused("fd 3 not from the parent", channel, fd3_own_socket, "fd 3 was not created by the parent process");
  expect_refused("fd 4 the read end", channel, fd4_read_end, "");
  expect_refused("unexpected fd 7", channel, extra_fd7, "unexpected open descriptor 7");

  const HelperPolicy memfds = memfd_policy();
  expect_accepted("memfd contract", memfds, memfds_ok);
  expect_refused("unsealed request", memfds, memfds_unsealed_request, "fd 0 (request) is not a sealed memfd");
  expect_refused("oversized request", memfds, memfds_oversized_request,
                 "fd 0 (request) is not a non-empty regular file of at most 1024 bytes");
  expect_refused("sealed response", memfds, memfds_sealed_response, "fd 1 (response) is not an empty, growable memfd");

  HelperPolicy sealed = channel_policy();
  sealed.extra_fd = ExtraFd{ExtraFd::Kind::kSealedMemfd, "input", 1024};
  expect_accepted("fd 5 sealed memfd", sealed, fd5_sealed_memfd);
  expect_refused("fd 5 missing", sealed, nullptr, "fd 5 (input) is not a non-empty regular file");
  expect_refused("fd 5 too large", sealed, fd5_big_memfd, "fd 5 (input) is not a non-empty regular file of at most 1024 bytes");

  HelperPolicy directory = channel_policy();
  directory.extra_fd = ExtraFd{ExtraFd::Kind::kDirectory, "data", 0};
  expect_accepted("fd 5 private directory", directory, fd5_private_directory);
  expect_refused("fd 5 directory mode 0755", directory, fd5_open_directory, "fd 5 (data) must be owned by uid");

  if (g_failures != 0) std::fprintf(stderr, "%d case(s) failed\n", g_failures);
  return g_failures == 0 ? 0 : 1;
}
