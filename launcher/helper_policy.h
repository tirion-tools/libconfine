// OS-neutral helper policy schema. A policy says what a helper may do; the OS backend (linux/) enforces
// every clause or refuses to launch. The caller owns the table of policies.
#pragma once

#include <cstdint>
#include <string_view>

namespace confine {

// What the helper may reach over the network.
enum class Network : uint8_t {
  kNone,             // no socket of its own and none passed in
  kBrokeredSockets,  // no socket/connect of its own; uses connected sockets its parent passes
};

// The only filesystem tree the helper sees besides its own binary and runtime libraries.
struct Filesystem {
  enum class Kind : uint8_t {
    kNone,
    kDirectoryNoExec,  // the directory passed as fd 5 (ExtraFd::Kind::kDirectory), read-write and noexec at `mount_point`
  };
  Kind kind;
  std::string_view mount_point;  // absolute, one component (e.g. "/data")
};

// The descriptor the parent passes as fd 5, if any; `name` appears in refusals ("fd 5 (<name>) ...").
struct ExtraFd {
  enum class Kind : uint8_t {
    kNone,
    kDirectory,    // a directory owned by the caller's uid with mode 0700
    kSealedMemfd,  // a non-empty memfd sealed WRITE|GROW|SHRINK|SEAL of at most `max_bytes`
  };
  Kind kind;
  std::string_view name;
  uint64_t max_bytes;  // kSealedMemfd
};

// How the helper talks to its parent.
// kChannel: the SEQPACKET channel at fd 3.
// kMemfds: one operation per process: fd 0 a sealed request memfd of at most `request_max` bytes, fd 1 an
// empty, unsealed response memfd, fd 2 the log; the launcher's fd 3 channel is not passed on.
enum class Io : uint8_t { kChannel, kMemfds };

// Caps on resources the helper may use (0: inherited from the parent).
struct ResourceLimits {
  uint32_t open_files;
  uint64_t address_space;  // bytes
  uint64_t file_size;      // bytes, largest file it may write
  uint32_t pending_signals;
};

struct HelperPolicy {
  std::string_view helper;       // binary name in the packaged helper directory
  std::string_view helper_mode;  // the helper's first argument for kMemfds helpers (e.g. "--mode=x")
  Io io;
  uint64_t request_max;  // kMemfds: largest request memfd (bytes)
  Network network;
  Filesystem filesystem;
  ExtraFd extra_fd;
  bool child_processes;     // fork/exec after start
  bool descriptor_sending;  // SCM_RIGHTS from the helper
  bool runtime_libraries;   // dynamically linked: needs a library manifest (linux/dynamic_box.h)
  bool core_dumps;
  bool memory_lock;
  bool message_queues;
  bool realtime_priority;
  ResourceLimits limits;
};

}  // namespace confine
