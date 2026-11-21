# Third-party notices

The code in this repository is MIT-licensed (`LICENSE`, Copyright (c) 2026 Tirion) unless this file says otherwise.

## Bundled third-party code and data

None. Every file in this repository was written for it.

## Dependencies (not bundled)

Dependencies are not vendored: they are fetched at build time (Rust crates from crates.io, pinned in `Cargo.lock`) under their own licences, and the gate
checks their licences (`cargo deny`, `deny.toml`). Nothing from them is redistributed in this repository.

- The launcher (`launcher/`) links [libseccomp](https://github.com/seccomp/libseccomp) (LGPL-2.1) dynamically.
