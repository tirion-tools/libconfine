#!/usr/bin/env bash
# The local gate (run it in the pinned toolchain: tools/container.sh tools/gate.sh [JOB...]).
# Jobs, in order: fmt, clippy, test, launcher, launcher-san, audit. Exit status 1 when any job fails; a summary of
# every job is printed at the end. The crate parses no untrusted input (allowlists and policies are
# the caller's packaged data), so there is no fuzz target.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
JOBS=("$@")
[[ ${#JOBS[@]} -gt 0 ]] || JOBS=(fmt clippy test launcher launcher-san audit)

fmt() { cargo fmt --check; }
clippy() { cargo clippy --locked --all-targets -- -D warnings; }
test() { cargo test --locked; }
# The C++ launcher on its own: strict warnings as errors and the invocation-contract tests.
launcher() {
  cmake -S launcher -B build/launcher -G Ninja -DCMAKE_BUILD_TYPE=Release >/dev/null \
    && cmake --build build/launcher \
    && ctest --test-dir build/launcher --output-on-failure
}
# The same tests under ASan + UBSan (any report is fatal).
launcher-san() {
  local san=(-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
  cmake -S launcher -B build/launcher-san -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    "-DCMAKE_CXX_FLAGS=${san[*]}" "-DCMAKE_EXE_LINKER_FLAGS=${san[*]}" >/dev/null \
    && cmake --build build/launcher-san \
    && ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1 ctest --test-dir build/launcher-san --output-on-failure
}
audit() { cargo deny --locked check; }

declare -A RESULT
fail=0
for j in "${JOBS[@]}"; do
  echo "=== $j"
  start=$SECONDS
  if "$j"; then RESULT[$j]="PASS $((SECONDS - start))s"; else RESULT[$j]="FAIL $((SECONDS - start))s"; fail=1; fi
done
echo "=== summary"
for j in "${JOBS[@]}"; do echo "$j: ${RESULT[$j]}"; done
exit $fail
