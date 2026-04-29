#!/bin/bash
# SPDX-License-Identifier: MIT
# Configure + build all fuzz harnesses of this project with clang + libFuzzer + ASan + UBSan.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
project="$(cd "$here/.." && pwd)"
build_dir="$project/build/fuzz"
if [[ ! -f "$build_dir/build.ninja" ]]; then
    CC=clang meson setup "$build_dir" "$project" \
        --buildtype=debug \
        -Dtests=false \
        -Dfuzzing=true \
        -Db_sanitize=address,undefined \
        -Db_lundef=false
fi
ninja -C "$build_dir"
echo
echo "fuzz binaries:"
ls -1 "$build_dir"/fuzzing/fuzz_* 2>/dev/null || echo "  (none found)"
