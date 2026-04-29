#!/bin/bash
# SPDX-License-Identifier: MIT
# Run a fuzz target.
# Usage: ./run.sh <target-suffix> [max-total-time-secs] [extra libfuzzer args...]
set -euo pipefail
if [[ $# -lt 1 ]]; then
    echo "usage: $0 <target-name> [max-time-secs] [extra libfuzzer args]" >&2
    echo "available targets:" >&2
    here_tmp="$(cd "$(dirname "$0")" && pwd)"
    project_tmp="$(cd "$here_tmp/.." && pwd)"
    ls -1 "$project_tmp/build/fuzz/fuzzing/fuzz_"* 2>/dev/null | xargs -I{} basename {} | sed 's/^fuzz_//' | sed 's/^/  /' >&2
    exit 2
fi
target="$1"; shift
max_time="${1:-300}"; [[ $# -gt 0 ]] && shift
here="$(cd "$(dirname "$0")" && pwd)"
project="$(cd "$here/.." && pwd)"
binary="$project/build/fuzz/fuzzing/fuzz_$target"
if [[ ! -x "$binary" ]]; then
    echo "error: $binary not built; run ./build.sh first" >&2
    exit 1
fi
corpus="$here/corpus/$target"
crashes="$here/crashes/$target"
mkdir -p "$corpus" "$crashes"
echo "target   : fuzz_$target"
echo "corpus   : $corpus"
echo "crashes  : $crashes"
echo "max time : ${max_time}s"
echo
exec "$binary" \
    -max_total_time="$max_time" \
    -artifact_prefix="$crashes/" \
    "$@" \
    "$corpus"
