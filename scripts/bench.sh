#!/bin/bash
# SPDX-License-Identifier: MIT
# Benchmark bc-integrity vs AIDE on a few local corpora.
# Output: Markdown table with median wall-time and RSS, plus ratios.
# Constraints:
#   - Reads only. Never writes outside /tmp.
#   - Uses an isolated AIDE config in /tmp; never touches /etc/aide.conf.

set -euo pipefail

BC_INTEGRITY_BIN="${BC_INTEGRITY_BIN:-/usr/local/bin/bc-integrity}"
AIDE_BIN="${AIDE_BIN:-/usr/bin/aide}"
RUNS="${BENCH_RUNS:-3}"
TMPDIR_ROOT="$(mktemp -d /tmp/bcint_bench_XXXXXX)"
trap 'rm -rf "$TMPDIR_ROOT"' EXIT

if [[ ! -x "$BC_INTEGRITY_BIN" ]]; then
  echo "error: $BC_INTEGRITY_BIN not executable" >&2
  exit 2
fi
if [[ ! -x "$AIDE_BIN" ]]; then
  echo "error: $AIDE_BIN not found, skipping" >&2
  exit 2
fi

# Default corpora (override via $BENCH_CORPORA="path1 path2 ...").
DEFAULT_CORPORA=(
  "/etc"
  "/usr/local/include"
  "/var/benchmarks/2026-04-12"
)
if [[ -n "${BENCH_CORPORA:-}" ]]; then
  read -ra CORPORA <<< "$BENCH_CORPORA"
else
  CORPORA=()
  for c in "${DEFAULT_CORPORA[@]}"; do
    if [[ -d "$c" ]]; then
      CORPORA+=("$c")
    else
      echo "info: corpus '$c' missing, skipping" >&2
    fi
  done
fi

if [[ ${#CORPORA[@]} -eq 0 ]]; then
  echo "error: no usable corpus" >&2
  exit 2
fi

# bench one (cmd...) -> emits "<wall_seconds> <rss_kbytes>" once.
bench_one() {
  local out_file="$1"
  shift
  /usr/bin/time -v -o "$out_file" "$@" >/dev/null 2>/dev/null || true
  local wall_str
  wall_str=$(grep "Elapsed (wall clock)" "$out_file" || true)
  local rss_kb
  rss_kb=$(grep "Maximum resident set size" "$out_file" | awk '{print $NF}')
  # Convert wall format "h:mm:ss" or "m:ss.cc" to seconds
  local secs
  secs=$(echo "$wall_str" | awk -F'): ' '{print $2}' | awk -F: '
    {
      if (NF == 3) { printf("%.3f\n", $1*3600 + $2*60 + $3); }
      else if (NF == 2) { printf("%.3f\n", $1*60 + $2); }
      else { printf("%.3f\n", $1); }
    }')
  echo "$secs $rss_kb"
}

median() {
  python3 -c "import sys; vals=sorted(float(x) for x in sys.argv[1:]); n=len(vals); print('%.3f' % (vals[n//2] if n%2 else (vals[n//2-1]+vals[n//2])/2))" "$@"
}

run_corpus() {
  local corpus="$1"
  local label
  label=$(echo "$corpus" | tr '/' '_' | sed 's/^_//' | cut -c1-40)
  local file_count
  file_count=$(find "$corpus" -type f 2>/dev/null | wc -l || echo 0)
  echo "## Corpus: $corpus ($file_count files)"
  echo

  local bcint_manifest="$TMPDIR_ROOT/${label}.hrbl"
  local aide_dbdir="$TMPDIR_ROOT/${label}_aide"
  mkdir -p "$aide_dbdir"
  local aide_conf="$TMPDIR_ROOT/${label}_aide.conf"
  cat > "$aide_conf" <<EOF
database_in=file:$aide_dbdir/aide.db.gz
database_out=file:$aide_dbdir/aide.db.new.gz
gzip_dbout=yes
log_level=error
report_level=changed_attributes
report_url=stdout

ContentMin = p+u+g+s+m+i+n+sha256

$corpus ContentMin
EOF

  local bcint_init=()
  local bcint_init_rss=()
  local bcint_check=()
  local bcint_check_rss=()
  local aide_init=()
  local aide_init_rss=()
  local aide_check=()
  local aide_check_rss=()

  for ((i=1; i<=RUNS; i++)); do
    rm -f "$bcint_manifest"
    local r
    r=$(bench_one "$TMPDIR_ROOT/t_bcint_init_${label}_$i" "$BC_INTEGRITY_BIN" manifest --output="$bcint_manifest" --default-exclude-virtual=false "$corpus")
    bcint_init+=("$(echo "$r" | awk '{print $1}')")
    bcint_init_rss+=("$(echo "$r" | awk '{print $2}')")

    r=$(bench_one "$TMPDIR_ROOT/t_bcint_check_${label}_$i" "$BC_INTEGRITY_BIN" verify --mode=strict --default-exclude-virtual=false "$corpus" "$bcint_manifest")
    bcint_check+=("$(echo "$r" | awk '{print $1}')")
    bcint_check_rss+=("$(echo "$r" | awk '{print $2}')")

    rm -f "$aide_dbdir/aide.db.gz" "$aide_dbdir/aide.db.new.gz"
    r=$(bench_one "$TMPDIR_ROOT/t_aide_init_${label}_$i" "$AIDE_BIN" --config="$aide_conf" --init)
    aide_init+=("$(echo "$r" | awk '{print $1}')")
    aide_init_rss+=("$(echo "$r" | awk '{print $2}')")

    cp "$aide_dbdir/aide.db.new.gz" "$aide_dbdir/aide.db.gz" 2>/dev/null || true
    r=$(bench_one "$TMPDIR_ROOT/t_aide_check_${label}_$i" "$AIDE_BIN" --config="$aide_conf" --check)
    aide_check+=("$(echo "$r" | awk '{print $1}')")
    aide_check_rss+=("$(echo "$r" | awk '{print $2}')")
  done

  local bcint_init_med=$(median "${bcint_init[@]}")
  local bcint_check_med=$(median "${bcint_check[@]}")
  local aide_init_med=$(median "${aide_init[@]}")
  local aide_check_med=$(median "${aide_check[@]}")
  local bcint_init_rss_med=$(median "${bcint_init_rss[@]}")
  local bcint_check_rss_med=$(median "${bcint_check_rss[@]}")
  local aide_init_rss_med=$(median "${aide_init_rss[@]}")
  local aide_check_rss_med=$(median "${aide_check_rss[@]}")

  local ratio_init ratio_check
  ratio_init=$(python3 -c "print('%.2f' % ($aide_init_med / $bcint_init_med))" 2>/dev/null || echo "n/a")
  ratio_check=$(python3 -c "print('%.2f' % ($aide_check_med / $bcint_check_med))" 2>/dev/null || echo "n/a")

  printf "| Phase | bc-integrity (s) | bc-integrity RSS (KB) | AIDE (s) | AIDE RSS (KB) | Speedup |\n"
  printf "|---|---|---|---|---|---|\n"
  printf "| init    | %s | %s | %s | %s | %sx |\n" "$bcint_init_med" "$bcint_init_rss_med" "$aide_init_med" "$aide_init_rss_med" "$ratio_init"
  printf "| check   | %s | %s | %s | %s | %sx |\n" "$bcint_check_med" "$bcint_check_rss_med" "$aide_check_med" "$aide_check_rss_med" "$ratio_check"
  echo
}

echo "# bc-integrity vs AIDE"
echo
echo "Host: $(uname -n)"
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "CPU: $(awk -F: '/model name/{print $2; exit}' /proc/cpuinfo | sed 's/^ //')"
echo "Runs per cell: $RUNS (median retained)"
echo "AIDE: $($AIDE_BIN --version 2>&1 | head -1)"
echo "bc-integrity: $($BC_INTEGRITY_BIN --version)"
echo

for corpus in "${CORPORA[@]}"; do
  run_corpus "$corpus"
done
