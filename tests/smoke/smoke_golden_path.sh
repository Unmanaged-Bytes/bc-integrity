#!/bin/bash
# SPDX-License-Identifier: MIT
set -euo pipefail

BCINT="${BCINT:-/usr/local/bin/bc-integrity}"
BCHRBL="${BCHRBL:-/usr/local/bin/bc-hrbl}"

if [ ! -x "$BCINT" ]; then
  echo "FAIL: bc-integrity binary not found at $BCINT" >&2
  exit 2
fi
if [ ! -x "$BCHRBL" ]; then
  echo "FAIL: bc-hrbl binary not found at $BCHRBL" >&2
  exit 2
fi

TMP=$(mktemp -d /tmp/bcint-smoke-XXXXXX)
trap 'rm -rf "$TMP"' EXIT

# 1. Build a fixture tree (mix of files, dir, symlink, hidden, special perms)
mkdir -p "$TMP/fixture/sub" "$TMP/fixture/.hidden_dir"
echo "alpha" > "$TMP/fixture/file_a.txt"
echo "beta" > "$TMP/fixture/sub/file_b.txt"
echo "gamma" > "$TMP/fixture/.hidden_dir/file_h.txt"
ln -s "file_a.txt" "$TMP/fixture/lnk"
chmod 0644 "$TMP/fixture/file_a.txt"
chmod 0644 "$TMP/fixture/sub/file_b.txt"
touch -d "2024-01-01" "$TMP/fixture/file_a.txt"
touch -d "2024-01-02" "$TMP/fixture/sub/file_b.txt"

# 2. Manifest baseline
"$BCINT" manifest --output="$TMP/m1.hrbl" "$TMP/fixture"
test -s "$TMP/m1.hrbl" || { echo "FAIL: m1.hrbl is empty" >&2; exit 1; }

# Validate hrbl format via bc-hrbl verify
"$BCHRBL" verify "$TMP/m1.hrbl" >/dev/null

# 3. Verify identical (exit 0)
"$BCINT" verify "$TMP/fixture" "$TMP/m1.hrbl"

# 4. Modify the tree (3 changes: content, mode, symlink target) + 1 add
echo "alpha-modified" > "$TMP/fixture/file_a.txt"
chmod 0600 "$TMP/fixture/sub/file_b.txt"
rm "$TMP/fixture/lnk" && ln -s "sub/file_b.txt" "$TMP/fixture/lnk"
echo "delta" > "$TMP/fixture/new_file.txt"

# 5. Verify detects (exit 1)
set +e
OUT_VERIFY=$("$BCINT" verify "$TMP/fixture" "$TMP/m1.hrbl")
EC_VERIFY=$?
set -e
test "$EC_VERIFY" = "1" || { echo "FAIL: verify expected exit 1, got $EC_VERIFY" >&2; exit 1; }

echo "$OUT_VERIFY" | grep -q "~\* file_a.txt" || { echo "FAIL: missing content+meta change for file_a.txt" >&2; echo "$OUT_VERIFY" >&2; exit 1; }
echo "$OUT_VERIFY" | grep -q "~m sub/file_b.txt mode" || { echo "FAIL: missing mode change for sub/file_b.txt" >&2; echo "$OUT_VERIFY" >&2; exit 1; }
echo "$OUT_VERIFY" | grep -q "~m lnk" || { echo "FAIL: missing meta change for lnk" >&2; echo "$OUT_VERIFY" >&2; exit 1; }
echo "$OUT_VERIFY" | grep -q "+ new_file.txt" || { echo "FAIL: missing add for new_file.txt" >&2; echo "$OUT_VERIFY" >&2; exit 1; }

# 6. JSON output parses (header + summary lines)
set +e
"$BCINT" verify --format=json "$TMP/fixture" "$TMP/m1.hrbl" > "$TMP/verify.ndjson"
EC_VJSON=$?
set -e
test "$EC_VJSON" = "1" || { echo "FAIL: verify json expected exit 1, got $EC_VJSON" >&2; exit 1; }
test -s "$TMP/verify.ndjson"
grep -q '"type":"header"' "$TMP/verify.ndjson" || { echo "FAIL: missing JSON header" >&2; cat "$TMP/verify.ndjson" >&2; exit 1; }
grep -q '"type":"summary"' "$TMP/verify.ndjson" || { echo "FAIL: missing JSON summary" >&2; cat "$TMP/verify.ndjson" >&2; exit 1; }

# 7. Diff between 2 manifests (m1 vs m2)
"$BCINT" manifest --output="$TMP/m2.hrbl" "$TMP/fixture"
set +e
OUT_DIFF=$("$BCINT" diff "$TMP/m1.hrbl" "$TMP/m2.hrbl")
EC_DIFF=$?
set -e
test "$EC_DIFF" = "1" || { echo "FAIL: diff expected exit 1, got $EC_DIFF" >&2; exit 1; }
echo "$OUT_DIFF" | grep -q "file_a.txt" || { echo "FAIL: diff missing file_a.txt" >&2; echo "$OUT_DIFF" >&2; exit 1; }
echo "$OUT_DIFF" | grep -q "+ new_file.txt" || { echo "FAIL: diff missing add for new_file.txt" >&2; echo "$OUT_DIFF" >&2; exit 1; }

# 8. Diff identical (m2 vs m2 -> exit 0)
"$BCINT" diff "$TMP/m2.hrbl" "$TMP/m2.hrbl"

# 9. Verify mode=meta (skip rehash, still detects mode change)
set +e
"$BCINT" verify --mode=meta "$TMP/fixture" "$TMP/m1.hrbl" > "$TMP/verify_meta.txt"
EC=$?
set -e
test "$EC" = "1" || { echo "FAIL: verify mode=meta expected exit 1, got $EC" >&2; cat "$TMP/verify_meta.txt" >&2; exit 1; }
grep -q "sub/file_b.txt mode" "$TMP/verify_meta.txt" || { echo "FAIL: mode=meta missing mode change for sub/file_b.txt" >&2; cat "$TMP/verify_meta.txt" >&2; exit 1; }

# 10. Verify mode=content (only digest)
set +e
"$BCINT" verify --mode=content "$TMP/fixture" "$TMP/m1.hrbl" > "$TMP/verify_content.txt"
EC=$?
set -e
test "$EC" = "1" || { echo "FAIL: verify mode=content expected exit 1, got $EC" >&2; cat "$TMP/verify_content.txt" >&2; exit 1; }
grep -E -q "~c file_a.txt|~\* file_a.txt" "$TMP/verify_content.txt" || { echo "FAIL: mode=content missing content change for file_a.txt" >&2; cat "$TMP/verify_content.txt" >&2; exit 1; }

# 11. Glob include filter keeps only *.txt entries
"$BCINT" manifest --include='*.txt' --output="$TMP/m_filtered.hrbl" "$TMP/fixture"
INSPECT_FILTERED=$("$BCHRBL" inspect "$TMP/m_filtered.hrbl")
echo "$INSPECT_FILTERED" | grep -q "file_a.txt" || { echo "FAIL: include filter dropped file_a.txt" >&2; exit 1; }
if echo "$INSPECT_FILTERED" | grep -q '"lnk":'; then
  echo "FAIL: include='*.txt' should not include 'lnk' entry" >&2
  exit 1
fi

# 12. Threads=0 (mono-thread mode) produces same digest as auto
"$BCINT" --threads=0 manifest --output="$TMP/m_mono.hrbl" "$TMP/fixture"
DIGEST_MONO=$("$BCHRBL" query "$TMP/m_mono.hrbl" "entries.'file_a.txt'.digest_hex")
DIGEST_AUTO=$("$BCHRBL" query "$TMP/m2.hrbl" "entries.'file_a.txt'.digest_hex")
test "$DIGEST_MONO" = "$DIGEST_AUTO" || { echo "FAIL: digest mono ($DIGEST_MONO) != auto ($DIGEST_AUTO)" >&2; exit 1; }

echo "smoke_golden_path: PASS"
exit 0
