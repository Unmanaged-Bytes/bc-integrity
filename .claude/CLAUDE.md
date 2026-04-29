# bc-integrity — project context

CLI file integrity manifest tool. Captures content digest plus filesystem
metadata (mode, uid, gid, mtime, ino, nlink, link_target) into a binary
`.hrbl` manifest. Verifies trees against a manifest and diffs two
manifests over time.

Consumer of the modern `bc-*` stack: bc-core, bc-allocators, bc-containers,
bc-concurrency, bc-io, bc-runtime, bc-hrbl. External runtime dependency:
`liburing` (>= 2.5) — required for batched io_uring file reads in the
hashing phase.

## Status

v0.1 functional. Three subcommands shipped:

- `manifest <root> --output=<out.hrbl>` — adaptive walk (serial probe
  with budget `max(workers × 256, 4096)` entries, escalates to parallel
  beyond) + capture meta + digest (sha256 / xxh3 / xxh128) + manifest
  write. Flags: `--threads`, `--digest-algorithm`, `--follow-symlinks`
  (off), `--include-hidden` (off), `--include-special` (off),
  `--default-exclude-virtual` (on), `--include=<glob>`, `--exclude=<glob>`.
- `verify <root> <manifest.hrbl>` — `--mode=strict|content|meta`,
  `--format=text|json`, `--exit-on-first`, `--threads`. Exit 0 identical,
  1 differences, 2 system error.
- `diff <m1.hrbl> <m2.hrbl>` — `--format=text|json`, `--ignore-meta`,
  `--ignore-mtime`. Exit 0 identical, 1 different.

Performance vs AIDE 0.19.1: 2.35× /etc, 3.18× source-code 18k files,
**41.7× init / 18.34× check on 1M files / 22 GB**.

## Path semantics

Entries are keyed **relative to the root**. The absolute root is captured
in `meta.root_path`. The root directory itself is **not** tracked as an
entry — only files and subdirectories under it are. A metadata change on
the root dir (e.g. its mtime updating when a file is added inside) is
not reported.

## Invariants (do not break)

- **No comments in `.c` files** — code names itself. Public / internal
  `.h` may carry one-line contracts if the signature is insufficient.
- **No defensive null-checks at function entry.** Return `false` /
  `0` / NULL on legitimate failure; never assert in production paths.
- **SPDX-License-Identifier: MIT** header on every `.c` and `.h`.
- **Strict C11** with `-Wall -Wextra -Wpedantic -Werror -pedantic
  -Wconversion -Wshadow -Wformat=2`.
- **Sanitizers (asan/tsan/ubsan/memcheck) stay green** in CI. **TSAN is
  load-bearing** — the manifest path dispatches parallel hashing.
- **cppcheck stays clean**; never edit `cppcheck-suppressions.txt` to
  hide real findings.
- **Manifest format is bc-hrbl `.hrbl`** — no ad-hoc text format. Use
  `bc-hrbl inspect` for human-readable JSON export.
- **Graceful signal handling** — SIGINT / SIGTERM propagate through walk
  and dispatch, exit code 130.
- **liburing is required** (no fallback) — `BC_INTEGRITY_HAVE_IO_URING`
  is always defined.

## Test coverage

84.7% line coverage (2946/3475 lines) over 209 cmocka tests. Modules at
≥ 95%: cli_parsers, verify_meta, verify_content, verify_output,
walk_filters, verify_strict. The uncovered ~15% are predominantly
defensive `return false` paths after `bc-*` library failures (OOM,
stderr-fd closed) and rare kernel paths (DT_UNKNOWN, EINTR retry,
io_uring queue setup failures) — non-testable without fault injection.

## Known issue

`bc_hrbl_writer_finalize_to_file` reportedly fails on the full 1M-file
manifest at the very end of the write phase. The walk and capture
complete successfully; the failure is at finalize. Pre-existing, not
caused by Wave E2/F. To investigate when revisiting bc-hrbl.
