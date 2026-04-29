# bc-integrity

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Language: C11](https://img.shields.io/badge/language-C11-informational)
![Platform: Linux](https://img.shields.io/badge/platform-Linux-lightgrey)

> System change detector for filesystem trees. Captures content digest
> **and** metadata (mode, uid, gid, mtime, link target, ino, nlink) into
> a binary `.hrbl` manifest. Verifies a tree against a manifest, or diffs
> two manifests over time. CLI-first, parallel, SIMD-accelerated.

## What it does

`bc-integrity` snapshots a directory tree into a binary manifest, then
detects any subsequent change — whether **content** (different digest) or
**system** (chmod, chown, falsified mtime, redirected symlink, hard-link
substitution). Use cases: Linux system integrity monitoring (`/etc`,
`/usr/local/bin`, `/storage/backups`), lightweight intrusion detection,
configuration drift audit.

Three subcommands:

```
bc-integrity manifest <root> --output=<file.hrbl>
bc-integrity verify   <root> <file.hrbl> [--mode=strict|content|meta]
bc-integrity diff     <a.hrbl> <b.hrbl>
```

The `.hrbl` manifest is inspectable via `bc-hrbl inspect <file>` (one-way
JSON export for debugging).

### Path semantics

Entries are keyed by **path relative to the root** (e.g. for
`bc-integrity manifest /etc`, the entry for `/etc/sudoers` is keyed
`sudoers`, not `/etc/sudoers`). The absolute root is captured once in
`meta.root_path` for traceability. This makes manifests **portable**:
the same manifest can verify a tree mounted at a different absolute
path (e.g. compare a baseline taken on a server against a snapshot
mounted on another host).

The **root directory itself is not tracked as an entry**. Files and
subdirectories under the root are tracked, but a metadata change on
the root dir (e.g. its own mtime ticking when a file is added inside)
is not reported. If you need that, scan one level above
(`bc-integrity manifest /` instead of `bc-integrity manifest /etc`)
and rely on `--include`/`--exclude` to scope.

## Performance — vs AIDE 0.19.1

Median of `perf stat -r 5` runs on ws-desktop-00 (AMD Ryzen 7 5700G,
16 threads, 32 GB), Debian 13. `drop_caches` between cold runs. AIDE
ruleset matched to bc-integrity scope: `p+u+g+s+m+i+n+sha256`.

### Manifest creation (init)

| Corpus | Files | Size | bc-integrity | AIDE | **Speedup** |
|---|---:|---:|---:|---:|---:|
| `/etc` | 1 604 | 14 MB | 30 ms | 70 ms | **2.35×** |
| `/usr/local/include` | 45 | 224 KB | 3.8 ms | 4.9 ms | **1.30×** |
| `/usr/share/doc` | 14 007 | 320 MB | 299 ms | 612 ms | **2.05×** |
| benchmark mixed | 7 092 | 82 MB | 101 ms | 210 ms | **2.08×** |
| benchmark source code | 18 064 | 531 MB | 280 ms | 889 ms | **3.18×** |
| benchmark large files | 3 000 × 1 MB | 3 GB | 384 ms | 2002 ms | **5.22×** |
| `/var/benchmarks` (full) | 1 072 096 | 22 GB | 1.84 s | 76.76 s | **41.7×** |

### Verify

| Corpus | bc-integrity | AIDE | **Speedup** |
|---|---:|---:|---:|
| `/etc` | 25 ms | 60 ms | **2.40×** |
| `/usr/local/include` | 3.7 ms | 4.9 ms | **1.32×** |
| `/usr/share/doc` | 260 ms | 583 ms | **2.24×** |
| benchmark mixed | 92 ms | 198 ms | **2.15×** |
| benchmark source code | 287 ms | 863 ms | **3.01×** |
| benchmark large files | 384 ms | 1992 ms | **5.18×** |

**Reading**: bc-integrity wins across the entire corpus range, including
on small trees. On `/etc` (1.6k files), the lazy walk avoids the parallel
thread-pool overhead and matches single-threaded performance, then
crosses 2× as soon as the manifest writer kicks in. On real-world trees
(>5k files or >100 MB) the speedup ranges from 2× to 5× over AIDE; on a
1M-file / 22 GB tree it reaches **40×+**. The walk uses a budget-bounded
serial probe (`max(workers × 256, 4096)` entries) and only escalates to
the parallel walk if the corpus is large enough to amortize the overhead.

## Strengths

- **Multi-threaded**: parallel walk + `io_uring` batched read for large
  files (≥ 1 MiB). AIDE is single-threaded.
- **mmap-able binary format**: the `.hrbl` manifest is read zero-copy via
  `bc_hrbl_reader`, queryable by path without parsing the whole file.
- **Explicit metadata**: captures `mode`, `uid`, `gid`, `mtime_sec`,
  `mtime_nsec`, `ino`, `nlink`, `link_target`, `kind`. A `chmod 4755` is
  detected even when content is unchanged.
- **Three verify modes**:
  - `strict` (default) — digest + metadata
  - `content` — digest only
  - `meta` — metadata only, no rehash (very fast)
- **Structured JSON output** (NDJSON `header`/`change`/`summary`) aligned
  with the `bc-hash` schema — easy to script.
- **Safe defaults**: symlinks captured but not followed, special files
  (devices/fifos/sockets) skipped, hidden files/dirs skipped, virtual
  filesystems (`/proc`, `/sys`, `/dev`, `/run`, `/tmp`) skipped. All
  opt-in via flags.
- **Fuzz harnesses**: 2 libFuzzer harnesses on the manifest reader and
  diff, validated at 2M+ and 16k iterations with no crash.
- **Full pipeline**: 4 sanitizers (asan/tsan/ubsan/memcheck) + cppcheck
  cross-arch (Zen 3 + Tiger Lake) on every commit.
- **External scheduling**: no daemon, no in-process scheduler. Drive
  periodic scans from any external scheduler of your choice.

## Weaknesses / known limits

- **Very small corpora**: gain shrinks below 1.5× when the corpus is so
  small (<50 files) that filesystem cache effects dominate any wall-time
  difference. The lazy serial walk keeps bc-integrity competitive with
  AIDE down to `/usr/local/include`-sized trees.
- **Larger manifest format than AIDE on small corpora** (3.4× larger
  uncompressed on 7k files). At scale the trend reverses — on 1M files
  the `.hrbl` is 200 MB raw / 29 MB gzipped vs AIDE's 223 MB raw / 38 MB
  gzipped (bc-integrity ~24% smaller compressed). Format is mmap-able and
  queryable by path; external `gzip` works if needed.
- **Lower IPC than AIDE** (0.85 vs 1.65) — AIDE is more cycle-efficient
  per-instruction (assembly nettle SHA256). bc-integrity compensates
  with parallelism.
- **No cryptographic manifest signing** (could be added later if needed).
- **Linux only** (uses `getdents64`, `fadvise`, `io_uring`).
- **No incremental update mode** — a fresh manifest is regenerated on
  each scan.
- **Permission-denied entries** — files or directories the scanning user
  cannot read are recorded in the manifest with `ok=false` and `errno` /
  `error_message` populated, but **no digest** is computed. The walk
  continues, the scan does not abort. A short notice is emitted on
  stderr per affected path. To capture integrity of files restricted to
  root, run `bc-integrity` as root (e.g. via the system scheduler).
  Subsequent `verify` correctly reports the entry as `ok=false` again
  if the permission state is unchanged, or as a meta change if it was
  unblocked since the manifest was taken.
- **Manifest write failure on very large + deep trees** — on corpora
  combining ≳700k entries with very deep nesting (>50 directory levels),
  `bc-integrity manifest` may fail at the final write step with
  `failed to finalize manifest to file`. The scan completes (capture
  succeeds), only the serialization to the `.hrbl` buffer fails. Cause
  is in the underlying `bc-hrbl` library, under investigation in that
  repository. Workaround: scope the scan with `--exclude` to reduce
  either entry count or depth. Smaller subtrees serialize without
  issue (319k entries / 5.4 GB observed working).
- **Glob pattern complexity cap** — the `--include` / `--exclude` glob
  matcher refuses patterns with more than 4 `**` segments and returns
  no match. This guards against pathological backtracking found by
  fuzzing on adversarial inputs (a pattern like `**/**/**/**/**/x`
  against a long path could take seconds in the worst case). Real-world
  patterns (`**/*.c`, `build/**`, `src/**/test_*.c`) use 1-2 `**` and
  are unaffected.

## Quick start

```bash
# 1. Create a baseline manifest
bc-integrity manifest /etc --output=/var/lib/bc-integrity/etc.hrbl

# 2. Verify the tree against the manifest (digest + metadata)
bc-integrity verify /etc /var/lib/bc-integrity/etc.hrbl
echo $?  # 0 = identical, 1 = differences detected

# 3. Diff two manifests across time
bc-integrity diff manifest_yesterday.hrbl manifest_today.hrbl

# 4. Inspect manifest as JSON for debugging
bc-hrbl inspect /var/lib/bc-integrity/etc.hrbl | jq .
```

## Dependencies

bc-integrity is built on the [`bc-*`](https://github.com/Unmanaged-Bytes)
ecosystem. All `bc-*` libraries are linked via `pkg-config` after install:

| Library | Role | Repository |
|---|---|---|
| `bc-core` | SIMD-accelerated primitives (hash, copy, find, format, sort, writers) | [Unmanaged-Bytes/bc-core](https://github.com/Unmanaged-Bytes/bc-core) |
| `bc-allocators` | Pool / arena / typed-array allocators | [Unmanaged-Bytes/bc-allocators](https://github.com/Unmanaged-Bytes/bc-allocators) |
| `bc-containers` | Vector / map / ring / set, AVX-2 / AVX-512 dispatch | [Unmanaged-Bytes/bc-containers](https://github.com/Unmanaged-Bytes/bc-containers) |
| `bc-concurrency` | Lock-free MPMC queue (Vyukov), per-worker slots, parallel-for | [Unmanaged-Bytes/bc-concurrency](https://github.com/Unmanaged-Bytes/bc-concurrency) |
| `bc-io` | `getdents64` walk, parallel directory iteration, mmap, file open | [Unmanaged-Bytes/bc-io](https://github.com/Unmanaged-Bytes/bc-io) |
| `bc-runtime` | CLI parser, error collector, application lifecycle | [Unmanaged-Bytes/bc-runtime](https://github.com/Unmanaged-Bytes/bc-runtime) |
| `bc-hrbl` | Hash-Routed Binary Layout (manifest format reader / writer / verify) | [Unmanaged-Bytes/bc-hrbl](https://github.com/Unmanaged-Bytes/bc-hrbl) |

External (system):

| Package | Role | Required |
|---|---|---|
| `liburing` (≥ 2.0) | io_uring batched read for large file digests | required |
| `meson` (≥ 1.0) + `ninja` | Build system | required |
| `cmocka` | Unit tests | required to run tests |
| `valgrind` | memcheck sanitizer | optional |

## Build

```bash
# Build + install
meson setup build/release --buildtype=release
meson compile -C build/release
sudo meson install -C build/release    # /usr/local/bin/bc-integrity

# Tests
meson test -C build/release

# Sanitizers (asan/tsan/ubsan)
meson setup build/asan --buildtype=debug -Db_sanitize=address
meson compile -C build/asan
meson test -C build/asan
```

## License

MIT — see [LICENSE](LICENSE).
