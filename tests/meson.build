# SPDX-License-Identifier: MIT

cmocka_dep = dependency('cmocka')

bc_integrity_cli_test_sources = [
  '../src/cli/bc_integrity_cli_spec.c',
  '../src/cli/bc_integrity_cli_parsers.c',
]

test_bc_integrity_cli_spec_unit = executable('test_bc_integrity_cli_spec_unit',
  'test_bc_integrity_cli_spec_unit.c',
  bc_integrity_cli_test_sources,
  include_directories : [bc_integrity_internal_inc],
  dependencies : [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_runtime_dep],
  c_args : [bc_integrity_version_c_arg],
)
test('bc_integrity_cli_spec_unit', test_bc_integrity_cli_spec_unit)

test_bc_integrity_cli_parsers_unit = executable('test_bc_integrity_cli_parsers_unit',
  'test_bc_integrity_cli_parsers_unit.c',
  '../src/cli/bc_integrity_cli_parsers.c',
  include_directories : [bc_integrity_internal_inc],
  dependencies : [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_runtime_dep],
)
test('bc_integrity_cli_parsers_unit', test_bc_integrity_cli_parsers_unit)

test_bc_integrity_walk_filters_unit = executable('test_bc_integrity_walk_filters_unit',
  'test_bc_integrity_walk_filters_unit.c',
  '../src/walk/bc_integrity_walk_filters.c',
  include_directories : [bc_integrity_internal_inc],
  dependencies : [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_concurrency_dep, bc_containers_dep, bc_runtime_dep],
)
test('bc_integrity_walk_filters_unit', test_bc_integrity_walk_filters_unit)

test_bc_integrity_walk_serial_unit = executable('test_bc_integrity_walk_serial_unit',
  'test_bc_integrity_walk_serial_unit.c',
  '../src/walk/bc_integrity_walk_serial.c',
  '../src/walk/bc_integrity_walk_filters.c',
  '../src/filter/bc_integrity_filter_glob.c',
  '../src/capture/bc_integrity_capture_entry.c',
  include_directories : [bc_integrity_internal_inc],
  dependencies : [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_concurrency_dep, bc_containers_dep, bc_io_dep, bc_runtime_dep, xxhash_dep],
)
test('bc_integrity_walk_serial_unit', test_bc_integrity_walk_serial_unit)

test_bc_integrity_capture_entry_unit = executable('test_bc_integrity_capture_entry_unit',
  'test_bc_integrity_capture_entry_unit.c',
  '../src/capture/bc_integrity_capture_entry.c',
  include_directories : [bc_integrity_internal_inc],
  dependencies : [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_runtime_dep, xxhash_dep],
)
test('bc_integrity_capture_entry_unit', test_bc_integrity_capture_entry_unit)

bc_integrity_capture_hash_test_sources = [
  'test_bc_integrity_capture_hash_unit.c',
  '../src/capture/bc_integrity_capture_hash_simple.c',
]
if liburing_dep.found()
  bc_integrity_capture_hash_test_sources += '../src/capture/bc_integrity_capture_hash_batch_uring.c'
else
  bc_integrity_capture_hash_test_sources += '../src/capture/bc_integrity_capture_hash_batch_sync.c'
endif

bc_integrity_capture_hash_test_deps = [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_runtime_dep, xxhash_dep]
if liburing_dep.found()
  bc_integrity_capture_hash_test_deps += liburing_dep
endif

test_bc_integrity_capture_hash_unit = executable('test_bc_integrity_capture_hash_unit',
  bc_integrity_capture_hash_test_sources,
  include_directories : [bc_integrity_internal_inc],
  dependencies : bc_integrity_capture_hash_test_deps,
)
test('bc_integrity_capture_hash_unit', test_bc_integrity_capture_hash_unit)

bc_integrity_dispatch_test_sources = [
  'test_bc_integrity_dispatch_unit.c',
  '../src/dispatch/bc_integrity_dispatch.c',
  '../src/capture/bc_integrity_capture_entry.c',
  '../src/capture/bc_integrity_capture_hash_simple.c',
]
if liburing_dep.found()
  bc_integrity_dispatch_test_sources += '../src/capture/bc_integrity_capture_hash_batch_uring.c'
else
  bc_integrity_dispatch_test_sources += '../src/capture/bc_integrity_capture_hash_batch_sync.c'
endif

bc_integrity_dispatch_test_deps = [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_concurrency_dep, bc_containers_dep, bc_runtime_dep, xxhash_dep]
if liburing_dep.found()
  bc_integrity_dispatch_test_deps += liburing_dep
endif

test_bc_integrity_dispatch_unit = executable('test_bc_integrity_dispatch_unit',
  bc_integrity_dispatch_test_sources,
  include_directories : [bc_integrity_internal_inc],
  dependencies : bc_integrity_dispatch_test_deps,
)
test('bc_integrity_dispatch_unit', test_bc_integrity_dispatch_unit)

bc_integrity_dispatch_smallcorpus_test_sources = [
  'test_bc_integrity_dispatch_smallcorpus_unit.c',
  '../src/dispatch/bc_integrity_dispatch.c',
  '../src/capture/bc_integrity_capture_entry.c',
  '../src/capture/bc_integrity_capture_hash_simple.c',
]
if liburing_dep.found()
  bc_integrity_dispatch_smallcorpus_test_sources += '../src/capture/bc_integrity_capture_hash_batch_uring.c'
else
  bc_integrity_dispatch_smallcorpus_test_sources += '../src/capture/bc_integrity_capture_hash_batch_sync.c'
endif

test_bc_integrity_dispatch_smallcorpus_unit = executable('test_bc_integrity_dispatch_smallcorpus_unit',
  bc_integrity_dispatch_smallcorpus_test_sources,
  include_directories : [bc_integrity_internal_inc],
  dependencies : bc_integrity_dispatch_test_deps,
)
test('bc_integrity_dispatch_smallcorpus_unit', test_bc_integrity_dispatch_smallcorpus_unit, suite : 'concurrency-heavy')

test_bc_integrity_manifest_writer_unit = executable('test_bc_integrity_manifest_writer_unit',
  'test_bc_integrity_manifest_writer_unit.c',
  '../src/manifest/bc_integrity_manifest_writer.c',
  '../src/cli/bc_integrity_cli_spec.c',
  '../src/cli/bc_integrity_cli_parsers.c',
  '../src/capture/bc_integrity_capture_entry.c',
  include_directories : [bc_integrity_internal_inc],
  dependencies : [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_containers_dep, bc_runtime_dep, bc_hrbl_dep, xxhash_dep],
  c_args : [bc_integrity_version_c_arg],
)
test('bc_integrity_manifest_writer_unit', test_bc_integrity_manifest_writer_unit)

test_bc_integrity_end_to_end = executable('test_bc_integrity_end_to_end',
  'test_bc_integrity_end_to_end.c',
  dependencies : [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_hrbl_dep],
  c_args : [
    '-DBC_INTEGRITY_TEST_BINARY_PATH="' + bc_integrity_bin.full_path() + '"',
  ],
)
test('bc_integrity_end_to_end', test_bc_integrity_end_to_end, depends : [bc_integrity_bin], timeout : 120)

test_bc_integrity_filter_glob_unit = executable('test_bc_integrity_filter_glob_unit',
  'test_bc_integrity_filter_glob_unit.c',
  '../src/filter/bc_integrity_filter_glob.c',
  include_directories : [bc_integrity_internal_inc],
  dependencies : [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_runtime_dep],
)
test('bc_integrity_filter_glob_unit', test_bc_integrity_filter_glob_unit)

test_bc_integrity_verify_strict_unit = executable('test_bc_integrity_verify_strict_unit',
  'test_bc_integrity_verify_strict_unit.c',
  '../src/verify/bc_integrity_verify_strict.c',
  include_directories : [bc_integrity_internal_inc],
  dependencies : [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_runtime_dep],
)
test('bc_integrity_verify_strict_unit', test_bc_integrity_verify_strict_unit)

test_bc_integrity_verify_content_unit = executable('test_bc_integrity_verify_content_unit',
  'test_bc_integrity_verify_content_unit.c',
  '../src/verify/bc_integrity_verify_content.c',
  include_directories : [bc_integrity_internal_inc],
  dependencies : [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_runtime_dep],
)
test('bc_integrity_verify_content_unit', test_bc_integrity_verify_content_unit)

test_bc_integrity_verify_meta_unit = executable('test_bc_integrity_verify_meta_unit',
  'test_bc_integrity_verify_meta_unit.c',
  '../src/verify/bc_integrity_verify_meta.c',
  include_directories : [bc_integrity_internal_inc],
  dependencies : [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_runtime_dep],
)
test('bc_integrity_verify_meta_unit', test_bc_integrity_verify_meta_unit)

test_bc_integrity_diff_unit = executable('test_bc_integrity_diff_unit',
  'test_bc_integrity_diff_unit.c',
  '../src/diff/bc_integrity_diff.c',
  '../src/verify/bc_integrity_verify_strict.c',
  '../src/verify/bc_integrity_verify_content.c',
  '../src/verify/bc_integrity_verify_meta.c',
  '../src/verify/bc_integrity_verify_output.c',
  '../src/manifest/bc_integrity_manifest_writer.c',
  '../src/cli/bc_integrity_cli_spec.c',
  '../src/cli/bc_integrity_cli_parsers.c',
  '../src/capture/bc_integrity_capture_entry.c',
  include_directories : [bc_integrity_internal_inc],
  dependencies : [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_containers_dep, bc_runtime_dep, bc_hrbl_dep, xxhash_dep],
  c_args : [bc_integrity_version_c_arg],
)
test('bc_integrity_diff_unit', test_bc_integrity_diff_unit)

test_bc_integrity_verify_end_to_end = executable('test_bc_integrity_verify_end_to_end',
  'test_bc_integrity_verify_end_to_end.c',
  dependencies : [cmocka_dep],
  c_args : [
    '-DBC_INTEGRITY_TEST_BINARY_PATH="' + bc_integrity_bin.full_path() + '"',
  ],
)
test('bc_integrity_verify_end_to_end', test_bc_integrity_verify_end_to_end, depends : [bc_integrity_bin], timeout : 120)

test_bc_integrity_diff_end_to_end = executable('test_bc_integrity_diff_end_to_end',
  'test_bc_integrity_diff_end_to_end.c',
  dependencies : [cmocka_dep],
  c_args : [
    '-DBC_INTEGRITY_TEST_BINARY_PATH="' + bc_integrity_bin.full_path() + '"',
  ],
)
test('bc_integrity_diff_end_to_end', test_bc_integrity_diff_end_to_end, depends : [bc_integrity_bin], timeout : 120)

test_bc_integrity_smoke = find_program('sh')
test('bc_integrity_version_smoke',
  test_bc_integrity_smoke,
  args : ['-c', bc_integrity_bin.full_path() + ' --version | grep -q "^bc-integrity rolling$"'],
  depends : [bc_integrity_bin],
)

# === Coverage Agent A ===
test_bc_integrity_verify_output_extended = executable('test_bc_integrity_verify_output_extended',
  'test_bc_integrity_verify_output_extended.c',
  '../src/verify/bc_integrity_verify_output.c',
  include_directories : [bc_integrity_internal_inc],
  dependencies : [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_runtime_dep],
)
test('bc_integrity_verify_output_extended', test_bc_integrity_verify_output_extended)

test_bc_integrity_walk_parallel_extended = executable('test_bc_integrity_walk_parallel_extended',
  'test_bc_integrity_walk_parallel_extended.c',
  '../src/walk/bc_integrity_walk_parallel.c',
  '../src/walk/bc_integrity_walk_serial.c',
  '../src/walk/bc_integrity_walk_filters.c',
  '../src/filter/bc_integrity_filter_glob.c',
  '../src/capture/bc_integrity_capture_entry.c',
  include_directories : [bc_integrity_internal_inc],
  dependencies : [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_concurrency_dep, bc_containers_dep, bc_io_dep, bc_runtime_dep, xxhash_dep],
)
test('bc_integrity_walk_parallel_extended', test_bc_integrity_walk_parallel_extended, timeout : 120, suite : 'concurrency-heavy')

bc_integrity_capture_hash_uring_ext_sources = [
  'test_bc_integrity_capture_hash_uring_extended.c',
  '../src/capture/bc_integrity_capture_hash_simple.c',
]
if liburing_dep.found()
  bc_integrity_capture_hash_uring_ext_sources += '../src/capture/bc_integrity_capture_hash_batch_uring.c'
else
  bc_integrity_capture_hash_uring_ext_sources += '../src/capture/bc_integrity_capture_hash_batch_sync.c'
endif

bc_integrity_capture_hash_uring_ext_deps = [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_runtime_dep, xxhash_dep]
if liburing_dep.found()
  bc_integrity_capture_hash_uring_ext_deps += liburing_dep
endif

test_bc_integrity_capture_hash_uring_extended = executable('test_bc_integrity_capture_hash_uring_extended',
  bc_integrity_capture_hash_uring_ext_sources,
  include_directories : [bc_integrity_internal_inc],
  dependencies : bc_integrity_capture_hash_uring_ext_deps,
)
test('bc_integrity_capture_hash_uring_extended', test_bc_integrity_capture_hash_uring_extended)

# === Coverage Agent B ===
test_bc_integrity_verify_run_extended = executable('test_bc_integrity_verify_run_extended',
  'test_bc_integrity_verify_run_extended.c',
  dependencies : [cmocka_dep],
  c_args : [
    '-DBC_INTEGRITY_TEST_BINARY_PATH="' + bc_integrity_bin.full_path() + '"',
  ],
)
test('bc_integrity_verify_run_extended', test_bc_integrity_verify_run_extended, depends : [bc_integrity_bin], timeout : 180)

test_bc_integrity_diff_extended = executable('test_bc_integrity_diff_extended',
  'test_bc_integrity_diff_extended.c',
  '../src/diff/bc_integrity_diff.c',
  '../src/verify/bc_integrity_verify_strict.c',
  '../src/verify/bc_integrity_verify_content.c',
  '../src/verify/bc_integrity_verify_meta.c',
  '../src/verify/bc_integrity_verify_output.c',
  '../src/manifest/bc_integrity_manifest_writer.c',
  '../src/cli/bc_integrity_cli_spec.c',
  '../src/cli/bc_integrity_cli_parsers.c',
  '../src/capture/bc_integrity_capture_entry.c',
  include_directories : [bc_integrity_internal_inc],
  dependencies : [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_containers_dep, bc_runtime_dep, bc_hrbl_dep, xxhash_dep],
  c_args : [bc_integrity_version_c_arg],
)
test('bc_integrity_diff_extended', test_bc_integrity_diff_extended)

test_bc_integrity_manifest_writer_extended = executable('test_bc_integrity_manifest_writer_extended',
  'test_bc_integrity_manifest_writer_extended.c',
  '../src/manifest/bc_integrity_manifest_writer.c',
  '../src/cli/bc_integrity_cli_spec.c',
  '../src/cli/bc_integrity_cli_parsers.c',
  '../src/capture/bc_integrity_capture_entry.c',
  include_directories : [bc_integrity_internal_inc],
  dependencies : [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_containers_dep, bc_runtime_dep, bc_hrbl_dep, xxhash_dep],
  c_args : [bc_integrity_version_c_arg],
)
test('bc_integrity_manifest_writer_extended', test_bc_integrity_manifest_writer_extended)

# === Coverage Agent C ===
test_bc_integrity_cli_parsers_extended = executable('test_bc_integrity_cli_parsers_extended',
  'test_bc_integrity_cli_parsers_extended.c',
  '../src/cli/bc_integrity_cli_parsers.c',
  include_directories : [bc_integrity_internal_inc],
  dependencies : [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_runtime_dep],
)
test('bc_integrity_cli_parsers_extended', test_bc_integrity_cli_parsers_extended)

test_bc_integrity_walk_filters_extended = executable('test_bc_integrity_walk_filters_extended',
  'test_bc_integrity_walk_filters_extended.c',
  '../src/walk/bc_integrity_walk_filters.c',
  include_directories : [bc_integrity_internal_inc],
  dependencies : [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_concurrency_dep, bc_containers_dep, bc_runtime_dep],
)
test('bc_integrity_walk_filters_extended', test_bc_integrity_walk_filters_extended)

test_bc_integrity_filter_glob_extended = executable('test_bc_integrity_filter_glob_extended',
  'test_bc_integrity_filter_glob_extended.c',
  '../src/filter/bc_integrity_filter_glob.c',
  include_directories : [bc_integrity_internal_inc],
  dependencies : [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_runtime_dep],
)
test('bc_integrity_filter_glob_extended', test_bc_integrity_filter_glob_extended)

bc_integrity_dispatch_extended_test_sources = [
  'test_bc_integrity_dispatch_extended.c',
  '../src/dispatch/bc_integrity_dispatch.c',
  '../src/capture/bc_integrity_capture_entry.c',
  '../src/capture/bc_integrity_capture_hash_simple.c',
]
if liburing_dep.found()
  bc_integrity_dispatch_extended_test_sources += '../src/capture/bc_integrity_capture_hash_batch_uring.c'
else
  bc_integrity_dispatch_extended_test_sources += '../src/capture/bc_integrity_capture_hash_batch_sync.c'
endif

test_bc_integrity_dispatch_extended = executable('test_bc_integrity_dispatch_extended',
  bc_integrity_dispatch_extended_test_sources,
  include_directories : [bc_integrity_internal_inc],
  dependencies : bc_integrity_dispatch_test_deps,
)
test('bc_integrity_dispatch_extended', test_bc_integrity_dispatch_extended, suite : 'concurrency-heavy')

# === Coverage Agent D ===
bc_integrity_coverage_d_test_sources = [
  'test_bc_integrity_coverage_d.c',
  '../src/cli/bc_integrity_cli_spec.c',
  '../src/cli/bc_integrity_cli_parsers.c',
  '../src/capture/bc_integrity_capture_entry.c',
  '../src/walk/bc_integrity_walk_serial.c',
  '../src/walk/bc_integrity_walk_filters.c',
  '../src/filter/bc_integrity_filter_glob.c',
  '../src/manifest/bc_integrity_manifest_writer.c',
  '../src/diff/bc_integrity_diff.c',
  '../src/verify/bc_integrity_verify_strict.c',
  '../src/verify/bc_integrity_verify_content.c',
  '../src/verify/bc_integrity_verify_meta.c',
  '../src/verify/bc_integrity_verify_output.c',
]

test_bc_integrity_coverage_d = executable('test_bc_integrity_coverage_d',
  bc_integrity_coverage_d_test_sources,
  include_directories : [bc_integrity_internal_inc],
  dependencies : [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_concurrency_dep, bc_containers_dep, bc_io_dep, bc_runtime_dep, bc_hrbl_dep, xxhash_dep],
  c_args : [
    bc_integrity_version_c_arg,
    '-DBC_INTEGRITY_TEST_BINARY_PATH="' + bc_integrity_bin.full_path() + '"',
  ],
)
test('bc_integrity_coverage_d', test_bc_integrity_coverage_d, depends : [bc_integrity_bin], timeout : 240, suite : 'no-valgrind')

# === Axe C : integration tests ===
test_bc_integrity_hrbl_compat = executable('test_bc_integrity_hrbl_compat',
  'test_bc_integrity_hrbl_compat.c',
  dependencies : [cmocka_dep],
  c_args : [
    '-DBC_INTEGRITY_TEST_BINARY_PATH="' + bc_integrity_bin.full_path() + '"',
    '-DBC_HRBL_TEST_BINARY_PATH="/usr/local/bin/bc-hrbl"',
  ],
)
test('bc_integrity_hrbl_compat', test_bc_integrity_hrbl_compat, depends : [bc_integrity_bin], timeout : 120)

test_bc_integrity_reproducibility = executable('test_bc_integrity_reproducibility',
  'test_bc_integrity_reproducibility.c',
  dependencies : [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_hrbl_dep],
  c_args : [
    '-DBC_INTEGRITY_TEST_BINARY_PATH="' + bc_integrity_bin.full_path() + '"',
  ],
)
test('bc_integrity_reproducibility', test_bc_integrity_reproducibility, depends : [bc_integrity_bin], timeout : 120)

# === Axe B : smoke golden path ===
bc_integrity_smoke_script_path = meson.current_source_dir() / 'smoke' / 'smoke_golden_path.sh'

test_bc_integrity_smoke_unit = executable('test_bc_integrity_smoke_unit',
  'test_bc_integrity_smoke_unit.c',
  dependencies : [cmocka_dep],
  c_args : [
    '-DBC_INTEGRITY_TEST_BINARY_PATH="' + bc_integrity_bin.full_path() + '"',
    '-DBC_HRBL_TEST_BINARY_PATH="/usr/local/bin/bc-hrbl"',
    '-DBC_INTEGRITY_SMOKE_SCRIPT_PATH="' + bc_integrity_smoke_script_path + '"',
  ],
)
test('bc_integrity_smoke_unit', test_bc_integrity_smoke_unit, depends : [bc_integrity_bin], timeout : 120)


# === Glob cap test ===
test_bc_integrity_filter_glob_cap_unit = executable(
  'test_bc_integrity_filter_glob_cap_unit',
  'test_bc_integrity_filter_glob_cap_unit.c',
  '../src/filter/bc_integrity_filter_glob.c',
  include_directories : [bc_integrity_internal_inc],
  dependencies : [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_runtime_dep],
)
test('bc_integrity_filter_glob_cap_unit', test_bc_integrity_filter_glob_cap_unit)
