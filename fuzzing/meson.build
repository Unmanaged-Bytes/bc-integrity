# SPDX-License-Identifier: MIT

fuzzer_c_args = []
fuzzer_link_args = []
if cc.get_id() == 'clang'
  fuzzer_c_args += ['-fsanitize=fuzzer', '-DBC_FUZZ_LIBFUZZER']
  fuzzer_link_args += ['-fsanitize=fuzzer']
endif

bc_integrity_fuzz_diff_sources = [
  '../src/diff/bc_integrity_diff.c',
  '../src/verify/bc_integrity_verify_strict.c',
  '../src/verify/bc_integrity_verify_content.c',
  '../src/verify/bc_integrity_verify_meta.c',
  '../src/verify/bc_integrity_verify_output.c',
]

bc_integrity_fuzz_filter_glob_sources = [
  '../src/filter/bc_integrity_filter_glob.c',
]

bc_integrity_fuzz_cli_parsers_sources = [
  '../src/cli/bc_integrity_cli_parsers.c',
]

bc_integrity_fuzz_walk_filters_sources = [
  '../src/walk/bc_integrity_walk_filters.c',
]

bc_integrity_fuzz_capture_meta_sources = [
  '../src/capture/bc_integrity_capture_entry.c',
]

executable('fuzz_bc_integrity_manifest_reader',
  'fuzz_bc_integrity_manifest_reader.c',
  include_directories : [bc_integrity_internal_inc],
  dependencies : [bc_core_dep, bc_allocators_dep, bc_hrbl_dep],
  c_args : fuzzer_c_args,
  link_args : fuzzer_link_args,
)

executable('fuzz_bc_integrity_diff',
  ['fuzz_bc_integrity_diff.c'] + bc_integrity_fuzz_diff_sources,
  include_directories : [bc_integrity_internal_inc],
  dependencies : bc_integrity_deps + [xxhash_dep],
  c_args : fuzzer_c_args,
  link_args : fuzzer_link_args,
)

executable('fuzz_bc_integrity_filter_glob',
  ['fuzz_bc_integrity_filter_glob.c'] + bc_integrity_fuzz_filter_glob_sources,
  include_directories : [bc_integrity_internal_inc],
  dependencies : [bc_core_dep, bc_allocators_dep],
  c_args : fuzzer_c_args,
  link_args : fuzzer_link_args,
)

executable('fuzz_bc_integrity_cli_parsers',
  ['fuzz_bc_integrity_cli_parsers.c'] + bc_integrity_fuzz_cli_parsers_sources,
  include_directories : [bc_integrity_internal_inc],
  dependencies : [bc_core_dep, bc_runtime_dep],
  c_args : fuzzer_c_args,
  link_args : fuzzer_link_args,
)

executable('fuzz_bc_integrity_walk_filters',
  ['fuzz_bc_integrity_walk_filters.c'] + bc_integrity_fuzz_walk_filters_sources,
  include_directories : [bc_integrity_internal_inc],
  dependencies : [bc_core_dep, bc_allocators_dep, bc_concurrency_dep, bc_containers_dep, bc_runtime_dep],
  c_args : fuzzer_c_args,
  link_args : fuzzer_link_args,
)

executable('fuzz_bc_integrity_capture_meta',
  ['fuzz_bc_integrity_capture_meta.c'] + bc_integrity_fuzz_capture_meta_sources,
  include_directories : [bc_integrity_internal_inc],
  dependencies : [bc_core_dep, bc_allocators_dep, bc_runtime_dep, xxhash_dep],
  c_args : fuzzer_c_args,
  link_args : fuzzer_link_args,
)
