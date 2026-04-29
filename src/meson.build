# SPDX-License-Identifier: MIT

bc_integrity_sources = [
  'bc_integrity_main.c',
  'cli/bc_integrity_cli_spec.c',
  'cli/bc_integrity_cli_parsers.c',
  'walk/bc_integrity_walk_parallel.c',
  'walk/bc_integrity_walk_serial.c',
  'walk/bc_integrity_walk_filters.c',
  'capture/bc_integrity_capture_entry.c',
  'capture/bc_integrity_capture_hash_simple.c',
  'dispatch/bc_integrity_dispatch.c',
  'filter/bc_integrity_filter_glob.c',
  'manifest/bc_integrity_manifest_writer.c',
  'verify/bc_integrity_verify_strict.c',
  'verify/bc_integrity_verify_content.c',
  'verify/bc_integrity_verify_meta.c',
  'verify/bc_integrity_verify_output.c',
  'verify/bc_integrity_verify_run.c',
  'diff/bc_integrity_diff.c',
]

bc_integrity_sources += 'capture/bc_integrity_capture_hash_batch_uring.c'

bc_integrity_version_c_arg = '-DBC_INTEGRITY_VERSION_STRING="@0@"'.format(meson.project_version())

bc_integrity_bin = executable('bc-integrity',
  bc_integrity_sources,
  include_directories : [bc_integrity_internal_inc],
  dependencies : bc_integrity_deps + [xxhash_dep],
  c_args : lto_c_args + [bc_integrity_version_c_arg],
  link_args : lto_link_args,
  install : true,
)
