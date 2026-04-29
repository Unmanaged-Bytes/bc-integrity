// SPDX-License-Identifier: MIT

#ifndef BC_INTEGRITY_CLI_INTERNAL_H
#define BC_INTEGRITY_CLI_INTERNAL_H

#include "bc_runtime.h"
#include "bc_runtime_cli.h"

#include <stdbool.h>
#include <stddef.h>

typedef enum {
  BC_INTEGRITY_DIGEST_ALGORITHM_SHA256,
  BC_INTEGRITY_DIGEST_ALGORITHM_XXH3,
  BC_INTEGRITY_DIGEST_ALGORITHM_XXH128,
} bc_integrity_digest_algorithm_t;

typedef enum {
  BC_INTEGRITY_THREADS_MODE_AUTO,
  BC_INTEGRITY_THREADS_MODE_AUTO_IO,
  BC_INTEGRITY_THREADS_MODE_MONO,
  BC_INTEGRITY_THREADS_MODE_EXPLICIT,
} bc_integrity_threads_mode_t;

typedef enum {
  BC_INTEGRITY_VERIFY_MODE_STRICT,
  BC_INTEGRITY_VERIFY_MODE_CONTENT,
  BC_INTEGRITY_VERIFY_MODE_META,
} bc_integrity_verify_mode_t;

typedef enum {
  BC_INTEGRITY_OUTPUT_FORMAT_TEXT,
  BC_INTEGRITY_OUTPUT_FORMAT_JSON,
} bc_integrity_output_format_t;

typedef struct bc_integrity_manifest_options {
  const char *root_path;
  const char *output_path;
  bc_integrity_digest_algorithm_t digest_algorithm;
  bc_integrity_threads_mode_t threads_mode;
  size_t explicit_worker_count;
  bool follow_symlinks;
  bool include_hidden;
  bool include_special;
  bool default_exclude_virtual;
  bool skip_digest;
  bool defer_digest;
  const char *include_list;
  const char *exclude_list;
} bc_integrity_manifest_options_t;

typedef struct bc_integrity_verify_options {
  const char *root_path;
  const char *manifest_path;
  bc_integrity_verify_mode_t mode;
  bc_integrity_output_format_t format;
  bc_integrity_threads_mode_t threads_mode;
  size_t explicit_worker_count;
  bool exit_on_first;
  bool follow_symlinks;
  bool include_hidden;
  bool include_special;
  bool default_exclude_virtual;
  const char *include_list;
  const char *exclude_list;
} bc_integrity_verify_options_t;

typedef struct bc_integrity_diff_options {
  const char *manifest_path_a;
  const char *manifest_path_b;
  bc_integrity_output_format_t format;
  bool ignore_meta;
  bool ignore_mtime;
} bc_integrity_diff_options_t;

const bc_runtime_cli_program_spec_t *bc_integrity_cli_program_spec(void);

bool bc_integrity_cli_parse_digest_algorithm(
    const char *value, bc_integrity_digest_algorithm_t *out_algorithm);

bool bc_integrity_cli_parse_threads(const char *value,
                                    bc_integrity_threads_mode_t *out_mode,
                                    size_t *out_explicit_worker_count);

bool bc_integrity_cli_parse_verify_mode(const char *value,
                                        bc_integrity_verify_mode_t *out_mode);

bool bc_integrity_cli_parse_output_format(
    const char *value, bc_integrity_output_format_t *out_format);

bool bc_integrity_cli_bind_manifest_options(
    const bc_runtime_config_store_t *store,
    const bc_runtime_cli_parsed_t *parsed,
    bc_integrity_manifest_options_t *out_options);

bool bc_integrity_cli_bind_verify_options(
    const bc_runtime_config_store_t *store,
    const bc_runtime_cli_parsed_t *parsed,
    bc_integrity_verify_options_t *out_options);

bool bc_integrity_cli_bind_diff_options(
    const bc_runtime_config_store_t *store,
    const bc_runtime_cli_parsed_t *parsed,
    bc_integrity_diff_options_t *out_options);

const char *bc_integrity_cli_digest_algorithm_name(
    bc_integrity_digest_algorithm_t algorithm);

#endif /* BC_INTEGRITY_CLI_INTERNAL_H */
