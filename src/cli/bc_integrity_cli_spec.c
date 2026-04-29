// SPDX-License-Identifier: MIT

#include "bc_integrity_cli_internal.h"

#include "bc_core.h"
#include "bc_core_io.h"
#include "bc_runtime.h"
#include "bc_runtime_cli.h"

#include <stddef.h>

#ifndef BC_INTEGRITY_VERSION_STRING
#define BC_INTEGRITY_VERSION_STRING "0.0.0-unversioned"
#endif

#define BC_INTEGRITY_CLI_STDERR_BUFFER_BYTES ((size_t)512)

static void bc_integrity_cli_spec_emit_stderr(const char *message) {
  char buffer[BC_INTEGRITY_CLI_STDERR_BUFFER_BYTES];
  bc_core_writer_t writer;
  if (!bc_core_writer_init_standard_error(&writer, buffer, sizeof(buffer))) {
    return;
  }
  (void)bc_core_writer_write_cstring(&writer, message);
  (void)bc_core_writer_destroy(&writer);
}

static void bc_integrity_cli_spec_emit_stderr_invalid(const char *option,
                                                      const char *value) {
  char buffer[BC_INTEGRITY_CLI_STDERR_BUFFER_BYTES];
  bc_core_writer_t writer;
  if (!bc_core_writer_init_standard_error(&writer, buffer, sizeof(buffer))) {
    return;
  }
  (void)bc_core_writer_write_cstring(&writer,
                                     "bc-integrity: invalid value for ");
  (void)bc_core_writer_write_cstring(&writer, option);
  (void)bc_core_writer_write_cstring(&writer, ": '");
  (void)bc_core_writer_write_cstring(&writer, value);
  (void)bc_core_writer_write_cstring(&writer, "'\n");
  (void)bc_core_writer_destroy(&writer);
}

static const char *const bc_integrity_digest_algorithm_values[] = {
    "sha256", "xxh3", "xxh128", NULL};

static const char *const bc_integrity_verify_mode_values[] = {
    "strict", "content", "meta", NULL};

static const char *const bc_integrity_output_format_values[] = {"text", "json",
                                                                NULL};

static const bc_runtime_cli_option_spec_t bc_integrity_global_options[] = {
    {
        .long_name = "threads",
        .type = BC_RUNTIME_CLI_OPTION_STRING,
        .default_value = "auto",
        .value_placeholder = "auto|auto-io|0|N",
        .help_summary = "thread mode: auto (CPU-bound), auto-io (I/O-bound), 0 "
                        "(single-thread), N (1..logical_cpu_count)",
    },
};

static const bc_runtime_cli_option_spec_t bc_integrity_manifest_options[] = {
    {
        .long_name = "output",
        .type = BC_RUNTIME_CLI_OPTION_STRING,
        .required = true,
        .value_placeholder = "PATH",
        .help_summary = "path to write the .hrbl manifest",
    },
    {
        .long_name = "digest-algorithm",
        .type = BC_RUNTIME_CLI_OPTION_ENUM,
        .allowed_values = bc_integrity_digest_algorithm_values,
        .default_value = "sha256",
        .value_placeholder = "sha256|xxh3|xxh128",
        .help_summary = "digest algorithm for file content",
    },
    {
        .long_name = "follow-symlinks",
        .type = BC_RUNTIME_CLI_OPTION_FLAG,
        .help_summary = "follow symlinks during the walk (default: capture "
                        "symlinks but do not follow)",
    },
    {
        .long_name = "include-hidden",
        .type = BC_RUNTIME_CLI_OPTION_FLAG,
        .help_summary = "include hidden files and directories (default: skip)",
    },
    {
        .long_name = "include-special",
        .type = BC_RUNTIME_CLI_OPTION_FLAG,
        .help_summary =
            "include device files, fifos, and sockets (default: skip)",
    },
    {
        .long_name = "default-exclude-virtual",
        .type = BC_RUNTIME_CLI_OPTION_BOOLEAN,
        .default_value = "true",
        .value_placeholder = "true|false",
        .help_summary =
            "exclude /proc /sys /dev /run /tmp from the walk (default: true)",
    },
    {
        .long_name = "include",
        .type = BC_RUNTIME_CLI_OPTION_LIST,
        .value_placeholder = "GLOB",
        .help_summary =
            "only include relative paths matching glob (repeatable)",
    },
    {
        .long_name = "exclude",
        .type = BC_RUNTIME_CLI_OPTION_LIST,
        .value_placeholder = "GLOB",
        .help_summary = "exclude relative paths matching glob (repeatable)",
    },
};

static const bc_runtime_cli_option_spec_t bc_integrity_verify_options[] = {
    {
        .long_name = "mode",
        .type = BC_RUNTIME_CLI_OPTION_ENUM,
        .allowed_values = bc_integrity_verify_mode_values,
        .default_value = "strict",
        .value_placeholder = "strict|content|meta",
        .help_summary = "verification mode: strict (digest+meta), content "
                        "(digest only), meta (no rehash)",
    },
    {
        .long_name = "format",
        .type = BC_RUNTIME_CLI_OPTION_ENUM,
        .allowed_values = bc_integrity_output_format_values,
        .default_value = "text",
        .value_placeholder = "text|json",
        .help_summary = "output format for change records",
    },
    {
        .long_name = "exit-on-first",
        .type = BC_RUNTIME_CLI_OPTION_FLAG,
        .help_summary = "exit immediately after the first detected change",
    },
    {
        .long_name = "follow-symlinks",
        .type = BC_RUNTIME_CLI_OPTION_FLAG,
        .help_summary = "follow symlinks during the walk (default: do not "
                        "follow)",
    },
    {
        .long_name = "include-hidden",
        .type = BC_RUNTIME_CLI_OPTION_FLAG,
        .help_summary = "include hidden files and directories (default: skip)",
    },
    {
        .long_name = "include-special",
        .type = BC_RUNTIME_CLI_OPTION_FLAG,
        .help_summary =
            "include device files, fifos, and sockets (default: skip)",
    },
    {
        .long_name = "default-exclude-virtual",
        .type = BC_RUNTIME_CLI_OPTION_BOOLEAN,
        .default_value = "true",
        .value_placeholder = "true|false",
        .help_summary =
            "exclude /proc /sys /dev /run /tmp from the walk (default: true)",
    },
    {
        .long_name = "include",
        .type = BC_RUNTIME_CLI_OPTION_LIST,
        .value_placeholder = "GLOB",
        .help_summary =
            "only include relative paths matching glob (repeatable)",
    },
    {
        .long_name = "exclude",
        .type = BC_RUNTIME_CLI_OPTION_LIST,
        .value_placeholder = "GLOB",
        .help_summary = "exclude relative paths matching glob (repeatable)",
    },
};

static const bc_runtime_cli_option_spec_t bc_integrity_diff_options[] = {
    {
        .long_name = "format",
        .type = BC_RUNTIME_CLI_OPTION_ENUM,
        .allowed_values = bc_integrity_output_format_values,
        .default_value = "text",
        .value_placeholder = "text|json",
        .help_summary = "output format for change records",
    },
    {
        .long_name = "ignore-meta",
        .type = BC_RUNTIME_CLI_OPTION_FLAG,
        .help_summary = "skip metadata-only differences (compare content only)",
    },
    {
        .long_name = "ignore-mtime",
        .type = BC_RUNTIME_CLI_OPTION_FLAG,
        .help_summary = "skip mtime differences in the comparison",
    },
};

static const bc_runtime_cli_command_spec_t bc_integrity_commands[] = {
    {
        .name = "manifest",
        .summary = "build a .hrbl manifest of a directory tree",
        .options = bc_integrity_manifest_options,
        .option_count = sizeof(bc_integrity_manifest_options) /
                        sizeof(bc_integrity_manifest_options[0]),
        .positional_usage = "<root>",
        .positional_min = 1,
        .positional_max = 1,
    },
    {
        .name = "verify",
        .summary = "verify a directory tree against a .hrbl manifest",
        .options = bc_integrity_verify_options,
        .option_count = sizeof(bc_integrity_verify_options) /
                        sizeof(bc_integrity_verify_options[0]),
        .positional_usage = "<root> <manifest.hrbl>",
        .positional_min = 2,
        .positional_max = 2,
    },
    {
        .name = "diff",
        .summary = "compare two .hrbl manifests",
        .options = bc_integrity_diff_options,
        .option_count = sizeof(bc_integrity_diff_options) /
                        sizeof(bc_integrity_diff_options[0]),
        .positional_usage = "<old.hrbl> <new.hrbl>",
        .positional_min = 2,
        .positional_max = 2,
    },
};

static const bc_runtime_cli_program_spec_t bc_integrity_program_spec_value = {
    .program_name = "bc-integrity",
    .version = BC_INTEGRITY_VERSION_STRING,
    .summary = "CLI file integrity manifest tool",
    .global_options = bc_integrity_global_options,
    .global_option_count = sizeof(bc_integrity_global_options) /
                           sizeof(bc_integrity_global_options[0]),
    .commands = bc_integrity_commands,
    .command_count =
        sizeof(bc_integrity_commands) / sizeof(bc_integrity_commands[0]),
};

const bc_runtime_cli_program_spec_t *bc_integrity_cli_program_spec(void) {
  return &bc_integrity_program_spec_value;
}

bool bc_integrity_cli_bind_manifest_options(
    const bc_runtime_config_store_t *store,
    const bc_runtime_cli_parsed_t *parsed,
    bc_integrity_manifest_options_t *out_options) {
  bc_core_zero(out_options, sizeof(*out_options));

  const char *threads_value = NULL;
  if (!bc_runtime_config_store_get_string(store, "global.threads",
                                          &threads_value)) {
    bc_integrity_cli_spec_emit_stderr(
        "bc-integrity: internal error: missing global.threads\n");
    return false;
  }
  if (!bc_integrity_cli_parse_threads(threads_value, &out_options->threads_mode,
                                      &out_options->explicit_worker_count)) {
    bc_integrity_cli_spec_emit_stderr_invalid("--threads", threads_value);
    return false;
  }

  const char *output_value = NULL;
  if (!bc_runtime_config_store_get_string(store, "manifest.output",
                                          &output_value)) {
    bc_integrity_cli_spec_emit_stderr(
        "bc-integrity: internal error: missing manifest.output\n");
    return false;
  }
  out_options->output_path = output_value;

  const char *digest_value = NULL;
  if (!bc_runtime_config_store_get_string(store, "manifest.digest-algorithm",
                                          &digest_value)) {
    bc_integrity_cli_spec_emit_stderr(
        "bc-integrity: internal error: missing manifest.digest-algorithm\n");
    return false;
  }
  if (!bc_integrity_cli_parse_digest_algorithm(
          digest_value, &out_options->digest_algorithm)) {
    bc_integrity_cli_spec_emit_stderr_invalid("--digest-algorithm",
                                              digest_value);
    return false;
  }

  bool follow_symlinks = false;
  (void)bc_runtime_config_store_get_boolean(store, "manifest.follow-symlinks",
                                            &follow_symlinks);
  out_options->follow_symlinks = follow_symlinks;

  bool include_hidden = false;
  (void)bc_runtime_config_store_get_boolean(store, "manifest.include-hidden",
                                            &include_hidden);
  out_options->include_hidden = include_hidden;

  bool include_special = false;
  (void)bc_runtime_config_store_get_boolean(store, "manifest.include-special",
                                            &include_special);
  out_options->include_special = include_special;

  bool default_exclude_virtual = true;
  (void)bc_runtime_config_store_get_boolean(
      store, "manifest.default-exclude-virtual", &default_exclude_virtual);
  out_options->default_exclude_virtual = default_exclude_virtual;

  const char *include_value = NULL;
  if (bc_runtime_config_store_get_string(store, "manifest.include",
                                         &include_value)) {
    out_options->include_list = include_value;
  }
  const char *exclude_value = NULL;
  if (bc_runtime_config_store_get_string(store, "manifest.exclude",
                                         &exclude_value)) {
    out_options->exclude_list = exclude_value;
  }

  if (parsed->positional_count != 1) {
    bc_integrity_cli_spec_emit_stderr(
        "bc-integrity: manifest requires exactly one root path\n");
    return false;
  }
  out_options->root_path = parsed->positional_values[0];
  return true;
}

bool bc_integrity_cli_bind_verify_options(
    const bc_runtime_config_store_t *store,
    const bc_runtime_cli_parsed_t *parsed,
    bc_integrity_verify_options_t *out_options) {
  bc_core_zero(out_options, sizeof(*out_options));

  const char *threads_value = NULL;
  if (!bc_runtime_config_store_get_string(store, "global.threads",
                                          &threads_value)) {
    bc_integrity_cli_spec_emit_stderr(
        "bc-integrity: internal error: missing global.threads\n");
    return false;
  }
  if (!bc_integrity_cli_parse_threads(threads_value, &out_options->threads_mode,
                                      &out_options->explicit_worker_count)) {
    bc_integrity_cli_spec_emit_stderr_invalid("--threads", threads_value);
    return false;
  }

  const char *mode_value = NULL;
  if (!bc_runtime_config_store_get_string(store, "verify.mode", &mode_value)) {
    bc_integrity_cli_spec_emit_stderr(
        "bc-integrity: internal error: missing verify.mode\n");
    return false;
  }
  if (!bc_integrity_cli_parse_verify_mode(mode_value, &out_options->mode)) {
    bc_integrity_cli_spec_emit_stderr_invalid("--mode", mode_value);
    return false;
  }

  const char *format_value = NULL;
  if (!bc_runtime_config_store_get_string(store, "verify.format",
                                          &format_value)) {
    bc_integrity_cli_spec_emit_stderr(
        "bc-integrity: internal error: missing verify.format\n");
    return false;
  }
  if (!bc_integrity_cli_parse_output_format(format_value,
                                            &out_options->format)) {
    bc_integrity_cli_spec_emit_stderr_invalid("--format", format_value);
    return false;
  }

  bool exit_on_first = false;
  (void)bc_runtime_config_store_get_boolean(store, "verify.exit-on-first",
                                            &exit_on_first);
  out_options->exit_on_first = exit_on_first;

  bool follow_symlinks = false;
  (void)bc_runtime_config_store_get_boolean(store, "verify.follow-symlinks",
                                            &follow_symlinks);
  out_options->follow_symlinks = follow_symlinks;

  bool include_hidden = false;
  (void)bc_runtime_config_store_get_boolean(store, "verify.include-hidden",
                                            &include_hidden);
  out_options->include_hidden = include_hidden;

  bool include_special = false;
  (void)bc_runtime_config_store_get_boolean(store, "verify.include-special",
                                            &include_special);
  out_options->include_special = include_special;

  bool default_exclude_virtual = true;
  (void)bc_runtime_config_store_get_boolean(
      store, "verify.default-exclude-virtual", &default_exclude_virtual);
  out_options->default_exclude_virtual = default_exclude_virtual;

  const char *include_value = NULL;
  if (bc_runtime_config_store_get_string(store, "verify.include",
                                         &include_value)) {
    out_options->include_list = include_value;
  }
  const char *exclude_value = NULL;
  if (bc_runtime_config_store_get_string(store, "verify.exclude",
                                         &exclude_value)) {
    out_options->exclude_list = exclude_value;
  }

  if (parsed->positional_count != 2) {
    bc_integrity_cli_spec_emit_stderr(
        "bc-integrity: verify requires <root> and <manifest.hrbl>\n");
    return false;
  }
  out_options->root_path = parsed->positional_values[0];
  out_options->manifest_path = parsed->positional_values[1];
  return true;
}

bool bc_integrity_cli_bind_diff_options(
    const bc_runtime_config_store_t *store,
    const bc_runtime_cli_parsed_t *parsed,
    bc_integrity_diff_options_t *out_options) {
  bc_core_zero(out_options, sizeof(*out_options));

  const char *format_value = NULL;
  if (!bc_runtime_config_store_get_string(store, "diff.format",
                                          &format_value)) {
    bc_integrity_cli_spec_emit_stderr(
        "bc-integrity: internal error: missing diff.format\n");
    return false;
  }
  if (!bc_integrity_cli_parse_output_format(format_value,
                                            &out_options->format)) {
    bc_integrity_cli_spec_emit_stderr_invalid("--format", format_value);
    return false;
  }

  bool ignore_meta = false;
  (void)bc_runtime_config_store_get_boolean(store, "diff.ignore-meta",
                                            &ignore_meta);
  out_options->ignore_meta = ignore_meta;

  bool ignore_mtime = false;
  (void)bc_runtime_config_store_get_boolean(store, "diff.ignore-mtime",
                                            &ignore_mtime);
  out_options->ignore_mtime = ignore_mtime;

  if (parsed->positional_count != 2) {
    bc_integrity_cli_spec_emit_stderr(
        "bc-integrity: diff requires <old.hrbl> and <new.hrbl>\n");
    return false;
  }
  out_options->manifest_path_a = parsed->positional_values[0];
  out_options->manifest_path_b = parsed->positional_values[1];
  return true;
}

const char *bc_integrity_cli_digest_algorithm_name(
    bc_integrity_digest_algorithm_t algorithm) {
  switch (algorithm) {
  case BC_INTEGRITY_DIGEST_ALGORITHM_XXH3:
    return "xxh3";
  case BC_INTEGRITY_DIGEST_ALGORITHM_XXH128:
    return "xxh128";
  case BC_INTEGRITY_DIGEST_ALGORITHM_SHA256:
  default:
    return "sha256";
  }
}
