// SPDX-License-Identifier: MIT

#include "bc_integrity_capture_internal.h"
#include "bc_integrity_cli_internal.h"
#include "bc_integrity_diff_internal.h"
#include "bc_integrity_dispatch_internal.h"
#include "bc_integrity_entry_internal.h"
#include "bc_integrity_manifest_internal.h"
#include "bc_integrity_verify_internal.h"
#include "bc_integrity_walk_internal.h"

#include "bc_allocators.h"
#include "bc_concurrency.h"
#include "bc_runtime_signal.h"
#include "bc_containers_vector.h"
#include "bc_core.h"
#include "bc_core_io.h"
#include "bc_runtime.h"
#include "bc_runtime_cli.h"
#include "bc_runtime_error_collector.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define BC_INTEGRITY_EX_USAGE 64
#define BC_INTEGRITY_STDERR_BUFFER_BYTES ((size_t)512)
#define BC_INTEGRITY_ENTRY_INITIAL_CAPACITY 1024
#define BC_INTEGRITY_ENTRY_MAX_CAPACITY (1ULL << 28)
#define BC_INTEGRITY_HOST_BUFFER_BYTES 256

typedef struct bc_integrity_application_state {
  const bc_runtime_cli_parsed_t *parsed;
  bc_integrity_manifest_options_t manifest_options;
  bc_integrity_verify_options_t verify_options;
  bc_integrity_diff_options_t diff_options;
  bc_containers_vector_t *entries;
  bc_runtime_error_collector_t *errors;
  char canonical_root_buffer[PATH_MAX];
  size_t canonical_root_length;
  char host_buffer[BC_INTEGRITY_HOST_BUFFER_BYTES];
  int exit_code;
} bc_integrity_application_state_t;

static void bc_integrity_emit_stderr(const char *message) {
  char buffer[BC_INTEGRITY_STDERR_BUFFER_BYTES];
  bc_core_writer_t writer;
  if (!bc_core_writer_init_standard_error(&writer, buffer, sizeof(buffer))) {
    return;
  }
  (void)bc_core_writer_write_cstring(&writer, message);
  (void)bc_core_writer_destroy(&writer);
}

static void bc_integrity_emit_stderr_quoted_path(const char *prefix,
                                                 const char *path,
                                                 const char *suffix) {
  char buffer[BC_INTEGRITY_STDERR_BUFFER_BYTES];
  bc_core_writer_t writer;
  if (!bc_core_writer_init_standard_error(&writer, buffer, sizeof(buffer))) {
    return;
  }
  (void)bc_core_writer_write_cstring(&writer, prefix);
  (void)bc_core_writer_write_cstring(&writer, path);
  (void)bc_core_writer_write_cstring(&writer, suffix);
  (void)bc_core_writer_destroy(&writer);
}

static uint64_t bc_integrity_realtime_unix_seconds(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_REALTIME, &now) != 0) {
    return 0;
  }
  return (uint64_t)now.tv_sec;
}

static uint64_t bc_integrity_monotonic_milliseconds(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
    return 0;
  }
  return (uint64_t)now.tv_sec * 1000u + (uint64_t)(now.tv_nsec / 1000000);
}

static bool bc_integrity_command_name_equal(const char *command_name,
                                            const char *expected,
                                            size_t expected_length) {
  if (command_name == NULL) {
    return false;
  }
  size_t actual_length = 0;
  (void)bc_core_length(command_name, '\0', &actual_length);
  if (actual_length != expected_length) {
    return false;
  }
  bool equal = false;
  (void)bc_core_equal(command_name, expected, expected_length, &equal);
  return equal;
}

static bool bc_integrity_application_is_manifest(
    const bc_integrity_application_state_t *state) {
  if (state->parsed == NULL || state->parsed->command == NULL) {
    return false;
  }
  return bc_integrity_command_name_equal(state->parsed->command->name,
                                         "manifest", 8);
}

static bool bc_integrity_application_is_verify(
    const bc_integrity_application_state_t *state) {
  if (state->parsed == NULL || state->parsed->command == NULL) {
    return false;
  }
  return bc_integrity_command_name_equal(state->parsed->command->name, "verify",
                                         6);
}

static bool bc_integrity_application_is_diff(
    const bc_integrity_application_state_t *state) {
  if (state->parsed == NULL || state->parsed->command == NULL) {
    return false;
  }
  return bc_integrity_command_name_equal(state->parsed->command->name, "diff",
                                         4);
}

static bool bc_integrity_resolve_canonical_root(const char *input_path,
                                                char *output_buffer,
                                                size_t output_capacity,
                                                size_t *out_length) {
  char tmp[PATH_MAX];
  if (realpath(input_path, tmp) == NULL) {
    return false;
  }
  size_t length = 0;
  (void)bc_core_length(tmp, '\0', &length);
  while (length > 1 && tmp[length - 1] == '/') {
    length -= 1;
  }
  if (length + 1 > output_capacity) {
    return false;
  }
  bc_core_copy(output_buffer, tmp, length);
  output_buffer[length] = '\0';
  *out_length = length;
  return true;
}

static bool bc_integrity_application_init(const bc_runtime_t *application,
                                          void *user_data) {
  bc_integrity_application_state_t *state =
      (bc_integrity_application_state_t *)user_data;

  bc_allocators_context_t *memory_context = NULL;
  if (!bc_runtime_memory_context(application, &memory_context)) {
    state->exit_code = 1;
    return false;
  }

  if (!bc_runtime_error_collector_create(memory_context, &state->errors)) {
    state->exit_code = 1;
    return false;
  }

  if (!bc_integrity_application_is_manifest(state)) {
    return true;
  }

  if (!bc_containers_vector_create(memory_context, sizeof(bc_integrity_entry_t),
                                   BC_INTEGRITY_ENTRY_INITIAL_CAPACITY,
                                   BC_INTEGRITY_ENTRY_MAX_CAPACITY,
                                   &state->entries)) {
    state->exit_code = 1;
    return false;
  }

  if (gethostname(state->host_buffer, sizeof(state->host_buffer)) != 0) {
    state->host_buffer[0] = '\0';
  } else {
    state->host_buffer[sizeof(state->host_buffer) - 1] = '\0';
  }

  return true;
}

static bool bc_integrity_run_manifest(const bc_runtime_t *application,
                                      bc_integrity_application_state_t *state) {
  bc_allocators_context_t *memory_context = NULL;
  if (!bc_runtime_memory_context(application, &memory_context)) {
    state->exit_code = 1;
    return false;
  }
  bc_concurrency_context_t *concurrency_context = NULL;
  if (!bc_runtime_parallel_context(application, &concurrency_context)) {
    state->exit_code = 1;
    return false;
  }
  bc_runtime_signal_handler_t *signal_handler = NULL;
  bc_runtime_signal_handler(application, &signal_handler);

  if (!bc_integrity_resolve_canonical_root(state->manifest_options.root_path,
                                           state->canonical_root_buffer,
                                           sizeof(state->canonical_root_buffer),
                                           &state->canonical_root_length)) {
    bc_integrity_emit_stderr_quoted_path(
        "bc-integrity: cannot resolve root path '",
        state->manifest_options.root_path, "'\n");
    state->exit_code = 1;
    return false;
  }

  struct stat root_stat;
  if (stat(state->canonical_root_buffer, &root_stat) != 0) {
    bc_integrity_emit_stderr_quoted_path("bc-integrity: cannot stat root '",
                                         state->canonical_root_buffer, "'\n");
    state->exit_code = 1;
    return false;
  }
  if (!S_ISDIR(root_stat.st_mode)) {
    bc_integrity_emit_stderr_quoted_path(
        "bc-integrity: root must be a directory: '",
        state->canonical_root_buffer, "'\n");
    state->exit_code = 1;
    return false;
  }

  uint64_t started_at_unix_sec = bc_integrity_realtime_unix_seconds();
  uint64_t started_monotonic_ms = bc_integrity_monotonic_milliseconds();

  state->manifest_options.defer_digest = !state->manifest_options.skip_digest;

  bool walk_ok = bc_integrity_walk_run(
      memory_context, concurrency_context, signal_handler,
      &state->manifest_options, state->canonical_root_buffer,
      state->canonical_root_length, state->entries, state->errors);

  bool interrupted = false;
  bc_runtime_should_stop(application, &interrupted);
  if (interrupted) {
    bc_integrity_emit_stderr("bc-integrity: interrupted by signal, aborting "
                             "before manifest write\n");
    state->exit_code = 130;
    return false;
  }

  if (!walk_ok) {
    bc_runtime_error_collector_flush_to_stderr(state->errors, "bc-integrity");
    state->exit_code = 1;
    return false;
  }

  if (state->manifest_options.defer_digest) {
    if (!bc_integrity_dispatch_compute_digests(
            memory_context, concurrency_context, signal_handler,
            state->manifest_options.digest_algorithm, state->entries)) {
      bc_runtime_error_collector_flush_to_stderr(state->errors, "bc-integrity");
      state->exit_code = 1;
      return false;
    }
    bc_runtime_should_stop(application, &interrupted);
    if (interrupted) {
      bc_integrity_emit_stderr("bc-integrity: interrupted by signal, aborting "
                               "before manifest write\n");
      state->exit_code = 130;
      return false;
    }
  }

  uint64_t completed_at_unix_sec = bc_integrity_realtime_unix_seconds();
  uint64_t walltime_ms =
      bc_integrity_monotonic_milliseconds() - started_monotonic_ms;

  bc_integrity_manifest_summary_t summary;
  bc_core_zero(&summary, sizeof(summary));
  summary.created_at_unix_sec = started_at_unix_sec;
  summary.completed_at_unix_sec = completed_at_unix_sec;
  summary.walltime_ms = walltime_ms;
  summary.host = state->host_buffer;
  summary.root_path_absolute = state->canonical_root_buffer;

  size_t entry_count = bc_containers_vector_length(state->entries);
  for (size_t entry_index = 0; entry_index < entry_count; ++entry_index) {
    bc_integrity_entry_t entry;
    if (!bc_containers_vector_get(state->entries, entry_index, &entry)) {
      continue;
    }
    switch (entry.kind) {
    case BC_INTEGRITY_ENTRY_KIND_FILE:
      summary.file_count += 1;
      if (entry.ok) {
        summary.total_bytes += entry.size_bytes;
      }
      break;
    case BC_INTEGRITY_ENTRY_KIND_DIRECTORY:
      summary.directory_count += 1;
      break;
    case BC_INTEGRITY_ENTRY_KIND_SYMLINK:
      summary.symlink_count += 1;
      break;
    default:
      break;
    }
    if (!entry.ok) {
      summary.errors_count += 1;
    }
  }

  if (!bc_integrity_manifest_write_to_file(
          memory_context, &state->manifest_options, state->entries, &summary,
          state->manifest_options.output_path)) {
    bc_integrity_emit_stderr_quoted_path(
        "bc-integrity: cannot write manifest to '",
        state->manifest_options.output_path, "'\n");
    state->exit_code = 1;
    return false;
  }

  bc_runtime_error_collector_flush_to_stderr(state->errors, "bc-integrity");
  state->exit_code = 0;
  return true;
}

static bool bc_integrity_run_verify(const bc_runtime_t *application,
                                    bc_integrity_application_state_t *state) {
  bc_allocators_context_t *memory_context = NULL;
  if (!bc_runtime_memory_context(application, &memory_context)) {
    state->exit_code = 1;
    return false;
  }
  bc_concurrency_context_t *concurrency_context = NULL;
  if (!bc_runtime_parallel_context(application, &concurrency_context)) {
    state->exit_code = 1;
    return false;
  }
  bc_runtime_signal_handler_t *signal_handler = NULL;
  bc_runtime_signal_handler(application, &signal_handler);

  int verify_exit = 2;
  if (!bc_integrity_verify_run(memory_context, concurrency_context,
                               signal_handler, &state->verify_options,
                               state->errors, &verify_exit)) {
    state->exit_code = 1;
    return false;
  }

  bool interrupted = false;
  bc_runtime_should_stop(application, &interrupted);
  if (interrupted) {
    state->exit_code = 130;
    return false;
  }

  bc_runtime_error_collector_flush_to_stderr(state->errors, "bc-integrity");
  state->exit_code = verify_exit;
  return true;
}

static bool bc_integrity_run_diff(const bc_runtime_t *application,
                                  bc_integrity_application_state_t *state) {
  bc_allocators_context_t *memory_context = NULL;
  if (!bc_runtime_memory_context(application, &memory_context)) {
    state->exit_code = 1;
    return false;
  }
  int diff_exit = 2;
  if (!bc_integrity_diff_run(memory_context, &state->diff_options,
                             &diff_exit)) {
    state->exit_code = 1;
    return false;
  }
  state->exit_code = diff_exit;
  return true;
}

static bool bc_integrity_application_run(const bc_runtime_t *application,
                                         void *user_data) {
  bc_integrity_application_state_t *state =
      (bc_integrity_application_state_t *)user_data;

  if (bc_integrity_application_is_manifest(state)) {
    return bc_integrity_run_manifest(application, state);
  }
  if (bc_integrity_application_is_verify(state)) {
    return bc_integrity_run_verify(application, state);
  }
  if (bc_integrity_application_is_diff(state)) {
    return bc_integrity_run_diff(application, state);
  }

  bc_integrity_emit_stderr_quoted_path(
      "bc-integrity: ", state->parsed->command->name, ": unknown subcommand\n");
  state->exit_code = BC_INTEGRITY_EX_USAGE;
  return true;
}

static void bc_integrity_application_cleanup(const bc_runtime_t *application,
                                             void *user_data) {
  bc_integrity_application_state_t *state =
      (bc_integrity_application_state_t *)user_data;
  bc_allocators_context_t *memory_context = NULL;
  if (!bc_runtime_memory_context(application, &memory_context)) {
    return;
  }
  if (state->entries != NULL) {
    bc_containers_vector_destroy(memory_context, state->entries);
    state->entries = NULL;
  }
  if (state->errors != NULL) {
    bc_runtime_error_collector_destroy(memory_context, state->errors);
    state->errors = NULL;
  }
}

int main(int argument_count, char **argument_values) {
  const bc_runtime_cli_program_spec_t *spec = bc_integrity_cli_program_spec();

  bc_allocators_context_config_t cli_memory_config = {.tracking_enabled = true};
  bc_allocators_context_t *cli_memory_context = NULL;
  if (!bc_allocators_context_create(&cli_memory_config, &cli_memory_context)) {
    bc_integrity_emit_stderr(
        "bc-integrity: failed to initialize CLI memory context\n");
    return 1;
  }

  bc_runtime_config_store_t *cli_store = NULL;
  if (!bc_runtime_config_store_create(cli_memory_context, &cli_store)) {
    bc_integrity_emit_stderr(
        "bc-integrity: failed to initialize CLI config store\n");
    bc_allocators_context_destroy(cli_memory_context);
    return 1;
  }

  bc_runtime_cli_parsed_t parsed;
  bc_runtime_cli_parse_status_t parse_status = bc_runtime_cli_parse(
      spec, argument_count, (const char *const *)argument_values, cli_store,
      &parsed, stderr);

  if (parse_status == BC_RUNTIME_CLI_PARSE_HELP_GLOBAL) {
    bc_runtime_cli_print_help_global(spec, stdout);
    bc_runtime_config_store_destroy(cli_memory_context, cli_store);
    bc_allocators_context_destroy(cli_memory_context);
    return 0;
  }
  if (parse_status == BC_RUNTIME_CLI_PARSE_HELP_COMMAND) {
    bc_runtime_cli_print_help_command(spec, parsed.command, stdout);
    bc_runtime_config_store_destroy(cli_memory_context, cli_store);
    bc_allocators_context_destroy(cli_memory_context);
    return 0;
  }
  if (parse_status == BC_RUNTIME_CLI_PARSE_VERSION) {
    bc_runtime_cli_print_version(spec, stdout);
    bc_runtime_config_store_destroy(cli_memory_context, cli_store);
    bc_allocators_context_destroy(cli_memory_context);
    return 0;
  }
  if (parse_status == BC_RUNTIME_CLI_PARSE_ERROR) {
    bc_runtime_config_store_destroy(cli_memory_context, cli_store);
    bc_allocators_context_destroy(cli_memory_context);
    return 2;
  }

  bc_integrity_application_state_t state;
  bc_core_zero(&state, sizeof(state));
  state.parsed = &parsed;
  state.exit_code = BC_INTEGRITY_EX_USAGE;

  bc_integrity_threads_mode_t threads_mode = BC_INTEGRITY_THREADS_MODE_AUTO;
  size_t explicit_worker_count = 0;

  if (bc_integrity_command_name_equal(parsed.command->name, "manifest", 8)) {
    if (!bc_integrity_cli_bind_manifest_options(cli_store, &parsed,
                                                &state.manifest_options)) {
      bc_runtime_config_store_destroy(cli_memory_context, cli_store);
      bc_allocators_context_destroy(cli_memory_context);
      return 2;
    }
    threads_mode = state.manifest_options.threads_mode;
    explicit_worker_count = state.manifest_options.explicit_worker_count;
  } else if (bc_integrity_command_name_equal(parsed.command->name, "verify",
                                             6)) {
    if (!bc_integrity_cli_bind_verify_options(cli_store, &parsed,
                                              &state.verify_options)) {
      bc_runtime_config_store_destroy(cli_memory_context, cli_store);
      bc_allocators_context_destroy(cli_memory_context);
      return 2;
    }
    threads_mode = state.verify_options.threads_mode;
    explicit_worker_count = state.verify_options.explicit_worker_count;
  } else if (bc_integrity_command_name_equal(parsed.command->name, "diff", 4)) {
    if (!bc_integrity_cli_bind_diff_options(cli_store, &parsed,
                                            &state.diff_options)) {
      bc_runtime_config_store_destroy(cli_memory_context, cli_store);
      bc_allocators_context_destroy(cli_memory_context);
      return 2;
    }
  }

  bc_concurrency_config_t parallel_config;
  bc_core_zero(&parallel_config, sizeof(parallel_config));
  if (threads_mode == BC_INTEGRITY_THREADS_MODE_MONO) {
    parallel_config.worker_count_explicit = true;
    parallel_config.worker_count = 0;
  } else if (threads_mode == BC_INTEGRITY_THREADS_MODE_EXPLICIT) {
    parallel_config.worker_count_explicit = true;
    parallel_config.worker_count =
        explicit_worker_count >= 1 ? explicit_worker_count - 1 : 0;
    size_t logical_processor_count = bc_concurrency_logical_processor_count();
    if (explicit_worker_count > logical_processor_count) {
      bc_integrity_emit_stderr(
          "bc-integrity: --threads exceeds online logical processors\n");
      bc_runtime_config_store_destroy(cli_memory_context, cli_store);
      bc_allocators_context_destroy(cli_memory_context);
      return 2;
    }
    if (explicit_worker_count > bc_concurrency_physical_core_count()) {
      parallel_config.allow_oversubscribe = true;
    }
  } else if (threads_mode == BC_INTEGRITY_THREADS_MODE_AUTO_IO) {
    size_t logical_processor_count = bc_concurrency_logical_processor_count();
    parallel_config.allow_oversubscribe = true;
    parallel_config.worker_count_explicit = true;
    parallel_config.worker_count =
        logical_processor_count >= 2 ? logical_processor_count - 1 : 0;
  }

  bc_runtime_config_t runtime_config = {
      .max_pool_memory = 0,
      .memory_tracking_enabled = true,
      .log_level = BC_RUNTIME_LOG_LEVEL_WARN,
      .config_file_path = NULL,
      .argument_count = 0,
      .argument_values = NULL,
      .parallel_config = &parallel_config,
  };
  bc_runtime_callbacks_t runtime_callbacks = {
      .init = bc_integrity_application_init,
      .cleanup = bc_integrity_application_cleanup,
      .run = bc_integrity_application_run,
  };

  bc_runtime_t *runtime = NULL;
  if (!bc_runtime_create(&runtime_config, &runtime_callbacks, &state,
                         &runtime)) {
    bc_integrity_emit_stderr("bc-integrity: failed to initialize runtime\n");
    bc_runtime_config_store_destroy(cli_memory_context, cli_store);
    bc_allocators_context_destroy(cli_memory_context);
    return 1;
  }

  bc_runtime_run(runtime);
  bc_runtime_destroy(runtime);

  bc_runtime_config_store_destroy(cli_memory_context, cli_store);
  bc_allocators_context_destroy(cli_memory_context);

  return state.exit_code;
}
