// SPDX-License-Identifier: MIT

#include "bc_integrity_walk_internal.h"

#include "bc_integrity_capture_internal.h"
#include "bc_integrity_entry_internal.h"
#include "bc_integrity_filter_internal.h"

#include "bc_allocators.h"
#include "bc_allocators_pool.h"
#include "bc_concurrency.h"
#include "bc_concurrency_signal.h"
#include "bc_containers_vector.h"
#include "bc_core.h"
#include "bc_io_walk.h"
#include "bc_runtime_error_collector.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>
#include <unistd.h>

#define BC_INTEGRITY_WALK_INITIAL_VECTOR_CAPACITY ((size_t)1024)
#define BC_INTEGRITY_WALK_MAX_VECTOR_CAPACITY ((size_t)1U << 28)
#define BC_INTEGRITY_WALK_SERIAL_BUDGET_PER_WORKER ((size_t)256)
#define BC_INTEGRITY_WALK_SERIAL_BUDGET_FLOOR ((size_t)4096)

typedef struct bc_integrity_walk_worker_slot {
  bc_containers_vector_t *entries;
  bc_runtime_error_collector_t *errors;
  bool initialized;
} bc_integrity_walk_worker_slot_t;

typedef struct bc_integrity_walk_context {
  size_t worker_slot_index;
  bc_allocators_context_t *main_memory_context;
  const bc_integrity_manifest_options_t *options;
  const char *canonical_root_path;
  size_t canonical_root_path_length;
  const bc_integrity_filter_t *filter;
} bc_integrity_walk_context_t;

static bool bc_integrity_walk_relative_path(
    bc_allocators_context_t *memory_context, const char *canonical_root_path,
    size_t canonical_root_path_length, const char *absolute_path,
    size_t absolute_path_length, const char **out_relative_path,
    size_t *out_relative_path_length) {
  if (absolute_path_length < canonical_root_path_length) {
    return false;
  }
  bool prefix_equal = false;
  if (!bc_core_equal(absolute_path, canonical_root_path,
                     canonical_root_path_length, &prefix_equal) ||
      !prefix_equal) {
    return false;
  }
  size_t relative_offset = canonical_root_path_length;
  while (relative_offset < absolute_path_length &&
         absolute_path[relative_offset] == '/') {
    relative_offset += 1u;
  }
  size_t relative_length = absolute_path_length - relative_offset;
  char *copy = NULL;
  if (!bc_allocators_pool_allocate(memory_context, relative_length + 1u,
                                   (void **)&copy)) {
    return false;
  }
  bc_core_copy(copy, absolute_path + relative_offset, relative_length);
  copy[relative_length] = '\0';
  *out_relative_path = copy;
  *out_relative_path_length = relative_length;
  return true;
}

static bool
bc_integrity_walk_ensure_slot(const bc_integrity_walk_context_t *context,
                              bc_allocators_context_t *worker_memory,
                              bc_integrity_walk_worker_slot_t **out_slot) {
  bc_integrity_walk_worker_slot_t *slot =
      (bc_integrity_walk_worker_slot_t *)bc_concurrency_worker_slot(
          context->worker_slot_index);
  if (slot == NULL) {
    return false;
  }
  if (!slot->initialized) {
    if (!bc_containers_vector_create(
            worker_memory, sizeof(bc_integrity_entry_t),
            BC_INTEGRITY_WALK_INITIAL_VECTOR_CAPACITY,
            BC_INTEGRITY_WALK_MAX_VECTOR_CAPACITY, &slot->entries)) {
      return false;
    }
    if (!bc_runtime_error_collector_create(worker_memory, &slot->errors)) {
      return false;
    }
    slot->initialized = true;
  }
  *out_slot = slot;
  return true;
}

static int
bc_integrity_walk_open_parent_directory(const char *absolute_path,
                                        size_t absolute_path_length,
                                        size_t *out_basename_offset) {
  size_t last_slash_offset = 0;
  if (!bc_core_find_last_byte(absolute_path, absolute_path_length, '/',
                              &last_slash_offset)) {
    *out_basename_offset = 0;
    return open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  }
  *out_basename_offset = last_slash_offset + 1u;
  if (last_slash_offset == 0) {
    return open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  }
  char parent_buffer[4096];
  if (last_slash_offset >= sizeof(parent_buffer)) {
    return -1;
  }
  bc_core_copy(parent_buffer, absolute_path, last_slash_offset);
  parent_buffer[last_slash_offset] = '\0';
  return open(parent_buffer, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
}

static bool
bc_integrity_walk_clone_path(bc_allocators_context_t *memory_context,
                             const char *path, size_t path_length,
                             const char **out_copy) {
  char *copy = NULL;
  if (!bc_allocators_pool_allocate(memory_context, path_length + 1u,
                                   (void **)&copy)) {
    return false;
  }
  if (path_length > 0) {
    bc_core_copy(copy, path, path_length);
  }
  copy[path_length] = '\0';
  *out_copy = copy;
  return true;
}

static bool
bc_integrity_walk_capture_for_entry(const bc_integrity_walk_context_t *context,
                                    bc_allocators_context_t *worker_memory,
                                    bc_integrity_walk_worker_slot_t *slot,
                                    const bc_io_walk_entry_t *entry,
                                    bool follow_for_stat) {
  size_t basename_offset = 0;
  int parent_directory_fd = bc_integrity_walk_open_parent_directory(
      entry->absolute_path, entry->absolute_path_length, &basename_offset);
  if (parent_directory_fd < 0) {
    (void)bc_runtime_error_collector_append(slot->errors, worker_memory,
                                            entry->absolute_path, "open-parent",
                                            errno);
    return false;
  }

  const char *basename = entry->absolute_path + basename_offset;

  struct stat stat_buffer;
  int stat_flags = follow_for_stat ? 0 : AT_SYMLINK_NOFOLLOW;
  if (fstatat(parent_directory_fd, basename, &stat_buffer, stat_flags) != 0) {
    (void)bc_runtime_error_collector_append(
        slot->errors, worker_memory, entry->absolute_path, "lstat", errno);
    close(parent_directory_fd);
    return false;
  }

  const char *relative_path = NULL;
  size_t relative_path_length = 0;
  if (!bc_integrity_walk_relative_path(
          worker_memory, context->canonical_root_path,
          context->canonical_root_path_length, entry->absolute_path,
          entry->absolute_path_length, &relative_path, &relative_path_length)) {
    (void)bc_runtime_error_collector_append(slot->errors, worker_memory,
                                            entry->absolute_path,
                                            "relative-path", EINVAL);
    close(parent_directory_fd);
    return false;
  }
  if (relative_path_length == 0) {
    close(parent_directory_fd);
    return true;
  }

  if (context->filter != NULL &&
      !bc_integrity_filter_accepts_path(context->filter, relative_path,
                                        relative_path_length)) {
    close(parent_directory_fd);
    return true;
  }

  const char *absolute_path_copy = NULL;
  if (!bc_integrity_walk_clone_path(worker_memory, entry->absolute_path,
                                    entry->absolute_path_length,
                                    &absolute_path_copy)) {
    (void)bc_runtime_error_collector_append(slot->errors, worker_memory,
                                            entry->absolute_path,
                                            "clone-absolute", ENOMEM);
    close(parent_directory_fd);
    return false;
  }

  bool defer_digest =
      context->options->skip_digest || context->options->defer_digest;

  bc_integrity_entry_t built_entry;
  bc_core_zero(&built_entry, sizeof(built_entry));
  bc_integrity_capture_entry_from_stat(
      worker_memory, &stat_buffer, context->options->digest_algorithm,
      parent_directory_fd, basename, entry->absolute_path,
      entry->absolute_path_length, relative_path, relative_path_length,
      defer_digest, &built_entry);
  built_entry.absolute_path = absolute_path_copy;
  built_entry.absolute_path_length = entry->absolute_path_length;
  close(parent_directory_fd);

  if (!bc_containers_vector_push(worker_memory, slot->entries, &built_entry)) {
    (void)bc_runtime_error_collector_append(slot->errors, worker_memory,
                                            entry->absolute_path, "vector-push",
                                            ENOMEM);
    return false;
  }
  return true;
}

// cppcheck-suppress constParameterCallback ; signature fixed by
// bc_io_walk_filter_fn
static bool bc_integrity_walk_filter(const bc_io_walk_entry_t *entry,
                                     void *user_data) {
  bc_integrity_walk_context_t *context =
      (bc_integrity_walk_context_t *)user_data;

  bc_allocators_context_t *worker_memory = bc_concurrency_worker_memory();
  if (worker_memory == NULL) {
    worker_memory = context->main_memory_context;
  }

  if (entry->kind == BC_IO_WALK_ENTRY_SYMLINK) {
    bc_integrity_walk_worker_slot_t *slot = NULL;
    if (!bc_integrity_walk_ensure_slot(context, worker_memory, &slot)) {
      return false;
    }
    (void)bc_integrity_walk_capture_for_entry(context, worker_memory, slot,
                                              entry, false);
    return false;
  }

  if (entry->kind == BC_IO_WALK_ENTRY_OTHER) {
    if (!context->options->include_special) {
      return false;
    }
    bc_integrity_walk_worker_slot_t *slot = NULL;
    if (!bc_integrity_walk_ensure_slot(context, worker_memory, &slot)) {
      return false;
    }
    (void)bc_integrity_walk_capture_for_entry(context, worker_memory, slot,
                                              entry, false);
    return false;
  }

  if (context->options->default_exclude_virtual &&
      bc_integrity_walk_is_virtual_subpath(
          context->canonical_root_path, context->canonical_root_path_length,
          entry->absolute_path, entry->absolute_path_length)) {
    return false;
  }
  return true;
}

// cppcheck-suppress constParameterCallback ; signature fixed by
// bc_io_walk_visit_fn
static bool bc_integrity_walk_visit(const bc_io_walk_entry_t *entry,
                                    void *user_data) {
  bc_integrity_walk_context_t *context =
      (bc_integrity_walk_context_t *)user_data;

  if (entry->kind != BC_IO_WALK_ENTRY_FILE &&
      entry->kind != BC_IO_WALK_ENTRY_DIRECTORY) {
    return true;
  }

  bc_allocators_context_t *worker_memory = bc_concurrency_worker_memory();
  if (worker_memory == NULL) {
    worker_memory = context->main_memory_context;
  }
  bc_integrity_walk_worker_slot_t *slot = NULL;
  if (!bc_integrity_walk_ensure_slot(context, worker_memory, &slot)) {
    return false;
  }

  bool follow_for_stat = (entry->kind == BC_IO_WALK_ENTRY_FILE ||
                          entry->kind == BC_IO_WALK_ENTRY_DIRECTORY) &&
                         context->options->follow_symlinks;
  (void)bc_integrity_walk_capture_for_entry(context, worker_memory, slot, entry,
                                            follow_for_stat);
  return true;
}

// cppcheck-suppress constParameterCallback ; signature fixed by
// bc_io_walk_should_descend_fn
static bool bc_integrity_walk_should_descend(const bc_io_walk_entry_t *entry,
                                             void *user_data) {
  const bc_integrity_walk_context_t *context =
      (const bc_integrity_walk_context_t *)user_data;

  if (context->options->default_exclude_virtual &&
      bc_integrity_walk_is_virtual_subpath(
          context->canonical_root_path, context->canonical_root_path_length,
          entry->absolute_path, entry->absolute_path_length)) {
    return false;
  }

  if (context->filter == NULL) {
    return true;
  }
  size_t prefix_length = context->canonical_root_path_length;
  if (entry->absolute_path_length <= prefix_length) {
    return true;
  }
  size_t relative_offset = prefix_length;
  while (relative_offset < entry->absolute_path_length &&
         entry->absolute_path[relative_offset] == '/') {
    relative_offset += 1u;
  }
  if (relative_offset >= entry->absolute_path_length) {
    return true;
  }
  size_t relative_length = entry->absolute_path_length - relative_offset;
  return bc_integrity_filter_accepts_directory(
      context->filter, entry->absolute_path + relative_offset, relative_length);
}

// cppcheck-suppress constParameterCallback ; signature fixed by
// bc_io_walk_error_fn
static void bc_integrity_walk_on_error(const char *path, const char *stage,
                                       int errno_value, void *user_data) {
  const bc_integrity_walk_context_t *context =
      (const bc_integrity_walk_context_t *)user_data;
  bc_allocators_context_t *worker_memory = bc_concurrency_worker_memory();
  if (worker_memory == NULL) {
    worker_memory = context->main_memory_context;
  }
  bc_integrity_walk_worker_slot_t *slot = NULL;
  if (!bc_integrity_walk_ensure_slot(context, worker_memory, &slot)) {
    return;
  }
  (void)bc_runtime_error_collector_append(slot->errors, worker_memory, path,
                                          stage, errno_value);
}

typedef struct bc_integrity_walk_merge_argument {
  bc_containers_vector_t *destination_entries;
  bc_allocators_context_t *destination_memory_context;
  bc_runtime_error_collector_t *destination_errors;
  bool ok;
} bc_integrity_walk_merge_argument_t;

// cppcheck-suppress constParameterCallback ; signature fixed by
// bc_concurrency_foreach_slot
static void bc_integrity_walk_merge_worker_slot(void *slot_data,
                                                size_t worker_index,
                                                void *arg) {
  (void)worker_index;
  const bc_integrity_walk_worker_slot_t *slot =
      (const bc_integrity_walk_worker_slot_t *)slot_data;
  bc_integrity_walk_merge_argument_t *merge_argument =
      (bc_integrity_walk_merge_argument_t *)arg;
  if (!merge_argument->ok || !slot->initialized) {
    return;
  }
  if (slot->entries != NULL) {
    size_t count = bc_containers_vector_length(slot->entries);
    for (size_t entry_index = 0; entry_index < count; ++entry_index) {
      bc_integrity_entry_t entry;
      if (!bc_containers_vector_get(slot->entries, entry_index, &entry)) {
        merge_argument->ok = false;
        return;
      }
      if (!bc_containers_vector_push(merge_argument->destination_memory_context,
                                     merge_argument->destination_entries,
                                     &entry)) {
        merge_argument->ok = false;
        return;
      }
    }
  }
  if (slot->errors != NULL) {
    bc_runtime_error_collector_flush_to_stderr(slot->errors, "bc-integrity");
  }
}

static bool bc_integrity_walk_try_serial(
    bc_allocators_context_t *memory_context,
    const bc_concurrency_context_t *concurrency_context,
    bc_concurrency_signal_handler_t *signal_handler,
    const bc_integrity_manifest_options_t *options,
    const char *canonical_root_path, size_t canonical_root_path_length,
    bc_containers_vector_t *destination_entries,
    bc_runtime_error_collector_t *errors, bool *out_completed) {
  *out_completed = false;
  size_t worker_count =
      bc_concurrency_effective_worker_count(concurrency_context);
  if (worker_count <= 1) {
    if (!bc_integrity_walk_run_serial(memory_context, signal_handler, options,
                                      canonical_root_path,
                                      canonical_root_path_length,
                                      destination_entries, errors)) {
      return false;
    }
    *out_completed = true;
    return true;
  }
  size_t budget = worker_count * BC_INTEGRITY_WALK_SERIAL_BUDGET_PER_WORKER;
  if (budget < BC_INTEGRITY_WALK_SERIAL_BUDGET_FLOOR) {
    budget = BC_INTEGRITY_WALK_SERIAL_BUDGET_FLOOR;
  }
  bool budget_exceeded = false;
  if (!bc_integrity_walk_run_serial_with_budget(
          memory_context, signal_handler, options, canonical_root_path,
          canonical_root_path_length, destination_entries, errors, budget,
          &budget_exceeded)) {
    return false;
  }
  if (budget_exceeded) {
    bc_containers_vector_clear(destination_entries);
    return true;
  }
  *out_completed = true;
  return true;
}

bool bc_integrity_walk_run(bc_allocators_context_t *memory_context,
                           bc_concurrency_context_t *concurrency_context,
                           bc_concurrency_signal_handler_t *signal_handler,
                           const bc_integrity_manifest_options_t *options,
                           const char *canonical_root_path,
                           size_t canonical_root_path_length,
                           bc_containers_vector_t *destination_entries,
                           bc_runtime_error_collector_t *errors) {
  bool serial_completed = false;
  if (!bc_integrity_walk_try_serial(memory_context, concurrency_context,
                                    signal_handler, options,
                                    canonical_root_path,
                                    canonical_root_path_length,
                                    destination_entries, errors,
                                    &serial_completed)) {
    return false;
  }
  if (serial_completed) {
    return true;
  }

  bc_integrity_walk_context_t context;
  bc_core_zero(&context, sizeof(context));
  context.main_memory_context = memory_context;
  context.options = options;
  context.canonical_root_path = canonical_root_path;
  context.canonical_root_path_length = canonical_root_path_length;

  bc_integrity_filter_t *filter = NULL;
  if (options->include_list != NULL || options->exclude_list != NULL) {
    if (!bc_integrity_filter_create(memory_context, options->include_list,
                                    options->exclude_list, &filter)) {
      (void)bc_runtime_error_collector_append(
          errors, memory_context, canonical_root_path, "filter-create", ENOMEM);
      return false;
    }
    context.filter = filter;
  }

  bc_concurrency_slot_config_t slot_config = {
      .size = sizeof(bc_integrity_walk_worker_slot_t),
      .init = NULL,
      .destroy = NULL,
      .arg = NULL,
  };
  if (!bc_concurrency_register_slot(concurrency_context, &slot_config,
                                    &context.worker_slot_index)) {
    (void)bc_runtime_error_collector_append(
        errors, memory_context, canonical_root_path, "register-slot", ENOMEM);
    return false;
  }

  if (options->default_exclude_virtual &&
      bc_integrity_walk_is_virtual_root(canonical_root_path,
                                        canonical_root_path_length)) {
    (void)bc_runtime_error_collector_append(
        errors, memory_context, canonical_root_path, "virtual-root", EPERM);
    return false;
  }

  bc_io_walk_config_t walk_config = {
      .root = canonical_root_path,
      .root_length = canonical_root_path_length,
      .main_memory_context = memory_context,
      .concurrency_context = concurrency_context,
      .signal_handler = signal_handler,
      .queue_capacity = 0,
      .follow_symlinks = options->follow_symlinks,
      .include_hidden = options->include_hidden,
      .filter = bc_integrity_walk_filter,
      .filter_user_data = &context,
      .should_descend = bc_integrity_walk_should_descend,
      .should_descend_user_data = &context,
      .visit = bc_integrity_walk_visit,
      .visit_user_data = &context,
      .on_error = bc_integrity_walk_on_error,
      .error_user_data = &context,
  };
  bc_io_walk_stats_t stats;
  bool walk_ok = bc_io_walk_parallel(&walk_config, &stats);

  bc_integrity_walk_merge_argument_t merge_argument = {
      .destination_entries = destination_entries,
      .destination_memory_context = memory_context,
      .destination_errors = errors,
      .ok = true,
  };
  bc_concurrency_foreach_slot(concurrency_context, context.worker_slot_index,
                              bc_integrity_walk_merge_worker_slot,
                              &merge_argument);

  if (filter != NULL) {
    bc_integrity_filter_destroy(memory_context, filter);
  }

  return walk_ok && merge_argument.ok;
}
