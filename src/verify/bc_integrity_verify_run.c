// SPDX-License-Identifier: MIT

#include "bc_integrity_verify_internal.h"

#include "bc_integrity_capture_internal.h"
#include "bc_integrity_dispatch_internal.h"
#include "bc_integrity_entry_internal.h"
#include "bc_integrity_walk_internal.h"

#include "bc_allocators.h"
#include "bc_allocators_pool.h"
#include "bc_concurrency.h"
#include "bc_containers_vector.h"
#include "bc_core.h"
#include "bc_core_format.h"
#include "bc_core_io.h"
#include "bc_core_sort.h"
#include "bc_hrbl.h"
#include "bc_runtime_error_collector.h"

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>

#define BC_INTEGRITY_VERIFY_EXIT_OK 0
#define BC_INTEGRITY_VERIFY_EXIT_DIFF 1
#define BC_INTEGRITY_VERIFY_EXIT_ERROR 2
#define BC_INTEGRITY_VERIFY_STDOUT_BUFFER_BYTES ((size_t)(64 * 1024))
#define BC_INTEGRITY_VERIFY_STDERR_BUFFER_BYTES ((size_t)512)
#define BC_INTEGRITY_VERIFY_INITIAL_VECTOR_CAPACITY ((size_t)1024)
#define BC_INTEGRITY_VERIFY_MAX_VECTOR_CAPACITY ((size_t)1U << 28)

typedef struct bc_integrity_verify_record {
  const char *relative_path;
  size_t relative_path_length;
  bc_integrity_meta_snapshot_t snapshot;
} bc_integrity_verify_record_t;

static void bc_integrity_verify_emit_stderr(const char *message) {
  char buffer[BC_INTEGRITY_VERIFY_STDERR_BUFFER_BYTES];
  bc_core_writer_t writer;
  if (!bc_core_writer_init_standard_error(&writer, buffer, sizeof(buffer))) {
    return;
  }
  (void)bc_core_writer_write_cstring(&writer, message);
  (void)bc_core_writer_destroy(&writer);
}

static void bc_integrity_verify_emit_stderr_quoted(const char *prefix,
                                                   const char *value,
                                                   const char *suffix) {
  char buffer[BC_INTEGRITY_VERIFY_STDERR_BUFFER_BYTES];
  bc_core_writer_t writer;
  if (!bc_core_writer_init_standard_error(&writer, buffer, sizeof(buffer))) {
    return;
  }
  (void)bc_core_writer_write_cstring(&writer, prefix);
  (void)bc_core_writer_write_cstring(&writer, value);
  (void)bc_core_writer_write_cstring(&writer, suffix);
  (void)bc_core_writer_destroy(&writer);
}

static int bc_integrity_verify_path_compare(const char *left,
                                            size_t left_length,
                                            const char *right,
                                            size_t right_length) {
  size_t shared = left_length < right_length ? left_length : right_length;
  int comparison = 0;
  if (shared > 0) {
    (void)bc_core_compare(left, right, shared, &comparison);
  }
  if (comparison != 0) {
    return comparison;
  }
  if (left_length < right_length) {
    return -1;
  }
  if (left_length > right_length) {
    return 1;
  }
  return 0;
}

static bool bc_integrity_verify_record_less_than(const void *left_pointer,
                                                 const void *right_pointer,
                                                 void *user_data) {
  (void)user_data;
  const bc_integrity_verify_record_t *left =
      (const bc_integrity_verify_record_t *)left_pointer;
  const bc_integrity_verify_record_t *right =
      (const bc_integrity_verify_record_t *)right_pointer;
  return bc_integrity_verify_path_compare(
             left->relative_path, left->relative_path_length,
             right->relative_path, right->relative_path_length) < 0;
}

static bc_integrity_entry_kind_t
bc_integrity_verify_kind_from_name(const char *name, size_t length) {
  if (length == 4) {
    bool is_file = false;
    (void)bc_core_equal(name, "file", 4, &is_file);
    if (is_file) {
      return BC_INTEGRITY_ENTRY_KIND_FILE;
    }
    bool is_fifo = false;
    (void)bc_core_equal(name, "fifo", 4, &is_fifo);
    if (is_fifo) {
      return BC_INTEGRITY_ENTRY_KIND_FIFO;
    }
  }
  if (length == 3) {
    bool is_dir = false;
    (void)bc_core_equal(name, "dir", 3, &is_dir);
    if (is_dir) {
      return BC_INTEGRITY_ENTRY_KIND_DIRECTORY;
    }
  }
  if (length == 7) {
    bool is_symlink = false;
    (void)bc_core_equal(name, "symlink", 7, &is_symlink);
    if (is_symlink) {
      return BC_INTEGRITY_ENTRY_KIND_SYMLINK;
    }
  }
  if (length == 6) {
    bool is_socket = false;
    (void)bc_core_equal(name, "socket", 6, &is_socket);
    if (is_socket) {
      return BC_INTEGRITY_ENTRY_KIND_SOCKET;
    }
    bool is_device = false;
    (void)bc_core_equal(name, "device", 6, &is_device);
    if (is_device) {
      return BC_INTEGRITY_ENTRY_KIND_DEVICE;
    }
  }
  return BC_INTEGRITY_ENTRY_KIND_FILE;
}

static bool
bc_integrity_verify_clone_path(bc_allocators_context_t *memory_context,
                               const char *path, size_t length,
                               char **out_copy) {
  char *copy = NULL;
  if (!bc_allocators_pool_allocate(memory_context, length + 1u,
                                   (void **)&copy)) {
    return false;
  }
  if (length > 0) {
    bc_core_copy(copy, path, length);
  }
  copy[length] = '\0';
  *out_copy = copy;
  return true;
}

static bool bc_integrity_verify_field_name_equals(const char *key,
                                                  size_t key_length,
                                                  const char *literal,
                                                  size_t literal_length) {
  if (key_length != literal_length) {
    return false;
  }
  bool equal = false;
  (void)bc_core_equal(key, literal, literal_length, &equal);
  return equal;
}

static bool bc_integrity_verify_load_record_from_block(
    bc_allocators_context_t *memory_context,
    const bc_hrbl_value_ref_t *entry_block, const char *relative_path,
    size_t relative_path_length, bc_integrity_verify_record_t *out_record) {
  out_record->relative_path = relative_path;
  out_record->relative_path_length = relative_path_length;
  out_record->snapshot.present = true;

  bc_hrbl_iter_t iter;
  if (!bc_hrbl_reader_iter_block(entry_block, &iter)) {
    return false;
  }
  bool kind_seen = false;
  bc_hrbl_value_ref_t value;
  const char *key = NULL;
  size_t key_length = 0;
  while (bc_hrbl_iter_next(&iter, &value, &key, &key_length)) {
    if (key_length == 0) {
      continue;
    }
    if (bc_integrity_verify_field_name_equals(key, key_length, "kind", 4)) {
      const char *kind_value = NULL;
      size_t kind_length = 0;
      if (bc_hrbl_reader_get_string(&value, &kind_value, &kind_length)) {
        out_record->snapshot.kind =
            bc_integrity_verify_kind_from_name(kind_value, kind_length);
        kind_seen = true;
      }
      continue;
    }
    if (bc_integrity_verify_field_name_equals(key, key_length, "size_bytes",
                                              10)) {
      uint64_t value_u64 = 0;
      if (bc_hrbl_reader_get_uint64(&value, &value_u64)) {
        out_record->snapshot.size_bytes = value_u64;
      }
      continue;
    }
    if (bc_integrity_verify_field_name_equals(key, key_length, "mode", 4)) {
      uint64_t value_u64 = 0;
      if (bc_hrbl_reader_get_uint64(&value, &value_u64)) {
        out_record->snapshot.mode = value_u64;
      }
      continue;
    }
    if (bc_integrity_verify_field_name_equals(key, key_length, "uid", 3)) {
      uint64_t value_u64 = 0;
      if (bc_hrbl_reader_get_uint64(&value, &value_u64)) {
        out_record->snapshot.uid = value_u64;
      }
      continue;
    }
    if (bc_integrity_verify_field_name_equals(key, key_length, "gid", 3)) {
      uint64_t value_u64 = 0;
      if (bc_hrbl_reader_get_uint64(&value, &value_u64)) {
        out_record->snapshot.gid = value_u64;
      }
      continue;
    }
    if (bc_integrity_verify_field_name_equals(key, key_length, "mtime_sec",
                                              9)) {
      uint64_t value_u64 = 0;
      if (bc_hrbl_reader_get_uint64(&value, &value_u64)) {
        out_record->snapshot.mtime_sec = value_u64;
      }
      continue;
    }
    if (bc_integrity_verify_field_name_equals(key, key_length, "mtime_nsec",
                                              10)) {
      uint64_t value_u64 = 0;
      if (bc_hrbl_reader_get_uint64(&value, &value_u64)) {
        out_record->snapshot.mtime_nsec = value_u64;
      }
      continue;
    }
    if (bc_integrity_verify_field_name_equals(key, key_length, "ino", 3)) {
      uint64_t value_u64 = 0;
      if (bc_hrbl_reader_get_uint64(&value, &value_u64)) {
        out_record->snapshot.inode = value_u64;
      }
      continue;
    }
    if (bc_integrity_verify_field_name_equals(key, key_length, "nlink", 5)) {
      uint64_t value_u64 = 0;
      if (bc_hrbl_reader_get_uint64(&value, &value_u64)) {
        out_record->snapshot.nlink = value_u64;
      }
      continue;
    }
    if (bc_integrity_verify_field_name_equals(key, key_length, "digest_hex",
                                              10)) {
      const char *string_value = NULL;
      size_t string_length = 0;
      if (bc_hrbl_reader_get_string(&value, &string_value, &string_length)) {
        char *copy = NULL;
        if (!bc_integrity_verify_clone_path(memory_context, string_value,
                                            string_length, &copy)) {
          return false;
        }
        out_record->snapshot.digest_hex = copy;
        out_record->snapshot.digest_hex_length = string_length;
      }
      continue;
    }
    if (bc_integrity_verify_field_name_equals(key, key_length, "link_target",
                                              11)) {
      const char *string_value = NULL;
      size_t string_length = 0;
      if (bc_hrbl_reader_get_string(&value, &string_value, &string_length)) {
        char *copy = NULL;
        if (!bc_integrity_verify_clone_path(memory_context, string_value,
                                            string_length, &copy)) {
          return false;
        }
        out_record->snapshot.link_target = copy;
        out_record->snapshot.link_target_length = string_length;
      }
      continue;
    }
  }
  return kind_seen;
}

static bool
bc_integrity_verify_block_has_record_fields(const bc_hrbl_value_ref_t *block) {
  bc_hrbl_iter_t iter;
  if (!bc_hrbl_reader_iter_block(block, &iter)) {
    return false;
  }
  bc_hrbl_value_ref_t value;
  const char *key = NULL;
  size_t key_length = 0;
  while (bc_hrbl_iter_next(&iter, &value, &key, &key_length)) {
    if (bc_integrity_verify_field_name_equals(key, key_length, "kind", 4)) {
      return true;
    }
  }
  return false;
}

static bool bc_integrity_verify_collect_entries_recursive(
    bc_allocators_context_t *memory_context, const bc_hrbl_value_ref_t *block,
    const char *path_prefix, size_t path_prefix_length,
    bc_containers_vector_t *destination) {
  bc_hrbl_iter_t iter;
  if (!bc_hrbl_reader_iter_block(block, &iter)) {
    return true;
  }
  bc_hrbl_value_ref_t value;
  const char *key = NULL;
  size_t key_length = 0;
  while (bc_hrbl_iter_next(&iter, &value, &key, &key_length)) {
    if (value.kind != BC_HRBL_KIND_BLOCK) {
      continue;
    }
    size_t combined_length = path_prefix_length;
    if (path_prefix_length > 0) {
      combined_length += 1u;
    }
    combined_length += key_length;
    char *combined = NULL;
    if (!bc_allocators_pool_allocate(memory_context, combined_length + 1u,
                                     (void **)&combined)) {
      return false;
    }
    size_t offset = 0;
    if (path_prefix_length > 0) {
      bc_core_copy(combined, path_prefix, path_prefix_length);
      offset = path_prefix_length;
      combined[offset++] = '/';
    }
    if (key_length > 0) {
      bc_core_copy(combined + offset, key, key_length);
    }
    combined[combined_length] = '\0';

    if (!bc_integrity_verify_block_has_record_fields(&value)) {
      if (!bc_integrity_verify_collect_entries_recursive(
              memory_context, &value, combined, combined_length, destination)) {
        bc_allocators_pool_free(memory_context, combined);
        return false;
      }
      bc_allocators_pool_free(memory_context, combined);
      continue;
    }

    bc_integrity_verify_record_t record;
    bc_core_zero(&record, sizeof(record));
    if (!bc_integrity_verify_load_record_from_block(
            memory_context, &value, combined, combined_length, &record)) {
      bc_allocators_pool_free(memory_context, combined);
      return false;
    }
    if (!bc_containers_vector_push(memory_context, destination, &record)) {
      bc_allocators_pool_free(memory_context, combined);
      return false;
    }
  }
  return true;
}

static bool
bc_integrity_verify_collect_entries(bc_allocators_context_t *memory_context,
                                    const bc_hrbl_reader_t *reader,
                                    bc_containers_vector_t *destination) {
  bc_hrbl_value_ref_t entries_ref;
  if (!bc_hrbl_reader_find(reader, "entries", sizeof("entries") - 1u,
                           &entries_ref)) {
    return true;
  }
  return bc_integrity_verify_collect_entries_recursive(
      memory_context, &entries_ref, NULL, 0, destination);
}

static bc_integrity_digest_algorithm_t
bc_integrity_verify_load_algorithm(const bc_hrbl_reader_t *reader) {
  bc_hrbl_value_ref_t value_ref;
  if (!bc_hrbl_reader_find(reader, "meta.digest_algorithm",
                           sizeof("meta.digest_algorithm") - 1u, &value_ref)) {
    return BC_INTEGRITY_DIGEST_ALGORITHM_SHA256;
  }
  const char *value = NULL;
  size_t length = 0;
  if (!bc_hrbl_reader_get_string(&value_ref, &value, &length)) {
    return BC_INTEGRITY_DIGEST_ALGORITHM_SHA256;
  }
  if (length == 4) {
    bool is_xxh3 = false;
    (void)bc_core_equal(value, "xxh3", 4, &is_xxh3);
    if (is_xxh3) {
      return BC_INTEGRITY_DIGEST_ALGORITHM_XXH3;
    }
  }
  if (length == 6) {
    bool is_xxh128 = false;
    (void)bc_core_equal(value, "xxh128", 6, &is_xxh128);
    if (is_xxh128) {
      return BC_INTEGRITY_DIGEST_ALGORITHM_XXH128;
    }
  }
  return BC_INTEGRITY_DIGEST_ALGORITHM_SHA256;
}

static bc_integrity_verify_change_kind_t
bc_integrity_verify_compare_one(const bc_integrity_verify_options_t *options,
                                const bc_integrity_meta_snapshot_t *expected,
                                const bc_integrity_meta_snapshot_t *actual) {
  switch (options->mode) {
  case BC_INTEGRITY_VERIFY_MODE_CONTENT:
    return bc_integrity_verify_compare_content(expected, actual);
  case BC_INTEGRITY_VERIFY_MODE_META:
    return bc_integrity_verify_compare_meta(expected, actual, false);
  case BC_INTEGRITY_VERIFY_MODE_STRICT:
  default:
    return bc_integrity_verify_compare_strict(expected, actual, false);
  }
}

static const char *
bc_integrity_verify_mode_label(bc_integrity_verify_mode_t mode) {
  switch (mode) {
  case BC_INTEGRITY_VERIFY_MODE_CONTENT:
    return "content";
  case BC_INTEGRITY_VERIFY_MODE_META:
    return "meta";
  case BC_INTEGRITY_VERIFY_MODE_STRICT:
  default:
    return "strict";
  }
}

static const char *
bc_integrity_verify_algorithm_label(bc_integrity_digest_algorithm_t algorithm) {
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

static void
bc_integrity_verify_tally_change(bc_integrity_verify_change_kind_t kind,
                                 bc_integrity_verify_json_summary_t *summary) {
  switch (kind) {
  case BC_INTEGRITY_VERIFY_CHANGE_ADDED:
    summary->added += 1u;
    break;
  case BC_INTEGRITY_VERIFY_CHANGE_REMOVED:
    summary->removed += 1u;
    break;
  case BC_INTEGRITY_VERIFY_CHANGE_CONTENT:
    summary->content += 1u;
    break;
  case BC_INTEGRITY_VERIFY_CHANGE_META:
    summary->meta += 1u;
    break;
  case BC_INTEGRITY_VERIFY_CHANGE_BOTH:
    summary->both += 1u;
    break;
  case BC_INTEGRITY_VERIFY_CHANGE_NONE:
  default:
    break;
  }
}

bool bc_integrity_verify_run(bc_allocators_context_t *memory_context,
                             bc_concurrency_context_t *concurrency_context,
                             bc_concurrency_signal_handler_t *signal_handler,
                             const bc_integrity_verify_options_t *options,
                             bc_runtime_error_collector_t *errors,
                             int *out_exit_code) {
  (void)signal_handler;
  bc_hrbl_verify_status_t verify_status =
      bc_hrbl_verify_file(options->manifest_path);
  if (verify_status != BC_HRBL_VERIFY_OK) {
    bc_integrity_verify_emit_stderr_quoted(
        "bc-integrity: verify: invalid manifest '", options->manifest_path,
        "'\n");
    *out_exit_code = BC_INTEGRITY_VERIFY_EXIT_ERROR;
    return true;
  }

  char canonical_root[PATH_MAX];
  if (realpath(options->root_path, canonical_root) == NULL) {
    bc_integrity_verify_emit_stderr_quoted(
        "bc-integrity: verify: cannot resolve root '", options->root_path,
        "'\n");
    *out_exit_code = BC_INTEGRITY_VERIFY_EXIT_ERROR;
    return true;
  }
  size_t canonical_root_length = 0;
  (void)bc_core_length(canonical_root, '\0', &canonical_root_length);
  while (canonical_root_length > 1 &&
         canonical_root[canonical_root_length - 1] == '/') {
    canonical_root[--canonical_root_length] = '\0';
  }

  struct stat root_stat;
  if (stat(canonical_root, &root_stat) != 0 || !S_ISDIR(root_stat.st_mode)) {
    bc_integrity_verify_emit_stderr_quoted(
        "bc-integrity: verify: root must be a directory: '", canonical_root,
        "'\n");
    *out_exit_code = BC_INTEGRITY_VERIFY_EXIT_ERROR;
    return true;
  }

  bc_hrbl_reader_t *reader = NULL;
  if (!bc_hrbl_reader_open(memory_context, options->manifest_path, &reader)) {
    bc_integrity_verify_emit_stderr_quoted(
        "bc-integrity: verify: cannot open manifest '", options->manifest_path,
        "'\n");
    *out_exit_code = BC_INTEGRITY_VERIFY_EXIT_ERROR;
    return true;
  }

  bc_integrity_digest_algorithm_t digest_algorithm =
      bc_integrity_verify_load_algorithm(reader);

  bc_containers_vector_t *expected_records = NULL;
  if (!bc_containers_vector_create(
          memory_context, sizeof(bc_integrity_verify_record_t),
          BC_INTEGRITY_VERIFY_INITIAL_VECTOR_CAPACITY,
          BC_INTEGRITY_VERIFY_MAX_VECTOR_CAPACITY, &expected_records)) {
    bc_hrbl_reader_destroy(reader);
    *out_exit_code = BC_INTEGRITY_VERIFY_EXIT_ERROR;
    return true;
  }

  if (!bc_integrity_verify_collect_entries(memory_context, reader,
                                           expected_records)) {
    bc_containers_vector_destroy(memory_context, expected_records);
    bc_hrbl_reader_destroy(reader);
    bc_integrity_verify_emit_stderr(
        "bc-integrity: verify: failed to enumerate manifest entries\n");
    *out_exit_code = BC_INTEGRITY_VERIFY_EXIT_ERROR;
    return true;
  }

  bc_containers_vector_t *actual_entries = NULL;
  if (!bc_containers_vector_create(memory_context, sizeof(bc_integrity_entry_t),
                                   BC_INTEGRITY_VERIFY_INITIAL_VECTOR_CAPACITY,
                                   BC_INTEGRITY_VERIFY_MAX_VECTOR_CAPACITY,
                                   &actual_entries)) {
    bc_containers_vector_destroy(memory_context, expected_records);
    bc_hrbl_reader_destroy(reader);
    *out_exit_code = BC_INTEGRITY_VERIFY_EXIT_ERROR;
    return true;
  }

  bc_integrity_manifest_options_t walk_options;
  bc_core_zero(&walk_options, sizeof(walk_options));
  walk_options.root_path = canonical_root;
  walk_options.digest_algorithm = digest_algorithm;
  walk_options.threads_mode = options->threads_mode;
  walk_options.explicit_worker_count = options->explicit_worker_count;
  walk_options.follow_symlinks = options->follow_symlinks;
  walk_options.include_hidden = options->include_hidden;
  walk_options.include_special = options->include_special;
  walk_options.default_exclude_virtual = options->default_exclude_virtual;
  walk_options.skip_digest = (options->mode == BC_INTEGRITY_VERIFY_MODE_META);
  walk_options.defer_digest = !walk_options.skip_digest;
  walk_options.include_list = options->include_list;
  walk_options.exclude_list = options->exclude_list;

  bool walk_ok = bc_integrity_walk_run(
      memory_context, concurrency_context, signal_handler, &walk_options,
      canonical_root, canonical_root_length, actual_entries, errors);
  if (!walk_ok) {
    bc_runtime_error_collector_flush_to_stderr(errors, "bc-integrity");
    bc_containers_vector_destroy(memory_context, actual_entries);
    bc_containers_vector_destroy(memory_context, expected_records);
    bc_hrbl_reader_destroy(reader);
    *out_exit_code = BC_INTEGRITY_VERIFY_EXIT_ERROR;
    return true;
  }

  if (walk_options.defer_digest) {
    if (!bc_integrity_dispatch_compute_digests(
            memory_context, concurrency_context, signal_handler,
            digest_algorithm, actual_entries)) {
      bc_runtime_error_collector_flush_to_stderr(errors, "bc-integrity");
      bc_containers_vector_destroy(memory_context, actual_entries);
      bc_containers_vector_destroy(memory_context, expected_records);
      bc_hrbl_reader_destroy(reader);
      *out_exit_code = BC_INTEGRITY_VERIFY_EXIT_ERROR;
      return true;
    }
  }

  bc_containers_vector_t *actual_records = NULL;
  if (!bc_containers_vector_create(
          memory_context, sizeof(bc_integrity_verify_record_t),
          BC_INTEGRITY_VERIFY_INITIAL_VECTOR_CAPACITY,
          BC_INTEGRITY_VERIFY_MAX_VECTOR_CAPACITY, &actual_records)) {
    bc_containers_vector_destroy(memory_context, actual_entries);
    bc_containers_vector_destroy(memory_context, expected_records);
    bc_hrbl_reader_destroy(reader);
    *out_exit_code = BC_INTEGRITY_VERIFY_EXIT_ERROR;
    return true;
  }
  size_t actual_count = bc_containers_vector_length(actual_entries);
  for (size_t index = 0; index < actual_count; ++index) {
    bc_integrity_entry_t entry;
    if (!bc_containers_vector_get(actual_entries, index, &entry)) {
      continue;
    }
    bc_integrity_verify_record_t record;
    bc_core_zero(&record, sizeof(record));
    record.relative_path = entry.relative_path;
    record.relative_path_length = entry.relative_path_length;
    record.snapshot.present = true;
    record.snapshot.kind = entry.kind;
    record.snapshot.size_bytes = entry.size_bytes;
    record.snapshot.mode = entry.mode;
    record.snapshot.uid = entry.uid;
    record.snapshot.gid = entry.gid;
    record.snapshot.mtime_sec = entry.mtime_sec;
    record.snapshot.mtime_nsec = entry.mtime_nsec;
    record.snapshot.inode = entry.inode;
    record.snapshot.nlink = entry.nlink;
    if (entry.digest_hex_length > 0) {
      char *digest_copy = NULL;
      if (!bc_integrity_verify_clone_path(memory_context, entry.digest_hex,
                                          entry.digest_hex_length,
                                          &digest_copy)) {
        bc_containers_vector_destroy(memory_context, actual_records);
        bc_containers_vector_destroy(memory_context, actual_entries);
        bc_containers_vector_destroy(memory_context, expected_records);
        bc_hrbl_reader_destroy(reader);
        *out_exit_code = BC_INTEGRITY_VERIFY_EXIT_ERROR;
        return true;
      }
      record.snapshot.digest_hex = digest_copy;
      record.snapshot.digest_hex_length = entry.digest_hex_length;
    }
    if (entry.link_target_length > 0) {
      record.snapshot.link_target = entry.link_target;
      record.snapshot.link_target_length = entry.link_target_length;
    }
    if (!bc_containers_vector_push(memory_context, actual_records, &record)) {
      bc_containers_vector_destroy(memory_context, actual_records);
      bc_containers_vector_destroy(memory_context, actual_entries);
      bc_containers_vector_destroy(memory_context, expected_records);
      bc_hrbl_reader_destroy(reader);
      *out_exit_code = BC_INTEGRITY_VERIFY_EXIT_ERROR;
      return true;
    }
  }

  size_t expected_count = bc_containers_vector_length(expected_records);
  bc_integrity_verify_record_t *expected_array = NULL;
  if (expected_count > 0) {
    if (!bc_allocators_pool_allocate(memory_context,
                                     expected_count *
                                         sizeof(bc_integrity_verify_record_t),
                                     (void **)&expected_array)) {
      bc_containers_vector_destroy(memory_context, actual_records);
      bc_containers_vector_destroy(memory_context, actual_entries);
      bc_containers_vector_destroy(memory_context, expected_records);
      bc_hrbl_reader_destroy(reader);
      *out_exit_code = BC_INTEGRITY_VERIFY_EXIT_ERROR;
      return true;
    }
    for (size_t index = 0; index < expected_count; ++index) {
      (void)bc_containers_vector_get(expected_records, index,
                                     &expected_array[index]);
    }
  }

  size_t actual_record_count = bc_containers_vector_length(actual_records);
  bc_integrity_verify_record_t *actual_array = NULL;
  if (actual_record_count > 0) {
    if (!bc_allocators_pool_allocate(memory_context,
                                     actual_record_count *
                                         sizeof(bc_integrity_verify_record_t),
                                     (void **)&actual_array)) {
      if (expected_array != NULL) {
        bc_allocators_pool_free(memory_context, expected_array);
      }
      bc_containers_vector_destroy(memory_context, actual_records);
      bc_containers_vector_destroy(memory_context, actual_entries);
      bc_containers_vector_destroy(memory_context, expected_records);
      bc_hrbl_reader_destroy(reader);
      *out_exit_code = BC_INTEGRITY_VERIFY_EXIT_ERROR;
      return true;
    }
    for (size_t index = 0; index < actual_record_count; ++index) {
      (void)bc_containers_vector_get(actual_records, index,
                                     &actual_array[index]);
    }
  }

  if (expected_count > 1) {
    bc_core_sort_with_compare(expected_array, expected_count,
                              sizeof(bc_integrity_verify_record_t),
                              bc_integrity_verify_record_less_than, NULL);
  }
  if (actual_record_count > 1) {
    bc_core_sort_with_compare(actual_array, actual_record_count,
                              sizeof(bc_integrity_verify_record_t),
                              bc_integrity_verify_record_less_than, NULL);
  }

  char stdout_buffer[BC_INTEGRITY_VERIFY_STDOUT_BUFFER_BYTES];
  bc_core_writer_t stdout_writer;
  bool stdout_writer_ready = bc_core_writer_init_standard_output(
      &stdout_writer, stdout_buffer, sizeof(stdout_buffer));

  uint64_t started_at_unix_sec = 0;
  uint64_t started_monotonic_ms = 0;
  {
    struct timespec realtime_now;
    if (clock_gettime(CLOCK_REALTIME, &realtime_now) == 0) {
      started_at_unix_sec = (uint64_t)realtime_now.tv_sec;
    }
    struct timespec monotonic_now;
    if (clock_gettime(CLOCK_MONOTONIC, &monotonic_now) == 0) {
      started_monotonic_ms = (uint64_t)monotonic_now.tv_sec * 1000u +
                             (uint64_t)(monotonic_now.tv_nsec / 1000000);
    }
  }

  if (stdout_writer_ready &&
      options->format == BC_INTEGRITY_OUTPUT_FORMAT_JSON) {
    bc_integrity_verify_json_header_options_t header_options;
    bc_core_zero(&header_options, sizeof(header_options));
    header_options.command = "verify";
    header_options.root_path = canonical_root;
    header_options.manifest_path = options->manifest_path;
    header_options.mode = bc_integrity_verify_mode_label(options->mode);
    header_options.digest_algorithm =
        bc_integrity_verify_algorithm_label(digest_algorithm);
    header_options.started_at_unix_sec = started_at_unix_sec;
    (void)bc_integrity_verify_emit_json_header(&stdout_writer, &header_options);
  }

  bc_integrity_verify_json_summary_t summary;
  bc_core_zero(&summary, sizeof(summary));

  size_t change_count = 0;
  size_t cursor_expected = 0;
  size_t cursor_actual = 0;
  bool exit_early = false;
  while (cursor_expected < expected_count &&
         cursor_actual < actual_record_count && !exit_early) {
    const bc_integrity_verify_record_t *expected_record =
        &expected_array[cursor_expected];
    const bc_integrity_verify_record_t *actual_record =
        &actual_array[cursor_actual];
    int comparison = bc_integrity_verify_path_compare(
        expected_record->relative_path, expected_record->relative_path_length,
        actual_record->relative_path, actual_record->relative_path_length);
    if (comparison < 0) {
      if (stdout_writer_ready) {
        if (options->format == BC_INTEGRITY_OUTPUT_FORMAT_JSON) {
          (void)bc_integrity_verify_emit_change_json(
              &stdout_writer, BC_INTEGRITY_VERIFY_CHANGE_REMOVED,
              expected_record->relative_path,
              expected_record->relative_path_length, &expected_record->snapshot,
              NULL);
        } else {
          (void)bc_integrity_verify_emit_change_text(
              &stdout_writer, BC_INTEGRITY_VERIFY_CHANGE_REMOVED,
              expected_record->relative_path,
              expected_record->relative_path_length, &expected_record->snapshot,
              NULL);
        }
      }
      bc_integrity_verify_tally_change(BC_INTEGRITY_VERIFY_CHANGE_REMOVED,
                                       &summary);
      change_count += 1;
      cursor_expected += 1;
    } else if (comparison > 0) {
      if (stdout_writer_ready) {
        if (options->format == BC_INTEGRITY_OUTPUT_FORMAT_JSON) {
          (void)bc_integrity_verify_emit_change_json(
              &stdout_writer, BC_INTEGRITY_VERIFY_CHANGE_ADDED,
              actual_record->relative_path, actual_record->relative_path_length,
              NULL, &actual_record->snapshot);
        } else {
          (void)bc_integrity_verify_emit_change_text(
              &stdout_writer, BC_INTEGRITY_VERIFY_CHANGE_ADDED,
              actual_record->relative_path, actual_record->relative_path_length,
              NULL, &actual_record->snapshot);
        }
      }
      bc_integrity_verify_tally_change(BC_INTEGRITY_VERIFY_CHANGE_ADDED,
                                       &summary);
      change_count += 1;
      cursor_actual += 1;
    } else {
      bc_integrity_verify_change_kind_t change =
          bc_integrity_verify_compare_one(options, &expected_record->snapshot,
                                          &actual_record->snapshot);
      if (change != BC_INTEGRITY_VERIFY_CHANGE_NONE) {
        if (stdout_writer_ready) {
          if (options->format == BC_INTEGRITY_OUTPUT_FORMAT_JSON) {
            (void)bc_integrity_verify_emit_change_json(
                &stdout_writer, change, expected_record->relative_path,
                expected_record->relative_path_length,
                &expected_record->snapshot, &actual_record->snapshot);
          } else {
            (void)bc_integrity_verify_emit_change_text(
                &stdout_writer, change, expected_record->relative_path,
                expected_record->relative_path_length,
                &expected_record->snapshot, &actual_record->snapshot);
          }
        }
        bc_integrity_verify_tally_change(change, &summary);
        change_count += 1;
      }
      cursor_expected += 1;
      cursor_actual += 1;
    }
    if (options->exit_on_first && change_count > 0) {
      exit_early = true;
    }
  }
  while (cursor_expected < expected_count && !exit_early) {
    const bc_integrity_verify_record_t *expected_record =
        &expected_array[cursor_expected];
    if (stdout_writer_ready) {
      if (options->format == BC_INTEGRITY_OUTPUT_FORMAT_JSON) {
        (void)bc_integrity_verify_emit_change_json(
            &stdout_writer, BC_INTEGRITY_VERIFY_CHANGE_REMOVED,
            expected_record->relative_path,
            expected_record->relative_path_length, &expected_record->snapshot,
            NULL);
      } else {
        (void)bc_integrity_verify_emit_change_text(
            &stdout_writer, BC_INTEGRITY_VERIFY_CHANGE_REMOVED,
            expected_record->relative_path,
            expected_record->relative_path_length, &expected_record->snapshot,
            NULL);
      }
    }
    bc_integrity_verify_tally_change(BC_INTEGRITY_VERIFY_CHANGE_REMOVED,
                                     &summary);
    change_count += 1;
    cursor_expected += 1;
    if (options->exit_on_first) {
      exit_early = true;
    }
  }
  while (cursor_actual < actual_record_count && !exit_early) {
    const bc_integrity_verify_record_t *actual_record =
        &actual_array[cursor_actual];
    if (stdout_writer_ready) {
      if (options->format == BC_INTEGRITY_OUTPUT_FORMAT_JSON) {
        (void)bc_integrity_verify_emit_change_json(
            &stdout_writer, BC_INTEGRITY_VERIFY_CHANGE_ADDED,
            actual_record->relative_path, actual_record->relative_path_length,
            NULL, &actual_record->snapshot);
      } else {
        (void)bc_integrity_verify_emit_change_text(
            &stdout_writer, BC_INTEGRITY_VERIFY_CHANGE_ADDED,
            actual_record->relative_path, actual_record->relative_path_length,
            NULL, &actual_record->snapshot);
      }
    }
    bc_integrity_verify_tally_change(BC_INTEGRITY_VERIFY_CHANGE_ADDED,
                                     &summary);
    change_count += 1;
    cursor_actual += 1;
    if (options->exit_on_first) {
      exit_early = true;
    }
  }

  if (stdout_writer_ready &&
      options->format == BC_INTEGRITY_OUTPUT_FORMAT_JSON) {
    summary.files_total = (uint64_t)expected_count;
    summary.changes_total = (uint64_t)change_count;
    summary.errors_count = (uint64_t)bc_runtime_error_collector_count(errors);
    uint64_t now_ms = 0;
    struct timespec monotonic_now;
    if (clock_gettime(CLOCK_MONOTONIC, &monotonic_now) == 0) {
      now_ms = (uint64_t)monotonic_now.tv_sec * 1000u +
               (uint64_t)(monotonic_now.tv_nsec / 1000000);
    }
    summary.wall_ms =
        (now_ms >= started_monotonic_ms) ? (now_ms - started_monotonic_ms) : 0;
    (void)bc_integrity_verify_emit_json_summary(&stdout_writer, &summary);
  }

  if (stdout_writer_ready) {
    (void)bc_core_writer_destroy(&stdout_writer);
  }

  if (expected_array != NULL) {
    bc_allocators_pool_free(memory_context, expected_array);
  }
  if (actual_array != NULL) {
    bc_allocators_pool_free(memory_context, actual_array);
  }
  bc_containers_vector_destroy(memory_context, actual_records);
  bc_containers_vector_destroy(memory_context, actual_entries);
  bc_containers_vector_destroy(memory_context, expected_records);
  bc_hrbl_reader_destroy(reader);

  *out_exit_code = (change_count == 0) ? BC_INTEGRITY_VERIFY_EXIT_OK
                                       : BC_INTEGRITY_VERIFY_EXIT_DIFF;
  return true;
}
