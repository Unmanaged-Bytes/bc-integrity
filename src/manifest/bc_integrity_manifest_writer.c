// SPDX-License-Identifier: MIT

#include "bc_integrity_manifest_internal.h"

#include "bc_integrity_cli_internal.h"
#include "bc_integrity_entry_internal.h"

#include "bc_allocators.h"
#include "bc_containers_vector.h"
#include "bc_core.h"
#include "bc_core_io.h"
#include "bc_hrbl.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BC_INTEGRITY_MANIFEST_SCHEMA_VERSION UINT64_C(1)
#define BC_INTEGRITY_MANIFEST_TOOL_NAME "bc-integrity"
#define BC_INTEGRITY_MANIFEST_STDERR_BUFFER_BYTES ((size_t)256)

#ifndef BC_INTEGRITY_VERSION_STRING
#define BC_INTEGRITY_VERSION_STRING "0.0.0-unversioned"
#endif

static void bc_integrity_manifest_emit_stderr(const char *message) {
  char buffer[BC_INTEGRITY_MANIFEST_STDERR_BUFFER_BYTES];
  bc_core_writer_t writer;
  if (!bc_core_writer_init_standard_error(&writer, buffer, sizeof(buffer))) {
    return;
  }
  (void)bc_core_writer_write_cstring(&writer, message);
  (void)bc_core_writer_destroy(&writer);
}

static size_t bc_integrity_manifest_cstr_length(const char *value) {
  size_t length = 0;
  (void)bc_core_length(value, '\0', &length);
  return length;
}

static bool bc_integrity_manifest_set_string(bc_hrbl_writer_t *writer,
                                             const char *key,
                                             const char *value) {
  return bc_hrbl_writer_set_string(
      writer, key, bc_integrity_manifest_cstr_length(key), value,
      bc_integrity_manifest_cstr_length(value));
}

static bool bc_integrity_manifest_set_uint64(bc_hrbl_writer_t *writer,
                                             const char *key, uint64_t value) {
  return bc_hrbl_writer_set_uint64(
      writer, key, bc_integrity_manifest_cstr_length(key), value);
}

static bool bc_integrity_manifest_set_int64(bc_hrbl_writer_t *writer,
                                            const char *key, int64_t value) {
  return bc_hrbl_writer_set_int64(
      writer, key, bc_integrity_manifest_cstr_length(key), value);
}

static bool bc_integrity_manifest_set_bool(bc_hrbl_writer_t *writer,
                                           const char *key, bool value) {
  return bc_hrbl_writer_set_bool(writer, key,
                                 bc_integrity_manifest_cstr_length(key), value);
}

static bool bc_integrity_manifest_begin_block_named(bc_hrbl_writer_t *writer,
                                                    const char *key) {
  return bc_hrbl_writer_begin_block(writer, key,
                                    bc_integrity_manifest_cstr_length(key));
}

static bool bc_integrity_manifest_write_meta(
    bc_hrbl_writer_t *writer, const bc_integrity_manifest_options_t *options,
    const bc_integrity_manifest_summary_t *summary) {
  if (!bc_integrity_manifest_begin_block_named(writer, "meta")) {
    return false;
  }
  if (!bc_integrity_manifest_set_uint64(writer, "schema_version",
                                        BC_INTEGRITY_MANIFEST_SCHEMA_VERSION)) {
    return false;
  }
  if (!bc_integrity_manifest_set_string(writer, "tool",
                                        BC_INTEGRITY_MANIFEST_TOOL_NAME)) {
    return false;
  }
  if (!bc_integrity_manifest_set_string(writer, "tool_version",
                                        BC_INTEGRITY_VERSION_STRING)) {
    return false;
  }
  if (!bc_integrity_manifest_set_uint64(writer, "created_at_unix_sec",
                                        summary->created_at_unix_sec)) {
    return false;
  }
  if (!bc_integrity_manifest_set_string(
          writer, "host", summary->host != NULL ? summary->host : "unknown")) {
    return false;
  }
  if (!bc_integrity_manifest_set_string(writer, "root_path",
                                        summary->root_path_absolute != NULL
                                            ? summary->root_path_absolute
                                            : options->root_path)) {
    return false;
  }
  if (!bc_integrity_manifest_set_string(
          writer, "digest_algorithm",
          bc_integrity_cli_digest_algorithm_name(options->digest_algorithm))) {
    return false;
  }
  if (!bc_integrity_manifest_set_uint64(writer, "file_count",
                                        summary->file_count)) {
    return false;
  }
  if (!bc_integrity_manifest_set_uint64(writer, "dir_count",
                                        summary->directory_count)) {
    return false;
  }
  if (!bc_integrity_manifest_set_uint64(writer, "symlink_count",
                                        summary->symlink_count)) {
    return false;
  }
  if (!bc_integrity_manifest_set_uint64(writer, "total_bytes",
                                        summary->total_bytes)) {
    return false;
  }

  if (!bc_integrity_manifest_begin_block_named(writer, "walk_options")) {
    return false;
  }
  if (!bc_integrity_manifest_set_bool(writer, "follow_symlinks",
                                      options->follow_symlinks)) {
    return false;
  }
  if (!bc_integrity_manifest_set_bool(writer, "include_hidden",
                                      options->include_hidden)) {
    return false;
  }
  if (!bc_integrity_manifest_set_bool(writer, "include_special",
                                      options->include_special)) {
    return false;
  }
  if (!bc_integrity_manifest_set_bool(writer, "default_exclude_virtual",
                                      options->default_exclude_virtual)) {
    return false;
  }
  if (!bc_hrbl_writer_end_block(writer)) {
    return false;
  }

  return bc_hrbl_writer_end_block(writer);
}

static bool
bc_integrity_manifest_write_entry(bc_hrbl_writer_t *writer,
                                  const bc_integrity_entry_t *entry) {
  if (!bc_hrbl_writer_begin_block(writer, entry->relative_path,
                                  entry->relative_path_length)) {
    return false;
  }
  if (!bc_integrity_manifest_set_string(
          writer, "kind", bc_integrity_entry_kind_name(entry->kind))) {
    return false;
  }
  if (!bc_integrity_manifest_set_bool(writer, "ok", entry->ok)) {
    return false;
  }
  if (entry->ok) {
    if (entry->kind == BC_INTEGRITY_ENTRY_KIND_FILE &&
        entry->digest_hex_length > 0) {
      if (!bc_hrbl_writer_set_string(
              writer, "digest_hex",
              bc_integrity_manifest_cstr_length("digest_hex"),
              entry->digest_hex, entry->digest_hex_length)) {
        return false;
      }
    }
    if (entry->kind == BC_INTEGRITY_ENTRY_KIND_SYMLINK &&
        entry->link_target != NULL) {
      if (!bc_hrbl_writer_set_string(
              writer, "link_target",
              bc_integrity_manifest_cstr_length("link_target"),
              entry->link_target, entry->link_target_length)) {
        return false;
      }
    }
  } else {
    if (!bc_integrity_manifest_set_int64(writer, "errno",
                                         (int64_t)entry->errno_value)) {
      return false;
    }
    if (entry->error_message_length > 0) {
      if (!bc_hrbl_writer_set_string(
              writer, "error_message",
              bc_integrity_manifest_cstr_length("error_message"),
              entry->error_message, entry->error_message_length)) {
        return false;
      }
    }
  }

  if (!bc_integrity_manifest_set_uint64(writer, "size_bytes",
                                        entry->size_bytes)) {
    return false;
  }
  if (!bc_integrity_manifest_set_uint64(writer, "mode", entry->mode)) {
    return false;
  }
  if (!bc_integrity_manifest_set_uint64(writer, "uid", entry->uid)) {
    return false;
  }
  if (!bc_integrity_manifest_set_uint64(writer, "gid", entry->gid)) {
    return false;
  }
  if (!bc_integrity_manifest_set_uint64(writer, "mtime_sec",
                                        entry->mtime_sec)) {
    return false;
  }
  if (!bc_integrity_manifest_set_uint64(writer, "mtime_nsec",
                                        entry->mtime_nsec)) {
    return false;
  }
  if (!bc_integrity_manifest_set_uint64(writer, "ino", entry->inode)) {
    return false;
  }
  if (!bc_integrity_manifest_set_uint64(writer, "nlink", entry->nlink)) {
    return false;
  }

  return bc_hrbl_writer_end_block(writer);
}

static bool bc_integrity_manifest_write_summary(
    bc_hrbl_writer_t *writer, const bc_integrity_manifest_summary_t *summary) {
  if (!bc_integrity_manifest_begin_block_named(writer, "summary")) {
    return false;
  }
  if (!bc_integrity_manifest_set_uint64(writer, "completed_at_unix_sec",
                                        summary->completed_at_unix_sec)) {
    return false;
  }
  if (!bc_integrity_manifest_set_uint64(writer, "walltime_ms",
                                        summary->walltime_ms)) {
    return false;
  }
  if (!bc_integrity_manifest_set_uint64(writer, "errors_count",
                                        summary->errors_count)) {
    return false;
  }
  return bc_hrbl_writer_end_block(writer);
}

bool bc_integrity_manifest_write_to_file(
    bc_allocators_context_t *memory_context,
    const bc_integrity_manifest_options_t *options,
    const bc_containers_vector_t *entries,
    const bc_integrity_manifest_summary_t *summary, const char *output_path) {
  bc_hrbl_writer_t *writer = NULL;
  if (!bc_hrbl_writer_create(memory_context, &writer)) {
    bc_integrity_manifest_emit_stderr(
        "bc-integrity: failed to create hrbl writer\n");
    return false;
  }

  bool success = false;

  if (!bc_integrity_manifest_write_meta(writer, options, summary)) {
    goto cleanup;
  }

  if (!bc_integrity_manifest_begin_block_named(writer, "entries")) {
    goto cleanup;
  }
  size_t entry_count = bc_containers_vector_length(entries);
  for (size_t entry_index = 0; entry_index < entry_count; ++entry_index) {
    bc_integrity_entry_t entry;
    if (!bc_containers_vector_get(entries, entry_index, &entry)) {
      goto cleanup;
    }
    if (entry.relative_path_length == 0) {
      continue;
    }
    if (!bc_integrity_manifest_write_entry(writer, &entry)) {
      goto cleanup;
    }
  }
  if (!bc_hrbl_writer_end_block(writer)) {
    goto cleanup;
  }

  if (!bc_integrity_manifest_write_summary(writer, summary)) {
    goto cleanup;
  }

  if (!bc_hrbl_writer_finalize_to_file(writer, output_path)) {
    bc_integrity_manifest_emit_stderr(
        "bc-integrity: failed to finalize manifest to file\n");
    goto cleanup;
  }
  success = true;

cleanup:
  bc_hrbl_writer_destroy(writer);
  return success;
}
