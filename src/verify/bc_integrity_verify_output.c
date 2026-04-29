// SPDX-License-Identifier: MIT

#include "bc_integrity_verify_internal.h"

#include "bc_core.h"
#include "bc_core_format.h"
#include "bc_core_io.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define BC_INTEGRITY_VERIFY_OUTPUT_TIMESTAMP_BUFFER_SIZE ((size_t)32)

static bool bc_integrity_verify_output_emit_field_uint64(
    bc_core_writer_t *writer, const char *relative_path,
    size_t relative_path_length, const char *field_name, uint64_t old_value,
    uint64_t new_value) {
  if (!bc_core_writer_write_cstring(writer, "~m ")) {
    return false;
  }
  if (!bc_core_writer_write_bytes(writer, relative_path,
                                  relative_path_length)) {
    return false;
  }
  if (!bc_core_writer_write_char(writer, ' ')) {
    return false;
  }
  if (!bc_core_writer_write_cstring(writer, field_name)) {
    return false;
  }
  if (!bc_core_writer_write_cstring(writer, ": ")) {
    return false;
  }
  if (!bc_core_writer_write_unsigned_integer_64_decimal(writer, old_value)) {
    return false;
  }
  if (!bc_core_writer_write_cstring(writer, "->")) {
    return false;
  }
  if (!bc_core_writer_write_unsigned_integer_64_decimal(writer, new_value)) {
    return false;
  }
  return bc_core_writer_write_char(writer, '\n');
}

static bool bc_integrity_verify_output_emit_field_string(
    bc_core_writer_t *writer, const char *relative_path,
    size_t relative_path_length, const char *field_name, const char *old_value,
    size_t old_length, const char *new_value, size_t new_length) {
  if (!bc_core_writer_write_cstring(writer, "~m ")) {
    return false;
  }
  if (!bc_core_writer_write_bytes(writer, relative_path,
                                  relative_path_length)) {
    return false;
  }
  if (!bc_core_writer_write_char(writer, ' ')) {
    return false;
  }
  if (!bc_core_writer_write_cstring(writer, field_name)) {
    return false;
  }
  if (!bc_core_writer_write_cstring(writer, ": ")) {
    return false;
  }
  if (old_length > 0) {
    if (!bc_core_writer_write_bytes(writer, old_value, old_length)) {
      return false;
    }
  } else {
    if (!bc_core_writer_write_cstring(writer, "(none)")) {
      return false;
    }
  }
  if (!bc_core_writer_write_cstring(writer, "->")) {
    return false;
  }
  if (new_length > 0) {
    if (!bc_core_writer_write_bytes(writer, new_value, new_length)) {
      return false;
    }
  } else {
    if (!bc_core_writer_write_cstring(writer, "(none)")) {
      return false;
    }
  }
  return bc_core_writer_write_char(writer, '\n');
}

static bool bc_integrity_verify_output_strings_equal_lengths(
    const char *left, size_t left_length, const char *right,
    size_t right_length) {
  if (left_length != right_length) {
    return false;
  }
  if (left_length == 0) {
    return true;
  }
  bool equal = false;
  (void)bc_core_equal(left, right, left_length, &equal);
  return equal;
}

static bool bc_integrity_verify_output_emit_meta_fields(
    bc_core_writer_t *writer, const char *relative_path,
    size_t relative_path_length, const bc_integrity_meta_snapshot_t *expected,
    const bc_integrity_meta_snapshot_t *actual) {
  if (expected->mode != actual->mode) {
    if (!bc_integrity_verify_output_emit_field_uint64(
            writer, relative_path, relative_path_length, "mode", expected->mode,
            actual->mode)) {
      return false;
    }
  }
  if (expected->uid != actual->uid) {
    if (!bc_integrity_verify_output_emit_field_uint64(
            writer, relative_path, relative_path_length, "uid", expected->uid,
            actual->uid)) {
      return false;
    }
  }
  if (expected->gid != actual->gid) {
    if (!bc_integrity_verify_output_emit_field_uint64(
            writer, relative_path, relative_path_length, "gid", expected->gid,
            actual->gid)) {
      return false;
    }
  }
  if (expected->mtime_sec != actual->mtime_sec) {
    if (!bc_integrity_verify_output_emit_field_uint64(
            writer, relative_path, relative_path_length, "mtime_sec",
            expected->mtime_sec, actual->mtime_sec)) {
      return false;
    }
  }
  if (expected->mtime_nsec != actual->mtime_nsec) {
    if (!bc_integrity_verify_output_emit_field_uint64(
            writer, relative_path, relative_path_length, "mtime_nsec",
            expected->mtime_nsec, actual->mtime_nsec)) {
      return false;
    }
  }
  if (expected->size_bytes != actual->size_bytes) {
    if (!bc_integrity_verify_output_emit_field_uint64(
            writer, relative_path, relative_path_length, "size_bytes",
            expected->size_bytes, actual->size_bytes)) {
      return false;
    }
  }
  if (expected->inode != actual->inode) {
    if (!bc_integrity_verify_output_emit_field_uint64(
            writer, relative_path, relative_path_length, "ino", expected->inode,
            actual->inode)) {
      return false;
    }
  }
  if (expected->nlink != actual->nlink) {
    if (!bc_integrity_verify_output_emit_field_uint64(
            writer, relative_path, relative_path_length, "nlink",
            expected->nlink, actual->nlink)) {
      return false;
    }
  }
  if (!bc_integrity_verify_output_strings_equal_lengths(
          expected->link_target, expected->link_target_length,
          actual->link_target, actual->link_target_length)) {
    if (!bc_integrity_verify_output_emit_field_string(
            writer, relative_path, relative_path_length, "link_target",
            expected->link_target, expected->link_target_length,
            actual->link_target, actual->link_target_length)) {
      return false;
    }
  }
  return true;
}

bool bc_integrity_verify_emit_change_text(
    bc_core_writer_t *writer, bc_integrity_verify_change_kind_t kind,
    const char *relative_path, size_t relative_path_length,
    const bc_integrity_meta_snapshot_t *expected,
    const bc_integrity_meta_snapshot_t *actual) {
  switch (kind) {
  case BC_INTEGRITY_VERIFY_CHANGE_ADDED:
    if (!bc_core_writer_write_cstring(writer, "+ ")) {
      return false;
    }
    if (!bc_core_writer_write_bytes(writer, relative_path,
                                    relative_path_length)) {
      return false;
    }
    return bc_core_writer_write_char(writer, '\n');
  case BC_INTEGRITY_VERIFY_CHANGE_REMOVED:
    if (!bc_core_writer_write_cstring(writer, "- ")) {
      return false;
    }
    if (!bc_core_writer_write_bytes(writer, relative_path,
                                    relative_path_length)) {
      return false;
    }
    return bc_core_writer_write_char(writer, '\n');
  case BC_INTEGRITY_VERIFY_CHANGE_CONTENT:
    if (!bc_core_writer_write_cstring(writer, "~c ")) {
      return false;
    }
    if (!bc_core_writer_write_bytes(writer, relative_path,
                                    relative_path_length)) {
      return false;
    }
    return bc_core_writer_write_char(writer, '\n');
  case BC_INTEGRITY_VERIFY_CHANGE_META:
    if (expected == NULL || actual == NULL) {
      return true;
    }
    return bc_integrity_verify_output_emit_meta_fields(
        writer, relative_path, relative_path_length, expected, actual);
  case BC_INTEGRITY_VERIFY_CHANGE_BOTH:
    if (!bc_core_writer_write_cstring(writer, "~* ")) {
      return false;
    }
    if (!bc_core_writer_write_bytes(writer, relative_path,
                                    relative_path_length)) {
      return false;
    }
    if (!bc_core_writer_write_char(writer, '\n')) {
      return false;
    }
    if (expected == NULL || actual == NULL) {
      return true;
    }
    return bc_integrity_verify_output_emit_meta_fields(
        writer, relative_path, relative_path_length, expected, actual);
  case BC_INTEGRITY_VERIFY_CHANGE_NONE:
  default:
    return true;
  }
}

static bool bc_integrity_verify_output_json_string_escape(
    bc_core_writer_t *writer, const char *value, size_t value_length) {
  if (!bc_core_writer_write_char(writer, '"')) {
    return false;
  }
  for (size_t index = 0; index < value_length; ++index) {
    unsigned char byte = (unsigned char)value[index];
    switch (byte) {
    case '"':
      if (!bc_core_writer_write_cstring(writer, "\\\"")) {
        return false;
      }
      break;
    case '\\':
      if (!bc_core_writer_write_cstring(writer, "\\\\")) {
        return false;
      }
      break;
    case '\n':
      if (!bc_core_writer_write_cstring(writer, "\\n")) {
        return false;
      }
      break;
    case '\r':
      if (!bc_core_writer_write_cstring(writer, "\\r")) {
        return false;
      }
      break;
    case '\t':
      if (!bc_core_writer_write_cstring(writer, "\\t")) {
        return false;
      }
      break;
    default:
      if (byte < 0x20u) {
        if (!bc_core_writer_write_unicode_codepoint_escape(writer,
                                                           (uint32_t)byte)) {
          return false;
        }
      } else {
        if (!bc_core_writer_write_char(writer, (char)byte)) {
          return false;
        }
      }
    }
  }
  return bc_core_writer_write_char(writer, '"');
}

static bool
bc_integrity_verify_output_json_string_cstring(bc_core_writer_t *writer,
                                               const char *value) {
  size_t length = 0;
  (void)bc_core_length(value, '\0', &length);
  return bc_integrity_verify_output_json_string_escape(writer, value, length);
}

static const char *bc_integrity_verify_output_change_label(
    bc_integrity_verify_change_kind_t kind) {
  switch (kind) {
  case BC_INTEGRITY_VERIFY_CHANGE_ADDED:
    return "added";
  case BC_INTEGRITY_VERIFY_CHANGE_REMOVED:
    return "removed";
  case BC_INTEGRITY_VERIFY_CHANGE_CONTENT:
    return "content";
  case BC_INTEGRITY_VERIFY_CHANGE_META:
    return "meta";
  case BC_INTEGRITY_VERIFY_CHANGE_BOTH:
    return "both";
  case BC_INTEGRITY_VERIFY_CHANGE_NONE:
  default:
    return "none";
  }
}

static bool bc_integrity_verify_output_emit_json_field_uint64_change(
    bc_core_writer_t *writer, const char *field_name, uint64_t old_value,
    uint64_t new_value, bool *first_field) {
  if (!*first_field) {
    if (!bc_core_writer_write_char(writer, ',')) {
      return false;
    }
  }
  *first_field = false;
  if (!bc_integrity_verify_output_json_string_cstring(writer, field_name)) {
    return false;
  }
  if (!bc_core_writer_write_cstring(writer, ":{\"old\":")) {
    return false;
  }
  if (!bc_core_writer_write_unsigned_integer_64_decimal(writer, old_value)) {
    return false;
  }
  if (!bc_core_writer_write_cstring(writer, ",\"new\":")) {
    return false;
  }
  if (!bc_core_writer_write_unsigned_integer_64_decimal(writer, new_value)) {
    return false;
  }
  return bc_core_writer_write_char(writer, '}');
}

static bool bc_integrity_verify_output_emit_json_field_string_change(
    bc_core_writer_t *writer, const char *field_name, const char *old_value,
    size_t old_length, const char *new_value, size_t new_length,
    bool *first_field) {
  if (!*first_field) {
    if (!bc_core_writer_write_char(writer, ',')) {
      return false;
    }
  }
  *first_field = false;
  if (!bc_integrity_verify_output_json_string_cstring(writer, field_name)) {
    return false;
  }
  if (!bc_core_writer_write_cstring(writer, ":{\"old\":")) {
    return false;
  }
  if (old_length > 0) {
    if (!bc_integrity_verify_output_json_string_escape(writer, old_value,
                                                       old_length)) {
      return false;
    }
  } else {
    if (!bc_core_writer_write_cstring(writer, "null")) {
      return false;
    }
  }
  if (!bc_core_writer_write_cstring(writer, ",\"new\":")) {
    return false;
  }
  if (new_length > 0) {
    if (!bc_integrity_verify_output_json_string_escape(writer, new_value,
                                                       new_length)) {
      return false;
    }
  } else {
    if (!bc_core_writer_write_cstring(writer, "null")) {
      return false;
    }
  }
  return bc_core_writer_write_char(writer, '}');
}

static bool bc_integrity_verify_output_emit_json_meta_changes(
    bc_core_writer_t *writer, const bc_integrity_meta_snapshot_t *expected,
    const bc_integrity_meta_snapshot_t *actual) {
  if (!bc_core_writer_write_cstring(writer, ",\"meta_changes\":{")) {
    return false;
  }
  bool first_field = true;
  if (expected->mode != actual->mode) {
    if (!bc_integrity_verify_output_emit_json_field_uint64_change(
            writer, "mode", expected->mode, actual->mode, &first_field)) {
      return false;
    }
  }
  if (expected->uid != actual->uid) {
    if (!bc_integrity_verify_output_emit_json_field_uint64_change(
            writer, "uid", expected->uid, actual->uid, &first_field)) {
      return false;
    }
  }
  if (expected->gid != actual->gid) {
    if (!bc_integrity_verify_output_emit_json_field_uint64_change(
            writer, "gid", expected->gid, actual->gid, &first_field)) {
      return false;
    }
  }
  if (expected->mtime_sec != actual->mtime_sec) {
    if (!bc_integrity_verify_output_emit_json_field_uint64_change(
            writer, "mtime_sec", expected->mtime_sec, actual->mtime_sec,
            &first_field)) {
      return false;
    }
  }
  if (expected->mtime_nsec != actual->mtime_nsec) {
    if (!bc_integrity_verify_output_emit_json_field_uint64_change(
            writer, "mtime_nsec", expected->mtime_nsec, actual->mtime_nsec,
            &first_field)) {
      return false;
    }
  }
  if (expected->size_bytes != actual->size_bytes) {
    if (!bc_integrity_verify_output_emit_json_field_uint64_change(
            writer, "size_bytes", expected->size_bytes, actual->size_bytes,
            &first_field)) {
      return false;
    }
  }
  if (expected->inode != actual->inode) {
    if (!bc_integrity_verify_output_emit_json_field_uint64_change(
            writer, "ino", expected->inode, actual->inode, &first_field)) {
      return false;
    }
  }
  if (expected->nlink != actual->nlink) {
    if (!bc_integrity_verify_output_emit_json_field_uint64_change(
            writer, "nlink", expected->nlink, actual->nlink, &first_field)) {
      return false;
    }
  }
  if (!bc_integrity_verify_output_strings_equal_lengths(
          expected->link_target, expected->link_target_length,
          actual->link_target, actual->link_target_length)) {
    if (!bc_integrity_verify_output_emit_json_field_string_change(
            writer, "link_target", expected->link_target,
            expected->link_target_length, actual->link_target,
            actual->link_target_length, &first_field)) {
      return false;
    }
  }
  return bc_core_writer_write_char(writer, '}');
}

bool bc_integrity_verify_emit_change_json(
    bc_core_writer_t *writer, bc_integrity_verify_change_kind_t kind,
    const char *relative_path, size_t relative_path_length,
    const bc_integrity_meta_snapshot_t *expected,
    const bc_integrity_meta_snapshot_t *actual) {
  if (!bc_core_writer_write_cstring(writer, "{\"type\":\"change\",\"path\":")) {
    return false;
  }
  if (!bc_integrity_verify_output_json_string_escape(writer, relative_path,
                                                     relative_path_length)) {
    return false;
  }
  if (!bc_core_writer_write_cstring(writer, ",\"change\":")) {
    return false;
  }
  if (!bc_integrity_verify_output_json_string_cstring(
          writer, bc_integrity_verify_output_change_label(kind))) {
    return false;
  }
  bool include_meta_changes = (kind == BC_INTEGRITY_VERIFY_CHANGE_META ||
                               kind == BC_INTEGRITY_VERIFY_CHANGE_BOTH) &&
                              expected != NULL && actual != NULL;
  if (include_meta_changes) {
    if (!bc_integrity_verify_output_emit_json_meta_changes(writer, expected,
                                                           actual)) {
      return false;
    }
  }
  if (kind == BC_INTEGRITY_VERIFY_CHANGE_CONTENT ||
      kind == BC_INTEGRITY_VERIFY_CHANGE_BOTH) {
    if (expected != NULL && expected->digest_hex_length > 0 && actual != NULL &&
        actual->digest_hex_length > 0) {
      if (!bc_core_writer_write_cstring(writer, ",\"digest\":{\"old\":")) {
        return false;
      }
      if (!bc_integrity_verify_output_json_string_escape(
              writer, expected->digest_hex, expected->digest_hex_length)) {
        return false;
      }
      if (!bc_core_writer_write_cstring(writer, ",\"new\":")) {
        return false;
      }
      if (!bc_integrity_verify_output_json_string_escape(
              writer, actual->digest_hex, actual->digest_hex_length)) {
        return false;
      }
      if (!bc_core_writer_write_char(writer, '}')) {
        return false;
      }
    }
  }
  return bc_core_writer_write_cstring(writer, "}\n");
}

static void bc_integrity_verify_output_format_timestamp(uint64_t unix_seconds,
                                                        char *out_buffer,
                                                        size_t buffer_size,
                                                        size_t *out_length) {
  time_t seconds = (time_t)unix_seconds;
  struct tm tm_utc;
  if (gmtime_r(&seconds, &tm_utc) == NULL) {
    static const char fallback[] = "1970-01-01T00:00:00Z";
    size_t fallback_length = sizeof(fallback) - 1U;
    if (fallback_length < buffer_size) {
      bc_core_copy(out_buffer, fallback, fallback_length);
      out_buffer[fallback_length] = '\0';
      *out_length = fallback_length;
      return;
    }
    *out_length = 0;
    return;
  }
  size_t formatted =
      strftime(out_buffer, buffer_size, "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
  *out_length = formatted;
}

bool bc_integrity_verify_emit_json_header(
    bc_core_writer_t *writer,
    const bc_integrity_verify_json_header_options_t *options) {
  if (!bc_core_writer_write_cstring(
          writer,
          "{\"type\":\"header\",\"tool\":\"bc-integrity\",\"schema_version\":1,"
          "\"command\":")) {
    return false;
  }
  if (!bc_integrity_verify_output_json_string_cstring(writer,
                                                      options->command)) {
    return false;
  }
  if (options->root_path != NULL) {
    if (!bc_core_writer_write_cstring(writer, ",\"root_path\":")) {
      return false;
    }
    if (!bc_integrity_verify_output_json_string_cstring(writer,
                                                        options->root_path)) {
      return false;
    }
  }
  if (options->manifest_path != NULL) {
    if (!bc_core_writer_write_cstring(writer, ",\"manifest_path\":")) {
      return false;
    }
    if (!bc_integrity_verify_output_json_string_cstring(
            writer, options->manifest_path)) {
      return false;
    }
  }
  if (options->manifest_path_a != NULL) {
    if (!bc_core_writer_write_cstring(writer, ",\"manifest_path_a\":")) {
      return false;
    }
    if (!bc_integrity_verify_output_json_string_cstring(
            writer, options->manifest_path_a)) {
      return false;
    }
  }
  if (options->manifest_path_b != NULL) {
    if (!bc_core_writer_write_cstring(writer, ",\"manifest_path_b\":")) {
      return false;
    }
    if (!bc_integrity_verify_output_json_string_cstring(
            writer, options->manifest_path_b)) {
      return false;
    }
  }
  if (options->mode != NULL) {
    if (!bc_core_writer_write_cstring(writer, ",\"mode\":")) {
      return false;
    }
    if (!bc_integrity_verify_output_json_string_cstring(writer,
                                                        options->mode)) {
      return false;
    }
  }
  if (options->digest_algorithm != NULL) {
    if (!bc_core_writer_write_cstring(writer, ",\"algorithm\":")) {
      return false;
    }
    if (!bc_integrity_verify_output_json_string_cstring(
            writer, options->digest_algorithm)) {
      return false;
    }
  }
  char timestamp_buffer[BC_INTEGRITY_VERIFY_OUTPUT_TIMESTAMP_BUFFER_SIZE];
  size_t timestamp_length = 0;
  bc_integrity_verify_output_format_timestamp(
      options->started_at_unix_sec, timestamp_buffer, sizeof(timestamp_buffer),
      &timestamp_length);
  if (!bc_core_writer_write_cstring(writer, ",\"started_at\":")) {
    return false;
  }
  if (!bc_integrity_verify_output_json_string_escape(writer, timestamp_buffer,
                                                     timestamp_length)) {
    return false;
  }
  return bc_core_writer_write_cstring(writer, "}\n");
}

bool bc_integrity_verify_emit_json_summary(
    bc_core_writer_t *writer,
    const bc_integrity_verify_json_summary_t *summary) {
  if (!bc_core_writer_write_cstring(writer,
                                    "{\"type\":\"summary\",\"files_total\":")) {
    return false;
  }
  if (!bc_core_writer_write_unsigned_integer_64_decimal(writer,
                                                        summary->files_total)) {
    return false;
  }
  if (!bc_core_writer_write_cstring(writer, ",\"changes_total\":")) {
    return false;
  }
  if (!bc_core_writer_write_unsigned_integer_64_decimal(
          writer, summary->changes_total)) {
    return false;
  }
  if (!bc_core_writer_write_cstring(writer, ",\"added\":")) {
    return false;
  }
  if (!bc_core_writer_write_unsigned_integer_64_decimal(writer,
                                                        summary->added)) {
    return false;
  }
  if (!bc_core_writer_write_cstring(writer, ",\"removed\":")) {
    return false;
  }
  if (!bc_core_writer_write_unsigned_integer_64_decimal(writer,
                                                        summary->removed)) {
    return false;
  }
  if (!bc_core_writer_write_cstring(writer, ",\"content\":")) {
    return false;
  }
  if (!bc_core_writer_write_unsigned_integer_64_decimal(writer,
                                                        summary->content)) {
    return false;
  }
  if (!bc_core_writer_write_cstring(writer, ",\"meta\":")) {
    return false;
  }
  if (!bc_core_writer_write_unsigned_integer_64_decimal(writer,
                                                        summary->meta)) {
    return false;
  }
  if (!bc_core_writer_write_cstring(writer, ",\"both\":")) {
    return false;
  }
  if (!bc_core_writer_write_unsigned_integer_64_decimal(writer,
                                                        summary->both)) {
    return false;
  }
  if (!bc_core_writer_write_cstring(writer, ",\"errors_count\":")) {
    return false;
  }
  if (!bc_core_writer_write_unsigned_integer_64_decimal(
          writer, summary->errors_count)) {
    return false;
  }
  if (!bc_core_writer_write_cstring(writer, ",\"wall_ms\":")) {
    return false;
  }
  if (!bc_core_writer_write_unsigned_integer_64_decimal(writer,
                                                        summary->wall_ms)) {
    return false;
  }
  return bc_core_writer_write_cstring(writer, "}\n");
}
