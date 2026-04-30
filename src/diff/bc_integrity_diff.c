// SPDX-License-Identifier: MIT

#include "bc_integrity_diff_internal.h"

#include "bc_integrity_verify_internal.h"

#include "bc_allocators.h"
#include "bc_allocators_pool.h"
#include "bc_containers_vector.h"
#include "bc_core.h"
#include "bc_core_io.h"
#include "bc_core_sort.h"
#include "bc_hrbl.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define BC_INTEGRITY_DIFF_EXIT_OK 0
#define BC_INTEGRITY_DIFF_EXIT_DIFF 1
#define BC_INTEGRITY_DIFF_EXIT_ERROR 2
#define BC_INTEGRITY_DIFF_STDOUT_BUFFER_BYTES ((size_t)(64 * 1024))
#define BC_INTEGRITY_DIFF_STDERR_BUFFER_BYTES ((size_t)512)
#define BC_INTEGRITY_DIFF_INITIAL_VECTOR_CAPACITY ((size_t)1024)
#define BC_INTEGRITY_DIFF_MAX_VECTOR_CAPACITY ((size_t)1U << 28)
#define BC_INTEGRITY_DIFF_KEY_BUFFER_SIZE ((size_t)4096)

typedef struct bc_integrity_diff_record {
    const char* relative_path;
    size_t relative_path_length;
    bc_integrity_meta_snapshot_t snapshot;
} bc_integrity_diff_record_t;

static void bc_integrity_diff_emit_stderr_quoted(const char* prefix, const char* value, const char* suffix)
{
    char buffer[BC_INTEGRITY_DIFF_STDERR_BUFFER_BYTES];
    bc_core_writer_t writer;
    if (!bc_core_writer_init_standard_error(&writer, buffer, sizeof(buffer))) {
        return;
    }
    (void)bc_core_writer_write_cstring(&writer, prefix);
    (void)bc_core_writer_write_cstring(&writer, value);
    (void)bc_core_writer_write_cstring(&writer, suffix);
    (void)bc_core_writer_destroy(&writer);
}

static int bc_integrity_diff_path_compare(const char* left, size_t left_length, const char* right, size_t right_length)
{
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

static bool bc_integrity_diff_record_less_than(const void* left_pointer, const void* right_pointer, void* user_data)
{
    (void)user_data;
    const bc_integrity_diff_record_t* left = (const bc_integrity_diff_record_t*)left_pointer;
    const bc_integrity_diff_record_t* right = (const bc_integrity_diff_record_t*)right_pointer;
    return bc_integrity_diff_path_compare(left->relative_path, left->relative_path_length, right->relative_path,
                                          right->relative_path_length) < 0;
}

static bc_integrity_entry_kind_t bc_integrity_diff_kind_from_name(const char* name, size_t length)
{
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

static bool bc_integrity_diff_path_needs_quoting(const char* path, size_t length)
{
    for (size_t index = 0; index < length; ++index) {
        char byte = path[index];
        if (!((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') || (byte >= '0' && byte <= '9') || byte == '_' || byte == '-')) {
            return true;
        }
    }
    return length == 0;
}

static bool bc_integrity_diff_clone_string(bc_allocators_context_t* memory_context, const char* value, size_t length, char** out_copy)
{
    char* copy = NULL;
    if (!bc_allocators_pool_allocate(memory_context, length + 1u, (void**)&copy)) {
        return false;
    }
    if (length > 0) {
        bc_core_copy(copy, value, length);
    }
    copy[length] = '\0';
    *out_copy = copy;
    return true;
}

static bool bc_integrity_diff_format_entry_key(char* buffer, size_t buffer_size, const char* path, size_t path_length, const char* suffix,
                                               size_t* out_length)
{
    size_t prefix_length = sizeof("entries.") - 1u;
    size_t suffix_length = 0;
    (void)bc_core_length(suffix, '\0', &suffix_length);
    bool needs_quoting = bc_integrity_diff_path_needs_quoting(path, path_length);
    size_t total = prefix_length + path_length + suffix_length;
    if (needs_quoting) {
        total += 2u;
    }
    if (total >= buffer_size) {
        return false;
    }
    size_t offset = 0;
    bc_core_copy(buffer + offset, "entries.", prefix_length);
    offset += prefix_length;
    if (needs_quoting) {
        buffer[offset++] = '\'';
    }
    if (path_length > 0) {
        bc_core_copy(buffer + offset, path, path_length);
        offset += path_length;
    }
    if (needs_quoting) {
        buffer[offset++] = '\'';
    }
    if (suffix_length > 0) {
        bc_core_copy(buffer + offset, suffix, suffix_length);
        offset += suffix_length;
    }
    buffer[offset] = '\0';
    *out_length = offset;
    return true;
}

static bool bc_integrity_diff_lookup_uint64(const bc_hrbl_reader_t* reader, const char* key, size_t key_length, uint64_t* out_value)
{
    bc_hrbl_value_ref_t value_ref;
    if (!bc_hrbl_reader_find(reader, key, key_length, &value_ref)) {
        return false;
    }
    return bc_hrbl_reader_get_uint64(&value_ref, out_value);
}

static bool bc_integrity_diff_lookup_string(const bc_hrbl_reader_t* reader, const char* key, size_t key_length, const char** out_value,
                                            size_t* out_length)
{
    bc_hrbl_value_ref_t value_ref;
    if (!bc_hrbl_reader_find(reader, key, key_length, &value_ref)) {
        return false;
    }
    return bc_hrbl_reader_get_string(&value_ref, out_value, out_length);
}

static bool bc_integrity_diff_load_record(bc_allocators_context_t* memory_context, const bc_hrbl_reader_t* reader,
                                          const char* relative_path, size_t relative_path_length, bc_integrity_diff_record_t* out_record)
{
    char key_buffer[BC_INTEGRITY_DIFF_KEY_BUFFER_SIZE];
    size_t key_length = 0;

    out_record->relative_path = relative_path;
    out_record->relative_path_length = relative_path_length;
    out_record->snapshot.present = true;

    if (!bc_integrity_diff_format_entry_key(key_buffer, sizeof(key_buffer), relative_path, relative_path_length, ".kind", &key_length)) {
        return false;
    }
    const char* kind_value = NULL;
    size_t kind_length = 0;
    if (bc_integrity_diff_lookup_string(reader, key_buffer, key_length, &kind_value, &kind_length)) {
        out_record->snapshot.kind = bc_integrity_diff_kind_from_name(kind_value, kind_length);
    }

    uint64_t value_u64 = 0;
    (void)bc_integrity_diff_format_entry_key(key_buffer, sizeof(key_buffer), relative_path, relative_path_length, ".size_bytes",
                                             &key_length);
    if (bc_integrity_diff_lookup_uint64(reader, key_buffer, key_length, &value_u64)) {
        out_record->snapshot.size_bytes = value_u64;
    }
    (void)bc_integrity_diff_format_entry_key(key_buffer, sizeof(key_buffer), relative_path, relative_path_length, ".mode", &key_length);
    if (bc_integrity_diff_lookup_uint64(reader, key_buffer, key_length, &value_u64)) {
        out_record->snapshot.mode = value_u64;
    }
    (void)bc_integrity_diff_format_entry_key(key_buffer, sizeof(key_buffer), relative_path, relative_path_length, ".uid", &key_length);
    if (bc_integrity_diff_lookup_uint64(reader, key_buffer, key_length, &value_u64)) {
        out_record->snapshot.uid = value_u64;
    }
    (void)bc_integrity_diff_format_entry_key(key_buffer, sizeof(key_buffer), relative_path, relative_path_length, ".gid", &key_length);
    if (bc_integrity_diff_lookup_uint64(reader, key_buffer, key_length, &value_u64)) {
        out_record->snapshot.gid = value_u64;
    }
    (void)bc_integrity_diff_format_entry_key(key_buffer, sizeof(key_buffer), relative_path, relative_path_length, ".mtime_sec",
                                             &key_length);
    if (bc_integrity_diff_lookup_uint64(reader, key_buffer, key_length, &value_u64)) {
        out_record->snapshot.mtime_sec = value_u64;
    }
    (void)bc_integrity_diff_format_entry_key(key_buffer, sizeof(key_buffer), relative_path, relative_path_length, ".mtime_nsec",
                                             &key_length);
    if (bc_integrity_diff_lookup_uint64(reader, key_buffer, key_length, &value_u64)) {
        out_record->snapshot.mtime_nsec = value_u64;
    }
    (void)bc_integrity_diff_format_entry_key(key_buffer, sizeof(key_buffer), relative_path, relative_path_length, ".ino", &key_length);
    if (bc_integrity_diff_lookup_uint64(reader, key_buffer, key_length, &value_u64)) {
        out_record->snapshot.inode = value_u64;
    }
    (void)bc_integrity_diff_format_entry_key(key_buffer, sizeof(key_buffer), relative_path, relative_path_length, ".nlink", &key_length);
    if (bc_integrity_diff_lookup_uint64(reader, key_buffer, key_length, &value_u64)) {
        out_record->snapshot.nlink = value_u64;
    }

    (void)bc_integrity_diff_format_entry_key(key_buffer, sizeof(key_buffer), relative_path, relative_path_length, ".digest_hex",
                                             &key_length);
    const char* string_value = NULL;
    size_t string_length = 0;
    if (bc_integrity_diff_lookup_string(reader, key_buffer, key_length, &string_value, &string_length)) {
        char* copy = NULL;
        if (!bc_integrity_diff_clone_string(memory_context, string_value, string_length, &copy)) {
            return false;
        }
        out_record->snapshot.digest_hex = copy;
        out_record->snapshot.digest_hex_length = string_length;
    }

    (void)bc_integrity_diff_format_entry_key(key_buffer, sizeof(key_buffer), relative_path, relative_path_length, ".link_target",
                                             &key_length);
    if (bc_integrity_diff_lookup_string(reader, key_buffer, key_length, &string_value, &string_length)) {
        char* copy = NULL;
        if (!bc_integrity_diff_clone_string(memory_context, string_value, string_length, &copy)) {
            return false;
        }
        out_record->snapshot.link_target = copy;
        out_record->snapshot.link_target_length = string_length;
    }

    return true;
}

static bool bc_integrity_diff_collect_recursive(bc_allocators_context_t* memory_context, const bc_hrbl_reader_t* reader,
                                                const bc_hrbl_value_ref_t* block, const char* path_prefix, size_t path_prefix_length,
                                                bc_containers_vector_t* destination)
{
    bc_hrbl_iter_t iter;
    if (!bc_hrbl_reader_iter_block(block, &iter)) {
        return true;
    }
    bc_hrbl_value_ref_t value;
    const char* key = NULL;
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
        char* combined = NULL;
        if (!bc_allocators_pool_allocate(memory_context, combined_length + 1u, (void**)&combined)) {
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

        bc_integrity_diff_record_t record;
        bc_core_zero(&record, sizeof(record));
        if (!bc_integrity_diff_load_record(memory_context, reader, combined, combined_length, &record)) {
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

static bool bc_integrity_diff_collect_entries(bc_allocators_context_t* memory_context, const bc_hrbl_reader_t* reader,
                                              bc_containers_vector_t* destination)
{
    bc_hrbl_value_ref_t entries_ref;
    if (!bc_hrbl_reader_find(reader, "entries", sizeof("entries") - 1u, &entries_ref)) {
        return true;
    }
    return bc_integrity_diff_collect_recursive(memory_context, reader, &entries_ref, NULL, 0, destination);
}

static bool bc_integrity_diff_load_side(bc_allocators_context_t* memory_context, const char* manifest_path, bc_hrbl_reader_t** out_reader,
                                        bc_integrity_diff_record_t** out_array, size_t* out_count)
{
    bc_hrbl_verify_status_t verify_status = bc_hrbl_verify_file(manifest_path);
    if (verify_status != BC_HRBL_VERIFY_OK) {
        bc_integrity_diff_emit_stderr_quoted("bc-integrity: diff: invalid manifest '", manifest_path, "'\n");
        return false;
    }
    if (!bc_hrbl_reader_open(memory_context, manifest_path, out_reader)) {
        bc_integrity_diff_emit_stderr_quoted("bc-integrity: diff: cannot open manifest '", manifest_path, "'\n");
        return false;
    }
    bc_containers_vector_t* vector = NULL;
    if (!bc_containers_vector_create(memory_context, sizeof(bc_integrity_diff_record_t), BC_INTEGRITY_DIFF_INITIAL_VECTOR_CAPACITY,
                                     BC_INTEGRITY_DIFF_MAX_VECTOR_CAPACITY, &vector)) {
        bc_hrbl_reader_close(*out_reader);
        *out_reader = NULL;
        return false;
    }
    if (!bc_integrity_diff_collect_entries(memory_context, *out_reader, vector)) {
        bc_containers_vector_destroy(memory_context, vector);
        bc_hrbl_reader_close(*out_reader);
        *out_reader = NULL;
        return false;
    }
    size_t count = bc_containers_vector_length(vector);
    bc_integrity_diff_record_t* array = NULL;
    if (count > 0) {
        if (!bc_allocators_pool_allocate(memory_context, count * sizeof(bc_integrity_diff_record_t), (void**)&array)) {
            bc_containers_vector_destroy(memory_context, vector);
            bc_hrbl_reader_close(*out_reader);
            *out_reader = NULL;
            return false;
        }
        for (size_t index = 0; index < count; ++index) {
            (void)bc_containers_vector_get(vector, index, &array[index]);
        }
    }
    bc_containers_vector_destroy(memory_context, vector);
    if (count > 1) {
        bc_core_sort_with_compare(array, count, sizeof(bc_integrity_diff_record_t), bc_integrity_diff_record_less_than, NULL);
    }
    *out_array = array;
    *out_count = count;
    return true;
}

static bc_integrity_verify_change_kind_t bc_integrity_diff_classify(const bc_integrity_diff_options_t* options,
                                                                    const bc_integrity_meta_snapshot_t* expected,
                                                                    const bc_integrity_meta_snapshot_t* actual)
{
    bc_integrity_verify_change_kind_t content_change = bc_integrity_verify_compare_content(expected, actual);
    bc_integrity_verify_change_kind_t meta_change = bc_integrity_verify_compare_meta(expected, actual, options->ignore_mtime);
    bool content_diff = content_change != BC_INTEGRITY_VERIFY_CHANGE_NONE;
    bool meta_diff = meta_change != BC_INTEGRITY_VERIFY_CHANGE_NONE;
    if (options->ignore_meta) {
        meta_diff = false;
    }
    if (content_diff && meta_diff) {
        return BC_INTEGRITY_VERIFY_CHANGE_BOTH;
    }
    if (content_diff) {
        return BC_INTEGRITY_VERIFY_CHANGE_CONTENT;
    }
    if (meta_diff) {
        return BC_INTEGRITY_VERIFY_CHANGE_META;
    }
    return BC_INTEGRITY_VERIFY_CHANGE_NONE;
}

bool bc_integrity_diff_run(bc_allocators_context_t* memory_context, const bc_integrity_diff_options_t* options, int* out_exit_code)
{
    bc_hrbl_reader_t* reader_a = NULL;
    bc_hrbl_reader_t* reader_b = NULL;
    bc_integrity_diff_record_t* records_a = NULL;
    bc_integrity_diff_record_t* records_b = NULL;
    size_t count_a = 0;
    size_t count_b = 0;

    if (!bc_integrity_diff_load_side(memory_context, options->manifest_path_a, &reader_a, &records_a, &count_a)) {
        *out_exit_code = BC_INTEGRITY_DIFF_EXIT_ERROR;
        return true;
    }
    if (!bc_integrity_diff_load_side(memory_context, options->manifest_path_b, &reader_b, &records_b, &count_b)) {
        if (records_a != NULL) {
            bc_allocators_pool_free(memory_context, records_a);
        }
        bc_hrbl_reader_close(reader_a);
        *out_exit_code = BC_INTEGRITY_DIFF_EXIT_ERROR;
        return true;
    }

    char stdout_buffer[BC_INTEGRITY_DIFF_STDOUT_BUFFER_BYTES];
    bc_core_writer_t stdout_writer;
    bool stdout_writer_ready = bc_core_writer_init_standard_output(&stdout_writer, stdout_buffer, sizeof(stdout_buffer));

    uint64_t started_at_unix_sec = 0;
    uint64_t started_monotonic_ms = 0;
    {
        struct timespec realtime_now;
        if (clock_gettime(CLOCK_REALTIME, &realtime_now) == 0) {
            started_at_unix_sec = (uint64_t)realtime_now.tv_sec;
        }
        struct timespec monotonic_now;
        if (clock_gettime(CLOCK_MONOTONIC, &monotonic_now) == 0) {
            started_monotonic_ms = (uint64_t)monotonic_now.tv_sec * 1000u + (uint64_t)(monotonic_now.tv_nsec / 1000000);
        }
    }

    if (stdout_writer_ready && options->format == BC_INTEGRITY_OUTPUT_FORMAT_JSON) {
        bc_integrity_verify_json_header_options_t header_options;
        bc_core_zero(&header_options, sizeof(header_options));
        header_options.command = "diff";
        header_options.manifest_path_a = options->manifest_path_a;
        header_options.manifest_path_b = options->manifest_path_b;
        header_options.started_at_unix_sec = started_at_unix_sec;
        (void)bc_integrity_verify_emit_json_header(&stdout_writer, &header_options);
    }

    bc_integrity_verify_json_summary_t summary;
    bc_core_zero(&summary, sizeof(summary));

    size_t change_count = 0;
    size_t cursor_a = 0;
    size_t cursor_b = 0;
    while (cursor_a < count_a && cursor_b < count_b) {
        const bc_integrity_diff_record_t* left = &records_a[cursor_a];
        const bc_integrity_diff_record_t* right = &records_b[cursor_b];
        int comparison = bc_integrity_diff_path_compare(left->relative_path, left->relative_path_length, right->relative_path,
                                                        right->relative_path_length);
        if (comparison < 0) {
            if (stdout_writer_ready) {
                if (options->format == BC_INTEGRITY_OUTPUT_FORMAT_JSON) {
                    (void)bc_integrity_verify_emit_change_json(&stdout_writer, BC_INTEGRITY_VERIFY_CHANGE_REMOVED, left->relative_path,
                                                               left->relative_path_length, &left->snapshot, NULL);
                } else {
                    (void)bc_integrity_verify_emit_change_text(&stdout_writer, BC_INTEGRITY_VERIFY_CHANGE_REMOVED, left->relative_path,
                                                               left->relative_path_length, &left->snapshot, NULL);
                }
            }
            summary.removed += 1u;
            change_count += 1;
            cursor_a += 1;
        } else if (comparison > 0) {
            if (stdout_writer_ready) {
                if (options->format == BC_INTEGRITY_OUTPUT_FORMAT_JSON) {
                    (void)bc_integrity_verify_emit_change_json(&stdout_writer, BC_INTEGRITY_VERIFY_CHANGE_ADDED, right->relative_path,
                                                               right->relative_path_length, NULL, &right->snapshot);
                } else {
                    (void)bc_integrity_verify_emit_change_text(&stdout_writer, BC_INTEGRITY_VERIFY_CHANGE_ADDED, right->relative_path,
                                                               right->relative_path_length, NULL, &right->snapshot);
                }
            }
            summary.added += 1u;
            change_count += 1;
            cursor_b += 1;
        } else {
            bc_integrity_verify_change_kind_t change = bc_integrity_diff_classify(options, &left->snapshot, &right->snapshot);
            if (change != BC_INTEGRITY_VERIFY_CHANGE_NONE) {
                if (stdout_writer_ready) {
                    if (options->format == BC_INTEGRITY_OUTPUT_FORMAT_JSON) {
                        (void)bc_integrity_verify_emit_change_json(&stdout_writer, change, left->relative_path, left->relative_path_length,
                                                                   &left->snapshot, &right->snapshot);
                    } else {
                        (void)bc_integrity_verify_emit_change_text(&stdout_writer, change, left->relative_path, left->relative_path_length,
                                                                   &left->snapshot, &right->snapshot);
                    }
                }
                if (change == BC_INTEGRITY_VERIFY_CHANGE_CONTENT) {
                    summary.content += 1u;
                } else if (change == BC_INTEGRITY_VERIFY_CHANGE_META) {
                    summary.meta += 1u;
                } else if (change == BC_INTEGRITY_VERIFY_CHANGE_BOTH) {
                    summary.both += 1u;
                }
                change_count += 1;
            }
            cursor_a += 1;
            cursor_b += 1;
        }
    }
    while (cursor_a < count_a) {
        const bc_integrity_diff_record_t* left = &records_a[cursor_a];
        if (stdout_writer_ready) {
            if (options->format == BC_INTEGRITY_OUTPUT_FORMAT_JSON) {
                (void)bc_integrity_verify_emit_change_json(&stdout_writer, BC_INTEGRITY_VERIFY_CHANGE_REMOVED, left->relative_path,
                                                           left->relative_path_length, &left->snapshot, NULL);
            } else {
                (void)bc_integrity_verify_emit_change_text(&stdout_writer, BC_INTEGRITY_VERIFY_CHANGE_REMOVED, left->relative_path,
                                                           left->relative_path_length, &left->snapshot, NULL);
            }
        }
        summary.removed += 1u;
        change_count += 1;
        cursor_a += 1;
    }
    while (cursor_b < count_b) {
        const bc_integrity_diff_record_t* right = &records_b[cursor_b];
        if (stdout_writer_ready) {
            if (options->format == BC_INTEGRITY_OUTPUT_FORMAT_JSON) {
                (void)bc_integrity_verify_emit_change_json(&stdout_writer, BC_INTEGRITY_VERIFY_CHANGE_ADDED, right->relative_path,
                                                           right->relative_path_length, NULL, &right->snapshot);
            } else {
                (void)bc_integrity_verify_emit_change_text(&stdout_writer, BC_INTEGRITY_VERIFY_CHANGE_ADDED, right->relative_path,
                                                           right->relative_path_length, NULL, &right->snapshot);
            }
        }
        summary.added += 1u;
        change_count += 1;
        cursor_b += 1;
    }

    if (stdout_writer_ready && options->format == BC_INTEGRITY_OUTPUT_FORMAT_JSON) {
        summary.files_total = (uint64_t)((count_a > count_b) ? count_a : count_b);
        summary.changes_total = (uint64_t)change_count;
        uint64_t now_ms = 0;
        struct timespec monotonic_now;
        if (clock_gettime(CLOCK_MONOTONIC, &monotonic_now) == 0) {
            now_ms = (uint64_t)monotonic_now.tv_sec * 1000u + (uint64_t)(monotonic_now.tv_nsec / 1000000);
        }
        summary.wall_ms = (now_ms >= started_monotonic_ms) ? (now_ms - started_monotonic_ms) : 0;
        (void)bc_integrity_verify_emit_json_summary(&stdout_writer, &summary);
    }

    if (stdout_writer_ready) {
        (void)bc_core_writer_destroy(&stdout_writer);
    }

    if (records_a != NULL) {
        bc_allocators_pool_free(memory_context, records_a);
    }
    if (records_b != NULL) {
        bc_allocators_pool_free(memory_context, records_b);
    }
    bc_hrbl_reader_close(reader_a);
    bc_hrbl_reader_close(reader_b);

    *out_exit_code = (change_count == 0) ? BC_INTEGRITY_DIFF_EXIT_OK : BC_INTEGRITY_DIFF_EXIT_DIFF;
    return true;
}
