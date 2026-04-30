// SPDX-License-Identifier: MIT

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include "bc_allocators.h"
#include "bc_containers_vector.h"
#include "bc_hrbl.h"
#include "bc_integrity_cli_internal.h"
#include "bc_integrity_diff_internal.h"
#include "bc_integrity_entry_internal.h"
#include "bc_integrity_manifest_internal.h"

typedef struct fixture_state {
    char manifest_path_a[256];
    char manifest_path_b[256];
    bc_allocators_context_t* memory_context;
} fixture_state_t;

static int fixture_setup(void** state)
{
    fixture_state_t* fixture = malloc(sizeof(*fixture));
    if (fixture == NULL) {
        return -1;
    }
    snprintf(fixture->manifest_path_a, sizeof(fixture->manifest_path_a), "/tmp/bc_integrity_diff_ext_%d_a.hrbl", getpid());
    snprintf(fixture->manifest_path_b, sizeof(fixture->manifest_path_b), "/tmp/bc_integrity_diff_ext_%d_b.hrbl", getpid());
    bc_allocators_context_config_t config = {.tracking_enabled = true};
    fixture->memory_context = NULL;
    bc_allocators_context_create(&config, &fixture->memory_context);
    *state = fixture;
    return 0;
}

static int fixture_teardown(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    bc_allocators_context_destroy(fixture->memory_context);
    unlink(fixture->manifest_path_a);
    unlink(fixture->manifest_path_b);
    free(fixture);
    return 0;
}

static void make_file_entry(bc_integrity_entry_t* entry, const char* path, const char* digest_hex, uint64_t mode, uint64_t mtime_sec)
{
    memset(entry, 0, sizeof(*entry));
    entry->relative_path = path;
    entry->relative_path_length = strlen(path);
    entry->kind = BC_INTEGRITY_ENTRY_KIND_FILE;
    entry->ok = true;
    entry->size_bytes = 32;
    entry->mode = mode;
    entry->uid = 1000;
    entry->gid = 1000;
    entry->mtime_sec = mtime_sec;
    entry->mtime_nsec = 0;
    entry->inode = (uint64_t)(100 + (unsigned char)path[0]);
    entry->nlink = 1;
    size_t digest_length = strlen(digest_hex);
    memcpy(entry->digest_hex, digest_hex, digest_length);
    entry->digest_hex[digest_length] = '\0';
    entry->digest_hex_length = digest_length;
}

static void write_manifest(bc_allocators_context_t* memory_context, const char* output_path, bc_integrity_entry_t* entries_array,
                           size_t entries_count, bc_integrity_digest_algorithm_t algorithm)
{
    bc_containers_vector_t* entries = NULL;
    bc_containers_vector_create(memory_context, sizeof(bc_integrity_entry_t), 8, 4096, &entries);
    for (size_t index = 0; index < entries_count; ++index) {
        bc_containers_vector_push(memory_context, entries, &entries_array[index]);
    }
    bc_integrity_manifest_options_t options;
    memset(&options, 0, sizeof(options));
    options.root_path = "/tmp/dummy";
    options.output_path = output_path;
    options.digest_algorithm = algorithm;
    options.default_exclude_virtual = true;

    bc_integrity_manifest_summary_t summary;
    memset(&summary, 0, sizeof(summary));
    summary.created_at_unix_sec = 1700000000;
    summary.completed_at_unix_sec = 1700000005;
    summary.file_count = entries_count;
    summary.host = "test";
    summary.root_path_absolute = "/tmp/dummy";

    assert_true(bc_integrity_manifest_write_to_file(memory_context, &options, entries, &summary, output_path));
    bc_containers_vector_destroy(memory_context, entries);
}

static int run_diff(fixture_state_t* fixture, bool ignore_meta, bool ignore_mtime, bc_integrity_output_format_t format)
{
    bc_integrity_diff_options_t options;
    memset(&options, 0, sizeof(options));
    options.manifest_path_a = fixture->manifest_path_a;
    options.manifest_path_b = fixture->manifest_path_b;
    options.format = format;
    options.ignore_meta = ignore_meta;
    options.ignore_mtime = ignore_mtime;
    int exit_code = -1;
    assert_true(bc_integrity_diff_run(fixture->memory_context, &options, &exit_code));
    return exit_code;
}

static void write_garbage_file(const char* path)
{
    FILE* file = fopen(path, "wb");
    assert_non_null(file);
    fputs("garbage data not hrbl", file);
    fclose(file);
}

static void test_diff_empty_vs_empty_no_diff(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    write_manifest(fixture->memory_context, fixture->manifest_path_a, NULL, 0, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    write_manifest(fixture->memory_context, fixture->manifest_path_b, NULL, 0, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    assert_int_equal(run_diff(fixture, false, false, BC_INTEGRITY_OUTPUT_FORMAT_TEXT), 0);
}

static void test_diff_empty_vs_populated_returns_diff(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    bc_integrity_entry_t entries_b[2];
    make_file_entry(&entries_b[0], "added_one.txt", "1111111111111111111111111111111111111111111111111111111111111111", 0644, 1700000000);
    make_file_entry(&entries_b[1], "added_two.txt", "2222222222222222222222222222222222222222222222222222222222222222", 0644, 1700000000);
    write_manifest(fixture->memory_context, fixture->manifest_path_a, NULL, 0, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    write_manifest(fixture->memory_context, fixture->manifest_path_b, entries_b, 2, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    assert_int_equal(run_diff(fixture, false, false, BC_INTEGRITY_OUTPUT_FORMAT_TEXT), 1);
}

static void test_diff_populated_vs_empty_returns_diff(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    bc_integrity_entry_t entries_a[1];
    make_file_entry(&entries_a[0], "removed.txt", "3333333333333333333333333333333333333333333333333333333333333333", 0644, 1700000000);
    write_manifest(fixture->memory_context, fixture->manifest_path_a, entries_a, 1, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    write_manifest(fixture->memory_context, fixture->manifest_path_b, NULL, 0, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    assert_int_equal(run_diff(fixture, false, false, BC_INTEGRITY_OUTPUT_FORMAT_TEXT), 1);
}

static void test_diff_invalid_manifest_a_returns_two(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    write_garbage_file(fixture->manifest_path_a);
    bc_integrity_entry_t entries_b[1];
    make_file_entry(&entries_b[0], "x.txt", "4444444444444444444444444444444444444444444444444444444444444444", 0644, 1700000000);
    write_manifest(fixture->memory_context, fixture->manifest_path_b, entries_b, 1, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    assert_int_equal(run_diff(fixture, false, false, BC_INTEGRITY_OUTPUT_FORMAT_TEXT), 2);
}

static void test_diff_ignore_mtime_skips_only_mtime_change(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    bc_integrity_entry_t entries_a[1];
    bc_integrity_entry_t entries_b[1];
    make_file_entry(&entries_a[0], "x.txt", "5555555555555555555555555555555555555555555555555555555555555555", 0644, 1700000000);
    make_file_entry(&entries_b[0], "x.txt", "5555555555555555555555555555555555555555555555555555555555555555", 0644, 1800000000);
    write_manifest(fixture->memory_context, fixture->manifest_path_a, entries_a, 1, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    write_manifest(fixture->memory_context, fixture->manifest_path_b, entries_b, 1, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    assert_int_equal(run_diff(fixture, false, true, BC_INTEGRITY_OUTPUT_FORMAT_TEXT), 0);
}

static void test_diff_ignore_meta_skips_meta_only_changes(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    bc_integrity_entry_t entries_a[1];
    bc_integrity_entry_t entries_b[1];
    make_file_entry(&entries_a[0], "x.txt", "5555555555555555555555555555555555555555555555555555555555555555", 0644, 1700000000);
    make_file_entry(&entries_b[0], "x.txt", "5555555555555555555555555555555555555555555555555555555555555555", 0700, 1700000000);
    write_manifest(fixture->memory_context, fixture->manifest_path_a, entries_a, 1, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    write_manifest(fixture->memory_context, fixture->manifest_path_b, entries_b, 1, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    assert_int_equal(run_diff(fixture, true, false, BC_INTEGRITY_OUTPUT_FORMAT_TEXT), 0);
}

static void test_diff_content_change_detected(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    bc_integrity_entry_t entries_a[1];
    bc_integrity_entry_t entries_b[1];
    make_file_entry(&entries_a[0], "x.txt", "1111111111111111111111111111111111111111111111111111111111111111", 0644, 1700000000);
    make_file_entry(&entries_b[0], "x.txt", "9999999999999999999999999999999999999999999999999999999999999999", 0644, 1700000000);
    write_manifest(fixture->memory_context, fixture->manifest_path_a, entries_a, 1, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    write_manifest(fixture->memory_context, fixture->manifest_path_b, entries_b, 1, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    assert_int_equal(run_diff(fixture, false, false, BC_INTEGRITY_OUTPUT_FORMAT_TEXT), 1);
}

static void test_diff_both_change_classified_json(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    bc_integrity_entry_t entries_a[1];
    bc_integrity_entry_t entries_b[1];
    make_file_entry(&entries_a[0], "x.txt", "1111111111111111111111111111111111111111111111111111111111111111", 0644, 1700000000);
    make_file_entry(&entries_b[0], "x.txt", "9999999999999999999999999999999999999999999999999999999999999999", 0700, 1700000000);
    write_manifest(fixture->memory_context, fixture->manifest_path_a, entries_a, 1, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    write_manifest(fixture->memory_context, fixture->manifest_path_b, entries_b, 1, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    assert_int_equal(run_diff(fixture, false, false, BC_INTEGRITY_OUTPUT_FORMAT_JSON), 1);
}

static void test_diff_json_format_runs_clean(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    bc_integrity_entry_t entries_a[2];
    bc_integrity_entry_t entries_b[2];
    make_file_entry(&entries_a[0], "alpha.txt", "1111111111111111111111111111111111111111111111111111111111111111", 0644, 1700000000);
    make_file_entry(&entries_a[1], "removed.txt", "2222222222222222222222222222222222222222222222222222222222222222", 0644, 1700000000);
    make_file_entry(&entries_b[0], "added.txt", "3333333333333333333333333333333333333333333333333333333333333333", 0644, 1700000000);
    make_file_entry(&entries_b[1], "alpha.txt", "8888888888888888888888888888888888888888888888888888888888888888", 0700, 1700000000);
    write_manifest(fixture->memory_context, fixture->manifest_path_a, entries_a, 2, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    write_manifest(fixture->memory_context, fixture->manifest_path_b, entries_b, 2, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    assert_int_equal(run_diff(fixture, false, false, BC_INTEGRITY_OUTPUT_FORMAT_JSON), 1);
}

static void test_diff_symlink_kind_preserved(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    bc_integrity_entry_t link_entry;
    memset(&link_entry, 0, sizeof(link_entry));
    link_entry.relative_path = "link";
    link_entry.relative_path_length = strlen("link");
    link_entry.kind = BC_INTEGRITY_ENTRY_KIND_SYMLINK;
    link_entry.ok = true;
    link_entry.size_bytes = 8;
    link_entry.mode = 0120777;
    link_entry.mtime_sec = 1700000000;
    link_entry.link_target = "target";
    link_entry.link_target_length = strlen("target");

    bc_integrity_entry_t link_entry_b;
    memcpy(&link_entry_b, &link_entry, sizeof(link_entry_b));
    link_entry_b.link_target = "different";
    link_entry_b.link_target_length = strlen("different");

    write_manifest(fixture->memory_context, fixture->manifest_path_a, &link_entry, 1, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    write_manifest(fixture->memory_context, fixture->manifest_path_b, &link_entry_b, 1, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    assert_int_equal(run_diff(fixture, false, false, BC_INTEGRITY_OUTPUT_FORMAT_TEXT), 1);
}

static void test_diff_fifo_socket_device_kinds(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    bc_integrity_entry_t entries[3];
    memset(entries, 0, sizeof(entries));
    entries[0].relative_path = "fifo_entry";
    entries[0].relative_path_length = strlen("fifo_entry");
    entries[0].kind = BC_INTEGRITY_ENTRY_KIND_FIFO;
    entries[0].ok = true;
    entries[0].mode = 010644;
    entries[0].mtime_sec = 1700000000;
    entries[1].relative_path = "socket_entry";
    entries[1].relative_path_length = strlen("socket_entry");
    entries[1].kind = BC_INTEGRITY_ENTRY_KIND_SOCKET;
    entries[1].ok = true;
    entries[1].mode = 0140644;
    entries[1].mtime_sec = 1700000000;
    entries[2].relative_path = "device_entry";
    entries[2].relative_path_length = strlen("device_entry");
    entries[2].kind = BC_INTEGRITY_ENTRY_KIND_DEVICE;
    entries[2].ok = true;
    entries[2].mode = 020644;
    entries[2].mtime_sec = 1700000000;

    write_manifest(fixture->memory_context, fixture->manifest_path_a, entries, 3, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    write_manifest(fixture->memory_context, fixture->manifest_path_b, entries, 3, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    assert_int_equal(run_diff(fixture, false, false, BC_INTEGRITY_OUTPUT_FORMAT_TEXT), 0);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_diff_empty_vs_empty_no_diff, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_diff_empty_vs_populated_returns_diff, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_diff_populated_vs_empty_returns_diff, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_diff_invalid_manifest_a_returns_two, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_diff_ignore_mtime_skips_only_mtime_change, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_diff_ignore_meta_skips_meta_only_changes, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_diff_content_change_detected, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_diff_both_change_classified_json, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_diff_json_format_runs_clean, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_diff_symlink_kind_preserved, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_diff_fifo_socket_device_kinds, fixture_setup, fixture_teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
