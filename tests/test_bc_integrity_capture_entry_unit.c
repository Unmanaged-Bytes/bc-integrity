// SPDX-License-Identifier: MIT

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include <fcntl.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bc_allocators.h"
#include "bc_core_hash.h"
#include "bc_integrity_capture_internal.h"
#include "bc_integrity_entry_internal.h"

static bool sha256_is_available(void)
{
    uint8_t probe[BC_CORE_SHA256_DIGEST_SIZE];
    return bc_core_sha256("", 0, probe);
}

typedef struct fixture_state {
    char directory_path[256];
} fixture_state_t;

static int fixture_setup(void** state)
{
    fixture_state_t* fixture = malloc(sizeof(*fixture));
    if (fixture == NULL) {
        return -1;
    }
    snprintf(fixture->directory_path, sizeof(fixture->directory_path), "/tmp/bc_integrity_capture_test_%d_XXXXXX", getpid());
    if (mkdtemp(fixture->directory_path) == NULL) {
        free(fixture);
        return -1;
    }
    *state = fixture;
    return 0;
}

static int fixture_teardown(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    char command[512];
    snprintf(command, sizeof(command), "rm -rf '%s'", fixture->directory_path);
    int rc = system(command);
    (void)rc;
    free(fixture);
    return 0;
}

static void write_file(const char* path, const char* content)
{
    FILE* file = fopen(path, "wb");
    assert_non_null(file);
    fputs(content, file);
    fclose(file);
}

static void test_capture_regular_file_sha256(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    if (!sha256_is_available()) {
        skip();
        return;
    }
    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/file.txt", fixture->directory_path);
    write_file(file_path, "hello\n");

    bc_allocators_context_config_t allocator_config = {.tracking_enabled = true};
    bc_allocators_context_t* memory_context = NULL;
    assert_true(bc_allocators_context_create(&allocator_config, &memory_context));

    struct stat stat_buffer;
    assert_int_equal(lstat(file_path, &stat_buffer), 0);

    int dir_fd = open(fixture->directory_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert_true(dir_fd >= 0);

    bc_integrity_entry_t entry;
    bc_integrity_capture_entry_from_stat(memory_context, &stat_buffer, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, dir_fd, "file.txt", file_path,
                                         strlen(file_path), "file.txt", strlen("file.txt"), false, &entry);
    close(dir_fd);

    assert_int_equal(entry.kind, BC_INTEGRITY_ENTRY_KIND_FILE);
    assert_true(entry.ok);
    assert_int_equal(entry.size_bytes, 6u);
    assert_int_equal(entry.digest_hex_length, 64u);
    assert_string_equal(entry.digest_hex, "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03");

    bc_allocators_context_destroy(memory_context);
}

static void test_capture_symlink(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    char file_path[512];
    char link_path[512];
    snprintf(file_path, sizeof(file_path), "%s/target.txt", fixture->directory_path);
    snprintf(link_path, sizeof(link_path), "%s/link.txt", fixture->directory_path);
    write_file(file_path, "data");
    assert_int_equal(symlink("target.txt", link_path), 0);

    bc_allocators_context_config_t allocator_config = {.tracking_enabled = true};
    bc_allocators_context_t* memory_context = NULL;
    assert_true(bc_allocators_context_create(&allocator_config, &memory_context));

    struct stat stat_buffer;
    assert_int_equal(lstat(link_path, &stat_buffer), 0);

    int dir_fd = open(fixture->directory_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert_true(dir_fd >= 0);

    bc_integrity_entry_t entry;
    bc_integrity_capture_entry_from_stat(memory_context, &stat_buffer, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, dir_fd, "link.txt", link_path,
                                         strlen(link_path), "link.txt", strlen("link.txt"), false, &entry);
    close(dir_fd);

    assert_int_equal(entry.kind, BC_INTEGRITY_ENTRY_KIND_SYMLINK);
    assert_true(entry.ok);
    assert_non_null(entry.link_target);
    assert_string_equal(entry.link_target, "target.txt");
    assert_int_equal(entry.link_target_length, 10u);

    bc_allocators_context_destroy(memory_context);
}

static void test_capture_directory_no_digest(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    char sub_path[512];
    snprintf(sub_path, sizeof(sub_path), "%s/subdir", fixture->directory_path);
    assert_int_equal(mkdir(sub_path, 0755), 0);

    bc_allocators_context_config_t allocator_config = {.tracking_enabled = true};
    bc_allocators_context_t* memory_context = NULL;
    assert_true(bc_allocators_context_create(&allocator_config, &memory_context));

    struct stat stat_buffer;
    assert_int_equal(lstat(sub_path, &stat_buffer), 0);

    int dir_fd = open(fixture->directory_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert_true(dir_fd >= 0);

    bc_integrity_entry_t entry;
    bc_integrity_capture_entry_from_stat(memory_context, &stat_buffer, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, dir_fd, "subdir", sub_path,
                                         strlen(sub_path), "subdir", strlen("subdir"), false, &entry);
    close(dir_fd);

    assert_int_equal(entry.kind, BC_INTEGRITY_ENTRY_KIND_DIRECTORY);
    assert_true(entry.ok);
    assert_int_equal(entry.digest_hex_length, 0u);
    assert_null(entry.link_target);

    bc_allocators_context_destroy(memory_context);
}

static void test_compute_digest_xxh3(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/x.bin", fixture->directory_path);
    write_file(file_path, "abc");

    char digest_buffer[BC_INTEGRITY_DIGEST_HEX_BUFFER_SIZE];
    size_t digest_length = 0;
    int errno_value = 0;
    assert_true(
        bc_integrity_capture_compute_digest(file_path, 3, BC_INTEGRITY_DIGEST_ALGORITHM_XXH3, digest_buffer, &digest_length, &errno_value));
    assert_int_equal(digest_length, 16u);

    assert_true(bc_integrity_capture_compute_digest(file_path, 3, BC_INTEGRITY_DIGEST_ALGORITHM_XXH128, digest_buffer, &digest_length,
                                                    &errno_value));
    assert_int_equal(digest_length, 32u);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_capture_regular_file_sha256, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_capture_symlink, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_capture_directory_no_digest, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_compute_digest_xxh3, fixture_setup, fixture_teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
