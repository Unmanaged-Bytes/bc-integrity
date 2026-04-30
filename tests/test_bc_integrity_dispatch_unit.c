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
#include "bc_concurrency.h"
#include "bc_containers_vector.h"
#include "bc_core.h"
#include "bc_core_hash.h"
#include "bc_integrity_dispatch_internal.h"
#include "bc_integrity_entry_internal.h"

#if __has_include(<valgrind/valgrind.h>)
#include <valgrind/valgrind.h>
#define BC_INTEGRITY_TEST_HAS_VALGRIND_HEADER 1
#else
#define BC_INTEGRITY_TEST_HAS_VALGRIND_HEADER 0
#endif

static bool bc_integrity_test_under_valgrind(void)
{
#if BC_INTEGRITY_TEST_HAS_VALGRIND_HEADER
    return RUNNING_ON_VALGRIND != 0;
#else
    return false;
#endif
}

static bool sha256_is_available(void)
{
    uint8_t probe[BC_CORE_SHA256_DIGEST_SIZE];
    return bc_core_sha256("", 0, probe);
}

typedef struct fixture_state {
    char directory_path[256];
    bc_allocators_context_t* memory_context;
    bc_concurrency_context_t* concurrency_context;
} fixture_state_t;

static int fixture_setup(void** state)
{
    fixture_state_t* fixture = malloc(sizeof(*fixture));
    if (fixture == NULL) {
        return -1;
    }
    snprintf(fixture->directory_path, sizeof(fixture->directory_path), "/tmp/bc_integrity_dispatch_test_%d_XXXXXX", getpid());
    if (mkdtemp(fixture->directory_path) == NULL) {
        free(fixture);
        return -1;
    }
    bc_allocators_context_config_t config = {.tracking_enabled = true};
    if (!bc_allocators_context_create(&config, &fixture->memory_context)) {
        free(fixture);
        return -1;
    }
    bc_concurrency_config_t parallel_config;
    bc_core_zero(&parallel_config, sizeof(parallel_config));
    parallel_config.worker_count_explicit = true;
    parallel_config.worker_count = 1;
    if (!bc_concurrency_create(fixture->memory_context, &parallel_config, &fixture->concurrency_context)) {
        bc_allocators_context_destroy(fixture->memory_context);
        free(fixture);
        return -1;
    }
    *state = fixture;
    return 0;
}

static int fixture_teardown(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    bc_concurrency_destroy(fixture->concurrency_context);
    bc_allocators_context_destroy(fixture->memory_context);
    char command[512];
    snprintf(command, sizeof(command), "rm -rf '%s'", fixture->directory_path);
    int rc = system(command);
    (void)rc;
    free(fixture);
    return 0;
}

static void write_file(const char* path, const char* content, size_t length)
{
    FILE* file = fopen(path, "wb");
    assert_non_null(file);
    fwrite(content, 1, length, file);
    fclose(file);
}

static void make_entry(bc_integrity_entry_t* entry, const char* absolute_path, size_t file_size)
{
    bc_core_zero(entry, sizeof(*entry));
    entry->relative_path = absolute_path;
    entry->relative_path_length = strlen(absolute_path);
    entry->absolute_path = absolute_path;
    entry->absolute_path_length = strlen(absolute_path);
    entry->kind = BC_INTEGRITY_ENTRY_KIND_FILE;
    entry->ok = true;
    entry->size_bytes = (uint64_t)file_size;
}

static void test_dispatch_two_files(void** state)
{
    if (!sha256_is_available() || bc_integrity_test_under_valgrind()) {
        skip();
        return;
    }
    fixture_state_t* fixture = (fixture_state_t*)*state;

    char file_path_a[512];
    char file_path_b[512];
    snprintf(file_path_a, sizeof(file_path_a), "%s/a.txt", fixture->directory_path);
    snprintf(file_path_b, sizeof(file_path_b), "%s/b.txt", fixture->directory_path);
    write_file(file_path_a, "hello\n", 6);
    write_file(file_path_b, "world\n", 6);

    bc_containers_vector_t* entries = NULL;
    assert_true(bc_containers_vector_create(fixture->memory_context, sizeof(bc_integrity_entry_t), 4, 16, &entries));
    bc_integrity_entry_t entry_a;
    bc_integrity_entry_t entry_b;
    make_entry(&entry_a, file_path_a, 6);
    make_entry(&entry_b, file_path_b, 6);
    assert_true(bc_containers_vector_push(fixture->memory_context, entries, &entry_a));
    assert_true(bc_containers_vector_push(fixture->memory_context, entries, &entry_b));

    assert_true(bc_integrity_dispatch_compute_digests(fixture->memory_context, fixture->concurrency_context, NULL,
                                                      BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, entries));

    bc_integrity_entry_t entry_check;
    assert_true(bc_containers_vector_get(entries, 0, &entry_check));
    assert_int_equal(entry_check.digest_hex_length, 64u);
    assert_string_equal(entry_check.digest_hex, "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03");

    bc_containers_vector_destroy(fixture->memory_context, entries);
}

static void test_dispatch_zero_size_file(void** state)
{
    if (!sha256_is_available() || bc_integrity_test_under_valgrind()) {
        skip();
        return;
    }
    fixture_state_t* fixture = (fixture_state_t*)*state;

    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/empty.bin", fixture->directory_path);
    write_file(file_path, "", 0);

    bc_containers_vector_t* entries = NULL;
    assert_true(bc_containers_vector_create(fixture->memory_context, sizeof(bc_integrity_entry_t), 4, 16, &entries));
    bc_integrity_entry_t entry_zero;
    make_entry(&entry_zero, file_path, 0);
    assert_true(bc_containers_vector_push(fixture->memory_context, entries, &entry_zero));

    assert_true(bc_integrity_dispatch_compute_digests(fixture->memory_context, fixture->concurrency_context, NULL,
                                                      BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, entries));

    bc_integrity_entry_t entry_check;
    assert_true(bc_containers_vector_get(entries, 0, &entry_check));
    assert_int_equal(entry_check.digest_hex_length, 64u);
    assert_string_equal(entry_check.digest_hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    bc_containers_vector_destroy(fixture->memory_context, entries);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_dispatch_two_files, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_dispatch_zero_size_file, fixture_setup, fixture_teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
