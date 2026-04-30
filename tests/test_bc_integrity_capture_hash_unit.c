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

#include "bc_core_hash.h"
#include "bc_integrity_capture_hash_internal.h"
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
} fixture_state_t;

static int fixture_setup(void** state)
{
    fixture_state_t* fixture = malloc(sizeof(*fixture));
    if (fixture == NULL) {
        return -1;
    }
    snprintf(fixture->directory_path, sizeof(fixture->directory_path), "/tmp/bc_integrity_hash_test_%d_XXXXXX", getpid());
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

static void test_compute_sha256_hello(void** state)
{
    if (!sha256_is_available()) {
        skip();
        return;
    }
    fixture_state_t* fixture = (fixture_state_t*)*state;
    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/hello.txt", fixture->directory_path);
    write_file(file_path, "hello\n");

    char digest_buffer[BC_INTEGRITY_DIGEST_HEX_BUFFER_SIZE];
    size_t digest_length = 0;
    int errno_value = 0;
    assert_true(bc_integrity_hash_compute_for_algorithm(file_path, 6, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, digest_buffer, &digest_length,
                                                        &errno_value));
    assert_int_equal(digest_length, 64u);
    assert_string_equal(digest_buffer, "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03");
}

static void test_compute_xxh3(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/x.bin", fixture->directory_path);
    write_file(file_path, "abc");

    char digest_buffer[BC_INTEGRITY_DIGEST_HEX_BUFFER_SIZE];
    size_t digest_length = 0;
    int errno_value = 0;
    assert_true(bc_integrity_hash_compute_for_algorithm(file_path, 3, BC_INTEGRITY_DIGEST_ALGORITHM_XXH3, digest_buffer, &digest_length,
                                                        &errno_value));
    assert_int_equal(digest_length, 16u);
}

static void test_compute_xxh128(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/x128.bin", fixture->directory_path);
    write_file(file_path, "0123456789abcdef");

    char digest_buffer[BC_INTEGRITY_DIGEST_HEX_BUFFER_SIZE];
    size_t digest_length = 0;
    int errno_value = 0;
    assert_true(bc_integrity_hash_compute_for_algorithm(file_path, 16, BC_INTEGRITY_DIGEST_ALGORITHM_XXH128, digest_buffer, &digest_length,
                                                        &errno_value));
    assert_int_equal(digest_length, 32u);
}

static void test_consume_batch_two_files(void** state)
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
    write_file(file_path_a, "hello\n");
    write_file(file_path_b, "world\n");

    bc_integrity_hash_ring_t* ring = (bc_integrity_hash_ring_t*)aligned_alloc(64, bc_integrity_hash_ring_struct_size());
    assert_non_null(ring);
    assert_true(bc_integrity_hash_ring_init(ring));

    bc_integrity_hash_consumer_state_t state_a;
    bc_integrity_hash_consumer_state_t state_b;
    bc_integrity_hash_consumer_begin(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, &state_a);
    bc_integrity_hash_consumer_begin(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, &state_b);

    bc_integrity_hash_batch_item_t items[2];
    items[0].absolute_path = file_path_a;
    items[0].file_size = 6;
    items[0].consumer_context = &state_a;
    items[0].success = false;
    items[0].errno_value = 0;
    items[1].absolute_path = file_path_b;
    items[1].file_size = 6;
    items[1].consumer_context = &state_b;
    items[1].success = false;
    items[1].errno_value = 0;

    bc_integrity_hash_consumer_fn_t consumer = bc_integrity_hash_consumer_function_for(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    assert_true(bc_integrity_hash_consume_batch(ring, items, 2, consumer));
    assert_true(items[0].success);
    assert_true(items[1].success);

    char digest_a[BC_INTEGRITY_DIGEST_HEX_BUFFER_SIZE];
    char digest_b[BC_INTEGRITY_DIGEST_HEX_BUFFER_SIZE];
    size_t digest_a_length = 0;
    size_t digest_b_length = 0;
    assert_true(bc_integrity_hash_finalize_into_hex(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, &state_a, digest_a, &digest_a_length));
    assert_true(bc_integrity_hash_finalize_into_hex(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, &state_b, digest_b, &digest_b_length));
    assert_int_equal(digest_a_length, 64u);
    assert_int_equal(digest_b_length, 64u);
    assert_string_equal(digest_a, "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03");

    bc_integrity_hash_ring_destroy(ring);
    free(ring);
}

static void test_consume_batch_missing_file(void** state)
{
    if (!sha256_is_available() || bc_integrity_test_under_valgrind()) {
        skip();
        return;
    }
    fixture_state_t* fixture = (fixture_state_t*)*state;
    char file_path_missing[512];
    snprintf(file_path_missing, sizeof(file_path_missing), "%s/does_not_exist", fixture->directory_path);

    bc_integrity_hash_ring_t* ring = (bc_integrity_hash_ring_t*)aligned_alloc(64, bc_integrity_hash_ring_struct_size());
    assert_non_null(ring);
    assert_true(bc_integrity_hash_ring_init(ring));

    bc_integrity_hash_consumer_state_t state_missing;
    bc_integrity_hash_consumer_begin(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, &state_missing);

    bc_integrity_hash_batch_item_t items[1];
    items[0].absolute_path = file_path_missing;
    items[0].file_size = 1;
    items[0].consumer_context = &state_missing;
    items[0].success = false;
    items[0].errno_value = 0;

    bc_integrity_hash_consumer_fn_t consumer = bc_integrity_hash_consumer_function_for(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    assert_true(bc_integrity_hash_consume_batch(ring, items, 1, consumer));
    assert_false(items[0].success);
    assert_true(items[0].errno_value != 0);

    bc_integrity_hash_ring_destroy(ring);
    free(ring);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_compute_sha256_hello, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_compute_xxh3, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_compute_xxh128, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_consume_batch_two_files, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_consume_batch_missing_file, fixture_setup, fixture_teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
