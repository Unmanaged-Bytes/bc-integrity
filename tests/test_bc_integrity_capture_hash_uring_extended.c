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
#include <stdint.h>
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

static bool under_valgrind(void)
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
    snprintf(fixture->directory_path, sizeof(fixture->directory_path), "/tmp/bc_integrity_uring_ext_%d_XXXXXX", getpid());
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

static void write_file(const char* path, const void* data, size_t length)
{
    FILE* file = fopen(path, "wb");
    assert_non_null(file);
    if (length > 0) {
        fwrite(data, 1, length, file);
    }
    fclose(file);
}

static void hex_lower(const uint8_t* bytes, size_t length, char* out_hex)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t index = 0; index < length; ++index) {
        out_hex[index * 2U] = digits[(bytes[index] >> 4) & 0x0FU];
        out_hex[index * 2U + 1U] = digits[bytes[index] & 0x0FU];
    }
    out_hex[length * 2U] = '\0';
}

static bc_integrity_hash_ring_t* alloc_ring(void)
{
    bc_integrity_hash_ring_t* ring = (bc_integrity_hash_ring_t*)aligned_alloc(64, bc_integrity_hash_ring_struct_size());
    assert_non_null(ring);
    return ring;
}

static void test_ring_struct_size_nonzero(void** state)
{
    (void)state;
    size_t size = bc_integrity_hash_ring_struct_size();
    assert_true(size > 0);
}

static void test_ring_init_destroy_idempotent(void** state)
{
    (void)state;
    if (under_valgrind()) {
        skip();
        return;
    }
    bc_integrity_hash_ring_t* ring = alloc_ring();
    assert_true(bc_integrity_hash_ring_init(ring));
    bc_integrity_hash_ring_destroy(ring);
    bc_integrity_hash_ring_destroy(ring);
    free(ring);
}

static void test_consume_batch_small_files_sha256(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    if (!sha256_is_available() || under_valgrind()) {
        skip();
        return;
    }
    enum { COUNT = 5 };
    char paths[COUNT][512];
    const char* contents[COUNT] = {"alpha", "bravo", "charlie", "delta", "echo"};
    bc_integrity_hash_consumer_state_t states[COUNT];
    bc_integrity_hash_batch_item_t items[COUNT];

    for (size_t index = 0; index < COUNT; ++index) {
        snprintf(paths[index], sizeof(paths[index]), "%s/file_%zu.dat", fixture->directory_path, index);
        write_file(paths[index], contents[index], strlen(contents[index]));
        bc_integrity_hash_consumer_begin(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, &states[index]);
        items[index].absolute_path = paths[index];
        items[index].file_size = strlen(contents[index]);
        items[index].consumer_context = &states[index];
        items[index].success = false;
        items[index].errno_value = 0;
    }

    bc_integrity_hash_ring_t* ring = alloc_ring();
    assert_true(bc_integrity_hash_ring_init(ring));
    bc_integrity_hash_consumer_fn_t consumer = bc_integrity_hash_consumer_function_for(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    assert_true(bc_integrity_hash_consume_batch(ring, items, COUNT, consumer));
    for (size_t index = 0; index < COUNT; ++index) {
        assert_true(items[index].success);
        char actual_digest[BC_INTEGRITY_DIGEST_HEX_BUFFER_SIZE];
        size_t actual_length = 0;
        assert_true(
            bc_integrity_hash_finalize_into_hex(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, &states[index], actual_digest, &actual_length));
        assert_int_equal(actual_length, 64u);

        uint8_t reference[BC_CORE_SHA256_DIGEST_SIZE];
        assert_true(bc_core_sha256(contents[index], strlen(contents[index]), reference));
        char reference_hex[BC_CORE_SHA256_DIGEST_SIZE * 2U + 1U];
        hex_lower(reference, BC_CORE_SHA256_DIGEST_SIZE, reference_hex);
        assert_string_equal(actual_digest, reference_hex);
    }
    bc_integrity_hash_ring_destroy(ring);
    free(ring);
}

static void test_consume_batch_xxh3_64(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    if (under_valgrind()) {
        skip();
        return;
    }
    char path[512];
    snprintf(path, sizeof(path), "%s/x.bin", fixture->directory_path);
    const char* content = "xxh3_input";
    write_file(path, content, strlen(content));

    bc_integrity_hash_consumer_state_t consumer_state;
    bc_integrity_hash_consumer_begin(BC_INTEGRITY_DIGEST_ALGORITHM_XXH3, &consumer_state);
    bc_integrity_hash_batch_item_t item;
    item.absolute_path = path;
    item.file_size = strlen(content);
    item.consumer_context = &consumer_state;
    item.success = false;
    item.errno_value = 0;

    bc_integrity_hash_ring_t* ring = alloc_ring();
    assert_true(bc_integrity_hash_ring_init(ring));
    bc_integrity_hash_consumer_fn_t consumer = bc_integrity_hash_consumer_function_for(BC_INTEGRITY_DIGEST_ALGORITHM_XXH3);
    assert_true(bc_integrity_hash_consume_batch(ring, &item, 1, consumer));
    assert_true(item.success);
    char digest[BC_INTEGRITY_DIGEST_HEX_BUFFER_SIZE];
    size_t digest_length = 0;
    assert_true(bc_integrity_hash_finalize_into_hex(BC_INTEGRITY_DIGEST_ALGORITHM_XXH3, &consumer_state, digest, &digest_length));
    assert_int_equal(digest_length, 16u);

    bc_integrity_hash_ring_destroy(ring);
    free(ring);
}

static void test_consume_batch_xxh128(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    if (under_valgrind()) {
        skip();
        return;
    }
    char path[512];
    snprintf(path, sizeof(path), "%s/y.bin", fixture->directory_path);
    const char* content = "xxh128_input_text";
    write_file(path, content, strlen(content));

    bc_integrity_hash_consumer_state_t consumer_state;
    bc_integrity_hash_consumer_begin(BC_INTEGRITY_DIGEST_ALGORITHM_XXH128, &consumer_state);
    bc_integrity_hash_batch_item_t item;
    item.absolute_path = path;
    item.file_size = strlen(content);
    item.consumer_context = &consumer_state;
    item.success = false;
    item.errno_value = 0;

    bc_integrity_hash_ring_t* ring = alloc_ring();
    assert_true(bc_integrity_hash_ring_init(ring));
    bc_integrity_hash_consumer_fn_t consumer = bc_integrity_hash_consumer_function_for(BC_INTEGRITY_DIGEST_ALGORITHM_XXH128);
    assert_true(bc_integrity_hash_consume_batch(ring, &item, 1, consumer));
    assert_true(item.success);
    char digest[BC_INTEGRITY_DIGEST_HEX_BUFFER_SIZE];
    size_t digest_length = 0;
    assert_true(bc_integrity_hash_finalize_into_hex(BC_INTEGRITY_DIGEST_ALGORITHM_XXH128, &consumer_state, digest, &digest_length));
    assert_int_equal(digest_length, 32u);

    bc_integrity_hash_ring_destroy(ring);
    free(ring);
}

static void test_consume_batch_more_than_slot_count(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    if (!sha256_is_available() || under_valgrind()) {
        skip();
        return;
    }
    const size_t total = BC_INTEGRITY_HASH_RING_SLOT_COUNT + 8U;
    char(*paths)[512] = malloc(sizeof(char[512]) * total);
    bc_integrity_hash_consumer_state_t* states = malloc(sizeof(bc_integrity_hash_consumer_state_t) * total);
    bc_integrity_hash_batch_item_t* items = malloc(sizeof(bc_integrity_hash_batch_item_t) * total);
    assert_non_null(paths);
    assert_non_null(states);
    assert_non_null(items);

    for (size_t index = 0; index < total; ++index) {
        snprintf(paths[index], sizeof(paths[index]), "%s/big_%zu.dat", fixture->directory_path, index);
        char buffer[64];
        int len = snprintf(buffer, sizeof(buffer), "content-%zu", index);
        write_file(paths[index], buffer, (size_t)len);
        bc_integrity_hash_consumer_begin(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, &states[index]);
        items[index].absolute_path = paths[index];
        items[index].file_size = (size_t)len;
        items[index].consumer_context = &states[index];
        items[index].success = false;
        items[index].errno_value = 0;
    }

    bc_integrity_hash_ring_t* ring = alloc_ring();
    assert_true(bc_integrity_hash_ring_init(ring));
    bc_integrity_hash_consumer_fn_t consumer = bc_integrity_hash_consumer_function_for(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    assert_true(bc_integrity_hash_consume_batch(ring, items, total, consumer));
    for (size_t index = 0; index < total; ++index) {
        assert_true(items[index].success);
    }
    bc_integrity_hash_ring_destroy(ring);
    free(ring);
    free(paths);
    free(states);
    free(items);
}

static void test_consume_batch_empty_file_via_fallback(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    if (!sha256_is_available() || under_valgrind()) {
        skip();
        return;
    }
    char path[512];
    snprintf(path, sizeof(path), "%s/empty.bin", fixture->directory_path);
    write_file(path, "", 0);

    bc_integrity_hash_consumer_state_t consumer_state;
    bc_integrity_hash_consumer_begin(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, &consumer_state);
    bc_integrity_hash_batch_item_t item;
    item.absolute_path = path;
    item.file_size = 0;
    item.consumer_context = &consumer_state;
    item.success = false;
    item.errno_value = 0;

    bc_integrity_hash_ring_t* ring = alloc_ring();
    assert_true(bc_integrity_hash_ring_init(ring));
    bc_integrity_hash_consumer_fn_t consumer = bc_integrity_hash_consumer_function_for(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    assert_true(bc_integrity_hash_consume_batch(ring, &item, 1, consumer));
    assert_true(item.success);
    char digest[BC_INTEGRITY_DIGEST_HEX_BUFFER_SIZE];
    size_t digest_length = 0;
    assert_true(bc_integrity_hash_finalize_into_hex(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, &consumer_state, digest, &digest_length));
    assert_string_equal(digest, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991"
                                "b7852b855");

    bc_integrity_hash_ring_destroy(ring);
    free(ring);
}

static void test_consume_batch_too_large_file_uses_fallback(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    if (!sha256_is_available() || under_valgrind()) {
        skip();
        return;
    }
    char path[512];
    snprintf(path, sizeof(path), "%s/large.bin", fixture->directory_path);
    size_t size = BC_INTEGRITY_HASH_RING_SLOT_BUFFER_BYTES + 1024U;
    unsigned char* data = malloc(size);
    assert_non_null(data);
    memset(data, 0x5A, size);
    write_file(path, data, size);

    bc_integrity_hash_consumer_state_t consumer_state;
    bc_integrity_hash_consumer_begin(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, &consumer_state);
    bc_integrity_hash_batch_item_t item;
    item.absolute_path = path;
    item.file_size = size;
    item.consumer_context = &consumer_state;
    item.success = false;
    item.errno_value = 0;

    bc_integrity_hash_ring_t* ring = alloc_ring();
    assert_true(bc_integrity_hash_ring_init(ring));
    bc_integrity_hash_consumer_fn_t consumer = bc_integrity_hash_consumer_function_for(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    assert_true(bc_integrity_hash_consume_batch(ring, &item, 1, consumer));
    assert_true(item.success);
    char digest[BC_INTEGRITY_DIGEST_HEX_BUFFER_SIZE];
    size_t digest_length = 0;
    assert_true(bc_integrity_hash_finalize_into_hex(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, &consumer_state, digest, &digest_length));
    assert_int_equal(digest_length, 64u);

    uint8_t reference[BC_CORE_SHA256_DIGEST_SIZE];
    assert_true(bc_core_sha256(data, size, reference));
    char reference_hex[BC_CORE_SHA256_DIGEST_SIZE * 2U + 1U];
    hex_lower(reference, BC_CORE_SHA256_DIGEST_SIZE, reference_hex);
    assert_string_equal(digest, reference_hex);

    bc_integrity_hash_ring_destroy(ring);
    free(ring);
    free(data);
}

static void test_consume_batch_mixed_success_and_missing(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    if (!sha256_is_available() || under_valgrind()) {
        skip();
        return;
    }
    char path_ok[512];
    char path_missing[512];
    snprintf(path_ok, sizeof(path_ok), "%s/ok.txt", fixture->directory_path);
    snprintf(path_missing, sizeof(path_missing), "%s/nope.txt", fixture->directory_path);
    write_file(path_ok, "data", 4);

    bc_integrity_hash_consumer_state_t state_ok;
    bc_integrity_hash_consumer_state_t state_missing;
    bc_integrity_hash_consumer_begin(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, &state_ok);
    bc_integrity_hash_consumer_begin(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, &state_missing);
    bc_integrity_hash_batch_item_t items[2];
    items[0].absolute_path = path_ok;
    items[0].file_size = 4;
    items[0].consumer_context = &state_ok;
    items[0].success = false;
    items[0].errno_value = 0;
    items[1].absolute_path = path_missing;
    items[1].file_size = 4;
    items[1].consumer_context = &state_missing;
    items[1].success = false;
    items[1].errno_value = 0;

    bc_integrity_hash_ring_t* ring = alloc_ring();
    assert_true(bc_integrity_hash_ring_init(ring));
    bc_integrity_hash_consumer_fn_t consumer = bc_integrity_hash_consumer_function_for(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    assert_true(bc_integrity_hash_consume_batch(ring, items, 2, consumer));
    assert_true(items[0].success);
    assert_false(items[1].success);
    assert_true(items[1].errno_value != 0);

    bc_integrity_hash_ring_destroy(ring);
    free(ring);
}

static void test_consume_batch_zero_items_succeeds(void** state)
{
    (void)state;
    if (under_valgrind()) {
        skip();
        return;
    }
    bc_integrity_hash_ring_t* ring = alloc_ring();
    assert_true(bc_integrity_hash_ring_init(ring));
    bc_integrity_hash_consumer_fn_t consumer = bc_integrity_hash_consumer_function_for(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    assert_true(bc_integrity_hash_consume_batch(ring, NULL, 0, consumer));
    bc_integrity_hash_ring_destroy(ring);
    free(ring);
}

static void test_consume_batch_medium_file(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    if (!sha256_is_available() || under_valgrind()) {
        skip();
        return;
    }
    char path[512];
    snprintf(path, sizeof(path), "%s/medium.bin", fixture->directory_path);
    size_t size = 64U * 1024U;
    unsigned char* data = malloc(size);
    assert_non_null(data);
    for (size_t i = 0; i < size; ++i) {
        data[i] = (unsigned char)(i & 0xFF);
    }
    write_file(path, data, size);

    bc_integrity_hash_consumer_state_t consumer_state;
    bc_integrity_hash_consumer_begin(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, &consumer_state);
    bc_integrity_hash_batch_item_t item;
    item.absolute_path = path;
    item.file_size = size;
    item.consumer_context = &consumer_state;
    item.success = false;
    item.errno_value = 0;

    bc_integrity_hash_ring_t* ring = alloc_ring();
    assert_true(bc_integrity_hash_ring_init(ring));
    bc_integrity_hash_consumer_fn_t consumer = bc_integrity_hash_consumer_function_for(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    assert_true(bc_integrity_hash_consume_batch(ring, &item, 1, consumer));
    assert_true(item.success);
    char digest[BC_INTEGRITY_DIGEST_HEX_BUFFER_SIZE];
    size_t digest_length = 0;
    assert_true(bc_integrity_hash_finalize_into_hex(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, &consumer_state, digest, &digest_length));

    uint8_t reference[BC_CORE_SHA256_DIGEST_SIZE];
    assert_true(bc_core_sha256(data, size, reference));
    char reference_hex[BC_CORE_SHA256_DIGEST_SIZE * 2U + 1U];
    hex_lower(reference, BC_CORE_SHA256_DIGEST_SIZE, reference_hex);
    assert_string_equal(digest, reference_hex);

    bc_integrity_hash_ring_destroy(ring);
    free(ring);
    free(data);
}

static void test_consume_batch_at_slot_boundary(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    if (!sha256_is_available() || under_valgrind()) {
        skip();
        return;
    }
    const size_t count = BC_INTEGRITY_HASH_RING_SLOT_COUNT;
    char(*paths)[512] = malloc(sizeof(char[512]) * count);
    bc_integrity_hash_consumer_state_t* states = malloc(sizeof(bc_integrity_hash_consumer_state_t) * count);
    bc_integrity_hash_batch_item_t* items = malloc(sizeof(bc_integrity_hash_batch_item_t) * count);
    assert_non_null(paths);
    assert_non_null(states);
    assert_non_null(items);
    for (size_t index = 0; index < count; ++index) {
        snprintf(paths[index], sizeof(paths[index]), "%s/b_%zu.dat", fixture->directory_path, index);
        char buffer[16];
        int len = snprintf(buffer, sizeof(buffer), "v%zu", index);
        write_file(paths[index], buffer, (size_t)len);
        bc_integrity_hash_consumer_begin(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, &states[index]);
        items[index].absolute_path = paths[index];
        items[index].file_size = (size_t)len;
        items[index].consumer_context = &states[index];
        items[index].success = false;
        items[index].errno_value = 0;
    }

    bc_integrity_hash_ring_t* ring = alloc_ring();
    assert_true(bc_integrity_hash_ring_init(ring));
    bc_integrity_hash_consumer_fn_t consumer = bc_integrity_hash_consumer_function_for(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    assert_true(bc_integrity_hash_consume_batch(ring, items, count, consumer));
    for (size_t index = 0; index < count; ++index) {
        assert_true(items[index].success);
    }

    bc_integrity_hash_ring_destroy(ring);
    free(ring);
    free(paths);
    free(states);
    free(items);
}

static void test_consume_batch_many_missing_files(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    if (!sha256_is_available() || under_valgrind()) {
        skip();
        return;
    }
    enum { COUNT = 10 };
    char paths[COUNT][512];
    bc_integrity_hash_consumer_state_t states[COUNT];
    bc_integrity_hash_batch_item_t items[COUNT];
    for (size_t index = 0; index < COUNT; ++index) {
        snprintf(paths[index], sizeof(paths[index]), "%s/missing_%zu.txt", fixture->directory_path, index);
        bc_integrity_hash_consumer_begin(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, &states[index]);
        items[index].absolute_path = paths[index];
        items[index].file_size = 4;
        items[index].consumer_context = &states[index];
        items[index].success = false;
        items[index].errno_value = 0;
    }

    bc_integrity_hash_ring_t* ring = alloc_ring();
    assert_true(bc_integrity_hash_ring_init(ring));
    bc_integrity_hash_consumer_fn_t consumer = bc_integrity_hash_consumer_function_for(BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    assert_true(bc_integrity_hash_consume_batch(ring, items, COUNT, consumer));
    for (size_t index = 0; index < COUNT; ++index) {
        assert_false(items[index].success);
        assert_true(items[index].errno_value != 0);
    }
    bc_integrity_hash_ring_destroy(ring);
    free(ring);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ring_struct_size_nonzero),
        cmocka_unit_test(test_ring_init_destroy_idempotent),
        cmocka_unit_test_setup_teardown(test_consume_batch_small_files_sha256, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_consume_batch_xxh3_64, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_consume_batch_xxh128, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_consume_batch_more_than_slot_count, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_consume_batch_empty_file_via_fallback, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_consume_batch_too_large_file_uses_fallback, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_consume_batch_mixed_success_and_missing, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_consume_batch_zero_items_succeeds, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_consume_batch_medium_file, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_consume_batch_at_slot_boundary, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_consume_batch_many_missing_files, fixture_setup, fixture_teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
