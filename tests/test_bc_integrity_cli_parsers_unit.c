// SPDX-License-Identifier: MIT

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>

#include <cmocka.h>

#include <stdbool.h>

#include "bc_integrity_cli_internal.h"

static void test_parse_digest_algorithm_valid(void** state)
{
    (void)state;
    bc_integrity_digest_algorithm_t algorithm = BC_INTEGRITY_DIGEST_ALGORITHM_SHA256;
    assert_true(bc_integrity_cli_parse_digest_algorithm("sha256", &algorithm));
    assert_int_equal(algorithm, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
    assert_true(bc_integrity_cli_parse_digest_algorithm("xxh3", &algorithm));
    assert_int_equal(algorithm, BC_INTEGRITY_DIGEST_ALGORITHM_XXH3);
    assert_true(bc_integrity_cli_parse_digest_algorithm("xxh128", &algorithm));
    assert_int_equal(algorithm, BC_INTEGRITY_DIGEST_ALGORITHM_XXH128);
}

static void test_parse_digest_algorithm_invalid(void** state)
{
    (void)state;
    bc_integrity_digest_algorithm_t algorithm = BC_INTEGRITY_DIGEST_ALGORITHM_SHA256;
    assert_false(bc_integrity_cli_parse_digest_algorithm("md5", &algorithm));
    assert_false(bc_integrity_cli_parse_digest_algorithm("", &algorithm));
    assert_false(bc_integrity_cli_parse_digest_algorithm("SHA256", &algorithm));
    assert_false(bc_integrity_cli_parse_digest_algorithm("xxh", &algorithm));
}

static void test_parse_threads_auto(void** state)
{
    (void)state;
    bc_integrity_threads_mode_t mode = BC_INTEGRITY_THREADS_MODE_MONO;
    size_t worker_count = 9999;
    assert_true(bc_integrity_cli_parse_threads("auto", &mode, &worker_count));
    assert_int_equal(mode, BC_INTEGRITY_THREADS_MODE_AUTO);
    assert_int_equal(worker_count, 0);
}

static void test_parse_threads_auto_io(void** state)
{
    (void)state;
    bc_integrity_threads_mode_t mode = BC_INTEGRITY_THREADS_MODE_MONO;
    size_t worker_count = 9999;
    assert_true(bc_integrity_cli_parse_threads("auto-io", &mode, &worker_count));
    assert_int_equal(mode, BC_INTEGRITY_THREADS_MODE_AUTO_IO);
    assert_int_equal(worker_count, 0);
}

static void test_parse_threads_zero(void** state)
{
    (void)state;
    bc_integrity_threads_mode_t mode = BC_INTEGRITY_THREADS_MODE_AUTO;
    size_t worker_count = 9999;
    assert_true(bc_integrity_cli_parse_threads("0", &mode, &worker_count));
    assert_int_equal(mode, BC_INTEGRITY_THREADS_MODE_MONO);
    assert_int_equal(worker_count, 0);
}

static void test_parse_threads_explicit(void** state)
{
    (void)state;
    bc_integrity_threads_mode_t mode = BC_INTEGRITY_THREADS_MODE_AUTO;
    size_t worker_count = 0;
    assert_true(bc_integrity_cli_parse_threads("4", &mode, &worker_count));
    assert_int_equal(mode, BC_INTEGRITY_THREADS_MODE_EXPLICIT);
    assert_int_equal(worker_count, 4);
    assert_true(bc_integrity_cli_parse_threads("16", &mode, &worker_count));
    assert_int_equal(mode, BC_INTEGRITY_THREADS_MODE_EXPLICIT);
    assert_int_equal(worker_count, 16);
}

static void test_parse_threads_invalid(void** state)
{
    (void)state;
    bc_integrity_threads_mode_t mode = BC_INTEGRITY_THREADS_MODE_AUTO;
    size_t worker_count = 0;
    assert_false(bc_integrity_cli_parse_threads("", &mode, &worker_count));
    assert_false(bc_integrity_cli_parse_threads("abc", &mode, &worker_count));
    assert_false(bc_integrity_cli_parse_threads("4N", &mode, &worker_count));
    assert_false(bc_integrity_cli_parse_threads("auto-cpu", &mode, &worker_count));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_digest_algorithm_valid), cmocka_unit_test(test_parse_digest_algorithm_invalid),
        cmocka_unit_test(test_parse_threads_auto),           cmocka_unit_test(test_parse_threads_auto_io),
        cmocka_unit_test(test_parse_threads_zero),           cmocka_unit_test(test_parse_threads_explicit),
        cmocka_unit_test(test_parse_threads_invalid),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
