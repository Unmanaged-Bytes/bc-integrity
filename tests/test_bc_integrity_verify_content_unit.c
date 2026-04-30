// SPDX-License-Identifier: MIT

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include <stdbool.h>

#include "bc_integrity_verify_internal.h"

static void make_baseline(bc_integrity_meta_snapshot_t* snapshot)
{
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->present = true;
    snapshot->kind = BC_INTEGRITY_ENTRY_KIND_FILE;
    snapshot->size_bytes = 42;
    snapshot->mode = 0100644;
    snapshot->digest_hex = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03";
    snapshot->digest_hex_length = 64;
}

static void test_content_identical_returns_none(void** state)
{
    (void)state;
    bc_integrity_meta_snapshot_t expected;
    bc_integrity_meta_snapshot_t actual;
    make_baseline(&expected);
    make_baseline(&actual);
    assert_int_equal(bc_integrity_verify_compare_content(&expected, &actual), BC_INTEGRITY_VERIFY_CHANGE_NONE);
}

static void test_content_meta_change_returns_none(void** state)
{
    (void)state;
    bc_integrity_meta_snapshot_t expected;
    bc_integrity_meta_snapshot_t actual;
    make_baseline(&expected);
    make_baseline(&actual);
    actual.mode = 0100600;
    actual.uid = 0;
    actual.mtime_sec = 1234;
    assert_int_equal(bc_integrity_verify_compare_content(&expected, &actual), BC_INTEGRITY_VERIFY_CHANGE_NONE);
}

static void test_content_digest_mismatch_returns_content(void** state)
{
    (void)state;
    bc_integrity_meta_snapshot_t expected;
    bc_integrity_meta_snapshot_t actual;
    make_baseline(&expected);
    make_baseline(&actual);
    actual.digest_hex = "0000000000000000000000000000000000000000000000000000000000000000";
    assert_int_equal(bc_integrity_verify_compare_content(&expected, &actual), BC_INTEGRITY_VERIFY_CHANGE_CONTENT);
}

static void test_content_kind_mismatch_returns_content(void** state)
{
    (void)state;
    bc_integrity_meta_snapshot_t expected;
    bc_integrity_meta_snapshot_t actual;
    make_baseline(&expected);
    make_baseline(&actual);
    actual.kind = BC_INTEGRITY_ENTRY_KIND_DIRECTORY;
    actual.digest_hex = NULL;
    actual.digest_hex_length = 0;
    assert_int_equal(bc_integrity_verify_compare_content(&expected, &actual), BC_INTEGRITY_VERIFY_CHANGE_CONTENT);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_content_identical_returns_none),
        cmocka_unit_test(test_content_meta_change_returns_none),
        cmocka_unit_test(test_content_digest_mismatch_returns_content),
        cmocka_unit_test(test_content_kind_mismatch_returns_content),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
