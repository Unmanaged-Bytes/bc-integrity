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
    snapshot->uid = 1000;
    snapshot->gid = 1000;
    snapshot->mtime_sec = 1700000000;
    snapshot->mtime_nsec = 0;
    snapshot->inode = 99;
    snapshot->nlink = 1;
    snapshot->digest_hex = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03";
    snapshot->digest_hex_length = 64;
    snapshot->link_target = NULL;
    snapshot->link_target_length = 0;
}

static void test_strict_identical_returns_none(void** state)
{
    (void)state;
    bc_integrity_meta_snapshot_t expected;
    bc_integrity_meta_snapshot_t actual;
    make_baseline(&expected);
    make_baseline(&actual);
    assert_int_equal(bc_integrity_verify_compare_strict(&expected, &actual, false), BC_INTEGRITY_VERIFY_CHANGE_NONE);
}

static void test_strict_digest_mismatch_returns_content(void** state)
{
    (void)state;
    bc_integrity_meta_snapshot_t expected;
    bc_integrity_meta_snapshot_t actual;
    make_baseline(&expected);
    make_baseline(&actual);
    actual.digest_hex = "0000000000000000000000000000000000000000000000000000000000000000";
    assert_int_equal(bc_integrity_verify_compare_strict(&expected, &actual, false), BC_INTEGRITY_VERIFY_CHANGE_CONTENT);
}

static void test_strict_mode_change_returns_meta(void** state)
{
    (void)state;
    bc_integrity_meta_snapshot_t expected;
    bc_integrity_meta_snapshot_t actual;
    make_baseline(&expected);
    make_baseline(&actual);
    actual.mode = 0100600;
    assert_int_equal(bc_integrity_verify_compare_strict(&expected, &actual, false), BC_INTEGRITY_VERIFY_CHANGE_META);
}

static void test_strict_both_change_returns_both(void** state)
{
    (void)state;
    bc_integrity_meta_snapshot_t expected;
    bc_integrity_meta_snapshot_t actual;
    make_baseline(&expected);
    make_baseline(&actual);
    actual.mode = 0100600;
    actual.digest_hex = "0000000000000000000000000000000000000000000000000000000000000000";
    assert_int_equal(bc_integrity_verify_compare_strict(&expected, &actual, false), BC_INTEGRITY_VERIFY_CHANGE_BOTH);
}

static void test_strict_ignore_mtime_skips_mtime(void** state)
{
    (void)state;
    bc_integrity_meta_snapshot_t expected;
    bc_integrity_meta_snapshot_t actual;
    make_baseline(&expected);
    make_baseline(&actual);
    actual.mtime_sec = 1700000777;
    assert_int_equal(bc_integrity_verify_compare_strict(&expected, &actual, true), BC_INTEGRITY_VERIFY_CHANGE_NONE);
    assert_int_equal(bc_integrity_verify_compare_strict(&expected, &actual, false), BC_INTEGRITY_VERIFY_CHANGE_META);
}

static void test_strict_link_target_change_returns_meta(void** state)
{
    (void)state;
    bc_integrity_meta_snapshot_t expected;
    bc_integrity_meta_snapshot_t actual;
    make_baseline(&expected);
    make_baseline(&actual);
    expected.link_target = "old.txt";
    expected.link_target_length = strlen("old.txt");
    actual.link_target = "new.txt";
    actual.link_target_length = strlen("new.txt");
    assert_int_equal(bc_integrity_verify_compare_strict(&expected, &actual, false), BC_INTEGRITY_VERIFY_CHANGE_META);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_strict_identical_returns_none),   cmocka_unit_test(test_strict_digest_mismatch_returns_content),
        cmocka_unit_test(test_strict_mode_change_returns_meta), cmocka_unit_test(test_strict_both_change_returns_both),
        cmocka_unit_test(test_strict_ignore_mtime_skips_mtime), cmocka_unit_test(test_strict_link_target_change_returns_meta),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
