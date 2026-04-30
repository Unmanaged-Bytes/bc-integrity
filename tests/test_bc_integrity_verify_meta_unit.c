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
    snapshot->mtime_nsec = 12345;
    snapshot->inode = 99;
    snapshot->nlink = 1;
}

static void test_meta_identical_returns_none(void** state)
{
    (void)state;
    bc_integrity_meta_snapshot_t expected;
    bc_integrity_meta_snapshot_t actual;
    make_baseline(&expected);
    make_baseline(&actual);
    assert_int_equal(bc_integrity_verify_compare_meta(&expected, &actual, false), BC_INTEGRITY_VERIFY_CHANGE_NONE);
}

static void test_meta_mode_change_detected(void** state)
{
    (void)state;
    bc_integrity_meta_snapshot_t expected;
    bc_integrity_meta_snapshot_t actual;
    make_baseline(&expected);
    make_baseline(&actual);
    actual.mode = 0100600;
    assert_int_equal(bc_integrity_verify_compare_meta(&expected, &actual, false), BC_INTEGRITY_VERIFY_CHANGE_META);
}

static void test_meta_uid_change_detected(void** state)
{
    (void)state;
    bc_integrity_meta_snapshot_t expected;
    bc_integrity_meta_snapshot_t actual;
    make_baseline(&expected);
    make_baseline(&actual);
    actual.uid = 0;
    assert_int_equal(bc_integrity_verify_compare_meta(&expected, &actual, false), BC_INTEGRITY_VERIFY_CHANGE_META);
}

static void test_meta_inode_change_detected(void** state)
{
    (void)state;
    bc_integrity_meta_snapshot_t expected;
    bc_integrity_meta_snapshot_t actual;
    make_baseline(&expected);
    make_baseline(&actual);
    actual.inode = 100;
    assert_int_equal(bc_integrity_verify_compare_meta(&expected, &actual, false), BC_INTEGRITY_VERIFY_CHANGE_META);
}

static void test_meta_ignore_mtime_skips_mtime(void** state)
{
    (void)state;
    bc_integrity_meta_snapshot_t expected;
    bc_integrity_meta_snapshot_t actual;
    make_baseline(&expected);
    make_baseline(&actual);
    actual.mtime_sec = 1701234567;
    actual.mtime_nsec = 9999;
    assert_int_equal(bc_integrity_verify_compare_meta(&expected, &actual, true), BC_INTEGRITY_VERIFY_CHANGE_NONE);
    assert_int_equal(bc_integrity_verify_compare_meta(&expected, &actual, false), BC_INTEGRITY_VERIFY_CHANGE_META);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_meta_identical_returns_none),   cmocka_unit_test(test_meta_mode_change_detected),
        cmocka_unit_test(test_meta_uid_change_detected),      cmocka_unit_test(test_meta_inode_change_detected),
        cmocka_unit_test(test_meta_ignore_mtime_skips_mtime),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
