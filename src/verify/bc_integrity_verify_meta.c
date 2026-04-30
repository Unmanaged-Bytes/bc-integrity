// SPDX-License-Identifier: MIT

#include "bc_integrity_verify_internal.h"

#include "bc_core.h"

#include <stdbool.h>
#include <stddef.h>

static bool bc_integrity_verify_meta_strings_equal(const char* left, size_t left_length, const char* right, size_t right_length)
{
    if (left_length != right_length) {
        return false;
    }
    if (left_length == 0) {
        return true;
    }
    bool equal = false;
    (void)bc_core_equal(left, right, left_length, &equal);
    return equal;
}

bc_integrity_verify_change_kind_t bc_integrity_verify_compare_meta(const bc_integrity_meta_snapshot_t* expected,
                                                                   const bc_integrity_meta_snapshot_t* actual, bool ignore_mtime)
{
    if (expected->kind != actual->kind) {
        return BC_INTEGRITY_VERIFY_CHANGE_META;
    }
    if (expected->size_bytes != actual->size_bytes) {
        return BC_INTEGRITY_VERIFY_CHANGE_META;
    }
    if (expected->mode != actual->mode) {
        return BC_INTEGRITY_VERIFY_CHANGE_META;
    }
    if (expected->uid != actual->uid) {
        return BC_INTEGRITY_VERIFY_CHANGE_META;
    }
    if (expected->gid != actual->gid) {
        return BC_INTEGRITY_VERIFY_CHANGE_META;
    }
    if (!ignore_mtime) {
        if (expected->mtime_sec != actual->mtime_sec) {
            return BC_INTEGRITY_VERIFY_CHANGE_META;
        }
        if (expected->mtime_nsec != actual->mtime_nsec) {
            return BC_INTEGRITY_VERIFY_CHANGE_META;
        }
    }
    if (expected->inode != actual->inode) {
        return BC_INTEGRITY_VERIFY_CHANGE_META;
    }
    if (expected->nlink != actual->nlink) {
        return BC_INTEGRITY_VERIFY_CHANGE_META;
    }
    if (!bc_integrity_verify_meta_strings_equal(expected->link_target, expected->link_target_length, actual->link_target,
                                                actual->link_target_length)) {
        return BC_INTEGRITY_VERIFY_CHANGE_META;
    }
    return BC_INTEGRITY_VERIFY_CHANGE_NONE;
}
