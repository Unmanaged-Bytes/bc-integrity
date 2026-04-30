// SPDX-License-Identifier: MIT

#include "bc_integrity_verify_internal.h"

#include "bc_core.h"

#include <stdbool.h>
#include <stddef.h>

static bool bc_integrity_verify_strict_strings_equal(const char* left, size_t left_length, const char* right, size_t right_length)
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

static bool bc_integrity_verify_strict_meta_matches(const bc_integrity_meta_snapshot_t* expected,
                                                    const bc_integrity_meta_snapshot_t* actual, bool ignore_mtime)
{
    if (expected->kind != actual->kind) {
        return false;
    }
    if (expected->size_bytes != actual->size_bytes) {
        return false;
    }
    if (expected->mode != actual->mode) {
        return false;
    }
    if (expected->uid != actual->uid) {
        return false;
    }
    if (expected->gid != actual->gid) {
        return false;
    }
    if (!ignore_mtime) {
        if (expected->mtime_sec != actual->mtime_sec) {
            return false;
        }
        if (expected->mtime_nsec != actual->mtime_nsec) {
            return false;
        }
    }
    if (expected->inode != actual->inode) {
        return false;
    }
    if (expected->nlink != actual->nlink) {
        return false;
    }
    if (!bc_integrity_verify_strict_strings_equal(expected->link_target, expected->link_target_length, actual->link_target,
                                                  actual->link_target_length)) {
        return false;
    }
    return true;
}

static bool bc_integrity_verify_strict_digest_matches(const bc_integrity_meta_snapshot_t* expected,
                                                      const bc_integrity_meta_snapshot_t* actual)
{
    return bc_integrity_verify_strict_strings_equal(expected->digest_hex, expected->digest_hex_length, actual->digest_hex,
                                                    actual->digest_hex_length);
}

bc_integrity_verify_change_kind_t bc_integrity_verify_compare_strict(const bc_integrity_meta_snapshot_t* expected,
                                                                     const bc_integrity_meta_snapshot_t* actual, bool ignore_mtime)
{
    bool meta_equal = bc_integrity_verify_strict_meta_matches(expected, actual, ignore_mtime);
    bool digest_equal = bc_integrity_verify_strict_digest_matches(expected, actual);
    if (meta_equal && digest_equal) {
        return BC_INTEGRITY_VERIFY_CHANGE_NONE;
    }
    if (!meta_equal && !digest_equal) {
        return BC_INTEGRITY_VERIFY_CHANGE_BOTH;
    }
    if (!digest_equal) {
        return BC_INTEGRITY_VERIFY_CHANGE_CONTENT;
    }
    return BC_INTEGRITY_VERIFY_CHANGE_META;
}
