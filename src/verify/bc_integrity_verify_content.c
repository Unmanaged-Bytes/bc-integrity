// SPDX-License-Identifier: MIT

#include "bc_integrity_verify_internal.h"

#include "bc_core.h"

#include <stdbool.h>
#include <stddef.h>

bc_integrity_verify_change_kind_t bc_integrity_verify_compare_content(
    const bc_integrity_meta_snapshot_t *expected,
    const bc_integrity_meta_snapshot_t *actual) {
  if (expected->kind != actual->kind) {
    return BC_INTEGRITY_VERIFY_CHANGE_CONTENT;
  }
  if (expected->digest_hex_length != actual->digest_hex_length) {
    return BC_INTEGRITY_VERIFY_CHANGE_CONTENT;
  }
  if (expected->digest_hex_length == 0) {
    return BC_INTEGRITY_VERIFY_CHANGE_NONE;
  }
  bool equal = false;
  (void)bc_core_equal(expected->digest_hex, actual->digest_hex,
                      expected->digest_hex_length, &equal);
  return equal ? BC_INTEGRITY_VERIFY_CHANGE_NONE
               : BC_INTEGRITY_VERIFY_CHANGE_CONTENT;
}
