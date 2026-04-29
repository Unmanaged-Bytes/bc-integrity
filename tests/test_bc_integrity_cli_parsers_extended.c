// SPDX-License-Identifier: MIT

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>

#include <cmocka.h>

#include <stdbool.h>

#include "bc_integrity_cli_internal.h"

static void test_parse_digest_algorithm_null_value(void **state) {
  (void)state;
  bc_integrity_digest_algorithm_t algorithm =
      BC_INTEGRITY_DIGEST_ALGORITHM_SHA256;
  assert_false(bc_integrity_cli_parse_digest_algorithm(NULL, &algorithm));
}

static void test_parse_digest_algorithm_whitespace(void **state) {
  (void)state;
  bc_integrity_digest_algorithm_t algorithm =
      BC_INTEGRITY_DIGEST_ALGORITHM_SHA256;
  assert_false(bc_integrity_cli_parse_digest_algorithm(" sha256", &algorithm));
  assert_false(bc_integrity_cli_parse_digest_algorithm("sha256 ", &algorithm));
  assert_false(bc_integrity_cli_parse_digest_algorithm("\t", &algorithm));
}

static void test_parse_digest_algorithm_partial_prefixes(void **state) {
  (void)state;
  bc_integrity_digest_algorithm_t algorithm =
      BC_INTEGRITY_DIGEST_ALGORITHM_SHA256;
  assert_false(bc_integrity_cli_parse_digest_algorithm("sha", &algorithm));
  assert_false(bc_integrity_cli_parse_digest_algorithm("sha2", &algorithm));
  assert_false(
      bc_integrity_cli_parse_digest_algorithm("sha256extra", &algorithm));
  assert_false(bc_integrity_cli_parse_digest_algorithm("xxh1280", &algorithm));
  assert_false(bc_integrity_cli_parse_digest_algorithm("xxh32", &algorithm));
}

static void test_parse_verify_mode_strict(void **state) {
  (void)state;
  bc_integrity_verify_mode_t mode = BC_INTEGRITY_VERIFY_MODE_META;
  assert_true(bc_integrity_cli_parse_verify_mode("strict", &mode));
  assert_int_equal(mode, BC_INTEGRITY_VERIFY_MODE_STRICT);
}

static void test_parse_verify_mode_content(void **state) {
  (void)state;
  bc_integrity_verify_mode_t mode = BC_INTEGRITY_VERIFY_MODE_STRICT;
  assert_true(bc_integrity_cli_parse_verify_mode("content", &mode));
  assert_int_equal(mode, BC_INTEGRITY_VERIFY_MODE_CONTENT);
}

static void test_parse_verify_mode_meta(void **state) {
  (void)state;
  bc_integrity_verify_mode_t mode = BC_INTEGRITY_VERIFY_MODE_STRICT;
  assert_true(bc_integrity_cli_parse_verify_mode("meta", &mode));
  assert_int_equal(mode, BC_INTEGRITY_VERIFY_MODE_META);
}

static void test_parse_verify_mode_invalid(void **state) {
  (void)state;
  bc_integrity_verify_mode_t mode = BC_INTEGRITY_VERIFY_MODE_STRICT;
  assert_false(bc_integrity_cli_parse_verify_mode("STRICT", &mode));
  assert_false(bc_integrity_cli_parse_verify_mode("loose", &mode));
  assert_false(bc_integrity_cli_parse_verify_mode("", &mode));
  assert_false(bc_integrity_cli_parse_verify_mode("strict ", &mode));
  assert_false(bc_integrity_cli_parse_verify_mode("met", &mode));
}

static void test_parse_verify_mode_null_value(void **state) {
  (void)state;
  bc_integrity_verify_mode_t mode = BC_INTEGRITY_VERIFY_MODE_STRICT;
  assert_false(bc_integrity_cli_parse_verify_mode(NULL, &mode));
}

static void test_parse_output_format_text(void **state) {
  (void)state;
  bc_integrity_output_format_t format = BC_INTEGRITY_OUTPUT_FORMAT_JSON;
  assert_true(bc_integrity_cli_parse_output_format("text", &format));
  assert_int_equal(format, BC_INTEGRITY_OUTPUT_FORMAT_TEXT);
}

static void test_parse_output_format_json(void **state) {
  (void)state;
  bc_integrity_output_format_t format = BC_INTEGRITY_OUTPUT_FORMAT_TEXT;
  assert_true(bc_integrity_cli_parse_output_format("json", &format));
  assert_int_equal(format, BC_INTEGRITY_OUTPUT_FORMAT_JSON);
}

static void test_parse_output_format_invalid(void **state) {
  (void)state;
  bc_integrity_output_format_t format = BC_INTEGRITY_OUTPUT_FORMAT_TEXT;
  assert_false(bc_integrity_cli_parse_output_format("yaml", &format));
  assert_false(bc_integrity_cli_parse_output_format("JSON", &format));
  assert_false(bc_integrity_cli_parse_output_format("", &format));
  assert_false(bc_integrity_cli_parse_output_format("xml", &format));
}

static void test_parse_output_format_null_value(void **state) {
  (void)state;
  bc_integrity_output_format_t format = BC_INTEGRITY_OUTPUT_FORMAT_TEXT;
  assert_false(bc_integrity_cli_parse_output_format(NULL, &format));
}

static void test_parse_threads_large_value(void **state) {
  (void)state;
  bc_integrity_threads_mode_t mode = BC_INTEGRITY_THREADS_MODE_AUTO;
  size_t worker_count = 0;
  assert_true(bc_integrity_cli_parse_threads("999999", &mode, &worker_count));
  assert_int_equal(mode, BC_INTEGRITY_THREADS_MODE_EXPLICIT);
  assert_int_equal(worker_count, 999999u);
}

static void test_parse_threads_negative_rejected(void **state) {
  (void)state;
  bc_integrity_threads_mode_t mode = BC_INTEGRITY_THREADS_MODE_AUTO;
  size_t worker_count = 0;
  assert_false(bc_integrity_cli_parse_threads("-1", &mode, &worker_count));
  assert_false(bc_integrity_cli_parse_threads("-4", &mode, &worker_count));
}

static void test_parse_threads_partial_number(void **state) {
  (void)state;
  bc_integrity_threads_mode_t mode = BC_INTEGRITY_THREADS_MODE_AUTO;
  size_t worker_count = 0;
  assert_false(bc_integrity_cli_parse_threads("12abc", &mode, &worker_count));
  assert_false(bc_integrity_cli_parse_threads("4 ", &mode, &worker_count));
  assert_false(bc_integrity_cli_parse_threads(" 4", &mode, &worker_count));
}

static void test_parse_threads_one_worker(void **state) {
  (void)state;
  bc_integrity_threads_mode_t mode = BC_INTEGRITY_THREADS_MODE_AUTO;
  size_t worker_count = 0;
  assert_true(bc_integrity_cli_parse_threads("1", &mode, &worker_count));
  assert_int_equal(mode, BC_INTEGRITY_THREADS_MODE_EXPLICIT);
  assert_int_equal(worker_count, 1u);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_parse_digest_algorithm_null_value),
      cmocka_unit_test(test_parse_digest_algorithm_whitespace),
      cmocka_unit_test(test_parse_digest_algorithm_partial_prefixes),
      cmocka_unit_test(test_parse_verify_mode_strict),
      cmocka_unit_test(test_parse_verify_mode_content),
      cmocka_unit_test(test_parse_verify_mode_meta),
      cmocka_unit_test(test_parse_verify_mode_invalid),
      cmocka_unit_test(test_parse_verify_mode_null_value),
      cmocka_unit_test(test_parse_output_format_text),
      cmocka_unit_test(test_parse_output_format_json),
      cmocka_unit_test(test_parse_output_format_invalid),
      cmocka_unit_test(test_parse_output_format_null_value),
      cmocka_unit_test(test_parse_threads_large_value),
      cmocka_unit_test(test_parse_threads_negative_rejected),
      cmocka_unit_test(test_parse_threads_partial_number),
      cmocka_unit_test(test_parse_threads_one_worker),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
