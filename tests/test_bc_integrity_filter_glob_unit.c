// SPDX-License-Identifier: MIT

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include <stdbool.h>

#include "bc_allocators.h"
#include "bc_integrity_filter_internal.h"

static void test_glob_simple_star_matches_basename(void **state) {
  (void)state;
  assert_true(bc_integrity_filter_glob_matches("*.txt", "file.txt",
                                               strlen("file.txt")));
  assert_false(bc_integrity_filter_glob_matches("*.txt", "file.bin",
                                                strlen("file.bin")));
}

static void test_glob_question_mark_matches_single_char(void **state) {
  (void)state;
  assert_true(
      bc_integrity_filter_glob_matches("?.txt", "a.txt", strlen("a.txt")));
  assert_false(
      bc_integrity_filter_glob_matches("?.txt", "ab.txt", strlen("ab.txt")));
}

static void test_glob_double_star_descends_subdirs(void **state) {
  (void)state;
  assert_true(bc_integrity_filter_glob_matches("src/**/foo.c", "src/a/b/foo.c",
                                               strlen("src/a/b/foo.c")));
  assert_true(bc_integrity_filter_glob_matches("**/foo.c", "src/foo.c",
                                               strlen("src/foo.c")));
  assert_true(bc_integrity_filter_glob_matches("**", "any/path/here.txt",
                                               strlen("any/path/here.txt")));
}

static void test_glob_star_does_not_cross_slash(void **state) {
  (void)state;
  assert_false(bc_integrity_filter_glob_matches("*.c", "sub/file.c",
                                                strlen("sub/file.c")));
}

static void test_glob_charset_matches(void **state) {
  (void)state;
  assert_true(
      bc_integrity_filter_glob_matches("[abc].txt", "a.txt", strlen("a.txt")));
  assert_true(
      bc_integrity_filter_glob_matches("[abc].txt", "b.txt", strlen("b.txt")));
  assert_false(
      bc_integrity_filter_glob_matches("[abc].txt", "d.txt", strlen("d.txt")));
  assert_true(bc_integrity_filter_glob_matches("file[0-9].log", "file3.log",
                                               strlen("file3.log")));
}

static void test_filter_accepts_path_with_only_excludes(void **state) {
  (void)state;
  bc_allocators_context_config_t config = {.tracking_enabled = true};
  bc_allocators_context_t *memory_context = NULL;
  assert_true(bc_allocators_context_create(&config, &memory_context));

  bc_integrity_filter_t *filter = NULL;
  assert_true(bc_integrity_filter_create(memory_context, NULL,
                                         "*.tmp\nbuild/**", &filter));

  assert_true(bc_integrity_filter_accepts_path(filter, "src/main.c",
                                               strlen("src/main.c")));
  assert_false(
      bc_integrity_filter_accepts_path(filter, "x.tmp", strlen("x.tmp")));
  assert_false(bc_integrity_filter_accepts_path(filter, "build/x.o",
                                                strlen("build/x.o")));

  bc_integrity_filter_destroy(memory_context, filter);
  bc_allocators_context_destroy(memory_context);
}

static void test_filter_accepts_path_with_includes_only(void **state) {
  (void)state;
  bc_allocators_context_config_t config = {.tracking_enabled = true};
  bc_allocators_context_t *memory_context = NULL;
  assert_true(bc_allocators_context_create(&config, &memory_context));

  bc_integrity_filter_t *filter = NULL;
  assert_true(
      bc_integrity_filter_create(memory_context, "*.txt", NULL, &filter));

  assert_true(
      bc_integrity_filter_accepts_path(filter, "file.txt", strlen("file.txt")));
  assert_false(
      bc_integrity_filter_accepts_path(filter, "file.bin", strlen("file.bin")));

  bc_integrity_filter_destroy(memory_context, filter);
  bc_allocators_context_destroy(memory_context);
}

static void test_filter_exclude_takes_precedence(void **state) {
  (void)state;
  bc_allocators_context_config_t config = {.tracking_enabled = true};
  bc_allocators_context_t *memory_context = NULL;
  assert_true(bc_allocators_context_create(&config, &memory_context));

  bc_integrity_filter_t *filter = NULL;
  assert_true(bc_integrity_filter_create(memory_context, "*.txt", "secret.txt",
                                         &filter));

  assert_true(
      bc_integrity_filter_accepts_path(filter, "ok.txt", strlen("ok.txt")));
  assert_false(bc_integrity_filter_accepts_path(filter, "secret.txt",
                                                strlen("secret.txt")));

  bc_integrity_filter_destroy(memory_context, filter);
  bc_allocators_context_destroy(memory_context);
}

static void test_filter_directory_descent_with_recursive_exclude(void **state) {
  (void)state;
  bc_allocators_context_config_t config = {.tracking_enabled = true};
  bc_allocators_context_t *memory_context = NULL;
  assert_true(bc_allocators_context_create(&config, &memory_context));

  bc_integrity_filter_t *filter = NULL;
  assert_true(
      bc_integrity_filter_create(memory_context, NULL, "build/**", &filter));

  assert_false(
      bc_integrity_filter_accepts_directory(filter, "build", strlen("build")));
  assert_true(
      bc_integrity_filter_accepts_directory(filter, "src", strlen("src")));

  bc_integrity_filter_destroy(memory_context, filter);
  bc_allocators_context_destroy(memory_context);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_glob_simple_star_matches_basename),
      cmocka_unit_test(test_glob_question_mark_matches_single_char),
      cmocka_unit_test(test_glob_double_star_descends_subdirs),
      cmocka_unit_test(test_glob_star_does_not_cross_slash),
      cmocka_unit_test(test_glob_charset_matches),
      cmocka_unit_test(test_filter_accepts_path_with_only_excludes),
      cmocka_unit_test(test_filter_accepts_path_with_includes_only),
      cmocka_unit_test(test_filter_exclude_takes_precedence),
      cmocka_unit_test(test_filter_directory_descent_with_recursive_exclude),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
