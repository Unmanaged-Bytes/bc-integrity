// SPDX-License-Identifier: MIT

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include <stdbool.h>

#include "bc_integrity_walk_internal.h"

static void test_is_hidden_segment_dot_file_at_top(void **state) {
  (void)state;
  assert_true(bc_integrity_walk_is_hidden_segment(".", 1));
  assert_true(bc_integrity_walk_is_hidden_segment("..", 2));
  assert_true(
      bc_integrity_walk_is_hidden_segment(".config", strlen(".config")));
}

static void test_is_hidden_segment_null_input(void **state) {
  (void)state;
  assert_false(bc_integrity_walk_is_hidden_segment(NULL, 5));
  assert_false(bc_integrity_walk_is_hidden_segment(NULL, 0));
}

static void test_is_hidden_segment_complex_paths(void **state) {
  (void)state;
  assert_true(bc_integrity_walk_is_hidden_segment("a/b/c/.hidden/x",
                                                  strlen("a/b/c/.hidden/x")));
  assert_true(bc_integrity_walk_is_hidden_segment("normal/.config",
                                                  strlen("normal/.config")));
  assert_true(bc_integrity_walk_is_hidden_segment("path/.hidden/file",
                                                  strlen("path/.hidden/file")));
}

static void test_is_hidden_segment_dotfile_with_extension(void **state) {
  (void)state;
  assert_false(bc_integrity_walk_is_hidden_segment("dotfile.txt",
                                                   strlen("dotfile.txt")));
  assert_false(bc_integrity_walk_is_hidden_segment("name.with.dots",
                                                   strlen("name.with.dots")));
  assert_false(
      bc_integrity_walk_is_hidden_segment("dir/file.ext", strlen("dir/file.ext")));
  assert_false(bc_integrity_walk_is_hidden_segment("a.b/c.d", strlen("a.b/c.d")));
}

static void test_is_virtual_root_all_paths(void **state) {
  (void)state;
  assert_true(bc_integrity_walk_is_virtual_root("/proc", strlen("/proc")));
  assert_true(bc_integrity_walk_is_virtual_root("/sys", strlen("/sys")));
  assert_true(bc_integrity_walk_is_virtual_root("/dev", strlen("/dev")));
  assert_true(bc_integrity_walk_is_virtual_root("/run", strlen("/run")));
  assert_true(bc_integrity_walk_is_virtual_root("/tmp", strlen("/tmp")));
}

static void test_is_virtual_root_partial_match_rejected(void **state) {
  (void)state;
  assert_false(bc_integrity_walk_is_virtual_root("/pro", strlen("/pro")));
  assert_false(
      bc_integrity_walk_is_virtual_root("/procfile", strlen("/procfile")));
  assert_false(bc_integrity_walk_is_virtual_root("/sysadmin",
                                                 strlen("/sysadmin")));
  assert_false(bc_integrity_walk_is_virtual_root("/", 1));
  assert_false(bc_integrity_walk_is_virtual_root("/var", strlen("/var")));
}

static void test_is_virtual_subpath_user_explicitly_inside(void **state) {
  (void)state;
  const char *root = "/proc";
  size_t root_length = strlen("/proc");
  assert_false(bc_integrity_walk_is_virtual_subpath(
      root, root_length, "/proc/cpuinfo", strlen("/proc/cpuinfo")));
  assert_false(bc_integrity_walk_is_virtual_subpath(
      root, root_length, "/proc/123/status", strlen("/proc/123/status")));
}

static void test_is_virtual_subpath_user_explicitly_inside_dev(void **state) {
  (void)state;
  const char *root = "/dev";
  size_t root_length = strlen("/dev");
  assert_false(bc_integrity_walk_is_virtual_subpath(
      root, root_length, "/dev/sda", strlen("/dev/sda")));
}

static void test_is_virtual_subpath_user_explicitly_inside_run(void **state) {
  (void)state;
  const char *root = "/run/user/1000";
  size_t root_length = strlen("/run/user/1000");
  assert_false(bc_integrity_walk_is_virtual_subpath(
      root, root_length, "/run/user/1000/x", strlen("/run/user/1000/x")));
}

static void test_is_virtual_subpath_null_inputs(void **state) {
  (void)state;
  assert_false(
      bc_integrity_walk_is_virtual_subpath(NULL, 0, "/proc/foo", 9));
  assert_false(
      bc_integrity_walk_is_virtual_subpath("/", 1, NULL, 0));
  assert_false(bc_integrity_walk_is_virtual_subpath(NULL, 0, NULL, 0));
}

static void test_is_virtual_subpath_each_virtual(void **state) {
  (void)state;
  const char *root = "/";
  size_t root_length = 1;
  assert_true(bc_integrity_walk_is_virtual_subpath(
      root, root_length, "/proc", strlen("/proc")));
  assert_true(bc_integrity_walk_is_virtual_subpath(
      root, root_length, "/sys/kernel/debug",
      strlen("/sys/kernel/debug")));
  assert_true(bc_integrity_walk_is_virtual_subpath(
      root, root_length, "/dev", strlen("/dev")));
  assert_true(bc_integrity_walk_is_virtual_subpath(
      root, root_length, "/run", strlen("/run")));
  assert_true(bc_integrity_walk_is_virtual_subpath(
      root, root_length, "/tmp", strlen("/tmp")));
}

static void test_is_virtual_subpath_lookalike_paths(void **state) {
  (void)state;
  const char *root = "/";
  size_t root_length = 1;
  assert_false(bc_integrity_walk_is_virtual_subpath(
      root, root_length, "/procfs", strlen("/procfs")));
  assert_false(bc_integrity_walk_is_virtual_subpath(
      root, root_length, "/system", strlen("/system")));
  assert_false(bc_integrity_walk_is_virtual_subpath(
      root, root_length, "/development", strlen("/development")));
  assert_false(bc_integrity_walk_is_virtual_subpath(
      root, root_length, "/tmpfile", strlen("/tmpfile")));
}

static void test_is_virtual_subpath_root_inside_one_filters_others(void **state) {
  (void)state;
  const char *root = "/tmp";
  size_t root_length = strlen("/tmp");
  assert_false(bc_integrity_walk_is_virtual_subpath(
      root, root_length, "/tmp/scan", strlen("/tmp/scan")));
  assert_true(bc_integrity_walk_is_virtual_subpath(
      root, root_length, "/proc/cpuinfo", strlen("/proc/cpuinfo")));
  assert_true(bc_integrity_walk_is_virtual_subpath(
      root, root_length, "/sys/kernel", strlen("/sys/kernel")));
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_is_hidden_segment_dot_file_at_top),
      cmocka_unit_test(test_is_hidden_segment_null_input),
      cmocka_unit_test(test_is_hidden_segment_complex_paths),
      cmocka_unit_test(test_is_hidden_segment_dotfile_with_extension),
      cmocka_unit_test(test_is_virtual_root_all_paths),
      cmocka_unit_test(test_is_virtual_root_partial_match_rejected),
      cmocka_unit_test(test_is_virtual_subpath_user_explicitly_inside),
      cmocka_unit_test(test_is_virtual_subpath_user_explicitly_inside_dev),
      cmocka_unit_test(test_is_virtual_subpath_user_explicitly_inside_run),
      cmocka_unit_test(test_is_virtual_subpath_null_inputs),
      cmocka_unit_test(test_is_virtual_subpath_each_virtual),
      cmocka_unit_test(test_is_virtual_subpath_lookalike_paths),
      cmocka_unit_test(test_is_virtual_subpath_root_inside_one_filters_others),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
