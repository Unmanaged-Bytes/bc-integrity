// SPDX-License-Identifier: MIT

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include <stdbool.h>

#include "bc_integrity_walk_internal.h"

static void test_is_hidden_segment_root_dot(void **state) {
  (void)state;
  assert_true(
      bc_integrity_walk_is_hidden_segment(".bashrc", strlen(".bashrc")));
  assert_true(bc_integrity_walk_is_hidden_segment(".git", strlen(".git")));
  assert_true(
      bc_integrity_walk_is_hidden_segment(".cache/foo", strlen(".cache/foo")));
}

static void test_is_hidden_segment_inner_dot(void **state) {
  (void)state;
  assert_true(
      bc_integrity_walk_is_hidden_segment("a/.git/b", strlen("a/.git/b")));
  assert_true(
      bc_integrity_walk_is_hidden_segment("foo/.cache", strlen("foo/.cache")));
  assert_true(bc_integrity_walk_is_hidden_segment("path/with/.dotted",
                                                  strlen("path/with/.dotted")));
}

static void test_is_hidden_segment_negative(void **state) {
  (void)state;
  assert_false(bc_integrity_walk_is_hidden_segment("regular.txt",
                                                   strlen("regular.txt")));
  assert_false(bc_integrity_walk_is_hidden_segment("a.b/c", strlen("a.b/c")));
  assert_false(bc_integrity_walk_is_hidden_segment("dir/file.ext",
                                                   strlen("dir/file.ext")));
  assert_false(bc_integrity_walk_is_hidden_segment("", 0));
}

static void test_is_virtual_root_positive(void **state) {
  (void)state;
  assert_true(bc_integrity_walk_is_virtual_root("/proc", 5));
  assert_true(bc_integrity_walk_is_virtual_root("/sys", 4));
  assert_true(bc_integrity_walk_is_virtual_root("/dev", 4));
  assert_true(bc_integrity_walk_is_virtual_root("/run", 4));
  assert_true(bc_integrity_walk_is_virtual_root("/tmp", 4));
}

static void test_is_virtual_root_negative(void **state) {
  (void)state;
  assert_false(bc_integrity_walk_is_virtual_root("/etc", 4));
  assert_false(bc_integrity_walk_is_virtual_root("/home", 5));
  assert_false(bc_integrity_walk_is_virtual_root("/proc/version",
                                                 strlen("/proc/version")));
  assert_false(
      bc_integrity_walk_is_virtual_root("/tmp/foo", strlen("/tmp/foo")));
}

static void test_is_virtual_subpath_filters_when_root_outside(void **state) {
  (void)state;
  const char *root = "/";
  size_t root_length = 1;
  assert_true(bc_integrity_walk_is_virtual_subpath(
      root, root_length, "/proc/cpuinfo", strlen("/proc/cpuinfo")));
  assert_true(bc_integrity_walk_is_virtual_subpath(
      root, root_length, "/sys/kernel", strlen("/sys/kernel")));
  assert_true(bc_integrity_walk_is_virtual_subpath(
      root, root_length, "/tmp/file", strlen("/tmp/file")));
  assert_false(bc_integrity_walk_is_virtual_subpath(
      root, root_length, "/etc/hosts", strlen("/etc/hosts")));
  assert_false(bc_integrity_walk_is_virtual_subpath(
      root, root_length, "/usr/bin/ls", strlen("/usr/bin/ls")));
}

static void
test_is_virtual_subpath_not_filtered_when_root_inside(void **state) {
  (void)state;
  const char *root = "/tmp/scan";
  size_t root_length = strlen("/tmp/scan");
  assert_false(bc_integrity_walk_is_virtual_subpath(
      root, root_length, "/tmp/scan/file", strlen("/tmp/scan/file")));
  assert_false(bc_integrity_walk_is_virtual_subpath(
      root, root_length, "/tmp/scan", strlen("/tmp/scan")));
}

static void test_is_virtual_subpath_proc_in_etc_walk(void **state) {
  (void)state;
  const char *root = "/etc";
  size_t root_length = strlen("/etc");
  assert_false(bc_integrity_walk_is_virtual_subpath(
      root, root_length, "/etc/hosts", strlen("/etc/hosts")));
  assert_false(bc_integrity_walk_is_virtual_subpath(
      root, root_length, "/etc/passwd", strlen("/etc/passwd")));
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_is_hidden_segment_root_dot),
      cmocka_unit_test(test_is_hidden_segment_inner_dot),
      cmocka_unit_test(test_is_hidden_segment_negative),
      cmocka_unit_test(test_is_virtual_root_positive),
      cmocka_unit_test(test_is_virtual_root_negative),
      cmocka_unit_test(test_is_virtual_subpath_filters_when_root_outside),
      cmocka_unit_test(test_is_virtual_subpath_not_filtered_when_root_inside),
      cmocka_unit_test(test_is_virtual_subpath_proc_in_etc_walk),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
