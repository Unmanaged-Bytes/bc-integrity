// SPDX-License-Identifier: MIT

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include <stdbool.h>
#include <unistd.h>

#include "bc_allocators.h"
#include "bc_containers_vector.h"
#include "bc_hrbl.h"
#include "bc_integrity_cli_internal.h"
#include "bc_integrity_diff_internal.h"
#include "bc_integrity_entry_internal.h"
#include "bc_integrity_manifest_internal.h"

typedef struct fixture_state {
  char manifest_path_a[256];
  char manifest_path_b[256];
} fixture_state_t;

static int fixture_setup(void **state) {
  fixture_state_t *fixture = malloc(sizeof(*fixture));
  if (fixture == NULL) {
    return -1;
  }
  snprintf(fixture->manifest_path_a, sizeof(fixture->manifest_path_a),
           "/tmp/bc_integrity_diff_unit_%d_a.hrbl", getpid());
  snprintf(fixture->manifest_path_b, sizeof(fixture->manifest_path_b),
           "/tmp/bc_integrity_diff_unit_%d_b.hrbl", getpid());
  *state = fixture;
  return 0;
}

static int fixture_teardown(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  unlink(fixture->manifest_path_a);
  unlink(fixture->manifest_path_b);
  free(fixture);
  return 0;
}

static void make_file_entry(bc_integrity_entry_t *entry, const char *path,
                            const char *digest_hex, uint64_t mode) {
  memset(entry, 0, sizeof(*entry));
  entry->relative_path = path;
  entry->relative_path_length = strlen(path);
  entry->kind = BC_INTEGRITY_ENTRY_KIND_FILE;
  entry->ok = true;
  entry->size_bytes = 16;
  entry->mode = mode;
  entry->uid = 1000;
  entry->gid = 1000;
  entry->mtime_sec = 1700000000;
  entry->mtime_nsec = 0;
  entry->inode = (uint64_t)(100 + (unsigned char)path[0]);
  entry->nlink = 1;
  size_t digest_length = strlen(digest_hex);
  memcpy(entry->digest_hex, digest_hex, digest_length);
  entry->digest_hex[digest_length] = '\0';
  entry->digest_hex_length = digest_length;
}

static void write_manifest(bc_allocators_context_t *memory_context,
                           const char *output_path,
                           bc_integrity_entry_t *entries_array,
                           size_t entries_count) {
  bc_containers_vector_t *entries = NULL;
  assert_true(bc_containers_vector_create(
      memory_context, sizeof(bc_integrity_entry_t), 8, 1024, &entries));
  for (size_t index = 0; index < entries_count; ++index) {
    assert_true(bc_containers_vector_push(memory_context, entries,
                                          &entries_array[index]));
  }
  bc_integrity_manifest_options_t options;
  memset(&options, 0, sizeof(options));
  options.root_path = "/tmp/dummy";
  options.output_path = output_path;
  options.digest_algorithm = BC_INTEGRITY_DIGEST_ALGORITHM_SHA256;
  options.default_exclude_virtual = true;

  bc_integrity_manifest_summary_t summary;
  memset(&summary, 0, sizeof(summary));
  summary.created_at_unix_sec = 1700000000;
  summary.completed_at_unix_sec = 1700000005;
  summary.file_count = entries_count;
  summary.host = "test";
  summary.root_path_absolute = "/tmp/dummy";

  assert_true(bc_integrity_manifest_write_to_file(
      memory_context, &options, entries, &summary, output_path));
  bc_containers_vector_destroy(memory_context, entries);
}

static void test_diff_added_removed_modified(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;

  bc_allocators_context_config_t config = {.tracking_enabled = true};
  bc_allocators_context_t *memory_context = NULL;
  assert_true(bc_allocators_context_create(&config, &memory_context));

  bc_integrity_entry_t entries_a[2];
  make_file_entry(
      &entries_a[0], "alpha.txt",
      "1111111111111111111111111111111111111111111111111111111111111111", 0644);
  make_file_entry(
      &entries_a[1], "removed.txt",
      "3333333333333333333333333333333333333333333333333333333333333333", 0644);
  write_manifest(memory_context, fixture->manifest_path_a, entries_a, 2);

  bc_integrity_entry_t entries_b[2];
  make_file_entry(
      &entries_b[0], "added.txt",
      "5555555555555555555555555555555555555555555555555555555555555555", 0644);
  make_file_entry(
      &entries_b[1], "alpha.txt",
      "9999999999999999999999999999999999999999999999999999999999999999", 0644);
  write_manifest(memory_context, fixture->manifest_path_b, entries_b, 2);

  bc_integrity_diff_options_t options;
  memset(&options, 0, sizeof(options));
  options.manifest_path_a = fixture->manifest_path_a;
  options.manifest_path_b = fixture->manifest_path_b;
  options.format = BC_INTEGRITY_OUTPUT_FORMAT_TEXT;
  options.ignore_meta = false;
  options.ignore_mtime = false;

  int exit_code = -1;
  assert_true(bc_integrity_diff_run(memory_context, &options, &exit_code));
  assert_int_equal(exit_code, 1);

  bc_allocators_context_destroy(memory_context);
}

static void test_diff_identical_manifests_no_diff(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;

  bc_allocators_context_config_t config = {.tracking_enabled = true};
  bc_allocators_context_t *memory_context = NULL;
  assert_true(bc_allocators_context_create(&config, &memory_context));

  bc_integrity_entry_t entries[1];
  make_file_entry(
      &entries[0], "file.txt",
      "1234567890123456789012345678901234567890123456789012345678901234", 0644);
  write_manifest(memory_context, fixture->manifest_path_a, entries, 1);
  write_manifest(memory_context, fixture->manifest_path_b, entries, 1);

  bc_integrity_diff_options_t options;
  memset(&options, 0, sizeof(options));
  options.manifest_path_a = fixture->manifest_path_a;
  options.manifest_path_b = fixture->manifest_path_b;
  options.format = BC_INTEGRITY_OUTPUT_FORMAT_TEXT;

  int exit_code = -1;
  assert_true(bc_integrity_diff_run(memory_context, &options, &exit_code));
  assert_int_equal(exit_code, 0);

  bc_allocators_context_destroy(memory_context);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test_setup_teardown(test_diff_added_removed_modified,
                                      fixture_setup, fixture_teardown),
      cmocka_unit_test_setup_teardown(test_diff_identical_manifests_no_diff,
                                      fixture_setup, fixture_teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
