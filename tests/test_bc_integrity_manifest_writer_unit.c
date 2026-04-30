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
#include "bc_integrity_entry_internal.h"
#include "bc_integrity_manifest_internal.h"

typedef struct fixture_state {
  char file_path[256];
} fixture_state_t;

static int fixture_setup(void **state) {
  fixture_state_t *fixture = malloc(sizeof(*fixture));
  if (fixture == NULL) {
    return -1;
  }
  snprintf(fixture->file_path, sizeof(fixture->file_path),
           "/tmp/bc_integrity_manifest_writer_%d.hrbl", getpid());
  *state = fixture;
  return 0;
}

static int fixture_teardown(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  unlink(fixture->file_path);
  free(fixture);
  return 0;
}

static void make_file_entry(bc_integrity_entry_t *entry, const char *path,
                            const char *digest_hex) {
  memset(entry, 0, sizeof(*entry));
  entry->relative_path = path;
  entry->relative_path_length = strlen(path);
  entry->kind = BC_INTEGRITY_ENTRY_KIND_FILE;
  entry->ok = true;
  entry->size_bytes = 42;
  entry->mode = 0100644;
  entry->uid = 1000;
  entry->gid = 1000;
  entry->mtime_sec = 1700000000;
  entry->mtime_nsec = 12345;
  entry->inode = 99;
  entry->nlink = 1;
  size_t digest_length = strlen(digest_hex);
  memcpy(entry->digest_hex, digest_hex, digest_length);
  entry->digest_hex[digest_length] = '\0';
  entry->digest_hex_length = digest_length;
}

static void test_writer_round_trip_via_reader(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;

  bc_allocators_context_config_t allocator_config = {.tracking_enabled = true};
  bc_allocators_context_t *memory_context = NULL;
  assert_true(bc_allocators_context_create(&allocator_config, &memory_context));

  bc_containers_vector_t *entries = NULL;
  assert_true(bc_containers_vector_create(
      memory_context, sizeof(bc_integrity_entry_t), 8, 1024, &entries));

  bc_integrity_entry_t entry_a;
  make_file_entry(
      &entry_a, "alpha.txt",
      "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03");
  assert_true(bc_containers_vector_push(memory_context, entries, &entry_a));

  bc_integrity_entry_t entry_b;
  make_file_entry(
      &entry_b, "beta.txt",
      "0000000000000000000000000000000000000000000000000000000000000000");
  entry_b.size_bytes = 0;
  assert_true(bc_containers_vector_push(memory_context, entries, &entry_b));

  bc_integrity_manifest_options_t options;
  memset(&options, 0, sizeof(options));
  options.root_path = "/tmp/dummy";
  options.output_path = fixture->file_path;
  options.digest_algorithm = BC_INTEGRITY_DIGEST_ALGORITHM_SHA256;
  options.default_exclude_virtual = true;

  bc_integrity_manifest_summary_t summary;
  memset(&summary, 0, sizeof(summary));
  summary.created_at_unix_sec = 1700000000;
  summary.completed_at_unix_sec = 1700000005;
  summary.walltime_ms = 5000;
  summary.file_count = 2;
  summary.directory_count = 0;
  summary.symlink_count = 0;
  summary.total_bytes = 84;
  summary.host = "ws-test";
  summary.root_path_absolute = "/tmp/dummy";

  assert_true(bc_integrity_manifest_write_to_file(
      memory_context, &options, entries, &summary, fixture->file_path));

  bc_hrbl_reader_t *reader = NULL;
  assert_true(bc_hrbl_reader_open(memory_context, fixture->file_path, &reader));

  bc_hrbl_value_ref_t meta_ref;
  assert_true(
      bc_hrbl_reader_find(reader, "meta.tool", strlen("meta.tool"), &meta_ref));
  const char *tool_name = NULL;
  size_t tool_length = 0;
  assert_true(bc_hrbl_reader_get_string(&meta_ref, &tool_name, &tool_length));
  assert_int_equal(tool_length, strlen("bc-integrity"));
  assert_memory_equal(tool_name, "bc-integrity", tool_length);

  bc_hrbl_value_ref_t schema_ref;
  assert_true(bc_hrbl_reader_find(reader, "meta.schema_version",
                                  strlen("meta.schema_version"), &schema_ref));
  uint64_t schema_value = 0;
  assert_true(bc_hrbl_reader_get_uint64(&schema_ref, &schema_value));
  assert_int_equal(schema_value, 1u);

  bc_hrbl_value_ref_t digest_ref;
  assert_true(bc_hrbl_reader_find(reader, "entries.'alpha.txt'.digest_hex",
                                  strlen("entries.'alpha.txt'.digest_hex"),
                                  &digest_ref));
  const char *digest_value = NULL;
  size_t digest_length = 0;
  assert_true(
      bc_hrbl_reader_get_string(&digest_ref, &digest_value, &digest_length));
  assert_int_equal(digest_length, 64u);

  bc_hrbl_value_ref_t errors_ref;
  assert_true(bc_hrbl_reader_find(reader, "summary.errors_count",
                                  strlen("summary.errors_count"), &errors_ref));
  uint64_t errors_value = 1234u;
  assert_true(bc_hrbl_reader_get_uint64(&errors_ref, &errors_value));
  assert_int_equal(errors_value, 0u);

  bc_hrbl_reader_close(reader);
  bc_containers_vector_destroy(memory_context, entries);
  bc_allocators_context_destroy(memory_context);
}

static void test_writer_handles_symlink_entry(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;

  bc_allocators_context_config_t allocator_config = {.tracking_enabled = true};
  bc_allocators_context_t *memory_context = NULL;
  assert_true(bc_allocators_context_create(&allocator_config, &memory_context));

  bc_containers_vector_t *entries = NULL;
  assert_true(bc_containers_vector_create(
      memory_context, sizeof(bc_integrity_entry_t), 4, 1024, &entries));

  bc_integrity_entry_t link_entry;
  memset(&link_entry, 0, sizeof(link_entry));
  link_entry.relative_path = "link.txt";
  link_entry.relative_path_length = strlen("link.txt");
  link_entry.kind = BC_INTEGRITY_ENTRY_KIND_SYMLINK;
  link_entry.ok = true;
  link_entry.size_bytes = 8;
  link_entry.mode = 0120777;
  link_entry.uid = 1000;
  link_entry.gid = 1000;
  link_entry.link_target = "file.txt";
  link_entry.link_target_length = strlen("file.txt");
  assert_true(bc_containers_vector_push(memory_context, entries, &link_entry));

  bc_integrity_manifest_options_t options;
  memset(&options, 0, sizeof(options));
  options.root_path = "/tmp/dummy";
  options.output_path = fixture->file_path;
  options.digest_algorithm = BC_INTEGRITY_DIGEST_ALGORITHM_SHA256;

  bc_integrity_manifest_summary_t summary;
  memset(&summary, 0, sizeof(summary));
  summary.symlink_count = 1;
  summary.host = "ws-test";
  summary.root_path_absolute = "/tmp/dummy";

  assert_true(bc_integrity_manifest_write_to_file(
      memory_context, &options, entries, &summary, fixture->file_path));

  bc_hrbl_reader_t *reader = NULL;
  assert_true(bc_hrbl_reader_open(memory_context, fixture->file_path, &reader));

  bc_hrbl_value_ref_t link_ref;
  assert_true(bc_hrbl_reader_find(reader, "entries.'link.txt'.link_target",
                                  strlen("entries.'link.txt'.link_target"),
                                  &link_ref));
  const char *target = NULL;
  size_t target_length = 0;
  assert_true(bc_hrbl_reader_get_string(&link_ref, &target, &target_length));
  assert_int_equal(target_length, 8u);
  assert_memory_equal(target, "file.txt", 8u);

  bc_hrbl_reader_close(reader);
  bc_containers_vector_destroy(memory_context, entries);
  bc_allocators_context_destroy(memory_context);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test_setup_teardown(test_writer_round_trip_via_reader,
                                      fixture_setup, fixture_teardown),
      cmocka_unit_test_setup_teardown(test_writer_handles_symlink_entry,
                                      fixture_setup, fixture_teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
