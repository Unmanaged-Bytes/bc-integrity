// SPDX-License-Identifier: MIT

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include "bc_allocators.h"
#include "bc_containers_vector.h"
#include "bc_hrbl.h"
#include "bc_integrity_cli_internal.h"
#include "bc_integrity_entry_internal.h"
#include "bc_integrity_manifest_internal.h"

typedef struct fixture_state {
  char file_path[256];
  bc_allocators_context_t *memory_context;
  bc_containers_vector_t *entries;
} fixture_state_t;

static int fixture_setup(void **state) {
  fixture_state_t *fixture = malloc(sizeof(*fixture));
  if (fixture == NULL) {
    return -1;
  }
  snprintf(fixture->file_path, sizeof(fixture->file_path),
           "/tmp/bc_integrity_manifest_writer_ext_%d.hrbl", getpid());
  bc_allocators_context_config_t allocator_config = {.tracking_enabled = true};
  fixture->memory_context = NULL;
  bc_allocators_context_create(&allocator_config, &fixture->memory_context);
  fixture->entries = NULL;
  bc_containers_vector_create(fixture->memory_context,
                              sizeof(bc_integrity_entry_t), 8, 4096,
                              &fixture->entries);
  *state = fixture;
  return 0;
}

static int fixture_teardown(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  bc_containers_vector_destroy(fixture->memory_context, fixture->entries);
  bc_allocators_context_destroy(fixture->memory_context);
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
  entry->size_bytes = 100;
  entry->mode = 0100644;
  entry->uid = 1000;
  entry->gid = 1000;
  entry->mtime_sec = 1700000000;
  entry->mtime_nsec = 12345;
  entry->inode = 123;
  entry->nlink = 1;
  size_t digest_length = strlen(digest_hex);
  memcpy(entry->digest_hex, digest_hex, digest_length);
  entry->digest_hex[digest_length] = '\0';
  entry->digest_hex_length = digest_length;
}

static void make_options(bc_integrity_manifest_options_t *options,
                         const char *output_path,
                         bc_integrity_digest_algorithm_t algorithm) {
  memset(options, 0, sizeof(*options));
  options->root_path = "/tmp";
  options->output_path = output_path;
  options->digest_algorithm = algorithm;
}

static void make_summary(bc_integrity_manifest_summary_t *summary) {
  memset(summary, 0, sizeof(*summary));
  summary->host = "host";
  summary->root_path_absolute = "/tmp";
}

static void test_writer_meta_block_complete_fields(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  bc_integrity_entry_t entry;
  make_file_entry(
      &entry, "s.txt",
      "1111111111111111111111111111111111111111111111111111111111111111");
  bc_containers_vector_push(fixture->memory_context, fixture->entries, &entry);

  bc_integrity_manifest_options_t options;
  make_options(&options, fixture->file_path,
               BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
  options.follow_symlinks = true;
  options.include_hidden = true;
  options.include_special = true;
  options.default_exclude_virtual = false;

  bc_integrity_manifest_summary_t summary;
  make_summary(&summary);
  summary.file_count = 17;
  summary.directory_count = 5;
  summary.symlink_count = 2;
  summary.total_bytes = 102400;
  summary.host = "ws-extended";
  summary.root_path_absolute = "/abs/etc";

  assert_true(bc_integrity_manifest_write_to_file(fixture->memory_context,
                                                  &options, fixture->entries,
                                                  &summary, fixture->file_path));

  bc_hrbl_reader_t *reader = NULL;
  assert_true(bc_hrbl_reader_open(fixture->memory_context, fixture->file_path,
                                  &reader));

  bc_hrbl_value_ref_t value_ref;
  uint64_t u_value = 0;
  const char *s_value = NULL;
  size_t s_length = 0;

  assert_true(bc_hrbl_reader_find(reader, "meta.host", strlen("meta.host"),
                                  &value_ref));
  assert_true(bc_hrbl_reader_get_string(&value_ref, &s_value, &s_length));
  assert_memory_equal(s_value, "ws-extended", s_length);
  assert_true(bc_hrbl_reader_find(reader, "meta.root_path",
                                  strlen("meta.root_path"), &value_ref));
  assert_true(bc_hrbl_reader_get_string(&value_ref, &s_value, &s_length));
  assert_memory_equal(s_value, "/abs/etc", s_length);
  assert_true(bc_hrbl_reader_find(reader, "meta.file_count",
                                  strlen("meta.file_count"), &value_ref));
  assert_true(bc_hrbl_reader_get_uint64(&value_ref, &u_value));
  assert_int_equal(u_value, 17u);
  assert_true(bc_hrbl_reader_find(reader, "meta.dir_count",
                                  strlen("meta.dir_count"), &value_ref));
  assert_true(bc_hrbl_reader_get_uint64(&value_ref, &u_value));
  assert_int_equal(u_value, 5u);
  assert_true(bc_hrbl_reader_find(reader, "meta.symlink_count",
                                  strlen("meta.symlink_count"), &value_ref));
  assert_true(bc_hrbl_reader_get_uint64(&value_ref, &u_value));
  assert_int_equal(u_value, 2u);
  assert_true(bc_hrbl_reader_find(reader, "meta.total_bytes",
                                  strlen("meta.total_bytes"), &value_ref));
  assert_true(bc_hrbl_reader_get_uint64(&value_ref, &u_value));
  assert_int_equal(u_value, 102400u);
  assert_true(bc_hrbl_reader_find(reader,
                                  "meta.walk_options.follow_symlinks",
                                  strlen("meta.walk_options.follow_symlinks"),
                                  &value_ref));
  assert_true(bc_hrbl_reader_find(reader, "meta.walk_options.include_hidden",
                                  strlen("meta.walk_options.include_hidden"),
                                  &value_ref));
  bc_hrbl_reader_destroy(reader);
}

static void test_writer_summary_block_fields(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  bc_integrity_manifest_options_t options;
  make_options(&options, fixture->file_path,
               BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
  bc_integrity_manifest_summary_t summary;
  make_summary(&summary);
  summary.completed_at_unix_sec = 1700000999;
  summary.walltime_ms = 4321;
  summary.errors_count = 7;
  assert_true(bc_integrity_manifest_write_to_file(fixture->memory_context,
                                                  &options, fixture->entries,
                                                  &summary, fixture->file_path));
  bc_hrbl_reader_t *reader = NULL;
  assert_true(bc_hrbl_reader_open(fixture->memory_context, fixture->file_path,
                                  &reader));
  bc_hrbl_value_ref_t value_ref;
  uint64_t u_value = 0;
  assert_true(bc_hrbl_reader_find(reader, "summary.completed_at_unix_sec",
                                  strlen("summary.completed_at_unix_sec"),
                                  &value_ref));
  assert_true(bc_hrbl_reader_get_uint64(&value_ref, &u_value));
  assert_int_equal(u_value, 1700000999u);
  assert_true(bc_hrbl_reader_find(reader, "summary.walltime_ms",
                                  strlen("summary.walltime_ms"), &value_ref));
  assert_true(bc_hrbl_reader_get_uint64(&value_ref, &u_value));
  assert_int_equal(u_value, 4321u);
  assert_true(bc_hrbl_reader_find(reader, "summary.errors_count",
                                  strlen("summary.errors_count"), &value_ref));
  assert_true(bc_hrbl_reader_get_uint64(&value_ref, &u_value));
  assert_int_equal(u_value, 7u);
  bc_hrbl_reader_destroy(reader);
}

static void test_writer_empty_manifest_no_entries(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  bc_integrity_manifest_options_t options;
  make_options(&options, fixture->file_path,
               BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
  bc_integrity_manifest_summary_t summary;
  make_summary(&summary);

  assert_true(bc_integrity_manifest_write_to_file(fixture->memory_context,
                                                  &options, fixture->entries,
                                                  &summary, fixture->file_path));

  bc_hrbl_reader_t *reader = NULL;
  assert_true(bc_hrbl_reader_open(fixture->memory_context, fixture->file_path,
                                  &reader));

  bc_hrbl_value_ref_t value_ref;
  assert_true(bc_hrbl_reader_find(reader, "entries", strlen("entries"),
                                  &value_ref));

  bc_hrbl_reader_destroy(reader);
}

static void test_writer_error_entry_records_errno_and_message(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  bc_integrity_entry_t error_entry;
  memset(&error_entry, 0, sizeof(error_entry));
  error_entry.relative_path = "broken.txt";
  error_entry.relative_path_length = strlen("broken.txt");
  error_entry.kind = BC_INTEGRITY_ENTRY_KIND_FILE;
  error_entry.ok = false;
  error_entry.errno_value = EACCES;
  const char *msg = "perm denied";
  size_t msg_length = strlen(msg);
  memcpy(error_entry.error_message, msg, msg_length);
  error_entry.error_message_length = msg_length;
  bc_containers_vector_push(fixture->memory_context, fixture->entries,
                            &error_entry);
  bc_integrity_manifest_options_t options;
  make_options(&options, fixture->file_path,
               BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
  bc_integrity_manifest_summary_t summary;
  make_summary(&summary);
  summary.errors_count = 1;
  assert_true(bc_integrity_manifest_write_to_file(fixture->memory_context,
                                                  &options, fixture->entries,
                                                  &summary, fixture->file_path));
  bc_hrbl_reader_t *reader = NULL;
  assert_true(bc_hrbl_reader_open(fixture->memory_context, fixture->file_path,
                                  &reader));
  bc_hrbl_value_ref_t value_ref;
  assert_true(bc_hrbl_reader_find(reader, "entries.'broken.txt'.errno",
                                  strlen("entries.'broken.txt'.errno"),
                                  &value_ref));
  int64_t i_value = 0;
  assert_true(bc_hrbl_reader_get_int64(&value_ref, &i_value));
  assert_int_equal(i_value, (int64_t)EACCES);
  assert_true(bc_hrbl_reader_find(reader,
                                  "entries.'broken.txt'.error_message",
                                  strlen("entries.'broken.txt'.error_message"),
                                  &value_ref));
  const char *msg_value = NULL;
  size_t msg_value_length = 0;
  assert_true(
      bc_hrbl_reader_get_string(&value_ref, &msg_value, &msg_value_length));
  assert_int_equal(msg_value_length, strlen(msg));
  bc_hrbl_reader_destroy(reader);
}

static void test_writer_skip_zero_length_relative_path(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  bc_integrity_entry_t skipped;
  memset(&skipped, 0, sizeof(skipped));
  skipped.kind = BC_INTEGRITY_ENTRY_KIND_FILE;
  skipped.ok = true;
  bc_containers_vector_push(fixture->memory_context, fixture->entries,
                            &skipped);
  bc_integrity_entry_t kept;
  make_file_entry(
      &kept, "kept.txt",
      "1111111111111111111111111111111111111111111111111111111111111111");
  bc_containers_vector_push(fixture->memory_context, fixture->entries, &kept);
  bc_integrity_manifest_options_t options;
  make_options(&options, fixture->file_path,
               BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
  bc_integrity_manifest_summary_t summary;
  make_summary(&summary);
  assert_true(bc_integrity_manifest_write_to_file(fixture->memory_context,
                                                  &options, fixture->entries,
                                                  &summary, fixture->file_path));
  bc_hrbl_reader_t *reader = NULL;
  assert_true(bc_hrbl_reader_open(fixture->memory_context, fixture->file_path,
                                  &reader));
  bc_hrbl_value_ref_t value_ref;
  assert_true(bc_hrbl_reader_find(reader, "entries.'kept.txt'.kind",
                                  strlen("entries.'kept.txt'.kind"),
                                  &value_ref));
  bc_hrbl_reader_destroy(reader);
}

static void check_algorithm_label(fixture_state_t *fixture,
                                  bc_integrity_digest_algorithm_t algorithm,
                                  const char *expected) {
  bc_integrity_manifest_options_t options;
  make_options(&options, fixture->file_path, algorithm);
  bc_integrity_manifest_summary_t summary;
  make_summary(&summary);

  assert_true(bc_integrity_manifest_write_to_file(fixture->memory_context,
                                                  &options, fixture->entries,
                                                  &summary, fixture->file_path));

  bc_hrbl_reader_t *reader = NULL;
  assert_true(bc_hrbl_reader_open(fixture->memory_context, fixture->file_path,
                                  &reader));

  bc_hrbl_value_ref_t value_ref;
  const char *s_value = NULL;
  size_t s_length = 0;
  assert_true(bc_hrbl_reader_find(reader, "meta.digest_algorithm",
                                  strlen("meta.digest_algorithm"), &value_ref));
  assert_true(bc_hrbl_reader_get_string(&value_ref, &s_value, &s_length));
  assert_int_equal(s_length, strlen(expected));
  assert_memory_equal(s_value, expected, s_length);

  bc_hrbl_reader_destroy(reader);
}

static void test_writer_xxh3_label(void **state) {
  check_algorithm_label((fixture_state_t *)*state,
                        BC_INTEGRITY_DIGEST_ALGORITHM_XXH3, "xxh3");
}
static void test_writer_xxh128_label(void **state) {
  check_algorithm_label((fixture_state_t *)*state,
                        BC_INTEGRITY_DIGEST_ALGORITHM_XXH128, "xxh128");
}

static void test_writer_directory_entry_no_digest(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  bc_integrity_entry_t dir_entry;
  memset(&dir_entry, 0, sizeof(dir_entry));
  dir_entry.relative_path = "subdir";
  dir_entry.relative_path_length = strlen("subdir");
  dir_entry.kind = BC_INTEGRITY_ENTRY_KIND_DIRECTORY;
  dir_entry.ok = true;
  dir_entry.mode = 040755;
  bc_containers_vector_push(fixture->memory_context, fixture->entries,
                            &dir_entry);
  bc_integrity_manifest_options_t options;
  make_options(&options, fixture->file_path,
               BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
  bc_integrity_manifest_summary_t summary;
  make_summary(&summary);
  assert_true(bc_integrity_manifest_write_to_file(fixture->memory_context,
                                                  &options, fixture->entries,
                                                  &summary, fixture->file_path));
  bc_hrbl_reader_t *reader = NULL;
  assert_true(bc_hrbl_reader_open(fixture->memory_context, fixture->file_path,
                                  &reader));
  bc_hrbl_value_ref_t value_ref;
  const char *s_value = NULL;
  size_t s_length = 0;
  assert_true(bc_hrbl_reader_find(reader, "entries.subdir.kind",
                                  strlen("entries.subdir.kind"), &value_ref));
  assert_true(bc_hrbl_reader_get_string(&value_ref, &s_value, &s_length));
  assert_memory_equal(s_value, "dir", s_length);
  assert_false(bc_hrbl_reader_find(reader, "entries.subdir.digest_hex",
                                   strlen("entries.subdir.digest_hex"),
                                   &value_ref));
  bc_hrbl_reader_destroy(reader);
}

static void test_writer_stress_thousand_entries(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  size_t entry_count = 1024;
  char *paths = malloc(entry_count * 32);
  assert_non_null(paths);
  bc_integrity_entry_t entry_template;
  for (size_t index = 0; index < entry_count; ++index) {
    snprintf(paths + index * 32, 32, "f_%05zu.dat", index);
    make_file_entry(
        &entry_template, paths + index * 32,
        "1111111111111111111111111111111111111111111111111111111111111111");
    bc_containers_vector_push(fixture->memory_context, fixture->entries,
                              &entry_template);
  }
  bc_integrity_manifest_options_t options;
  make_options(&options, fixture->file_path,
               BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
  bc_integrity_manifest_summary_t summary;
  make_summary(&summary);
  summary.file_count = entry_count;
  assert_true(bc_integrity_manifest_write_to_file(fixture->memory_context,
                                                  &options, fixture->entries,
                                                  &summary, fixture->file_path));
  bc_hrbl_reader_t *reader = NULL;
  assert_true(bc_hrbl_reader_open(fixture->memory_context, fixture->file_path,
                                  &reader));
  bc_hrbl_value_ref_t value_ref;
  uint64_t u_value = 0;
  assert_true(bc_hrbl_reader_find(reader, "entries.'f_00000.dat'.kind",
                                  strlen("entries.'f_00000.dat'.kind"),
                                  &value_ref));
  assert_true(bc_hrbl_reader_find(reader, "entries.'f_01023.dat'.kind",
                                  strlen("entries.'f_01023.dat'.kind"),
                                  &value_ref));
  assert_true(bc_hrbl_reader_find(reader, "meta.file_count",
                                  strlen("meta.file_count"), &value_ref));
  assert_true(bc_hrbl_reader_get_uint64(&value_ref, &u_value));
  assert_int_equal(u_value, entry_count);
  bc_hrbl_reader_destroy(reader);
  free(paths);
}

static void test_writer_fifo_socket_device_kinds(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  bc_integrity_entry_t entries[3];
  memset(entries, 0, sizeof(entries));
  entries[0].relative_path = "fifo_node";
  entries[0].relative_path_length = strlen("fifo_node");
  entries[0].kind = BC_INTEGRITY_ENTRY_KIND_FIFO;
  entries[0].ok = true;
  entries[1].relative_path = "socket_node";
  entries[1].relative_path_length = strlen("socket_node");
  entries[1].kind = BC_INTEGRITY_ENTRY_KIND_SOCKET;
  entries[1].ok = true;
  entries[2].relative_path = "device_node";
  entries[2].relative_path_length = strlen("device_node");
  entries[2].kind = BC_INTEGRITY_ENTRY_KIND_DEVICE;
  entries[2].ok = true;
  for (size_t index = 0; index < 3; ++index) {
    bc_containers_vector_push(fixture->memory_context, fixture->entries,
                              &entries[index]);
  }
  bc_integrity_manifest_options_t options;
  make_options(&options, fixture->file_path,
               BC_INTEGRITY_DIGEST_ALGORITHM_SHA256);
  bc_integrity_manifest_summary_t summary;
  make_summary(&summary);
  assert_true(bc_integrity_manifest_write_to_file(fixture->memory_context,
                                                  &options, fixture->entries,
                                                  &summary, fixture->file_path));
  bc_hrbl_reader_t *reader = NULL;
  assert_true(bc_hrbl_reader_open(fixture->memory_context, fixture->file_path,
                                  &reader));
  bc_hrbl_value_ref_t value_ref;
  const char *s_value = NULL;
  size_t s_length = 0;
  assert_true(bc_hrbl_reader_find(reader, "entries.fifo_node.kind",
                                  strlen("entries.fifo_node.kind"),
                                  &value_ref));
  assert_true(bc_hrbl_reader_get_string(&value_ref, &s_value, &s_length));
  assert_memory_equal(s_value, "fifo", s_length);
  assert_true(bc_hrbl_reader_find(reader, "entries.socket_node.kind",
                                  strlen("entries.socket_node.kind"),
                                  &value_ref));
  assert_true(bc_hrbl_reader_get_string(&value_ref, &s_value, &s_length));
  assert_memory_equal(s_value, "socket", s_length);
  assert_true(bc_hrbl_reader_find(reader, "entries.device_node.kind",
                                  strlen("entries.device_node.kind"),
                                  &value_ref));
  assert_true(bc_hrbl_reader_get_string(&value_ref, &s_value, &s_length));
  assert_memory_equal(s_value, "device", s_length);
  bc_hrbl_reader_destroy(reader);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test_setup_teardown(test_writer_meta_block_complete_fields,
                                      fixture_setup, fixture_teardown),
      cmocka_unit_test_setup_teardown(test_writer_summary_block_fields,
                                      fixture_setup, fixture_teardown),
      cmocka_unit_test_setup_teardown(test_writer_empty_manifest_no_entries,
                                      fixture_setup, fixture_teardown),
      cmocka_unit_test_setup_teardown(
          test_writer_error_entry_records_errno_and_message, fixture_setup,
          fixture_teardown),
      cmocka_unit_test_setup_teardown(
          test_writer_skip_zero_length_relative_path, fixture_setup,
          fixture_teardown),
      cmocka_unit_test_setup_teardown(test_writer_xxh3_label, fixture_setup,
                                      fixture_teardown),
      cmocka_unit_test_setup_teardown(test_writer_xxh128_label, fixture_setup,
                                      fixture_teardown),
      cmocka_unit_test_setup_teardown(test_writer_directory_entry_no_digest,
                                      fixture_setup, fixture_teardown),
      cmocka_unit_test_setup_teardown(test_writer_stress_thousand_entries,
                                      fixture_setup, fixture_teardown),
      cmocka_unit_test_setup_teardown(test_writer_fifo_socket_device_kinds,
                                      fixture_setup, fixture_teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
