// SPDX-License-Identifier: MIT

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "bc_allocators.h"
#include "bc_hrbl.h"
#include "bc_hrbl_reader.h"
#include "bc_hrbl_types.h"
#include "bc_hrbl_verify.h"

#ifndef BC_INTEGRITY_TEST_BINARY_PATH
#define BC_INTEGRITY_TEST_BINARY_PATH "/usr/local/bin/bc-integrity"
#endif

typedef struct fixture_state {
  char fixture_directory[256];
  char manifest_path_a[300];
  char manifest_path_b[300];
} fixture_state_t;

static int fixture_setup(void **state) {
  fixture_state_t *fixture = malloc(sizeof(*fixture));
  if (fixture == NULL) {
    return -1;
  }
  snprintf(fixture->fixture_directory, sizeof(fixture->fixture_directory),
           "/tmp/bc_integrity_repro_%d_XXXXXX", getpid());
  if (mkdtemp(fixture->fixture_directory) == NULL) {
    free(fixture);
    return -1;
  }
  snprintf(fixture->manifest_path_a, sizeof(fixture->manifest_path_a),
           "%s_a.hrbl", fixture->fixture_directory);
  snprintf(fixture->manifest_path_b, sizeof(fixture->manifest_path_b),
           "%s_b.hrbl", fixture->fixture_directory);
  *state = fixture;
  return 0;
}

static int fixture_teardown(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  char command[1024];
  snprintf(command, sizeof(command),
           "chmod -R u+rwx '%s' 2>/dev/null; rm -rf '%s'",
           fixture->fixture_directory, fixture->fixture_directory);
  int rc = system(command);
  (void)rc;
  unlink(fixture->manifest_path_a);
  unlink(fixture->manifest_path_b);
  free(fixture);
  return 0;
}

static void write_file(const char *path, const char *content) {
  FILE *file = fopen(path, "wb");
  assert_non_null(file);
  fputs(content, file);
  fclose(file);
}

static void freeze_file_metadata(const char *path) {
  assert_int_equal(chmod(path, 0644), 0);
  struct timeval times[2];
  times[0].tv_sec = 1700000000;
  times[0].tv_usec = 0;
  times[1].tv_sec = 1700000000;
  times[1].tv_usec = 0;
  assert_int_equal(utimes(path, times), 0);
}

static void freeze_dir_metadata(const char *path) {
  assert_int_equal(chmod(path, 0755), 0);
  struct timeval times[2];
  times[0].tv_sec = 1700000000;
  times[0].tv_usec = 0;
  times[1].tv_sec = 1700000000;
  times[1].tv_usec = 0;
  assert_int_equal(utimes(path, times), 0);
}

static void build_stable_tree(const char *root) {
  char path[512];

  for (int index = 1; index <= 8; ++index) {
    snprintf(path, sizeof(path), "%s/file_%d.txt", root, index);
    char content[64];
    snprintf(content, sizeof(content), "stable-content-%d", index);
    write_file(path, content);
    freeze_file_metadata(path);
  }

  snprintf(path, sizeof(path), "%s/sub", root);
  assert_int_equal(mkdir(path, 0755), 0);

  snprintf(path, sizeof(path), "%s/sub/inner.txt", root);
  write_file(path, "inner-stable");
  freeze_file_metadata(path);

  snprintf(path, sizeof(path), "%s/sub", root);
  freeze_dir_metadata(path);
}

static int run_bc_integrity_manifest(const char *root, const char *output,
                                     const char *threads_argument) {
  pid_t pid = fork();
  if (pid < 0) {
    return -1;
  }
  if (pid == 0) {
    char output_argument[512];
    snprintf(output_argument, sizeof(output_argument), "--output=%s", output);
    if (threads_argument != NULL) {
      char *argv[] = {
          (char *)BC_INTEGRITY_TEST_BINARY_PATH,
          (char *)threads_argument,
          "manifest",
          output_argument,
          "--default-exclude-virtual=false",
          (char *)root,
          NULL,
      };
      execv(argv[0], argv);
      _exit(127);
    }
    char *argv[] = {
        (char *)BC_INTEGRITY_TEST_BINARY_PATH, "manifest",   output_argument,
        "--default-exclude-virtual=false",     (char *)root, NULL,
    };
    execv(argv[0], argv);
    _exit(127);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int run_bc_integrity_diff(const char *manifest_a,
                                 const char *manifest_b) {
  pid_t pid = fork();
  if (pid < 0) {
    return -1;
  }
  if (pid == 0) {
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      dup2(devnull, STDOUT_FILENO);
      close(devnull);
    }
    char *argv[] = {
        (char *)BC_INTEGRITY_TEST_BINARY_PATH,
        "diff",
        (char *)manifest_a,
        (char *)manifest_b,
        NULL,
    };
    execv(argv[0], argv);
    _exit(127);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

typedef struct entry_record {
  char name[256];
  char digest_hex[160];
  uint64_t mode;
  uint64_t uid;
  uint64_t gid;
  uint64_t size_bytes;
  uint64_t ino;
  bool has_digest;
} entry_record_t;

typedef struct entry_table {
  entry_record_t records[64];
  size_t count;
} entry_table_t;

static int compare_entry_record(const void *lhs, const void *rhs) {
  const entry_record_t *left = (const entry_record_t *)lhs;
  const entry_record_t *right = (const entry_record_t *)rhs;
  return strcmp(left->name, right->name);
}

static void load_entries(const char *manifest_path, entry_table_t *out_table) {
  bc_hrbl_verify_status_t verify_status = bc_hrbl_verify_file(manifest_path);
  assert_int_equal(verify_status, BC_HRBL_VERIFY_OK);

  bc_allocators_context_config_t allocator_config = {.tracking_enabled = true};
  bc_allocators_context_t *memory_context = NULL;
  assert_true(bc_allocators_context_create(&allocator_config, &memory_context));

  bc_hrbl_reader_t *reader = NULL;
  assert_true(
      bc_hrbl_reader_open(memory_context, manifest_path, &reader));

  bc_hrbl_value_ref_t entries_value;
  assert_true(bc_hrbl_reader_find(reader, "entries", strlen("entries"),
                                  &entries_value));

  bc_hrbl_iter_t iter;
  assert_true(bc_hrbl_reader_iter_block(&entries_value, &iter));

  out_table->count = 0;

  bc_hrbl_value_ref_t child_value;
  const char *key = NULL;
  size_t key_length = 0;
  while (bc_hrbl_iter_next(&iter, &child_value, &key, &key_length)) {
    assert_true(out_table->count < 64);
    entry_record_t *record = &out_table->records[out_table->count];
    size_t copy_length =
        key_length < sizeof(record->name) - 1 ? key_length
                                              : sizeof(record->name) - 1;
    memcpy(record->name, key, copy_length);
    record->name[copy_length] = '\0';
    record->digest_hex[0] = '\0';
    record->has_digest = false;
    record->mode = 0;
    record->uid = 0;
    record->gid = 0;
    record->size_bytes = 0;
    record->ino = 0;

    bc_hrbl_iter_t field_iter;
    assert_true(bc_hrbl_reader_iter_block(&child_value, &field_iter));
    bc_hrbl_value_ref_t field_value;
    const char *field_key = NULL;
    size_t field_key_length = 0;
    while (bc_hrbl_iter_next(&field_iter, &field_value, &field_key,
                             &field_key_length)) {
      if (field_key_length == strlen("digest_hex") &&
          memcmp(field_key, "digest_hex", field_key_length) == 0) {
        const char *digest_data = NULL;
        size_t digest_length = 0;
        if (bc_hrbl_reader_get_string(&field_value, &digest_data,
                                      &digest_length)) {
          size_t digest_copy =
              digest_length < sizeof(record->digest_hex) - 1
                  ? digest_length
                  : sizeof(record->digest_hex) - 1;
          memcpy(record->digest_hex, digest_data, digest_copy);
          record->digest_hex[digest_copy] = '\0';
          record->has_digest = true;
        }
      } else if (field_key_length == strlen("mode") &&
                 memcmp(field_key, "mode", field_key_length) == 0) {
        bc_hrbl_reader_get_uint64(&field_value, &record->mode);
      } else if (field_key_length == strlen("uid") &&
                 memcmp(field_key, "uid", field_key_length) == 0) {
        bc_hrbl_reader_get_uint64(&field_value, &record->uid);
      } else if (field_key_length == strlen("gid") &&
                 memcmp(field_key, "gid", field_key_length) == 0) {
        bc_hrbl_reader_get_uint64(&field_value, &record->gid);
      } else if (field_key_length == strlen("size_bytes") &&
                 memcmp(field_key, "size_bytes", field_key_length) == 0) {
        bc_hrbl_reader_get_uint64(&field_value, &record->size_bytes);
      } else if (field_key_length == strlen("ino") &&
                 memcmp(field_key, "ino", field_key_length) == 0) {
        bc_hrbl_reader_get_uint64(&field_value, &record->ino);
      }
    }

    ++out_table->count;
  }

  qsort(out_table->records, out_table->count, sizeof(entry_record_t),
        compare_entry_record);

  bc_hrbl_reader_destroy(reader);
  bc_allocators_context_destroy(memory_context);
}

static void assert_tables_equivalent(const entry_table_t *table_a,
                                     const entry_table_t *table_b) {
  assert_int_equal(table_a->count, table_b->count);
  for (size_t index = 0; index < table_a->count; ++index) {
    const entry_record_t *record_a = &table_a->records[index];
    const entry_record_t *record_b = &table_b->records[index];
    assert_string_equal(record_a->name, record_b->name);
    assert_int_equal(record_a->has_digest, record_b->has_digest);
    if (record_a->has_digest) {
      assert_string_equal(record_a->digest_hex, record_b->digest_hex);
    }
    assert_int_equal(record_a->mode, record_b->mode);
    assert_int_equal(record_a->uid, record_b->uid);
    assert_int_equal(record_a->gid, record_b->gid);
    assert_int_equal(record_a->size_bytes, record_b->size_bytes);
    assert_int_equal(record_a->ino, record_b->ino);
  }
}

static void test_repeated_manifest_produces_identical_digests(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  build_stable_tree(fixture->fixture_directory);

  assert_int_equal(run_bc_integrity_manifest(fixture->fixture_directory,
                                             fixture->manifest_path_a, NULL),
                   0);
  assert_int_equal(run_bc_integrity_manifest(fixture->fixture_directory,
                                             fixture->manifest_path_b, NULL),
                   0);

  entry_table_t table_a;
  entry_table_t table_b;
  load_entries(fixture->manifest_path_a, &table_a);
  load_entries(fixture->manifest_path_b, &table_b);

  assert_tables_equivalent(&table_a, &table_b);
  assert_true(table_a.count >= 9u);
}

static void test_threads_modes_produce_identical_digests(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  build_stable_tree(fixture->fixture_directory);

  assert_int_equal(run_bc_integrity_manifest(fixture->fixture_directory,
                                             fixture->manifest_path_a,
                                             "--threads=0"),
                   0);
  assert_int_equal(run_bc_integrity_manifest(fixture->fixture_directory,
                                             fixture->manifest_path_b,
                                             "--threads=auto"),
                   0);

  entry_table_t table_serial;
  entry_table_t table_parallel;
  load_entries(fixture->manifest_path_a, &table_serial);
  load_entries(fixture->manifest_path_b, &table_parallel);

  assert_tables_equivalent(&table_serial, &table_parallel);
  assert_true(table_serial.count >= 9u);
}

static void test_diff_two_identical_manifests_returns_zero(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  build_stable_tree(fixture->fixture_directory);

  assert_int_equal(run_bc_integrity_manifest(fixture->fixture_directory,
                                             fixture->manifest_path_a, NULL),
                   0);
  assert_int_equal(run_bc_integrity_manifest(fixture->fixture_directory,
                                             fixture->manifest_path_b, NULL),
                   0);

  int diff_exit =
      run_bc_integrity_diff(fixture->manifest_path_a, fixture->manifest_path_b);
  assert_int_equal(diff_exit, 0);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test_setup_teardown(
          test_repeated_manifest_produces_identical_digests, fixture_setup,
          fixture_teardown),
      cmocka_unit_test_setup_teardown(
          test_threads_modes_produce_identical_digests, fixture_setup,
          fixture_teardown),
      cmocka_unit_test_setup_teardown(
          test_diff_two_identical_manifests_returns_zero, fixture_setup,
          fixture_teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
