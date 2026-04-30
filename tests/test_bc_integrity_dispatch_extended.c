// SPDX-License-Identifier: MIT

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bc_allocators.h"
#include "bc_concurrency.h"
#include "bc_runtime_signal.h"
#include "bc_containers_vector.h"
#include "bc_core.h"
#include "bc_core_hash.h"
#include "bc_integrity_dispatch_internal.h"
#include "bc_integrity_entry_internal.h"

#if __has_include(<valgrind/valgrind.h>)
#include <valgrind/valgrind.h>
#define BC_INTEGRITY_TEST_HAS_VALGRIND_HEADER 1
#else
#define BC_INTEGRITY_TEST_HAS_VALGRIND_HEADER 0
#endif

static bool bc_integrity_test_under_valgrind(void) {
#if BC_INTEGRITY_TEST_HAS_VALGRIND_HEADER
  return RUNNING_ON_VALGRIND != 0;
#else
  return false;
#endif
}

static bool sha256_is_available(void) {
  uint8_t probe[BC_CORE_SHA256_DIGEST_SIZE];
  return bc_core_sha256("", 0, probe);
}

typedef struct dispatch_ext_state {
  char directory_path[256];
  bc_allocators_context_t *memory_context;
  bc_concurrency_context_t *concurrency_context;
  size_t worker_count;
} dispatch_ext_state_t;

static int dispatch_ext_make_state(void **state, size_t worker_count) {
  dispatch_ext_state_t *fixture = malloc(sizeof(*fixture));
  if (fixture == NULL) {
    return -1;
  }
  fixture->worker_count = worker_count;
  snprintf(fixture->directory_path, sizeof(fixture->directory_path),
           "/tmp/bc_integrity_dispatch_ext_%d_XXXXXX", getpid());
  if (mkdtemp(fixture->directory_path) == NULL) {
    free(fixture);
    return -1;
  }
  bc_allocators_context_config_t config = {.tracking_enabled = true};
  if (!bc_allocators_context_create(&config, &fixture->memory_context)) {
    free(fixture);
    return -1;
  }
  bc_concurrency_config_t parallel_config;
  bc_core_zero(&parallel_config, sizeof(parallel_config));
  parallel_config.worker_count_explicit = true;
  parallel_config.worker_count = worker_count;
  parallel_config.allow_oversubscribe = true;
  if (!bc_concurrency_create(fixture->memory_context, &parallel_config,
                             &fixture->concurrency_context)) {
    bc_allocators_context_destroy(fixture->memory_context);
    free(fixture);
    return -1;
  }
  *state = fixture;
  return 0;
}

static int setup_workers_4(void **state) {
  return dispatch_ext_make_state(state, 4);
}

static int setup_workers_mono(void **state) {
  return dispatch_ext_make_state(state, 0);
}

static int dispatch_ext_teardown(void **state) {
  dispatch_ext_state_t *fixture = (dispatch_ext_state_t *)*state;
  bc_concurrency_destroy(fixture->concurrency_context);
  bc_allocators_context_destroy(fixture->memory_context);
  char command[512];
  snprintf(command, sizeof(command), "rm -rf '%s'", fixture->directory_path);
  int rc = system(command);
  (void)rc;
  free(fixture);
  return 0;
}

static void write_file(const char *path, const char *content, size_t length) {
  FILE *file = fopen(path, "wb");
  assert_non_null(file);
  if (length > 0) {
    fwrite(content, 1, length, file);
  }
  fclose(file);
}

static void write_filled_file(const char *path, char fill, size_t length) {
  FILE *file = fopen(path, "wb");
  assert_non_null(file);
  for (size_t i = 0; i < length; ++i) {
    fputc(fill, file);
  }
  fclose(file);
}

static void make_entry_file(bc_integrity_entry_t *entry,
                            const char *absolute_path, size_t file_size) {
  bc_core_zero(entry, sizeof(*entry));
  entry->relative_path = absolute_path;
  entry->relative_path_length = strlen(absolute_path);
  entry->absolute_path = absolute_path;
  entry->absolute_path_length = strlen(absolute_path);
  entry->kind = BC_INTEGRITY_ENTRY_KIND_FILE;
  entry->ok = true;
  entry->size_bytes = (uint64_t)file_size;
}

static void test_dispatch_zero_entries_noop(void **state) {
  dispatch_ext_state_t *fixture = (dispatch_ext_state_t *)*state;
  bc_containers_vector_t *entries = NULL;
  assert_true(bc_containers_vector_create(
      fixture->memory_context, sizeof(bc_integrity_entry_t), 4, 16, &entries));
  assert_true(bc_integrity_dispatch_compute_digests(
      fixture->memory_context, fixture->concurrency_context, NULL,
      BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, entries));
  assert_int_equal(bc_containers_vector_length(entries), 0u);
  bc_containers_vector_destroy(fixture->memory_context, entries);
}

static void test_dispatch_skips_directory_kind(void **state) {
  if (!sha256_is_available() || bc_integrity_test_under_valgrind()) {
    skip();
    return;
  }
  dispatch_ext_state_t *fixture = (dispatch_ext_state_t *)*state;

  bc_containers_vector_t *entries = NULL;
  assert_true(bc_containers_vector_create(
      fixture->memory_context, sizeof(bc_integrity_entry_t), 4, 16, &entries));

  bc_integrity_entry_t entry_dir;
  bc_core_zero(&entry_dir, sizeof(entry_dir));
  entry_dir.relative_path = "subdir";
  entry_dir.relative_path_length = strlen("subdir");
  entry_dir.absolute_path = "subdir";
  entry_dir.absolute_path_length = strlen("subdir");
  entry_dir.kind = BC_INTEGRITY_ENTRY_KIND_DIRECTORY;
  entry_dir.ok = true;
  assert_true(bc_containers_vector_push(fixture->memory_context, entries,
                                        &entry_dir));

  bc_integrity_entry_t entry_link;
  bc_core_zero(&entry_link, sizeof(entry_link));
  entry_link.relative_path = "link";
  entry_link.relative_path_length = strlen("link");
  entry_link.absolute_path = "link";
  entry_link.absolute_path_length = strlen("link");
  entry_link.kind = BC_INTEGRITY_ENTRY_KIND_SYMLINK;
  entry_link.ok = true;
  assert_true(bc_containers_vector_push(fixture->memory_context, entries,
                                        &entry_link));

  assert_true(bc_integrity_dispatch_compute_digests(
      fixture->memory_context, fixture->concurrency_context, NULL,
      BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, entries));

  bc_integrity_entry_t check;
  assert_true(bc_containers_vector_get(entries, 0, &check));
  assert_int_equal(check.digest_hex_length, 0u);
  assert_true(bc_containers_vector_get(entries, 1, &check));
  assert_int_equal(check.digest_hex_length, 0u);

  bc_containers_vector_destroy(fixture->memory_context, entries);
}

static void test_dispatch_skips_not_ok_entry(void **state) {
  if (!sha256_is_available() || bc_integrity_test_under_valgrind()) {
    skip();
    return;
  }
  dispatch_ext_state_t *fixture = (dispatch_ext_state_t *)*state;

  bc_containers_vector_t *entries = NULL;
  assert_true(bc_containers_vector_create(
      fixture->memory_context, sizeof(bc_integrity_entry_t), 4, 16, &entries));

  bc_integrity_entry_t entry;
  bc_core_zero(&entry, sizeof(entry));
  entry.relative_path = "broken";
  entry.relative_path_length = strlen("broken");
  entry.absolute_path = "broken";
  entry.absolute_path_length = strlen("broken");
  entry.kind = BC_INTEGRITY_ENTRY_KIND_FILE;
  entry.ok = false;
  entry.size_bytes = 100;
  assert_true(
      bc_containers_vector_push(fixture->memory_context, entries, &entry));

  assert_true(bc_integrity_dispatch_compute_digests(
      fixture->memory_context, fixture->concurrency_context, NULL,
      BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, entries));

  bc_integrity_entry_t check;
  assert_true(bc_containers_vector_get(entries, 0, &check));
  assert_int_equal(check.digest_hex_length, 0u);

  bc_containers_vector_destroy(fixture->memory_context, entries);
}

static void test_dispatch_skips_already_digested(void **state) {
  if (!sha256_is_available() || bc_integrity_test_under_valgrind()) {
    skip();
    return;
  }
  dispatch_ext_state_t *fixture = (dispatch_ext_state_t *)*state;

  char file_path[512];
  snprintf(file_path, sizeof(file_path), "%s/already.txt",
           fixture->directory_path);
  write_file(file_path, "abc", 3);

  bc_containers_vector_t *entries = NULL;
  assert_true(bc_containers_vector_create(
      fixture->memory_context, sizeof(bc_integrity_entry_t), 4, 16, &entries));

  bc_integrity_entry_t entry;
  make_entry_file(&entry, file_path, 3);
  const char *precomputed = "deadbeef";
  size_t precomputed_len = strlen(precomputed);
  memcpy(entry.digest_hex, precomputed, precomputed_len);
  entry.digest_hex[precomputed_len] = '\0';
  entry.digest_hex_length = precomputed_len;
  assert_true(
      bc_containers_vector_push(fixture->memory_context, entries, &entry));

  assert_true(bc_integrity_dispatch_compute_digests(
      fixture->memory_context, fixture->concurrency_context, NULL,
      BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, entries));

  bc_integrity_entry_t check;
  assert_true(bc_containers_vector_get(entries, 0, &check));
  assert_int_equal(check.digest_hex_length, precomputed_len);
  assert_string_equal(check.digest_hex, "deadbeef");

  bc_containers_vector_destroy(fixture->memory_context, entries);
}

static void test_dispatch_open_failure_records_error(void **state) {
  if (!sha256_is_available() || bc_integrity_test_under_valgrind()) {
    skip();
    return;
  }
  dispatch_ext_state_t *fixture = (dispatch_ext_state_t *)*state;

  char missing_path[512];
  snprintf(missing_path, sizeof(missing_path), "%s/does_not_exist.bin",
           fixture->directory_path);

  bc_containers_vector_t *entries = NULL;
  assert_true(bc_containers_vector_create(
      fixture->memory_context, sizeof(bc_integrity_entry_t), 4, 16, &entries));

  bc_integrity_entry_t entry;
  make_entry_file(&entry, missing_path, 64);
  assert_true(
      bc_containers_vector_push(fixture->memory_context, entries, &entry));

  assert_true(bc_integrity_dispatch_compute_digests(
      fixture->memory_context, fixture->concurrency_context, NULL,
      BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, entries));

  bc_integrity_entry_t check;
  assert_true(bc_containers_vector_get(entries, 0, &check));
  assert_int_equal(check.digest_hex_length, 0u);
  assert_int_not_equal(check.errno_value, 0);

  bc_containers_vector_destroy(fixture->memory_context, entries);
}

static void test_dispatch_parallel_above_threshold_with_ring(void **state) {
  if (!sha256_is_available() || bc_integrity_test_under_valgrind()) {
    skip();
    return;
  }
  dispatch_ext_state_t *fixture = (dispatch_ext_state_t *)*state;
  size_t entry_count = 24;
  size_t file_size = 64 * 1024;

  bc_containers_vector_t *entries = NULL;
  assert_true(bc_containers_vector_create(fixture->memory_context,
                                          sizeof(bc_integrity_entry_t), 16, 64,
                                          &entries));

  char *paths = malloc(entry_count * 512);
  assert_non_null(paths);
  for (size_t i = 0; i < entry_count; ++i) {
    char *path = paths + i * 512;
    snprintf(path, 512, "%s/big_%04zu.bin", fixture->directory_path, i);
    write_filled_file(path, (char)('a' + (i % 16)), file_size);
    bc_integrity_entry_t entry;
    make_entry_file(&entry, path, file_size);
    assert_true(
        bc_containers_vector_push(fixture->memory_context, entries, &entry));
  }

  assert_true(bc_integrity_dispatch_compute_digests(
      fixture->memory_context, fixture->concurrency_context, NULL,
      BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, entries));

  for (size_t i = 0; i < entry_count; ++i) {
    bc_integrity_entry_t check;
    assert_true(bc_containers_vector_get(entries, i, &check));
    assert_int_equal(check.digest_hex_length, 64u);
  }

  free(paths);
  bc_containers_vector_destroy(fixture->memory_context, entries);
}

static void test_dispatch_parallel_oversize_files(void **state) {
  if (!sha256_is_available() || bc_integrity_test_under_valgrind()) {
    skip();
    return;
  }
  dispatch_ext_state_t *fixture = (dispatch_ext_state_t *)*state;
  size_t entry_count = 24;

  bc_containers_vector_t *entries = NULL;
  assert_true(bc_containers_vector_create(fixture->memory_context,
                                          sizeof(bc_integrity_entry_t), 16, 64,
                                          &entries));

  char *paths = malloc(entry_count * 512);
  assert_non_null(paths);
  for (size_t i = 0; i < entry_count; ++i) {
    char *path = paths + i * 512;
    snprintf(path, 512, "%s/huge_%04zu.bin", fixture->directory_path, i);
    size_t file_size = (i < 4) ? 256 * 1024 : 64 * 1024;
    write_filled_file(path, (char)('a' + (i % 16)), file_size);
    bc_integrity_entry_t entry;
    make_entry_file(&entry, path, file_size);
    assert_true(
        bc_containers_vector_push(fixture->memory_context, entries, &entry));
  }

  assert_true(bc_integrity_dispatch_compute_digests(
      fixture->memory_context, fixture->concurrency_context, NULL,
      BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, entries));

  for (size_t i = 0; i < entry_count; ++i) {
    bc_integrity_entry_t check;
    assert_true(bc_containers_vector_get(entries, i, &check));
    assert_int_equal(check.digest_hex_length, 64u);
  }

  free(paths);
  bc_containers_vector_destroy(fixture->memory_context, entries);
}

static void test_dispatch_parallel_mixed_sizes(void **state) {
  if (!sha256_is_available() || bc_integrity_test_under_valgrind()) {
    skip();
    return;
  }
  dispatch_ext_state_t *fixture = (dispatch_ext_state_t *)*state;
  size_t entry_count = 24;

  bc_containers_vector_t *entries = NULL;
  assert_true(bc_containers_vector_create(fixture->memory_context,
                                          sizeof(bc_integrity_entry_t), 16, 64,
                                          &entries));

  char *paths = malloc(entry_count * 512);
  assert_non_null(paths);
  for (size_t i = 0; i < entry_count; ++i) {
    char *path = paths + i * 512;
    snprintf(path, 512, "%s/mix_%04zu.bin", fixture->directory_path, i);
    size_t file_size;
    if (i % 3 == 0) {
      file_size = 0;
    } else if (i % 3 == 1) {
      file_size = 1;
    } else {
      file_size = 64 * 1024;
    }
    write_filled_file(path, (char)('a' + (i % 16)), file_size);
    bc_integrity_entry_t entry;
    make_entry_file(&entry, path, file_size);
    assert_true(
        bc_containers_vector_push(fixture->memory_context, entries, &entry));
  }

  assert_true(bc_integrity_dispatch_compute_digests(
      fixture->memory_context, fixture->concurrency_context, NULL,
      BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, entries));

  for (size_t i = 0; i < entry_count; ++i) {
    bc_integrity_entry_t check;
    assert_true(bc_containers_vector_get(entries, i, &check));
    assert_int_equal(check.digest_hex_length, 64u);
  }

  free(paths);
  bc_containers_vector_destroy(fixture->memory_context, entries);
}

static void test_dispatch_signal_stop_before_run(void **state) {
  if (!sha256_is_available() || bc_integrity_test_under_valgrind()) {
    skip();
    return;
  }
  dispatch_ext_state_t *fixture = (dispatch_ext_state_t *)*state;

  bc_runtime_signal_handler_t *signal_handler = NULL;
  assert_true(bc_runtime_signal_handler_create(fixture->memory_context,
                                                   &signal_handler));
  assert_true(
      bc_runtime_signal_handler_install(signal_handler, SIGUSR1));

  size_t entry_count = 5;
  bc_containers_vector_t *entries = NULL;
  assert_true(bc_containers_vector_create(fixture->memory_context,
                                          sizeof(bc_integrity_entry_t), 8, 32,
                                          &entries));
  char *paths = malloc(entry_count * 512);
  assert_non_null(paths);
  for (size_t i = 0; i < entry_count; ++i) {
    char *path = paths + i * 512;
    snprintf(path, 512, "%s/sig_%04zu.bin", fixture->directory_path, i);
    write_filled_file(path, 'x', 16);
    bc_integrity_entry_t entry;
    make_entry_file(&entry, path, 16);
    assert_true(
        bc_containers_vector_push(fixture->memory_context, entries, &entry));
  }

  raise(SIGUSR1);

  assert_true(bc_integrity_dispatch_compute_digests(
      fixture->memory_context, fixture->concurrency_context, signal_handler,
      BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, entries));

  free(paths);
  bc_containers_vector_destroy(fixture->memory_context, entries);
  bc_runtime_signal_handler_destroy(signal_handler);
}

static void test_dispatch_signal_stop_parallel_path(void **state) {
  if (!sha256_is_available() || bc_integrity_test_under_valgrind()) {
    skip();
    return;
  }
  dispatch_ext_state_t *fixture = (dispatch_ext_state_t *)*state;

  bc_runtime_signal_handler_t *signal_handler = NULL;
  assert_true(bc_runtime_signal_handler_create(fixture->memory_context,
                                                   &signal_handler));
  assert_true(
      bc_runtime_signal_handler_install(signal_handler, SIGUSR1));

  size_t entry_count = 24;
  bc_containers_vector_t *entries = NULL;
  assert_true(bc_containers_vector_create(fixture->memory_context,
                                          sizeof(bc_integrity_entry_t), 16, 64,
                                          &entries));
  char *paths = malloc(entry_count * 512);
  assert_non_null(paths);
  for (size_t i = 0; i < entry_count; ++i) {
    char *path = paths + i * 512;
    snprintf(path, 512, "%s/par_%04zu.bin", fixture->directory_path, i);
    write_filled_file(path, 'y', 64 * 1024);
    bc_integrity_entry_t entry;
    make_entry_file(&entry, path, 64 * 1024);
    assert_true(
        bc_containers_vector_push(fixture->memory_context, entries, &entry));
  }

  raise(SIGUSR1);

  assert_true(bc_integrity_dispatch_compute_digests(
      fixture->memory_context, fixture->concurrency_context, signal_handler,
      BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, entries));

  free(paths);
  bc_containers_vector_destroy(fixture->memory_context, entries);
  bc_runtime_signal_handler_destroy(signal_handler);
}

static void test_dispatch_parallel_ring_with_missing_file(void **state) {
  if (!sha256_is_available() || bc_integrity_test_under_valgrind()) {
    skip();
    return;
  }
  dispatch_ext_state_t *fixture = (dispatch_ext_state_t *)*state;
  size_t entry_count = 24;

  bc_containers_vector_t *entries = NULL;
  assert_true(bc_containers_vector_create(fixture->memory_context,
                                          sizeof(bc_integrity_entry_t), 16, 64,
                                          &entries));

  char *paths = malloc(entry_count * 512);
  assert_non_null(paths);
  for (size_t i = 0; i < entry_count; ++i) {
    char *path = paths + i * 512;
    snprintf(path, 512, "%s/ring_%04zu.bin", fixture->directory_path, i);
    if (i % 6 != 0) {
      write_filled_file(path, (char)('a' + (i % 16)), 64 * 1024);
    }
    bc_integrity_entry_t entry;
    make_entry_file(&entry, path, 64 * 1024);
    assert_true(
        bc_containers_vector_push(fixture->memory_context, entries, &entry));
  }

  assert_true(bc_integrity_dispatch_compute_digests(
      fixture->memory_context, fixture->concurrency_context, NULL,
      BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, entries));

  free(paths);
  bc_containers_vector_destroy(fixture->memory_context, entries);
}

static void test_dispatch_parallel_oversize_with_missing_file(void **state) {
  if (!sha256_is_available() || bc_integrity_test_under_valgrind()) {
    skip();
    return;
  }
  dispatch_ext_state_t *fixture = (dispatch_ext_state_t *)*state;
  size_t entry_count = 24;

  bc_containers_vector_t *entries = NULL;
  assert_true(bc_containers_vector_create(fixture->memory_context,
                                          sizeof(bc_integrity_entry_t), 16, 64,
                                          &entries));

  char *paths = malloc(entry_count * 512);
  assert_non_null(paths);
  for (size_t i = 0; i < entry_count; ++i) {
    char *path = paths + i * 512;
    snprintf(path, 512, "%s/big_miss_%04zu.bin", fixture->directory_path, i);
    size_t file_size = (i < 4) ? 256 * 1024 : 64 * 1024;
    if (i != 0) {
      write_filled_file(path, (char)('a' + (i % 16)), file_size);
    }
    bc_integrity_entry_t entry;
    make_entry_file(&entry, path, file_size);
    assert_true(
        bc_containers_vector_push(fixture->memory_context, entries, &entry));
  }

  assert_true(bc_integrity_dispatch_compute_digests(
      fixture->memory_context, fixture->concurrency_context, NULL,
      BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, entries));

  bc_integrity_entry_t check;
  assert_true(bc_containers_vector_get(entries, 0, &check));
  assert_int_not_equal(check.errno_value, 0);

  free(paths);
  bc_containers_vector_destroy(fixture->memory_context, entries);
}

static void test_dispatch_sequential_mixed_kinds(void **state) {
  if (!sha256_is_available() || bc_integrity_test_under_valgrind()) {
    skip();
    return;
  }
  dispatch_ext_state_t *fixture = (dispatch_ext_state_t *)*state;

  char file_path_a[512];
  char file_path_b[512];
  snprintf(file_path_a, sizeof(file_path_a), "%s/seq_a.txt",
           fixture->directory_path);
  snprintf(file_path_b, sizeof(file_path_b), "%s/seq_b.txt",
           fixture->directory_path);
  write_file(file_path_a, "hi", 2);
  write_file(file_path_b, "yo", 2);

  bc_containers_vector_t *entries = NULL;
  assert_true(bc_containers_vector_create(
      fixture->memory_context, sizeof(bc_integrity_entry_t), 8, 32, &entries));

  bc_integrity_entry_t entry_dir;
  bc_core_zero(&entry_dir, sizeof(entry_dir));
  entry_dir.relative_path = "subdir";
  entry_dir.relative_path_length = strlen("subdir");
  entry_dir.absolute_path = "subdir";
  entry_dir.absolute_path_length = strlen("subdir");
  entry_dir.kind = BC_INTEGRITY_ENTRY_KIND_DIRECTORY;
  entry_dir.ok = true;
  assert_true(bc_containers_vector_push(fixture->memory_context, entries,
                                        &entry_dir));

  bc_integrity_entry_t entry_a;
  make_entry_file(&entry_a, file_path_a, 2);
  assert_true(
      bc_containers_vector_push(fixture->memory_context, entries, &entry_a));

  bc_integrity_entry_t entry_broken;
  bc_core_zero(&entry_broken, sizeof(entry_broken));
  entry_broken.relative_path = "bad";
  entry_broken.relative_path_length = strlen("bad");
  entry_broken.absolute_path = "bad";
  entry_broken.absolute_path_length = strlen("bad");
  entry_broken.kind = BC_INTEGRITY_ENTRY_KIND_FILE;
  entry_broken.ok = false;
  entry_broken.size_bytes = 100;
  assert_true(bc_containers_vector_push(fixture->memory_context, entries,
                                        &entry_broken));

  bc_integrity_entry_t entry_pre;
  make_entry_file(&entry_pre, file_path_b, 2);
  const char *prehash = "deadbeef";
  size_t prehash_len = strlen(prehash);
  memcpy(entry_pre.digest_hex, prehash, prehash_len);
  entry_pre.digest_hex[prehash_len] = '\0';
  entry_pre.digest_hex_length = prehash_len;
  assert_true(
      bc_containers_vector_push(fixture->memory_context, entries, &entry_pre));

  bc_integrity_entry_t entry_b;
  make_entry_file(&entry_b, file_path_b, 2);
  assert_true(
      bc_containers_vector_push(fixture->memory_context, entries, &entry_b));

  assert_true(bc_integrity_dispatch_compute_digests(
      fixture->memory_context, fixture->concurrency_context, NULL,
      BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, entries));

  bc_integrity_entry_t check;
  assert_true(bc_containers_vector_get(entries, 1, &check));
  assert_int_equal(check.digest_hex_length, 64u);
  assert_true(bc_containers_vector_get(entries, 4, &check));
  assert_int_equal(check.digest_hex_length, 64u);

  bc_containers_vector_destroy(fixture->memory_context, entries);
}

static void test_dispatch_sequential_zero_size(void **state) {
  if (!sha256_is_available() || bc_integrity_test_under_valgrind()) {
    skip();
    return;
  }
  dispatch_ext_state_t *fixture = (dispatch_ext_state_t *)*state;

  char file_path[512];
  snprintf(file_path, sizeof(file_path), "%s/empty.bin",
           fixture->directory_path);
  write_file(file_path, "", 0);
  char file_path_b[512];
  snprintf(file_path_b, sizeof(file_path_b), "%s/data.bin",
           fixture->directory_path);
  write_file(file_path_b, "abc", 3);

  bc_containers_vector_t *entries = NULL;
  assert_true(bc_containers_vector_create(
      fixture->memory_context, sizeof(bc_integrity_entry_t), 4, 16, &entries));
  bc_integrity_entry_t entry_zero;
  make_entry_file(&entry_zero, file_path, 0);
  assert_true(
      bc_containers_vector_push(fixture->memory_context, entries, &entry_zero));
  bc_integrity_entry_t entry_data;
  make_entry_file(&entry_data, file_path_b, 3);
  assert_true(
      bc_containers_vector_push(fixture->memory_context, entries, &entry_data));

  assert_true(bc_integrity_dispatch_compute_digests(
      fixture->memory_context, fixture->concurrency_context, NULL,
      BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, entries));

  bc_integrity_entry_t check;
  assert_true(bc_containers_vector_get(entries, 0, &check));
  assert_int_equal(check.digest_hex_length, 64u);
  assert_string_equal(
      check.digest_hex,
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

  bc_containers_vector_destroy(fixture->memory_context, entries);
}

static void test_dispatch_xxh3_algorithm(void **state) {
  if (bc_integrity_test_under_valgrind()) {
    skip();
    return;
  }
  dispatch_ext_state_t *fixture = (dispatch_ext_state_t *)*state;

  char file_path[512];
  snprintf(file_path, sizeof(file_path), "%s/x.txt",
           fixture->directory_path);
  write_file(file_path, "hello", 5);

  bc_containers_vector_t *entries = NULL;
  assert_true(bc_containers_vector_create(
      fixture->memory_context, sizeof(bc_integrity_entry_t), 4, 16, &entries));
  bc_integrity_entry_t entry;
  make_entry_file(&entry, file_path, 5);
  assert_true(
      bc_containers_vector_push(fixture->memory_context, entries, &entry));

  assert_true(bc_integrity_dispatch_compute_digests(
      fixture->memory_context, fixture->concurrency_context, NULL,
      BC_INTEGRITY_DIGEST_ALGORITHM_XXH3, entries));

  bc_integrity_entry_t check;
  assert_true(bc_containers_vector_get(entries, 0, &check));
  assert_int_equal(check.digest_hex_length, 16u);

  bc_containers_vector_destroy(fixture->memory_context, entries);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test_setup_teardown(test_dispatch_zero_entries_noop,
                                      setup_workers_4, dispatch_ext_teardown),
      cmocka_unit_test_setup_teardown(test_dispatch_skips_directory_kind,
                                      setup_workers_4, dispatch_ext_teardown),
      cmocka_unit_test_setup_teardown(test_dispatch_skips_not_ok_entry,
                                      setup_workers_4, dispatch_ext_teardown),
      cmocka_unit_test_setup_teardown(test_dispatch_skips_already_digested,
                                      setup_workers_4, dispatch_ext_teardown),
      cmocka_unit_test_setup_teardown(test_dispatch_open_failure_records_error,
                                      setup_workers_mono, dispatch_ext_teardown),
      cmocka_unit_test_setup_teardown(
          test_dispatch_parallel_above_threshold_with_ring, setup_workers_4,
          dispatch_ext_teardown),
      cmocka_unit_test_setup_teardown(test_dispatch_parallel_oversize_files,
                                      setup_workers_4, dispatch_ext_teardown),
      cmocka_unit_test_setup_teardown(test_dispatch_parallel_mixed_sizes,
                                      setup_workers_4, dispatch_ext_teardown),
      cmocka_unit_test_setup_teardown(test_dispatch_signal_stop_before_run,
                                      setup_workers_mono, dispatch_ext_teardown),
      cmocka_unit_test_setup_teardown(test_dispatch_signal_stop_parallel_path,
                                      setup_workers_4, dispatch_ext_teardown),
      cmocka_unit_test_setup_teardown(test_dispatch_parallel_ring_with_missing_file,
                                      setup_workers_4, dispatch_ext_teardown),
      cmocka_unit_test_setup_teardown(
          test_dispatch_parallel_oversize_with_missing_file, setup_workers_4,
          dispatch_ext_teardown),
      cmocka_unit_test_setup_teardown(test_dispatch_sequential_mixed_kinds,
                                      setup_workers_mono, dispatch_ext_teardown),
      cmocka_unit_test_setup_teardown(test_dispatch_sequential_zero_size,
                                      setup_workers_mono, dispatch_ext_teardown),
      cmocka_unit_test_setup_teardown(test_dispatch_xxh3_algorithm,
                                      setup_workers_4, dispatch_ext_teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
