// SPDX-License-Identifier: MIT

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include <fcntl.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bc_allocators.h"
#include "bc_concurrency.h"
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

typedef struct smallcorpus_state {
  char directory_path[256];
  bc_allocators_context_t *memory_context;
  bc_concurrency_context_t *concurrency_context;
  size_t worker_count;
} smallcorpus_state_t;

static int smallcorpus_make_state(void **state, size_t worker_count) {
  smallcorpus_state_t *fixture = malloc(sizeof(*fixture));
  if (fixture == NULL) {
    return -1;
  }
  fixture->worker_count = worker_count;
  snprintf(fixture->directory_path, sizeof(fixture->directory_path),
           "/tmp/bc_integrity_dispatch_smallcorpus_%d_XXXXXX", getpid());
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
  return smallcorpus_make_state(state, 4);
}

static int setup_workers_mono(void **state) {
  return smallcorpus_make_state(state, 0);
}

static int smallcorpus_teardown(void **state) {
  smallcorpus_state_t *fixture = (smallcorpus_state_t *)*state;
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
  fwrite(content, 1, length, file);
  fclose(file);
}

static void make_entry(bc_integrity_entry_t *entry, const char *absolute_path,
                       size_t file_size) {
  bc_core_zero(entry, sizeof(*entry));
  entry->relative_path = absolute_path;
  entry->relative_path_length = strlen(absolute_path);
  entry->absolute_path = absolute_path;
  entry->absolute_path_length = strlen(absolute_path);
  entry->kind = BC_INTEGRITY_ENTRY_KIND_FILE;
  entry->ok = true;
  entry->size_bytes = (uint64_t)file_size;
}

static const char *expected_digest_for_payload(size_t index) {
  static const char *digests[] = {
      "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
      "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d",
      "2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6",
      "18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4",
      "3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea",
      "252f10c83610ebca1a059c0bae8255eba2f95be4d1d7bcfa89d7248a82d9f111",
      "cd0aa9856147b6c5b4ff2b7dfee5da20aa38253099ef1b4a64aced233c9afe29",
      "aaa9402664f1a41f40ebbc52c9993eb66aeb366602958fdfaa283b71e64db123",
      "de7d1b721a1e0632b7cf04edf5032c8ecffa9f9a08492152b926f1a5a7e765d7",
      "189f40034be7a199f1fa9891668ee3ab6049f82d38c68be70f596eab2e1857b7",
  };
  return digests[index];
}

static char payload_for_index(size_t index) { return 'a' + (char)index; }

static void run_dispatch_and_verify(smallcorpus_state_t *fixture,
                                    size_t entry_count) {
  bc_containers_vector_t *entries = NULL;
  assert_true(bc_containers_vector_create(fixture->memory_context,
                                          sizeof(bc_integrity_entry_t), 16, 256,
                                          &entries));
  char *paths = malloc(entry_count * 512);
  assert_non_null(paths);
  for (size_t index = 0; index < entry_count; ++index) {
    char *path = paths + index * 512;
    snprintf(path, 512, "%s/file_%04zu.bin", fixture->directory_path, index);
    char single_byte = payload_for_index(index % 10);
    write_file(path, &single_byte, 1);
    bc_integrity_entry_t entry;
    make_entry(&entry, path, 1);
    assert_true(
        bc_containers_vector_push(fixture->memory_context, entries, &entry));
  }

  assert_true(bc_integrity_dispatch_compute_digests(
      fixture->memory_context, fixture->concurrency_context, NULL,
      BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, entries));

  for (size_t index = 0; index < entry_count; ++index) {
    bc_integrity_entry_t entry_check;
    assert_true(bc_containers_vector_get(entries, index, &entry_check));
    assert_int_equal(entry_check.digest_hex_length, 64u);
    assert_string_equal(entry_check.digest_hex,
                        expected_digest_for_payload(index % 10));
  }

  free(paths);
  bc_containers_vector_destroy(fixture->memory_context, entries);
}

static void test_fallback_below_threshold_workers4(void **state) {
  if (!sha256_is_available() || bc_integrity_test_under_valgrind()) {
    skip();
    return;
  }
  smallcorpus_state_t *fixture = (smallcorpus_state_t *)*state;
  run_dispatch_and_verify(fixture, 5);
}

static void test_parallel_above_threshold_workers4(void **state) {
  if (!sha256_is_available() || bc_integrity_test_under_valgrind()) {
    skip();
    return;
  }
  smallcorpus_state_t *fixture = (smallcorpus_state_t *)*state;
  run_dispatch_and_verify(fixture, 100);
}

static void test_fallback_forced_single_worker(void **state) {
  if (!sha256_is_available() || bc_integrity_test_under_valgrind()) {
    skip();
    return;
  }
  smallcorpus_state_t *fixture = (smallcorpus_state_t *)*state;
  run_dispatch_and_verify(fixture, 50);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test_setup_teardown(test_fallback_below_threshold_workers4,
                                      setup_workers_4, smallcorpus_teardown),
      cmocka_unit_test_setup_teardown(test_parallel_above_threshold_workers4,
                                      setup_workers_4, smallcorpus_teardown),
      cmocka_unit_test_setup_teardown(test_fallback_forced_single_worker,
                                      setup_workers_mono, smallcorpus_teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
