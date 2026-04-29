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
#include "bc_integrity_cli_internal.h"
#include "bc_integrity_entry_internal.h"
#include "bc_integrity_walk_internal.h"
#include "bc_runtime_error_collector.h"

typedef struct walk_serial_state {
  char directory_path[256];
  bc_allocators_context_t *memory_context;
  bc_runtime_error_collector_t *errors;
} walk_serial_state_t;

static int walk_serial_setup(void **state) {
  walk_serial_state_t *fixture = malloc(sizeof(*fixture));
  if (fixture == NULL) {
    return -1;
  }
  snprintf(fixture->directory_path, sizeof(fixture->directory_path),
           "/tmp/bc_integrity_walk_serial_%d_XXXXXX", getpid());
  if (mkdtemp(fixture->directory_path) == NULL) {
    free(fixture);
    return -1;
  }
  bc_allocators_context_config_t config = {.tracking_enabled = true};
  if (!bc_allocators_context_create(&config, &fixture->memory_context)) {
    free(fixture);
    return -1;
  }
  if (!bc_runtime_error_collector_create(fixture->memory_context,
                                         &fixture->errors)) {
    bc_allocators_context_destroy(fixture->memory_context);
    free(fixture);
    return -1;
  }
  *state = fixture;
  return 0;
}

static int walk_serial_teardown(void **state) {
  walk_serial_state_t *fixture = (walk_serial_state_t *)*state;
  bc_runtime_error_collector_destroy(fixture->memory_context, fixture->errors);
  bc_allocators_context_destroy(fixture->memory_context);
  char command[512];
  snprintf(command, sizeof(command), "rm -rf '%s'", fixture->directory_path);
  int rc = system(command);
  (void)rc;
  free(fixture);
  return 0;
}

static void create_file(const char *parent, const char *name) {
  char path[512];
  snprintf(path, sizeof(path), "%s/%s", parent, name);
  FILE *fp = fopen(path, "wb");
  assert_non_null(fp);
  fputc('a', fp);
  fclose(fp);
}

static void test_walk_serial_completes_below_budget(void **state) {
  walk_serial_state_t *fixture = (walk_serial_state_t *)*state;
  for (size_t index = 0; index < 5; ++index) {
    char name[32];
    snprintf(name, sizeof(name), "file_%zu.txt", index);
    create_file(fixture->directory_path, name);
  }

  bc_containers_vector_t *entries = NULL;
  assert_true(bc_containers_vector_create(fixture->memory_context,
                                          sizeof(bc_integrity_entry_t), 16, 256,
                                          &entries));

  bc_integrity_manifest_options_t options;
  bc_core_zero(&options, sizeof(options));
  options.root_path = fixture->directory_path;
  options.digest_algorithm = BC_INTEGRITY_DIGEST_ALGORITHM_SHA256;
  options.defer_digest = true;
  options.default_exclude_virtual = false;

  size_t directory_path_length = strlen(fixture->directory_path);

  bool budget_exceeded = false;
  bool walk_ok = bc_integrity_walk_run_serial_with_budget(
      fixture->memory_context, NULL, &options, fixture->directory_path,
      directory_path_length, entries, fixture->errors, 100, &budget_exceeded);
  assert_true(walk_ok);
  assert_false(budget_exceeded);
  assert_true(bc_containers_vector_length(entries) >= 5);

  bc_containers_vector_destroy(fixture->memory_context, entries);
}

static void test_walk_serial_bail_above_budget(void **state) {
  walk_serial_state_t *fixture = (walk_serial_state_t *)*state;
  for (size_t index = 0; index < 50; ++index) {
    char name[32];
    snprintf(name, sizeof(name), "file_%zu.txt", index);
    create_file(fixture->directory_path, name);
  }

  bc_containers_vector_t *entries = NULL;
  assert_true(bc_containers_vector_create(fixture->memory_context,
                                          sizeof(bc_integrity_entry_t), 16,
                                          1024, &entries));

  bc_integrity_manifest_options_t options;
  bc_core_zero(&options, sizeof(options));
  options.root_path = fixture->directory_path;
  options.digest_algorithm = BC_INTEGRITY_DIGEST_ALGORITHM_SHA256;
  options.defer_digest = true;
  options.default_exclude_virtual = false;

  size_t directory_path_length = strlen(fixture->directory_path);

  bool budget_exceeded = false;
  bool walk_ok = bc_integrity_walk_run_serial_with_budget(
      fixture->memory_context, NULL, &options, fixture->directory_path,
      directory_path_length, entries, fixture->errors, 10, &budget_exceeded);
  assert_true(walk_ok);
  assert_true(budget_exceeded);

  bc_containers_vector_destroy(fixture->memory_context, entries);
}

static void test_walk_serial_zero_budget_unlimited(void **state) {
  walk_serial_state_t *fixture = (walk_serial_state_t *)*state;
  for (size_t index = 0; index < 20; ++index) {
    char name[32];
    snprintf(name, sizeof(name), "file_%zu.txt", index);
    create_file(fixture->directory_path, name);
  }

  bc_containers_vector_t *entries = NULL;
  assert_true(bc_containers_vector_create(fixture->memory_context,
                                          sizeof(bc_integrity_entry_t), 16, 64,
                                          &entries));

  bc_integrity_manifest_options_t options;
  bc_core_zero(&options, sizeof(options));
  options.root_path = fixture->directory_path;
  options.digest_algorithm = BC_INTEGRITY_DIGEST_ALGORITHM_SHA256;
  options.defer_digest = true;
  options.default_exclude_virtual = false;

  size_t directory_path_length = strlen(fixture->directory_path);

  bool walk_ok = bc_integrity_walk_run_serial(
      fixture->memory_context, NULL, &options, fixture->directory_path,
      directory_path_length, entries, fixture->errors);
  assert_true(walk_ok);
  assert_true(bc_containers_vector_length(entries) >= 20);

  bc_containers_vector_destroy(fixture->memory_context, entries);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test_setup_teardown(test_walk_serial_completes_below_budget,
                                      walk_serial_setup, walk_serial_teardown),
      cmocka_unit_test_setup_teardown(test_walk_serial_bail_above_budget,
                                      walk_serial_setup, walk_serial_teardown),
      cmocka_unit_test_setup_teardown(test_walk_serial_zero_budget_unlimited,
                                      walk_serial_setup, walk_serial_teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
