// SPDX-License-Identifier: MIT

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>

#include <cmocka.h>

#include <stdbool.h>
#include <string.h>

#include "bc_integrity_cli_internal.h"
#include "bc_runtime.h"
#include "bc_runtime_cli.h"

static void test_program_spec_pointer_is_non_null(void **state) {
  (void)state;
  const bc_runtime_cli_program_spec_t *spec = bc_integrity_cli_program_spec();
  assert_non_null(spec);
}

static void test_program_spec_identity(void **state) {
  (void)state;
  const bc_runtime_cli_program_spec_t *spec = bc_integrity_cli_program_spec();
  assert_non_null(spec->program_name);
  assert_string_equal(spec->program_name, "bc-integrity");
  assert_non_null(spec->version);
  assert_string_equal(spec->version, "rolling");
}

static void test_program_spec_commands_declared(void **state) {
  (void)state;
  const bc_runtime_cli_program_spec_t *spec = bc_integrity_cli_program_spec();
  assert_int_equal(spec->command_count, 3u);
  assert_non_null(spec->commands);
  assert_string_equal(spec->commands[0].name, "manifest");
  assert_string_equal(spec->commands[1].name, "verify");
  assert_string_equal(spec->commands[2].name, "diff");
}

static void test_program_spec_global_threads_option(void **state) {
  (void)state;
  const bc_runtime_cli_program_spec_t *spec = bc_integrity_cli_program_spec();
  assert_int_equal(spec->global_option_count, 1u);
  assert_non_null(spec->global_options);
  assert_string_equal(spec->global_options[0].long_name, "threads");
}

static void test_program_spec_manifest_options(void **state) {
  (void)state;
  const bc_runtime_cli_program_spec_t *spec = bc_integrity_cli_program_spec();
  const bc_runtime_cli_command_spec_t *manifest = NULL;
  for (size_t index = 0; index < spec->command_count; ++index) {
    if (strcmp(spec->commands[index].name, "manifest") == 0) {
      manifest = &spec->commands[index];
      break;
    }
  }
  assert_non_null(manifest);
  assert_int_equal(manifest->positional_min, 1u);
  assert_int_equal(manifest->positional_max, 1u);
  assert_true(manifest->option_count >= 6u);

  bool found_output = false;
  bool found_digest = false;
  bool found_follow = false;
  bool found_hidden = false;
  bool found_special = false;
  bool found_default_exclude = false;
  for (size_t index = 0; index < manifest->option_count; ++index) {
    const char *name = manifest->options[index].long_name;
    if (strcmp(name, "output") == 0) {
      found_output = true;
    } else if (strcmp(name, "digest-algorithm") == 0) {
      found_digest = true;
    } else if (strcmp(name, "follow-symlinks") == 0) {
      found_follow = true;
    } else if (strcmp(name, "include-hidden") == 0) {
      found_hidden = true;
    } else if (strcmp(name, "include-special") == 0) {
      found_special = true;
    } else if (strcmp(name, "default-exclude-virtual") == 0) {
      found_default_exclude = true;
    }
  }
  assert_true(found_output);
  assert_true(found_digest);
  assert_true(found_follow);
  assert_true(found_hidden);
  assert_true(found_special);
  assert_true(found_default_exclude);
}

static void test_digest_algorithm_name_round_trip(void **state) {
  (void)state;
  assert_string_equal(bc_integrity_cli_digest_algorithm_name(
                          BC_INTEGRITY_DIGEST_ALGORITHM_SHA256),
                      "sha256");
  assert_string_equal(bc_integrity_cli_digest_algorithm_name(
                          BC_INTEGRITY_DIGEST_ALGORITHM_XXH3),
                      "xxh3");
  assert_string_equal(bc_integrity_cli_digest_algorithm_name(
                          BC_INTEGRITY_DIGEST_ALGORITHM_XXH128),
                      "xxh128");
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_program_spec_pointer_is_non_null),
      cmocka_unit_test(test_program_spec_identity),
      cmocka_unit_test(test_program_spec_commands_declared),
      cmocka_unit_test(test_program_spec_global_threads_option),
      cmocka_unit_test(test_program_spec_manifest_options),
      cmocka_unit_test(test_digest_algorithm_name_round_trip),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
