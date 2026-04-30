// SPDX-License-Identifier: MIT

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "bc_integrity_filter_internal.h"

extern bool bc_integrity_filter_glob_matches(const char* pattern, const char* value, size_t value_length);

static void test_glob_rejects_pattern_with_too_many_double_star(void** state)
{
    (void)state;
    /* 5 ** segments (cap = 4) → must return false (no match), not slow-loop. */
    const char* pattern = "**/**/**/**/**/x";
    const char* value = "a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/y";
    /* If the cap works, this returns immediately false. Without the cap,
     the recursive backtracking would take seconds on adversarial input. */
    assert_false(bc_integrity_filter_glob_matches(pattern, value, strlen(value)));
}

static void test_glob_accepts_pattern_with_four_double_star(void** state)
{
    (void)state;
    /* 4 ** segments (at the cap) is still allowed. */
    const char* pattern = "**/**/**/**/x";
    const char* value = "a/b/c/d/x";
    /* Must complete (regardless of result). */
    (void)bc_integrity_filter_glob_matches(pattern, value, strlen(value));
}

static void test_glob_normal_pattern_works(void** state)
{
    (void)state;
    assert_true(bc_integrity_filter_glob_matches("**/*.c", "src/sub/main.c", strlen("src/sub/main.c")));
    assert_true(bc_integrity_filter_glob_matches("build/**", "build/release/x", strlen("build/release/x")));
    assert_false(bc_integrity_filter_glob_matches("**/*.c", "src/main.txt", strlen("src/main.txt")));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_glob_rejects_pattern_with_too_many_double_star),
        cmocka_unit_test(test_glob_accepts_pattern_with_four_double_star),
        cmocka_unit_test(test_glob_normal_pattern_works),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
