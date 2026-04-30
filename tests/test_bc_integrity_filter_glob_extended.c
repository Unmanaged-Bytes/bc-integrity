// SPDX-License-Identifier: MIT

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include <stdbool.h>

#include "bc_allocators.h"
#include "bc_integrity_filter_internal.h"

static void test_glob_empty_pattern_empty_value(void** state)
{
    (void)state;
    assert_true(bc_integrity_filter_glob_matches("", "", 0));
}

static void test_glob_empty_pattern_nonempty_value(void** state)
{
    (void)state;
    assert_false(bc_integrity_filter_glob_matches("", "abc", 3));
}

static void test_glob_nonempty_pattern_empty_value(void** state)
{
    (void)state;
    assert_false(bc_integrity_filter_glob_matches("abc", "", 0));
}

static void test_glob_trailing_star_after_match(void** state)
{
    (void)state;
    assert_true(bc_integrity_filter_glob_matches("abc*", "abc", strlen("abc")));
    assert_true(bc_integrity_filter_glob_matches("foo***", "foo", strlen("foo")));
    assert_true(bc_integrity_filter_glob_matches("a*", "a", 1));
}

static void test_glob_charset_negation(void** state)
{
    (void)state;
    assert_true(bc_integrity_filter_glob_matches("[!abc].txt", "d.txt", strlen("d.txt")));
    assert_false(bc_integrity_filter_glob_matches("[!abc].txt", "a.txt", strlen("a.txt")));
    assert_false(bc_integrity_filter_glob_matches("[!abc].txt", "b.txt", strlen("b.txt")));
}

static void test_glob_unclosed_bracket_treated_literally(void** state)
{
    (void)state;
    assert_true(bc_integrity_filter_glob_matches("[abc", "[abc", strlen("[abc")));
    assert_false(bc_integrity_filter_glob_matches("[abc", "abc", strlen("abc")));
    assert_false(bc_integrity_filter_glob_matches("[abc", "xabc", strlen("xabc")));
}

static void test_glob_charset_with_slash_rejected(void** state)
{
    (void)state;
    assert_false(bc_integrity_filter_glob_matches("[a/]xyz", "/xyz", strlen("/xyz")));
}

static void test_glob_question_mark_does_not_cross_slash(void** state)
{
    (void)state;
    assert_false(bc_integrity_filter_glob_matches("?xyz", "/xyz", strlen("/xyz")));
}

static void test_glob_double_star_at_start_matches_anything(void** state)
{
    (void)state;
    assert_true(bc_integrity_filter_glob_matches("**", "", 0));
    assert_true(bc_integrity_filter_glob_matches("**", "a", 1));
    assert_true(bc_integrity_filter_glob_matches("**", "deep/nested/path", strlen("deep/nested/path")));
}

static void test_glob_double_star_middle(void** state)
{
    (void)state;
    assert_true(bc_integrity_filter_glob_matches("a/**/b", "a/b", strlen("a/b")));
    assert_true(bc_integrity_filter_glob_matches("a/**/b", "a/x/b", strlen("a/x/b")));
    assert_true(bc_integrity_filter_glob_matches("a/**/b", "a/x/y/z/b", strlen("a/x/y/z/b")));
    assert_false(bc_integrity_filter_glob_matches("a/**/b", "a/x/c", strlen("a/x/c")));
}

static void test_glob_pattern_done_value_not_done(void** state)
{
    (void)state;
    assert_false(bc_integrity_filter_glob_matches("foo", "foo/bar", strlen("foo/bar")));
}

static void test_glob_pattern_not_done_value_done(void** state)
{
    (void)state;
    assert_false(bc_integrity_filter_glob_matches("foo/bar", "foo", strlen("foo")));
}

static void test_glob_charset_range(void** state)
{
    (void)state;
    assert_true(bc_integrity_filter_glob_matches("[a-c].txt", "b.txt", strlen("b.txt")));
    assert_false(bc_integrity_filter_glob_matches("[a-c].txt", "z.txt", strlen("z.txt")));
    assert_true(bc_integrity_filter_glob_matches("[A-Z][0-9]", "B5", strlen("B5")));
}

static void test_glob_question_mark_in_middle(void** state)
{
    (void)state;
    assert_true(bc_integrity_filter_glob_matches("?ello", "hello", strlen("hello")));
    assert_true(bc_integrity_filter_glob_matches("?ello", "jello", strlen("jello")));
    assert_false(bc_integrity_filter_glob_matches("?ello", "ello", strlen("ello")));
}

static void test_glob_star_with_charset(void** state)
{
    (void)state;
    assert_true(bc_integrity_filter_glob_matches("[abc]*", "abacus", strlen("abacus")));
    assert_true(bc_integrity_filter_glob_matches("[abc]*", "ball", strlen("ball")));
    assert_false(bc_integrity_filter_glob_matches("[abc]*", "zebra", strlen("zebra")));
}

static void test_filter_create_with_empty_strings(void** state)
{
    (void)state;
    bc_allocators_context_config_t config = {.tracking_enabled = true};
    bc_allocators_context_t* memory_context = NULL;
    assert_true(bc_allocators_context_create(&config, &memory_context));

    bc_integrity_filter_t* filter = NULL;
    assert_true(bc_integrity_filter_create(memory_context, "", "", &filter));
    assert_true(bc_integrity_filter_accepts_path(filter, "x.txt", strlen("x.txt")));
    assert_true(bc_integrity_filter_accepts_directory(filter, "x", strlen("x")));
    bc_integrity_filter_destroy(memory_context, filter);
    bc_allocators_context_destroy(memory_context);
}

static void test_filter_null_filter_accepts(void** state)
{
    (void)state;
    assert_true(bc_integrity_filter_accepts_path(NULL, "anything", strlen("anything")));
    assert_true(bc_integrity_filter_accepts_directory(NULL, "anything", strlen("anything")));
}

static void test_filter_directory_root_always_accepted(void** state)
{
    (void)state;
    bc_allocators_context_config_t config = {.tracking_enabled = true};
    bc_allocators_context_t* memory_context = NULL;
    assert_true(bc_allocators_context_create(&config, &memory_context));

    bc_integrity_filter_t* filter = NULL;
    assert_true(bc_integrity_filter_create(memory_context, NULL, "build/**", &filter));
    assert_true(bc_integrity_filter_accepts_directory(filter, "", 0));

    bc_integrity_filter_destroy(memory_context, filter);
    bc_allocators_context_destroy(memory_context);
}

static void test_filter_directory_excluded_by_exact_pattern(void** state)
{
    (void)state;
    bc_allocators_context_config_t config = {.tracking_enabled = true};
    bc_allocators_context_t* memory_context = NULL;
    assert_true(bc_allocators_context_create(&config, &memory_context));

    bc_integrity_filter_t* filter = NULL;
    assert_true(bc_integrity_filter_create(memory_context, NULL, "node_modules", &filter));
    assert_false(bc_integrity_filter_accepts_directory(filter, "node_modules", strlen("node_modules")));
    assert_true(bc_integrity_filter_accepts_directory(filter, "src", strlen("src")));

    bc_integrity_filter_destroy(memory_context, filter);
    bc_allocators_context_destroy(memory_context);
}

static void test_filter_directory_double_star_prefix_excludes_all(void** state)
{
    (void)state;
    bc_allocators_context_config_t config = {.tracking_enabled = true};
    bc_allocators_context_t* memory_context = NULL;
    assert_true(bc_allocators_context_create(&config, &memory_context));

    bc_integrity_filter_t* filter = NULL;
    assert_true(bc_integrity_filter_create(memory_context, NULL, "**", &filter));
    assert_false(bc_integrity_filter_accepts_directory(filter, "anything", strlen("anything")));

    bc_integrity_filter_destroy(memory_context, filter);
    bc_allocators_context_destroy(memory_context);
}

static void test_filter_directory_double_star_prefix_branch(void** state)
{
    (void)state;
    bc_allocators_context_config_t config = {.tracking_enabled = true};
    bc_allocators_context_t* memory_context = NULL;
    assert_true(bc_allocators_context_create(&config, &memory_context));

    bc_integrity_filter_t* filter = NULL;
    assert_true(bc_integrity_filter_create(memory_context, NULL, "**/*.tmp", &filter));
    assert_false(bc_integrity_filter_accepts_directory(filter, "subdir", strlen("subdir")));

    bc_integrity_filter_destroy(memory_context, filter);
    bc_allocators_context_destroy(memory_context);
}

static void test_filter_directory_slash_double_star_suffix(void** state)
{
    (void)state;
    bc_allocators_context_config_t config = {.tracking_enabled = true};
    bc_allocators_context_t* memory_context = NULL;
    assert_true(bc_allocators_context_create(&config, &memory_context));

    bc_integrity_filter_t* filter = NULL;
    assert_true(bc_integrity_filter_create(memory_context, NULL, "build/**", &filter));
    assert_false(bc_integrity_filter_accepts_directory(filter, "build", strlen("build")));

    bc_integrity_filter_destroy(memory_context, filter);
    bc_allocators_context_destroy(memory_context);
}

static void test_glob_star_backtrack_across_slash(void** state)
{
    (void)state;
    assert_false(bc_integrity_filter_glob_matches("*x", "/x", strlen("/x")));
    assert_false(bc_integrity_filter_glob_matches("*x", "y/x", strlen("y/x")));
}

static void test_glob_long_subdir_pattern_value_done_early(void** state)
{
    (void)state;
    assert_false(bc_integrity_filter_glob_matches("a/b/c/d/e/f", "a/b/c", strlen("a/b/c")));
}

static void test_filter_multi_pattern_split(void** state)
{
    (void)state;
    bc_allocators_context_config_t config = {.tracking_enabled = true};
    bc_allocators_context_t* memory_context = NULL;
    assert_true(bc_allocators_context_create(&config, &memory_context));

    bc_integrity_filter_t* filter = NULL;
    assert_true(bc_integrity_filter_create(memory_context, "*.c\n*.h\n*.txt", "secret*\n.git/**", &filter));

    assert_true(bc_integrity_filter_accepts_path(filter, "main.c", strlen("main.c")));
    assert_true(bc_integrity_filter_accepts_path(filter, "header.h", strlen("header.h")));
    assert_true(bc_integrity_filter_accepts_path(filter, "readme.txt", strlen("readme.txt")));
    assert_false(bc_integrity_filter_accepts_path(filter, "secret123", strlen("secret123")));
    assert_false(bc_integrity_filter_accepts_path(filter, "main.cpp", strlen("main.cpp")));

    bc_integrity_filter_destroy(memory_context, filter);
    bc_allocators_context_destroy(memory_context);
}

static void test_filter_destroy_null_safe(void** state)
{
    (void)state;
    bc_allocators_context_config_t config = {.tracking_enabled = true};
    bc_allocators_context_t* memory_context = NULL;
    assert_true(bc_allocators_context_create(&config, &memory_context));

    bc_integrity_filter_destroy(memory_context, NULL);

    bc_allocators_context_destroy(memory_context);
}

static void test_filter_single_pattern_no_separator(void** state)
{
    (void)state;
    bc_allocators_context_config_t config = {.tracking_enabled = true};
    bc_allocators_context_t* memory_context = NULL;
    assert_true(bc_allocators_context_create(&config, &memory_context));

    bc_integrity_filter_t* filter = NULL;
    assert_true(bc_integrity_filter_create(memory_context, "*.md", NULL, &filter));
    assert_true(bc_integrity_filter_accepts_path(filter, "doc.md", strlen("doc.md")));
    assert_false(bc_integrity_filter_accepts_path(filter, "doc.html", strlen("doc.html")));

    bc_integrity_filter_destroy(memory_context, filter);
    bc_allocators_context_destroy(memory_context);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_glob_empty_pattern_empty_value),
        cmocka_unit_test(test_glob_empty_pattern_nonempty_value),
        cmocka_unit_test(test_glob_nonempty_pattern_empty_value),
        cmocka_unit_test(test_glob_trailing_star_after_match),
        cmocka_unit_test(test_glob_charset_negation),
        cmocka_unit_test(test_glob_unclosed_bracket_treated_literally),
        cmocka_unit_test(test_glob_charset_with_slash_rejected),
        cmocka_unit_test(test_glob_question_mark_does_not_cross_slash),
        cmocka_unit_test(test_glob_double_star_at_start_matches_anything),
        cmocka_unit_test(test_glob_double_star_middle),
        cmocka_unit_test(test_glob_pattern_done_value_not_done),
        cmocka_unit_test(test_glob_pattern_not_done_value_done),
        cmocka_unit_test(test_glob_charset_range),
        cmocka_unit_test(test_glob_question_mark_in_middle),
        cmocka_unit_test(test_glob_star_with_charset),
        cmocka_unit_test(test_filter_create_with_empty_strings),
        cmocka_unit_test(test_filter_null_filter_accepts),
        cmocka_unit_test(test_filter_directory_root_always_accepted),
        cmocka_unit_test(test_filter_directory_excluded_by_exact_pattern),
        cmocka_unit_test(test_filter_directory_double_star_prefix_excludes_all),
        cmocka_unit_test(test_filter_directory_double_star_prefix_branch),
        cmocka_unit_test(test_filter_directory_slash_double_star_suffix),
        cmocka_unit_test(test_glob_star_backtrack_across_slash),
        cmocka_unit_test(test_glob_long_subdir_pattern_value_done_early),
        cmocka_unit_test(test_filter_multi_pattern_split),
        cmocka_unit_test(test_filter_destroy_null_safe),
        cmocka_unit_test(test_filter_single_pattern_no_separator),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
