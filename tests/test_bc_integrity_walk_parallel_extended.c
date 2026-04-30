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
#include "bc_integrity_cli_internal.h"
#include "bc_integrity_entry_internal.h"
#include "bc_integrity_walk_internal.h"
#include "bc_runtime_error_collector.h"

typedef struct walk_parallel_state {
    char directory_path[256];
    bc_allocators_context_t* memory_context;
    bc_concurrency_context_t* concurrency_context;
    bc_runtime_error_collector_t* errors;
} walk_parallel_state_t;

static int walk_parallel_setup(void** state)
{
    walk_parallel_state_t* fixture = malloc(sizeof(*fixture));
    if (fixture == NULL) {
        return -1;
    }
    snprintf(fixture->directory_path, sizeof(fixture->directory_path), "/tmp/bc_integrity_walk_par_%d_XXXXXX", getpid());
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
    parallel_config.worker_count = 2;
    if (!bc_concurrency_create(fixture->memory_context, &parallel_config, &fixture->concurrency_context)) {
        bc_allocators_context_destroy(fixture->memory_context);
        free(fixture);
        return -1;
    }
    if (!bc_runtime_error_collector_create(fixture->memory_context, &fixture->errors)) {
        bc_concurrency_destroy(fixture->concurrency_context);
        bc_allocators_context_destroy(fixture->memory_context);
        free(fixture);
        return -1;
    }
    *state = fixture;
    return 0;
}

static int walk_parallel_teardown(void** state)
{
    walk_parallel_state_t* fixture = (walk_parallel_state_t*)*state;
    bc_runtime_error_collector_destroy(fixture->memory_context, fixture->errors);
    bc_concurrency_destroy(fixture->concurrency_context);
    bc_allocators_context_destroy(fixture->memory_context);
    char command[512];
    snprintf(command, sizeof(command), "rm -rf '%s'", fixture->directory_path);
    int rc = system(command);
    (void)rc;
    free(fixture);
    return 0;
}

static void create_file_at(const char* parent, const char* name, const char* contents)
{
    char path[4096];
    snprintf(path, sizeof(path), "%s/%s", parent, name);
    FILE* fp = fopen(path, "wb");
    assert_non_null(fp);
    fputs(contents, fp);
    fclose(fp);
}

static void create_dir_at(const char* parent, const char* name)
{
    char path[4096];
    snprintf(path, sizeof(path), "%s/%s", parent, name);
    assert_int_equal(mkdir(path, 0755), 0);
}

static void create_symlink_at(const char* parent, const char* target, const char* name)
{
    char path[4096];
    snprintf(path, sizeof(path), "%s/%s", parent, name);
    assert_int_equal(symlink(target, path), 0);
}

static void create_fifo_at(const char* parent, const char* name)
{
    char path[4096];
    snprintf(path, sizeof(path), "%s/%s", parent, name);
    assert_int_equal(mkfifo(path, 0644), 0);
}

static bc_containers_vector_t* make_entries_vector(walk_parallel_state_t* fix)
{
    bc_containers_vector_t* entries = NULL;
    assert_true(bc_containers_vector_create(fix->memory_context, sizeof(bc_integrity_entry_t), 16, (size_t)1U << 24, &entries));
    return entries;
}

static void make_default_options(bc_integrity_manifest_options_t* options, const char* root_path)
{
    bc_core_zero(options, sizeof(*options));
    options->root_path = root_path;
    options->digest_algorithm = BC_INTEGRITY_DIGEST_ALGORITHM_SHA256;
    options->defer_digest = true;
    options->default_exclude_virtual = false;
    options->include_hidden = true;
    options->include_special = false;
    options->follow_symlinks = false;
}

static void test_walk_parallel_small_tree(void** state)
{
    walk_parallel_state_t* fixture = (walk_parallel_state_t*)*state;
    for (size_t index = 0; index < 8; ++index) {
        char name[32];
        snprintf(name, sizeof(name), "file_%zu.txt", index);
        create_file_at(fixture->directory_path, name, "hello");
    }
    bc_containers_vector_t* entries = make_entries_vector(fixture);

    bc_integrity_manifest_options_t options;
    make_default_options(&options, fixture->directory_path);

    size_t directory_path_length = strlen(fixture->directory_path);
    bool walk_ok = bc_integrity_walk_run(fixture->memory_context, fixture->concurrency_context, NULL, &options, fixture->directory_path,
                                         directory_path_length, entries, fixture->errors);
    assert_true(walk_ok);
    assert_true(bc_containers_vector_length(entries) >= 8);

    bc_containers_vector_destroy(fixture->memory_context, entries);
}

static void test_walk_parallel_medium_tree_forces_parallel(void** state)
{
    walk_parallel_state_t* fixture = (walk_parallel_state_t*)*state;
    create_dir_at(fixture->directory_path, "sub_a");
    create_dir_at(fixture->directory_path, "sub_b");
    char sub_a[1024];
    char sub_b[1024];
    snprintf(sub_a, sizeof(sub_a), "%s/sub_a", fixture->directory_path);
    snprintf(sub_b, sizeof(sub_b), "%s/sub_b", fixture->directory_path);
    for (size_t index = 0; index < 32000; ++index) {
        char name[64];
        snprintf(name, sizeof(name), "f_%zu.txt", index);
        const char* parent = (index % 2 == 0) ? sub_a : sub_b;
        create_file_at(parent, name, "x");
    }
    for (size_t index = 0; index < 200; ++index) {
        char name[64];
        snprintf(name, sizeof(name), "lnk_%zu", index);
        create_symlink_at(sub_a, "../sub_b", name);
    }
    for (size_t index = 0; index < 50; ++index) {
        char name[64];
        snprintf(name, sizeof(name), "fifo_%zu", index);
        create_fifo_at(sub_b, name);
    }

    bc_containers_vector_t* entries = make_entries_vector(fixture);

    bc_integrity_manifest_options_t options;
    make_default_options(&options, fixture->directory_path);
    options.include_special = true;
    options.default_exclude_virtual = true;

    size_t directory_path_length = strlen(fixture->directory_path);
    bool walk_ok = bc_integrity_walk_run(fixture->memory_context, fixture->concurrency_context, NULL, &options, fixture->directory_path,
                                         directory_path_length, entries, fixture->errors);
    assert_true(walk_ok);
    assert_true(bc_containers_vector_length(entries) >= 32000);

    bc_containers_vector_destroy(fixture->memory_context, entries);
}

static void test_walk_parallel_skip_hidden(void** state)
{
    walk_parallel_state_t* fixture = (walk_parallel_state_t*)*state;
    create_file_at(fixture->directory_path, "visible.txt", "v");
    create_file_at(fixture->directory_path, ".hidden.txt", "h");

    bc_containers_vector_t* entries = make_entries_vector(fixture);

    bc_integrity_manifest_options_t options;
    make_default_options(&options, fixture->directory_path);
    options.include_hidden = false;

    size_t directory_path_length = strlen(fixture->directory_path);
    bool walk_ok = bc_integrity_walk_run(fixture->memory_context, fixture->concurrency_context, NULL, &options, fixture->directory_path,
                                         directory_path_length, entries, fixture->errors);
    assert_true(walk_ok);

    size_t count = bc_containers_vector_length(entries);
    bool found_hidden = false;
    bool found_visible = false;
    for (size_t index = 0; index < count; ++index) {
        bc_integrity_entry_t entry;
        assert_true(bc_containers_vector_get(entries, index, &entry));
        if (entry.relative_path != NULL && entry.relative_path_length > 0) {
            if (strcmp(entry.relative_path, ".hidden.txt") == 0) {
                found_hidden = true;
            }
            if (strcmp(entry.relative_path, "visible.txt") == 0) {
                found_visible = true;
            }
        }
    }
    assert_false(found_hidden);
    assert_true(found_visible);

    bc_containers_vector_destroy(fixture->memory_context, entries);
}

static void test_walk_parallel_skip_special(void** state)
{
    walk_parallel_state_t* fixture = (walk_parallel_state_t*)*state;
    create_file_at(fixture->directory_path, "regular.txt", "r");
    create_fifo_at(fixture->directory_path, "fifo_special");

    bc_containers_vector_t* entries = make_entries_vector(fixture);

    bc_integrity_manifest_options_t options;
    make_default_options(&options, fixture->directory_path);
    options.include_special = false;

    size_t directory_path_length = strlen(fixture->directory_path);
    bool walk_ok = bc_integrity_walk_run(fixture->memory_context, fixture->concurrency_context, NULL, &options, fixture->directory_path,
                                         directory_path_length, entries, fixture->errors);
    assert_true(walk_ok);

    size_t count = bc_containers_vector_length(entries);
    bool found_fifo = false;
    for (size_t index = 0; index < count; ++index) {
        bc_integrity_entry_t entry;
        assert_true(bc_containers_vector_get(entries, index, &entry));
        if (entry.relative_path != NULL && strcmp(entry.relative_path, "fifo_special") == 0) {
            found_fifo = true;
        }
    }
    assert_false(found_fifo);

    bc_containers_vector_destroy(fixture->memory_context, entries);
}

static void test_walk_parallel_include_special(void** state)
{
    walk_parallel_state_t* fixture = (walk_parallel_state_t*)*state;
    create_file_at(fixture->directory_path, "regular.txt", "r");
    create_fifo_at(fixture->directory_path, "fifo_special");

    bc_containers_vector_t* entries = make_entries_vector(fixture);

    bc_integrity_manifest_options_t options;
    make_default_options(&options, fixture->directory_path);
    options.include_special = true;

    size_t directory_path_length = strlen(fixture->directory_path);
    bool walk_ok = bc_integrity_walk_run(fixture->memory_context, fixture->concurrency_context, NULL, &options, fixture->directory_path,
                                         directory_path_length, entries, fixture->errors);
    assert_true(walk_ok);

    size_t count = bc_containers_vector_length(entries);
    bool found_fifo = false;
    for (size_t index = 0; index < count; ++index) {
        bc_integrity_entry_t entry;
        assert_true(bc_containers_vector_get(entries, index, &entry));
        if (entry.relative_path != NULL && strcmp(entry.relative_path, "fifo_special") == 0) {
            found_fifo = true;
        }
    }
    assert_true(found_fifo);

    bc_containers_vector_destroy(fixture->memory_context, entries);
}

static void test_walk_parallel_with_symlinks_no_follow(void** state)
{
    walk_parallel_state_t* fixture = (walk_parallel_state_t*)*state;
    create_file_at(fixture->directory_path, "target.txt", "t");
    create_symlink_at(fixture->directory_path, "target.txt", "link.txt");

    bc_containers_vector_t* entries = make_entries_vector(fixture);

    bc_integrity_manifest_options_t options;
    make_default_options(&options, fixture->directory_path);
    options.follow_symlinks = false;

    size_t directory_path_length = strlen(fixture->directory_path);
    bool walk_ok = bc_integrity_walk_run(fixture->memory_context, fixture->concurrency_context, NULL, &options, fixture->directory_path,
                                         directory_path_length, entries, fixture->errors);
    assert_true(walk_ok);

    size_t count = bc_containers_vector_length(entries);
    bool found_symlink = false;
    for (size_t index = 0; index < count; ++index) {
        bc_integrity_entry_t entry;
        assert_true(bc_containers_vector_get(entries, index, &entry));
        if (entry.relative_path != NULL && strcmp(entry.relative_path, "link.txt") == 0) {
            found_symlink = true;
        }
    }
    assert_true(found_symlink);

    bc_containers_vector_destroy(fixture->memory_context, entries);
}

static void test_walk_parallel_empty_tree(void** state)
{
    walk_parallel_state_t* fixture = (walk_parallel_state_t*)*state;
    bc_containers_vector_t* entries = make_entries_vector(fixture);

    bc_integrity_manifest_options_t options;
    make_default_options(&options, fixture->directory_path);

    size_t directory_path_length = strlen(fixture->directory_path);
    bool walk_ok = bc_integrity_walk_run(fixture->memory_context, fixture->concurrency_context, NULL, &options, fixture->directory_path,
                                         directory_path_length, entries, fixture->errors);
    assert_true(walk_ok);

    bc_containers_vector_destroy(fixture->memory_context, entries);
}

static void test_walk_parallel_default_exclude_virtual_root_rejected(void** state)
{
    walk_parallel_state_t* fixture = (walk_parallel_state_t*)*state;
    for (size_t index = 0; index < 6000; ++index) {
        char name[32];
        snprintf(name, sizeof(name), "f_%zu.txt", index);
        create_file_at(fixture->directory_path, name, "x");
    }
    bc_containers_vector_t* entries = make_entries_vector(fixture);

    bc_integrity_manifest_options_t options;
    make_default_options(&options, fixture->directory_path);
    options.default_exclude_virtual = true;
    options.root_path = "/proc";

    bool walk_ok =
        bc_integrity_walk_run(fixture->memory_context, fixture->concurrency_context, NULL, &options, "/proc", 5, entries, fixture->errors);
    assert_false(walk_ok);

    bc_containers_vector_destroy(fixture->memory_context, entries);
}

static void test_walk_parallel_filter_include_glob(void** state)
{
    walk_parallel_state_t* fixture = (walk_parallel_state_t*)*state;
    create_dir_at(fixture->directory_path, "child_dir");
    char child_dir[1024];
    snprintf(child_dir, sizeof(child_dir), "%s/child_dir", fixture->directory_path);
    for (size_t index = 0; index < 6000; ++index) {
        char name[64];
        snprintf(name, sizeof(name), "keep_%zu.txt", index);
        create_file_at(fixture->directory_path, name, "k");
    }
    for (size_t index = 0; index < 6000; ++index) {
        char name[64];
        snprintf(name, sizeof(name), "reject_%zu.dat", index);
        create_file_at(child_dir, name, "r");
    }

    bc_containers_vector_t* entries = make_entries_vector(fixture);

    bc_integrity_manifest_options_t options;
    make_default_options(&options, fixture->directory_path);
    options.include_list = "*.txt";

    size_t directory_path_length = strlen(fixture->directory_path);
    bool walk_ok = bc_integrity_walk_run(fixture->memory_context, fixture->concurrency_context, NULL, &options, fixture->directory_path,
                                         directory_path_length, entries, fixture->errors);
    assert_true(walk_ok);

    size_t count = bc_containers_vector_length(entries);
    bool found_dat = false;
    size_t txt_count = 0;
    for (size_t index = 0; index < count; ++index) {
        bc_integrity_entry_t entry;
        assert_true(bc_containers_vector_get(entries, index, &entry));
        if (entry.relative_path == NULL || entry.relative_path_length < 4) {
            continue;
        }
        const char* suffix = entry.relative_path + entry.relative_path_length - 4U;
        if (strcmp(suffix, ".dat") == 0) {
            found_dat = true;
        }
        if (strcmp(suffix, ".txt") == 0) {
            txt_count += 1;
        }
    }
    assert_false(found_dat);
    assert_true(txt_count >= 6000);

    bc_containers_vector_destroy(fixture->memory_context, entries);
}

static void test_walk_parallel_filter_exclude_glob(void** state)
{
    walk_parallel_state_t* fixture = (walk_parallel_state_t*)*state;
    for (size_t index = 0; index < 6000; ++index) {
        char name[64];
        snprintf(name, sizeof(name), "f_%zu.tmp", index);
        create_file_at(fixture->directory_path, name, "t");
    }
    for (size_t index = 0; index < 6000; ++index) {
        char name[64];
        snprintf(name, sizeof(name), "f_%zu.txt", index);
        create_file_at(fixture->directory_path, name, "x");
    }

    bc_containers_vector_t* entries = make_entries_vector(fixture);

    bc_integrity_manifest_options_t options;
    make_default_options(&options, fixture->directory_path);
    options.exclude_list = "*.tmp";

    size_t directory_path_length = strlen(fixture->directory_path);
    bool walk_ok = bc_integrity_walk_run(fixture->memory_context, fixture->concurrency_context, NULL, &options, fixture->directory_path,
                                         directory_path_length, entries, fixture->errors);
    assert_true(walk_ok);

    size_t count = bc_containers_vector_length(entries);
    bool found_tmp = false;
    for (size_t index = 0; index < count; ++index) {
        bc_integrity_entry_t entry;
        assert_true(bc_containers_vector_get(entries, index, &entry));
        if (entry.relative_path == NULL || entry.relative_path_length < 4) {
            continue;
        }
        const char* suffix = entry.relative_path + entry.relative_path_length - 4U;
        if (strcmp(suffix, ".tmp") == 0) {
            found_tmp = true;
        }
    }
    assert_false(found_tmp);

    bc_containers_vector_destroy(fixture->memory_context, entries);
}

static void test_walk_parallel_signal_stop_interrupts(void** state)
{
    walk_parallel_state_t* fixture = (walk_parallel_state_t*)*state;
    create_file_at(fixture->directory_path, "small.txt", "s");

    bc_runtime_signal_handler_t* signal_handler = NULL;
    assert_true(bc_runtime_signal_handler_create(fixture->memory_context, &signal_handler));
    assert_true(bc_runtime_signal_handler_install(signal_handler, SIGUSR1));
    raise(SIGUSR1);

    bc_containers_vector_t* entries = make_entries_vector(fixture);

    bc_integrity_manifest_options_t options;
    make_default_options(&options, fixture->directory_path);

    size_t directory_path_length = strlen(fixture->directory_path);
    bool walk_ok = bc_integrity_walk_run(fixture->memory_context, fixture->concurrency_context, signal_handler, &options,
                                         fixture->directory_path, directory_path_length, entries, fixture->errors);
    (void)walk_ok;

    bc_containers_vector_destroy(fixture->memory_context, entries);
    bc_runtime_signal_handler_destroy(signal_handler);
}

static void test_walk_parallel_serial_when_one_worker(void** state)
{
    walk_parallel_state_t* fixture = (walk_parallel_state_t*)*state;
    create_file_at(fixture->directory_path, "a.txt", "a");
    create_file_at(fixture->directory_path, "b.txt", "b");

    bc_concurrency_context_t* single_worker_ctx = NULL;
    bc_concurrency_config_t single_config;
    bc_core_zero(&single_config, sizeof(single_config));
    single_config.worker_count_explicit = true;
    single_config.worker_count = 0;
    assert_true(bc_concurrency_create(fixture->memory_context, &single_config, &single_worker_ctx));

    bc_containers_vector_t* entries = make_entries_vector(fixture);

    bc_integrity_manifest_options_t options;
    make_default_options(&options, fixture->directory_path);

    size_t directory_path_length = strlen(fixture->directory_path);
    bool walk_ok = bc_integrity_walk_run(fixture->memory_context, single_worker_ctx, NULL, &options, fixture->directory_path,
                                         directory_path_length, entries, fixture->errors);
    assert_true(walk_ok);
    assert_true(bc_containers_vector_length(entries) >= 2);

    bc_containers_vector_destroy(fixture->memory_context, entries);
    bc_concurrency_destroy(single_worker_ctx);
}

static void test_walk_parallel_unreadable_subdirectory(void** state)
{
    walk_parallel_state_t* fixture = (walk_parallel_state_t*)*state;
    for (size_t index = 0; index < 6000; ++index) {
        char name[64];
        snprintf(name, sizeof(name), "f_%zu.txt", index);
        create_file_at(fixture->directory_path, name, "x");
    }
    create_dir_at(fixture->directory_path, "denied");
    char denied_path[1024];
    snprintf(denied_path, sizeof(denied_path), "%s/denied", fixture->directory_path);
    assert_int_equal(chmod(denied_path, 0000), 0);

    bc_containers_vector_t* entries = make_entries_vector(fixture);

    bc_integrity_manifest_options_t options;
    make_default_options(&options, fixture->directory_path);

    size_t directory_path_length = strlen(fixture->directory_path);
    bool walk_ok = bc_integrity_walk_run(fixture->memory_context, fixture->concurrency_context, NULL, &options, fixture->directory_path,
                                         directory_path_length, entries, fixture->errors);
    (void)walk_ok;

    (void)chmod(denied_path, 0755);
    bc_containers_vector_destroy(fixture->memory_context, entries);
}

static void test_walk_parallel_default_exclude_virtual_non_virtual_root(void** state)
{
    walk_parallel_state_t* fixture = (walk_parallel_state_t*)*state;
    for (size_t index = 0; index < 8000; ++index) {
        char name[64];
        snprintf(name, sizeof(name), "f_%zu.txt", index);
        create_file_at(fixture->directory_path, name, "x");
    }
    bc_containers_vector_t* entries = make_entries_vector(fixture);

    bc_integrity_manifest_options_t options;
    make_default_options(&options, fixture->directory_path);
    options.default_exclude_virtual = true;

    size_t directory_path_length = strlen(fixture->directory_path);
    bool walk_ok = bc_integrity_walk_run(fixture->memory_context, fixture->concurrency_context, NULL, &options, fixture->directory_path,
                                         directory_path_length, entries, fixture->errors);
    assert_true(walk_ok);
    assert_true(bc_containers_vector_length(entries) >= 8000);

    bc_containers_vector_destroy(fixture->memory_context, entries);
}

static void test_walk_parallel_subdirs_recursive(void** state)
{
    walk_parallel_state_t* fixture = (walk_parallel_state_t*)*state;
    char level1_path[600];
    char level2_path[600];
    char deep_file_path[700];
    char mid_file_path[700];
    int n1 = snprintf(level1_path, sizeof(level1_path), "%s/level1", fixture->directory_path);
    assert_true(n1 > 0 && (size_t)n1 < sizeof(level1_path));
    assert_int_equal(mkdir(level1_path, 0755), 0);
    int n2 = snprintf(level2_path, sizeof(level2_path), "%s/level2", level1_path);
    assert_true(n2 > 0 && (size_t)n2 < sizeof(level2_path));
    assert_int_equal(mkdir(level2_path, 0755), 0);
    int n3 = snprintf(deep_file_path, sizeof(deep_file_path), "%s/deep.txt", level2_path);
    assert_true(n3 > 0 && (size_t)n3 < sizeof(deep_file_path));
    FILE* fp = fopen(deep_file_path, "wb");
    assert_non_null(fp);
    fputs("d", fp);
    fclose(fp);
    int n4 = snprintf(mid_file_path, sizeof(mid_file_path), "%s/mid.txt", level1_path);
    assert_true(n4 > 0 && (size_t)n4 < sizeof(mid_file_path));
    fp = fopen(mid_file_path, "wb");
    assert_non_null(fp);
    fputs("m", fp);
    fclose(fp);

    bc_containers_vector_t* entries = make_entries_vector(fixture);

    bc_integrity_manifest_options_t options;
    make_default_options(&options, fixture->directory_path);

    size_t directory_path_length = strlen(fixture->directory_path);
    bool walk_ok = bc_integrity_walk_run(fixture->memory_context, fixture->concurrency_context, NULL, &options, fixture->directory_path,
                                         directory_path_length, entries, fixture->errors);
    assert_true(walk_ok);

    size_t count = bc_containers_vector_length(entries);
    bool found_deep = false;
    bool found_mid = false;
    for (size_t index = 0; index < count; ++index) {
        bc_integrity_entry_t entry;
        assert_true(bc_containers_vector_get(entries, index, &entry));
        if (entry.relative_path == NULL) {
            continue;
        }
        if (strcmp(entry.relative_path, "level1/level2/deep.txt") == 0) {
            found_deep = true;
        }
        if (strcmp(entry.relative_path, "level1/mid.txt") == 0) {
            found_mid = true;
        }
    }
    assert_true(found_deep);
    assert_true(found_mid);

    bc_containers_vector_destroy(fixture->memory_context, entries);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_walk_parallel_small_tree, walk_parallel_setup, walk_parallel_teardown),
        cmocka_unit_test_setup_teardown(test_walk_parallel_medium_tree_forces_parallel, walk_parallel_setup, walk_parallel_teardown),
        cmocka_unit_test_setup_teardown(test_walk_parallel_skip_hidden, walk_parallel_setup, walk_parallel_teardown),
        cmocka_unit_test_setup_teardown(test_walk_parallel_skip_special, walk_parallel_setup, walk_parallel_teardown),
        cmocka_unit_test_setup_teardown(test_walk_parallel_include_special, walk_parallel_setup, walk_parallel_teardown),
        cmocka_unit_test_setup_teardown(test_walk_parallel_with_symlinks_no_follow, walk_parallel_setup, walk_parallel_teardown),
        cmocka_unit_test_setup_teardown(test_walk_parallel_empty_tree, walk_parallel_setup, walk_parallel_teardown),
        cmocka_unit_test_setup_teardown(test_walk_parallel_default_exclude_virtual_root_rejected, walk_parallel_setup,
                                        walk_parallel_teardown),
        cmocka_unit_test_setup_teardown(test_walk_parallel_filter_include_glob, walk_parallel_setup, walk_parallel_teardown),
        cmocka_unit_test_setup_teardown(test_walk_parallel_filter_exclude_glob, walk_parallel_setup, walk_parallel_teardown),
        cmocka_unit_test_setup_teardown(test_walk_parallel_signal_stop_interrupts, walk_parallel_setup, walk_parallel_teardown),
        cmocka_unit_test_setup_teardown(test_walk_parallel_serial_when_one_worker, walk_parallel_setup, walk_parallel_teardown),
        cmocka_unit_test_setup_teardown(test_walk_parallel_subdirs_recursive, walk_parallel_setup, walk_parallel_teardown),
        cmocka_unit_test_setup_teardown(test_walk_parallel_default_exclude_virtual_non_virtual_root, walk_parallel_setup,
                                        walk_parallel_teardown),
        cmocka_unit_test_setup_teardown(test_walk_parallel_unreadable_subdirectory, walk_parallel_setup, walk_parallel_teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
