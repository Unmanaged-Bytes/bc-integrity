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
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "bc_allocators.h"
#include "bc_hrbl.h"

#ifndef BC_INTEGRITY_TEST_BINARY_PATH
#error "BC_INTEGRITY_TEST_BINARY_PATH must be defined"
#endif

typedef struct fixture_state {
    char fixture_directory[256];
    char manifest_path[300];
} fixture_state_t;

static int fixture_setup(void** state)
{
    fixture_state_t* fixture = malloc(sizeof(*fixture));
    if (fixture == NULL) {
        return -1;
    }
    snprintf(fixture->fixture_directory, sizeof(fixture->fixture_directory), "/tmp/bc_integrity_e2e_%d_XXXXXX", getpid());
    if (mkdtemp(fixture->fixture_directory) == NULL) {
        free(fixture);
        return -1;
    }
    snprintf(fixture->manifest_path, sizeof(fixture->manifest_path), "%s.hrbl", fixture->fixture_directory);
    *state = fixture;
    return 0;
}

static int fixture_teardown(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    char command[1024];
    snprintf(command, sizeof(command), "rm -rf '%s'", fixture->fixture_directory);
    int rc = system(command);
    (void)rc;
    unlink(fixture->manifest_path);
    free(fixture);
    return 0;
}

static void write_file(const char* path, const char* content)
{
    FILE* file = fopen(path, "wb");
    assert_non_null(file);
    fputs(content, file);
    fclose(file);
}

static int run_bc_integrity(const char* root, const char* output, bool default_exclude_virtual)
{
    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        char output_argument[512];
        snprintf(output_argument, sizeof(output_argument), "--output=%s", output);
        char default_exclude_argument[64];
        snprintf(default_exclude_argument, sizeof(default_exclude_argument), "--default-exclude-virtual=%s",
                 default_exclude_virtual ? "true" : "false");
        char* argv[] = {
            (char*)BC_INTEGRITY_TEST_BINARY_PATH, "manifest", output_argument, default_exclude_argument, (char*)root, NULL,
        };
        execv(argv[0], argv);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static void build_test_tree(const char* root)
{
    char path[512];

    snprintf(path, sizeof(path), "%s/file.txt", root);
    write_file(path, "hello");

    snprintf(path, sizeof(path), "%s/sub", root);
    assert_int_equal(mkdir(path, 0755), 0);

    snprintf(path, sizeof(path), "%s/sub/regular.txt", root);
    write_file(path, "regular");

    snprintf(path, sizeof(path), "%s/.hidden", root);
    assert_int_equal(mkdir(path, 0755), 0);

    snprintf(path, sizeof(path), "%s/.hidden/file.txt", root);
    write_file(path, "should-skip");

    snprintf(path, sizeof(path), "%s/link.txt", root);
    assert_int_equal(symlink("file.txt", path), 0);
}

static void test_e2e_manifest_includes_files_dirs_symlinks(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    build_test_tree(fixture->fixture_directory);

    int exit_code = run_bc_integrity(fixture->fixture_directory, fixture->manifest_path, false);
    assert_int_equal(exit_code, 0);

    bc_allocators_context_config_t allocator_config = {.tracking_enabled = true};
    bc_allocators_context_t* memory_context = NULL;
    assert_true(bc_allocators_context_create(&allocator_config, &memory_context));

    bc_hrbl_reader_t* reader = NULL;
    assert_true(bc_hrbl_reader_open(memory_context, fixture->manifest_path, &reader));

    bc_hrbl_value_ref_t value_ref;

    assert_true(bc_hrbl_reader_find(reader, "entries.'file.txt'.kind", strlen("entries.'file.txt'.kind"), &value_ref));
    const char* kind = NULL;
    size_t kind_length = 0;
    assert_true(bc_hrbl_reader_get_string(&value_ref, &kind, &kind_length));
    assert_memory_equal(kind, "file", 4);

    assert_true(bc_hrbl_reader_find(reader, "entries.'link.txt'.kind", strlen("entries.'link.txt'.kind"), &value_ref));
    assert_true(bc_hrbl_reader_get_string(&value_ref, &kind, &kind_length));
    assert_memory_equal(kind, "symlink", 7);

    assert_true(bc_hrbl_reader_find(reader, "entries.'link.txt'.link_target", strlen("entries.'link.txt'.link_target"), &value_ref));
    const char* target = NULL;
    size_t target_length = 0;
    assert_true(bc_hrbl_reader_get_string(&value_ref, &target, &target_length));
    assert_int_equal(target_length, 8u);
    assert_memory_equal(target, "file.txt", 8u);

    assert_true(bc_hrbl_reader_find(reader, "entries.sub.kind", strlen("entries.sub.kind"), &value_ref));
    assert_true(bc_hrbl_reader_get_string(&value_ref, &kind, &kind_length));
    assert_memory_equal(kind, "dir", 3);

    assert_true(bc_hrbl_reader_find(reader, "entries.'sub/regular.txt'.kind", strlen("entries.'sub/regular.txt'.kind"), &value_ref));
    assert_true(bc_hrbl_reader_get_string(&value_ref, &kind, &kind_length));
    assert_memory_equal(kind, "file", 4);

    assert_false(bc_hrbl_reader_find(reader, "entries.'.hidden'.kind", strlen("entries.'.hidden'.kind"), &value_ref));
    assert_false(bc_hrbl_reader_find(reader, "entries.'.hidden/file.txt'.kind", strlen("entries.'.hidden/file.txt'.kind"), &value_ref));

    assert_true(bc_hrbl_reader_find(reader, "meta.file_count", strlen("meta.file_count"), &value_ref));
    uint64_t file_count = 0;
    assert_true(bc_hrbl_reader_get_uint64(&value_ref, &file_count));
    assert_int_equal(file_count, 2u);

    assert_true(bc_hrbl_reader_find(reader, "meta.symlink_count", strlen("meta.symlink_count"), &value_ref));
    uint64_t symlink_count = 0;
    assert_true(bc_hrbl_reader_get_uint64(&value_ref, &symlink_count));
    assert_int_equal(symlink_count, 1u);

    assert_true(bc_hrbl_reader_find(reader, "meta.dir_count", strlen("meta.dir_count"), &value_ref));
    uint64_t dir_count = 0;
    assert_true(bc_hrbl_reader_get_uint64(&value_ref, &dir_count));
    assert_int_equal(dir_count, 1u);

    assert_true(bc_hrbl_reader_find(reader, "summary.errors_count", strlen("summary.errors_count"), &value_ref));
    uint64_t errors_count = 0;
    assert_true(bc_hrbl_reader_get_uint64(&value_ref, &errors_count));
    assert_int_equal(errors_count, 0u);

    bc_hrbl_reader_close(reader);
    bc_allocators_context_destroy(memory_context);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_e2e_manifest_includes_files_dirs_symlinks, fixture_setup, fixture_teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
