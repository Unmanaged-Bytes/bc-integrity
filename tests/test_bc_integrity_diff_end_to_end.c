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

#ifndef BC_INTEGRITY_TEST_BINARY_PATH
#define BC_INTEGRITY_TEST_BINARY_PATH "/usr/local/bin/bc-integrity"
#endif

typedef struct fixture_state {
    char fixture_directory[256];
    char manifest_path_a[300];
    char manifest_path_b[300];
} fixture_state_t;

static int fixture_setup(void** state)
{
    fixture_state_t* fixture = malloc(sizeof(*fixture));
    if (fixture == NULL) {
        return -1;
    }
    snprintf(fixture->fixture_directory, sizeof(fixture->fixture_directory), "/tmp/bc_integrity_diff_e2e_%d_XXXXXX", getpid());
    if (mkdtemp(fixture->fixture_directory) == NULL) {
        free(fixture);
        return -1;
    }
    snprintf(fixture->manifest_path_a, sizeof(fixture->manifest_path_a), "%s_a.hrbl", fixture->fixture_directory);
    snprintf(fixture->manifest_path_b, sizeof(fixture->manifest_path_b), "%s_b.hrbl", fixture->fixture_directory);
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
    unlink(fixture->manifest_path_a);
    unlink(fixture->manifest_path_b);
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

static int run_bc_integrity_manifest(const char* root, const char* output)
{
    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        char output_argument[512];
        snprintf(output_argument, sizeof(output_argument), "--output=%s", output);
        char* argv[] = {
            (char*)BC_INTEGRITY_TEST_BINARY_PATH, "manifest", output_argument, "--default-exclude-virtual=false", (char*)root, NULL,
        };
        execv(argv[0], argv);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int run_bc_integrity_diff(const char* manifest_a, const char* manifest_b, const char* extra_argument, char* capture_output,
                                 size_t output_size)
{
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        if (extra_argument != NULL) {
            char* argv[] = {
                (char*)BC_INTEGRITY_TEST_BINARY_PATH, "diff", (char*)extra_argument, (char*)manifest_a, (char*)manifest_b, NULL,
            };
            execv(argv[0], argv);
            _exit(127);
        } else {
            char* argv[] = {
                (char*)BC_INTEGRITY_TEST_BINARY_PATH, "diff", (char*)manifest_a, (char*)manifest_b, NULL,
            };
            execv(argv[0], argv);
            _exit(127);
        }
    }
    close(pipefd[1]);
    size_t total = 0;
    if (capture_output != NULL && output_size > 0) {
        while (total + 1 < output_size) {
            ssize_t bytes_read = read(pipefd[0], capture_output + total, output_size - 1 - total);
            if (bytes_read <= 0) {
                break;
            }
            total += (size_t)bytes_read;
        }
        capture_output[total] = '\0';
    } else {
        char drain[4096];
        while (read(pipefd[0], drain, sizeof(drain)) > 0) {
        }
    }
    close(pipefd[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static void test_diff_identical_manifests_returns_zero(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    char path[512];
    snprintf(path, sizeof(path), "%s/file1.txt", fixture->fixture_directory);
    write_file(path, "hello");

    assert_int_equal(run_bc_integrity_manifest(fixture->fixture_directory, fixture->manifest_path_a), 0);
    assert_int_equal(run_bc_integrity_manifest(fixture->fixture_directory, fixture->manifest_path_b), 0);

    assert_int_equal(run_bc_integrity_diff(fixture->manifest_path_a, fixture->manifest_path_b, NULL, NULL, 0), 0);
}

static void test_diff_added_removed_changed_reported(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    char path[512];
    snprintf(path, sizeof(path), "%s/keep.txt", fixture->fixture_directory);
    write_file(path, "stable");
    snprintf(path, sizeof(path), "%s/will_remove.txt", fixture->fixture_directory);
    write_file(path, "doomed");

    assert_int_equal(run_bc_integrity_manifest(fixture->fixture_directory, fixture->manifest_path_a), 0);

    snprintf(path, sizeof(path), "%s/will_remove.txt", fixture->fixture_directory);
    assert_int_equal(unlink(path), 0);
    snprintf(path, sizeof(path), "%s/keep.txt", fixture->fixture_directory);
    write_file(path, "modified");
    snprintf(path, sizeof(path), "%s/added.txt", fixture->fixture_directory);
    write_file(path, "fresh");

    assert_int_equal(run_bc_integrity_manifest(fixture->fixture_directory, fixture->manifest_path_b), 0);

    char output[8192];
    int exit_code = run_bc_integrity_diff(fixture->manifest_path_a, fixture->manifest_path_b, NULL, output, sizeof(output));
    assert_int_equal(exit_code, 1);
    assert_non_null(strstr(output, "+ added.txt"));
    assert_non_null(strstr(output, "- will_remove.txt"));
    assert_non_null(strstr(output, "keep.txt"));
}

static void test_diff_ignore_meta_skips_meta_changes(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    char path[512];
    snprintf(path, sizeof(path), "%s/file.txt", fixture->fixture_directory);
    write_file(path, "hello");
    assert_int_equal(run_bc_integrity_manifest(fixture->fixture_directory, fixture->manifest_path_a), 0);
    assert_int_equal(chmod(path, 0700), 0);
    assert_int_equal(run_bc_integrity_manifest(fixture->fixture_directory, fixture->manifest_path_b), 0);
    assert_int_equal(run_bc_integrity_diff(fixture->manifest_path_a, fixture->manifest_path_b, "--ignore-meta", NULL, 0), 0);
    assert_int_equal(run_bc_integrity_diff(fixture->manifest_path_a, fixture->manifest_path_b, NULL, NULL, 0), 1);
}

static void test_diff_json_emits_header_summary_and_meta_changes(void** state)
{
    fixture_state_t* fixture = (fixture_state_t*)*state;
    char path[512];
    snprintf(path, sizeof(path), "%s/file.txt", fixture->fixture_directory);
    write_file(path, "stable");
    assert_int_equal(run_bc_integrity_manifest(fixture->fixture_directory, fixture->manifest_path_a), 0);
    assert_int_equal(chmod(path, 0700), 0);
    assert_int_equal(run_bc_integrity_manifest(fixture->fixture_directory, fixture->manifest_path_b), 0);

    char output[16384];
    int exit_code = run_bc_integrity_diff(fixture->manifest_path_a, fixture->manifest_path_b, "--format=json", output, sizeof(output));
    assert_int_equal(exit_code, 1);
    assert_non_null(strstr(output, "\"type\":\"header\""));
    assert_non_null(strstr(output, "\"tool\":\"bc-integrity\""));
    assert_non_null(strstr(output, "\"command\":\"diff\""));
    assert_non_null(strstr(output, "\"manifest_path_a\":"));
    assert_non_null(strstr(output, "\"manifest_path_b\":"));
    assert_non_null(strstr(output, "\"started_at\":"));
    assert_non_null(strstr(output, "\"type\":\"change\""));
    assert_non_null(strstr(output, "\"meta_changes\":{"));
    assert_non_null(strstr(output, "\"mode\":{\"old\":"));
    assert_non_null(strstr(output, "\"type\":\"summary\""));
    assert_non_null(strstr(output, "\"changes_total\":1"));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_diff_identical_manifests_returns_zero, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_diff_added_removed_changed_reported, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_diff_ignore_meta_skips_meta_changes, fixture_setup, fixture_teardown),
        cmocka_unit_test_setup_teardown(test_diff_json_emits_header_summary_and_meta_changes, fixture_setup, fixture_teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
