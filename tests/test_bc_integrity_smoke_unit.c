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
#include <sys/wait.h>
#include <unistd.h>

#ifndef BC_INTEGRITY_TEST_BINARY_PATH
#define BC_INTEGRITY_TEST_BINARY_PATH "/usr/local/bin/bc-integrity"
#endif

#ifndef BC_HRBL_TEST_BINARY_PATH
#define BC_HRBL_TEST_BINARY_PATH "/usr/local/bin/bc-hrbl"
#endif

#ifndef BC_INTEGRITY_SMOKE_SCRIPT_PATH
#define BC_INTEGRITY_SMOKE_SCRIPT_PATH "tests/smoke/smoke_golden_path.sh"
#endif

static bool path_is_executable(const char* path)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        return false;
    }
    if (!S_ISREG(st.st_mode)) {
        return false;
    }
    return (st.st_mode & S_IXUSR) != 0;
}

static int run_smoke_script(char* captured_output, size_t output_size, size_t* bytes_written)
{
    int pipefd[2];
    if (pipe(pipefd) != 0) {
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
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        setenv("BCINT", BC_INTEGRITY_TEST_BINARY_PATH, 1);
        setenv("BCHRBL", BC_HRBL_TEST_BINARY_PATH, 1);

        char* argv[] = {
            (char*)"/bin/bash",
            (char*)BC_INTEGRITY_SMOKE_SCRIPT_PATH,
            NULL,
        };
        execv(argv[0], argv);
        _exit(127);
    }
    close(pipefd[1]);
    size_t total = 0;
    if (captured_output != NULL && output_size > 0) {
        while (total + 1 < output_size) {
            ssize_t bytes_read = read(pipefd[0], captured_output + total, output_size - 1 - total);
            if (bytes_read <= 0) {
                break;
            }
            total += (size_t)bytes_read;
        }
        captured_output[total] = '\0';
    } else {
        char drain[4096];
        while (read(pipefd[0], drain, sizeof(drain)) > 0) {
        }
    }
    close(pipefd[0]);
    if (bytes_written != NULL) {
        *bytes_written = total;
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status)) {
        return -1;
    }
    return WEXITSTATUS(status);
}

static void test_smoke_golden_path(void** state)
{
    (void)state;

    if (!path_is_executable(BC_HRBL_TEST_BINARY_PATH)) {
        skip();
    }
    if (!path_is_executable(BC_INTEGRITY_TEST_BINARY_PATH)) {
        skip();
    }

    assert_true(path_is_executable(BC_INTEGRITY_SMOKE_SCRIPT_PATH));

    char output[16384];
    size_t output_length = 0;
    int exit_code = run_smoke_script(output, sizeof(output), &output_length);
    if (exit_code != 0) {
        fprintf(stderr, "smoke_golden_path script failed with exit=%d\n", exit_code);
        fprintf(stderr, "--- captured output (%zu bytes) ---\n", output_length);
        fprintf(stderr, "%s\n", output);
        fprintf(stderr, "--- end captured output ---\n");
    }
    assert_int_equal(exit_code, 0);
    assert_non_null(strstr(output, "smoke_golden_path: PASS"));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_smoke_golden_path),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
