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
  char manifest_path[300];
} fixture_state_t;

static int fixture_setup(void **state) {
  fixture_state_t *fixture = malloc(sizeof(*fixture));
  if (fixture == NULL) {
    return -1;
  }
  snprintf(fixture->fixture_directory, sizeof(fixture->fixture_directory),
           "/tmp/bc_integrity_verify_e2e_%d_XXXXXX", getpid());
  if (mkdtemp(fixture->fixture_directory) == NULL) {
    free(fixture);
    return -1;
  }
  snprintf(fixture->manifest_path, sizeof(fixture->manifest_path), "%s.hrbl",
           fixture->fixture_directory);
  *state = fixture;
  return 0;
}

static int fixture_teardown(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  char command[1024];
  snprintf(command, sizeof(command), "rm -rf '%s'", fixture->fixture_directory);
  int rc = system(command);
  (void)rc;
  unlink(fixture->manifest_path);
  free(fixture);
  return 0;
}

static void write_file(const char *path, const char *content) {
  FILE *file = fopen(path, "wb");
  assert_non_null(file);
  fputs(content, file);
  fclose(file);
}

static int run_bc_integrity_manifest(const char *root, const char *output) {
  pid_t pid = fork();
  if (pid < 0) {
    return -1;
  }
  if (pid == 0) {
    char output_argument[512];
    snprintf(output_argument, sizeof(output_argument), "--output=%s", output);
    char *argv[] = {
        (char *)BC_INTEGRITY_TEST_BINARY_PATH, "manifest",   output_argument,
        "--default-exclude-virtual=false",     (char *)root, NULL,
    };
    execv(argv[0], argv);
    _exit(127);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int run_bc_integrity_verify(const char *root, const char *manifest_path,
                                   const char *mode_argument) {
  pid_t pid = fork();
  if (pid < 0) {
    return -1;
  }
  if (pid == 0) {
    char *argv[] = {
        (char *)BC_INTEGRITY_TEST_BINARY_PATH,
        "verify",
        (char *)mode_argument,
        "--default-exclude-virtual=false",
        (char *)root,
        (char *)manifest_path,
        NULL,
    };
    execv(argv[0], argv);
    _exit(127);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int run_bc_integrity_verify_capture(
    const char *root, const char *manifest_path, const char *mode_argument,
    const char *format_argument, char *capture_output, size_t output_size) {
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
    char *argv[] = {
        (char *)BC_INTEGRITY_TEST_BINARY_PATH,
        "verify",
        (char *)mode_argument,
        (char *)format_argument,
        "--default-exclude-virtual=false",
        (char *)root,
        (char *)manifest_path,
        NULL,
    };
    execv(argv[0], argv);
    _exit(127);
  }
  close(pipefd[1]);
  size_t total = 0;
  if (capture_output != NULL && output_size > 0) {
    while (total + 1 < output_size) {
      ssize_t bytes_read =
          read(pipefd[0], capture_output + total, output_size - 1 - total);
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

static void build_test_tree(const char *root) {
  char path[512];
  snprintf(path, sizeof(path), "%s/file1.txt", root);
  write_file(path, "hello");
  snprintf(path, sizeof(path), "%s/sub", root);
  assert_int_equal(mkdir(path, 0755), 0);
  snprintf(path, sizeof(path), "%s/sub/file2.txt", root);
  write_file(path, "world");
}

static void test_verify_identical_returns_zero(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  build_test_tree(fixture->fixture_directory);
  assert_int_equal(run_bc_integrity_manifest(fixture->fixture_directory,
                                             fixture->manifest_path),
                   0);
  assert_int_equal(run_bc_integrity_verify(fixture->fixture_directory,
                                           fixture->manifest_path,
                                           "--mode=strict"),
                   0);
}

static void test_verify_strict_detects_content_change(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  build_test_tree(fixture->fixture_directory);
  assert_int_equal(run_bc_integrity_manifest(fixture->fixture_directory,
                                             fixture->manifest_path),
                   0);
  char path[512];
  snprintf(path, sizeof(path), "%s/file1.txt", fixture->fixture_directory);
  write_file(path, "modified");
  assert_int_equal(run_bc_integrity_verify(fixture->fixture_directory,
                                           fixture->manifest_path,
                                           "--mode=strict"),
                   1);
}

static void test_verify_content_only_ignores_meta_change(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  build_test_tree(fixture->fixture_directory);
  assert_int_equal(run_bc_integrity_manifest(fixture->fixture_directory,
                                             fixture->manifest_path),
                   0);
  char path[512];
  snprintf(path, sizeof(path), "%s/sub/file2.txt", fixture->fixture_directory);
  assert_int_equal(chmod(path, 0700), 0);
  assert_int_equal(run_bc_integrity_verify(fixture->fixture_directory,
                                           fixture->manifest_path,
                                           "--mode=content"),
                   0);
}

static void test_verify_meta_only_detects_mode_change(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  build_test_tree(fixture->fixture_directory);
  assert_int_equal(run_bc_integrity_manifest(fixture->fixture_directory,
                                             fixture->manifest_path),
                   0);
  char path[512];
  snprintf(path, sizeof(path), "%s/sub/file2.txt", fixture->fixture_directory);
  assert_int_equal(chmod(path, 0700), 0);
  assert_int_equal(run_bc_integrity_verify(fixture->fixture_directory,
                                           fixture->manifest_path,
                                           "--mode=meta"),
                   1);
}

static void test_verify_added_file_reported(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  build_test_tree(fixture->fixture_directory);
  assert_int_equal(run_bc_integrity_manifest(fixture->fixture_directory,
                                             fixture->manifest_path),
                   0);
  char path[512];
  snprintf(path, sizeof(path), "%s/file3.txt", fixture->fixture_directory);
  write_file(path, "new");
  assert_int_equal(run_bc_integrity_verify(fixture->fixture_directory,
                                           fixture->manifest_path,
                                           "--mode=strict"),
                   1);
}

static void test_verify_removed_file_reported(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  build_test_tree(fixture->fixture_directory);
  assert_int_equal(run_bc_integrity_manifest(fixture->fixture_directory,
                                             fixture->manifest_path),
                   0);
  char path[512];
  snprintf(path, sizeof(path), "%s/sub/file2.txt", fixture->fixture_directory);
  assert_int_equal(unlink(path), 0);
  assert_int_equal(run_bc_integrity_verify(fixture->fixture_directory,
                                           fixture->manifest_path,
                                           "--mode=strict"),
                   1);
}

static void test_verify_json_emits_header_and_summary(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  build_test_tree(fixture->fixture_directory);
  assert_int_equal(run_bc_integrity_manifest(fixture->fixture_directory,
                                             fixture->manifest_path),
                   0);
  char output[16384];
  int exit_code = run_bc_integrity_verify_capture(
      fixture->fixture_directory, fixture->manifest_path, "--mode=strict",
      "--format=json", output, sizeof(output));
  assert_int_equal(exit_code, 0);
  assert_non_null(strstr(output, "\"type\":\"header\""));
  assert_non_null(strstr(output, "\"tool\":\"bc-integrity\""));
  assert_non_null(strstr(output, "\"command\":\"verify\""));
  assert_non_null(strstr(output, "\"mode\":\"strict\""));
  assert_non_null(strstr(output, "\"manifest_path\":"));
  assert_non_null(strstr(output, "\"root_path\":"));
  assert_non_null(strstr(output, "\"started_at\":"));
  assert_non_null(strstr(output, "\"type\":\"summary\""));
  assert_non_null(strstr(output, "\"changes_total\":0"));
  assert_non_null(strstr(output, "\"errors_count\":0"));
  assert_non_null(strstr(output, "\"wall_ms\":"));
}

static void test_verify_json_meta_change_includes_meta_changes(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  build_test_tree(fixture->fixture_directory);
  assert_int_equal(run_bc_integrity_manifest(fixture->fixture_directory,
                                             fixture->manifest_path),
                   0);
  char path[512];
  snprintf(path, sizeof(path), "%s/sub/file2.txt", fixture->fixture_directory);
  assert_int_equal(chmod(path, 0700), 0);
  char output[16384];
  int exit_code = run_bc_integrity_verify_capture(
      fixture->fixture_directory, fixture->manifest_path, "--mode=meta",
      "--format=json", output, sizeof(output));
  assert_int_equal(exit_code, 1);
  assert_non_null(strstr(output, "\"type\":\"change\""));
  assert_non_null(strstr(output, "\"change\":\"meta\""));
  assert_non_null(strstr(output, "\"meta_changes\":{"));
  assert_non_null(strstr(output, "\"mode\":{\"old\":"));
  assert_non_null(strstr(output, "\"new\":"));
  assert_non_null(strstr(output, "\"meta\":1"));
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test_setup_teardown(test_verify_identical_returns_zero,
                                      fixture_setup, fixture_teardown),
      cmocka_unit_test_setup_teardown(test_verify_strict_detects_content_change,
                                      fixture_setup, fixture_teardown),
      cmocka_unit_test_setup_teardown(
          test_verify_content_only_ignores_meta_change, fixture_setup,
          fixture_teardown),
      cmocka_unit_test_setup_teardown(test_verify_meta_only_detects_mode_change,
                                      fixture_setup, fixture_teardown),
      cmocka_unit_test_setup_teardown(test_verify_added_file_reported,
                                      fixture_setup, fixture_teardown),
      cmocka_unit_test_setup_teardown(test_verify_removed_file_reported,
                                      fixture_setup, fixture_teardown),
      cmocka_unit_test_setup_teardown(test_verify_json_emits_header_and_summary,
                                      fixture_setup, fixture_teardown),
      cmocka_unit_test_setup_teardown(
          test_verify_json_meta_change_includes_meta_changes, fixture_setup,
          fixture_teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
