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
           "/tmp/bc_integrity_verify_ext_%d_XXXXXX", getpid());
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

static int run_manifest(const char *root, const char *output,
                        const char *algorithm) {
  pid_t pid = fork();
  if (pid < 0) {
    return -1;
  }
  if (pid == 0) {
    char output_argument[512];
    snprintf(output_argument, sizeof(output_argument), "--output=%s", output);
    char algorithm_argument[64] = "--digest-algorithm=sha256";
    if (algorithm != NULL) {
      snprintf(algorithm_argument, sizeof(algorithm_argument),
               "--digest-algorithm=%s", algorithm);
    }
    char *argv[] = {
        (char *)BC_INTEGRITY_TEST_BINARY_PATH,
        "manifest",
        output_argument,
        algorithm_argument,
        "--default-exclude-virtual=false",
        (char *)root,
        NULL,
    };
    execv(argv[0], argv);
    _exit(127);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int run_verify(const char *root, const char *manifest_path,
                      const char *const *extra_args, size_t extra_args_count,
                      char *capture_output, size_t output_size) {
  int pipefd[2];
  int errfd[2];
  if (pipe(pipefd) < 0) {
    return -1;
  }
  if (pipe(errfd) < 0) {
    close(pipefd[0]);
    close(pipefd[1]);
    return -1;
  }
  pid_t pid = fork();
  if (pid < 0) {
    close(pipefd[0]);
    close(pipefd[1]);
    close(errfd[0]);
    close(errfd[1]);
    return -1;
  }
  if (pid == 0) {
    close(pipefd[0]);
    close(errfd[0]);
    dup2(pipefd[1], STDOUT_FILENO);
    dup2(errfd[1], STDERR_FILENO);
    close(pipefd[1]);
    close(errfd[1]);
    char *argv[16];
    size_t cursor = 0;
    argv[cursor++] = (char *)BC_INTEGRITY_TEST_BINARY_PATH;
    argv[cursor++] = (char *)"verify";
    for (size_t index = 0; index < extra_args_count; ++index) {
      argv[cursor++] = (char *)extra_args[index];
    }
    argv[cursor++] = (char *)"--default-exclude-virtual=false";
    argv[cursor++] = (char *)root;
    argv[cursor++] = (char *)manifest_path;
    argv[cursor] = NULL;
    execv(argv[0], argv);
    _exit(127);
  }
  close(pipefd[1]);
  close(errfd[1]);
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
  char drain_err[4096];
  while (read(errfd[0], drain_err, sizeof(drain_err)) > 0) {
  }
  close(pipefd[0]);
  close(errfd[0]);
  int status = 0;
  waitpid(pid, &status, 0);
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static void build_basic_tree(const char *root) {
  char path[512];
  snprintf(path, sizeof(path), "%s/alpha.txt", root);
  write_file(path, "aaa");
  snprintf(path, sizeof(path), "%s/beta.txt", root);
  write_file(path, "bbb");
  snprintf(path, sizeof(path), "%s/sub", root);
  assert_int_equal(mkdir(path, 0755), 0);
  snprintf(path, sizeof(path), "%s/sub/gamma.txt", root);
  write_file(path, "ccc");
}

static void test_verify_corrupted_manifest_returns_two(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  build_basic_tree(fixture->fixture_directory);
  write_file(fixture->manifest_path, "not a real hrbl manifest at all");
  const char *args[] = {"--mode=strict"};
  assert_int_equal(run_verify(fixture->fixture_directory,
                              fixture->manifest_path, args, 1, NULL, 0),
                   2);
}

static void test_verify_missing_manifest_returns_two(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  build_basic_tree(fixture->fixture_directory);
  char missing_manifest[400];
  snprintf(missing_manifest, sizeof(missing_manifest), "%s/no_such.hrbl",
           fixture->fixture_directory);
  const char *args[] = {"--mode=strict"};
  assert_int_equal(run_verify(fixture->fixture_directory, missing_manifest,
                              args, 1, NULL, 0),
                   2);
}

static void test_verify_root_inexistent_returns_two(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  build_basic_tree(fixture->fixture_directory);
  assert_int_equal(run_manifest(fixture->fixture_directory,
                                fixture->manifest_path, NULL),
                   0);
  char missing_root[400];
  snprintf(missing_root, sizeof(missing_root), "%s/inexistant_subdir",
           fixture->fixture_directory);
  const char *args[] = {"--mode=strict"};
  assert_int_equal(
      run_verify(missing_root, fixture->manifest_path, args, 1, NULL, 0), 2);
}

static void test_verify_root_is_file_returns_two(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  build_basic_tree(fixture->fixture_directory);
  assert_int_equal(run_manifest(fixture->fixture_directory,
                                fixture->manifest_path, NULL),
                   0);
  char file_root[400];
  snprintf(file_root, sizeof(file_root), "%s/alpha.txt",
           fixture->fixture_directory);
  const char *args[] = {"--mode=strict"};
  assert_int_equal(
      run_verify(file_root, fixture->manifest_path, args, 1, NULL, 0), 2);
}

static void test_verify_exit_on_first_change_short_circuits(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  build_basic_tree(fixture->fixture_directory);
  assert_int_equal(run_manifest(fixture->fixture_directory,
                                fixture->manifest_path, NULL),
                   0);
  char path[512];
  snprintf(path, sizeof(path), "%s/alpha.txt", fixture->fixture_directory);
  write_file(path, "modified-alpha");
  snprintf(path, sizeof(path), "%s/beta.txt", fixture->fixture_directory);
  write_file(path, "modified-beta");
  const char *args[] = {"--mode=strict", "--exit-on-first"};
  assert_int_equal(run_verify(fixture->fixture_directory,
                              fixture->manifest_path, args, 2, NULL, 0),
                   1);
}

static void test_verify_exit_on_first_with_removed_short_circuits(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  build_basic_tree(fixture->fixture_directory);
  char path1[512];
  char path2[512];
  snprintf(path1, sizeof(path1), "%s/zzz_removed_one.txt",
           fixture->fixture_directory);
  write_file(path1, "first");
  snprintf(path2, sizeof(path2), "%s/zzz_removed_two.txt",
           fixture->fixture_directory);
  write_file(path2, "second");
  assert_int_equal(run_manifest(fixture->fixture_directory,
                                fixture->manifest_path, NULL),
                   0);
  unlink(path1);
  unlink(path2);
  const char *args[] = {"--mode=strict", "--exit-on-first"};
  assert_int_equal(run_verify(fixture->fixture_directory,
                              fixture->manifest_path, args, 2, NULL, 0),
                   1);
}

static void test_verify_json_added_emits_change_record(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  build_basic_tree(fixture->fixture_directory);
  assert_int_equal(run_manifest(fixture->fixture_directory,
                                fixture->manifest_path, NULL),
                   0);
  char path[512];
  snprintf(path, sizeof(path), "%s/zeta.txt", fixture->fixture_directory);
  write_file(path, "newly-added");
  const char *args[] = {"--mode=strict", "--format=json"};
  char output[32768];
  int exit_code = run_verify(fixture->fixture_directory, fixture->manifest_path,
                             args, 2, output, sizeof(output));
  assert_int_equal(exit_code, 1);
  assert_non_null(strstr(output, "\"change\":\"added\""));
  assert_non_null(strstr(output, "zeta.txt"));
  assert_non_null(strstr(output, "\"added\":1"));
}

static void test_verify_json_removed_emits_change_record(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  build_basic_tree(fixture->fixture_directory);
  char path_zeta[512];
  snprintf(path_zeta, sizeof(path_zeta), "%s/zeta.txt",
           fixture->fixture_directory);
  write_file(path_zeta, "to-remove");
  assert_int_equal(run_manifest(fixture->fixture_directory,
                                fixture->manifest_path, NULL),
                   0);
  unlink(path_zeta);
  const char *args[] = {"--mode=strict", "--format=json"};
  char output[32768];
  int exit_code = run_verify(fixture->fixture_directory, fixture->manifest_path,
                             args, 2, output, sizeof(output));
  assert_int_equal(exit_code, 1);
  assert_non_null(strstr(output, "\"change\":\"removed\""));
  assert_non_null(strstr(output, "\"removed\":1"));
}

static void test_verify_strict_mtime_change_detected(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  build_basic_tree(fixture->fixture_directory);
  assert_int_equal(run_manifest(fixture->fixture_directory,
                                fixture->manifest_path, NULL),
                   0);
  char path[512];
  snprintf(path, sizeof(path), "%s/alpha.txt", fixture->fixture_directory);
  struct timespec times[2];
  times[0].tv_sec = 1234567890;
  times[0].tv_nsec = 0;
  times[1].tv_sec = 1234567890;
  times[1].tv_nsec = 0;
  utimensat(AT_FDCWD, path, times, 0);
  const char *args[] = {"--mode=strict"};
  assert_int_equal(run_verify(fixture->fixture_directory,
                              fixture->manifest_path, args, 1, NULL, 0),
                   1);
}

static void test_verify_empty_directory_zero_changes(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  assert_int_equal(run_manifest(fixture->fixture_directory,
                                fixture->manifest_path, NULL),
                   0);
  const char *args[] = {"--mode=strict"};
  assert_int_equal(run_verify(fixture->fixture_directory,
                              fixture->manifest_path, args, 1, NULL, 0),
                   0);
}

static void test_verify_json_summary_files_total_present(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  build_basic_tree(fixture->fixture_directory);
  assert_int_equal(run_manifest(fixture->fixture_directory,
                                fixture->manifest_path, NULL),
                   0);
  const char *args[] = {"--mode=strict", "--format=json"};
  char output[16384];
  int exit_code = run_verify(fixture->fixture_directory, fixture->manifest_path,
                             args, 2, output, sizeof(output));
  assert_int_equal(exit_code, 0);
  assert_non_null(strstr(output, "\"files_total\":"));
  assert_non_null(strstr(output, "\"changes_total\":0"));
}

static void test_verify_with_symlink_kind(void **state) {
  fixture_state_t *fixture = (fixture_state_t *)*state;
  char target_path[512];
  snprintf(target_path, sizeof(target_path), "%s/target.txt",
           fixture->fixture_directory);
  write_file(target_path, "target-content");
  char link_path[512];
  snprintf(link_path, sizeof(link_path), "%s/link",
           fixture->fixture_directory);
  symlink("target.txt", link_path);
  assert_int_equal(run_manifest(fixture->fixture_directory,
                                fixture->manifest_path, NULL),
                   0);
  const char *args[] = {"--mode=strict"};
  assert_int_equal(run_verify(fixture->fixture_directory,
                              fixture->manifest_path, args, 1, NULL, 0),
                   0);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test_setup_teardown(test_verify_corrupted_manifest_returns_two,
                                      fixture_setup, fixture_teardown),
      cmocka_unit_test_setup_teardown(test_verify_missing_manifest_returns_two,
                                      fixture_setup, fixture_teardown),
      cmocka_unit_test_setup_teardown(test_verify_root_inexistent_returns_two,
                                      fixture_setup, fixture_teardown),
      cmocka_unit_test_setup_teardown(test_verify_root_is_file_returns_two,
                                      fixture_setup, fixture_teardown),
      cmocka_unit_test_setup_teardown(
          test_verify_exit_on_first_change_short_circuits, fixture_setup,
          fixture_teardown),
      cmocka_unit_test_setup_teardown(
          test_verify_exit_on_first_with_removed_short_circuits, fixture_setup,
          fixture_teardown),
      cmocka_unit_test_setup_teardown(test_verify_json_added_emits_change_record,
                                      fixture_setup, fixture_teardown),
      cmocka_unit_test_setup_teardown(
          test_verify_json_removed_emits_change_record, fixture_setup,
          fixture_teardown),
      cmocka_unit_test_setup_teardown(test_verify_strict_mtime_change_detected,
                                      fixture_setup, fixture_teardown),
      cmocka_unit_test_setup_teardown(test_verify_empty_directory_zero_changes,
                                      fixture_setup, fixture_teardown),
      cmocka_unit_test_setup_teardown(test_verify_json_summary_files_total_present,
                                      fixture_setup, fixture_teardown),
      cmocka_unit_test_setup_teardown(test_verify_with_symlink_kind,
                                      fixture_setup, fixture_teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
