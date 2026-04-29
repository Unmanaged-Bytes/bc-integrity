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

#ifndef BC_HRBL_TEST_BINARY_PATH
#define BC_HRBL_TEST_BINARY_PATH "/usr/local/bin/bc-hrbl"
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
           "/tmp/bc_integrity_hrbl_compat_%d_XXXXXX", getpid());
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

static bool bc_hrbl_binary_available(void) {
  struct stat st;
  if (stat(BC_HRBL_TEST_BINARY_PATH, &st) != 0) {
    return false;
  }
  return (st.st_mode & S_IXUSR) != 0;
}

static void write_file(const char *path, const char *content) {
  FILE *file = fopen(path, "wb");
  assert_non_null(file);
  fputs(content, file);
  fclose(file);
}

static void build_test_tree(const char *root) {
  char path[512];

  for (int index = 1; index <= 6; ++index) {
    snprintf(path, sizeof(path), "%s/file_%d.txt", root, index);
    char content[32];
    snprintf(content, sizeof(content), "content-%d", index);
    write_file(path, content);
  }

  snprintf(path, sizeof(path), "%s/sub", root);
  assert_int_equal(mkdir(path, 0755), 0);

  snprintf(path, sizeof(path), "%s/sub/inner.txt", root);
  write_file(path, "inner-content");

  snprintf(path, sizeof(path), "%s/lnk", root);
  assert_int_equal(symlink("file_1.txt", path), 0);
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

static int run_bc_hrbl_verify(const char *manifest_path) {
  pid_t pid = fork();
  if (pid < 0) {
    return -1;
  }
  if (pid == 0) {
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      dup2(devnull, STDOUT_FILENO);
      close(devnull);
    }
    char *argv[] = {
        (char *)BC_HRBL_TEST_BINARY_PATH,
        "verify",
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

static int run_bc_hrbl_capture(const char *subcommand, const char *manifest_path,
                               const char *path_argument, char *capture_output,
                               size_t output_size) {
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
    if (path_argument != NULL) {
      char *argv[] = {
          (char *)BC_HRBL_TEST_BINARY_PATH, (char *)subcommand,
          (char *)manifest_path,            (char *)path_argument,
          NULL,
      };
      execv(argv[0], argv);
      _exit(127);
    }
    char *argv[] = {
        (char *)BC_HRBL_TEST_BINARY_PATH,
        (char *)subcommand,
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

static void test_hrbl_verify_accepts_bc_integrity_manifest(void **state) {
  if (!bc_hrbl_binary_available()) {
    skip();
  }
  fixture_state_t *fixture = (fixture_state_t *)*state;
  build_test_tree(fixture->fixture_directory);

  assert_int_equal(run_bc_integrity_manifest(fixture->fixture_directory,
                                             fixture->manifest_path),
                   0);

  int verify_exit = run_bc_hrbl_verify(fixture->manifest_path);
  assert_int_equal(verify_exit, 0);
}

static void test_hrbl_inspect_produces_valid_json(void **state) {
  if (!bc_hrbl_binary_available()) {
    skip();
  }
  fixture_state_t *fixture = (fixture_state_t *)*state;
  build_test_tree(fixture->fixture_directory);

  assert_int_equal(run_bc_integrity_manifest(fixture->fixture_directory,
                                             fixture->manifest_path),
                   0);

  char inspect_output[32768];
  int inspect_exit = run_bc_hrbl_capture(
      "inspect", fixture->manifest_path, NULL, inspect_output,
      sizeof(inspect_output));
  assert_int_equal(inspect_exit, 0);

  size_t output_length = strlen(inspect_output);
  assert_true(output_length > 2);

  size_t lead = 0;
  while (lead < output_length && (inspect_output[lead] == ' ' ||
                                  inspect_output[lead] == '\t' ||
                                  inspect_output[lead] == '\n' ||
                                  inspect_output[lead] == '\r')) {
    ++lead;
  }
  assert_true(lead < output_length);
  assert_int_equal(inspect_output[lead], '{');

  assert_non_null(strstr(inspect_output, "\"entries\""));
  assert_non_null(strstr(inspect_output, "\"file_1.txt\""));
  assert_non_null(strstr(inspect_output, "\"sub\""));
  assert_non_null(strstr(inspect_output, "\"lnk\""));
  assert_non_null(strstr(inspect_output, "\"kind\""));
  assert_non_null(strstr(inspect_output, "\"digest_hex\""));
}

static void test_hrbl_query_finds_known_path(void **state) {
  if (!bc_hrbl_binary_available()) {
    skip();
  }
  fixture_state_t *fixture = (fixture_state_t *)*state;
  build_test_tree(fixture->fixture_directory);

  assert_int_equal(run_bc_integrity_manifest(fixture->fixture_directory,
                                             fixture->manifest_path),
                   0);

  char query_output[256];
  int query_exit = run_bc_hrbl_capture("query", fixture->manifest_path,
                                       "entries.'file_1.txt'.kind",
                                       query_output, sizeof(query_output));
  assert_int_equal(query_exit, 0);
  assert_non_null(strstr(query_output, "file"));

  char query_dir_output[256];
  int query_dir_exit = run_bc_hrbl_capture(
      "query", fixture->manifest_path, "entries.sub.kind", query_dir_output,
      sizeof(query_dir_output));
  assert_int_equal(query_dir_exit, 0);
  assert_non_null(strstr(query_dir_output, "dir"));

  char query_lnk_output[256];
  int query_lnk_exit = run_bc_hrbl_capture(
      "query", fixture->manifest_path, "entries.lnk.kind", query_lnk_output,
      sizeof(query_lnk_output));
  assert_int_equal(query_lnk_exit, 0);
  assert_non_null(strstr(query_lnk_output, "symlink"));
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test_setup_teardown(
          test_hrbl_verify_accepts_bc_integrity_manifest, fixture_setup,
          fixture_teardown),
      cmocka_unit_test_setup_teardown(test_hrbl_inspect_produces_valid_json,
                                      fixture_setup, fixture_teardown),
      cmocka_unit_test_setup_teardown(test_hrbl_query_finds_known_path,
                                      fixture_setup, fixture_teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
