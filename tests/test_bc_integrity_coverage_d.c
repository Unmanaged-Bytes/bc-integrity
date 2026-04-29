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
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "bc_allocators.h"
#include "bc_concurrency.h"
#include "bc_containers_vector.h"
#include "bc_core.h"
#include "bc_hrbl.h"
#include "bc_integrity_capture_internal.h"
#include "bc_integrity_cli_internal.h"
#include "bc_integrity_diff_internal.h"
#include "bc_integrity_entry_internal.h"
#include "bc_integrity_manifest_internal.h"
#include "bc_integrity_verify_internal.h"
#include "bc_integrity_walk_internal.h"
#include "bc_runtime.h"
#include "bc_runtime_cli.h"
#include "bc_runtime_error_collector.h"

#ifndef BC_INTEGRITY_TEST_BINARY_PATH
#define BC_INTEGRITY_TEST_BINARY_PATH "/usr/local/bin/bc-integrity"
#endif

typedef struct coverage_d_fixture {
  char fixture_directory[256];
  char manifest_path[300];
  char manifest_path_b[300];
  bc_allocators_context_t *memory_context;
} coverage_d_fixture_t;

static int coverage_d_setup(void **state) {
  coverage_d_fixture_t *fixture = malloc(sizeof(*fixture));
  if (fixture == NULL) {
    return -1;
  }
  snprintf(fixture->fixture_directory, sizeof(fixture->fixture_directory),
           "/tmp/bc_integrity_cov_d_%d_XXXXXX", getpid());
  if (mkdtemp(fixture->fixture_directory) == NULL) {
    free(fixture);
    return -1;
  }
  snprintf(fixture->manifest_path, sizeof(fixture->manifest_path), "%s.hrbl",
           fixture->fixture_directory);
  snprintf(fixture->manifest_path_b, sizeof(fixture->manifest_path_b),
           "%s.b.hrbl", fixture->fixture_directory);
  bc_allocators_context_config_t allocator_config = {.tracking_enabled = true};
  fixture->memory_context = NULL;
  bc_allocators_context_create(&allocator_config, &fixture->memory_context);
  *state = fixture;
  return 0;
}

static int coverage_d_teardown(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  if (fixture->memory_context != NULL) {
    bc_allocators_context_destroy(fixture->memory_context);
  }
  char command[1024];
  snprintf(command, sizeof(command), "rm -rf '%s'", fixture->fixture_directory);
  int rc = system(command);
  (void)rc;
  unlink(fixture->manifest_path);
  unlink(fixture->manifest_path_b);
  free(fixture);
  return 0;
}

static void cov_write_file(const char *path, const char *content) {
  FILE *file = fopen(path, "wb");
  assert_non_null(file);
  fputs(content, file);
  fclose(file);
}

static void cov_write_file_bytes(const char *path, const void *data,
                                 size_t length) {
  FILE *file = fopen(path, "wb");
  assert_non_null(file);
  if (length > 0) {
    fwrite(data, 1, length, file);
  }
  fclose(file);
}

static int cov_run_collect(char *const argv[], char *capture_output,
                           size_t output_size, char *capture_stderr,
                           size_t stderr_size) {
  int outfd[2];
  int errfd[2];
  if (pipe(outfd) < 0) {
    return -1;
  }
  if (pipe(errfd) < 0) {
    close(outfd[0]);
    close(outfd[1]);
    return -1;
  }
  pid_t pid = fork();
  if (pid < 0) {
    close(outfd[0]);
    close(outfd[1]);
    close(errfd[0]);
    close(errfd[1]);
    return -1;
  }
  if (pid == 0) {
    close(outfd[0]);
    close(errfd[0]);
    dup2(outfd[1], STDOUT_FILENO);
    dup2(errfd[1], STDERR_FILENO);
    close(outfd[1]);
    close(errfd[1]);
    execv(argv[0], argv);
    _exit(127);
  }
  close(outfd[1]);
  close(errfd[1]);
  size_t out_total = 0;
  if (capture_output != NULL && output_size > 0) {
    while (out_total + 1 < output_size) {
      ssize_t bytes_read =
          read(outfd[0], capture_output + out_total, output_size - 1 - out_total);
      if (bytes_read <= 0) {
        break;
      }
      out_total += (size_t)bytes_read;
    }
    capture_output[out_total] = '\0';
  } else {
    char drain[4096];
    while (read(outfd[0], drain, sizeof(drain)) > 0) {
    }
  }
  size_t err_total = 0;
  if (capture_stderr != NULL && stderr_size > 0) {
    while (err_total + 1 < stderr_size) {
      ssize_t bytes_read =
          read(errfd[0], capture_stderr + err_total, stderr_size - 1 - err_total);
      if (bytes_read <= 0) {
        break;
      }
      err_total += (size_t)bytes_read;
    }
    capture_stderr[err_total] = '\0';
  } else {
    char drain_err[4096];
    while (read(errfd[0], drain_err, sizeof(drain_err)) > 0) {
    }
  }
  close(outfd[0]);
  close(errfd[0]);
  int status = 0;
  waitpid(pid, &status, 0);
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int cov_run_manifest_args(const char *root, const char *output,
                                 const char *const *extra_args,
                                 size_t extra_args_count) {
  char *argv[24];
  size_t cursor = 0;
  argv[cursor++] = (char *)BC_INTEGRITY_TEST_BINARY_PATH;
  for (size_t index = 0; index < extra_args_count; ++index) {
    argv[cursor++] = (char *)extra_args[index];
  }
  argv[cursor++] = (char *)"manifest";
  char output_argument[512];
  snprintf(output_argument, sizeof(output_argument), "--output=%s", output);
  argv[cursor++] = output_argument;
  argv[cursor++] = (char *)"--default-exclude-virtual=false";
  argv[cursor++] = (char *)root;
  argv[cursor] = NULL;
  return cov_run_collect(argv, NULL, 0, NULL, 0);
}

static int cov_run_with_args(const char *const *args, size_t args_count,
                             char *capture_output, size_t output_size,
                             char *capture_stderr, size_t stderr_size) {
  char *argv[24];
  size_t cursor = 0;
  argv[cursor++] = (char *)BC_INTEGRITY_TEST_BINARY_PATH;
  for (size_t index = 0; index < args_count; ++index) {
    argv[cursor++] = (char *)args[index];
  }
  argv[cursor] = NULL;
  return cov_run_collect(argv, capture_output, output_size, capture_stderr,
                         stderr_size);
}

static void cov_build_basic_tree(const char *root) {
  char path[512];
  snprintf(path, sizeof(path), "%s/file_a.txt", root);
  cov_write_file(path, "alpha-content");
  snprintf(path, sizeof(path), "%s/file_b.txt", root);
  cov_write_file(path, "beta-content");
  snprintf(path, sizeof(path), "%s/sub", root);
  assert_int_equal(mkdir(path, 0755), 0);
  snprintf(path, sizeof(path), "%s/sub/inside.txt", root);
  cov_write_file(path, "inside-content");
}

/* === main.c orchestration === */

static void test_main_help_global_exit_zero(void **state) {
  (void)state;
  const char *args[] = {"--help"};
  char output[8192];
  int exit_code = cov_run_with_args(args, 1, output, sizeof(output), NULL, 0);
  assert_int_equal(exit_code, 0);
  assert_non_null(strstr(output, "bc-integrity"));
}

static void test_main_help_per_subcommand(void **state) {
  (void)state;
  const char *args_manifest[] = {"manifest", "--help"};
  char output[8192];
  int exit_code = cov_run_with_args(args_manifest, 2, output, sizeof(output),
                                    NULL, 0);
  assert_int_equal(exit_code, 0);
  assert_non_null(strstr(output, "manifest"));

  const char *args_verify[] = {"verify", "--help"};
  exit_code = cov_run_with_args(args_verify, 2, output, sizeof(output), NULL, 0);
  assert_int_equal(exit_code, 0);
  assert_non_null(strstr(output, "verify"));

  const char *args_diff[] = {"diff", "--help"};
  exit_code = cov_run_with_args(args_diff, 2, output, sizeof(output), NULL, 0);
  assert_int_equal(exit_code, 0);
  assert_non_null(strstr(output, "diff"));
}

static void test_main_version_exit_zero(void **state) {
  (void)state;
  const char *args[] = {"--version"};
  char output[1024];
  int exit_code = cov_run_with_args(args, 1, output, sizeof(output), NULL, 0);
  assert_int_equal(exit_code, 0);
  assert_non_null(strstr(output, "rolling"));
}

static void test_main_unknown_subcommand_exits_two(void **state) {
  (void)state;
  const char *args[] = {"frobnicate"};
  int exit_code = cov_run_with_args(args, 1, NULL, 0, NULL, 0);
  assert_int_equal(exit_code, 2);
}

static void test_main_no_subcommand_exits_two(void **state) {
  (void)state;
  const char *args[] = {""};
  int exit_code = cov_run_with_args(args, 0, NULL, 0, NULL, 0);
  assert_int_equal(exit_code, 2);
}

static void test_main_manifest_threads_zero_singlethreaded(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  const char *extra[] = {"--threads=0"};
  int rc = cov_run_manifest_args(fixture->fixture_directory,
                                 fixture->manifest_path, extra, 1);
  assert_int_equal(rc, 0);
}

static void test_main_manifest_threads_one(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  const char *extra[] = {"--threads=1"};
  int rc = cov_run_manifest_args(fixture->fixture_directory,
                                 fixture->manifest_path, extra, 1);
  assert_int_equal(rc, 0);
}

static void test_main_manifest_threads_auto_io(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  const char *extra[] = {"--threads=auto-io"};
  int rc = cov_run_manifest_args(fixture->fixture_directory,
                                 fixture->manifest_path, extra, 1);
  assert_int_equal(rc, 0);
}

static void test_main_manifest_threads_exceeds_logical(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  size_t logical = bc_concurrency_logical_processor_count();
  if (logical == 0) {
    skip();
    return;
  }
  char threads_arg[64];
  snprintf(threads_arg, sizeof(threads_arg), "--threads=%zu", logical + 16u);
  const char *extra[] = {threads_arg};
  int rc = cov_run_manifest_args(fixture->fixture_directory,
                                 fixture->manifest_path, extra, 1);
  assert_int_equal(rc, 2);
}

static void test_main_manifest_digest_xxh3(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  char *argv[16];
  size_t cursor = 0;
  argv[cursor++] = (char *)BC_INTEGRITY_TEST_BINARY_PATH;
  argv[cursor++] = (char *)"manifest";
  argv[cursor++] = (char *)"--digest-algorithm=xxh3";
  char output_arg[512];
  snprintf(output_arg, sizeof(output_arg), "--output=%s",
           fixture->manifest_path);
  argv[cursor++] = output_arg;
  argv[cursor++] = (char *)"--default-exclude-virtual=false";
  argv[cursor++] = (char *)fixture->fixture_directory;
  argv[cursor] = NULL;
  int rc = cov_run_collect(argv, NULL, 0, NULL, 0);
  assert_int_equal(rc, 0);
}

static void test_main_manifest_digest_xxh128(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  char *argv[16];
  size_t cursor = 0;
  argv[cursor++] = (char *)BC_INTEGRITY_TEST_BINARY_PATH;
  argv[cursor++] = (char *)"manifest";
  argv[cursor++] = (char *)"--digest-algorithm=xxh128";
  char output_arg[512];
  snprintf(output_arg, sizeof(output_arg), "--output=%s",
           fixture->manifest_path);
  argv[cursor++] = output_arg;
  argv[cursor++] = (char *)"--default-exclude-virtual=false";
  argv[cursor++] = (char *)fixture->fixture_directory;
  argv[cursor] = NULL;
  int rc = cov_run_collect(argv, NULL, 0, NULL, 0);
  assert_int_equal(rc, 0);
}

static void test_main_manifest_with_include_glob(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  char *argv[16];
  size_t cursor = 0;
  argv[cursor++] = (char *)BC_INTEGRITY_TEST_BINARY_PATH;
  argv[cursor++] = (char *)"manifest";
  argv[cursor++] = (char *)"--include=*.txt";
  char output_arg[512];
  snprintf(output_arg, sizeof(output_arg), "--output=%s",
           fixture->manifest_path);
  argv[cursor++] = output_arg;
  argv[cursor++] = (char *)"--default-exclude-virtual=false";
  argv[cursor++] = (char *)fixture->fixture_directory;
  argv[cursor] = NULL;
  int rc = cov_run_collect(argv, NULL, 0, NULL, 0);
  assert_int_equal(rc, 0);
}

static void test_main_manifest_with_exclude_glob(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  char *argv[16];
  size_t cursor = 0;
  argv[cursor++] = (char *)BC_INTEGRITY_TEST_BINARY_PATH;
  argv[cursor++] = (char *)"manifest";
  argv[cursor++] = (char *)"--exclude=file_b.txt";
  char output_arg[512];
  snprintf(output_arg, sizeof(output_arg), "--output=%s",
           fixture->manifest_path);
  argv[cursor++] = output_arg;
  argv[cursor++] = (char *)"--default-exclude-virtual=false";
  argv[cursor++] = (char *)fixture->fixture_directory;
  argv[cursor] = NULL;
  int rc = cov_run_collect(argv, NULL, 0, NULL, 0);
  assert_int_equal(rc, 0);
}

static void test_main_manifest_include_hidden(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  char hidden_path[512];
  snprintf(hidden_path, sizeof(hidden_path), "%s/.hidden_one.txt",
           fixture->fixture_directory);
  cov_write_file(hidden_path, "hidden-content");
  char *argv[16];
  size_t cursor = 0;
  argv[cursor++] = (char *)BC_INTEGRITY_TEST_BINARY_PATH;
  argv[cursor++] = (char *)"manifest";
  argv[cursor++] = (char *)"--include-hidden";
  char output_arg[512];
  snprintf(output_arg, sizeof(output_arg), "--output=%s",
           fixture->manifest_path);
  argv[cursor++] = output_arg;
  argv[cursor++] = (char *)"--default-exclude-virtual=false";
  argv[cursor++] = (char *)fixture->fixture_directory;
  argv[cursor] = NULL;
  int rc = cov_run_collect(argv, NULL, 0, NULL, 0);
  assert_int_equal(rc, 0);
}

static void test_main_manifest_follow_symlinks(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  char target_path[512];
  char link_path[512];
  snprintf(target_path, sizeof(target_path), "%s/file_a.txt",
           fixture->fixture_directory);
  snprintf(link_path, sizeof(link_path), "%s/sym_link",
           fixture->fixture_directory);
  assert_int_equal(symlink(target_path, link_path), 0);
  char *argv[16];
  size_t cursor = 0;
  argv[cursor++] = (char *)BC_INTEGRITY_TEST_BINARY_PATH;
  argv[cursor++] = (char *)"manifest";
  argv[cursor++] = (char *)"--follow-symlinks";
  char output_arg[512];
  snprintf(output_arg, sizeof(output_arg), "--output=%s",
           fixture->manifest_path);
  argv[cursor++] = output_arg;
  argv[cursor++] = (char *)"--default-exclude-virtual=false";
  argv[cursor++] = (char *)fixture->fixture_directory;
  argv[cursor] = NULL;
  int rc = cov_run_collect(argv, NULL, 0, NULL, 0);
  assert_int_equal(rc, 0);
}

static void test_main_manifest_root_inexistent_exits_one(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  char missing_root[400];
  snprintf(missing_root, sizeof(missing_root), "%s/no_such_dir",
           fixture->fixture_directory);
  char *argv[8];
  size_t cursor = 0;
  argv[cursor++] = (char *)BC_INTEGRITY_TEST_BINARY_PATH;
  argv[cursor++] = (char *)"manifest";
  char output_arg[512];
  snprintf(output_arg, sizeof(output_arg), "--output=%s",
           fixture->manifest_path);
  argv[cursor++] = output_arg;
  argv[cursor++] = (char *)"--default-exclude-virtual=false";
  argv[cursor++] = missing_root;
  argv[cursor] = NULL;
  int rc = cov_run_collect(argv, NULL, 0, NULL, 0);
  assert_int_equal(rc, 1);
}

static void test_main_manifest_root_is_file_exits_one(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  char file_path[512];
  snprintf(file_path, sizeof(file_path), "%s/just_a_file.txt",
           fixture->fixture_directory);
  cov_write_file(file_path, "data");
  char *argv[8];
  size_t cursor = 0;
  argv[cursor++] = (char *)BC_INTEGRITY_TEST_BINARY_PATH;
  argv[cursor++] = (char *)"manifest";
  char output_arg[512];
  snprintf(output_arg, sizeof(output_arg), "--output=%s",
           fixture->manifest_path);
  argv[cursor++] = output_arg;
  argv[cursor++] = (char *)"--default-exclude-virtual=false";
  argv[cursor++] = file_path;
  argv[cursor] = NULL;
  int rc = cov_run_collect(argv, NULL, 0, NULL, 0);
  assert_int_equal(rc, 1);
}

static void test_main_manifest_missing_output_arg_exits_two(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  const char *args[] = {"manifest", fixture->fixture_directory};
  int rc = cov_run_with_args(args, 2, NULL, 0, NULL, 0);
  assert_int_equal(rc, 2);
}

static void test_main_manifest_extra_positional_exits_two(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  char *argv[16];
  size_t cursor = 0;
  argv[cursor++] = (char *)BC_INTEGRITY_TEST_BINARY_PATH;
  argv[cursor++] = (char *)"manifest";
  char output_arg[512];
  snprintf(output_arg, sizeof(output_arg), "--output=%s",
           fixture->manifest_path);
  argv[cursor++] = output_arg;
  argv[cursor++] = (char *)"--default-exclude-virtual=false";
  argv[cursor++] = (char *)fixture->fixture_directory;
  argv[cursor++] = (char *)fixture->fixture_directory;
  argv[cursor] = NULL;
  int rc = cov_run_collect(argv, NULL, 0, NULL, 0);
  assert_int_equal(rc, 2);
}

static void test_main_diff_missing_args_exits_two(void **state) {
  (void)state;
  const char *args[] = {"diff"};
  int rc = cov_run_with_args(args, 1, NULL, 0, NULL, 0);
  assert_int_equal(rc, 2);
}

static void test_main_diff_one_arg_exits_two(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  cov_run_manifest_args(fixture->fixture_directory, fixture->manifest_path,
                        NULL, 0);
  const char *args[] = {"diff", fixture->manifest_path};
  int rc = cov_run_with_args(args, 2, NULL, 0, NULL, 0);
  assert_int_equal(rc, 2);
}

static void test_main_diff_two_identical_manifests_exits_zero(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  assert_int_equal(cov_run_manifest_args(fixture->fixture_directory,
                                         fixture->manifest_path, NULL, 0),
                   0);
  assert_int_equal(cov_run_manifest_args(fixture->fixture_directory,
                                         fixture->manifest_path_b, NULL, 0),
                   0);
  const char *args[] = {"diff", fixture->manifest_path, fixture->manifest_path_b};
  int rc = cov_run_with_args(args, 3, NULL, 0, NULL, 0);
  assert_int_equal(rc, 0);
}

static void test_main_verify_missing_args_exits_two(void **state) {
  (void)state;
  const char *args[] = {"verify"};
  int rc = cov_run_with_args(args, 1, NULL, 0, NULL, 0);
  assert_int_equal(rc, 2);
}

static void test_main_invalid_threads_value_exits_two(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  char *argv[16];
  size_t cursor = 0;
  argv[cursor++] = (char *)BC_INTEGRITY_TEST_BINARY_PATH;
  argv[cursor++] = (char *)"--threads=banana";
  argv[cursor++] = (char *)"manifest";
  char output_arg[512];
  snprintf(output_arg, sizeof(output_arg), "--output=%s",
           fixture->manifest_path);
  argv[cursor++] = output_arg;
  argv[cursor++] = (char *)"--default-exclude-virtual=false";
  argv[cursor++] = (char *)fixture->fixture_directory;
  argv[cursor] = NULL;
  int rc = cov_run_collect(argv, NULL, 0, NULL, 0);
  assert_int_equal(rc, 2);
}

static void test_main_invalid_digest_algorithm_exits_two(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  char *argv[16];
  size_t cursor = 0;
  argv[cursor++] = (char *)BC_INTEGRITY_TEST_BINARY_PATH;
  argv[cursor++] = (char *)"manifest";
  argv[cursor++] = (char *)"--digest-algorithm=md5";
  char output_arg[512];
  snprintf(output_arg, sizeof(output_arg), "--output=%s",
           fixture->manifest_path);
  argv[cursor++] = output_arg;
  argv[cursor++] = (char *)"--default-exclude-virtual=false";
  argv[cursor++] = (char *)fixture->fixture_directory;
  argv[cursor] = NULL;
  int rc = cov_run_collect(argv, NULL, 0, NULL, 0);
  assert_int_equal(rc, 2);
}

static void test_main_verify_threads_zero_singlethreaded(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  assert_int_equal(cov_run_manifest_args(fixture->fixture_directory,
                                         fixture->manifest_path, NULL, 0),
                   0);
  const char *args[] = {"--threads=0",
                        "verify",
                        "--default-exclude-virtual=false",
                        fixture->fixture_directory,
                        fixture->manifest_path};
  int rc = cov_run_with_args(args, 5, NULL, 0, NULL, 0);
  assert_int_equal(rc, 0);
}

static void test_main_verify_meta_mode_no_rehash(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  assert_int_equal(cov_run_manifest_args(fixture->fixture_directory,
                                         fixture->manifest_path, NULL, 0),
                   0);
  const char *args[] = {"verify",
                        "--mode=meta",
                        "--default-exclude-virtual=false",
                        fixture->fixture_directory,
                        fixture->manifest_path};
  int rc = cov_run_with_args(args, 5, NULL, 0, NULL, 0);
  assert_int_equal(rc, 0);
}

static void test_main_verify_content_mode_compares_only_digest(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  assert_int_equal(cov_run_manifest_args(fixture->fixture_directory,
                                         fixture->manifest_path, NULL, 0),
                   0);
  const char *args[] = {"verify",
                        "--mode=content",
                        "--default-exclude-virtual=false",
                        fixture->fixture_directory,
                        fixture->manifest_path};
  int rc = cov_run_with_args(args, 5, NULL, 0, NULL, 0);
  assert_int_equal(rc, 0);
}

/* === verify_meta.c branch tests === */

static void cov_make_baseline(bc_integrity_meta_snapshot_t *snapshot) {
  memset(snapshot, 0, sizeof(*snapshot));
  snapshot->present = true;
  snapshot->kind = BC_INTEGRITY_ENTRY_KIND_FILE;
  snapshot->size_bytes = 100;
  snapshot->mode = 0100644;
  snapshot->uid = 1000;
  snapshot->gid = 1000;
  snapshot->mtime_sec = 1700000000;
  snapshot->mtime_nsec = 12345;
  snapshot->inode = 99;
  snapshot->nlink = 1;
}

static void test_meta_kind_change_branch(void **state) {
  (void)state;
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  cov_make_baseline(&expected);
  cov_make_baseline(&actual);
  actual.kind = BC_INTEGRITY_ENTRY_KIND_DIRECTORY;
  assert_int_equal(bc_integrity_verify_compare_meta(&expected, &actual, false),
                   BC_INTEGRITY_VERIFY_CHANGE_META);
}

static void test_meta_size_change_branch(void **state) {
  (void)state;
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  cov_make_baseline(&expected);
  cov_make_baseline(&actual);
  actual.size_bytes = 200;
  assert_int_equal(bc_integrity_verify_compare_meta(&expected, &actual, false),
                   BC_INTEGRITY_VERIFY_CHANGE_META);
}

static void test_meta_gid_change_branch(void **state) {
  (void)state;
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  cov_make_baseline(&expected);
  cov_make_baseline(&actual);
  actual.gid = 33;
  assert_int_equal(bc_integrity_verify_compare_meta(&expected, &actual, false),
                   BC_INTEGRITY_VERIFY_CHANGE_META);
}

static void test_meta_mtime_sec_change_branch(void **state) {
  (void)state;
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  cov_make_baseline(&expected);
  cov_make_baseline(&actual);
  actual.mtime_sec = 1700001000;
  assert_int_equal(bc_integrity_verify_compare_meta(&expected, &actual, false),
                   BC_INTEGRITY_VERIFY_CHANGE_META);
}

static void test_meta_mtime_nsec_change_branch(void **state) {
  (void)state;
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  cov_make_baseline(&expected);
  cov_make_baseline(&actual);
  actual.mtime_nsec = 999999;
  assert_int_equal(bc_integrity_verify_compare_meta(&expected, &actual, false),
                   BC_INTEGRITY_VERIFY_CHANGE_META);
}

static void test_meta_nlink_change_branch(void **state) {
  (void)state;
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  cov_make_baseline(&expected);
  cov_make_baseline(&actual);
  actual.nlink = 5;
  assert_int_equal(bc_integrity_verify_compare_meta(&expected, &actual, false),
                   BC_INTEGRITY_VERIFY_CHANGE_META);
}

static void test_meta_link_target_change_branch(void **state) {
  (void)state;
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  cov_make_baseline(&expected);
  cov_make_baseline(&actual);
  expected.kind = BC_INTEGRITY_ENTRY_KIND_SYMLINK;
  actual.kind = BC_INTEGRITY_ENTRY_KIND_SYMLINK;
  expected.link_target = "old/path";
  expected.link_target_length = 8;
  actual.link_target = "new/path";
  actual.link_target_length = 8;
  assert_int_equal(bc_integrity_verify_compare_meta(&expected, &actual, false),
                   BC_INTEGRITY_VERIFY_CHANGE_META);
}

static void test_meta_link_target_length_diff_branch(void **state) {
  (void)state;
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  cov_make_baseline(&expected);
  cov_make_baseline(&actual);
  expected.kind = BC_INTEGRITY_ENTRY_KIND_SYMLINK;
  actual.kind = BC_INTEGRITY_ENTRY_KIND_SYMLINK;
  expected.link_target = "abc";
  expected.link_target_length = 3;
  actual.link_target = "abcdef";
  actual.link_target_length = 6;
  assert_int_equal(bc_integrity_verify_compare_meta(&expected, &actual, false),
                   BC_INTEGRITY_VERIFY_CHANGE_META);
}

static void test_meta_link_target_zero_length_equal_branch(void **state) {
  (void)state;
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  cov_make_baseline(&expected);
  cov_make_baseline(&actual);
  expected.link_target = NULL;
  expected.link_target_length = 0;
  actual.link_target = NULL;
  actual.link_target_length = 0;
  assert_int_equal(bc_integrity_verify_compare_meta(&expected, &actual, false),
                   BC_INTEGRITY_VERIFY_CHANGE_NONE);
}

/* === verify_strict.c branch tests === */

static void cov_make_strict_baseline(bc_integrity_meta_snapshot_t *snapshot) {
  cov_make_baseline(snapshot);
  snapshot->digest_hex =
      "1111111111111111111111111111111111111111111111111111111111111111";
  snapshot->digest_hex_length = 64;
}

static void test_strict_meta_only_change(void **state) {
  (void)state;
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  cov_make_strict_baseline(&expected);
  cov_make_strict_baseline(&actual);
  actual.mode = 0100600;
  assert_int_equal(
      bc_integrity_verify_compare_strict(&expected, &actual, false),
      BC_INTEGRITY_VERIFY_CHANGE_META);
}

static void test_strict_content_only_change(void **state) {
  (void)state;
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  cov_make_strict_baseline(&expected);
  cov_make_strict_baseline(&actual);
  actual.digest_hex =
      "9999999999999999999999999999999999999999999999999999999999999999";
  assert_int_equal(
      bc_integrity_verify_compare_strict(&expected, &actual, false),
      BC_INTEGRITY_VERIFY_CHANGE_CONTENT);
}

static void test_strict_both_meta_and_content_change(void **state) {
  (void)state;
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  cov_make_strict_baseline(&expected);
  cov_make_strict_baseline(&actual);
  actual.mode = 0100700;
  actual.digest_hex =
      "8888888888888888888888888888888888888888888888888888888888888888";
  assert_int_equal(
      bc_integrity_verify_compare_strict(&expected, &actual, false),
      BC_INTEGRITY_VERIFY_CHANGE_BOTH);
}

static void test_strict_no_change_returns_none(void **state) {
  (void)state;
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  cov_make_strict_baseline(&expected);
  cov_make_strict_baseline(&actual);
  assert_int_equal(
      bc_integrity_verify_compare_strict(&expected, &actual, false),
      BC_INTEGRITY_VERIFY_CHANGE_NONE);
}

static void test_strict_kind_change(void **state) {
  (void)state;
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  cov_make_strict_baseline(&expected);
  cov_make_strict_baseline(&actual);
  actual.kind = BC_INTEGRITY_ENTRY_KIND_DIRECTORY;
  assert_int_equal(
      bc_integrity_verify_compare_strict(&expected, &actual, false),
      BC_INTEGRITY_VERIFY_CHANGE_META);
}

static void test_strict_uid_change(void **state) {
  (void)state;
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  cov_make_strict_baseline(&expected);
  cov_make_strict_baseline(&actual);
  actual.uid = 9000;
  assert_int_equal(
      bc_integrity_verify_compare_strict(&expected, &actual, false),
      BC_INTEGRITY_VERIFY_CHANGE_META);
}

static void test_strict_gid_change(void **state) {
  (void)state;
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  cov_make_strict_baseline(&expected);
  cov_make_strict_baseline(&actual);
  actual.gid = 9000;
  assert_int_equal(
      bc_integrity_verify_compare_strict(&expected, &actual, false),
      BC_INTEGRITY_VERIFY_CHANGE_META);
}

static void test_strict_size_change(void **state) {
  (void)state;
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  cov_make_strict_baseline(&expected);
  cov_make_strict_baseline(&actual);
  actual.size_bytes = 999;
  assert_int_equal(
      bc_integrity_verify_compare_strict(&expected, &actual, false),
      BC_INTEGRITY_VERIFY_CHANGE_META);
}

static void test_strict_inode_change(void **state) {
  (void)state;
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  cov_make_strict_baseline(&expected);
  cov_make_strict_baseline(&actual);
  actual.inode = 100000;
  assert_int_equal(
      bc_integrity_verify_compare_strict(&expected, &actual, false),
      BC_INTEGRITY_VERIFY_CHANGE_META);
}

static void test_strict_nlink_change(void **state) {
  (void)state;
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  cov_make_strict_baseline(&expected);
  cov_make_strict_baseline(&actual);
  actual.nlink = 7;
  assert_int_equal(
      bc_integrity_verify_compare_strict(&expected, &actual, false),
      BC_INTEGRITY_VERIFY_CHANGE_META);
}

static void test_strict_mtime_sec_change(void **state) {
  (void)state;
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  cov_make_strict_baseline(&expected);
  cov_make_strict_baseline(&actual);
  actual.mtime_sec = 1800000000;
  assert_int_equal(
      bc_integrity_verify_compare_strict(&expected, &actual, false),
      BC_INTEGRITY_VERIFY_CHANGE_META);
  assert_int_equal(
      bc_integrity_verify_compare_strict(&expected, &actual, true),
      BC_INTEGRITY_VERIFY_CHANGE_NONE);
}

static void test_strict_mtime_nsec_change(void **state) {
  (void)state;
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  cov_make_strict_baseline(&expected);
  cov_make_strict_baseline(&actual);
  actual.mtime_nsec = 999999;
  assert_int_equal(
      bc_integrity_verify_compare_strict(&expected, &actual, false),
      BC_INTEGRITY_VERIFY_CHANGE_META);
  assert_int_equal(
      bc_integrity_verify_compare_strict(&expected, &actual, true),
      BC_INTEGRITY_VERIFY_CHANGE_NONE);
}

static void test_content_digest_length_differ(void **state) {
  (void)state;
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  cov_make_strict_baseline(&expected);
  cov_make_strict_baseline(&actual);
  expected.digest_hex_length = 64;
  actual.digest_hex_length = 16;
  assert_int_equal(bc_integrity_verify_compare_content(&expected, &actual),
                   BC_INTEGRITY_VERIFY_CHANGE_CONTENT);
}

static void test_content_kind_differ(void **state) {
  (void)state;
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  cov_make_strict_baseline(&expected);
  cov_make_strict_baseline(&actual);
  actual.kind = BC_INTEGRITY_ENTRY_KIND_DIRECTORY;
  assert_int_equal(bc_integrity_verify_compare_content(&expected, &actual),
                   BC_INTEGRITY_VERIFY_CHANGE_CONTENT);
}

static void test_content_zero_length_returns_none(void **state) {
  (void)state;
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  memset(&expected, 0, sizeof(expected));
  memset(&actual, 0, sizeof(actual));
  expected.kind = BC_INTEGRITY_ENTRY_KIND_DIRECTORY;
  actual.kind = BC_INTEGRITY_ENTRY_KIND_DIRECTORY;
  expected.digest_hex_length = 0;
  actual.digest_hex_length = 0;
  assert_int_equal(bc_integrity_verify_compare_content(&expected, &actual),
                   BC_INTEGRITY_VERIFY_CHANGE_NONE);
}

static void test_strict_link_target_change(void **state) {
  (void)state;
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  cov_make_strict_baseline(&expected);
  cov_make_strict_baseline(&actual);
  expected.kind = BC_INTEGRITY_ENTRY_KIND_SYMLINK;
  actual.kind = BC_INTEGRITY_ENTRY_KIND_SYMLINK;
  expected.link_target = "/old";
  expected.link_target_length = 4;
  actual.link_target = "/new";
  actual.link_target_length = 4;
  assert_int_equal(
      bc_integrity_verify_compare_strict(&expected, &actual, false),
      BC_INTEGRITY_VERIFY_CHANGE_META);
}

/* === diff.c kind change branch === */

static void cov_make_file_entry(bc_integrity_entry_t *entry, const char *path,
                                bc_integrity_entry_kind_t kind,
                                const char *digest_hex, uint64_t mode) {
  memset(entry, 0, sizeof(*entry));
  entry->relative_path = path;
  entry->relative_path_length = strlen(path);
  entry->kind = kind;
  entry->ok = true;
  entry->size_bytes = 32;
  entry->mode = mode;
  entry->uid = 1000;
  entry->gid = 1000;
  entry->mtime_sec = 1700000000;
  entry->mtime_nsec = 0;
  entry->inode = 100;
  entry->nlink = 1;
  if (digest_hex != NULL) {
    size_t digest_length = strlen(digest_hex);
    memcpy(entry->digest_hex, digest_hex, digest_length);
    entry->digest_hex[digest_length] = '\0';
    entry->digest_hex_length = digest_length;
  }
}

static void cov_write_simple_manifest(bc_allocators_context_t *memory_context,
                                      const char *output_path,
                                      bc_integrity_entry_t *entries_array,
                                      size_t entries_count) {
  bc_containers_vector_t *entries = NULL;
  bc_containers_vector_create(memory_context, sizeof(bc_integrity_entry_t), 8,
                              4096, &entries);
  for (size_t index = 0; index < entries_count; ++index) {
    bc_containers_vector_push(memory_context, entries, &entries_array[index]);
  }
  bc_integrity_manifest_options_t options;
  memset(&options, 0, sizeof(options));
  options.root_path = "/tmp/dummy";
  options.output_path = output_path;
  options.digest_algorithm = BC_INTEGRITY_DIGEST_ALGORITHM_SHA256;
  options.default_exclude_virtual = true;

  bc_integrity_manifest_summary_t summary;
  memset(&summary, 0, sizeof(summary));
  summary.created_at_unix_sec = 1700000000;
  summary.completed_at_unix_sec = 1700000005;
  summary.walltime_ms = 5000;
  summary.file_count = entries_count;
  summary.host = "host";
  summary.root_path_absolute = "/tmp/dummy";

  assert_true(bc_integrity_manifest_write_to_file(
      memory_context, &options, entries, &summary, output_path));
  bc_containers_vector_destroy(memory_context, entries);
}

static void test_diff_kind_change_file_to_dir(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  bc_integrity_entry_t entry_file;
  bc_integrity_entry_t entry_dir;
  cov_make_file_entry(
      &entry_file, "x", BC_INTEGRITY_ENTRY_KIND_FILE,
      "1111111111111111111111111111111111111111111111111111111111111111", 0644);
  cov_make_file_entry(&entry_dir, "x", BC_INTEGRITY_ENTRY_KIND_DIRECTORY, NULL,
                      0755);
  cov_write_simple_manifest(fixture->memory_context, fixture->manifest_path,
                            &entry_file, 1);
  cov_write_simple_manifest(fixture->memory_context, fixture->manifest_path_b,
                            &entry_dir, 1);
  bc_integrity_diff_options_t options;
  memset(&options, 0, sizeof(options));
  options.manifest_path_a = fixture->manifest_path;
  options.manifest_path_b = fixture->manifest_path_b;
  options.format = BC_INTEGRITY_OUTPUT_FORMAT_TEXT;
  int exit_code = -1;
  assert_true(
      bc_integrity_diff_run(fixture->memory_context, &options, &exit_code));
  assert_int_equal(exit_code, 1);
}

static void test_diff_ignore_mtime_only_mtime_diff_zero(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  bc_integrity_entry_t entry_a;
  bc_integrity_entry_t entry_b;
  cov_make_file_entry(
      &entry_a, "x", BC_INTEGRITY_ENTRY_KIND_FILE,
      "1111111111111111111111111111111111111111111111111111111111111111", 0644);
  cov_make_file_entry(
      &entry_b, "x", BC_INTEGRITY_ENTRY_KIND_FILE,
      "1111111111111111111111111111111111111111111111111111111111111111", 0644);
  entry_b.mtime_sec = 1900000000;
  cov_write_simple_manifest(fixture->memory_context, fixture->manifest_path,
                            &entry_a, 1);
  cov_write_simple_manifest(fixture->memory_context, fixture->manifest_path_b,
                            &entry_b, 1);
  bc_integrity_diff_options_t options;
  memset(&options, 0, sizeof(options));
  options.manifest_path_a = fixture->manifest_path;
  options.manifest_path_b = fixture->manifest_path_b;
  options.format = BC_INTEGRITY_OUTPUT_FORMAT_TEXT;
  options.ignore_mtime = true;
  int exit_code = -1;
  assert_true(
      bc_integrity_diff_run(fixture->memory_context, &options, &exit_code));
  assert_int_equal(exit_code, 0);
}

static void test_diff_invalid_manifest_b_returns_two(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  bc_integrity_entry_t entry_a;
  cov_make_file_entry(
      &entry_a, "x", BC_INTEGRITY_ENTRY_KIND_FILE,
      "1111111111111111111111111111111111111111111111111111111111111111", 0644);
  cov_write_simple_manifest(fixture->memory_context, fixture->manifest_path,
                            &entry_a, 1);
  cov_write_file(fixture->manifest_path_b, "garbage");
  bc_integrity_diff_options_t options;
  memset(&options, 0, sizeof(options));
  options.manifest_path_a = fixture->manifest_path;
  options.manifest_path_b = fixture->manifest_path_b;
  options.format = BC_INTEGRITY_OUTPUT_FORMAT_TEXT;
  int exit_code = -1;
  assert_true(
      bc_integrity_diff_run(fixture->memory_context, &options, &exit_code));
  assert_int_equal(exit_code, 2);
}

static void test_diff_json_format_added_only(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  bc_integrity_entry_t entry_b;
  cov_make_file_entry(
      &entry_b, "added.txt", BC_INTEGRITY_ENTRY_KIND_FILE,
      "1111111111111111111111111111111111111111111111111111111111111111", 0644);
  cov_write_simple_manifest(fixture->memory_context, fixture->manifest_path,
                            NULL, 0);
  cov_write_simple_manifest(fixture->memory_context, fixture->manifest_path_b,
                            &entry_b, 1);
  bc_integrity_diff_options_t options;
  memset(&options, 0, sizeof(options));
  options.manifest_path_a = fixture->manifest_path;
  options.manifest_path_b = fixture->manifest_path_b;
  options.format = BC_INTEGRITY_OUTPUT_FORMAT_JSON;
  int exit_code = -1;
  assert_true(
      bc_integrity_diff_run(fixture->memory_context, &options, &exit_code));
  assert_int_equal(exit_code, 1);
}

/* === manifest_writer.c specific paths === */

static void test_writer_path_with_dot_prefix_uses_quoting(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  bc_integrity_entry_t entry;
  cov_make_file_entry(
      &entry, ".dotfile", BC_INTEGRITY_ENTRY_KIND_FILE,
      "1111111111111111111111111111111111111111111111111111111111111111", 0644);
  cov_write_simple_manifest(fixture->memory_context, fixture->manifest_path,
                            &entry, 1);
  bc_hrbl_reader_t *reader = NULL;
  assert_true(bc_hrbl_reader_open(fixture->memory_context,
                                  fixture->manifest_path, &reader));
  bc_hrbl_value_ref_t value_ref;
  assert_true(bc_hrbl_reader_find(reader, "entries.'.dotfile'.kind",
                                  strlen("entries.'.dotfile'.kind"),
                                  &value_ref));
  bc_hrbl_reader_destroy(reader);
}

static void test_writer_path_with_slash_uses_quoting(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  bc_integrity_entry_t entry;
  cov_make_file_entry(
      &entry, "sub/nested.txt", BC_INTEGRITY_ENTRY_KIND_FILE,
      "1111111111111111111111111111111111111111111111111111111111111111", 0644);
  cov_write_simple_manifest(fixture->memory_context, fixture->manifest_path,
                            &entry, 1);
  bc_hrbl_reader_t *reader = NULL;
  assert_true(bc_hrbl_reader_open(fixture->memory_context,
                                  fixture->manifest_path, &reader));
  bc_hrbl_value_ref_t value_ref;
  assert_true(bc_hrbl_reader_find(reader, "entries.'sub/nested.txt'.kind",
                                  strlen("entries.'sub/nested.txt'.kind"),
                                  &value_ref));
  bc_hrbl_reader_destroy(reader);
}

static void test_writer_path_simple_no_quoting(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  bc_integrity_entry_t entry;
  cov_make_file_entry(
      &entry, "simple", BC_INTEGRITY_ENTRY_KIND_FILE,
      "1111111111111111111111111111111111111111111111111111111111111111", 0644);
  cov_write_simple_manifest(fixture->memory_context, fixture->manifest_path,
                            &entry, 1);
  bc_hrbl_reader_t *reader = NULL;
  assert_true(bc_hrbl_reader_open(fixture->memory_context,
                                  fixture->manifest_path, &reader));
  bc_hrbl_value_ref_t value_ref;
  assert_true(bc_hrbl_reader_find(reader, "entries.simple.kind",
                                  strlen("entries.simple.kind"), &value_ref));
  bc_hrbl_reader_destroy(reader);
}

static void test_writer_summary_with_walltime_set(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  bc_integrity_entry_t entry;
  cov_make_file_entry(
      &entry, "simple", BC_INTEGRITY_ENTRY_KIND_FILE,
      "1111111111111111111111111111111111111111111111111111111111111111", 0644);
  cov_write_simple_manifest(fixture->memory_context, fixture->manifest_path,
                            &entry, 1);
  bc_hrbl_reader_t *reader = NULL;
  assert_true(bc_hrbl_reader_open(fixture->memory_context,
                                  fixture->manifest_path, &reader));
  bc_hrbl_value_ref_t value_ref;
  assert_true(bc_hrbl_reader_find(reader, "summary.walltime_ms",
                                  strlen("summary.walltime_ms"), &value_ref));
  uint64_t walltime = 0;
  assert_true(bc_hrbl_reader_get_uint64(&value_ref, &walltime));
  assert_int_equal(walltime, 5000u);
  bc_hrbl_reader_destroy(reader);
}

static void test_writer_with_no_host_uses_unknown(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  bc_integrity_manifest_options_t options;
  memset(&options, 0, sizeof(options));
  options.root_path = "/tmp/dummy";
  options.output_path = fixture->manifest_path;
  options.digest_algorithm = BC_INTEGRITY_DIGEST_ALGORITHM_SHA256;
  options.default_exclude_virtual = true;
  bc_integrity_manifest_summary_t summary;
  memset(&summary, 0, sizeof(summary));
  summary.host = NULL;
  summary.root_path_absolute = NULL;
  bc_containers_vector_t *entries = NULL;
  bc_containers_vector_create(fixture->memory_context,
                              sizeof(bc_integrity_entry_t), 8, 4096, &entries);
  assert_true(bc_integrity_manifest_write_to_file(fixture->memory_context,
                                                  &options, entries, &summary,
                                                  fixture->manifest_path));
  bc_hrbl_reader_t *reader = NULL;
  assert_true(bc_hrbl_reader_open(fixture->memory_context,
                                  fixture->manifest_path, &reader));
  bc_hrbl_value_ref_t value_ref;
  assert_true(bc_hrbl_reader_find(reader, "meta.host", strlen("meta.host"),
                                  &value_ref));
  const char *host_value = NULL;
  size_t host_length = 0;
  assert_true(bc_hrbl_reader_get_string(&value_ref, &host_value, &host_length));
  assert_int_equal(host_length, 7u);
  assert_memory_equal(host_value, "unknown", 7u);
  bc_hrbl_reader_destroy(reader);
  bc_containers_vector_destroy(fixture->memory_context, entries);
}

/* === capture_entry.c additional paths === */

static void test_capture_empty_file(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  char file_path[512];
  snprintf(file_path, sizeof(file_path), "%s/empty.bin",
           fixture->fixture_directory);
  cov_write_file_bytes(file_path, NULL, 0);
  struct stat stat_buffer;
  assert_int_equal(lstat(file_path, &stat_buffer), 0);
  int dir_fd =
      open(fixture->fixture_directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  assert_true(dir_fd >= 0);
  bc_integrity_entry_t entry;
  bc_integrity_capture_entry_from_stat(
      fixture->memory_context, &stat_buffer,
      BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, dir_fd, "empty.bin", file_path,
      strlen(file_path), "empty.bin", strlen("empty.bin"), false, &entry);
  close(dir_fd);
  assert_int_equal(entry.kind, BC_INTEGRITY_ENTRY_KIND_FILE);
  assert_true(entry.ok);
  assert_int_equal(entry.size_bytes, 0u);
  assert_int_equal(entry.digest_hex_length, 64u);
}

static void test_capture_broken_symlink(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  char link_path[512];
  snprintf(link_path, sizeof(link_path), "%s/broken_link",
           fixture->fixture_directory);
  assert_int_equal(symlink("/nonexistent/target/path", link_path), 0);
  struct stat stat_buffer;
  assert_int_equal(lstat(link_path, &stat_buffer), 0);
  int dir_fd =
      open(fixture->fixture_directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  assert_true(dir_fd >= 0);
  bc_integrity_entry_t entry;
  bc_integrity_capture_entry_from_stat(
      fixture->memory_context, &stat_buffer,
      BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, dir_fd, "broken_link", link_path,
      strlen(link_path), "broken_link", strlen("broken_link"), false, &entry);
  close(dir_fd);
  assert_int_equal(entry.kind, BC_INTEGRITY_ENTRY_KIND_SYMLINK);
  assert_true(entry.ok);
  assert_non_null(entry.link_target);
  assert_int_equal(entry.link_target_length, strlen("/nonexistent/target/path"));
}

static void test_capture_compute_digest_unreadable_file(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  if (geteuid() == 0) {
    skip();
    return;
  }
  char file_path[512];
  snprintf(file_path, sizeof(file_path), "%s/unreadable.txt",
           fixture->fixture_directory);
  cov_write_file(file_path, "some-data");
  assert_int_equal(chmod(file_path, 0000), 0);
  char digest_buffer[BC_INTEGRITY_DIGEST_HEX_BUFFER_SIZE];
  size_t digest_length = 0;
  int errno_value = 0;
  bool ok = bc_integrity_capture_compute_digest(
      file_path, 9, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, digest_buffer,
      &digest_length, &errno_value);
  (void)ok;
  chmod(file_path, 0644);
  unlink(file_path);
}

static void test_capture_set_error_message_basic(void **state) {
  (void)state;
  bc_integrity_entry_t entry;
  memset(&entry, 0, sizeof(entry));
  entry.ok = true;
  bc_integrity_capture_set_error_message(&entry, ENOENT);
  assert_false(entry.ok);
  assert_int_equal(entry.errno_value, ENOENT);
  assert_true(entry.error_message_length > 0);
}

static void test_capture_kind_name_round_trip_all_kinds(void **state) {
  (void)state;
  assert_string_equal(
      bc_integrity_entry_kind_name(BC_INTEGRITY_ENTRY_KIND_FILE), "file");
  assert_string_equal(
      bc_integrity_entry_kind_name(BC_INTEGRITY_ENTRY_KIND_DIRECTORY), "dir");
  assert_string_equal(
      bc_integrity_entry_kind_name(BC_INTEGRITY_ENTRY_KIND_SYMLINK), "symlink");
  assert_string_equal(
      bc_integrity_entry_kind_name(BC_INTEGRITY_ENTRY_KIND_FIFO), "fifo");
  assert_string_equal(
      bc_integrity_entry_kind_name(BC_INTEGRITY_ENTRY_KIND_SOCKET), "socket");
  assert_string_equal(
      bc_integrity_entry_kind_name(BC_INTEGRITY_ENTRY_KIND_DEVICE), "device");
}

static void test_capture_fifo_kind_via_stat(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  char fifo_path[512];
  snprintf(fifo_path, sizeof(fifo_path), "%s/my_fifo_capture",
           fixture->fixture_directory);
  if (mkfifo(fifo_path, 0644) != 0) {
    skip();
    return;
  }
  struct stat stat_buffer;
  assert_int_equal(lstat(fifo_path, &stat_buffer), 0);
  int dir_fd =
      open(fixture->fixture_directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  assert_true(dir_fd >= 0);
  bc_integrity_entry_t entry;
  bc_integrity_capture_entry_from_stat(
      fixture->memory_context, &stat_buffer,
      BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, dir_fd, "my_fifo_capture",
      fifo_path, strlen(fifo_path), "my_fifo_capture",
      strlen("my_fifo_capture"), false, &entry);
  close(dir_fd);
  assert_int_equal(entry.kind, BC_INTEGRITY_ENTRY_KIND_FIFO);
  unlink(fifo_path);
}

static void test_capture_socket_kind_via_stat(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  char socket_path[512];
  snprintf(socket_path, sizeof(socket_path), "%s/my_socket",
           fixture->fixture_directory);
  /* Create a unix socket via socket()/bind() */
  int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sfd < 0) {
    skip();
    return;
  }
  struct {
    sa_family_t family;
    char path[108];
  } addr;
  memset(&addr, 0, sizeof(addr));
  addr.family = AF_UNIX;
  size_t socket_path_length = strlen(socket_path);
  if (socket_path_length >= sizeof(addr.path)) {
    close(sfd);
    skip();
    return;
  }
  memcpy(addr.path, socket_path, socket_path_length);
  addr.path[socket_path_length] = '\0';
  if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(sfd);
    skip();
    return;
  }
  close(sfd);
  struct stat stat_buffer;
  assert_int_equal(lstat(socket_path, &stat_buffer), 0);
  int dir_fd =
      open(fixture->fixture_directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  assert_true(dir_fd >= 0);
  bc_integrity_entry_t entry;
  bc_integrity_capture_entry_from_stat(
      fixture->memory_context, &stat_buffer,
      BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, dir_fd, "my_socket", socket_path,
      strlen(socket_path), "my_socket", strlen("my_socket"), false, &entry);
  close(dir_fd);
  assert_int_equal(entry.kind, BC_INTEGRITY_ENTRY_KIND_SOCKET);
  unlink(socket_path);
}

static void test_capture_long_link_target(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  char link_path[512];
  snprintf(link_path, sizeof(link_path), "%s/long_link",
           fixture->fixture_directory);
  char long_target[2048];
  for (size_t index = 0; index < sizeof(long_target) - 1; ++index) {
    long_target[index] = 'a' + (char)(index % 26);
  }
  long_target[sizeof(long_target) - 1] = '\0';
  if (symlink(long_target, link_path) != 0) {
    skip();
    return;
  }
  struct stat stat_buffer;
  assert_int_equal(lstat(link_path, &stat_buffer), 0);
  int dir_fd =
      open(fixture->fixture_directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  assert_true(dir_fd >= 0);
  bc_integrity_entry_t entry;
  bc_integrity_capture_entry_from_stat(
      fixture->memory_context, &stat_buffer,
      BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, dir_fd, "long_link", link_path,
      strlen(link_path), "long_link", strlen("long_link"), false, &entry);
  close(dir_fd);
  assert_int_equal(entry.kind, BC_INTEGRITY_ENTRY_KIND_SYMLINK);
  unlink(link_path);
}

static void test_capture_compute_digest_missing_file(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  char file_path[512];
  snprintf(file_path, sizeof(file_path), "%s/never_exists.txt",
           fixture->fixture_directory);
  char digest_buffer[BC_INTEGRITY_DIGEST_HEX_BUFFER_SIZE];
  size_t digest_length = 0;
  int errno_value = 0;
  assert_false(bc_integrity_capture_compute_digest(
      file_path, 0, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, digest_buffer,
      &digest_length, &errno_value));
  assert_true(errno_value != 0);
}

/* === walk_serial.c with include/exclude filters === */

static void test_walk_serial_with_include_filter(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  bc_runtime_error_collector_t *errors = NULL;
  assert_true(bc_runtime_error_collector_create(fixture->memory_context,
                                                &errors));
  bc_containers_vector_t *entries = NULL;
  assert_true(bc_containers_vector_create(fixture->memory_context,
                                          sizeof(bc_integrity_entry_t), 16, 256,
                                          &entries));
  bc_integrity_manifest_options_t options;
  bc_core_zero(&options, sizeof(options));
  options.root_path = fixture->fixture_directory;
  options.digest_algorithm = BC_INTEGRITY_DIGEST_ALGORITHM_SHA256;
  options.defer_digest = true;
  options.default_exclude_virtual = false;
  options.include_list = "*.txt";
  size_t directory_path_length = strlen(fixture->fixture_directory);
  bool walk_ok = bc_integrity_walk_run_serial(
      fixture->memory_context, NULL, &options, fixture->fixture_directory,
      directory_path_length, entries, errors);
  assert_true(walk_ok);
  bc_containers_vector_destroy(fixture->memory_context, entries);
  bc_runtime_error_collector_destroy(fixture->memory_context, errors);
}

static void test_walk_serial_with_exclude_filter(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  bc_runtime_error_collector_t *errors = NULL;
  assert_true(bc_runtime_error_collector_create(fixture->memory_context,
                                                &errors));
  bc_containers_vector_t *entries = NULL;
  assert_true(bc_containers_vector_create(fixture->memory_context,
                                          sizeof(bc_integrity_entry_t), 16, 256,
                                          &entries));
  bc_integrity_manifest_options_t options;
  bc_core_zero(&options, sizeof(options));
  options.root_path = fixture->fixture_directory;
  options.digest_algorithm = BC_INTEGRITY_DIGEST_ALGORITHM_SHA256;
  options.defer_digest = true;
  options.default_exclude_virtual = false;
  options.exclude_list = "file_b.txt";
  size_t directory_path_length = strlen(fixture->fixture_directory);
  bool walk_ok = bc_integrity_walk_run_serial(
      fixture->memory_context, NULL, &options, fixture->fixture_directory,
      directory_path_length, entries, errors);
  assert_true(walk_ok);
  bc_containers_vector_destroy(fixture->memory_context, entries);
  bc_runtime_error_collector_destroy(fixture->memory_context, errors);
}

static void test_walk_serial_with_include_special(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  char fifo_path[512];
  snprintf(fifo_path, sizeof(fifo_path), "%s/my_fifo",
           fixture->fixture_directory);
  if (mkfifo(fifo_path, 0644) != 0) {
    skip();
    return;
  }
  bc_runtime_error_collector_t *errors = NULL;
  assert_true(bc_runtime_error_collector_create(fixture->memory_context,
                                                &errors));
  bc_containers_vector_t *entries = NULL;
  assert_true(bc_containers_vector_create(fixture->memory_context,
                                          sizeof(bc_integrity_entry_t), 16, 256,
                                          &entries));
  bc_integrity_manifest_options_t options;
  bc_core_zero(&options, sizeof(options));
  options.root_path = fixture->fixture_directory;
  options.digest_algorithm = BC_INTEGRITY_DIGEST_ALGORITHM_SHA256;
  options.defer_digest = true;
  options.default_exclude_virtual = false;
  options.include_special = true;
  size_t directory_path_length = strlen(fixture->fixture_directory);
  bool walk_ok = bc_integrity_walk_run_serial(
      fixture->memory_context, NULL, &options, fixture->fixture_directory,
      directory_path_length, entries, errors);
  assert_true(walk_ok);
  size_t length = bc_containers_vector_length(entries);
  bool found_fifo = false;
  for (size_t index = 0; index < length; ++index) {
    bc_integrity_entry_t entry;
    if (!bc_containers_vector_get(entries, index, &entry)) {
      continue;
    }
    if (entry.kind == BC_INTEGRITY_ENTRY_KIND_FIFO) {
      found_fifo = true;
      break;
    }
  }
  assert_true(found_fifo);
  bc_containers_vector_destroy(fixture->memory_context, entries);
  bc_runtime_error_collector_destroy(fixture->memory_context, errors);
  unlink(fifo_path);
}

static void test_walk_serial_with_hidden_dir_skipped(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  char hidden_dir[512];
  snprintf(hidden_dir, sizeof(hidden_dir), "%s/.hidden_dir",
           fixture->fixture_directory);
  assert_int_equal(mkdir(hidden_dir, 0755), 0);
  char inside[600];
  snprintf(inside, sizeof(inside), "%s/inside.txt", hidden_dir);
  cov_write_file(inside, "secret");
  bc_runtime_error_collector_t *errors = NULL;
  assert_true(bc_runtime_error_collector_create(fixture->memory_context,
                                                &errors));
  bc_containers_vector_t *entries = NULL;
  assert_true(bc_containers_vector_create(fixture->memory_context,
                                          sizeof(bc_integrity_entry_t), 16, 256,
                                          &entries));
  bc_integrity_manifest_options_t options;
  bc_core_zero(&options, sizeof(options));
  options.root_path = fixture->fixture_directory;
  options.digest_algorithm = BC_INTEGRITY_DIGEST_ALGORITHM_SHA256;
  options.defer_digest = true;
  options.default_exclude_virtual = false;
  options.include_hidden = false;
  size_t directory_path_length = strlen(fixture->fixture_directory);
  bool walk_ok = bc_integrity_walk_run_serial(
      fixture->memory_context, NULL, &options, fixture->fixture_directory,
      directory_path_length, entries, errors);
  assert_true(walk_ok);
  size_t length = bc_containers_vector_length(entries);
  for (size_t index = 0; index < length; ++index) {
    bc_integrity_entry_t entry;
    if (!bc_containers_vector_get(entries, index, &entry)) {
      continue;
    }
    assert_null(strstr(entry.relative_path, ".hidden_dir"));
  }
  bc_containers_vector_destroy(fixture->memory_context, entries);
  bc_runtime_error_collector_destroy(fixture->memory_context, errors);
}

static void test_walk_serial_root_inexistent_returns_false(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  bc_runtime_error_collector_t *errors = NULL;
  assert_true(bc_runtime_error_collector_create(fixture->memory_context,
                                                &errors));
  bc_containers_vector_t *entries = NULL;
  assert_true(bc_containers_vector_create(fixture->memory_context,
                                          sizeof(bc_integrity_entry_t), 16, 256,
                                          &entries));
  bc_integrity_manifest_options_t options;
  bc_core_zero(&options, sizeof(options));
  options.digest_algorithm = BC_INTEGRITY_DIGEST_ALGORITHM_SHA256;
  options.defer_digest = true;
  options.default_exclude_virtual = false;
  const char *missing_root = "/no/such/root/exists/anywhere";
  bool walk_ok = bc_integrity_walk_run_serial(
      fixture->memory_context, NULL, &options, missing_root,
      strlen(missing_root), entries, errors);
  assert_false(walk_ok);
  bc_containers_vector_destroy(fixture->memory_context, entries);
  bc_runtime_error_collector_destroy(fixture->memory_context, errors);
}

static void test_walk_serial_virtual_root_blocked(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  bc_runtime_error_collector_t *errors = NULL;
  assert_true(bc_runtime_error_collector_create(fixture->memory_context,
                                                &errors));
  bc_containers_vector_t *entries = NULL;
  assert_true(bc_containers_vector_create(fixture->memory_context,
                                          sizeof(bc_integrity_entry_t), 16, 256,
                                          &entries));
  bc_integrity_manifest_options_t options;
  bc_core_zero(&options, sizeof(options));
  options.digest_algorithm = BC_INTEGRITY_DIGEST_ALGORITHM_SHA256;
  options.defer_digest = true;
  options.default_exclude_virtual = true;
  const char *root = "/proc";
  bool walk_ok = bc_integrity_walk_run_serial(
      fixture->memory_context, NULL, &options, root, strlen(root), entries,
      errors);
  assert_false(walk_ok);
  bc_containers_vector_destroy(fixture->memory_context, entries);
  bc_runtime_error_collector_destroy(fixture->memory_context, errors);
}

/* === verify_run.c via fork+exec, additional paths === */

static void test_verify_meta_only_mtime_change(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  assert_int_equal(cov_run_manifest_args(fixture->fixture_directory,
                                         fixture->manifest_path, NULL, 0),
                   0);
  char file_a[512];
  snprintf(file_a, sizeof(file_a), "%s/file_a.txt",
           fixture->fixture_directory);
  struct timespec times[2];
  times[0].tv_sec = 1234567890;
  times[0].tv_nsec = 0;
  times[1].tv_sec = 1234567890;
  times[1].tv_nsec = 0;
  utimensat(AT_FDCWD, file_a, times, 0);
  const char *args[] = {"verify",
                        "--mode=meta",
                        "--default-exclude-virtual=false",
                        fixture->fixture_directory,
                        fixture->manifest_path};
  int rc = cov_run_with_args(args, 5, NULL, 0, NULL, 0);
  assert_int_equal(rc, 1);
}

static void test_verify_zero_changes_json(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  assert_int_equal(cov_run_manifest_args(fixture->fixture_directory,
                                         fixture->manifest_path, NULL, 0),
                   0);
  const char *args[] = {"verify",
                        "--mode=strict",
                        "--format=json",
                        "--default-exclude-virtual=false",
                        fixture->fixture_directory,
                        fixture->manifest_path};
  char output[16384];
  int rc = cov_run_with_args(args, 6, output, sizeof(output), NULL, 0);
  assert_int_equal(rc, 0);
  assert_non_null(strstr(output, "\"changes_total\":0"));
}

static void test_verify_many_entries_consistent(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  for (size_t index = 0; index < 25; ++index) {
    char path[600];
    snprintf(path, sizeof(path), "%s/file_%02zu.txt",
             fixture->fixture_directory, index);
    char content[64];
    snprintf(content, sizeof(content), "content-%zu", index);
    cov_write_file(path, content);
  }
  assert_int_equal(cov_run_manifest_args(fixture->fixture_directory,
                                         fixture->manifest_path, NULL, 0),
                   0);
  const char *args[] = {"verify",
                        "--mode=strict",
                        "--default-exclude-virtual=false",
                        fixture->fixture_directory,
                        fixture->manifest_path};
  int rc = cov_run_with_args(args, 5, NULL, 0, NULL, 0);
  assert_int_equal(rc, 0);
}

static void test_verify_path_prefix_relation(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  char path[512];
  snprintf(path, sizeof(path), "%s/foo", fixture->fixture_directory);
  cov_write_file(path, "alpha");
  snprintf(path, sizeof(path), "%s/foobar", fixture->fixture_directory);
  cov_write_file(path, "beta");
  snprintf(path, sizeof(path), "%s/foobarbaz", fixture->fixture_directory);
  cov_write_file(path, "gamma");
  assert_int_equal(cov_run_manifest_args(fixture->fixture_directory,
                                         fixture->manifest_path, NULL, 0),
                   0);
  const char *args[] = {"verify",
                        "--mode=strict",
                        "--default-exclude-virtual=false",
                        fixture->fixture_directory,
                        fixture->manifest_path};
  int rc = cov_run_with_args(args, 5, NULL, 0, NULL, 0);
  assert_int_equal(rc, 0);
}

static void test_verify_socket_entry_in_manifest(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  char socket_path[512];
  snprintf(socket_path, sizeof(socket_path), "%s/mysock",
           fixture->fixture_directory);
  int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sfd < 0) {
    skip();
    return;
  }
  struct {
    sa_family_t family;
    char path[108];
  } addr;
  memset(&addr, 0, sizeof(addr));
  addr.family = AF_UNIX;
  size_t socket_path_length = strlen(socket_path);
  if (socket_path_length >= sizeof(addr.path)) {
    close(sfd);
    skip();
    return;
  }
  memcpy(addr.path, socket_path, socket_path_length);
  addr.path[socket_path_length] = '\0';
  if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(sfd);
    skip();
    return;
  }
  close(sfd);
  char *m_argv[16];
  size_t cursor = 0;
  m_argv[cursor++] = (char *)BC_INTEGRITY_TEST_BINARY_PATH;
  m_argv[cursor++] = (char *)"manifest";
  m_argv[cursor++] = (char *)"--include-special";
  char output_arg[512];
  snprintf(output_arg, sizeof(output_arg), "--output=%s",
           fixture->manifest_path);
  m_argv[cursor++] = output_arg;
  m_argv[cursor++] = (char *)"--default-exclude-virtual=false";
  m_argv[cursor++] = (char *)fixture->fixture_directory;
  m_argv[cursor] = NULL;
  int rc = cov_run_collect(m_argv, NULL, 0, NULL, 0);
  assert_int_equal(rc, 0);

  const char *args[] = {"verify",
                        "--mode=meta",
                        "--include-special",
                        "--default-exclude-virtual=false",
                        fixture->fixture_directory,
                        fixture->manifest_path};
  rc = cov_run_with_args(args, 6, NULL, 0, NULL, 0);
  assert_int_equal(rc, 0);
  unlink(socket_path);
}

static void test_verify_fifo_entry_in_manifest(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  char fifo_path[512];
  snprintf(fifo_path, sizeof(fifo_path), "%s/myfifo",
           fixture->fixture_directory);
  if (mkfifo(fifo_path, 0644) != 0) {
    skip();
    return;
  }
  char *m_argv[16];
  size_t cursor = 0;
  m_argv[cursor++] = (char *)BC_INTEGRITY_TEST_BINARY_PATH;
  m_argv[cursor++] = (char *)"manifest";
  m_argv[cursor++] = (char *)"--include-special";
  char output_arg[512];
  snprintf(output_arg, sizeof(output_arg), "--output=%s",
           fixture->manifest_path);
  m_argv[cursor++] = output_arg;
  m_argv[cursor++] = (char *)"--default-exclude-virtual=false";
  m_argv[cursor++] = (char *)fixture->fixture_directory;
  m_argv[cursor] = NULL;
  int rc = cov_run_collect(m_argv, NULL, 0, NULL, 0);
  assert_int_equal(rc, 0);

  const char *args[] = {"verify",
                        "--mode=meta",
                        "--include-special",
                        "--default-exclude-virtual=false",
                        fixture->fixture_directory,
                        fixture->manifest_path};
  rc = cov_run_with_args(args, 6, NULL, 0, NULL, 0);
  assert_int_equal(rc, 0);
}

static void test_verify_entry_removed_from_filesystem(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  char extra[512];
  snprintf(extra, sizeof(extra), "%s/extra_to_remove.txt",
           fixture->fixture_directory);
  cov_write_file(extra, "to-be-removed");
  assert_int_equal(cov_run_manifest_args(fixture->fixture_directory,
                                         fixture->manifest_path, NULL, 0),
                   0);
  unlink(extra);
  const char *args[] = {"verify",
                        "--mode=strict",
                        "--default-exclude-virtual=false",
                        fixture->fixture_directory,
                        fixture->manifest_path};
  int rc = cov_run_with_args(args, 5, NULL, 0, NULL, 0);
  assert_int_equal(rc, 1);
}

/* === cli_spec.c bind_*_options error paths === */

static void test_cli_bind_manifest_missing_threads_returns_false(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  bc_runtime_config_store_t *store = NULL;
  assert_true(bc_runtime_config_store_create(fixture->memory_context, &store));
  bc_runtime_cli_parsed_t parsed;
  memset(&parsed, 0, sizeof(parsed));
  bc_integrity_manifest_options_t options;
  assert_false(bc_integrity_cli_bind_manifest_options(store, &parsed, &options));
  bc_runtime_config_store_destroy(fixture->memory_context, store);
}

static void test_cli_bind_verify_missing_threads_returns_false(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  bc_runtime_config_store_t *store = NULL;
  assert_true(bc_runtime_config_store_create(fixture->memory_context, &store));
  bc_runtime_cli_parsed_t parsed;
  memset(&parsed, 0, sizeof(parsed));
  bc_integrity_verify_options_t options;
  assert_false(bc_integrity_cli_bind_verify_options(store, &parsed, &options));
  bc_runtime_config_store_destroy(fixture->memory_context, store);
}

static void test_cli_bind_diff_missing_format_returns_false(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  bc_runtime_config_store_t *store = NULL;
  assert_true(bc_runtime_config_store_create(fixture->memory_context, &store));
  bc_runtime_cli_parsed_t parsed;
  memset(&parsed, 0, sizeof(parsed));
  bc_integrity_diff_options_t options;
  assert_false(bc_integrity_cli_bind_diff_options(store, &parsed, &options));
  bc_runtime_config_store_destroy(fixture->memory_context, store);
}

static void test_cli_bind_manifest_via_full_parse_succeeds(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  bc_runtime_config_store_t *store = NULL;
  assert_true(bc_runtime_config_store_create(fixture->memory_context, &store));
  const bc_runtime_cli_program_spec_t *spec = bc_integrity_cli_program_spec();
  const char *argv[] = {"bc-integrity", "manifest",
                        "--output=/tmp/dummy.hrbl", "/tmp"};
  bc_runtime_cli_parsed_t parsed;
  bc_runtime_cli_parse_status_t status =
      bc_runtime_cli_parse(spec, 4, argv, store, &parsed, stderr);
  assert_int_equal(status, BC_RUNTIME_CLI_PARSE_OK);
  bc_integrity_manifest_options_t options;
  assert_true(bc_integrity_cli_bind_manifest_options(store, &parsed, &options));
  assert_string_equal(options.output_path, "/tmp/dummy.hrbl");
  assert_string_equal(options.root_path, "/tmp");
  bc_runtime_config_store_destroy(fixture->memory_context, store);
}

static void test_cli_bind_verify_via_full_parse_succeeds(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  bc_runtime_config_store_t *store = NULL;
  assert_true(bc_runtime_config_store_create(fixture->memory_context, &store));
  const bc_runtime_cli_program_spec_t *spec = bc_integrity_cli_program_spec();
  const char *argv[] = {"bc-integrity", "verify", "--mode=strict", "/tmp",
                        "/tmp/m.hrbl"};
  bc_runtime_cli_parsed_t parsed;
  bc_runtime_cli_parse_status_t status =
      bc_runtime_cli_parse(spec, 5, argv, store, &parsed, stderr);
  assert_int_equal(status, BC_RUNTIME_CLI_PARSE_OK);
  bc_integrity_verify_options_t options;
  assert_true(bc_integrity_cli_bind_verify_options(store, &parsed, &options));
  assert_int_equal(options.mode, BC_INTEGRITY_VERIFY_MODE_STRICT);
  bc_runtime_config_store_destroy(fixture->memory_context, store);
}

static void test_cli_bind_diff_via_full_parse_succeeds(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  bc_runtime_config_store_t *store = NULL;
  assert_true(bc_runtime_config_store_create(fixture->memory_context, &store));
  const bc_runtime_cli_program_spec_t *spec = bc_integrity_cli_program_spec();
  const char *argv[] = {"bc-integrity", "diff", "--format=json",
                        "/tmp/a.hrbl", "/tmp/b.hrbl"};
  bc_runtime_cli_parsed_t parsed;
  bc_runtime_cli_parse_status_t status =
      bc_runtime_cli_parse(spec, 5, argv, store, &parsed, stderr);
  assert_int_equal(status, BC_RUNTIME_CLI_PARSE_OK);
  bc_integrity_diff_options_t options;
  assert_true(bc_integrity_cli_bind_diff_options(store, &parsed, &options));
  assert_int_equal(options.format, BC_INTEGRITY_OUTPUT_FORMAT_JSON);
  bc_runtime_config_store_destroy(fixture->memory_context, store);
}

static void test_cli_program_spec_diff_options_complete(void **state) {
  (void)state;
  const bc_runtime_cli_program_spec_t *spec = bc_integrity_cli_program_spec();
  const bc_runtime_cli_command_spec_t *diff = NULL;
  for (size_t index = 0; index < spec->command_count; ++index) {
    if (strcmp(spec->commands[index].name, "diff") == 0) {
      diff = &spec->commands[index];
      break;
    }
  }
  assert_non_null(diff);
  assert_int_equal(diff->positional_min, 2u);
  assert_int_equal(diff->positional_max, 2u);
  bool found_format = false;
  bool found_ignore_meta = false;
  bool found_ignore_mtime = false;
  for (size_t index = 0; index < diff->option_count; ++index) {
    const char *name = diff->options[index].long_name;
    if (strcmp(name, "format") == 0) {
      found_format = true;
    } else if (strcmp(name, "ignore-meta") == 0) {
      found_ignore_meta = true;
    } else if (strcmp(name, "ignore-mtime") == 0) {
      found_ignore_mtime = true;
    }
  }
  assert_true(found_format);
  assert_true(found_ignore_meta);
  assert_true(found_ignore_mtime);
}

static void test_cli_bind_manifest_invalid_threads_emits_invalid(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  bc_runtime_config_store_t *store = NULL;
  assert_true(bc_runtime_config_store_create(fixture->memory_context, &store));
  const bc_runtime_cli_program_spec_t *spec = bc_integrity_cli_program_spec();
  const char *argv[] = {"bc-integrity", "--threads=invalid_word", "manifest",
                        "--output=/tmp/dummy.hrbl", "/tmp"};
  bc_runtime_cli_parsed_t parsed;
  bc_runtime_cli_parse_status_t status =
      bc_runtime_cli_parse(spec, 5, argv, store, &parsed, stderr);
  assert_int_equal(status, BC_RUNTIME_CLI_PARSE_OK);
  bc_integrity_manifest_options_t options;
  assert_false(bc_integrity_cli_bind_manifest_options(store, &parsed, &options));
  bc_runtime_config_store_destroy(fixture->memory_context, store);
}

static void test_cli_bind_verify_invalid_threads_emits_invalid(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  bc_runtime_config_store_t *store = NULL;
  assert_true(bc_runtime_config_store_create(fixture->memory_context, &store));
  const bc_runtime_cli_program_spec_t *spec = bc_integrity_cli_program_spec();
  const char *argv[] = {"bc-integrity", "--threads=garbage", "verify", "/tmp",
                        "/tmp/m.hrbl"};
  bc_runtime_cli_parsed_t parsed;
  bc_runtime_cli_parse_status_t status =
      bc_runtime_cli_parse(spec, 5, argv, store, &parsed, stderr);
  assert_int_equal(status, BC_RUNTIME_CLI_PARSE_OK);
  bc_integrity_verify_options_t options;
  assert_false(bc_integrity_cli_bind_verify_options(store, &parsed, &options));
  bc_runtime_config_store_destroy(fixture->memory_context, store);
}

static void test_cli_bind_manifest_too_few_positional(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  bc_runtime_config_store_t *store = NULL;
  assert_true(bc_runtime_config_store_create(fixture->memory_context, &store));
  const bc_runtime_cli_program_spec_t *spec = bc_integrity_cli_program_spec();
  const char *argv[] = {"bc-integrity", "manifest", "--output=/tmp/dummy.hrbl",
                        "/tmp"};
  bc_runtime_cli_parsed_t parsed;
  bc_runtime_cli_parse_status_t status =
      bc_runtime_cli_parse(spec, 4, argv, store, &parsed, stderr);
  assert_int_equal(status, BC_RUNTIME_CLI_PARSE_OK);
  parsed.positional_count = 0;
  bc_integrity_manifest_options_t options;
  assert_false(bc_integrity_cli_bind_manifest_options(store, &parsed, &options));
  bc_runtime_config_store_destroy(fixture->memory_context, store);
}

static void test_cli_bind_verify_too_few_positional(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  bc_runtime_config_store_t *store = NULL;
  assert_true(bc_runtime_config_store_create(fixture->memory_context, &store));
  const bc_runtime_cli_program_spec_t *spec = bc_integrity_cli_program_spec();
  const char *argv[] = {"bc-integrity", "verify", "/tmp", "/tmp/m.hrbl"};
  bc_runtime_cli_parsed_t parsed;
  bc_runtime_cli_parse_status_t status =
      bc_runtime_cli_parse(spec, 4, argv, store, &parsed, stderr);
  assert_int_equal(status, BC_RUNTIME_CLI_PARSE_OK);
  parsed.positional_count = 1;
  bc_integrity_verify_options_t options;
  assert_false(bc_integrity_cli_bind_verify_options(store, &parsed, &options));
  bc_runtime_config_store_destroy(fixture->memory_context, store);
}

static void test_cli_bind_diff_too_few_positional(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  bc_runtime_config_store_t *store = NULL;
  assert_true(bc_runtime_config_store_create(fixture->memory_context, &store));
  const bc_runtime_cli_program_spec_t *spec = bc_integrity_cli_program_spec();
  const char *argv[] = {"bc-integrity", "diff", "/tmp/a.hrbl", "/tmp/b.hrbl"};
  bc_runtime_cli_parsed_t parsed;
  bc_runtime_cli_parse_status_t status =
      bc_runtime_cli_parse(spec, 4, argv, store, &parsed, stderr);
  assert_int_equal(status, BC_RUNTIME_CLI_PARSE_OK);
  parsed.positional_count = 1;
  bc_integrity_diff_options_t options;
  assert_false(bc_integrity_cli_bind_diff_options(store, &parsed, &options));
  bc_runtime_config_store_destroy(fixture->memory_context, store);
}

static void test_cli_bind_manifest_with_include_exclude_lists(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  bc_runtime_config_store_t *store = NULL;
  assert_true(bc_runtime_config_store_create(fixture->memory_context, &store));
  const bc_runtime_cli_program_spec_t *spec = bc_integrity_cli_program_spec();
  const char *argv[] = {"bc-integrity",
                        "manifest",
                        "--output=/tmp/dummy.hrbl",
                        "--include=*.txt",
                        "--exclude=junk.bin",
                        "--include-hidden",
                        "--follow-symlinks",
                        "/tmp"};
  bc_runtime_cli_parsed_t parsed;
  bc_runtime_cli_parse_status_t status =
      bc_runtime_cli_parse(spec, 8, argv, store, &parsed, stderr);
  assert_int_equal(status, BC_RUNTIME_CLI_PARSE_OK);
  bc_integrity_manifest_options_t options;
  assert_true(bc_integrity_cli_bind_manifest_options(store, &parsed, &options));
  assert_non_null(options.include_list);
  assert_non_null(options.exclude_list);
  assert_true(options.include_hidden);
  assert_true(options.follow_symlinks);
  bc_runtime_config_store_destroy(fixture->memory_context, store);
}

static void test_cli_bind_verify_with_include_exclude_lists(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  bc_runtime_config_store_t *store = NULL;
  assert_true(bc_runtime_config_store_create(fixture->memory_context, &store));
  const bc_runtime_cli_program_spec_t *spec = bc_integrity_cli_program_spec();
  const char *argv[] = {"bc-integrity",
                        "verify",
                        "--mode=meta",
                        "--format=json",
                        "--include=*.txt",
                        "--exclude=junk.bin",
                        "--exit-on-first",
                        "/tmp",
                        "/tmp/m.hrbl"};
  bc_runtime_cli_parsed_t parsed;
  bc_runtime_cli_parse_status_t status =
      bc_runtime_cli_parse(spec, 9, argv, store, &parsed, stderr);
  assert_int_equal(status, BC_RUNTIME_CLI_PARSE_OK);
  bc_integrity_verify_options_t options;
  assert_true(bc_integrity_cli_bind_verify_options(store, &parsed, &options));
  assert_int_equal(options.mode, BC_INTEGRITY_VERIFY_MODE_META);
  assert_int_equal(options.format, BC_INTEGRITY_OUTPUT_FORMAT_JSON);
  assert_true(options.exit_on_first);
  assert_non_null(options.include_list);
  assert_non_null(options.exclude_list);
  bc_runtime_config_store_destroy(fixture->memory_context, store);
}

static void test_cli_bind_diff_with_ignore_flags(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  bc_runtime_config_store_t *store = NULL;
  assert_true(bc_runtime_config_store_create(fixture->memory_context, &store));
  const bc_runtime_cli_program_spec_t *spec = bc_integrity_cli_program_spec();
  const char *argv[] = {"bc-integrity",  "diff",          "--format=text",
                        "--ignore-meta", "--ignore-mtime", "/tmp/a.hrbl",
                        "/tmp/b.hrbl"};
  bc_runtime_cli_parsed_t parsed;
  bc_runtime_cli_parse_status_t status =
      bc_runtime_cli_parse(spec, 7, argv, store, &parsed, stderr);
  assert_int_equal(status, BC_RUNTIME_CLI_PARSE_OK);
  bc_integrity_diff_options_t options;
  assert_true(bc_integrity_cli_bind_diff_options(store, &parsed, &options));
  assert_true(options.ignore_meta);
  assert_true(options.ignore_mtime);
  bc_runtime_config_store_destroy(fixture->memory_context, store);
}

static void test_main_diff_format_json_with_changes(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  assert_int_equal(cov_run_manifest_args(fixture->fixture_directory,
                                         fixture->manifest_path, NULL, 0),
                   0);
  char path[512];
  snprintf(path, sizeof(path), "%s/file_a.txt", fixture->fixture_directory);
  cov_write_file(path, "modified-content");
  assert_int_equal(cov_run_manifest_args(fixture->fixture_directory,
                                         fixture->manifest_path_b, NULL, 0),
                   0);
  const char *args[] = {"diff", "--format=json", fixture->manifest_path,
                        fixture->manifest_path_b};
  char output[16384];
  int rc = cov_run_with_args(args, 4, output, sizeof(output), NULL, 0);
  assert_int_equal(rc, 1);
  assert_non_null(strstr(output, "\"changes_total\":"));
}

static void test_main_diff_ignore_meta_zero(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  assert_int_equal(cov_run_manifest_args(fixture->fixture_directory,
                                         fixture->manifest_path, NULL, 0),
                   0);
  char path[512];
  snprintf(path, sizeof(path), "%s/file_a.txt", fixture->fixture_directory);
  chmod(path, 0600);
  assert_int_equal(cov_run_manifest_args(fixture->fixture_directory,
                                         fixture->manifest_path_b, NULL, 0),
                   0);
  const char *args[] = {"diff", "--ignore-meta", fixture->manifest_path,
                        fixture->manifest_path_b};
  int rc = cov_run_with_args(args, 4, NULL, 0, NULL, 0);
  assert_int_equal(rc, 0);
}

static void test_main_diff_with_text_format_explicit(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  assert_int_equal(cov_run_manifest_args(fixture->fixture_directory,
                                         fixture->manifest_path, NULL, 0),
                   0);
  assert_int_equal(cov_run_manifest_args(fixture->fixture_directory,
                                         fixture->manifest_path_b, NULL, 0),
                   0);
  const char *args[] = {"diff", "--format=text", fixture->manifest_path,
                        fixture->manifest_path_b};
  int rc = cov_run_with_args(args, 4, NULL, 0, NULL, 0);
  assert_int_equal(rc, 0);
}

static void test_main_diff_invalid_manifest_a_exits_two(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  cov_write_file(fixture->manifest_path, "not a manifest");
  assert_int_equal(cov_run_manifest_args(fixture->fixture_directory,
                                         fixture->manifest_path_b, NULL, 0),
                   0);
  const char *args[] = {"diff", fixture->manifest_path, fixture->manifest_path_b};
  int rc = cov_run_with_args(args, 3, NULL, 0, NULL, 0);
  assert_int_equal(rc, 2);
}

static void test_main_verify_invalid_mode_exits_two(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  assert_int_equal(cov_run_manifest_args(fixture->fixture_directory,
                                         fixture->manifest_path, NULL, 0),
                   0);
  const char *args[] = {"verify", "--mode=loose", fixture->fixture_directory,
                        fixture->manifest_path};
  int rc = cov_run_with_args(args, 4, NULL, 0, NULL, 0);
  assert_int_equal(rc, 2);
}

static void test_main_verify_invalid_format_exits_two(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  assert_int_equal(cov_run_manifest_args(fixture->fixture_directory,
                                         fixture->manifest_path, NULL, 0),
                   0);
  const char *args[] = {"verify", "--format=xml", fixture->fixture_directory,
                        fixture->manifest_path};
  int rc = cov_run_with_args(args, 4, NULL, 0, NULL, 0);
  assert_int_equal(rc, 2);
}

static void test_main_verify_invalid_threads_exits_two(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  assert_int_equal(cov_run_manifest_args(fixture->fixture_directory,
                                         fixture->manifest_path, NULL, 0),
                   0);
  const char *args[] = {"--threads=banana",
                        "verify",
                        "--default-exclude-virtual=false",
                        fixture->fixture_directory,
                        fixture->manifest_path};
  int rc = cov_run_with_args(args, 5, NULL, 0, NULL, 0);
  assert_int_equal(rc, 2);
}

static void test_main_diff_invalid_format_exits_two(void **state) {
  coverage_d_fixture_t *fixture = (coverage_d_fixture_t *)*state;
  cov_build_basic_tree(fixture->fixture_directory);
  assert_int_equal(cov_run_manifest_args(fixture->fixture_directory,
                                         fixture->manifest_path, NULL, 0),
                   0);
  assert_int_equal(cov_run_manifest_args(fixture->fixture_directory,
                                         fixture->manifest_path_b, NULL, 0),
                   0);
  const char *args[] = {"diff", "--format=xml", fixture->manifest_path,
                        fixture->manifest_path_b};
  int rc = cov_run_with_args(args, 4, NULL, 0, NULL, 0);
  assert_int_equal(rc, 2);
}

static void test_cli_program_spec_verify_options_complete(void **state) {
  (void)state;
  const bc_runtime_cli_program_spec_t *spec = bc_integrity_cli_program_spec();
  const bc_runtime_cli_command_spec_t *verify = NULL;
  for (size_t index = 0; index < spec->command_count; ++index) {
    if (strcmp(spec->commands[index].name, "verify") == 0) {
      verify = &spec->commands[index];
      break;
    }
  }
  assert_non_null(verify);
  assert_int_equal(verify->positional_min, 2u);
  assert_int_equal(verify->positional_max, 2u);
  bool found_mode = false;
  bool found_format = false;
  bool found_exit_on_first = false;
  for (size_t index = 0; index < verify->option_count; ++index) {
    const char *name = verify->options[index].long_name;
    if (strcmp(name, "mode") == 0) {
      found_mode = true;
    } else if (strcmp(name, "format") == 0) {
      found_format = true;
    } else if (strcmp(name, "exit-on-first") == 0) {
      found_exit_on_first = true;
    }
  }
  assert_true(found_mode);
  assert_true(found_format);
  assert_true(found_exit_on_first);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test_setup_teardown(test_main_help_global_exit_zero,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_main_help_per_subcommand,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_main_version_exit_zero,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_main_unknown_subcommand_exits_two,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_main_no_subcommand_exits_two,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_main_manifest_threads_zero_singlethreaded,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_main_manifest_threads_one,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_main_manifest_threads_auto_io,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(
          test_main_manifest_threads_exceeds_logical, coverage_d_setup,
          coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_main_manifest_digest_xxh3,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_main_manifest_digest_xxh128,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_main_manifest_with_include_glob,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_main_manifest_with_exclude_glob,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_main_manifest_include_hidden,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_main_manifest_follow_symlinks,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(
          test_main_manifest_root_inexistent_exits_one, coverage_d_setup,
          coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_main_manifest_root_is_file_exits_one,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(
          test_main_manifest_missing_output_arg_exits_two, coverage_d_setup,
          coverage_d_teardown),
      cmocka_unit_test_setup_teardown(
          test_main_manifest_extra_positional_exits_two, coverage_d_setup,
          coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_main_diff_missing_args_exits_two,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_main_diff_one_arg_exits_two,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(
          test_main_diff_two_identical_manifests_exits_zero, coverage_d_setup,
          coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_main_verify_missing_args_exits_two,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_main_invalid_threads_value_exits_two,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(
          test_main_invalid_digest_algorithm_exits_two, coverage_d_setup,
          coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_main_verify_threads_zero_singlethreaded,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_main_verify_meta_mode_no_rehash,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(
          test_main_verify_content_mode_compares_only_digest, coverage_d_setup,
          coverage_d_teardown),

      cmocka_unit_test(test_meta_kind_change_branch),
      cmocka_unit_test(test_meta_size_change_branch),
      cmocka_unit_test(test_meta_gid_change_branch),
      cmocka_unit_test(test_meta_mtime_sec_change_branch),
      cmocka_unit_test(test_meta_mtime_nsec_change_branch),
      cmocka_unit_test(test_meta_nlink_change_branch),
      cmocka_unit_test(test_meta_link_target_change_branch),
      cmocka_unit_test(test_meta_link_target_length_diff_branch),
      cmocka_unit_test(test_meta_link_target_zero_length_equal_branch),

      cmocka_unit_test(test_strict_meta_only_change),
      cmocka_unit_test(test_strict_content_only_change),
      cmocka_unit_test(test_strict_both_meta_and_content_change),
      cmocka_unit_test(test_strict_no_change_returns_none),
      cmocka_unit_test(test_strict_kind_change),
      cmocka_unit_test(test_strict_uid_change),
      cmocka_unit_test(test_strict_gid_change),
      cmocka_unit_test(test_strict_size_change),
      cmocka_unit_test(test_strict_inode_change),
      cmocka_unit_test(test_strict_nlink_change),
      cmocka_unit_test(test_strict_mtime_sec_change),
      cmocka_unit_test(test_strict_mtime_nsec_change),
      cmocka_unit_test(test_strict_link_target_change),
      cmocka_unit_test(test_content_digest_length_differ),
      cmocka_unit_test(test_content_kind_differ),
      cmocka_unit_test(test_content_zero_length_returns_none),

      cmocka_unit_test_setup_teardown(test_diff_kind_change_file_to_dir,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_diff_ignore_mtime_only_mtime_diff_zero,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_diff_invalid_manifest_b_returns_two,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_diff_json_format_added_only,
                                      coverage_d_setup, coverage_d_teardown),

      cmocka_unit_test_setup_teardown(test_writer_path_with_dot_prefix_uses_quoting,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_writer_path_with_slash_uses_quoting,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_writer_path_simple_no_quoting,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_writer_summary_with_walltime_set,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_writer_with_no_host_uses_unknown,
                                      coverage_d_setup, coverage_d_teardown),

      cmocka_unit_test_setup_teardown(test_capture_empty_file,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_capture_broken_symlink,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_capture_compute_digest_unreadable_file,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test(test_capture_set_error_message_basic),
      cmocka_unit_test(test_capture_kind_name_round_trip_all_kinds),
      cmocka_unit_test_setup_teardown(test_capture_fifo_kind_via_stat,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_capture_socket_kind_via_stat,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_capture_long_link_target,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_capture_compute_digest_missing_file,
                                      coverage_d_setup, coverage_d_teardown),

      cmocka_unit_test_setup_teardown(test_walk_serial_with_include_filter,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_walk_serial_with_exclude_filter,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_walk_serial_with_include_special,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_walk_serial_with_hidden_dir_skipped,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(
          test_walk_serial_root_inexistent_returns_false, coverage_d_setup,
          coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_walk_serial_virtual_root_blocked,
                                      coverage_d_setup, coverage_d_teardown),

      cmocka_unit_test_setup_teardown(test_verify_meta_only_mtime_change,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_verify_zero_changes_json,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_verify_many_entries_consistent,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_verify_path_prefix_relation,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_verify_socket_entry_in_manifest,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_verify_fifo_entry_in_manifest,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_verify_entry_removed_from_filesystem,
                                      coverage_d_setup, coverage_d_teardown),

      cmocka_unit_test_setup_teardown(
          test_cli_bind_manifest_missing_threads_returns_false,
          coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(
          test_cli_bind_verify_missing_threads_returns_false, coverage_d_setup,
          coverage_d_teardown),
      cmocka_unit_test_setup_teardown(
          test_cli_bind_diff_missing_format_returns_false, coverage_d_setup,
          coverage_d_teardown),
      cmocka_unit_test_setup_teardown(
          test_cli_bind_manifest_via_full_parse_succeeds, coverage_d_setup,
          coverage_d_teardown),
      cmocka_unit_test_setup_teardown(
          test_cli_bind_verify_via_full_parse_succeeds, coverage_d_setup,
          coverage_d_teardown),
      cmocka_unit_test_setup_teardown(
          test_cli_bind_diff_via_full_parse_succeeds, coverage_d_setup,
          coverage_d_teardown),
      cmocka_unit_test(test_cli_program_spec_diff_options_complete),
      cmocka_unit_test(test_cli_program_spec_verify_options_complete),

      cmocka_unit_test_setup_teardown(
          test_cli_bind_manifest_invalid_threads_emits_invalid,
          coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(
          test_cli_bind_verify_invalid_threads_emits_invalid, coverage_d_setup,
          coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_cli_bind_manifest_too_few_positional,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_cli_bind_verify_too_few_positional,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_cli_bind_diff_too_few_positional,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(
          test_cli_bind_manifest_with_include_exclude_lists, coverage_d_setup,
          coverage_d_teardown),
      cmocka_unit_test_setup_teardown(
          test_cli_bind_verify_with_include_exclude_lists, coverage_d_setup,
          coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_cli_bind_diff_with_ignore_flags,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_main_diff_format_json_with_changes,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_main_diff_ignore_meta_zero,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_main_diff_with_text_format_explicit,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_main_diff_invalid_manifest_a_exits_two,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_main_verify_invalid_mode_exits_two,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_main_verify_invalid_format_exits_two,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_main_verify_invalid_threads_exits_two,
                                      coverage_d_setup, coverage_d_teardown),
      cmocka_unit_test_setup_teardown(test_main_diff_invalid_format_exits_two,
                                      coverage_d_setup, coverage_d_teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
