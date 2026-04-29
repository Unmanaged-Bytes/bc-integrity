// SPDX-License-Identifier: MIT

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include <stdbool.h>
#include <stdint.h>

#include "bc_core_io.h"
#include "bc_integrity_entry_internal.h"
#include "bc_integrity_verify_internal.h"

#define BUFFER_SIZE ((size_t)4096)

static void init_writer(bc_core_writer_t *writer, char *buffer, size_t size) {
  memset(buffer, 0, size);
  assert_true(bc_core_writer_init_buffer_only(writer, buffer, size));
}

static void make_snapshot(bc_integrity_meta_snapshot_t *snap) {
  memset(snap, 0, sizeof(*snap));
  snap->present = true;
  snap->kind = BC_INTEGRITY_ENTRY_KIND_FILE;
  snap->size_bytes = 1024;
  snap->mode = 0644;
  snap->uid = 1000;
  snap->gid = 1000;
  snap->mtime_sec = 1700000000;
  snap->mtime_nsec = 12345;
  snap->inode = 42;
  snap->nlink = 1;
  snap->digest_hex = "";
  snap->digest_hex_length = 0;
  snap->link_target = "";
  snap->link_target_length = 0;
}

static void test_emit_text_added_removed_content(void **state) {
  (void)state;
  struct {
    bc_integrity_verify_change_kind_t kind;
    const char *expected;
    size_t length;
  } cases[] = {
      {BC_INTEGRITY_VERIFY_CHANGE_ADDED, "+ new.txt\n", 10},
      {BC_INTEGRITY_VERIFY_CHANGE_REMOVED, "- new.txt\n", 10},
      {BC_INTEGRITY_VERIFY_CHANGE_CONTENT, "~c new.txt\n", 11},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    char buffer[BUFFER_SIZE];
    bc_core_writer_t writer;
    init_writer(&writer, buffer, sizeof(buffer));
    assert_true(bc_integrity_verify_emit_change_text(
        &writer, cases[i].kind, "new.txt", 7, NULL, NULL));
    const char *data = NULL;
    size_t length = 0;
    assert_true(bc_core_writer_buffer_data(&writer, &data, &length));
    assert_int_equal(length, cases[i].length);
    assert_memory_equal(data, cases[i].expected, cases[i].length);
    (void)bc_core_writer_destroy(&writer);
  }
}

static void test_emit_text_meta_all_uint_fields(void **state) {
  (void)state;
  char buffer[BUFFER_SIZE];
  bc_core_writer_t writer;
  init_writer(&writer, buffer, sizeof(buffer));

  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  make_snapshot(&expected);
  make_snapshot(&actual);
  actual.mode = 0755;
  actual.uid = 1001;
  actual.gid = 1002;
  actual.mtime_sec = 1700000001;
  actual.mtime_nsec = 99999;
  actual.size_bytes = 2048;
  actual.inode = 43;
  actual.nlink = 2;

  assert_true(bc_integrity_verify_emit_change_text(
      &writer, BC_INTEGRITY_VERIFY_CHANGE_META, "p.bin", 5, &expected,
      &actual));

  const char *data = NULL;
  size_t length = 0;
  assert_true(bc_core_writer_buffer_data(&writer, &data, &length));
  assert_non_null(strstr(data, "mode: "));
  assert_non_null(strstr(data, "uid: "));
  assert_non_null(strstr(data, "gid: "));
  assert_non_null(strstr(data, "mtime_sec: "));
  assert_non_null(strstr(data, "mtime_nsec: "));
  assert_non_null(strstr(data, "size_bytes: "));
  assert_non_null(strstr(data, "ino: "));
  assert_non_null(strstr(data, "nlink: "));
  (void)bc_core_writer_destroy(&writer);
}

static void test_emit_text_meta_link_targets(void **state) {
  (void)state;
  struct {
    const char *old_value;
    size_t old_length;
    const char *new_value;
    size_t new_length;
    const char *expected_substr;
  } cases[] = {
      {"old/path", 8, "new/path", 8, "link_target: old/path->new/path"},
      {"old/path", 8, "", 0, "link_target: old/path->(none)"},
      {"", 0, "new/path", 8, "link_target: (none)->new/path"},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    char buffer[BUFFER_SIZE];
    bc_core_writer_t writer;
    init_writer(&writer, buffer, sizeof(buffer));
    bc_integrity_meta_snapshot_t expected;
    bc_integrity_meta_snapshot_t actual;
    make_snapshot(&expected);
    make_snapshot(&actual);
    expected.link_target = cases[i].old_value;
    expected.link_target_length = cases[i].old_length;
    actual.link_target = cases[i].new_value;
    actual.link_target_length = cases[i].new_length;

    assert_true(bc_integrity_verify_emit_change_text(
        &writer, BC_INTEGRITY_VERIFY_CHANGE_META, "lnk", 3, &expected,
        &actual));
    const char *data = NULL;
    size_t length = 0;
    assert_true(bc_core_writer_buffer_data(&writer, &data, &length));
    assert_non_null(strstr(data, cases[i].expected_substr));
    (void)bc_core_writer_destroy(&writer);
  }
}

static void test_emit_text_meta_no_diff(void **state) {
  (void)state;
  char buffer[BUFFER_SIZE];
  bc_core_writer_t writer;
  init_writer(&writer, buffer, sizeof(buffer));

  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  make_snapshot(&expected);
  make_snapshot(&actual);

  assert_true(bc_integrity_verify_emit_change_text(
      &writer, BC_INTEGRITY_VERIFY_CHANGE_META, "f.txt", 5, &expected,
      &actual));

  const char *data = NULL;
  size_t length = 0;
  assert_true(bc_core_writer_buffer_data(&writer, &data, &length));
  assert_int_equal(length, 0);
  (void)bc_core_writer_destroy(&writer);
}

static void test_emit_text_null_kinds(void **state) {
  (void)state;
  bc_integrity_verify_change_kind_t kinds[] = {
      BC_INTEGRITY_VERIFY_CHANGE_META, BC_INTEGRITY_VERIFY_CHANGE_NONE};
  for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); ++i) {
    char buffer[BUFFER_SIZE];
    bc_core_writer_t writer;
    init_writer(&writer, buffer, sizeof(buffer));
    assert_true(bc_integrity_verify_emit_change_text(&writer, kinds[i], "x", 1,
                                                     NULL, NULL));
    (void)bc_core_writer_destroy(&writer);
  }
}

static void test_emit_text_both(void **state) {
  (void)state;
  char buffer[BUFFER_SIZE];
  bc_core_writer_t writer;
  init_writer(&writer, buffer, sizeof(buffer));

  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  make_snapshot(&expected);
  make_snapshot(&actual);
  actual.mode = 0700;

  assert_true(bc_integrity_verify_emit_change_text(
      &writer, BC_INTEGRITY_VERIFY_CHANGE_BOTH, "x.bin", 5, &expected,
      &actual));

  const char *data = NULL;
  size_t length = 0;
  assert_true(bc_core_writer_buffer_data(&writer, &data, &length));
  assert_non_null(strstr(data, "~* x.bin\n"));
  assert_non_null(strstr(data, "~m x.bin mode: "));

  init_writer(&writer, buffer, sizeof(buffer));
  assert_true(bc_integrity_verify_emit_change_text(
      &writer, BC_INTEGRITY_VERIFY_CHANGE_BOTH, "x", 1, NULL, NULL));
  (void)bc_core_writer_destroy(&writer);
}

static void test_emit_json_simple_kinds(void **state) {
  (void)state;
  struct {
    bc_integrity_verify_change_kind_t kind;
    const char *label;
  } cases[] = {
      {BC_INTEGRITY_VERIFY_CHANGE_ADDED, "\"change\":\"added\""},
      {BC_INTEGRITY_VERIFY_CHANGE_REMOVED, "\"change\":\"removed\""},
      {BC_INTEGRITY_VERIFY_CHANGE_CONTENT, "\"change\":\"content\""},
      {BC_INTEGRITY_VERIFY_CHANGE_META, "\"change\":\"meta\""},
      {BC_INTEGRITY_VERIFY_CHANGE_BOTH, "\"change\":\"both\""},
      {BC_INTEGRITY_VERIFY_CHANGE_NONE, "\"change\":\"none\""},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    char buffer[BUFFER_SIZE];
    bc_core_writer_t writer;
    init_writer(&writer, buffer, sizeof(buffer));
    assert_true(bc_integrity_verify_emit_change_json(&writer, cases[i].kind,
                                                     "p", 1, NULL, NULL));
    const char *data = NULL;
    size_t length = 0;
    assert_true(bc_core_writer_buffer_data(&writer, &data, &length));
    assert_non_null(strstr(data, cases[i].label));
    (void)bc_core_writer_destroy(&writer);
  }
}

static void test_emit_json_content_with_digest(void **state) {
  (void)state;
  char buffer[BUFFER_SIZE];
  bc_core_writer_t writer;
  init_writer(&writer, buffer, sizeof(buffer));

  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  make_snapshot(&expected);
  make_snapshot(&actual);
  expected.digest_hex = "aaaaaa";
  expected.digest_hex_length = 6;
  actual.digest_hex = "bbbbbb";
  actual.digest_hex_length = 6;

  assert_true(bc_integrity_verify_emit_change_json(
      &writer, BC_INTEGRITY_VERIFY_CHANGE_CONTENT, "x", 1, &expected, &actual));

  const char *data = NULL;
  size_t length = 0;
  assert_true(bc_core_writer_buffer_data(&writer, &data, &length));
  assert_non_null(
      strstr(data, "\"digest\":{\"old\":\"aaaaaa\",\"new\":\"bbbbbb\"}"));
  (void)bc_core_writer_destroy(&writer);
}

static void test_emit_json_meta_uint_fields(void **state) {
  (void)state;
  char buffer[BUFFER_SIZE];
  bc_core_writer_t writer;
  init_writer(&writer, buffer, sizeof(buffer));

  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  make_snapshot(&expected);
  make_snapshot(&actual);
  actual.mode = 0700;
  actual.uid = 1001;
  actual.gid = 1002;
  actual.mtime_sec = 1700000001;
  actual.mtime_nsec = 99999;
  actual.size_bytes = 2048;
  actual.inode = 43;
  actual.nlink = 2;

  assert_true(bc_integrity_verify_emit_change_json(
      &writer, BC_INTEGRITY_VERIFY_CHANGE_META, "p", 1, &expected, &actual));

  const char *data = NULL;
  size_t length = 0;
  assert_true(bc_core_writer_buffer_data(&writer, &data, &length));
  assert_non_null(strstr(data, "\"meta_changes\":{"));
  static const char *fields[] = {
      "\"mode\":{\"old\":",       "\"uid\":{\"old\":",
      "\"gid\":{\"old\":",        "\"mtime_sec\":{\"old\":",
      "\"mtime_nsec\":{\"old\":", "\"size_bytes\":{\"old\":",
      "\"ino\":{\"old\":",        "\"nlink\":{\"old\":",
  };
  for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
    assert_non_null(strstr(data, fields[i]));
  }
  (void)bc_core_writer_destroy(&writer);
}

static void test_emit_json_meta_link_targets(void **state) {
  (void)state;
  struct {
    size_t old_length;
    size_t new_length;
    const char *expected;
  } cases[] = {
      {3, 3, "\"link_target\":{\"old\":\"old\",\"new\":\"new\"}"},
      {3, 0, "\"link_target\":{\"old\":\"old\",\"new\":null}"},
      {0, 3, "\"link_target\":{\"old\":null,\"new\":\"new\"}"},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    char buffer[BUFFER_SIZE];
    bc_core_writer_t writer;
    init_writer(&writer, buffer, sizeof(buffer));
    bc_integrity_meta_snapshot_t expected;
    bc_integrity_meta_snapshot_t actual;
    make_snapshot(&expected);
    make_snapshot(&actual);
    expected.link_target = "old";
    expected.link_target_length = cases[i].old_length;
    actual.link_target = "new";
    actual.link_target_length = cases[i].new_length;

    assert_true(bc_integrity_verify_emit_change_json(
        &writer, BC_INTEGRITY_VERIFY_CHANGE_META, "lnk", 3, &expected,
        &actual));
    const char *data = NULL;
    size_t length = 0;
    assert_true(bc_core_writer_buffer_data(&writer, &data, &length));
    assert_non_null(strstr(data, cases[i].expected));
    (void)bc_core_writer_destroy(&writer);
  }
}

static void test_emit_json_both_with_digest_and_meta(void **state) {
  (void)state;
  char buffer[BUFFER_SIZE];
  bc_core_writer_t writer;
  init_writer(&writer, buffer, sizeof(buffer));

  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  make_snapshot(&expected);
  make_snapshot(&actual);
  expected.digest_hex = "ab";
  expected.digest_hex_length = 2;
  actual.digest_hex = "cd";
  actual.digest_hex_length = 2;
  actual.mode = 0700;

  assert_true(bc_integrity_verify_emit_change_json(
      &writer, BC_INTEGRITY_VERIFY_CHANGE_BOTH, "y", 1, &expected, &actual));

  const char *data = NULL;
  size_t length = 0;
  assert_true(bc_core_writer_buffer_data(&writer, &data, &length));
  assert_non_null(strstr(data, "\"meta_changes\":{\"mode\":"));
  assert_non_null(strstr(data, "\"digest\":{"));
  (void)bc_core_writer_destroy(&writer);
}

static void test_emit_json_path_with_special_chars(void **state) {
  (void)state;
  char buffer[BUFFER_SIZE];
  bc_core_writer_t writer;
  init_writer(&writer, buffer, sizeof(buffer));

  const char *path = "a\"b\\c\nd\re\tf\x01";
  size_t length = strlen(path);
  assert_true(bc_integrity_verify_emit_change_json(
      &writer, BC_INTEGRITY_VERIFY_CHANGE_ADDED, path, length, NULL, NULL));

  const char *data = NULL;
  size_t out_length = 0;
  assert_true(bc_core_writer_buffer_data(&writer, &data, &out_length));
  static const char *escapes[] = {"\\\"", "\\\\", "\\n", "\\r", "\\t", "\\u00"};
  for (size_t i = 0; i < sizeof(escapes) / sizeof(escapes[0]); ++i) {
    assert_non_null(strstr(data, escapes[i]));
  }
  (void)bc_core_writer_destroy(&writer);
}

static void test_emit_json_header(void **state) {
  (void)state;
  char buffer[BUFFER_SIZE];
  bc_core_writer_t writer;

  bc_integrity_verify_json_header_options_t options;
  memset(&options, 0, sizeof(options));
  options.command = "verify";
  init_writer(&writer, buffer, sizeof(buffer));
  assert_true(bc_integrity_verify_emit_json_header(&writer, &options));
  (void)bc_core_writer_destroy(&writer);

  options.command = "diff";
  options.root_path = "/root";
  options.manifest_path = "/m.hrbl";
  options.manifest_path_a = "/a.hrbl";
  options.manifest_path_b = "/b.hrbl";
  options.mode = "strict";
  options.digest_algorithm = "sha256";
  options.started_at_unix_sec = 1700000000;
  init_writer(&writer, buffer, sizeof(buffer));
  assert_true(bc_integrity_verify_emit_json_header(&writer, &options));
  const char *data = NULL;
  size_t length = 0;
  assert_true(bc_core_writer_buffer_data(&writer, &data, &length));
  static const char *fields[] = {
      "\"command\":\"diff\"",       "\"root_path\":\"/root\"",
      "\"manifest_path\":\"/m.hrbl\"", "\"manifest_path_a\":\"/a.hrbl\"",
      "\"manifest_path_b\":\"/b.hrbl\"", "\"mode\":\"strict\"",
      "\"algorithm\":\"sha256\"",   "\"started_at\":\"2023-11-14T22:13:20Z\"",
  };
  for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
    assert_non_null(strstr(data, fields[i]));
  }
  (void)bc_core_writer_destroy(&writer);
}

static void test_emit_json_summary(void **state) {
  (void)state;
  char buffer[BUFFER_SIZE];
  bc_core_writer_t writer;
  init_writer(&writer, buffer, sizeof(buffer));

  bc_integrity_verify_json_summary_t summary;
  memset(&summary, 0, sizeof(summary));
  summary.files_total = 100;
  summary.changes_total = 7;
  summary.added = 1;
  summary.removed = 2;
  summary.content = 3;
  summary.meta = 4;
  summary.both = 5;
  summary.errors_count = 6;
  summary.wall_ms = 1234;

  assert_true(bc_integrity_verify_emit_json_summary(&writer, &summary));
  const char *data = NULL;
  size_t length = 0;
  assert_true(bc_core_writer_buffer_data(&writer, &data, &length));
  static const char *fields[] = {
      "\"type\":\"summary\"",   "\"files_total\":100", "\"changes_total\":7",
      "\"added\":1",            "\"removed\":2",        "\"content\":3",
      "\"meta\":4",             "\"both\":5",           "\"errors_count\":6",
      "\"wall_ms\":1234",
  };
  for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
    assert_non_null(strstr(data, fields[i]));
  }
  (void)bc_core_writer_destroy(&writer);
}

static void test_emit_writer_too_small(void **state) {
  (void)state;
  bc_core_writer_t writer;
  char tiny[4];

  init_writer(&writer, tiny, sizeof(tiny));
  assert_false(bc_integrity_verify_emit_change_text(
      &writer, BC_INTEGRITY_VERIFY_CHANGE_ADDED, "long_name", 9, NULL, NULL));
  (void)bc_core_writer_destroy(&writer);

  init_writer(&writer, tiny, sizeof(tiny));
  assert_false(bc_integrity_verify_emit_change_json(
      &writer, BC_INTEGRITY_VERIFY_CHANGE_ADDED, "long_name", 9, NULL, NULL));
  (void)bc_core_writer_destroy(&writer);

  bc_integrity_verify_json_header_options_t header;
  memset(&header, 0, sizeof(header));
  header.command = "verify";
  init_writer(&writer, tiny, sizeof(tiny));
  assert_false(bc_integrity_verify_emit_json_header(&writer, &header));
  (void)bc_core_writer_destroy(&writer);

  bc_integrity_verify_json_summary_t summary;
  memset(&summary, 0, sizeof(summary));
  init_writer(&writer, tiny, sizeof(tiny));
  assert_false(bc_integrity_verify_emit_json_summary(&writer, &summary));
  (void)bc_core_writer_destroy(&writer);
}

static void make_full_change_snapshots(bc_integrity_meta_snapshot_t *expected,
                                       bc_integrity_meta_snapshot_t *actual) {
  make_snapshot(expected);
  make_snapshot(actual);
  actual->mode = 0700;
  actual->uid = 1001;
  actual->gid = 1002;
  actual->mtime_sec = 1700000001;
  actual->mtime_nsec = 99999;
  actual->size_bytes = 2048;
  actual->inode = 43;
  actual->nlink = 2;
  expected->link_target = "old/path";
  expected->link_target_length = 8;
  actual->link_target = "new/path";
  actual->link_target_length = 8;
  expected->digest_hex = "ab";
  expected->digest_hex_length = 2;
  actual->digest_hex = "cd";
  actual->digest_hex_length = 2;
}

static void run_text_with_buffer_size(size_t size,
                                      bc_integrity_verify_change_kind_t kind) {
  char *buffer = malloc(size);
  assert_non_null(buffer);
  bc_core_writer_t writer;
  assert_true(bc_core_writer_init_buffer_only(&writer, buffer, size));

  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  make_full_change_snapshots(&expected, &actual);

  (void)bc_integrity_verify_emit_change_text(&writer, kind, "p.bin", 5,
                                             &expected, &actual);
  (void)bc_core_writer_destroy(&writer);
  free(buffer);
}

static void run_text_simple_with_buffer_size(
    size_t size, bc_integrity_verify_change_kind_t kind) {
  char *buffer = malloc(size);
  assert_non_null(buffer);
  bc_core_writer_t writer;
  assert_true(bc_core_writer_init_buffer_only(&writer, buffer, size));
  (void)bc_integrity_verify_emit_change_text(&writer, kind, "name.txt", 8,
                                             NULL, NULL);
  (void)bc_core_writer_destroy(&writer);
  free(buffer);
}

static void run_text_link_with_buffer_size(size_t size, size_t old_len,
                                           size_t new_len) {
  char *buffer = malloc(size);
  assert_non_null(buffer);
  bc_core_writer_t writer;
  assert_true(bc_core_writer_init_buffer_only(&writer, buffer, size));
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  make_snapshot(&expected);
  make_snapshot(&actual);
  expected.link_target = "old/path";
  expected.link_target_length = old_len;
  actual.link_target = "new/path";
  actual.link_target_length = new_len;
  (void)bc_integrity_verify_emit_change_text(
      &writer, BC_INTEGRITY_VERIFY_CHANGE_META, "lnk", 3, &expected, &actual);
  (void)bc_core_writer_destroy(&writer);
  free(buffer);
}

static void run_json_with_buffer_size(size_t size,
                                      bc_integrity_verify_change_kind_t kind) {
  char *buffer = malloc(size);
  assert_non_null(buffer);
  bc_core_writer_t writer;
  assert_true(bc_core_writer_init_buffer_only(&writer, buffer, size));
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  make_full_change_snapshots(&expected, &actual);
  (void)bc_integrity_verify_emit_change_json(
      &writer, kind, "p\"\\\n\r\t\x01" "b", 9, &expected, &actual);
  (void)bc_core_writer_destroy(&writer);
  free(buffer);
}

static void run_json_link_with_buffer_size(size_t size, size_t old_len,
                                           size_t new_len) {
  char *buffer = malloc(size);
  assert_non_null(buffer);
  bc_core_writer_t writer;
  assert_true(bc_core_writer_init_buffer_only(&writer, buffer, size));
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  make_snapshot(&expected);
  make_snapshot(&actual);
  expected.link_target = "old";
  expected.link_target_length = old_len;
  actual.link_target = "new";
  actual.link_target_length = new_len;
  (void)bc_integrity_verify_emit_change_json(
      &writer, BC_INTEGRITY_VERIFY_CHANGE_META, "lnk", 3, &expected, &actual);
  (void)bc_core_writer_destroy(&writer);
  free(buffer);
}

static void test_buffer_sweep_text_meta(void **state) {
  (void)state;
  for (size_t size = 1; size <= 256; ++size) {
    run_text_with_buffer_size(size, BC_INTEGRITY_VERIFY_CHANGE_META);
  }
}

static void test_buffer_sweep_text_both(void **state) {
  (void)state;
  for (size_t size = 1; size <= 256; ++size) {
    run_text_with_buffer_size(size, BC_INTEGRITY_VERIFY_CHANGE_BOTH);
  }
}

static void test_buffer_sweep_text_simple_kinds(void **state) {
  (void)state;
  bc_integrity_verify_change_kind_t kinds[] = {
      BC_INTEGRITY_VERIFY_CHANGE_ADDED, BC_INTEGRITY_VERIFY_CHANGE_REMOVED,
      BC_INTEGRITY_VERIFY_CHANGE_CONTENT};
  for (size_t k = 0; k < sizeof(kinds) / sizeof(kinds[0]); ++k) {
    for (size_t size = 1; size <= 32; ++size) {
      run_text_simple_with_buffer_size(size, kinds[k]);
    }
  }
}

static void test_buffer_sweep_text_link_targets(void **state) {
  (void)state;
  size_t cases[][2] = {{8, 0}, {0, 8}};
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    for (size_t size = 1; size <= 128; ++size) {
      run_text_link_with_buffer_size(size, cases[i][0], cases[i][1]);
    }
  }
}

static void test_buffer_sweep_json_meta(void **state) {
  (void)state;
  for (size_t size = 1; size <= 320; ++size) {
    run_json_with_buffer_size(size, BC_INTEGRITY_VERIFY_CHANGE_META);
  }
}

static void test_buffer_sweep_json_both(void **state) {
  (void)state;
  for (size_t size = 1; size <= 512; ++size) {
    run_json_with_buffer_size(size, BC_INTEGRITY_VERIFY_CHANGE_BOTH);
  }
}

static void test_buffer_sweep_json_content_with_digest(void **state) {
  (void)state;
  bc_integrity_meta_snapshot_t expected;
  bc_integrity_meta_snapshot_t actual;
  make_snapshot(&expected);
  make_snapshot(&actual);
  expected.digest_hex = "aaaaaa";
  expected.digest_hex_length = 6;
  actual.digest_hex = "bbbbbb";
  actual.digest_hex_length = 6;
  for (size_t size = 1; size <= 256; ++size) {
    char *buffer = malloc(size);
    assert_non_null(buffer);
    bc_core_writer_t writer;
    assert_true(bc_core_writer_init_buffer_only(&writer, buffer, size));
    (void)bc_integrity_verify_emit_change_json(
        &writer, BC_INTEGRITY_VERIFY_CHANGE_CONTENT, "x", 1, &expected,
        &actual);
    (void)bc_core_writer_destroy(&writer);
    free(buffer);
  }
}

static void test_buffer_sweep_json_link_targets(void **state) {
  (void)state;
  size_t cases[][2] = {{3, 0}, {0, 3}};
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    for (size_t size = 1; size <= 128; ++size) {
      run_json_link_with_buffer_size(size, cases[i][0], cases[i][1]);
    }
  }
}

static void test_buffer_sweep_json_header(void **state) {
  (void)state;
  bc_integrity_verify_json_header_options_t options;
  memset(&options, 0, sizeof(options));
  options.command = "verify";
  options.root_path = "/r";
  options.manifest_path = "/m";
  options.manifest_path_a = "/a";
  options.manifest_path_b = "/b";
  options.mode = "strict";
  options.digest_algorithm = "sha256";
  options.started_at_unix_sec = 1700000000;
  for (size_t size = 1; size <= 320; ++size) {
    char *buffer = malloc(size);
    assert_non_null(buffer);
    bc_core_writer_t writer;
    assert_true(bc_core_writer_init_buffer_only(&writer, buffer, size));
    (void)bc_integrity_verify_emit_json_header(&writer, &options);
    (void)bc_core_writer_destroy(&writer);
    free(buffer);
  }
}

static void test_buffer_sweep_json_summary(void **state) {
  (void)state;
  bc_integrity_verify_json_summary_t summary;
  memset(&summary, 0, sizeof(summary));
  summary.files_total = 100;
  summary.changes_total = 7;
  summary.added = 1;
  summary.removed = 2;
  summary.content = 3;
  summary.meta = 4;
  summary.both = 5;
  summary.errors_count = 6;
  summary.wall_ms = 1234;
  for (size_t size = 1; size <= 256; ++size) {
    char *buffer = malloc(size);
    assert_non_null(buffer);
    bc_core_writer_t writer;
    assert_true(bc_core_writer_init_buffer_only(&writer, buffer, size));
    (void)bc_integrity_verify_emit_json_summary(&writer, &summary);
    (void)bc_core_writer_destroy(&writer);
    free(buffer);
  }
}

static void test_buffer_sweep_json_special_path(void **state) {
  (void)state;
  for (size_t size = 1; size <= 96; ++size) {
    char *buffer = malloc(size);
    assert_non_null(buffer);
    bc_core_writer_t writer;
    assert_true(bc_core_writer_init_buffer_only(&writer, buffer, size));
    const char *path = "a\"b\\c\nd\re\tf\x01";
    (void)bc_integrity_verify_emit_change_json(
        &writer, BC_INTEGRITY_VERIFY_CHANGE_ADDED, path, 12, NULL, NULL);
    (void)bc_core_writer_destroy(&writer);
    free(buffer);
  }
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_emit_text_added_removed_content),
      cmocka_unit_test(test_emit_text_meta_all_uint_fields),
      cmocka_unit_test(test_emit_text_meta_link_targets),
      cmocka_unit_test(test_emit_text_meta_no_diff),
      cmocka_unit_test(test_emit_text_null_kinds),
      cmocka_unit_test(test_emit_text_both),
      cmocka_unit_test(test_emit_json_simple_kinds),
      cmocka_unit_test(test_emit_json_content_with_digest),
      cmocka_unit_test(test_emit_json_meta_uint_fields),
      cmocka_unit_test(test_emit_json_meta_link_targets),
      cmocka_unit_test(test_emit_json_both_with_digest_and_meta),
      cmocka_unit_test(test_emit_json_path_with_special_chars),
      cmocka_unit_test(test_emit_json_header),
      cmocka_unit_test(test_emit_json_summary),
      cmocka_unit_test(test_emit_writer_too_small),
      cmocka_unit_test(test_buffer_sweep_text_meta),
      cmocka_unit_test(test_buffer_sweep_text_both),
      cmocka_unit_test(test_buffer_sweep_text_simple_kinds),
      cmocka_unit_test(test_buffer_sweep_text_link_targets),
      cmocka_unit_test(test_buffer_sweep_json_meta),
      cmocka_unit_test(test_buffer_sweep_json_both),
      cmocka_unit_test(test_buffer_sweep_json_content_with_digest),
      cmocka_unit_test(test_buffer_sweep_json_link_targets),
      cmocka_unit_test(test_buffer_sweep_json_header),
      cmocka_unit_test(test_buffer_sweep_json_summary),
      cmocka_unit_test(test_buffer_sweep_json_special_path),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
