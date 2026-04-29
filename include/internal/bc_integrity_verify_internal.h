// SPDX-License-Identifier: MIT

#ifndef BC_INTEGRITY_VERIFY_INTERNAL_H
#define BC_INTEGRITY_VERIFY_INTERNAL_H

#include "bc_integrity_cli_internal.h"
#include "bc_integrity_entry_internal.h"

#include "bc_allocators.h"
#include "bc_concurrency.h"
#include "bc_concurrency_signal.h"
#include "bc_core_io.h"
#include "bc_runtime_error_collector.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum bc_integrity_verify_change_kind {
  BC_INTEGRITY_VERIFY_CHANGE_NONE = 0,
  BC_INTEGRITY_VERIFY_CHANGE_ADDED,
  BC_INTEGRITY_VERIFY_CHANGE_REMOVED,
  BC_INTEGRITY_VERIFY_CHANGE_CONTENT,
  BC_INTEGRITY_VERIFY_CHANGE_META,
  BC_INTEGRITY_VERIFY_CHANGE_BOTH,
} bc_integrity_verify_change_kind_t;

typedef struct bc_integrity_meta_snapshot {
  bool present;
  bc_integrity_entry_kind_t kind;
  uint64_t size_bytes;
  uint64_t mode;
  uint64_t uid;
  uint64_t gid;
  uint64_t mtime_sec;
  uint64_t mtime_nsec;
  uint64_t inode;
  uint64_t nlink;
  const char *digest_hex;
  size_t digest_hex_length;
  const char *link_target;
  size_t link_target_length;
} bc_integrity_meta_snapshot_t;

bc_integrity_verify_change_kind_t
bc_integrity_verify_compare_strict(const bc_integrity_meta_snapshot_t *expected,
                                   const bc_integrity_meta_snapshot_t *actual,
                                   bool ignore_mtime);

bc_integrity_verify_change_kind_t bc_integrity_verify_compare_content(
    const bc_integrity_meta_snapshot_t *expected,
    const bc_integrity_meta_snapshot_t *actual);

bc_integrity_verify_change_kind_t
bc_integrity_verify_compare_meta(const bc_integrity_meta_snapshot_t *expected,
                                 const bc_integrity_meta_snapshot_t *actual,
                                 bool ignore_mtime);

bool bc_integrity_verify_emit_change_text(
    bc_core_writer_t *writer, bc_integrity_verify_change_kind_t kind,
    const char *relative_path, size_t relative_path_length,
    const bc_integrity_meta_snapshot_t *expected,
    const bc_integrity_meta_snapshot_t *actual);

bool bc_integrity_verify_emit_change_json(
    bc_core_writer_t *writer, bc_integrity_verify_change_kind_t kind,
    const char *relative_path, size_t relative_path_length,
    const bc_integrity_meta_snapshot_t *expected,
    const bc_integrity_meta_snapshot_t *actual);

typedef struct bc_integrity_verify_json_header_options {
  const char *command;
  const char *root_path;
  const char *manifest_path;
  const char *manifest_path_a;
  const char *manifest_path_b;
  const char *mode;
  const char *digest_algorithm;
  uint64_t started_at_unix_sec;
} bc_integrity_verify_json_header_options_t;

typedef struct bc_integrity_verify_json_summary {
  uint64_t files_total;
  uint64_t changes_total;
  uint64_t added;
  uint64_t removed;
  uint64_t content;
  uint64_t meta;
  uint64_t both;
  uint64_t errors_count;
  uint64_t wall_ms;
} bc_integrity_verify_json_summary_t;

bool bc_integrity_verify_emit_json_header(
    bc_core_writer_t *writer,
    const bc_integrity_verify_json_header_options_t *options);

bool bc_integrity_verify_emit_json_summary(
    bc_core_writer_t *writer,
    const bc_integrity_verify_json_summary_t *summary);

bool bc_integrity_verify_run(bc_allocators_context_t *memory_context,
                             bc_concurrency_context_t *concurrency_context,
                             bc_concurrency_signal_handler_t *signal_handler,
                             const bc_integrity_verify_options_t *options,
                             bc_runtime_error_collector_t *errors,
                             int *out_exit_code);

#endif /* BC_INTEGRITY_VERIFY_INTERNAL_H */
