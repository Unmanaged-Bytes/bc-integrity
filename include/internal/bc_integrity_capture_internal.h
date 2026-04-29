// SPDX-License-Identifier: MIT

#ifndef BC_INTEGRITY_CAPTURE_INTERNAL_H
#define BC_INTEGRITY_CAPTURE_INTERNAL_H

#include "bc_integrity_cli_internal.h"

#include "bc_integrity_entry_internal.h"

#include "bc_allocators.h"

#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>

bool bc_integrity_capture_entry_from_stat(
    bc_allocators_context_t *memory_context, const struct stat *stat_buffer,
    bc_integrity_digest_algorithm_t digest_algorithm, int parent_directory_fd,
    const char *basename, const char *absolute_path,
    size_t absolute_path_length, const char *relative_path,
    size_t relative_path_length, bool skip_digest,
    bc_integrity_entry_t *out_entry);

bool bc_integrity_capture_compute_digest(
    const char *absolute_path, size_t file_size,
    bc_integrity_digest_algorithm_t digest_algorithm, char *out_digest_hex,
    size_t *out_digest_hex_length, int *out_errno_value);

void bc_integrity_capture_set_error_message(bc_integrity_entry_t *entry,
                                            int errno_value);

#endif /* BC_INTEGRITY_CAPTURE_INTERNAL_H */
