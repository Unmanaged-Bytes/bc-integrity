// SPDX-License-Identifier: MIT

#ifndef BC_INTEGRITY_MANIFEST_INTERNAL_H
#define BC_INTEGRITY_MANIFEST_INTERNAL_H

#include "bc_integrity_cli_internal.h"

#include "bc_allocators.h"
#include "bc_containers_vector.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct bc_integrity_manifest_summary {
    uint64_t file_count;
    uint64_t directory_count;
    uint64_t symlink_count;
    uint64_t total_bytes;
    uint64_t errors_count;
    uint64_t created_at_unix_sec;
    uint64_t completed_at_unix_sec;
    uint64_t walltime_ms;
    const char* host;
    const char* root_path_absolute;
} bc_integrity_manifest_summary_t;

bool bc_integrity_manifest_write_to_file(bc_allocators_context_t* memory_context, const bc_integrity_manifest_options_t* options,
                                         const bc_containers_vector_t* entries, const bc_integrity_manifest_summary_t* summary,
                                         const char* output_path);

#endif /* BC_INTEGRITY_MANIFEST_INTERNAL_H */
