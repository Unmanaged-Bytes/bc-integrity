// SPDX-License-Identifier: MIT

#ifndef BC_INTEGRITY_FILTER_INTERNAL_H
#define BC_INTEGRITY_FILTER_INTERNAL_H

#include "bc_allocators.h"

#include <stdbool.h>
#include <stddef.h>

typedef struct bc_integrity_filter bc_integrity_filter_t;

bool bc_integrity_filter_create(bc_allocators_context_t* memory_context, const char* include_list, const char* exclude_list,
                                bc_integrity_filter_t** out_filter);

void bc_integrity_filter_destroy(bc_allocators_context_t* memory_context, bc_integrity_filter_t* filter);

bool bc_integrity_filter_accepts_path(const bc_integrity_filter_t* filter, const char* relative_path, size_t relative_path_length);

bool bc_integrity_filter_accepts_directory(const bc_integrity_filter_t* filter, const char* relative_path, size_t relative_path_length);

bool bc_integrity_filter_glob_matches(const char* pattern, const char* value, size_t value_length);

#endif /* BC_INTEGRITY_FILTER_INTERNAL_H */
