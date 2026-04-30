// SPDX-License-Identifier: MIT

#ifndef BC_INTEGRITY_WALK_INTERNAL_H
#define BC_INTEGRITY_WALK_INTERNAL_H

#include "bc_integrity_cli_internal.h"

#include "bc_allocators.h"
#include "bc_concurrency.h"
#include "bc_runtime_signal.h"
#include "bc_containers_vector.h"
#include "bc_runtime_error_collector.h"

#include <stdbool.h>
#include <stddef.h>

bool bc_integrity_walk_run(bc_allocators_context_t* memory_context, bc_concurrency_context_t* concurrency_context,
                           bc_runtime_signal_handler_t* signal_handler, const bc_integrity_manifest_options_t* options,
                           const char* canonical_root_path, size_t canonical_root_path_length, bc_containers_vector_t* destination_entries,
                           bc_runtime_error_collector_t* errors);

bool bc_integrity_walk_run_serial(bc_allocators_context_t* memory_context, bc_runtime_signal_handler_t* signal_handler,
                                  const bc_integrity_manifest_options_t* options, const char* canonical_root_path,
                                  size_t canonical_root_path_length, bc_containers_vector_t* destination_entries,
                                  bc_runtime_error_collector_t* errors);

bool bc_integrity_walk_run_serial_with_budget(bc_allocators_context_t* memory_context, bc_runtime_signal_handler_t* signal_handler,
                                              const bc_integrity_manifest_options_t* options, const char* canonical_root_path,
                                              size_t canonical_root_path_length, bc_containers_vector_t* destination_entries,
                                              bc_runtime_error_collector_t* errors, size_t entry_budget, bool* out_budget_exceeded);

bool bc_integrity_walk_is_hidden_segment(const char* relative_path, size_t relative_path_length);

bool bc_integrity_walk_is_virtual_root(const char* canonical_root_path, size_t canonical_root_path_length);

bool bc_integrity_walk_is_virtual_subpath(const char* canonical_root_path, size_t canonical_root_path_length, const char* absolute_path,
                                          size_t absolute_path_length);

#endif /* BC_INTEGRITY_WALK_INTERNAL_H */
