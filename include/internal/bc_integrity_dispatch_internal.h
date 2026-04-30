// SPDX-License-Identifier: MIT

#ifndef BC_INTEGRITY_DISPATCH_INTERNAL_H
#define BC_INTEGRITY_DISPATCH_INTERNAL_H

#include "bc_integrity_cli_internal.h"
#include "bc_integrity_entry_internal.h"

#include "bc_allocators.h"
#include "bc_concurrency.h"
#include "bc_runtime_signal.h"
#include "bc_containers_vector.h"

#include <stdbool.h>
#include <stddef.h>

/* Falls back to sequential hashing when pending files <= worker_count * 4
   (threshold tuned to amortize 3-phases parallel orchestration overhead). */
bool bc_integrity_dispatch_compute_digests(
    bc_allocators_context_t *memory_context,
    bc_concurrency_context_t *concurrency_context,
    bc_runtime_signal_handler_t *signal_handler,
    bc_integrity_digest_algorithm_t digest_algorithm,
    bc_containers_vector_t *entries);

#endif /* BC_INTEGRITY_DISPATCH_INTERNAL_H */
