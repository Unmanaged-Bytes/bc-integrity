// SPDX-License-Identifier: MIT

#ifndef BC_INTEGRITY_DIFF_INTERNAL_H
#define BC_INTEGRITY_DIFF_INTERNAL_H

#include "bc_integrity_cli_internal.h"
#include "bc_integrity_verify_internal.h"

#include "bc_allocators.h"

#include <stdbool.h>
#include <stddef.h>

bool bc_integrity_diff_run(bc_allocators_context_t *memory_context,
                           const bc_integrity_diff_options_t *options,
                           int *out_exit_code);

#endif /* BC_INTEGRITY_DIFF_INTERNAL_H */
