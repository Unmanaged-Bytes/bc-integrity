// SPDX-License-Identifier: MIT

#ifndef BC_INTEGRITY_CAPTURE_HASH_INTERNAL_H
#define BC_INTEGRITY_CAPTURE_HASH_INTERNAL_H

#include "bc_integrity_cli_internal.h"

#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BC_INTEGRITY_HASH_RING_SLOT_COUNT 32
#define BC_INTEGRITY_HASH_RING_SLOT_BUFFER_BYTES ((size_t)(128 * 1024))

typedef bool (*bc_integrity_hash_consumer_fn_t)(void *consumer_context,
                                                const void *chunk_data,
                                                size_t chunk_size);

typedef struct bc_integrity_hash_batch_item {
  const char *absolute_path;
  size_t file_size;
  void *consumer_context;
  bool success;
  int errno_value;
} bc_integrity_hash_batch_item_t;

typedef struct bc_integrity_hash_ring bc_integrity_hash_ring_t;

size_t bc_integrity_hash_ring_struct_size(void);
bool bc_integrity_hash_ring_init(bc_integrity_hash_ring_t *ring);
void bc_integrity_hash_ring_destroy(bc_integrity_hash_ring_t *ring);

bool bc_integrity_hash_consume_batch(bc_integrity_hash_ring_t *ring,
                                     bc_integrity_hash_batch_item_t *items,
                                     size_t item_count,
                                     bc_integrity_hash_consumer_fn_t consumer);

bool bc_integrity_hash_consume_file(const char *absolute_path,
                                    size_t file_size_hint,
                                    void *consumer_context,
                                    bc_integrity_hash_consumer_fn_t consumer,
                                    int *out_errno_value);

bool bc_integrity_hash_compute_for_algorithm(
    const char *absolute_path, size_t file_size,
    bc_integrity_digest_algorithm_t digest_algorithm, char *out_digest_hex,
    size_t *out_digest_hex_length, int *out_errno_value);

bool bc_integrity_hash_finalize_into_hex(
    bc_integrity_digest_algorithm_t digest_algorithm, void *consumer_state,
    char *out_digest_hex, size_t *out_digest_hex_length);

void bc_integrity_hash_consumer_begin(
    bc_integrity_digest_algorithm_t digest_algorithm, void *consumer_state);

bc_integrity_hash_consumer_fn_t bc_integrity_hash_consumer_function_for(
    bc_integrity_digest_algorithm_t digest_algorithm);

#define BC_INTEGRITY_HASH_CONSUMER_STATE_BYTES ((size_t)768)

typedef struct bc_integrity_hash_consumer_state {
  alignas(64) unsigned char opaque[BC_INTEGRITY_HASH_CONSUMER_STATE_BYTES];
} bc_integrity_hash_consumer_state_t;

#endif /* BC_INTEGRITY_CAPTURE_HASH_INTERNAL_H */
