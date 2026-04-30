// SPDX-License-Identifier: MIT

#include "bc_integrity_dispatch_internal.h"

#include "bc_integrity_capture_hash_internal.h"
#include "bc_integrity_capture_internal.h"
#include "bc_integrity_entry_internal.h"

#include "bc_allocators.h"
#include "bc_allocators_pool.h"
#include "bc_concurrency.h"
#include "bc_containers_vector.h"
#include "bc_core.h"
#include "bc_core_sort.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BC_INTEGRITY_DISPATCH_BATCH_SIZE                                       \
  ((size_t)BC_INTEGRITY_HASH_RING_SLOT_COUNT)
#define BC_INTEGRITY_DISPATCH_URING_MIN_FILE_BYTES ((size_t)(64 * 1024))
#define BC_INTEGRITY_DISPATCH_URING_USEFUL_RATIO 8U

#define BC_INTEGRITY_DISPATCH_SMALL_CORPUS_FILES_PER_WORKER ((size_t)4)

typedef struct bc_integrity_dispatch_descriptor {
  size_t entry_index;
  uint64_t file_size;
} bc_integrity_dispatch_descriptor_t;

typedef struct bc_integrity_dispatch_context {
  bc_containers_vector_t *entries;
  const size_t *processing_order;
  size_t pending_count;
  size_t batch_count;
  size_t ring_slot_index;
  bool ring_enabled;
  bc_integrity_digest_algorithm_t digest_algorithm;
  bc_runtime_signal_handler_t *signal_handler;
} bc_integrity_dispatch_context_t;

static bool bc_integrity_dispatch_descriptor_size_descending(
    const void *left_pointer, const void *right_pointer, void *user_data) {
  (void)user_data;
  const bc_integrity_dispatch_descriptor_t *left =
      (const bc_integrity_dispatch_descriptor_t *)left_pointer;
  const bc_integrity_dispatch_descriptor_t *right =
      (const bc_integrity_dispatch_descriptor_t *)right_pointer;
  return left->file_size > right->file_size;
}

static bool bc_integrity_dispatch_should_stop(
    const bc_runtime_signal_handler_t *signal_handler) {
  if (signal_handler == NULL) {
    return false;
  }
  bool should_stop = false;
  bc_runtime_signal_handler_should_stop(signal_handler, &should_stop);
  return should_stop;
}

static bool bc_integrity_dispatch_collect_pending(
    bc_allocators_context_t *memory_context,
    const bc_containers_vector_t *entries,
    bc_integrity_dispatch_descriptor_t **out_descriptors,
    size_t *out_pending_count, size_t *out_uring_eligible_count) {
  size_t entry_count = bc_containers_vector_length(entries);
  bc_integrity_dispatch_descriptor_t *descriptors = NULL;
  if (entry_count > 0) {
    if (!bc_allocators_pool_allocate(
            memory_context,
            entry_count * sizeof(bc_integrity_dispatch_descriptor_t),
            (void **)&descriptors)) {
      return false;
    }
  }
  size_t pending_count = 0;
  size_t uring_eligible_count = 0;
  for (size_t index = 0; index < entry_count; ++index) {
    bc_integrity_entry_t entry;
    if (!bc_containers_vector_get(entries, index, &entry)) {
      continue;
    }
    if (entry.kind != BC_INTEGRITY_ENTRY_KIND_FILE) {
      continue;
    }
    if (!entry.ok) {
      continue;
    }
    if (entry.digest_hex_length > 0) {
      continue;
    }
    descriptors[pending_count].entry_index = index;
    descriptors[pending_count].file_size = entry.size_bytes;
    pending_count += 1;
    if (entry.size_bytes >=
            (uint64_t)BC_INTEGRITY_DISPATCH_URING_MIN_FILE_BYTES &&
        entry.size_bytes <=
            (uint64_t)BC_INTEGRITY_HASH_RING_SLOT_BUFFER_BYTES) {
      uring_eligible_count += 1;
    }
  }
  *out_descriptors = descriptors;
  *out_pending_count = pending_count;
  *out_uring_eligible_count = uring_eligible_count;
  return true;
}

static bool bc_integrity_dispatch_build_processing_order(
    bc_allocators_context_t *memory_context,
    bc_integrity_dispatch_descriptor_t *descriptors, size_t pending_count,
    size_t worker_count, size_t **out_processing_order) {
  if (pending_count == 0) {
    *out_processing_order = NULL;
    return true;
  }
  bc_core_sort_with_compare(
      descriptors, pending_count, sizeof(bc_integrity_dispatch_descriptor_t),
      bc_integrity_dispatch_descriptor_size_descending, NULL);
  size_t *processing_order = NULL;
  if (!bc_allocators_pool_allocate(memory_context,
                                   pending_count * sizeof(size_t),
                                   (void **)&processing_order)) {
    return false;
  }
  size_t bucket_count = worker_count > 0 ? worker_count : 1;
  size_t write_position = 0;
  for (size_t bucket_index = 0; bucket_index < bucket_count; ++bucket_index) {
    for (size_t descriptor_index = bucket_index;
         descriptor_index < pending_count; descriptor_index += bucket_count) {
      processing_order[write_position] =
          descriptors[descriptor_index].entry_index;
      write_position += 1;
    }
  }
  *out_processing_order = processing_order;
  return true;
}

static void bc_integrity_dispatch_apply_result(
    bc_containers_vector_t *entries, size_t entry_index,
    const bc_integrity_hash_batch_item_t *batch_item,
    bc_integrity_digest_algorithm_t digest_algorithm,
    bc_integrity_hash_consumer_state_t *consumer_state) {
  bc_integrity_entry_t entry;
  if (!bc_containers_vector_get(entries, entry_index, &entry)) {
    return;
  }
  if (!batch_item->success) {
    bc_integrity_capture_set_error_message(
        &entry, batch_item->errno_value == 0 ? EIO : batch_item->errno_value);
    (void)bc_containers_vector_set(entries, entry_index, &entry);
    return;
  }
  size_t digest_length = 0;
  if (!bc_integrity_hash_finalize_into_hex(digest_algorithm, consumer_state,
                                           entry.digest_hex, &digest_length)) {
    bc_integrity_capture_set_error_message(&entry, EIO);
    (void)bc_containers_vector_set(entries, entry_index, &entry);
    return;
  }
  entry.digest_hex_length = digest_length;
  (void)bc_containers_vector_set(entries, entry_index, &entry);
}

static void bc_integrity_dispatch_process_zero_size(
    bc_containers_vector_t *entries, size_t entry_index,
    bc_integrity_digest_algorithm_t digest_algorithm) {
  bc_integrity_entry_t entry;
  if (!bc_containers_vector_get(entries, entry_index, &entry)) {
    return;
  }
  bc_integrity_hash_consumer_state_t consumer_state;
  bc_integrity_hash_consumer_begin(digest_algorithm, &consumer_state);
  size_t digest_length = 0;
  if (!bc_integrity_hash_finalize_into_hex(digest_algorithm, &consumer_state,
                                           entry.digest_hex, &digest_length)) {
    bc_integrity_capture_set_error_message(&entry, EIO);
  } else {
    entry.digest_hex_length = digest_length;
  }
  (void)bc_containers_vector_set(entries, entry_index, &entry);
}

static void bc_integrity_dispatch_process_oversize(
    bc_containers_vector_t *entries, size_t entry_index,
    bc_integrity_digest_algorithm_t digest_algorithm) {
  bc_integrity_entry_t entry;
  if (!bc_containers_vector_get(entries, entry_index, &entry)) {
    return;
  }
  size_t digest_length = 0;
  int errno_value = 0;
  if (!bc_integrity_hash_compute_for_algorithm(
          entry.absolute_path, entry.size_bytes, digest_algorithm,
          entry.digest_hex, &digest_length, &errno_value)) {
    bc_integrity_capture_set_error_message(&entry, errno_value);
  } else {
    entry.digest_hex_length = digest_length;
  }
  (void)bc_containers_vector_set(entries, entry_index, &entry);
}

static bool bc_integrity_dispatch_path_fits_ring(uint64_t file_size) {
  return file_size >= (uint64_t)BC_INTEGRITY_DISPATCH_URING_MIN_FILE_BYTES &&
         file_size <= (uint64_t)BC_INTEGRITY_HASH_RING_SLOT_BUFFER_BYTES;
}

static void bc_integrity_dispatch_process_small_file(
    bc_containers_vector_t *entries, size_t entry_index,
    bc_integrity_digest_algorithm_t digest_algorithm) {
  bc_integrity_entry_t entry;
  if (!bc_containers_vector_get(entries, entry_index, &entry)) {
    return;
  }
  size_t digest_length = 0;
  int errno_value = 0;
  if (!bc_integrity_hash_compute_for_algorithm(
          entry.absolute_path, entry.size_bytes, digest_algorithm,
          entry.digest_hex, &digest_length, &errno_value)) {
    bc_integrity_capture_set_error_message(&entry, errno_value);
  } else {
    entry.digest_hex_length = digest_length;
  }
  (void)bc_containers_vector_set(entries, entry_index, &entry);
}

static void bc_integrity_dispatch_iteration(size_t iteration_index,
                                            void *argument) {
  bc_integrity_dispatch_context_t *context =
      (bc_integrity_dispatch_context_t *)argument;
  if (bc_integrity_dispatch_should_stop(context->signal_handler)) {
    return;
  }
  size_t batch_start = iteration_index * BC_INTEGRITY_DISPATCH_BATCH_SIZE;
  size_t remaining = context->pending_count - batch_start;
  size_t batch_size = remaining < BC_INTEGRITY_DISPATCH_BATCH_SIZE
                          ? remaining
                          : BC_INTEGRITY_DISPATCH_BATCH_SIZE;

  bc_integrity_hash_batch_item_t batch_items[BC_INTEGRITY_DISPATCH_BATCH_SIZE];
  bc_integrity_hash_consumer_state_t
      consumer_states[BC_INTEGRITY_DISPATCH_BATCH_SIZE];
  size_t entry_indices[BC_INTEGRITY_DISPATCH_BATCH_SIZE];
  size_t prepared_count = 0;
  for (size_t offset = 0; offset < batch_size; ++offset) {
    size_t entry_index = context->processing_order[batch_start + offset];
    bc_integrity_entry_t entry;
    if (!bc_containers_vector_get(context->entries, entry_index, &entry)) {
      continue;
    }
    if (entry.size_bytes == 0) {
      bc_integrity_dispatch_process_zero_size(context->entries, entry_index,
                                              context->digest_algorithm);
      continue;
    }
    if (!context->ring_enabled ||
        entry.size_bytes <
            (uint64_t)BC_INTEGRITY_DISPATCH_URING_MIN_FILE_BYTES) {
      bc_integrity_dispatch_process_small_file(context->entries, entry_index,
                                               context->digest_algorithm);
      continue;
    }
    if (!bc_integrity_dispatch_path_fits_ring(entry.size_bytes)) {
      bc_integrity_dispatch_process_oversize(context->entries, entry_index,
                                             context->digest_algorithm);
      continue;
    }
    bc_integrity_hash_consumer_begin(context->digest_algorithm,
                                     &consumer_states[prepared_count]);
    batch_items[prepared_count].absolute_path = entry.absolute_path;
    batch_items[prepared_count].file_size = (size_t)entry.size_bytes;
    batch_items[prepared_count].consumer_context =
        &consumer_states[prepared_count];
    batch_items[prepared_count].success = false;
    batch_items[prepared_count].errno_value = 0;
    entry_indices[prepared_count] = entry_index;
    prepared_count += 1;
  }
  if (prepared_count == 0) {
    return;
  }
  bc_integrity_hash_ring_t *ring =
      (bc_integrity_hash_ring_t *)bc_concurrency_worker_slot(
          context->ring_slot_index);
  bc_integrity_hash_consumer_fn_t consumer_function =
      bc_integrity_hash_consumer_function_for(context->digest_algorithm);
  bc_integrity_hash_consume_batch(ring, batch_items, prepared_count,
                                  consumer_function);
  for (size_t index = 0; index < prepared_count; ++index) {
    bc_integrity_dispatch_apply_result(
        context->entries, entry_indices[index], &batch_items[index],
        context->digest_algorithm, &consumer_states[index]);
  }
}

static void bc_integrity_dispatch_run_sequential(
    bc_containers_vector_t *entries,
    const bc_runtime_signal_handler_t *signal_handler,
    bc_integrity_digest_algorithm_t digest_algorithm) {
  size_t entry_count = bc_containers_vector_length(entries);
  for (size_t index = 0; index < entry_count; ++index) {
    if (bc_integrity_dispatch_should_stop(signal_handler)) {
      return;
    }
    bc_integrity_entry_t entry;
    if (!bc_containers_vector_get(entries, index, &entry)) {
      continue;
    }
    if (entry.kind != BC_INTEGRITY_ENTRY_KIND_FILE) {
      continue;
    }
    if (!entry.ok) {
      continue;
    }
    if (entry.digest_hex_length > 0) {
      continue;
    }
    if (entry.size_bytes == 0) {
      bc_integrity_dispatch_process_zero_size(entries, index, digest_algorithm);
      continue;
    }
    bc_integrity_dispatch_process_small_file(entries, index, digest_algorithm);
  }
}

static void bc_integrity_dispatch_ring_init(void *data, size_t worker_index,
                                            void *arg) {
  (void)worker_index;
  (void)arg;
  bc_integrity_hash_ring_init((bc_integrity_hash_ring_t *)data);
}

static void bc_integrity_dispatch_ring_destroy(void *data, size_t worker_index,
                                               void *arg) {
  (void)worker_index;
  (void)arg;
  bc_integrity_hash_ring_destroy((bc_integrity_hash_ring_t *)data);
}

bool bc_integrity_dispatch_compute_digests(
    bc_allocators_context_t *memory_context,
    bc_concurrency_context_t *concurrency_context,
    bc_runtime_signal_handler_t *signal_handler,
    bc_integrity_digest_algorithm_t digest_algorithm,
    bc_containers_vector_t *entries) {
  bc_integrity_dispatch_descriptor_t *descriptors = NULL;
  size_t pending_count = 0;
  size_t uring_eligible_count = 0;
  if (!bc_integrity_dispatch_collect_pending(memory_context, entries,
                                             &descriptors, &pending_count,
                                             &uring_eligible_count)) {
    return false;
  }
  if (pending_count == 0) {
    if (descriptors != NULL) {
      bc_allocators_pool_free(memory_context, descriptors);
    }
    return true;
  }

  size_t worker_count =
      bc_concurrency_effective_worker_count(concurrency_context);
  size_t small_corpus_threshold =
      worker_count * BC_INTEGRITY_DISPATCH_SMALL_CORPUS_FILES_PER_WORKER;
  if (worker_count <= 1 || pending_count <= small_corpus_threshold) {
    if (descriptors != NULL) {
      bc_allocators_pool_free(memory_context, descriptors);
    }
    bc_integrity_dispatch_run_sequential(entries, signal_handler,
                                         digest_algorithm);
    return true;
  }

  size_t *processing_order = NULL;
  if (!bc_integrity_dispatch_build_processing_order(memory_context, descriptors,
                                                    pending_count, worker_count,
                                                    &processing_order)) {
    bc_allocators_pool_free(memory_context, descriptors);
    return false;
  }
  bc_allocators_pool_free(memory_context, descriptors);

  bool ring_useful =
      uring_eligible_count * BC_INTEGRITY_DISPATCH_URING_USEFUL_RATIO >=
      pending_count;
  size_t ring_slot_index = 0;
  if (ring_useful) {
    bc_concurrency_slot_config_t slot_config = {
        .size = bc_integrity_hash_ring_struct_size(),
        .init = bc_integrity_dispatch_ring_init,
        .destroy = bc_integrity_dispatch_ring_destroy,
        .arg = NULL,
    };
    if (!bc_concurrency_register_slot(concurrency_context, &slot_config,
                                      &ring_slot_index)) {
      ring_useful = false;
    }
  }

  size_t batch_count = (pending_count + BC_INTEGRITY_DISPATCH_BATCH_SIZE - 1) /
                       BC_INTEGRITY_DISPATCH_BATCH_SIZE;

  bc_integrity_dispatch_context_t context = {
      .entries = entries,
      .processing_order = processing_order,
      .pending_count = pending_count,
      .batch_count = batch_count,
      .ring_slot_index = ring_slot_index,
      .ring_enabled = ring_useful,
      .digest_algorithm = digest_algorithm,
      .signal_handler = signal_handler,
  };

  bool dispatch_ok =
      bc_concurrency_for(concurrency_context, 0, batch_count, 1,
                         bc_integrity_dispatch_iteration, &context);

  if (processing_order != NULL) {
    bc_allocators_pool_free(memory_context, processing_order);
  }
  return dispatch_ok;
}
