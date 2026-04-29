// SPDX-License-Identifier: MIT

#include "bc_integrity_capture_hash_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <liburing.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#define BC_INTEGRITY_HASH_RING_QUEUE_DEPTH                                     \
  ((unsigned int)(BC_INTEGRITY_HASH_RING_SLOT_COUNT * 5U))
#define BC_INTEGRITY_HASH_RING_OP_OPENAT 0U
#define BC_INTEGRITY_HASH_RING_OP_READ 1U
#define BC_INTEGRITY_HASH_RING_OP_PROBE 2U
#define BC_INTEGRITY_HASH_RING_OP_CLOSE 3U

typedef struct bc_integrity_hash_ring {
  struct io_uring ring;
  bool ring_ready;
  unsigned char slot_buffers[BC_INTEGRITY_HASH_RING_SLOT_COUNT]
                            [BC_INTEGRITY_HASH_RING_SLOT_BUFFER_BYTES];
  unsigned char slot_growth_probes[BC_INTEGRITY_HASH_RING_SLOT_COUNT];
} bc_integrity_hash_ring_t;

size_t bc_integrity_hash_ring_struct_size(void) {
  return sizeof(bc_integrity_hash_ring_t);
}

bool bc_integrity_hash_ring_init(bc_integrity_hash_ring_t *ring) {
  memset(&ring->ring, 0, sizeof(ring->ring));
  ring->ring_ready = false;
  int queue_status =
      io_uring_queue_init(BC_INTEGRITY_HASH_RING_QUEUE_DEPTH, &ring->ring, 0);
  if (queue_status < 0) {
    return false;
  }
  int register_status = io_uring_register_files_sparse(
      &ring->ring, BC_INTEGRITY_HASH_RING_SLOT_COUNT);
  if (register_status < 0) {
    io_uring_queue_exit(&ring->ring);
    return false;
  }
  ring->ring_ready = true;
  return true;
}

void bc_integrity_hash_ring_destroy(bc_integrity_hash_ring_t *ring) {
  if (ring->ring_ready) {
    io_uring_queue_exit(&ring->ring);
    ring->ring_ready = false;
  }
}

static uint64_t
bc_integrity_hash_ring_encode_user_data(unsigned int slot_index,
                                        unsigned int operation_code) {
  return ((uint64_t)slot_index << 8) | (uint64_t)operation_code;
}

static unsigned int bc_integrity_hash_ring_decode_slot(uint64_t user_data) {
  return (unsigned int)(user_data >> 8);
}

static unsigned int
bc_integrity_hash_ring_decode_operation(uint64_t user_data) {
  return (unsigned int)(user_data & 0xFFU);
}

static bool bc_integrity_hash_ring_submit_slot(
    struct io_uring *ring, unsigned int slot_index,
    const bc_integrity_hash_batch_item_t *item, void *buffer_address,
    unsigned char *probe_byte_address) {
  struct io_uring_sqe *open_sqe = io_uring_get_sqe(ring);
  struct io_uring_sqe *read_sqe = io_uring_get_sqe(ring);
  struct io_uring_sqe *probe_sqe = io_uring_get_sqe(ring);
  struct io_uring_sqe *close_sqe = io_uring_get_sqe(ring);
  if (open_sqe == NULL || read_sqe == NULL || probe_sqe == NULL ||
      close_sqe == NULL) {
    return false;
  }
  int open_flags = O_RDONLY;
  io_uring_prep_openat_direct(open_sqe, AT_FDCWD, item->absolute_path,
                              open_flags, 0, slot_index);
  open_sqe->flags |= IOSQE_IO_LINK;
  io_uring_sqe_set_data64(open_sqe,
                          bc_integrity_hash_ring_encode_user_data(
                              slot_index, BC_INTEGRITY_HASH_RING_OP_OPENAT));
  io_uring_prep_read(read_sqe, (int)slot_index, buffer_address,
                     (unsigned int)item->file_size, 0);
  read_sqe->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
  io_uring_sqe_set_data64(read_sqe,
                          bc_integrity_hash_ring_encode_user_data(
                              slot_index, BC_INTEGRITY_HASH_RING_OP_READ));
  io_uring_prep_read(probe_sqe, (int)slot_index, probe_byte_address, 1U,
                     (uint64_t)item->file_size);
  probe_sqe->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
  io_uring_sqe_set_data64(probe_sqe,
                          bc_integrity_hash_ring_encode_user_data(
                              slot_index, BC_INTEGRITY_HASH_RING_OP_PROBE));
  io_uring_prep_close_direct(close_sqe, slot_index);
  io_uring_sqe_set_data64(close_sqe,
                          bc_integrity_hash_ring_encode_user_data(
                              slot_index, BC_INTEGRITY_HASH_RING_OP_CLOSE));
  return true;
}

static bool bc_integrity_hash_ring_fits_in_slot(
    const bc_integrity_hash_batch_item_t *item) {
  return item->file_size > 0 &&
         item->file_size <= BC_INTEGRITY_HASH_RING_SLOT_BUFFER_BYTES;
}

static bool bc_integrity_hash_ring_handle_cqe(
    bc_integrity_hash_ring_t *ring, bc_integrity_hash_batch_item_t *items,
    const size_t *slot_to_item, size_t *slot_bytes_read,
    bc_integrity_hash_consumer_fn_t consumer_function,
    struct io_uring_cqe *cqe) {
  uint64_t user_data = io_uring_cqe_get_data64(cqe);
  unsigned int slot_index = bc_integrity_hash_ring_decode_slot(user_data);
  unsigned int operation_code =
      bc_integrity_hash_ring_decode_operation(user_data);
  int cqe_result = cqe->res;
  size_t item_index = slot_to_item[slot_index];
  bc_integrity_hash_batch_item_t *item = &items[item_index];

  if (operation_code == BC_INTEGRITY_HASH_RING_OP_OPENAT) {
    if (cqe_result < 0) {
      item->success = false;
      item->errno_value = -cqe_result;
    }
    return true;
  }

  if (operation_code == BC_INTEGRITY_HASH_RING_OP_READ) {
    if (cqe_result < 0) {
      if (item->errno_value == 0) {
        item->success = false;
        item->errno_value = (cqe_result == -ECANCELED) ? EIO : -cqe_result;
      }
      return true;
    }
    if ((size_t)cqe_result != item->file_size) {
      item->success = false;
      item->errno_value = EIO;
      return true;
    }
    slot_bytes_read[slot_index] = (size_t)cqe_result;
    return true;
  }

  if (operation_code == BC_INTEGRITY_HASH_RING_OP_PROBE) {
    if (item->errno_value != 0) {
      return true;
    }
    if (cqe_result < 0) {
      item->success = false;
      item->errno_value = (cqe_result == -ECANCELED) ? EIO : -cqe_result;
      return true;
    }
    if (cqe_result > 0) {
      item->success = false;
      item->errno_value = EIO;
      return true;
    }
    size_t bytes_to_consume = slot_bytes_read[slot_index];
    if (bytes_to_consume == 0) {
      item->success = false;
      item->errno_value = EIO;
      return true;
    }
    const unsigned char *buffer_address = ring->slot_buffers[slot_index];
    if (!consumer_function(item->consumer_context, buffer_address,
                           bytes_to_consume)) {
      item->success = false;
      item->errno_value = EIO;
      return true;
    }
    item->success = true;
    item->errno_value = 0;
    return true;
  }

  return true;
}

static bool bc_integrity_hash_ring_drive_chunk(
    bc_integrity_hash_ring_t *ring, bc_integrity_hash_batch_item_t *items,
    size_t chunk_start, size_t chunk_count,
    bc_integrity_hash_consumer_fn_t consumer_function) {
  size_t slot_to_item[BC_INTEGRITY_HASH_RING_SLOT_COUNT];
  size_t slot_bytes_read[BC_INTEGRITY_HASH_RING_SLOT_COUNT] = {0};
  unsigned int submitted_slot_count = 0;

  for (size_t offset = 0; offset < chunk_count; ++offset) {
    size_t item_index = chunk_start + offset;
    const bc_integrity_hash_batch_item_t *item = &items[item_index];
    if (!bc_integrity_hash_ring_fits_in_slot(item)) {
      continue;
    }
    unsigned int slot_index = submitted_slot_count;
    if (!bc_integrity_hash_ring_submit_slot(
            &ring->ring, slot_index, item, ring->slot_buffers[slot_index],
            &ring->slot_growth_probes[slot_index])) {
      return false;
    }
    slot_to_item[slot_index] = item_index;
    submitted_slot_count += 1;
  }

  if (submitted_slot_count == 0) {
    return true;
  }

  int submit_status = io_uring_submit(&ring->ring);
  if (submit_status < 0) {
    return false;
  }

  unsigned int expected_completion_count = 4U * submitted_slot_count;
  unsigned int completions_seen = 0;
  struct io_uring_cqe *cqe_batch[BC_INTEGRITY_HASH_RING_QUEUE_DEPTH];
  while (completions_seen < expected_completion_count) {
    struct io_uring_cqe *wait_sentinel = NULL;
    int wait_status = io_uring_wait_cqe(&ring->ring, &wait_sentinel);
    if (wait_status < 0) {
      if (wait_status == -EINTR) {
        continue;
      }
      return false;
    }
    unsigned int batch_count = io_uring_peek_batch_cqe(
        &ring->ring, cqe_batch, BC_INTEGRITY_HASH_RING_QUEUE_DEPTH);
    for (unsigned int i = 0; i < batch_count; ++i) {
      bc_integrity_hash_ring_handle_cqe(ring, items, slot_to_item,
                                        slot_bytes_read, consumer_function,
                                        cqe_batch[i]);
    }
    io_uring_cq_advance(&ring->ring, batch_count);
    completions_seen += batch_count;
  }

  return true;
}

static void bc_integrity_hash_ring_fallback_sync(
    bc_integrity_hash_batch_item_t *item,
    bc_integrity_hash_consumer_fn_t consumer_function) {
  int fallback_errno = 0;
  if (bc_integrity_hash_consume_file(item->absolute_path, item->file_size,
                                     item->consumer_context, consumer_function,
                                     &fallback_errno)) {
    item->success = true;
    item->errno_value = 0;
  } else {
    item->success = false;
    item->errno_value = fallback_errno;
  }
}

bool bc_integrity_hash_consume_batch(
    bc_integrity_hash_ring_t *ring, bc_integrity_hash_batch_item_t *items,
    size_t item_count, bc_integrity_hash_consumer_fn_t consumer_function) {
  for (size_t index = 0; index < item_count; ++index) {
    items[index].success = false;
    items[index].errno_value = 0;
  }

  size_t processed = 0;
  while (processed < item_count) {
    size_t chunk_remaining = item_count - processed;
    size_t chunk_count = chunk_remaining < BC_INTEGRITY_HASH_RING_SLOT_COUNT
                             ? chunk_remaining
                             : BC_INTEGRITY_HASH_RING_SLOT_COUNT;
    if (!bc_integrity_hash_ring_drive_chunk(ring, items, processed, chunk_count,
                                            consumer_function)) {
      for (size_t offset = 0; offset < chunk_count; ++offset) {
        bc_integrity_hash_batch_item_t *item = &items[processed + offset];
        if (!item->success && item->errno_value == 0) {
          bc_integrity_hash_ring_fallback_sync(item, consumer_function);
        }
      }
      processed += chunk_count;
      continue;
    }
    for (size_t offset = 0; offset < chunk_count; ++offset) {
      bc_integrity_hash_batch_item_t *item = &items[processed + offset];
      if (item->success) {
        continue;
      }
      if (bc_integrity_hash_ring_fits_in_slot(item) && item->errno_value != 0) {
        continue;
      }
      bc_integrity_hash_ring_fallback_sync(item, consumer_function);
    }
    processed += chunk_count;
  }

  return true;
}
