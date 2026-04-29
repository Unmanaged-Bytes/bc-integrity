// SPDX-License-Identifier: MIT

#include "bc_integrity_capture_hash_internal.h"

#include "bc_core.h"
#include "bc_core_hash.h"

#define XXH_INLINE_ALL
#include <xxhash.h>

#include <errno.h>
#include <fcntl.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#define BC_INTEGRITY_HASH_STREAM_BUFFER_SIZE                                   \
  BC_INTEGRITY_HASH_RING_SLOT_BUFFER_BYTES
#define BC_INTEGRITY_HASH_FADVISE_THRESHOLD BC_INTEGRITY_HASH_STREAM_BUFFER_SIZE

static const char bc_integrity_hash_hex_alphabet[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

typedef struct bc_integrity_hash_sha256_state {
  bc_core_sha256_context_t digest_context;
} bc_integrity_hash_sha256_state_t;

typedef struct bc_integrity_hash_xxh3_state {
  XXH3_state_t digest_context;
} bc_integrity_hash_xxh3_state_t;

typedef struct bc_integrity_hash_internal_state {
  bc_integrity_digest_algorithm_t algorithm;
  union {
    bc_integrity_hash_sha256_state_t sha256;
    bc_integrity_hash_xxh3_state_t xxh3;
  } algo;
} __attribute__((aligned(64))) bc_integrity_hash_internal_state_t;

_Static_assert(sizeof(bc_integrity_hash_internal_state_t) <=
                   BC_INTEGRITY_HASH_CONSUMER_STATE_BYTES,
               "BC_INTEGRITY_HASH_CONSUMER_STATE_BYTES too small");

static void bc_integrity_hash_encode_hex(const uint8_t *digest_bytes,
                                         size_t digest_size, char *out_buffer) {
  for (size_t index = 0; index < digest_size; ++index) {
    uint8_t byte = digest_bytes[index];
    out_buffer[(2u * index) + 0u] =
        bc_integrity_hash_hex_alphabet[(byte >> 4) & 0x0Fu];
    out_buffer[(2u * index) + 1u] =
        bc_integrity_hash_hex_alphabet[byte & 0x0Fu];
  }
}

static bool bc_integrity_hash_consumer_sha256(void *consumer_context,
                                              const void *chunk_data,
                                              size_t chunk_size) {
  bc_integrity_hash_internal_state_t *state =
      (bc_integrity_hash_internal_state_t *)consumer_context;
  return bc_core_sha256_update(&state->algo.sha256.digest_context, chunk_data,
                               chunk_size);
}

static bool bc_integrity_hash_consumer_xxh3(void *consumer_context,
                                            const void *chunk_data,
                                            size_t chunk_size) {
  bc_integrity_hash_internal_state_t *state =
      (bc_integrity_hash_internal_state_t *)consumer_context;
  return XXH3_64bits_update(&state->algo.xxh3.digest_context, chunk_data,
                            chunk_size) == XXH_OK;
}

static bool bc_integrity_hash_consumer_xxh128(void *consumer_context,
                                              const void *chunk_data,
                                              size_t chunk_size) {
  bc_integrity_hash_internal_state_t *state =
      (bc_integrity_hash_internal_state_t *)consumer_context;
  return XXH3_128bits_update(&state->algo.xxh3.digest_context, chunk_data,
                             chunk_size) == XXH_OK;
}

bc_integrity_hash_consumer_fn_t bc_integrity_hash_consumer_function_for(
    bc_integrity_digest_algorithm_t digest_algorithm) {
  switch (digest_algorithm) {
  case BC_INTEGRITY_DIGEST_ALGORITHM_XXH3:
    return bc_integrity_hash_consumer_xxh3;
  case BC_INTEGRITY_DIGEST_ALGORITHM_XXH128:
    return bc_integrity_hash_consumer_xxh128;
  case BC_INTEGRITY_DIGEST_ALGORITHM_SHA256:
  default:
    return bc_integrity_hash_consumer_sha256;
  }
}

void bc_integrity_hash_consumer_begin(
    bc_integrity_digest_algorithm_t digest_algorithm, void *consumer_state) {
  bc_integrity_hash_internal_state_t *state =
      (bc_integrity_hash_internal_state_t *)consumer_state;
  state->algorithm = digest_algorithm;
  switch (digest_algorithm) {
  case BC_INTEGRITY_DIGEST_ALGORITHM_XXH3:
    XXH3_64bits_reset(&state->algo.xxh3.digest_context);
    return;
  case BC_INTEGRITY_DIGEST_ALGORITHM_XXH128:
    XXH3_128bits_reset(&state->algo.xxh3.digest_context);
    return;
  case BC_INTEGRITY_DIGEST_ALGORITHM_SHA256:
  default:
    bc_core_sha256_init(&state->algo.sha256.digest_context);
    return;
  }
}

bool bc_integrity_hash_finalize_into_hex(
    bc_integrity_digest_algorithm_t digest_algorithm, void *consumer_state,
    char *out_digest_hex, size_t *out_digest_hex_length) {
  bc_integrity_hash_internal_state_t *state =
      (bc_integrity_hash_internal_state_t *)consumer_state;
  switch (digest_algorithm) {
  case BC_INTEGRITY_DIGEST_ALGORITHM_XXH3: {
    XXH64_hash_t digest = XXH3_64bits_digest(&state->algo.xxh3.digest_context);
    XXH64_canonical_t canonical;
    XXH64_canonicalFromHash(&canonical, digest);
    bc_integrity_hash_encode_hex(canonical.digest, sizeof(canonical.digest),
                                 out_digest_hex);
    *out_digest_hex_length = sizeof(canonical.digest) * 2u;
    out_digest_hex[*out_digest_hex_length] = '\0';
    return true;
  }
  case BC_INTEGRITY_DIGEST_ALGORITHM_XXH128: {
    XXH128_hash_t digest =
        XXH3_128bits_digest(&state->algo.xxh3.digest_context);
    XXH128_canonical_t canonical;
    XXH128_canonicalFromHash(&canonical, digest);
    bc_integrity_hash_encode_hex(canonical.digest, sizeof(canonical.digest),
                                 out_digest_hex);
    *out_digest_hex_length = sizeof(canonical.digest) * 2u;
    out_digest_hex[*out_digest_hex_length] = '\0';
    return true;
  }
  case BC_INTEGRITY_DIGEST_ALGORITHM_SHA256:
  default: {
    uint8_t digest[BC_CORE_SHA256_DIGEST_SIZE];
    if (!bc_core_sha256_finalize(&state->algo.sha256.digest_context, digest)) {
      return false;
    }
    bc_integrity_hash_encode_hex(digest, BC_CORE_SHA256_DIGEST_SIZE,
                                 out_digest_hex);
    *out_digest_hex_length = BC_CORE_SHA256_DIGEST_SIZE * 2u;
    out_digest_hex[*out_digest_hex_length] = '\0';
    return true;
  }
  }
}

static bool bc_integrity_hash_open_read_only(const char *absolute_path,
                                             int *out_file_descriptor,
                                             int *out_errno_value) {
  int flags_with_noatime = O_RDONLY | O_CLOEXEC | O_NOATIME;
  int file_descriptor = open(absolute_path, flags_with_noatime);
  if (file_descriptor < 0 && errno == EPERM) {
    int flags_without_noatime = O_RDONLY | O_CLOEXEC;
    file_descriptor = open(absolute_path, flags_without_noatime);
  }
  if (file_descriptor < 0) {
    *out_errno_value = errno;
    return false;
  }
  *out_file_descriptor = file_descriptor;
  return true;
}

bool bc_integrity_hash_consume_file(const char *absolute_path,
                                    size_t file_size_hint,
                                    void *consumer_context,
                                    bc_integrity_hash_consumer_fn_t consumer,
                                    int *out_errno_value) {
  *out_errno_value = 0;
  int file_descriptor = -1;
  if (!bc_integrity_hash_open_read_only(absolute_path, &file_descriptor,
                                        out_errno_value)) {
    return false;
  }
  if (file_size_hint > BC_INTEGRITY_HASH_FADVISE_THRESHOLD) {
    posix_fadvise(file_descriptor, (off_t)0, (off_t)0, POSIX_FADV_SEQUENTIAL);
  }
  static __thread unsigned char
      stream_buffer[BC_INTEGRITY_HASH_STREAM_BUFFER_SIZE]
      __attribute__((aligned(64)));
  while (true) {
    ssize_t bytes_read =
        read(file_descriptor, stream_buffer, sizeof(stream_buffer));
    if (bytes_read < 0) {
      if (errno == EINTR) {
        continue;
      }
      *out_errno_value = errno;
      close(file_descriptor);
      return false;
    }
    if (bytes_read == 0) {
      close(file_descriptor);
      return true;
    }
    if (!consumer(consumer_context, stream_buffer, (size_t)bytes_read)) {
      *out_errno_value = EIO;
      close(file_descriptor);
      return false;
    }
    if ((size_t)bytes_read < sizeof(stream_buffer)) {
      close(file_descriptor);
      return true;
    }
  }
}

bool bc_integrity_hash_compute_for_algorithm(
    const char *absolute_path, size_t file_size,
    bc_integrity_digest_algorithm_t digest_algorithm, char *out_digest_hex,
    size_t *out_digest_hex_length, int *out_errno_value) {
  alignas(64) bc_integrity_hash_consumer_state_t public_state;
  bc_integrity_hash_consumer_begin(digest_algorithm, &public_state);
  bc_integrity_hash_consumer_fn_t consumer =
      bc_integrity_hash_consumer_function_for(digest_algorithm);
  if (!bc_integrity_hash_consume_file(absolute_path, file_size, &public_state,
                                      consumer, out_errno_value)) {
    return false;
  }
  if (!bc_integrity_hash_finalize_into_hex(digest_algorithm, &public_state,
                                           out_digest_hex,
                                           out_digest_hex_length)) {
    *out_errno_value = EIO;
    return false;
  }
  return true;
}
