// SPDX-License-Identifier: MIT

#include "bc_integrity_capture_internal.h"

#include "bc_allocators.h"
#include "bc_allocators_pool.h"
#include "bc_core.h"
#include "bc_core_format.h"
#include "bc_core_hash.h"

#define XXH_INLINE_ALL
#include <xxhash.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BC_INTEGRITY_CAPTURE_READ_BUFFER_SIZE ((size_t)(128 * 1024))
#define BC_INTEGRITY_CAPTURE_FADVISE_THRESHOLD                                 \
  BC_INTEGRITY_CAPTURE_READ_BUFFER_SIZE

static const char bc_integrity_capture_hex_alphabet[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

static void bc_integrity_capture_encode_hex(const uint8_t *digest_bytes,
                                            size_t digest_size,
                                            char *out_buffer) {
  for (size_t index = 0; index < digest_size; ++index) {
    uint8_t byte = digest_bytes[index];
    out_buffer[(2u * index) + 0u] =
        bc_integrity_capture_hex_alphabet[(byte >> 4) & 0x0Fu];
    out_buffer[(2u * index) + 1u] =
        bc_integrity_capture_hex_alphabet[byte & 0x0Fu];
  }
}

static bc_integrity_entry_kind_t
bc_integrity_capture_kind_from_mode(mode_t mode) {
  if (S_ISREG(mode)) {
    return BC_INTEGRITY_ENTRY_KIND_FILE;
  }
  if (S_ISDIR(mode)) {
    return BC_INTEGRITY_ENTRY_KIND_DIRECTORY;
  }
  if (S_ISLNK(mode)) {
    return BC_INTEGRITY_ENTRY_KIND_SYMLINK;
  }
  if (S_ISFIFO(mode)) {
    return BC_INTEGRITY_ENTRY_KIND_FIFO;
  }
  if (S_ISSOCK(mode)) {
    return BC_INTEGRITY_ENTRY_KIND_SOCKET;
  }
  return BC_INTEGRITY_ENTRY_KIND_DEVICE;
}

const char *bc_integrity_entry_kind_name(bc_integrity_entry_kind_t kind) {
  switch (kind) {
  case BC_INTEGRITY_ENTRY_KIND_DIRECTORY:
    return "dir";
  case BC_INTEGRITY_ENTRY_KIND_SYMLINK:
    return "symlink";
  case BC_INTEGRITY_ENTRY_KIND_FIFO:
    return "fifo";
  case BC_INTEGRITY_ENTRY_KIND_SOCKET:
    return "socket";
  case BC_INTEGRITY_ENTRY_KIND_DEVICE:
    return "device";
  case BC_INTEGRITY_ENTRY_KIND_FILE:
  default:
    return "file";
  }
}

void bc_integrity_capture_set_error_message(bc_integrity_entry_t *entry,
                                            int errno_value) {
  entry->ok = false;
  entry->errno_value = errno_value;
  char tmp[BC_INTEGRITY_ERROR_MESSAGE_BUFFER_SIZE];
  const char *message = strerror_r(errno_value, tmp, sizeof(tmp));
  if (message == NULL) {
    message = "unknown error";
  }
  size_t message_length = 0;
  (void)bc_core_length(message, '\0', &message_length);
  if (message_length >= sizeof(entry->error_message)) {
    message_length = sizeof(entry->error_message) - 1u;
  }
  bc_core_copy(entry->error_message, message, message_length);
  entry->error_message[message_length] = '\0';
  entry->error_message_length = message_length;
}

static bool bc_integrity_capture_read_link(
    bc_allocators_context_t *memory_context, int parent_directory_fd,
    const char *basename, const char *absolute_path,
    const char **out_link_target, size_t *out_link_target_length,
    int *out_errno_value) {
  char buffer[4096];
  ssize_t read_length;
  if (parent_directory_fd >= 0 && basename != NULL) {
    read_length =
        readlinkat(parent_directory_fd, basename, buffer, sizeof(buffer));
  } else {
    read_length = readlink(absolute_path, buffer, sizeof(buffer));
  }
  if (read_length < 0) {
    *out_errno_value = errno;
    return false;
  }
  if ((size_t)read_length >= sizeof(buffer)) {
    *out_errno_value = ENAMETOOLONG;
    return false;
  }
  char *copy = NULL;
  if (!bc_allocators_pool_allocate(memory_context, (size_t)read_length + 1u,
                                   (void **)&copy)) {
    *out_errno_value = ENOMEM;
    return false;
  }
  bc_core_copy(copy, buffer, (size_t)read_length);
  copy[read_length] = '\0';
  *out_link_target = copy;
  *out_link_target_length = (size_t)read_length;
  return true;
}

static bool bc_integrity_capture_compute_sha256(int file_descriptor,
                                                char *out_digest_hex,
                                                size_t *out_digest_hex_length,
                                                int *out_errno_value) {
  bc_core_sha256_context_t sha256_context;
  if (!bc_core_sha256_init(&sha256_context)) {
    *out_errno_value = EIO;
    return false;
  }
  static __thread unsigned char buffer[BC_INTEGRITY_CAPTURE_READ_BUFFER_SIZE]
      __attribute__((aligned(64)));
  while (true) {
    ssize_t bytes_read = read(file_descriptor, buffer, sizeof(buffer));
    if (bytes_read < 0) {
      if (errno == EINTR) {
        continue;
      }
      *out_errno_value = errno;
      return false;
    }
    if (bytes_read == 0) {
      break;
    }
    if (!bc_core_sha256_update(&sha256_context, buffer, (size_t)bytes_read)) {
      *out_errno_value = EIO;
      return false;
    }
  }
  uint8_t digest[BC_CORE_SHA256_DIGEST_SIZE];
  if (!bc_core_sha256_finalize(&sha256_context, digest)) {
    *out_errno_value = EIO;
    return false;
  }
  bc_integrity_capture_encode_hex(digest, BC_CORE_SHA256_DIGEST_SIZE,
                                  out_digest_hex);
  *out_digest_hex_length = BC_CORE_SHA256_DIGEST_SIZE * 2u;
  out_digest_hex[*out_digest_hex_length] = '\0';
  return true;
}

static bool bc_integrity_capture_compute_xxh3(int file_descriptor,
                                              char *out_digest_hex,
                                              size_t *out_digest_hex_length,
                                              int *out_errno_value) {
  XXH3_state_t state;
  if (XXH3_64bits_reset(&state) != XXH_OK) {
    *out_errno_value = EIO;
    return false;
  }
  static __thread unsigned char buffer[BC_INTEGRITY_CAPTURE_READ_BUFFER_SIZE]
      __attribute__((aligned(64)));
  while (true) {
    ssize_t bytes_read = read(file_descriptor, buffer, sizeof(buffer));
    if (bytes_read < 0) {
      if (errno == EINTR) {
        continue;
      }
      *out_errno_value = errno;
      return false;
    }
    if (bytes_read == 0) {
      break;
    }
    if (XXH3_64bits_update(&state, buffer, (size_t)bytes_read) != XXH_OK) {
      *out_errno_value = EIO;
      return false;
    }
  }
  XXH64_hash_t digest = XXH3_64bits_digest(&state);
  XXH64_canonical_t canonical;
  XXH64_canonicalFromHash(&canonical, digest);
  bc_integrity_capture_encode_hex(canonical.digest, sizeof(canonical.digest),
                                  out_digest_hex);
  *out_digest_hex_length = sizeof(canonical.digest) * 2u;
  out_digest_hex[*out_digest_hex_length] = '\0';
  return true;
}

static bool bc_integrity_capture_compute_xxh128(int file_descriptor,
                                                char *out_digest_hex,
                                                size_t *out_digest_hex_length,
                                                int *out_errno_value) {
  XXH3_state_t state;
  if (XXH3_128bits_reset(&state) != XXH_OK) {
    *out_errno_value = EIO;
    return false;
  }
  static __thread unsigned char buffer[BC_INTEGRITY_CAPTURE_READ_BUFFER_SIZE]
      __attribute__((aligned(64)));
  while (true) {
    ssize_t bytes_read = read(file_descriptor, buffer, sizeof(buffer));
    if (bytes_read < 0) {
      if (errno == EINTR) {
        continue;
      }
      *out_errno_value = errno;
      return false;
    }
    if (bytes_read == 0) {
      break;
    }
    if (XXH3_128bits_update(&state, buffer, (size_t)bytes_read) != XXH_OK) {
      *out_errno_value = EIO;
      return false;
    }
  }
  XXH128_hash_t digest = XXH3_128bits_digest(&state);
  XXH128_canonical_t canonical;
  XXH128_canonicalFromHash(&canonical, digest);
  bc_integrity_capture_encode_hex(canonical.digest, sizeof(canonical.digest),
                                  out_digest_hex);
  *out_digest_hex_length = sizeof(canonical.digest) * 2u;
  out_digest_hex[*out_digest_hex_length] = '\0';
  return true;
}

bool bc_integrity_capture_compute_digest(
    const char *absolute_path, size_t file_size,
    bc_integrity_digest_algorithm_t digest_algorithm, char *out_digest_hex,
    size_t *out_digest_hex_length, int *out_errno_value) {
  int open_flags = O_RDONLY | O_CLOEXEC | O_NOATIME;
  int file_descriptor = open(absolute_path, open_flags);
  if (file_descriptor < 0 && errno == EPERM) {
    file_descriptor = open(absolute_path, O_RDONLY | O_CLOEXEC);
  }
  if (file_descriptor < 0) {
    *out_errno_value = errno;
    return false;
  }
  if (file_size > BC_INTEGRITY_CAPTURE_FADVISE_THRESHOLD) {
    posix_fadvise(file_descriptor, (off_t)0, (off_t)0, POSIX_FADV_SEQUENTIAL);
  }

  bool ok = false;
  switch (digest_algorithm) {
  case BC_INTEGRITY_DIGEST_ALGORITHM_XXH3:
    ok = bc_integrity_capture_compute_xxh3(file_descriptor, out_digest_hex,
                                           out_digest_hex_length,
                                           out_errno_value);
    break;
  case BC_INTEGRITY_DIGEST_ALGORITHM_XXH128:
    ok = bc_integrity_capture_compute_xxh128(file_descriptor, out_digest_hex,
                                             out_digest_hex_length,
                                             out_errno_value);
    break;
  case BC_INTEGRITY_DIGEST_ALGORITHM_SHA256:
  default:
    ok = bc_integrity_capture_compute_sha256(file_descriptor, out_digest_hex,
                                             out_digest_hex_length,
                                             out_errno_value);
    break;
  }
  close(file_descriptor);
  return ok;
}

bool bc_integrity_capture_entry_from_stat(
    bc_allocators_context_t *memory_context, const struct stat *stat_buffer,
    bc_integrity_digest_algorithm_t digest_algorithm, int parent_directory_fd,
    const char *basename, const char *absolute_path,
    size_t absolute_path_length, const char *relative_path,
    size_t relative_path_length, bool skip_digest,
    bc_integrity_entry_t *out_entry) {
  (void)absolute_path_length;
  bc_core_zero(out_entry, sizeof(*out_entry));
  out_entry->relative_path = relative_path;
  out_entry->relative_path_length = relative_path_length;
  out_entry->kind = bc_integrity_capture_kind_from_mode(stat_buffer->st_mode);
  out_entry->size_bytes = (uint64_t)stat_buffer->st_size;
  out_entry->mode = (uint64_t)stat_buffer->st_mode;
  out_entry->uid = (uint64_t)stat_buffer->st_uid;
  out_entry->gid = (uint64_t)stat_buffer->st_gid;
  out_entry->mtime_sec = (uint64_t)stat_buffer->st_mtim.tv_sec;
  out_entry->mtime_nsec = (uint64_t)stat_buffer->st_mtim.tv_nsec;
  out_entry->inode = (uint64_t)stat_buffer->st_ino;
  out_entry->nlink = (uint64_t)stat_buffer->st_nlink;
  out_entry->ok = true;

  if (out_entry->kind == BC_INTEGRITY_ENTRY_KIND_SYMLINK) {
    const char *link_target = NULL;
    size_t link_target_length = 0;
    int errno_value = 0;
    if (bc_integrity_capture_read_link(memory_context, parent_directory_fd,
                                       basename, absolute_path, &link_target,
                                       &link_target_length, &errno_value)) {
      out_entry->link_target = link_target;
      out_entry->link_target_length = link_target_length;
    } else {
      bc_integrity_capture_set_error_message(out_entry, errno_value);
    }
    return true;
  }

  if (out_entry->kind == BC_INTEGRITY_ENTRY_KIND_FILE && !skip_digest) {
    int errno_value = 0;
    size_t digest_length = 0;
    if (bc_integrity_capture_compute_digest(
            absolute_path, (size_t)stat_buffer->st_size, digest_algorithm,
            out_entry->digest_hex, &digest_length, &errno_value)) {
      out_entry->digest_hex_length = digest_length;
    } else {
      bc_integrity_capture_set_error_message(out_entry, errno_value);
    }
    return true;
  }

  return true;
}
