// SPDX-License-Identifier: MIT

#ifndef BC_INTEGRITY_ENTRY_INTERNAL_H
#define BC_INTEGRITY_ENTRY_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BC_INTEGRITY_DIGEST_HEX_MAX_LENGTH ((size_t)64)
#define BC_INTEGRITY_DIGEST_HEX_BUFFER_SIZE                                    \
  (BC_INTEGRITY_DIGEST_HEX_MAX_LENGTH + 1U)
#define BC_INTEGRITY_ERROR_MESSAGE_BUFFER_SIZE ((size_t)128)

typedef enum {
  BC_INTEGRITY_ENTRY_KIND_FILE,
  BC_INTEGRITY_ENTRY_KIND_DIRECTORY,
  BC_INTEGRITY_ENTRY_KIND_SYMLINK,
  BC_INTEGRITY_ENTRY_KIND_FIFO,
  BC_INTEGRITY_ENTRY_KIND_SOCKET,
  BC_INTEGRITY_ENTRY_KIND_DEVICE,
} bc_integrity_entry_kind_t;

typedef struct bc_integrity_entry {
  const char *relative_path;
  size_t relative_path_length;
  const char *absolute_path;
  size_t absolute_path_length;
  bc_integrity_entry_kind_t kind;
  bool ok;
  int errno_value;
  char error_message[BC_INTEGRITY_ERROR_MESSAGE_BUFFER_SIZE];
  size_t error_message_length;
  char digest_hex[BC_INTEGRITY_DIGEST_HEX_BUFFER_SIZE];
  size_t digest_hex_length;
  uint64_t size_bytes;
  uint64_t mode;
  uint64_t uid;
  uint64_t gid;
  uint64_t mtime_sec;
  uint64_t mtime_nsec;
  uint64_t inode;
  uint64_t nlink;
  const char *link_target;
  size_t link_target_length;
} bc_integrity_entry_t;

const char *bc_integrity_entry_kind_name(bc_integrity_entry_kind_t kind);

#endif /* BC_INTEGRITY_ENTRY_INTERNAL_H */
