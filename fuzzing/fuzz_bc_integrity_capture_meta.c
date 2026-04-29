// SPDX-License-Identifier: MIT

#include "bc_allocators.h"
#include "bc_integrity_capture_internal.h"
#include "bc_integrity_entry_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define BC_INTEGRITY_FUZZ_CAPTURE_PATH_BUFFER_SIZE 8192u

static const mode_t bc_integrity_fuzz_capture_safe_modes[] = {
    S_IFDIR | 0755u,
    S_IFIFO | 0644u,
    S_IFSOCK | 0600u,
    S_IFBLK | 0600u,
    S_IFCHR | 0600u,
};

static const size_t bc_integrity_fuzz_capture_safe_mode_count =
    sizeof(bc_integrity_fuzz_capture_safe_modes) /
    sizeof(bc_integrity_fuzz_capture_safe_modes[0]);

static int bc_integrity_fuzz_capture_meta_one(const uint8_t *data, size_t size) {
  if (size < 2u) {
    return 0;
  }
  unsigned int mode_index = data[0] % bc_integrity_fuzz_capture_safe_mode_count;
  unsigned int errno_choice = data[1];

  size_t path_offset = 2u;
  size_t path_length = size - path_offset;
  if (path_length >= BC_INTEGRITY_FUZZ_CAPTURE_PATH_BUFFER_SIZE) {
    path_length = BC_INTEGRITY_FUZZ_CAPTURE_PATH_BUFFER_SIZE - 1u;
  }

  char absolute_buffer[BC_INTEGRITY_FUZZ_CAPTURE_PATH_BUFFER_SIZE];
  for (size_t index = 0; index < path_length; ++index) {
    uint8_t byte = data[path_offset + index];
    if (byte == '\0') {
      byte = '_';
    }
    absolute_buffer[index] = (char)byte;
  }
  absolute_buffer[path_length] = '\0';

  size_t relative_split = path_length / 2u;
  const char *absolute_path = absolute_buffer;
  size_t absolute_length = path_length;
  const char *relative_path = absolute_buffer + relative_split;
  size_t relative_length = path_length - relative_split;

  bc_allocators_context_config_t config;
  memset(&config, 0, sizeof(config));
  bc_allocators_context_t *memory = NULL;
  if (!bc_allocators_context_create(&config, &memory)) {
    return 0;
  }

  struct stat stat_buffer;
  memset(&stat_buffer, 0, sizeof(stat_buffer));
  stat_buffer.st_mode = bc_integrity_fuzz_capture_safe_modes[mode_index];
  stat_buffer.st_size = 0;
  stat_buffer.st_uid = 0;
  stat_buffer.st_gid = 0;
  stat_buffer.st_ino = 1u;
  stat_buffer.st_nlink = 1u;
  stat_buffer.st_mtim.tv_sec = 0;
  stat_buffer.st_mtim.tv_nsec = 0;

  bc_integrity_entry_t entry;
  memset(&entry, 0, sizeof(entry));
  (void)bc_integrity_capture_entry_from_stat(
      memory, &stat_buffer, BC_INTEGRITY_DIGEST_ALGORITHM_SHA256, -1, NULL,
      absolute_path, absolute_length, relative_path, relative_length, true,
      &entry);
  (void)bc_integrity_entry_kind_name(entry.kind);

  bc_integrity_entry_t error_entry;
  memset(&error_entry, 0, sizeof(error_entry));
  bc_integrity_capture_set_error_message(&error_entry, (int)errno_choice);
  (void)bc_integrity_entry_kind_name(error_entry.kind);

  for (bc_integrity_entry_kind_t kind = BC_INTEGRITY_ENTRY_KIND_FILE;
       kind <= BC_INTEGRITY_ENTRY_KIND_DEVICE;
       kind = (bc_integrity_entry_kind_t)(kind + 1)) {
    (void)bc_integrity_entry_kind_name(kind);
  }

  bc_allocators_context_destroy(memory);
  return 0;
}

#ifdef BC_FUZZ_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  return bc_integrity_fuzz_capture_meta_one(data, size);
}
#else
int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <input-file>\n", argv[0]);
    return 2;
  }
  FILE *file = fopen(argv[1], "rb");
  if (file == NULL) {
    return 2;
  }
  uint8_t buffer[1u << 16];
  size_t length = fread(buffer, 1u, sizeof(buffer), file);
  fclose(file);
  return bc_integrity_fuzz_capture_meta_one(buffer, length);
}
#endif
