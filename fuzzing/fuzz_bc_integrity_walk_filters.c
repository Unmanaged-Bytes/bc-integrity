// SPDX-License-Identifier: MIT

#include "bc_integrity_walk_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BC_INTEGRITY_FUZZ_WALK_BUFFER_SIZE 4096u

static int bc_integrity_fuzz_walk_filters_one(const uint8_t *data, size_t size) {
  size_t path_length = size;
  if (path_length >= BC_INTEGRITY_FUZZ_WALK_BUFFER_SIZE) {
    path_length = BC_INTEGRITY_FUZZ_WALK_BUFFER_SIZE - 1u;
  }
  char buffer[BC_INTEGRITY_FUZZ_WALK_BUFFER_SIZE];
  for (size_t index = 0; index < path_length; ++index) {
    uint8_t byte = data[index];
    if (byte == '\0') {
      byte = '_';
    }
    buffer[index] = (char)byte;
  }
  buffer[path_length] = '\0';

  (void)bc_integrity_walk_is_hidden_segment(buffer, path_length);
  (void)bc_integrity_walk_is_virtual_root(buffer, path_length);
  (void)bc_integrity_walk_is_virtual_subpath(buffer, path_length, buffer,
                                             path_length);

  if (path_length > 1u) {
    size_t split = path_length / 2u;
    (void)bc_integrity_walk_is_virtual_subpath(buffer, split, buffer + split,
                                               path_length - split);
    (void)bc_integrity_walk_is_virtual_subpath(buffer + split,
                                               path_length - split, buffer,
                                               split);
  }

  return 0;
}

#ifdef BC_FUZZ_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  return bc_integrity_fuzz_walk_filters_one(data, size);
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
  return bc_integrity_fuzz_walk_filters_one(buffer, length);
}
#endif
