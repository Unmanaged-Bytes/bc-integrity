// SPDX-License-Identifier: MIT

#include "bc_allocators.h"
#include "bc_hrbl_reader.h"
#include "bc_hrbl_verify.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int bc_integrity_fuzz_manifest_reader_one(const uint8_t *data,
                                                 size_t size) {
  if (bc_hrbl_verify_buffer(data, size) != BC_HRBL_VERIFY_OK) {
    return 0;
  }
  bc_allocators_context_config_t config;
  memset(&config, 0, sizeof(config));
  bc_allocators_context_t *memory = NULL;
  if (!bc_allocators_context_create(&config, &memory)) {
    return 0;
  }
  bc_hrbl_reader_t *reader = NULL;
  if (bc_hrbl_reader_open_buffer(memory, data, size, &reader)) {
    uint64_t root_count = 0u;
    (void)bc_hrbl_reader_root_count(reader, &root_count);
    bc_hrbl_value_ref_t value;
    (void)bc_hrbl_reader_find(reader, "meta", 4u, &value);
    (void)bc_hrbl_reader_find(reader, "meta.tool", 9u, &value);
    (void)bc_hrbl_reader_find(reader, "meta.root_path", 14u, &value);
    (void)bc_hrbl_reader_find(reader, "meta.digest_algorithm", 21u, &value);
    (void)bc_hrbl_reader_find(reader, "meta.file_count", 15u, &value);
    (void)bc_hrbl_reader_find(reader, "entries", 7u, &value);
    if (bc_hrbl_reader_find(reader, "entries", 7u, &value)) {
      bc_hrbl_iter_t iter;
      if (bc_hrbl_reader_iter_block(&value, &iter)) {
        bc_hrbl_value_ref_t child;
        const char *key = NULL;
        size_t key_length = 0;
        size_t bounded = 0;
        while (bc_hrbl_iter_next(&iter, &child, &key, &key_length) &&
               bounded < 256) {
          bounded += 1u;
        }
      }
    }
    bc_hrbl_reader_close(reader);
  }
  bc_allocators_context_destroy(memory);
  return 0;
}

#ifdef BC_FUZZ_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  return bc_integrity_fuzz_manifest_reader_one(data, size);
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
  return bc_integrity_fuzz_manifest_reader_one(buffer, length);
}
#endif
