// SPDX-License-Identifier: MIT

#include "bc_integrity_cli_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BC_INTEGRITY_FUZZ_CLI_BUFFER_SIZE 4096u

static int bc_integrity_fuzz_cli_parsers_one(const uint8_t *data, size_t size) {
  if (size < 1u) {
    return 0;
  }
  unsigned int selector = data[0] & 0x03u;
  size_t value_length = size - 1u;
  if (value_length >= BC_INTEGRITY_FUZZ_CLI_BUFFER_SIZE) {
    value_length = BC_INTEGRITY_FUZZ_CLI_BUFFER_SIZE - 1u;
  }

  char buffer[BC_INTEGRITY_FUZZ_CLI_BUFFER_SIZE];
  for (size_t index = 0; index < value_length; ++index) {
    uint8_t byte = data[index + 1u];
    if (byte == '\0') {
      byte = '_';
    }
    buffer[index] = (char)byte;
  }
  buffer[value_length] = '\0';

  switch (selector) {
  case 0: {
    bc_integrity_digest_algorithm_t algorithm = BC_INTEGRITY_DIGEST_ALGORITHM_SHA256;
    (void)bc_integrity_cli_parse_digest_algorithm(buffer, &algorithm);
    break;
  }
  case 1: {
    bc_integrity_threads_mode_t mode = BC_INTEGRITY_THREADS_MODE_AUTO;
    size_t worker_count = 0;
    (void)bc_integrity_cli_parse_threads(buffer, &mode, &worker_count);
    break;
  }
  case 2: {
    bc_integrity_verify_mode_t mode = BC_INTEGRITY_VERIFY_MODE_STRICT;
    (void)bc_integrity_cli_parse_verify_mode(buffer, &mode);
    break;
  }
  case 3:
  default: {
    bc_integrity_output_format_t format = BC_INTEGRITY_OUTPUT_FORMAT_TEXT;
    (void)bc_integrity_cli_parse_output_format(buffer, &format);
    break;
  }
  }

  return 0;
}

#ifdef BC_FUZZ_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  return bc_integrity_fuzz_cli_parsers_one(data, size);
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
  return bc_integrity_fuzz_cli_parsers_one(buffer, length);
}
#endif
