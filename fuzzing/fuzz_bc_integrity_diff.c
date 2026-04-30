// SPDX-License-Identifier: MIT

#include "bc_allocators.h"
#include "bc_hrbl_reader.h"
#include "bc_hrbl_verify.h"
#include "bc_integrity_cli_internal.h"
#include "bc_integrity_diff_internal.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool bc_integrity_fuzz_diff_write_temp(const char* suffix, const uint8_t* data, size_t size, char* out_path, size_t out_path_size)
{
    int written = snprintf(out_path, out_path_size, "/tmp/bc_integrity_fuzz_diff_%d_%s.hrbl", getpid(), suffix);
    if (written < 0 || (size_t)written >= out_path_size) {
        return false;
    }
    int fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        return false;
    }
    ssize_t total = 0;
    while ((size_t)total < size) {
        ssize_t written_bytes = write(fd, data + total, size - (size_t)total);
        if (written_bytes <= 0) {
            close(fd);
            unlink(out_path);
            return false;
        }
        total += written_bytes;
    }
    close(fd);
    return true;
}

static int bc_integrity_fuzz_diff_one(const uint8_t* data, size_t size)
{
    if (size < 4) {
        return 0;
    }
    uint32_t split = ((uint32_t)data[0]) | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
    size_t available = size - 4u;
    if (available == 0) {
        return 0;
    }
    size_t split_offset = (size_t)(split % available);
    const uint8_t* side_a = data + 4u;
    size_t side_a_length = split_offset;
    const uint8_t* side_b = data + 4u + split_offset;
    size_t side_b_length = available - split_offset;

    char path_a[128];
    char path_b[128];
    if (!bc_integrity_fuzz_diff_write_temp("a", side_a, side_a_length, path_a, sizeof(path_a))) {
        return 0;
    }
    if (!bc_integrity_fuzz_diff_write_temp("b", side_b, side_b_length, path_b, sizeof(path_b))) {
        unlink(path_a);
        return 0;
    }

    bc_allocators_context_config_t config;
    memset(&config, 0, sizeof(config));
    bc_allocators_context_t* memory = NULL;
    if (!bc_allocators_context_create(&config, &memory)) {
        unlink(path_a);
        unlink(path_b);
        return 0;
    }

    bc_integrity_diff_options_t options;
    memset(&options, 0, sizeof(options));
    options.manifest_path_a = path_a;
    options.manifest_path_b = path_b;
    options.format = BC_INTEGRITY_OUTPUT_FORMAT_TEXT;
    int exit_code = 0;
    (void)bc_integrity_diff_run(memory, &options, &exit_code);

    bc_allocators_context_destroy(memory);
    unlink(path_a);
    unlink(path_b);
    return 0;
}

#ifdef BC_FUZZ_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    return bc_integrity_fuzz_diff_one(data, size);
}
#else
int main(int argc, char** argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <input-file>\n", argv[0]);
        return 2;
    }
    FILE* file = fopen(argv[1], "rb");
    if (file == NULL) {
        return 2;
    }
    uint8_t buffer[1u << 16];
    size_t length = fread(buffer, 1u, sizeof(buffer), file);
    fclose(file);
    return bc_integrity_fuzz_diff_one(buffer, length);
}
#endif
