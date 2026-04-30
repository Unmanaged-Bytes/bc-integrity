// SPDX-License-Identifier: MIT

#include "bc_allocators.h"
#include "bc_integrity_filter_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BC_INTEGRITY_FUZZ_FILTER_MAX_PATTERNS 8u
#define BC_INTEGRITY_FUZZ_FILTER_LIST_BUFFER_SIZE 4096u
#define BC_INTEGRITY_FUZZ_FILTER_PATH_BUFFER_SIZE 4096u

static int bc_integrity_fuzz_filter_glob_one(const uint8_t* data, size_t size)
{
    if (size < 2u) {
        return 0;
    }

    size_t cursor = 0;
    unsigned int pattern_count = (data[cursor] % BC_INTEGRITY_FUZZ_FILTER_MAX_PATTERNS) + 1u;
    cursor += 1u;

    char list_buffer[BC_INTEGRITY_FUZZ_FILTER_LIST_BUFFER_SIZE];
    size_t list_length = 0;

    for (unsigned int index = 0; index < pattern_count; ++index) {
        if (cursor >= size) {
            break;
        }
        size_t pattern_length = data[cursor];
        cursor += 1u;
        if (cursor + pattern_length > size) {
            pattern_length = size - cursor;
        }
        if (list_length + pattern_length + 2u >= sizeof(list_buffer)) {
            break;
        }
        for (size_t byte_index = 0; byte_index < pattern_length; ++byte_index) {
            uint8_t byte = data[cursor + byte_index];
            if (byte == '\0' || byte == '\n') {
                byte = '_';
            }
            list_buffer[list_length + byte_index] = (char)byte;
        }
        list_length += pattern_length;
        if (index + 1u < pattern_count) {
            list_buffer[list_length] = '\n';
            list_length += 1u;
        }
        cursor += pattern_length;
    }
    list_buffer[list_length] = '\0';

    char path_buffer[BC_INTEGRITY_FUZZ_FILTER_PATH_BUFFER_SIZE];
    size_t path_length = 0;
    if (cursor < size) {
        path_length = size - cursor;
        if (path_length >= sizeof(path_buffer)) {
            path_length = sizeof(path_buffer) - 1u;
        }
        for (size_t index = 0; index < path_length; ++index) {
            uint8_t byte = data[cursor + index];
            if (byte == '\0') {
                byte = '_';
            }
            path_buffer[index] = (char)byte;
        }
    }
    path_buffer[path_length] = '\0';

    bc_allocators_context_config_t config;
    memset(&config, 0, sizeof(config));
    bc_allocators_context_t* memory = NULL;
    if (!bc_allocators_context_create(&config, &memory)) {
        return 0;
    }

    bc_integrity_filter_t* filter = NULL;
    if (bc_integrity_filter_create(memory, list_buffer, list_buffer, &filter)) {
        (void)bc_integrity_filter_accepts_path(filter, path_buffer, path_length);
        (void)bc_integrity_filter_accepts_directory(filter, path_buffer, path_length);
        bc_integrity_filter_destroy(memory, filter);
    }

    if (list_length > 0) {
        (void)bc_integrity_filter_glob_matches(list_buffer, path_buffer, path_length);
    }

    bc_allocators_context_destroy(memory);
    return 0;
}

#ifdef BC_FUZZ_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    return bc_integrity_fuzz_filter_glob_one(data, size);
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
    return bc_integrity_fuzz_filter_glob_one(buffer, length);
}
#endif
