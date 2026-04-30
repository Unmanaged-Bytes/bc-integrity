// SPDX-License-Identifier: MIT

#include "bc_integrity_cli_internal.h"

#include "bc_core.h"
#include "bc_core_parse.h"

#include <stdint.h>

static bool bc_integrity_cli_parsers_strings_equal(const char* a, const char* b)
{
    if (a == NULL || b == NULL) {
        return false;
    }
    size_t length_a = 0;
    size_t length_b = 0;
    (void)bc_core_length(a, '\0', &length_a);
    (void)bc_core_length(b, '\0', &length_b);
    if (length_a != length_b) {
        return false;
    }
    bool equal = false;
    (void)bc_core_equal(a, b, length_a, &equal);
    return equal;
}

bool bc_integrity_cli_parse_digest_algorithm(const char* value, bc_integrity_digest_algorithm_t* out_algorithm)
{
    if (bc_integrity_cli_parsers_strings_equal(value, "sha256")) {
        *out_algorithm = BC_INTEGRITY_DIGEST_ALGORITHM_SHA256;
        return true;
    }
    if (bc_integrity_cli_parsers_strings_equal(value, "xxh3")) {
        *out_algorithm = BC_INTEGRITY_DIGEST_ALGORITHM_XXH3;
        return true;
    }
    if (bc_integrity_cli_parsers_strings_equal(value, "xxh128")) {
        *out_algorithm = BC_INTEGRITY_DIGEST_ALGORITHM_XXH128;
        return true;
    }
    return false;
}

bool bc_integrity_cli_parse_verify_mode(const char* value, bc_integrity_verify_mode_t* out_mode)
{
    if (bc_integrity_cli_parsers_strings_equal(value, "strict")) {
        *out_mode = BC_INTEGRITY_VERIFY_MODE_STRICT;
        return true;
    }
    if (bc_integrity_cli_parsers_strings_equal(value, "content")) {
        *out_mode = BC_INTEGRITY_VERIFY_MODE_CONTENT;
        return true;
    }
    if (bc_integrity_cli_parsers_strings_equal(value, "meta")) {
        *out_mode = BC_INTEGRITY_VERIFY_MODE_META;
        return true;
    }
    return false;
}

bool bc_integrity_cli_parse_output_format(const char* value, bc_integrity_output_format_t* out_format)
{
    if (bc_integrity_cli_parsers_strings_equal(value, "text")) {
        *out_format = BC_INTEGRITY_OUTPUT_FORMAT_TEXT;
        return true;
    }
    if (bc_integrity_cli_parsers_strings_equal(value, "json")) {
        *out_format = BC_INTEGRITY_OUTPUT_FORMAT_JSON;
        return true;
    }
    return false;
}

bool bc_integrity_cli_parse_threads(const char* value, bc_integrity_threads_mode_t* out_mode, size_t* out_explicit_worker_count)
{
    if (bc_integrity_cli_parsers_strings_equal(value, "auto")) {
        *out_mode = BC_INTEGRITY_THREADS_MODE_AUTO;
        *out_explicit_worker_count = 0;
        return true;
    }
    if (bc_integrity_cli_parsers_strings_equal(value, "auto-io")) {
        *out_mode = BC_INTEGRITY_THREADS_MODE_AUTO_IO;
        *out_explicit_worker_count = 0;
        return true;
    }
    size_t length = 0;
    (void)bc_core_length(value, '\0', &length);
    if (length == 0) {
        return false;
    }
    uint64_t parsed = 0;
    size_t consumed = 0;
    if (!bc_core_parse_unsigned_integer_64_decimal(value, length, &parsed, &consumed)) {
        return false;
    }
    if (consumed != length) {
        return false;
    }
    if (parsed == 0) {
        *out_mode = BC_INTEGRITY_THREADS_MODE_MONO;
        *out_explicit_worker_count = 0;
        return true;
    }
    *out_mode = BC_INTEGRITY_THREADS_MODE_EXPLICIT;
    *out_explicit_worker_count = (size_t)parsed;
    return true;
}
