// SPDX-License-Identifier: MIT

#include "bc_integrity_filter_internal.h"

#include "bc_allocators_pool.h"
#include "bc_core.h"

#include <stdbool.h>
#include <stddef.h>

#define BC_INTEGRITY_FILTER_LIST_SEPARATOR '\n'

struct bc_integrity_filter {
  char **include_patterns;
  size_t include_count;
  char **exclude_patterns;
  size_t exclude_count;
  char *include_buffer;
  char *exclude_buffer;
};

static size_t bc_integrity_filter_cstr_length(const char *value) {
  size_t length = 0;
  (void)bc_core_length(value, '\0', &length);
  return length;
}

static bool bc_integrity_filter_glob_segment(const char *pattern,
                                             size_t pattern_length,
                                             const char *value,
                                             size_t value_length) {
  size_t pattern_index = 0;
  size_t value_index = 0;
  size_t star_pattern_index = pattern_length + 1u;
  size_t star_value_index = 0;
  while (value_index < value_length) {
    if (pattern_index < pattern_length && pattern[pattern_index] == '?') {
      if (value[value_index] == '/') {
        return false;
      }
      pattern_index += 1u;
      value_index += 1u;
      continue;
    }
    if (pattern_index < pattern_length && pattern[pattern_index] == '*') {
      star_pattern_index = pattern_index;
      star_value_index = value_index;
      pattern_index += 1u;
      continue;
    }
    if (pattern_index < pattern_length && pattern[pattern_index] == '[') {
      size_t close_index = pattern_index + 1u;
      while (close_index < pattern_length && pattern[close_index] != ']') {
        close_index += 1u;
      }
      if (close_index >= pattern_length) {
        if (pattern[pattern_index] == value[value_index]) {
          pattern_index += 1u;
          value_index += 1u;
          continue;
        }
      } else {
        bool negate = false;
        size_t start = pattern_index + 1u;
        if (start < close_index && pattern[start] == '!') {
          negate = true;
          start += 1u;
        }
        bool matched = false;
        size_t cursor = start;
        while (cursor < close_index) {
          if (cursor + 2u < close_index && pattern[cursor + 1u] == '-') {
            char low = pattern[cursor];
            char high = pattern[cursor + 2u];
            if (value[value_index] >= low && value[value_index] <= high) {
              matched = true;
            }
            cursor += 3u;
          } else {
            if (pattern[cursor] == value[value_index]) {
              matched = true;
            }
            cursor += 1u;
          }
        }
        if ((matched && !negate) || (!matched && negate)) {
          if (value[value_index] == '/') {
            goto fallback;
          }
          pattern_index = close_index + 1u;
          value_index += 1u;
          continue;
        }
        goto fallback;
      }
    }
    if (pattern_index < pattern_length &&
        pattern[pattern_index] == value[value_index]) {
      pattern_index += 1u;
      value_index += 1u;
      continue;
    }
  fallback:
    if (star_pattern_index < pattern_length) {
      pattern_index = star_pattern_index + 1u;
      star_value_index += 1u;
      if (value[star_value_index - 1u] == '/') {
        return false;
      }
      value_index = star_value_index;
      continue;
    }
    return false;
  }
  while (pattern_index < pattern_length && pattern[pattern_index] == '*') {
    pattern_index += 1u;
  }
  return pattern_index == pattern_length;
}

#define BC_INTEGRITY_FILTER_GLOB_MAX_DOUBLE_STAR_SEGMENTS 4u

static size_t bc_integrity_filter_glob_count_double_star_segments(
    const char *pattern, size_t pattern_length) {
  size_t count = 0u;
  size_t segment_start = 0u;
  while (segment_start < pattern_length) {
    size_t segment_end = segment_start;
    while (segment_end < pattern_length && pattern[segment_end] != '/') {
      segment_end += 1u;
    }
    size_t segment_length = segment_end - segment_start;
    if (segment_length == 2u && pattern[segment_start] == '*' &&
        pattern[segment_start + 1u] == '*') {
      count += 1u;
    }
    if (segment_end >= pattern_length) {
      break;
    }
    segment_start = segment_end + 1u;
  }
  return count;
}

static bool bc_integrity_filter_glob_match_recursive(const char *pattern,
                                                     size_t pattern_length,
                                                     const char *value,
                                                     size_t value_length) {
  size_t pattern_segment_start = 0;
  size_t value_segment_start = 0;
  while (pattern_segment_start <= pattern_length) {
    size_t pattern_segment_end = pattern_segment_start;
    while (pattern_segment_end < pattern_length &&
           pattern[pattern_segment_end] != '/') {
      pattern_segment_end += 1u;
    }
    size_t pattern_segment_length = pattern_segment_end - pattern_segment_start;
    bool is_double_star = pattern_segment_length == 2u &&
                          pattern[pattern_segment_start] == '*' &&
                          pattern[pattern_segment_start + 1u] == '*';
    if (is_double_star) {
      if (pattern_segment_end >= pattern_length) {
        return true;
      }
      size_t next_pattern_start = pattern_segment_end + 1u;
      size_t value_cursor = value_segment_start;
      while (true) {
        if (bc_integrity_filter_glob_match_recursive(
                pattern + next_pattern_start,
                pattern_length - next_pattern_start, value + value_cursor,
                value_length - value_cursor)) {
          return true;
        }
        while (value_cursor < value_length && value[value_cursor] != '/') {
          value_cursor += 1u;
        }
        if (value_cursor >= value_length) {
          return false;
        }
        value_cursor += 1u;
      }
    }
    size_t value_segment_end = value_segment_start;
    while (value_segment_end < value_length &&
           value[value_segment_end] != '/') {
      value_segment_end += 1u;
    }
    size_t value_segment_length = value_segment_end - value_segment_start;
    if (!bc_integrity_filter_glob_segment(
            pattern + pattern_segment_start, pattern_segment_length,
            value + value_segment_start, value_segment_length)) {
      return false;
    }
    bool pattern_done = pattern_segment_end >= pattern_length;
    bool value_done = value_segment_end >= value_length;
    if (pattern_done && value_done) {
      return true;
    }
    if (pattern_done || value_done) {
      return false;
    }
    pattern_segment_start = pattern_segment_end + 1u;
    value_segment_start = value_segment_end + 1u;
  }
  return false;
}

bool bc_integrity_filter_glob_matches(const char *pattern, const char *value,
                                      size_t value_length) {
  size_t pattern_length = bc_integrity_filter_cstr_length(pattern);
  if (bc_integrity_filter_glob_count_double_star_segments(pattern,
                                                          pattern_length) >
      BC_INTEGRITY_FILTER_GLOB_MAX_DOUBLE_STAR_SEGMENTS) {
    return false;
  }
  return bc_integrity_filter_glob_match_recursive(pattern, pattern_length,
                                                  value, value_length);
}

static bool bc_integrity_filter_pattern_directory_prefix_matches(
    const char *pattern, const char *value, size_t value_length) {
  size_t pattern_length = bc_integrity_filter_cstr_length(pattern);
  if (bc_integrity_filter_glob_count_double_star_segments(pattern,
                                                          pattern_length) >
      BC_INTEGRITY_FILTER_GLOB_MAX_DOUBLE_STAR_SEGMENTS) {
    return false;
  }
  if (pattern_length >= 3u && pattern[pattern_length - 3u] == '/' &&
      pattern[pattern_length - 2u] == '*' &&
      pattern[pattern_length - 1u] == '*') {
    size_t prefix_length = pattern_length - 3u;
    if (bc_integrity_filter_glob_match_recursive(pattern, prefix_length, value,
                                                 value_length)) {
      return true;
    }
  }
  if (pattern_length >= 2u && pattern[0] == '*' && pattern[1] == '*') {
    return true;
  }
  return false;
}

static bool
bc_integrity_filter_count_and_split(bc_allocators_context_t *memory_context,
                                    const char *list, char **out_buffer,
                                    char ***out_patterns, size_t *out_count) {
  if (list == NULL || list[0] == '\0') {
    *out_buffer = NULL;
    *out_patterns = NULL;
    *out_count = 0;
    return true;
  }
  size_t list_length = bc_integrity_filter_cstr_length(list);
  char *buffer = NULL;
  if (!bc_allocators_pool_allocate(memory_context, list_length + 1u,
                                   (void **)&buffer)) {
    return false;
  }
  bc_core_copy(buffer, list, list_length);
  buffer[list_length] = '\0';

  size_t count = 1u;
  for (size_t index = 0; index < list_length; ++index) {
    if (buffer[index] == BC_INTEGRITY_FILTER_LIST_SEPARATOR) {
      count += 1u;
    }
  }

  char **patterns = NULL;
  if (!bc_allocators_pool_allocate(memory_context, count * sizeof(char *),
                                   (void **)&patterns)) {
    bc_allocators_pool_free(memory_context, buffer);
    return false;
  }

  size_t write_index = 0;
  patterns[write_index++] = buffer;
  for (size_t index = 0; index < list_length; ++index) {
    if (buffer[index] == BC_INTEGRITY_FILTER_LIST_SEPARATOR) {
      buffer[index] = '\0';
      if (write_index < count) {
        patterns[write_index++] = buffer + index + 1u;
      }
    }
  }

  *out_buffer = buffer;
  *out_patterns = patterns;
  *out_count = count;
  return true;
}

bool bc_integrity_filter_create(bc_allocators_context_t *memory_context,
                                const char *include_list,
                                const char *exclude_list,
                                bc_integrity_filter_t **out_filter) {
  bc_integrity_filter_t *filter = NULL;
  if (!bc_allocators_pool_allocate(
          memory_context, sizeof(bc_integrity_filter_t), (void **)&filter)) {
    return false;
  }
  bc_core_zero(filter, sizeof(*filter));

  if (!bc_integrity_filter_count_and_split(
          memory_context, include_list, &filter->include_buffer,
          &filter->include_patterns, &filter->include_count)) {
    bc_allocators_pool_free(memory_context, filter);
    return false;
  }
  if (!bc_integrity_filter_count_and_split(
          memory_context, exclude_list, &filter->exclude_buffer,
          &filter->exclude_patterns, &filter->exclude_count)) {
    if (filter->include_patterns != NULL) {
      bc_allocators_pool_free(memory_context, filter->include_patterns);
    }
    if (filter->include_buffer != NULL) {
      bc_allocators_pool_free(memory_context, filter->include_buffer);
    }
    bc_allocators_pool_free(memory_context, filter);
    return false;
  }
  *out_filter = filter;
  return true;
}

void bc_integrity_filter_destroy(bc_allocators_context_t *memory_context,
                                 bc_integrity_filter_t *filter) {
  if (filter == NULL) {
    return;
  }
  if (filter->exclude_patterns != NULL) {
    bc_allocators_pool_free(memory_context, filter->exclude_patterns);
  }
  if (filter->exclude_buffer != NULL) {
    bc_allocators_pool_free(memory_context, filter->exclude_buffer);
  }
  if (filter->include_patterns != NULL) {
    bc_allocators_pool_free(memory_context, filter->include_patterns);
  }
  if (filter->include_buffer != NULL) {
    bc_allocators_pool_free(memory_context, filter->include_buffer);
  }
  bc_allocators_pool_free(memory_context, filter);
}

bool bc_integrity_filter_accepts_path(const bc_integrity_filter_t *filter,
                                      const char *relative_path,
                                      size_t relative_path_length) {
  if (filter == NULL) {
    return true;
  }
  for (size_t index = 0; index < filter->exclude_count; ++index) {
    if (bc_integrity_filter_glob_matches(filter->exclude_patterns[index],
                                         relative_path, relative_path_length)) {
      return false;
    }
  }
  if (filter->include_count == 0) {
    return true;
  }
  for (size_t index = 0; index < filter->include_count; ++index) {
    if (bc_integrity_filter_glob_matches(filter->include_patterns[index],
                                         relative_path, relative_path_length)) {
      return true;
    }
  }
  return false;
}

bool bc_integrity_filter_accepts_directory(const bc_integrity_filter_t *filter,
                                           const char *relative_path,
                                           size_t relative_path_length) {
  if (filter == NULL) {
    return true;
  }
  if (relative_path_length == 0) {
    return true;
  }
  for (size_t index = 0; index < filter->exclude_count; ++index) {
    if (bc_integrity_filter_glob_matches(filter->exclude_patterns[index],
                                         relative_path, relative_path_length)) {
      return false;
    }
    if (bc_integrity_filter_pattern_directory_prefix_matches(
            filter->exclude_patterns[index], relative_path,
            relative_path_length)) {
      return false;
    }
  }
  return true;
}
