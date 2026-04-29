// SPDX-License-Identifier: MIT

#include "bc_integrity_walk_internal.h"

#include "bc_core.h"

#include <stdbool.h>
#include <stddef.h>

static const char *const bc_integrity_walk_virtual_top_level_paths[] = {
    "/proc", "/sys", "/dev", "/run", "/tmp",
};

static const size_t bc_integrity_walk_virtual_top_level_count =
    sizeof(bc_integrity_walk_virtual_top_level_paths) /
    sizeof(bc_integrity_walk_virtual_top_level_paths[0]);

static bool bc_integrity_walk_path_starts_with(const char *path,
                                               size_t path_length,
                                               const char *prefix,
                                               size_t prefix_length) {
  if (path_length < prefix_length) {
    return false;
  }
  bool equal = false;
  (void)bc_core_equal(path, prefix, prefix_length, &equal);
  return equal;
}

bool bc_integrity_walk_is_hidden_segment(const char *relative_path,
                                         size_t relative_path_length) {
  if (relative_path == NULL || relative_path_length == 0) {
    return false;
  }
  if (relative_path[0] == '.') {
    return true;
  }
  for (size_t index = 1; index < relative_path_length; ++index) {
    if (relative_path[index - 1] == '/' && relative_path[index] == '.') {
      return true;
    }
  }
  return false;
}

bool bc_integrity_walk_is_virtual_root(const char *canonical_root_path,
                                       size_t canonical_root_path_length) {
  for (size_t index = 0; index < bc_integrity_walk_virtual_top_level_count;
       ++index) {
    const char *prefix = bc_integrity_walk_virtual_top_level_paths[index];
    size_t prefix_length = 0;
    (void)bc_core_length(prefix, '\0', &prefix_length);
    if (canonical_root_path_length == prefix_length &&
        bc_integrity_walk_path_starts_with(canonical_root_path,
                                           canonical_root_path_length, prefix,
                                           prefix_length)) {
      return true;
    }
  }
  return false;
}

static bool bc_integrity_walk_path_is_descendant_or_equal(
    const char *path, size_t path_length, const char *prefix,
    size_t prefix_length) {
  if (path_length < prefix_length) {
    return false;
  }
  if (!bc_integrity_walk_path_starts_with(path, path_length, prefix,
                                          prefix_length)) {
    return false;
  }
  if (path_length == prefix_length) {
    return true;
  }
  return path[prefix_length] == '/' || path[prefix_length] == '\0';
}

bool bc_integrity_walk_is_virtual_subpath(const char *canonical_root_path,
                                          size_t canonical_root_path_length,
                                          const char *absolute_path,
                                          size_t absolute_path_length) {
  if (canonical_root_path == NULL || absolute_path == NULL) {
    return false;
  }
  for (size_t index = 0; index < bc_integrity_walk_virtual_top_level_count;
       ++index) {
    const char *prefix = bc_integrity_walk_virtual_top_level_paths[index];
    size_t prefix_length = 0;
    (void)bc_core_length(prefix, '\0', &prefix_length);

    if (bc_integrity_walk_path_is_descendant_or_equal(
            canonical_root_path, canonical_root_path_length, prefix,
            prefix_length)) {
      continue;
    }

    if (bc_integrity_walk_path_is_descendant_or_equal(
            absolute_path, absolute_path_length, prefix, prefix_length)) {
      return true;
    }
  }
  return false;
}
