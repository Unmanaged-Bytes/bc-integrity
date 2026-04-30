// SPDX-License-Identifier: MIT

#include "bc_integrity_walk_internal.h"

#include "bc_integrity_capture_internal.h"
#include "bc_integrity_entry_internal.h"
#include "bc_integrity_filter_internal.h"

#include "bc_allocators.h"
#include "bc_allocators_pool.h"
#include "bc_runtime_signal.h"
#include "bc_containers_vector.h"
#include "bc_core.h"
#include "bc_io_dirent_reader.h"
#include "bc_runtime_error_collector.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>
#include <unistd.h>

#define BC_INTEGRITY_WALK_SERIAL_PATH_BUFFER_BYTES ((size_t)4096)

typedef struct bc_integrity_walk_serial_context {
    bc_allocators_context_t* memory_context;
    bc_containers_vector_t* destination_entries;
    bc_runtime_error_collector_t* errors;
    bc_runtime_signal_handler_t* signal_handler;
    const bc_integrity_manifest_options_t* options;
    const bc_integrity_filter_t* filter;
    const char* canonical_root_path;
    size_t canonical_root_path_length;
    size_t entry_budget;
    size_t entry_count;
    bool budget_exceeded;
} bc_integrity_walk_serial_context_t;

static bool bc_integrity_walk_serial_should_stop(const bc_integrity_walk_serial_context_t* context)
{
    if (context->budget_exceeded) {
        return true;
    }
    if (context->signal_handler == NULL) {
        return false;
    }
    bool should_stop = false;
    bc_runtime_signal_handler_should_stop(context->signal_handler, &should_stop);
    return should_stop;
}

static bool bc_integrity_walk_serial_check_budget(bc_integrity_walk_serial_context_t* context)
{
    if (context->entry_budget == 0) {
        return true;
    }
    context->entry_count += 1u;
    if (context->entry_count > context->entry_budget) {
        context->budget_exceeded = true;
        return false;
    }
    return true;
}

static bool bc_integrity_walk_serial_relative_path(bc_allocators_context_t* memory_context, const char* canonical_root_path,
                                                   size_t canonical_root_path_length, const char* absolute_path,
                                                   size_t absolute_path_length, const char** out_relative_path,
                                                   size_t* out_relative_path_length)
{
    if (absolute_path_length < canonical_root_path_length) {
        return false;
    }
    bool prefix_equal = false;
    if (!bc_core_equal(absolute_path, canonical_root_path, canonical_root_path_length, &prefix_equal) || !prefix_equal) {
        return false;
    }
    size_t relative_offset = canonical_root_path_length;
    while (relative_offset < absolute_path_length && absolute_path[relative_offset] == '/') {
        relative_offset += 1u;
    }
    size_t relative_length = absolute_path_length - relative_offset;
    char* copy = NULL;
    if (!bc_allocators_pool_allocate(memory_context, relative_length + 1u, (void**)&copy)) {
        return false;
    }
    if (relative_length > 0) {
        bc_core_copy(copy, absolute_path + relative_offset, relative_length);
    }
    copy[relative_length] = '\0';
    *out_relative_path = copy;
    *out_relative_path_length = relative_length;
    return true;
}

static bool bc_integrity_walk_serial_clone_path(bc_allocators_context_t* memory_context, const char* path, size_t path_length,
                                                const char** out_copy)
{
    char* copy = NULL;
    if (!bc_allocators_pool_allocate(memory_context, path_length + 1u, (void**)&copy)) {
        return false;
    }
    if (path_length > 0) {
        bc_core_copy(copy, path, path_length);
    }
    copy[path_length] = '\0';
    *out_copy = copy;
    return true;
}

static bool bc_integrity_walk_serial_capture_entry(bc_integrity_walk_serial_context_t* context, int parent_directory_fd,
                                                   const char* child_name, const char* absolute_path, size_t absolute_path_length,
                                                   bool follow_for_stat)
{
    struct stat stat_buffer;
    int stat_flags = follow_for_stat ? 0 : AT_SYMLINK_NOFOLLOW;
    if (fstatat(parent_directory_fd, child_name, &stat_buffer, stat_flags) != 0) {
        (void)bc_runtime_error_collector_append(context->errors, context->memory_context, absolute_path, "lstat", errno);
        return false;
    }

    const char* relative_path = NULL;
    size_t relative_path_length = 0;
    if (!bc_integrity_walk_serial_relative_path(context->memory_context, context->canonical_root_path, context->canonical_root_path_length,
                                                absolute_path, absolute_path_length, &relative_path, &relative_path_length)) {
        (void)bc_runtime_error_collector_append(context->errors, context->memory_context, absolute_path, "relative-path", EINVAL);
        return false;
    }
    if (relative_path_length == 0) {
        return true;
    }

    if (context->filter != NULL && !bc_integrity_filter_accepts_path(context->filter, relative_path, relative_path_length)) {
        return true;
    }

    const char* absolute_path_copy = NULL;
    if (!bc_integrity_walk_serial_clone_path(context->memory_context, absolute_path, absolute_path_length, &absolute_path_copy)) {
        (void)bc_runtime_error_collector_append(context->errors, context->memory_context, absolute_path, "clone-absolute", ENOMEM);
        return false;
    }

    bool defer_digest = context->options->skip_digest || context->options->defer_digest;

    bc_integrity_entry_t built_entry;
    bc_core_zero(&built_entry, sizeof(built_entry));
    bc_integrity_capture_entry_from_stat(context->memory_context, &stat_buffer, context->options->digest_algorithm, parent_directory_fd,
                                         child_name, absolute_path, absolute_path_length, relative_path, relative_path_length, defer_digest,
                                         &built_entry);
    built_entry.absolute_path = absolute_path_copy;
    built_entry.absolute_path_length = absolute_path_length;

    if (!bc_containers_vector_push(context->memory_context, context->destination_entries, &built_entry)) {
        (void)bc_runtime_error_collector_append(context->errors, context->memory_context, absolute_path, "vector-push", ENOMEM);
        return false;
    }
    (void)bc_integrity_walk_serial_check_budget(context);
    return true;
}

static bool bc_integrity_walk_serial_should_descend_directory(const bc_integrity_walk_serial_context_t* context, const char* absolute_path,
                                                              size_t absolute_path_length)
{
    if (context->options->default_exclude_virtual &&
        bc_integrity_walk_is_virtual_subpath(context->canonical_root_path, context->canonical_root_path_length, absolute_path,
                                             absolute_path_length)) {
        return false;
    }
    if (context->filter == NULL) {
        return true;
    }
    if (absolute_path_length <= context->canonical_root_path_length) {
        return true;
    }
    size_t relative_offset = context->canonical_root_path_length;
    while (relative_offset < absolute_path_length && absolute_path[relative_offset] == '/') {
        relative_offset += 1u;
    }
    if (relative_offset >= absolute_path_length) {
        return true;
    }
    size_t relative_length = absolute_path_length - relative_offset;
    return bc_integrity_filter_accepts_directory(context->filter, absolute_path + relative_offset, relative_length);
}

static bool bc_integrity_walk_serial_recurse(bc_integrity_walk_serial_context_t* context, int directory_fd, const char* directory_path,
                                             size_t directory_path_length);

static bool bc_integrity_walk_serial_handle_dirent(bc_integrity_walk_serial_context_t* context, int directory_fd,
                                                   const char* directory_path, size_t directory_path_length,
                                                   const bc_io_dirent_entry_t* entry)
{
    if (entry->name_length == 1 && entry->name[0] == '.') {
        return true;
    }
    if (entry->name_length == 2 && entry->name[0] == '.' && entry->name[1] == '.') {
        return true;
    }
    if (!context->options->include_hidden && entry->name[0] == '.') {
        return true;
    }
    if (directory_path_length + 1u + entry->name_length + 1u > BC_INTEGRITY_WALK_SERIAL_PATH_BUFFER_BYTES) {
        (void)bc_runtime_error_collector_append(context->errors, context->memory_context, directory_path, "path-too-long", ENAMETOOLONG);
        return true;
    }
    char child_path[BC_INTEGRITY_WALK_SERIAL_PATH_BUFFER_BYTES];
    bc_core_copy(child_path, directory_path, directory_path_length);
    size_t child_path_length = directory_path_length;
    if (child_path_length == 0 || child_path[child_path_length - 1u] != '/') {
        child_path[child_path_length++] = '/';
    }
    bc_core_copy(child_path + child_path_length, entry->name, entry->name_length);
    child_path_length += entry->name_length;
    child_path[child_path_length] = '\0';

    unsigned char d_type = entry->d_type;
    if (d_type == DT_UNKNOWN) {
        struct stat probe_stat;
        if (fstatat(directory_fd, entry->name, &probe_stat, AT_SYMLINK_NOFOLLOW) == 0) {
            if (S_ISREG(probe_stat.st_mode)) {
                d_type = DT_REG;
            } else if (S_ISDIR(probe_stat.st_mode)) {
                d_type = DT_DIR;
            } else if (S_ISLNK(probe_stat.st_mode)) {
                d_type = DT_LNK;
            } else {
                d_type = DT_UNKNOWN;
            }
        }
    }

    if (d_type == DT_LNK) {
        return bc_integrity_walk_serial_capture_entry(context, directory_fd, entry->name, child_path, child_path_length, false);
    }
    if (d_type == DT_REG) {
        return bc_integrity_walk_serial_capture_entry(context, directory_fd, entry->name, child_path, child_path_length,
                                                      context->options->follow_symlinks);
    }
    if (d_type == DT_DIR) {
        if (context->options->default_exclude_virtual &&
            bc_integrity_walk_is_virtual_subpath(context->canonical_root_path, context->canonical_root_path_length, child_path,
                                                 child_path_length)) {
            return true;
        }
        if (!bc_integrity_walk_serial_should_descend_directory(context, child_path, child_path_length)) {
            return true;
        }
        (void)bc_integrity_walk_serial_capture_entry(context, directory_fd, entry->name, child_path, child_path_length,
                                                     context->options->follow_symlinks);
        int child_open_flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC;
        if (!context->options->follow_symlinks) {
            child_open_flags |= O_NOFOLLOW;
        }
        int child_fd = openat(directory_fd, entry->name, child_open_flags);
        if (child_fd < 0) {
            (void)bc_runtime_error_collector_append(context->errors, context->memory_context, child_path, "open", errno);
            return true;
        }
        bool descend_ok = bc_integrity_walk_serial_recurse(context, child_fd, child_path, child_path_length);
        close(child_fd);
        return descend_ok;
    }
    if (context->options->include_special) {
        return bc_integrity_walk_serial_capture_entry(context, directory_fd, entry->name, child_path, child_path_length, false);
    }
    return true;
}

static bool bc_integrity_walk_serial_recurse(bc_integrity_walk_serial_context_t* context, int directory_fd, const char* directory_path,
                                             size_t directory_path_length)
{
    if (bc_integrity_walk_serial_should_stop(context)) {
        return true;
    }
    bc_io_dirent_reader_t* reader = NULL;
    if (!bc_io_dirent_reader_create(context->memory_context, directory_fd, &reader)) {
        (void)bc_runtime_error_collector_append(context->errors, context->memory_context, directory_path, "dirent-reader-alloc", ENOMEM);
        return true;
    }
    while (true) {
        if (bc_integrity_walk_serial_should_stop(context)) {
            break;
        }
        bc_io_dirent_entry_t dirent;
        bool has_entry = false;
        if (!bc_io_dirent_reader_next(reader, &dirent, &has_entry)) {
            int reader_errno = 0;
            bc_io_dirent_reader_last_errno(reader, &reader_errno);
            (void)bc_runtime_error_collector_append(context->errors, context->memory_context, directory_path, "getdents", reader_errno);
            break;
        }
        if (!has_entry) {
            break;
        }
        (void)bc_integrity_walk_serial_handle_dirent(context, directory_fd, directory_path, directory_path_length, &dirent);
    }
    bc_io_dirent_reader_destroy(context->memory_context, reader);
    return true;
}

bool bc_integrity_walk_run_serial_with_budget(bc_allocators_context_t* memory_context, bc_runtime_signal_handler_t* signal_handler,
                                              const bc_integrity_manifest_options_t* options, const char* canonical_root_path,
                                              size_t canonical_root_path_length, bc_containers_vector_t* destination_entries,
                                              bc_runtime_error_collector_t* errors, size_t entry_budget, bool* out_budget_exceeded)
{
    *out_budget_exceeded = false;
    bc_integrity_filter_t* filter = NULL;
    if (options->include_list != NULL || options->exclude_list != NULL) {
        if (!bc_integrity_filter_create(memory_context, options->include_list, options->exclude_list, &filter)) {
            (void)bc_runtime_error_collector_append(errors, memory_context, canonical_root_path, "filter-create", ENOMEM);
            return false;
        }
    }

    if (options->default_exclude_virtual && bc_integrity_walk_is_virtual_root(canonical_root_path, canonical_root_path_length)) {
        (void)bc_runtime_error_collector_append(errors, memory_context, canonical_root_path, "virtual-root", EPERM);
        if (filter != NULL) {
            bc_integrity_filter_destroy(memory_context, filter);
        }
        return false;
    }

    int root_open_flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC;
    if (!options->follow_symlinks) {
        root_open_flags |= O_NOFOLLOW;
    }
    int root_fd = open(canonical_root_path, root_open_flags);
    if (root_fd < 0) {
        (void)bc_runtime_error_collector_append(errors, memory_context, canonical_root_path, "open", errno);
        if (filter != NULL) {
            bc_integrity_filter_destroy(memory_context, filter);
        }
        return false;
    }

    bc_integrity_walk_serial_context_t context = {
        .memory_context = memory_context,
        .destination_entries = destination_entries,
        .errors = errors,
        .signal_handler = signal_handler,
        .options = options,
        .filter = filter,
        .canonical_root_path = canonical_root_path,
        .canonical_root_path_length = canonical_root_path_length,
        .entry_budget = entry_budget,
        .entry_count = 0,
        .budget_exceeded = false,
    };

    bool walk_ok = bc_integrity_walk_serial_recurse(&context, root_fd, canonical_root_path, canonical_root_path_length);
    close(root_fd);
    if (filter != NULL) {
        bc_integrity_filter_destroy(memory_context, filter);
    }
    *out_budget_exceeded = context.budget_exceeded;
    return walk_ok;
}

bool bc_integrity_walk_run_serial(bc_allocators_context_t* memory_context, bc_runtime_signal_handler_t* signal_handler,
                                  const bc_integrity_manifest_options_t* options, const char* canonical_root_path,
                                  size_t canonical_root_path_length, bc_containers_vector_t* destination_entries,
                                  bc_runtime_error_collector_t* errors)
{
    bool budget_exceeded = false;
    return bc_integrity_walk_run_serial_with_budget(memory_context, signal_handler, options, canonical_root_path,
                                                    canonical_root_path_length, destination_entries, errors, 0, &budget_exceeded);
}
