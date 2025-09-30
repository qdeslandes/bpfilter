/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <bpfilter/dump.h>
#include <bpfilter/list.h>

/**
 * @file handle.h
 *
 * A `bf_handle` respresents the a reference to all the BPF objects created for
 * a chain. It is not required to keep a reference to a `bf_program` and its
 * bytecode as long as we can access the maps and link.
 *
 * A handle can be created from the system's state, which guarantees there will
 * be no divergence between the system's state and the serialized data.
 */

struct bf_link;
struct bf_map;
struct bf_wpack;
typedef struct bf_wpack bf_wpack_t;
struct bf_hookopts;

/**
 * @brief Handle for a chain's BPF objects.
 */
struct bf_handle
{
    /// File descriptor of the BPF program.
    int prog_fd;

    /** Link attaching the BPF program to a hook. NULL if the program is not
     * attached. */
    struct bf_link *link;

    /// Map containing the packets and bytes counters. NULL if unused.
    struct bf_map *counters;

    /// Map containing the printing messages. NULL if unused.
    struct bf_map *printer;

    /// Map containing the logged packets. NULL if unused.
    struct bf_map *logger;

    /// List of set maps used by the program. Empty if unused.
    bf_list sets;
};

#define _free_bf_handle_ __attribute__((cleanup(bf_handle_free)))

/**
 * @brief Allocate and initialize a chain handle.
 *
 * @param handle `bf_handle` object to allocate and initialize. On failure,
 *        this parameter is unchanged. Can't be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_handle_new(struct bf_handle **handle);

/**
 * @brief Allocate and initialize a chain handle from a BPF link or BPF program
 *        file descriptor.
 *
 * @param handle Handle to allocate and initialize. On failure, this parameter
 *        is unchanged. Can't be NULL.
 * @param fd File descriptor of the BPF link or BPF program represented by the
 *        handle. This file descriptor will be duplicated if needed, so it
 *        can be safely closed once the function returns
 * @param hookopts If the chain is attached, reference to the hook options used.
 *        On success, `hookopts` is owned by the handle.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_handle_new_from_fd(struct bf_handle **handle, int fd,
                          struct bf_hookopts **hookopts);

/**
 * @brief Deallocate and deinitialize a handle.
 *
 * If `*handle` is NULL, this function has no effect.
 *
 * All the file descriptors of the BPF objects will be closed, but they will
 * remain attached to the system if the BPF link or the BPF program is pinned
 * to the system.
 *
 * @param handle Handle to deallocate and deinitialize. Can't be NULL.
 */
void bf_handle_free(struct bf_handle **handle);

/**
 * @brief Dump the content of a handle.
 *
 * @param handle Handle to print. Can't be NULL.
 * @param prefix Prefix to use for the dump. Can't be NULL.
 */
void bf_handle_dump(const struct bf_handle *handle, prefix_t *prefix);
