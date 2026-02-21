/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/bpf.h>

#include <bpfilter/dump.h>
#include <bpfilter/hook.h>
#include <bpfilter/list.h>
#include <bpfilter/pack.h>

struct bf_chain;
struct bf_link;
struct bf_map;
struct bf_counter;

/**
 * @file handle.h
 *
 * @ref bf_handle is used to manage BPF object references (program fd, link,
 * maps) separately from the bytecode generation context. This allows the
 * bytecode generator (bf_program) to be discarded after generation while
 * keeping the BPF objects alive.
 */

/**
 * BPF object handle.
 *
 * Holds references to BPF objects (program fd, link, maps) that need to
 * persist after bytecode generation is complete.
 */
struct bf_handle
{
    /** Name of the chain. */
    const char *name;

    /** File descriptor of the loaded BPF program. -1 if not loaded. */
    int prog_fd;

    /** Link attaching the program to a hook. NULL if not attached. */
    struct bf_link *link;

    /** Counters map. NULL if not created. */
    struct bf_map *cmap;

    /** Printer map. NULL if not created. */
    struct bf_map *pmap;

    /** Log map. NULL if not created. */
    struct bf_map *lmap;

    /** Context map, stores serialized chain data. NULL if not created. */
    struct bf_map *xmap;

    /** List of set maps. If a set is empty in the chain, NULL is inserted in
     * this list instead of a `bf_map` to preserve sets indexes. */
    bf_list sets;
};

#define _free_bf_handle_ __attribute__((__cleanup__(bf_handle_free)))

/**
 * @brief Allocate and initialize a new bf_handle object.
 *
 * @param handle `bf_handle` object to allocate and initialize. Can't be NULL.
 * @param name Name of the chain. Can't be NULL or empty.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_handle_new(struct bf_handle **handle, const char *name);

/**
 * @brief Allocate and initialize a bf_handle from serialized data.
 *
 * @param handle `bf_handle` object to allocate and initialize. Can't be NULL.
 * @param name Name of the chain to restore the context for. Can't be NULL.
 * @param node Node containing the serialized handle data.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_handle_new_from_dir(struct bf_handle **handle, const char *name,
                           struct bf_chain **chain);

/**
 * @brief Free a `bf_handle` object.
 *
 * Closes all file descriptors and frees all owned objects. If the BPF objects
 * are pinned, they will survive the close.
 *
 * @param handle `bf_handle` object to free. If `*handle` is NULL, this function
 *        has no effect. Can't be NULL.
 */
void bf_handle_free(struct bf_handle **handle);

/**
 * @brief Serialize a bf_handle.
 *
 * Only serializes the chain's name (for pin path restoration). The actual BPF
 * objects are restored from pins, not from serialized data.
 *
 * @param handle Handle to serialize. Can't be NULL.
 * @param pack bf_wpack_t object to serialize the handle into. Can't be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_handle_pack(const struct bf_handle *handle, bf_wpack_t *pack);

/**
 * @brief Dump the content of a `bf_handle` object.
 *
 * @param handle `bf_handle` object to dump. Can't be NULL.
 * @param prefix Prefix to use for the dump. Can't be NULL.
 */
void bf_handle_dump(const struct bf_handle *handle, prefix_t *prefix);

/**
 * @brief Persist the chain and the runtime context in a BPF map.
 *
 * @param handle Handle defining the context to persist. Can't be NULL.
 * @param chain Chain to persist the context for. Can't be NULL.
 * @param token_fd BPF token file descriptor, or -1 if no token is used.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_handle_persist_context(struct bf_handle *handle,
                              const struct bf_chain *chain, int token_fd);

/**
 * @brief Pin the BPF objects to the filesystem.
 *
 * Pins the program and all maps/link in the directory named after the chain's
 * name within `bf_ctx_get_pindir_fd`.
 * The link is only pinned if the program is attached.
 *
 * @param handle Handle containing the BPF objects to pin. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_handle_pin(struct bf_handle *handle);

/**
 * @brief Unpin the BPF objects from the filesystem.
 *
 * @param handle Handle containing the BPF objects to unpin. Can't be NULL.
 */
void bf_handle_unpin(struct bf_handle *handle);

/**
 * @brief Get a counter value from the handle's counters map.
 *
 * @param handle Handle to get the counter from. Can't be NULL.
 * @param counter_idx Index of the counter to get.
 * @param counter Counter structure to fill with the values. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_handle_get_counter(const struct bf_handle *handle, uint32_t counter_idx,
                          struct bf_counter *counter);

/**
 * @brief Attach the BPF program to a hook.
 *
 * Creates a `bf_link` to attach the program to the specified hook.
 *
 * @param handle Handle containing the loaded BPF program. Can't be NULL.
 * @param hook Hook to attach the program to.
 * @param hookopts Hook-specific options. Can't be NULL. Ownership is taken.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_handle_attach(struct bf_handle *handle, enum bf_hook hook,
                     struct bf_hookopts **hookopts);

/**
 * @brief Detach the program from its hook.
 *
 * Frees the link object, which detaches the program from the hook.
 *
 * @param handle Handle to detach. Can't be NULL.
 */
void bf_handle_detach(struct bf_handle *handle);

/**
 * @brief Unload the BPF program and destroy all BPF objects.
 *
 * Closes all file descriptors and frees all BPF objects. After this call,
 * the handle is empty but still valid.
 *
 * @param handle Handle to unload. Can't be NULL.
 */
void bf_handle_unload(struct bf_handle *handle);
