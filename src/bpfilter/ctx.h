/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>

#include <bpfilter/dump.h>
#include <bpfilter/ns.h>

#include "cgen/elfstub.h"

/**
 * @file ctx.h
 *
 * Runtime context for bpfilter.
 *
 * The runtime context (`bf_ctx`) stores the configuration and state
 * required to generate and manage BPF programs: the path to the BPF
 * filesystem used for pinning, an optional BPF token for unprivileged
 * operations, the daemon's original namespaces, and lazily-loaded ELF stubs
 * integrated into the generated programs.
 */

/**
 * @struct bf_ctx
 *
 * bpfilter runtime context, used to cache options and data to manipulate chains
 * more efficiently.
 */
struct bf_ctx
{
    /// Path to the BPF filesystem to use for pinning objects and BPF token.
    const char *bpffs_path;

    /// BPF token file descriptor
    int token_fd;

    /// Namespaces the daemon was started in.
    struct bf_ns ns;

    /// Elf stubs used by the BPF programs, lazy loaded
    struct bf_elfstub *stubs[_BF_ELFSTUB_MAX];
};

typedef struct bf_ctx bf_ctx_t;

extern bf_ctx_t *global_ctx;

#define _free_bf_ctx_ __attribute__((cleanup(bf_ctx_free)))

/**
 * @brief Allocate and intializes a bpfilter runtime context.
 *
 * @param ctx Context to allocate and initialize. Can't be NULL. On success,
 *        `*ctx` points to the new context and the caller is responsible for
 *         freeing it using `bf_ctx_free`. On error, `*ctx` is unchanged.
 * @param bpffs_path Path to the BPF filesystem to pin chains to. If NULL,
 *        the default path `/sys/fs/bpf` is used. All the chains will be pinned
 *        into the subdirectory `<bpffs_path>/bpfilter`.
 * @param with_bpf_token If true, create a BPF token from `bpffs_path` (or the
 *        default BPF FS path if NULL). The token will be used to perform
 *        sensitive operation from a user namespace, not all operations are
 *        supported (i.e. reading objects from `bpffs_path`).
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_ctx_new(bf_ctx_t **ctx, const char *bpffs_path, bool with_bpf_token);

/**
 * @brief Cleanup and free a bpfilter runtime contxt.
 *
 * @param ctx Context to cleanup and free. Can't be NULL. If `*ctx` is NULL,
 *        this function has no effect.
 */
void bf_ctx_free(bf_ctx_t **ctx);

/**
 * @brief Dump a bpfilter runtime context.
 *
 * @param ctx Context to dump to stdout. Can't be NULL.
 * @param prefix Prefix for each line logged, or NULL for no prefix.
 */
void bf_ctx_dump(const bf_ctx_t *ctx, prefix_t *prefix);

/**
 * @brief Get a ELF stub by ID.
 *
 * The ELF stubs are lazily loaded into the context: the ELF stub is created
 * the first time it is requested, then it is cached in the context.
 *
 * @param ctx Context to fetch the ELF stub for. Can't be NULL.
 * @param id ID of the ELF stub to request.
 * @return Non-owning pointer to an ELF stub on success, or NULL on failure.
 */
const struct bf_elfstub *bf_ctx_get_elfstub(bf_ctx_t *ctx,
                                            enum bf_elfstub_id id);

/**
 * @brief Get a file descriptor to the directory to pin the BPF objects into.
 *
 * BPF objects are pinned within a subdirectory of `ctx->bpffs_path`. The
 * subdirectory is created (if needed) when the file descriptor is opened.
 *
 * @param ctx Context to get the pin directory file descriptor for. Can't be NULL.
 * @return Owning file descriptor to a pin directory, or a negative errno
 *         value on error.
 */
int bf_ctx_get_pindir_fd(const bf_ctx_t *ctx);

/**
 * @brief Get the daemon's original namespaces.
 *
 * During the creation of the bpfilter runtime context, a reference to the
 * current namespace is collected. When attaching the BPF program, the daemon
 * will jump to the client's namespace before performing the BPF system call
 * before jumping back to its original namespace.
 *
 * @param ctx Context to get the namespace for. Can't be NULL.
 * @return Non-owning pointer to the daemon's namespace.
 */
static inline const struct bf_ns *bf_ctx_get_ns(const bf_ctx_t *ctx)
{
    assert(ctx);

    return &ctx->ns;
}

/**
 * @brief Get the file descriptor of the BPF token.
 *
 * @param ctx Context to get the BPF token for. Can't be NULL.
 * @return Non-owning BPF token of `ctx` (should not be closed). If no BPF
 *         token has been created, `-1` is returned.
 */
static inline int bf_ctx_get_token_fd(const bf_ctx_t *ctx)
{
    assert(ctx);

    return ctx->token_fd;
}
