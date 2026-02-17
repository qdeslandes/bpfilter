/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "ctx.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include <bpfilter/bpf.h>
#include <bpfilter/dump.h>
#include <bpfilter/helper.h>
#include <bpfilter/io.h>
#include <bpfilter/logger.h>

#include "cgen/elfstub.h"

#define _BF_CTX_DEFAULT_BPFFS_PATH "/sys/fs/bpf"
#define _BF_CTX_PIN_DIR "bpfilter"

bf_ctx_t *global_ctx = NULL;

static int _bf_gen_token(const char *path)
{
    _cleanup_close_ int mnt_fd = -1;
    _cleanup_close_ int bpffs_fd = -1;
    _cleanup_close_ int token_fd = -1;

    assert(path);

    mnt_fd = open(path, O_DIRECTORY);
    if (mnt_fd < 0)
        return bf_err_r(-errno, "failed to open '%s'", path);

    bpffs_fd = openat(mnt_fd, ".", O_RDWR, 0);
    if (bpffs_fd < 0)
        return bf_err_r(-errno, "failed to get bpffs FD from '%s'", path);

    token_fd = bf_bpf_token_create(bpffs_fd);
    if (token_fd < 0)
        return bf_err_r(token_fd, "failed to create BPF token for '%s'", path);

    return TAKE_FD(token_fd);
}

int bf_ctx_new(bf_ctx_t **ctx, const char *bpffs_path, bool with_bpf_token)
{
    _free_bf_ctx_ bf_ctx_t *_ctx = NULL;
    int r;

    assert(ctx);

    _ctx = calloc(1, sizeof(*_ctx));
    if (!_ctx)
        return bf_log_oom();

    _ctx->token_fd = -1;

    if (!bpffs_path)
        bpffs_path = _BF_CTX_DEFAULT_BPFFS_PATH;
    _ctx->bpffs_path = strdup(bpffs_path);
    if (!_ctx->bpffs_path)
        return bf_log_oom();

    if (with_bpf_token) {
        _ctx->token_fd = _bf_gen_token(bpffs_path);
        if (_ctx->token_fd < 0)
            return bf_err_r(_ctx->token_fd, "failed to open BPF token");
    }

    r = bf_ns_init(&_ctx->ns, getpid());
    if (r)
        return bf_err_r(r, "failed to initialise current bf_ns");

    *ctx = TAKE_PTR(_ctx);

    return 0;
}

void bf_ctx_free(bf_ctx_t **ctx)
{
    bf_ctx_t *_ctx;

    assert(ctx);

    _ctx = *ctx;
    if (!_ctx)
        return;

    bf_free(_ctx->bpffs_path);
    bf_close(_ctx->token_fd);
    bf_ns_clean(&_ctx->ns);

    for (enum bf_elfstub_id id = 0; id < _BF_ELFSTUB_MAX; ++id)
        bf_elfstub_free(&_ctx->stubs[id]);

    bf_free(*ctx);
}

void bf_ctx_dump(const bf_ctx_t *ctx, prefix_t *prefix)
{
    assert(ctx);

    if (!prefix)
        prefix = EMPTY_PREFIX;

    DUMP(prefix, "bf_ctx_t * at %p", ctx);

    bf_dump_prefix_push(prefix);

    DUMP(prefix, "bpffs_path: %s", ctx->bpffs_path);
    DUMP(prefix, "token_fd: %d", ctx->token_fd);

    // Namespaces
    DUMP(prefix, "ns: struct bf_ns")
    bf_dump_prefix_push(prefix);

    DUMP(prefix, "net: struct bf_ns_info");
    bf_dump_prefix_push(prefix);
    DUMP(prefix, "fd: %d", ctx->ns.net.fd);
    DUMP(bf_dump_prefix_last(prefix), "inode: %u", ctx->ns.net.inode);
    bf_dump_prefix_pop(prefix);

    DUMP(bf_dump_prefix_last(prefix), "mnt: struct bf_ns_info");
    bf_dump_prefix_push(prefix);
    DUMP(prefix, "fd: %d", ctx->ns.mnt.fd);
    DUMP(bf_dump_prefix_last(prefix), "inode: %u", ctx->ns.mnt.inode);
    bf_dump_prefix_pop(prefix);

    bf_dump_prefix_pop(prefix);

    // ELF stubs
    DUMP(bf_dump_prefix_last(prefix), "stubs: struct bf_elfstub *[%d]",
         _BF_ELFSTUB_MAX);
    bf_dump_prefix_push(prefix);
    for (enum bf_elfstub_id id = 0; id < _BF_ELFSTUB_MAX; ++id) {
        if (id == _BF_ELFSTUB_MAX - 1)
            bf_dump_prefix_last(prefix);

        if (ctx->stubs[id]) {
            DUMP(prefix, "[%d]: %zu insns", id, ctx->stubs[id]->ninsns)
        } else {
            DUMP(prefix, "[%d]: (not loaded)", id)
        }
    }
    bf_dump_prefix_pop(prefix);

    bf_dump_prefix_pop(prefix);
}

const struct bf_elfstub *bf_ctx_get_elfstub(bf_ctx_t *ctx,
                                            enum bf_elfstub_id id)
{
    int r;

    assert(ctx);

    if (id < 0 || id >= _BF_ELFSTUB_MAX) {
        bf_err_r(-EINVAL, "invalid ELF stub ID %d", id);
        return NULL;
    }

    if (!ctx->stubs[id]) {
        r = bf_elfstub_new(&ctx->stubs[id], id);
        if (r) {
            bf_err_r(r, "failed to create ELF stub ID %u", id);
            return NULL;
        }
    }

    return ctx->stubs[id];
}

int bf_ctx_get_pindir_fd(const bf_ctx_t *ctx)
{
    _cleanup_close_ int bpffs_fd = -1;
    _cleanup_close_ int pindir_fd = -1;

    assert(ctx);

    bpffs_fd = bf_opendir(ctx->bpffs_path);
    if (bpffs_fd < 0) {
        return bf_err_r(bpffs_fd, "failed to open BPF FS at %s",
                        ctx->bpffs_path);
    }

    pindir_fd = bf_opendir_at(bpffs_fd, _BF_CTX_PIN_DIR, true);
    if (pindir_fd < 0) {
        return bf_err_r(pindir_fd,
                        "failed to open pin directory %s/" _BF_CTX_PIN_DIR,
                        ctx->bpffs_path);
    }

    return TAKE_FD(pindir_fd);
}
