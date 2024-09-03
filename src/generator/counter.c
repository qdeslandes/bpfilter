/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "generator/counter.h"

#include <limits.h>
#include <string.h>

#include "core/logger.h"
#include "core/marsh.h"
#include "shared/helper.h"

int bf_counter_ctx_new(struct bf_counter_ctx **ctx, uint32_t prog_id, size_t n_rules)
{
    bf_assert(ctx);
    bf_assert(n_rules < USHRT_MAX);

    *ctx = malloc(sizeof(**ctx) + n_rules * sizeof(uint16_t));
    if (!*ctx)
        return -ENOMEM;

    (*ctx)->map_fd = -1;
    (*ctx)->prog_id = prog_id;
    snprintf((*ctx)->map_name, BPF_OBJ_NAME_LEN, "bf_cmap_%08x", prog_id);
    snprintf((*ctx)->map_pin_path, PIN_PATH_LEN, "/sys/fs/bpf/bf_cmap_%08x", prog_id);
    (*ctx)->n_rules = n_rules;
    
    for (size_t i = 0; i < n_rules; ++i)
        (*ctx)->mapping[i] = -1;

    return 0;
}

int bf_counter_ctx_new_from_marsh(struct bf_counter_ctx **ctx, const struct bf_marsh *marsh)
{
    _cleanup_bf_counter_ctx_ struct bf_counter_ctx *_ctx = NULL;
    struct bf_marsh *child = NULL;
    uint32_t prog_id;
    size_t n_rules;
    int r;

    bf_assert(ctx);
    bf_assert(marsh);

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -ENOENT;
    memcpy(&prog_id, child->data, sizeof(prog_id));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -ENOENT;
    memcpy(&n_rules, child->data, sizeof(n_rules));

    r = bf_counter_ctx_new(&_ctx, prog_id, n_rules);
    if (r < 0)
        return r;

    while ((child = bf_marsh_next_child(marsh, child))) {
        struct bf_marsh *entry = NULL;
        size_t index;

        if (!(entry = bf_marsh_next_child(child, entry)))
            return -ENOENT;    
        memcpy(&index, entry->data, sizeof(index)); 

        if (!(entry = bf_marsh_next_child(child, entry)))
            return -ENOENT;
        memcpy(&_ctx->mapping[index], entry->data, sizeof(_ctx->mapping[index]));

        if (bf_marsh_next_child(child, entry))
            return -E2BIG;
    }

    *ctx = TAKE_PTR(_ctx);

    return 0;
}

void bf_counter_ctx_free(struct bf_counter_ctx **ctx)
{
    bf_assert(ctx);

    if (!*ctx)
        return;

    closep(&(*ctx)->map_fd);
    freep(ctx);
}

int bf_counter_ctx_marsh(const struct bf_counter_ctx *ctx, struct bf_marsh **marsh)
{
    _cleanup_bf_marsh_ struct bf_marsh *_marsh = NULL;
    const char *name_suffix = ctx->map_name + 8; // Skip the 'bf_cmap_' part.
    int r;

    bf_assert(ctx);
    bf_assert(marsh);

    r = bf_marsh_new(&_marsh, NULL, 0);
    if (r < 0)
        return r;

    r |= bf_marsh_add_child_raw(&_marsh, &ctx->prog_id, sizeof(ctx->prog_id)); 
    r |= bf_marsh_add_child_raw(&_marsh, &ctx->n_rules, sizeof(ctx->n_rules));

    for (size_t i = 0; i < ctx->n_rules; ++i) {
        _cleanup_bf_marsh_ struct bf_marsh *child = NULL;

        if (ctx->mapping[i] == -1)
            continue;

        r = bf_marsh_new(&child, NULL, 0);
        if (r < 0)
            return r;

        r |= bf_marsh_add_child_raw(&child, &i, sizeof(i));
        r |= bf_marsh_add_child_raw(&child, &ctx->mapping[i], sizeof(ctx->mapping[i]));
        if (r < 0)
            return r;

        r = bf_marsh_add_child_obj(&_marsh, child);
        if (r < 0)
            return r;
    }

    *marsh = TAKE_PTR(_marsh);

    return 0;
}

void bf_counter_ctx_dump(const struct bf_counter_ctx *ctx, prefix_t *prefix)
{
    bf_assert(ctx);
    bf_assert(prefix);
}
