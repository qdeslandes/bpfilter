/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/handle.h"

#include <linux/bpf.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpfilter/bpf.h>
#include <bpfilter/chain.h>
#include <bpfilter/counter.h>
#include <bpfilter/dump.h>
#include <bpfilter/helper.h>
#include <bpfilter/hook.h>
#include <bpfilter/io.h>
#include <bpfilter/list.h>
#include <bpfilter/logger.h>
#include <bpfilter/pack.h>

#include "cgen/prog/link.h"
#include "cgen/prog/map.h"

#define _BF_PROG_NAME "bf_prog"
#define _BF_LINK_NAME "bf_link"

/**
 * @brief Open a file descriptor to the handle's pin directory.
 *
 * @param name Name of the runtime context to open. Can't be NULL.
 * @return Handle to chain `name` pin directory, or a negative errno value on
 *         failure.
 */
static int _bf_handle_get_fd(const char *name)
{
    _cleanup_close_ int bf_fd = -1;
    _cleanup_close_ int chain_fd = -1;

    assert(name);

    bf_fd = bf_ctx_get_pindir_fd(global_ctx);
    if (bf_fd < 0)
        return bf_fd;

    chain_fd = bf_opendir_at(bf_fd, name, true);
    if (chain_fd < 0)
        return chain_fd;

    return TAKE_FD(chain_fd);
}

int bf_handle_new(struct bf_handle **handle, const char *name)
{
    _free_bf_handle_ struct bf_handle *_handle = NULL;

    assert(handle);
    assert(name);

    _handle = calloc(1, sizeof(*_handle));
    if (!_handle)
        return -ENOMEM;

    _handle->name = strdup(name);
    if (!_handle->name)
        return -ENOMEM;

    _handle->prog_fd = -1;
    _handle->sets = bf_list_default(bf_map_free, bf_map_pack);

    *handle = TAKE_PTR(_handle);

    return 0;
}

int bf_handle_new_from_dir(struct bf_handle **handle, const char *name,
                           struct bf_chain **chain)
{
    _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
    _free_bf_handle_ struct bf_handle *_handle = NULL;
    _cleanup_free_ uint32_t *map_ids = NULL;
    _cleanup_close_ int link_fd = -1;
    _cleanup_close_ int link_extra_fd = -1;
    _cleanup_close_ int dir_fd = -1;
    struct bpf_prog_info prog_info = {};
    bf_rpack_node_t child;
    int r;

    assert(handle);
    assert(name);

    dir_fd = _bf_handle_get_fd(name);
    if (dir_fd < 0) {
        return bf_err_r(dir_fd, "bf_handle: %s: failed to open pin directory",
                        name);
    }

    r = bf_handle_new(&_handle, name);
    if (r)
        return r;

    r = bf_bpf_obj_get(_BF_PROG_NAME, dir_fd, &_handle->prog_fd);
    if (r < 0)
        return bf_err_r(r, "failed to restore bf_handle.prog_fd from pin");

    // Restore the context map
    {
        _cleanup_close_ int xmap_fd = -1;

        r = bf_bpf_obj_get("ctx_map", dir_fd, &xmap_fd);
        if (r == 0) {
            r = bf_map_new_from_fd(&_handle->xmap, xmap_fd);
            if (r)
                return bf_err_r(r, "failed to restore ctx map from pin");
        } else if (r != -ENOENT) {
            return bf_err_r(r, "failed to open pinned ctx map");
        }
    }

    // Restore the link + hookopts if any
    {
        _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
        _free_bf_rpack_ bf_rpack_t *rpack = NULL;
        _cleanup_free_ void *value = NULL;
        bf_rpack_node_t node;
        uint32_t key = 0;
        int r;

        value = malloc(_handle->xmap->value_size);
        if (!value)
            return -ENOMEM;

        r = bf_bpf_map_lookup_elem(_handle->xmap->fd, &key, value);
        if (r < 0)
            return bf_err_r(errno, "failed to read ctx map");

        r = bf_rpack_new(&rpack, value, _handle->xmap->value_size);
        if (r)
            return bf_err_r(r, "failed to create rpack from ctx map data");

        node = bf_rpack_root(rpack);

        r = bf_rpack_kv_node(node, "chain", &child);
        if (r)
            return bf_rpack_key_err(r, "bf_handle.chain");
        r = bf_chain_new_from_pack(chain, child);
        if (r)
            return bf_err_r(r, "failed to restore chain");

        r = bf_rpack_kv_node(node, "hookopts", &child);
        if (r)
            return bf_rpack_key_err(r, "bf_handle.hookopts");
        if (!bf_rpack_is_nil(child)) {
            r = bf_hookopts_new_from_pack(&hookopts, child);
            if (r)
                return bf_rpack_key_err(r, "bf_handle.hookopts");

            r = bf_bpf_obj_get("bf_link", dir_fd, &link_fd);
            if (r)
                return bf_err_r(r, "failed to open chain's link");

            r = bf_bpf_obj_get("bf_link_extra", dir_fd, &link_extra_fd);
            if (r != 0 && r != -ENOENT)
                return bf_err_r(r, "failed to open chain's link extra");

            r = bf_link_new_from_fd(&_handle->link, &hookopts, link_fd,
                                    link_extra_fd);
            if (r)
                return bf_err_r(r, "failed to restore bf_link");
        }
    }

    r = bf_bpf_obj_get_info(_handle->prog_fd, &prog_info, sizeof(prog_info));
    if (r)
        return bf_err_r(r, "failed to get program info for '%s'", name);

    if (prog_info.nr_map_ids > 0) {
        uint32_t nr_map_ids = prog_info.nr_map_ids;

        map_ids = calloc(nr_map_ids, sizeof(*map_ids));
        if (!map_ids)
            return -ENOMEM;

        memset(&prog_info, 0, sizeof(prog_info));
        prog_info.nr_map_ids = nr_map_ids;
        prog_info.map_ids = bf_ptr_to_u64(map_ids);

        r = bf_bpf_obj_get_info(_handle->prog_fd, &prog_info,
                                sizeof(prog_info));
        if (r)
            return bf_err_r(r, "failed to get map IDs for '%s'", name);
    }

    for (uint32_t i = 0; i < prog_info.nr_map_ids; ++i) {
        _cleanup_close_ int map_fd = -1;
        _free_bf_map_ struct bf_map *map = NULL;

        map_fd = bf_bpf_map_get_fd_by_id(map_ids[i]);
        if (map_fd < 0) {
            return bf_err_r(map_fd, "failed to get fd for map ID %u",
                            map_ids[i]);
        }

        r = bf_map_new_from_fd(&map, map_fd);
        if (r)
            return bf_err_r(r, "failed to restore map from ID %u", map_ids[i]);

        switch (map->type) {
        case BF_MAP_TYPE_COUNTERS:
            _handle->cmap = TAKE_PTR(map);
            break;
        case BF_MAP_TYPE_PRINTER:
            _handle->pmap = TAKE_PTR(map);
            break;
        case BF_MAP_TYPE_LOG:
            _handle->lmap = TAKE_PTR(map);
            break;
        case BF_MAP_TYPE_SET:
            r = bf_list_push(&_handle->sets, (void **)&map);
            if (r)
                return r;
            break;
        default:
            return bf_err_r(-EINVAL, "unknown bf_map type %d", map->type);
        }
    }

    *handle = TAKE_PTR(_handle);

    return 0;
}

void bf_handle_free(struct bf_handle **handle)
{
    assert(handle);

    if (!*handle)
        return;

    unlinkat(bf_ctx_get_pindir_fd(global_ctx), (*handle)->name, AT_REMOVEDIR);
    freep((void *)&(*handle)->name);
    closep(&(*handle)->prog_fd);

    bf_link_free(&(*handle)->link);
    bf_map_free(&(*handle)->cmap);
    bf_map_free(&(*handle)->pmap);
    bf_map_free(&(*handle)->lmap);
    bf_map_free(&(*handle)->xmap);
    bf_list_clean(&(*handle)->sets);

    freep((void *)handle);
}

int bf_handle_pack(const struct bf_handle *handle, bf_wpack_t *pack)
{
    assert(handle);
    assert(pack);

    bf_wpack_kv_str(pack, "name", handle->name);

    if (handle->link) {
        bf_wpack_open_object(pack, "hookopts");
        bf_hookopts_pack(handle->link->hookopts, pack);
        bf_wpack_close_object(pack);
    } else {
        bf_wpack_kv_nil(pack, "hookopts");
    }

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}

void bf_handle_dump(const struct bf_handle *handle, prefix_t *prefix)
{
    assert(handle);
    assert(prefix);

    DUMP(prefix, "struct bf_handle at %p", handle);

    bf_dump_prefix_push(prefix);

    DUMP(prefix, "name: %s", handle->name);
    DUMP(prefix, "prog_fd: %d", handle->prog_fd);

    if (handle->link) {
        DUMP(prefix, "link: struct bf_link *");
        bf_dump_prefix_push(prefix);
        bf_link_dump(handle->link, bf_dump_prefix_last(prefix));
        bf_dump_prefix_pop(prefix);
    } else {
        DUMP(prefix, "link: struct bf_link * (NULL)");
    }

    if (handle->cmap) {
        DUMP(prefix, "cmap: struct bf_map *");
        bf_dump_prefix_push(prefix);
        bf_map_dump(handle->cmap, bf_dump_prefix_last(prefix));
        bf_dump_prefix_pop(prefix);
    } else {
        DUMP(prefix, "cmap: struct bf_map * (NULL)");
    }

    if (handle->pmap) {
        DUMP(prefix, "pmap: struct bf_map *");
        bf_dump_prefix_push(prefix);
        bf_map_dump(handle->pmap, bf_dump_prefix_last(prefix));
        bf_dump_prefix_pop(prefix);
    } else {
        DUMP(prefix, "pmap: struct bf_map * (NULL)");
    }

    if (handle->lmap) {
        DUMP(prefix, "lmap: struct bf_map *");
        bf_dump_prefix_push(prefix);
        bf_map_dump(handle->lmap, bf_dump_prefix_last(prefix));
        bf_dump_prefix_pop(prefix);
    } else {
        DUMP(prefix, "lmap: struct bf_map * (NULL)");
    }

    if (handle->xmap) {
        DUMP(prefix, "xmap: struct bf_map *");
        bf_dump_prefix_push(prefix);
        bf_map_dump(handle->xmap, bf_dump_prefix_last(prefix));
        bf_dump_prefix_pop(prefix);
    } else {
        DUMP(prefix, "xmap: struct bf_map * (NULL)");
    }

    DUMP(prefix, "sets: bf_list<bf_map>[%lu]", bf_list_size(&handle->sets));
    bf_dump_prefix_push(prefix);
    bf_list_foreach (&handle->sets, map_node) {
        struct bf_map *map = bf_list_node_get_data(map_node);

        if (bf_list_is_tail(&handle->sets, map_node))
            bf_dump_prefix_last(prefix);

        if (!map) {
            DUMP(prefix, "struct bf_map * (NULL)");
            continue;
        }

        bf_map_dump(map, prefix);
    }
    bf_dump_prefix_pop(prefix);

    bf_dump_prefix_pop(prefix);
}

int bf_handle_pin(struct bf_handle *handle)
{
    _cleanup_close_ int dir_fd = -1;
    int r;

    assert(handle);

    dir_fd = _bf_handle_get_fd(handle->name);
    if (dir_fd < 0) {
        return bf_err_r(dir_fd, "bf_handle: %s: failed to open pin directory",
                        handle->name);
    }

    r = bf_bpf_obj_pin(_BF_PROG_NAME, handle->prog_fd, dir_fd);
    if (r && r != -EEXIST) {
        bf_err_r(r, "failed to pin BPF program");
        goto err_unpin_all;
    }

    if (handle->link) {
        r = bf_link_pin(handle->link, dir_fd);
        if (r && r != -EEXIST) {
            bf_err_r(r, "failed to pin BPF link");
            goto err_unpin_all;
        }
    }

    if (handle->xmap) {
        r = bf_map_pin(handle->xmap, dir_fd);
        if (r && r != -EEXIST) {
            bf_err_r(r, "failed to pin ctx map");
            goto err_unpin_all;
        }
    }

    return 0;

err_unpin_all:
    closep(&dir_fd);
    bf_handle_unpin(handle);
    return r;
}

void bf_handle_unpin(struct bf_handle *handle)
{
    _cleanup_close_ int dir_fd = -1;

    assert(handle);

    dir_fd = _bf_handle_get_fd(handle->name);
    if (dir_fd < 0) {
        bf_warn_r(dir_fd, "bf_handle: %s: failed to open pin directory",
                  handle->name);
        return;
    }

    if (handle->link)
        bf_link_unpin(handle->link, dir_fd);
    if (handle->xmap)
        bf_map_unpin(handle->xmap, dir_fd);

    unlinkat(dir_fd, _BF_PROG_NAME, 0);
    unlinkat(bf_ctx_get_pindir_fd(global_ctx), handle->name, AT_REMOVEDIR);
}

int bf_handle_get_counter(const struct bf_handle *handle, uint32_t counter_idx,
                          struct bf_counter *counter)
{
    int r;

    assert(handle);
    assert(counter);

    if (!handle->cmap)
        return bf_err_r(-ENOENT, "handle has no counters map");

    r = bf_bpf_map_lookup_elem(handle->cmap->fd, &counter_idx, counter);
    if (r < 0)
        return bf_err_r(r, "failed to lookup counters map");

    return 0;
}

int bf_handle_attach(struct bf_handle *handle, enum bf_hook hook,
                     struct bf_hookopts **hookopts)
{
    int r;

    assert(handle);
    assert(hookopts);

    if (handle->link)
        return bf_err_r(-EEXIST, "program is already attached");

    r = bf_link_new(&handle->link, _BF_LINK_NAME, hook, hookopts,
                    handle->prog_fd);
    if (r)
        return bf_err_r(r, "failed to attach bf_link");

    return 0;
}

void bf_handle_detach(struct bf_handle *handle)
{
    assert(handle);

    if (handle->link) {
        (void)bf_bpf_link_detach(handle->link->fd);
        if (handle->link->fd_extra >= 0)
            (void)bf_bpf_link_detach(handle->link->fd_extra);
    }

    bf_link_free(&handle->link);
}

int bf_handle_persist_context(struct bf_handle *handle,
                              const struct bf_chain *chain, int token_fd)
{
    _free_bf_map_ struct bf_map *map = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _cleanup_close_ int pin_fd = -1;
    const void *data;
    size_t data_len;
    uint32_t key = 0;
    int r;

    assert(handle);
    assert(chain);

    r = bf_wpack_new(&wpack);
    if (r)
        return bf_err_r(r, "failed to create wpack for ctx map");

    bf_wpack_open_object(wpack, "chain");
    bf_chain_pack(chain, wpack);
    bf_wpack_close_object(wpack);

    if (handle->link) {
        bf_wpack_open_object(wpack, "hookopts");
        bf_hookopts_pack(handle->link->hookopts, wpack);
        bf_wpack_close_object(wpack);
    } else {
        bf_wpack_kv_nil(wpack, "hookopts");
    }

    r = bf_wpack_get_data(wpack, &data, &data_len);
    if (r)
        return bf_err_r(r, "failed to get serialized chain data");

    if (handle->xmap) {
        pin_fd = _bf_handle_get_fd(handle->name);
        bf_map_unpin(handle->xmap, pin_fd);
        bf_map_free(&handle->xmap);
    }

    r = bf_map_new(&handle->xmap, "ctx_map", BF_MAP_TYPE_CTX, sizeof(uint32_t),
                   data_len, 1, token_fd);
    if (r)
        return bf_err_r(r, "failed to create the ctx bf_map object");

    r = bf_map_set_elem(handle->xmap, &key, (void *)data);
    if (r)
        return bf_err_r(r, "failed to set ctx map elem");

    return 0;
}
