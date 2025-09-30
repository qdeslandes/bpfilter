/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/handle.h"

#include <unistd.h>

#include <bpfilter/bpf.h>
#include <bpfilter/pack.h>

#include "bpfilter/dump.h"
#include "bpfilter/helper.h"
#include "cgen/prog/link.h"
#include "cgen/prog/map.h"

int bf_handle_new(struct bf_handle **handle)
{
    _free_bf_handle_ struct bf_handle *_handle = NULL;

    bf_assert(handle);

    _handle = calloc(1, sizeof(*_handle));
    if (!_handle)
        return -ENOMEM;

    _handle->prog_fd = -1;
    _handle->sets = bf_list_default(bf_map_free, bf_map_pack);

    *handle = TAKE_PTR(_handle);

    return 0;
}

static int _bf_handle_id_is_link(uint32_t id)
{
    int r = bf_bpf_link_get_fd_by_id(id);
    if (r == -ENOENT)
        return 0;
    if (r < 0)
        return r;

    closep(&r);
    return 1;
}

static int _bf_handle_id_is_prog(uint32_t id)
{
    int r = bf_bpf_prog_get_fd_by_id(id);
    if (r == -ENOENT)
        return 0;
    if (r < 0)
        return r;

    closep(&r);
    return 1;
}

int bf_handle_new_from_fd(struct bf_handle **handle, int fd,
                          struct bf_hookopts **hookopts)
{
    union
    {
        struct bpf_link_info link_info;
        struct bpf_prog_info prog_info;
    } fd_info;
    _free_bf_handle_ struct bf_handle *_handle = NULL;
    _cleanup_free_ uint32_t *map_ids = NULL;
    struct bpf_prog_info prog_info;
    uint32_t prog_id;
    int r;

    bf_assert(handle);

    r = bf_handle_new(&_handle);
    if (r)
        return bf_err_r(r, "failed to create a new bf_handle to restore");

    r = bf_bpf_obj_get_info_by_fd(fd, &fd_info, sizeof(fd_info));
    if (r)
        return bf_err_r(r, "failed to get BPF object info by FD");

    if (_bf_handle_id_is_link(fd_info.link_info.id) == 1) {
        /* If the ID is a link, read the link info and store the program ID
         * and program info. */
        r = bf_link_new_from_id(&_handle->link, fd_info.link_info.id, hookopts);
        if (r)
            return bf_err_r(r, "failed to restore link");

        prog_id = fd_info.link_info.prog_id;
        _handle->prog_fd = bf_bpf_prog_get_fd_by_id(prog_id);
        if (_handle->prog_fd < 0) {
            return bf_err_r(_handle->prog_fd,
                            "failed to open BPF program ID %u", prog_id);
        }

        memset(&prog_info, 0, sizeof(prog_info));
        r = bf_bpf_obj_get_info_by_fd(_handle->prog_fd, &prog_info,
                                      sizeof(prog_info));
        if (r)
            return bf_err_r(r, "failed to request BPF program info");
    } else if (_bf_handle_id_is_prog(fd_info.prog_info.id) != 1) {
        /* If `fd` is a file descriptor of the program, duplicate it, so we
         * can keep if in `_handle`. */
        _handle->prog_fd = dup(fd);
        if (_handle->prog_fd < 0)
            return bf_err_r(errno, "failed to duplicate program FD");

        prog_id = fd_info.prog_info.id;
        prog_info = fd_info.prog_info;
    } else {
        return bf_err_r(-ENOENT, "bf_handle FD is neither a program or a link");
    }

    if (prog_info.nr_map_ids) {
        /* If there are map IDs in the program info structure, we need to
         * request them. */
        struct bpf_prog_info info;

        memset(&info, 0, sizeof(info));

        map_ids = malloc(sizeof(uint32_t) * prog_info.nr_map_ids);
        if (!map_ids)
            return -ENOMEM;

        info.nr_map_ids = prog_info.nr_map_ids;
        info.map_ids = bf_ptr_to_u64(map_ids);
        r = bf_bpf_obj_get_info_by_fd(_handle->prog_fd, &info, sizeof(info));
        if (r) {
            return bf_err_r(r,
                            "failed to request BPF program info with map IDs");
        }

        prog_info.map_ids = bf_ptr_to_u64(map_ids);
    }

    for (uint32_t i = 0; i < prog_info.nr_map_ids; ++i) {
        _free_bf_map_ struct bf_map *map = NULL;
        uint32_t id = ((uint32_t *)prog_info.map_ids)[i];

        r = bf_map_new_from_id(&map, id);
        if (r)
            return bf_err_r(r, "failed to load map");

        switch (map->type) {
        case BF_MAP_TYPE_COUNTERS:
            if (_handle->counters)
                return bf_err_r(-EEXIST, "bf_handle: duplicate counter map");
            _handle->counters = TAKE_PTR(map);
            break;
        case BF_MAP_TYPE_PRINTER:
            if (_handle->printer)
                return bf_err_r(-EEXIST, "bf_handle: duplicate printer map");
            _handle->printer = TAKE_PTR(map);
            break;
        case BF_MAP_TYPE_LOG:
            if (_handle->logger)
                return bf_err_r(-EEXIST, "bf_handle: duplicate log map");
            _handle->logger = TAKE_PTR(map);
            break;
        case BF_MAP_TYPE_SET:
            r = bf_list_add_tail(&_handle->sets, map);
            if (r)
                return bf_err_r(r, "bf_handle: failed to insert set map");
            TAKE_PTR(map);
            break;
        default:
            return bf_err_r(-EINVAL, "unknown map type %d", map->type);
        }
    }

    *handle = TAKE_PTR(_handle);

    return 0;
}

void bf_handle_free(struct bf_handle **handle)
{
    struct bf_handle *_handle;

    bf_assert(handle);

    _handle = *handle;
    if (!_handle)
        return;

    closep(&_handle->prog_fd);
    bf_map_free(&_handle->counters);
    bf_map_free(&_handle->printer);
    bf_map_free(&_handle->logger);
    bf_list_clean(&_handle->sets);
    freep((void *)handle);
}

void bf_handle_dump(const struct bf_handle *handle, prefix_t *prefix)
{
    bf_assert(handle);
    bf_assert(prefix);

    DUMP(prefix, "struct bf_handle at %p", handle);

    bf_dump_prefix_push(prefix);
    DUMP(prefix, "prog_fd: %d", handle->prog_fd);

    if (handle->link) {
        DUMP(prefix, "link: struct bf_link * %p", handle->link);
        bf_dump_prefix_push(prefix);
        bf_link_dump(handle->link, prefix);
        bf_dump_prefix_pop(prefix);
    } else {
        DUMP(prefix, "link: struct bf_link * (NULL)");
    }

    if (handle->counters) {
        DUMP(prefix, "counters: struct bf_map * %p", handle->counters);
        bf_dump_prefix_push(prefix);
        bf_map_dump(handle->counters, prefix);
        bf_dump_prefix_pop(prefix);
    } else {
        DUMP(prefix, "counters: struct bf_map * (NULL)");
    }

    if (handle->printer) {
        DUMP(prefix, "printer: struct bf_map * %p", handle->printer);
        bf_dump_prefix_push(prefix);
        bf_map_dump(handle->printer, prefix);
        bf_dump_prefix_pop(prefix);
    } else {
        DUMP(prefix, "printer: struct bf_map * (NULL)");
    }

    if (handle->logger) {
        DUMP(prefix, "logger: struct bf_map * %p", handle->logger);
        bf_dump_prefix_push(prefix);
        bf_map_dump(handle->logger, prefix);
        bf_dump_prefix_pop(prefix);
    } else {
        DUMP(prefix, "logger: struct bf_map * (NULL)");
    }

    DUMP(prefix, "sets: bf_list<bf_map>[%lu]", bf_list_size(&handle->sets));
    bf_dump_prefix_push(prefix);
    bf_list_foreach (&handle->sets, set_node) {
        struct bf_map *set = bf_list_node_get_data(set_node);

        if (bf_list_is_tail(&handle->sets, set_node))
            bf_dump_prefix_last(prefix);

        bf_map_dump(set, prefix);
    }
    bf_dump_prefix_pop(prefix);

    bf_dump_prefix_pop(prefix);
}
