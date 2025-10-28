/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "fake.h"

static int _bft_list_dummy_pack(const void *data, bf_wpack_t *pack)
{
    const size_t *_data = data;

    bf_wpack_kv_u64(pack, "size_t", *_data);

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}

bf_list *bft_list_dummy(size_t len, bft_list_dummy_inserter inserter)
{
    _free_bf_list_ bf_list *list = NULL;
    bf_list_ops ops = bf_list_ops_default(freep, _bft_list_dummy_pack);
    int r;

    r = bf_list_new(&list, &ops);
    if (r)
        return NULL;

    for (size_t i = 0; i < len; ++i) {
        _cleanup_free_ size_t *value = malloc(sizeof(i));
        if (!value)
            return NULL;

        *value = i;

        r = inserter(list, value);
        if (r)
            return NULL;

        TAKE_PTR(value);
    }

    return TAKE_PTR(list);
}

bool bft_list_dummy_eq(const void *lhs, const void *rhs)
{
    const size_t *_lhs = lhs;
    const size_t *_rhs = rhs;

    return *_lhs == *_rhs;
}

bool bft_list_eq(const bf_list *lhs, const bf_list *rhs, bft_list_eq_cb cb)
{
    if (bf_list_size(lhs) != bf_list_size(rhs))
        return false;

    if (!cb)
        return true;

    for (const bf_list_node *lhs_node = bf_list_get_head(lhs),
                            *rhs_node = bf_list_get_head(rhs);
         lhs_node && rhs_node; lhs_node = bf_list_node_next(lhs_node),
                            rhs_node = bf_list_node_next(rhs_node)) {
        if (!cb(bf_list_node_get_data(lhs_node),
                bf_list_node_get_data(rhs_node)))
            return false;
    }

    return true;
}
