/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "core/matcher.h"

#include "core/marsh.h"
#include "shared/helper.h"

int bf_matcher_new(struct bf_matcher **matcher, enum bf_matcher_field field,
                   enum bf_matcher_op op, uint8_t (*data)[16])
{
    struct bf_matcher *_matcher;

    _matcher = malloc(sizeof(*_matcher));
    if (!_matcher)
        return -ENOMEM;

    _matcher->field = field;
    _matcher->op = op;
    memcpy(_matcher->raw, *data, sizeof(_matcher->raw));

    *matcher = _matcher;

    return 0;
}

void bf_matcher_free(struct bf_matcher **matcher)
{
    if (!*matcher)
        return;

    free(*matcher);
    *matcher = NULL;
}

int bf_matcher_marsh(const struct bf_matcher *matcher, struct bf_marsh **marsh)
{
    bf_assert(matcher);
    bf_assert(marsh);

    _cleanup_bf_marsh_ struct bf_marsh *_marsh = NULL;
    int r;

    r = bf_marsh_new(&_marsh, NULL, 0);
    if (r < 0)
        return r;

    r |= bf_marsh_add_child_raw(&_marsh, &matcher->field,
                                sizeof(matcher->field));
    r |= bf_marsh_add_child_raw(&_marsh, &matcher->op, sizeof(matcher->op));
    r |=
        bf_marsh_add_child_raw(&_marsh, &matcher->raw[0], sizeof(matcher->raw));
    if (r)
        return bf_err_code(r, "failed to serialize matcher");

    *marsh = TAKE_PTR(_marsh);
    return 0;
}

int bf_matcher_unmarsh(const struct bf_marsh *marsh,
                       struct bf_matcher **matcher)
{
    bf_assert(marsh);
    bf_assert(matcher);

    _cleanup_bf_matcher_ struct bf_matcher *_matcher = NULL;
    struct bf_marsh *child = NULL;
    enum bf_matcher_field field;
    enum bf_matcher_op op;
    uint8_t raw[16];
    int r;

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&field, child->data, sizeof(field));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&op, child->data, sizeof(op));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&raw[0], child->data, sizeof(raw));

    if (bf_marsh_next_child(marsh, child))
        bf_warn("matcher marsh has more children than expected");

    r = bf_matcher_new(&_matcher, field, op, &raw);
    if (r < 0)
        return r;

    *matcher = TAKE_PTR(_matcher);

    return 0;
}

void bf_matcher_dump(const struct bf_matcher *matcher, prefix_t *prefix)
{
    prefix_t _prefix = {};
    prefix = prefix ?: &_prefix;

    DUMP(prefix, "struct bf_matcher at %p", matcher);

    bf_dump_prefix_push(prefix);

    DUMP(prefix, "field: %u", matcher->field);
    DUMP(prefix, "op: %u", matcher->op);
    bf_dump_hex(bf_dump_prefix_last(prefix), matcher->raw,
                sizeof(matcher->raw));

    bf_dump_prefix_pop(prefix);
}
