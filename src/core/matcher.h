/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdint.h>

#include "core/dump.h"

struct bf_marsh;

enum bf_matcher_field
{
    BF_MATCHER_IP4_ADDR,
    _BF_MATCHER_MAX
};

enum bf_matcher_op
{
    BF_MATCHER_EQ,
    _BF_MATCHER_MAP
};

struct bf_matcher
{
    enum bf_matcher_field field;
    enum bf_matcher_op op;

    union
    {
        uint8_t u8;
        uint16_t u16;
        uint32_t u32;
        uint64_t u64;
        uint8_t raw[16];
    };
};

#define _cleanup_bf_matcher_ __attribute__((__cleanup__(bf_matcher_free)))

int bf_matcher_new(struct bf_matcher **matcher, enum bf_matcher_field field,
                   enum bf_matcher_op op, uint8_t (*data)[16]);
void bf_matcher_free(struct bf_matcher **matcher);
int bf_matcher_marsh(const struct bf_matcher *matcher, struct bf_marsh **marsh);
int bf_matcher_unmarsh(const struct bf_marsh *marsh,
                       struct bf_matcher **matcher);
void bf_matcher_dump(const struct bf_matcher *matcher, prefix_t *prefix);
