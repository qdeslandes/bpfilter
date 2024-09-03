// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/bpf.h>

#include <stdint.h>

#include "core/helper.h"
#include "core/dump.h"
#include "shared/front.h"
#include "core/hook.h"

struct bf_marsh;

#define _cleanup_bf_counter_ctx_ __attribute__((__cleanup__(bf_counter_ctx_free)))

/**
 * Counters context for a BPF program.
 *
 * The counter context is responsible for creating, using, and destroying
 * a counters map for a BPF program.
 *
 * One of the responsibilities of the counter context is to keep track of the
 * mapping between the rules and their counter in the BPF map as not all rule
 * need a counter to be defined.
 */
struct bf_counter_ctx
{
    /// File descriptor of the counters map.
    int map_fd;

    /// Program ID.
    uint32_t prog_id;

    /// Name of the counters map.
    char map_name[BPF_OBJ_NAME_LEN];

    /// Path the map should be pinned to.
    char map_pin_path[PIN_PATH_LEN];

    /// Number of rules. Defines the number of entries in the mapping array.
    size_t n_rules;

    /** Mapping between the rule index and the counter index in the map. Using
     * a 16-bits value allows for up to 65535 rules to be defined in a single
     * program. If 1000 rules are defined in a program, this context will use
     * 1000 * sizeof(uint16_t) bytes to store the mapping. It is far from ideal,
     * but let's wait for this to be a *real* issue before we make the
     * implementation more complex. */
    uint16_t mapping[0];
};

int bf_counter_ctx_new(struct bf_counter_ctx **ctx, uint32_t prog_id, size_t n_rules);
int bf_counter_ctx_new_from_marsh(struct bf_counter_ctx **ctx, const struct bf_marsh *marsh);
void bf_counter_ctx_free(struct bf_counter_ctx **ctx);
/**
 * only marsh the index reprensenting an actual rule
 * Build as:
 * - name suffix
 * - number of rules
 * - container
 *   - rule index
 *   - map index
 * - container [...]
 */
int bf_counter_ctx_marsh(const struct bf_counter_ctx *ctx, struct bf_marsh **marsh);
void bf_counter_ctx_dump(const struct bf_counter_ctx *ctx, prefix_t *prefix);
