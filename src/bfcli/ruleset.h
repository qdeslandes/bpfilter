
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include "core/chain.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/set.h"

#define bfc_ruleset_default()                                                  \
    {                                                                          \
        .chains = bf_list_default(bf_chain_free, bf_chain_marsh),              \
        .sets = bf_list_default(bf_set_free, bf_set_marsh),                    \
        .hookopts = bf_list_default(bf_hookopts_free, bf_hookopts_marsh),      \
    }

#define _clean_bfc_ruleset_ __attribute__((__cleanup__(bfc_ruleset_clean)))

struct bfc_ruleset
{
    bf_list chains;
    bf_list sets;
    bf_list hookopts;
};

struct bfc_opts;

void bfc_ruleset_clean(struct bfc_ruleset *ruleset);

int bfc_ruleset_set(const struct bfc_opts *opts);
int bfc_ruleset_get(const struct bfc_opts *opts);
int bfc_ruleset_flush(const struct bfc_opts *opts);
