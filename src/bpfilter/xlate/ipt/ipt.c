/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include <linux/in.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bpfilter/cgen/cgen.h"
#include "bpfilter/cgen/program.h"
#include "bpfilter/ctx.h"
#include "bpfilter/xlate/front.h"
#include "bpfilter/xlate/ipt/dump.h"
#include "bpfilter/xlate/ipt/helpers.h"
#include "core/chain.h"
#include "core/counter.h"
#include "core/front.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/if.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/matcher.h"
#include "core/request.h"
#include "core/response.h"
#include "core/rule.h"
#include "core/verdict.h"

/**
 * @file ipt.c
 *
 * @warning Only LOCAL_IN and LOCAL_OUT chains are currently supported, until
 * BPF_NETFILTER programs can be generated. To ensure only those rules are
 * processed, we store the index and length of the chains statically.
 */

struct bf_ipt_cache
{
    unsigned int valid_hooks;
    unsigned int hook_entry[NF_INET_NUMHOOKS];
    unsigned int underflow[NF_INET_NUMHOOKS];
    unsigned int num_entries;
    unsigned int size;
    struct ipt_entry *entries;
};

#define _cleanup_bf_ipt_cache_ __attribute__((cleanup(_bf_ipt_cache_free)))

/**
 * Get rule from an ipt_entry structure at a given offset.
 *
 * @param ipt_entry_ptr Pointer to a valid ipt_entry structure.
 * @param offset Offset of the rule to get. Must be a valid offset.
 * @return Pointer to the rule at @p offset.
 */
#define bf_ipt_entries_get_rule(ipt_entry_ptr, offset)                         \
    ((struct ipt_entry *)((void *)(ipt_entry_ptr)->entrytable + (offset)))

/**
 * Get size of an xt_counters_info structure.
 *
 * @param xt_counters_info_ptr Pointer to a valid xt_counters_info structure.
 * @return Size of the structure, including variable length counters field.
 */
#define bf_xt_counters_info_size(xt_counters_info_ptr)                         \
    (sizeof(struct xt_counters_info) +                                         \
     (xt_counters_info_ptr)->num_counters * sizeof(struct xt_counters))

/**
 * Get size of an ipt_replace structure.
 *
 * @param ipt_replace_ptr Pointer to a valid ipt_replace structure.
 * @return Size of the structure, including variable length entries field.
 */
#define bf_ipt_replace_size(ipt_replace_ptr)                                   \
    (sizeof(struct ipt_replace) + (ipt_replace_ptr)->size)

static struct bf_ipt_cache *_bf_cache = NULL;

static void _bf_ipt_cache_free(struct bf_ipt_cache **cache);

/// Default iptables filter table. Required to initialize iptables. NOLINTBEGIN
static unsigned char _bf_default_ipt_filter[] = {
    0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x78, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00, 0x30, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x98, 0x00, 0x00, 0x00, 0x30, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x10, 0x32, 0x40, 0x36, 0x43, 0x56, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x70, 0x00, 0x98, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xfe, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x70, 0x00, 0x98, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x00, 0x98, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x70, 0x00, 0xb0, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x45, 0x52, 0x52, 0x4f, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}; // NOLINTEND

static int _bf_ipt_setup(void);
static int _bf_ipt_teardown(void);
static int _bf_ipt_request_handler(struct bf_request *request,
                                   struct bf_response **response);
static int _bf_ipt_marsh(struct bf_marsh **marsh);
static int _bf_ipt_unmarsh(struct bf_marsh *marsh);

const struct bf_front_ops ipt_front = {
    .setup = _bf_ipt_setup,
    .teardown = _bf_ipt_teardown,
    .request_handler = _bf_ipt_request_handler,
    .marsh = _bf_ipt_marsh,
    .unmarsh = _bf_ipt_unmarsh,
};

/**
 * Convert an iptables hook to a bpfilter hook.
 *
 * @param ipt_hook iptables hook. Must be valid.
 * @return bpfilter hook.
 */
static enum bf_hook _bf_ipt_hook_to_bf_hook(enum nf_inet_hooks ipt_hook)
{
    bf_assert(0 <= ipt_hook && ipt_hook <= NF_INET_NUMHOOKS);

    switch (ipt_hook) {
    case NF_INET_PRE_ROUTING:
        return BF_HOOK_NF_PRE_ROUTING;
    case NF_INET_LOCAL_IN:
        return BF_HOOK_NF_LOCAL_IN;
    case NF_INET_FORWARD:
        return BF_HOOK_NF_FORWARD;
    case NF_INET_LOCAL_OUT:
        return BF_HOOK_NF_LOCAL_OUT;
    case NF_INET_POST_ROUTING:
        return BF_HOOK_NF_POST_ROUTING;
    default:
        bf_abort("invalid ipt_hook: %d", ipt_hook);
    }
}

static int _bf_ipt_cache_new(struct bf_ipt_cache **cache)
{
    _cleanup_bf_ipt_cache_ struct bf_ipt_cache *_cache = NULL;

    bf_assert(cache);

    _cache = calloc(1, sizeof(*_cache));
    if (!_cache)
        return -ENOMEM;

    *cache = TAKE_PTR(_cache);

    return 0;
}

static void _bf_ipt_cache_free(struct bf_ipt_cache **cache)
{
    if (!*cache)
        return;

    free((*cache)->entries);
    free(*cache);

    *cache = NULL;
}

/**
 * Convert an iptables target to a bpfilter verdict.
 *
 * @param ipt_target iptables target to convert.
 * @param verdict Verdict to store the conversion in.
 * @return 0 on success, negative error code on failure.
 */
static int _bf_ipt_target_to_verdict(struct ipt_entry_target *ipt_target,
                                     enum bf_verdict *verdict)
{
    if (bf_streq("", ipt_target->u.user.name)) {
        struct ipt_standard_target *ipt_std_target =
            (struct xt_standard_target *)ipt_target;

        if (ipt_std_target->verdict >= 0) {
            return bf_err_r(
                -ENOTSUP,
                "target expects jump to a user-defined chain, this is not supported");
        }

        switch (-ipt_std_target->verdict - 1) {
        case NF_ACCEPT:
            *verdict = BF_VERDICT_ACCEPT;
            break;
        case NF_DROP:
            *verdict = BF_VERDICT_DROP;
            break;
        default:
            return bf_err_r(-ENOTSUP, "unsupported verdict: %d",
                            ipt_std_target->verdict);
        }
    } else {
        return bf_err_r(-ENOTSUP, "unsupported target: %s",
                        ipt_target->u.user.name);
    }

    return 0;
}

/**
 * Translate an iptables rule into a bpfilter rule.
 *
 * @todo Bound check the target.
 *
 * @param ipt_rule iptables rule to translate.
 * @param rule Rule to store the translation in.
 * @return 0 on success, negative error code on failure.
 */
static int _bf_ipt_to_rule(const struct ipt_entry *ipt_rule,
                           struct bf_rule **rule)
{
    _cleanup_bf_rule_ struct bf_rule *_rule = NULL;
    size_t offset = sizeof(*ipt_rule);
    int r;

    r = bf_rule_new(&_rule);
    if (r < 0)
        return r;

    if (strlen(ipt_rule->ip.iniface)) {
        r = bf_if_index_from_name(ipt_rule->ip.iniface);
        if (r < 0) {
            return bf_err_r(errno, "can't find index for interface %s",
                            ipt_rule->ip.iniface);
        }

        r = bf_rule_add_matcher(_rule, BF_MATCHER_META_IFINDEX, BF_MATCHER_EQ,
                                &r, sizeof(r));
        if (r < 0)
            return r;
    }

    _rule->counters = true;

    if (ipt_rule->ip.src.s_addr || ipt_rule->ip.smsk.s_addr) {
        struct bf_matcher_ip4_addr addr = {
            .addr = ipt_rule->ip.src.s_addr,
            .mask = ipt_rule->ip.smsk.s_addr,
        };

        r = bf_rule_add_matcher(_rule, BF_MATCHER_IP4_SRC_ADDR,
                                ipt_rule->ip.invflags & IPT_INV_SRCIP ?
                                    BF_MATCHER_EQ :
                                    BF_MATCHER_NE,
                                &addr, sizeof(addr));
        if (r)
            return r;
    }

    if (ipt_rule->ip.dst.s_addr || ipt_rule->ip.dmsk.s_addr) {
        struct bf_matcher_ip4_addr addr = {
            .addr = ipt_rule->ip.dst.s_addr,
            .mask = ipt_rule->ip.dmsk.s_addr,
        };

        r = bf_rule_add_matcher(_rule, BF_MATCHER_IP4_DST_ADDR,
                                ipt_rule->ip.invflags & IPT_INV_DSTIP ?
                                    BF_MATCHER_EQ :
                                    BF_MATCHER_NE,
                                &addr, sizeof(addr));
        if (r)
            return r;
    }

    if (ipt_rule->ip.proto) {
        uint8_t ip_proto = (uint8_t)ipt_rule->ip.proto;

        if (ip_proto != ipt_rule->ip.proto) {
            return bf_err_r(-EINVAL, "invalid ip.proto %d", ipt_rule->ip.proto);
        }
        r = bf_rule_add_matcher(_rule, BF_MATCHER_IP4_PROTO, BF_MATCHER_EQ,
                                &ip_proto, sizeof(uint8_t));
        if (r < 0)
            return r;
    }

    if (offset < ipt_rule->target_offset) {
        return bf_err_r(-EINVAL,
                        "iptables custom matchers are not (yet) supported!");
    }

    r = _bf_ipt_target_to_verdict(ipt_get_target(ipt_rule), &_rule->verdict);
    if (r < 0)
        return r;

    *rule = TAKE_PTR(_rule);

    return 0;
}

static bool _bf_ipt_entry_is_empty(const struct ipt_entry *entry)
{
    return entry->ip.dmsk.s_addr == 0 && entry->ip.dst.s_addr == 0 &&
           entry->ip.flags == 0 && entry->ip.iniface[0] == 0 &&
           entry->ip.iniface_mask[0] == 0 && entry->ip.invflags == 0 &&
           entry->ip.outiface[0] == 0 && entry->ip.outiface_mask[0] == 0 &&
           entry->ip.proto == 0 && entry->ip.smsk.s_addr == 0 &&
           entry->ip.src.s_addr == 0;
}

/**
 * Translate iptables rules into bpfilter format.
 *
 * @param ipt iptables rules.
 * @param cgens Array of codegens, indexed by hook. At most one codegen per
 *        hook will be generated.
 * @return 0 on success, negative error code on failure.
 */
static int _bf_ipt_xlate_set_rules(struct ipt_replace *ipt,
                                   struct bf_cgen *(*cgens)[_BF_HOOK_MAX])
{
    struct ipt_entry *first_rule;
    struct ipt_entry *last_rule;
    int r;

    bf_assert(ipt);
    bf_assert(cgens);

    for (int i = 0; i < NF_INET_NUMHOOKS; ++i) {
        _cleanup_bf_cgen_ struct bf_cgen *cgen = NULL;
        _cleanup_bf_chain_ struct bf_chain *chain = NULL;
        enum bf_hook hook = _bf_ipt_hook_to_bf_hook(i);
        enum bf_verdict policy;

        if (!ipt_is_hook_enabled(ipt, i)) {
            bf_dbg("ipt hook %d is not enabled, skipping", i);
            continue;
        }

        first_rule = ipt_get_first_rule(ipt, i);
        last_rule = ipt_get_last_rule(ipt, i);

        if (!_bf_ipt_entry_is_empty(last_rule))
            return bf_err_r(-EINVAL, "last IPT rule isn't a valid policy");

        /* We assume the last rule is a policy (ipt_entry.ip field is filled
         * with 0), and use it as the verdict if true. */
        r = _bf_ipt_target_to_verdict(ipt_get_target(last_rule), &policy);
        if (r < 0)
            return bf_err_r(r, "invalid IPT policy verdict");

        r = bf_chain_new(&chain, hook, policy, NULL, NULL);
        if (r < 0)
            return bf_err_r(r, "failed to create a new chain for IPT front");

        /* Loop from the first rule, to the last rule (excluded). As we assume
         * the last rule is the policy, we don't need to generate a bf_rule
         * structure for it. */
        for (size_t rule_idx = 0; first_rule < last_rule;
             ++rule_idx, first_rule = ipt_get_next_rule(first_rule)) {
            _cleanup_bf_rule_ struct bf_rule *rule = NULL;
            r = _bf_ipt_to_rule(first_rule, &rule);
            if (r < 0)
                return r;

            rule->index = rule_idx++;
            r = bf_chain_add_rule(chain, rule);
            if (r < 0)
                return r;

            /* Rule has been added to the chain, so if anything goes wrong from
             * here, it wil be freed by the chain directly. */
            TAKE_PTR(rule);
        }

        r = bf_cgen_new(&cgen, BF_FRONT_IPT, &chain);
        if (r < 0)
            return r;

        (*cgens)[hook] = TAKE_PTR(cgen);
    }

    return 0;
}

/**
 * Modify existing iptables rules.
 *
 * @todo If processing for any codegen fails, all codegens should be unloaded
 * and/or discarded.
 *
 * @param replace New rules, in iptables format.
 * @param len Length of the new rules.
 * @return 0 on success, negative error code on failure.
 */
static int _bf_ipt_set_rules_handler(struct ipt_replace *replace, size_t len)
{
    _cleanup_free_ struct ipt_entry *entries = NULL;
    struct bf_cgen *cgens[_BF_HOOK_MAX] = {};
    int r;

    bf_assert(replace);
    bf_assert(bf_ipt_replace_size(replace) == len);

    bf_ipt_dump_replace(replace, NULL);

    r = _bf_ipt_xlate_set_rules(replace, &cgens);
    if (r < 0)
        return bf_err_r(r, "failed to translate iptables rules");

    /* Copy entries now, so we don't have to unload the codegens if the copy
     * fails. */
    entries = bf_memdup(replace->entries, replace->size);
    if (!entries) {
        r = bf_err_r(-ENOMEM, "failed to duplicate iptables rules");
        goto end_free_cgens;
    }

    for (int i = 0; i < _BF_HOOK_MAX; i++) {
        _cleanup_bf_cgen_ struct bf_cgen *new_cgen = TAKE_PTR(cgens[i]);
        struct bf_cgen *cur_cgen;

        if (!new_cgen)
            continue;

        cur_cgen =
            bf_ctx_get_cgen(new_cgen->chain->hook, &new_cgen->chain->hook_opts);
        if (cur_cgen) {
            r = bf_cgen_update(cur_cgen, &new_cgen->chain);
            if (r) {
                bf_err_r(r, "failed to update existing codegen for hook %s",
                         bf_hook_to_str(cur_cgen->chain->hook));
                goto end_free_cgens;
            }
        } else {
            r = bf_cgen_up(new_cgen);
            if (r) {
                bf_err_r(r, "failed to generate bytecode for hook %s",
                         bf_hook_to_str(new_cgen->chain->hook));
                goto end_free_cgens;
            }

            /** @todo This shouldn't be faillable: the complex part is to
             * load and attach the codegen, we shouldn't be able to fail
             * solely because we can't store the codegen! */
            r = bf_ctx_set_cgen(new_cgen);
            if (r < 0) {
                bf_cgen_unload(new_cgen);
                return r;
            }

            TAKE_PTR(cur_cgen);
        }
    }

    _bf_cache->valid_hooks = replace->valid_hooks;
    memcpy(_bf_cache->hook_entry, replace->hook_entry,
           sizeof(_bf_cache->hook_entry));
    memcpy(_bf_cache->underflow, replace->underflow,
           sizeof(_bf_cache->underflow));
    _bf_cache->size = replace->size;
    _bf_cache->num_entries = replace->num_entries;

    free(_bf_cache->entries);
    _bf_cache->entries = TAKE_PTR(entries);

end_free_cgens:
    for (int i = 0; i < _BF_HOOK_MAX; i++)
        bf_cgen_free(&cgens[i]);

    return r;
}

/**
 * Set counters for a rule.
 *
 * @todo Actually update the counters.
 *
 * @param counters iptables structure containing the counters and their value.
 * @param len Length of the counters structure.
 * @return 0 on success, negative error code on failure.
 */
static int _bf_ipt_set_counters_handler(struct xt_counters_info *counters,
                                        size_t len)
{
    bf_assert(counters);
    bf_assert(bf_xt_counters_info_size(counters) == len);

    return 0;
}

int _bf_ipt_get_info_handler(struct bf_request *request,
                             struct bf_response **response)
{
    struct ipt_getinfo *info = (struct ipt_getinfo *)request->data;

    bf_assert(request);
    bf_assert(sizeof(*info) == request->data_len);

    if (!bf_streq(info->name, "filter")) {
        return bf_err_r(-EINVAL, "can't process IPT_SO_GET_INFO for table %s",
                        info->name);
    }

    info->valid_hooks = _bf_cache->valid_hooks;
    memcpy(info->hook_entry, _bf_cache->hook_entry,
           sizeof(_bf_cache->hook_entry));
    memcpy(info->underflow, _bf_cache->underflow, sizeof(_bf_cache->underflow));
    info->num_entries = _bf_cache->num_entries;
    info->size = _bf_cache->size;

    return bf_response_new_success(response, (const char *)info,
                                   sizeof(struct ipt_getinfo));
}

/**
 * Get the entries of a table, including counters.
 *
 * @param request
 * @param response
 * @return 0 on success, negative errno value on failure.
 */
int _bf_ipt_get_entries_handler(struct bf_request *request,
                                struct bf_response **response)
{
    struct ipt_get_entries *entries;
    int r;

    bf_assert(request);
    bf_assert(response);

    entries = (struct ipt_get_entries *)request->data;

    if (!bf_streq(entries->name, "filter")) {
        return bf_err_r(-EINVAL, "can't process IPT_SO_GET_INFO for table %s",
                        entries->name);
    }

    if (entries->size != _bf_cache->size) {
        return bf_err_r(
            -EINVAL,
            "not enough space to store entries: %u available, %u required",
            entries->size, _bf_cache->size);
    }

    memcpy(entries->entrytable, _bf_cache->entries, _bf_cache->size);

    for (int i = 0; i < NF_INET_NUMHOOKS; ++i) {
        struct ipt_entry *first_rule;
        struct ipt_entry *last_rule;
        struct bf_cgen *cgen;
        enum bf_counter_type counter_idx;

        if (!(_bf_cache->valid_hooks & (1 << i))) {
            bf_dbg("ipt hook %d is not enabled, skipping", i);
            continue;
        }

        first_rule = bf_ipt_entries_get_rule(entries, _bf_cache->hook_entry[i]);
        last_rule = bf_ipt_entries_get_rule(entries, _bf_cache->underflow[i]);
        cgen = bf_ctx_get_cgen(_bf_ipt_hook_to_bf_hook(i), BF_FRONT_IPT);
        enum bf_counter_type rule_count = bf_list_size(&cgen->chain->rules);

        for (counter_idx = 0; first_rule <= last_rule;
             ++counter_idx, first_rule = ipt_get_next_rule(first_rule)) {
            struct bf_counter counter = {};

            /* Note that the policy is considered a rule, but we must access
             * via the unambiguous counter enum rather than overflowing. */
            bool is_policy = counter_idx == rule_count;
            r = bf_cgen_get_counter(
                cgen, is_policy ? BF_COUNTER_POLICY : counter_idx, &counter);
            if (r) {
                return bf_err_r(r, "failed to get IPT counter for index %u",
                                counter_idx);
            }

            first_rule->counters.bcnt = counter.bytes;
            first_rule->counters.pcnt = counter.packets;
        }

        if (counter_idx != rule_count + 1) {
            /* We expect len(cgen->rules) + 1 as the policy is considered
             * a rule for iptables, but not for bpfilter. */
            return bf_err_r(-EINVAL, "invalid number of rules requested");
        }
    }

    return bf_response_new_success(response, (const char *)entries,
                                   sizeof(*entries) + entries->size);
}

static int _bf_ipt_setup(void)
{
    int r;

    if (_bf_cache) {
        bf_info("cache already initialised, skipping initialisation");
        return 0;
    }

    r = _bf_ipt_cache_new(&_bf_cache);
    if (r < 0)
        return r;

    return _bf_ipt_set_rules_handler(
        (struct ipt_replace *)_bf_default_ipt_filter,
        sizeof(_bf_default_ipt_filter));
}

static int _bf_ipt_teardown(void)
{
    _cleanup_bf_ipt_cache_ struct bf_ipt_cache *cache = _bf_cache;

    return 0;
}

/**
 * @todo Wouldn't it be better to have a separate handler for each request type?
 *  In which case struct bf_front_ops would contain a handler for each request
 *  type, and the front would handle custom (BF_REQ_CUSTOM) requests itself.
 * @todo Document that request and responses are not const: they will be free
 *  by the daemon once the front is done with them. Hence, the front is free
 *  to modify the requests content.
 * @todo Check bf_assertions: a malformed request could cause the daemon to
 * crash.
 *
 * @param request
 * @param response
 * @return
 */
static int _bf_ipt_request_handler(struct bf_request *request,
                                   struct bf_response **response)
{
    int r;

    switch (request->cmd) {
    case BF_REQ_RULES_SET:
        r = _bf_ipt_set_rules_handler((struct ipt_replace *)request->data,
                                      request->data_len);
        if (r < 0)
            return r;

        return bf_response_new_success(response, request->data,
                                       request->data_len);
    case BF_REQ_COUNTERS_SET:
        r = _bf_ipt_set_counters_handler(
            (struct xt_counters_info *)request->data, request->data_len);
        if (r < 0)
            return r;

        return bf_response_new_success(response, request->data,
                                       request->data_len);
    case BF_REQ_CUSTOM:
        switch (request->ipt_cmd) {
        case IPT_SO_GET_INFO:
            return _bf_ipt_get_info_handler(request, response);
        case IPT_SO_GET_ENTRIES:
            return _bf_ipt_get_entries_handler(request, response);
        default:
            return bf_warn_r(-ENOTSUP,
                             "unsupported custom ipt request type: %d",
                             request->ipt_cmd);
        };
    default:
        return bf_warn_r(-ENOTSUP, "unsupported ipt request type: %d",
                         request->cmd);
    };

    return 0;
}

static int _bf_ipt_marsh(struct bf_marsh **marsh)
{
    int r = 0;

    bf_assert(marsh);

    if (!_bf_cache)
        return 0;

    r |= bf_marsh_add_child_raw(marsh, &_bf_cache->valid_hooks,
                                sizeof(_bf_cache->valid_hooks));
    r |= bf_marsh_add_child_raw(marsh, &_bf_cache->hook_entry,
                                sizeof(_bf_cache->hook_entry));
    r |= bf_marsh_add_child_raw(marsh, &_bf_cache->underflow,
                                sizeof(_bf_cache->underflow));
    r |= bf_marsh_add_child_raw(marsh, &_bf_cache->num_entries,
                                sizeof(_bf_cache->num_entries));
    r |= bf_marsh_add_child_raw(marsh, &_bf_cache->size,
                                sizeof(_bf_cache->size));
    r |= bf_marsh_add_child_raw(marsh, _bf_cache->entries, _bf_cache->size);
    if (r)
        return r;

    bf_dbg("Saved bf_ipt_cache at %p:", _bf_cache);
    bf_dbg("  valid_hooks: %u", _bf_cache->valid_hooks);
    bf_dbg("  num_entries: %u", _bf_cache->num_entries);
    bf_dbg("  size: %u", _bf_cache->size);

    return 0;
}

static int _bf_ipt_unmarsh(struct bf_marsh *marsh)
{
    _cleanup_bf_ipt_cache_ struct bf_ipt_cache *cache = NULL;
    struct bf_marsh *child = NULL;
    int r;

    bf_assert(marsh);

    if (marsh->data_len == 0)
        return 0;

    r = _bf_ipt_cache_new(&cache);
    if (r < 0)
        return -ENOMEM;

    if (!(child = bf_marsh_next_child(marsh, NULL)))
        return -EINVAL;
    memcpy(&cache->valid_hooks, child->data, sizeof(cache->valid_hooks));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&cache->hook_entry, child->data, sizeof(cache->hook_entry));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&cache->underflow, child->data, sizeof(cache->underflow));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&cache->num_entries, child->data, sizeof(cache->num_entries));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&cache->size, child->data, sizeof(cache->size));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    cache->entries = bf_memdup(child->data, child->data_len);
    if (!cache->entries)
        return -ENOMEM;

    if (bf_marsh_next_child(marsh, child))
        bf_warn("codegen marsh has more children than expected");

    _bf_cache = TAKE_PTR(cache);

    bf_dbg("Restored bf_ipt_cache at %p:", _bf_cache);
    bf_dbg("  valid_hooks: %u", _bf_cache->valid_hooks);
    bf_dbg("  num_entries: %u", _bf_cache->num_entries);
    bf_dbg("  size: %u", _bf_cache->size);

    return 0;
}
