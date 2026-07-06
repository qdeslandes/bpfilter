/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>

#include <bpfilter/core/list.h>
#include <bpfilter/counter.h>
#include <bpfilter/dump.h>
#include <bpfilter/helper.h>
#include <bpfilter/hook.h>
#include <bpfilter/pack.h>
#include <bpfilter/verdict.h>

struct bf_hookopts;
struct bf_matcher;
struct bf_rule;
struct bf_set;

#define _free_bf_chain_ __attribute__((cleanup(bf_chain_free)))

/**
 * @brief Features used by the rules defined in the chain.
 *
 * Some features used by the rules have an impact at the chain or program level,
 * these flags are used to define which feature is used at the chain level,  and
 * generate the bytecode accordingly.
 *
 * For example, a pointer to the log ring buffer is store in the program's
 * runtime context. This pointer should not be populated if no rule is has a
 * 'log' instruction.
 *
 * Similarly, the L4 header slice and the normalized L4 protocol ID are only
 * computed in the program's prologue if a rule consumes them, and the
 * interface index is only derived and stored in the runtime context if a
 * rule filters on it.
 *
 * Grouping the list of required features at the chain level prevents us from
 * parsing all the rules and matchers everytime the feature would affect the
 * bytecode.
 *
 * The packet-header parsing pipeline as a whole (dynptr creation, header
 * slice requests, L3/L4 protocol derivation) is gated on
 * @ref bf_chain_needs_pkt_parse : new matchers reading r6, r7, r8, r9, or
 * the dynptr must set an appropriate flag.
 */
enum bf_chain_flags
{
    /** A rule will log data to the ring buffer. */
    BF_CHAIN_LOG,

    /** A rule uses rate-limited logging (log ... every). */
    BF_CHAIN_LOG_RATELIMIT,

    /** A rule will filter on IPv6 nexthdr field. */
    BF_CHAIN_STORE_NEXTHDR,

    /** A rule reads the L3 header (pinned in r6) or the L3 protocol ID
     * (r7). */
    BF_CHAIN_NEEDS_L3,

    /** A rule reads the L4 header slice: the slice is requested and its
     * address is pinned in r9. The `l4_hdr` and `l4_size` runtime context
     * fields are only populated under `BF_CHAIN_LOG` (and `BF_CHAIN_FLOW_HASH`
     * for `l4_hdr`). */
    BF_CHAIN_NEEDS_L4_HDR,

    /** A rule reads the normalized L4 protocol ID (r8). */
    BF_CHAIN_NEEDS_L4_PROTO,

    /** A rule computes the packet's flow hash: the flow-hash ELF stub reads
     * `l3_hdr` and `l4_hdr` from the runtime context. */
    BF_CHAIN_FLOW_HASH,

    /** A rule reads the interface index from the runtime context
     * (`meta.iface`). This flag uses the last free bit of `bf_chain.flags`:
     * adding another flag requires widening the field and its pack format. */
    BF_CHAIN_NEEDS_IFINDEX,

    _BF_CHAIN_FLAGS_MAX,
};

struct bf_chain
{
    const char *name;
    uint8_t flags;
    enum bf_hook hook;
    enum bf_verdict policy;
    bf_list sets;
    bf_list rules;

    /// Policy counters. Not serialized.
    struct bf_counter policy_counters;

    /// Error counters. Not serialized.
    struct bf_counter error_counters;
};

/**
 * @brief Check if the chain requires the packet-header parsing pipeline.
 *
 * The flavor prologues only emit the parsing pipeline (dynptr creation,
 * header slice requests, L3/L4 protocol derivation) if a rule consumes one
 * of its outputs: any of these flags implies the pipeline must run.
 *
 * @param chain Chain to check. Can't be NULL.
 * @return True if the chain consumes packet-header parsing state.
 */
static inline bool bf_chain_needs_pkt_parse(const struct bf_chain *chain)
{
    return chain->flags &
           (BF_FLAG(BF_CHAIN_LOG) | BF_FLAG(BF_CHAIN_STORE_NEXTHDR) |
            BF_FLAG(BF_CHAIN_NEEDS_L3) | BF_FLAG(BF_CHAIN_NEEDS_L4_HDR) |
            BF_FLAG(BF_CHAIN_NEEDS_L4_PROTO) | BF_FLAG(BF_CHAIN_FLOW_HASH));
}

/**
 * Allocate and initialize a `bf_chain` object.
 *
 * The content of `sets` and `rules` is stolen by the constructor if the
 * function succeeds, in which case the source lists are empty and the chain
 * is responsible for the data. Otherwise, both list are unchanged.
 *
 * @param chain `bf_chain` object to allocate and initialize. On failure,
 *        this parameter is unchanged. Can't be NULL.
 * @param name Name of the chain. Can't be NULL.
 * @param hook Expected hook to attach the chain to.
 * @param policy Default action of the chain if no rule matched.
 * @param sets List of sets used by `rules`.
 * @param rules List of rules.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_chain_new(struct bf_chain **chain, const char *name, enum bf_hook hook,
                 enum bf_verdict policy, bf_list *sets, bf_list *rules);

/**
 * @brief Allocate and initialize a new chain from serialized data.
 *
 * @param chain Chain object to allocate and initialize from the serialized
 *        data. The caller will own the object. On failure, `*chain` is
 *        unchanged. Can't be NULL.
 * @param node Node containing the serialized chain. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_chain_new_from_pack(struct bf_chain **chain, bf_rpack_node_t node);

/**
 * Deallocate a `bf_chain` object.
 *
 * @param chain `bf_chain` object to cleanup and deallocate. If `*chain`
 *        is NULL, this function has no effect. Can't be NULL.
 */
void bf_chain_free(struct bf_chain **chain);

/**
 * @brief Serialize a chain.
 *
 * @param chain Chain to serialize. Can't be NULL.
 * @param pack `bf_wpack_t` object to serialize the chain into. Can't be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_chain_pack(const struct bf_chain *chain, bf_wpack_t *pack);

/**
 * Dump the content of a `bf_chain` object.
 *
 * @param chain `bf_chain` object to print. Can't be NULL.
 * @param prefix Prefix to use for the dump. Can't be NULL.
 */
void bf_chain_dump(const struct bf_chain *chain, prefix_t *prefix);

/**
 * Insert a rule into the chain.
 *
 * The chain will own the rule and is responsible for freeing it. The rule's
 * index will automatically be updated.
 *
 * @todo Rules without any matcher should be rejected.
 *
 * @param chain Chain to insert the rule into. Can't be NULL.
 * @param rule Rule to insert into the chain. Can't be NULL.
 * @return 0 on success, or a negative errno value on error.
 */
int bf_chain_add_rule(struct bf_chain *chain, struct bf_rule *rule);

/**
 * @brief Insert a set into a chain.
 *
 * The chain will own the set and is responsible for freeing it. Once inserted,
 * its index in the chain can be used in a rule's matcher.
 *
 * @param chain Chain to insert the rule into. Can't be NULL.
 * @param set Set to insert into the chain. Can't be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_chain_add_set(struct bf_chain *chain, struct bf_set *set);

/**
 * @brief Get the set used by a matcher.
 *
 * @param chain Chain to get the set from. Can't be NULL.
 * @param matcher Matching filtering on a set. Can't be NULL.
 * @return The set `matcher` filters on, or NULL if the set can't be found or
 *         if `matcher->type` is not `BF_MATCHER_SET`.
 */
struct bf_set *bf_chain_get_set_for_matcher(const struct bf_chain *chain,
                                            const struct bf_matcher *matcher);

/**
 * @brief Get a set from the chain by name.
 *
 * Returns a pointer to the set with the given name. The returned pointer
 * is owned by the chain and should not be freed by the caller.
 *
 * @param chain Chain to get the set from. Can't be NULL.
 * @param set_name Name of the set to retrieve. Can't be NULL.
 * @return Pointer to the set, or NULL if not found.
 */
struct bf_set *bf_chain_get_set_by_name(struct bf_chain *chain,
                                        const char *set_name);

/** Allocate and initialize a chain as a copy of another chain.
 *
 * @param dest The destination chain. It will be allocated during the call.
 *        Can't be NULL.
 * @param src The source chain, to copy from. Can't be NULL.
 * @return 0 on success, negative error code on failure.
 */
int bf_chain_new_from_copy(struct bf_chain **dest, const struct bf_chain *src);
