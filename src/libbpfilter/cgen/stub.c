/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/stub.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/in.h> // NOLINT
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <endian.h>
#include <stdbool.h>
#include <stddef.h>

#include <bpfilter/chain.h>
#include <bpfilter/ctx.h>
#include <bpfilter/elfstub.h>
#include <bpfilter/flavor.h>
#include <bpfilter/helper.h>
#include <bpfilter/matcher.h>
#include <bpfilter/rule.h>
#include <bpfilter/set.h>
#include <bpfilter/verdict.h>

#include "cgen/jmp.h"
#include "cgen/printer.h"
#include "cgen/program.h"
#include "cgen/swich.h"
#include "filter.h"

#define _BF_LOW_EH_BITMASK 0x1801800000000801ULL

/**
 * @brief Tracks which L3/L4 parsing branches are actually needed by a chain.
 *
 * Computed by walking every non-disabled rule's matchers (and, for set
 * matchers, each set key component). Used to elide unused branches of the
 * unconditional L3/L4 header pre-parser emitted by
 * `bf_stub_parse_l3_hdr()` and `bf_stub_parse_l4_hdr()`.
 *
 * Removing unused branches is safe because every rule emits a per-layer
 * protocol guard (`bf_stub_rule_check_protocol`) that bails to the next
 * rule when `r7`/`r8` doesn't match: packets of an unfiltered family
 * simply hit those guards and skip every rule, without needing their
 * L3/L4 header pre-parsed.
 */
struct bf_proto_used
{
    bool ip4; /**< Any matcher requires the IPv4 parsing branch. */
    bool ip6; /**< Any matcher requires the IPv6 parsing branch. */
    bool tcp; /**< Any matcher needs the TCP header sliced. */
    bool udp; /**< Any matcher needs the UDP header sliced. */
    bool icmp; /**< Any matcher needs the ICMP header sliced. */
    bool icmpv6; /**< Any matcher needs the ICMPv6 header sliced. */
    bool any_l4; /**< Any matcher needs r8 (the L4 proto id) set. */
};

/**
 * @brief Fold a single matcher type into the protocol-usage bitmask.
 *
 * Looks up the matcher's `bf_matcher_meta` to discover which layer and
 * protocol header are required, then sets the matching bits in `out`.
 *
 * Layer-3 matchers set `ip4`/`ip6` based on `meta->hdr_id`. Layer-4
 * matchers set the matching L4 bool and `any_l4`. Meta matchers without
 * a layer that nonetheless require a sliced L4 header (port-based meta
 * matchers, flow hash, flow probability) force both `tcp` and `udp` on:
 * the packet's actual L4 protocol is only known at runtime, and the L4
 * stub's swich must cover both TCP and UDP so the header is sliced
 * regardless of which one the packet uses. `meta.l4_proto` only needs
 * `r8` set, not the header sliced.
 */
static void _bf_stub_account_matcher_type(enum bf_matcher_type type,
                                          struct bf_proto_used *out)
{
    const struct bf_matcher_meta *meta;

    assert(out);

    /* Meta matchers that don't carry a layer in their meta but still
     * need the L4 stub to slice the L4 header. The packet's actual L4
     * proto isn't known at codegen time, so both TCP and UDP cases must
     * remain in the swich for the slice to happen. */
    switch (type) {
    case BF_MATCHER_META_SPORT:
    case BF_MATCHER_META_DPORT:
    case BF_MATCHER_META_FLOW_HASH:
    case BF_MATCHER_META_FLOW_PROBABILITY:
        out->tcp = true;
        out->udp = true;
        out->any_l4 = true;
        break;
    case BF_MATCHER_META_L4_PROTO:
        /* Only needs r8 (the L4 proto id), set by the L3 stub. The L4
         * header doesn't have to be sliced. */
        out->any_l4 = true;
        break;
    default:
        break;
    }

    meta = bf_matcher_get_meta(type);
    if (!meta)
        return;

    if (meta->layer == BF_MATCHER_LAYER_3) {
        if (meta->hdr_id == ETH_P_IP)
            out->ip4 = true;
        else if (meta->hdr_id == ETH_P_IPV6)
            out->ip6 = true;
    } else if (meta->layer == BF_MATCHER_LAYER_4) {
        out->any_l4 = true;
        switch (meta->hdr_id) {
        case IPPROTO_TCP:
            out->tcp = true;
            break;
        case IPPROTO_UDP:
            out->udp = true;
            break;
        case IPPROTO_ICMP:
            out->icmp = true;
            break;
        case IPPROTO_ICMPV6:
            out->icmpv6 = true;
            break;
        default:
            break;
        }
    }
}

/**
 * @brief Walk the chain and compute which L3/L4 parsing branches are
 *        actually referenced by at least one (non-disabled) rule.
 *
 * Iterates every non-disabled rule's matchers. For `BF_MATCHER_SET`
 * matchers, each `set->key[i]` component is folded into the bitmask
 * because the set lookup will read those header fields.
 *
 * Post-processing rules:
 * - If `any_l4` is set, force `ip4 = ip6 = true`: `r8` is populated
 *   only inside the IPv4/IPv6 parsing blocks (`LDX r8, [r0+iphdr.protocol]`
 *   and the IPv6 nexthdr path), so any L4 matcher requires both blocks
 *   to remain reachable.
 * - If `chain->flags & BF_FLAG(BF_CHAIN_STORE_NEXTHDR)`, force `ip6 = true`
 *   (the EH-store path lives in the IPv6 block).
 */
static void _bf_stub_collect_proto_used(const struct bf_chain *chain,
                                        struct bf_proto_used *out)
{
    assert(chain);
    assert(out);

    *out = (struct bf_proto_used) {0};

    bf_list_foreach (&chain->rules, rule_node) {
        const struct bf_rule *rule = bf_list_node_get_data(rule_node);

        if (rule->disabled)
            continue;

        bf_list_foreach (&rule->matchers, matcher_node) {
            const struct bf_matcher *matcher =
                bf_list_node_get_data(matcher_node);
            enum bf_matcher_type type = bf_matcher_get_type(matcher);

            if (type == BF_MATCHER_SET) {
                const struct bf_set *set =
                    bf_chain_get_set_for_matcher(chain, matcher);

                if (!set)
                    continue;

                for (size_t i = 0; i < set->n_comps; ++i)
                    _bf_stub_account_matcher_type(set->key[i], out);
            } else {
                _bf_stub_account_matcher_type(type, out);
            }
        }
    }

    /* `r8` is populated inside the IPv4/IPv6 parsing blocks only, so any
     * L4 matcher implicitly requires both L3 branches to remain present. */
    if (out->any_l4)
        out->ip4 = out->ip6 = true;

    /* The EH-store path lives in the IPv6 parsing block. */
    if (chain->flags & BF_FLAG(BF_CHAIN_STORE_NEXTHDR))
        out->ip6 = true;
}

/**
 * @brief Whether the IPv4 block of `bf_stub_parse_l3_hdr()` must still
 *        compute `l4_offset` (from `iphdr.ihl`) and load `r8 = iphdr.protocol`.
 *
 * The IPv4 block's only externally observable effects are setting `r8`
 * (the L4 proto id) and writing `bf_runtime.l4_offset`. Both are consumed
 * exclusively by L4-aware matchers and by `bf_stub_parse_l4_hdr()`, all
 * of which set `any_l4 = true` in `_bf_stub_account_matcher_type()`.
 *
 * When no L4 matcher exists, the entire IPv4 block — including its
 * `JNE r7, ETH_P_IP` guard — is pure dead code on the hot path and can
 * be elided. L3 IPv4 matchers (`ip.saddr`, `ip.daddr`, sets keyed on IP)
 * read the sliced header from `bf_runtime.l3_hdr`, which is populated
 * earlier in this function, so they are unaffected.
 */
static inline bool _bf_stub_need_ip4_l4_prep(const struct bf_proto_used *used)
{
    return used->any_l4;
}

/**
 * @brief Whether the IPv6 block of `bf_stub_parse_l3_hdr()` must still
 *        load `r8 = ipv6hdr.nexthdr`, run the EH-detection cascade, and
 *        write `bf_runtime.l4_offset`.
 *
 * Like the IPv4 case, the IPv6 block's only externally observable
 * effects are setting `r8` and writing `l4_offset`. Additionally, when
 * `BF_CHAIN_STORE_NEXTHDR` is set, the EH parser stores nexthdr meta
 * via `BF_ELFSTUB_PARSE_IPV6_NH` for later `ipv6.nexthdr` matchers; in
 * practice `STORE_NEXTHDR` already implies `any_l4 = true` (since
 * `ipv6.nexthdr` is an L4-layer matcher) but we OR both conditions to
 * be conservative.
 */
static inline bool _bf_stub_need_ip6_l4_prep(const struct bf_proto_used *used,
                                             const struct bf_chain *chain)
{
    return used->any_l4 || (chain->flags & BF_FLAG(BF_CHAIN_STORE_NEXTHDR));
}

/**
 * @brief Whether `bf_runtime.l3_offset` must actually be stored on the BPF
 *        stack for the generated program.
 *
 * After the LDX→MOV-imm swap in `bf_stub_parse_l3_hdr()`, that function no
 * longer reads `ctx->l3_offset`. The only remaining reader is the IPv6
 * EH/NH elfstub (`bf_parse_ipv6`), which is fixed up into the program
 * only when the IPv6 block of the L3 stub is emitted, i.e. when
 * `used.ip6 && _bf_stub_need_ip6_l4_prep(...)`.
 *
 * When that condition does not hold, every `BPF_ST_MEM(... l3_offset ...)`
 * store emitted by the L2 stub / flavor prologues is a dead write on the
 * per-packet hot path and can be elided.
 */
bool bf_stub_l3_offset_needed_in_ctx(const struct bf_chain *chain)
{
    struct bf_proto_used used;

    assert(chain);

    _bf_stub_collect_proto_used(chain, &used);
    return used.ip6 && _bf_stub_need_ip6_l4_prep(&used, chain);
}

/**
 * @brief Whether `bf_runtime.ifindex` must actually be stored on the BPF
 *        stack for the generated program.
 *
 * The only reader of `bf_runtime.ifindex` anywhere in the codegen is
 * `_bf_matcher_generate_meta_iface()` in `cgen/matcher/meta.c`, which
 * emits an `LDX [r10 + ctx.ifindex]` for every `BF_MATCHER_META_IFACE`
 * matcher. No ELF stub, logger, or packet-builder reads the field. When
 * no rule in the chain references `meta.iface` — directly, or as a
 * `BF_MATCHER_SET` key component — the ifindex setup block emitted by
 * each flavor prologue is dead code on the per-packet hot path and can
 * be elided.
 *
 * Disabled rules are skipped, matching the convention in
 * `_bf_stub_collect_proto_used()`.
 */
bool bf_stub_ifindex_needed_in_ctx(const struct bf_chain *chain)
{
    assert(chain);

    bf_list_foreach (&chain->rules, rule_node) {
        const struct bf_rule *rule = bf_list_node_get_data(rule_node);

        if (rule->disabled)
            continue;

        bf_list_foreach (&rule->matchers, matcher_node) {
            const struct bf_matcher *matcher =
                bf_list_node_get_data(matcher_node);
            enum bf_matcher_type type = bf_matcher_get_type(matcher);

            if (type == BF_MATCHER_META_IFACE)
                return true;

            if (type == BF_MATCHER_SET) {
                const struct bf_set *set =
                    bf_chain_get_set_for_matcher(chain, matcher);

                if (!set)
                    continue;

                for (size_t i = 0; i < set->n_comps; ++i) {
                    if (set->key[i] == BF_MATCHER_META_IFACE)
                        return true;
                }
            }
        }
    }

    return false;
}

/**
 * Return the codegen-time-constant value of `bf_runtime.l3_offset` for the
 * given program flavor.
 *
 * `l3_offset` is set exactly once by the flavor's prologue:
 * - TC and XDP call `bf_stub_parse_l2_ethhdr()`, which stores
 *   `sizeof(struct ethhdr)` (14).
 * - NF and CGROUP_SKB store `0` directly (no Ethernet header is available;
 *   the packet starts at L3).
 *
 * Returning this constant lets `bf_stub_parse_l3_hdr()` fold the
 * `l3_offset` load + add into immediate forms when computing `l4_offset`,
 * saving instructions on the hot path.
 */
static int _bf_stub_l3_offset_const(enum bf_flavor flavor)
{
    switch (flavor) {
    case BF_FLAVOR_TC:
    case BF_FLAVOR_XDP:
        return (int)sizeof(struct ethhdr);
    default:
        /* BF_FLAVOR_NF and BF_FLAVOR_CGROUP_SKB explicitly store 0. */
        return 0;
    }
}

/**
 * Return whether the chain emits any per-packet logging.
 *
 * The `bf_runtime` fields `l2_size`, `l3_size` and `l4_size` are only
 * read by the `bf_pkt_log` elfstub (`BF_ELFSTUB_PKT_LOG`), which is
 * itself only invoked from `bf_packet_gen_inline_log()` when at least
 * one non-disabled rule has `rule->log` set — the exact condition that
 * sets `BF_CHAIN_LOG` in `_bf_chain_check_rule()`. When the chain has
 * no logging, the size stores in the L2/L3/L4 pre-parser stubs are
 * dead and can be elided from every packet's hot path.
 */
static inline bool _bf_stub_needs_pkt_log(const struct bf_program *program)
{
    return program->runtime.chain->flags & BF_FLAG(BF_CHAIN_LOG);
}

/**
 * Generate stub to create a dynptr.
 *
 * @param program Program to generate the stub for. Must not be NULL.
 * @param arg_reg Register where the first argument to the dynptr creation
 *        function is located (SKB or xdp_md structure).
 * @param kfunc Name of the kfunc to use to create the dynamic pointer.
 * @return 0 on success, or negative errno value on error.
 */
static int _bf_stub_make_ctx_dynptr(struct bf_program *program, int arg_reg,
                                    const char *kfunc)
{
    int ret_code;
    int r;

    assert(program);
    assert(kfunc);

    // Call bpf_dynptr_from_xxx()
    if (arg_reg != BPF_REG_1)
        EMIT(program, BPF_MOV64_IMM(BPF_REG_1, arg_reg));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_2, 0));
    EMIT(program, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, BF_PROG_CTX_OFF(dynptr)));
    EMIT_KFUNC_CALL(program, kfunc);

    // If the function call failed, quit the program
    {
        _clean_bf_jmpctx_ struct bf_jmpctx _ =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0));

        // Update the error counter
        r = bf_program_emit_update_counters(
            program, bf_program_error_counter_idx(program));
        if (r)
            return r;

        if (bf_ctx_is_verbose(BF_VERBOSE_BPF))
            EMIT_PRINT(program, "failed to create a new dynamic pointer");

        r = program->runtime.ops->get_verdict(BF_VERDICT_ACCEPT, &ret_code);
        if (r)
            return r;

        EMIT(program, BPF_MOV64_IMM(BPF_REG_0, ret_code));
        EMIT(program, BPF_EXIT_INSN());
    }

    return 0;
}

int bf_stub_make_ctx_xdp_dynptr(struct bf_program *program, int md_reg)
{
    assert(program);

    return _bf_stub_make_ctx_dynptr(program, md_reg, "bpf_dynptr_from_xdp");
}

int bf_stub_make_ctx_skb_dynptr(struct bf_program *program, int skb_reg)
{
    assert(program);

    return _bf_stub_make_ctx_dynptr(program, skb_reg, "bpf_dynptr_from_skb");
}

int bf_stub_parse_l2_ethhdr(struct bf_program *program)
{
    int ret_code;
    int r;

    assert(program);

    // Call bpf_dynptr_slice()
    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(dynptr)));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_2, 0));
    EMIT(program, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, BF_PROG_CTX_OFF(l2)));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_4, sizeof(struct ethhdr)));

    /* `l2_size` is only read by `bf_pkt_log` (BF_ELFSTUB_PKT_LOG), which
     * is emitted by `bf_packet_gen_inline_log()` only for rules with
     * `rule->log` set — the same condition that sets `BF_CHAIN_LOG`.
     * Skip this dead store on every per-packet hot path when the chain
     * has no logging rule. `r4` itself is still needed as the 4th
     * argument to `bpf_dynptr_slice` below, so the MOV imm above stays. */
    if (_bf_stub_needs_pkt_log(program)) {
        EMIT(program, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_4,
                                  BF_PROG_CTX_OFF(l2_size)));
    }

    EMIT_KFUNC_CALL(program, "bpf_dynptr_slice");

    // If the function call failed, quit the program
    {
        _clean_bf_jmpctx_ struct bf_jmpctx _ =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 0));

        // Update the error counter
        r = bf_program_emit_update_counters(
            program, bf_program_error_counter_idx(program));
        if (r)
            return r;

        if (bf_ctx_is_verbose(BF_VERBOSE_BPF))
            EMIT_PRINT(program, "failed to create L2 dynamic pointer slice");

        r = program->runtime.ops->get_verdict(BF_VERDICT_ACCEPT, &ret_code);
        if (r)
            return r;

        EMIT(program, BPF_MOV64_IMM(BPF_REG_0, ret_code));
        EMIT(program, BPF_EXIT_INSN());
    }

    // Store the L2 header address into the runtime context
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, BF_PROG_CTX_OFF(l2_hdr)));

    // Store the L3 protocol ID in r7
    EMIT(program, BPF_LDX_MEM(BPF_H, BPF_REG_7, BPF_REG_0,
                              offsetof(struct ethhdr, h_proto)));

    /* After the LDX→MOV swap in `bf_stub_parse_l3_hdr()`, the only
     * consumer of `ctx->l3_offset` is the IPv6 EH/NH elfstub. Elide
     * this store when that elfstub isn't reachable in this program. */
    if (bf_stub_l3_offset_needed_in_ctx(program->runtime.chain)) {
        // Set bf_runtime.l3_offset
        EMIT(program, BPF_ST_MEM(BPF_W, BPF_REG_10, BF_PROG_CTX_OFF(l3_offset),
                                 sizeof(struct ethhdr)));
    }

    return 0;
}

int bf_stub_parse_l3_hdr(struct bf_program *program)
{
    _clean_bf_jmpctx_ struct bf_jmpctx _ = bf_jmpctx_default();
    struct bf_proto_used used;
    int ret_code;
    int l3_off_const;
    int r;

    assert(program);

    /* Discover which L3/L4 branches the chain actually filters on, so we
     * can elide unused branches of the pre-parser. Safe because every
     * rule emits its own per-layer protocol guard
     * (`bf_stub_rule_check_protocol`) that bails out when r7/r8 doesn't
     * match: packets of an unfiltered family hit those guards and skip
     * every rule, without needing their L3/L4 header pre-parsed. */
    _bf_stub_collect_proto_used(program->runtime.chain, &used);

    /* If the chain filters on neither IPv4 nor IPv6, the entire L3 stub
     * is dead code: no L3 header to slice, no L4 proto id to extract.
     * Returning immediately also leaves r7 with whatever value the L2
     * stub (or flavor prologue) wrote, so any `meta.l3_proto` matcher
     * comparing r7 directly still observes the real ethertype. */
    if (!used.ip4 && !used.ip6)
        return 0;

    /* l3_offset is a codegen-time constant determined by the program's
     * flavor prologue. Folding it into the l4_offset computation removes
     * one stack load (and, for the IPv6 fast path, an extra ALU op) from
     * every packet on the dominant L3 paths. */
    l3_off_const = _bf_stub_l3_offset_const(program->flavor);

    /* Store the size of the L3 protocol header in r4, depending on the protocol
     * ID stored in r7. If the protocol is not supported, we store 0 into r7
     * and we skip the instructions below.
     *
     * Note: the most common protocol (IPv4) is emitted last so that its body
     * falls through to the end of the swich, saving one JMP_A in the hot
     * path. Each option is emitted only if the chain actually filters on
     * that L3 protocol. */
    {
        _clean_bf_swich_ struct bf_swich swich =
            bf_swich_get(program, BPF_REG_7);

        if (used.ip6) {
            EMIT_SWICH_OPTION(&swich, htobe16(ETH_P_IPV6),
                              BPF_MOV64_IMM(BPF_REG_4, sizeof(struct ipv6hdr)));
        }
        if (used.ip4) {
            EMIT_SWICH_OPTION(&swich, htobe16(ETH_P_IP),
                              BPF_MOV64_IMM(BPF_REG_4, sizeof(struct iphdr)));
        }
        EMIT_SWICH_DEFAULT(&swich, BPF_MOV64_IMM(BPF_REG_7, 0));

        r = bf_swich_generate(&swich);
        if (r)
            return r;
    }
    _ = bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_7, 0, 0));

    /* `l3_size` is only read by `bf_pkt_log`; elide the store when the
     * chain has no logging rule. See _bf_stub_needs_pkt_log() comment. */
    if (_bf_stub_needs_pkt_log(program)) {
        EMIT(program, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_4,
                                  BF_PROG_CTX_OFF(l3_size)));
    }

    // Call bpf_dynptr_slice()
    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(dynptr)));
    /* `l3_offset` is a codegen-time constant determined by the flavor
     * prologue (sizeof(ethhdr) for TC/XDP, 0 for NF/CGROUP_SKB). Use the
     * immediate form so we don't reach back into the runtime context for
     * a value we already know — removes a per-packet stack load and lets
     * the JIT keep r2 in a register. */
    EMIT(program, BPF_MOV64_IMM(BPF_REG_2, l3_off_const));
    EMIT(program, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, BF_PROG_CTX_OFF(l2)));
    EMIT_KFUNC_CALL(program, "bpf_dynptr_slice");

    // If the function call failed, quit the program
    {
        _clean_bf_jmpctx_ struct bf_jmpctx _ =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 0));

        r = bf_program_emit_update_counters(
            program, bf_program_error_counter_idx(program));
        if (r)
            return r;

        if (bf_ctx_is_verbose(BF_VERBOSE_BPF))
            EMIT_PRINT(program, "failed to create L3 dynamic pointer slice");

        r = program->runtime.ops->get_verdict(BF_VERDICT_ACCEPT, &ret_code);
        if (r)
            return r;

        EMIT(program, BPF_MOV64_IMM(BPF_REG_0, ret_code));
        EMIT(program, BPF_EXIT_INSN());
    }

    // Store the L3 header address into the runtime context
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, BF_PROG_CTX_OFF(l3_hdr)));

    /* Unsupported L3 protocols have been filtered out at the beginning of this
     * function and would jump over the block below, so there is no need to
     * worry about them here. Each per-family block below is emitted only if
     * the chain actually filters on that L3 protocol *and* needs the L4
     * proto id / l4_offset prepared for downstream consumers (the L4 stub
     * or any L4-layer matcher). For L3-only filtering chains the entire
     * block — including the inner JNE guard — is elided. */
    if (used.ip4 && _bf_stub_need_ip4_l4_prep(&used)) {
        // IPv4
        _clean_bf_jmpctx_ struct bf_jmpctx _ = bf_jmpctx_get(
            program, BPF_JMP_IMM(BPF_JNE, BPF_REG_7, htobe16(ETH_P_IP), 0));

        EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_0, 0));
        EMIT(program, BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0x0f));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 2));
        /* l3_offset is a codegen-time constant set by the flavor's prologue
         * (sizeof(ethhdr) for TC/XDP, 0 for NF/CGROUP_SKB). Fold the add
         * of l3_offset into an ALU64_IMM, removing one LDX from the hot
         * path. When the constant is 0, skip the ADD entirely. */
        if (l3_off_const != 0) {
            EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, l3_off_const));
        }
        EMIT(program, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1,
                                  BF_PROG_CTX_OFF(l4_offset)));
        EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_8, BPF_REG_0,
                                  offsetof(struct iphdr, protocol)));
    }

    if (used.ip6 && _bf_stub_need_ip6_l4_prep(&used, program->runtime.chain)) {
        // IPv6
        struct bf_jmpctx tcpjmp, udpjmp, noehjmp, ehjmp;
        struct bpf_insn ld64[2] = {BPF_LD_IMM64(BPF_REG_2, _BF_LOW_EH_BITMASK)};
        _clean_bf_jmpctx_ struct bf_jmpctx _ = bf_jmpctx_get(
            program, BPF_JMP_IMM(BPF_JNE, BPF_REG_7, htobe16(ETH_P_IPV6), 0));

        EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_8, BPF_REG_0,
                                  offsetof(struct ipv6hdr, nexthdr)));

        /* Fast path for TCP and UDP: quickly recognize the most used protocol
         * to process them as fast as possible. */
        tcpjmp = bf_jmpctx_get(program,
                               BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, IPPROTO_TCP, 0));
        udpjmp = bf_jmpctx_get(program,
                               BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, IPPROTO_UDP, 0));

        /* For all the EH protocol numbers <64, use a bitmask:
         * mask = (1<<0) | (1<<43) | (1<<44) | (1<<50) | (1<<51) | (1<<60)
         *
         * Pseudo-code:
         * - r3 = 1 << r8 (nexthdr)
         * - r3 = r3 & mask
         * - if r3 != 0: go to slow path (EH present) */
        EMIT(program, ld64[0]);
        EMIT(program, ld64[1]);
        EMIT(program, BPF_JMP_IMM(BPF_JGE, BPF_REG_8, 64, 4));
        EMIT(program, BPF_MOV64_IMM(BPF_REG_3, 1));
        EMIT(program, BPF_ALU64_REG(BPF_LSH, BPF_REG_3, BPF_REG_8));
        EMIT(program, BPF_ALU64_REG(BPF_AND, BPF_REG_3, BPF_REG_2));
        EMIT(program, BPF_JMP_IMM(BPF_JNE, BPF_REG_3, 0, 4));

        // EH with protocol numbers >64 are processed individually
        EMIT(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 135, 3));
        EMIT(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 139, 2));
        EMIT(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 140, 1));

        // If no EH matched, nexthdr is L4, skip EH processing
        noehjmp = bf_jmpctx_get(program, BPF_JMP_A(0));

        // Process EH
        EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
        EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(arg)));
        // If any rule filters on ipv6.nexthdr, store the EH in the runtime context
        // during process, so we won't have to process the EH again.
        if (program->runtime.chain->flags & BF_FLAG(BF_CHAIN_STORE_NEXTHDR))
            EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_PARSE_IPV6_NH);
        else
            EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_PARSE_IPV6_EH);
        EMIT(program, BPF_MOV64_REG(BPF_REG_8, BPF_REG_0));

        ehjmp = bf_jmpctx_get(program, BPF_JMP_A(0));

        // If no EH found, all the jmp will end up here
        bf_jmpctx_cleanup(&tcpjmp);
        bf_jmpctx_cleanup(&udpjmp);
        bf_jmpctx_cleanup(&noehjmp);

        /* Process IPv6 header, no EH (BPF_REG_8 already contains nexthdr).
         * l3_offset is a codegen-time constant set by the flavor's prologue,
         * so l4_offset = l3_offset + sizeof(ipv6hdr) can be written with a
         * single ST_MEM immediate, removing both a stack load and an ALU
         * op from the IPv6 fast path. */
        EMIT(program, BPF_ST_MEM(BPF_W, BPF_REG_10, BF_PROG_CTX_OFF(l4_offset),
                                 l3_off_const + (int)sizeof(struct ipv6hdr)));

        bf_jmpctx_cleanup(&ehjmp);
    }

    return 0;
}

int bf_stub_parse_l4_hdr(struct bf_program *program)
{
    _clean_bf_jmpctx_ struct bf_jmpctx _ = bf_jmpctx_default();
    struct bf_proto_used used;
    int ret_code;
    int r;

    assert(program);

    /* Discover which L4 protocols the chain actually filters on; if none
     * of the L4 headers we know how to slice are referenced, the L4 stub
     * is dead code and we can return immediately. r8 is already populated
     * by the L3 stub for any meta.l4_proto-style matchers that may care. */
    _bf_stub_collect_proto_used(program->runtime.chain, &used);

    if (!used.tcp && !used.udp && !used.icmp && !used.icmpv6)
        return 0;

    /* Parse the L4 protocol and handle unuspported protocol, similarly to
     * bf_stub_parse_l3_hdr() above.
     *
     * Note: the most common protocol (TCP) is emitted last so that its body
     * falls through to the end of the swich, saving one JMP_A in the hot
     * path. Each option is emitted only if the chain actually filters on
     * that L4 protocol. */
    {
        _clean_bf_swich_ struct bf_swich swich =
            bf_swich_get(program, BPF_REG_8);

        if (used.icmpv6) {
            EMIT_SWICH_OPTION(
                &swich, IPPROTO_ICMPV6,
                BPF_MOV64_IMM(BPF_REG_4, sizeof(struct icmp6hdr)));
        }
        if (used.icmp) {
            EMIT_SWICH_OPTION(&swich, IPPROTO_ICMP,
                              BPF_MOV64_IMM(BPF_REG_4, sizeof(struct icmphdr)));
        }
        if (used.udp) {
            EMIT_SWICH_OPTION(&swich, IPPROTO_UDP,
                              BPF_MOV64_IMM(BPF_REG_4, sizeof(struct udphdr)));
        }
        if (used.tcp) {
            EMIT_SWICH_OPTION(&swich, IPPROTO_TCP,
                              BPF_MOV64_IMM(BPF_REG_4, sizeof(struct tcphdr)));
        }
        EMIT_SWICH_DEFAULT(&swich, BPF_MOV64_IMM(BPF_REG_8, 0));

        r = bf_swich_generate(&swich);
        if (r)
            return r;
    }
    _ = bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 0, 0));

    /* `l4_size` is only read by `bf_pkt_log`; elide the store when the
     * chain has no logging rule. See _bf_stub_needs_pkt_log() comment. */
    if (_bf_stub_needs_pkt_log(program)) {
        EMIT(program, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_4,
                                  BF_PROG_CTX_OFF(l4_size)));
    }

    // Call bpf_dynptr_slice()
    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(dynptr)));
    EMIT(program,
         BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, BF_PROG_CTX_OFF(l4_offset)));
    EMIT(program, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, BF_PROG_CTX_OFF(l4)));
    EMIT_KFUNC_CALL(program, "bpf_dynptr_slice");

    // If the function call failed, quit the program
    {
        _clean_bf_jmpctx_ struct bf_jmpctx _ =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 0));

        r = bf_program_emit_update_counters(
            program, bf_program_error_counter_idx(program));
        if (r)
            return r;

        if (bf_ctx_is_verbose(BF_VERBOSE_BPF))
            EMIT_PRINT(program, "failed to create L4 dynamic pointer slice");

        r = program->runtime.ops->get_verdict(BF_VERDICT_ACCEPT, &ret_code);
        if (r)
            return r;

        EMIT(program, BPF_MOV64_IMM(BPF_REG_0, ret_code));
        EMIT(program, BPF_EXIT_INSN());
    }

    // Store the L4 header address into the runtime context
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, BF_PROG_CTX_OFF(l4_hdr)));

    return 0;
}

int bf_stub_rule_check_protocol(struct bf_program *program,
                                const struct bf_matcher_meta *meta)
{
    assert(program);
    assert(meta);

    switch (meta->layer) {
    case BF_MATCHER_LAYER_3:
        EMIT_FIXUP_JMP_NEXT_RULE(
            program, BPF_JMP_IMM(BPF_JNE, BPF_REG_7,
                                 htobe16((uint16_t)meta->hdr_id), 0));
        break;
    case BF_MATCHER_LAYER_4:
        EMIT_FIXUP_JMP_NEXT_RULE(
            program, BPF_JMP_IMM(BPF_JNE, BPF_REG_8, (uint8_t)meta->hdr_id, 0));
        break;
    default:
        return bf_err_r(-EINVAL, "rule can't check for layer ID %d",
                        meta->layer);
    }

    return 0;
}

int bf_stub_load_header(struct bf_program *program,
                        const struct bf_matcher_meta *meta, int reg)
{
    assert(program);
    assert(meta);

    /* When the caller targets r6 (the documented "header currently
     * filtered on" register), consult `program->loaded_hdr` and skip the
     * `LDX_MEM` if r6 already holds the requested layer's header pointer
     * from an earlier matcher in the same rule. r6 is callee-saved in
     * BPF, so its value survives BPF helper and kfunc calls; the cache is
     * invalidated at every rule boundary by `_bf_program_generate_rule()`
     * because `JMP_NEXT_RULE` fixups converge from arbitrary points. */
    switch (meta->layer) {
    case BF_MATCHER_LAYER_3:
        if (reg == BPF_REG_6 && program->loaded_hdr == BF_LOADED_HDR_L3)
            return 0;
        EMIT(program,
             BPF_LDX_MEM(BPF_DW, reg, BPF_REG_10, BF_PROG_CTX_OFF(l3_hdr)));
        if (reg == BPF_REG_6)
            program->loaded_hdr = BF_LOADED_HDR_L3;
        break;
    case BF_MATCHER_LAYER_4:
        if (reg == BPF_REG_6 && program->loaded_hdr == BF_LOADED_HDR_L4)
            return 0;
        EMIT(program,
             BPF_LDX_MEM(BPF_DW, reg, BPF_REG_10, BF_PROG_CTX_OFF(l4_hdr)));
        if (reg == BPF_REG_6)
            program->loaded_hdr = BF_LOADED_HDR_L4;
        break;
    default:
        return bf_err_r(-EINVAL,
                        "layer ID %d is not a valid layer to load header for",
                        meta->layer);
    }

    return 0;
}

int bf_stub_load(struct bf_program *program, size_t src_offset, size_t size,
                 int dst_offset)
{
    size_t src_off = src_offset;
    int dst_off = dst_offset;
    size_t remaining_size = size;

    assert(program);

    while (remaining_size) {
        int bpf_size = BPF_B;
        size_t copy_bytes = 1;

        if (BF_ALIGNED_64(src_off) && BF_ALIGNED_64(dst_off) &&
            remaining_size >= 8) {
            bpf_size = BPF_DW;
            copy_bytes = 8;
        } else if (BF_ALIGNED_32(src_off) && BF_ALIGNED_32(dst_off) &&
                   remaining_size >= 4) {
            bpf_size = BPF_W;
            copy_bytes = 4;
        } else if (BF_ALIGNED_16(src_off) && BF_ALIGNED_16(dst_off) &&
                   remaining_size >= 2) {
            bpf_size = BPF_H;
            copy_bytes = 2;
        }

        EMIT(program, BPF_LDX_MEM(bpf_size, BPF_REG_1, BPF_REG_6, src_off));
        EMIT(program, BPF_STX_MEM(bpf_size, BPF_REG_10, BPF_REG_1, dst_off));

        remaining_size -= copy_bytes;
        src_off += copy_bytes;
        dst_off += (int)copy_bytes;
    }

    return 0;
}

int bf_stub_stx_payload(struct bf_program *program,
                        const struct bf_matcher_meta *meta, size_t offset)
{
    assert(program);
    assert(meta);

    return bf_stub_load(program, meta->hdr_payload_offset,
                        meta->hdr_payload_size, BF_PROG_SCR_OFF(offset));
}
