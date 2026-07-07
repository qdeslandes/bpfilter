/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/matcher/meta.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>
#include <linux/in.h> // NOLINT
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>

#include <endian.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <bpfilter/logger.h>
#include <bpfilter/matcher.h>

#include "cgen/jmp.h"
#include "cgen/matcher/cmp.h"
#include "cgen/program.h"
#include "cgen/runtime.h"
#include "filter.h"

/// Mask to extract the 20-bit flow label from the IPv6 header's first word.
#define IPV6_FLOW_LABEL_MASK 0x000FFFFF

/// xxHash32 finalizer multiplication constants.
#define XXH32_PRIME1 0x85ebca77
#define XXH32_PRIME2 0xc2b2ae3d

/** @todo Add support for input and output interface filtering based on the
 * program's hook. */
static int _bf_matcher_generate_meta_iface(struct bf_program *program,
                                           const struct bf_matcher *matcher)
{
    EMIT(program,
         BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, BF_PROG_CTX_OFF(ifindex)));
    EMIT_FIXUP_JMP_NEXT_RULE(
        program, BPF_JMP_IMM(bf_cmp_get_jmp_ins(matcher), BPF_REG_1,
                             *(uint32_t *)bf_matcher_payload(matcher), 0));

    return 0;
}

static int
_bf_matcher_generate_meta_probability(struct bf_program *program,
                                      const struct bf_matcher *matcher)
{
    float proba = *(float *)bf_matcher_payload(matcher);
    uint32_t threshold = (uint32_t)((double)UINT32_MAX * (proba / 100.0));

    EMIT(program, BPF_EMIT_CALL(BPF_FUNC_get_prandom_u32));

    if (bf_matcher_get_negate(matcher)) {
        EMIT_FIXUP_JMP_NEXT_RULE(program,
                                 BPF_JMP_IMM(BPF_JLE, BPF_REG_0, threshold, 0));
    } else {
        EMIT_FIXUP_JMP_NEXT_RULE(program,
                                 BPF_JMP_IMM(BPF_JGT, BPF_REG_0, threshold, 0));
    }

    return 0;
}

static int
_bf_matcher_generate_meta_flow_probability(struct bf_program *program,
                                           const struct bf_matcher *matcher)
{
    float proba = *(float *)bf_matcher_payload(matcher);
    uint32_t threshold = (uint32_t)((double)UINT32_MAX * (proba / 100.0));
    struct bf_jmpctx ip6jmp, l4jmp;

    // Ensure L3 is IPv4 or IPv6, skip to next rule otherwise
    EMIT(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_7, htobe16(ETH_P_IP), 2));
    EMIT(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_7, htobe16(ETH_P_IPV6), 1));
    EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP_A(0));

    // Ensure L4 is TCP or UDP, skip to next rule otherwise
    EMIT(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, IPPROTO_TCP, 2));
    EMIT(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, IPPROTO_UDP, 1));
    EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP_A(0));

    /* Compute the packet's flow hash inline, bit-for-bit identical to the
     * former bf_flow_hash ELF stub: XOR-fold the packet's 5-tuple (source
     * and destination addresses, ports, and L4 protocol) plus the IPv6 flow
     * label into a 32-bit accumulator, then apply the xxHash32 avalanche
     * finalizer. All packets of a flow hash to the same value, making the
     * probability decision consistent per-flow rather than per-packet.
     *
     * The guards above establish the domain: r7 is IPv4 or IPv6, so r6
     * points to a full fixed L3 header within verifier-visible bounds, and
     * r8 is TCP or UDP, so r9 points to an L4 header covering the port
     * fields, which TCP and UDP store at the same offsets (see the
     * static_assert in cgen/stub.c). r1 holds the hash accumulator, r2 and
     * r3 are scratch; accumulator arithmetic uses ALU32 forms to match the
     * stub's __u32 semantics. */
    ip6jmp = bf_jmpctx_get(
        program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_7, htobe16(ETH_P_IPV6), 0));

    // IPv4: hash = rotate_right(saddr, 8) ^ daddr ^ (l4_proto << 16)
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_6,
                              offsetof(struct iphdr, saddr)));
    EMIT(program, BPF_MOV32_REG(BPF_REG_2, BPF_REG_1));
    EMIT(program, BPF_ALU32_IMM(BPF_RSH, BPF_REG_1, 8));
    EMIT(program, BPF_ALU32_IMM(BPF_LSH, BPF_REG_2, 24));
    EMIT(program, BPF_ALU32_REG(BPF_OR, BPF_REG_1, BPF_REG_2));
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6,
                              offsetof(struct iphdr, daddr)));
    EMIT(program, BPF_ALU32_REG(BPF_XOR, BPF_REG_1, BPF_REG_2));
    EMIT(program, BPF_MOV32_REG(BPF_REG_2, BPF_REG_8));
    EMIT(program, BPF_ALU32_IMM(BPF_LSH, BPF_REG_2, 16));
    EMIT(program, BPF_ALU32_REG(BPF_XOR, BPF_REG_1, BPF_REG_2));

    l4jmp = bf_jmpctx_get(program, BPF_JMP_A(0));
    bf_jmpctx_cleanup(&ip6jmp);

    /* IPv6: same shape over the 4-word addresses, plus the flow label. Each
     * 8-byte address half is folded to 32 bits with a DW load and
     * (dw >> 32) ^ dw: the low 32 bits equal the stub's word-XOR on either
     * host endianness, as both halves are read from packet memory exactly
     * like the stub's 32-bit member loads. */
    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6,
                              offsetof(struct ipv6hdr, saddr)));
    EMIT(program, BPF_MOV64_REG(BPF_REG_2, BPF_REG_1));
    EMIT(program, BPF_ALU64_IMM(BPF_RSH, BPF_REG_2, 32));
    EMIT(program, BPF_ALU32_REG(BPF_XOR, BPF_REG_1, BPF_REG_2));
    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6,
                              offsetof(struct ipv6hdr, saddr) + 8));
    EMIT(program, BPF_MOV64_REG(BPF_REG_3, BPF_REG_2));
    EMIT(program, BPF_ALU64_IMM(BPF_RSH, BPF_REG_3, 32));
    EMIT(program, BPF_ALU32_REG(BPF_XOR, BPF_REG_2, BPF_REG_3));
    EMIT(program, BPF_ALU32_REG(BPF_XOR, BPF_REG_1, BPF_REG_2));

    // Rotate the folded source address right by 8 bits
    EMIT(program, BPF_MOV32_REG(BPF_REG_2, BPF_REG_1));
    EMIT(program, BPF_ALU32_IMM(BPF_RSH, BPF_REG_1, 8));
    EMIT(program, BPF_ALU32_IMM(BPF_LSH, BPF_REG_2, 24));
    EMIT(program, BPF_ALU32_REG(BPF_OR, BPF_REG_1, BPF_REG_2));

    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6,
                              offsetof(struct ipv6hdr, daddr)));
    EMIT(program, BPF_MOV64_REG(BPF_REG_3, BPF_REG_2));
    EMIT(program, BPF_ALU64_IMM(BPF_RSH, BPF_REG_3, 32));
    EMIT(program, BPF_ALU32_REG(BPF_XOR, BPF_REG_2, BPF_REG_3));
    EMIT(program, BPF_ALU32_REG(BPF_XOR, BPF_REG_1, BPF_REG_2));
    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6,
                              offsetof(struct ipv6hdr, daddr) + 8));
    EMIT(program, BPF_MOV64_REG(BPF_REG_3, BPF_REG_2));
    EMIT(program, BPF_ALU64_IMM(BPF_RSH, BPF_REG_3, 32));
    EMIT(program, BPF_ALU32_REG(BPF_XOR, BPF_REG_2, BPF_REG_3));
    EMIT(program, BPF_ALU32_REG(BPF_XOR, BPF_REG_1, BPF_REG_2));

    /* Flow label: BPF_ENDIAN(BPF_FROM_BE) on the header's first word is the
     * bytecode equivalent of the stub's bpf_ntohl(). */
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, 0));
    EMIT(program, BPF_ENDIAN(BPF_FROM_BE, BPF_REG_2, 32));
    EMIT(program, BPF_ALU32_IMM(BPF_AND, BPF_REG_2, IPV6_FLOW_LABEL_MASK));
    EMIT(program, BPF_ALU32_REG(BPF_XOR, BPF_REG_1, BPF_REG_2));
    EMIT(program, BPF_MOV32_REG(BPF_REG_2, BPF_REG_8));
    EMIT(program, BPF_ALU32_IMM(BPF_LSH, BPF_REG_2, 16));
    EMIT(program, BPF_ALU32_REG(BPF_XOR, BPF_REG_1, BPF_REG_2));

    bf_jmpctx_cleanup(&l4jmp);

    /* Ports: fold (source << 16) | dest, identical to the stub's packing —
     * a BPF_H load zero-extends the raw network-order 16-bit field exactly
     * like the stub's __be16 member read. */
    EMIT(program, BPF_LDX_MEM(BPF_H, BPF_REG_2, BPF_REG_9,
                              offsetof(struct tcphdr, source)));
    EMIT(program, BPF_ALU32_IMM(BPF_LSH, BPF_REG_2, 16));
    EMIT(program, BPF_LDX_MEM(BPF_H, BPF_REG_3, BPF_REG_9,
                              offsetof(struct tcphdr, dest)));
    EMIT(program, BPF_ALU32_REG(BPF_OR, BPF_REG_2, BPF_REG_3));
    EMIT(program, BPF_ALU32_REG(BPF_XOR, BPF_REG_1, BPF_REG_2));

    // xxHash32 avalanche finalizer for uniform distribution
    EMIT(program, BPF_MOV32_REG(BPF_REG_2, BPF_REG_1));
    EMIT(program, BPF_ALU32_IMM(BPF_RSH, BPF_REG_2, 15));
    EMIT(program, BPF_ALU32_REG(BPF_XOR, BPF_REG_1, BPF_REG_2));
    EMIT(program, BPF_ALU32_IMM(BPF_MUL, BPF_REG_1, XXH32_PRIME1));
    EMIT(program, BPF_MOV32_REG(BPF_REG_2, BPF_REG_1));
    EMIT(program, BPF_ALU32_IMM(BPF_RSH, BPF_REG_2, 13));
    EMIT(program, BPF_ALU32_REG(BPF_XOR, BPF_REG_1, BPF_REG_2));
    EMIT(program, BPF_ALU32_IMM(BPF_MUL, BPF_REG_1, XXH32_PRIME2));
    EMIT(program, BPF_MOV32_REG(BPF_REG_2, BPF_REG_1));
    EMIT(program, BPF_ALU32_IMM(BPF_RSH, BPF_REG_2, 16));
    EMIT(program, BPF_ALU32_REG(BPF_XOR, BPF_REG_1, BPF_REG_2));

    /* Compare the computed hash with the threshold based on probability.
     * The hash is uniformly distributed across 32 bits, so we compare against
     * UINT32_MAX * (proba / 100.0) to select the desired percentage of flows. */
    if (bf_matcher_get_negate(matcher)) {
        EMIT_FIXUP_JMP_NEXT_RULE(
            program, BPF_JMP32_IMM(BPF_JLE, BPF_REG_1, threshold, 0));
    } else {
        EMIT_FIXUP_JMP_NEXT_RULE(
            program, BPF_JMP32_IMM(BPF_JGT, BPF_REG_1, threshold, 0));
    }

    return 0;
}

int bf_matcher_generate_meta(struct bf_program *program,
                             const struct bf_matcher *matcher)
{
    switch (bf_matcher_get_type(matcher)) {
    case BF_MATCHER_META_IFACE:
        return _bf_matcher_generate_meta_iface(program, matcher);
    case BF_MATCHER_META_L3_PROTO: {
        uint16_t be_val = htobe16(*(uint16_t *)bf_matcher_payload(matcher));
        return bf_cmp_value(program, matcher, &be_val, 2, BPF_REG_7);
    }
    case BF_MATCHER_META_L4_PROTO:
        return bf_cmp_value(program, matcher, bf_matcher_payload(matcher), 1,
                            BPF_REG_8);
    case BF_MATCHER_META_PROBABILITY:
        return _bf_matcher_generate_meta_probability(program, matcher);
    case BF_MATCHER_META_FLOW_PROBABILITY:
        return _bf_matcher_generate_meta_flow_probability(program, matcher);
    case BF_MATCHER_META_MARK:
    case BF_MATCHER_META_FLOW_HASH:
        return bf_err_r(-ENOTSUP,
                        "matcher '%s' requires flavor-specific dispatch",
                        bf_matcher_type_to_str(bf_matcher_get_type(matcher)));
    default:
        return bf_err_r(-EINVAL, "unknown matcher type %d",
                        bf_matcher_get_type(matcher));
    }
}
