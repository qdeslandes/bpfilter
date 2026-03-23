/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/nf.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <bpfilter/btf.h>
#include <bpfilter/flavor.h>
#include <bpfilter/helper.h>
#include <bpfilter/hook.h>
#include <bpfilter/matcher.h>
#include <bpfilter/verdict.h>

#include "cgen/jmp.h"
#include "cgen/matcher/cmp.h"
#include "cgen/matcher/packet.h"
#include "cgen/program.h"
#include "cgen/stub.h"
#include "filter.h"

#define BF_NF_PRIO_EVEN 2
#define BF_NF_PRIO_ODD 1

static inline bool _bf_nf_hook_is_ingress(enum bf_hook hook)
{
    return hook == BF_HOOK_NF_PRE_ROUTING || hook == BF_HOOK_NF_LOCAL_IN ||
           hook == BF_HOOK_NF_FORWARD;
}

static int _bf_nf_gen_inline_prologue(struct bf_program *program)
{
    int r;
    int offset;

    assert(program);

    if (program->runtime.needs_ifindex) {
        // Copy the ifindex from bpf_nf_ctx.state.{in,out}.ifindex to runtime context
        if ((offset = bf_btf_get_field_off("bpf_nf_ctx", "state")) < 0)
            return offset;
        EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, offset));
        if (_bf_nf_hook_is_ingress(program->runtime.chain->hook)) {
            if ((offset = bf_btf_get_field_off("nf_hook_state", "in")) < 0)
                return offset;
            EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_2, offset));
        } else {
            if ((offset = bf_btf_get_field_off("nf_hook_state", "out")) < 0)
                return offset;
            EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_2, offset));
        }

        if ((offset = bf_btf_get_field_off("net_device", "ifindex")) < 0)
            return offset;
        EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_3, offset));
        EMIT(program,
             BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_4, BF_PROG_CTX_OFF(ifindex)));
    }

    // Load skb pointer from bpf_nf_ctx.skb into R1 (R1 held ctx; the ifindex
    // chain above used R2/R3/R4, so R1 = bpf_nf_ctx* is still valid here).
    if ((offset = bf_btf_get_field_off("bpf_nf_ctx", "skb")) < 0)
        return offset;
    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_1, offset));

    // Read sk_buff.protocol directly when needed: it already holds the
    // network-byte-order ethertype, replacing the pf→ethertype dispatch.
    if (program->runtime.needs_l3_proto) {
        if ((offset = bf_btf_get_field_off("sk_buff", "protocol")) < 0)
            return offset;
        EMIT(program, BPF_LDX_MEM(BPF_H, BPF_REG_7, BPF_REG_1, offset));
    }

    // Calculate the packet size (+ETH_HLEN) and store it into the runtime context
    if ((offset = bf_btf_get_field_off("sk_buff", "len")) < 0)
        return offset;
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, offset));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, ETH_HLEN));
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2, BF_PROG_CTX_OFF(pkt_size)));

    if (program->runtime.needs_l3) {
        r = bf_stub_make_ctx_skb_dynptr(program, BPF_REG_1);
        if (r)
            return r;

        r = bf_stub_parse_l3_hdr(program, 0);
        if (r)
            return r;

        if (program->runtime.needs_l4) {
            r = bf_stub_parse_l4_hdr(program);
            if (r)
                return r;
        }
    } else if (program->runtime.needs_l3_proto || program->runtime.needs_ifindex) {
        /* No L3/L4 header parsing needed, but some prologue loads were
         * emitted.  Zero R8 (L4 protocol ID) so that any stale register
         * value cannot accidentally satisfy a protocol guard. */
        EMIT(program, BPF_MOV64_IMM(BPF_REG_8, 0));
    }

    return 0;
}

static int _bf_nf_gen_inline_epilogue(struct bf_program *program)
{
    (void)program;

    return 0;
}

static int _bf_nf_gen_inline_matcher(struct bf_program *program,
                                     const struct bf_matcher *matcher)
{
    int offset;

    assert(program);
    assert(matcher);

    switch (bf_matcher_get_type(matcher)) {
    case BF_MATCHER_META_MARK:
        EMIT(program,
             BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, BF_PROG_CTX_OFF(arg)));
        if ((offset = bf_btf_get_field_off("bpf_nf_ctx", "skb")) < 0)
            return offset;
        EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, offset));
        if ((offset = bf_btf_get_field_off("sk_buff", "mark")) < 0)
            return offset;
        EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_2, offset));

        return bf_cmp_value(program, bf_matcher_get_op(matcher),
                            bf_matcher_payload(matcher), 4, BPF_REG_1);
    default:
        return bf_matcher_generate_packet(program, matcher);
    }
}

/**
 * Convert a standard verdict into a return value.
 *
 * @param verdict Verdict to convert. Must be valid.
 * @return Netfilter return code corresponding to the verdict, as an integer.
 */
static int _bf_nf_get_verdict(enum bf_verdict verdict)
{
    switch (verdict) {
    case BF_VERDICT_ACCEPT:
        return NF_ACCEPT;
    case BF_VERDICT_DROP:
        return NF_DROP;
    default:
        return -ENOTSUP;
    }
}

const struct bf_flavor_ops bf_flavor_ops_nf = {
    .gen_inline_prologue = _bf_nf_gen_inline_prologue,
    .gen_inline_epilogue = _bf_nf_gen_inline_epilogue,
    .get_verdict = _bf_nf_get_verdict,
    .gen_inline_matcher = _bf_nf_gen_inline_matcher,
};
