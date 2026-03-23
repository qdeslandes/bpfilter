/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>

#include <stddef.h>
#include <stdint.h>

#include <bpfilter/flavor.h>
#include <bpfilter/helper.h>
#include <bpfilter/logger.h>
#include <bpfilter/verdict.h>

#include "cgen/jmp.h"
#include "cgen/matcher/packet.h"
#include "cgen/program.h"
#include "cgen/stub.h"
#include "filter.h"

/**
 * Generate XDP program prologue.
 *
 * Read the ethertype directly from xdp_md->data via XDP direct packet access
 * (with a bounds check) instead of calling bf_stub_parse_l2_ethhdr(), which
 * would invoke bpf_dynptr_slice() just to extract 2 bytes. This saves one
 * kfunc call and ~5 BPF instructions per packet on the fast path.
 *
 * @param program Program to generate the prologue for. Must not be NULL.
 * @return 0 on success, or negative errno value on error.
 */
static int _bf_xdp_gen_inline_prologue(struct bf_program *program)
{
    int r;

    assert(program);

    /* Load data and data_end pointers from xdp_md. R1 = ctx (xdp_md *). */
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
                              offsetof(struct xdp_md, data)));
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
                              offsetof(struct xdp_md, data_end)));

    /* Bounds check: data + ETH_HLEN <= data_end; accept short/invalid frames.
     * This replaces bf_stub_parse_l2_ethhdr(), which called bpf_dynptr_slice()
     * just to read ethhdr.h_proto. R4 is a scratch register for the check.
     * R7 is callee-saved and will hold the ethertype across the kfunc call. */
    EMIT(program, BPF_MOV64_REG(BPF_REG_4, BPF_REG_2));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, ETH_HLEN));
    {
        _clean_bf_jmpctx_ struct bf_jmpctx _ =
            bf_jmpctx_get(program, BPF_JMP_REG(BPF_JLE, BPF_REG_4, BPF_REG_3, 0));

        r = program->runtime.ops->get_verdict(BF_VERDICT_ACCEPT);
        if (r < 0)
            return r;
        EMIT(program, BPF_MOV64_IMM(BPF_REG_0, r));
        EMIT(program, BPF_EXIT_INSN());
    }

    /* Read ethertype directly via XDP packet access into R7. */
    EMIT(program, BPF_LDX_MEM(BPF_H, BPF_REG_7, BPF_REG_2,
                              offsetof(struct ethhdr, h_proto)));

    /* Compute pkt_size = data_end - data and store it into the runtime context. */
    EMIT(program, BPF_ALU64_REG(BPF_SUB, BPF_REG_3, BPF_REG_2));
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_3, BF_PROG_CTX_OFF(pkt_size)));

    /* Store the ingress ifindex into the runtime context. R1 still valid. */
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
                              offsetof(struct xdp_md, ingress_ifindex)));
    EMIT(program,
         BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_2, BF_PROG_CTX_OFF(ifindex)));

    if (program->runtime.needs_l3) {
        /* Create the XDP dynptr. R1 still points to xdp_md. */
        r = bf_stub_make_ctx_xdp_dynptr(program, BPF_REG_1);
        if (r)
            return r;

        /* Parse L3 (R7 already holds the ethertype) and optionally L4. */
        r = bf_stub_parse_l3_hdr(program, ETH_HLEN);
        if (r)
            return r;

        if (program->runtime.needs_l4) {
            r = bf_stub_parse_l4_hdr(program);
            if (r)
                return r;
        }
    } else {
        /* No rule inspects L3/L4 headers: skip dynptr creation and header
         * parsing entirely.  Zero R8 (L4 protocol ID) so that any stale
         * register value cannot accidentally satisfy a protocol guard. */
        EMIT(program, BPF_MOV64_IMM(BPF_REG_8, 0));
    }

    return 0;
}

static int _bf_xdp_gen_inline_epilogue(struct bf_program *program)
{
    (void)program;

    return 0;
}

/**
 * @brief Generate bytecode to redirect a packet using XDP.
 *
 * XDP redirect only supports egress direction - the packet is always
 * transmitted out of the target interface. The BPF_F_INGRESS flag is
 * ignored by XDP's bpf_redirect().
 *
 * @param program Program to generate bytecode for. Can't be NULL.
 * @param ifindex Target interface index.
 * @param dir Direction (must be BF_REDIRECT_EGRESS for XDP).
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_xdp_gen_inline_redirect(struct bf_program *program,
                                       uint32_t ifindex,
                                       enum bf_redirect_dir dir)
{
    assert(program);

    if (dir != BF_REDIRECT_EGRESS)
        return bf_err_r(-ENOTSUP, "XDP redirect only supports 'out' direction");

    // bpf_redirect(ifindex, flags) - flags are ignored for XDP
    EMIT(program, BPF_MOV64_IMM(BPF_REG_1, ifindex));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_2, 0));
    EMIT(program, BPF_EMIT_CALL(BPF_FUNC_redirect));

    // Return value from bpf_redirect() is the action (XDP_REDIRECT on success)
    EMIT(program, BPF_EXIT_INSN());

    return 0;
}

static int _bf_xdp_get_verdict(enum bf_verdict verdict)
{
    switch (verdict) {
    case BF_VERDICT_ACCEPT:
        return XDP_PASS;
    case BF_VERDICT_DROP:
        return XDP_DROP;
    default:
        return -ENOTSUP;
    }
}

const struct bf_flavor_ops bf_flavor_ops_xdp = {
    .gen_inline_prologue = _bf_xdp_gen_inline_prologue,
    .gen_inline_epilogue = _bf_xdp_gen_inline_epilogue,
    .gen_inline_redirect = _bf_xdp_gen_inline_redirect,
    .get_verdict = _bf_xdp_get_verdict,
    .gen_inline_matcher = bf_matcher_generate_packet,
};
