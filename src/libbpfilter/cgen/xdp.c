/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/xdp.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include <stddef.h>
#include <stdint.h>

#include <bpfilter/flavor.h>
#include <bpfilter/helper.h>
#include <bpfilter/logger.h>
#include <bpfilter/verdict.h>

#include "cgen/jmp.h"
#include "cgen/packet.h"
#include "cgen/program.h"
#include "cgen/stub.h"
#include "filter.h"

/**
 * Generate XDP program prologue.
 *
 * The packet-header parsing pipeline is only emitted if the chain consumes
 * its outputs (see @ref bf_chain_needs_pkt_parse ): otherwise the prologue
 * reduces to the `ifindex` store if a rule filters on it
 * (`BF_CHAIN_NEEDS_IFINDEX`), or nothing at all.
 *
 * @warning When the parsing pipeline is emitted,
 * @ref bf_stub_parse_l2l3_hdr_direct will check for the L3 protocol: if it
 * is neither IPv4 nor IPv6, every L3 and L4 matcher is skipped.
 *
 * @param program Program to generate the prologue for. Must not be NULL.
 * @return 0 on success, or negative errno value on error.
 */
static int _bf_xdp_gen_inline_prologue(struct bf_program *program)
{
    /* The L4 fast paths in the L2+L3 parsing stubs jump over the dedicated
     * L4 slice request: l4_done is closed by the scope cleanup on return, so
     * no instruction may be emitted between the bf_stub_parse_l4_hdr() call
     * and the end of this function. */
    _clean_bf_jmpctx_ struct bf_jmpctx l4_done = bf_jmpctx_default();
    int r;

    assert(program);

    // Store the ingress ifindex into the runtime context
    if (program->runtime.chain->flags & BF_FLAG(BF_CHAIN_NEEDS_IFINDEX)) {
        EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
                                  offsetof(struct xdp_md, ingress_ifindex)));
        EMIT(program, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_2,
                                  BF_PROG_CTX_OFF(ifindex)));
    }

    /* No rule consumes packet-header state: skip the parsing pipeline
     * entirely. r7 and r8 keep their prologue-reset value of 0, r6 and r9
     * stay unwritten as no matcher can read them. */
    if (!bf_chain_needs_pkt_parse(program->runtime.chain))
        return 0;

    /* The direct-access parsing stub expects the packet bounds in r2
     * (data) and r3 (data_end). r1 still holds the program's argument. */
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
                              offsetof(struct xdp_md, data)));
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
                              offsetof(struct xdp_md, data_end)));

    r = bf_stub_parse_l2l3_hdr_direct(program, &l4_done);
    if (r)
        return r;

    r = bf_stub_parse_l4_hdr(program);
    if (r)
        return r;

    return 0;
}

static int _bf_xdp_gen_inline_store_pkt_size(struct bf_program *program)
{
    assert(program);

    EMIT(program,
         BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, BF_PROG_CTX_OFF(arg)));
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
                              offsetof(struct xdp_md, data)));
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1,
                              offsetof(struct xdp_md, data_end)));
    EMIT(program, BPF_ALU64_REG(BPF_SUB, BPF_REG_3, BPF_REG_2));
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_3, BF_PROG_CTX_OFF(pkt_size)));

    return 0;
}

static int _bf_xdp_gen_inline_get_pkt_size(struct bf_program *program)
{
    assert(program);

    EMIT(program,
         BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, BF_PROG_CTX_OFF(arg)));
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
                              offsetof(struct xdp_md, data)));
    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_1,
                              offsetof(struct xdp_md, data_end)));
    EMIT(program, BPF_ALU64_REG(BPF_SUB, BPF_REG_1, BPF_REG_2));

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

/**
 * Convert a standard verdict into a return value.
 *
 * @param verdict Verdict to convert. Must be valid.
 * @param ret_code XDP return code. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_xdp_get_verdict(enum bf_verdict verdict, int *ret_code)
{
    assert(ret_code);

    switch (verdict) {
    case BF_VERDICT_ACCEPT:
    case BF_VERDICT_NEXT:
        *ret_code = XDP_PASS;
        return 0;
    case BF_VERDICT_DROP:
        *ret_code = XDP_DROP;
        return 0;
    default:
        return -ENOTSUP;
    }
}

const struct bf_flavor_ops bf_flavor_ops_xdp = {
    .gen_inline_prologue = _bf_xdp_gen_inline_prologue,
    .gen_inline_store_pkt_size = _bf_xdp_gen_inline_store_pkt_size,
    .gen_inline_get_pkt_size = _bf_xdp_gen_inline_get_pkt_size,
    .gen_inline_epilogue = _bf_xdp_gen_inline_epilogue,
    .gen_inline_redirect = _bf_xdp_gen_inline_redirect,
    .get_verdict = _bf_xdp_get_verdict,
    .gen_inline_matcher = bf_packet_gen_inline_matcher,
    .gen_inline_log = bf_packet_gen_inline_log,
};
