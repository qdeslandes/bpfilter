/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "daemon/cgen/tc.h"

#include <linux/pkt_cls.h>

#include <bpf/libbpf.h>
#include <errno.h>

#include "core/bpf.h"
#include "daemon/context.h"
#include "core/front.h"
#include "core/helper.h"
#include "core/logger.h"
#include "daemon/cgen/codegen.h"
#include "daemon/cgen/program.h"
#include "daemon/cgen/reg.h"
#include "daemon/cgen/stub.h"

#include "external/filter.h"

static int _tc_gen_inline_prologue(struct bf_program *program);
static int _tc_gen_inline_epilogue(struct bf_program *program);
static int _tc_get_verdict(enum bf_verdict verdict);
static int _tc_attach_prog(struct bf_program *new_prog,
                           struct bf_program *old_prog);
static int _tc_detach_prog(struct bf_program *program);

const struct bf_flavor_ops bf_flavor_ops_tc = {
    .gen_inline_prologue = _tc_gen_inline_prologue,
    .gen_inline_epilogue = _tc_gen_inline_epilogue,
    .get_verdict = _tc_get_verdict,
    .attach_prog = _tc_attach_prog,
    .detach_prog = _tc_detach_prog,
};

static int _tc_gen_inline_prologue(struct bf_program *program)
{
    int r;

    bf_assert(program);

    r = bf_stub_make_ctx_skb_dynptr(program, BF_REG_1);
    if (r)
        return r;

    // Copy __sk_buff pointer into BF_REG_1
    EMIT(program,
         BPF_LDX_MEM(BPF_DW, BF_REG_1, BF_REG_CTX, BF_PROG_CTX_OFF(arg)));

    // Copy __sk_buff.data into BF_REG_2
    EMIT(program, BPF_LDX_MEM(BPF_W, BF_REG_2, BF_REG_1,
                              offsetof(struct __sk_buff, data)));

    // Copy __sk_buff.data_end into BF_REG_3
    EMIT(program, BPF_LDX_MEM(BPF_W, BF_REG_3, BF_REG_1,
                              offsetof(struct __sk_buff, data_end)));

    // Calculate packet size
    EMIT(program, BPF_ALU64_REG(BPF_SUB, BF_REG_3, BF_REG_2));

    // Copy packet size into context
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BF_REG_CTX, BF_REG_3, BF_PROG_CTX_OFF(pkt_size)));

    r = bf_stub_parse_l2_ethhdr(program);
    if (r)
        return r;

    r = bf_stub_parse_l3_hdr(program);
    if (r)
        return r;

    r = bf_stub_parse_l4_hdr(program);
    if (r)
        return r;

    return 0;
}

static int _tc_gen_inline_epilogue(struct bf_program *program)
{
    UNUSED(program);

    return 0;
}

/**
 * Convert a standard verdict into a return value.
 *
 * @param verdict Verdict to convert. Must be valid.
 * @return TC return code corresponding to the verdict, as an integer.
 */
static int _tc_get_verdict(enum bf_verdict verdict)
{
    bf_assert(0 <= verdict && verdict < _BF_VERDICT_MAX);

    static const int verdicts[] = {
        [BF_VERDICT_ACCEPT] = TC_ACT_OK,
        [BF_VERDICT_DROP] = TC_ACT_SHOT,
    };

    static_assert(ARRAY_SIZE(verdicts) == _BF_VERDICT_MAX);

    return verdicts[verdict];
}

static int _tc_attach_prog(struct bf_program *new_prog,
                           struct bf_program *old_prog)
{
    _cleanup_close_ int prog_fd = -1;
    _cleanup_close_ int link_fd = -1;
    int r;

    bf_assert(new_prog);

    r = bf_bpf_prog_load(new_prog->prog_name,
                         bf_hook_to_bpf_prog_type(new_prog->hook),
                         new_prog->img, new_prog->img_size,
                         bf_hook_to_attach_type(new_prog->hook), &prog_fd);
    if (r)
        return bf_err_code(r, "failed to load new bf_program");

    if (old_prog) {
        r = bf_bpf_link_update(old_prog->runtime.prog_fd, prog_fd);
        if (r)
            return bf_err_code(
                r, "failed to updated existing link for TC bf_program");

        new_prog->runtime.prog_fd = TAKE_FD(old_prog->runtime.prog_fd);
    } else {
        r = bf_bpf_tc_link_create(prog_fd, new_prog->ifindex,
                                  bf_hook_to_attach_type(new_prog->hook),
                                  &link_fd);
        if (r)
            return bf_err_code(r,
                               "failed to create new link for TC bf_program");

        new_prog->runtime.prog_fd = TAKE_FD(link_fd);
    }

    return 0;
}

/**
 * Detach the TC BPF program.
 *
 * @param program Attached TC BPF program. Can't be NULL.
 * @return 0 on success, negative errno value on failure.
 */
static int _tc_detach_prog(struct bf_program *program)
{
    bf_assert(program);

    return bf_bpf_link_detach(program->runtime.prog_fd);
}