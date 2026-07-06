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
#include <stddef.h>

#include <bpfilter/ctx.h>
#include <bpfilter/elfstub.h>
#include <bpfilter/flavor.h>
#include <bpfilter/helper.h>
#include <bpfilter/matcher.h>
#include <bpfilter/verdict.h>

#include "cgen/jmp.h"
#include "cgen/printer.h"
#include "cgen/program.h"
#include "cgen/swich.h"
#include "filter.h"

#define _BF_LOW_EH_BITMASK 0x1801800000000801ULL

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
        EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
        EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(arg)));
        EMIT_LOAD_COUNTERS_FD_FIXUP(program, BPF_REG_2);
        EMIT(program,
             BPF_MOV32_IMM(BPF_REG_3, bf_program_error_counter_idx(program)));
        EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_UPDATE_COUNTERS);

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

/**
 * Emit instructions to get a dynptr slice for the packet's L2 Ethernet
 * header.
 *
 * The Ethernet header is processed the following way:
 * - Create a BPF dynamic pointer slice for the header.
 * - If the slice creation fails, the error counter is updated and the
 *   program accepts the packet
 * - The header address returned by @c bpf_dynptr_slice is stored in
 *   `bf_runtime.l2_hdr`, and the header size in `bf_runtime.l2_size`, only
 *   when the chain logs packets ( @c BF_CHAIN_LOG ): the packet logging ELF
 *   stub is their only consumer
 * - The L3 protocol ID (extracted from the ethertype field) is stored in @c r7
 * - The offset of the L3 header is stored in `bf_runtime.l3_offset`
 *
 * This stub is only used on the @ref bf_stub_parse_l2l3_hdr fallback path,
 * when the packet is too short for the combined L2+L3 slice request.
 *
 * @param program Program to emit instructions into.
 * @return 0 on success, or negative errno value on error.
 */
static int _bf_stub_parse_l2_ethhdr(struct bf_program *program)
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

    // l2_size is only read by the packet logging ELF stub
    if (program->runtime.chain->flags & BF_FLAG(BF_CHAIN_LOG)) {
        EMIT(program, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_4,
                                  BF_PROG_CTX_OFF(l2_size)));
    }

    EMIT_KFUNC_CALL(program, "bpf_dynptr_slice");

    // If the function call failed, quit the program
    {
        _clean_bf_jmpctx_ struct bf_jmpctx _ =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 0));

        // Update the error counter
        EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
        EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(arg)));
        EMIT_LOAD_COUNTERS_FD_FIXUP(program, BPF_REG_2);
        EMIT(program,
             BPF_MOV32_IMM(BPF_REG_3, bf_program_error_counter_idx(program)));
        EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_UPDATE_COUNTERS);

        if (bf_ctx_is_verbose(BF_VERBOSE_BPF))
            EMIT_PRINT(program, "failed to create L2 dynamic pointer slice");

        r = program->runtime.ops->get_verdict(BF_VERDICT_ACCEPT, &ret_code);
        if (r)
            return r;

        EMIT(program, BPF_MOV64_IMM(BPF_REG_0, ret_code));
        EMIT(program, BPF_EXIT_INSN());
    }

    // l2_hdr is only read by the packet logging ELF stub
    if (program->runtime.chain->flags & BF_FLAG(BF_CHAIN_LOG)) {
        EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0,
                                  BF_PROG_CTX_OFF(l2_hdr)));
    }

    // Store the L3 protocol ID in r7
    EMIT(program, BPF_LDX_MEM(BPF_H, BPF_REG_7, BPF_REG_0,
                              offsetof(struct ethhdr, h_proto)));

    // Set bf_runtime.l3_offset
    EMIT(program, BPF_ST_MEM(BPF_W, BPF_REG_10, BF_PROG_CTX_OFF(l3_offset),
                             sizeof(struct ethhdr)));

    return 0;
}

/**
 * @brief Emit the L3 header slice request.
 *
 * The size of the requested slice depends on the L3 protocol ID stored in
 * @c r7 : 20 bytes for IPv4, 40 bytes for IPv6. For any other protocol, @c r7
 * is set to 0 and @p skip is initialized with a jump over the slice request:
 * the caller is responsible for closing @p skip , so the jump can span the L4
 * derivation logic emitted after this stub.
 *
 * The slice offset is read from `bf_runtime.l3_offset`. On success, the
 * header address is stored in `bf_runtime.l3_hdr` and pinned in @c r6 . If
 * the slice request fails, the error counter is updated and the program
 * accepts the packet.
 *
 * @param program Program to emit instructions into. Can't be NULL.
 * @param skip Jump context for the unsupported L3 protocol case, initialized
 *        by this function and closed by the caller. Can't be NULL.
 * @return 0 on success, or negative errno value on error.
 */
static int _bf_stub_slice_l3(struct bf_program *program, struct bf_jmpctx *skip)
{
    int ret_code;
    int r;

    assert(program);
    assert(skip);

    /* Store the size of the L3 protocol header in r4, depending on the protocol
     * ID stored in r7. If the protocol is not supported, we store 0 into r7
     * and we skip the instructions below. */
    {
        _clean_bf_swich_ struct bf_swich swich =
            bf_swich_get(program, BPF_REG_7);

        EMIT_SWICH_OPTION(&swich, htobe16(ETH_P_IP),
                          BPF_MOV64_IMM(BPF_REG_4, sizeof(struct iphdr)));
        EMIT_SWICH_OPTION(&swich, htobe16(ETH_P_IPV6),
                          BPF_MOV64_IMM(BPF_REG_4, sizeof(struct ipv6hdr)));
        EMIT_SWICH_DEFAULT(&swich, BPF_MOV64_IMM(BPF_REG_7, 0));

        r = bf_swich_generate(&swich);
        if (r)
            return r;
    }
    *skip = bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_7, 0, 0));

    // Call bpf_dynptr_slice()
    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(dynptr)));
    EMIT(program,
         BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, BF_PROG_CTX_OFF(l3_offset)));
    EMIT(program, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, BF_PROG_CTX_OFF(l2)));
    EMIT_KFUNC_CALL(program, "bpf_dynptr_slice");

    // If the function call failed, quit the program
    {
        _clean_bf_jmpctx_ struct bf_jmpctx _ =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 0));

        EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
        EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(arg)));
        EMIT_LOAD_COUNTERS_FD_FIXUP(program, BPF_REG_2);
        EMIT(program,
             BPF_MOV32_IMM(BPF_REG_3, bf_program_error_counter_idx(program)));
        EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_UPDATE_COUNTERS);

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

    /* Pin the L3 header address in r6 for the program's lifetime: r6 is
     * callee-saved, so it survives every helper, kfunc, and ELF stub call
     * emitted on the match path. */
    EMIT(program, BPF_MOV64_REG(BPF_REG_6, BPF_REG_0));

    return 0;
}

/**
 * @brief Emit the L4 offset and protocol derivation from the L3 header.
 *
 * The L3 header is read through @c r6 , pinned by the slice stage. Depending
 * on the L3 protocol ID stored in @c r7 :
 * - IPv4: the L4 offset is computed from the IHL field, and the L4 protocol
 *   ID is stored in @c r8 .
 * - IPv6: the next header value is stored in @c r8 ; if extension headers are
 *   present, the EH parsing ELF stub is called to locate the L4 header.
 *
 * `bf_runtime.l4_offset` is updated on both paths: the L4 slice request and
 * the EH parsing ELF stubs read it. `bf_runtime.l3_size` is only written when
 * the chain logs packets ( @c BF_CHAIN_LOG ): the packet logging ELF stub is
 * its only consumer.
 * Callers must ensure this stub is only reached when @c r7 contains a
 * supported L3 protocol ID (IPv4 or IPv6) and @c r6 points to the L3 header.
 *
 * @param program Program to emit instructions into. Can't be NULL.
 * @param l3_offset Offset of the L3 header in the packet, known at generation
 *        time: `ETH_HLEN` for flavors with an L2 header, 0 otherwise. The EH
 *        parsing ELF stubs read `bf_runtime.l3_offset`, so the context field
 *        must be populated with the same value.
 * @return 0 on success, or negative errno value on error.
 */
static int _bf_stub_derive_l4(struct bf_program *program, uint32_t l3_offset)
{
    assert(program);

    {
        // IPv4
        _clean_bf_jmpctx_ struct bf_jmpctx _ = bf_jmpctx_get(
            program, BPF_JMP_IMM(BPF_JNE, BPF_REG_7, htobe16(ETH_P_IP), 0));

        if (program->runtime.chain->flags & BF_FLAG(BF_CHAIN_LOG)) {
            EMIT(program,
                 BPF_ST_MEM(BPF_B, BPF_REG_10, BF_PROG_CTX_OFF(l3_size),
                            sizeof(struct iphdr)));
        }
        EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_6, 0));
        EMIT(program, BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0x0f));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 2));
        if (l3_offset)
            EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, l3_offset));
        EMIT(program, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1,
                                  BF_PROG_CTX_OFF(l4_offset)));
        EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_8, BPF_REG_6,
                                  offsetof(struct iphdr, protocol)));
    }

    {
        // IPv6
        struct bf_jmpctx tcpjmp, udpjmp, noehjmp, ehjmp;
        struct bpf_insn ld64[2] = {BPF_LD_IMM64(BPF_REG_2, _BF_LOW_EH_BITMASK)};
        _clean_bf_jmpctx_ struct bf_jmpctx _ = bf_jmpctx_get(
            program, BPF_JMP_IMM(BPF_JNE, BPF_REG_7, htobe16(ETH_P_IPV6), 0));

        if (program->runtime.chain->flags & BF_FLAG(BF_CHAIN_LOG)) {
            EMIT(program,
                 BPF_ST_MEM(BPF_B, BPF_REG_10, BF_PROG_CTX_OFF(l3_size),
                            sizeof(struct ipv6hdr)));
        }
        EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_8, BPF_REG_6,
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

        // Process IPv6 header, no EH (BPF_REG_8 already contains nexthdr)
        EMIT(program, BPF_ST_MEM(BPF_W, BPF_REG_10, BF_PROG_CTX_OFF(l4_offset),
                                 l3_offset + sizeof(struct ipv6hdr)));

        bf_jmpctx_cleanup(&ehjmp);
    }

    return 0;
}

int bf_stub_parse_l3_hdr(struct bf_program *program)
{
    _clean_bf_jmpctx_ struct bf_jmpctx skip = bf_jmpctx_default();
    int r;

    assert(program);

    r = _bf_stub_slice_l3(program, &skip);
    if (r)
        return r;

    // The L3 header is located at the very beginning of the packet data
    return _bf_stub_derive_l4(program, 0);
}

int bf_stub_parse_l2l3_hdr(struct bf_program *program)
{
    _clean_bf_jmpctx_ struct bf_jmpctx l3skip = bf_jmpctx_default();
    struct bf_jmpctx shortjmp, ip4jmp, ip6jmp, endjmp;
    int r;

    assert(program);

    /* Request a single slice covering the Ethernet header and the largest
     * supported L3 header: any Ethernet frame carrying a full IPv6 header,
     * and any frame padded to the Ethernet minimum size, satisfies the
     * request, so both header pointers are derived from a single kfunc call.
     * The bounce buffer spans the contiguous l2 and l3 runtime context areas
     * (see the static_assert in cgen/runtime.h). */
    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(dynptr)));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_2, 0));
    EMIT(program, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, BF_PROG_CTX_OFF(l2)));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_4, ETH_HLEN + BF_L3_SLICE_LEN));
    EMIT_KFUNC_CALL(program, "bpf_dynptr_slice");

    /* A NULL slice is not an error here: the packet is smaller than
     * ETH_HLEN + BF_L3_SLICE_LEN bytes, fall back to separate L2 and L3
     * slice requests. */
    shortjmp = bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0));

    /* l2_hdr and l2_size are only read by the packet logging ELF stub: skip
     * the stores when the chain doesn't log packets. */
    if (program->runtime.chain->flags & BF_FLAG(BF_CHAIN_LOG)) {
        EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0,
                                  BF_PROG_CTX_OFF(l2_hdr)));
        EMIT(program,
             BPF_ST_MEM(BPF_B, BPF_REG_10, BF_PROG_CTX_OFF(l2_size), ETH_HLEN));
    }

    // Store the L3 protocol ID in r7
    EMIT(program, BPF_LDX_MEM(BPF_H, BPF_REG_7, BPF_REG_0,
                              offsetof(struct ethhdr, h_proto)));

    // Set bf_runtime.l3_offset
    EMIT(program,
         BPF_ST_MEM(BPF_W, BPF_REG_10, BF_PROG_CTX_OFF(l3_offset), ETH_HLEN));

    /* Pin the L3 header address in r6 for the program's lifetime and store it
     * into the runtime context. */
    EMIT(program, BPF_MOV64_REG(BPF_REG_6, BPF_REG_0));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, ETH_HLEN));
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_6, BF_PROG_CTX_OFF(l3_hdr)));

    /* Supported L3 protocols jump over the fallback block, straight to the
     * L4 derivation. Unsupported protocols set r7 to 0 (matching the swich
     * default semantics of the fallback) and jump to the end of the stub. */
    ip4jmp = bf_jmpctx_get(
        program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_7, htobe16(ETH_P_IP), 0));
    ip6jmp = bf_jmpctx_get(
        program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_7, htobe16(ETH_P_IPV6), 0));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_7, 0));
    endjmp = bf_jmpctx_get(program, BPF_JMP_A(0));

    // Fallback for short packets: separate L2 and L3 slice requests
    bf_jmpctx_cleanup(&shortjmp);

    r = _bf_stub_parse_l2_ethhdr(program);
    if (r)
        return r;

    r = _bf_stub_slice_l3(program, &l3skip);
    if (r)
        return r;

    // Both paths converge on the shared L4 derivation stage
    bf_jmpctx_cleanup(&ip4jmp);
    bf_jmpctx_cleanup(&ip6jmp);

    r = _bf_stub_derive_l4(program, ETH_HLEN);
    if (r)
        return r;

    bf_jmpctx_cleanup(&endjmp);

    return 0;
}

int bf_stub_parse_l4_hdr(struct bf_program *program)
{
    _clean_bf_jmpctx_ struct bf_jmpctx _ = bf_jmpctx_default();
    uint8_t flags;
    int ret_code;
    int r;

    assert(program);

    flags = program->runtime.chain->flags;

    /* If no rule reads the L4 header slice nor the normalized L4 protocol ID,
     * skip the L4 parsing entirely: r8 keeps the raw nexthdr value from the L3
     * parsing, and r9, l4_hdr, and l4_size are left unwritten. */
    if (!(flags &
          (BF_FLAG(BF_CHAIN_NEEDS_L4_HDR) | BF_FLAG(BF_CHAIN_NEEDS_L4_PROTO))))
        return 0;

    /* If only the normalized L4 protocol ID is read, reset r8 to 0 for
     * unsupported protocols but skip the header slice request. */
    if (!(flags & BF_FLAG(BF_CHAIN_NEEDS_L4_HDR))) {
        _clean_bf_jmpctx_ struct bf_jmpctx j0 = bf_jmpctx_get(
            program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, IPPROTO_TCP, 0));
        _clean_bf_jmpctx_ struct bf_jmpctx j1 = bf_jmpctx_get(
            program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, IPPROTO_UDP, 0));
        _clean_bf_jmpctx_ struct bf_jmpctx j2 = bf_jmpctx_get(
            program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, IPPROTO_ICMP, 0));
        _clean_bf_jmpctx_ struct bf_jmpctx j3 = bf_jmpctx_get(
            program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, IPPROTO_ICMPV6, 0));

        EMIT(program, BPF_MOV64_IMM(BPF_REG_8, 0));

        return 0;
    }

    /* Parse the L4 protocol and handle unuspported protocol, similarly to
     * bf_stub_parse_l3_hdr() above. */
    {
        _clean_bf_swich_ struct bf_swich swich =
            bf_swich_get(program, BPF_REG_8);

        EMIT_SWICH_OPTION(&swich, IPPROTO_TCP,
                          BPF_MOV64_IMM(BPF_REG_4, sizeof(struct tcphdr)));
        EMIT_SWICH_OPTION(&swich, IPPROTO_UDP,
                          BPF_MOV64_IMM(BPF_REG_4, sizeof(struct udphdr)));
        EMIT_SWICH_OPTION(&swich, IPPROTO_ICMP,
                          BPF_MOV64_IMM(BPF_REG_4, sizeof(struct icmphdr)));
        EMIT_SWICH_OPTION(&swich, IPPROTO_ICMPV6,
                          BPF_MOV64_IMM(BPF_REG_4, sizeof(struct icmp6hdr)));
        EMIT_SWICH_DEFAULT(&swich, BPF_MOV64_IMM(BPF_REG_8, 0));

        r = bf_swich_generate(&swich);
        if (r)
            return r;
    }
    _ = bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 0, 0));

    // l4_size is only read by the packet logging ELF stub
    if (flags & BF_FLAG(BF_CHAIN_LOG)) {
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

        EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
        EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(arg)));
        EMIT_LOAD_COUNTERS_FD_FIXUP(program, BPF_REG_2);
        EMIT(program,
             BPF_MOV32_IMM(BPF_REG_3, bf_program_error_counter_idx(program)));
        EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_UPDATE_COUNTERS);

        if (bf_ctx_is_verbose(BF_VERBOSE_BPF))
            EMIT_PRINT(program, "failed to create L4 dynamic pointer slice");

        r = program->runtime.ops->get_verdict(BF_VERDICT_ACCEPT, &ret_code);
        if (r)
            return r;

        EMIT(program, BPF_MOV64_IMM(BPF_REG_0, ret_code));
        EMIT(program, BPF_EXIT_INSN());
    }

    /* l4_hdr is only read by the packet logging and flow-hash ELF stubs:
     * matchers use the pinned r9 instead. */
    if (flags & (BF_FLAG(BF_CHAIN_LOG) | BF_FLAG(BF_CHAIN_FLOW_HASH))) {
        EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0,
                                  BF_PROG_CTX_OFF(l4_hdr)));
    }

    // Pin the L4 header address in r9 for the program's lifetime
    EMIT(program, BPF_MOV64_REG(BPF_REG_9, BPF_REG_0));

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

int bf_stub_hdr_reg(const struct bf_matcher_meta *meta)
{
    assert(meta);

    switch (meta->layer) {
    case BF_MATCHER_LAYER_3:
        return BPF_REG_6;
    case BF_MATCHER_LAYER_4:
        return BPF_REG_9;
    default:
        return bf_err_r(-EINVAL, "layer ID %d has no pinned header register",
                        meta->layer);
    }
}

int bf_stub_load(struct bf_program *program, int src_reg, size_t src_offset,
                 size_t size, int dst_offset)
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

        EMIT(program, BPF_LDX_MEM(bpf_size, BPF_REG_1, src_reg, src_off));
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
    int src_reg;

    assert(program);
    assert(meta);

    src_reg = bf_stub_hdr_reg(meta);
    if (src_reg < 0)
        return src_reg;

    return bf_stub_load(program, src_reg, meta->hdr_payload_offset,
                        meta->hdr_payload_size, BF_PROG_SCR_OFF(offset));
}
