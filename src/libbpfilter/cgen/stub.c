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

/* bf_stub_parse_l2l3_hdr_direct() checks the packet against a two-tier
 * direct-access window: the full ETH_HLEN + BF_L3_SLICE_LEN combined window
 * (sized for the fixed IPv6 header) first, then, on its miss, the IPv4
 * short-packet salvage with per-protocol L4 bounds, leaving the slice
 * fallback to packets missing both.
 *
 * Maximum number of fast-path escapes converging on the slow entry of
 * bf_stub_parse_l2l3_hdr_direct(): IPv4 with options, the IPv6 low extension
 * header bitmask hit, the three individual >64 extension header checks, and
 * the IPv6 L4 bounds check failure. */
#define _BF_DIRECT_SLOW_JMPS_MAX 6

/* Maximum number of salvage escapes converging on the slice fallback of
 * bf_stub_parse_l2l3_hdr_direct(): the fixed IPv4 header bounds check, the
 * ethertype check, the IHL check, and the per-protocol L4 bounds check. */
#define _BF_DIRECT_FB_JMPS_MAX 4

/* Maximum number of jumps converging on the l4_done jump of
 * bf_stub_parse_l2l3_hdr_direct(): the IPv4 and IPv6 unsupported-L4-protocol
 * escapes, the IPv4 fast-path exit, the IPv6 fast-path jump over the salvage,
 * and the salvage's unsupported-L4-protocol escape. */
#define _BF_DIRECT_DONE_JMPS_MAX 5

/* Maximum number of jumps converging on the end of
 * bf_stub_parse_l2l3_hdr_direct(), reached on both chain variants:
 * L3-only chains emit the two supported-ethertype checks, the
 * unsupported-ethertype jump, and the salvage exit; L4-proto-only chains
 * emit the unsupported-ethertype jump, the IPv4 and IPv6 raw-protocol
 * exits, and the salvage exit. */
#define _BF_DIRECT_END_JMPS_MAX 4

/* The IPv4 L4 fast paths in bf_stub_parse_l2l3_hdr() and
 * bf_stub_parse_l2l3_hdr_direct() pin r9 into the combined L2+L3 window
 * (dynptr slice or bounds-checked packet area) instead of requesting a
 * dedicated L4 slice: this is only sound while the fixed IPv4 header plus the
 * largest supported fixed L4 header fit within the window past ETH_HLEN. */
static_assert(sizeof(struct iphdr) + sizeof(struct tcphdr) <= BF_L3_SLICE_LEN,
              "fixed IPv4 + TCP headers must fit in the L3 slice area");

/* The IPv6 L4 fast path in bf_stub_parse_l2l3_hdr_direct() bounds-checks a
 * single sizeof(struct tcphdr) window past the fixed IPv6 header before
 * pinning r9: it is only sound while no supported L4 protocol has a larger
 * fixed header. The IPv4 short-packet salvage doesn't rely on this
 * assumption: its L4 bounds are per-protocol by construction. */
static_assert(sizeof(struct udphdr) <= sizeof(struct tcphdr) &&
                  sizeof(struct icmphdr) <= sizeof(struct tcphdr) &&
                  sizeof(struct icmp6hdr) <= sizeof(struct tcphdr),
              "TCP must have the largest supported fixed L4 header");

/* The meta.sport and meta.dport matchers read their field from the pinned r9
 * at the tcphdr offsets recorded in their `bf_matcher_meta`, under the dual
 * TCP/UDP guard of bf_stub_rule_check_l4_dual(): this is only sound while
 * both headers store their port fields at the same offsets. */
static_assert(offsetof(struct tcphdr, source) ==
                      offsetof(struct udphdr, source) &&
                  offsetof(struct tcphdr, dest) ==
                      offsetof(struct udphdr, dest),
              "TCP and UDP headers must share their port field offsets");

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
        r = program->runtime.ops->gen_inline_get_pkt_size(program);
        if (r)
            return r;

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
 * This stub is only used on the short-packet fallback paths of
 * @ref bf_stub_parse_l2l3_hdr and @ref bf_stub_parse_l2l3_hdr_direct , when
 * the packet doesn't cover the combined L2+L3 window.
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
        r = program->runtime.ops->gen_inline_get_pkt_size(program);
        if (r)
            return r;

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

        // Update the error counter
        r = program->runtime.ops->gen_inline_get_pkt_size(program);
        if (r)
            return r;

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
 * The emitted bytecode depends on the chain's flags, mirroring
 * @ref bf_stub_parse_l4_hdr :
 * - Neither @c BF_CHAIN_NEEDS_L4_HDR nor @c BF_CHAIN_NEEDS_L4_PROTO : no
 *   instruction is emitted, @c r8 keeps its prologue-reset value of 0, and
 *   `bf_runtime.l4_offset` is left unwritten.
 * - @c BF_CHAIN_NEEDS_L4_PROTO only: the L4 protocol ID is derived into
 *   @c r8 , but no L4 slice request follows, so `bf_runtime.l4_offset` is
 *   dead: the offset computation and its stack store are skipped. The EH
 *   parsing ELF stubs still write `l4_offset` as their own loop state.
 * - @c BF_CHAIN_NEEDS_L4_HDR : the full derivation described above is
 *   emitted, including the `bf_runtime.l4_offset` store read by the L4 slice
 *   request.
 *
 * `bf_runtime.l3_size` is only written when the chain logs packets
 * ( @c BF_CHAIN_LOG ): the packet logging ELF stub is its only consumer.
 * Callers must ensure this stub is only reached when @c r7 contains a
 * supported L3 protocol ID (IPv4 or IPv6) and @c r6 points to the L3 header.
 *
 * When the chain consumes the L4 header slice ( @c BF_CHAIN_NEEDS_L4_HDR ),
 * plain IPv4 packets (IHL == 5) on the combined-slice path of
 * @ref bf_stub_parse_l2l3_hdr bypass this stage entirely: the fast path
 * emitted there derives the L4 state without going through the L4 offset.
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
    uint8_t flags;

    assert(program);

    flags = program->runtime.chain->flags;

    /* If no rule reads the L4 header slice nor the normalized L4 protocol ID,
     * skip the L4 derivation entirely: r8 keeps its prologue-reset value of 0,
     * and l4_offset is left unwritten. */
    if (!(flags &
          (BF_FLAG(BF_CHAIN_NEEDS_L4_HDR) | BF_FLAG(BF_CHAIN_NEEDS_L4_PROTO))))
        return 0;

    {
        // IPv4
        _clean_bf_jmpctx_ struct bf_jmpctx _ = bf_jmpctx_get(
            program, BPF_JMP_IMM(BPF_JNE, BPF_REG_7, htobe16(ETH_P_IP), 0));

        if (flags & BF_FLAG(BF_CHAIN_LOG)) {
            EMIT(program,
                 BPF_ST_MEM(BPF_B, BPF_REG_10, BF_PROG_CTX_OFF(l3_size),
                            sizeof(struct iphdr)));
        }

        /* l4_offset is only read by the L4 slice request: when no rule reads
         * the L4 header slice, skip the IHL-based offset computation and its
         * stack store. The protocol field sits at a fixed offset, independent
         * of the IHL. */
        if (flags & BF_FLAG(BF_CHAIN_NEEDS_L4_HDR)) {
            EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_6, 0));
            EMIT(program, BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0x0f));
            EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 2));
            if (l3_offset)
                EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, l3_offset));
            EMIT(program, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1,
                                      BF_PROG_CTX_OFF(l4_offset)));
        }
        EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_8, BPF_REG_6,
                                  offsetof(struct iphdr, protocol)));
    }

    {
        // IPv6
        struct bf_jmpctx tcpjmp, udpjmp, noehjmp, ehjmp;
        struct bpf_insn ld64[2] = {BPF_LD_IMM64(BPF_REG_2, _BF_LOW_EH_BITMASK)};
        _clean_bf_jmpctx_ struct bf_jmpctx _ = bf_jmpctx_get(
            program, BPF_JMP_IMM(BPF_JNE, BPF_REG_7, htobe16(ETH_P_IPV6), 0));

        if (flags & BF_FLAG(BF_CHAIN_LOG)) {
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
        if (flags & BF_FLAG(BF_CHAIN_STORE_NEXTHDR))
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
         * l4_offset is only read by the L4 slice request: skip the store when
         * no rule reads the L4 header slice. The EH parsing ELF stubs write
         * l4_offset themselves as their own loop state. */
        if (flags & BF_FLAG(BF_CHAIN_NEEDS_L4_HDR)) {
            EMIT(program,
                 BPF_ST_MEM(BPF_W, BPF_REG_10, BF_PROG_CTX_OFF(l4_offset),
                            l3_offset + sizeof(struct ipv6hdr)));
        }

        bf_jmpctx_cleanup(&ehjmp);
    }

    return 0;
}

/**
 * @brief Emit the compare-chain form of the L4 protocol normalization.
 *
 * Same @c r8 normalization semantics as the swich shape used by
 * @ref bf_stub_parse_l4_hdr : @c r8 is left untouched when it holds a
 * supported L4 protocol ID, and zeroed otherwise. Supported protocols land on
 * the first instruction emitted after this helper returns; unsupported
 * protocols go through @p miss , which the caller closes past its @c r9
 * pinning block, preserving the r9-written-only-behind-a-supported-r8
 * invariant relied upon by the per-rule L4 guards.
 *
 * Unlike the swich, this form doesn't select the L4 header size into @c r4 :
 * it is only valid when the size register is dead, i.e. when the chain
 * doesn't store `bf_runtime.l4_size` ( @c BF_CHAIN_LOG unset) and no slice
 * request consumes the size.
 *
 * @param program Program to emit instructions into. Can't be NULL.
 * @param miss Jump context for the unsupported L4 protocol case, initialized
 *        by this function and closed by the caller. Can't be NULL.
 * @return 0 on success, or negative errno value on error.
 */
static int _bf_stub_normalize_l4_proto(struct bf_program *program,
                                       struct bf_jmpctx *miss)
{
    static const int protos[] = {IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP,
                                 IPPROTO_ICMPV6};
    struct bf_jmpctx matchjmps[ARRAY_SIZE(protos)];

    assert(program);
    assert(miss);

    for (size_t i = 0; i < ARRAY_SIZE(protos); ++i) {
        matchjmps[i] = bf_jmpctx_get(
            program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, protos[i], 0));
    }

    EMIT(program, BPF_MOV64_IMM(BPF_REG_8, 0));
    *miss = bf_jmpctx_get(program, BPF_JMP_A(0));

    for (size_t i = 0; i < ARRAY_SIZE(protos); ++i)
        bf_jmpctx_cleanup(&matchjmps[i]);

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

int bf_stub_parse_l2l3_hdr(struct bf_program *program,
                           struct bf_jmpctx *l4_done)
{
    _clean_bf_jmpctx_ struct bf_jmpctx l3skip = bf_jmpctx_default();
    struct bf_jmpctx slowjmp = bf_jmpctx_default();
    struct bf_jmpctx shortjmp, ip4jmp, ip6jmp, endjmp;
    bool l4_fast_path;
    int r;

    assert(program);
    assert(l4_done);

    /* The IPv4 L4 fast path is only emitted when a rule reads the L4 header
     * slice: otherwise no L4 slice request follows this stub, and there is
     * nothing for l4_done to jump over. */
    l4_fast_path =
        program->runtime.chain->flags & BF_FLAG(BF_CHAIN_NEEDS_L4_HDR);
    *l4_done = (struct bf_jmpctx)bf_jmpctx_default();

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

    if (!l4_fast_path) {
        /* Supported L3 protocols jump over the fallback block, straight to
         * the L4 derivation. Unsupported protocols set r7 to 0 (matching the
         * swich default semantics of the fallback) and jump to the end of the
         * stub. */
        ip4jmp = bf_jmpctx_get(
            program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_7, htobe16(ETH_P_IP), 0));
        ip6jmp = bf_jmpctx_get(
            program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_7, htobe16(ETH_P_IPV6), 0));
        EMIT(program, BPF_MOV64_IMM(BPF_REG_7, 0));
        endjmp = bf_jmpctx_get(program, BPF_JMP_A(0));
    } else {
        struct bf_jmpctx zerojmp;

        /* IPv6 jumps over the fallback block, straight to the L4 derivation;
         * IPv4 jumps to the fast path below. Unsupported protocols set r7 to
         * 0 (matching the swich default semantics of the fallback) and jump
         * to the end of the stub. */
        ip6jmp = bf_jmpctx_get(
            program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_7, htobe16(ETH_P_IPV6), 0));
        ip4jmp = bf_jmpctx_get(
            program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_7, htobe16(ETH_P_IP), 0));
        EMIT(program, BPF_MOV64_IMM(BPF_REG_7, 0));
        endjmp = bf_jmpctx_get(program, BPF_JMP_A(0));

        /* IPv4 L4 fast path: for a plain 20-byte IPv4 header, the combined
         * slice bytes remaining past the L3 header cover the full fixed L4
         * header of every supported protocol (see the static_assert above),
         * so r9 is derived from r6 and the dedicated L4 slice request in
         * bf_stub_parse_l4_hdr() is jumped over through l4_done. */
        bf_jmpctx_cleanup(&ip4jmp);

        /* The shared L4 derivation stage is bypassed, so its l3_size store
         * must be replicated. l3_size is only read by the packet logging ELF
         * stub. */
        if (program->runtime.chain->flags & BF_FLAG(BF_CHAIN_LOG)) {
            EMIT(program,
                 BPF_ST_MEM(BPF_B, BPF_REG_10, BF_PROG_CTX_OFF(l3_size),
                            sizeof(struct iphdr)));
        }

        /* Anything but a plain 20-byte IPv4 header (options, malformed
         * version nibble) goes through the shared L4 derivation and the
         * dedicated L4 slice request. */
        EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_6, 0));
        slowjmp = bf_jmpctx_get(
            program, BPF_JMP_IMM(BPF_JNE, BPF_REG_1, (IPVERSION << 4) | 5, 0));

        EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_8, BPF_REG_6,
                                  offsetof(struct iphdr, protocol)));

        /* Same r8 normalization semantics as bf_stub_parse_l4_hdr(), relied
         * upon by meta.l4_proto and the per-rule L4 guards: r8 is untouched
         * for supported L4 protocols, zeroed otherwise, and r9 is only
         * written behind a supported r8. Logging chains keep the swich shape,
         * as the header size it selects into r4 feeds the l4_size store; on
         * other chains the size register is dead and the compare-chain form
         * is emitted instead. */
        if (program->runtime.chain->flags & BF_FLAG(BF_CHAIN_LOG)) {
            _clean_bf_swich_ struct bf_swich swich =
                bf_swich_get(program, BPF_REG_8);

            EMIT_SWICH_OPTION(&swich, IPPROTO_TCP,
                              BPF_MOV64_IMM(BPF_REG_4, sizeof(struct tcphdr)));
            EMIT_SWICH_OPTION(&swich, IPPROTO_UDP,
                              BPF_MOV64_IMM(BPF_REG_4, sizeof(struct udphdr)));
            EMIT_SWICH_OPTION(&swich, IPPROTO_ICMP,
                              BPF_MOV64_IMM(BPF_REG_4, sizeof(struct icmphdr)));
            EMIT_SWICH_OPTION(
                &swich, IPPROTO_ICMPV6,
                BPF_MOV64_IMM(BPF_REG_4, sizeof(struct icmp6hdr)));
            EMIT_SWICH_DEFAULT(&swich, BPF_MOV64_IMM(BPF_REG_8, 0));

            r = bf_swich_generate(&swich);
            if (r)
                return r;

            /* Unsupported L4 protocols skip the r9 pinning, as in
             * bf_stub_parse_l4_hdr(): r9 stays unwritten, and the per-rule L4
             * guards on r8 keep the matchers unreachable on this path. */
            zerojmp =
                bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 0, 0));

            // l4_size is only read by the packet logging ELF stub
            EMIT(program, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_4,
                                      BF_PROG_CTX_OFF(l4_size)));
        } else {
            r = _bf_stub_normalize_l4_proto(program, &zerojmp);
            if (r)
                return r;
        }

        // Pin the L4 header address in r9 for the program's lifetime
        EMIT(program, BPF_MOV64_REG(BPF_REG_9, BPF_REG_6));
        EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, sizeof(struct iphdr)));

        /* l4_hdr is only read by the packet logging ELF stub: matchers use
         * the pinned r9 instead. */
        if (program->runtime.chain->flags & BF_FLAG(BF_CHAIN_LOG)) {
            EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_9,
                                      BF_PROG_CTX_OFF(l4_hdr)));
        }

        bf_jmpctx_cleanup(&zerojmp);
        *l4_done = bf_jmpctx_get(program, BPF_JMP_A(0));
    }

    // Fallback for short packets: separate L2 and L3 slice requests
    bf_jmpctx_cleanup(&shortjmp);

    r = _bf_stub_parse_l2_ethhdr(program);
    if (r)
        return r;

    r = _bf_stub_slice_l3(program, &l3skip);
    if (r)
        return r;

    /* Both paths converge on the shared L4 derivation stage. On the fast
     * path, ip4jmp is already closed and only IPv4 headers with options
     * reach this stage, through slowjmp. */
    if (!l4_fast_path)
        bf_jmpctx_cleanup(&ip4jmp);
    bf_jmpctx_cleanup(&ip6jmp);
    bf_jmpctx_cleanup(&slowjmp);

    r = _bf_stub_derive_l4(program, ETH_HLEN);
    if (r)
        return r;

    bf_jmpctx_cleanup(&endjmp);

    return 0;
}

/**
 * @brief Emit the IPv4 short-packet salvage block of
 *        @ref bf_stub_parse_l2l3_hdr_direct .
 *
 * The direct parsing's combined bounds check is sized for the fixed IPv6
 * header (ETH_HLEN + BF_L3_SLICE_LEN bytes), but a plain IPv4 packet only
 * needs ETH_HLEN + sizeof(struct iphdr) bytes of direct access, plus its
 * protocol's fixed L4 header when the chain consumes the L4 header slice.
 * This block runs on the combined check's miss and re-checks the packet
 * against these smaller, protocol-aware bounds, keeping short plain IPv4
 * packets (minimal ICMP messages, empty UDP datagrams) on direct packet
 * access instead of the slice fallback and its three kfunc calls.
 *
 * On entry, @c r2 and @c r3 must still hold `xdp_md.data` and
 * `xdp_md.data_end` from the stub's entry. Escapes for packets the block
 * can't salvage (too short for the fixed IPv4 header, non-IPv4 ethertype,
 * IPv4 options, packet not covering the protocol's fixed L4 header) are
 * appended to @p fbjmps , which the caller closes on the slice fallback.
 * Salvaged packets join the main fast paths: through @p endjmps when the
 * chain doesn't read the L4 header slice, or by falling through toward the
 * caller's l4_done jump otherwise, with the unsupported-L4-protocol escape
 * appended to @p donejmps .
 *
 * @param program Program to emit instructions into. Can't be NULL.
 * @param fbjmps Escapes to the slice fallback, appended to by this function
 *        and closed by the caller. Can't be NULL.
 * @param n_fb Number of entries in @p fbjmps . Can't be NULL.
 * @param endjmps Jumps to the end of the stub, appended to by this function
 *        and closed by the caller. Can't be NULL.
 * @param n_end Number of entries in @p endjmps . Can't be NULL.
 * @param donejmps Jumps to the caller's l4_done jump, appended to by this
 *        function and closed by the caller. Can't be NULL.
 * @param n_done Number of entries in @p donejmps . Can't be NULL.
 * @return 0 on success, or negative errno value on error.
 */
static int _bf_stub_direct_ip4_salvage(struct bf_program *program,
                                       struct bf_jmpctx *fbjmps, size_t *n_fb,
                                       struct bf_jmpctx *endjmps, size_t *n_end,
                                       struct bf_jmpctx *donejmps,
                                       size_t *n_done)
{
    uint8_t flags;
    bool needs_l4;
    int r;

    assert(program);
    assert(fbjmps);
    assert(n_fb);
    assert(endjmps);
    assert(n_end);
    assert(donejmps);
    assert(n_done);

    flags = program->runtime.chain->flags;
    needs_l4 = flags & (BF_FLAG(BF_CHAIN_NEEDS_L4_HDR) |
                        BF_FLAG(BF_CHAIN_NEEDS_L4_PROTO));

    /* Packets too short for the ethertype plus a full fixed IPv4 header keep
     * the slice fallback behavior, r7 left unloaded: the fallback's L2 slice
     * re-reads the ethertype. r2 and r3 still hold data and data_end from the
     * stub's entry, as the failed combined bounds check only clobbered r4. */
    EMIT(program, BPF_MOV64_REG(BPF_REG_4, BPF_REG_2));
    EMIT(program,
         BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, ETH_HLEN + sizeof(struct iphdr)));
    fbjmps[(*n_fb)++] =
        bf_jmpctx_get(program, BPF_JMP_REG(BPF_JGT, BPF_REG_4, BPF_REG_3, 0));

    // Store the L3 protocol ID in r7
    EMIT(program, BPF_LDX_MEM(BPF_H, BPF_REG_7, BPF_REG_2,
                              offsetof(struct ethhdr, h_proto)));

    /* Only IPv4 fits its fixed L3 header below the combined window: an IPv6
     * packet this short can't hold its fixed header, so it goes through the
     * slice fallback, whose L3 slice request fails into the
     * error-counter/accept path. */
    fbjmps[(*n_fb)++] = bf_jmpctx_get(
        program, BPF_JMP_IMM(BPF_JNE, BPF_REG_7, htobe16(ETH_P_IP), 0));

    // Pin the L3 header address in r6 for the program's lifetime
    EMIT(program, BPF_MOV64_REG(BPF_REG_6, BPF_REG_2));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, ETH_HLEN));

    /* Same BF_CHAIN_LOG-gated stores as the main fast path. l3_offset stays
     * unwritten, as only the slow paths read it: they are entered through the
     * slice fallback, where _bf_stub_parse_l2_ethhdr() stores it. */
    if (flags & BF_FLAG(BF_CHAIN_LOG)) {
        EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2,
                                  BF_PROG_CTX_OFF(l2_hdr)));
        EMIT(program,
             BPF_ST_MEM(BPF_B, BPF_REG_10, BF_PROG_CTX_OFF(l2_size), ETH_HLEN));
        EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_6,
                                  BF_PROG_CTX_OFF(l3_hdr)));
    }

    if (!needs_l4) {
        /* No rule consumes L4 state: nothing left to derive, jump to the end
         * of the stub with r7 holding the supported ethertype, as on the main
         * fast path. */
        endjmps[(*n_end)++] = bf_jmpctx_get(program, BPF_JMP_A(0));
        return 0;
    }

    // l3_size is only read by the packet logging ELF stub
    if (flags & BF_FLAG(BF_CHAIN_LOG)) {
        EMIT(program, BPF_ST_MEM(BPF_B, BPF_REG_10, BF_PROG_CTX_OFF(l3_size),
                                 sizeof(struct iphdr)));
    }

    if (!(flags & BF_FLAG(BF_CHAIN_NEEDS_L4_HDR))) {
        /* Only the normalized L4 protocol ID is consumed: load the raw
         * protocol (fixed offset, independent of the IHL) and let the
         * normalization chain in bf_stub_parse_l4_hdr() run after the stub,
         * as on the main fast path. */
        EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_8, BPF_REG_6,
                                  offsetof(struct iphdr, protocol)));
        endjmps[(*n_end)++] = bf_jmpctx_get(program, BPF_JMP_A(0));
        return 0;
    }

    /* IPv4 options on a packet too short for the combined window go through
     * the slice fallback: lazy dynptr creation, L3 slice request, shared L4
     * derivation, and dedicated L4 slice request. */
    EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_6, 0));
    fbjmps[(*n_fb)++] = bf_jmpctx_get(
        program, BPF_JMP_IMM(BPF_JNE, BPF_REG_1, (IPVERSION << 4) | 5, 0));

    EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_8, BPF_REG_6,
                              offsetof(struct iphdr, protocol)));

    /* Same r8 normalization semantics as bf_stub_parse_l4_hdr(): r8 is
     * untouched for supported L4 protocols, zeroed otherwise, and r9 is only
     * written behind a supported r8. The swich shape is used regardless of
     * BF_CHAIN_LOG: the header size it selects into r4 feeds the
     * per-protocol bounds check below, so the size register is never dead
     * here and the compare-chain form doesn't apply. */
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

    /* Unsupported L4 protocols skip the bounds check and the r9 pinning,
     * going through l4_done as on the main fast paths: r9 stays unwritten,
     * and the per-rule L4 guards on r8 keep the matchers unreachable on this
     * path. */
    donejmps[(*n_done)++] =
        bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 0, 0));

    /* Per-protocol bounds check: the packet only has to cover its own fixed
     * L4 header past the fixed IPv4 header, not a window sized for the
     * largest one. Packets failing it (e.g. truncated TCP) reach the slice
     * fallback, where the dedicated L4 slice request fails into the
     * error-counter/accept path. */
    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, sizeof(struct iphdr)));
    EMIT(program, BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_4));
    fbjmps[(*n_fb)++] =
        bf_jmpctx_get(program, BPF_JMP_REG(BPF_JGT, BPF_REG_1, BPF_REG_3, 0));

    // l4_size is only read by the packet logging ELF stub
    if (flags & BF_FLAG(BF_CHAIN_LOG)) {
        EMIT(program, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_4,
                                  BF_PROG_CTX_OFF(l4_size)));
    }

    /* Pin the L4 header address in r9 for the program's lifetime: the
     * per-protocol bounds check above covers the protocol's fixed L4 header
     * past the fixed IPv4 header. */
    EMIT(program, BPF_MOV64_REG(BPF_REG_9, BPF_REG_6));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, sizeof(struct iphdr)));

    /* l4_hdr is only read by the packet logging ELF stub: matchers use the
     * pinned r9 instead. */
    if (flags & BF_FLAG(BF_CHAIN_LOG)) {
        EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_9,
                                  BF_PROG_CTX_OFF(l4_hdr)));
    }

    // Fall through into the caller's l4_done jump
    return 0;
}

int bf_stub_parse_l2l3_hdr_direct(struct bf_program *program,
                                  struct bf_jmpctx *l4_done)
{
    _clean_bf_jmpctx_ struct bf_jmpctx l3skip = bf_jmpctx_default();
    struct bf_jmpctx slowjmps[_BF_DIRECT_SLOW_JMPS_MAX] = {};
    struct bf_jmpctx fbjmps[_BF_DIRECT_FB_JMPS_MAX] = {};
    struct bf_jmpctx donejmps[_BF_DIRECT_DONE_JMPS_MAX] = {};
    struct bf_jmpctx endjmps[_BF_DIRECT_END_JMPS_MAX] = {};
    struct bf_jmpctx shortjmp, tailjmp, ip4jmp, ip6jmp, tcpjmp, udpjmp;
    size_t n_slow = 0;
    size_t n_fb = 0;
    size_t n_done = 0;
    size_t n_end = 0;
    bool needs_l4;
    uint8_t flags;
    int r;

    assert(program);
    assert(l4_done);

    flags = program->runtime.chain->flags;
    needs_l4 = flags & (BF_FLAG(BF_CHAIN_NEEDS_L4_HDR) |
                        BF_FLAG(BF_CHAIN_NEEDS_L4_PROTO));
    *l4_done = (struct bf_jmpctx)bf_jmpctx_default();

    /* Combined bounds check, substituting for the combined L2+L3 slice
     * request: past this check, ETH_HLEN + BF_L3_SLICE_LEN bytes are directly
     * accessible from r2, the same window the combined slice provides on the
     * dynptr path. Packets too short for the window go through the IPv4
     * short-packet salvage below before falling back to the slice-based
     * parsing. */
    EMIT(program, BPF_MOV64_REG(BPF_REG_4, BPF_REG_2));
    EMIT(program,
         BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, ETH_HLEN + BF_L3_SLICE_LEN));
    shortjmp =
        bf_jmpctx_get(program, BPF_JMP_REG(BPF_JGT, BPF_REG_4, BPF_REG_3, 0));

    // Store the L3 protocol ID in r7
    EMIT(program, BPF_LDX_MEM(BPF_H, BPF_REG_7, BPF_REG_2,
                              offsetof(struct ethhdr, h_proto)));

    /* Pin the L3 header address in r6 for the program's lifetime: matchers
     * load at generation-time-constant offsets covered by the bounds check
     * above, so a packet pointer behaves exactly like a slice pointer. */
    EMIT(program, BPF_MOV64_REG(BPF_REG_6, BPF_REG_2));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, ETH_HLEN));

    /* l2_hdr, l2_size, and l3_hdr are only read by the packet logging ELF
     * stub on this path: it copies the headers with bpf_probe_read_kernel(),
     * which accepts a spilled packet pointer as well as a slice pointer. The
     * EH parsing ELF stubs also dereference l3_hdr, but they are only
     * reachable through the slow paths, where _bf_stub_slice_l3() overwrites
     * it with a slice pointer first. */
    if (flags & BF_FLAG(BF_CHAIN_LOG)) {
        EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2,
                                  BF_PROG_CTX_OFF(l2_hdr)));
        EMIT(program,
             BPF_ST_MEM(BPF_B, BPF_REG_10, BF_PROG_CTX_OFF(l2_size), ETH_HLEN));
        EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_6,
                                  BF_PROG_CTX_OFF(l3_hdr)));
    }

    if (!needs_l4) {
        /* No rule consumes L4 state: supported protocols keep r7 and fall to
         * the end of the stub, unsupported protocols set r7 to 0 (matching
         * the swich default semantics of the slice-based parsing). */
        endjmps[n_end++] = bf_jmpctx_get(
            program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_7, htobe16(ETH_P_IP), 0));
        endjmps[n_end++] = bf_jmpctx_get(
            program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_7, htobe16(ETH_P_IPV6), 0));
        EMIT(program, BPF_MOV64_IMM(BPF_REG_7, 0));
        endjmps[n_end++] = bf_jmpctx_get(program, BPF_JMP_A(0));
    } else {
        /* IPv6 jumps to its own L4 handling block below; IPv4 jumps to the
         * fast path right after this dispatch. Unsupported protocols set r7
         * to 0 (matching the swich default semantics of the slice-based
         * parsing) and jump to the end of the stub. */
        ip6jmp = bf_jmpctx_get(
            program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_7, htobe16(ETH_P_IPV6), 0));
        ip4jmp = bf_jmpctx_get(
            program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_7, htobe16(ETH_P_IP), 0));
        EMIT(program, BPF_MOV64_IMM(BPF_REG_7, 0));
        endjmps[n_end++] = bf_jmpctx_get(program, BPF_JMP_A(0));

        // IPv4 L4 handling
        bf_jmpctx_cleanup(&ip4jmp);

        // l3_size is only read by the packet logging ELF stub
        if (flags & BF_FLAG(BF_CHAIN_LOG)) {
            EMIT(program,
                 BPF_ST_MEM(BPF_B, BPF_REG_10, BF_PROG_CTX_OFF(l3_size),
                            sizeof(struct iphdr)));
        }

        if (flags & BF_FLAG(BF_CHAIN_NEEDS_L4_HDR)) {
            /* Anything but a plain 20-byte IPv4 header (options, malformed
             * version nibble) goes through the slow path: lazy dynptr
             * creation, L3 slice request, shared L4 derivation, and dedicated
             * L4 slice request. */
            EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_6, 0));
            slowjmps[n_slow++] =
                bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BPF_REG_1,
                                                   (IPVERSION << 4) | 5, 0));

            EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_8, BPF_REG_6,
                                      offsetof(struct iphdr, protocol)));

            /* Same r8 normalization semantics as bf_stub_parse_l4_hdr(),
             * relied upon by meta.l4_proto and the per-rule L4 guards: r8 is
             * untouched for supported L4 protocols, zeroed otherwise, and r9
             * is only written behind a supported r8. Unsupported protocols
             * skip the r9 pinning but still go through l4_done, as
             * bf_stub_parse_l4_hdr() has nothing left to do for them.
             * Logging chains keep the swich shape, as the header size it
             * selects into r4 feeds the l4_size store; on other chains the
             * size register is dead and the compare-chain form is emitted
             * instead. */
            if (flags & BF_FLAG(BF_CHAIN_LOG)) {
                _clean_bf_swich_ struct bf_swich swich =
                    bf_swich_get(program, BPF_REG_8);

                EMIT_SWICH_OPTION(
                    &swich, IPPROTO_TCP,
                    BPF_MOV64_IMM(BPF_REG_4, sizeof(struct tcphdr)));
                EMIT_SWICH_OPTION(
                    &swich, IPPROTO_UDP,
                    BPF_MOV64_IMM(BPF_REG_4, sizeof(struct udphdr)));
                EMIT_SWICH_OPTION(
                    &swich, IPPROTO_ICMP,
                    BPF_MOV64_IMM(BPF_REG_4, sizeof(struct icmphdr)));
                EMIT_SWICH_OPTION(
                    &swich, IPPROTO_ICMPV6,
                    BPF_MOV64_IMM(BPF_REG_4, sizeof(struct icmp6hdr)));
                EMIT_SWICH_DEFAULT(&swich, BPF_MOV64_IMM(BPF_REG_8, 0));

                r = bf_swich_generate(&swich);
                if (r)
                    return r;

                donejmps[n_done++] = bf_jmpctx_get(
                    program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 0, 0));

                // l4_size is only read by the packet logging ELF stub
                EMIT(program, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_4,
                                          BF_PROG_CTX_OFF(l4_size)));
            } else {
                r = _bf_stub_normalize_l4_proto(program, &donejmps[n_done++]);
                if (r)
                    return r;
            }

            /* Pin the L4 header address in r9 for the program's lifetime:
             * the combined bounds check covers the full fixed L4 header past
             * the fixed IPv4 header (see the static_assert above). */
            EMIT(program, BPF_MOV64_REG(BPF_REG_9, BPF_REG_6));
            EMIT(program,
                 BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, sizeof(struct iphdr)));

            /* l4_hdr is only read by the packet logging ELF stub: matchers
             * use the pinned r9 instead. */
            if (flags & BF_FLAG(BF_CHAIN_LOG)) {
                EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_9,
                                          BF_PROG_CTX_OFF(l4_hdr)));
            }

            donejmps[n_done++] = bf_jmpctx_get(program, BPF_JMP_A(0));
        } else {
            /* Only the normalized L4 protocol ID is consumed: load the raw
             * protocol (fixed offset, independent of the IHL) and let the
             * normalization chain in bf_stub_parse_l4_hdr() run after the
             * stub, as on the slice-based path. */
            EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_8, BPF_REG_6,
                                      offsetof(struct iphdr, protocol)));
            endjmps[n_end++] = bf_jmpctx_get(program, BPF_JMP_A(0));
        }

        // IPv6 L4 handling
        bf_jmpctx_cleanup(&ip6jmp);

        // l3_size is only read by the packet logging ELF stub
        if (flags & BF_FLAG(BF_CHAIN_LOG)) {
            EMIT(program,
                 BPF_ST_MEM(BPF_B, BPF_REG_10, BF_PROG_CTX_OFF(l3_size),
                            sizeof(struct ipv6hdr)));
        }

        EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_8, BPF_REG_6,
                                  offsetof(struct ipv6hdr, nexthdr)));

        /* Same EH detection sequence as _bf_stub_derive_l4(), with two
         * differences: packets carrying an extension header jump to the slow
         * path (the EH parsing ELF stubs need the dynptr), and the bitmask
         * uses r1/r4 as scratch registers to preserve data_end in r3. The
         * tcpjmp and udpjmp escapes are closed by the L4 handling blocks
         * below, past the normalization when it is an identity for TCP and
         * UDP. */
        {
            struct bpf_insn ld64[2] = {
                BPF_LD_IMM64(BPF_REG_1, _BF_LOW_EH_BITMASK)};

            /* Fast path for TCP and UDP: quickly recognize the most used
             * protocols to process them as fast as possible. */
            tcpjmp = bf_jmpctx_get(
                program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, IPPROTO_TCP, 0));
            udpjmp = bf_jmpctx_get(
                program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, IPPROTO_UDP, 0));

            /* For all the EH protocol numbers <64, use a bitmask:
             * mask = (1<<0) | (1<<43) | (1<<44) | (1<<50) | (1<<51) | (1<<60)
             *
             * Pseudo-code:
             * - r4 = 1 << r8 (nexthdr)
             * - r4 = r4 & mask
             * - if r4 != 0: go to slow path (EH present) */
            EMIT(program, ld64[0]);
            EMIT(program, ld64[1]);
            EMIT(program, BPF_JMP_IMM(BPF_JGE, BPF_REG_8, 64, 4));
            EMIT(program, BPF_MOV64_IMM(BPF_REG_4, 1));
            EMIT(program, BPF_ALU64_REG(BPF_LSH, BPF_REG_4, BPF_REG_8));
            EMIT(program, BPF_ALU64_REG(BPF_AND, BPF_REG_4, BPF_REG_1));
            slowjmps[n_slow++] =
                bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BPF_REG_4, 0, 0));

            // EH with protocol numbers >64 are processed individually
            slowjmps[n_slow++] =
                bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 135, 0));
            slowjmps[n_slow++] =
                bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 139, 0));
            slowjmps[n_slow++] =
                bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 140, 0));
        }

        if (flags & BF_FLAG(BF_CHAIN_NEEDS_L4_HDR)) {
            struct bf_jmpctx okjmp;

            /* Same r8 normalization semantics as bf_stub_parse_l4_hdr(),
             * relied upon by meta.l4_proto and the per-rule L4 guards: r8 is
             * untouched for supported L4 protocols, zeroed otherwise, and r9
             * is only written behind a supported r8. Unsupported protocols
             * skip the bounds check and the r9 pinning, going through l4_done
             * as on the IPv4 fast path. Logging chains keep the swich shape,
             * as the header size it selects into r4 feeds the l4_size store;
             * on other chains the size register is dead and the compare-chain
             * form is emitted instead. */
            if (flags & BF_FLAG(BF_CHAIN_LOG)) {
                /* If no EH matched, nexthdr is L4: TCP and UDP go through
                 * the swich too, as it selects their header size into r4. */
                bf_jmpctx_cleanup(&tcpjmp);
                bf_jmpctx_cleanup(&udpjmp);

                {
                    _clean_bf_swich_ struct bf_swich swich =
                        bf_swich_get(program, BPF_REG_8);

                    EMIT_SWICH_OPTION(
                        &swich, IPPROTO_TCP,
                        BPF_MOV64_IMM(BPF_REG_4, sizeof(struct tcphdr)));
                    EMIT_SWICH_OPTION(
                        &swich, IPPROTO_UDP,
                        BPF_MOV64_IMM(BPF_REG_4, sizeof(struct udphdr)));
                    EMIT_SWICH_OPTION(
                        &swich, IPPROTO_ICMP,
                        BPF_MOV64_IMM(BPF_REG_4, sizeof(struct icmphdr)));
                    EMIT_SWICH_OPTION(
                        &swich, IPPROTO_ICMPV6,
                        BPF_MOV64_IMM(BPF_REG_4, sizeof(struct icmp6hdr)));
                    EMIT_SWICH_DEFAULT(&swich, BPF_MOV64_IMM(BPF_REG_8, 0));

                    r = bf_swich_generate(&swich);
                    if (r)
                        return r;
                }

                donejmps[n_done++] = bf_jmpctx_get(
                    program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 0, 0));
            } else {
                r = _bf_stub_normalize_l4_proto(program, &donejmps[n_done++]);
                if (r)
                    return r;

                /* TCP and UDP escape the EH detection straight to the
                 * compare chain's match target: r8 already holds a supported
                 * protocol on those paths, so the normalization is an
                 * identity for them. */
                bf_jmpctx_cleanup(&tcpjmp);
                bf_jmpctx_cleanup(&udpjmp);
            }

            /* Second bounds check: the combined window ends exactly at the
             * end of the fixed IPv6 header, so the L4 window is checked
             * separately, against the largest supported fixed L4 header (see
             * the static_assert above). r3 still holds data_end, untouched
             * since the stub's entry. */
            EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
            EMIT(program,
                 BPF_ALU64_IMM(BPF_ADD, BPF_REG_1,
                               sizeof(struct ipv6hdr) + sizeof(struct tcphdr)));
            okjmp = bf_jmpctx_get(
                program, BPF_JMP_REG(BPF_JLE, BPF_REG_1, BPF_REG_3, 0));

            /* The packet is too short for the direct L4 window: store the L4
             * offset and let the dedicated L4 slice request take over on the
             * slow path. */
            EMIT(program,
                 BPF_ST_MEM(BPF_W, BPF_REG_10, BF_PROG_CTX_OFF(l4_offset),
                            ETH_HLEN + sizeof(struct ipv6hdr)));
            slowjmps[n_slow++] = bf_jmpctx_get(program, BPF_JMP_A(0));

            bf_jmpctx_cleanup(&okjmp);

            // l4_size is only read by the packet logging ELF stub
            if (flags & BF_FLAG(BF_CHAIN_LOG)) {
                EMIT(program, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_4,
                                          BF_PROG_CTX_OFF(l4_size)));
            }

            // Pin the L4 header address in r9 for the program's lifetime
            EMIT(program, BPF_MOV64_REG(BPF_REG_9, BPF_REG_6));
            EMIT(program,
                 BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, sizeof(struct ipv6hdr)));

            /* l4_hdr is only read by the packet logging ELF stub: matchers
             * use the pinned r9 instead. */
            if (flags & BF_FLAG(BF_CHAIN_LOG)) {
                EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_9,
                                          BF_PROG_CTX_OFF(l4_hdr)));
            }

            /* Both combined-window L4 fast paths jump over the IPv4
             * short-packet salvage below, into the l4_done jump emitted past
             * it. */
            donejmps[n_done++] = bf_jmpctx_get(program, BPF_JMP_A(0));
        } else {
            // If no EH matched, nexthdr is L4
            bf_jmpctx_cleanup(&tcpjmp);
            bf_jmpctx_cleanup(&udpjmp);

            /* r8 holds the raw nexthdr value, normalized by the chain in
             * bf_stub_parse_l4_hdr() after the stub. */
            endjmps[n_end++] = bf_jmpctx_get(program, BPF_JMP_A(0));
        }
    }

    /* IPv4 short-packet salvage: the combined window is sized for the fixed
     * IPv6 header, so plain IPv4 packets shorter than
     * ETH_HLEN + BF_L3_SLICE_LEN bytes fail the combined bounds check even
     * though ETH_HLEN + sizeof(struct iphdr) bytes (plus the protocol's fixed
     * L4 header when the chain consumes L4 state) are enough for direct
     * access. Re-check the packet against these smaller, protocol-aware
     * bounds before surrendering to the slice fallback below. */
    bf_jmpctx_cleanup(&shortjmp);

    r = _bf_stub_direct_ip4_salvage(program, fbjmps, &n_fb, endjmps, &n_end,
                                    donejmps, &n_done);
    if (r)
        return r;

    if (flags & BF_FLAG(BF_CHAIN_NEEDS_L4_HDR)) {
        /* All L4 fast paths (combined-window IPv4 and IPv6, salvaged IPv4)
         * fall through or jump into the l4_done jump, over the dedicated L4
         * slice request. */
        for (size_t i = 0; i < n_done; ++i)
            bf_jmpctx_cleanup(&donejmps[i]);
        *l4_done = bf_jmpctx_get(program, BPF_JMP_A(0));
    }

    /* Slice fallback: the packet missed both direct-access windows. Create
     * the dynptr (skipped on the fast paths) and fall back to separate L2 and
     * L3 slice requests, preserving the exact semantics of the slice-based
     * parsing. */
    for (size_t i = 0; i < n_fb; ++i)
        bf_jmpctx_cleanup(&fbjmps[i]);

    EMIT(program,
         BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, BF_PROG_CTX_OFF(arg)));
    r = _bf_stub_make_ctx_dynptr(program, BPF_REG_1, "bpf_dynptr_from_xdp");
    if (r)
        return r;

    r = _bf_stub_parse_l2_ethhdr(program);
    if (r)
        return r;

    if (needs_l4) {
        /* Slow entry for the fast-path escapes (IPv4 options, IPv6 extension
         * headers, IPv6 packets too short for the direct L4 window): r7
         * already holds a supported ethertype, this block stores l3_offset
         * and creates the missing dynptr. The slice fallback path above jumps
         * over both, having gone through _bf_stub_parse_l2_ethhdr() (which
         * stores l3_offset itself) and the first dynptr creation. */
        tailjmp = bf_jmpctx_get(program, BPF_JMP_A(0));

        for (size_t i = 0; i < n_slow; ++i)
            bf_jmpctx_cleanup(&slowjmps[i]);

        /* Set bf_runtime.l3_offset, read by the L3 slice request and the EH
         * parsing ELF stubs on the slow paths. The fast path never reads it,
         * so the store is deferred to this block. */
        EMIT(program, BPF_ST_MEM(BPF_W, BPF_REG_10, BF_PROG_CTX_OFF(l3_offset),
                                 ETH_HLEN));

        EMIT(program,
             BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, BF_PROG_CTX_OFF(arg)));
        r = _bf_stub_make_ctx_dynptr(program, BPF_REG_1, "bpf_dynptr_from_xdp");
        if (r)
            return r;

        bf_jmpctx_cleanup(&tailjmp);
    }

    /* All the fallback paths converge on the slice-based L3 parsing and the
     * shared L4 derivation: _bf_stub_slice_l3() re-pins r6 as a slice pointer
     * and overwrites l3_hdr, so every consumer of stored header pointers on
     * the slow paths sees slice memory, exactly as on the dynptr path. */
    r = _bf_stub_slice_l3(program, &l3skip);
    if (r)
        return r;

    r = _bf_stub_derive_l4(program, ETH_HLEN);
    if (r)
        return r;

    for (size_t i = 0; i < n_end; ++i)
        bf_jmpctx_cleanup(&endjmps[i]);

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

        // Update the error counter
        r = program->runtime.ops->gen_inline_get_pkt_size(program);
        if (r)
            return r;

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

    /* l4_hdr is only read by the packet logging ELF stub: matchers use the
     * pinned r9 instead. */
    if (flags & BF_FLAG(BF_CHAIN_LOG)) {
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
        EMIT_FIXUP_JMP_GUARD_MISS(
            program, BPF_JMP_IMM(BPF_JNE, BPF_REG_7,
                                 htobe16((uint16_t)meta->hdr_id), 0));
        break;
    case BF_MATCHER_LAYER_4:
        EMIT_FIXUP_JMP_GUARD_MISS(
            program, BPF_JMP_IMM(BPF_JNE, BPF_REG_8, (uint8_t)meta->hdr_id, 0));
        break;
    default:
        return bf_err_r(-EINVAL, "rule can't check for layer ID %d",
                        meta->layer);
    }

    return 0;
}

int bf_stub_rule_check_l4_dual(struct bf_program *program)
{
    assert(program);

    /* r8 is normalized by the prologue (0 for unsupported protocols), and r9
     * is pinned whenever r8 holds a supported L4 protocol: past these two
     * jumps, reading the L4 header from r9 is sound, exactly as behind a
     * specific L4 guard. */
    EMIT(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, IPPROTO_TCP, 1));
    EMIT_FIXUP_JMP_GUARD_MISS(program,
                              BPF_JMP_IMM(BPF_JNE, BPF_REG_8, IPPROTO_UDP, 0));

    return 0;
}

int bf_stub_hdr_reg(const struct bf_matcher_meta *meta)
{
    assert(meta);

    if (meta->l4_dual)
        return BPF_REG_9;

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
