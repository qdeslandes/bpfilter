/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

struct bf_jmpctx;
struct bf_matcher_meta;
struct bf_program;

/**
 * Emit instructions to get a dynptr for an XDP program.
 *
 * Prepare arguments and call bpf_dynptr_from_xdp(). If the return value is
 * different from 0, jump to the end of the program and accept the packet.
 *
 * The initialised dynptr is stored in the program's runtime context.
 *
 * @param program Program to emit instructions into.
 * @param md_reg Scratch register containing the pointer to the xdp_md.
 * @return 0 on success, or negative errno value on error.
 */
int bf_stub_make_ctx_xdp_dynptr(struct bf_program *program, int md_reg);

/**
 * Emit instructions to get a dynptr for an XDP program.
 *
 * Prepare arguments and call bpf_dynptr_from_skb(). If the return value is
 * different from 0, jump to the end of the program and accept the packet.
 *
 * The initialised dynptr is stored in the program's runtime context.
 *
 * @param program Program to emit instructions into.
 * @param skb_reg Scratch register containing the pointer to the skb.
 * @return 0 on success, or negative errno value on error.
 */
int bf_stub_make_ctx_skb_dynptr(struct bf_program *program, int skb_reg);

/**
 * Emit instructions to get a dynptr slice for the packet's L3 header.
 *
 * This stub is used by flavors where the packet data starts at the L3 header
 * (no L2 header). The L3 header is processed the following way:
 * - Create a BPF dynamic pointer slice for the header. The size of the slice
 *   to request depends on the L3 protocol ID stored in @c r7
 * - If the slice creation fails, the error counter is updated and the
 *   program accepts the packet
 * - Once the slice has been requested, the L3 header is processed to extract
 *   the offset of the L4 header and the L4 protocol ID
 *
 * Besides storing the header address in `bf_runtime.l3_hdr`, this function
 * pins it in @c r6 for the program's lifetime: @c r6 is callee-saved, so it
 * survives every helper, kfunc, and ELF stub call on the match path.
 *
 * If the L3 protocol is not supported, the slice request and the L4
 * derivation are skipped, and the L3 protocol ID register is set to 0. On
 * that path @c r6 is left uninitialized: matchers must be guarded by an L3
 * protocol check on @c r7 before reading it.
 *
 * The L4 derivation stage is gated on the chain's flags: when the chain sets
 * neither @c BF_CHAIN_NEEDS_L4_HDR nor @c BF_CHAIN_NEEDS_L4_PROTO , it emits
 * nothing, @c r8 keeps its prologue-reset value of 0, and
 * `bf_runtime.l4_offset` is left unwritten.
 *
 * @param program Program to emit instructions into.
 * @return 0 on success, or negative errno value on error.
 */
int bf_stub_parse_l3_hdr(struct bf_program *program);

/**
 * Emit instructions to parse the packet's L2 Ethernet header and L3 header
 * from a single dynptr slice.
 *
 * A single `ETH_HLEN + BF_L3_SLICE_LEN` bytes slice is requested at the
 * beginning of the packet, covering the Ethernet header and the largest
 * supported L3 header, so both header pointers are derived from a single
 * kfunc call. If the packet is too short for the combined request (e.g. an
 * unpadded small IPv4 datagram on TC egress), the stub falls back to separate
 * L2 and L3 slice requests, preserving the exact semantics of the combined
 * path.
 *
 * On every path:
 * - The L3 header address is stored in `bf_runtime.l3_hdr` and pinned in
 *   @c r6 for the program's lifetime
 * - The L3 protocol ID (extracted from the ethertype field) is stored in
 *   @c r7 , and the L3 header is processed to extract the offset of the L4
 *   header and the L4 protocol ID
 * - If a slice request fails on the fallback path, the error counter is
 *   updated and the program accepts the packet
 *
 * `bf_runtime.l2_hdr`, `bf_runtime.l2_size`, and `bf_runtime.l3_size` are
 * only written when the chain logs packets ( @c BF_CHAIN_LOG ): the packet
 * logging ELF stub is their only consumer.
 *
 * If the L3 protocol is not supported, the L4 derivation is skipped and the
 * L3 protocol ID register is set to 0. On that path @c r6 might be left
 * uninitialized: matchers must be guarded by an L3 protocol check on @c r7
 * before reading it.
 *
 * The shared L4 derivation stage is gated on the chain's flags: when the
 * chain sets neither @c BF_CHAIN_NEEDS_L4_HDR nor @c BF_CHAIN_NEEDS_L4_PROTO ,
 * it emits nothing, @c r8 keeps its prologue-reset value of 0, and
 * `bf_runtime.l4_offset` is left unwritten.
 *
 * When the chain consumes the L4 header slice ( @c BF_CHAIN_NEEDS_L4_HDR ),
 * plain IPv4 packets (IHL == 5) on the combined-slice path take an L4 fast
 * path: the L4 protocol ID is normalized into @c r8 , @c r9 is pinned
 * `sizeof(struct iphdr)` bytes into the combined slice (whose remaining bytes
 * cover the full fixed L4 header of every supported protocol), and
 * `bf_runtime.l4_hdr` and `bf_runtime.l4_size` are written under the same
 * chain flags as @ref bf_stub_parse_l4_hdr . The fast path ends with a
 * forward jump stored in @p l4_done : the caller must close it after the
 * @ref bf_stub_parse_l4_hdr call, with no instruction emitted in between, so
 * the fast path skips the dedicated L4 slice request entirely. When the
 * chain doesn't consume the L4 header slice, no fast path is emitted and
 * @p l4_done is initialized to a no-op.
 *
 * @param program Program to emit instructions into.
 * @param l4_done Jump context over the dedicated L4 slice request,
 *        initialized by this function and closed by the caller. Can't be
 *        NULL.
 * @return 0 on success, or negative errno value on error.
 */
int bf_stub_parse_l2l3_hdr(struct bf_program *program,
                           struct bf_jmpctx *l4_done);

/**
 * Emit instructions to parse the packet's L2 Ethernet header and L3 header
 * through direct packet access, for XDP programs.
 *
 * Semantics mirror @ref bf_stub_parse_l2l3_hdr , but the combined L2+L3 slice
 * request is replaced with a single pointer bounds check: XDP programs loaded
 * without `BPF_F_XDP_HAS_FRAGS` have the whole packet directly accessible
 * through `xdp_md.data` and `xdp_md.data_end`, so no kfunc call is emitted on
 * the fast path. The dynptr creation becomes lazy: the dynptr is only created
 * on the slow paths that genuinely need it (packets too short for the
 * combined window, IPv4 with options, IPv6 with extension headers, and IPv6
 * packets too short for the direct L4 window), which then converge on the
 * slice-based L3 parsing and the shared L4 derivation.
 *
 * On entry, @c r2 must hold `xdp_md.data` and @c r3 `xdp_md.data_end`,
 * converted to packet pointers by the verifier. @c r3 is preserved across the
 * whole fast block: the IPv6 L4 fast path reuses it for its own bounds check.
 *
 * On the fast path, @c r6 (and @c r9 under @c BF_CHAIN_NEEDS_L4_HDR ) are
 * pinned as packet pointers with a verified range instead of slice pointers:
 * matchers load at generation-time-constant offsets within the checked range,
 * so their bytecode is unchanged. Unlike @ref bf_stub_parse_l2l3_hdr , the
 * `l3_hdr` store is gated on @c BF_CHAIN_LOG : the packet logging ELF stub
 * reads it through `bpf_probe_read_kernel()`, and the EH parsing ELF stubs
 * are only reachable through the slow paths, where the L3 slice request
 * overwrites `l3_hdr` with a slice pointer first.
 *
 * When the chain consumes the L4 header slice ( @c BF_CHAIN_NEEDS_L4_HDR ),
 * both plain IPv4 packets and IPv6 packets without extension headers derive
 * the L4 state inline and end with a forward jump stored in @p l4_done , with
 * the same contract as @ref bf_stub_parse_l2l3_hdr : the caller must close it
 * after the @ref bf_stub_parse_l4_hdr call, with no instruction emitted in
 * between.
 *
 * @warning This stub must not be used when the chain computes flow hashes
 * ( @c BF_CHAIN_FLOW_HASH ): the flow-hash ELF stub dereferences
 * `bf_runtime.l3_hdr` and `bf_runtime.l4_hdr` directly, so both must remain
 * dynptr slice pointers, not spilled packet pointers.
 *
 * @param program Program to emit instructions into. Can't be NULL.
 * @param l4_done Jump context over the dedicated L4 slice request,
 *        initialized by this function and closed by the caller. Can't be
 *        NULL.
 * @return 0 on success, or negative errno value on error.
 */
int bf_stub_parse_l2l3_hdr_direct(struct bf_program *program,
                                  struct bf_jmpctx *l4_done);

/**
 * Emit instructions to get a dynptr slice for the packet's L4 header.
 *
 * This function behaves similarly to @ref bf_stub_parse_l3_hdr but for the
 * L4 header, with the following differences:
 * - The size of the slice to request depends on the L4 protocol ID stored in @c r8
 * - There is no logic to process the L4 header and determine the L5 protocol
 *
 * The header address is pinned in @c r9 for the program's lifetime: @c r9 is
 * callee-saved, so it survives every helper, kfunc, and ELF stub call on the
 * match path. The address is also stored in `bf_runtime.l4_hdr` when the
 * packet logging or flow-hash ELF stubs consume it ( @c BF_CHAIN_LOG or
 * @c BF_CHAIN_FLOW_HASH ), and the header size in `bf_runtime.l4_size` under
 * @c BF_CHAIN_LOG only.
 *
 * If the L4 protocol is not supported, this function returns before requesting
 * a dynamic pointer slice, and the L4 protocol ID register is set to 0. On
 * that path @c r9 is left uninitialized: matchers must be guarded by an L4
 * protocol check on @c r8 before reading it.
 *
 * The emitted bytecode depends on the chain's flags:
 * - @c BF_CHAIN_NEEDS_L4_HDR: the full L4 parsing described above is emitted.
 * - @c BF_CHAIN_NEEDS_L4_PROTO only: @c r8 is reset to 0 for unsupported
 *   protocols, but no header slice is requested and @c r9,
 *   `bf_runtime.l4_hdr`, and `bf_runtime.l4_size` are left unwritten.
 * - Neither: no instruction is emitted, and @c r8 keeps the raw nexthdr value
 *   from the L3 parsing.
 *
 * @param program Program to emit instructions into.
 * @return 0 on success, or negative errno value on error.
 */
int bf_stub_parse_l4_hdr(struct bf_program *program);

/**
 * @brief Emit the instructions to check if the packet contains a specific
 *        protocol.
 *
 * This stub is emitted at the beginning of the first rule of a guard group,
 * to ensure the protocol the group's rules apply to is actually available in
 * the packet. On a protocol mismatch, the emitted jump resolves to the end of
 * the current guard group (see `bf_program.guard_group`), not to the next
 * rule: consecutive rules with the same guard signature are skipped as a
 * whole.
 *
 * @param program Program to emit the instructions into. Can't be NULL.
 * @param meta Metadata for the matcher type to apply. Can't be NULL.
 * @return 0 on success, or negative error value on error.
 */
int bf_stub_rule_check_protocol(struct bf_program *program,
                                const struct bf_matcher_meta *meta);

/**
 * @brief Return the register holding the pinned header address for a layer.
 *
 * The prologue parse stubs pin the L3 header address in `R6` and the L4
 * header address in `R9` for the program's lifetime, so matchers read header
 * fields directly from these registers. This function emits no instruction.
 *
 * @param meta Metadata for the matcher type to apply. Defines the layer to
 *        return the header register for. Can't be NULL.
 * @return Register number on success, or negative errno value on error.
 */
int bf_stub_hdr_reg(const struct bf_matcher_meta *meta);

/**
 * @brief Copy bytes from `src_reg + src_offset` to `R10 + dst_offset`.
 *
 * The access size per iteration is determined by checking alignment of both
 * source and destination offsets (both advance each iteration), picking the
 * largest width where both are aligned and remaining >= width.
 *
 * @param program Program to emit the instructions into. Can't be NULL.
 * @param src_reg Register holding the base address to read from.
 * @param src_offset Byte offset from `src_reg` to start reading from.
 * @param size Number of bytes to copy.
 * @param dst_offset Byte offset from `R10` (stack pointer) to write to. Use
 *        `BF_PROG_SCR_OFF()` for scratch area offsets.
 * @return 0 on success, or negative error value on error.
 */
int bf_stub_load(struct bf_program *program, int src_reg, size_t src_offset,
                 size_t size, int dst_offset);

int bf_stub_stx_payload(struct bf_program *program,
                        const struct bf_matcher_meta *meta, size_t offset);
