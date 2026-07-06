/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include "cgen/matcher/cmp.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <bpfilter/logger.h>
#include <bpfilter/matcher.h>

#include "cgen/jmp.h"
#include "cgen/program.h"

uint8_t bf_cmp_get_jmp_ins(const struct bf_matcher *matcher)
{
    bool continue_on_equal;

    assert(matcher);

    switch (bf_matcher_get_op(matcher)) {
    case BF_MATCHER_EQ:
    case BF_MATCHER_ALL:
        continue_on_equal = true;
        break;
    case BF_MATCHER_ANY:
    case BF_MATCHER_IN:
        continue_on_equal = false;
        break;
    default:
        bf_abort("invalid matcher op to get jmp instruction %d",
                 bf_matcher_get_op(matcher));
    }

    continue_on_equal ^= bf_matcher_get_negate(matcher);

    return continue_on_equal ? BPF_JNE : BPF_JEQ;
}

#define _BF_MASK_LAST_BYTE 15

static inline uint64_t _bf_read_u64(const void *ptr)
{
    uint64_t val;

    memcpy(&val, ptr, sizeof(val));

    return val;
}

/**
 * @brief Compute a network prefix mask.
 *
 * @param prefixlen Prefix length in bits.
 * @param mask Output buffer. Can't be NULL.
 * @param mask_len Size of mask buffer in bytes (4 or 16).
 */
static void _bf_prefix_to_mask(unsigned int prefixlen, uint8_t *mask,
                               size_t mask_len)
{
    assert(mask);

    memset(mask, 0x00, mask_len);
    memset(mask, 0xff, prefixlen / 8);
    if (prefixlen % 8)
        mask[prefixlen / 8] = (0xff << (8 - (prefixlen % 8))) & 0xff;
}

int bf_cmp_value(struct bf_program *program, const struct bf_matcher *matcher,
                 const void *ref, unsigned int size, int reg)
{
    enum bf_matcher_op op = bf_matcher_get_op(matcher);
    uint8_t jmp_op;

    assert(program);
    assert(matcher);
    assert(ref);

    if (op != BF_MATCHER_EQ)
        return bf_err_r(-EINVAL, "unsupported operator %d", op);

    jmp_op = bf_cmp_get_jmp_ins(matcher);

    switch (size) {
    case 1:
    case 2: {
        /* Small values: compare directly via JMP_IMM.
         * For size 1, ref is uint8_t; for size 2, ref is uint16_t.
         * Both fit in a signed 32-bit immediate. */
        uint32_t val =
            (size == 1) ? *(const uint8_t *)ref : *(const uint16_t *)ref;

        EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP_IMM(jmp_op, reg, val, 0));
        break;
    }
    case 4: {
        /* 32-bit values: `reg` is loaded with `LDX_MEM(BPF_W)` which
         * zero-extends, so a JMP32 immediate compare matches the full
         * unsigned 32-bit pattern exactly. */
        uint32_t val = *(const uint32_t *)ref;

        EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP32_IMM(jmp_op, reg, val, 0));
        break;
    }
    case 8: {
        /* 64-bit values: load the immediate in R2 with `LD_IMM64` (2
         * instruction slots, 1 executed instruction), then compare with
         * `JMP_REG`. */
        struct bpf_insn ld64[2] = {BPF_LD_IMM64(BPF_REG_2, _bf_read_u64(ref))};

        EMIT(program, ld64[0]);
        EMIT(program, ld64[1]);
        EMIT_FIXUP_JMP_NEXT_RULE(program,
                                 BPF_JMP_REG(jmp_op, reg, BPF_REG_2, 0));
        break;
    }
    case 16: {
        /* 128-bit values: reg holds low 64 bits, reg+1 holds high 64 bits.
         * Compare each half against the reference, loaded in R3 with
         * `LD_IMM64`. */
        const uint8_t *addr = ref;
        struct bpf_insn ld64_lo[2] = {
            BPF_LD_IMM64(BPF_REG_3, _bf_read_u64(addr))};
        struct bpf_insn ld64_hi[2] = {
            BPF_LD_IMM64(BPF_REG_3, _bf_read_u64(addr + 8))};

        EMIT(program, ld64_lo[0]);
        EMIT(program, ld64_lo[1]);

        if (jmp_op == BPF_JNE) {
            EMIT_FIXUP_JMP_NEXT_RULE(program,
                                     BPF_JMP_REG(BPF_JNE, reg, BPF_REG_3, 0));

            EMIT(program, ld64_hi[0]);
            EMIT(program, ld64_hi[1]);
            EMIT_FIXUP_JMP_NEXT_RULE(
                program, BPF_JMP_REG(BPF_JNE, reg + 1, BPF_REG_3, 0));
        } else {
            /* JEQ: the address must differ in at least one half.
             * If the first half differs, the matcher matched — jump
             * past the second half check and the unconditional
             * jump-to-next-rule. If the first half matches, check the
             * second half: if it also matches, the full address is
             * equal, so the matcher fails — jump to next rule. */
            _clean_bf_jmpctx_ struct bf_jmpctx j0 = bf_jmpctx_default();
            _clean_bf_jmpctx_ struct bf_jmpctx j1 = bf_jmpctx_default();

            j0 =
                bf_jmpctx_get(program, BPF_JMP_REG(BPF_JNE, reg, BPF_REG_3, 0));

            EMIT(program, ld64_hi[0]);
            EMIT(program, ld64_hi[1]);
            j1 = bf_jmpctx_get(program,
                               BPF_JMP_REG(BPF_JNE, reg + 1, BPF_REG_3, 0));

            EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP_A(0));
        }
        break;
    }
    default:
        return bf_err_r(-EINVAL, "unsupported comparison size %u", size);
    }

    return 0;
}

int bf_cmp_masked_value(struct bf_program *program,
                        const struct bf_matcher *matcher, const void *ref,
                        unsigned int prefixlen, unsigned int size, int reg)
{
    enum bf_matcher_op op = bf_matcher_get_op(matcher);
    uint8_t jmp_op;

    assert(program);
    assert(matcher);
    assert(ref);

    if (op != BF_MATCHER_EQ)
        return bf_err_r(-EINVAL, "unsupported operator %d", op);

    jmp_op = bf_cmp_get_jmp_ins(matcher);

    switch (size) {
    case 4: {
        uint32_t mask;
        const uint32_t *addr = ref;
        uint32_t masked_ref;

        _bf_prefix_to_mask(prefixlen, (uint8_t *)&mask, 4);
        masked_ref = *addr & mask;

        /* The reference value is masked at codegen time; only the loaded
         * field needs masking at runtime, and only for partial prefixes. */
        if (mask != ~0U)
            EMIT(program, BPF_ALU32_IMM(BPF_AND, reg, mask));

        EMIT_FIXUP_JMP_NEXT_RULE(program,
                                 BPF_JMP32_IMM(jmp_op, reg, masked_ref, 0));
        break;
    }
    case 16: {
        uint8_t mask[16];
        uint8_t masked_lo[8], masked_hi[8];
        const uint8_t *addr = ref;

        _bf_prefix_to_mask(prefixlen, mask, 16);

        // Apply mask to loaded reg/reg+1 if not a full /128
        if (mask[_BF_MASK_LAST_BYTE] != (uint8_t)~0) {
            struct bpf_insn mask_lo[2] = {
                BPF_LD_IMM64(BPF_REG_3, _bf_read_u64(mask))};
            struct bpf_insn mask_hi[2] = {
                BPF_LD_IMM64(BPF_REG_3, _bf_read_u64(mask + 8))};

            EMIT(program, mask_lo[0]);
            EMIT(program, mask_lo[1]);
            EMIT(program, BPF_ALU64_REG(BPF_AND, reg, BPF_REG_3));

            EMIT(program, mask_hi[0]);
            EMIT(program, mask_hi[1]);
            EMIT(program, BPF_ALU64_REG(BPF_AND, reg + 1, BPF_REG_3));
        }

        for (int i = 0; i < 8; i++)
            masked_lo[i] = addr[i] & mask[i];
        for (int i = 0; i < 8; i++)
            masked_hi[i] = addr[i + 8] & mask[i + 8];

        struct bpf_insn ld64_lo[2] = {
            BPF_LD_IMM64(BPF_REG_3, _bf_read_u64(masked_lo))};
        struct bpf_insn ld64_hi[2] = {
            BPF_LD_IMM64(BPF_REG_3, _bf_read_u64(masked_hi))};

        EMIT(program, ld64_lo[0]);
        EMIT(program, ld64_lo[1]);

        if (jmp_op == BPF_JNE) {
            EMIT_FIXUP_JMP_NEXT_RULE(program,
                                     BPF_JMP_REG(BPF_JNE, reg, BPF_REG_3, 0));

            EMIT(program, ld64_hi[0]);
            EMIT(program, ld64_hi[1]);
            EMIT_FIXUP_JMP_NEXT_RULE(
                program, BPF_JMP_REG(BPF_JNE, reg + 1, BPF_REG_3, 0));
        } else {
            _clean_bf_jmpctx_ struct bf_jmpctx j0 = bf_jmpctx_default();
            _clean_bf_jmpctx_ struct bf_jmpctx j1 = bf_jmpctx_default();

            j0 =
                bf_jmpctx_get(program, BPF_JMP_REG(BPF_JNE, reg, BPF_REG_3, 0));

            EMIT(program, ld64_hi[0]);
            EMIT(program, ld64_hi[1]);
            j1 = bf_jmpctx_get(program,
                               BPF_JMP_REG(BPF_JNE, reg + 1, BPF_REG_3, 0));

            EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP_A(0));
        }
        break;
    }
    default:
        return bf_err_r(-EINVAL, "unsupported masked comparison size %u", size);
    }

    return 0;
}

int bf_cmp_range(struct bf_program *program, const struct bf_matcher *matcher,
                 uint32_t min, uint32_t max, int reg)
{
    assert(program);
    assert(matcher);

    if (bf_matcher_get_negate(matcher)) {
        _clean_bf_jmpctx_ struct bf_jmpctx j0 = bf_jmpctx_default();
        _clean_bf_jmpctx_ struct bf_jmpctx j1 = bf_jmpctx_default();

        j0 = bf_jmpctx_get(program, BPF_JMP32_IMM(BPF_JLT, reg, min, 0));
        j1 = bf_jmpctx_get(program, BPF_JMP32_IMM(BPF_JGT, reg, max, 0));
        EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP_A(0));

        return 0;
    }

    EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP32_IMM(BPF_JLT, reg, min, 0));
    EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP32_IMM(BPF_JGT, reg, max, 0));

    return 0;
}

int bf_cmp_bitfield(struct bf_program *program,
                    const struct bf_matcher *matcher, uint32_t flags, int reg)
{
    enum bf_matcher_op op = bf_matcher_get_op(matcher);

    assert(program);
    assert(matcher);

    if (op != BF_MATCHER_ANY && op != BF_MATCHER_ALL)
        return bf_err_r(-EINVAL, "unsupported operator %d", op);

    EMIT(program, BPF_ALU32_IMM(BPF_AND, reg, flags));
    EMIT_FIXUP_JMP_NEXT_RULE(
        program, BPF_JMP32_IMM(bf_cmp_get_jmp_ins(matcher), reg,
                               op == BF_MATCHER_ANY ? 0 : flags, 0));

    return 0;
}
