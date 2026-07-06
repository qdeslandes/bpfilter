/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include "cgen/packet.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/in.h> // NOLINT
#include <linux/ipv6.h>

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#include <bpfilter/chain.h>
#include <bpfilter/elfstub.h>
#include <bpfilter/helper.h>
#include <bpfilter/logger.h>
#include <bpfilter/matcher.h>
#include <bpfilter/rule.h>
#include <bpfilter/set.h>

#include "cgen/jmp.h"
#include "cgen/matcher/cmp.h"
#include "cgen/matcher/meta.h"
#include "cgen/matcher/set.h"
#include "cgen/program.h"
#include "cgen/runtime.h"
#include "cgen/stub.h"
#include "filter.h"

/**
 * Packet matcher codegen follows a four-stage pipeline:
 *
 * 1. Protocol check: `_bf_program_generate_rule()` (in program.c)
 *    emits deduplicated protocol guards before the matcher loop,
 *    so each L3/L4 protocol is verified at most once per rule. Guards
 *    are further deduplicated across rules: consecutive rules with the
 *    same guard signature form a guard group where only the first rule
 *    emits the guards (`r7`/`r8` are invariant after the prologue), and
 *    a guard miss jumps past the whole group.
 *
 * 2. Field load:  the prologue parse stubs pin the L3 header address in
 *    `R6` and the L4 header address in `R9` for the program's lifetime,
 *    so `_bf_matcher_pkt_load_field()` reads the target field directly
 *    from the pinned register returned by `bf_stub_hdr_reg()` (and
 *    `reg+1` for 128-bit values such as IPv6 addresses). On the plain
 *    IPv4 fast path of the L2 flavors, `R9` aliases the combined L2+L3
 *    slice (`R6 + sizeof(struct iphdr)`) instead of a dedicated L4
 *    slice; both point to enough verifier-visible bytes for every fixed
 *    L4 header load.
 *
 *    `_bf_matcher_pkt_load_and_cmp()` skips the load entirely when
 *    `bf_program.field_cache` records that the previous rule left the
 *    same field in `R1`/`R2`. This is sound because:
 *    - `BF_FIXUP_TYPE_JMP_NEXT_RULE` fixups always resolve to the start
 *      of the immediately following rule, and guard-miss jumps resolve
 *      to the point where their guard group closes, before the closing
 *      rule's own guards: a rule is entered either from the rule right
 *      before it, or, when it opens a guard group, from earlier
 *      guard-miss jumps landing on its guards.
 *    - A cache-eligible rule (single cacheable matcher, no log, no
 *      counters, no mark, exit verdict; enforced by
 *      `_bf_program_generate_rule()`) emits exactly: protocol guard(s)
 *      (elided when the rule sits inside an open guard group), field
 *      load, non-mutating compare(s), and `MOV r0` + `EXIT`. Its only
 *      jumps out are the guard miss (field not loaded, jumps past the
 *      whole guard group) and the compare miss (field loaded, jumps to
 *      the next rule).
 *    - Both rules carry a single matcher of the same type, hence the
 *      same guard signature derived from the same `bf_matcher_meta`,
 *      hence sit in the same guard group: the producer's guard-miss path
 *      jumps past the consumer entirely, so every path reaching the
 *      consumer's compare runs through the producer's compare-miss path,
 *      where the field was loaded. On a forced guard group break (jump
 *      displacement threshold), the consumer re-emits guards identical
 *      to the producer's: on the path where the producer's guard failed,
 *      the consumer's guard fails too, so the stale register is never
 *      read.
 *    - The eligibility conditions exclude every helper/kfunc/ELF-stub
 *      call and `R1`/`R2` mutation between the load and the reuse.
 *
 * 3. Comparison:  A `bf_cmp_*` function compares the value in the
 *    specified register against the matcher's reference payload.
 *
 * On top of the pipeline, consecutive cache-eligible rules carrying the
 * same matcher type and the same exit verdict form a verdict run
 * (`bf_program.verdict_run`, managed by `_bf_program_generate_rule()`).
 * Every rule of the run but the last is a member: it emits only an
 * inverted-polarity compare (`bf_cmp_value()`), whose miss falls through
 * directly into the next rule's compare — which is why the field cache
 * stays valid across the run without any jump — and whose match jumps to
 * the run's shared verdict block, i.e. the closing rule's `MOV r0` +
 * `EXIT` pair, where all the run's matches converge. Members skip their
 * private verdict pair entirely.
 *
 * 4. Tree runs: verdict runs holding enough unique reference values are
 *    emitted by `bf_program_generate()` (in program.c) as a single
 *    search-tree block instead of the member protocol.
 *    `bf_packet_gen_verdict_run_tree()` loads the field once — honoring
 *    and publishing the field cache exactly like stage 2 — then walks a
 *    balanced binary search tree over the run's sorted, deduplicated
 *    reference values: internal nodes bisect the range with an unsigned
 *    strict-greater compare, leaves test equality and jump to the
 *    block's shared verdict pair. Comparing in sorted order is sound
 *    because the codegen-time keys and the emitted immediates are read
 *    from the reference payloads exactly as the runtime loads read the
 *    packet field, by the same host: the ordering is consistent even
 *    though the bytes are network-ordered, and equality is
 *    byte-order-agnostic. No tree instruction mutates `r1`/`r2` (`r3` is
 *    the only scratch), so the cache soundness argument of stage 2
 *    carries over both into and out of the block. Every leaf chunk's
 *    miss converges on the block's next-rule jump, landing on the rule
 *    following the block.
 */

#define BF_IPV6_EH_HOPOPTS(x) ((x) << 0)
#define BF_IPV6_EH_ROUTING(x) ((x) << 1)
#define BF_IPV6_EH_FRAGMENT(x) ((x) << 2)
#define BF_IPV6_EH_AH(x) ((x) << 3)
#define BF_IPV6_EH_DSTOPTS(x) ((x) << 4)
#define BF_IPV6_EH_MH(x) ((x) << 5)

/**
 * @brief Load a packet field from the header into the specified register.
 *
 * `src_reg` must point to the header base (see `bf_stub_hdr_reg()`). For
 * 128-bit fields (IPv6 addresses), the low 8 bytes are loaded into `reg` and
 * the high 8 bytes into `reg + 1`.
 *
 * @param program Program to emit into. Can't be NULL.
 * @param meta Matcher metadata describing field offset and size. Can't be NULL.
 * @param src_reg BPF register holding the header base address.
 * @param reg BPF register to load the value into.
 * @return 0 on success, negative errno on error.
 */
static int _bf_matcher_pkt_load_field(struct bf_program *program,
                                      const struct bf_matcher_meta *meta,
                                      int src_reg, int reg)
{
    switch (meta->hdr_payload_size) {
    case 1:
        EMIT(program,
             BPF_LDX_MEM(BPF_B, reg, src_reg, meta->hdr_payload_offset));
        break;
    case 2:
        EMIT(program,
             BPF_LDX_MEM(BPF_H, reg, src_reg, meta->hdr_payload_offset));
        break;
    case 4:
        EMIT(program,
             BPF_LDX_MEM(BPF_W, reg, src_reg, meta->hdr_payload_offset));
        break;
    case 8:
        EMIT(program,
             BPF_LDX_MEM(BPF_DW, reg, src_reg, meta->hdr_payload_offset));
        break;
    case 16:
        EMIT(program,
             BPF_LDX_MEM(BPF_DW, reg, src_reg, meta->hdr_payload_offset));
        EMIT(program, BPF_LDX_MEM(BPF_DW, reg + 1, src_reg,
                                  meta->hdr_payload_offset + 8));
        break;
    default:
        return -EINVAL;
    }

    return 0;
}

static int _bf_matcher_pkt_load(struct bf_program *program,
                                const struct bf_matcher_meta *meta, int reg)
{
    int src_reg;

    src_reg = bf_stub_hdr_reg(meta);
    if (src_reg < 0)
        return src_reg;

    return _bf_matcher_pkt_load_field(program, meta, src_reg, reg);
}

bool bf_packet_matcher_is_cacheable(const struct bf_matcher *matcher)
{
    assert(matcher);

    if (bf_matcher_get_op(matcher) != BF_MATCHER_EQ)
        return false;

    /* Only matchers dispatched to `_bf_matcher_pkt_load_and_cmp()`: every
     * `bf_cmp_value()` size path they use (1, 2, 4, and 16 bytes) leaves
     * the loaded registers unmodified (the 16-byte compare loads its
     * reference into `r3`, the smaller compares use immediates). The
     * `negate` flag only flips the jump opcode, so negated matchers
     * remain cacheable. */
    switch (bf_matcher_get_type(matcher)) {
    case BF_MATCHER_IP4_SADDR:
    case BF_MATCHER_IP4_DADDR:
    case BF_MATCHER_IP4_PROTO:
    case BF_MATCHER_IP6_SADDR:
    case BF_MATCHER_IP6_DADDR:
    case BF_MATCHER_ICMP_TYPE:
    case BF_MATCHER_ICMP_CODE:
    case BF_MATCHER_ICMPV6_TYPE:
    case BF_MATCHER_ICMPV6_CODE:
        return true;
    default:
        return false;
    }
}

/**
 * @brief Generic load + value compare for matchers whose field size and offset
 * are fully described by `_bf_matcher_metas`.
 *
 * Emits: field load (from the pinned header register) -> `bf_cmp_value`.
 *
 * @param program Program to generate bytecode into. Can't be NULL.
 * @param matcher Matcher to generate bytecode for. Can't be NULL.
 * @param meta Matcher metadata describing field size and offset. Can't be NULL.
 * @return 0 on success, negative errno on error.
 */
static int _bf_matcher_pkt_load_and_cmp(struct bf_program *program,
                                        const struct bf_matcher *matcher,
                                        const struct bf_matcher_meta *meta)
{
    int r;

    /* Skip the load if the previous rule left the same field in R1 (and
     * R2 for 16-byte fields). The matcher type alone identifies the field:
     * it determines the `bf_matcher_meta` entry, i.e. the layer, the
     * guard's protocol ID, the field offset, and the field size. See the
     * soundness argument in the pipeline comment at the top of this file. */
    if (!(program->field_cache.rule_eligible && program->field_cache.valid &&
          program->field_cache.type == bf_matcher_get_type(matcher))) {
        r = _bf_matcher_pkt_load(program, meta, BPF_REG_1);
        if (r)
            return r;
    }

    if (program->field_cache.rule_eligible) {
        program->field_cache.valid = true;
        program->field_cache.type = bf_matcher_get_type(matcher);
    }

    return bf_cmp_value(program, matcher, bf_matcher_payload(matcher),
                        meta->hdr_payload_size, BPF_REG_1);
}

/** Maximum number of values compared linearly in a tree leaf chunk. */
#define _BF_TREE_LEAF_MAX 4

/**
 * @brief Reference value of a tree-run member, in comparison order.
 *
 * Keys mirror the runtime representation of the packet field: comparing
 * them at codegen time and comparing the emitted immediates at runtime
 * yield the same order, since both are computed by the same host from the
 * same bytes.
 */
struct bf_tree_key
{
    /** Reference value for sizes up to 4 bytes (zero-extended), or the low
     * 8 bytes of a 16-byte value, as `_bf_matcher_pkt_load_field()` loads
     * them into `r1`. */
    uint64_t k0;

    /** High 8 bytes of a 16-byte value, as `_bf_matcher_pkt_load_field()`
     * loads them into `r2`. Zero for smaller sizes. */
    uint64_t k1;
};

static int _bf_tree_key_cmp(const void *lhs, const void *rhs)
{
    const struct bf_tree_key *lkey = lhs;
    const struct bf_tree_key *rkey = rhs;

    if (lkey->k0 != rkey->k0)
        return lkey->k0 < rkey->k0 ? -1 : 1;
    if (lkey->k1 != rkey->k1)
        return lkey->k1 < rkey->k1 ? -1 : 1;

    return 0;
}

/**
 * @brief Emit a tree leaf chunk: linear equality tests over a short range.
 *
 * Each value emits the same compare shape as the verdict-run member path
 * in `bf_cmp_value()`: a match jumps to the block's shared verdict pair
 * (pending `BF_FIXUP_TYPE_JMP_VERDICT` fixup), a miss falls through to
 * the next value. The chunk closes with an unconditional
 * `BF_FIXUP_TYPE_JMP_NEXT_RULE` jump: a miss must jump over the shared
 * verdict block, never fall into it.
 *
 * @param program Program to generate bytecode into. Can't be NULL.
 * @param keys Sorted, deduplicated reference values. Can't be NULL.
 * @param low First index of the chunk.
 * @param high Last index of the chunk (inclusive).
 * @param size Field size in bytes: 1, 2, 4, or 16.
 * @return 0 on success, negative errno on error.
 */
static int _bf_tree_emit_leaf_chunk(struct bf_program *program,
                                    const struct bf_tree_key *keys, size_t low,
                                    size_t high, unsigned int size)
{
    for (size_t i = low; i <= high; ++i) {
        switch (size) {
        case 1:
        case 2:
            EMIT_FIXUP_JMP_VERDICT(
                program,
                BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, (uint32_t)keys[i].k0, 0));
            break;
        case 4:
            EMIT_FIXUP_JMP_VERDICT(
                program,
                BPF_JMP32_IMM(BPF_JEQ, BPF_REG_1, (uint32_t)keys[i].k0, 0));
            break;
        case 16: {
            struct bpf_insn ld64_lo[2] = {BPF_LD_IMM64(BPF_REG_3, keys[i].k0)};
            struct bpf_insn ld64_hi[2] = {BPF_LD_IMM64(BPF_REG_3, keys[i].k1)};

            EMIT(program, ld64_lo[0]);
            EMIT(program, ld64_lo[1]);

            {
                /* Low half mismatch: skip the high half check and fall
                 * through to the next value's compare. */
                _clean_bf_jmpctx_ struct bf_jmpctx j0 = bf_jmpctx_get(
                    program, BPF_JMP_REG(BPF_JNE, BPF_REG_1, BPF_REG_3, 0));

                EMIT(program, ld64_hi[0]);
                EMIT(program, ld64_hi[1]);
                EMIT_FIXUP_JMP_VERDICT(
                    program, BPF_JMP_REG(BPF_JEQ, BPF_REG_2, BPF_REG_3, 0));
            }
            break;
        }
        default:
            return bf_err_r(-EINVAL, "unsupported tree comparison size %u",
                            size);
        }
    }

    EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP_A(0));

    return 0;
}

/**
 * @brief Recursively emit a search tree over a sorted key range.
 *
 * Ranges of at most `_BF_TREE_LEAF_MAX` values emit a leaf chunk; larger
 * ranges emit an internal node: an unsigned strict-greater compare
 * against the pivot (the middle key) jumping to the right subtree, so the
 * left subtree keeps pivot equality.
 *
 * For 16-byte fields, internal nodes pivot on `k0` only: the pivot index
 * is first extended to the last entry sharing its `k0`, so every entry
 * equal on `k0` stays in the left subtree and the strict-greater test
 * remains a correct partition. When the pivot's `k0` group reaches the
 * end of the range, the split moves below the group instead; when the
 * whole range shares one `k0`, the node pivots on `k1`, which is unique
 * after deduplication. A packet whose low half differs from the shared
 * `k0` may then take either branch: it fails every leaf equality test
 * anyway.
 *
 * @param program Program to generate bytecode into. Can't be NULL.
 * @param keys Sorted, deduplicated reference values. Can't be NULL.
 * @param low First index of the range.
 * @param high Last index of the range (inclusive).
 * @param size Field size in bytes: 1, 2, 4, or 16.
 * @return 0 on success, negative errno on error.
 */
static int _bf_tree_emit_range(struct bf_program *program,
                               const struct bf_tree_key *keys, size_t low,
                               size_t high, unsigned int size)
{
    size_t mid = low + ((high - low) / 2);
    bool pivot_on_k1 = false;
    int r;

    if (high - low + 1 <= _BF_TREE_LEAF_MAX)
        return _bf_tree_emit_leaf_chunk(program, keys, low, high, size);

    if (size == 16) {
        while (mid < high && keys[mid + 1].k0 == keys[mid].k0)
            ++mid;

        if (mid == high) {
            mid = low + ((high - low) / 2);
            while (mid > low && keys[mid - 1].k0 == keys[mid].k0)
                --mid;

            if (mid == low) {
                pivot_on_k1 = true;
                mid = low + ((high - low) / 2);
            } else {
                --mid;
            }
        }
    }

    {
        _clean_bf_jmpctx_ struct bf_jmpctx right = bf_jmpctx_default();

        if (size == 16) {
            struct bpf_insn ld64[2] = {BPF_LD_IMM64(
                BPF_REG_3, pivot_on_k1 ? keys[mid].k1 : keys[mid].k0)};

            EMIT(program, ld64[0]);
            EMIT(program, ld64[1]);
            right = bf_jmpctx_get(
                program,
                BPF_JMP_REG(BPF_JGT, pivot_on_k1 ? BPF_REG_2 : BPF_REG_1,
                            BPF_REG_3, 0));
        } else {
            right = bf_jmpctx_get(
                program,
                BPF_JMP32_IMM(BPF_JGT, BPF_REG_1, (uint32_t)keys[mid].k0, 0));
        }

        r = _bf_tree_emit_range(program, keys, low, mid, size);
        if (r)
            return r;

        /* The jump closes here: a strict-greater packet lands on the
         * right subtree, emitted below. The left subtree never falls
         * through: its leaf chunks all end with a next-rule jump. */
    }

    return _bf_tree_emit_range(program, keys, mid + 1, high, size);
}

int bf_packet_gen_verdict_run_tree(struct bf_program *program,
                                   const struct bf_matcher **matchers, size_t n)
{
    _cleanup_free_ struct bf_tree_key *keys = NULL;
    const struct bf_matcher_meta *meta;
    enum bf_matcher_type type;
    unsigned int size;
    size_t n_unique;
    int r;

    assert(program);
    assert(matchers);
    assert(n > 0);

    type = bf_matcher_get_type(matchers[0]);
    meta = bf_matcher_get_meta(type);
    if (!meta)
        return bf_err_r(-EINVAL, "missing meta for matcher type %d", type);

    size = meta->hdr_payload_size;

    /* Read each reference payload exactly as `bf_cmp_value()` and the
     * runtime field loads do, so codegen-time ordering matches the
     * emitted compares on any host endianness. */
    keys = calloc(n, sizeof(*keys));
    if (!keys)
        return -ENOMEM;

    for (size_t i = 0; i < n; ++i) {
        const void *ref = bf_matcher_payload(matchers[i]);

        switch (size) {
        case 1:
            keys[i].k0 = *(const uint8_t *)ref;
            break;
        case 2:
            keys[i].k0 = *(const uint16_t *)ref;
            break;
        case 4:
            keys[i].k0 = *(const uint32_t *)ref;
            break;
        case 16:
            keys[i].k0 = bf_read_u64(ref);
            keys[i].k1 = bf_read_u64((const uint8_t *)ref + 8);
            break;
        default:
            return bf_err_r(-EINVAL, "unsupported tree comparison size %u",
                            size);
        }
    }

    qsort(keys, n, sizeof(*keys), _bf_tree_key_cmp);

    /* Duplicate values within a run share the verdict: later occurrences
     * are dead code on the linear path, so dropping them is safe. */
    n_unique = 0;
    for (size_t i = 0; i < n; ++i) {
        if (n_unique && keys[i].k0 == keys[n_unique - 1].k0 &&
            keys[i].k1 == keys[n_unique - 1].k1)
            continue;
        keys[n_unique++] = keys[i];
    }

    /* Same cache-aware load as `_bf_matcher_pkt_load_and_cmp()`: the
     * block sits in one guard group with its same-type neighbors, and no
     * tree instruction mutates r1/r2, so the cache is sound both into
     * and out of the block. */
    if (!(program->field_cache.rule_eligible && program->field_cache.valid &&
          program->field_cache.type == type)) {
        r = _bf_matcher_pkt_load(program, meta, BPF_REG_1);
        if (r)
            return r;
    }

    if (program->field_cache.rule_eligible) {
        program->field_cache.valid = true;
        program->field_cache.type = type;
    }

    return _bf_tree_emit_range(program, keys, 0, n_unique - 1, size);
}

static int _bf_matcher_pkt_generate_net(struct bf_program *program,
                                        const struct bf_matcher *matcher,
                                        const struct bf_matcher_meta *meta)
{
    const uint32_t prefixlen = *(const uint32_t *)bf_matcher_payload(matcher);
    const void *data =
        (const uint8_t *)bf_matcher_payload(matcher) + sizeof(uint32_t);
    int r;

    r = _bf_matcher_pkt_load(program, meta, BPF_REG_1);
    if (r)
        return r;

    return bf_cmp_masked_value(program, matcher, data, prefixlen,
                               meta->hdr_payload_size, BPF_REG_1);
}

static int _bf_matcher_pkt_generate_port(struct bf_program *program,
                                         const struct bf_matcher *matcher,
                                         const struct bf_matcher_meta *meta)
{
    int r;

    r = _bf_matcher_pkt_load(program, meta, BPF_REG_1);
    if (r)
        return r;

    if (bf_matcher_get_op(matcher) == BF_MATCHER_RANGE) {
        uint16_t *ports = (uint16_t *)bf_matcher_payload(matcher);
        /* Convert the big-endian value stored in the packet into a
         * little-endian value for x86 and arm before comparing it to the
         * reference value. This is a JLT/JGT comparison, we need to have the
         * MSB where the machine expects then. */
        EMIT(program, BPF_BSWAP(BPF_REG_1, 16));
        return bf_cmp_range(program, matcher, ports[0], ports[1], BPF_REG_1);
    }

    return bf_cmp_value(program, matcher, bf_matcher_payload(matcher),
                        meta->hdr_payload_size, BPF_REG_1);
}

static int
_bf_matcher_pkt_generate_tcp_flags(struct bf_program *program,
                                   const struct bf_matcher *matcher,
                                   const struct bf_matcher_meta *meta)
{
    int r;

    r = _bf_matcher_pkt_load(program, meta, BPF_REG_1);
    if (r)
        return r;

    switch (bf_matcher_get_op(matcher)) {
    case BF_MATCHER_ANY:
    case BF_MATCHER_ALL:
        return bf_cmp_bitfield(program, matcher,
                               *(uint8_t *)bf_matcher_payload(matcher),
                               BPF_REG_1);
    case BF_MATCHER_EQ:
        return bf_cmp_value(program, matcher, bf_matcher_payload(matcher),
                            meta->hdr_payload_size, BPF_REG_1);
    default:
        return bf_err_r(-EINVAL, "unsupported operator %d",
                        bf_matcher_get_op(matcher));
    }
}

static int
_bf_matcher_pkt_generate_ip6_nexthdr(struct bf_program *program,
                                     const struct bf_matcher *matcher)
{
    const uint8_t ehdr = *(uint8_t *)bf_matcher_payload(matcher);
    uint8_t eh_mask;
    uint8_t jmp_op;

    jmp_op = bf_cmp_get_jmp_ins(matcher);

    switch (ehdr) {
    case IPPROTO_HOPOPTS:
    case IPPROTO_ROUTING:
    case IPPROTO_DSTOPTS:
    case IPPROTO_FRAGMENT:
    case IPPROTO_AH:
    case IPPROTO_MH:
        eh_mask = (BF_IPV6_EH_HOPOPTS(ehdr == IPPROTO_HOPOPTS) |
                   BF_IPV6_EH_ROUTING(ehdr == IPPROTO_ROUTING) |
                   BF_IPV6_EH_FRAGMENT(ehdr == IPPROTO_FRAGMENT) |
                   BF_IPV6_EH_AH(ehdr == IPPROTO_AH) |
                   BF_IPV6_EH_DSTOPTS(ehdr == IPPROTO_DSTOPTS) |
                   BF_IPV6_EH_MH(ehdr == IPPROTO_MH));
        EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10,
                                  BF_PROG_CTX_OFF(ipv6_eh)));
        EMIT(program, BPF_ALU64_IMM(BPF_AND, BPF_REG_1, eh_mask));

        /* Extension header check: after AND with eh_mask, a non-zero
         * result means the header is present. For EQ (jmp_op=JNE),
         * we want to skip if zero (not present), so we use the
         * *opposite* opcode here. */
        EMIT_FIXUP_JMP_NEXT_RULE(
            program, BPF_JMP_IMM(jmp_op == BPF_JNE ? BPF_JEQ : BPF_JNE,
                                 BPF_REG_1, 0, 0));
        break;
    default:
        /* check l4 protocols using `BPF_REG_8` */
        EMIT_FIXUP_JMP_NEXT_RULE(program,
                                 BPF_JMP_IMM(jmp_op, BPF_REG_8, ehdr, 0));
        break;
    }

    return 0;
}

static int _bf_matcher_pkt_generate_ip4_dscp(struct bf_program *program,
                                             const struct bf_matcher *matcher,
                                             const struct bf_matcher_meta *meta)
{
    uint8_t dscp;
    int r;

    r = _bf_matcher_pkt_load(program, meta, BPF_REG_1);
    if (r)
        return r;

    dscp = *(uint8_t *)bf_matcher_payload(matcher);

    /* IPv4 TOS byte: [DSCP 6b] [ECN 2b]. Mask with 0xfc to isolate
     * the 6-bit DSCP field, then compare against dscp << 2. */
    EMIT(program, BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0xfc));

    EMIT_FIXUP_JMP_NEXT_RULE(program,
                             BPF_JMP_IMM(bf_cmp_get_jmp_ins(matcher), BPF_REG_1,
                                         (uint8_t)dscp << 2, 0));

    return 0;
}

static int _bf_matcher_pkt_generate_ip6_dscp(struct bf_program *program,
                                             const struct bf_matcher *matcher,
                                             const struct bf_matcher_meta *meta)
{
    uint8_t dscp;
    int src_reg;

    src_reg = bf_stub_hdr_reg(meta);
    if (src_reg < 0)
        return src_reg;

    dscp = *(uint8_t *)bf_matcher_payload(matcher);

    /* IPv6 DSCP occupies bits 6-11 of the header (big-endian view):
     *   [version 4b] [DSCP 6b] [ECN 2b] [flow label (high 4b)]
     * Load 2 bytes, convert to big-endian, mask with 0x0fc0 to isolate
     * the 6-bit DSCP field, then compare against dscp << 6. */
    EMIT(program, BPF_LDX_MEM(BPF_H, BPF_REG_1, src_reg, 0));
    EMIT(program, BPF_ENDIAN(BPF_TO_BE, BPF_REG_1, 16));
    EMIT(program, BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0x0fc0));

    EMIT_FIXUP_JMP_NEXT_RULE(program,
                             BPF_JMP_IMM(bf_cmp_get_jmp_ins(matcher), BPF_REG_1,
                                         (uint16_t)dscp << 6, 0));

    return 0;
}

static int _bf_matcher_pkt_generate_set(struct bf_program *program,
                                        const struct bf_matcher *matcher)
{
    const struct bf_set *set;
    size_t offset = 0;
    int r;

    assert(program);
    assert(matcher);

    set = bf_chain_get_set_for_matcher(program->runtime.chain, matcher);
    if (!set) {
        return bf_err_r(-ENOENT, "set #%u not found in %s",
                        *(uint32_t *)bf_matcher_payload(matcher),
                        program->runtime.chain->name);
    }

    if (set->use_trie) {
        const struct bf_matcher_meta *meta = bf_matcher_get_meta(set->key[0]);
        int src_reg;

        if (!meta) {
            return bf_err_r(-EINVAL, "missing meta for '%s'",
                            bf_matcher_type_to_str(set->key[0]));
        }

        src_reg = bf_stub_hdr_reg(meta);
        if (src_reg < 0)
            return src_reg;

        return bf_set_generate_trie_lookup(program, matcher, src_reg,
                                           meta->hdr_payload_offset,
                                           meta->hdr_payload_size);
    }

    for (size_t i = 0; i < set->n_comps; ++i) {
        enum bf_matcher_type type = set->key[i];
        const struct bf_matcher_meta *meta = bf_matcher_get_meta(type);

        if (!meta) {
            return bf_err_r(-EINVAL, "missing meta for '%s'",
                            bf_matcher_type_to_str(type));
        }

        r = bf_stub_stx_payload(program, meta, offset);
        if (r) {
            return bf_err_r(r,
                            "failed to generate bytecode to load packet data");
        }

        offset += meta->hdr_payload_size;
    }

    return bf_set_generate_map_lookup(program, matcher, BF_PROG_SCR_OFF(0));
}

int bf_packet_gen_inline_matcher(struct bf_program *program,
                                 const struct bf_matcher *matcher)
{
    const struct bf_matcher_meta *meta;

    assert(program);
    assert(matcher);

    meta = bf_matcher_get_meta(bf_matcher_get_type(matcher));

    switch (bf_matcher_get_type(matcher)) {
    case BF_MATCHER_META_IFACE:
    case BF_MATCHER_META_L3_PROTO:
    case BF_MATCHER_META_L4_PROTO:
    case BF_MATCHER_META_PROBABILITY:
    case BF_MATCHER_META_SPORT:
    case BF_MATCHER_META_DPORT:
    case BF_MATCHER_META_FLOW_PROBABILITY:
        return bf_matcher_generate_meta(program, matcher);
    case BF_MATCHER_META_MARK:
    case BF_MATCHER_META_FLOW_HASH:
        return bf_err_r(-ENOTSUP,
                        "matcher '%s' is not supported by this flavor",
                        bf_matcher_type_to_str(bf_matcher_get_type(matcher)));
    case BF_MATCHER_IP4_DSCP:
        return _bf_matcher_pkt_generate_ip4_dscp(program, matcher, meta);
    case BF_MATCHER_IP4_SADDR:
    case BF_MATCHER_IP4_DADDR:
    case BF_MATCHER_IP4_PROTO:
    case BF_MATCHER_IP6_SADDR:
    case BF_MATCHER_IP6_DADDR:
    case BF_MATCHER_ICMP_TYPE:
    case BF_MATCHER_ICMP_CODE:
    case BF_MATCHER_ICMPV6_TYPE:
    case BF_MATCHER_ICMPV6_CODE:
        return _bf_matcher_pkt_load_and_cmp(program, matcher, meta);
    case BF_MATCHER_IP4_SNET:
    case BF_MATCHER_IP4_DNET:
    case BF_MATCHER_IP6_SNET:
    case BF_MATCHER_IP6_DNET:
        return _bf_matcher_pkt_generate_net(program, matcher, meta);
    case BF_MATCHER_TCP_SPORT:
    case BF_MATCHER_TCP_DPORT:
    case BF_MATCHER_UDP_SPORT:
    case BF_MATCHER_UDP_DPORT:
        return _bf_matcher_pkt_generate_port(program, matcher, meta);
    case BF_MATCHER_TCP_FLAGS:
        return _bf_matcher_pkt_generate_tcp_flags(program, matcher, meta);
    case BF_MATCHER_IP6_NEXTHDR:
        return _bf_matcher_pkt_generate_ip6_nexthdr(program, matcher);
    case BF_MATCHER_IP6_DSCP:
        return _bf_matcher_pkt_generate_ip6_dscp(program, matcher, meta);
    case BF_MATCHER_SET:
        return _bf_matcher_pkt_generate_set(program, matcher);
    default:
        return bf_err_r(-EINVAL, "unknown matcher type %d",
                        bf_matcher_get_type(matcher));
    }
}

int bf_packet_gen_inline_log(struct bf_program *program,
                             const struct bf_rule *rule)
{
    assert(program);
    assert(rule);

    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(arg)));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_2, rule->index));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_3, rule->log));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_4, rule->verdict));

    // Pack l3_proto and l4_proto
    EMIT(program, BPF_MOV64_REG(BPF_REG_5, BPF_REG_7));
    EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_5, 16));
    EMIT(program, BPF_ALU64_REG(BPF_OR, BPF_REG_5, BPF_REG_8));

    EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_PKT_LOG);

    return 0;
}
