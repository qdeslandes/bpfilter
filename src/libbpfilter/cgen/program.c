/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/program.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/limits.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpfilter/bpf.h>
#include <bpfilter/btf.h>
#include <bpfilter/chain.h>
#include <bpfilter/core/hashset.h>
#include <bpfilter/core/list.h>
#include <bpfilter/counter.h>
#include <bpfilter/ctx.h>
#include <bpfilter/dump.h>
#include <bpfilter/flavor.h>
#include <bpfilter/helper.h>
#include <bpfilter/hook.h>
#include <bpfilter/io.h>
#include <bpfilter/logger.h>
#include <bpfilter/matcher.h>
#include <bpfilter/pack.h>
#include <bpfilter/rule.h>
#include <bpfilter/set.h>
#include <bpfilter/verdict.h>

#include "cgen/cgroup_skb.h"
#include "cgen/cgroup_sock_addr.h"
#include "cgen/dump.h"
#include "cgen/fixup.h"
#include "cgen/handle.h"
#include "cgen/jmp.h"
#include "cgen/nf.h"
#include "cgen/packet.h"
#include "cgen/printer.h"
#include "cgen/prog/link.h"
#include "cgen/prog/map.h"
#include "cgen/stub.h"
#include "cgen/tc.h"
#include "cgen/xdp.h"
#include "filter.h"

#define _BF_LOG_BUF_SIZE                                                       \
    (UINT32_MAX >> 8) /* verifier maximum in kernels <= 5.1 */
#define _BF_LOG_MAP_N_ENTRIES 1000
#define _BF_LOG_MAP_SIZE                                                       \
    _bf_round_next_power_of_2(sizeof(struct bf_log) * _BF_LOG_MAP_N_ENTRIES)
#define _BF_SET_MAP_PREFIX "bf_set_"
#define _BF_COUNTER_MAP_NAME "bf_cmap"
#define _BF_PRINTER_MAP_NAME "bf_pmap"
#define _BF_LOG_MAP_NAME "bf_lmap"
#define _BF_STATE_MAP_NAME "bf_smap"

static inline size_t _bf_round_next_power_of_2(size_t value)
{
    if (value == 0)
        return 1;

    value--;
    value |= value >> 1;
    value |= value >> 2;
    value |= value >> 4;
    value |= value >> 8;
    value |= value >> 16;
#if SIZE_MAX > 0xFFFFFFFFU
    value |= value >> 32;
#endif

    return ++value;
}

/**
 * @brief Sets sharing the same key format, collapsed to a single BPF map.
 *
 * For hash-keyed sets, one `bf_set_group` exists for every unique key
 * format among a chain's non-empty sets. The sets list preserves insertion
 * order; a set's position is its bit index within the group's bitmask
 * value.
 *
 * LPM trie sets are never grouped together: each non-empty trie set gets
 * its own group of size 1. See `_bf_program_build_set_groups()` for the
 * rationale.
 */
struct bf_set_group
{
    /** Non-empty sets that map to the same BPF map. For hash-keyed groups,
     * all sets share the same key format; LPM trie groups always hold a
     * single set. Non-owning pointers into the chain's `bf_set` list.
     * Never empty. */
    bf_list sets;

    /** Backing BPF map. Populated during `bf_program_load()`; the map is
     * owned by `bf_program->handle->sets`. */
    struct bf_map *map;
};

#define _free_bf_set_group_ __attribute__((__cleanup__(_bf_set_group_free)))

static void _bf_set_group_free(struct bf_set_group **group)
{
    assert(group);

    if (!*group)
        return;

    bf_list_clean(&(*group)->sets);
    BF_FREEP(group);
}

static int _bf_set_group_new(struct bf_set_group **group)
{
    _free_bf_set_group_ struct bf_set_group *_group = NULL;

    assert(group);

    _group = calloc(1, sizeof(*_group));
    if (!_group)
        return -ENOMEM;

    /* The list holds non-owning const struct bf_set * pointers; no free
     * callback. Groups are temporary (not serialized), so no pack callback
     * either. */
    _group->sets = bf_list_default(NULL, NULL);

    *group = TAKE_PTR(_group);

    return 0;
}

static struct bf_set_group *
_bf_program_find_set_group(const struct bf_program *program,
                           const struct bf_set *set)
{
    assert(program);

    if (!set)
        return NULL;

    bf_list_foreach (&program->set_groups, group_node) {
        struct bf_set_group *group = bf_list_node_get_data(group_node);
        bf_list_foreach (&group->sets, set_node) {
            if (bf_list_node_get_data(set_node) == set)
                return group;
        }
    }

    return NULL;
}

static int _bf_program_build_set_groups(struct bf_program *program)
{
    assert(program);

    bf_list_clean(&program->set_groups);
    program->set_groups = bf_list_default(_bf_set_group_free, NULL);

    bf_list_foreach (&program->runtime.chain->sets, set_node) {
        struct bf_set *set = bf_list_node_get_data(set_node);
        struct bf_set_group *match = NULL;
        int r;

        if (bf_hashset_is_empty(&set->elems))
            continue;

        /* Inline-eligible sets (see `bf_set_is_inline_eligible()`) keep
         * their group and their BPF map even though the packet-flavor
         * codegen replaces their per-packet lookup with an inline search
         * tree: the pinned `bf_set_*` maps are user-visible artifacts of
         * the chain, and creating them is a load-time cost only. Their
         * map simply ends up with no `BF_FIXUP_TYPE_SET_MAP_FD` reference,
         * which `_bf_program_fixup()` handles naturally. */

        /* LPM trie sets are not grouped: BPF LPM trie lookup always
         * returns the longest-prefix match, so the read-modify-write
         * step in _bf_program_load_sets_maps() can't preserve the
         * per-set bitmask when prefixes overlap. */
        if (!set->use_trie) {
            bf_list_foreach (&program->set_groups, group_node) {
                struct bf_set_group *group = bf_list_node_get_data(group_node);
                const struct bf_set *head =
                    bf_list_node_get_data(bf_list_get_head(&group->sets));

                if (bf_set_same_key(set, head)) {
                    match = group;
                    break;
                }
            }
        }

        if (match) {
            r = bf_list_add_tail(&match->sets, set);
            if (r)
                return bf_err_r(r, "failed to add set to existing group");
        } else {
            _free_bf_set_group_ struct bf_set_group *new_group = NULL;

            r = _bf_set_group_new(&new_group);
            if (r)
                return bf_err_r(r, "failed to allocate set group");

            r = bf_list_add_tail(&new_group->sets, set);
            if (r)
                return bf_err_r(r, "failed to seed set group");

            r = bf_list_push(&program->set_groups, (void **)&new_group);
            if (r)
                return bf_err_r(r, "failed to register set group");
        }
    }

    return 0;
}

int bf_program_set_bit_index(const struct bf_program *program,
                             const struct bf_set *set, size_t *bit_index)
{
    assert(program);
    assert(set);
    assert(bit_index);

    bf_list_foreach (&program->set_groups, group_node) {
        struct bf_set_group *group = bf_list_node_get_data(group_node);
        size_t i = 0;

        bf_list_foreach (&group->sets, set_node) {
            if (bf_list_node_get_data(set_node) == set) {
                *bit_index = i;
                return 0;
            }
            ++i;
        }
    }

    return -ENOENT;
}

static const struct bf_flavor_ops *bf_flavor_ops_get(enum bf_flavor flavor)
{
    static const struct bf_flavor_ops *flavor_ops[] = {
        [BF_FLAVOR_TC] = &bf_flavor_ops_tc,
        [BF_FLAVOR_NF] = &bf_flavor_ops_nf,
        [BF_FLAVOR_XDP] = &bf_flavor_ops_xdp,
        [BF_FLAVOR_CGROUP_SKB] = &bf_flavor_ops_cgroup_skb,
        [BF_FLAVOR_CGROUP_SOCK_ADDR] = &bf_flavor_ops_cgroup_sock_addr,
    };

    static_assert_enum_mapping(flavor_ops, _BF_FLAVOR_MAX);

    return flavor_ops[flavor];
}

int bf_program_new(struct bf_program **program, const struct bf_chain *chain,
                   struct bf_handle *handle)
{
    _free_bf_program_ struct bf_program *_program = NULL;
    int r;

    assert(program);
    assert(chain);
    assert(handle);

    _program = calloc(1, sizeof(*_program));
    if (!_program)
        return -ENOMEM;

    _program->flavor = bf_hook_to_flavor(chain->hook);
    _program->runtime.ops = bf_flavor_ops_get(_program->flavor);
    _program->runtime.chain = chain;
    _program->img = bf_vector_default(sizeof(struct bpf_insn));
    _program->fixups = bf_list_default(bf_fixup_free, NULL);
    _program->set_groups = bf_list_default(_bf_set_group_free, NULL);
    _program->handle = handle;

    r = bf_vector_reserve(&_program->img, 512);
    if (r)
        return r;

    r = bf_printer_new(&_program->printer);
    if (r)
        return r;

    *program = TAKE_PTR(_program);

    return 0;
}

void bf_program_free(struct bf_program **program)
{
    assert(program);

    if (!*program)
        return;

    bf_list_clean(&(*program)->fixups);
    bf_list_clean(&(*program)->set_groups);
    bf_vector_clean(&(*program)->img);

    bf_printer_free(&(*program)->printer);

    free(*program);
    *program = NULL;
}

void bf_program_dump(const struct bf_program *program, prefix_t *prefix)
{
    assert(program);
    assert(prefix);

    DUMP(prefix, "struct bf_program at %p", program);

    bf_dump_prefix_push(prefix);

    DUMP(prefix, "handle: struct bf_handle *");
    bf_dump_prefix_push(prefix);
    bf_handle_dump(program->handle, bf_dump_prefix_last(prefix));
    bf_dump_prefix_pop(prefix);

    DUMP(prefix, "printer: struct bf_printer *");
    bf_dump_prefix_push(prefix);
    bf_printer_dump(program->printer, prefix);
    bf_dump_prefix_pop(prefix);

    DUMP(prefix, "img: %p", program->img.data);
    DUMP(prefix, "img.size: %lu", program->img.size);
    DUMP(prefix, "img.cap: %lu", program->img.cap);

    DUMP(prefix, "fixups: bf_list<struct bf_fixup>[%lu]",
         bf_list_size(&program->fixups));
    bf_dump_prefix_push(prefix);
    bf_list_foreach (&program->fixups, fixup_node) {
        struct bf_fixup *fixup = bf_list_node_get_data(fixup_node);

        if (bf_list_is_tail(&program->fixups, fixup_node))
            bf_dump_prefix_last(prefix);

        bf_fixup_dump(fixup, prefix);
    }
    bf_dump_prefix_pop(prefix);

    DUMP(prefix, "groups: bf_list<struct bf_set_group>[%lu]",
         bf_list_size(&program->set_groups));
    bf_dump_prefix_push(prefix);
    bf_list_foreach (&program->set_groups, group_node) {
        const struct bf_set_group *group = bf_list_node_get_data(group_node);
        size_t i = 0;

        if (bf_list_is_tail(&program->set_groups, group_node))
            bf_dump_prefix_last(prefix);

        DUMP(prefix, "struct bf_set_group at %p (%lu set(s), map=%p)", group,
             bf_list_size(&group->sets), (void *)group->map);
        bf_dump_prefix_push(prefix);
        bf_list_foreach (&group->sets, set_node) {
            const struct bf_set *set = bf_list_node_get_data(set_node);

            if (bf_list_is_tail(&group->sets, set_node))
                bf_dump_prefix_last(prefix);
            DUMP(prefix, "bit %lu: bf_set '%s' (%lu element(s))", i,
                 set->name ?: "<anonymous>", bf_hashset_size(&set->elems));
            ++i;
        }
        bf_dump_prefix_pop(prefix);
    }
    bf_dump_prefix_pop(prefix);

    DUMP(bf_dump_prefix_last(prefix), "runtime: <anonymous>");
    bf_dump_prefix_push(prefix);
    DUMP(bf_dump_prefix_last(prefix), "ops: %p", program->runtime.ops);
    bf_dump_prefix_pop(prefix);

    bf_dump_prefix_pop(prefix);
}

static void _bf_program_fixup_insn(struct bpf_insn *insn,
                                   enum bf_fixup_insn type, int32_t value)
{
    switch (type) {
    case BF_FIXUP_INSN_OFF:
        assert(!insn->off);
        assert(value < SHRT_MAX);
        insn->off = (int16_t)value;
        break;
    case BF_FIXUP_INSN_IMM:
        assert(!insn->imm);
        insn->imm = value;
        break;
    default:
        bf_abort(
            "unsupported fixup instruction type, this should not happen: %d",
            type);
        break;
    }
}

static int _bf_program_fixup(struct bf_program *program,
                             enum bf_fixup_type type)
{
    assert(program);
    assert(type >= 0 && type < _BF_FIXUP_TYPE_MAX);

    bf_list_foreach (&program->fixups, fixup_node) {
        enum bf_fixup_insn insn_type = _BF_FIXUP_INSN_MAX;
        int32_t value;
        size_t offset;
        struct bf_fixup *fixup = bf_list_node_get_data(fixup_node);
        struct bpf_insn *insn;

        if (type != fixup->type)
            continue;

        insn = bf_vector_get(&program->img, fixup->insn);
        if (!insn) {
            return bf_err_r(-EINVAL,
                            "fixup references invalid instruction index %lu",
                            fixup->insn);
        }

        switch (type) {
        case BF_FIXUP_TYPE_JMP_NEXT_RULE:
        case BF_FIXUP_TYPE_JMP_GUARD_MISS:
        case BF_FIXUP_TYPE_JMP_VERDICT:
        case BF_FIXUP_TYPE_JMP_MATCH:
            insn_type = BF_FIXUP_INSN_OFF;
            value = (int)(program->img.size - fixup->insn - 1U);
            break;
        case BF_FIXUP_TYPE_COUNTERS_MAP_FD:
            insn_type = BF_FIXUP_INSN_IMM;
            value = program->handle->cmap->fd;
            break;
        case BF_FIXUP_TYPE_PRINTER_MAP_FD:
            insn_type = BF_FIXUP_INSN_IMM;
            value = program->handle->pmap->fd;
            break;
        case BF_FIXUP_TYPE_LOG_MAP_FD:
            insn_type = BF_FIXUP_INSN_IMM;
            value = program->handle->lmap->fd;
            break;
        case BF_FIXUP_TYPE_STATE_MAP_FD:
            insn_type = BF_FIXUP_INSN_IMM;
            value = program->handle->smap->fd;
            break;
        case BF_FIXUP_TYPE_SET_MAP_FD: {
            const struct bf_set_group *group =
                _bf_program_find_set_group(program, fixup->attr.set_ptr);
            if (!group || !group->map) {
                return bf_err_r(
                    -ENOENT, "set map fixup: set '%s' not in any loaded group",
                    fixup->attr.set_ptr ?
                        (fixup->attr.set_ptr->name ?: "<anonymous>") :
                        "(null)");
            }
            insn_type = BF_FIXUP_INSN_IMM;
            value = group->map->fd;
            break;
        }
        case BF_FIXUP_ELFSTUB_CALL:
            insn_type = BF_FIXUP_INSN_IMM;
            offset = program->elfstubs_location[fixup->attr.elfstub_id] -
                     fixup->insn - 1;
            if (offset >= INT_MAX)
                return bf_err_r(-EINVAL, "invalid ELF stub call offset");
            value = (int32_t)offset;
            break;
        default:
            bf_abort("unsupported fixup type, this should not happen: %d",
                     type);
            break;
        }

        _bf_program_fixup_insn(insn, insn_type, value);
        bf_list_delete(&program->fixups, fixup_node);
    }

    return 0;
}

int bf_program_fixup(struct bf_program *program, enum bf_fixup_type type)
{
    return _bf_program_fixup(program, type);
}

/* Pseudo-layer bit tracking the dual TCP/UDP guard in `checked_layers`: the
 * dual condition is recorded separately from the specific L4 guard, so a
 * specific guard subsumes (and suppresses) a later dual guard, while a dual
 * guard followed by a specific L4 matcher still emits the specific guard. */
#define _BF_CHECKED_L4_DUAL BF_FLAG(_BF_MATCHER_LAYER_MAX)

static int _bf_program_check_proto(struct bf_program *program,
                                   enum bf_matcher_type type,
                                   uint32_t *checked_layers)
{
    const struct bf_matcher_meta *meta;

    assert(program);
    assert(checked_layers);

    meta = bf_matcher_get_meta(type);
    if (!meta)
        return bf_err_r(-EINVAL, "missing meta for matcher type %d", type);

    /* Dual TCP/UDP metas guard on r8 holding either protocol, unless a
     * specific L4 guard (which subsumes the dual condition) or a previous
     * dual guard is already established. cgroup_sock_addr programs keep
     * their own self-contained codegen: r8 holds the socket's user port
     * there, not an IPPROTO. */
    if (meta->l4_dual && program->flavor != BF_FLAVOR_CGROUP_SOCK_ADDR) {
        int r;

        if (*checked_layers &
            (BF_FLAG(BF_MATCHER_LAYER_4) | _BF_CHECKED_L4_DUAL))
            return 0;

        r = bf_stub_rule_check_l4_dual(program);
        if (r)
            return r;
        *checked_layers |= _BF_CHECKED_L4_DUAL;

        return 0;
    }

    if (*checked_layers & BF_FLAG(meta->layer))
        return 0;

    if (meta->layer == BF_MATCHER_LAYER_2 ||
        meta->layer == BF_MATCHER_LAYER_3 ||
        meta->layer == BF_MATCHER_LAYER_4) {
        int r = bf_stub_rule_check_protocol(program, meta);
        if (r)
            return r;
        *checked_layers |= BF_FLAG(meta->layer);
    }

    return 0;
}

/**
 * @brief Protocol guard signature of a rule.
 *
 * Mirrors the protocol conditions `_bf_program_check_proto()` would emit
 * for the rule: for each of layers 3 and 4, whether a guard is emitted and
 * the protocol ID it tests, plus whether the dual TCP/UDP guard is emitted.
 * Rules with equal signatures establish the same r7/r8 conditions, so
 * consecutive ones share a guard group.
 */
struct bf_guard_sig
{
    /** The rule guards on an L3 protocol. */
    bool has_l3;
    /** L3 protocol guarded on (`bf_matcher_meta.hdr_id`). */
    uint16_t l3_proto;
    /** The rule guards on an L4 protocol. */
    bool has_l4;
    /** L4 protocol guarded on (`bf_matcher_meta.hdr_id`). */
    uint8_t l4_proto;
    /** The rule guards on the dual TCP/UDP condition
     * (`bf_matcher_meta.l4_dual`), not subsumed by a specific L4 guard. */
    bool has_l4_dual;
};

/**
 * @brief Fold a matcher type into a rule's guard signature.
 *
 * Only the first matcher requiring a given layer contributes to the
 * signature, mirroring the `checked_layers` dedup in
 * `_bf_program_generate_rule()`: later matchers on an already-recorded
 * layer never emit a guard. A dual TCP/UDP meta contributes only when no
 * specific L4 guard is recorded yet, mirroring the emission-time
 * subsumption in `_bf_program_check_proto()`: both walk the matcher list
 * in the same order, so signature and emission stay consistent.
 *
 * @param program Program the rule belongs to. Can't be NULL.
 * @param sig Signature to update. Can't be NULL.
 * @param type Matcher type to fold in.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_guard_sig_add(const struct bf_program *program,
                             struct bf_guard_sig *sig,
                             enum bf_matcher_type type)
{
    const struct bf_matcher_meta *meta;

    assert(program);
    assert(sig);

    meta = bf_matcher_get_meta(type);
    if (!meta)
        return bf_err_r(-EINVAL, "missing meta for matcher type %d", type);

    if (meta->l4_dual && program->flavor != BF_FLAVOR_CGROUP_SOCK_ADDR) {
        if (!sig->has_l4)
            sig->has_l4_dual = true;
        return 0;
    }

    switch (meta->layer) {
    case BF_MATCHER_LAYER_3:
        if (!sig->has_l3) {
            sig->has_l3 = true;
            sig->l3_proto = (uint16_t)meta->hdr_id;
        }
        break;
    case BF_MATCHER_LAYER_4:
        if (!sig->has_l4) {
            sig->has_l4 = true;
            sig->l4_proto = (uint8_t)meta->hdr_id;
        }
        break;
    default:
        break;
    }

    return 0;
}

/**
 * @brief Compute a rule's guard signature, without emitting anything.
 *
 * Iterates the rule's matchers the same way the guard-emission loop does,
 * expanding `BF_MATCHER_SET` matchers into their key components.
 *
 * @param program Program the rule belongs to. Can't be NULL.
 * @param rule Rule to compute the signature of. Can't be NULL.
 * @param sig On success, the rule's guard signature. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_program_rule_guard_sig(const struct bf_program *program,
                                      const struct bf_rule *rule,
                                      struct bf_guard_sig *sig)
{
    int r;

    assert(program);
    assert(rule);
    assert(sig);

    memset(sig, 0, sizeof(*sig));

    bf_list_foreach (&rule->matchers, matcher_node) {
        struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);

        if (bf_matcher_get_type(matcher) == BF_MATCHER_SET) {
            const struct bf_set *set =
                bf_chain_get_set_for_matcher(program->runtime.chain, matcher);

            if (!set) {
                return bf_err_r(-ENOENT, "rule %u references non-existent set",
                                rule->index);
            }

            for (size_t i = 0; i < set->n_comps; ++i) {
                r = _bf_guard_sig_add(program, sig, set->key[i]);
                if (r)
                    return r;
            }
        } else {
            r = _bf_guard_sig_add(program, sig, bf_matcher_get_type(matcher));
            if (r)
                return r;
        }
    }

    return 0;
}

/**
 * @brief Emit a rule's protocol guards, deduplicated across rules.
 *
 * Protocol guard stage: consecutive rules with the same guard signature
 * share a guard group. Only the first rule of the group emits the r7/r8
 * protocol guards (through `bf_stub_rule_check_protocol()`, or
 * `bf_stub_rule_check_l4_dual()` for the dual TCP/UDP condition of the
 * meta port matchers), and a guard miss jumps past the whole group: the
 * pending `BF_FIXUP_TYPE_JMP_GUARD_MISS` fixups resolve when the group
 * closes. A specific L4 guard subsumes the dual condition: within a rule,
 * it suppresses a later dual guard (while a dual guard doesn't suppress a
 * later specific guard), and across rules, the `has_l4_dual` signature
 * field keeps single-protocol rules from joining dual-guarded groups.
 * In-group rules are entered only from the previous rule's matcher-miss
 * paths, all of which are post-guard, so their protocol conditions are
 * already established. The group is force-closed before the accumulated
 * guard-miss offset can overflow the jump's 16-bit displacement: the
 * breaking rule re-emits its guards, and packets on the guard-miss path
 * fail them again, hopping group to group.
 *
 * @param program Program to generate bytecode into. Can't be NULL.
 * @param rule Rule to emit the guards of. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_program_emit_rule_guards(struct bf_program *program,
                                        const struct bf_rule *rule)
{
    uint32_t checked_layers = 0;
    struct bf_guard_sig sig;
    int r;

    r = _bf_program_rule_guard_sig(program, rule, &sig);
    if (r)
        return r;

    if (program->guard_group.active &&
        program->guard_group.has_l3 == sig.has_l3 &&
        program->guard_group.l3_proto == sig.l3_proto &&
        program->guard_group.has_l4 == sig.has_l4 &&
        program->guard_group.l4_proto == sig.l4_proto &&
        program->guard_group.has_l4_dual == sig.has_l4_dual &&
        program->img.size - program->guard_group.start_insn < SHRT_MAX / 2)
        return 0;

    r = _bf_program_fixup(program, BF_FIXUP_TYPE_JMP_GUARD_MISS);
    if (r)
        return bf_err_r(r, "failed to generate guard miss fixups");

    program->guard_group.active = true;
    program->guard_group.has_l3 = sig.has_l3;
    program->guard_group.l3_proto = sig.l3_proto;
    program->guard_group.has_l4 = sig.has_l4;
    program->guard_group.l4_proto = sig.l4_proto;
    program->guard_group.has_l4_dual = sig.has_l4_dual;
    program->guard_group.start_insn = program->img.size;

    bf_list_foreach (&rule->matchers, matcher_node) {
        struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);

        if (bf_matcher_get_type(matcher) == BF_MATCHER_SET) {
            const struct bf_set *set =
                bf_chain_get_set_for_matcher(program->runtime.chain, matcher);

            if (!set) {
                return bf_err_r(-ENOENT, "rule %u references non-existent set",
                                rule->index);
            }

            for (size_t i = 0; i < set->n_comps && !r; ++i)
                r = _bf_program_check_proto(program, set->key[i],
                                            &checked_layers);
        } else {
            r = _bf_program_check_proto(program, bf_matcher_get_type(matcher),
                                        &checked_layers);
        }

        if (r)
            return r;
    }

    return 0;
}

/**
 * @brief Check whether a rule may join a field-cache run.
 *
 * A rule may consume and publish the r1/r2 field cache (see the
 * pipeline comment in cgen/packet.c), and be a member of a verdict run,
 * only if its whole body is a single cacheable matcher followed by an
 * exiting verdict: log, counters, mark, and REDIRECT emit
 * helper/kfunc/ELF-stub calls that clobber r1-r5, and CONTINUE falls
 * through to the next rule after a match, with register state diverging
 * from the compare-miss path.
 *
 * Tree emission of a run (see `_bf_program_collect_verdict_run()`)
 * additionally requires the matcher to be non-negated: a negated-EQ
 * member means "field != value -> verdict" and is not a membership test.
 * Negated members keep the linear member path, which folds the polarity
 * per member.
 *
 * @param rule Rule to check. Can't be NULL.
 * @return True if the rule is run-eligible.
 */
static bool _bf_rule_is_run_eligible(const struct bf_rule *rule)
{
    return bf_list_size(&rule->matchers) == 1 &&
           bf_packet_matcher_is_cacheable(
               bf_list_node_get_data(bf_list_get_head(&rule->matchers))) &&
           !rule->log && !rule->has_counters && !bf_rule_mark_is_set(rule) &&
           (rule->verdict == BF_VERDICT_ACCEPT ||
            rule->verdict == BF_VERDICT_DROP ||
            rule->verdict == BF_VERDICT_NEXT);
}

/**
 * @brief Get the type of a rule's single matcher.
 *
 * Only meaningful for run-eligible rules, which carry exactly one matcher.
 *
 * @param rule Rule to get the matcher type of. Can't be NULL.
 * @return The rule's single matcher's type.
 */
static enum bf_matcher_type _bf_rule_matcher_type(const struct bf_rule *rule)
{
    return bf_matcher_get_type(
        bf_list_node_get_data(bf_list_get_head(&rule->matchers)));
}

/** Minimum number of unique reference values in a collected verdict run for
 * the run to be emitted as a search tree instead of a linear compare
 * chain. */
#define _BF_RUN_TREE_MIN_VALUES 8

/** Worst-case instruction slots emitted per tree value for field sizes up
 * to 4 bytes: one internal-node compare plus one leaf compare, rounded up
 * to cover the per-chunk next-rule jump. */
#define _BF_RUN_TREE_SLOTS_PER_VALUE 3

/** Worst-case instruction slots emitted per tree value for 16-byte fields:
 * internal nodes and leaves each need two `LD_IMM64` (2 slots apiece) and
 * two compare/jump instructions, plus the per-chunk next-rule jump. */
#define _BF_RUN_TREE_SLOTS_PER_VALUE_16 9

/**
 * @brief Check whether a rule may join the verdict run being collected.
 *
 * Same predicate as the incremental verdict-run membership in
 * `_bf_program_generate_rule()`, plus non-negation: see
 * `_bf_rule_is_run_eligible()`.
 *
 * @param rule Rule to check. Can't be NULL.
 * @param type Matcher type of the run's first rule.
 * @param verdict Verdict of the run's first rule.
 * @return True if the rule may join the run.
 */
static bool _bf_rule_joins_run(const struct bf_rule *rule,
                               enum bf_matcher_type type,
                               enum bf_verdict verdict)
{
    return _bf_rule_is_run_eligible(rule) &&
           _bf_rule_matcher_type(rule) == type && rule->verdict == verdict &&
           !bf_matcher_get_negate(
               bf_list_node_get_data(bf_list_get_head(&rule->matchers)));
}

/**
 * @brief Collect a maximal verdict run starting at a rule.
 *
 * Starting from the enabled rule at @p start_node, walk the chain forward
 * collecting consecutive rules eligible for tree emission: run-eligible
 * (see `_bf_rule_is_run_eligible()`), non-negated, carrying the same
 * matcher type and the same verdict as the first rule. Disabled rules
 * inside the window are skipped, mirroring the next-enabled-rule peek of
 * the incremental machinery.
 *
 * Collection stops before the worst-case emitted block size can overflow
 * the `SHRT_MAX / 2` displacement guard shared with the guard-group and
 * verdict-run force-close logic: a value costs at most 3 instruction
 * slots for field sizes up to 4 bytes, 9 slots for 16-byte fields. A
 * longer run simply continues into a following tree block, which
 * re-enters through the guard group and the field cache, so the split
 * costs nothing on the hot path.
 *
 * Runs shorter than `_BF_RUN_TREE_MIN_VALUES` are not collected: they
 * can't reach the unique-value threshold, and the incremental machinery
 * handles them.
 *
 * @param start_node Node of the run's first rule. The rule must be
 *        enabled. Can't be NULL.
 * @param matchers On success, array of the collected rules' matchers, in
 *        chain order, owned by the caller. NULL if no run was collected.
 *        Can't be NULL.
 * @param n_matchers On success, number of collected matchers. 0 if no run
 *        was collected. Can't be NULL.
 * @param last_node On success, node of the run's last collected rule;
 *        unchanged if no run was collected. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_program_collect_verdict_run(bf_list_node *start_node,
                                           const struct bf_matcher ***matchers,
                                           size_t *n_matchers,
                                           bf_list_node **last_node)
{
    _cleanup_free_ const struct bf_matcher **_matchers = NULL;
    const struct bf_rule *first = bf_list_node_get_data(start_node);
    const struct bf_matcher_meta *meta;
    enum bf_matcher_type type;
    bf_list_node *last = NULL;
    size_t count = 0;
    size_t cap;
    size_t n;

    assert(start_node);
    assert(matchers);
    assert(n_matchers);
    assert(last_node);

    *matchers = NULL;
    *n_matchers = 0;

    if (!_bf_rule_is_run_eligible(first))
        return 0;

    type = _bf_rule_matcher_type(first);

    meta = bf_matcher_get_meta(type);
    if (!meta)
        return bf_err_r(-EINVAL, "missing meta for matcher type %d", type);

    cap = (size_t)(SHRT_MAX / 2) / (meta->hdr_payload_size == 16 ?
                                        _BF_RUN_TREE_SLOTS_PER_VALUE_16 :
                                        _BF_RUN_TREE_SLOTS_PER_VALUE);

    for (bf_list_node *node = start_node; node && count < cap;
         node = bf_list_node_next(node)) {
        const struct bf_rule *rule = bf_list_node_get_data(node);

        if (rule->disabled)
            continue;

        if (!_bf_rule_joins_run(rule, type, first->verdict))
            break;

        ++count;
        last = node;
    }

    if (count < _BF_RUN_TREE_MIN_VALUES)
        return 0;

    _matchers = malloc(count * sizeof(*_matchers));
    if (!_matchers)
        return -ENOMEM;

    n = 0;
    for (bf_list_node *node = start_node; n < count;
         node = bf_list_node_next(node)) {
        const struct bf_rule *rule = bf_list_node_get_data(node);

        if (rule->disabled)
            continue;

        _matchers[n++] =
            bf_list_node_get_data(bf_list_get_head(&rule->matchers));
    }

    *matchers = TAKE_PTR(_matchers);
    *n_matchers = count;
    *last_node = last;

    return 0;
}

/**
 * @brief Check whether a run reaches the tree unique-value threshold.
 *
 * Counts unique reference payloads, stopping as soon as
 * `_BF_RUN_TREE_MIN_VALUES` are found. Runs below the threshold stay on
 * the linear member path: a search tree over a handful of values doesn't
 * beat the compare chain.
 *
 * @param matchers Matchers of the collected run. Can't be NULL.
 * @param n Number of matchers in @p matchers . Can't be 0.
 * @return True if the run holds at least `_BF_RUN_TREE_MIN_VALUES` unique
 *         reference values.
 */
static bool _bf_run_reaches_tree_threshold(const struct bf_matcher **matchers,
                                           size_t n)
{
    const struct bf_matcher_meta *meta =
        bf_matcher_get_meta(bf_matcher_get_type(matchers[0]));
    const void *uniques[_BF_RUN_TREE_MIN_VALUES];
    size_t n_unique = 0;

    assert(meta);

    for (size_t i = 0; i < n; ++i) {
        const void *payload = bf_matcher_payload(matchers[i]);
        bool dup = false;

        for (size_t j = 0; j < n_unique; ++j) {
            if (memcmp(payload, uniques[j], meta->hdr_payload_size) == 0) {
                dup = true;
                break;
            }
        }

        if (dup)
            continue;

        uniques[n_unique++] = payload;
        if (n_unique == _BF_RUN_TREE_MIN_VALUES)
            return true;
    }

    return false;
}

/**
 * @brief Generate a collected verdict run as a search-tree block.
 *
 * Reproduces the stages of `_bf_program_generate_rule()` for the whole
 * run at once: guard group open/join (one emission covers the block, as
 * every rule of the run carries the same matcher type, hence the same
 * signature), field-cache eligibility (every collected rule satisfies the
 * conditions by construction), tree emission, then the shared verdict
 * block. The incremental verdict-run member protocol is bypassed; if the
 * preceding rule joined the run as a member (a negated same-type,
 * same-verdict rule is eligible for the linear run but not for the tree),
 * its pending match jumps resolve to the block's shared verdict pair,
 * which carries the same verdict by construction.
 *
 * Fixups resolve in the same order as the closing rule of a linear run:
 * pending `BF_FIXUP_TYPE_JMP_VERDICT` jumps land on the shared
 * `MOV r0` + `EXIT` pair, and `BF_FIXUP_TYPE_JMP_NEXT_RULE` jumps land
 * right after it, on the rule following the block.
 *
 * @param program Program to generate bytecode into. Can't be NULL.
 * @param rule First rule of the run. Can't be NULL.
 * @param matchers Matchers of the run's rules. Can't be NULL.
 * @param n Number of matchers in @p matchers . Can't be 0.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_program_generate_verdict_run_tree(
    struct bf_program *program, const struct bf_rule *rule,
    const struct bf_matcher **matchers, size_t n)
{
    int ret_code;
    int r;

    r = _bf_program_emit_rule_guards(program, rule);
    if (r)
        return r;

    program->field_cache.rule_eligible = true;

    r = bf_packet_gen_verdict_run_tree(program, matchers, n);
    if (r)
        return r;

    r = program->runtime.ops->get_verdict(rule->verdict, &ret_code);
    if (r)
        return r;

    r = _bf_program_fixup(program, BF_FIXUP_TYPE_JMP_VERDICT);
    if (r)
        return bf_err_r(r, "failed to generate verdict fixups");
    program->verdict_run.active = false;

    EMIT(program, BPF_MOV64_IMM(BPF_REG_0, ret_code));
    EMIT(program, BPF_EXIT_INSN());

    r = _bf_program_fixup(program, BF_FIXUP_TYPE_JMP_NEXT_RULE);
    if (r)
        return bf_err_r(r, "failed to generate next rule fixups");

    return 0;
}

static int _bf_program_generate_rule(struct bf_program *program,
                                     struct bf_rule *rule,
                                     const struct bf_rule *next)
{
    bool run_member;
    int ret_code;
    int r = 0;

    assert(program);
    assert(rule);
    assert(program->runtime.ops->gen_inline_matcher);
    assert(program->runtime.ops->gen_inline_log);

    if (rule->disabled)
        return 0;

    program->field_cache.rule_eligible = _bf_rule_is_run_eligible(rule);
    if (!program->field_cache.rule_eligible)
        program->field_cache.valid = false;

    /* Verdict-run stage: consecutive run-eligible rules carrying the same
     * matcher type (hence the same guard signature and field-cache key)
     * and the same verdict share a single `MOV r0` + `EXIT` block. Every
     * rule of the run but the last is a member: its compare jumps to the
     * shared block on match (a pending `BF_FIXUP_TYPE_JMP_VERDICT` fixup)
     * and falls through to the next rule on mismatch. The run closes on
     * the first non-member rule, whose own `MOV r0` becomes the shared
     * block: the pending fixups resolve right before it. The run is
     * force-closed before the accumulated match-jump offset can overflow
     * the jump's 16-bit displacement: the breaking rule emits its verdict
     * in normal polarity, resolving all pending match jumps to its own
     * verdict pair (correct, since every run rule shares the verdict),
     * and a new run simply restarts at the next rule. */
    run_member =
        program->field_cache.rule_eligible && next &&
        _bf_rule_is_run_eligible(next) &&
        _bf_rule_matcher_type(next) == _bf_rule_matcher_type(rule) &&
        next->verdict == rule->verdict &&
        !(program->verdict_run.active &&
          program->img.size - program->verdict_run.start_insn >= SHRT_MAX / 2);
    if (run_member) {
        program->verdict_run.member = true;
        if (!program->verdict_run.active) {
            program->verdict_run.active = true;
            program->verdict_run.verdict = rule->verdict;
            program->verdict_run.start_insn = program->img.size;
        }
    }

    /* Protocol guard stage: open or join the rule's guard group, see
     * `_bf_program_emit_rule_guards()`. */
    r = _bf_program_emit_rule_guards(program, rule);
    if (r)
        return r;

    bf_list_foreach (&rule->matchers, matcher_node) {
        struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);

        r = program->runtime.ops->gen_inline_matcher(program, matcher);
        if (r)
            return r;
    }

    program->verdict_run.member = false;

    if (bf_rule_mark_is_set(rule)) {
        if (!program->runtime.ops->gen_inline_set_mark) {
            return bf_err_r(-ENOTSUP, "set mark is not supported by %s",
                            program->runtime.chain->name);
        }

        r = program->runtime.ops->gen_inline_set_mark(program,
                                                      bf_rule_mark_get(rule));
        if (r) {
            return bf_err_r(r,
                            "failed to generate bytecode to set mark for '%s'",
                            program->runtime.chain->name);
        }
    }

    /* The packet logging and update counters ELF stubs both read
     * ctx->pkt_size: derive and store it here, on the only per-rule paths
     * reaching those stubs. Rules carrying log or counters are excluded from
     * verdict runs and field-cache eligibility, so the op's r1-r3 clobbering
     * can't invalidate a published field cache. */
    if (rule->log || rule->has_counters) {
        r = program->runtime.ops->gen_inline_store_pkt_size(program);
        if (r)
            return r;
    }

    if (rule->log && rule->log_rate_ns) {
        /* Rate-limited log: check last_log_ts in the state map before
         * logging. Only r0 to r3 are used: bpf_ktime_get_ns() is called
         * before the state map pointer is loaded, so no value has to
         * survive a helper call. R9 is reserved for the L4 header address
         * in packet flavors and can't be borrowed here.
         *
         * The helper is called before the NULL check: the NULL branch only
         * exists to satisfy the verifier, as the prologue lookup on a
         * single-entry array map can't miss at runtime. */
        EMIT(program, BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns));
        EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10,
                                  BF_PROG_CTX_OFF(state_map)));
        {
            // Outer skip: state_map is NULL (shouldn't happen at runtime,
            // but the verifier requires the NULL check).
            _clean_bf_jmpctx_ struct bf_jmpctx null_ctx =
                bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, 0));

            if (rule->index > 0) {
                EMIT(program,
                     BPF_ALU64_IMM(
                         BPF_ADD, BPF_REG_1,
                         (int)(rule->index * sizeof(struct bf_rule_state))));
            }

            EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, 0));
            EMIT(program, BPF_MOV64_REG(BPF_REG_3, BPF_REG_0));
            EMIT(program, BPF_ALU64_REG(BPF_SUB, BPF_REG_3, BPF_REG_2));

            {
                // Load log_rate_ns as a 64-bit immediate into R2.
                const struct bpf_insn rate_insn[2] = {
                    BPF_LD_IMM64(BPF_REG_2, rule->log_rate_ns),
                };
                EMIT(program, rate_insn[0]);
                EMIT(program, rate_insn[1]);
            }

            {
                // Inner skip: delta < log_rate_ns means still within window.
                _clean_bf_jmpctx_ struct bf_jmpctx rate_ctx = bf_jmpctx_get(
                    program, BPF_JMP_REG(BPF_JLT, BPF_REG_3, BPF_REG_2, 0));

                EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0, 0));

                r = program->runtime.ops->gen_inline_log(program, rule);
                if (r)
                    return r;
            }
        }
    } else if (rule->log) {
        r = program->runtime.ops->gen_inline_log(program, rule);
        if (r)
            return r;
    }

    if (rule->has_counters) {
        EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
        EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(arg)));
        EMIT_LOAD_COUNTERS_FD_FIXUP(program, BPF_REG_2);
        EMIT(program, BPF_MOV32_IMM(BPF_REG_3, rule->index));
        EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_UPDATE_COUNTERS);
    }

    /* A run member's verdict materializes through the run's shared
     * verdict block: its compare already jumps there on match, and mark,
     * log, and counters blocks are unreachable by eligibility, so the
     * verdict switch is skipped entirely. */
    if (!run_member) {
        switch (rule->verdict) {
        case BF_VERDICT_ACCEPT:
        case BF_VERDICT_DROP:
        case BF_VERDICT_NEXT:
            r = program->runtime.ops->get_verdict(rule->verdict, &ret_code);
            if (r)
                return r;

            /* Closing rule of a verdict run: its `MOV r0` is the run's
             * shared verdict block, so the pending match jumps resolve
             * right before it. The closing rule's verdict equals the
             * run's by construction. */
            if (program->verdict_run.active) {
                r = _bf_program_fixup(program, BF_FIXUP_TYPE_JMP_VERDICT);
                if (r)
                    return bf_err_r(r, "failed to generate verdict fixups");
                program->verdict_run.active = false;
            }

            EMIT(program, BPF_MOV64_IMM(BPF_REG_0, ret_code));
            EMIT(program, BPF_EXIT_INSN());
            break;
        case BF_VERDICT_REDIRECT:
            if (!program->runtime.ops->gen_inline_redirect) {
                return bf_err_r(-ENOTSUP,
                                "redirect is not supported by %s hook",
                                bf_hook_to_str(program->runtime.chain->hook));
            }
            r = program->runtime.ops->gen_inline_redirect(
                program, rule->redirect_ifindex, rule->redirect_dir);
            if (r)
                return r;
            break;
        case BF_VERDICT_CONTINUE:
            // Fall through to next rule or default chain policy.
            break;
        default:
            bf_abort("unsupported verdict, this should not happen: %d",
                     rule->verdict);
            break;
        }
    }

    r = _bf_program_fixup(program, BF_FIXUP_TYPE_JMP_NEXT_RULE);
    if (r)
        return bf_err_r(r, "failed to generate next rule fixups");

    return 0;
}

static int _bf_program_generate_elfstubs(struct bf_program *program)
{
    const struct bf_elfstub *elfstub;
    size_t start_at;
    int r;

    assert(program);

    bf_list_foreach (&program->fixups, fixup_node) {
        struct bf_fixup *fixup = bf_list_node_get_data(fixup_node);
        size_t off = program->img.size;

        if (fixup->type != BF_FIXUP_ELFSTUB_CALL)
            continue;

        // Only generate each ELF stub once
        if (program->elfstubs_location[fixup->attr.elfstub_id])
            continue;

        bf_dbg("generate ELF stub for ID %d", fixup->attr.elfstub_id);

        elfstub = bf_ctx_get_elfstub(fixup->attr.elfstub_id);
        if (!elfstub) {
            return bf_err_r(-ENOENT, "no ELF stub found for ID %d",
                            fixup->attr.elfstub_id);
        }

        start_at = program->img.size;

        for (size_t i = 0; i < elfstub->ninsns; ++i) {
            r = bf_program_emit(program, elfstub->insns[i]);
            if (r)
                return bf_err_r(r, "failed to insert ELF stub instruction");
        }

        bf_list_foreach (&elfstub->strs, pstr_node) {
            _free_bf_fixup_ struct bf_fixup *fixup = NULL;
            struct bf_printk_str *pstr = bf_list_node_get_data(pstr_node);
            size_t insn_idx = start_at + pstr->insn_idx;
            const struct bf_printer_msg *msg =
                bf_printer_add_msg(program->printer, pstr->str);
            struct bpf_insn ld_insn[2] = {
                BPF_LD_MAP_FD(BPF_REG_1, 0),
            };

            ld_insn[0].src_reg = BPF_PSEUDO_MAP_VALUE;
            ld_insn[1].imm = (int)bf_printer_msg_offset(msg);

            r = bf_vector_set(&program->img, insn_idx, &ld_insn[0]);
            if (r) {
                return bf_err_r(
                    r, "failed to set ELF stub instruction at index %lu",
                    insn_idx);
            }
            r = bf_vector_set(&program->img, insn_idx + 1, &ld_insn[1]);
            if (r) {
                return bf_err_r(
                    r, "failed to set ELF stub instruction at index %lu",
                    insn_idx + 1);
            }

            r = bf_fixup_new(&fixup, BF_FIXUP_TYPE_PRINTER_MAP_FD, insn_idx,
                             NULL);
            if (r)
                return r;

            r = bf_list_add_tail(&program->fixups, fixup);
            if (r)
                return r;

            TAKE_PTR(fixup);
        }

        program->elfstubs_location[fixup->attr.elfstub_id] = off;
    }

    return 0;
}

int bf_program_emit_kfunc_call(struct bf_program *program, const char *name)
{
    int r;

    assert(program);
    assert(name);

    r = bf_btf_get_id(name);
    if (r < 0)
        return r;

    EMIT(program, ((struct bpf_insn) {.code = BPF_JMP | BPF_CALL,
                                      .dst_reg = 0,
                                      .src_reg = BPF_PSEUDO_KFUNC_CALL,
                                      .off = 0,
                                      .imm = r}));

    return 0;
}

int bf_program_emit_fixup(struct bf_program *program, enum bf_fixup_type type,
                          struct bpf_insn insn, const union bf_fixup_attr *attr)
{
    _free_bf_fixup_ struct bf_fixup *fixup = NULL;
    int r;

    assert(program);

    EMIT(program, insn);

    r = bf_fixup_new(&fixup, type, program->img.size - 1, attr);
    if (r)
        return r;

    r = bf_list_add_tail(&program->fixups, fixup);
    if (r)
        return r;

    TAKE_PTR(fixup);

    return 0;
}

int bf_program_emit_fixup_elfstub(struct bf_program *program,
                                  enum bf_elfstub_id id)
{
    _free_bf_fixup_ struct bf_fixup *fixup = NULL;
    int r;

    assert(program);

    EMIT(program, BPF_CALL_REL(0));

    r = bf_fixup_new(&fixup, BF_FIXUP_ELFSTUB_CALL, program->img.size - 1,
                     NULL);
    if (r)
        return r;

    fixup->attr.elfstub_id = id;

    r = bf_list_add_tail(&program->fixups, fixup);
    if (r)
        return r;

    TAKE_PTR(fixup);

    return 0;
}

int bf_program_generate(struct bf_program *program)
{
    const struct bf_chain *chain = program->runtime.chain;
    int ret_code;
    int r;

    r = _bf_program_build_set_groups(program);
    if (r)
        return bf_err_r(r, "failed to build set groups");

    // Save the program's argument into the context.
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, BF_PROG_CTX_OFF(arg)));

    // Reset the protocol ID registers
    EMIT(program, BPF_MOV64_IMM(BPF_REG_7, 0));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_8, 0));

    // If at least one rule logs the matched packets, populate ctx->log_map
    if (program->runtime.chain->flags & BF_FLAG(BF_CHAIN_LOG)) {
        EMIT_LOAD_LOG_FD_FIXUP(program, BPF_REG_2);
        EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2,
                                  BF_PROG_CTX_OFF(log_map)));
    }

    // Zeroing IPv6 extension headers
    if (program->runtime.chain->flags & BF_FLAG(BF_CHAIN_STORE_NEXTHDR)) {
        EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_7,
                                  BF_PROG_CTX_OFF(ipv6_eh)));
    }

    r = program->runtime.ops->gen_inline_prologue(program);
    if (r)
        return r;

    // Populate ctx->state_map with the base pointer from the single-entry
    // state map. The key (0) is written to scratch[0..3] temporarily.
    // Placed after gen_inline_prologue so R1-R5 are free: the helper call
    // does not need to be followed by a ctx restore.
    if (program->runtime.chain->flags & BF_FLAG(BF_CHAIN_LOG_RATELIMIT)) {
        EMIT(program, BPF_ST_MEM(BPF_W, BPF_REG_10, BF_PROG_SCR_OFF(0), 0));
        EMIT_LOAD_STATE_FD_FIXUP(program, BPF_REG_1);
        EMIT(program, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
        EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, BF_PROG_SCR_OFF(0)));
        EMIT(program, BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem));
        EMIT(program, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0,
                                  BF_PROG_CTX_OFF(state_map)));
    }

    for (bf_list_node *rule_node = bf_list_get_head(&chain->rules); rule_node;
         rule_node = bf_list_node_next(rule_node)) {
        struct bf_rule *rule = bf_list_node_get_data(rule_node);
        bf_list_node *next_node = bf_list_node_next(rule_node);
        const struct bf_rule *next = NULL;

        /* Tree stage: collect a maximal verdict run; if it holds enough
         * unique reference values, emit it as a single search-tree block
         * and resume the walk past the consumed rules. Shorter or
         * repetitive runs fall through to `_bf_program_generate_rule()`,
         * whose incremental verdict-run machinery handles them.
         * cgroup_sock_addr chains keep the linear path: the tree emitter
         * relies on the packet-flavor field loads. */
        if (!rule->disabled && program->flavor != BF_FLAVOR_CGROUP_SOCK_ADDR) {
            _cleanup_free_ const struct bf_matcher **matchers = NULL;
            bf_list_node *last_node = NULL;
            size_t n = 0;

            r = _bf_program_collect_verdict_run(rule_node, &matchers, &n,
                                                &last_node);
            if (r)
                return r;

            if (n && _bf_run_reaches_tree_threshold(matchers, n)) {
                r = _bf_program_generate_verdict_run_tree(program, rule,
                                                          matchers, n);
                if (r)
                    return r;

                rule_node = last_node;
                continue;
            }
        }

        /* Peek at the next enabled rule, skipping disabled ones: the
         * verdict-run logic groups a rule with the rule that actually
         * generates the following bytecode. */
        while (next_node && !next) {
            const struct bf_rule *candidate = bf_list_node_get_data(next_node);

            if (!candidate->disabled)
                next = candidate;
            next_node = bf_list_node_next(next_node);
        }

        r = _bf_program_generate_rule(program, rule, next);
        if (r)
            return r;
    }

    /* Close the trailing guard group: pending guard-miss jumps resolve to
     * the chain-policy path, the same convergence point as the last rule's
     * next-rule jumps. */
    r = _bf_program_fixup(program, BF_FIXUP_TYPE_JMP_GUARD_MISS);
    if (r)
        return bf_err_r(r, "failed to generate guard miss fixups");
    program->guard_group.active = false;

    r = program->runtime.ops->gen_inline_epilogue(program);
    if (r)
        return r;

    // Call the update counters function
    /// @todo Allow chains to have no counters at all.
    r = program->runtime.ops->gen_inline_store_pkt_size(program);
    if (r)
        return r;

    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(arg)));
    EMIT_LOAD_COUNTERS_FD_FIXUP(program, BPF_REG_2);
    EMIT(program,
         BPF_MOV32_IMM(BPF_REG_3, bf_program_chain_counter_idx(program)));
    EMIT_FIXUP_ELFSTUB(program, BF_ELFSTUB_UPDATE_COUNTERS);

    r = program->runtime.ops->get_verdict(chain->policy, &ret_code);
    if (r)
        return r;
    EMIT(program, BPF_MOV64_IMM(BPF_REG_0, ret_code));
    EMIT(program, BPF_EXIT_INSN());

    r = _bf_program_generate_elfstubs(program);
    if (r)
        return r;

    r = _bf_program_fixup(program, BF_FIXUP_ELFSTUB_CALL);
    if (r)
        return bf_err_r(r, "failed to generate ELF stub call fixups");

    return 0;
}

static int _bf_program_load_printer_map(struct bf_program *program)
{
    _cleanup_free_ void *pstr = NULL;
    size_t pstr_len;
    uint32_t key = 0;
    int r;

    assert(program);

    r = bf_printer_assemble(program->printer, &pstr, &pstr_len);
    if (r)
        return bf_err_r(r, "failed to assemble printer map string");

    r = bf_map_new(&program->handle->pmap, _BF_PRINTER_MAP_NAME,
                   BF_MAP_TYPE_PRINTER, sizeof(uint32_t), pstr_len, 1);
    if (r)
        return bf_err_r(r, "failed to create the printer bf_map object");

    r = bf_map_set_elem(program->handle->pmap, &key, pstr);
    if (r)
        return bf_err_r(r, "failed to set print map elem");

    r = _bf_program_fixup(program, BF_FIXUP_TYPE_PRINTER_MAP_FD);
    if (r)
        return bf_err_r(r, "failed to fixup printer map FD");

    return 0;
}

static int _bf_program_load_counters_map(struct bf_program *program)
{
    int r;

    assert(program);

    r = bf_map_new(&program->handle->cmap, _BF_COUNTER_MAP_NAME,
                   BF_MAP_TYPE_COUNTERS, sizeof(uint32_t),
                   sizeof(struct bf_counter),
                   bf_list_size(&program->runtime.chain->rules) + 2);
    if (r)
        return bf_err_r(r, "failed to create the counters bf_map object");

    r = _bf_program_fixup(program, BF_FIXUP_TYPE_COUNTERS_MAP_FD);
    if (r)
        return bf_err_r(r, "failed to fixup counters map FD");

    return 0;
}

static int _bf_program_load_log_map(struct bf_program *program)
{
    int r;

    assert(program);

    // Do not create a log map if it's unused in the chain
    if (!(program->runtime.chain->flags & BF_FLAG(BF_CHAIN_LOG)))
        return 0;

    r = bf_map_new(&program->handle->lmap, _BF_LOG_MAP_NAME, BF_MAP_TYPE_LOG, 0,
                   0, _BF_LOG_MAP_SIZE);
    if (r)
        return bf_err_r(r, "failed to create the log bf_map object");

    r = _bf_program_fixup(program, BF_FIXUP_TYPE_LOG_MAP_FD);
    if (r)
        return bf_err_r(r, "failed to fixup log map FD");

    return 0;
}

static int _bf_program_load_state_map(struct bf_program *program)
{
    size_t n_rules;
    int r;

    assert(program);

    if (!(program->runtime.chain->flags & BF_FLAG(BF_CHAIN_LOG_RATELIMIT)))
        return 0;

    n_rules = bf_list_size(&program->runtime.chain->rules);
    if (n_rules == 0)
        return 0;

    r = bf_map_new(&program->handle->smap, _BF_STATE_MAP_NAME,
                   BF_MAP_TYPE_STATE, sizeof(uint32_t),
                   n_rules * sizeof(struct bf_rule_state), 1);
    if (r)
        return bf_err_r(r, "failed to create the state bf_map object");

    r = _bf_program_fixup(program, BF_FIXUP_TYPE_STATE_MAP_FD);
    if (r)
        return bf_err_r(r, "failed to fixup state map FD");

    return 0;
}

static uint64_t _bf_dedup_hash(const void *data, void *ctx)
{
    return bf_fnv1a(data, *(const size_t *)ctx, bf_fnv1a_init());
}

static bool _bf_dedup_equal(const void *lhs, const void *rhs, void *ctx)
{
    return memcmp(lhs, rhs, *(const size_t *)ctx) == 0;
}

/**
 * @brief Load set maps, one BPF map per `bf_set_group`.
 *
 * Hash-keyed sets that share the same key format have already been
 * grouped by `_bf_program_build_set_groups()`; LPM trie sets each occupy
 * their own single-set group. Each group collapses to one BPF map whose
 * value is a bitmask: bit `i` of byte `i / CHAR_BIT` identifies the `i`-th
 * set in the group.
 *
 * Per-group keys and bitmask values are prepared in user space so a single
 * `bf_bpf_map_update_batch()` call populates the map on the kernel side.
 *
 * Group ownership of the created maps is transferred to `handle->sets`;
 * the `bf_set_group::map` pointer is a non-owning back-reference used by
 * `_bf_program_fixup()` when resolving `BF_FIXUP_TYPE_SET_MAP_FD` fixups.
 */
static int _bf_program_load_sets_maps(struct bf_program *new_prog)
{
    char name[BPF_OBJ_NAME_LEN];
    size_t map_idx = 0;
    int r;

    assert(new_prog);

    bf_list_foreach (&new_prog->set_groups, group_node) {
        struct bf_set_group *group = bf_list_node_get_data(group_node);
        const struct bf_set *key_set =
            bf_list_node_get_data(bf_list_get_head(&group->sets));
        size_t n_sets = bf_list_size(&group->sets);
        size_t i = 0;
        _cleanup_free_ uint8_t *keys = NULL;
        size_t key_size = key_set->elem_size;
        _cleanup_free_ uint8_t *values = NULL;
        size_t value_size = (n_sets + CHAR_BIT - 1) / CHAR_BIT;
        const bf_hashset_ops dedup_ops = {
            .hash = _bf_dedup_hash,
            .equal = _bf_dedup_equal,
            // The dedup hashset borrows elements from `bf_set`s.
            .free = NULL,
        };
        _clean_bf_hashset_ bf_hashset unique_elements =
            bf_hashset_default(&dedup_ops, &key_size);
        size_t n_total_elems = 0;
        size_t n_unique_elems;
        _free_bf_map_ struct bf_map *new_map = NULL;
        struct bf_map *map_ref;

        // Upper-bound the set capacity to avoid incremental rehashing.
        bf_list_foreach (&group->sets, set_node) {
            const struct bf_set *set = bf_list_node_get_data(set_node);

            n_total_elems += bf_hashset_size(&set->elems);
        }

        r = bf_hashset_reserve(&unique_elements, n_total_elems);
        if (r)
            return bf_err_r(r, "failed to reserve dedup hashset capacity");

        // Find all unique elements across all sets in this group.
        bf_list_foreach (&group->sets, set_node) {
            const struct bf_set *set = bf_list_node_get_data(set_node);

            bf_hashset_foreach (&set->elems, elem) {
                void *to_add = elem->data;
                r = bf_hashset_add(&unique_elements, &to_add);
                if (r && r != -EEXIST)
                    return bf_err_r(r, "failed to dedup element");
            }
        }
        n_unique_elems = bf_hashset_size(&unique_elements);

        // Compute bf_map keys and values for batch insertion.
        keys = calloc(n_unique_elems, key_size);
        if (!keys)
            return bf_err_r(-ENOMEM, "failed to allocate map keys");

        values = calloc(n_unique_elems, value_size);
        if (!values)
            return bf_err_r(-ENOMEM, "failed to allocate map values");

        bf_hashset_foreach (&unique_elements, hentry) {
            size_t bit_idx = 0;

            // Compute the key.
            memcpy(keys + (i * key_size), hentry->data, key_size);

            // Compute the value (bitmask).
            bf_list_foreach (&group->sets, set_node) {
                const struct bf_set *set = bf_list_node_get_data(set_node);

                if (bf_hashset_contains(&set->elems, hentry->data)) {
                    values[(i * value_size) + (bit_idx / CHAR_BIT)] |=
                        (uint8_t)(1U << (bit_idx % CHAR_BIT));
                }
                ++bit_idx;
            }
            ++i;
        }

        // Create the BPF map from the computed keys and values.
        (void)snprintf(name, BPF_OBJ_NAME_LEN, _BF_SET_MAP_PREFIX "%04x",
                       (uint16_t)map_idx++);

        r = bf_map_new_from_set(&new_map, name, key_set, n_unique_elems,
                                value_size);
        if (r)
            return r;

        r = bf_bpf_map_update_batch(new_map->fd, keys, values, n_unique_elems,
                                    BPF_ANY);
        if (r)
            return bf_err_r(r, "failed to add set elements to the map");

        map_ref = new_map;
        r = bf_list_push(&new_prog->handle->sets, (void **)&new_map);
        if (r)
            return r;
        group->map = map_ref;
    }

    return _bf_program_fixup(new_prog, BF_FIXUP_TYPE_SET_MAP_FD);
}

int bf_program_load(struct bf_program *prog)
{
    _cleanup_free_ char *log_buf = NULL;
    int r;

    assert(prog);

    r = _bf_program_load_sets_maps(prog);
    if (r)
        return bf_err_r(r, "failed to load the sets map");

    r = _bf_program_load_counters_map(prog);
    if (r)
        return bf_err_r(r, "failed to load the counter map");

    r = _bf_program_load_printer_map(prog);
    if (r)
        return bf_err_r(r, "failed to load the printer map");

    r = _bf_program_load_log_map(prog);
    if (r)
        return bf_err_r(r, "failed to load the log map");

    r = _bf_program_load_state_map(prog);
    if (r)
        return bf_err_r(r, "failed to load the state map");

    if (bf_ctx_is_verbose(BF_VERBOSE_DEBUG)) {
        log_buf = malloc(_BF_LOG_BUF_SIZE);
        if (!log_buf) {
            return bf_err_r(-ENOMEM,
                            "failed to allocate BPF_PROG_LOAD logs buffer");
        }
    }

    if (bf_ctx_is_verbose(BF_VERBOSE_BYTECODE))
        bf_program_dump_bytecode(prog);

    r = bf_bpf_prog_load(prog->handle->prog_name,
                         bf_hook_to_bpf_prog_type(prog->runtime.chain->hook),
                         prog->img.data, prog->img.size,
                         bf_hook_to_bpf_attach_type(prog->runtime.chain->hook),
                         log_buf, log_buf ? _BF_LOG_BUF_SIZE : 0,
                         bf_ctx_token(), &prog->handle->prog_fd);
    if (r) {
        return bf_err_r(r, "failed to load bf_program (%lu insns):\n%s\nerrno:",
                        prog->img.size, log_buf ? log_buf : "<NO LOG BUFFER>");
    }

    return r;
}

int bf_program_get_counter(const struct bf_program *program,
                           uint32_t counter_idx, struct bf_counter *counter)
{
    assert(program);
    assert(counter);

    return bf_handle_get_counter(program->handle, counter_idx, counter);
}

size_t bf_program_chain_counter_idx(const struct bf_program *program)
{
    return bf_list_size(&program->runtime.chain->rules);
}

size_t bf_program_error_counter_idx(const struct bf_program *program)
{
    return bf_list_size(&program->runtime.chain->rules) + 1;
}
