/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

#include <bpfilter/dump.h>
#include <bpfilter/elfstub.h>

struct bf_set;

/**
 * Field to fixup in a @c bpf_insn structure.
 */
enum bf_fixup_insn
{
    BF_FIXUP_INSN_OFF,
    BF_FIXUP_INSN_IMM,
    _BF_FIXUP_INSN_MAX,
};

/**
 * Type of the fixup.
 *
 * Defines how a fixup should be processed.
 */
enum bf_fixup_type
{
    /// Jump to the beginning of the next rule.
    BF_FIXUP_TYPE_JMP_NEXT_RULE,
    /** Jump to the end of the current guard group. Resolved lazily when the
     * group closes, unlike @c BF_FIXUP_TYPE_JMP_NEXT_RULE which resolves at
     * the end of every rule. */
    BF_FIXUP_TYPE_JMP_GUARD_MISS,
    /** Jump to the shared verdict block of the current verdict run. Resolved
     * lazily when the run closes, right before the closing rule emits its
     * `MOV r0`. */
    BF_FIXUP_TYPE_JMP_VERDICT,
    /** Jump to the end of the current matcher's inline block, where execution
     * continues with the rest of the rule. Emitted and resolved within a
     * single matcher's codegen (see `_bf_matcher_pkt_generate_set_inline()`
     * in packet.c), so it never leaks into the rule-level resolutions. */
    BF_FIXUP_TYPE_JMP_MATCH,
    /// Set the counters map file descriptor in the @c BPF_LD_MAP_FD instruction.
    BF_FIXUP_TYPE_COUNTERS_MAP_FD,
    /// Set the printer map file descriptor in the @c BPF_LD_MAP_FD instruction.
    BF_FIXUP_TYPE_PRINTER_MAP_FD,
    /// Set the log map file descriptor in the @c BPF_LD_MAP_FD instruction.
    BF_FIXUP_TYPE_LOG_MAP_FD,
    /// Set the state map file descriptor in the @c BPF_LD_MAP_FD instruction.
    BF_FIXUP_TYPE_STATE_MAP_FD,
    /// Set a set map file descriptor in the @c BPF_LD_MAP_FD instruction.
    BF_FIXUP_TYPE_SET_MAP_FD,
    /// Call an ELF stub.
    BF_FIXUP_ELFSTUB_CALL,
    _BF_FIXUP_TYPE_MAX
};

union bf_fixup_attr
{
    /** Set referenced by a `BF_FIXUP_TYPE_SET_MAP_FD` fixup. The fixup
     * holds a non-owning pointer to a set in the generator's chain. */
    const struct bf_set *set_ptr;
    enum bf_elfstub_id elfstub_id;
};

struct bf_fixup
{
    enum bf_fixup_type type;
    size_t insn;
    union bf_fixup_attr attr;
};

#define _free_bf_fixup_ __attribute__((cleanup(bf_fixup_free)))

int bf_fixup_new(struct bf_fixup **fixup, enum bf_fixup_type type,
                 size_t insn_offset, const union bf_fixup_attr *attr);
void bf_fixup_free(struct bf_fixup **fixup);
void bf_fixup_dump(const struct bf_fixup *fixup, prefix_t *prefix);
