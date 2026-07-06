/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>

struct bf_matcher;
struct bf_program;
struct bf_rule;

/**
 * @brief Check whether a matcher's codegen is compatible with the cross-rule
 * packet field cache.
 *
 * A matcher is cacheable if its bytecode is a plain field load followed by a
 * non-mutating compare: the loaded value survives in `r1` (and `r2` for
 * 128-bit fields) when the compare jumps to the next rule. Matchers that
 * modify the loaded registers (network masking, port byte-swap, bitfield
 * `AND`), call into helpers or ELF stubs (sets), or don't read from the
 * pinned header registers (meta matchers) are excluded.
 *
 * @param matcher Matcher to check. Can't be NULL.
 * @return True if the matcher's codegen can consume and publish the field
 *         cache, false otherwise.
 */
bool bf_packet_matcher_is_cacheable(const struct bf_matcher *matcher);

/**
 * @brief Generate bytecode for a packet-based matcher.
 *
 * Dispatches to the appropriate matcher codegen function based on the matcher
 * type. Handles all matchers that operate on packet headers or metadata common
 * to all packet-based flavors.
 *
 * `BF_MATCHER_META_MARK` and `BF_MATCHER_META_FLOW_HASH` are not supported
 * by this function and return `-ENOTSUP`, as they require flavor-specific
 * context access.
 *
 * @param program Program being generated. Can't be NULL.
 * @param matcher Matcher to generate code for. Can't be NULL.
 * @return 0 on success, negative errno on error.
 */
int bf_packet_gen_inline_matcher(struct bf_program *program,
                                 const struct bf_matcher *matcher);

/**
 * @brief Generate bytecode for packet-based rule logging.
 *
 * Sets up registers and calls the packet log ELF stub. Shared by all
 * packet-based flavors (TC, NF, XDP, cgroup_skb).
 *
 * @param program Program being generated. Can't be NULL.
 * @param rule Rule whose log action to generate. Can't be NULL.
 * @return 0 on success, negative errno on error.
 */
int bf_packet_gen_inline_log(struct bf_program *program,
                             const struct bf_rule *rule);
