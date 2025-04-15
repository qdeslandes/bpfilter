/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdint.h>

#include "core/counter.h"
#include "core/dump.h"
#include "core/front.h"
#include "core/list.h"

struct bf_chain;
struct bf_marsh;
struct bf_program;
struct bf_ns;
struct bf_hookopts;

#define _cleanup_bf_cgen_ __attribute__((cleanup(bf_cgen_free)))

/**
 * Convenience macro to initialize a list of @ref bf_cgen .
 *
 * @return An initialized @ref bf_list that can contain @ref bf_cgen objects.
 */
#define bf_cgen_list()                                                         \
    ((bf_list) {.ops = {.free = (bf_list_ops_free)bf_cgen_free,                \
                        .marsh = (bf_list_ops_marsh)bf_cgen_marsh}})

/**
 * @struct bf_cgen
 *
 * A codegen is a BPF bytecode generation context used to create a BPF program
 * for a given set of rules, sets, and policy (a chain).
 */
struct bf_cgen
{
    /// Front used to define the chain.
    enum bf_front front;

    /// Chain containing the rules, sets, and policy.
    struct bf_chain *chain;

    /// Program generated by the codegen.
    struct bf_program *program;
};

/**
 * Allocate and initialise a new codegen.
 *
 * @param cgen Codegen to allocate and initialise. Can't be NULL.
 * @param front Front used to define the chain.
 * @param chain Chain containing the codegen's rules, sets, and policy. On
 *        success, the new codegen will take ownership of the chain, and
 *        @c *chain will be NULL. Can't be NULL, and @c *chain must point to
 *        a valid @ref bf_chain .
 * @return 0 on success, or negative errno value on failure.
 */
int bf_cgen_new(struct bf_cgen **cgen, enum bf_front front,
                struct bf_chain **chain);

/**
 * Allocate a new codegen and intialize it from serialized data.
 *
 * @param cgen Codegen to allocate and initialize. On success, @p *cgen will
 *        point to the new codegen object. On failure, @p *cgen is unchanged.
 *        Can't be NULL.
 * @param marsh Serialized data to use to initialize the codegen.
 * @return 0 on success, or negative errno value on error.
 */
int bf_cgen_new_from_marsh(struct bf_cgen **cgen, const struct bf_marsh *marsh);

/**
 * Free a codegen.
 *
 * If one or more programs are loaded, they won't be unloaded. Use @ref
 * bf_cgen_unload first to ensure programs are unloaded. This behaviour
 * is expected so @ref bf_cgen can be freed without unloading the BPF
 * program, during a daemon restart for example.
 *
 * @param cgen Codegen to free. Can't be NULL.
 */
void bf_cgen_free(struct bf_cgen **cgen);

/**
 * Serialize a @ref bf_cgen object.
 *
 * @param cgen Codegen object to serialize. Can't be NULL.
 * @param marsh Marsh object to allocate. On success, @p *marsh points to the
 *              serialized codegen object. On failure this parameter is
 *              unchanged. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_cgen_marsh(const struct bf_cgen *cgen, struct bf_marsh **marsh);

/**
 * Create and load a `bf_program` into the kernel.
 *
 * Create a new `bf_program` for `cgen`, and generate it based on the chain
 * stored in the codegen. Once the generation is complete, the program is
 * loaded into the kernel.
 *
 * @param cgen Codegen to load into the kernel. Can't be NULL.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_cgen_load(struct bf_cgen *cgen);

/**
 * Attach a loaded program to a hook.
 *
 * `ns` is the namespace the codegen should switch to before attaching the
 * program. This is required to ensure the interface index the program is
 * attached to (for XDP and TC programs) is correct, and the interface index
 * the program filters on (e.g. `meta.ifindex`, for all hooks) is correct too.
 *
 * @param cgen Codegen to attach to the kernel. Can't be NULL.
 * @param ns Namespaces to switch to before attaching the programs. Can't be NULL.
 * @param hookopts Hook options. Can't be NULL.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_cgen_attach(struct bf_cgen *cgen, const struct bf_ns *ns,
                   struct bf_hookopts **hookopts);

/**
 * Update the program attached to the hook.
 *
 * A new program will be generated based on `new_chain`, before it is loaded
 * into the kernel. The link used by the codegen is updated to point to the
 * new program.
 *
 * On success, the new program is stored in the codegen, and the previous
 * program is unloaded and freed.
 *
 * @param cgen Codegen to update. It should already contain a program attached
 *        to a hook. Can't be NULL.
 * @param new_chain Chain containing the new rules, sets, and policy.
 *        Can't be NULL.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_cgen_update(struct bf_cgen *cgen, struct bf_chain **new_chain);

/**
 * Detach a program from the kernel.
 *
 * The program is not unloaded or unpinned from the filesystem.
 *
 * @param cgen Codegen to detach. Can't be NULL.
 */
void bf_cgen_detach(struct bf_cgen *cgen);

/**
 * Unload a program from the kernel.
 *
 * @param cgen Codege to unload. Can't be NULL.
 */
void bf_cgen_unload(struct bf_cgen *cgen);

void bf_cgen_dump(const struct bf_cgen *cgen, prefix_t *prefix);

/**
 * @enum bf_counter_type
 *
 * Special counter types for @ref bf_cgen_get_counter .
 */
enum bf_counter_type
{
    BF_COUNTER_POLICY = -2,
    BF_COUNTER_ERRORS = -1,
};

/**
 * Get packets and bytes counter at a specific index.
 *
 * Counters are referenced by their index in the counters map or the enum
 * values defined by @ref bf_counter_type .
 *
 * The counter from all the program generated from @p cgen are summarised
 * together.
 *
 * @param cgen Codegen to get the counter for. Can't be NULL.
 * @param counter_idx Index of the counter to get. If @p counter_idx doesn't
 *        correspond to a valid index, -E2BIG is returned.
 * @param counter Counter structure to fill with the counter values. Can't be
 *        NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_cgen_get_counter(const struct bf_cgen *cgen,
                        enum bf_counter_type counter_idx,
                        struct bf_counter *counter);

/**
 * Get the counters for all the rules.
 *
 * Create a new `bf_counter` structure for each rule (and the policy/error
 * counters) and add it to the list.
 *
 * The caller owns the `bf_counter` in the list and is responsible for freeing
 * it.
 *
 * A `bf_counter` object will be created even if the rule has no counter
 * define, but it will be empty.
 *
 * @param cgen Codegen to fetch the counters for. Can't be NULL.
 * @param counters List of counters, filled by the function. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_cgen_get_counters(const struct bf_cgen *cgen, bf_list *counters);
