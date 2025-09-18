/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/cgen.h"

#include <linux/bpf.h>

#include <bpf/bpf.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <bpfilter/bpf.h>
#include <bpfilter/chain.h>
#include <bpfilter/counter.h>
#include <bpfilter/dump.h>
#include <bpfilter/front.h>
#include <bpfilter/helper.h>
#include <bpfilter/hook.h>
#include <bpfilter/io.h>
#include <bpfilter/list.h>
#include <bpfilter/logger.h>
#include <bpfilter/ns.h>
#include <bpfilter/pack.h>

#include "cgen/dump.h"
#include "cgen/prog/link.h"
#include "cgen/program.h"
#include "ctx.h"
#include "opts.h"

int bf_cgen_new(struct bf_cgen **cgen, enum bf_front front,
                struct bf_chain **chain)
{
    bf_assert(cgen && chain && *chain);

    *cgen = malloc(sizeof(struct bf_cgen));
    if (!*cgen)
        return -ENOMEM;

    (*cgen)->front = front;
    (*cgen)->chain = TAKE_PTR(*chain);
    (*cgen)->fd = -1;
    (*cgen)->link = NULL;

    return 0;
}

int bf_cgen_new_from_pack(struct bf_cgen **cgen, bf_rpack_node_t node)
{
    _free_bf_cgen_ struct bf_cgen *_cgen = NULL;
    _cleanup_close_ int fd = -1;
    _cleanup_close_ int dir_fd = -1;
    bf_rpack_node_t child;
    int r;

    bf_assert(cgen);

    _cgen = malloc(sizeof(*_cgen));
    if (!_cgen)
        return -ENOMEM;

    _cgen->program = NULL;

    r = bf_rpack_kv_enum(node, "front", &_cgen->front);
    if (r)
        return bf_rpack_key_err(r, "bf_cgen.front");

    r = bf_rpack_kv_obj(node, "chain", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_cgen.chain");
    r = bf_chain_new_from_pack(&_cgen->chain, child);
    if (r)
        return bf_rpack_key_err(r, "bf_cgen.chain");

    if ((dir_fd = bf_ctx_get_pindir_fd()) < 0) {
        return bf_err_r(dir_fd,
                        "failed to open chain pin directory for '%s'",
                        _cgen->chain->name);
    }

    r = bf_bpf_obj_get(_cgen->chain->name, dir_fd, &fd);
    if (r) {
        return bf_err_r(r, "failed to open program for chain %s",
                        _cgen->chain->name);
    }

    uint32_t id;
    r = bf_bpf_obj_get_id(fd, &id);
    if (r)
        bf_err_r(r, "failed to get ID for chain %s", _cgen->chain->name);
    bf_info("object ID is %u", id);

    _cleanup_close_ int _fd = -1;
    if ((r = bf_bpf_prog_get_fd_by_id(id)) > 0) {
        _cgen->fd = TAKE_FD(fd);
        bf_info("restored porgram");
    } else if ((r = bf_bpf_link_get_fd_by_id(id)) > 0) {
        r = bf_link_new_from_obj(&_cgen->link, &fd);
        if (r)
            return bf_err_r(r, "failed to restore link");
        bf_info("restored link");
    }

    *cgen = TAKE_PTR(_cgen);

    return 0;
}

void bf_cgen_free(struct bf_cgen **cgen)
{
    _cleanup_close_ int pin_fd = -1;

    bf_assert(cgen);

    if (!*cgen)
        return;

    closep(&(*cgen)->fd);
    bf_link_free(&(*cgen)->link);
    bf_chain_free(&(*cgen)->chain);

    freep((void *)cgen);
}

int bf_cgen_pack(const struct bf_cgen *cgen, bf_wpack_t *pack)
{
    bf_assert(cgen);
    bf_assert(pack);

    bf_wpack_kv_enum(pack, "front", cgen->front);

    bf_wpack_open_object(pack, "chain");
    bf_chain_pack(cgen->chain, pack);
    bf_wpack_close_object(pack);

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}

void bf_cgen_dump(const struct bf_cgen *cgen, prefix_t *prefix)
{
    bf_assert(cgen);
    bf_assert(prefix);

    DUMP(prefix, "struct bf_cgen at %p", cgen);

    bf_dump_prefix_push(prefix);
    DUMP(prefix, "front: %s", bf_front_to_str(cgen->front));

    // Chain
    DUMP(prefix, "chain: struct bf_chain *");
    bf_dump_prefix_push(prefix);
    bf_chain_dump(cgen->chain, bf_dump_prefix_last(prefix));
    bf_dump_prefix_pop(prefix);

    bf_dump_prefix_pop(prefix);
}

int bf_cgen_get_counter(const struct bf_cgen *cgen,
                        enum bf_counter_type counter_idx,
                        struct bf_counter *counter)
{
    bf_assert(cgen && counter);

    /* There are two more counter than rules. The special counters must
     * be accessed via the specific values, to avoid confusion. */
    enum bf_counter_type rule_count = bf_list_size(&cgen->chain->rules);
    if (counter_idx == BF_COUNTER_POLICY) {
        counter_idx = rule_count;
    } else if (counter_idx == BF_COUNTER_ERRORS) {
        counter_idx = rule_count + 1;
    } else if (counter_idx < 0 || counter_idx >= rule_count) {
        return -EINVAL;
    }

    return bf_program_get_counter(cgen->program, counter_idx, counter);
}

int bf_cgen_set(struct bf_cgen *cgen, const struct bf_ns *ns,
                struct bf_hookopts **hookopts)
{
    _free_bf_program_ struct bf_program *prog = NULL;
    _cleanup_close_ int pindir_fd = -1;
    int r;

    bf_assert(cgen);

    if (bf_opts_persist()) {
        pindir_fd = bf_ctx_get_pindir_fd();
        if (pindir_fd < 0)
            return pindir_fd;
    }

    r = bf_program_new(&prog, cgen->chain);
    if (r < 0)
        return r;

    r = bf_program_generate(prog);
    if (r < 0)
        return bf_err_r(r, "failed to generate bf_program");

    r = bf_program_load(prog);
    if (r < 0)
        return bf_err_r(r, "failed to load the chain");

    cgen->fd = TAKE_FD(prog->runtime.prog_fd);

    if (hookopts) {
        r = bf_ns_set(ns, bf_ctx_get_ns());
        if (r)
            return bf_err_r(r, "failed to switch to the client's namespaces");

        r = bf_link_new(&cgen->link, "bf_link");
        if (r)
            return r;

        r = bf_link_attach(cgen->link, cgen->chain->hook, hookopts, cgen->fd);
        if (r) {
            return bf_err_r(r, "failed to attach bf_link for %s program",
                            bf_flavor_to_str(prog->flavor));
        }

        cgen->fd = -1;

        if (bf_ns_set(bf_ctx_get_ns(), ns))
            bf_abort("failed to restore previous namespaces, aborting");
    }

    if (bf_opts_persist()) {
        r = bf_link_pin_name(cgen->link, pindir_fd, cgen->chain->name);
        if (r)
            return r;
    }

    cgen->program = TAKE_PTR(prog);

    return r;
}

int bf_cgen_load(struct bf_cgen *cgen)
{
    _free_bf_program_ struct bf_program *prog = NULL;
    _cleanup_close_ int pindir_fd = -1;
    int r;

    bf_assert(cgen);

    if (bf_opts_persist()) {
        pindir_fd = _bf_cgen_get_chain_pindir_fd(cgen->chain->name);
        if (pindir_fd < 0)
            return pindir_fd;
    }

    r = bf_program_new(&prog, cgen->chain);
    if (r < 0)
        return r;

    r = bf_program_generate(prog);
    if (r < 0)
        return bf_err_r(r, "failed to generate bf_program");

    r = bf_program_load(prog);
    if (r < 0)
        return bf_err_r(r, "failed to load the chain");

    if (bf_opts_persist()) {
        r = bf_program_pin(prog, pindir_fd);
        if (r)
            return r;
    }

    bf_info("load %s", cgen->chain->name);
    bf_cgen_dump(cgen, EMPTY_PREFIX);

    cgen->program = TAKE_PTR(prog);

    return r;
}

int bf_cgen_attach(struct bf_cgen *cgen, const struct bf_ns *ns,
                   struct bf_hookopts **hookopts)
{
    _cleanup_close_ int pindir_fd = -1;
    int r;

    bf_assert(cgen && ns && hookopts);

    bf_info("attaching %s to %s", cgen->chain->name,
            bf_hook_to_str(cgen->chain->hook));
    bf_hookopts_dump(*hookopts, EMPTY_PREFIX);

    if (bf_opts_persist()) {
        pindir_fd = _bf_cgen_get_chain_pindir_fd(cgen->chain->name);
        if (pindir_fd < 0)
            return pindir_fd;
    }

    r = bf_ns_set(ns, bf_ctx_get_ns());
    if (r)
        return bf_err_r(r, "failed to switch to the client's namespaces");

    r = bf_program_attach(cgen->program, hookopts);
    if (r < 0)
        return bf_err_r(r, "failed to attach chain '%s'", cgen->chain->name);

    if (bf_ns_set(bf_ctx_get_ns(), ns))
        bf_abort("failed to restore previous namespaces, aborting");

    if (bf_opts_persist()) {
        r = bf_link_pin(cgen->program->link, pindir_fd);
        if (r) {
            bf_program_detach(cgen->program);
            return r;
        }
    }

    return r;
}

int bf_cgen_update(struct bf_cgen *cgen, struct bf_chain **new_chain)
{
    _free_bf_program_ struct bf_program *new_prog = NULL;
    _cleanup_close_ int pindir_fd = -1;
    struct bf_program *old_prog;
    int r;

    bf_assert(cgen && new_chain);

    old_prog = cgen->program;

    if (bf_opts_persist()) {
        pindir_fd = _bf_cgen_get_chain_pindir_fd((*new_chain)->name);
        if (pindir_fd < 0)
            return pindir_fd;
    }

    r = bf_program_new(&new_prog, *new_chain);
    if (r < 0)
        return bf_err_r(r, "failed to create a new bf_program");

    r = bf_program_generate(new_prog);
    if (r < 0) {
        return bf_err_r(r,
                        "failed to generate the bytecode for a new bf_program");
    }

    r = bf_program_load(new_prog);
    if (r)
        return bf_err_r(r, "failed to load new program");

    if (bf_opts_persist())
        bf_program_unpin(old_prog, pindir_fd);

    r = bf_link_update(old_prog->link, cgen->chain->hook,
                       new_prog->runtime.prog_fd);
    if (r) {
        bf_err_r(r, "failed to update bf_link object with new program");
        if (bf_opts_persist() && bf_program_pin(old_prog, pindir_fd) < 0)
            bf_err("failed to repin old program, ignoring");
        return r;
    }

    // We updated the old link, we need to store it in the new program
    bf_swap(new_prog->link, old_prog->link);

    if (bf_opts_persist()) {
        r = bf_program_pin(new_prog, pindir_fd);
        if (r)
            bf_warn_r(r, "failed to pin new prog, ignoring");
    }

    bf_swap(cgen->program, new_prog);

    bf_chain_free(&cgen->chain);
    cgen->chain = TAKE_PTR(*new_chain);

    return 0;
}

void bf_cgen_detach(struct bf_cgen *cgen)
{
    bf_assert(cgen);

    if (cgen->link) {
        bf_link_detach(cgen->link);
        bf_link_free(&cgen->link);
    }
}

void bf_cgen_unload(struct bf_cgen *cgen)
{
    _cleanup_close_ int chain_fd = -1;

    bf_assert(cgen);

    bf_cgen_detach(cgen);
    closep(&cgen->fd);
}

int bf_cgen_get_counters(const struct bf_cgen *cgen, bf_list *counters)
{
    bf_list _counters = bf_list_default_from(*counters);
    int r;

    bf_assert(cgen && counters);

    /* Iterate over all the rules, then the policy counter (size(rules)) and
     * the errors counters (sizeof(rules) + 1)*/
    for (size_t i = 0; i < bf_list_size(&cgen->chain->rules) + 2; ++i) {
        _free_bf_counter_ struct bf_counter *counter = NULL;
        ssize_t idx = (ssize_t)i;

        if (i == bf_list_size(&cgen->chain->rules))
            idx = BF_COUNTER_POLICY;
        else if (i == bf_list_size(&cgen->chain->rules) + 1)
            idx = BF_COUNTER_ERRORS;

        r = bf_counter_new(&counter, 0, 0);
        if (r)
            return r;

        r = bf_cgen_get_counter(cgen, idx, counter);
        if (r)
            return r;

        r = bf_list_add_tail(&_counters, counter);
        if (r)
            return r;

        TAKE_PTR(counter);
    }

    *counters = bf_list_move(_counters);

    return 0;
}
