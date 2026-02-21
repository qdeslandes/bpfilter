/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include <errno.h>
#include <unistd.h>

#include <bpfilter/chain.h>
#include <bpfilter/counter.h>
#include <bpfilter/helper.h>
#include <bpfilter/hook.h>
#include <bpfilter/io.h>
#include <bpfilter/list.h>
#include <bpfilter/logger.h>
#include <bpfilter/pack.h>
#include <bpfilter/request.h>
#include <bpfilter/response.h>

#include <bpfilter/set.h>

#include "cgen/cgen.h"
#include "cgen/handle.h"
#include "cgen/prog/link.h"
#include "cgen/prog/map.h"
#include "cgen/program.h"
#include "ctx.h"

static int _bf_get_all_cgen(bf_list *cgens)
{
    _clean_bf_list_ bf_list _cgens = bf_list_default_from(*cgens);
    int r;

    assert(cgens);

    bf_dir_foreach(bf_ctx_get_pindir_fd(global_ctx), iter)
    {
        _free_bf_cgen_ struct bf_cgen *cgen = NULL;

        r = bf_cgen_new_from_name(&cgen, global_ctx, iter.child_name);
        if (r)
            return bf_err_r(r, "failed to restore cgen %s", iter.child_name);

        r = bf_list_push(&_cgens, (void **)&cgen);
        if (r) {
            return bf_err_r(r, "failed to add discovered cgen %s to list",
                            iter.child_name);
        }
    }

    bf_swap(*cgens, _cgens);

    return 0;
}

static struct bf_cgen *_bf_get_cgen(const char *name)
{
    struct bf_cgen *cgen;
    int r;

    assert(name);

    bf_info("_bf_get_cgen for %s", name);
    r = bf_cgen_new_from_name(&cgen, global_ctx, name);
    if (r) {
        bf_info("failed _bf_get_cgen for %s", name);
        bf_err_r(r, "failed to restore cgen %s", name);
        return NULL;
    }

    bf_info("success _bf_get_cgen %s", name);
    return cgen;
}

int _bf_cli_ruleset_flush(bf_ctx_t *ctx, const struct bf_request *request,
                          struct bf_response **response)
{
    _clean_bf_list_ bf_list cgens = bf_list_default(bf_cgen_free, NULL);
    int r;

    (void)request;
    (void)response;

    r = _bf_get_all_cgen(&cgens);
    if (r)
        return r;

    bf_list_foreach (&cgens, node) {
        struct bf_cgen *cgen = bf_list_node_get_data(node);

        bf_cgen_unload(cgen);
        bf_info("flushed chain %s", cgen->chain->name);
    }

    return 0;
}

static int _bf_cli_ruleset_get(bf_ctx_t *ctx, const struct bf_request *request,
                               struct bf_response **response)
{
    _clean_bf_list_ bf_list cgens = bf_list_default(bf_cgen_free, NULL);
    _clean_bf_list_ bf_list chains = bf_list_default(NULL, bf_chain_pack);
    _clean_bf_list_ bf_list hookopts = bf_list_default(NULL, bf_hookopts_pack);
    _clean_bf_list_ bf_list counters =
        bf_list_default(bf_list_free, bf_list_pack);
    _free_bf_wpack_ bf_wpack_t *pack = NULL;
    int r;

    (void)request;

    r = bf_wpack_new(&pack);
    if (r)
        return r;

    r = _bf_get_all_cgen(&cgens);
    if (r)
        return bf_err_r(r, "failed to gather cgens");

    bf_list_foreach (&cgens, cgen_node) {
        struct bf_cgen *cgen = bf_list_node_get_data(cgen_node);
        _free_bf_list_ bf_list *cgen_counters = NULL;

        r = bf_list_add_tail(&chains, cgen->chain);
        if (r)
            return bf_err_r(r, "failed to add chain to list");

        r = bf_list_add_tail(&hookopts, cgen->handle->link ?
                                            cgen->handle->link->hookopts :
                                            NULL);
        if (r)
            return bf_err_r(r, "failed to add hookopts to list");

        r = bf_list_new(&cgen_counters,
                        &bf_list_ops_default(bf_counter_free, bf_counter_pack));
        if (r)
            return r;

        r = bf_cgen_get_counters(cgen, cgen_counters);
        if (r)
            return r;

        r = bf_list_add_tail(&counters, cgen_counters);
        if (r)
            return r;

        TAKE_PTR(cgen_counters);
    }

    bf_wpack_open_object(pack, "ruleset");
    bf_wpack_kv_list(pack, "chains", &chains);
    bf_wpack_kv_list(pack, "hookopts", &hookopts);
    bf_wpack_kv_list(pack, "counters", &counters);
    bf_wpack_close_object(pack);

    return bf_response_new_from_pack(response, pack);
}

int _bf_cli_ruleset_set(bf_ctx_t *ctx, const struct bf_request *request,
                        struct bf_response **response)
{
    _clean_bf_list_ bf_list cgens = bf_list_default(NULL, NULL);
    _free_bf_rpack_ bf_rpack_t *pack;
    bf_rpack_node_t child, node;
    int r;

    assert(request);

    (void)response;

    _bf_cli_ruleset_flush(ctx, NULL, NULL);

    r = bf_rpack_new(&pack, bf_request_data(request),
                     bf_request_data_len(request));
    if (r)
        return r;

    r = bf_rpack_kv_array(bf_rpack_root(pack), "ruleset", &child);
    if (r)
        return r;
    bf_rpack_array_foreach (child, node) {
        _free_bf_cgen_ struct bf_cgen *cgen = NULL;
        _free_bf_chain_ struct bf_chain *chain = NULL;
        _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
        bf_rpack_node_t child;

        r = bf_rpack_kv_obj(node, "chain", &child);
        if (r)
            goto err_load;

        r = bf_chain_new_from_pack(&chain, child);
        if (r)
            goto err_load;

        r = bf_rpack_kv_node(node, "hookopts", &child);
        if (r)
            goto err_load;
        if (!bf_rpack_is_nil(child)) {
            r = bf_hookopts_new_from_pack(&hookopts, child);
            if (r)
                goto err_load;
        }

        cgen = _bf_get_cgen(chain->name);
        if (cgen) {
            bf_cgen_unload(cgen);
            bf_cgen_free(&cgen);
        }

        r = bf_cgen_new(&cgen, ctx, &chain);
        if (r)
            goto err_load;

        r = bf_cgen_set(cgen, bf_request_ns(request),
                        hookopts ? &hookopts : NULL);
        if (r) {
            bf_err_r(r, "failed to set chain '%s'", cgen->chain->name);
            goto err_load;
        }
    }

    return 0;

err_load:
    _bf_cli_ruleset_flush(ctx, NULL, NULL);
    return r;
}

int _bf_cli_chain_set(bf_ctx_t *ctx, const struct bf_request *request,
                      struct bf_response **response)
{
    _free_bf_cgen_ struct bf_cgen *cgen = NULL;
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
    _free_bf_rpack_ bf_rpack_t *pack = NULL;
    bf_rpack_node_t root, child;
    int r;

    assert(request);

    (void)response;

    r = bf_rpack_new(&pack, bf_request_data(request),
                     bf_request_data_len(request));
    if (r)
        return r;

    root = bf_rpack_root(pack);

    r = bf_rpack_kv_obj(root, "chain", &child);
    if (r)
        return r;
    r = bf_chain_new_from_pack(&chain, child);
    if (r)
        return r;

    r = bf_rpack_kv_node(root, "hookopts", &child);
    if (r)
        return r;
    if (!bf_rpack_is_nil(child)) {
        r = bf_hookopts_new_from_pack(&hookopts, child);
        if (r)
            return r;
    }

    cgen = _bf_get_cgen(chain->name);
    if (cgen) {
        bf_cgen_unload(cgen);
        bf_cgen_free(&cgen);
    }

    r = bf_cgen_new(&cgen, ctx, &chain);
    if (r)
        return r;

    r = bf_cgen_set(cgen, bf_request_ns(request), hookopts ? &hookopts : NULL);
    if (r)
        return r;

    return 0;
}

static int _bf_cli_chain_get(bf_ctx_t *ctx, const struct bf_request *request,
                             struct bf_response **response)
{
    _clean_bf_list_ bf_list counters =
        bf_list_default(bf_counter_free, bf_counter_pack);
    _free_bf_cgen_ struct bf_cgen *cgen;
    _cleanup_free_ char *name = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    int r;

    r = bf_rpack_new(&rpack, bf_request_data(request),
                     bf_request_data_len(request));
    if (r)
        return r;

    r = bf_rpack_kv_str(bf_rpack_root(rpack), "name", &name);
    if (r)
        return r;

    cgen = _bf_get_cgen(name);
    if (!cgen)
        return bf_err_r(-ENOENT, "chain '%s' not found", name);

    r = bf_cgen_get_counters(cgen, &counters);
    if (r)
        return bf_err_r(r, "failed to request counters for '%s'", name);

    r = bf_wpack_new(&wpack);
    if (r)
        return r;

    bf_wpack_open_object(wpack, "chain");
    r = bf_chain_pack(cgen->chain, wpack);
    if (r)
        return r;
    bf_wpack_close_object(wpack);

    if (cgen->handle->link) {
        bf_wpack_open_object(wpack, "hookopts");
        r = bf_hookopts_pack(cgen->handle->link->hookopts, wpack);
        if (r)
            return r;
        bf_wpack_close_object(wpack);
    } else {
        bf_wpack_kv_nil(wpack, "hookopts");
    }

    bf_wpack_kv_list(wpack, "counters", &counters);

    return bf_response_new_from_pack(response, wpack);
}

int _bf_cli_chain_prog_fd(bf_ctx_t *ctx, const struct bf_request *request,
                          struct bf_response **response)
{
    _free_bf_cgen_ struct bf_cgen *cgen = NULL;
    _free_bf_rpack_ bf_rpack_t *pack = NULL;
    _cleanup_free_ char *name = NULL;
    int r;

    (void)response;

    r = bf_rpack_new(&pack, bf_request_data(request),
                     bf_request_data_len(request));
    if (r)
        return r;

    r = bf_rpack_kv_str(bf_rpack_root(pack), "name", &name);
    if (r)
        return r;

    cgen = _bf_get_cgen(name);
    if (!cgen)
        return bf_err_r(-ENOENT, "failed to find chain '%s'", name);

    if (cgen->handle->prog_fd == -1)
        return bf_err_r(-ENODEV, "chain '%s' has no loaded program", name);

    r = bf_send_fd(bf_request_fd(request), cgen->handle->prog_fd);
    if (r < 0)
        return bf_err_r(errno, "failed to send prog FD for '%s'", name);

    return 0;
}

int _bf_cli_chain_logs_fd(bf_ctx_t *ctx, const struct bf_request *request,
                          struct bf_response **response)
{
    _free_bf_cgen_ struct bf_cgen *cgen = NULL;
    _free_bf_rpack_ bf_rpack_t *pack = NULL;
    _cleanup_free_ char *name = NULL;
    int r;

    (void)response;

    r = bf_rpack_new(&pack, bf_request_data(request),
                     bf_request_data_len(request));
    if (r)
        return r;

    r = bf_rpack_kv_str(bf_rpack_root(pack), "name", &name);
    if (r)
        return r;

    cgen = _bf_get_cgen(name);
    if (!cgen)
        return bf_err_r(-ENOENT, "failed to find chain '%s'", name);

    if (!cgen->handle->lmap)
        return bf_err_r(-ENOENT, "chain '%s' has no logs buffer", name);

    r = bf_send_fd(bf_request_fd(request), cgen->handle->lmap->fd);
    if (r < 0)
        return bf_err_r(errno, "failed to send logs FD for '%s'", name);

    return 0;
}

int _bf_cli_chain_load(bf_ctx_t *ctx, const struct bf_request *request,
                       struct bf_response **response)
{
    _free_bf_cgen_ struct bf_cgen *cgen = NULL;
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_rpack_ bf_rpack_t *pack = NULL;
    bf_rpack_node_t child;
    int r;

    assert(request);

    (void)response;

    r = bf_rpack_new(&pack, bf_request_data(request),
                     bf_request_data_len(request));
    if (r)
        return r;

    r = bf_rpack_kv_obj(bf_rpack_root(pack), "chain", &child);
    if (r)
        return r;
    r = bf_chain_new_from_pack(&chain, child);
    if (r)
        return r;

    cgen = _bf_get_cgen(chain->name);
    if (cgen) {
        return bf_err_r(-EEXIST,
                        "_bf_cli_chain_load: chain '%s' already exists",
                        chain->name);
    }

    r = bf_cgen_new(&cgen, ctx, &chain);
    if (r)
        return r;

    r = bf_cgen_load(cgen);
    if (r)
        return r;

    return r;
}

int _bf_cli_chain_attach(bf_ctx_t *ctx, const struct bf_request *request,
                         struct bf_response **response)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
    _free_bf_rpack_ bf_rpack_t *pack = NULL;
    _cleanup_free_ char *name = NULL;
    _free_bf_cgen_ struct bf_cgen *cgen = NULL;
    bf_rpack_node_t child;
    int r;

    assert(request);

    (void)response;

    r = bf_rpack_new(&pack, bf_request_data(request),
                     bf_request_data_len(request));
    if (r)
        return r;

    r = bf_rpack_kv_str(bf_rpack_root(pack), "name", &name);
    if (r)
        return r;

    r = bf_rpack_kv_obj(bf_rpack_root(pack), "hookopts", &child);
    if (r)
        return r;
    r = bf_hookopts_new_from_pack(&hookopts, child);
    if (r)
        return r;

    cgen = _bf_get_cgen(name);
    if (!cgen)
        return bf_err_r(-ENOENT, "chain '%s' does not exist", name);
    if (cgen->handle->link)
        return bf_err_r(-EBUSY, "chain '%s' is already linked to a hook", name);

    r = bf_hookopts_validate(hookopts, cgen->chain->hook);
    if (r)
        return bf_err_r(r, "failed to validate hook options");

    r = bf_cgen_attach(cgen, bf_request_ns(request), &hookopts);
    if (r)
        return bf_err_r(r, "failed to attach codegen to hook");

    return r;
}

int _bf_cli_chain_update(bf_ctx_t *ctx, const struct bf_request *request,
                         struct bf_response **response)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_cgen_ struct bf_cgen *cgen = NULL;
    _free_bf_rpack_ bf_rpack_t *pack = NULL;
    bf_rpack_node_t child;
    int r;

    assert(request);

    (void)response;

    r = bf_rpack_new(&pack, bf_request_data(request),
                     bf_request_data_len(request));
    if (r)
        return r;

    r = bf_rpack_kv_obj(bf_rpack_root(pack), "chain", &child);
    if (r)
        return r;
    r = bf_chain_new_from_pack(&chain, child);
    if (r)
        return r;

    cgen = _bf_get_cgen(chain->name);
    if (!cgen)
        return -ENOENT;

    r = bf_cgen_update(cgen, &chain);
    if (r)
        return -EINVAL;

    return r;
}

int _bf_cli_chain_flush(bf_ctx_t *ctx, const struct bf_request *request,
                        struct bf_response **response)
{
    _free_bf_cgen_ struct bf_cgen *cgen = NULL;
    _free_bf_rpack_ bf_rpack_t *pack = NULL;
    _cleanup_free_ char *name = NULL;
    int r;

    assert(request);

    (void)response;

    r = bf_rpack_new(&pack, bf_request_data(request),
                     bf_request_data_len(request));
    if (r)
        return r;

    r = bf_rpack_kv_str(bf_rpack_root(pack), "name", &name);
    if (r)
        return r;

    cgen = _bf_get_cgen(name);
    if (!cgen)
        return -ENOENT;

    bf_cgen_unload(cgen);

    return 0;
}

int _bf_cli_chain_update_set(bf_ctx_t *ctx, const struct bf_request *request,
                             struct bf_response **response)
{
    _free_bf_set_ struct bf_set *to_add = NULL;
    _free_bf_set_ struct bf_set *to_remove = NULL;
    _free_bf_chain_ struct bf_chain *new_chain = NULL;
    _free_bf_rpack_ bf_rpack_t *pack = NULL;
    struct bf_set *dest_set = NULL;
    _cleanup_free_ char *chain_name = NULL;
    _free_bf_cgen_ struct bf_cgen *cgen = NULL;
    bf_rpack_node_t child;
    int r;

    assert(request);

    (void)response;

    r = bf_rpack_new(&pack, bf_request_data(request),
                     bf_request_data_len(request));
    if (r)
        return r;

    r = bf_rpack_kv_str(bf_rpack_root(pack), "name", &chain_name);
    if (r)
        return r;

    r = bf_rpack_kv_obj(bf_rpack_root(pack), "to_add", &child);
    if (r)
        return r;
    r = bf_set_new_from_pack(&to_add, child);
    if (r)
        return r;

    r = bf_rpack_kv_obj(bf_rpack_root(pack), "to_remove", &child);
    if (r)
        return r;
    r = bf_set_new_from_pack(&to_remove, child);
    if (r)
        return r;

    if (!bf_streq(to_add->name, to_remove->name))
        return bf_err_r(-EINVAL, "to_add->name must match to_remove->name");

    cgen = _bf_get_cgen(chain_name);
    if (!cgen)
        return bf_err_r(-ENOENT, "chain '%s' does not exist", chain_name);

    r = bf_chain_new_from_copy(&new_chain, cgen->chain);
    if (r)
        return r;

    dest_set = bf_chain_get_set_by_name(new_chain, to_add->name);
    if (!dest_set)
        return bf_err_r(-ENOENT, "set '%s' does not exist", to_add->name);

    r = bf_set_add_many(dest_set, &to_add);
    if (r)
        return bf_err_r(r, "failed to calculate set union");

    r = bf_set_remove_many(dest_set, &to_remove);
    if (r)
        return bf_err_r(r, "failed to calculate set difference");

    r = bf_cgen_update(cgen, &new_chain);
    if (r)
        return bf_err_r(r, "failed to update chain with new set data");

    return 0;
}

int bf_cli_request_handler(bf_ctx_t *ctx, const struct bf_request *request,
                           struct bf_response **response)
{
    int r;

    assert(request);
    assert(response);

    switch (bf_request_cmd(request)) {
    case BF_REQ_RULESET_FLUSH:
        r = _bf_cli_ruleset_flush(ctx, request, response);
        break;
    case BF_REQ_RULESET_SET:
        r = _bf_cli_ruleset_set(ctx, request, response);
        break;
    case BF_REQ_RULESET_GET:
        r = _bf_cli_ruleset_get(ctx, request, response);
        break;
    case BF_REQ_CHAIN_SET:
        r = _bf_cli_chain_set(ctx, request, response);
        break;
    case BF_REQ_CHAIN_GET:
        r = _bf_cli_chain_get(ctx, request, response);
        break;
    case BF_REQ_CHAIN_PROG_FD:
        r = _bf_cli_chain_prog_fd(ctx, request, response);
        break;
    case BF_REQ_CHAIN_LOGS_FD:
        r = _bf_cli_chain_logs_fd(ctx, request, response);
        break;
    case BF_REQ_CHAIN_LOAD:
        r = _bf_cli_chain_load(ctx, request, response);
        break;
    case BF_REQ_CHAIN_ATTACH:
        r = _bf_cli_chain_attach(ctx, request, response);
        break;
    case BF_REQ_CHAIN_UPDATE:
        r = _bf_cli_chain_update(ctx, request, response);
        break;
    case BF_REQ_CHAIN_FLUSH:
        r = _bf_cli_chain_flush(ctx, request, response);
        break;
    case BF_REQ_CHAIN_UPDATE_SET:
        r = _bf_cli_chain_update_set(ctx, request, response);
        break;
    default:
        r = bf_err_r(-EINVAL, "unsupported command %d for CLI front-end",
                     bf_request_cmd(request));
        break;
    }

    /* If the callback don't need to send data back to the client, it can skip
     * the response creation and return a status code instead (0 on success,
     * negative errno value on error). The response is created based on the
     * status code. */
    if (!*response) {
        if (!r)
            r = bf_response_new_success(response, NULL, 0);
        else
            r = bf_response_new_failure(response, r);
    }

    return r;
}
