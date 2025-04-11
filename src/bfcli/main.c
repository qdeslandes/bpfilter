/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <argp.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bfcli/lexer.h"
#include "bfcli/parser.h"
#include "bfcli/print.h"
#include "core/chain.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/request.h"
#include "core/response.h"
#include "core/set.h"
#include "libbpfilter/bpfilter.h"
#include "version.h"

int bf_send(const struct bf_request *request, struct bf_response **response);

struct bf_ruleset_set_opts
{
    const char *input_file;
    const char *input_string;
};

struct bf_ruleset_get_opts
{
    bool with_counters;
};

static error_t _bf_ruleset_set_opts_parser(int key, const char *arg,
                                           struct argp_state *state)
{
    struct bf_ruleset_set_opts *opts = state->input;

    switch (key) {
    case 'f':
        opts->input_file = arg;
        break;
    case 's':
        opts->input_string = arg;
        break;
    case ARGP_KEY_END:
        if (!opts->input_file && !opts->input_string)
            return bf_err_r(-EINVAL, "--file or --str argument is required");
        if (opts->input_file && opts->input_string)
            return bf_err_r(-EINVAL, "--file is incompatible with --str");
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static int _bf_cli_parse_file(const char *file, struct bf_ruleset *ruleset)
{
    FILE *rules;
    int r;

    rules = fopen(file, "r");
    if (!rules)
        return bf_err_r(errno, "failed to read rules from %s:", file);

    yyin = rules;

    r = yyparse(ruleset);
    if (r == 1)
        r = bf_err_r(-EINVAL, "failed to parse rules, invalid syntax");
    else if (r == 2)
        r = bf_err_r(-ENOMEM, "failed to parse rules, not enough memory");

    return r;
}

static int _bf_cli_parse_str(const char *str, struct bf_ruleset *ruleset)
{
    YY_BUFFER_STATE buffer;
    int r;

    buffer = yy_scan_string(str);

    r = yyparse(ruleset);
    if (r == 1)
        r = bf_err_r(-EINVAL, "failed to parse rules, invalid syntax");
    else if (r == 2)
        r = bf_err_r(-ENOMEM, "failed to parse rules, not enough memory");

    yy_delete_buffer(buffer);

    return r;
}

int _bf_do_ruleset_set(int argc, char *argv[])
{
    static struct bf_ruleset_set_opts opts = {
        .input_file = NULL,
    };
    static struct argp_option options[] = {
        {"file", 'f', "INPUT_FILE", 0, "Input file to use a rules source", 0},
        {"str", 's', "INPUT_STRING", 0, "String to use as rules", 0},
        {0},
    };
    struct argp argp = {
        options, (argp_parser_t)_bf_ruleset_set_opts_parser,
        NULL,    NULL,
        0,       NULL,
        NULL,
    };
    struct bf_ruleset ruleset = {
        .chains = bf_list_default(bf_chain_free, bf_chain_marsh),
        .sets = bf_set_list(),
        .hookopts = bf_list_default(bf_hookopts_free, bf_hookopts_marsh),
    };
    int r;

    r = argp_parse(&argp, argc, argv, 0, 0, &opts);
    if (r) {
        bf_err_r(r, "failed to parse arguments");
        goto end_clean;
    }

    if (opts.input_file)
        r = _bf_cli_parse_file(opts.input_file, &ruleset);
    else
        r = _bf_cli_parse_str(opts.input_string, &ruleset);
    if (r) {
        bf_err_r(r, "failed to parse ruleset");
        goto end_clean;
    }

    // Send the chains to the daemon
    r = bf_cli_ruleset_set(&ruleset.chains, &ruleset.hookopts);
    if (r)
        bf_err_r(r, "failed to set ruleset");

end_clean:
    bf_list_clean(&ruleset.chains);
    bf_list_clean(&ruleset.sets);
    bf_list_clean(&ruleset.hookopts);

    return r;
}

#define streq(str, expected) (str) && bf_streq(str, expected)

static error_t _bf_ruleset_get_opts_parser(int key, const char *arg,
                                           struct argp_state *state)
{
    UNUSED(key);
    UNUSED(arg);
    UNUSED(state);

    return ARGP_ERR_UNKNOWN;
}

int _bf_do_ruleset_get(int argc, char *argv[])
{
    static struct argp_option options[] = {};
    struct argp argp = {
        options, (argp_parser_t)_bf_ruleset_get_opts_parser,
        NULL,    NULL,
        0,       NULL,
        NULL,
    };
    _clean_bf_list_ bf_list chains = bf_list_default(bf_chain_free, NULL);
    _clean_bf_list_ bf_list hookopts = bf_list_default(bf_hookopts_free, NULL);
    _clean_bf_list_ bf_list counters = bf_list_default(bf_list_free, NULL);
    int r;

    r = argp_parse(&argp, argc, argv, 0, 0, NULL);
    if (r)
        return bf_err_r(r, "failed to parse arguments");

    r = bf_cli_ruleset_get(&chains, &hookopts, &counters);
    if (r < 0)
        return bf_err_r(r, "failed to request ruleset");

    r = bf_cli_dump_ruleset(&chains, &hookopts, &counters);
    if (r)
        return bf_err_r(r, "failed to dump ruleset");

    return 0;
}

int _bf_do_chain_set(int argc, char *argv[])
{
    // Reuse ruleset_set parser and options
    static struct bf_ruleset_set_opts opts = {
        .input_file = NULL,
    };
    static struct argp_option options[] = {
        {"file", 'f', "INPUT_FILE", 0, "Input file to use as chain source", 0},
        {"str", 's', "INPUT_STRING", 0, "String to use as chain", 0},
        {0},
    };
    struct argp argp = {
        options, (argp_parser_t)_bf_ruleset_set_opts_parser,
        NULL,    NULL,
        0,       NULL,
        NULL,
    };
    struct bf_ruleset ruleset = {
        .chains = bf_list_default(bf_chain_free, bf_chain_marsh),
        .sets = bf_set_list(),
        .hookopts = bf_list_default(bf_hookopts_free, bf_hookopts_marsh),
    };
    int r;

    r = argp_parse(&argp, argc, argv, 0, 0, &opts);
    if (r) {
        bf_err_r(r, "failed to parse arguments");
        goto end_clean;
    }

    if (opts.input_file)
        r = _bf_cli_parse_file(opts.input_file, &ruleset);
    else
        r = _bf_cli_parse_str(opts.input_string, &ruleset);
    if (r) {
        bf_err_r(r, "failed to parse ruleset");
        goto end_clean;
    }

    if (bf_list_size(&ruleset.chains) != 1) {
        r = bf_err_r(-E2BIG, "multiple chains defined in source");
        goto end_clean;
    }

    // Send the chains to the daemon
    r = bf_cli_chain_set(
        bf_list_node_get_data(bf_list_get_head(&ruleset.chains)),
        bf_list_node_get_data(bf_list_get_head(&ruleset.hookopts)));
    if (r)
        bf_err_r(r, "failed to set chain");

end_clean:
    bf_list_clean(&ruleset.chains);
    bf_list_clean(&ruleset.sets);
    bf_list_clean(&ruleset.hookopts);

    return r;
}

struct bf_chain_load_opts
{
    const char *chain;
    bool update;
};

static error_t _bf_chain_load_opts_parser(int key, const char *arg,
                                          struct argp_state *state)
{
    struct bf_chain_load_opts *opts = state->input;

    switch (key) {
    case 'c':
        opts->chain = arg;
        break;
    case 'u':
        opts->update = true;
        break;
    case ARGP_KEY_END:
        if (!opts->chain) {
            (void)fprintf(stderr, "missing required --chain option");
            return -EINVAL;
        }
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

int _bf_do_chain_load(int argc, char *argv[])
{
    static struct bf_chain_load_opts opts = {};
    static struct argp_option options[] = {
        {"chain", 'c', "CHAIN", 0, "Chain to load.", 0},
        {"update", 'u', NULL, 0,
         "If set, update the chain with the same name that is already loaded.",
         0},
        {0},
    };
    struct argp argp = {
        options, (argp_parser_t)_bf_chain_load_opts_parser, NULL, NULL, 0, NULL,
        NULL,
    };
    struct bf_ruleset ruleset = {
        .chains = bf_list_default(bf_chain_free, bf_chain_marsh),
        .sets = bf_set_list(),
        .hookopts = bf_list_default(bf_hookopts_free, bf_hookopts_marsh),
    };
    int r;

    r = argp_parse(&argp, argc, argv, 0, 0, &opts);
    if (r) {
        bf_err_r(r, "failed to parse arguments");
        goto end_clean;
    }

    r = _bf_cli_parse_str(opts.chain, &ruleset);
    if (r) {
        bf_err_r(r, "failed to parse chain");
        goto end_clean;
    }

    if (bf_list_size(&ruleset.chains) != 1) {
        r = bf_err_r(-E2BIG, "multiple chains defined in source");
        goto end_clean;
    }

    if (bf_list_size(&ruleset.hookopts))
        bf_warn("Hook options are ignored when loading a chain");

    // Send the chains to the daemon
    r = bf_cli_chain_load(
        bf_list_node_get_data(bf_list_get_head(&ruleset.chains)), opts.update);
    if (r)
        bf_err_r(r, "failed to update chain");

end_clean:
    bf_list_clean(&ruleset.chains);
    bf_list_clean(&ruleset.sets);
    bf_list_clean(&ruleset.hookopts);

    return r;
}

struct bf_chain_attach_opts
{
    const char *name;
    struct bf_hookopts options;
};

static error_t _bf_chain_attach_opts_parser(int key, const char *arg,
                                          struct argp_state *state)
{
    _cleanup_free_ char *opt = NULL;
    struct bf_chain_attach_opts *opts = state->input;

    switch (key) {
    case 'n':
        opts->name = arg;
        break;
    case 'o':
        return bf_hookopts_parse_opt(&opts->options, arg);
    case ARGP_KEY_END:
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

int _bf_do_chain_attach(int argc, char *argv[])
{
    static struct bf_chain_attach_opts opts = {};
    static struct argp_option options[] = {
        {"name", 'n', "NAME", 0, "Name of the chain to attach.", 0},
        {"option", 'o', "HOOK_OPTION", 0, "Hook option to use.", 0},
        {0},
    };
    struct argp argp = {
        options, (argp_parser_t)_bf_chain_attach_opts_parser, NULL, NULL, 0, NULL,
        NULL,
    };
    struct bf_ruleset ruleset = {
        .chains = bf_list_default(bf_chain_free, bf_chain_marsh),
        .sets = bf_set_list(),
        .hookopts = bf_list_default(bf_hookopts_free, bf_hookopts_marsh),
    };
    int r;

    r = argp_parse(&argp, argc, argv, 0, 0, &opts);
    if (r)
        return bf_err_r(r, "failed to parse arguments");

    // Send the chains to the daemon
    r = bf_cli_chain_attach(opts.name, &opts.options);
    if (r)
        bf_err_r(r, "failed to attach chain");

    return r;
}

struct bf_chain_update_opts
{
    const char *input_file;
    const char *input_string;
    const char *chain_name;
};

static error_t _bf_chain_update_opts_parser(int key, const char *arg,
                                            struct argp_state *state)
{
    struct bf_chain_update_opts *opts = state->input;

    switch (key) {
    case 'f':
        opts->input_file = arg;
        break;
    case 's':
        opts->input_string = arg;
        break;
    case 'c':
        opts->chain_name = arg;
        break;
    case ARGP_KEY_END:
        if (!opts->input_file && !opts->input_string)
            return bf_err_r(-EINVAL, "--file or --str argument is required");
        if (opts->input_file && opts->input_string)
            return bf_err_r(-EINVAL, "--file is incompatible with --str");
        if (!opts->chain_name)
            return bf_err_r(-EINVAL, "--chain is required");
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

int _bf_do_chain_update(int argc, char *argv[])
{
    static struct bf_chain_update_opts opts = {};
    static struct argp_option options[] = {
        {"file", 'f', "INPUT_FILE", 0, "Input file to use as chain source", 0},
        {"str", 's', "INPUT_STRING", 0, "String to use as chain", 0},
        {"chain", 'c', "CHAIN_NAME", 0, "Name of the chain to update", 0},
        {0},
    };
    struct argp argp = {
        options, (argp_parser_t)_bf_chain_update_opts_parser,
        NULL,    NULL,
        0,       NULL,
        NULL,
    };
    struct bf_ruleset ruleset = {
        .chains = bf_list_default(bf_chain_free, bf_chain_marsh),
        .sets = bf_set_list(),
        .hookopts = bf_list_default(bf_hookopts_free, bf_hookopts_marsh),
    };
    int r;

    r = argp_parse(&argp, argc, argv, 0, 0, &opts);
    if (r) {
        bf_err_r(r, "failed to parse arguments");
        goto end_clean;
    }

    if (opts.input_file)
        r = _bf_cli_parse_file(opts.input_file, &ruleset);
    else
        r = _bf_cli_parse_str(opts.input_string, &ruleset);
    if (r) {
        bf_err_r(r, "failed to parse ruleset");
        goto end_clean;
    }

    if (bf_list_size(&ruleset.chains) != 1) {
        r = bf_err_r(-E2BIG, "multiple chains defined in source");
        goto end_clean;
    }

    if (bf_list_size(&ruleset.hookopts))
        bf_warn("Hook options are ignored when updating a chain");

    // Send the chains to the daemon
    r = bf_cli_chain_update(
        opts.chain_name,
        bf_list_node_get_data(bf_list_get_head(&ruleset.chains)));
    if (r)
        bf_err_r(r, "failed to update chain");

end_clean:
    bf_list_clean(&ruleset.chains);
    bf_list_clean(&ruleset.sets);
    bf_list_clean(&ruleset.hookopts);

    return r;
}

struct bf_chain_flush_opts
{
    const char *chain_name;
};

static error_t _bf_chain_flush_opts_parser(int key, const char *arg,
                                           struct argp_state *state)
{
    struct bf_chain_flush_opts *opts = state->input;

    switch (key) {
    case 'c':
        opts->chain_name = arg;
        break;
    case ARGP_KEY_END:
        if (!opts->chain_name)
            return bf_err_r(-EINVAL, "--chain is required");
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

int _bf_do_chain_flush(int argc, char *argv[])
{
    static struct bf_chain_flush_opts opts = {};
    static struct argp_option options[] = {
        {"chain", 'c', "CHAIN_NAME", 0, "Name of the chain to update", 0},
        {0},
    };
    struct argp argp = {
        options, (argp_parser_t)_bf_chain_flush_opts_parser,
        NULL,    NULL,
        0,       NULL,
        NULL,
    };
    int r;

    r = argp_parse(&argp, argc, argv, 0, 0, &opts);
    if (r) {
        return bf_err_r(r, "failed to parse arguments");
    }

    r = bf_cli_chain_flush(opts.chain_name);
    if (r)
        bf_err_r(r, "failed to flush chain");

    return r;
}

int main(int argc, char *argv[])
{
    const char *obj_str = NULL;
    const char *action_str = NULL;
    int argv_skip = 0;
    int r;

    if (argc > 1 && argv[1][0] != '-') {
        obj_str = argv[1];
        ++argv_skip;
    }

    if (obj_str && argc > 2 && argv[2][0] != '-') {
        action_str = argv[2];
        ++argv_skip;
    }

    argv += argv_skip;
    argc -= argv_skip;

    bf_logger_setup();

    // If any of the arguments is --version, print the version and return.
    for (int i = 0; i < argc; ++i) {
        if (bf_streq("--version", argv[i])) {
            bf_info("bfcli version %s, libbpfilter version %s", BF_VERSION,
                    bf_version());
            exit(0);
        }
    }

    if (streq(obj_str, "ruleset") && streq(action_str, "set")) {
        r = _bf_do_ruleset_set(argc, argv);
    } else if (streq(obj_str, "ruleset") && streq(action_str, "get")) {
        r = _bf_do_ruleset_get(argc, argv);
    } else if (streq(obj_str, "ruleset") && streq(action_str, "flush")) {
        r = bf_cli_ruleset_flush();
    } else if (streq(obj_str, "chain") && streq(action_str, "set")) {
        r = _bf_do_chain_set(argc, argv);
    } else if (streq(obj_str, "chain") && streq(action_str, "get")) {
        r = -ENOTSUP;
    } else if (streq(obj_str, "chain") && streq(action_str, "load")) {
        r = _bf_do_chain_load(argc, argv);
    } else if (streq(obj_str, "chain") && streq(action_str, "attach")) {
        r = _bf_do_chain_attach(argc, argv);
    } else if (streq(obj_str, "chain") && streq(action_str, "update")) {
        r = _bf_do_chain_update(argc, argv);
    } else if (streq(obj_str, "chain") && streq(action_str, "flush")) {
        r = _bf_do_chain_flush(argc, argv);
    } else {
        return bf_err_r(-EINVAL, "unrecognized object '%s' and action '%s'",
                        obj_str, action_str);
    }

    return r;
}

void yyerror(struct bf_ruleset *ruleset, const char *fmt, ...)
{
    UNUSED(ruleset);

    va_list args;

    va_start(args, fmt);
    bf_err_v(fmt, args);
    va_end(args);
}
