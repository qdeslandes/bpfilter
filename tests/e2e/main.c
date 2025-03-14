/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/limits.h>
#include <linux/pkt_cls.h>

#include <argp.h>

#include "core/logger.h"
#include "harness/daemon.h"
#include "harness/filters.h"
#include "harness/prog.h"
#include "harness/test.h"
#include "libbpfilter/bpfilter.h"
#include "packets.h"

static struct
{
    char bpfilter_path[PATH_MAX];
} _bf_opts;

static struct argp_option _bf_e2e_options[] = {
    {"bpfilter", 'b', "BPFILTER", 0,
     "Path to the bpfilter daemon binary. Defaults to 'bpfilter' in PATH", 0},
    {0},
};

static error_t _bf_e2e_argp_cb(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'b':
        bf_strncpy(_bf_opts.bpfilter_path, PATH_MAX, arg);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static int _bf_progtype_verdict[_BF_HOOK_MAX][2] = {
    [BF_HOOK_XDP] = {
        [BF_VERDICT_ACCEPT] = XDP_PASS,
        [BF_VERDICT_DROP] = XDP_DROP,
    },
    [BF_HOOK_TC_INGRESS] = {
        [BF_VERDICT_ACCEPT] = TC_ACT_OK,
        [BF_VERDICT_DROP] = TC_ACT_SHOT,
    },
    [BF_HOOK_NF_PRE_ROUTING] = {
        [BF_VERDICT_ACCEPT] = NF_ACCEPT,
        [BF_VERDICT_DROP] = NF_DROP,
    },
    [BF_HOOK_NF_LOCAL_IN] = {
        [BF_VERDICT_ACCEPT] = NF_ACCEPT,
        [BF_VERDICT_DROP] = NF_DROP,
    },
    [BF_HOOK_NF_FORWARD] = {
        [BF_VERDICT_ACCEPT] = NF_ACCEPT,
        [BF_VERDICT_DROP] = NF_DROP,
    },
    [BF_HOOK_CGROUP_INGRESS] = {
        [BF_VERDICT_ACCEPT] = SK_PASS,
        [BF_VERDICT_DROP] = SK_DROP,
    },
    [BF_HOOK_CGROUP_EGRESS] = {
        [BF_VERDICT_ACCEPT] = SK_PASS,
        [BF_VERDICT_DROP] = SK_DROP,
    },
    [BF_HOOK_NF_LOCAL_OUT] = {
        [BF_VERDICT_ACCEPT] = NF_ACCEPT,
        [BF_VERDICT_DROP] = NF_DROP,
    },
    [BF_HOOK_NF_POST_ROUTING] = {
        [BF_VERDICT_ACCEPT] = NF_ACCEPT,
        [BF_VERDICT_DROP] = NF_DROP,
    },
    [BF_HOOK_TC_EGRESS] = {
        [BF_VERDICT_ACCEPT] = TC_ACT_OK,
        [BF_VERDICT_DROP] = TC_ACT_SHOT,
    },
};

static bool _bf_progtype_has_l2[] = {
    [BF_HOOK_XDP] = true,
    [BF_HOOK_TC_INGRESS] = true,
    [BF_HOOK_NF_PRE_ROUTING] = false,
    [BF_HOOK_NF_LOCAL_IN] = false,
    [BF_HOOK_NF_FORWARD] = false,
    [BF_HOOK_CGROUP_INGRESS] = true,
    [BF_HOOK_CGROUP_EGRESS] = true,
    [BF_HOOK_NF_LOCAL_OUT] = false,
    [BF_HOOK_NF_POST_ROUTING] = false,
    [BF_HOOK_TC_EGRESS] = true,
};

int bf_test_run(struct bf_chain *chain, enum bf_verdict verdict, const struct bft_prog_run_args *args)
{
    bf_assert(chain && args);

    for (enum bf_hook hook = BF_HOOK_NF_LOCAL_OUT; hook < _BF_HOOK_MAX; ++hook) {
        _cleanup_bf_test_daemon_ struct bf_test_daemon daemon = bft_daemon_default();
        _free_bf_test_prog_ struct bf_test_prog *prog = NULL;
        const struct bft_prog_run_args *arg = &args[hook];
        int prog_r;
        int r;

        r = bf_test_daemon_init(&daemon, _bf_opts.bpfilter_path ?: "bpfilter",
            BF_TEST_DAEMON_TRANSIENT |
            BF_TEST_DAEMON_NO_IPTABLES |
            BF_TEST_DAEMON_NO_NFTABLES);
        if (r < 0)
            return bf_err_r(r, "failed to create the bpfiler daemon");

        r = bf_test_daemon_start(&daemon);
        if (r < 0)
            return bf_err_r(r, "failed to start the bpfilter daemon");

        chain->hook = hook;
        prog = bf_test_prog_get(chain);
        if (!prog){
            _cleanup_free_ const char *err = bf_test_process_stderr(&daemon.process);
            bf_info("stderr:\n%s", err);
            bf_test_daemon_stop(&daemon);
            return bf_err_r(-EINVAL, "failed to get BPF program");}

        prog_r = bf_test_prog_run(prog, _bf_progtype_verdict[chain->hook][verdict], arg->pkt, arg->pkt_len, &arg->ctx, arg->ctx_len);
        if (prog_r) {
            _cleanup_free_ const char *err = bf_test_process_stderr(&daemon.process);
            bf_info("stderr:\n%s", err);
            bf_test_daemon_stop(&daemon);
        }

        r = bf_test_daemon_stop(&daemon);
        if (r < 0)
            return bf_err_r(r, "failed to stop the bpfilter daemon");

        bf_info("program type %d", hook);
        assert_success(prog_r);
        break;
    }

    return 0;
}

Test(ip6, saddr_eq_nomask_match)
{
    _cleanup_bf_chain_ struct bf_chain *chain = bf_test_chain_get(
        BF_HOOK_XDP,
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            bf_rule_get(
                false,
                BF_VERDICT_DROP,
                (struct bf_matcher *[]) {
                    bf_matcher_get(BF_MATCHER_IP6_SADDR, BF_MATCHER_EQ,
                        (uint8_t[]) {
                            // IP address
                            0x54, 0x2c, 0x1a, 0x31, 0xf9, 0x64, 0x94, 0x6c,
                            0x5a, 0x24, 0xe7, 0x1e, 0x4d, 0x26, 0xb8, 0x7e,
                            // Prefix
                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        },
                        32
                    ),
                    NULL,
                }
            ),
            NULL,
        }
    );

    bf_test_run(chain, BF_VERDICT_DROP, pkt_remote_ip6_tcp);
}


int main(int argc, char *argv[])
{
    _free_bf_test_suite_ bf_test_suite *suite = NULL;
    struct argp argp = { _bf_e2e_options, _bf_e2e_argp_cb, NULL, NULL, 0, NULL, NULL};
    int failed = 0;
    int r;

    r = argp_parse(&argp, argc, argv, 0, 0, NULL);
    if (r)
        return r;

    r = bf_test_discover_test_suite(&suite);
    if (r < 0)
        return bf_err_r(r, "test suite discovery failed");

    bf_list_foreach (&suite->groups, group_node) {
        bf_test_group *group = bf_list_node_get_data(group_node);

        r = _cmocka_run_group_tests(group->name, group->cmtests,
                                    bf_list_size(&group->tests), NULL, NULL);
        if (r) {
            failed = 1;
            break;
        }
    }

    if (failed)
        fail_msg("At least one test group failed!");

    return 0;
}
