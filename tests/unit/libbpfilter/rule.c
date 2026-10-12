/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/rule.h>

#include "bpfilter/core/list.h"
#include "bpfilter/pack.h"
#include "bpfilter/runtime.h"
#include "fake.h"
#include "test.h"

static void to_from_str(void **state)
{
    (void)state;

    assert_enum_to_from_str(enum bf_log_opt, bf_log_opt_to_str,
                            bf_log_opt_from_str, BF_LOG_OPT_LINK,
                            _BF_LOG_OPT_MAX);
}

static void new_and_free(void **state)
{
    _free_bf_rule_ struct bf_rule *rule = NULL;

    (void)state;

    // Free rule manually
    assert_ok(bf_rule_new(&rule));
    bf_rule_free(&rule);
    assert_null(rule);

    // Free rule using the cleanup attribute
    assert_ok(bf_rule_new(&rule));
}

static void pack_and_unpack(void **state)
{
    _free_bf_rule_ struct bf_rule *source = NULL;
    _free_bf_rule_ struct bf_rule *destination = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    bf_rpack_node_t node;
    const void *data;
    size_t data_len;

    (void)state;

    // Pack the source rule
    assert_non_null(source = bft_rule_dummy(8));
    assert_ok(bf_rule_set_tcp_congestion(source, "reno"));
    assert_ok(bf_wpack_new(&wpack));
    bf_wpack_open_object(wpack, "rule");
    assert_ok(bf_rule_pack(source, wpack));
    bf_wpack_close_object(wpack);
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    // Unpack in the destination counter
    assert_ok(bf_rpack_new(&rpack, data, data_len));
    assert_ok(bf_rpack_kv_obj(bf_rpack_root(rpack), "rule", &node));
    assert_ok(bf_rule_new_from_pack(&destination, node));

    assert_true(bft_rule_equal(source, destination));
}

static void unpack_error(void **state)
{
    _free_bf_rule_ struct bf_rule *destination = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    const void *data;
    size_t data_len;

    (void)state;

    assert_ok(bf_wpack_new(&wpack));
    bf_wpack_kv_u32(wpack, "index", 8);
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    assert_ok(bf_rpack_new(&rpack, data, data_len));
    assert_err(bf_rule_new_from_pack(&destination, bf_rpack_root(rpack)));
}

/**
 * @brief Unpack a rule packed with the required keys and an optional
 *        `tcp_congestion` key.
 *
 * @param tcp_congestion Value of the `tcp_congestion` key. If NULL, the key
 *        is not packed, as for rules packed before it was introduced.
 * @param rule On success, contains the unpacked rule. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _unpack_tcp_congestion(const char *tcp_congestion,
                                  struct bf_rule **rule)
{
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    const void *data;
    size_t data_len;
    int r;

    r = bf_wpack_new(&wpack);
    if (r)
        return r;

    bf_wpack_kv_u32(wpack, "index", 0);
    bf_wpack_kv_u8(wpack, "log", 0);
    bf_wpack_kv_bool(wpack, "has_counters", false);
    bf_wpack_kv_u64(wpack, "mark", 0);
    bf_wpack_kv_int(wpack, "verdict", BF_VERDICT_ACCEPT);
    if (tcp_congestion)
        bf_wpack_kv_str(wpack, "tcp_congestion", tcp_congestion);
    bf_wpack_open_array(wpack, "matchers");
    bf_wpack_close_array(wpack);

    r = bf_wpack_get_data(wpack, &data, &data_len);
    if (r)
        return r;

    r = bf_rpack_new(&rpack, data, data_len);
    if (r)
        return r;

    return bf_rule_new_from_pack(rule, bf_rpack_root(rpack));
}

static void unpack_tcp_congestion_key(void **state)
{
    (void)state;

    {
        // Rules packed before tcp_congestion was introduced
        _free_bf_rule_ struct bf_rule *rule = NULL;

        assert_ok(_unpack_tcp_congestion(NULL, &rule));
        assert_false(bf_rule_has_tcp_congestion(rule));
    }

    {
        // Empty name: the rule doesn't set the algorithm
        _free_bf_rule_ struct bf_rule *rule = NULL;

        assert_ok(_unpack_tcp_congestion("", &rule));
        assert_false(bf_rule_has_tcp_congestion(rule));
    }

    {
        _free_bf_rule_ struct bf_rule *rule = NULL;

        assert_ok(_unpack_tcp_congestion("reno", &rule));
        assert_string_equal(rule->tcp_congestion, "reno");
    }

    {
        // Name too long for the kernel
        _free_bf_rule_ struct bf_rule *rule = NULL;

        assert_err(_unpack_tcp_congestion("0123456789abcdef", &rule));
        assert_null(rule);
    }
}

static void set_tcp_congestion(void **state)
{
    _free_bf_rule_ struct bf_rule *rule = NULL;

    (void)state;

    assert_ok(bf_rule_new(&rule));
    assert_false(bf_rule_has_tcp_congestion(rule));

    assert_ok(bf_rule_set_tcp_congestion(rule, "reno"));
    assert_true(bf_rule_has_tcp_congestion(rule));
    assert_string_equal(rule->tcp_congestion, "reno");

    // Longest name accepted by the kernel, then a shorter name overwriting it
    assert_ok(bf_rule_set_tcp_congestion(rule, "0123456789abcde"));
    assert_string_equal(rule->tcp_congestion, "0123456789abcde");
    assert_ok(bf_rule_set_tcp_congestion(rule, "bbr"));
    assert_memory_equal(rule->tcp_congestion,
                        (char[BF_TCP_CA_NAME_MAX]) {"bbr"}, BF_TCP_CA_NAME_MAX);

    // Invalid names leave the rule unchanged
    assert_err(bf_rule_set_tcp_congestion(rule, ""));
    assert_err(bf_rule_set_tcp_congestion(rule, "0123456789abcdef"));
    assert_string_equal(rule->tcp_congestion, "bbr");
}

static void dump(void **state)
{
    _free_bf_rule_ struct bf_rule *rule = NULL;

    (void)state;

    assert_non_null(rule = bft_rule_dummy(8));

    // Dump a list with matchers
    bf_rule_dump(rule, EMPTY_PREFIX);

    // Dump a list without matchers
    bf_list_clean(&rule->matchers);
    bf_rule_dump(rule, EMPTY_PREFIX);

    // Dump a rule setting the TCP congestion control algorithm
    assert_ok(bf_rule_set_tcp_congestion(rule, "reno"));
    bf_rule_dump(rule, EMPTY_PREFIX);
}

static void add_matcher(void **state)
{
    _free_bf_rule_ struct bf_rule *rule = NULL;
    _free_bf_matcher_ struct bf_matcher *matcher0 = NULL;
    _free_bf_matcher_ struct bf_matcher *matcher1 = NULL;
    (void)state;

    assert_non_null(rule = bft_rule_dummy(0));

    assert_non_null(matcher0 = bft_matcher_dummy("hello", 6));
    assert_ok(bf_rule_add_matcher(
        rule, bf_matcher_get_type(matcher0), bf_matcher_get_op(matcher0),
        bf_matcher_payload(matcher0), bf_matcher_payload_len(matcher0), false));
    assert_int_equal(bf_list_size(&rule->matchers), 1);
    assert_true(bft_matcher_equal(
        matcher0, bf_list_node_get_data(bf_list_get_tail(&rule->matchers))));

    assert_non_null(matcher1 = bft_matcher_dummy("", 1));
    assert_ok(bf_rule_add_matcher(
        rule, bf_matcher_get_type(matcher1), bf_matcher_get_op(matcher1),
        bf_matcher_payload(matcher1), bf_matcher_payload_len(matcher1), false));
    assert_int_equal(bf_list_size(&rule->matchers), 2);
    assert_true(bft_matcher_equal(
        matcher1, bf_list_node_get_data(bf_list_get_tail(&rule->matchers))));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(to_from_str),
        cmocka_unit_test(new_and_free),
        cmocka_unit_test(pack_and_unpack),
        cmocka_unit_test(unpack_error),
        cmocka_unit_test(unpack_tcp_congestion_key),
        cmocka_unit_test(set_tcp_congestion),
        cmocka_unit_test(dump),
        cmocka_unit_test(add_matcher),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
