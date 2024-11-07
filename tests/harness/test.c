/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "harness/test.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/dump.h"
#include "core/helper.h"
#include "core/list.h"
#include "core/logger.h"
#include "harness/sym.h"

int bf_test_new(bf_test **test, const char *name, bf_test_cb cb)
{
    _free_bf_test_ bf_test *_test = NULL;

    bf_assert(test && name && cb);

    _test = calloc(1, sizeof(*_test));
    if (!_test)
        return -ENOMEM;

    _test->name = strdup(name);
    if (!_test->name)
        return -ENOMEM;

    _test->cb = cb;

    *test = TAKE_PTR(_test);

    return 0;
}

void bf_test_free(bf_test **test)
{
    bf_assert(test);

    if (!*test)
        return;

    freep((void *)&(*test)->name);
    freep((void *)test);
}

void bf_test_dump(const bf_test *test, prefix_t *prefix)
{
    bf_assert(test && prefix);

    DUMP(prefix, "bf_test at %p", test);
    bf_dump_prefix_push(prefix);
    DUMP(prefix, "name: %s", test->name);
    DUMP(bf_dump_prefix_last(prefix), "cb: %p", test->cb);
    bf_dump_prefix_pop(prefix);
}

int bf_test_group_new(bf_test_group **group, const char *name)
{
    _free_bf_test_group_ bf_test_group *_group = NULL;

    bf_assert(group && name);

    _group = calloc(1, sizeof(*_group));
    if (!_group)
        return -ENOMEM;

    _group->name = strdup(name);
    if (!_group->name)
        return -ENOMEM;

    bf_list_init(&_group->tests,
                 (bf_list_ops[]) {{.free = (bf_list_ops_free)bf_test_free}});

    *group = TAKE_PTR(_group);

    return 0;
}

void bf_test_group_free(bf_test_group **group)
{
    bf_assert(group);

    if (!*group)
        return;

    freep((void *)&(*group)->name);
    freep((void *)&(*group)->cmtests);
    bf_list_clean(&(*group)->tests);
    freep((void *)group);
}

void bf_test_group_dump(const bf_test_group *group, prefix_t *prefix)
{
    bf_assert(group && prefix);

    DUMP(prefix, "bf_test_group at %p", group);
    bf_dump_prefix_push(prefix);
    DUMP(prefix, "name: %s", group->name);

    DUMP(prefix, "tests: bf_list<bf_test>[%lu]", bf_list_size(&group->tests));
    bf_dump_prefix_push(prefix);
    bf_list_foreach (&group->tests, test_node) {
        bf_test *test = bf_list_node_get_data(test_node);

        if (bf_list_is_tail(&group->tests, test_node))
            bf_dump_prefix_last(prefix);

        bf_test_dump(test, prefix);
    }
    bf_dump_prefix_pop(prefix);

    DUMP(bf_dump_prefix_last(prefix), "cmtests: (struct CMUnitTest *)%p",
         group->cmtests);
    bf_dump_prefix_pop(prefix);
}

bf_test *bf_test_group_get_test(bf_test_group *group, const char *test_name)
{
    bf_assert(group && test_name);

    bf_list_foreach (&group->tests, test_node) {
        bf_test *test = bf_list_node_get_data(test_node);
        if (bf_streq(test->name, test_name))
            return test;
    }

    return NULL;
}

int bf_test_group_add_test(bf_test_group *group, const char *test_name,
                           bf_test_cb cb)
{
    _free_bf_test_ bf_test *test = NULL;
    int r;

    bf_assert(group && test_name && cb);

    if (bf_test_group_get_test(group, test_name))
        return -EEXIST;

    r = bf_test_new(&test, test_name, cb);
    if (r)
        return r;

    r = bf_list_add_tail(&group->tests, test);
    if (r)
        return r;

    TAKE_PTR(test);

    return 0;
}

int bf_test_group_make_cmtests(bf_test_group *group)
{
    size_t index = 0;

    bf_assert(group);

    group->cmtests =
        calloc(bf_list_size(&group->tests), sizeof(struct CMUnitTest));
    if (!group->cmtests)
        return -ENOMEM;

    bf_list_foreach (&group->tests, test_node) {
        bf_test *test = bf_list_node_get_data(test_node);

        group->cmtests[index++] = (struct CMUnitTest) {
            .name = test->name,
            .test_func = test->cb,
        };
    }

    return 0;
}

int bf_test_suite_new(bf_test_suite **suite)
{
    _free_bf_test_suite_ bf_test_suite *_suite = NULL;

    bf_assert(suite);

    _suite = calloc(1, sizeof(*_suite));
    if (!_suite)
        return -ENOMEM;

    bf_list_init(
        &_suite->groups,
        (bf_list_ops[]) {{.free = (bf_list_ops_free)bf_test_group_free}});

    *suite = TAKE_PTR(_suite);

    return 0;
}

void bf_test_suite_free(bf_test_suite **suite)
{
    bf_assert(suite);

    if (!*suite)
        return;

    bf_list_clean(&(*suite)->groups);
    freep((void *)suite);
}

void bf_test_suite_dump(const bf_test_suite *suite, prefix_t *prefix)
{
    bf_assert(suite && prefix);

    DUMP(prefix, "bf_test_suite at %p", suite);
    bf_dump_prefix_push(prefix);
    DUMP(bf_dump_prefix_last(prefix), "groups: bf_list<bf_group>[%lu]",
         bf_list_size(&suite->groups));
    bf_dump_prefix_push(prefix);
    bf_list_foreach (&suite->groups, group_node) {
        bf_test_group *group = bf_list_node_get_data(group_node);

        if (bf_list_is_tail(&suite->groups, group_node))
            bf_dump_prefix_last(prefix);

        bf_test_group_dump(group, prefix);
    }
    bf_dump_prefix_pop(prefix);
    bf_dump_prefix_pop(prefix);
}

bf_test_group *bf_test_suite_get_group(bf_test_suite *suite,
                                       const char *group_name)
{
    bf_assert(suite && group_name);

    bf_list_foreach (&suite->groups, group_node) {
        bf_test_group *group = bf_list_node_get_data(group_node);
        if (bf_streq(group->name, group_name))
            return group;
    }

    return NULL;
}

int bf_test_suite_add_test(bf_test_suite *suite, const char *group_name,
                           const char *test_name, bf_test_cb cb)

{
    bf_test_group *group;
    int r;

    bf_assert(suite && group_name && test_name && cb);

    group = bf_test_suite_get_group(suite, group_name);
    if (!group) {
        _free_bf_test_group_ bf_test_group *new_group = NULL;

        r = bf_test_group_new(&new_group, group_name);
        if (r)
            return r;

        r = bf_list_add_tail(&suite->groups, new_group);
        if (r)
            return r;

        group = TAKE_PTR(new_group);
    }

    r = bf_test_group_add_test(group, test_name, cb);
    if (r)
        return r;

    return 0;
}

int bf_test_suite_add_symbol(bf_test_suite *suite, struct bf_test_sym *sym)
{
    _cleanup_free_ char *group_name = NULL;
    _cleanup_free_ char *test_name = NULL;
    const char *group_name_end;
    const char *test_name_start;
    int r;

    bf_assert(suite && sym);

    // Split symbol name into group name and test name
    group_name_end = strchr(sym->name, '_');
    if (!group_name_end || group_name_end - sym->name == 0)
        return -EINVAL;

    group_name = strndup(sym->name, group_name_end - sym->name);
    if (!group_name)
        return -ENOMEM;

    test_name_start = group_name_end + 2;
    if (!(sym->name <= test_name_start &&
          test_name_start < (sym->name + strlen(sym->name))))
        return -EINVAL;

    test_name = strdup(test_name_start);
    if (!test_name)
        return -ENOMEM;

    // Add test to suite
    r = bf_test_suite_add_test(suite, group_name, test_name, sym->cb);
    if (r)
        return r;

    return 0;
}

int bf_test_suite_make_cmtests(const bf_test_suite *suite)
{
    int r;

    bf_assert(suite);

    bf_list_foreach (&suite->groups, group_node) {
        bf_test_group *group = bf_list_node_get_data(group_node);

        r = bf_test_group_make_cmtests(group);
        if (r) {
            bf_warn_r(r, "failed to make CMocka unit test for group '%s'",
                      group->name);
            continue;
        }
    }

    return 0;
}