/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/bpf.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include "harness/cmocka.h"

#define _cleanup_bf_mock_ __attribute__((cleanup(bf_mock_cleanup)))

#define bf_mock_declare(ret, x, args)                                          \
    void bf_mock_##x##_enable(void);                                           \
    void bf_mock_##x##_disable(void);                                          \
    bool bf_mock_##x##_is_enabled(void);                                       \
    ret __wrap_##x args;

#define bf_mock_get(name, retval)                                              \
    ({                                                                         \
        bf_mock_##name##_enable();                                             \
        will_return(__wrap_##name, retval);                                    \
        (bf_mock) {                                                            \
            .disable = bf_mock_##name##_disable,                               \
            .wrap_name = BF_STR(__wrap_##name)                                 \
        };                                                                     \
    })

#define bf_mock_empty(name)                                                    \
    ({                                                                         \
        bf_mock_##name##_enable();                                             \
        (bf_mock) {                                                            \
            .disable = bf_mock_##name##_disable,                               \
            .wrap_name = BF_STR(__wrap_##name),                                \
        };  \
    })

#define bf_mock_will_return(mock, value)                                       \
    _will_return((mock).wrap_name, __FILE__, __LINE__, ((uintmax_t)(value)), 1)

#define bf_mock_will_return_always(mock, value)                                \
    _will_return((mock).wrap_name, __FILE__, __LINE__, ((uintmax_t)(value)), -1)


struct nlmsghdr;
struct nl_msg;

typedef struct
{
    void (*disable)(void);
    const char *wrap_name;
} bf_mock;

void bf_mock_cleanup(bf_mock *mock);

bf_mock_declare(void *, malloc, (size_t size));
bf_mock_declare(void *, calloc, (size_t nmemb, size_t size));
bf_mock_declare(int, open, (const char *pathname, int flags, mode_t mode));
bf_mock_declare(ssize_t, read, (int fd, void *buf, size_t count));
bf_mock_declare(ssize_t, write, (int fd, const void *buf, size_t count));
bf_mock_declare(struct btf *, btf__load_vmlinux_btf, (void));
bf_mock_declare(struct nl_msg *, nlmsg_alloc, ());
bf_mock_declare(struct nl_msg *, nlmsg_convert, (struct nlmsghdr * nlh));
bf_mock_declare(struct nlmsghdr *, nlmsg_put,
                (struct nl_msg * n, uint32_t pid, uint32_t seq, int type,
                 int payload, int flags));
bf_mock_declare(int, nlmsg_append,
                (struct nl_msg * n, void *data, size_t len, int pad));
bf_mock_declare(int, bf_bpf_obj_get, (const char *path, int *fd));
bf_mock_declare(int, vsnprintf, (char *str, size_t size, const char *fmt,
                va_list args));
bf_mock_declare(int, snprintf, (char *str, size_t size, const char *fmt, ...));
bf_mock_declare(int, bf_bpf, (enum bpf_cmd cmd, union bpf_attr *attr));
