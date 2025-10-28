/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "mock.h"

#include <errno.h>
#include <stdio.h>

void bft_mock_clean(bft_mock *mock)
{
    mock->disable();
}

// Create a function pointer to the real versioned symbol
// We bypass --wrap by using a different name and binding it via assembly
__asm__(".symver _btf_real_impl, btf__load_vmlinux_btf@LIBBPF_0.5.0");
extern struct btf *_btf_real_impl(void);

bft_mock_define(struct btf *, btf__load_vmlinux_btf, (void)) {
    if (!bft_mock_btf__load_vmlinux_btf_is_enabled()) {
        // Call the real function via our versioned binding
        return _btf_real_impl();
    }

    errno = 1;
    return mock_type(struct btf *);
}