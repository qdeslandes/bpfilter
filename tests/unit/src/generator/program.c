/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "generator/program.c"

#include "harness/cmocka.h"
#include "harness/helper.h"
#include "harness/mock.h"

Test(program, emit_fixup_call)
{
    expect_assert_failure(bf_program_emit_fixup_call(
        NULL, BF_CODEGEN_FIXUP_FUNCTION_ADD_COUNTER));

    {
        // Instructions buffer should grow
        _cleanup_bf_program_ struct bf_program *program = NULL;
        size_t start_cap;

        assert_int_equal(
            0, bf_program_new(&program, 1, BF_HOOK_IPT_FORWARD, BF_FRONT_IPT));

        start_cap = program->img_cap;

        // Instructions buffer is empty after initialisation, ensure it grows.
        assert_int_equal(0,
                         bf_program_emit_fixup_call(
                             program, BF_CODEGEN_FIXUP_FUNCTION_ADD_COUNTER));
        assert_int_not_equal(program->img_cap, start_cap);
    }
}
