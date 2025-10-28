# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

# - Define a new C test
#
# Create a new C-based test for bpfilter.
#
# Params:
# - GROUP: name of the group to add the test to.
# - SOURCE: source file defining the test.
#
# C-based tests are configured to be automatically build before running, which
# is different from CTest's default behaviour.
function(bf_add_c_test GROUP SOURCE)
    find_package(cmocka REQUIRED)

    set(source_wo_ext ${SOURCE})
    cmake_path(REMOVE_EXTENSION source_wo_ext)
    string(REPLACE "/" "." target_suffix "${source_wo_ext}")

    set(target_name "${GROUP}.${target_suffix}")

    add_executable(${target_name} EXCLUDE_FROM_ALL ${SOURCE} mock.c mock.h)

    # CMocka doesn't automatically discover the tests, -Wunused-function ensures
    # we run all the tests defined in a source file.
    target_compile_options(${target_name}
        PRIVATE
            -Werror=unused-function
    )

    target_link_libraries(${target_name}
        PRIVATE
            bf_global_flags
            harness
            cmocka
            libbpfilter
    )

    add_dependencies(test_bin ${target_name})
    target_link_options(${target_name} PRIVATE "-Wl,--wrap=btf__load_vmlinux_btf")
    target_include_directories(${target_name} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

    add_test(NAME ${target_name}
        COMMAND $<TARGET_FILE:${target_name}>
    )

    set_tests_properties(${target_name} PROPERTIES LABELS "${GROUP}")
endfunction()

bf_add_c_test(unit libbpfilter/btf.c)
bf_add_c_test(unit libbpfilter/list.c)