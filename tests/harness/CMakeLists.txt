# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

add_library(harness EXCLUDE_FROM_ALL
    STATIC
        fake.c fake.h
        test.c test.h
)

target_include_directories(harness
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(harness
    PUBLIC
        libbpfilter
)