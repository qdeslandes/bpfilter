# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

# - Compile stub programs to be integrated to bpfilter
#
# Compile stub programs located in src/bpfilter/cgen/bpf into ELF files using
# clang. The ELF file will be integrated into bpfilter, so the functions defined
# in can be merged into the generated BPF programs.
#
# Creating stubs is a way to rely on clang to generate the BPF bytecode of
# custom functions.
#
# Stubs source code is located in src/bpfilter/bpf/STUB_NAME.bpf.c.

function(bf_target_add_elfstubs TARGET)
    cmake_parse_arguments(PARSE_ARGV 1 _LOCAL "" "" "STUBS")

    find_program(CLANG_BIN clang REQUIRED)
    find_program(XXD_BIN xxd REQUIRED)
    find_program(SED_BIN sed REQUIRED)

    list(LENGTH _LOCAL_STUBS N_STUBS)

    set(PVT_HDR_TEMPLATE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cgen/elfstub_pvt.h.in)

    message(STATUS "Building ${N_STUBS} stub program(s) for target '${TARGET}'")

    foreach(_stub IN LISTS _LOCAL_STUBS)
        add_custom_command(
            COMMAND
                ${CLANG_BIN}
                    -O2
                    -target bpf
                    -I ${CMAKE_SOURCE_DIR}/src
                    -c ${CMAKE_CURRENT_SOURCE_DIR}/bpf/${_stub}.bpf.c
                    -o ${CMAKE_CURRENT_BINARY_DIR}/${_stub}.o
            COMMAND
                ${XXD_BIN}
                    -i
                    -n _bf_rawstub_${_stub}
                    ${CMAKE_CURRENT_BINARY_DIR}/${_stub}.o
                    ${CMAKE_BINARY_DIR}/include/${_stub}.inc.c
            COMMAND
                # By default, xxd variables are not static nor const, fix it
                ${SED_BIN}
                    -i 's/^unsigned /static const unsigned /'
                    ${CMAKE_BINARY_DIR}/include/${_stub}.inc.c
            DEPENDS
                ${CMAKE_CURRENT_SOURCE_DIR}/bpf/${_stub}.bpf.c
                ${ELFSTUB_PVT_TEMPLATE_PATH}
            OUTPUT
                ${CMAKE_BINARY_DIR}/include/${_stub}.inc.c
            COMMENT "Generate ${_stub} stub"
        )

        list(APPEND INC_DECL_LIST "#include \"${_stub}.inc.c\"")
        list(APPEND STRUCT_DECL_LIST "{ .elf = _bf_rawstub_${_stub}, .len = _bf_rawstub_${_stub}_len, },")

        target_sources(${TARGET}
            PRIVATE
                ${CMAKE_BINARY_DIR}/include/${_stub}.inc.c
        )

        # Do not compile the source file containing each stub, it will be
        # included in the elfstub_pvt.h header
        set_source_files_properties(${CMAKE_BINARY_DIR}/include/${_stub}.inc.c
            PROPERTIES
                HEADER_FILE_ONLY ON
        )

        message(VERBOSE "  - ${_stub}")
    endforeach()

    list(JOIN INC_DECL_LIST "\n" INC_DECL)
    list(JOIN STRUCT_DECL_LIST "\n" STRUCT_DECL)

    get_filename_component(ELFSTUB_PVT_FILENAME ${ELFSTUB_PVT_TEMPLATE_PATH} NAME_WLE)
    configure_file(
        ${ELFSTUB_PVT_TEMPLATE_PATH}
        ${CMAKE_BINARY_DIR}/include/${ELFSTUB_PVT_FILENAME}
        @ONLY
    )

    target_sources(${TARGET} PRIVATE ${ELFSTUB_PVT_PATH})
endfunction()

find_package(PkgConfig REQUIRED)
pkg_check_modules(nl REQUIRED IMPORTED_TARGET libnl-3.0)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/bpfilter.service.in
    ${CMAKE_BINARY_DIR}/output/usr/lib/systemd/system/bpfilter.service
    @ONLY
)

add_executable(bpfilter
    ${CMAKE_CURRENT_SOURCE_DIR}/main.c
    ${CMAKE_BINARY_DIR}/include/version.h
    ${CMAKE_CURRENT_SOURCE_DIR}/opts.h                   ${CMAKE_CURRENT_SOURCE_DIR}/opts.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/cgen.h              ${CMAKE_CURRENT_SOURCE_DIR}/cgen/cgen.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/cgroup.h            ${CMAKE_CURRENT_SOURCE_DIR}/cgen/cgroup.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/dump.h              ${CMAKE_CURRENT_SOURCE_DIR}/cgen/dump.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/elfstub.h           ${CMAKE_CURRENT_SOURCE_DIR}/cgen/elfstub.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/fixup.h             ${CMAKE_CURRENT_SOURCE_DIR}/cgen/fixup.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/jmp.h               ${CMAKE_CURRENT_SOURCE_DIR}/cgen/jmp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/ip4.h       ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/ip4.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/ip6.h       ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/ip6.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/set.h       ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/set.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/tcp.h       ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/tcp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/udp.h       ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/udp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/meta.h      ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/meta.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/icmp.h      ${CMAKE_CURRENT_SOURCE_DIR}/cgen/matcher/icmp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/nf.h                ${CMAKE_CURRENT_SOURCE_DIR}/cgen/nf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/printer.h           ${CMAKE_CURRENT_SOURCE_DIR}/cgen/printer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/program.h           ${CMAKE_CURRENT_SOURCE_DIR}/cgen/program.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/prog/link.h         ${CMAKE_CURRENT_SOURCE_DIR}/cgen/prog/link.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/prog/map.h          ${CMAKE_CURRENT_SOURCE_DIR}/cgen/prog/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/runtime.h
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/stub.h              ${CMAKE_CURRENT_SOURCE_DIR}/cgen/stub.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/swich.h             ${CMAKE_CURRENT_SOURCE_DIR}/cgen/swich.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/tc.h                ${CMAKE_CURRENT_SOURCE_DIR}/cgen/tc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/cgen/xdp.h               ${CMAKE_CURRENT_SOURCE_DIR}/cgen/xdp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ctx.h                    ${CMAKE_CURRENT_SOURCE_DIR}/ctx.c
    ${CMAKE_CURRENT_SOURCE_DIR}/xlate/cli.c
    ${CMAKE_CURRENT_SOURCE_DIR}/xlate/front.h            ${CMAKE_CURRENT_SOURCE_DIR}/xlate/front.c
    ${CMAKE_CURRENT_SOURCE_DIR}/xlate/ipt/dump.h         ${CMAKE_CURRENT_SOURCE_DIR}/xlate/ipt/dump.c
    ${CMAKE_CURRENT_SOURCE_DIR}/xlate/ipt/helpers.h
    ${CMAKE_CURRENT_SOURCE_DIR}/xlate/ipt/ipt.c
    # Do not build those until the nft front-end is fixed.
    # ${CMAKE_CURRENT_SOURCE_DIR}/xlate/nft/nfgroup.h      ${CMAKE_CURRENT_SOURCE_DIR}/xlate/nft/nfgroup.c
    # ${CMAKE_CURRENT_SOURCE_DIR}/xlate/nft/nfmsg.h        ${CMAKE_CURRENT_SOURCE_DIR}/xlate/nft/nfmsg.c
    ${CMAKE_CURRENT_SOURCE_DIR}/xlate/nft/nft.c

    ${CMAKE_SOURCE_DIR}/src/external/disasm.h            ${CMAKE_SOURCE_DIR}/src/external/disasm.c
    ${CMAKE_SOURCE_DIR}/src/external/murmur3.h           ${CMAKE_SOURCE_DIR}/src/external/murmur3.c
)

bf_target_add_elfstubs(bpfilter
    STUBS
        "parse_ipv6_eh"
)

target_compile_definitions(bpfilter
    PRIVATE
        BF_CONTACT="${BF_CONTACT}"
)

target_include_directories(bpfilter
    PUBLIC
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_BINARY_DIR}/include
)

target_link_libraries(bpfilter
    PRIVATE
        bf_global_flags
        core
        PkgConfig::nl
)

install(TARGETS bpfilter
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

install(
    FILES ${CMAKE_BINARY_DIR}/output/usr/lib/systemd/system/bpfilter.service
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system
)
