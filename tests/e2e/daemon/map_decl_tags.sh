#!/usr/bin/env bash

# Verify that pinned BPF maps have the expected BTF decl tags, which allow
# bpfilter to identify map types when reconstructing maps from file descriptors.

. "$(dirname "$0")"/../e2e_test_util.sh

CHAIN_DIR="${WORKDIR}/bpf/bpfilter/test_chain"

check_decl_tag() {
    local map_path="$1"
    local expected_tag="$2"

    local btf_id
    btf_id=$(${FROM_NS} bpftool -j map show pinned "${map_path}" | jq '.btf_id')
    [ -n "${btf_id}" ] && [ "${btf_id}" != "null" ] || {
        echo "ERROR: Map at ${map_path} has no BTF data"
        return 1
    }

    ${FROM_NS} bpftool btf dump id "${btf_id}" | grep -q "DECL_TAG '${expected_tag}'" || {
        echo "ERROR: Map at ${map_path} missing decl tag '${expected_tag}'"
        echo "BTF dump:"
        ${FROM_NS} bpftool btf dump id "${btf_id}"
        return 1
    }
}

make_sandbox
start_bpfilter
    ${FROM_NS} bfcli chain set --from-str "chain test_chain BF_HOOK_XDP{ifindex=${NS_IFINDEX}} ACCEPT
        set myset (ip4.saddr) in {
            192.168.1.1;
            192.168.1.2
        }
        rule (ip4.saddr) in myset log link counter DROP"

    # Counters, printer, and set maps must have their respective decl tags
    check_decl_tag "${CHAIN_DIR}/bf_cmap" "BF_MAP_TYPE_COUNTERS"
    check_decl_tag "${CHAIN_DIR}/bf_pmap" "BF_MAP_TYPE_PRINTER"

    SET_MAP=$(${FROM_NS} find "${CHAIN_DIR}" -name 'bf_set_*' | head -1)
    [ -n "${SET_MAP}" ] || { echo "ERROR: No set map found"; exit 1; }
    check_decl_tag "${SET_MAP}" "BF_MAP_TYPE_SET"

    # Log map (ring buffer) does not support BTF data
    BTF_ID=$(${FROM_NS} bpftool -j map show pinned "${CHAIN_DIR}/bf_lmap" | jq '.btf_id // empty')
    [ -z "${BTF_ID}" ] || { echo "ERROR: Log map should not have BTF data (btf_id=${BTF_ID})"; exit 1; }
stop_bpfilter
