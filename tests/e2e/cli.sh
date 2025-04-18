#!/usr/bin/env bash

set -e

# Define variables
NAMESPACE="test_ns"
COUNTERS_MAP_NAME="counters_map"
VETH_HOST="veth_host"
VETH_NS="veth_ns"
HOST_IP="10.0.0.1/24"
NS_IP="10.0.0.2/24"
HOST_IP_ADDR="10.0.0.1"
NS_IP_ADDR="10.0.0.2"

BLUE='\033[0;34m'
BLUE_BOLD='\033[1;34m'
GREEN='\033[0;32m'
GREEN_BOLD='\033[1;32m'
RED='\033[0;31m'
RED_BOLD='\033[1;31m'
YELLOW='\033[0;33m'
YELLOW_BOLD='\033[1;33m'
RESET='\033[0m'

BPFILTER_PID=0

log() {
    echo -e "${BLUE}[.] ${BLUE_BOLD}$1${RESET}"
}

expect_result() {
    local description="$1"
    local expected_result="$2"  # 0 = success, non-zero = failure
    shift 2

    echo "bpfilter PID ${BPFILTER_PID}"
    # Build the command string for eval
    local cmd="LD_LIBRARY_PATH=/tmp nsenter --user -t ${BPFILTER_PID} $*"

    # Capture both stdout and stderr
    local output
    local result=0
    output=$(eval "$cmd" 2>&1) || result=$?
    echo $$

    # Check if the result matches the expected result
    if { [ "$expected_result" -eq 0 ] && [ $result -eq 0 ]; } ||
       { [ "$expected_result" -ne 0 ] && [ $result -ne 0 ]; }; then
        # Success case
        echo -e "${GREEN}[+] -> Success: ${GREEN_BOLD}${description}${RESET}" >&2

        return 0
    else
        # Failure case
        echo -e "${RED}[-] -> Failure: ${RED_BOLD}${description}${RESET}" >&2

        # Print the command that was executed
        echo -e "${YELLOW}Command:${RESET} $cmd" >&2

        # Print the captured output
        echo -e "${YELLOW}Output:${RESET}" >&2
        echo "$output" >&2
        echo >&2

        return 1
    fi
}

# Wrapper function to maintain backward compatibility for expect_success
expect_success() {
    local description="$1"
    shift
    expect_result "$description" 0 "$@"
}

# Wrapper function to maintain backward compatibility for expect_failure
expect_failure() {
    local description="$1"
    shift
    expect_result "$description" 1 "$@"
}

BPFILTER_PID=0

# Function to cleanup on exit or error
cleanup() {
    echo "Cleanup bpfilter pid ${BPFILTER_PID}"
    if [ -n "$BPFILTER_PID" ]; then
        kill $BPFILTER_PID 2>/dev/null || true
    fi

    if [ "${1:-0}" -ne 0 ] && [ -f "$BPFILTER_OUTPUT_FILE" ]; then
        log "bpfilter output:"
        cat "$BPFILTER_OUTPUT_FILE"
    fi

    ip netns del ${NAMESPACE} 2>/dev/null || true
    exit ${1:-0}
}

# Set trap to ensure cleanup happens
trap 'cleanup $?' EXIT
trap 'cleanup 1' INT TERM


################################################################################
#
# Options
#
################################################################################

BFCLI="bfcli"
BPFILTER="bpfilter"

# Function to display usage information
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  --${BFCLI} PATH      Path to ${BFCLI} executable (default: $BFCLI)"
    echo "  --bpfilter PATH   Path to bpfilter executable (default: $BPFILTER)"
    echo "  -h, --help        Display this help message and exit"
    exit 1
}

# Parse command line options
while [[ $# -gt 0 ]]; do
    case "$1" in
        --${BFCLI})
            if [[ -z "$2" || "$2" == --* ]]; then
                echo "Error: --${BFCLI} requires a path argument."
                usage
            fi
            BFCLI="$2"
            shift 2
            ;;
        --bpfilter)
            if [[ -z "$2" || "$2" == --* ]]; then
                echo "Error: --bpfilter requires a path argument."
                usage
            fi
            BPFILTER="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Error: Unknown option '$1'"
            usage
            ;;
    esac
done


################################################################################
#
# Configure the network namespace
#
################################################################################



log "[SUITE] Setup"
#expect_success "validate namespace connectivity" \
#    ip netns exec ${NAMESPACE} ping -c 1 ${HOST_IP_ADDR}


################################################################################
#
# Start bpfilter
#
################################################################################

log "Starting bpfilter in background..."
BPFILTER_OUTPUT_FILE=$(mktemp)
MAKE_SMTH=/tmp/make_token_bin

/sbin/capsh --decode=$(grep CapBnd /proc/$$/status|cut -f2)
# Start bpfilter in user namespace and have it write its PID to a file
ls /run/netns
unshare --user --map-user=$(id -u) --map-group=$(id -g) --mount --keep-caps bash -c "
    mkdir /tmp/test
    mount bpffs -t bpf /tmp/test
    # Verify the mount
    mount | grep bpffs
    ls -la /sys/fs/bpf
    echo "MAKE_SMTH"
    ${MAKE_SMTH}; \
    echo "exexc"
    exec ${BPFILTER} --transient --verbose debug --verbose bpf
" > "$BPFILTER_OUTPUT_FILE" 2>&1 &

log "after unshare"
# Wait for bpfilter to initialize
sleep 0.25

# Get the actual PID of bpfilter
log "before pgrep: looking for ${BPFILTER}"
ps -aux | grep bpfilter
BPFILTER_PID=$(pgrep bpfilter)
log "after pgrep"
echo "bpfilter PID is ${BPFILTER_PID}"

# Wait for bpfilter to initialize
sleep 0.25

echo "add ns"
# ip netns add ${NAMESPACE}
echo "attach ns"
ip netns attach ${NAMESPACE} ${BPFILTER_PID}
echo "add link"
ip link add ${VETH_HOST} type veth peer name ${VETH_NS}

echo "config ns"
ip link set ${VETH_NS} netns ${NAMESPACE}

ip addr add ${HOST_IP} dev ${VETH_HOST}
ip netns exec ${NAMESPACE} ip addr add ${NS_IP} dev ${VETH_NS}

ip link set ${VETH_HOST} up
ip netns exec ${NAMESPACE} ip link set ${VETH_NS} up
ip netns exec ${NAMESPACE} ip link set lo up

HOST_IFINDEX=$(ip -o link show ${VETH_HOST} | awk '{print $1}' | cut -d: -f1)
NS_IFINDEX=$(ip netns exec ${NAMESPACE} ip -o link show ${VETH_NS} | awk '{print $1}' | cut -d: -f1)

log "Network interfaces configured:"
log "  ${HOST_IFINDEX}: ${VETH_HOST} @ ${HOST_IP_ADDR}"
log "  ${NS_IFINDEX}: ${VETH_NS} @ ${NS_IP_ADDR}"

################################################################################
#
# Run tests
#
################################################################################

log "[SUITE] netns: define chains from the host"
expect_failure "can't attach chain to netns iface from host" \
    ${BFCLI} ruleset set --str \"chain xdp BF_HOOK_XDP\{ifindex=${NS_IFINDEX}\} ACCEPT rule ip4.proto icmp counter DROP\"
#expect_success "can ping host iface from netns" \
#    ip netns exec ${NAMESPACE} ping -c 1 -W 0.25 ${HOST_IP_ADDR}
expect_success "attach chain to host iface" \
    ${BFCLI} ruleset set --str \"chain xdp BF_HOOK_TC_INGRESS\{ifindex=${HOST_IFINDEX}\} ACCEPT rule ip4.proto icmp counter DROP\"
#expect_failure "can't ping host iface from netns" \
#    ip netns exec ${NAMESPACE} ping -c 1 -W 0.25 ${HOST_IP_ADDR}
expect_success "pings have been blocked on ingress" \
    bpftool --json map dump name ${COUNTERS_MAP_NAME} \| jq --exit-status \'.[0].formatted.value.packets == 1\'
expect_success "flushing the ruleset" \
    ${BFCLI} ruleset flush

log "[SUITE] Define chain from the netns"
expect_failure "can't attach chain to host iface from netns" \
    ip netns exec ${NAMESPACE} ${BFCLI} ruleset set --str \"chain xdp BF_HOOK_XDP\{ifindex=${HOST_IFINDEX}\} ACCEPT rule ip4.proto icmp counter DROP\"
expect_success "can ping the netns iface from the host" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "attach chain to the netns iface" \
    ip netns exec ${NAMESPACE} ${BFCLI} ruleset set --str \"chain xdp BF_HOOK_XDP\{ifindex=${NS_IFINDEX}\} ACCEPT rule ip4.proto icmp counter DROP\"
expect_failure "can't ping the netns iface from the host" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "pings have been blocked on ingress" \
    bpftool --json map dump name ${COUNTERS_MAP_NAME} \| jq --exit-status \'.[0].formatted.value.packets == 1\'
expect_success "flushing the ruleset" \
    ${BFCLI} ruleset flush

log "[SUITE] netns: define chains from the netns"
expect_failure "no chain defined in --from-str" \
    ${BFCLI} chain set --from-str \"\"
expect_failure "multiple chains defined in --from-str, no --name" \
    ${BFCLI} chain set --from-str \"chain test0 BF_HOOK_XDP ACCEPT chain test1 BF_HOOK_XDP ACCEPT\"
expect_failure "multiple chains defined in --from-str, --name does not exist" \
    ${BFCLI} chain set --name invalid --from-str \"chain test0 BF_HOOK_XDP ACCEPT chain test1 BF_HOOK_XDP ACCEPT\"
expect_success "single chain defined in --from-str, do not attach" \
    ${BFCLI} chain set --from-str \"chain chain_set_xdp_0 BF_HOOK_XDP ACCEPT\"
expect_success "single chain defined in --from-str, attach" \
    ${BFCLI} chain set --from-str \"chain chain_set_xdp_1 BF_HOOK_XDP\{ifindex=${HOST_IFINDEX}\} ACCEPT\"
expect_success "multiple chains defined in --from-str, do not attach" \
    ${BFCLI} chain set --name chain_set_tc_0 --from-str \"chain chain_set_tc_0 BF_HOOK_TC_INGRESS ACCEPT chain chain_set_tc_1 BF_HOOK_TC_INGRESS ACCEPT\"
expect_success "multiple chains defined in --from-str, attach" \
    ${BFCLI} chain set --name chain_set_tc_2 --from-str \"chain chain_set_tc_2 BF_HOOK_TC_EGRESS\{ifindex=${HOST_IFINDEX}\} ACCEPT chain chain_set_tc_3 BF_HOOK_TC_INGRESS ACCEPT\"
expect_success "replace a chain that is not attached, do not attach the new one" \
    ${BFCLI} chain set --from-str \"chain chain_set_xdp_0 BF_HOOK_NF_LOCAL_IN ACCEPT\"
expect_success "replace a chain that is not attached, attach the new one" \
    ${BFCLI} chain set --from-str \"chain chain_set_tc_0 BF_HOOK_NF_LOCAL_IN\{family=inet4,priorities=101-102\} ACCEPT\"
expect_success "replace a chain that is attached, do not attach the new one" \
    ${BFCLI} chain set --from-str \"chain chain_set_xdp_1 BF_HOOK_NF_LOCAL_IN ACCEPT\"
expect_success "replace a chain that is attached, attach the new one" \
    ${BFCLI} chain set --from-str \"chain chain_set_tc_2 BF_HOOK_NF_LOCAL_IN\{family=inet4,priorities=103-104\} ACCEPT\"
expect_success "flush chain_set_xdp_0" \
    ${BFCLI} chain flush --name chain_set_xdp_0
expect_success "flush chain_set_xdp_1" \
    ${BFCLI} chain flush --name chain_set_xdp_1
expect_success "flush chain_set_tc_0" \
    ${BFCLI} chain flush --name chain_set_tc_0
expect_success "flush chain_set_tc_2" \
    ${BFCLI} chain flush --name chain_set_tc_2
expect_failure "ensure removed chain can't be fetched" \
    ${BFCLI} chain get --name chain_set_tc_2

log "[SUITE] chain load"
# No chain found
expect_failure "no chain defined in --from-str" \
    ${BFCLI} chain load --from-str \"\"
# Single chain found
expect_failure "single chain defined in --from-str, invalid --name" \
    ${BFCLI} chain load --name invalid_name --from-str \"chain chain_load_xdp_0 BF_HOOK_XDP ACCEPT\"
expect_success "single chain defined in --from-str, no --name" \
    ${BFCLI} chain load --from-str \"chain chain_load_xdp_1 BF_HOOK_XDP ACCEPT\"
expect_success "single chain defined in --from-str, select with valid --name" \
    ${BFCLI} chain load --name chain_load_xdp_2 --from-str \"chain chain_load_xdp_2 BF_HOOK_XDP ACCEPT\"
expect_success "get chain_load_xdp_1" \
    ${BFCLI} chain get --name chain_load_xdp_1
expect_success "get chain_load_xdp_2" \
    ${BFCLI} chain get --name chain_load_xdp_2
expect_success "flush chain_load_xdp_1" \
    ${BFCLI} chain flush --name chain_load_xdp_1
expect_success "flush chain_load_xdp_2" \
    ${BFCLI} chain flush --name chain_load_xdp_2
# Multiple chains found
expect_failure "multiple chains defined in --from-str, no --name" \
    ${BFCLI} chain load --from-str \"chain chain_load_tc_0 BF_HOOK_TC_INGRESS ACCEPT chain chain_load_tc_1 BF_HOOK_TC_INGRESS ACCEPT\"
expect_failure "multiple chains defined in --from-str, invalid --name" \
    ${BFCLI} chain load --name invalid --from-str \"chain chain_load_tc_2 BF_HOOK_TC_INGRESS ACCEPT chain chain_load_tc_3 BF_HOOK_TC_INGRESS ACCEPT\"
expect_success "multiple chains defined in --from-str, valid --name" \
    ${BFCLI} chain load --name chain_load_tc_4 --from-str \"chain chain_load_tc_4 BF_HOOK_TC_INGRESS ACCEPT chain chain_load_tc_5 BF_HOOK_TC_INGRESS ACCEPT\"
expect_success "get chain_load_tc_4" \
    ${BFCLI} chain get --name chain_load_tc_4
expect_success "flush chain_load_tc_4" \
    ${BFCLI} chain flush --name chain_load_tc_4

log "[SUITE] chain attach"
# Failures
expect_success "load an XDP chain" \
    ${BFCLI} chain load --from-str \"chain chain_attach_0 BF_HOOK_XDP ACCEPT\"
expect_failure "fail to attach with unsupported options" \
    ${BFCLI} chain attach --name chain_attach_0 --option family=inet4 --option priorities=101-102
expect_success "ensure hasn't been unloaded" \
    ${BFCLI} chain get --name chain_attach_0
expect_success "flush the chain" \
    ${BFCLI} chain flush --name chain_attach_0
# XDP
expect_success "pings from host to netns are accepted" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "load chain_attach_xdp_0" \
    ${BFCLI} chain load --from-str \"chain chain_attach_xdp_0 BF_HOOK_XDP ACCEPT rule ip4.proto icmp counter DROP\"
expect_success "load chain_attach_xdp_1" \
    ${BFCLI} chain load --from-str \"chain chain_attach_xdp_1 BF_HOOK_XDP ACCEPT\"
expect_success "attach chain_attach_xdp_0" \
    ${BFCLI} chain attach --name chain_attach_xdp_0 --option ifindex=${HOST_IFINDEX}
expect_failure "fails to attach chain_attach_xdp_1" \
    ${BFCLI} chain attach --name chain_attach_xdp_1 --option ifindex=${HOST_IFINDEX}
expect_failure "pings from host to netns are blocked by XDP chain" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "flush chain_attach_xdp_0" \
    ${BFCLI} chain flush --name chain_attach_xdp_0
expect_success "flush chain_attach_xdp_1" \
    ${BFCLI} chain flush --name chain_attach_xdp_1
# TC
expect_success "pings from host to netns are accepted" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "load chain_attach_tc_0" \
    ${BFCLI} chain load --from-str \"chain chain_attach_tc_0 BF_HOOK_TC_EGRESS ACCEPT rule ip4.proto icmp counter DROP\"
expect_success "load chain_attach_tc_1" \
    ${BFCLI} chain load --from-str \"chain chain_attach_tc_1 BF_HOOK_TC_EGRESS ACCEPT\"
expect_success "attach chain_attach_tc_0" \
    ${BFCLI} chain attach --name chain_attach_tc_0 --option ifindex=${HOST_IFINDEX}
expect_success "attach chain_attach_tc_1" \
    ${BFCLI} chain attach --name chain_attach_tc_1 --option ifindex=${HOST_IFINDEX}
expect_failure "pings from host to netns are blocked by TC chain" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "flush chain_attach_tc_0" \
    ${BFCLI} chain flush --name chain_attach_tc_0
expect_success "flush chain_attach_tc_1" \
    ${BFCLI} chain flush --name chain_attach_tc_1
# cgroup
expect_success "pings from host to netns are accepted" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "load chain_attach_cgroup_0" \
    ${BFCLI} chain load --from-str \"chain chain_attach_cgroup_0 BF_HOOK_CGROUP_INGRESS ACCEPT\"
expect_success "load chain_attach_cgroup_1" \
    ${BFCLI} chain load --from-str \"chain chain_attach_cgroup_1 BF_HOOK_CGROUP_INGRESS ACCEPT rule ip4.proto icmp counter DROP\"
expect_success "attach chain_attach_cgroup_0" \
    ${BFCLI} chain attach --name chain_attach_cgroup_0 --option cgpath=/sys/fs/cgroup
expect_success "fail to attach chain_attach_cgroup_1" \
    ${BFCLI} chain attach --name chain_attach_cgroup_1 --option cgpath=/sys/fs/cgroup
expect_failure "pings from host to netns are blocked by cgroup chain" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "flush chain_attach_cgroup_0" \
    ${BFCLI} chain flush --name chain_attach_cgroup_0
expect_success "flush chain_attach_cgroup_1" \
    ${BFCLI} chain flush --name chain_attach_cgroup_1
# Netfilter
expect_success "pings from host to netns are accepted" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "load chain_attach_nf_0" \
    ${BFCLI} chain load --from-str \"chain chain_attach_nf_0 BF_HOOK_NF_LOCAL_IN ACCEPT rule ip4.proto icmp counter DROP\"
expect_success "load chain_attach_nf_1" \
    ${BFCLI} chain load --from-str \"chain chain_attach_nf_1 BF_HOOK_NF_LOCAL_IN ACCEPT\"
expect_success "attach chain_attach_nf_0" \
    ${BFCLI} chain attach --name chain_attach_nf_0 --option family=inet4 --option priorities=101-102
expect_failure "fail to attach chain_attach_nf_1" \
    ${BFCLI} chain attach --name chain_attach_nf_1 --option family=inet4 --option priorities=101-102
expect_failure "pings from host to netns are blocked by Netfilter chain" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "flush chain_attach_nf_0" \
    ${BFCLI} chain flush --name chain_attach_nf_0
expect_success "flush chain_attach_nf_1" \
    ${BFCLI} chain flush --name chain_attach_nf_1

log "[SUITE] chain update"
# Failures
expect_failure "no chain defined in --from-str" \
    ${BFCLI} chain update --from-str \"\"
expect_failure "invalid --name" \
    ${BFCLI} chain update --name invalid_name --from-str \"chain chain_load_xdp_0 BF_HOOK_XDP ACCEPT\"
expect_failure "--name does not refer to an existing chain" \
    ${BFCLI} chain update --name chain_load_xdp_1 --from-str \"chain chain_load_xdp_1 BF_HOOK_XDP ACCEPT\"
expect_success "single chain defined in --from-str, do not attach" \
    ${BFCLI} chain set --from-str \"chain chain_load_xdp_2 BF_HOOK_XDP ACCEPT\"
expect_success "chain to update is not attached" \
    ${BFCLI} chain update --from-str \"chain chain_load_xdp_2 BF_HOOK_XDP ACCEPT\"
# Chain exist and is attached
expect_success "define chain to update" \
    ${BFCLI} chain set --from-str \"chain chain_load_xdp_3 BF_HOOK_XDP\{ifindex=${HOST_IFINDEX}\} ACCEPT\"
expect_success "pings from host to netns are accepted" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "update chain, new chain has no hook options" \
    ${BFCLI} chain update --from-str \"chain chain_load_xdp_3 BF_HOOK_XDP ACCEPT rule ip4.proto icmp counter DROP\"
expect_failure "pings from host to netns are blocked" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "update chain, new chain has hook options (which are ignored)" \
    ${BFCLI} chain update --name chain_load_xdp_3 --from-str \"chain chain_load_xdp_3 BF_HOOK_XDP\{ifindex=${HOST_IFINDEX}\} ACCEPT\"
expect_success "pings from host to netns are accepted" \
    ping -c 1 -W 0.25 ${NS_IP_ADDR}
expect_success "flush chain_load_xdp_3" \
    ${BFCLI} chain flush --name chain_load_xdp_3


################################################################################
#
# Cleanup
#
################################################################################

kill $BPFILTER_PID
exit 0
