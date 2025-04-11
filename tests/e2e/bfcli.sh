#!/bin/bash
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

log() {
    local ORANGE='\033[1;33m'
    local RESET='\033[0m'
    echo -e "${ORANGE}[.]${RESET} $1"
}

success() {
    local GREEN='\033[1;32m'
    local RESET='\033[0m'
    echo -e "${GREEN}[+]${RESET} -> Success" >&2
}

failure() {
    local RED='\033[1;31m'
    local RESET='\033[0m'
    echo -e "${RED}[-]${RESET} -> Failure" >&2
    exit 1
}

# Function to cleanup on exit or error
cleanup() {
    log "Cleanup"

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
# Configure the network namespace
#
################################################################################

ip netns add ${NAMESPACE}
ip link add ${VETH_HOST} type veth peer name ${VETH_NS}

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

log "[TEST] Validate initial connectivity"
ip netns exec ${NAMESPACE} ping -c 1 ${HOST_IP_ADDR} > /dev/null 2>&1 && success || failure


################################################################################
#
# Start bpfilter
#
################################################################################

log "Starting bpfilter in background..."
BPFILTER_OUTPUT_FILE=$(mktemp)
bpfilter --transient --verbose debug --verbose bpf > "$BPFILTER_OUTPUT_FILE" 2>&1 &
BPFILTER_PID=$!

# Wait for bpfilter to initialize
sleep 0.25


################################################################################
#
# Run tests
#
################################################################################

log "[TEST] Set ruleset to block ping to netns, do not attach"
bfcli ruleset set --str "chain xdp BF_HOOK_XDP ACCEPT rule ip4.proto icmp counter DROP" && success || failure

log "[TEST] Can ping netns iface from host"
ping -c 1 -I ${VETH_HOST} -W 0.25 ${NS_IP_ADDR} > /dev/null 2>&1 && success || failure
bpftool --json map dump name ${COUNTERS_MAP_NAME} | jq --exit-status '.[0].formatted.value.packets == 0' > /dev/null 2>&1 && success || failure
bpftool --json map dump name ${COUNTERS_MAP_NAME} | jq --exit-status '.[1].formatted.value.packets == 0' > /dev/null 2>&1 && success || failure

log "[TEST] Set ruleset to block ping to netns, attach"
bfcli ruleset set --str "chain xdp BF_HOOK_XDP{ifindex=${HOST_IFINDEX}} ACCEPT rule ip4.proto icmp counter DROP" && success || failure

log "[TEST] Can't ping netns iface from host"
! ping -c 1 -W 0.25 ${NS_IP_ADDR} > /dev/null 2>&1 && success || failure
bpftool --json map dump name ${COUNTERS_MAP_NAME} | jq --exit-status '.[0].formatted.value.packets == 1' > /dev/null 2>&1 && success || failure

log "Flushing the ruleset"
bfcli ruleset flush && success || failure

log "[TEST] Load chain to drop pings, do not attach"
bfcli chain load --chain "chain xdp BF_HOOK_XDP ACCEPT rule ip4.proto icmp counter DROP" && success || failure

log "[TEST] Can't load chain with existing name"
! bfcli chain load --chain "chain xdp BF_HOOK_XDP ACCEPT rule ip4.proto icmp counter DROP" && success || failure

log "[TEST] Load chain with existing name and --update"
bfcli chain load --update --chain "chain xdp BF_HOOK_XDP ACCEPT rule ip4.proto icmp counter DROP" && success || failure

log "[TEST] Load chain with new name and --update"
bfcli chain load --update --chain "chain another_xdp BF_HOOK_XDP ACCEPT rule ip4.proto icmp counter DROP" && success || failure

log "[TEST] Can ping netns iface from host (check for counter map for both chains)"
ping -c 1 -W 0.25 ${NS_IP_ADDR} > /dev/null 2>&1 && success || failure
bpftool --json map dump name ${COUNTERS_MAP_NAME} | jq --exit-status '.[0].elements.[0].formatted.value.packets == 0' > /dev/null 2>&1 && success || failure
bpftool --json map dump name ${COUNTERS_MAP_NAME} | jq --exit-status '.[1].elements.[0].formatted.value.packets == 0' > /dev/null 2>&1 && success || failure

log "Flushing the ruleset"
bfcli ruleset flush && success || failure

log "[TEST] Load a new XDP chain"
bfcli chain load --update --chain "chain xdp BF_HOOK_XDP ACCEPT rule ip4.proto icmp counter DROP" && success || failure

log "[TEST] Can ping netns iface from host "
ping -c 1 -W 0.25 ${NS_IP_ADDR} > /dev/null 2>&1 && success || failure
bpftool --json map dump name ${COUNTERS_MAP_NAME} | jq --exit-status '.[0].formatted.value.packets == 0' > /dev/null 2>&1 && success || failure

log "[TEST] Failed to attach XDP chain, wrong ifindex"
! bfcli chain attach --name xdp --option ifindex=9999 && success || failure

log "[TEST] Can ping netns iface from host "
ping -c 1 -W 0.25 ${NS_IP_ADDR} > /dev/null 2>&1 && success || failure
bpftool --json map dump name ${COUNTERS_MAP_NAME} | jq --exit-status '.[0].formatted.value.packets == 0' > /dev/null 2>&1 && success || failure

log "[TEST] Attach XDP chain"
bfcli chain attach --name xdp --option ifindex=${HOST_IFINDEX} && success || failure

log "[TEST] Can't ping netns iface from host "
! ping -c 1 -W 0.25 ${NS_IP_ADDR} > /dev/null 2>&1 && success || failure
bpftool --json map dump name ${COUNTERS_MAP_NAME} | jq --exit-status '.[0].formatted.value.packets == 1' > /dev/null 2>&1 && success || failure

log "[TEST] Load a new TC chain and attach it"
bfcli chain load --update --chain "chain tc BF_HOOK_TC_INGRESS ACCEPT rule ip4.proto icmp counter DROP" && success || failure
bfcli chain attach --name tc --option ifindex=${HOST_IFINDEX} && success || failure

log "[TEST] Load a new cgroup chain and attach it"
bfcli chain load --update --chain "chain cgroup BF_HOOK_CGROUP_INGRESS ACCEPT rule ip4.proto icmp counter DROP" && success || failure
bfcli chain attach --name cgroup --option cgpath=/sys/fs/cgroup/user.slice && success || failure

log "[TEST] Load a new Netfilter (INPUT) chain and attach it"
bpftool net
bfcli chain load --update --chain "chain netfilter BF_HOOK_NF_LOCAL_IN ACCEPT rule ip4.proto icmp counter DROP" && success || failure
bfcli chain attach --name netfilter --option family=inet4 --option priorities=100-101 && success || failure


################################################################################
#
# Cleanup
#
################################################################################

kill $BPFILTER_PID
exit 0
