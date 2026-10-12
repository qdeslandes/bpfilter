#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

. "$(dirname "$0")"/../e2e_test_util.sh

# Only connect hooks can set the TCP congestion control algorithm
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.dport eq 9990 setsockopt tcp_congestion reno ACCEPT"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6 ACCEPT rule meta.dport eq 9990 setsockopt tcp_congestion reno ACCEPT"
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG4 ACCEPT rule meta.dport eq 9990 setsockopt tcp_congestion reno ACCEPT")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_SENDMSG6 ACCEPT rule meta.dport eq 9990 setsockopt tcp_congestion reno ACCEPT")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_XDP ACCEPT rule ip4.proto tcp setsockopt tcp_congestion reno ACCEPT")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_TC_EGRESS ACCEPT rule ip4.proto tcp setsockopt tcp_congestion reno ACCEPT")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_NF_LOCAL_OUT ACCEPT rule ip4.proto tcp setsockopt tcp_congestion reno ACCEPT")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SKB_EGRESS ACCEPT rule ip4.proto tcp setsockopt tcp_congestion reno ACCEPT")

# Algorithm names are 1 to 15 characters long, BPF-defined algorithms can contain dots
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.l4_proto eq tcp setsockopt tcp_congestion 0123456789abcde ACCEPT"
${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.l4_proto eq tcp setsockopt tcp_congestion bpf.cubic ACCEPT"
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.l4_proto eq tcp setsockopt tcp_congestion 0123456789abcdef ACCEPT")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.l4_proto eq tcp setsockopt tcp_congestion ACCEPT")

# Unsupported or missing socket option, duplicated action
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.l4_proto eq tcp setsockopt so_mark 1 ACCEPT")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.l4_proto eq tcp setsockopt ACCEPT")
(! ${BFCLI} ruleset set --dry-run --from-str "chain test BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4 ACCEPT rule meta.l4_proto eq tcp setsockopt tcp_congestion reno setsockopt tcp_congestion cubic ACCEPT")

make_sandbox

NS_IP6_ADDR="fd00::2"
ip netns exec ${NETNS_NAME} ip addr add ${NS_IP6_ADDR}/64 dev ${VETH_NS} nodad

CGROUP_PATH=/sys/fs/cgroup/bftest_${_TEST_NAME}
mkdir -p ${CGROUP_PATH}
trap 'ret=$?; rmdir ${CGROUP_PATH} 2>/dev/null; cleanup; exit ${ret}' EXIT

# reno is always built in: make sure it isn't the namespace's default algorithm,
# so a socket using it was modified by bpfilter.
${FROM_NS} sysctl -qw net.ipv4.tcp_congestion_control=cubic

# Connect to a server listening on $1:$2 from the test cgroup, then print the
# TCP congestion control algorithm used by the client socket.
tcp_congestion() {
    ${FROM_NS} python3 -c "
import os, socket
with open('${CGROUP_PATH}/cgroup.procs', 'w') as f:
    f.write(str(os.getpid()))
family = socket.AF_INET6 if ':' in '$1' else socket.AF_INET
server = socket.socket(family, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('$1', $2))
server.listen()
client = socket.socket(family, socket.SOCK_STREAM)
client.settimeout(1)
client.connect(('$1', $2))
print(client.getsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, 16).rstrip(b'\0').decode())
"
}

udp4_connect() {
    ${FROM_NS} bash -c "echo \$\$ > ${CGROUP_PATH}/cgroup.procs && echo > /dev/udp/$1/$2" 2>/dev/null
}

# IPv4: only matching connections use the algorithm
${FROM_NS} ${BFCLI} chain set --from-str "chain c4 BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} ACCEPT rule meta.dport eq 9990 setsockopt tcp_congestion reno counter ACCEPT"
test "$(tcp_congestion ${NS_IP_ADDR} 9990)" = "reno"
test "$(tcp_congestion ${NS_IP_ADDR} 9991)" = "cubic"
test "$(get_counter c4 0)" = "1"
${FROM_NS} ${BFCLI} chain get --name c4 | grep -q "setsockopt tcp_congestion reno"

# IPv6: only matching connections use the algorithm
${FROM_NS} ${BFCLI} chain set --from-str "chain c6 BF_HOOK_CGROUP_SOCK_ADDR_CONNECT6{cgpath=${CGROUP_PATH}} ACCEPT rule meta.dport eq 9990 setsockopt tcp_congestion reno counter ACCEPT"
test "$(tcp_congestion ${NS_IP6_ADDR} 9990)" = "reno"
test "$(tcp_congestion ${NS_IP6_ADDR} 9991)" = "cubic"
test "$(get_counter c6 0)" = "1"
${FROM_NS} ${BFCLI} chain flush --name c6

# Unavailable algorithm and non-TCP socket: the socket is left unchanged, and
# the rule's verdict still applies
${FROM_NS} ${BFCLI} chain set --from-str "chain c4 BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=${CGROUP_PATH}} DROP rule meta.dport eq 9990 setsockopt tcp_congestion bf_missing counter ACCEPT"
test "$(tcp_congestion ${NS_IP_ADDR} 9990)" = "cubic"
udp4_connect ${NS_IP_ADDR} 9990
(! udp4_connect ${NS_IP_ADDR} 9991)
test "$(get_counter c4 0)" = "2"
