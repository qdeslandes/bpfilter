#!/usr/bin/env bash

. "$(dirname "$0")"/../e2e_test_util.sh

make_sandbox
start_bpfilter

# XDP: CONTINUE policy is not supported, codegen should fail.
(! ${FROM_NS} bfcli chain set --from-str "chain xdp_cont BF_HOOK_XDP{ifindex=${NS_IFINDEX}} CONTINUE rule ip4.proto icmp counter DROP")

# TC: CONTINUE policy defers to the next TC program (returns TCX_NEXT).
# With only the CONTINUE chain, ping should work.
${FROM_NS} bfcli chain set --from-str "chain tc1 BF_HOOK_TC_INGRESS{ifindex=${NS_IFINDEX}} CONTINUE rule ip4.proto icmp counter CONTINUE"
ping -c 1 -W 0.1 ${NS_IP_ADDR}
[ "$(read_counter --chain tc1 --rule-id 0)" -gt 0 ]

# Adding a second chain that drops ICMP: ping should fail.
${FROM_NS} bfcli chain set --from-str "chain tc2 BF_HOOK_TC_INGRESS{ifindex=${NS_IFINDEX}} ACCEPT rule ip4.proto icmp counter DROP"
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
[ "$(read_counter --chain tc2 --rule-id 0)" -gt 0 ]

# Adding a third chain: TC should not see traffic on it (tc2 already dropped).
${FROM_NS} bfcli chain set --from-str "chain tc3 BF_HOOK_TC_INGRESS{ifindex=${NS_IFINDEX}} ACCEPT rule ip4.proto icmp counter DROP"
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
[ "$(read_counter --chain tc3 --rule-id 0)" -eq 0 ]

${FROM_NS} bfcli chain flush --name tc1
${FROM_NS} bfcli chain flush --name tc2
${FROM_NS} bfcli chain flush --name tc3

# Cgroup: CONTINUE policy is equivalent to ACCEPT, all programs run.
ping -c 1 -W 0.1 ${NS_IP_ADDR}
${FROM_NS} bfcli chain set --from-str "chain cg1 BF_HOOK_CGROUP_INGRESS{cgpath=/sys/fs/cgroup} CONTINUE rule ip4.proto icmp counter CONTINUE"
ping -c 1 -W 0.1 ${NS_IP_ADDR}
[ "$(read_counter --chain cg1 --rule-id 0)" -gt 0 ]

${FROM_NS} bfcli chain set --from-str "chain cg2 BF_HOOK_CGROUP_INGRESS{cgpath=/sys/fs/cgroup} ACCEPT rule ip4.proto icmp counter DROP"
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
[ "$(read_counter --chain cg2 --rule-id 0)" -gt 0 ]

# Third cgroup chain: all programs run, so cg3 should see traffic.
${FROM_NS} bfcli chain set --from-str "chain cg3 BF_HOOK_CGROUP_INGRESS{cgpath=/sys/fs/cgroup} ACCEPT rule ip4.proto icmp counter DROP"
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
[ "$(read_counter --chain cg3 --rule-id 0)" -gt 0 ]

${FROM_NS} bfcli chain flush --name cg1
${FROM_NS} bfcli chain flush --name cg2
${FROM_NS} bfcli chain flush --name cg3

# Netfilter: CONTINUE policy is equivalent to ACCEPT.
# NF_DROP from one hook stops subsequent hooks (same as TC).
ping -c 1 -W 0.1 ${NS_IP_ADDR}
${FROM_NS} bfcli chain set --from-str "chain nf1 BF_HOOK_NF_LOCAL_IN{priorities=101-102} CONTINUE rule ip4.proto icmp counter CONTINUE"
ping -c 1 -W 0.1 ${NS_IP_ADDR}
[ "$(read_counter --chain nf1 --rule-id 0)" -gt 0 ]

${FROM_NS} bfcli chain set --from-str "chain nf2 BF_HOOK_NF_LOCAL_IN{priorities=103-104} ACCEPT rule ip4.proto icmp counter DROP"
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
[ "$(read_counter --chain nf2 --rule-id 0)" -gt 0 ]

# Third NF chain: nf2 drops, so nf3 should not see traffic.
${FROM_NS} bfcli chain set --from-str "chain nf3 BF_HOOK_NF_LOCAL_IN{priorities=105-106} ACCEPT rule ip4.proto icmp counter DROP"
(! ping -c 1 -W 0.1 ${NS_IP_ADDR})
[ "$(read_counter --chain nf3 --rule-id 0)" -eq 0 ]

${FROM_NS} bfcli chain flush --name nf1
${FROM_NS} bfcli chain flush --name nf2
${FROM_NS} bfcli chain flush --name nf3
