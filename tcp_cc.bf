# Use the reno TCP congestion control algorithm for every TCP connection to
# 1.1.1.1, from any process on the host. Other connections keep the default
# algorithm.
#
# BPF programs can't load the kernel module implementing an algorithm, so it
# must be available beforehand (see net.ipv4.tcp_available_congestion_control).
# reno is always built in the kernel.
chain tcp_cc BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4{cgpath=/sys/fs/cgroup} ACCEPT
    rule
        ip4.daddr eq 1.1.1.1
        meta.l4_proto eq tcp
        setsockopt tcp_congestion reno
        counter
        ACCEPT
