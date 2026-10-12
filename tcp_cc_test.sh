#!/usr/bin/env bash
#
# Attach tcp_cc.bf to the root cgroup, then open a TCP connection to 8.8.8.8
# and to 1.1.1.1, and print the congestion control algorithm each one uses:
# 8.8.8.8 should use the default algorithm, 1.1.1.1 the one set by the chain.
#
# ICMP has no congestion control: a TCP connection to port 443 is used as the
# ping. The chain is removed when the script exits.
#
# Usage: sudo ./tcp_cc_test.sh
#        sudo BFCLI=/path/to/bfcli ./tcp_cc_test.sh

set -euo pipefail

SCRIPT_DIR=$(dirname "$(realpath "$0")")
BFCLI=${BFCLI:-${SCRIPT_DIR}/build/output/sbin/bfcli}
CHAIN_FILE=${SCRIPT_DIR}/tcp_cc.bf
CHAIN_NAME=tcp_cc

if [[ ${EUID} -ne 0 ]]; then
    echo "error: must be run as root" >&2
    exit 1
fi

DEFAULT_CCA=$(sysctl -n net.ipv4.tcp_congestion_control)
CHAIN_CCA=$(awk '$1 == "setsockopt" && $2 == "tcp_congestion" { print $3 }' "${CHAIN_FILE}")

if [[ ${CHAIN_CCA} == "${DEFAULT_CCA}" ]]; then
    echo "error: ${CHAIN_CCA} is already the default algorithm" >&2
    exit 1
fi

# BPF programs can't load the module implementing an algorithm.
if ! grep -qwF "${CHAIN_CCA}" /proc/sys/net/ipv4/tcp_available_congestion_control; then
    echo "error: ${CHAIN_CCA} is not available, load it with 'modprobe tcp_${CHAIN_CCA}'" >&2
    exit 1
fi

# Connect to $1 on port 443, print the congestion control algorithm of the socket.
tcp_cca() {
    python3 - "$1" <<'EOF'
import socket
import sys

try:
    sock = socket.create_connection((sys.argv[1], 443), timeout=5)
except OSError as e:
    sys.exit(f"error: can't connect to {sys.argv[1]}:443: {e}")

with sock:
    cca = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, 16)
    print(cca.rstrip(b"\0").decode())
EOF
}

"${BFCLI}" chain set --from-file "${CHAIN_FILE}"

# The chain applies to every process on the host: remove it on exit.
trap '"${BFCLI}" chain flush --name "${CHAIN_NAME}"' EXIT
trap 'exit 1' INT TERM

echo "Chain ${CHAIN_NAME} attached to /sys/fs/cgroup"
echo "Default algorithm: ${DEFAULT_CCA}"

CCA_8888=$(tcp_cca 8.8.8.8)
echo "8.8.8.8: ${CCA_8888}"

CCA_1111=$(tcp_cca 1.1.1.1)
echo "1.1.1.1: ${CCA_1111}"

if [[ ${CCA_8888} != "${DEFAULT_CCA}" || ${CCA_1111} != "${CHAIN_CCA}" ]]; then
    echo "FAIL: expected ${DEFAULT_CCA} for 8.8.8.8 and ${CHAIN_CCA} for 1.1.1.1" >&2
    exit 1
fi

echo "PASS"
