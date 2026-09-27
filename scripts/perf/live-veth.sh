#!/usr/bin/env bash
set -euo pipefail

TX_IFACE="${NETSCOPE_VETH_TX:-veth-ns-tx}"
RX_IFACE="${NETSCOPE_VETH_RX:-veth-ns-rx}"

usage() {
  cat <<'EOF'
Usage:
  sudo scripts/perf/live-veth.sh up
  sudo scripts/perf/live-veth.sh status
  sudo scripts/perf/live-veth.sh down

Creates only a named Linux veth pair. No IP addresses or routes are added.
Override names with NETSCOPE_VETH_TX and NETSCOPE_VETH_RX.
EOF
}

valid_name() {
  [[ "$1" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]]
}

verified_pair() {
  local tx_details rx_details tx_index tx_peer_index rx_index rx_peer_index
  tx_details="$(ip -d -o link show dev "$TX_IFACE" 2>/dev/null)" || return 1
  rx_details="$(ip -d -o link show dev "$RX_IFACE" 2>/dev/null)" || return 1
  [[ "$tx_details" == *"veth"* && "$rx_details" == *"veth"* ]] || return 1
  tx_index="$(cat "/sys/class/net/$TX_IFACE/ifindex" 2>/dev/null)" || return 1
  tx_peer_index="$(cat "/sys/class/net/$TX_IFACE/iflink" 2>/dev/null)" || return 1
  rx_index="$(cat "/sys/class/net/$RX_IFACE/ifindex" 2>/dev/null)" || return 1
  rx_peer_index="$(cat "/sys/class/net/$RX_IFACE/iflink" 2>/dev/null)" || return 1
  [[ "$tx_peer_index" == "$rx_index" && "$rx_peer_index" == "$tx_index" ]]
}

if [[ $# -ne 1 ]]; then
  usage >&2
  exit 2
fi

ACTION="$1"
if ! valid_name "$TX_IFACE" || ! valid_name "$RX_IFACE" \
  || [[ "$TX_IFACE" == "$RX_IFACE" || "$TX_IFACE" == "." || "$TX_IFACE" == ".." || "$RX_IFACE" == "." || "$RX_IFACE" == ".." ]]; then
  echo "error: interface names must be distinct Linux names of at most 15 safe characters" >&2
  exit 2
fi

if ! command -v ip >/dev/null 2>&1; then
  echo "error: iproute2's ip command is required" >&2
  exit 1
fi

case "$ACTION" in
  up)
    if ip link show dev "$TX_IFACE" >/dev/null 2>&1 || ip link show dev "$RX_IFACE" >/dev/null 2>&1; then
      echo "error: refusing to replace an existing interface named $TX_IFACE or $RX_IFACE" >&2
      exit 1
    fi
    created=0
    cleanup_failed_setup() {
      if [[ "$created" -eq 1 ]] && verified_pair; then
        ip link del dev "$RX_IFACE" >/dev/null 2>&1 || true
      fi
    }
    trap cleanup_failed_setup ERR
    ip link add dev "$TX_IFACE" type veth peer name "$RX_IFACE"
    created=1
    ip link set dev "$RX_IFACE" address 02:00:00:00:00:01
    ip link set dev "$TX_IFACE" address 02:00:00:00:00:02
    ip link set dev "$TX_IFACE" up
    ip link set dev "$RX_IFACE" up
    trap - ERR
    echo "Created isolated veth pair: sender=$TX_IFACE receiver=$RX_IFACE"
    ip -s link show dev "$TX_IFACE"
    ip -s link show dev "$RX_IFACE"
    ;;
  status)
    ip -s link show dev "$TX_IFACE"
    ip -s link show dev "$RX_IFACE"
    ;;
  down)
    if ! ip link show dev "$RX_IFACE" >/dev/null 2>&1; then
      if ip link show dev "$TX_IFACE" >/dev/null 2>&1; then
        echo "error: sender $TX_IFACE exists without receiver $RX_IFACE; refusing cleanup" >&2
        exit 1
      fi
      echo "No receiver interface named $RX_IFACE exists."
      exit 0
    fi
    if ! verified_pair; then
      echo "error: refusing to delete $RX_IFACE because $TX_IFACE and $RX_IFACE are not verified veth peers" >&2
      exit 1
    fi
    ip link del dev "$RX_IFACE"
    echo "Removed veth pair: sender=$TX_IFACE receiver=$RX_IFACE"
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
