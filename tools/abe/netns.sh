#!/bin/bash
# tools/abe/netns.sh
#
# Builds/tears down the six-namespace ABE/ECN dumbbell lab topology
# described in plan.md section 10:
#
#   abe-s1, abe-s2 --- abe-r1 === (HTB+CoDel bottleneck) === abe-r2 --- abe-c1, abe-c2
#
# Every destructive operation is scoped to namespaces this script itself
# creates and records in $ABE_STATE_DIR/namespaces.manifest; `down` only
# ever removes resources listed there. This never touches the host's
# production network, other namespaces, or global qdisc/firewall state.
#
# Requires root (CAP_NET_ADMIN) and a kernel with netns, veth, sch_htb,
# sch_codel, sch_netem and sch_fq support. On WSL2 this is only useful
# for a quick functional trial (plan.md section 2); final measurements
# must run on a physical Linux host.
#
# Usage:
#   sudo tools/abe/netns.sh up
#   sudo tools/abe/netns.sh status
#   sudo tools/abe/netns.sh verify
#   sudo tools/abe/netns.sh set-queue [--mode ecn|noecn] [--target 5ms]
#                                     [--interval 100ms] [--limit 1000]
#                                     [--rate 10mbit]
#   sudo tools/abe/netns.sh set-rtt --ms 40
#   sudo tools/abe/netns.sh strip-ecn <on|off>
#   sudo tools/abe/netns.sh down

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "$HERE/lib.sh"

NAMESPACES=(abe-s1 abe-s2 abe-r1 abe-r2 abe-c1 abe-c2)

# Bottleneck/RTT defaults from plan.md section 10 items 4-5; changeable
# in place afterwards via `set-queue`/`set-rtt` without a full rebuild.
CODEL_MODE_DEFAULT="noecn"
CODEL_TARGET_DEFAULT="5ms"
CODEL_INTERVAL_DEFAULT="100ms"
CODEL_LIMIT_DEFAULT="1000"
BOTTLENECK_RATE_DEFAULT="10mbit"
RTT_MS_DEFAULT=40

_ABE_VETH_COUNTER=0

usage() {
    cat <<'EOF'
Usage: netns.sh <command> [options]

Commands:
  up                      Create the six-namespace dumbbell topology.
  down                    Tear down only namespaces this tool created.
  status                  Show whether the topology is up.
  verify                  Run connectivity/MTU/RTT sanity checks.
  set-queue [opts]        Reconfigure the forward bottleneck qdisc in place.
      --mode ecn|noecn      CoDel ECN marking mode (default: noecn)
      --target DURATION     CoDel target, e.g. 5ms (default: 5ms)
      --interval DURATION   CoDel interval, e.g. 100ms (default: 100ms)
      --limit PACKETS       CoDel queue limit (default: 1000)
      --rate RATE           HTB rate/ceil, e.g. 10mbit (default: 10mbit)
  set-rtt --ms N          Set unloaded RTT by splitting N/2 across the
                           forward and reverse netem delay qdiscs.
  strip-ecn <on|off>      Zero the IP ECN field on abe-r1/r1-bn ingress
                          (fault-injection arm "F": simulated bleaching).
                          Best-effort; verify with a capture before use.
EOF
}

abe_add_veth() {
    local ns_a="$1" if_a="$2" addr_a="$3" ns_b="$4" if_b="$5" addr_b="$6"
    _ABE_VETH_COUNTER=$((_ABE_VETH_COUNTER + 1))
    local tmp_a="vA${_ABE_VETH_COUNTER}" tmp_b="vB${_ABE_VETH_COUNTER}"

    ip link add "$tmp_a" type veth peer name "$tmp_b"
    ip link set "$tmp_a" netns "$ns_a"
    ip link set "$tmp_b" netns "$ns_b"
    ip -n "$ns_a" link set "$tmp_a" name "$if_a"
    ip -n "$ns_b" link set "$tmp_b" name "$if_b"
    ip -n "$ns_a" addr add "$addr_a" dev "$if_a"
    ip -n "$ns_b" addr add "$addr_b" dev "$if_b"
    ip -n "$ns_a" link set "$if_a" mtu 1500 up
    ip -n "$ns_b" link set "$if_b" mtu 1500 up
}

abe_disable_offloads() {
    local ns="$1" ifc="$2" feature
    for feature in tso gso gro ufo generic-segmentation-offload \
        generic-receive-offload tx-udp-fragmentation \
        tx-udp_tnl-segmentation tx-gso-partial; do
        ip netns exec "$ns" ethtool -K "$ifc" "$feature" off >/dev/null 2>&1 || true
    done
    ip netns exec "$ns" ethtool -k "$ifc" \
        > "$ABE_STATE_DIR/ethtool-${ns}-${ifc}.txt" 2>/dev/null || true
}

abe_apply_bottleneck_qdisc() {
    local rate="$1" target="$2" interval="$3" limit="$4" mode="$5"
    ip netns exec abe-r1 tc qdisc add dev r1-bn root handle 1: htb default 10
    ip netns exec abe-r1 tc class add dev r1-bn parent 1: classid 1:10 \
        rate "$rate" ceil "$rate" burst 16k cburst 16k quantum 1514
    ip netns exec abe-r1 tc qdisc add dev r1-bn parent 1:10 handle 10: codel \
        target "$target" interval "$interval" limit "$limit" "$mode"
}

abe_apply_netem_delay() {
    local ns="$1" ifc="$2" ms="$3"
    ip netns exec "$ns" tc qdisc add dev "$ifc" root netem delay "${ms}ms" limit 10000
}

cmd_up() {
    abe_require_root
    abe_require_cmd ip tc ethtool
    abe_state_init

    if abe_topology_is_up; then
        abe_die "topology already up (manifest: $ABE_MANIFEST). Run 'down' first."
    fi

    local ns
    for ns in "${NAMESPACES[@]}"; do
        if ip netns list | awk '{print $1}' | grep -qx "$ns"; then
            abe_die "namespace '$ns' already exists and is not owned by this tool; refusing to reuse it"
        fi
    done

    abe_log "creating namespaces: ${NAMESPACES[*]}"
    for ns in "${NAMESPACES[@]}"; do
        ip netns add "$ns"
        ip -n "$ns" link set lo up
    done
    # Record ownership immediately so a failure partway through still
    # leaves an accurate manifest for `down` to clean up.
    printf '%s\n' "${NAMESPACES[@]}" > "$ABE_MANIFEST"

    abe_log "wiring veth links"
    abe_add_veth abe-s1 s1-eth 10.77.1.2/24  abe-r1 r1-s1 10.77.1.1/24
    abe_add_veth abe-s2 s2-eth 10.77.2.2/24  abe-r1 r1-s2 10.77.2.1/24
    abe_add_veth abe-r1 r1-bn 10.77.12.1/30  abe-r2 r2-bn 10.77.12.2/30
    abe_add_veth abe-c1 c1-eth 10.77.3.2/24  abe-r2 r2-c1 10.77.3.1/24
    abe_add_veth abe-c2 c2-eth 10.77.4.2/24  abe-r2 r2-c2 10.77.4.1/24

    abe_log "configuring routes"
    ip -n abe-s1 route add default via 10.77.1.1
    ip -n abe-s2 route add default via 10.77.2.1
    ip -n abe-c1 route add default via 10.77.3.1
    ip -n abe-c2 route add default via 10.77.4.1

    ip netns exec abe-r1 sysctl -qw net.ipv4.ip_forward=1
    ip netns exec abe-r2 sysctl -qw net.ipv4.ip_forward=1

    ip -n abe-r1 route add 10.77.3.0/24 via 10.77.12.2
    ip -n abe-r1 route add 10.77.4.0/24 via 10.77.12.2
    ip -n abe-r2 route add 10.77.1.0/24 via 10.77.12.1
    ip -n abe-r2 route add 10.77.2.0/24 via 10.77.12.1

    abe_log "disabling segmentation offloads on lab veth ends"
    abe_disable_offloads abe-s1 s1-eth
    abe_disable_offloads abe-s2 s2-eth
    abe_disable_offloads abe-r1 r1-s1
    abe_disable_offloads abe-r1 r1-s2
    abe_disable_offloads abe-r1 r1-bn
    abe_disable_offloads abe-r2 r2-bn
    abe_disable_offloads abe-r2 r2-c1
    abe_disable_offloads abe-r2 r2-c2
    abe_disable_offloads abe-c1 c1-eth
    abe_disable_offloads abe-c2 c2-eth

    abe_log "installing forward bottleneck (HTB+CoDel) on abe-r1/r1-bn"
    abe_apply_bottleneck_qdisc "$BOTTLENECK_RATE_DEFAULT" "$CODEL_TARGET_DEFAULT" \
        "$CODEL_INTERVAL_DEFAULT" "$CODEL_LIMIT_DEFAULT" "$CODEL_MODE_DEFAULT"

    abe_log "installing uncongested reverse path (HTB+FIFO) on abe-r2/r2-bn"
    ip netns exec abe-r2 tc qdisc add dev r2-bn root handle 1: htb default 10
    ip netns exec abe-r2 tc class add dev r2-bn parent 1: classid 1:10 \
        rate 100mbit ceil 100mbit
    ip netns exec abe-r2 tc qdisc add dev r2-bn parent 1:10 handle 10: bfifo limit 1000000

    abe_log "installing propagation delay (${RTT_MS_DEFAULT}ms unloaded RTT)"
    local half=$((RTT_MS_DEFAULT / 2))
    abe_apply_netem_delay abe-r2 r2-c1 "$half"
    abe_apply_netem_delay abe-r2 r2-c2 "$half"
    abe_apply_netem_delay abe-r1 r1-s1 "$half"
    abe_apply_netem_delay abe-r1 r1-s2 "$half"

    abe_log "installing fq on sender egress for SO_TXTIME pacing"
    ip netns exec abe-s1 tc qdisc add dev s1-eth root fq
    ip netns exec abe-s2 tc qdisc add dev s2-eth root fq

    abe_log "topology up. Run 'sudo $0 verify' to sanity-check it."
}

cmd_down() {
    abe_require_root
    if ! abe_topology_is_up; then
        abe_log "no manifest found at $ABE_MANIFEST; nothing to do"
        return 0
    fi

    abe_log "tearing down namespaces recorded in $ABE_MANIFEST"
    local ns
    while IFS= read -r ns; do
        [ -n "$ns" ] || continue
        if ip netns list | awk '{print $1}' | grep -qx "$ns"; then
            ip netns del "$ns"
            abe_log "removed namespace $ns"
        else
            abe_log "namespace $ns already absent, skipping"
        fi
    done < "$ABE_MANIFEST"

    rm -f "$ABE_MANIFEST"
    abe_log "topology down"
}

cmd_status() {
    if ! abe_topology_is_up; then
        abe_log "topology DOWN (no manifest at $ABE_MANIFEST)"
        return 0
    fi

    abe_log "topology UP. Namespaces:"
    local ns
    while IFS= read -r ns; do
        [ -n "$ns" ] || continue
        if ip netns list | awk '{print $1}' | grep -qx "$ns"; then
            echo "  $ns: present"
        else
            echo "  $ns: MISSING (manifest is stale; run 'down' then 'up')"
        fi
    done < "$ABE_MANIFEST"
}

cmd_verify() {
    abe_topology_is_up || abe_die "topology is not up; run 'up' first"

    abe_log "ping abe-c1 -> abe-s1 (expect ~${RTT_MS_DEFAULT}ms rtt)"
    ip netns exec abe-c1 ping -c 5 -W 2 10.77.1.2

    abe_log "ping abe-s1 -> abe-c1"
    ip netns exec abe-s1 ping -c 5 -W 2 10.77.3.2

    abe_log "route abe-c1 -> 10.77.1.2"
    ip netns exec abe-c1 ip route get 10.77.1.2

    abe_log "route abe-s1 -> 10.77.3.2"
    ip netns exec abe-s1 ip route get 10.77.3.2

    abe_log "MTU probe (1472-byte payload, DF set) abe-c1 -> abe-s1"
    if ! ip netns exec abe-c1 ping -c 3 -M do -s 1472 10.77.1.2; then
        abe_log "MTU probe failed; check MTU 1500 on all veth ends in the path"
    fi

    abe_log "verify complete"
}

cmd_set_queue() {
    abe_require_root
    abe_topology_is_up || abe_die "topology is not up; run 'up' first"

    local mode="$CODEL_MODE_DEFAULT" target="$CODEL_TARGET_DEFAULT" \
        interval="$CODEL_INTERVAL_DEFAULT" limit="$CODEL_LIMIT_DEFAULT" \
        rate="$BOTTLENECK_RATE_DEFAULT"

    while [ $# -gt 0 ]; do
        case "$1" in
            --mode) mode="$2"; shift 2 ;;
            --target) target="$2"; shift 2 ;;
            --interval) interval="$2"; shift 2 ;;
            --limit) limit="$2"; shift 2 ;;
            --rate) rate="$2"; shift 2 ;;
            *) abe_die "unknown set-queue option: $1" ;;
        esac
    done

    case "$mode" in
        ecn|noecn) ;;
        *) abe_die "--mode must be 'ecn' or 'noecn'" ;;
    esac

    ip netns exec abe-r1 tc qdisc del dev r1-bn root 2>/dev/null || true
    abe_apply_bottleneck_qdisc "$rate" "$target" "$interval" "$limit" "$mode"
    abe_log "bottleneck reconfigured: rate=$rate codel target=$target interval=$interval limit=$limit mode=$mode"
}

cmd_set_rtt() {
    abe_require_root
    abe_topology_is_up || abe_die "topology is not up; run 'up' first"

    local ms="$RTT_MS_DEFAULT"
    while [ $# -gt 0 ]; do
        case "$1" in
            --ms) ms="$2"; shift 2 ;;
            *) abe_die "unknown set-rtt option: $1" ;;
        esac
    done

    local half=$((ms / 2))
    ip netns exec abe-r2 tc qdisc del dev r2-c1 root 2>/dev/null || true
    ip netns exec abe-r2 tc qdisc del dev r2-c2 root 2>/dev/null || true
    ip netns exec abe-r1 tc qdisc del dev r1-s1 root 2>/dev/null || true
    ip netns exec abe-r1 tc qdisc del dev r1-s2 root 2>/dev/null || true

    abe_apply_netem_delay abe-r2 r2-c1 "$half"
    abe_apply_netem_delay abe-r2 r2-c2 "$half"
    abe_apply_netem_delay abe-r1 r1-s1 "$half"
    abe_apply_netem_delay abe-r1 r1-s2 "$half"

    abe_log "unloaded RTT set to ~${ms}ms (${half}ms each direction)"
}

cmd_strip_ecn() {
    abe_require_root
    abe_topology_is_up || abe_die "topology is not up; run 'up' first"

    local state="${1:-}"
    case "$state" in
        on)
            ip netns exec abe-r1 tc qdisc add dev r1-bn ingress 2>/dev/null || true
            ip netns exec abe-r1 tc filter add dev r1-bn parent ffff: protocol ip u32 \
                match u32 0 0 action pedit munge ip tos set 0x00 pipe action ok
            abe_log "ECN bleaching enabled on abe-r1/r1-bn ingress (fault arm F)."
            abe_log "This is best-effort; verify with a capture before trusting results."
            ;;
        off)
            ip netns exec abe-r1 tc filter del dev r1-bn parent ffff: protocol ip u32 2>/dev/null || true
            ip netns exec abe-r1 tc qdisc del dev r1-bn ingress 2>/dev/null || true
            abe_log "ECN bleaching disabled."
            ;;
        *)
            abe_die "usage: $0 strip-ecn <on|off>"
            ;;
    esac
}

main() {
    local cmd="${1:-}"
    [ -n "$cmd" ] || { usage; exit 1; }
    shift || true

    case "$cmd" in
        up) cmd_up "$@" ;;
        down) cmd_down "$@" ;;
        status) cmd_status "$@" ;;
        verify) cmd_verify "$@" ;;
        set-queue) cmd_set_queue "$@" ;;
        set-rtt) cmd_set_rtt "$@" ;;
        strip-ecn) cmd_strip_ecn "$@" ;;
        -h|--help|help) usage ;;
        *) usage; exit 1 ;;
    esac
}

main "$@"
