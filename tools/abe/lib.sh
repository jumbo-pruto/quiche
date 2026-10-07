# Shared helpers for the ABE/ECN network-namespace lab harness
# (tools/abe/netns.sh, run.sh, matrix.sh). Sourced, not executed.
#
# See plan.md sections 10-11 for the topology and run-matrix this
# harness implements.

set -euo pipefail

ABE_STATE_DIR="${ABE_STATE_DIR:-/run/abe-lab}"
ABE_MANIFEST="$ABE_STATE_DIR/namespaces.manifest"

abe_log() {
    printf '[abe] %s\n' "$*" >&2
}

abe_die() {
    printf '[abe] ERROR: %s\n' "$*" >&2
    exit 1
}

abe_require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        abe_die "must be run as root (netns/tc/ethtool require CAP_NET_ADMIN)"
    fi
}

abe_require_cmd() {
    local cmd
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || abe_die "required command not found: $cmd"
    done
}

abe_state_init() {
    mkdir -p "$ABE_STATE_DIR"
}

# True if `netns.sh up` has run and has not been torn down. This is the
# single source of truth for which namespaces this tool owns; `down`
# only ever removes what is listed here.
abe_topology_is_up() {
    [ -f "$ABE_MANIFEST" ]
}
