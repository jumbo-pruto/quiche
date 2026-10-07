#!/bin/bash
# tools/abe/matrix.sh
#
# Runs the repeated arm matrix (plan.md section 11) against an
# already-up topology, in a randomized order (recorded for the record),
# by calling run.sh once per (arm, repetition).
#
# Usage:
#   sudo tools/abe/matrix.sh --arms "L E A AS" --repeats 10 -- --payload-bytes 33554432

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "$HERE/lib.sh"

ARMS="L E A AS"
REPEATS=10
OUT_ROOT="$HERE/results"
EXTRA_ARGS=()

usage() {
    cat <<'EOF'
Usage: matrix.sh [--arms "L E A AS"] [--repeats N] [--out-root DIR] [-- run.sh-args...]

Anything after `--` is forwarded verbatim to every run.sh invocation
(e.g. -- --payload-bytes 33554432 --codel-target 10ms).
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --arms) ARMS="$2"; shift 2 ;;
        --repeats) REPEATS="$2"; shift 2 ;;
        --out-root) OUT_ROOT="$2"; shift 2 ;;
        --) shift; EXTRA_ARGS=("$@"); break ;;
        -h|--help) usage; exit 0 ;;
        *) abe_die "unknown option: $1 (see --help)" ;;
    esac
done

abe_require_root
abe_topology_is_up || abe_die "topology is not up; run 'sudo tools/abe/netns.sh up' first"

mkdir -p "$OUT_ROOT"
SEQUENCE_FILE="$OUT_ROOT/order-$(date -u +%Y%m%dT%H%M%SZ).txt"
: > "$SEQUENCE_FILE"

# Build arm x repetition entries, then Fisher-Yates shuffle them so run
# order doesn't confound arm with time-varying host conditions (plan.md
# section 11 item 8). The actual order is recorded, not just intended.
ORDER=()
for arm in $ARMS; do
    for ((i = 1; i <= REPEATS; i++)); do
        ORDER+=("$arm:$i")
    done
done

n=${#ORDER[@]}
for ((i = n - 1; i > 0; i--)); do
    j=$((RANDOM % (i + 1)))
    tmp="${ORDER[i]}"
    ORDER[i]="${ORDER[j]}"
    ORDER[j]="$tmp"
done

abe_log "running ${#ORDER[@]} total runs (arms: $ARMS, repeats: $REPEATS)"

for entry in "${ORDER[@]}"; do
    arm="${entry%%:*}"
    rep="${entry##*:}"
    run_id="${arm}-rep${rep}-$(date -u +%Y%m%dT%H%M%SZ)"
    echo "$run_id" >> "$SEQUENCE_FILE"

    abe_log "=== running $run_id ==="
    "$HERE/run.sh" --mode "$arm" --run-id "$run_id" --out-dir "$OUT_ROOT/$run_id" \
        "${EXTRA_ARGS[@]}"
done

abe_log "matrix complete. Actual run order recorded in $SEQUENCE_FILE"
