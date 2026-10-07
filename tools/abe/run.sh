#!/bin/bash
# tools/abe/run.sh
#
# Executes one ABE/ECN lab run (one arm from plan.md section 11) against
# an already-up topology built by netns.sh. Starts quiche-server in
# abe-s1 and quiche-client in abe-c1, captures qlog (and, if tcpdump is
# available, pcap), then writes a JSON manifest describing the run.
#
# Only ever manages PIDs it starts itself; never touches unrelated
# processes or namespaces.
#
# Usage:
#   sudo tools/abe/run.sh --mode E --run-id e-trial-1
#   sudo tools/abe/run.sh --mode AS --payload-bytes 33554432 --integrity-only
#
# See `--help` for the full option list.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "$HERE/lib.sh"

REPO_ROOT="$(cd "$HERE/../.." && pwd)"

MODE=""
RUN_ID=""
OUT_DIR=""
PAYLOAD_BYTES=268435456
TIMEOUT_SEC=600
HTTP_VERSION="HTTP/3"
WIRE_VERSION="1"
SERVER_BIN="$REPO_ROOT/target/release/quiche-server"
CLIENT_BIN="$REPO_ROOT/target/release/quiche-client"
CERT="$REPO_ROOT/quiche/examples/cert.crt"
KEY="$REPO_ROOT/quiche/examples/cert.key"
ROOT_DIR="$REPO_ROOT/quiche/examples"
LISTEN_ADDR="10.77.1.2:4433"
CLIENT_HOST="10.77.1.2"
CODEL_TARGET="5ms"
CODEL_INTERVAL="100ms"
CODEL_LIMIT="1000"
BOTTLENECK_RATE="10mbit"
INTEGRITY_ONLY=0
CAPTURE=1

usage() {
    cat <<'EOF'
Usage: run.sh --mode {H0|L|E|A|AS|N|F} [options]

Options:
  --mode MODE            Arm to run (see plan.md section 11).
  --run-id ID             Run identifier (default: <mode>-<UTC timestamp>).
  --out-dir DIR           Output directory (default: tools/abe/results/<run-id>).
  --payload-bytes N       Bytes requested via /stream-bytes/N (default: 268435456).
  --timeout SEC           Client watchdog timeout (default: 600).
  --http-version VER      Default: HTTP/3.
  --wire-version HEX      Default: 1.
  --server-bin PATH       Default: target/release/quiche-server.
  --client-bin PATH       Default: target/release/quiche-client.
  --cert/--key/--root PATH
  --codel-target/--codel-interval/--codel-limit/--rate
                          Bottleneck overrides applied before the run.
  --integrity-only        Save the response body instead of discarding it.
  --no-capture            Skip tcpdump captures.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --mode) MODE="$2"; shift 2 ;;
        --run-id) RUN_ID="$2"; shift 2 ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --payload-bytes) PAYLOAD_BYTES="$2"; shift 2 ;;
        --timeout) TIMEOUT_SEC="$2"; shift 2 ;;
        --http-version) HTTP_VERSION="$2"; shift 2 ;;
        --wire-version) WIRE_VERSION="$2"; shift 2 ;;
        --server-bin) SERVER_BIN="$2"; shift 2 ;;
        --client-bin) CLIENT_BIN="$2"; shift 2 ;;
        --cert) CERT="$2"; shift 2 ;;
        --key) KEY="$2"; shift 2 ;;
        --root) ROOT_DIR="$2"; shift 2 ;;
        --codel-target) CODEL_TARGET="$2"; shift 2 ;;
        --codel-interval) CODEL_INTERVAL="$2"; shift 2 ;;
        --codel-limit) CODEL_LIMIT="$2"; shift 2 ;;
        --rate) BOTTLENECK_RATE="$2"; shift 2 ;;
        --integrity-only) INTEGRITY_ONLY=1; shift ;;
        --no-capture) CAPTURE=0; shift ;;
        -h|--help) usage; exit 0 ;;
        *) abe_die "unknown option: $1 (see --help)" ;;
    esac
done

[ -n "$MODE" ] || { usage; abe_die "--mode is required (H0|L|E|A|AS|N|F)"; }
abe_require_root
abe_topology_is_up || abe_die "topology is not up; run 'sudo tools/abe/netns.sh up' first"

RUN_ID="${RUN_ID:-${MODE}-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_DIR="${OUT_DIR:-$HERE/results/$RUN_ID}"
mkdir -p "$OUT_DIR/server-qlog" "$OUT_DIR/client-qlog"

# Map the arm to concrete server/client flags (plan.md section 11).
SERVER_ECN_FLAGS=()
CLIENT_ECN_FLAGS=()
CODEL_MODE="noecn"
case "$MODE" in
    H0|L)
        CODEL_MODE="noecn"
        ;;
    E)
        SERVER_ECN_FLAGS=(--ecn)
        CLIENT_ECN_FLAGS=(--ecn)
        CODEL_MODE="ecn"
        ;;
    A)
        SERVER_ECN_FLAGS=(--ecn --abe ca-only)
        CLIENT_ECN_FLAGS=(--ecn --abe ca-only)
        CODEL_MODE="ecn"
        ;;
    AS)
        SERVER_ECN_FLAGS=(--ecn --abe all-phases)
        CLIENT_ECN_FLAGS=(--ecn --abe all-phases)
        CODEL_MODE="ecn"
        ;;
    N)
        # Roomy/noncongested path: same policy as A, but with the
        # bottleneck rate raised so no CE/loss is expected.
        SERVER_ECN_FLAGS=(--ecn --abe ca-only)
        CLIENT_ECN_FLAGS=(--ecn --abe ca-only)
        CODEL_MODE="ecn"
        BOTTLENECK_RATE="1000mbit"
        ;;
    F)
        # Fault injection: ECN attempted, but bleached in-path (see
        # `netns.sh strip-ecn on`, applied below).
        SERVER_ECN_FLAGS=(--ecn --abe ca-only)
        CLIENT_ECN_FLAGS=(--ecn --abe ca-only)
        CODEL_MODE="ecn"
        ;;
    *)
        abe_die "unknown --mode '$MODE' (expected H0|L|E|A|AS|N|F)"
        ;;
esac

[ -x "$SERVER_BIN" ] || abe_die "server binary not found/executable: $SERVER_BIN (build: cargo build -p quiche_apps --release --features qlog)"
[ -x "$CLIENT_BIN" ] || abe_die "client binary not found/executable: $CLIENT_BIN"
[ -f "$CERT" ] || abe_die "cert not found: $CERT"
[ -f "$KEY" ] || abe_die "key not found: $KEY"

abe_log "run $RUN_ID: mode=$MODE codel=$CODEL_MODE rate=$BOTTLENECK_RATE payload=$PAYLOAD_BYTES"

# Reconfigure the shared bottleneck for this arm without a full rebuild.
"$HERE/netns.sh" set-queue --mode "$CODEL_MODE" --target "$CODEL_TARGET" \
    --interval "$CODEL_INTERVAL" --limit "$CODEL_LIMIT" --rate "$BOTTLENECK_RATE"

if [ "$MODE" = "F" ]; then
    "$HERE/netns.sh" strip-ecn on
else
    "$HERE/netns.sh" strip-ecn off
fi

ip netns exec abe-r1 tc -j -s -d qdisc show dev r1-bn \
    > "$OUT_DIR/tc-before.json" 2>/dev/null || true

PIDS=()
cleanup() {
    local pid
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] || continue
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] || continue
        wait "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT INT TERM

if [ "$CAPTURE" -eq 1 ] && command -v tcpdump >/dev/null 2>&1; then
    ip netns exec abe-s1 tcpdump -i s1-eth -w "$OUT_DIR/sender.pcap" -U udp port 4433 \
        >"$OUT_DIR/tcpdump-sender.log" 2>&1 &
    PIDS+=("$!")
    ip netns exec abe-c1 tcpdump -i c1-eth -w "$OUT_DIR/receiver.pcap" -U udp port 4433 \
        >"$OUT_DIR/tcpdump-receiver.log" 2>&1 &
    PIDS+=("$!")
    sleep 1
fi

START_EPOCH=$(date -u +%s.%N)

ip netns exec abe-s1 env QLOGDIR="$OUT_DIR/server-qlog" \
    "$SERVER_BIN" --listen "$LISTEN_ADDR" --cert "$CERT" --key "$KEY" \
    --root "$ROOT_DIR" --http-version "$HTTP_VERSION" --cc-algorithm cubic \
    "${SERVER_ECN_FLAGS[@]}" \
    >"$OUT_DIR/server.log" 2>&1 &
SERVER_PID=$!
PIDS+=("$SERVER_PID")

sleep 1

CLIENT_URL="https://${CLIENT_HOST}:4433/stream-bytes/${PAYLOAD_BYTES}"
CLIENT_ARGS=(--http-version "$HTTP_VERSION" --cc-algorithm cubic \
    --wire-version "$WIRE_VERSION" --no-verify "${CLIENT_ECN_FLAGS[@]}" "$CLIENT_URL")

set +e
if [ "$INTEGRITY_ONLY" -eq 1 ]; then
    ip netns exec abe-c1 env QLOGDIR="$OUT_DIR/client-qlog" timeout "$TIMEOUT_SEC" \
        "$CLIENT_BIN" "${CLIENT_ARGS[@]}" >"$OUT_DIR/client-body.txt" 2>"$OUT_DIR/client.log"
else
    ip netns exec abe-c1 env QLOGDIR="$OUT_DIR/client-qlog" timeout "$TIMEOUT_SEC" \
        "$CLIENT_BIN" "${CLIENT_ARGS[@]}" >/dev/null 2>"$OUT_DIR/client.log"
fi
CLIENT_EXIT=$?
set -e

END_EPOCH=$(date -u +%s.%N)

sleep 1
ip netns exec abe-r1 tc -j -s -d qdisc show dev r1-bn \
    > "$OUT_DIR/tc-after.json" 2>/dev/null || true

kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true

if [ "$CAPTURE" -eq 1 ]; then
    sleep 1
fi
cleanup
trap - EXIT INT TERM

WATCHDOG_TRIPPED=false
[ "$CLIENT_EXIT" -eq 124 ] && WATCHDOG_TRIPPED=true

GIT_REV="$(cd "$REPO_ROOT" && git rev-parse HEAD 2>/dev/null || echo unknown)"
GIT_DIRTY_FILES="$(cd "$REPO_ROOT" && git status --porcelain 2>/dev/null | wc -l | tr -d ' ')"

if command -v jq >/dev/null 2>&1; then
    jq -n \
        --arg run_id "$RUN_ID" --arg mode "$MODE" --arg codel_mode "$CODEL_MODE" \
        --arg codel_target "$CODEL_TARGET" --arg codel_interval "$CODEL_INTERVAL" \
        --arg codel_limit "$CODEL_LIMIT" --arg rate "$BOTTLENECK_RATE" \
        --argjson payload_bytes "$PAYLOAD_BYTES" \
        --argjson start_epoch "$START_EPOCH" --argjson end_epoch "$END_EPOCH" \
        --argjson client_exit_code "$CLIENT_EXIT" --argjson watchdog_tripped "$WATCHDOG_TRIPPED" \
        --arg server_bin "$SERVER_BIN" --arg client_bin "$CLIENT_BIN" \
        --arg http_version "$HTTP_VERSION" --arg wire_version "$WIRE_VERSION" \
        --arg git_rev "$GIT_REV" --argjson git_dirty_files "$GIT_DIRTY_FILES" \
        '{run_id:$run_id, mode:$mode, codel_mode:$codel_mode, codel_target:$codel_target,
          codel_interval:$codel_interval, codel_limit:$codel_limit, rate:$rate,
          payload_bytes:$payload_bytes, start_epoch:$start_epoch, end_epoch:$end_epoch,
          client_exit_code:$client_exit_code, watchdog_tripped:$watchdog_tripped,
          server_bin:$server_bin, client_bin:$client_bin, http_version:$http_version,
          wire_version:$wire_version, git_rev:$git_rev, git_dirty_files:$git_dirty_files}' \
        > "$OUT_DIR/manifest.json"
else
    abe_log "jq not found; writing a minimal manifest"
    cat > "$OUT_DIR/manifest.json" <<JSON
{"run_id":"$RUN_ID","mode":"$MODE","codel_mode":"$CODEL_MODE","payload_bytes":$PAYLOAD_BYTES,"client_exit_code":$CLIENT_EXIT,"watchdog_tripped":$WATCHDOG_TRIPPED,"git_rev":"$GIT_REV"}
JSON
fi

if [ "$CLIENT_EXIT" -ne 0 ]; then
    abe_log "client exited with code $CLIENT_EXIT (see $OUT_DIR/client.log); recorded in manifest.json"
fi

abe_log "run $RUN_ID complete: $OUT_DIR"
