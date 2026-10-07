# tools/abe: ABE/ECN network-namespace lab harness

Scripts that build the Linux network-namespace dumbbell topology and run
the ECN/ABE comparison matrix described in `plan.md` sections 10-12, on
top of the `--ecn`/`--abe` support added to `quiche-server`/`quiche-client`.

**Requires root (`CAP_NET_ADMIN`) and a real Linux kernel** (netns, veth,
`sch_htb`, `sch_codel`, `sch_netem`, `sch_fq`). WSL2 can run this for a
quick functional trial if its kernel has those modules, but per
`plan.md` section 2 it does not satisfy the no-VM condition for final
measurements — run the actual comparison on a physical Linux host.

Nothing here touches the host's production network. Every script is
scoped to namespaces named `abe-*` that it creates itself, and tracks
ownership in `/run/abe-lab/namespaces.manifest` (override with
`ABE_STATE_DIR`) so `down` never deletes anything it didn't create.

## Files

| File | Purpose |
| --- | --- |
| `lib.sh` | Shared logging/guard helpers, sourced by the other scripts. |
| `netns.sh` | Build/tear down the topology; reconfigure the bottleneck/RTT/fault in place. |
| `run.sh` | Run one arm (H0/L/E/A/AS/N/F) against the up topology; produces qlog, pcap, `manifest.json`. |
| `matrix.sh` | Loop `run.sh` over arms x repetitions in a randomized, recorded order. |
| `analyze.py` | Parse sender qlog (`quic:recovery_metrics_updated`) into a CSV / optional cwnd step plot. |
| `tests/` | Colocated fixture + unit tests for `analyze.py` (no root needed). |

## 1. Build the binaries (once, on the Linux host)

```bash
cd /path/to/quiche   # the Linux checkout, not a Windows path
cargo build -p quiche_apps --release --features qlog
```

## 2. Bring up the topology

```bash
sudo tools/abe/netns.sh up
sudo tools/abe/netns.sh verify   # ping/route/MTU sanity checks
sudo tools/abe/netns.sh status
```

`up` refuses to run if any `abe-*` namespace already exists and isn't
owned by this tool, and refuses to run twice without `down` in between.

## 3. Run one arm

```bash
sudo tools/abe/run.sh --mode E --run-id trial-1 --payload-bytes 33554432
```

`--mode` selects the arm per `plan.md` section 11:

| Mode | Server/client flags | CoDel mode |
| --- | --- | --- |
| `H0`, `L` | (none) | `noecn` |
| `E` | `--ecn` | `ecn` |
| `A` | `--ecn --abe ca-only` | `ecn` |
| `AS` | `--ecn --abe all-phases` | `ecn` |
| `N` | `--ecn --abe ca-only`, bottleneck raised to 1000mbit | `ecn` |
| `F` | `--ecn --abe ca-only`, ECN bleached in-path (`netns.sh strip-ecn on`) | `ecn` |

`run.sh` reconfigures the shared bottleneck (`netns.sh set-queue`) before
each run, so arms can be run back-to-back without rebuilding the
topology. Output goes to `tools/abe/results/<run-id>/`: `server.log`,
`client.log`, `server-qlog/`, `client-qlog/`, `sender.pcap`/`receiver.pcap`
(if `tcpdump` is installed), `tc-before.json`/`tc-after.json`, and
`manifest.json` (run parameters, git revision, exit code, watchdog
status).

Use `--integrity-only` for a small trial that saves the response body
(to verify content/length) instead of discarding it — do this once per
mode before running performance trials with large payloads.

## 4. Run the full repeated matrix

```bash
sudo tools/abe/matrix.sh --arms "L E A AS" --repeats 10 -- --payload-bytes 268435456
```

Runs are executed in a randomized order; the actual order is written to
`tools/abe/results/order-<timestamp>.txt`. `H0` is meant to be archived
as a separate historical baseline (run it once with `run.sh --mode H0`
before any code changes, not as part of the repeated matrix).

## 5. Adjust queue/RTT/fault conditions between runs

```bash
sudo tools/abe/netns.sh set-queue --mode ecn --target 10ms --interval 100ms --limit 1000 --rate 10mbit
sudo tools/abe/netns.sh set-rtt --ms 100
sudo tools/abe/netns.sh strip-ecn on   # simulate ECN bleaching (arm F); 'off' to restore
```

`run.sh` already calls `set-queue`/`strip-ecn` per its `--mode`; use
these directly for sweeps (`plan.md` section 11 item 3-4) or manual
diagnosis.

## 6. Analyze results

```bash
python3 tools/abe/analyze.py \
    --qlog "tools/abe/results/trial-1/server-qlog/*.sqlog" \
    --out tools/abe/results/trial-1/cwnd.csv \
    --plot tools/abe/results/trial-1/cwnd.png   # optional, needs matplotlib
```

Run the colocated parser tests any time (no root, no Linux-only
dependency):

```bash
python3 tools/abe/tests/test_analyze.py -v
```

## 7. Tear down

```bash
sudo tools/abe/netns.sh down
```

Only stops PIDs `run.sh`/`matrix.sh` started and deletes only the
namespaces recorded in the manifest. Never runs `pkill quiche-server`,
`ip -all netns delete`, or any host-wide reset.

## Known limitations (see plan.md for the full list)

- `strip-ecn` (arm `F`) uses a `tc pedit` rule to zero the whole IP ToS
  byte on `abe-r1`/`r1-bn` ingress; it is best-effort and should be
  verified with a packet capture before trusting results from that arm.
- `N` (roomy path) is implemented by raising the bottleneck rate rather
  than building a separate uncongested topology; this is a
  simplification, not a distinct physical path.
- Fairness (two simultaneous flows via `s2`/`c2`) and mixed-loss
  (`netem loss`) scenarios are not yet automated here; extend `run.sh`
  or add a sibling script before running those matrix rows.
- These scripts do not install packages, load kernel modules, or touch
  anything outside `abe-*` namespaces; provisioning (Phase A) is a
  one-time manual step per `plan.md` section 5.
