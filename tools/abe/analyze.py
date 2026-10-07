#!/usr/bin/env python3
"""Colocated qlog analysis helper for the ABE/ECN lab harness.

Parses quiche's sender qlog (JSON Text Sequences per RFC 7464) and
extracts a cwnd/ssthresh/bytes_in_flight time series from
`quic:recovery_metrics_updated` events, matching the qlog schema
currently emitted by this checkout (see plan.md section 3, "Actual
metric event name" / "Metric encoding").

Usage:
    python3 analyze.py --qlog path/to/server-qlog/*.sqlog --out out.csv
    python3 analyze.py --qlog a.sqlog --out out.csv --plot out.png
"""
from __future__ import annotations

import argparse
import csv
import glob
import json
import sys
from dataclasses import dataclass, field
from typing import Iterator, Optional

RECORD_SEPARATOR = "\x1e"

# Absolute/cumulative fields: carried forward unchanged when a later
# event omits them (plan.md section 12: "Forward-fill omitted delta
# fields only within one connection/path after the first known value").
CARRY_FIELDS = (
    "congestion_window",
    "ssthresh",
    "bytes_in_flight",
    "smoothed_rtt",
    "latest_rtt",
    "min_rtt",
    "rtt_variance",
    "pacing_rate",
)


def iter_qlog_records(path: str) -> Iterator[dict]:
    """Yields decoded JSON objects from a JSON-Text-Sequences qlog file.

    The first record is the qlog file header, not an event; callers
    distinguish it by the absence of a "name" field.
    """
    with open(path, "r", encoding="utf-8") as f:
        buf = f.read()

    for chunk in buf.split(RECORD_SEPARATOR):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            yield json.loads(chunk)
        except json.JSONDecodeError as e:
            print(
                f"warning: skipping malformed qlog record in {path}: {e}",
                file=sys.stderr,
            )


@dataclass
class Sample:
    time_s: float
    values: dict = field(default_factory=dict)


def extract_recovery_samples(path: str) -> list[Sample]:
    samples: list[Sample] = []
    carried: dict = {}
    last_time_ms: Optional[float] = None

    for record in iter_qlog_records(path):
        if record.get("name") != "quic:recovery_metrics_updated":
            continue

        time_ms = record.get("time")
        if time_ms is None:
            continue
        time_ms = float(time_ms)

        if last_time_ms is not None and time_ms < last_time_ms:
            print(
                f"warning: timestamp regression in {path} "
                f"({time_ms} < {last_time_ms}); keeping original record order",
                file=sys.stderr,
            )
        last_time_ms = time_ms

        data = record.get("data", {})
        for key in CARRY_FIELDS:
            if key in data and data[key] is not None:
                carried[key] = data[key]

        samples.append(Sample(time_s=time_ms / 1000.0, values=dict(carried)))

    return samples


def write_csv(samples: list[Sample], out_path: str) -> None:
    fields: set[str] = set()
    for s in samples:
        fields.update(s.values.keys())
    fieldnames = ["time_s"] + sorted(fields)

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for s in samples:
            row = {"time_s": f"{s.time_s:.6f}"}
            row.update(s.values)
            writer.writerow(row)


def maybe_plot(samples: list[Sample], out_path: str) -> None:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not available; skipping --plot", file=sys.stderr)
        return

    xs = [s.time_s for s in samples]
    cwnd = [s.values.get("congestion_window") for s in samples]

    fig, ax = plt.subplots()
    # Step plot: preserve reduction points, don't smooth 0.70/0.85 drops
    # (plan.md section 12).
    ax.step(xs, cwnd, where="post", label="cwnd (bytes)")
    ax.set_xlabel("time (s)")
    ax.set_ylabel("bytes")
    ax.legend()
    fig.savefig(out_path)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--qlog", nargs="+", required=True, help="qlog file(s)/glob(s)"
    )
    parser.add_argument("--out", required=True, help="output CSV path")
    parser.add_argument("--plot", help="optional PNG path for a cwnd step plot")
    args = parser.parse_args(argv)

    paths: list[str] = []
    for pattern in args.qlog:
        matched = glob.glob(pattern)
        paths.extend(matched if matched else [pattern])

    if not paths:
        print("no qlog files matched", file=sys.stderr)
        return 1

    all_samples: list[Sample] = []
    files_read = 0
    for path in paths:
        try:
            all_samples.extend(extract_recovery_samples(path))
            files_read += 1
        except OSError as e:
            print(f"warning: could not read {path}: {e}", file=sys.stderr)

    if files_read == 0:
        print("no qlog files could be read", file=sys.stderr)
        return 1

    all_samples.sort(key=lambda s: s.time_s)

    write_csv(all_samples, args.out)
    print(f"wrote {len(all_samples)} samples to {args.out}")

    if args.plot:
        maybe_plot(all_samples, args.plot)
        print(f"wrote plot to {args.plot}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
