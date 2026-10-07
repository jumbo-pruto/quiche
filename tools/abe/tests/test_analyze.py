#!/usr/bin/env python3
"""Colocated tests for tools/abe/analyze.py.

Run directly (no pytest dependency required):
    python3 tools/abe/tests/test_analyze.py
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ABE_DIR = os.path.dirname(HERE)
sys.path.insert(0, ABE_DIR)

import analyze  # noqa: E402

FIXTURE = os.path.join(HERE, "fixtures", "sample.sqlog")


class TestIterQlogRecords(unittest.TestCase):
    def test_skips_header_and_yields_all_records(self):
        records = list(analyze.iter_qlog_records(FIXTURE))
        # 1 header + 5 events.
        self.assertEqual(len(records), 6)
        self.assertNotIn("name", records[0])
        self.assertEqual(records[1]["name"], "quic:recovery_metrics_updated")

    def test_skips_malformed_record_without_raising(self):
        with tempfile.NamedTemporaryFile(
            "w", suffix=".sqlog", delete=False, encoding="utf-8"
        ) as f:
            f.write("\x1e{not json}\n")
            f.write('\x1e{"time": 1.0, "name": "quic:recovery_metrics_updated", "data": {}}\n')
            path = f.name
        try:
            records = list(analyze.iter_qlog_records(path))
            self.assertEqual(len(records), 1)
        finally:
            os.unlink(path)


class TestExtractRecoverySamples(unittest.TestCase):
    def test_extracts_expected_sample_count_and_times(self):
        samples = analyze.extract_recovery_samples(FIXTURE)
        self.assertEqual(len(samples), 5)
        self.assertAlmostEqual(samples[0].time_s, 1.0)
        self.assertAlmostEqual(samples[-1].time_s, 1.2)

    def test_forward_fills_omitted_carry_fields(self):
        samples = analyze.extract_recovery_samples(FIXTURE)
        # The last record only reports congestion_window; ssthresh and
        # bytes_in_flight must be carried forward from the prior sample.
        last = samples[-1]
        self.assertEqual(last.values["congestion_window"], 10150)
        self.assertEqual(last.values["ssthresh"], 9800)
        self.assertEqual(last.values["bytes_in_flight"], 16800)

    def test_reduction_point_is_preserved_not_smoothed(self):
        samples = analyze.extract_recovery_samples(FIXTURE)
        cwnds = [s.values["congestion_window"] for s in samples]
        # 14000 -> 15400 -> 16800 -> 9800 (reduction) -> 10150.
        self.assertEqual(cwnds, [14000, 15400, 16800, 9800, 10150])


class TestWriteCsv(unittest.TestCase):
    def test_round_trips_through_csv(self):
        samples = analyze.extract_recovery_samples(FIXTURE)
        with tempfile.NamedTemporaryFile(
            "w", suffix=".csv", delete=False, encoding="utf-8"
        ) as f:
            out_path = f.name
        try:
            analyze.write_csv(samples, out_path)
            with open(out_path, encoding="utf-8") as f:
                lines = f.readlines()
            # header + 5 data rows.
            self.assertEqual(len(lines), 6)
            self.assertIn("time_s", lines[0])
            self.assertIn("congestion_window", lines[0])
        finally:
            os.unlink(out_path)


class TestMain(unittest.TestCase):
    def test_main_writes_csv_for_glob(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_csv = os.path.join(tmp, "out.csv")
            rc = analyze.main(["--qlog", FIXTURE, "--out", out_csv])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(out_csv))

    def test_main_fails_on_no_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_csv = os.path.join(tmp, "out.csv")
            rc = analyze.main(
                ["--qlog", os.path.join(tmp, "nonexistent-*.sqlog"), "--out", out_csv]
            )
            self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
