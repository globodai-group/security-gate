import json
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

import yaml

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gate


FIXTURES = Path(__file__).with_name("fixtures")
ACTION = Path(__file__).resolve().parents[1] / "action.yml"


class GateTests(unittest.TestCase):
    def test_action_metadata_parses_and_declares_inputs(self):
        metadata = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
        self.assertIn("inputs", metadata)
        self.assertTrue({"mode", "path", "image", "config"}.issubset(metadata["inputs"]))

    def scan(self, name):
        return json.loads((FIXTURES / (name + ".json")).read_text(encoding="utf-8"))

    def evaluate(self, name, config="", today=date(2026, 11, 3)):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / ".security-gate.toml"
            config_path.write_text(config, encoding="utf-8")
            warnings = []
            ignores = gate.load_ignores(config_path, today=today, warn=warnings.append)
            findings = gate.evaluate_scan(self.scan(name), ignores)
        return findings, warnings

    def assert_blocks(self, name):
        findings, _ = self.evaluate(name)
        self.assertEqual(1, len(gate.emit_annotations(findings)))

    def test_critical_blocks(self):
        self.assert_blocks("critical")

    def test_high_blocks(self):
        self.assert_blocks("high")

    def test_moderate_passes(self):
        findings, _ = self.evaluate("moderate")
        self.assertEqual([], gate.emit_annotations(findings))

    def test_malware_blocks(self):
        self.assert_blocks("malware")

    def test_ignored_finding_passes(self):
        findings, _ = self.evaluate(
            "high",
            '[[ignore]]\nid = "GHSA-high-0001"\nreason = "Not reachable in this service"\nuntil = "2026-11-10"\n',
        )
        self.assertEqual([], gate.emit_annotations(findings))
        self.assertIsNotNone(findings[0]["ignored"])

    def test_expired_ignore_blocks(self):
        findings, warnings = self.evaluate(
            "high",
            '[[ignore]]\nid = "GHSA-high-0001"\nreason = "Temporary exception"\nuntil = "2026-11-02"\n',
        )
        self.assertEqual(1, len(gate.emit_annotations(findings)))
        self.assertEqual(["Ignore GHSA-high-0001 expired on 2026-11-02 and no longer applies"], warnings)

    def test_ignore_missing_reason_errors(self):
        with self.assertRaisesRegex(gate.GateError, "missing reason"):
            self.evaluate("high", '[[ignore]]\nid = "GHSA-high-0001"\nuntil = "2026-11-10"\n')

    def test_ignore_more_than_ninety_days_ahead_errors(self):
        with self.assertRaisesRegex(gate.GateError, "more than 90 days"):
            self.evaluate(
                "high",
                '[[ignore]]\nid = "GHSA-high-0001"\nreason = "Temporary exception"\nuntil = "2027-02-02"\n',
            )

    def test_unfixed_high_blocks(self):
        findings, _ = self.evaluate("unfixed-high")
        self.assertEqual("none", findings[0]["fixed"])
        self.assertEqual(1, len(gate.emit_annotations(findings)))

    def test_empty_scan_passes(self):
        findings, _ = self.evaluate("empty")
        self.assertEqual([], findings)
        self.assertEqual([], gate.emit_annotations(findings))

    def test_missing_scanner_severity_fetches_once(self):
        scan = self.scan("missing-severity")
        fetched = self.scan("high")["results"][0]["packages"][0]["vulnerabilities"][0]
        calls = []

        def fetch(identifier):
            calls.append(identifier)
            return fetched

        findings = gate.evaluate_scan(scan, [], fetch_advisory=fetch)
        self.assertEqual(["GHSA-fetch-0001"], calls)
        self.assertEqual("HIGH", findings[0]["severity"])

    def test_summary_lists_non_blocking_and_ignored(self):
        findings, _ = self.evaluate("moderate")
        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary.md"
            gate.write_summary(summary, findings)
            content = summary.read_text(encoding="utf-8")
        self.assertIn("non-blocking", content)
        self.assertIn("GHSA-moderate-0001", content)


if __name__ == "__main__":
    unittest.main()
