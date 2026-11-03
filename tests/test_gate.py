import io
import json
import tarfile
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import date, timedelta
from io import StringIO
from pathlib import Path

import yaml

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gate
import image_npm_lockfile


FIXTURES = Path(__file__).with_name("fixtures")
ACTION = Path(__file__).resolve().parents[1] / "action.yml"


class GateTests(unittest.TestCase):
    def test_action_metadata_parses_and_declares_inputs(self):
        metadata = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
        self.assertIn("inputs", metadata)
        self.assertTrue({"mode", "path", "image", "config"}.issubset(metadata["inputs"]))
        self.assertIn("verdict", metadata["outputs"])

    def test_action_forces_scanner_config_and_status_check(self):
        action = ACTION.read_text(encoding="utf-8")
        self.assertIn('scanner_config="$(mktemp "$RUNNER_TEMP/security-gate-osv-config.XXXXXX.toml")"', action)
        self.assertIn('scan source -r "$GATE_PATH" --format json --config "$scanner_config" --no-ignore', action)
        self.assertIn('scan image "$GATE_IMAGE" --format json --config "$scanner_config"', action)
        self.assertIn('--scanner-status "$scanner_status"', action)
        self.assertIn('scan source -r "$npm_dir" --format json --config "$scanner_config" --no-ignore', action)
        self.assertIn('--scanner-status "$npm_status"', action)

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

    def test_ignore_unknown_field_errors_with_location(self):
        with self.assertRaisesRegex(gate.GateError, r"unknown ignore field package at .+:5"):
            self.evaluate(
                "high",
                '[[ignore]]\nid = "GHSA-high-0001"\nreason = "Temporary exception"\nuntil = "2026-11-10"\npackage = "high-package"\n',
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

    def test_invalid_scanner_severity_fetches_advisory(self):
        fetched = self.scan("high")["results"][0]["packages"][0]["vulnerabilities"][0]
        for scanner_value in (None, "", "NONE"):
            with self.subTest(scanner_value=scanner_value):
                scan = self.scan("missing-severity")
                scan["results"][0]["packages"][0]["vulnerabilities"][0]["database_specific"] = {"severity": scanner_value}
                calls = []

                def fetch(identifier):
                    calls.append(identifier)
                    return fetched

                findings = gate.evaluate_scan(scan, [], fetch_advisory=fetch)
                self.assertEqual(["GHSA-fetch-0001"], calls)
                self.assertEqual("HIGH", findings[0]["severity"])

    def test_missing_scanner_severity_fetches_ghsa_alias(self):
        scan = {
            "results": [{
                "source": {"path": "requirements.txt", "type": "lockfile"},
                "packages": [{
                    "package": {"name": "py-package", "version": "1.0.0", "ecosystem": "PyPI"},
                    "vulnerabilities": [{
                        "id": "PYSEC-2026-0001",
                        "aliases": ["GHSA-pysec-0001"],
                    }],
                }],
            }],
        }
        calls = []

        def fetch(identifier):
            calls.append(identifier)
            if identifier == "GHSA-pysec-0001":
                return {"id": identifier, "database_specific": {"severity": "HIGH"}}
            return {"id": identifier}

        findings = gate.evaluate_scan(scan, [], fetch_advisory=fetch)
        self.assertEqual(["GHSA-pysec-0001"], calls)
        self.assertEqual("HIGH", findings[0]["severity"])
        self.assertEqual(1, len(gate.emit_annotations(findings)))

    def test_malware_ignore_is_rejected(self):
        with self.assertRaisesRegex(gate.GateError, "MAL advisories cannot be ignored"):
            self.evaluate(
                "malware",
                '[[ignore]]\nid = "MAL-2026-0001"\nreason = "Temporary exception"\nuntil = "2026-11-10"\n',
            )

    def test_malware_alias_cannot_be_ignored(self):
        scan = self.scan("high")
        scan["results"][0]["packages"][0]["vulnerabilities"][0]["aliases"] = ["MAL-2026-0001"]
        ignores = [{"id": "GHSA-high-0001", "reason": "Temporary exception", "until": date(2026, 11, 10)}]
        findings = gate.evaluate_scan(scan, ignores)
        self.assertEqual("CRITICAL", findings[0]["severity"])
        self.assertIsNone(findings[0]["ignored"])
        self.assertEqual(1, len(gate.emit_annotations(findings)))

    def test_resolve_ignore_config_rejects_symlink_outside_workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "workspace"
            workspace.mkdir()
            outside = root / "outside.toml"
            outside.write_text("", encoding="utf-8")
            config = workspace / ".security-gate.toml"
            config.symlink_to(outside)
            with self.assertRaisesRegex(gate.GateError, "must resolve inside workspace"):
                gate.resolve_ignore_config(config, workspace)

    def test_missing_ignore_config_inside_workspace_is_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            config = gate.resolve_ignore_config(workspace / ".security-gate.toml", workspace)
            self.assertEqual([], gate.load_ignores(config))

    def test_scanner_status_with_no_evaluated_advisories_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            config = workspace / ".security-gate.toml"
            config.write_text("", encoding="utf-8")
            errors = StringIO()
            with redirect_stderr(errors):
                status = gate.main([
                    "--input", str(FIXTURES / "empty.json"),
                    "--config", str(config),
                    "--workspace", str(workspace),
                    "--scanner-status", "1",
                ])
        self.assertEqual(2, status)
        self.assertIn("::error::security-gate failed: osv-scanner reported vulnerabilities", errors.getvalue())

    def test_scanner_status_applies_to_its_own_input(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            config = workspace / ".security-gate.toml"
            config.write_text("", encoding="utf-8")
            errors = StringIO()
            with redirect_stderr(errors):
                status = gate.main([
                    "--input", str(FIXTURES / "high.json"),
                    "--scanner-status", "1",
                    "--input", str(FIXTURES / "empty.json"),
                    "--scanner-status", "1",
                    "--config", str(config),
                    "--workspace", str(workspace),
                ])
        self.assertEqual(2, status)
        self.assertIn("osv-scanner reported vulnerabilities", errors.getvalue())

    def test_several_inputs_are_gated_together(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            config = workspace / ".security-gate.toml"
            config.write_text("", encoding="utf-8")
            status = gate.main([
                "--input", str(FIXTURES / "empty.json"),
                "--scanner-status", "0",
                "--input", str(FIXTURES / "high.json"),
                "--scanner-status", "1",
                "--config", str(config),
                "--workspace", str(workspace),
            ])
        self.assertEqual(1, status)

    def test_missing_scanner_status_for_an_input_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            config = workspace / ".security-gate.toml"
            config.write_text("", encoding="utf-8")
            with redirect_stderr(StringIO()):
                status = gate.main([
                    "--input", str(FIXTURES / "empty.json"),
                    "--input", str(FIXTURES / "high.json"),
                    "--scanner-status", "1",
                    "--config", str(config),
                    "--workspace", str(workspace),
                ])
        self.assertEqual(2, status)

    def test_summary_lists_non_blocking_and_ignored(self):
        findings, _ = self.evaluate("moderate")
        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary.md"
            gate.write_summary(summary, findings)
            content = summary.read_text(encoding="utf-8")
        self.assertIn("non-blocking", content)
        self.assertIn("GHSA-moderate-0001", content)

    def test_verdict_lists_advisory_ids(self):
        findings, _ = self.evaluate("moderate")
        with tempfile.TemporaryDirectory() as directory:
            verdict = Path(directory) / "verdict"
            gate.write_verdict(verdict, findings, 0)
            content = verdict.read_text(encoding="utf-8")
        self.assertIn("gate exit 0", content)
        self.assertIn("GHSA-moderate-0001", content)


def image_tar(members):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, content in members:
            info = tarfile.TarInfo(name)
            if content is None or content.startswith("hardlink:"):
                info.type = tarfile.SYMTYPE if content is None else tarfile.LNKTYPE
                info.linkname = "/etc/passwd" if content is None else content[len("hardlink:"):]
                archive.addfile(info)
                continue
            data = content.encode("utf-8")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    buffer.seek(0)
    return buffer


def manifest(name, version):
    return json.dumps({"name": name, "version": version})


class ImageNpmLockfileTests(unittest.TestCase):
    def packages(self, members):
        warnings = []
        return image_npm_lockfile.installed_packages(image_tar(members), warnings.append), warnings

    def test_lists_bun_pnpm_scoped_and_nested_packages(self):
        packages, warnings = self.packages([
            ("app/node_modules/lodash/package.json", manifest("lodash", "4.17.20")),
            ("app/node_modules/@scope/pkg/package.json", manifest("@scope/pkg", "1.0.0")),
            ("app/node_modules/a/node_modules/lodash/package.json", manifest("lodash", "4.17.21")),
            ("app/node_modules/.pnpm/hono@4.0.0/node_modules/hono/package.json", manifest("hono", "4.0.0")),
            ("app/node_modules/.bun/zod@3.0.0/node_modules/zod/package.json", manifest("zod", "3.0.0")),
            ("app/node_modules/dup/package.json", manifest("lodash", "4.17.20")),
        ])
        self.assertEqual(
            [("@scope/pkg", "1.0.0"), ("hono", "4.0.0"), ("lodash", "4.17.20"), ("lodash", "4.17.21"), ("zod", "3.0.0")],
            packages,
        )
        self.assertEqual([], warnings)

    def test_hard_linked_manifest_from_the_store_is_listed(self):
        packages, _ = self.packages([
            ("root/.bun/install/cache/lodash@4.17.20@@@1/package.json", manifest("lodash", "4.17.20")),
            ("usr/src/app/node_modules/lodash/package.json", "hardlink:root/.bun/install/cache/lodash@4.17.20@@@1/package.json"),
        ])
        self.assertEqual([("lodash", "4.17.20")], packages)

    def test_hard_linked_manifest_from_a_hashed_pnpm_store_is_listed(self):
        packages, _ = self.packages([
            ("root/.local/share/pnpm/store/v10/files/3f/0a1b2c", "\ufeff" + manifest("lodash", "4.17.20")),
            ("usr/src/app/node_modules/.pnpm/lodash@4.17.20/node_modules/lodash/package.json", "hardlink:root/.local/share/pnpm/store/v10/files/3f/0a1b2c"),
        ])
        self.assertEqual([("lodash", "4.17.20")], packages)

    def test_hard_link_to_a_missing_member_errors(self):
        with self.assertRaises(image_npm_lockfile.ImageStreamError):
            self.packages([("app/node_modules/missing/package.json", "hardlink:nowhere/package.json")])

    def test_corrupt_header_after_first_member_errors(self):
        stream = image_tar([
            ("app/node_modules/a/package.json", manifest("a", "1.0.0")),
            ("app/node_modules/b/package.json", manifest("b", "1.0.0")),
        ])
        data = bytearray(stream.getvalue())
        data[1024 + 148:1024 + 156] = b"0000000\0"
        with self.assertRaises(image_npm_lockfile.ImageStreamError):
            image_npm_lockfile.installed_packages(io.BytesIO(bytes(data)), lambda message: None)

    def test_warning_escapes_image_paths(self):
        output = StringIO()
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(output):
            image_npm_lockfile.main(
                ["--output", str(Path(directory) / "package-lock.json")],
                stream=image_tar([("app/node_modules/x\n::stop-commands::t/package.json", "{")]),
            )
        self.assertNotIn("\n::stop-commands::", output.getvalue())
        self.assertIn("%0A::stop-commands::", output.getvalue())

    def test_ignores_non_package_manifests(self):
        packages, _ = self.packages([
            ("app/package.json", manifest("app", "1.0.0")),
            ("app/node_modules/lodash/lib/package.json", manifest("inner", "1.0.0")),
            ("app/node_modules/.bin/package.json", manifest("bin", "1.0.0")),
            ("app/node_modules/@scope/package.json", manifest("scope", "1.0.0")),
            ("app/node_modules/nameless/package.json", json.dumps({"version": "1.0.0"})),
            ("app/node_modules/linked/package.json", None),
        ])
        self.assertEqual([], packages)

    def test_invalid_manifest_warns_and_is_skipped(self):
        packages, warnings = self.packages([
            ("app/node_modules/broken/package.json", "{"),
            ("app/node_modules/ok/package.json", manifest("ok", "1.0.0")),
        ])
        self.assertEqual([("ok", "1.0.0")], packages)
        self.assertEqual(1, len(warnings))

    def test_lockfile_entries_resolve_to_the_registry(self):
        lockfile = image_npm_lockfile.lockfile([("@scope/pkg", "1.0.0"), ("lodash", "4.17.20")])
        entries = [entry for key, entry in lockfile["packages"].items() if key]
        self.assertEqual(
            ["https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz", "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"],
            [entry["resolved"] for entry in entries],
        )
        self.assertEqual(2, len(set(lockfile["packages"])) - 1)

    def test_no_package_writes_no_lockfile(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "package-lock.json"
            with redirect_stdout(StringIO()):
                status = image_npm_lockfile.main(["--output", str(output)], stream=image_tar([("etc/os-release", "x")]))
            self.assertEqual(0, status)
            self.assertFalse(output.exists())

    def test_unreadable_stream_errors(self):
        with redirect_stderr(StringIO()):
            status = image_npm_lockfile.main(["--output", "unused"], stream=io.BytesIO(b"not a tar"))
        self.assertEqual(2, status)


if __name__ == "__main__":
    unittest.main()
