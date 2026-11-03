#!/usr/bin/env python3
"""Evaluate osv-scanner JSON with a fail-closed high-severity policy."""

import argparse
import ast
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, timedelta
from pathlib import Path


BLOCKING_SEVERITIES = {"CRITICAL", "HIGH"}
OSV_VULNERABILITY_URL = "https://api.osv.dev/v1/vulns/"


class GateError(Exception):
    """A configuration, input, or network error that must fail the gate."""


def canonical_id(vulnerability):
    identifiers = [str(vulnerability.get("id", ""))]
    identifiers.extend(str(alias) for alias in vulnerability.get("aliases", []))
    ghsas = sorted(identifier for identifier in identifiers if identifier.startswith("GHSA-"))
    return ghsas[0] if ghsas else identifiers[0]


def identifiers_for(vulnerability):
    identifiers = {str(vulnerability.get("id", "")), canonical_id(vulnerability)}
    identifiers.update(str(alias) for alias in vulnerability.get("aliases", []))
    return identifiers - {""}


def scanner_severity(vulnerability):
    database_specific = vulnerability.get("database_specific", {})
    if not isinstance(database_specific, dict):
        return ""
    value = database_specific.get("severity", "")
    return str(value).upper()


def severity(vulnerability):
    if any(identifier.startswith("MAL-") for identifier in identifiers_for(vulnerability)):
        return "CRITICAL"
    return scanner_severity(vulnerability) or "UNKNOWN"


def version_key(version):
    return tuple(
        (0, int(part)) if part.isdigit() else (1, part.lower())
        for part in re.split(r"[.\-+]", str(version))
        if part
    )


def compare_versions(left, right):
    left_key, right_key = version_key(left), version_key(right)
    return (left_key > right_key) - (left_key < right_key)


def fixed_version(vulnerability, ecosystem, name, installed):
    contained, later = [], []
    for affected in vulnerability.get("affected", []):
        package = affected.get("package", {})
        if (
            str(package.get("ecosystem", "")).lower() != str(ecosystem).lower()
            or str(package.get("name", "")).lower() != str(name).lower()
        ):
            continue
        for vulnerability_range in affected.get("ranges", []):
            active = False
            for event in vulnerability_range.get("events", []):
                if "introduced" in event:
                    try:
                        active = event["introduced"] == "0" or compare_versions(event["introduced"], installed) <= 0
                    except (TypeError, ValueError):
                        active = False
                if "fixed" in event:
                    try:
                        if compare_versions(installed, event["fixed"]) < 0:
                            later.append(event["fixed"])
                            if active:
                                contained.append(event["fixed"])
                    except (TypeError, ValueError):
                        pass
                    active = False
                if "last_affected" in event:
                    try:
                        active = active and compare_versions(installed, event["last_affected"]) <= 0
                    except (TypeError, ValueError):
                        active = False
    candidates = contained or later
    return min(candidates, key=version_key) if candidates else "none"


def parse_toml_string(value, path, line_number):
    if not value.startswith('"'):
        raise GateError("ignore value in %s:%d must be a TOML string" % (path, line_number))
    try:
        parsed = ast.literal_eval(value)
    except (SyntaxError, ValueError) as error:
        raise GateError("invalid TOML string in %s:%d" % (path, line_number)) from error
    if not isinstance(parsed, str):
        raise GateError("ignore value in %s:%d must be a string" % (path, line_number))
    return parsed


def remove_toml_comment(line):
    quoted = False
    escaped = False
    for index, character in enumerate(line):
        if escaped:
            escaped = False
        elif character == "\\" and quoted:
            escaped = True
        elif character == '"':
            quoted = not quoted
        elif character == "#" and not quoted:
            return line[:index]
    return line


def parse_ignore_config(path):
    try:
        content = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    except OSError as error:
        raise GateError("cannot read ignore file %s: %s" % (path, error)) from error

    entries = []
    current = None
    assignment = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$")
    for line_number, raw_line in enumerate(content.splitlines(), 1):
        line = remove_toml_comment(raw_line).strip()
        if not line:
            continue
        if line == "[[ignore]]":
            if current is not None:
                entries.append(current)
            current = {"_line": line_number}
            continue
        match = assignment.match(line)
        if current is None or not match:
            raise GateError("invalid ignore configuration at %s:%d" % (path, line_number))
        key, value = match.groups()
        if key in current:
            raise GateError("duplicate ignore field %s at %s:%d" % (key, path, line_number))
        current[key] = parse_toml_string(value, path, line_number)
    if current is not None:
        entries.append(current)
    return entries


def load_ignores(path, today=None, warn=None):
    today = today or date.today()
    warn = warn or (lambda message: print("::warning::%s" % message))
    rules = []
    for entry in parse_ignore_config(path):
        line = entry.pop("_line")
        missing = [field for field in ("id", "reason", "until") if not entry.get(field)]
        if missing:
            raise GateError("ignore at %s:%d missing %s" % (path, line, ", ".join(missing)))
        try:
            until = date.fromisoformat(entry["until"])
        except ValueError as error:
            raise GateError("ignore %s has invalid until date" % entry["id"]) from error
        if until > today + timedelta(days=90):
            raise GateError("ignore %s expires more than 90 days ahead" % entry["id"])
        if until < today:
            warn("Ignore %s expired on %s and no longer applies" % (entry["id"], until.isoformat()))
            continue
        rules.append({"id": entry["id"], "reason": entry["reason"], "until": until})
    return rules


def advisory_from_osv(identifier):
    url = OSV_VULNERABILITY_URL + urllib.parse.quote(identifier, safe="")
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            return json.load(response)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise GateError("OSV query failed for %s: %s" % (identifier, type(error).__name__)) from error


def location_for(result, package):
    source = result.get("source", {}) if isinstance(result.get("source"), dict) else {}
    for value in (
        package.get("layer"),
        package.get("layer_id"),
        package.get("path"),
        source.get("path"),
        source.get("name"),
        source.get("image"),
    ):
        if value:
            return str(value)
    locations = package.get("locations", [])
    if locations:
        first = locations[0]
        return str(first.get("path", first)) if isinstance(first, dict) else str(first)
    return "unknown"


def scan_packages(scan):
    results = scan.get("results")
    if not isinstance(results, list):
        raise GateError("scanner JSON has no results list")
    for result in results:
        if not isinstance(result, dict):
            raise GateError("scanner JSON contains an invalid result")
        packages = result.get("packages", [])
        if not isinstance(packages, list):
            raise GateError("scanner JSON contains invalid packages")
        for package_record in packages:
            if not isinstance(package_record, dict):
                raise GateError("scanner JSON contains an invalid package")
            package = package_record.get("package", {})
            vulnerabilities = package_record.get("vulnerabilities", [])
            if not isinstance(package, dict) or not isinstance(vulnerabilities, list):
                raise GateError("scanner JSON contains invalid vulnerability data")
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict) or not vulnerability.get("id"):
                    raise GateError("scanner JSON contains an invalid advisory")
                yield result, package_record, package, vulnerability


def evaluate_scan(scan, ignores, fetch_advisory=advisory_from_osv):
    cache = {}
    findings = []
    for result, package_record, package, vulnerability in scan_packages(scan):
        advisory = vulnerability
        identifier = str(vulnerability["id"])
        if not scanner_severity(vulnerability):
            if identifier not in cache:
                cache[identifier] = fetch_advisory(identifier)
            fetched = cache[identifier]
            if not isinstance(fetched, dict):
                raise GateError("OSV query returned invalid data for %s" % identifier)
            advisory = fetched
        finding_identifiers = identifiers_for(vulnerability) | identifiers_for(advisory)
        ignored = next((rule for rule in ignores if rule["id"] in finding_identifiers), None)
        name = str(package.get("name", "unknown"))
        ecosystem = str(package.get("ecosystem", ""))
        installed = str(package.get("version", package_record.get("version", "unknown")))
        summary = str(advisory.get("summary") or vulnerability.get("summary") or "No summary")
        finding = {
            "severity": severity(advisory),
            "id": canonical_id(advisory),
            "package": name,
            "installed": installed,
            "fixed": fixed_version(advisory, ecosystem, name, installed),
            "location": location_for(result, package_record),
            "summary": " ".join(summary.split()),
            "ignored": ignored,
        }
        findings.append(finding)
    return sorted(
        findings,
        key=lambda item: (item["severity"] not in BLOCKING_SEVERITIES, item["severity"] != "CRITICAL", item["id"], item["package"], item["location"]),
    )


def markdown_cell(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def write_summary(path, findings):
    if not path:
        return
    lines = [
        "## Security gate",
        "",
        "| Severity | ID | Package | Installed | Fixed | File or layer | Summary | Status |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    if not findings:
        lines.append("| — | — | — | — | — | — | No vulnerabilities found | pass |")
    for finding in findings:
        if finding["ignored"]:
            status = "ignored until %s: %s" % (finding["ignored"]["until"], finding["ignored"]["reason"])
        elif finding["severity"] in BLOCKING_SEVERITIES:
            status = "blocking"
        else:
            status = "non-blocking"
        lines.append(
            "| %s | %s | %s | %s | %s | %s | %s |"
            % tuple(markdown_cell(finding[field]) for field in ("severity", "id", "package", "installed", "fixed", "location", "summary"))
            + " %s |" % markdown_cell(status)
        )
    try:
        with open(path, "a", encoding="utf-8") as summary:
            summary.write("\n".join(lines) + "\n")
    except OSError as error:
        raise GateError("cannot write step summary: %s" % error) from error


def annotation_escape(value):
    return str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def emit_annotations(findings):
    blocking = []
    for finding in findings:
        if finding["ignored"] or finding["severity"] not in BLOCKING_SEVERITIES:
            continue
        blocking.append(finding)
        print(
            "::error title=%s %s in %s::installed %s; fixed version: %s; %s"
            % (
                annotation_escape(finding["severity"]),
                annotation_escape(finding["id"]),
                annotation_escape(finding["package"]),
                annotation_escape(finding["installed"]),
                annotation_escape(finding["fixed"]),
                annotation_escape(finding["location"]),
            )
        )
    return blocking


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="osv-scanner JSON output")
    parser.add_argument("--config", required=True, help="optional ignore TOML file")
    args = parser.parse_args(argv)
    try:
        with open(args.input, encoding="utf-8") as source:
            scan = json.load(source)
        ignores = load_ignores(args.config)
        findings = evaluate_scan(scan, ignores)
        write_summary(os.environ.get("GITHUB_STEP_SUMMARY"), findings)
        return 1 if emit_annotations(findings) else 0
    except (OSError, json.JSONDecodeError, GateError) as error:
        print("::error::security-gate failed: %s" % annotation_escape(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
