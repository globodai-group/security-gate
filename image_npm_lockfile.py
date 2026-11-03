#!/usr/bin/env python3
"""Write an npm lockfile listing every package installed in an image filesystem.

osv-scanner v2.7.0 image mode reads npm packages only from
node_modules/.package-lock.json, which bun and pnpm never write, so packages they
install are invisible to it. This reads a `docker export` tar stream from stdin,
takes each regular node_modules/<name>/package.json and
node_modules/@scope/<name>/package.json, and writes a package-lock.json that
osv-scanner scan source can evaluate. Nothing from the image is written to disk.
"""

import argparse
import json
import sys
import tarfile

# osv-scanner skips lockfile entries without a registry "resolved" URL (it treats
# them as local or linked packages), so each entry gets the public registry URL.
REGISTRY_TARBALL = "https://registry.npmjs.org/%s/-/%s-%s.tgz"
# A package.json larger than this is not a real npm manifest and is skipped.
MAX_MANIFEST_BYTES = 1024 * 1024


def is_package_manifest(member_name):
    parts = [part for part in member_name.split("/") if part not in ("", ".")]
    if len(parts) < 3 or parts[-1] != "package.json":
        return False
    if parts[-3] == "node_modules" and not parts[-2].startswith((".", "@")):
        return True
    return len(parts) >= 4 and parts[-4] == "node_modules" and parts[-3].startswith("@") and not parts[-2].startswith(".")


def installed_packages(stream, warn):
    packages = set()
    with tarfile.open(fileobj=stream, mode="r|*") as archive:
        for member in archive:
            if not member.isreg() or not is_package_manifest(member.name):
                continue
            if member.size > MAX_MANIFEST_BYTES:
                warn("skipped %s: larger than %d bytes" % (member.name, MAX_MANIFEST_BYTES))
                continue
            try:
                manifest = json.loads(archive.extractfile(member).read().decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as error:
                warn("skipped %s: %s" % (member.name, type(error).__name__))
                continue
            if not isinstance(manifest, dict):
                continue
            name, version = manifest.get("name"), manifest.get("version")
            if isinstance(name, str) and isinstance(version, str) and name and version:
                packages.add((name, version))
    return sorted(packages)


def lockfile(packages):
    entries = {"": {"name": "image", "version": "0.0.0"}}
    # npm lockfile keys are install paths; a unique path per package keeps every
    # installed version, including several versions of the same name.
    for index, (name, version) in enumerate(packages, 1):
        entries["node_modules/%d/node_modules/%s" % (index, name)] = {
            "name": name,
            "version": version,
            "resolved": REGISTRY_TARBALL % (name, name.split("/")[-1], version),
        }
    return {"name": "image", "version": "0.0.0", "lockfileVersion": 3, "requires": True, "packages": entries}


def main(argv=None, stream=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="package-lock.json to write when packages are found")
    args = parser.parse_args(argv)
    warn = lambda message: print("::warning::security-gate image npm: %s" % message)
    try:
        packages = installed_packages(stream or sys.stdin.buffer, warn)
    except (OSError, tarfile.TarError) as error:
        print("::error::security-gate cannot read the image filesystem: %s" % error, file=sys.stderr)
        return 2
    if not packages:
        print("security-gate: no npm package installed under node_modules in the image")
        return 0
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(lockfile(packages), handle, indent=2)
        handle.write("\n")
    print("security-gate: listed %d npm packages installed under node_modules in the image" % len(packages))
    return 0


if __name__ == "__main__":
    sys.exit(main())
