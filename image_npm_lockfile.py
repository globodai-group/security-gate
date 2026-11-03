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


class ImageStreamError(Exception):
    """The image filesystem stream is truncated, corrupt, or inconsistent."""


def parse_manifest(data):
    try:
        manifest = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError) as error:
        return None, type(error).__name__
    if not isinstance(manifest, dict):
        return None, "not a JSON object"
    name, version = manifest.get("name"), manifest.get("version")
    if isinstance(name, str) and isinstance(version, str) and name and version:
        return (name, version), None
    return None, None


def stored_manifest(archive, member):
    """Parse a regular file that may be the store copy of a manifest."""
    if member.size > MAX_MANIFEST_BYTES:
        return None, "larger than %d bytes" % MAX_MANIFEST_BYTES
    handle = archive.extractfile(member)
    head = handle.read(64)
    if not head.lstrip(b"\xef\xbb\xbf \t\r\n").startswith(b"{"):
        return None, "not a JSON object"
    return parse_manifest(head + handle.read())


def installed_packages(stream, warn):
    packages = set()
    # bun and pnpm hardlink node_modules files to their store (pnpm names store
    # files by content hash), and a tar stream holds each inode once: later
    # paths are hard links to the first one. Every regular file that can be a
    # manifest is therefore parsed and kept to resolve those links.
    regular = {}
    with tarfile.open(fileobj=stream, mode="r|*") as archive:
        for member in archive:
            if member.isreg():
                regular[member.name] = stored_manifest(archive, member)
                if not is_package_manifest(member.name):
                    continue
                package, problem = regular[member.name]
            elif member.islnk() and is_package_manifest(member.name):
                if member.linkname not in regular:
                    raise ImageStreamError("%s links to %s, which is not earlier in the stream" % (member.name, member.linkname))
                package, problem = regular[member.linkname]
            else:
                continue
            if package:
                packages.add(package)
            elif problem:
                warn("skipped %s: %s" % (member.name, problem))
        # tarfile ends iteration silently at a corrupt header after the first
        # member, so anything but end-of-archive padding left in the stream means
        # members were not read.
        while True:
            chunk = archive.fileobj.read(1024 * 1024)
            if not chunk:
                break
            if chunk.strip(b"\0"):
                raise ImageStreamError("unreadable data after the last tar member")
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


def annotation_escape(value):
    return str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def main(argv=None, stream=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="package-lock.json to write when packages are found")
    args = parser.parse_args(argv)
    warn = lambda message: print("::warning::security-gate image npm: %s" % annotation_escape(message))
    try:
        packages = installed_packages(stream or sys.stdin.buffer, warn)
    except (OSError, tarfile.TarError, ImageStreamError) as error:
        print("::error::security-gate cannot read the image filesystem: %s" % annotation_escape(error), file=sys.stderr)
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
