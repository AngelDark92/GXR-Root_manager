#!/usr/bin/env python3
"""Fail the run when the version sources disagree.

Checked sources:

* `tools/build_root.py` `VERSION` (the single source of truth),
* `app/AndroidManifest.xml` `android:versionName="<version>-root"`,
* an optional pushed tag `v<version>`.

No device access, no network.
"""

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TAG_RE = re.compile(r"v(\d+\.\d+\.\d+)\Z")


def check(tag=None, root=ROOT):
    sys.path.insert(0, str(root / "tools"))
    import release_policy

    version = release_policy.read_version(root)
    code, manifest_version = release_policy.read_manifest(root)
    if manifest_version != version:
        raise release_policy.PolicyError(
            f"AndroidManifest versionName {manifest_version} does not match source {version}")
    if code < 1:
        raise release_policy.PolicyError("AndroidManifest versionCode must be positive")
    if tag:
        match = TAG_RE.match(tag)
        if not match:
            raise release_policy.PolicyError(f"tag {tag!r} is not v<x.y.z>")
        if match.group(1) != version:
            raise release_policy.PolicyError(f"tag {tag} does not match source version {version}")
    print(f"Version sources agree: {version} (versionCode {code})"
          + (f", tag {tag}" if tag else ""))
    return 0


def main():
    parser = argparse.ArgumentParser(description="Verify every root-manager version source agrees")
    parser.add_argument("--tag", help="pushed tag to compare against the source version")
    arguments = parser.parse_args()
    try:
        return check(arguments.tag)
    except Exception as error:  # noqa: BLE001 - the CLI reports any policy failure the same way
        print(f"Version check failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
