#!/usr/bin/env python3
"""Fetch the JVM-only test dependency into `.local/testdeps`.

The jar is never committed and never packaged in the APK. `tests/testdeps.json` pins the URL,
size and SHA-256; a mismatch fails the run.
"""

import hashlib
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests" / "testdeps.json"
TARGET = ROOT / ".local" / "testdeps"


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def fetch(manifest=MANIFEST, target=TARGET):
    entries = json.loads(Path(manifest).read_text(encoding="utf-8"))
    if not entries:
        raise ValueError("tests/testdeps.json lists no dependencies")
    Path(target).mkdir(parents=True, exist_ok=True)
    for entry in entries:
        destination = Path(target) / entry["file"]
        if destination.is_file() and digest(destination) == entry["sha256"]:
            print(f"Present: {destination}")
            continue
        with urllib.request.urlopen(entry["url"], timeout=120) as response:
            payload = response.read()
        if len(payload) != entry["bytes"]:
            raise ValueError(f"{entry['file']}: expected {entry['bytes']} bytes, got {len(payload)}")
        actual = hashlib.sha256(payload).hexdigest()
        if actual != entry["sha256"]:
            raise ValueError(f"{entry['file']}: sha256 mismatch (expected {entry['sha256']}, got {actual})")
        destination.write_bytes(payload)
        print(f"Fetched: {destination} ({actual})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(fetch())
    except Exception as error:  # noqa: BLE001 - the CLI reports any fetch failure the same way
        print(f"Dependency fetch failed: {error}", file=sys.stderr)
        sys.exit(1)
