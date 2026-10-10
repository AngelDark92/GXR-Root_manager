#!/usr/bin/env python3
"""Publish a built APK as a GitHub Release: draft -> upload -> verify checksum -> published.

Idempotent: an already published release for the tag is left alone, a failed upload stays a
draft, and an existing tag is never moved. Requires the GitHub CLI (`gh`) with a
`contents: write` token in `GH_TOKEN`.
"""

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PublishError(RuntimeError):
    pass


def gh(*arguments, check=True):
    result = subprocess.run(["gh", *arguments], cwd=ROOT, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=300, check=False)
    if check and result.returncode:
        raise PublishError(f"gh {' '.join(arguments)} failed: {result.stderr.strip()}")
    return result


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def publish(tag, apk, title=None, notes_file=None):
    apk = Path(apk).resolve()
    if not apk.is_file():
        raise PublishError(f"APK missing: {apk}")
    checksum = apk.with_suffix(apk.suffix + ".sha256")
    expected = digest(apk)
    checksum.write_text(f"{expected}  {apk.name}\n", encoding="utf-8")
    if checksum.read_text(encoding="utf-8").split()[0] != digest(apk):
        raise PublishError("Checksum file does not match the APK bytes")

    view = gh("release", "view", tag, "--json", "isDraft,assets", check=False)
    if view.returncode == 0:
        if '"isDraft":true' not in view.stdout.replace(" ", ""):
            print(f"Release {tag} is already published; nothing to do.")
            return 0
        print(f"Release {tag} is a draft; uploading assets.")
        gh("release", "upload", tag, "--clobber", str(apk), str(checksum))
    else:
        create = ["release", "create", tag, "--title", title or f"Galaxy XR Root Manager {tag}",
                  "--draft"]
        create += (["--notes-file", str(notes_file)] if notes_file
                   else ["--generate-notes"])
        gh(*create, str(apk), str(checksum))

    if checksum.read_text(encoding="utf-8").split()[0] != digest(apk):
        raise PublishError("Uploaded checksum does not match the APK bytes")
    gh("release", "edit", tag, "--draft=false", "--latest")
    print(f"Published {tag} with {apk.name} ({expected})")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Publish a built APK as a GitHub Release")
    parser.add_argument("--tag", required=True, help="release tag, e.g. v0.3.6")
    parser.add_argument("--apk", required=True, type=Path)
    parser.add_argument("--title")
    parser.add_argument("--notes-file", type=Path)
    arguments = parser.parse_args()
    try:
        return publish(arguments.tag, arguments.apk, arguments.title, arguments.notes_file)
    except PublishError as error:
        print(f"Publish failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
