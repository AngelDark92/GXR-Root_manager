#!/usr/bin/env python3
"""Version and publish policy for the standalone Galaxy XR Root Manager repository.

Version truth lives in `tools/build_root.py` (`VERSION`). This module is its only writer;
`tools/verify_release_version.py` fails the run when another source disagrees.

Commit prefixes drive the bump: `fix:` patch, `feat:` minor, `rework:` major; an
optional `(scope)` or `!` sits between the keyword and the colon. Any other prefix bumps
nothing -- project policy, not vanilla Conventional Commits.

Publish gate (design notes: `docs/GitHub-CI-Notes-2026-10-10.md`):

* pushed tag `v<x.y.z>` -- publish only when it equals the source version;
* `refs/heads/main` -- publish when the source version is ahead of the newest `v*` tag, or
  when the commits after that tag ask for a bump. A `chore(release):` commit never counts,
  and a version already ahead of the tag is published as-is, so a re-run cannot double-bump;
* manual dispatch with `publish: true` -- publish the source version unchanged.

Every other push and every pull request is a build-and-test dry run.

Modes:

* default (plan) -- print the decision and write it to `$GITHUB_OUTPUT`;
* `--persist`     -- write the planned version into the sources and the changelog;
* `--commit`      -- deterministic bot commit for the persisted bump, push to `main`;
  pass `--version x.y.z` to commit exactly what the policy step planned.
"""

import argparse
import datetime
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD_ROOT_PY = ROOT / "tools" / "build_root.py"
MANIFEST = ROOT / "app" / "AndroidManifest.xml"
CHANGELOG = ROOT / "CHANGELOG.md"

VERSION_RE = re.compile(r'^VERSION = "(\d+\.\d+\.\d+)"$', re.MULTILINE)
MANIFEST_RE = re.compile(
    r'android:versionCode="(\d+)" android:versionName="(\d+\.\d+\.\d+)-root"')
TAG_RE = re.compile(r"v(\d+\.\d+\.\d+)\Z")

# Driver-compatible subject match (`release-policy.cjs`): an optional `(scope)` and `!`
# may sit between the keyword and the colon.
COMMIT_RE = re.compile(r"^(rework|feat|fix)(?:\([^\r\n)]+\))?!?:\s+\S")
DELTA_BY_TYPE = {"rework": "major", "feat": "minor", "fix": "patch"}
RANK = {"patch": 1, "minor": 2, "major": 3}
GROUPS = (("major", "Reworks"), ("minor", "Features"), ("patch", "Fixes"))
BOT_NAME = "github-actions[bot]"
BOT_MAIL = "41898282+github-actions[bot]@users.noreply.github.com"


class PolicyError(RuntimeError):
    pass


def git(*arguments):
    return subprocess.run(["git", *arguments], cwd=ROOT, capture_output=True,
                          text=True, check=False, timeout=60)


def parse_version(text):
    parts = tuple(int(part) for part in text.split("."))
    if len(parts) != 3:
        raise PolicyError(f"Not a x.y.z version: {text!r}")
    return parts


def format_version(parts):
    return ".".join(str(part) for part in parts)


def bump(version, delta):
    major, minor, patch = parse_version(version)
    if delta == "major":
        return format_version((major + 1, 0, 0))
    if delta == "minor":
        return format_version((major, minor + 1, 0))
    if delta == "patch":
        return format_version((major, minor, patch + 1))
    raise PolicyError(f"Unknown bump delta: {delta!r}")


def read_version(root=ROOT):
    match = VERSION_RE.search((root / "tools" / "build_root.py").read_text(encoding="utf-8"))
    if not match:
        raise PolicyError("tools/build_root.py has no VERSION constant")
    return match.group(1)


def read_manifest(root=ROOT):
    match = MANIFEST_RE.search((root / "app" / "AndroidManifest.xml").read_text(encoding="utf-8"))
    if not match:
        raise PolicyError("AndroidManifest.xml has no versionCode/versionName pair")
    return int(match.group(1)), match.group(2)


def tags_by_version():
    output = git("tag", "--list", "v*").stdout.split()
    found = {}
    for tag in output:
        match = TAG_RE.match(tag)
        if match:
            found[parse_version(match.group(1))] = match.group(1)
    return found


def newest_tag():
    found = tags_by_version()
    return format_version(max(found)) if found else None


def commit_subjects(since_version=None):
    arguments = ["log", "--pretty=%s"]
    if since_version:
        arguments.insert(1, f"v{since_version}..HEAD")
    result = git(*arguments)
    if result.returncode:
        raise PolicyError(f"git log failed: {result.stderr.strip()}")
    return [line for line in result.stdout.splitlines() if line.strip()]


def commit_delta(subject):
    match = COMMIT_RE.match(subject)
    return DELTA_BY_TYPE[match.group(1)] if match else None


def requested_delta(subjects):
    highest = None
    for subject in subjects:
        if subject.startswith("chore(release):"):
            continue
        delta = commit_delta(subject)
        if delta is not None and (highest is None or RANK[delta] > RANK[highest]):
            highest = delta
    return highest


def plan(ref=None, event=None, dispatch_publish=False):
    ref = ref if ref is not None else os.environ.get("GITHUB_REF", "")
    event = event if event is not None else os.environ.get("GITHUB_EVENT_NAME", "")
    current = read_version()
    newest = newest_tag()
    decision = {"current": current, "version": current, "publish": False, "bump": False,
                "tag": f"v{current}", "delta": None, "reason": ""}

    tag_match = TAG_RE.match(ref.removeprefix("refs/tags/")) if ref.startswith("refs/tags/") else None
    if tag_match:
        tagged = tag_match.group(1)
        if tagged != current:
            raise PolicyError(f"tag v{tagged} does not match source version {current}")
        decision["reason"] = f"tag v{tagged} matches the source version"
        decision["publish"] = True
        return decision

    if ref == "refs/heads/main":
        if newest is None:
            decision["reason"] = "first release: no v* tag exists yet"
            decision["publish"] = True
        elif parse_version(current) > parse_version(newest):
            decision["reason"] = f"source {current} is ahead of the newest tag v{newest}"
            decision["publish"] = True
        elif parse_version(current) == parse_version(newest):
            delta = requested_delta(commit_subjects(newest))
            if delta is None:
                decision["reason"] = f"no bump commits since v{newest}"
            else:
                decision["version"] = bump(current, delta)
                decision["tag"] = f"v{decision['version']}"
                decision["delta"] = delta
                decision["bump"] = True
                decision["publish"] = True
                decision["reason"] = f"{delta} bump from commits after v{newest}"
        else:
            decision["reason"] = f"source {current} is behind the newest tag v{newest}"
        return decision

    if dispatch_publish:
        decision["reason"] = "manual dispatch requested publish"
        decision["publish"] = True
        return decision

    decision["reason"] = f"dry run for {ref or event or 'this ref'}"
    return decision


def emit(decision, stream=None):
    stream = stream or os.environ.get("GITHUB_OUTPUT")
    pairs = {"version": decision["version"], "publish": str(decision["publish"]).lower(),
             "bump": str(decision["bump"]).lower(), "tag": decision["tag"],
             "delta": decision["delta"] or "", "reason": decision["reason"]}
    if stream:
        with open(stream, "a", encoding="utf-8") as handle:
            for key, value in pairs.items():
                handle.write(f"{key}={value}\n")
    return pairs


def changelog_section(version, delta, subjects, day):
    lines = [f"## [{version}] - {day}", ""]
    headings = {key: title for key, title in GROUPS}
    grouped = {"major": [], "minor": [], "patch": [], "other": []}
    for subject in subjects:
        if subject.startswith("chore(release):"):
            continue
        kind = commit_delta(subject)
        if kind is None:
            grouped["other"].append(subject)
        else:
            grouped[kind].append(subject)
    if delta:
        grouped[delta].insert(0, f"Release bump policy: {delta}.")
    for key in ("major", "minor", "patch", "other"):
        if not grouped[key]:
            continue
        lines.append(f"### {headings.get(key, 'Other')}")
        lines.extend(f"- {subject}" for subject in grouped[key])
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def persist(decision):
    if not decision["bump"]:
        print("No bump to persist.")
        return 0
    version = decision["version"]
    source = (ROOT / "tools" / "build_root.py").read_text(encoding="utf-8")
    updated, count = VERSION_RE.subn(f'VERSION = "{version}"', source, count=1)
    if count != 1:
        raise PolicyError("Could not rewrite VERSION in tools/build_root.py")
    (ROOT / "tools" / "build_root.py").write_text(updated, encoding="utf-8")

    manifest = MANIFEST.read_text(encoding="utf-8")
    code, _ = read_manifest()
    replaced, count = MANIFEST_RE.subn(
        f'android:versionCode="{code + 1}" android:versionName="{version}-root"',
        manifest, count=1)
    if count != 1:
        raise PolicyError("Could not rewrite the manifest version")
    MANIFEST.write_text(replaced, encoding="utf-8")

    day = datetime.date.today().isoformat()
    subjects = commit_subjects(newest_tag())
    section = changelog_section(version, decision["delta"], subjects, day)
    existing = CHANGELOG.read_text(encoding="utf-8") if CHANGELOG.exists() else "# Changelog\n"
    head, _, tail = existing.partition("\n## [")
    body = section + ("\n## [" + tail if tail else "")
    CHANGELOG.write_text(head.rstrip() + "\n\n" + body, encoding="utf-8")
    print(f"Persisted version {version} (versionCode {code + 1}).")
    return 0


def commit(decision):
    if not decision["bump"]:
        print("No bump to commit.")
        return 0
    sha = os.environ.get("GITHUB_SHA") or git("rev-parse", "HEAD").stdout.strip()
    date = git("show", "-s", "--format=%cI", sha).stdout.strip()
    if not date:
        raise PolicyError("Could not read the source commit date")
    message = f"chore(release): v{decision['version']}\n\nRelease-source: {sha}\n"
    environment = dict(os.environ, GIT_AUTHOR_DATE=date, GIT_COMMITTER_DATE=date)
    steps = [["add", "--", "tools/build_root.py", "app/AndroidManifest.xml", "CHANGELOG.md"],
             ["-c", f"user.name={BOT_NAME}", "-c", f"user.email={BOT_MAIL}",
              "commit", "--allow-empty", "-m", message]]
    for step in steps:
        result = subprocess.run(["git", *step], cwd=ROOT, env=environment, capture_output=True,
                                text=True, timeout=60)
        if result.returncode:
            raise PolicyError(f"git {step[0]} failed: {result.stderr.strip()}")
    fetch = git("fetch", "origin", "main")
    if fetch.returncode:
        raise PolicyError(f"git fetch failed: {fetch.stderr.strip()}")
    ancestor = git("merge-base", "--is-ancestor", "origin/main", "HEAD")
    if ancestor.returncode:
        raise PolicyError("main advanced concurrently; refusing to overwrite it")
    push = git("push", "origin", "HEAD:main")
    if push.returncode:
        raise PolicyError(f"git push failed: {push.stderr.strip()}")
    print(f"Pushed chore(release) commit for v{decision['version']}.")
    return 0


def planned_commit_decision(version):
    """Commit exactly what the policy step planned. Re-planning here would see the
    already-persisted tree as ahead of the previous tag and skip the commit."""
    return {"current": read_version(), "version": version, "publish": True, "bump": True,
            "tag": f"v{version}", "delta": None,
            "reason": "commit the version planned by the policy step"}


def main():
    parser = argparse.ArgumentParser(description="Compute and apply the root-manager release policy")
    parser.add_argument("--persist", action="store_true", help="write the planned version into the sources")
    parser.add_argument("--commit", action="store_true", help="commit and push the persisted bump")
    parser.add_argument("--version", help="the version the policy step planned (use with --commit)")
    parser.add_argument("--ref", help="override GITHUB_REF")
    parser.add_argument("--event", help="override GITHUB_EVENT_NAME")
    parser.add_argument("--dispatch-publish", action="store_true", help="pretend a dispatch asked to publish")
    arguments = parser.parse_args()
    dispatch = arguments.dispatch_publish or (
        (arguments.event or os.environ.get("GITHUB_EVENT_NAME", "")) == "workflow_dispatch"
        and os.environ.get("INPUT_PUBLISH", "").lower() == "true")
    try:
        if arguments.commit and arguments.version:
            return commit(planned_commit_decision(arguments.version))
        decision = plan(arguments.ref, arguments.event, dispatch)
        if arguments.persist:
            return persist(decision)
        if arguments.commit:
            return commit(decision)
        emit(decision)
    except PolicyError as error:
        print(f"Release policy failed: {error}", file=sys.stderr)
        return 1
    print(f"current={decision['current']} version={decision['version']} "
          f"publish={str(decision['publish']).lower()} bump={str(decision['bump']).lower()} "
          f"reason={decision['reason']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
