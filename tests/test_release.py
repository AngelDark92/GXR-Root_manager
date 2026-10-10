"""Release policy and version-source tests. No network, no device, no build tools."""

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


POLICY = load("release_policy", ROOT / "tools/release_policy.py")
sys.path.insert(0, str(ROOT / "tools"))
VERIFIER = load("verify_release_version", ROOT / "tools/verify_release_version.py")

MANIFEST = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
    '    package="dev.galaxyxr.rootmanager" android:versionCode="{code}" '
    'android:versionName="{version}-root">\n'
    '</manifest>\n'
)


class SyntheticRoot:
    def __init__(self, version="0.3.5", code=11, manifest_version=None):
        self.temporary = tempfile.TemporaryDirectory(prefix="gxr-release-")
        self.root = Path(self.temporary.name)
        (self.root / "tools").mkdir()
        (self.root / "app").mkdir()
        (self.root / "tools/build_root.py").write_text(
            f'ROOT = Path(__file__).resolve().parents[1]\nVERSION = "{version}"\n', encoding="utf-8")
        (self.root / "app/AndroidManifest.xml").write_text(
            MANIFEST.format(code=code, version=manifest_version or version), encoding="utf-8")

    def cleanup(self):
        self.temporary.cleanup()


class PolicyMathTests(unittest.TestCase):
    def test_bump_moves_the_right_component(self):
        self.assertEqual(POLICY.bump("0.3.5", "patch"), "0.3.6")
        self.assertEqual(POLICY.bump("0.3.5", "minor"), "0.4.0")
        self.assertEqual(POLICY.bump("0.3.5", "major"), "1.0.0")

    def test_unknown_delta_is_rejected(self):
        with self.assertRaises(POLICY.PolicyError):
            POLICY.bump("0.3.5", "tweak")

    def test_requested_delta_takes_the_highest_prefix(self):
        self.assertEqual(POLICY.requested_delta(["fix: a"]), "patch")
        self.assertEqual(POLICY.requested_delta(["fix: a", "feat: b"]), "minor")
        self.assertEqual(POLICY.requested_delta(["fix: a", "rework: c", "feat: b"]), "major")

    def test_only_known_prefixes_bump(self):
        self.assertEqual(POLICY.requested_delta(["docs: a", "chore: b", "test: c"]), None)

    def test_scoped_and_bang_prefixes_are_recognized(self):
        self.assertEqual(POLICY.requested_delta(["fix(ci): a"]), "patch")
        self.assertEqual(POLICY.requested_delta(["feat(ui): b"]), "minor")
        self.assertEqual(POLICY.requested_delta(["rework(api): c"]), "major")
        self.assertEqual(POLICY.requested_delta(["fix(ci)!: d"]), "patch")
        self.assertEqual(POLICY.requested_delta(["fixed: a", "fixes: b"]), None)

    def test_release_commits_never_trigger_another_bump(self):
        self.assertEqual(
            POLICY.requested_delta(["chore(release): v0.3.6", "Release-source: 1234"]), None)

    def test_changelog_groups_commits_and_skips_release_commits(self):
        section = POLICY.changelog_section(
            "0.3.6", "minor", ["feat: new thing", "fix: a bug", "chore(release): v0.3.6"], "2026-10-10")
        self.assertIn("## [0.3.6] - 2026-10-10", section)
        self.assertIn("### Features", section)
        self.assertIn("- feat: new thing", section)
        self.assertIn("### Fixes", section)
        self.assertNotIn("chore(release)", section)

    def test_changelog_groups_scoped_fix_commits_under_fixes(self):
        section = POLICY.changelog_section(
            "0.3.6", "patch", ["fix(ci): runner temp"], "2026-10-10")
        self.assertIn("### Fixes", section)
        self.assertIn("- fix(ci): runner temp", section)
        self.assertIn("- Release bump policy: patch.", section)


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.policy = POLICY
        self.calls = {}
        self.original = (POLICY.read_version, POLICY.newest_tag, POLICY.commit_subjects)

        def read_version(root=POLICY.ROOT):
            return self.calls["current"]

        def newest_tag():
            return self.calls.get("newest")

        def commit_subjects(since=None):
            return self.calls.get("subjects", [])

        POLICY.read_version = read_version
        POLICY.newest_tag = newest_tag
        POLICY.commit_subjects = commit_subjects
        self.addCleanup(self.restore)

    def restore(self):
        POLICY.read_version, POLICY.newest_tag, POLICY.commit_subjects = self.original

    def test_first_release_publishes_the_source_version_unchanged(self):
        self.calls.update(current="0.3.5", newest=None)
        decision = POLICY.plan(ref="refs/heads/main")
        self.assertTrue(decision["publish"])
        self.assertFalse(decision["bump"])
        self.assertEqual(decision["version"], "0.3.5")
        self.assertEqual(decision["tag"], "v0.3.5")

    def test_source_ahead_of_newest_tag_publishes_without_bumping_again(self):
        self.calls.update(current="0.3.6", newest="0.3.5", subjects=["feat: thing"])
        decision = POLICY.plan(ref="refs/heads/main")
        self.assertTrue(decision["publish"])
        self.assertFalse(decision["bump"])
        self.assertEqual(decision["version"], "0.3.6")

    def test_matching_tag_and_bump_commit_advances_the_version(self):
        self.calls.update(current="0.3.5", newest="0.3.5", subjects=["feat: thing"])
        decision = POLICY.plan(ref="refs/heads/main")
        self.assertTrue(decision["publish"])
        self.assertTrue(decision["bump"])
        self.assertEqual(decision["version"], "0.4.0")

    def test_no_bump_commits_publishes_nothing(self):
        self.calls.update(current="0.3.5", newest="0.3.5", subjects=["chore: tidy"])
        decision = POLICY.plan(ref="refs/heads/main")
        self.assertFalse(decision["publish"])
        self.assertFalse(decision["bump"])

    def test_source_behind_the_newest_tag_publishes_nothing(self):
        self.calls.update(current="0.3.4", newest="0.3.5")
        decision = POLICY.plan(ref="refs/heads/main")
        self.assertFalse(decision["publish"])

    def test_pull_requests_and_feature_branches_are_dry_runs(self):
        self.calls.update(current="0.3.5", newest="0.3.5", subjects=["feat: thing"])
        for ref in ("refs/pull/7/merge", "refs/heads/dev"):
            with self.subTest(ref=ref):
                self.assertFalse(POLICY.plan(ref=ref)["publish"])

    def test_dispatch_publishes_the_source_version_and_ignores_branches(self):
        self.calls.update(current="0.3.5", newest="0.3.5", subjects=["feat: thing"])
        decision = POLICY.plan(ref="refs/heads/dev", dispatch_publish=True)
        self.assertTrue(decision["publish"])
        self.assertFalse(decision["bump"])
        self.assertEqual(decision["version"], "0.3.5")

    def test_tag_push_publishes_only_the_matching_version(self):
        self.calls.update(current="0.3.5", newest=None)
        decision = POLICY.plan(ref="refs/tags/v0.3.5")
        self.assertTrue(decision["publish"])
        self.assertEqual(decision["version"], "0.3.5")
        with self.assertRaises(POLICY.PolicyError):
            POLICY.plan(ref="refs/tags/v9.9.9")


class VersionSourceTests(unittest.TestCase):
    def test_matching_sources_pass(self):
        synthetic = SyntheticRoot()
        self.addCleanup(synthetic.cleanup)
        self.assertEqual(VERIFIER.check(None, synthetic.root), 0)
        self.assertEqual(VERIFIER.check("v0.3.5", synthetic.root), 0)

    def test_manifest_drift_fails(self):
        synthetic = SyntheticRoot(manifest_version="0.3.4")
        self.addCleanup(synthetic.cleanup)
        with self.assertRaises(POLICY.PolicyError):
            VERIFIER.check(None, synthetic.root)

    def test_tag_drift_fails(self):
        synthetic = SyntheticRoot()
        self.addCleanup(synthetic.cleanup)
        for tag in ("v0.3.4", "0.3.5", "v0.3.5.1"):
            with self.subTest(tag=tag), self.assertRaises(POLICY.PolicyError):
                VERIFIER.check(tag, synthetic.root)

    def test_the_repository_itself_is_consistent(self):
        self.assertEqual(VERIFIER.check(None, ROOT), 0)
        code, manifest_version = POLICY.read_manifest(ROOT)
        self.assertEqual(manifest_version, POLICY.read_version(ROOT))
        self.assertGreaterEqual(code, 1)
        # The version moves with every release; assert the shape, not a pinned value.
        self.assertRegex(POLICY.read_version(ROOT), r"^\d+\.\d+\.\d+$")


class TestDependencyTests(unittest.TestCase):
    def test_pinned_dependency_manifest_is_well_formed(self):
        import json

        entries = json.loads((ROOT / "tests/testdeps.json").read_text(encoding="utf-8"))
        self.assertTrue(entries)
        for entry in entries:
            self.assertRegex(entry["sha256"], r"^[0-9a-f]{64}$")
            self.assertTrue(entry["url"].startswith("https://"))
            self.assertGreater(entry["bytes"], 0)

    def test_fetch_tool_rejects_a_corrupt_manifest(self):
        fetcher = load("fetch_test_deps", ROOT / "tools/fetch_test_deps.py")
        with tempfile.TemporaryDirectory(prefix="gxr-deps-") as folder:
            manifest = Path(folder) / "testdeps.json"
            manifest.write_text("[]", encoding="utf-8")
            with self.assertRaises(ValueError):
                fetcher.fetch(manifest, Path(folder) / "out")

    def test_fetch_tool_verifies_an_existing_jar(self):
        fetcher = load("fetch_test_deps_2", ROOT / "tools/fetch_test_deps.py")
        manifest = fetcher.MANIFEST
        cache = ROOT / ".local/testdeps"
        if not (cache / "json-20240303.jar").is_file():
            self.skipTest("run tools/fetch_test_deps.py once to exercise the cached path")
        self.assertEqual(fetcher.fetch(manifest, cache), 0)


if __name__ == "__main__":
    unittest.main()
