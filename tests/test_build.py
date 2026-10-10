import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import warnings
import zipfile


SCRIPT = Path(__file__).resolve().parents[1] / "tools/build.py"
SPEC = importlib.util.spec_from_file_location("root_manager_build", SCRIPT)
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


class BuildSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def make_apk(self, names):
        path = self.root / "test.apk"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(path, "w") as archive:
                for name in names:
                    archive.writestr(name, b"diagnostic test")
        return path

    def required(self):
        return ["AndroidManifest.xml", "classes.dex", "lib/arm64-v8a/libgxr_diagnostics.so"]

    def test_source_cannot_escape_project(self):
        with self.assertRaises(BUILD.BuildError):
            BUILD.within(self.root.parent / "outside", self.root)
        self.assertEqual(BUILD.within(self.root / "build", self.root), self.root / "build")

    def test_build_output_rejects_internal_and_unrelated_paths_before_tools(self):
        for output in (BUILD.ROOT / "build", BUILD.BUILD_ROOT, self.root / "outside"):
            with self.subTest(output=output), patch.object(BUILD, "validate_tools") as tools:
                with self.assertRaises(BUILD.BuildError):
                    BUILD.build(SimpleNamespace(output=output))
                tools.assert_not_called()
        self.assertEqual(BUILD.within(BUILD.DEFAULT_OUTPUT, BUILD.BUILD_ROOT), BUILD.DEFAULT_OUTPUT)
        self.assertFalse(BUILD.DEFAULT_OUTPUT.is_relative_to(BUILD.ROOT.parent))

    def test_frozen_inputs_do_not_follow_live_changes(self):
        resource = self.root / "app/res/values/strings.xml"
        resource.parent.mkdir(parents=True)
        resource.write_bytes(b"initial resource")
        expected = {str(resource.relative_to(self.root)): BUILD.sha256(resource)}
        snapshot = BUILD.freeze_inputs(self.root, self.root / "stage", [resource], expected)
        resource.write_bytes(b"changed resource")
        copied = snapshot / resource.relative_to(self.root)
        self.assertEqual(copied.read_bytes(), b"initial resource")
        with self.assertRaises(BUILD.BuildError):
            BUILD.freeze_inputs(self.root, self.root / "stage2", [resource], expected)

    def test_input_inventory_detects_added_resource(self):
        for name in ("app/AndroidManifest.xml", "app/jni/diagnostics.c", "app/src/Main.java", "app/res/values/strings.xml", "native/bootstrap_verifier.c"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"initial")
        before, _, _ = BUILD.collect_inputs(self.root)
        self.assertIn(self.root / "native/bootstrap_verifier.c", before)
        added = self.root / "app/res/values/new.xml"
        added.write_bytes(b"new resource")
        after, _, _ = BUILD.collect_inputs(self.root)
        self.assertNotEqual(set(before), set(after))
        self.assertIn(added, after)

    def test_zip_rejects_traversal_absolute_and_exploit_names(self):
        for name in ("../payload", "/payload", "C:/payload", "assets\\payload",
                     "assets/./file.json", "assets/CVE43499.json", "assets/cve-2026-43499", "assets/GhostLock.txt"):
            with self.subTest(name=name), self.assertRaises(BUILD.BuildError):
                BUILD.safe_zip_name(name)

    def test_audit_requires_all_diagnostic_entries(self):
        with self.assertRaises(BUILD.BuildError):
            BUILD.audit_apk(self.make_apk(["AndroidManifest.xml"]))
        self.assertEqual(BUILD.audit_apk(self.make_apk(self.required())), self.required())

    def test_audit_rejects_duplicates_and_unexpected_native_code(self):
        for extra in ("classes.dex", "lib/arm64-v8a/payload.so", "assets/payload.dex"):
            with self.subTest(extra=extra), self.assertRaises(BUILD.BuildError):
                BUILD.audit_apk(self.make_apk(self.required() + [extra]))

    def test_package_preserves_base_and_adds_diagnostic_files(self):
        base = self.make_apk(["AndroidManifest.xml", "resources.arsc"])
        dex = self.root / "classes.dex"
        native = self.root / "native.so"
        asset = self.root / "capabilities.json"
        for path in (dex, native):
            path.write_bytes(b"diagnostic")
        asset.write_bytes(b'{"diagnostic":true}')
        destination = self.root / "result.apk"
        BUILD.package_apk(base, destination, {
            "classes.dex": dex, "lib/arm64-v8a/libgxr_diagnostics.so": native,
            "assets/capabilities.json": asset,
        })
        with zipfile.ZipFile(destination) as archive:
            self.assertEqual(archive.read("resources.arsc"), b"diagnostic test")
            self.assertEqual(archive.read("assets/capabilities.json"), b'{"diagnostic":true}')

    def test_metadata_assets_reject_disguised_binary_or_invalid_json(self):
        BUILD.validate_asset("target-profile.json", b'{"original":"cve-2026-43499"}')
        for name, data in (("payload.json", b"\x7fELF\x00"), ("payload.md", b"binary\x00text"),
                           ("payload.json", b"not JSON"), ("payload.txt", b"\xff")):
            with self.subTest(name=name, data=data), self.assertRaises(BUILD.BuildError):
                BUILD.validate_asset(name, data)

    def test_package_rejects_collision(self):
        base = self.make_apk(["AndroidManifest.xml", "classes.dex"])
        dex = self.root / "dex"
        dex.write_bytes(b"diagnostic")
        with self.assertRaises(BUILD.BuildError):
            BUILD.package_apk(base, self.root / "result.apk", {"classes.dex": dex})

    def make_tools(self, revision=BUILD.NDK_REVISION):
        ndk = self.root / "ndk"
        ndk.mkdir()
        (ndk / "source.properties").write_text(f"Pkg.Revision = {revision}\n", encoding="utf-8")
        toolchain = ndk / "toolchains/llvm/prebuilt/windows-x86_64"
        (toolchain / "sysroot").mkdir(parents=True)
        build_tools = self.root / "build-tools"
        java_home = self.root / "java"
        files = [self.root / "android.jar", toolchain / "bin/clang.exe",
                 build_tools / "aapt2.exe", build_tools / "zipalign.exe",
                 build_tools / "lib/d8.jar", build_tools / "lib/apksigner.jar"]
        files.extend(java_home / f"bin/{name}.exe" for name in ("java", "javac", "jar", "keytool"))
        for path in files:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"synthetic tool")
        return self.root / "android.jar", build_tools, ndk, java_home

    def test_tool_validation_requires_exact_ndk(self):
        tools = self.make_tools("27.1.12297006")
        with self.assertRaisesRegex(BUILD.BuildError, BUILD.NDK_REVISION):
            BUILD.validate_tools(*tools)

    def test_tool_validation_requires_all_executables(self):
        inputs = self.make_tools()
        tools = BUILD.validate_tools(*inputs)
        self.assertIn("sysroot", tools)
        tools["keytool"].unlink()
        with self.assertRaisesRegex(BUILD.BuildError, "keytool.exe"):
            BUILD.validate_tools(*inputs)

    def test_missing_java_home_fails_before_execution(self):
        with self.assertRaisesRegex(BUILD.BuildError, "JAVA_HOME"):
            BUILD.validate_tools(self.root / "android.jar", self.root, self.root, None)

    def test_java17_and_java21_supported_older_or_unknown_rejected(self):
        BUILD.validate_java_versions('openjdk version "17.0.12"', "javac 17.0.12")
        BUILD.validate_java_versions('java version "21.0.5"', "javac 21.0.5")
        for runtime, compiler in (('java version "11.0.1"', "javac 21"),
                                  ('java version "21"', "javac 11"),
                                  ("unknown", "javac 21")):
            with self.subTest(runtime=runtime, compiler=compiler), self.assertRaises(BUILD.BuildError):
                BUILD.validate_java_versions(runtime, compiler)

    def test_runner_uses_argv_and_environment_password(self):
        runner = BUILD.Runner(self.root)
        with patch.object(BUILD.subprocess, "run") as process:
            process.return_value.stdout = "okay"
            process.return_value.returncode = 0
            self.assertEqual(runner.run(["tool.exe", "argument with spaces"]), "okay")
        arguments, options = process.call_args
        self.assertEqual(arguments[0], ["tool.exe", "argument with spaces"])
        self.assertIs(options["shell"], False)
        self.assertEqual(options["env"][BUILD.PASSWORD_ENV], "android")
        self.assertNotIn("android", runner.commands[0])

    def test_runner_bounds_failed_tool_output(self):
        runner = BUILD.Runner(self.root)
        with patch.object(BUILD.subprocess, "run") as process:
            process.return_value.stdout = "x" * 20000
            process.return_value.returncode = 2
            with self.assertRaises(BUILD.BuildError) as raised:
                runner.run(["tool.exe"])
        self.assertLess(len(str(raised.exception)), 8300)


if __name__ == "__main__":
    unittest.main()
