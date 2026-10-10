import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "tools/audit_bundle.py"
SPEC = importlib.util.spec_from_file_location("bundle_audit", SCRIPT)
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class BundleAuditTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name).resolve() / "workspace"
        self.workspace.mkdir()

    def write_elf(self, path, elf_class=2, machine=183):
        header = bytearray(64 if elf_class == 2 else 52)
        header[:4] = b"\x7fELF"
        header[4:7] = bytes((elf_class, 1, 1))
        struct.pack_into("<HH", header, 16, 3, machine)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(header)
        return path

    def test_elf_arm64_and_arm32_header_offsets(self):
        for elf_class, bits, machine, name in ((2, 64, 183, "AArch64"), (1, 32, 40, "ARM")):
            with self.subTest(bits=bits):
                path = self.write_elf(self.workspace / f"elf{bits}", elf_class, machine)
                result = AUDIT.elf_header(path)
                self.assertEqual((result["class"], result["machine"], result["machine_name"]), (bits, machine, name))
                self.assertEqual(result["machine_field_offset"], 18)
                self.assertTrue(result["header_only"])

    def test_invalid_or_truncated_elf_rejected(self):
        path = self.workspace / "invalid"
        for content in (b"not ELF", b"\x7fELF\x02\x01" + bytes(24), b"\x7fELF\x03\x01" + bytes(60)):
            path.write_bytes(content)
            with self.assertRaises(AUDIT.AuditError):
                AUDIT.elf_header(path)

    def test_output_escape_rejected(self):
        root = self.workspace / "root-manager"
        root.mkdir()
        with self.assertRaises(AUDIT.AuditError):
            AUDIT.bounded_path(self.workspace / "outside.json", root)

    def test_expected_binary_inventory_reports_missing_arm32(self):
        exploit = self.workspace / "exploit"
        for name in AUDIT.EXPECTED_BINARIES[:2]:
            self.write_elf(AUDIT.external_root(self.workspace) / "exploit/build" / name)
        inventory = AUDIT.binary_inventory(exploit, self.workspace)
        self.assertEqual([entry["status"] for entry in inventory], ["present", "present", "missing"])
        self.assertEqual(inventory[0]["bytes"], 64)
        self.assertEqual(len(inventory[0]["sha256"]), 64)
        self.assertTrue(inventory[2]["path"].endswith("cve-2026-43499-32"))
        self.assertEqual(inventory[0]["original_path"], "exploit/build/cve-2026-43499")
        self.assertFalse((exploit / "build").exists())

    def test_source_snapshots_detect_change_addition_and_removal(self):
        source = self.workspace / "source"
        source.mkdir()
        first = source / "main.c"
        first.write_bytes(b"original")
        before = AUDIT.snapshot_tree(source, self.workspace)
        self.assertTrue(AUDIT.compare_snapshots(before, AUDIT.snapshot_tree(source, self.workspace))["unchanged"])
        first.write_bytes(b"changed")
        changed = AUDIT.compare_snapshots(before, AUDIT.snapshot_tree(source, self.workspace))
        self.assertEqual(changed["changed_paths"], ["source/main.c"])
        first.unlink()
        (source / "other.c").write_bytes(b"new")
        changed = AUDIT.compare_snapshots(before, AUDIT.snapshot_tree(source, self.workspace))
        self.assertEqual(changed["changed_paths"], ["source/main.c", "source/other.c"])

    def test_relocated_binary_verification_rejects_hash_size_and_presence_changes(self):
        exploit = self.workspace / AUDIT.EXPLOIT
        build = AUDIT.external_root(self.workspace) / AUDIT.EXPLOIT / "build"
        for name in AUDIT.EXPECTED_BINARIES[:2]:
            self.write_elf(build / name)
        records = AUDIT.binary_inventory(exploit, self.workspace)
        self.assertEqual(AUDIT.verify_binary_inventory(records, self.workspace), 2)
        binary = build / AUDIT.EXPECTED_BINARIES[0]
        original = binary.read_bytes()
        for changed in (original[:-1] + b"\xff", original + b"extra"):
            binary.write_bytes(changed)
            with self.assertRaisesRegex(AUDIT.AuditError, "does not match"):
                AUDIT.verify_binary_inventory(records, self.workspace)
        binary.write_bytes(original)
        self.write_elf(build / AUDIT.EXPECTED_BINARIES[2], 1, 40)
        with self.assertRaisesRegex(AUDIT.AuditError, "Previously missing"):
            AUDIT.verify_binary_inventory(records, self.workspace)

    def test_offset_mismatches_report_observed_values_without_derivation(self):
        target = self.workspace / AUDIT.TARGET
        target.parent.mkdir(parents=True)
        target.write_text('#define BUILD_FINGERPRINT "historical/exact:14/build:user/release-keys"\n'
                          '#define PWQ_NR_ACTIVE_OFF 0x58\n#define PWQ_MAX_ACTIVE_OFF 0x5c\n', encoding="utf-8")
        profile = self.workspace / AUDIT.PROFILE
        profile.parent.mkdir(parents=True)
        profile.write_text("PWQ_NR_ACTIVE 0x24\nPWQ_MAX_ACTIVE 0x28\n", encoding="utf-8")
        observed = AUDIT.target_observations(self.workspace)
        self.assertEqual(len(observed["stale_documented_offsets"]), 2)
        self.assertEqual(observed["stale_documented_offsets"][0]["current_header"], "0x58")
        self.assertFalse(observed["new_offsets_derived"])
        self.assertFalse(observed["live_device_fingerprint_verified"])
        self.assertEqual(observed["target_header_evidence"]["matches"][0]["line"], 1)

    def test_reference_commands_only_compile_absolute_source_paths(self):
        exploit = self.workspace / "exploit"
        stage = self.workspace / "stage"
        commands = AUDIT.reference_commands(self.workspace / "clang.exe", self.workspace / "sysroot", exploit, stage)
        self.assertEqual([name for name, _ in commands], list(AUDIT.EXPECTED_BINARIES))
        self.assertIn("--target=aarch64-linux-android34", commands[0][1])
        self.assertIn("--target=armv7a-linux-androideabi28", commands[2][1])
        self.assertIn("-static", commands[2][1])
        for name, command in commands:
            self.assertEqual(command[command.index("-o") + 1], str(stage / name))
            self.assertEqual(command[0], str(self.workspace / "clang.exe"))

    def test_reference_compilation_records_external_artifacts(self):
        ndk = self.workspace / "ndk"
        toolchain = ndk / "toolchains/llvm/prebuilt/windows-x86_64"
        (toolchain / "bin").mkdir(parents=True)
        (toolchain / "sysroot").mkdir()
        (toolchain / "bin/clang.exe").write_bytes(b"synthetic compiler")
        (ndk / "source.properties").write_text(f"Pkg.Revision = {AUDIT.NDK_REVISION}\n")
        output = AUDIT.external_root(self.workspace) / "root-manager/build"

        def fake_compile(command, **options):
            artifact = Path(command[command.index("-o") + 1])
            arm32 = artifact.name == AUDIT.EXPECTED_BINARIES[2]
            self.write_elf(artifact, 1 if arm32 else 2, 40 if arm32 else 183)
            return subprocess.CompletedProcess(command, 0, "synthetic output")

        with patch.object(AUDIT.subprocess, "run", side_effect=fake_compile):
            report = AUDIT.compile_reference(ndk, self.workspace / "exploit", output, self.workspace)
        self.assertTrue(report["success"])
        self.assertTrue(Path(report["stage"]).is_relative_to(output))
        self.assertFalse(report["binaries_executed"])
        for result in report["results"]:
            record = result["artifact"]
            artifact = Path(record["path_root"]) / record["path"]
            self.assertTrue(artifact.is_relative_to(output))
            self.assertEqual(record["sha256"], AUDIT.digest_file(artifact))
        with self.assertRaises(AUDIT.AuditError):
            AUDIT.compile_reference(ndk, self.workspace / "exploit", self.workspace / "build", self.workspace)

    def test_raw_logs_absence_has_specific_selection_and_path(self):
        bundle = self.workspace / AUDIT.BUNDLE
        bundle.mkdir(parents=True)
        (bundle / "REPORT.md").write_text("historical runtime excerpt", encoding="utf-8")
        observation = AUDIT.runtime_log_observation(self.workspace)
        self.assertFalse(observation["raw_runtime_log_match_found"])
        self.assertEqual(observation["scanned_directory"], AUDIT.BUNDLE.as_posix())
        (bundle / "exp32.log").write_text("synthetic log", encoding="utf-8")
        observation = AUDIT.runtime_log_observation(self.workspace)
        self.assertTrue(observation["raw_runtime_log_match_found"])
        self.assertFalse(observation["content_validated_as_runtime_log"])

    def test_audit_preserves_failed_compile_report_and_original_inputs(self):
        target = self.workspace / AUDIT.TARGET
        target.parent.mkdir(parents=True)
        target.write_text('#define BUILD_FINGERPRINT "synthetic"\n', encoding="utf-8")
        profile = self.workspace / AUDIT.PROFILE
        profile.parent.mkdir(parents=True)
        profile.write_text("synthetic profile", encoding="utf-8")
        root = self.workspace / "root-manager"
        root.mkdir()
        output = root / "evidence/source-audit.json"
        original_hash = AUDIT.digest_file(target)
        with patch.object(AUDIT, "compile_reference", return_value={"success": False, "results": []}) as compile_mock:
            with self.assertRaisesRegex(AUDIT.AuditError, "compilation failed"):
                AUDIT.audit(output, self.workspace / "ndk", True, self.workspace, root)
        self.assertEqual(compile_mock.call_args.args[2], AUDIT.external_root(self.workspace) / "root-manager/build")
        report = json.loads(output.read_text(encoding="utf-8"))
        self.assertFalse(report["reference_compilation"]["success"])
        self.assertTrue(report["original_tree_integrity"]["unchanged"])
        self.assertFalse(report["device_commands_run"])
        self.assertEqual(AUDIT.digest_file(target), original_hash)
        with self.assertRaisesRegex(AUDIT.AuditError, "Preserve existing report"):
            AUDIT.audit(output, workspace=self.workspace, root=root)


if __name__ == "__main__":
    unittest.main()
