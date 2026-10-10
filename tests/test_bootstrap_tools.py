import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"tools/{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build = load("build_bootstrap")
preflight = load("bootstrap_preflight")


class BootstrapToolTests(unittest.TestCase):
    def test_unauthorized_inventory_never_reaches_shell(self):
        result = subprocess.CompletedProcess([], 0, "List of devices attached\nOWN unauthorized transport_id:1\n", "")
        with tempfile.TemporaryDirectory() as folder:
            adb = Path(folder) / "adb.exe"
            adb.write_bytes(b"test")
            with patch.object(preflight.subprocess, "run", return_value=result) as run:
                report = preflight.inspect(adb, "OWN")
        self.assertEqual(run.call_count, 1)
        self.assertEqual(report["transport_state"], "unauthorized")
        self.assertFalse(report["bootstrap_ready"])
        self.assertFalse(report["root_executed"])
        self.assertEqual(report["live"], {})

    def test_other_authorized_device_does_not_authorize_requested_serial(self):
        self.assertEqual(preflight.device_state("OTHER device\nOWN unauthorized\n", "OWN"), "unauthorized")
        self.assertEqual(preflight.device_state("OTHER device\n", "OWN"), "not_listed")

    def test_shell_failure_stops_remaining_probes(self):
        responses = [subprocess.CompletedProcess([], 0, "OWN device\n", ""),
                     subprocess.CompletedProcess([], 1, "", "unauthorized")]
        with tempfile.TemporaryDirectory() as folder:
            adb = Path(folder) / "adb.exe"
            adb.write_bytes(b"test")
            with patch.object(preflight.subprocess, "run", side_effect=responses) as run:
                report = preflight.inspect(adb, "OWN")
        self.assertEqual(run.call_count, 2)
        self.assertEqual(report["transport_state"], "shell_probe_failed")
        self.assertFalse(report["bootstrap_ready"])

    def test_serial_injection_rejected_before_process(self):
        with patch.object(preflight.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                preflight.inspect("missing", "OWN;reboot")
        run.assert_not_called()

    def test_invalid_ndk_revision_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "source.properties").write_text("Pkg.Revision = 1.2.3\n")
            with self.assertRaises(ValueError):
                build.validate_ndk(folder)

    def test_elf_wrong_architecture_or_class_rejected(self):
        elf = bytearray(64)
        elf[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HH", elf, 16, 3, 183)
        build.arm64_executable(elf)
        struct.pack_into("<H", elf, 18, 62)
        with self.assertRaises(ValueError):
            build.arm64_executable(elf)
        with self.assertRaises(ValueError):
            build.arm64_executable(b"not elf")

    def test_build_output_escape_rejected_before_compilation(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(build.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    build.build("unused", folder)
            run.assert_not_called()

    def test_internal_bootstrap_output_rejected_and_external_default_accepted(self):
        with patch.object(build, "validate_ndk", side_effect=ValueError("synthetic tool validation")) as validate:
            for output in (build.ROOT / "build", build.BUILD_ROOT):
                with self.subTest(output=output), self.assertRaisesRegex(ValueError, "Output"):
                    build.build("unused", output)
            validate.assert_not_called()
            with self.assertRaisesRegex(ValueError, "synthetic tool validation"):
                build.build("unused", build.DEFAULT_OUTPUT)
            validate.assert_called_once_with("unused")


if __name__ == "__main__":
    unittest.main()
