from pathlib import Path
import os
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class SafetyPolicyJvmTests(unittest.TestCase):
    def test_exact_identity_and_disabled_execution(self):
        java_home = Path(os.environ["JAVA_HOME"])
        suffix = ".exe" if os.name == "nt" else ""
        javac = java_home / "bin" / f"javac{suffix}"
        java = java_home / "bin" / f"java{suffix}"
        self.assertTrue(javac.is_file(), f"Missing {javac}; set JAVA_HOME to JDK 17 or newer.")
        with tempfile.TemporaryDirectory(prefix="gxr-policy-") as destination:
            compiled = subprocess.run([
                str(javac), "-encoding", "UTF-8", "-source", "17", "-target", "17",
                "-d", destination,
                str(ROOT / "app/src/dev/galaxyxr/rootmanager/SafetyPolicy.java"),
                str(ROOT / "tests/SafetyPolicyTest.java"),
            ], capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            executed = subprocess.run([
                str(java), "-cp", destination, "SafetyPolicyTest",
            ], capture_output=True, text=True, timeout=60)
            self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)
            self.assertIn("15 checks passed", executed.stdout)


if __name__ == "__main__":
    unittest.main()
