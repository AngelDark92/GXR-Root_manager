import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
JSON_JAR = ROOT / ".local/testdeps/json-20240303.jar"


class RootStatusTests(unittest.TestCase):
    def test_fresh_authenticated_status_evaluation_with_real_json(self):
        java_home = os.environ.get("JAVA_HOME")
        self.assertTrue(java_home, "Set JAVA_HOME to JDK 17 or newer to run synthetic root-status tests.")
        suffix = ".exe" if os.name == "nt" else ""
        javac = Path(java_home) / "bin" / f"javac{suffix}"
        java = Path(java_home) / "bin" / f"java{suffix}"
        for executable in (javac, java):
            self.assertTrue(executable.is_file(), f"Missing {executable}; set JAVA_HOME to JDK 17 or newer.")
        self.assertTrue(JSON_JAR.is_file(), f"Provide real org.json 20240303 dependency at {JSON_JAR}.")
        with tempfile.TemporaryDirectory(prefix="gxr-root-status-tests-") as temporary:
            classes = Path(temporary) / "classes"
            classes.mkdir()
            compiled = subprocess.run(
                [str(javac), "-encoding", "UTF-8", "-source", "17", "-target", "17",
                 "-cp", str(JSON_JAR), "-d", str(classes),
                 str(ROOT / "app/src/dev/galaxyxr/rootmanager/RootStatus.java"),
                 str(ROOT / "tests/RootStatusTest.java")],
                capture_output=True, text=True, timeout=300, shell=False,  # first javac on a cold CI runner can exceed 60s
            )
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            executed = subprocess.run(
                [str(java), "-cp", os.pathsep.join((str(classes), str(JSON_JAR))),
                 "dev.galaxyxr.rootmanager.RootStatusTest"],
                capture_output=True, text=True, timeout=120, shell=False,
            )
            self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)
            self.assertRegex(executed.stdout, r"Synthetic JVM root status: [1-9][0-9]+ scenarios passed; [1-9][0-9]+ assertions")
            print(executed.stdout.strip())


if __name__ == "__main__":
    unittest.main()
