import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import zipfile

from build import APK_NAME, ROOT, BUILD_ROOT, DEFAULT_OUTPUT, audit_apk, within
from audit_bundle import relocated_input, verify_binary_inventory


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify(ndk, build_tools, java_home, output=DEFAULT_OUTPUT, source_audit=None):
    workspace = ROOT.parent
    output = within(output, BUILD_ROOT)
    if output == BUILD_ROOT.resolve():
        raise ValueError("Select an output directory beneath the external build root")
    receipt = json.loads((output / "build-receipt.json").read_text(encoding="utf-8"))
    apk = output / APK_NAME
    if digest(apk) != receipt["apk_sha256"] or apk.stat().st_size != receipt["apk_bytes"]:
        raise ValueError("APK does not match build receipt")
    for name, expected in receipt["inputs_sha256"].items():
        path = (ROOT / name).resolve()
        if not path.is_relative_to(ROOT) or digest(path) != expected:
            raise ValueError(f"Source does not match build receipt: {name}")
    if digest(ROOT / "tools/build.py") != receipt["builder_sha256"]:
        raise ValueError("Builder does not match build receipt")
    source = json.loads(Path(source_audit or ROOT / "evidence/source-audit.json").read_text(encoding="utf-8"))
    for item in source["original_exploit_files_before"]:
        path = (workspace / item["path"]).resolve()
        if not path.is_relative_to(workspace / "root") or digest(relocated_input(path, workspace)) != item["sha256"]:
            raise ValueError(f"Original bundle changed: {item['path']}")
    supplied_checked = verify_binary_inventory(source["supplied_binary_inventory"], workspace)
    if not source["reference_compilation"]["success"]:
        raise ValueError("Reference compilation was incomplete")
    if receipt["root_execution"] or receipt["device_tests_run"]:
        raise ValueError("Unexpected runtime claim in diagnostic receipt")
    tools = Path(ndk).resolve() / "toolchains/llvm/prebuilt/windows-x86_64/bin"
    stage = Path(receipt["staging_directory"]).resolve()
    if stage.is_relative_to(ROOT / "build"):
        stage = (DEFAULT_OUTPUT / stage.relative_to(ROOT / "build")).resolve()
    if not stage.is_relative_to(output):
        raise ValueError("Staging directory escaped external output directory")
    native = stage / "libgxr_diagnostics.so"
    process = subprocess.run([str(tools / "llvm-nm.exe"), "--dynamic", "--undefined-only", str(native)],
                             check=True, capture_output=True, text=True, timeout=30)
    symbols = {line.split()[-1].split("@")[0] for line in process.stdout.splitlines() if line.strip()}
    prohibited = {"write", "pwrite", "pwrite64", "ioctl", "fork", "vfork", "clone", "execve", "execl",
                  "system", "kill", "syscall", "setuid", "setgid", "setrlimit", "sched_setaffinity"}
    if symbols.intersection(prohibited):
        raise ValueError(f"Unexpected mutation/process imports: {symbols.intersection(prohibited)}")
    names = audit_apk(apk)
    with zipfile.ZipFile(apk) as archive:
        if archive.read("lib/arm64-v8a/libgxr_diagnostics.so") != native.read_bytes():
            raise ValueError("Packaged diagnostic library differs from compiled library")
    java = Path(java_home).resolve() / "bin/java.exe"
    signer_jar = Path(build_tools).resolve() / "lib/apksigner.jar"
    if digest(java) != receipt["tools_sha256"]["java"] or digest(signer_jar) != receipt["tools_sha256"]["apksigner"]:
        raise ValueError("Selected signature tools do not match the build receipt")
    signer = [str(java), "-cp", str(signer_jar), "com.android.apksigner.ApkSignerTool"]
    signature = subprocess.run([*signer, "verify", "--verbose", "--print-certs", str(apk)],
                               check=True, capture_output=True, text=True, timeout=30).stdout
    if "Verifies" not in signature or "Verified using v3 scheme (APK Signature Scheme v3): true" not in signature:
        raise ValueError("APK lacks its expected Android 14-compatible v3 signature")
    report = {
        "apk_sha256": digest(apk), "apk_bytes": apk.stat().st_size,
        "all_receipt_source_hashes_match": True, "original_exploit_tree_unchanged": True,
        "original_exploit_files_checked": len(source["original_exploit_files_before"]),
        "supplied_binary_files_checked": supplied_checked,
        "reference_binaries_compiled": 3, "apk_contains_exploit_payload": False,
        "native_undefined_symbols": sorted(symbols), "forbidden_native_imports": [],
        "signature_verification": signature, "apk_entries": names,
        "device_commands_run": False, "headset_installation_performed": False,
        "root_execution_verified": False, "restoration_verified": False,
    }
    (output / "artifact-validation.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: report[key] for key in (
        "apk_sha256", "apk_bytes", "original_exploit_files_checked", "reference_binaries_compiled",
        "apk_contains_exploit_payload", "device_commands_run")}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify diagnostic APK and retained PC-only evidence; no device operations")
    parser.add_argument("--ndk", type=Path, required=True)
    parser.add_argument("--build-tools", type=Path, required=True)
    parser.add_argument("--java-home", type=Path, default=os.environ.get("JAVA_HOME"))
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--source-audit", type=Path, help="Fresh source audit matching the build inputs")
    args = parser.parse_args()
    if args.java_home is None:
        parser.error("--java-home or JAVA_HOME is required")
    verify(args.ndk, args.build_tools, args.java_home, args.output, args.source_audit)
