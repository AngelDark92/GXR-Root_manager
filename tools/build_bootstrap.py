"""PC-only NDK build for the read-only root-server verifier; never deploys."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BUILD_ROOT = ROOT.parent.parent / "builds" / ROOT.parent.name / ROOT.name
DEFAULT_OUTPUT = BUILD_ROOT / "build"
NDK_REVISION = "27.2.12479018"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def arm64_executable(data):
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("Expected little-endian ELF64")
    if int.from_bytes(data[18:20], "little") != 183:
        raise ValueError("Expected AArch64 machine")
    if int.from_bytes(data[16:18], "little") != 3:
        raise ValueError("Expected a position-independent executable")


def validate_ndk(ndk):
    ndk = Path(ndk).resolve()
    properties = (ndk / "source.properties").read_text(encoding="utf-8")
    revision = re.search(r"^Pkg\.Revision\s*=\s*(\S+)\s*$", properties, re.MULTILINE)
    if not revision or revision.group(1) != NDK_REVISION:
        raise ValueError(f"Expected NDK {NDK_REVISION}")
    base = ndk / "toolchains/llvm/prebuilt/windows-x86_64"
    compiler = base / "bin/clang.exe"
    if not compiler.is_file() or not (base / "sysroot").is_dir():
        raise ValueError("Missing Windows NDK compiler/sysroot")
    return compiler, base / "sysroot"


def build(ndk, output):
    output = Path(output).resolve()
    build_root = BUILD_ROOT.resolve()
    if not output.is_relative_to(build_root) or output == build_root:
        raise ValueError("Output must be a directory within the external build root")
    compiler, sysroot = validate_ndk(ndk)
    source = ROOT / "native/bootstrap_verifier.c"
    frozen = source.read_bytes()
    output.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="bootstrap-stage-", dir=output))
    snapshot = stage / "bootstrap_verifier.c"
    snapshot.write_bytes(frozen)
    binary = stage / "gxr-bootstrap-verifier"
    command = [str(compiler), "--target=aarch64-linux-android34", f"--sysroot={sysroot}",
               "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fPIE", "-pie",
               "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2",
               "-Wl,-z,relro,-z,now", str(snapshot), "-o", str(binary)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=90)
    (stage / "compiler-output.txt").write_text(result.stdout + result.stderr, encoding="utf-8")
    if result.returncode:
        raise ValueError(f"Compiler failed; retained diagnostics at {stage}")
    if source.read_bytes() != frozen:
        raise ValueError("Source changed during compilation; output not published")
    data = binary.read_bytes()
    arm64_executable(data)
    receipt = {
        "artifact_kind": "root_server_verifier_read_only", "artifact": str(binary),
        "artifact_sha256": digest(data), "artifact_bytes": len(data),
        "source_sha256": digest(frozen), "compiler_sha256": digest(compiler.read_bytes()),
        "builder_sha256": digest(Path(__file__).read_bytes()),
        "ndk_revision": NDK_REVISION, "target": "aarch64-linux-android34",
        "command": command, "stage": str(stage), "device_commands_run": False,
        "root_exploit_included": False, "runtime_verified": False,
    }
    (stage / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2))
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", required=True)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        build(args.ndk, args.output)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Build failed: {error}\n")


if __name__ == "__main__":
    main()
