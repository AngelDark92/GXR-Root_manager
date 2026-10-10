import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parent
BUNDLE = Path("root/ghostlock-usb-debug")
EXPLOIT = BUNDLE / "01_EXPLOIT"
PROFILE = BUNDLE / "03_TARGET-INFO/ghostlock-offsets/GXR_TARGET_PROFILE.md"
TARGET = EXPLOIT / "src/targets/xrvst2-I610UEU2AZF3/target.h"
NDK_REVISION = "27.2.12479018"
EXPECTED_BINARIES = ("cve-2026-43499", "cve-2026-43499-root", "cve-2026-43499-32")


def external_root(workspace):
    workspace = Path(workspace).resolve()
    return workspace.parent / "builds" / workspace.name


def relocated_input(path, workspace):
    path = bounded_path(path, workspace)
    relative = path.relative_to(Path(workspace).resolve())
    if "build" in relative.parts:
        return bounded_path(external_root(workspace) / relative, external_root(workspace))
    return path


class AuditError(RuntimeError):
    pass


def bounded_path(path, root):
    path = Path(path).resolve()
    root = Path(root).resolve()
    if not path.is_relative_to(root):
        raise AuditError(f"Path escapes {root}: {path}")
    return path


def digest_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_record(path, workspace):
    path = bounded_path(path, workspace)
    if not path.is_file():
        return {"path": path.relative_to(workspace).as_posix(), "status": "missing"}
    return {"path": path.relative_to(workspace).as_posix(), "status": "present",
            "bytes": path.stat().st_size, "sha256": digest_file(path)}


def snapshot_tree(tree, workspace):
    tree = bounded_path(tree, workspace)
    if not tree.is_dir():
        raise AuditError(f"Source directory missing: {tree}")
    return [file_record(path, workspace) for path in sorted(tree.rglob("*")) if path.is_file()]


def compare_snapshots(before, after):
    earlier = {record["path"]: record for record in before}
    later = {record["path"]: record for record in after}
    changed = sorted(path for path in earlier.keys() | later.keys() if earlier.get(path) != later.get(path))
    return {"unchanged": not changed, "changed_paths": changed}


def elf_header(path):
    with Path(path).open("rb") as stream:
        header = stream.read(64)
    if len(header) < 20 or header[:4] != b"\x7fELF":
        raise AuditError(f"Invalid ELF header: {path}")
    elf_class, data = header[4], header[5]
    if elf_class not in (1, 2) or data not in (1, 2):
        raise AuditError(f"Unsupported ELF header encoding: {path}")
    minimum = 52 if elf_class == 1 else 64
    if len(header) < minimum:
        raise AuditError(f"Truncated ELF header: {path}")
    byte_order = "<" if data == 1 else ">"
    elf_type, machine = struct.unpack_from(byte_order + "HH", header, 16)
    return {"artifact_offset": 0, "machine_field_offset": 18,
            "class": 32 if elf_class == 1 else 64,
            "endianness": "little" if data == 1 else "big", "type": elf_type,
            "machine": machine, "machine_name": {40: "ARM", 183: "AArch64"}.get(machine, "unknown"),
            "header_only": True}


def binary_inventory(exploit, workspace):
    result = []
    for name in EXPECTED_BINARIES:
        original = exploit / "build" / name
        path = relocated_input(original, workspace)
        record = file_record(path, external_root(workspace))
        record["original_path"] = original.relative_to(workspace).as_posix()
        record["path_root"] = str(external_root(workspace))
        if record["status"] == "present":
            record["elf"] = elf_header(path)
        result.append(record)
    return result


def verify_binary_inventory(records, workspace):
    workspace = Path(workspace).resolve()
    supplied_build = workspace / EXPLOIT / "build"
    checked = 0
    for record in records:
        original = bounded_path(workspace / record.get("original_path", record["path"]), supplied_build)
        if original.parent != supplied_build or original.name not in EXPECTED_BINARIES:
            raise AuditError(f"Unexpected supplied binary path: {original}")
        path = relocated_input(original, workspace)
        if record["status"] == "missing":
            if path.exists():
                raise AuditError(f"Previously missing supplied binary appeared: {path}")
            continue
        if record["status"] != "present" or not path.is_file():
            raise AuditError(f"Supplied binary missing or invalid: {path}")
        if path.stat().st_size != record["bytes"] or digest_file(path) != record["sha256"]:
            raise AuditError(f"Supplied binary does not match source audit: {path}")
        checked += 1
    return checked


def source_lines(path, workspace, pattern):
    record = file_record(path, workspace)
    if record["status"] != "present":
        return {**record, "matches": []}
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    record["matches"] = [{"line": index, "text": text} for index, text in enumerate(lines, 1)
                         if re.search(pattern, text)]
    return record


def target_observations(workspace):
    target = source_lines(workspace / TARGET, workspace,
                          r"^#define (BUILD_FINGERPRINT|PWQ_NR_ACTIVE_OFF|PWQ_MAX_ACTIVE_OFF)\b")
    profile = source_lines(workspace / PROFILE, workspace, r"^PWQ_(NR_ACTIVE|MAX_ACTIVE)\s+")
    fingerprint = None
    current = {}
    documented = {}
    for entry in target["matches"]:
        fingerprint_match = re.match(r'#define BUILD_FINGERPRINT "([^"]+)"', entry["text"])
        if fingerprint_match:
            fingerprint = fingerprint_match.group(1)
        offset = re.match(r"#define (PWQ_(?:NR_ACTIVE|MAX_ACTIVE))_OFF\s+(0x[0-9a-fA-F]+)", entry["text"])
        if offset:
            current[offset.group(1)] = offset.group(2)
    for entry in profile["matches"]:
        offset = re.match(r"(PWQ_(?:NR_ACTIVE|MAX_ACTIVE))\s+(0x[0-9a-fA-F]+)", entry["text"])
        if offset:
            documented[offset.group(1)] = offset.group(2)
    mismatches = [{"name": name, "documented": value, "current_header": current[name]}
                  for name, value in documented.items()
                  if name in current and int(value, 16) != int(current[name], 16)]
    return {"source_header_fingerprint": fingerprint, "live_device_fingerprint_verified": False,
            "target_header_evidence": target, "documented_profile_evidence": profile,
            "stale_documented_offsets": mismatches, "new_offsets_derived": False}


def historical_evidence(workspace):
    report = workspace / BUNDLE / "REPORT.md"
    return {"classification": "historical_report_claims_not_live_runtime_proof",
            "report": source_lines(report, workspace,
                                   r"^A Samsung|unprivileged `adb|stable `uid=0|reproducible across|"
                                   r"^root umh result|^uid=0\(root\)|^Permissive$|"
                                   r"^Tested several|reboot clears root|no on-disk changes"),
            "root_survives_reboot_demonstrated": False,
            "app_context_exploit_feasibility_demonstrated": False,
            "allocation_lifetime_safety_demonstrated": False}


def runtime_log_observation(workspace):
    scan = bounded_path(workspace / BUNDLE, workspace)
    logs = []
    for path in sorted(scan.rglob("*")):
        if not path.is_file():
            continue
        lower = path.name.lower()
        if path.suffix.lower() == ".log" or (path.suffix.lower() == ".txt" and
                                             lower.startswith(("logcat", "dmesg", "runtime", "exp32"))):
            logs.append(file_record(path, workspace))
    return {"scanned_directory": BUNDLE.as_posix(),
            "selection": "*.log and logcat/dmesg/runtime/exp32-prefixed *.txt files",
            "matching_files": logs, "raw_runtime_log_match_found": bool(logs),
            "content_validated_as_runtime_log": False,
            "absence_claim_scope": "only the named directory and selection; embedded REPORT snippets excluded"}


def reference_commands(clang, sysroot, exploit, stage):
    source = exploit / "src"
    common = ["-O2", "-g0", "-Wall", "-Wextra", "-Wno-unused-parameter",
              "-Wno-sign-compare", "-Wno-unused-function", f"-I{source}"]
    target64 = [str(clang), "--target=aarch64-linux-android34", f"--sysroot={sysroot}"]
    sources = [source / f"{name}.c" for name in ("main", "util", "slide", "fops", "pipe", "root", "preload")]
    return [
        (EXPECTED_BINARIES[0], [*target64, "-fPIC", "-shared", "-pthread", *common,
                               *map(str, sources), "-o", str(stage / EXPECTED_BINARIES[0])]),
        (EXPECTED_BINARIES[1], [*target64, "-fPIE", "-pie", "-O2", "-g0", "-Wall", "-Wextra",
                               str(source / "su_daemon.c"), "-o", str(stage / EXPECTED_BINARIES[1])]),
        (EXPECTED_BINARIES[2], [str(clang), "--target=armv7a-linux-androideabi28", f"--sysroot={sysroot}",
                               "-fPIE", "-pie", "-static", "-pthread", *common,
                               str(source / "exp32/main.c"), str(source / "exp32/stack.c"),
                               "-o", str(stage / EXPECTED_BINARIES[2])]),
    ]


def compile_reference(ndk, exploit, output_directory, workspace):
    output_directory = bounded_path(output_directory, external_root(workspace))
    output_directory.mkdir(parents=True, exist_ok=True)
    ndk = Path(ndk).resolve()
    properties = ndk / "source.properties"
    if not properties.is_file():
        raise AuditError("NDK source.properties missing")
    match = re.search(r"^Pkg\.Revision\s*=\s*(\S+)\s*$", properties.read_text(encoding="utf-8"), re.MULTILINE)
    if not match or match.group(1) != NDK_REVISION:
        raise AuditError(f"NDK revision must equal {NDK_REVISION}")
    toolchain = ndk / "toolchains/llvm/prebuilt/windows-x86_64"
    clang, sysroot = toolchain / "bin/clang.exe", toolchain / "sysroot"
    if not clang.is_file() or not sysroot.is_dir():
        raise AuditError("Windows NDK clang.exe or sysroot missing")
    stage = Path(tempfile.mkdtemp(prefix="reference-build-", dir=output_directory))
    results = []
    for name, command in reference_commands(clang, sysroot, exploit, stage):
        result = {"artifact_name": name, "command": command, "status": "failed"}
        try:
            process = subprocess.run(command, cwd=stage, shell=False, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
                                     timeout=180, check=False)
            result["exit_code"] = process.returncode
            result["output_tail"] = process.stdout[-8192:]
            if process.returncode == 0:
                result["artifact"] = file_record(stage / name, external_root(workspace))
                result["artifact"]["path_root"] = str(external_root(workspace))
                result["artifact"]["elf"] = elf_header(stage / name)
                expected = (32, 40) if name == EXPECTED_BINARIES[2] else (64, 183)
                actual = result["artifact"]["elf"]
                if (actual["class"], actual["machine"]) != expected:
                    raise AuditError(f"Reference artifact has unexpected ELF architecture: {name}")
                result["status"] = "compiled"
        except (OSError, subprocess.TimeoutExpired, AuditError) as error:
            result["error"] = f"{type(error).__name__}: {error}"[:8192]
        results.append(result)
        if result["status"] != "compiled":
            break
    return {"ndk_revision": NDK_REVISION, "clang_sha256": digest_file(clang),
            "stage": str(stage), "results": results,
            "success": len(results) == 3 and all(item["status"] == "compiled" for item in results),
            "binaries_executed": False, "same_byte_reproduction_claimed": False,
            "runtime_safety_claimed": False}


def audit(output, ndk=None, compile_requested=False, workspace=WORKSPACE, root=ROOT):
    workspace = Path(workspace).resolve()
    root = bounded_path(root, workspace)
    output = bounded_path(output, root)
    if output.exists():
        raise AuditError(f"Preserve existing report; choose another --output: {output}")
    if compile_requested and not ndk:
        raise AuditError("--compile-reference requires --ndk")
    exploit = workspace / EXPLOIT
    before = snapshot_tree(exploit, workspace)
    offset_files = snapshot_tree(workspace / BUNDLE / "03_TARGET-INFO/ghostlock-offsets", workspace)
    documentation = [file_record(workspace / path, workspace)
                     for path in (BUNDLE / "README.md", BUNDLE / "REPORT.md", Path("docs/VALIDATION.md"))]
    report = {"created_utc": datetime.now(timezone.utc).isoformat(), "audit_kind": "pc_source_only",
              "device_commands_run": False, "original_exploit_files_before": before,
              "supplied_binary_inventory": binary_inventory(exploit, workspace),
              "related_offset_extractor_files": offset_files, "documentation": documentation,
              "target_observations": target_observations(workspace),
              "historical_evidence": historical_evidence(workspace),
              "runtime_log_observation": runtime_log_observation(workspace),
              "reference_compilation": {"requested": compile_requested, "binaries_executed": False}}
    output.parent.mkdir(parents=True, exist_ok=True)
    compile_error = None
    if compile_requested:
        try:
            build_directory = external_root(workspace) / "root-manager/build"
            report["reference_compilation"].update(compile_reference(ndk, exploit, build_directory, workspace))
        except (AuditError, OSError) as error:
            compile_error = str(error)
            report["reference_compilation"].update({"success": False, "error": compile_error})
    after = snapshot_tree(exploit, workspace)
    report["original_exploit_files_after"] = after
    report["original_tree_integrity"] = compare_snapshots(before, after)
    report["reference_compile_source_inputs_sha256"] = {
        entry["path"]: entry["sha256"] for entry in before
        if entry["path"].startswith((EXPLOIT / "src").as_posix() + "/")}
    with output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(f"Source audit saved: {output}")
    if not report["original_tree_integrity"]["unchanged"]:
        raise AuditError("Original source tree changed; inspect preserved audit")
    if compile_requested and (compile_error or not report["reference_compilation"].get("success")):
        raise AuditError("Reference compilation failed; partial artifacts and report preserved")
    return report


def main():
    parser = argparse.ArgumentParser(description="Audit supplied Galaxy XR root bundle on PC; never execute binaries")
    parser.add_argument("--output", type=Path, default=ROOT / "evidence/source-audit.json")
    parser.add_argument("--compile-reference", action="store_true")
    parser.add_argument("--ndk", type=Path)
    args = parser.parse_args()
    try:
        audit(args.output, args.ndk, args.compile_reference)
    except (AuditError, OSError) as error:
        print(f"Audit failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
