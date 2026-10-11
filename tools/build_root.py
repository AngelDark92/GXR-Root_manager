import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
# Version truth for this repository. tools/verify_release_version.py fails the run when the
# manifest or a pushed tag disagrees with this constant; tools/release_policy.py is the only
# writer.
VERSION = "0.8.0"
BUILD_ROOT = ROOT.parent / f"{ROOT.name}-builds"
DEFAULT_OUTPUT = BUILD_ROOT / "build"
APK_NAME = f"GalaxyXR-Root-Manager-root-{VERSION}.apk"
NDK_REVISION = "27.2.12479018"
PASSWORD_ENV = "GXR_DEBUG_KEY_PASSWORD"

# Payload binaries intentionally packaged by this builder. Exact SHA-256 pins:
# gxr-exploit  = cve-2026-43499 preload (verified live slide leak 2026-10-08)
# gxr-rootd    = cve-2026-43499-root su daemon (RUNBOOK protocol)
# libadb.so    = LADB (GPLv3) arm64 adb 1.0.41 platform 34 client
# kernelsu-gxr.ko = KernelSU-Next v3.4.0 android12-5.10 module, fail-open DEFEX build,
#                   patched by tools/patch_kernelsu_module.py: the __versions section
#                   contents are zeroed in place (section kept). Vermagic is left at
#                   upstream 5.10.245-dirty, which this kernel tolerates while __versions
#                   is present. Loaded with allow_shell=1. Proven live 2026-10-09; see
#                   builds/gxr-kernel/ksu-probe-20261009/RECEIPT.md
PAYLOAD_PINS = {
    "gxr-exploit": "7a01fb0f95673dfab44cc3391821a2f31297d8b330913a019165ec7edc5e2f1f",
    "gxr-rootd": "dae607895d27462f492825f23958b184ef6a63fb21c8fad0aa352fd767ffbf88",
    "libadb.so": "47ea035fa5ed57f6149a2b025bbbd4b21584c355c05d0400416804715e4c12de",
    "kernelsu-gxr.ko": "f528ef24fca78fe429df7e7290058febf884e97dc533497549c345c5e8d3e2d6",
}


class BuildError(RuntimeError):
    pass


def require_file(path):
    path = Path(path).resolve()
    if not path.is_file():
        raise BuildError(f"Required file missing: {path}")
    return path


def within(path, root):
    path = Path(path).resolve()
    root = Path(root).resolve()
    if not path.is_relative_to(root):
        raise BuildError(f"Path must remain under {root}: {path}")
    return path


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_tools(android_jar, build_tools, ndk, java_home):
    if not java_home:
        raise BuildError("Supply --java-home or JAVA_HOME for Java 17 or newer")
    build_tools = Path(build_tools).resolve()
    ndk = Path(ndk).resolve()
    java_home = Path(java_home).resolve()
    properties = require_file(ndk / "source.properties").read_text(encoding="utf-8")
    match = re.search(r"^Pkg\.Revision\s*=\s*(\S+)\s*$", properties, re.MULTILINE)
    if not match or match.group(1) != NDK_REVISION:
        raise BuildError(f"NDK revision must equal {NDK_REVISION}")
    toolchain = ndk / "toolchains/llvm/prebuilt/windows-x86_64"
    sysroot = toolchain / "sysroot"
    if not sysroot.is_dir():
        raise BuildError(f"Required NDK sysroot missing: {sysroot}")
    return {
        "android_jar": require_file(android_jar),
        "aapt2": require_file(build_tools / "aapt2.exe"),
        "zipalign": require_file(build_tools / "zipalign.exe"),
        "d8": require_file(build_tools / "lib/d8.jar"),
        "apksigner": require_file(build_tools / "lib/apksigner.jar"),
        "java": require_file(java_home / "bin/java.exe"),
        "javac": require_file(java_home / "bin/javac.exe"),
        "jar": require_file(java_home / "bin/jar.exe"),
        "keytool": require_file(java_home / "bin/keytool.exe"),
        "clang": require_file(toolchain / "bin/clang.exe"),
        "sysroot": sysroot.resolve(),
    }


def validate_java_versions(runtime, compiler):
    runtime_match = re.search(r'\bversion\s+"(\d+)', runtime)
    compiler_match = re.match(r"javac (\d+)", compiler)
    if not runtime_match or int(runtime_match.group(1)) < 17:
        raise BuildError("Java runtime must be version 17 or newer")
    if not compiler_match or int(compiler_match.group(1)) < 17:
        raise BuildError("Java compiler must be version 17 or newer")


def safe_zip_name(name):
    if not name or name.startswith("/") or "\\" in name:
        raise BuildError(f"Unsafe APK entry: {name!r}")
    if any(part in {".", ".."} for part in name.split("/")) or ":" in name:
        raise BuildError(f"Unsafe APK entry: {name!r}")
    return name


def verify_payload_pins(root):
    for name, pinned in PAYLOAD_PINS.items():
        path = root / "app" / "payload" / name
        actual = sha256(path)
        if actual != pinned:
            raise BuildError(f"Payload {name} hash mismatch: expected {pinned}, got {actual}")


def audit_apk(path):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise BuildError("APK contains duplicate entries")
        for name in names:
            safe_zip_name(name)
        required = {"AndroidManifest.xml", "classes.dex", "lib/arm64-v8a/libgxr_diagnostics.so"}
        missing = required.difference(names)
        if missing:
            raise BuildError(f"APK missing entries: {', '.join(sorted(missing))}")
        for name in names:
            if name.startswith("lib/") and not name.endswith("/"):
                base = name.rsplit("/", 1)[-1]
                if base not in PAYLOAD_PINS and base != "libgxr_diagnostics.so":
                    raise BuildError(f"Unexpected native payload: {name}")
        for name in names:
            if name.startswith("assets/payload/"):
                base = name.rsplit("/", 1)[-1]
                if base not in PAYLOAD_PINS:
                    raise BuildError(f"Unexpected packaged payload: {name}")
        invalid = archive.testzip()
        if invalid:
            raise BuildError(f"APK corrupt entry: {invalid}")
    return names


def collect_inputs(root):
    app = root / "app"
    java = sorted(app.joinpath("src").rglob("*.java"))
    resources = sorted(path for path in app.joinpath("res").rglob("*") if path.is_file())
    payloads = [require_file(app / "payload" / name) for name in PAYLOAD_PINS]
    if not java or not resources:
        raise BuildError("App Java sources and resources are required")
    for path in java + resources + payloads:
        within(path, app)
    mandatory = [require_file(app / "AndroidManifest.xml"), require_file(app / "jni/diagnostics.c")]
    verifier = within(require_file(root / "native/bootstrap_verifier.c"), root / "native")
    return mandatory + java + resources + payloads + [verifier], java


def freeze_inputs(root, stage, inputs):
    snapshot = stage / "source-snapshot"
    for path in inputs:
        destination = snapshot / path.relative_to(root)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
    return snapshot


class Runner:
    def __init__(self, cwd):
        self.cwd = cwd
        self.commands = []
        self.env = os.environ.copy()
        self.env[PASSWORD_ENV] = "android"

    def run(self, argv):
        command = [str(value) for value in argv]
        self.commands.append(command)
        try:
            result = subprocess.run(command, cwd=self.cwd, env=self.env, shell=False,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, encoding="utf-8", errors="replace", check=False,
                                    timeout=240)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise BuildError(f"Tool failed: {command[0]}: {type(error).__name__}") from error
        output = result.stdout[-8192:]
        if result.returncode:
            raise BuildError(f"Tool exited {result.returncode}: {command[0]}\n{output}")
        return output.strip()


def build(args):
    output = within(args.output, BUILD_ROOT)
    if output == BUILD_ROOT.resolve():
        raise BuildError("Output must be a directory within the external build root")
    tools = validate_tools(args.android_jar, args.build_tools, args.ndk, args.java_home)
    verify_payload_pins(ROOT)
    local = within(ROOT / ".local", ROOT)
    inputs, java_sources = collect_inputs(ROOT)
    original_hashes = {str(path.relative_to(ROOT)): sha256(path) for path in inputs}
    output.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="root-build-", dir=output))
    snapshot = freeze_inputs(ROOT, stage, inputs)
    java_sources = [snapshot / path.relative_to(ROOT) for path in java_sources]
    runner = Runner(stage)
    versions = {}
    for key, arguments in (("java", ["-version"]), ("javac", ["-version"]),
                          ("aapt2", ["version"]), ("clang", ["--version"])):
        versions[key] = runner.run([tools[key], *arguments])
    validate_java_versions(versions["java"], versions["javac"])
    native = stage / "libgxr_diagnostics.so"
    runner.run([tools["clang"], "--target=aarch64-linux-android34", f"--sysroot={tools['sysroot']}",
                "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror",
                "-DGXR_ANDROID_JNI", "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2",
                "-Wl,-z,max-page-size=16384", "-Wl,-z,relro,-z,now",
                snapshot / "app/jni/diagnostics.c", snapshot / "native/bootstrap_verifier.c", "-o", native])
    resources = stage / "resources.zip"
    runner.run([tools["aapt2"], "compile", "--dir", snapshot / "app/res", "-o", resources])
    generated = stage / "generated"
    generated.mkdir()
    base = stage / "base.apk"
    runner.run([tools["aapt2"], "link", "-o", base, "-I", tools["android_jar"],
                "--manifest", snapshot / "app/AndroidManifest.xml", "--java", generated,
                "--min-sdk-version", "34", "--target-sdk-version", "34", resources])
    classes = stage / "classes"
    classes.mkdir()
    runner.run([tools["javac"], "-encoding", "UTF-8", "-source", "17", "-target", "17",
                "-classpath", tools["android_jar"], "-d", classes,
                *java_sources, *sorted(generated.rglob("*.java"))])
    classes_jar = stage / "classes.jar"
    runner.run([tools["jar"], "--create", "--file", classes_jar, "-C", classes, "."])
    dex = stage / "dex"
    dex.mkdir()
    runner.run([tools["java"], "-cp", tools["d8"], "com.android.tools.r8.D8",
                "--min-api", "34", "--lib", tools["android_jar"], "--output", dex, classes_jar])
    additions = {path.name: path for path in sorted(dex.glob("classes*.dex"))}
    additions["lib/arm64-v8a/libgxr_diagnostics.so"] = native
    # Payload binaries: adb as native lib (executable via nativeLibraryDir),
    # exploit + daemon as assets (copied to external storage at runtime).
    additions["lib/arm64-v8a/" + "libadb.so"] = ROOT / "app/payload/libadb.so"
    additions["assets/payload/gxr-exploit"] = ROOT / "app/payload/gxr-exploit"
    additions["assets/payload/gxr-rootd"] = ROOT / "app/payload/gxr-rootd"
    additions["assets/payload/kernelsu-gxr.ko"] = ROOT / "app/payload/kernelsu-gxr.ko"
    unsigned = stage / "unsigned.apk"
    with zipfile.ZipFile(base) as src, zipfile.ZipFile(unsigned, "w") as dst:
        seen = set()
        for entry in src.infolist():
            safe_zip_name(entry.filename)
            if entry.filename in seen:
                raise BuildError(f"Duplicate packaged entry: {entry.filename}")
            seen.add(entry.filename)
            dst.writestr(entry, src.read(entry.filename))
        for name, path in sorted(additions.items()):
            safe_zip_name(name)
            if name in seen:
                raise BuildError(f"Duplicate packaged entry: {name}")
            seen.add(name)
            dst.write(path, name, compress_type=zipfile.ZIP_DEFLATED)
    audit_apk(unsigned)
    aligned = stage / "aligned.apk"
    runner.run([tools["zipalign"], "-f", "-p", "4", unsigned, aligned])
    local.mkdir(parents=True, exist_ok=True)
    key = within(local / "debug.keystore", local)
    if not key.exists():
        runner.run([tools["keytool"], "-genkeypair", "-keystore", key, "-storetype", "PKCS12",
                    "-alias", "androiddebugkey", "-keyalg", "RSA", "-keysize", "2048",
                    "-validity", "10000", "-dname", "CN=Galaxy XR Root Manager Development",
                    "-storepass:env", PASSWORD_ENV, "-keypass:env", PASSWORD_ENV])
    signed = stage / "signed.apk"
    signer = [tools["java"], "-cp", tools["apksigner"], "com.android.apksigner.ApkSignerTool"]
    runner.run([*signer, "sign", "--ks", key, "--ks-key-alias", "androiddebugkey",
                "--ks-pass", f"env:{PASSWORD_ENV}", "--key-pass", f"env:{PASSWORD_ENV}",
                "--v4-signing-enabled", "false", "--out", signed, aligned])
    verification = runner.run([*signer, "verify", "--verbose", "--print-certs", signed])
    entries = audit_apk(signed)
    final_hashes = {str(path.relative_to(ROOT)): sha256(path) for path in inputs}
    if original_hashes != final_hashes:
        raise BuildError("Build inputs changed during compilation; artifact not published")
    receipt = {
        "artifact": APK_NAME, "artifact_kind": "local_adb_root_manager", "version": VERSION,
        "exploit_included": True, "exploit_sha256_pins": PAYLOAD_PINS,
        "exploit_run_mode": "one_attempt_per_boot_shell_context_local_adb",
        "automatic_root_restoration": False,
        "root_execution": True, "device_tests_run": False, "signing": "local_development",
        "ndk_revision": NDK_REVISION, "java_source_target": 17, "apk_sha256": sha256(signed),
        "apk_bytes": signed.stat().st_size, "android_jar_sha256": sha256(tools["android_jar"]),
        "inputs_sha256": final_hashes,
        "builder_sha256": sha256(Path(__file__)),
        "tools_sha256": {name: sha256(path) for name, path in tools.items() if path.is_file()},
        "tool_versions": versions, "commands": runner.commands,
        "signature_verification": verification, "apk_entries": entries,
        "staging_directory": str(stage),
    }
    staged_receipt = stage / "build-receipt.json"
    staged_receipt.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    destination = output / APK_NAME
    os.replace(signed, destination)
    os.replace(staged_receipt, output / "root-build-receipt.json")
    print(f"Built local-root APK: {destination}")
    print(f"SHA-256: {receipt['apk_sha256']}")
    return destination


def main():
    parser = argparse.ArgumentParser(description="Build Galaxy XR local-root APK (0.3.0) on Windows; no device access")
    parser.add_argument("--android-jar", type=Path, required=True)
    parser.add_argument("--build-tools", type=Path, required=True)
    parser.add_argument("--ndk", type=Path, required=True)
    parser.add_argument("--java-home", type=Path, default=os.environ.get("JAVA_HOME"))
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        build(args)
    except (BuildError, OSError, zipfile.BadZipFile) as error:
        print(f"Build failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())