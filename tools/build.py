import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
BUILD_ROOT = ROOT.parent.parent / "builds" / ROOT.parent.name / ROOT.name
DEFAULT_OUTPUT = BUILD_ROOT / "build"
APK_NAME = "GalaxyXR-Root-Manager-probes-0.2.1.apk"
NDK_REVISION = "27.2.12479018"
PASSWORD_ENV = "GXR_DEBUG_KEY_PASSWORD"
FORBIDDEN_NAMES = ("cve43499", "cve-2026-43499", "ghostlock")
ASSET_SUFFIXES = {".json", ".txt", ".md"}


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


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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
    if any(token in name.lower() for token in FORBIDDEN_NAMES):
        raise BuildError(f"Exploit payload entry prohibited: {name!r}")
    return name


def validate_asset(name, data):
    suffix = Path(name).suffix.lower()
    if suffix not in ASSET_SUFFIXES:
        raise BuildError(f"Unsupported diagnostic asset: {name}")
    try:
        text = data.decode("utf-8")
        if "\x00" in text:
            raise ValueError("Binary text asset")
        if suffix == ".json":
            json.loads(text)
    except (UnicodeError, ValueError) as error:
        raise BuildError(f"Diagnostic asset must be valid UTF-8 metadata: {name}") from error


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
        native = {name for name in names if name.startswith("lib/") and not name.endswith("/")}
        if native != {"lib/arm64-v8a/libgxr_diagnostics.so"}:
            raise BuildError("APK contains unexpected native payload")
        for name in names:
            if name.startswith("assets/") and not name.endswith("/"):
                validate_asset(name, archive.read(name))
        invalid = archive.testzip()
        if invalid:
            raise BuildError(f"APK corrupt entry: {invalid}")
    return names


def package_apk(base, destination, additions):
    with zipfile.ZipFile(base) as source, zipfile.ZipFile(destination, "w") as output:
        names = set()
        for entry in source.infolist():
            safe_zip_name(entry.filename)
            if entry.filename in names:
                raise BuildError(f"Duplicate resource entry: {entry.filename}")
            names.add(entry.filename)
            output.writestr(entry, source.read(entry))
        for name, path in sorted(additions.items()):
            safe_zip_name(name)
            if name in names:
                raise BuildError(f"Duplicate packaged entry: {name}")
            names.add(name)
            output.write(path, name, compress_type=zipfile.ZIP_DEFLATED)
    audit_apk(destination)


def collect_inputs(root):
    app = root / "app"
    mandatory = [require_file(app / "AndroidManifest.xml"), require_file(app / "jni/diagnostics.c")]
    java = sorted(app.joinpath("src").rglob("*.java"))
    resources = sorted(path for path in app.joinpath("res").rglob("*") if path.is_file())
    assets = sorted(path for path in app.joinpath("assets").rglob("*") if path.is_file())
    if not java or not resources:
        raise BuildError("App Java sources and resources are required")
    for path in mandatory + java + resources + assets:
        within(path, app)
        if any(token in str(path.relative_to(app)).lower() for token in FORBIDDEN_NAMES):
            raise BuildError(f"Exploit input prohibited: {path}")
    for path in assets:
        validate_asset(path.name, path.read_bytes())
    verifier = within(require_file(root / "native/bootstrap_verifier.c"), root / "native")
    return mandatory + java + resources + assets + [verifier], java, assets


def freeze_inputs(root, stage, inputs, expected_hashes):
    snapshot = stage / "source-snapshot"
    for path in inputs:
        relative = path.relative_to(root)
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != expected_hashes[str(relative)]:
            raise BuildError(f"Input changed before staging: {relative}")
        destination = snapshot / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
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
                                    timeout=180)
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
    local = within(ROOT / ".local", ROOT)
    inputs, java_sources, assets = collect_inputs(ROOT)
    original_hashes = {str(path.relative_to(ROOT)): sha256(path) for path in inputs}
    output.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="diagnostics-", dir=output))
    snapshot = freeze_inputs(ROOT, stage, inputs, original_hashes)
    java_sources = [snapshot / path.relative_to(ROOT) for path in java_sources]
    assets = [snapshot / path.relative_to(ROOT) for path in assets]
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
    for asset in assets:
        additions["assets/" + asset.relative_to(snapshot / "app/assets").as_posix()] = asset
    unsigned = stage / "unsigned.apk"
    package_apk(base, unsigned, additions)
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
    final_inputs, _, _ = collect_inputs(ROOT)
    final_hashes = {str(path.relative_to(ROOT)): sha256(path) for path in final_inputs}
    if original_hashes != final_hashes:
        raise BuildError("Build inputs changed during compilation; artifact not published")
    receipt = {
        "artifact": APK_NAME, "artifact_kind": "read_only_feasibility_probes", "version": "0.2.1",
        "exploit_included": False, "automatic_root_restoration": False,
        "root_status_operation": "fixed_read_only_status_after_same_socket_peer_authentication",
        "feasibility_probes": "forked_child_syscall_and_path_probes_read_only",
        "root_execution": False, "device_tests_run": False, "signing": "local_development",
        "ndk_revision": NDK_REVISION, "java_source_target": 17, "apk_sha256": sha256(signed),
        "apk_bytes": signed.stat().st_size, "android_jar_sha256": sha256(tools["android_jar"]),
        "inputs_sha256": final_hashes,
        "builder_sha256": sha256(Path(__file__)),
        "tools_sha256": {name: sha256(path) for name, path in tools.items() if path.is_file()},
        "tool_versions": versions, "commands": runner.commands,
        "signature_verification": verification, "apk_entries": entries, "staging_directory": str(stage),
    }
    staged_receipt = stage / "build-receipt.json"
    staged_receipt.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    destination = output / APK_NAME
    os.replace(signed, destination)
    os.replace(staged_receipt, output / "build-receipt.json")
    print(f"Built feasibility-probe APK: {destination}")
    print(f"SHA-256: {receipt['apk_sha256']}")
    return destination


def main():
    parser = argparse.ArgumentParser(description="Build Galaxy XR diagnostics APK on Windows; no device access")
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
