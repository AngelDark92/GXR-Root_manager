"""Record a read-only preflight. This tool never launches, deploys or retries root."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parent


def file_record(path):
    raw = Path(path).read_bytes()
    return {"path": str(Path(path).resolve()), "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()}


def device_state(inventory, serial):
    for line in inventory.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == serial:
            return fields[1]
    return "not_listed"


def inspect(adb, serial, app_report=None):
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", serial):
        raise ValueError("Invalid explicit device serial")
    adb = Path(adb).resolve(strict=True)
    commands = []

    def call(args):
        command = [str(adb), *args]
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        commands.append({"argv": command, "returncode": result.returncode,
                         "stdout": result.stdout[:16384], "stderr": result.stderr[:4096]})
        return result

    inventory = call(["devices", "-l"])
    state = device_state(inventory.stdout, serial) if inventory.returncode == 0 else "inventory_error"
    live = {}
    # A stale inventory cannot authorize a root operation: these are read-only shell probes.
    if state == "device":
        for key, args in {
            "model": ["getprop", "ro.product.model"],
            "fingerprint": ["getprop", "ro.build.fingerprint"],
            "kernel": ["uname", "-a"], "shell_identity": ["id"],
            "selinux": ["getenforce"],
            "boot_id": ["cat", "/proc/sys/kernel/random/boot_id"],
            "shell_status": ["cat", "/proc/self/status"],
        }.items():
            result = call(["-s", serial, "shell", "-T", *args])
            live[key] = {"available": result.returncode == 0, "value": result.stdout.strip()}
            if result.returncode != 0:
                state = "shell_probe_failed"
                break
    report = {"created_utc": datetime.now(timezone.utc).isoformat(),
              "kind": "external_bootstrap_preflight", "serial": serial,
              "adb": file_record(adb), "transport_state": state,
              "commands": commands, "live": live,
              "root_executed": False, "deployment_performed": False,
              "bootstrap_ready": False,
              "blockers": ["Exact target/kernel artifact binding remains unverified",
                           "Partial-failure allocation lifetime and supervisor timeout are unverified",
                           "Authenticated verifier and broker lack device runtime validation"]}
    if state != "device":
        report["blockers"].insert(0, f"ADB shell unavailable: {state}")
    historical = WORKSPACE / "root/ghostlock-usb-debug/03_TARGET-INFO/kernel-Image"
    if historical.is_file():
        report["historical_kernel_artifact"] = file_record(historical)
        report["historical_kernel_artifact"]["bound_to_live_device"] = False
    if app_report:
        raw = Path(app_report).read_bytes()
        supplied = json.loads(raw.decode("utf-8-sig").replace("\u00a0", " "))
        report["supplied_app_report"] = {**file_record(app_report),
             "timestamp_utc": supplied.get("timestamp_utc"),
             "fingerprint": supplied.get("fingerprint"), "independent_live_capture": False}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--app-report", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        output = args.output.resolve()
        if not output.is_relative_to(ROOT / "evidence"):
            raise ValueError("Preflight output must remain under root-manager/evidence")
        if output.exists():
            raise ValueError("Refusing to overwrite preflight evidence")
        report = inspect(args.adb, args.serial, args.app_report)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
        print(json.dumps({"evidence": str(output), "state": report["transport_state"],
                          "bootstrap_ready": False, "blockers": report["blockers"]}, indent=2))
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Preflight failed: {error}\n")


if __name__ == "__main__":
    main()
