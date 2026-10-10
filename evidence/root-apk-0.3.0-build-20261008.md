# 0.3.0 local-root APK — build and install record (2026-10-08)

## Artifact

`GalaxyXR-Root-Manager-root-0.3.0.apk` (versionCode 6, `0.3.0-root`), builder `tools/build_root.py`, output `../../builds/gxr-kernel/root-manager/build/`, receipt `root-build-receipt.json`. APK SHA-256 `786d61fd3b2d94992dcf196d6fabde003b983297da659db3f19281ea6593b494`.

First manager artifact with an intentionally packaged exploit (own artifact kind `local_adb_root_manager`, own builder; the read-only `build.py` gate does not apply). Payload pins enforced at build time:

- `gxr-exploit` = `cve-2026-43499` preload, sha256 `7a01fb0f95673dfab44cc3391821a2f31297d8b330913a019165ec7edc5e2f1f` (live slide leak verified this boot: `slide=001f0000 attempt=1/1`)
- `gxr-rootd` = `cve-2026-43499-root` daemon, sha256 `dae607895d27462f492825f23958b184ef6a63fb21c8fad0aa352fd767ffbf88`
- `libadb.so` = LADB arm64 adb 1.0.41, sha256 `47ea035fa5ed57f6149a2b025bbbd4b21584c355c05d0400416804715e4c12de` (executed on-device successfully)

## Architecture

LADB pattern, no Shizuku, no PC after setup: the app's own embedded adb pairs once with the headset's wireless debugging (pairing code from the Settings UI), then `Root now` runs the proven RUNBOOK sequence through its local shell — stage payloads to `/data/local/tmp/gxr-root/`, `EXPLOIT_ATTEMPTS=1 LD_PRELOAD=... /system/bin/true`, verify with `gxr-rootd -c id` expecting `uid=0(root)`.

Safety gates implemented in `RootEngine.java`: exact live fingerprint match (`UML2.260301.001`, now matching all 4 verified observations), 1 attempt per boot latched before launch, manual rearm after any non-rooted outcome, no kill of the exploit process on timeout (reports and leaves recovery to a manual reboot), danger confirm dialogs with obscured-touch rejection.

## Verified

- Built, signed (same dev key), installed on `R3GYB09JA5E`.
- `libadb.so` extracts to `nativeLibraryDir` (`.../lib/arm64/arm64/libadb.so` present) — executable path for untrusted_app confirmed.
- Exploit slide stage re-verified live this boot with the exact packaged binaries.

## Blocked on user gesture (by design)

Wireless debugging cannot be enabled from shell: `settings put global adb_wifi_enabled 1` does not stick (reads 0; Samsung/AOSP require the Developer-options UI toggle). Pairing codes likewise come only from the UI dialog.

Remaining end-to-end steps, all on-headset:
1. Settings → Developer options → Wireless debugging → ON.
2. Manager → enter pair port + code (from "Pair device with pairing code") → Pair once.
3. Enter connect port (from "IP address & Port") → Save.
4. Root now → supervised single attempt, then verify.

USB ADB remains as fallback supervision channel for the first supervised run.