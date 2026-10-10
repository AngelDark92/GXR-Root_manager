# Galaxy XR Root Manager

On-device root for the owner's Galaxy XR (SM-I610, `I610UEU2AZF3`, kernel 5.10.240, locked bootloader). **No PC needed** and nothing is flashed.

The app drives an embedded arm64 adb client against the headset's own wireless debugging, gets a `uid 2000` shell, runs the GhostLock (CVE-2026-43499) exploit, and a `uid 0` su daemon ends up answering on `/data/local/tmp/temp_su.sock`. Root is kernel-memory only: a restart clears it, so it is re-obtained once per boot. Verified live 2026-10-09 — see [docs/RUNBOOK-0.3.4-ondevice.md](docs/RUNBOOK-0.3.4-ondevice.md).

## Flow

0. **Pair once.** On the headset open Developer options > Wireless debugging > *Pair device with pairing code*, then in the app's **Pairing** card press **Find port** (the app discovers the pairing port over mDNS `_adb-tls-pairing._tcp`), type the 6-digit code and press **Pair now**. Pairing is required on this build, and the pairing port is *not* the connect port. The code is stored, and `Root now` refuses to run without it.
1. `RootEngine` starts its own adb server, discovers the wireless-debugging port via mDNS, connects to `localhost:<port>` and pins every later call with `ANDROID_SERIAL=localhost:<port>` (the headset exposes two transports, so an unpinned `adb shell` fails).
2. It checks the exact fingerprint, reads the boot id, latches **one attempt per boot**, stages `gxr-exploit` and `gxr-rootd` into `/data/local/tmp/gxr-root`, and runs the exploit in shell context (~1 minute).
3. It verifies root through the daemon (`gxr-rootd -c id` → `uid=0(root)`).

`RootService` (optional, started by `BootReceiver` on `BOOT_COMPLETED`/`LOCKED_BOOT_COMPLETED`) repeats steps 1–3 after each restart. It needs a one-time grant, because `settings`/`pm` are unreachable from the root daemon's own context:

```
adb shell pm grant dev.galaxyxr.rootmanager android.permission.WRITE_SECURE_SETTINGS
```

The grant survives reboots; only uninstall or a signer change loses it. With it the service can also re-enable Wireless debugging (`Settings.Global.adb_wifi_enabled=1`).

## Verify root semantics

`Verify root` runs in the **uid 2000 shell** context, which is the only context the daemon authorizes (it allowlists its initiating UID). Results: `verified_root`, `not_authorized`, `not_rooted`, `unreachable`. A missing or unreachable daemon means **root cannot be verified — never that the device has no root**. The app-process path (`NativeDiagnostics` → native verifier) can only ever report "manager access denied" from the app's own UID.

## Layout

```
app/AndroidManifest.xml                     activity, BootReceiver, RootService, AccessProvider
app/src/dev/galaxyxr/rootmanager/
  MainActivity.java     status, Root now, Verify root, boot toggle, log, advanced
  RootEngine.java       local-adb engine, boot-id latch, exploit run, verifyRoot()
  RootService.java      foreground re-root at boot (specialUse type)
  BootReceiver.java     boot/unlock/update trigger, fingerprint-gated
  PortDiscovery.java    mDNS discovery of the wireless-debugging port
  SafetyPolicy.java     target identity constants and policy helpers
  RootStatus.java       pure evaluator for the read-only status proof (JVM-tested)
  AccessStore.java / AccessProvider.java   preview consent API (grants nothing)
app/payload/            pinned exploit binaries (hashes enforced by the builder)
app/jni/, native/       diagnostics native library
tools/build_root.py     the 0.3.x builder (aapt2 → javac → d8 → zipalign → apksigner)
tools/release_policy.py version bump and publish gate used by CI
tools/verify_release_version.py fails when the manifest or a pushed tag disagrees with VERSION
tools/fetch_test_deps.py        pinned JVM test dependency for `.local/testdeps`
tests/                  python + JVM tests
docs/                   runbook, design notes, GitHub CI notes
```

## Build and test

From this repository root, Java 17+ in `JAVA_HOME` (JDK 21 used here), plus Android SDK platform 34,
build-tools 35.0.1 and NDK 27.2.12479018:

```sh
python -B tools/fetch_test_deps.py
python -B -m unittest discover -s tests -v
python -B tools/build_root.py \
  --android-jar "$ANDROID_SDK_ROOT/platforms/android-34/android.jar" \
  --build-tools "$ANDROID_SDK_ROOT/build-tools/35.0.1" \
  --ndk "$ANDROID_SDK_ROOT/ndk/27.2.12479018"
```

Artifacts go to `<repository>-builds/build` beside the repository (`GalaxyXR-Root-Manager-root-0.3.5.apk` plus `root-build-receipt.json` with per-input, per-tool and APK hashes). The development signing key stays in `.local/` and is never printed or distributed.

## Continuous integration

`ci.yml` runs the version check and the whole suite on `ubuntu-latest`. `release.yml` builds on
`windows-latest` with the Android SDK, uploads the APK and its receipt as a workflow artifact, and
publishes a GitHub Release only on `main`, on a matching `v*` tag, or on a workflow dispatch that
asked for it — everything else is a build-and-test dry run. Version truth is `VERSION` in
`tools/build_root.py`; `fix:` / `feat:` / `rework:` commits bump patch / minor / major. Design
notes: `docs/GitHub-CI-Notes-2026-10-10.md`.

## Limits and safety

- Never flash, remount, patch a boot image, unlock the bootloader, disable AVB, switch slots, write a verified partition, or change display settings. Nothing here does.
- Root lives in kernel memory: no persistence, no module loading, no app-facing `su` on `PATH`. Callers that expect `su` (root apps, Shizuku root mode) will not find it; Shizuku's ADB mode and this app's daemon are the available routes.
- The exploit sets SELinux permissive and clears `panic_on_oops` for the current boot only; an error after kernel changes can still crash the headset. One attempt per boot, no automatic retry after a partial failure — rearm manually.
- KernelSU is *not* part of this route: the Samsung module DFRoot late-loads aborts on this kernel because it requires DEFEX symbols that this firmware does not have (`ksu_samsung_defex_init()` fails closed), so the manager reports "not installed".
- The root daemon cannot drive framework services (`cmd: Can't find service: settings`); do `pm`/`settings` work over a uid 2000 shell or from the app with `WRITE_SECURE_SETTINGS`.

## Integration API (unchanged, grants nothing)

`ContentResolver.call()` on `content://dev.galaxyxr.rootmanager.access`: `getStatus`, `requestAccess`, `getAccess` (caller-scoped preview decision), `execute` (always `ROOT_BACKEND_UNAVAILABLE`). Callers are bound to UID, package and signer SHA-256; unknown or changed identities fail closed. The preview-approval UI is not part of the current frontend, so its review intent is dormant — the API and its refusal behaviour are unchanged.
