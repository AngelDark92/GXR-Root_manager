# Runbook — 0.3.4 on-device root, no PC

Artifact: `builds/gxr-kernel/root-manager/build/GalaxyXR-Root-Manager-root-0.3.4.apk`
SHA-256 `1520649fba800d6ddde179a97e20a4e16dcd9195a87039b0d94d66c41fe9a630`, size 2441985.
Source: `gxr-kernel/root-manager` (restored from `builds/gxr-kernel/root-manager-archive-20261009/root-manager`). Edit set: `app/AndroidManifest.xml` (boot receiver, foreground service, WAKE_LOCK/boot/FGS permissions); new `app/src/dev/galaxyxr/rootmanager/{BootReceiver,RootService}.java`; `RootEngine.java` (ANDROID_SERIAL pinning, 20 s stale-track recovery, pairing support, `verifyRoot()`, `runRoot(Log,Runnable)`); `PortDiscovery.java` (pairing-port discovery); rewritten `MainActivity.java`; `tests/SafetyPolicyTest.java:30,32`.
Signed with the local development key (`CN=Galaxy XR Root Manager Development`, cert SHA-256 `89f9fb69cdd7ca670d5f7b2f74306887dc564e556a93849bb4f9a00bb77e8539`).

Status: verified live on the headset — manual root at 20:57 and unattended boot re-root at 21:23 (both runs cited below); 45/45 tests OK; APK entry audit and in-APK payload-hash pins clean. No partition is written by any step below.

## What this run does

The app acts as a local adb client against the headset's own wireless debugging (`libadb.so`), pushes the two GhostLock binaries to `/data/local/tmp`, runs the exploit in shell context, then verifies `uid=0(root)` through the su daemon socket. RAM only; a reboot clears everything.

## Preconditions

- Battery >= 50%. Headset screen unlocked and worn/reachable.
- Live fingerprint must equal `samsung/xrvst2ue/xrvst2:14/UML2.260301.001/I610UEU2AZF3:user/release-keys` (the app refuses otherwise).
- `sha256sum` of the APK matches the value above.
- No other root attempt in this boot (the app latches one attempt per boot id).

## Steps (owner)

1. Headset: Settings > Developer options > Wireless debugging > ON.
2. Pair once, from the app: on the headset open Wireless debugging > *Pair device with pairing code* and leave that dialog open; in the app's **Pairing** card press **Find port**, type the 6-digit code, press **Pair now** (expect `Successfully paired to localhost:<port>`). `Root now` refuses to run until a code is saved.
3. Install the APK (PC `adb install` is fine for this step, or copy it to the headset and install locally; local install needs "Install unknown apps" for the file manager).
4. Open **Galaxy XR Root Manager**, press **Root now**, confirm the danger dialog.
5. When the headset shows "Allow wireless debugging?" tap **Always allow**.
6. Leave it alone. Pushing + exploit runs about a minute; the app then verifies root through the daemon.

## Expected evidence

App log (also written to its external files dir under `runs/`):

```
[+] ROOT VERIFIED
    uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0
    SELinux: Permissive
```

## Abort criteria

- No online connection within 90 s: the app stops itself (`wireless connection not authorized in time`) and does not retry this boot. Recheck the Allow dialog, then press Root now again (or reboot for a fresh latch).
- Fingerprint gate failure: stop; the build is not the verified target.
- Unexpected headset reboot during the run: wait for it to come back, unlock, then start over. The attempt latch resets with the boot id.
- Two failed attempts of the same step: stop, keep the log, escalate. No blind retry loops.

## Verified run (2026-10-09 20:57, boot fb22b689-5f8e-4f7d-a5af-781d0da7aab5)

App run `runs/run-1791572269093.txt` reached `[+] exploit completed attempt=1/1`, `uid=2000->0`, then `[+] ROOT VERIFIED`, `SELinux: Permissive`.

Independently re-verified from the host afterwards (not the app's own claim):

```
$ adb shell "/data/local/tmp/gxr-root/gxr-rootd -c 'id; getenforce'"
uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0
Permissive
```

`/proc/net/unix` shows `/data/local/tmp/temp_su.sock` as a live listening socket; `/data/local/tmp/gxr-root/{gxr-exploit,gxr-rootd}` are staged mode 755; the plain shell stays `uid=2000(shell)`.

Blocking bug fixed to get there: the headset's own adb server exposes two transports (`adb-<serial>-<suffix>._adb-tls-connect._tcp.` and `localhost:<port>`), so every `adb shell` failed with `more than one device/emulator` and the app died with `shell read timeout`. The app now pins each call with `ANDROID_SERIAL=localhost:<port>`.

## Verified boot re-root (2026-10-09 21:23, boot `64bddd9d-047a-4883-a4f0-ad20bafbed77`)

After a plain `adb reboot`, with no interaction at all:

```
21:23:48  am_proc_start: dev.galaxyxr.rootmanager,broadcast,{...BootReceiver}
21:23:48  am_foreground_service_start: .../.RootService, BOOT_COMPLETED, type 34
21:24:04  am_foreground_service_stop: ... STOP_FOREGROUND
```

`runs/run-1791573830101.txt` shows the service re-discovered a **new** port (41217 — it rotates every boot), passed the fingerprint and boot-id gates, latched, pushed, ran the exploit (`uid=2000->0`) and ended `[+] ROOT VERIFIED`. Verified from the host afterwards: `temp_su.sock` live, `gxr-rootd -c id` → `uid=0(root) … context=u:r:kernel:s0`.

Two defects this run exposed, both fixed: the service crashed on start because `android.permission.WAKE_LOCK` was not declared (first attempt at 21:19 died with `SecurityException`), and `LOCKED_BOOT_COMPLETED` was dropped from the receiver filter so the flow only runs after unlock. A failed pairing attempt on a stale saved port is now logged as informational and the stale port is cleared; it never blocks the run, because the app's key is already trusted.

Re-verified at 21:29:58 on the hardened build (`1520649f…`, boot after the reviewer fixes): FGS start type 34, stop at 21:30:25, no crash, `gxr-rootd -c id` → `uid=0(root)` again, run `runs/run-1791574200137.txt`. The boot notification stays hidden until the owner opens the app once and allows the notification permission (`numPostedByApp=0` on an ungranted `POST_NOTIFICATIONS`); the app requests it on open.

## KernelSU late-load at boot (0.3.5, verified 2026-10-09 22:10)

Artifact: `builds/gxr-kernel/root-manager/build/GalaxyXR-Root-Manager-root-0.3.5.apk`, SHA-256 `bfea442d6884d26a55c718d576f37025cbb3e890f551900b0dbcf419ebb25694`, 12 entries. Change set: `app/payload/kernelsu-gxr.ko` (pinned `f528ef24…3e2d6`), `tools/build_root.py` (payload pin, packaging, version), `RootEngine.java` (`PAYLOAD_KSU` staged with the other payloads; `loadKernelSu()` runs after root verifies), manifest versionCode 11.

The flow is otherwise unchanged: exploit → verify → **insmod the module with `allow_shell=1`** → check `/proc/modules`. KernelSU then owns root, SELinux returns to Enforcing, and the ghost daemon stops mattering. Repeatable; an already-loaded module reports `File exists`.

After a plain `adb reboot`, no interaction:

```
22:10:14  am_foreground_service_start: .../.RootService, BOOT_COMPLETED
/proc/modules: kernelsu 335872 0 - Live
$ adb shell 'su -c id'
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
shared_prefs/local_root.xml: ksu_loaded="true"
```

`su` reaches UID 2000 only because of `allow_shell=1`. Per-app grants live in `/data/adb/ksu/.allowlist` and **survive reboots** (Shizuku's uid `10220` was already there); the KernelSU-Next manager caches "not installed" if it probed while no driver was loaded, so reopen it to refresh. Mechanism notes: `builds/gxr-kernel/ksu-probe-20261009/RECEIPT.md`.

`RootEngine.KSU_MODULE_URL` points at the project's own KernelSU-Next-GXR release (`https://github.com/AngelDark92/KernelSU-Next-GXR/releases/latest`) — the upstream page's module does not work on this device. The release hosts the patched module, the matching manager APK and all hashes.

## Rollback

Reboot the headset (SELinux returns to Enforcing, root gone, `panic_on_oops` back to default), then uninstall the app if desired. Nothing is written to any verified partition; there is nothing else to undo.

> Note (current builds): this "nothing else to undo" predates the KernelSU late-load and the wireless-debugging setting writes. Since then, state survives a reboot: `/data/local/tmp/gxr-root` (stock Android does not clear `/data/local/tmp`), `/data/adb/ksu/*` (KernelSU-Next's, incl. `.allowlist`), and the `Settings.Global` adb values. Use the app's **Remove root** before uninstalling; see the README's "Remove root / uninstall".

## Never

No flashing, no remount, no AVB/slot change, no modification of any verified partition, no automatic root retry.
