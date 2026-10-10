# Shizuku shell-context verification (2026-10-08, serial R3GYB09JA5E, boot 611969ec-084a-4a59-b76f-1f6cc28e1ef3)

## State found

- Shizuku app `moe.shizuku.privileged.api` 13.6.0 (versionCode 1086) installed, UID 10220.
- No `shizuku_server` process: Shizuku was installed but never started. No starter files in `/data/local/tmp` or its external dirs.

## Server start (reproduction)

1. `adb shell pm path moe.shizuku.privileged.api` → APK path.
2. Pull APK, extract `lib/arm64-v8a/libshizuku.so` (the starter binary shipped inside the app).
3. `adb push` to `/data/local/tmp/libshizuku.so`, `chmod 755`, run it. Output:
   `info: starter begin`, `killing old process`, `apk path is /data/app/...`, `starting server`, `shizuku_server pid is 11393`.
4. Result: `shizuku_server` UID `2000`, GID `2000`, groups `1004 1007 1011 1015 1028 1078 1079 3001 3002 3003 3006 3009 3011 3012`, PPID 1 (init — survives app death and adb disconnect).

Group `3012` = `readtracefs`. This is exactly the shell context the proven exploit chain uses.

## Shell-context slide leak verified

Ran the tracefs leak steps by hand as shell (`tracing_on=1`, `sched_blocked_reason/enable=1`, read `per_cpu/cpu0/trace_pipe_raw`): event ID 85 (0x55) samples present, caller pointer `0xffffffc008386184` observed. With `SLIDE_TRACEFS_WORKER_CALLER_OFF=0x196184` (`target.h:26`), candidate slide this boot = `0x1f0000` (within ≤0x1f0000, 0x8000-aligned — valid).

## Consequence for the hybrid route

- A Shizuku UserService can run the whole proven exploit unchanged (leak + spray + trigger + root), because the code executes inside `shizuku_server` (UID 2000, group 3012, seccomp 0 in that process).
- The exploit's daemon authorizes the initiating UID (captured `root.c:132`, checked `su_daemon.c:646,652`). Initiated by Shizuku server → daemon authorizes UID 2000. The manager app (10244) must therefore run its su client through Shizuku too, not connect directly.
- Per-boot flow: Shizuku server dies on reboot. Restart needs either one `adb shell` command from any PC/wireless-debugging pairing via the Shizuku app UI on the headset. No persistent shell survives reboot without root.
- APK-side requirements: declare `moe.shizuku.manager.permission.API_V23`, bind the Shizuku UserService, user grants the app in the Shizuku UI. No special Android permissions beyond that.

## Answer to "which permissions"

Device settings: Developer options → USB debugging (start via PC) or Wireless debugging (start from the headset with pairing code). In the Shizuku app: grant the root-manager "allow shell privileges" once it requests. In the manager manifest: the Shizuku API permission above. Nothing else; the server provides the context.