# Local-ADB (LADB pattern) on-device verification — in progress (2026-10-08)

Goal: manager APK embeds an adb client (`libadb.so` arm64 from LADB, GPLv3) and pairs to the headset's own wireless debugging, giving a self-hosted UID-2000 shell with no PC and no Shizuku. This is the exact mechanism LADB/aShell You ship.

## Verified on-device so far

- LADB `libadb.so` (arm64, adb 1.0.41 / platform 34) executes on the headset: `version` prints correctly from `/data/local/tmp/libadb.so`.
- `adb start-server` inside a device shell starts the daemon on `127.0.0.1:5037` (netstat confirmed pid 11714/adb LISTEN).
- `adb_mdns_enabled` was `null` → set to `1` (persists); `svc adb restart` is not available on this build (svc has no adb subcommand), but adbd responds to prop changes.
- adbd runs TLS listeners on loopback: ports `42943`, `38335`, `39593` (`::ffff:127.0.0.1` LISTEN). These are the wireless-debugging connect/pair sockets; they exist while USB debugging is active.
- `adb connect localhost:<port>` to those ports did not complete from a short-lived shell (SYN_SENT on 42943; others timed out): plain TCP connect is refused until wireless-debugging authentication (pairing) is completed — expected, matches AOSP: adbd's TLS server only accepts paired keys.
- `settings put global adb_wifi_enabled 1` does not stick (reads 0): wireless debugging is toggled by the framework's Developer-options UI only, requiring a user gesture. Same for the connect/pair dialogs — they generate pairing codes bound to the UI session.

## Blocked on user action

The wireless-debugging toggle must be turned on once from the headset Settings UI. After that, `adb pair localhost:<pair_port> <code>` (code shown in the UI dialog) authenticates the app's embedded key; subsequent boots need only the toggle + open app (pairing persists in adbd's key store).

## Chain readiness (all previously verified)

- Exploit binaries (`cve-2026-43499` sha256 `7a01fb0f…2f1f`, `cve-2026-43499-root` sha256 `dae60789…bf88`) run as shell; slide-only run completed `attempt=1/1`, slide `001f0000` on current boot.
- Shell context has group 3012 (`readtracefs`), seccomp 0, CPUs 0-5 — full chain proven in REPORT.md and re-verified for the slide stage today.
- Shizuku server also demonstrated working (started, UID 2000) — fallback if local-adb pairing proves unreliable, but not required.

## Next

1. Owner enables Wireless debugging in headset Settings.
2. Re-test `adb connect localhost:<port>` from on-device daemon; expect success after pairing with the code from the UI.
3. If green: build 0.3.0 — manager embeds libadb.so + exploit assets, pairing screen, Root button running the exact RUNBOOK sequence through its own local shell, fingerprint gate, 1-attempt latch, verify via daemon status protocol.