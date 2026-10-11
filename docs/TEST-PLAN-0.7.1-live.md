# Live Test Plan — Root Manager v0.7.1+WIP (uncommitted changes)

Device: Galaxy XR SM-I610, I610UEU2AZF3. Serial R3GYB09JA5E.
Build under test: v0.7.1 plus the uncommitted working-tree changes
(preflight gates, removal gating, rearm dialog, sticky-bottom log, direct-su
verify, boot streak/loop breaker, dev-options navigation).
Runbook: owner executes each test on the headset; Hermes drives ADB
(logcat, screencap, status reads), reproduces and plans fixes for every
reported bug. One test at a time. After each test the owner answers **Ok**
(continue) or **Bugged** (describe what happened).

## Standing rules for this session

- Exploit-consuming tests run ONE attempt per boot, by design. Tests that
  spend the latch are marked **[spends latch]** and grouped late; if a run
  fails, reboot before the next latch-spending test (or use Rearm only where
  the test says so).
- Tests marked **[owner]** need a physical action only the owner can do
  (Settings navigation, pairing dialog, wearing the headset to tap).
- Hermes captures `adb exec-out screencap -p` before/after UI tests so
  panel layout is verifiable from the host.
- Never test on a device the owner needs rooted unless the owner confirms.
  Kernel root persists until restart regardless of app state.
- After each Bugged report: Hermes reproduces via ADB, identifies the
  failing code path (file:line), and plans the fix before the next test.

## Phase 0 — Build and install (Hermes, before any on-device test)

- P0.1 Build the WIP tree with `tools/build_root.py` (JAVA_HOME=F:/Runtimes/Java21),
  version untouched → `adb install -r` over the installed 0.7.1.
- P0.2 `adb shell am force-stop dev.galaxyxr.rootmanager` then relaunch.
  Expected: app opens, no crash, startup notice visible.

## Phase 1 — Startup, status, KernelSU gate (no latch spent)

- T1 Startup state. Fresh launch. Expected: status line "Checking root…"
  then a verify outcome; log card renders; no ANR within 10 s.
- T2 Verify root, unrooted+ungranted device. Press Verify root.
  Expected: label "Root could not be verified", reason names BOTH remedies
  (KernelSU grant, wireless debugging), contains "never means the device has no root".
- T3 Verify root, direct su path. Grant Root Manager in KernelSU-Next
  manager (Apps tab) while device rooted. Press Verify root.
  Expected: "Root active for this boot (KernelSU)" via channel kernelsu_su
  within ~10 s WITHOUT wireless debugging on. Log shows `uid=0(root)` + boot_id.
- T4 Verify root, boot-id mismatch. (Only if a stale su answer can be
  provoked — skip if not reproducible.) Expect state ksu_stale, honest wording.
- T5 KernelSU manager gate. Uninstall com.rifsxd.ksunext (or test before
  install). Press Root now. Expected: "Root locked" dialog, no engine work,
  Root now + Re-root checkbox disabled. Reinstall after.
- T6 Removal gate persistence. After any Remove root this boot: Root now,
  Remove root and Re-root checkbox all stay disabled until a restart.

## Phase 2 — Log card behavior (no latch spent)

- T7 Log auto-scroll sticky-bottom. Run any flow producing >20 log lines
  (pairing or verify with verbose output). While at bottom: new lines keep
  view pinned to newest. Then scroll up several lines: new lines must NOT
  move the view (yank = bug). Scroll back to bottom: following resumes.
- T8 Log selectable text. Long-press log: select-all/copy works, drag
  gestures scroll the log box, not just the page.
- T9 Page scroll to log on run start. Start a Root/Pair action: page
  scrolls once to the log card; subsequent lines do not re-trigger page scroll.

## Phase 3 — Pairing and ports (no latch spent)

- T10 Find port with wireless debugging on. Expected: pairing port found
  via mDNS, shown in Pairing card; no false "wireless debugging appears off".
- T11 Pair now. Enter the 6-digit code, press Pair now. Expected:
  "Pairing succeeded" dialog naming the port.
- T12 Pair now, wrong code. Expected: "Pairing failed" dialog naming the
  port, advice to re-open Pair device with pairing code.
- T13 Open Developer options button. Expected: opens General page (one tap
  above Developer options), in a SEPARATE XR window — app panel still visible
  beside it, so the code can be copied.
- T14 Dev options disabled path. (If dev options were off.) Expected: dialog
  explains Build number x7 path, "Open General" works.

## Phase 4 — Supervised root run **[spends latch]**

- T15 Preflight: removed-this-boot gate. (Skip unless a remove happened
  this boot.) Press Root now: dialog "Root was removed this boot", no engine work.
- T16 Preflight: latch gate after a previous failed attempt. Press Root now:
  dialog "Previous attempt did not verify root" with "Rearm and continue"
  one-tap button. Rearm clears latch, run starts, no stuck-busy state.
- T17 Preflight: missing pairing code. With code empty: dialog "Pairing
  code required", no run starts, app NOT left busy.
- T18 Full run, happy path. Preconditions: KSU installed, paired, code set,
  fresh boot. Press Root now → accept danger dialog. Expected: preflights
  pass BEFORE busy; run streams log lines; SELinux permissive for this boot
  only; exploit launches once; daemon check `uid=0(root)` over uid-2000 shell;
  KernelSU late-load LAST step only after root check passes; `kernelsu` in
  /proc/modules; outcome dialog "Root succeeded"; attempt latch spent.
- T19 Outcome wording, timeout case. (Only if a timeout occurs naturally.)
  Expect "Root run did not finish", never "no root".
- T20 Verify after success. Press Verify root. Expected: verified via
  direct su (KernelSU) if granted, else via daemon over shell; honest label.

## Phase 5 — Remove root **[leaves rooted-until-restart state]**

- T21 Remove root, connected. Press Remove root → confirm. Expected:
  auto_boot disabled FIRST; own artifacts gone (`/data/local/tmp/gxr-root/`
  empty, no temp_su.sock); wireless setting reverted; WRITE_SECURE_SETTINGS
  dropped last; report state removed/complete=true; boot id latched in
  removed_boot; Remove card states kernel root persists until restart.
- T22 Post-remove gating. After T21: Root now, Remove root, Re-root
  checkbox disabled (visual + real). Checkbox tap reverts silently, no
  double dialog.
- T23 Post-remove verify. Press Verify root. Expected: still reports root
  truthfully through su path (kernel still holds root) — NOT "no root".
- T24 Remove root, headset disconnected. (Kill wireless debugging /
  restart with wireless off.) Expected: settings revert still attempted;
  state not_connected; honest output; grant dropped only if shell reachable.

## Phase 6 — Boot flow **[owner reboots required]**

- T25 Re-root after restart, happy path. Enable Re-root after every
  restart (danger dialog path). Restart. Expected: boot receiver fires,
  foreground service type 34, manager gate passes, verify-first short-circuits
  if already rooted, one attempt, notification (if POST_NOTIFICATIONS granted)
  "Root active for this boot", streak reset to 0 on success.
- T26 Manager-absent boot lockout. Uninstall KSU manager, set auto-boot,
  restart. Expected: service notifies "Root locked: KernelSU-Next is not
  installed", stops before ANY engine work, no exploit, no setting writes.
  (Safe: nothing happens.)
- T27 Loop breaker. Simulate two consecutive failed boot runs (per
  runbook: boot_run_open left true, or two real failed attempts).
  Expected: auto_boot cleared by the app, notification "Automatic re-root
  stopped after repeated failures", service stops.
- T28 Connectivity failure does not count. Boot with wireless debugging
  unreachable but exploit never launched. Expected: streak NOT incremented
  (latch boot id ≠ attempt boot id).
- T29 WRITE_SECURE_SETTINGS dependency. After Remove root (grant dropped),
  enable auto-boot, restart. Expected: boot run dies pre-latch with clear
  connect failure; latch still free; README-consistent behavior. Re-grant
  over uid-2000 shell to restore unattended flow.

## Phase 7 — Diagnostics/evidence (no latch spent)

- T30 Status JSON sanity. `adb shell` uid-2000 read of engine status:
  attempt_boot, last_outcome, root_removed_this_boot all consistent with
  the live boot id.
- T31 Evidence pull. Reports in /sdcard/Android/data/dev.galaxyxr.rootmanager/files/
  newest first; preserved under evidence/ with fresh names; never overwritten.

## Order of execution

Phase 0 → 1 → 2 → 3 → 4 (T15–T17 need no reboot if gates not triggered;
T18 needs fresh boot) → 5 (needs rooted state from T18; ends with restart
built in via T22 gating check after reboot) → 6 (owner reboots) → 7.
If any test is Bugged: fix lands, rebuild, `adb install -r`, retest that
test before moving on.

## Fix planning per bug report

For each Bugged report Hermes will:
1. Reproduce via ADB (logcat + screencap + engine status) while owner confirms.
2. Name failing path file:line and root cause.
3. Propose minimal patch through the patch crew (exploit bot brief, verify
   pass), respecting AGENTS.md invariants (consent gates never removed,
   one attempt per boot, exact-build gate, evidence preserved).
4. Apply patch, rebuild, install, retest the failing test.