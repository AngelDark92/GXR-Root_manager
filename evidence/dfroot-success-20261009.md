# DFRoot (CVE-2026-43284 DirtyFrag) live result — SUCCESS (2026-10-09)

Serial `R3GYB09JA5E`, same boot as the 0.3.x local-adb work. Owner ran DFRoot 4.1 (`cd3e78f666b44b45d0ce59253ce4142c62440edb6470708597bbf49554cd06a4`) with KernelSU `samsung-v1.0_32664-release` (`c92f56c6569bfede6a37fdfa209e248c6a8f73b77214e51a3658ac2fec5dcf1e`) as SU manager.

## Owner-supplied DFRoot log (verbatim key lines)

```
patch: crash_dump64 <- splicehelper (1408 bytes)
patched 1408 bytes to /apex/com.android.runtime/bin/crash_dump64+0x0
Using KMI: android12-5.10
patch: /vendor/lib64/libbinderdebug.so <- dfroot.ko (12544 bytes)
patched 12544 bytes to /vendor/lib64/libbinderdebug.so+0x0
PACIASP/BTI found at hook site, advancing +4
Found: hook=0x68cb0 shellcode=0xb17a8 len=548
patch: /system/lib64/libc++.so <- shellcode (560 bytes)
patched 560 bytes to /system/lib64/libc++.so+0xb17a8
patched 16 bytes to /system/lib64/libc++.so+0x68cb0
=== init ===
libc++: loading custom module
kernel module: launching bootstrap
bootstrap: starting SU daemon
ksud start: SUCCESS
=== cleanup ===
restoring trampoline in /system/lib64/libc++.so (16 bytes)
restoring shellcode in /system/lib64/libc++.so (560 bytes)
```

## Independent PC verification (ADB, same boot)

- `/dev/df`, `/dev/dfm0`, `/dev/dfm1` exist — DFRoot markers present.
- `getenforce` = `Permissive` (was Enforcing before; module wrote `selinux_state`).
- `/proc/kallsyms' contains 131 `ksu` symbols — KernelSU LKM loaded in the running kernel (kptr normally hides symbols; module presence is what these hits show).
- `zygote64` runs as `root` as before (stock).
- `/data/adb` not shell-readable (expected; root-only).
- Shell `su` not present (KernelSU exposes su to granted apps, not adb shell).

## Interpretation

- CVE-2026-43284 is UNPATCHED on this kernel (`5.10.240-android12-9-perf-33775878-abI610UEU2AZF3`): ESP page-cache CBC write primitive works, crash_dump64 bridge works, module load works.
- Root is now supplied by KernelSU (kernel-based), started from a plain app — no PC, no wireless debugging, no Shizuku, no ADB.
- DFRoot "Start at Boot" receiver exists (`LOCKED_BOOT_COMPLETED` + `BOOT_COMPLETED`, `directBootAware`); per-boot persistence still to be tested across a reboot (next milestone).
- This supersedes the GhostLock APK route for daily use: simpler, app-context-native, with a full SU manager (per-app grants, modules).
- The earlier "connection pending" wireless-adb bug in our manager is moot for this route but remains unfixed in our 0.3.4 tree if that fallback is ever needed.

## Not verified yet

- Root surviving reboot (DFRoot Start-at-Boot enabled state unknown; KernelSU manager state unconfirmed from PC since shell has no su).
- KernelSU app UI: owner should open the KernelSU app and check "Working" status and grant lists.