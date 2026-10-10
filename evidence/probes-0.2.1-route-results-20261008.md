# 0.2.1 route-probe results — KASLR leak + spray alternatives (2026-10-08)

APK `GalaxyXR-Root-Manager-probes-0.2.1.apk` (versionCode 5, `0.2.1-probes`, SHA-256 `f554c8abce1dfcf22aa52e3fe2f054c22a4b67cf62806f0120b55cdb8f066767`), serial `R3GYB09JA5E`, boot `611969ec-084a-4a59-b76f-1f6cc28e1ef3` (device rebooted between 0.2.0 and 0.2.1 runs), app UID 10244. Report: `evidence/diagnostics-0.2.1-20261008-app.json`.

## Route A — perf_event_open KASLR leak: BLOCKED

| Probe | Result |
|---|---|
| `perf_event_open_hw_cpu_cycles` | exit 13 (EACCES) |
| `perf_event_open_sw_cpu_clock` | exit 13 (EACCES) |
| `perf_event_open_sw_page_faults` | exit 13 (EACCES) |

All three q3slide.c tiers denied in app context. Samsung denies perf_event_open to untrusted_app regardless of event type (unlike Meta Quest 3, where this route roots the device). IonStackQuest3 leak port is dead on this target.

## Route C — fork-hold spray without /proc/<child>/mem: VIABLE

| Probe | Result |
|---|---|
| `fork_hold_pause_reapable` | exit 0 — app can fork, child stays alive in `pause()`, kill+reap works |
| `ashmem_boot_path_open` | exit 0 (probe newline bug fixed) — `/dev/ashmem<boot_id>` open allowed |

Forked children pin their own `mm_struct` in the order-2 slab while alive. The original `/proc/<child>/mem` open only exists to pin mm_struct after child death. Alive children remove that dependency entirely: spray = fork batch → leak via KernelSnitch (runs inside the forked child, no cross-process read) → kill batch. `clone_child()` (`util.c:364`) and `clone_leak_child()` (`util.c:379`) already run their logic inside the child. No exploit-code rework needed beyond removing the `open_memfd()` calls; `mm_objs_per_slab` geometry unchanged.

## Standing blockers after this run

1. KASLR leak in app context. Tracefs denied (0.2.0), perf denied (0.2.1). Remaining candidates on this build: none known. `kptr_restrict` symbol exists in kernel (`kallsyms_vmlinux_sorted.txt:154772`) but its live value is unknown from app context and `/proc/kallsyms` is already denied.
2. Spray: unblocked via Route C.

## Consequence

APK-direct rooting now hangs entirely on the KASLR leak. If no app-accessible disclosure exists, remaining options are (a) hybrid external bootstrap (PC supplies slide once per boot over an authorized channel — still needs the device connected to something), or (b) accepting a bounded slide brute-force (63 candidates at 0x8000 alignment — rejected as unsafe: wrong slide = kernel write to wrong address, panic risk on a device with no recovery path).

The slide cannot be hardcoded or cached across boots. Until a leak route is found, APK-direct root stays blocked at stage 1.