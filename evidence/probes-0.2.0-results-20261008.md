# 0.2.0 feasibility probes — result record (2026-10-08)

Probe APK `GalaxyXR-Root-Manager-probes-0.2.0.apk` (versionCode 4, `0.2.0-probes`, SHA-256 `27717391c513e9d9683e3afaf160782d8c6979a3df9843055c7619af2cbd4384`) installed on serial `R3GYB09JA5E`, boot `d1d075c5-33cb-4663-ad10-d92525508a8d`, app UID `10244`, SELinux Enforcing. Reports: `evidence/diagnostics-0.2.0-20261008-app.json` (run 1) and `evidence/diagnostics-0.2.0-20261008-app-r2.json` (run 2, corrected `exec_self_lib` probe). Live shell identity M0: fingerprint `samsung/xrvst2ue/xrvst2:14/UML2.260301.001/I610UEU2AZF3:user/release-keys`, kernel `5.10.240-android12-9-perf-33775878-abI610UEU2AZF3`, slot suffix empty, AVB green, vbmeta locked, CPUs `0-5`, seccomp `0`, tracefs group `3012` (readtracefs) present in shell.

App-context probes (forked child per probe, exit code = errno or 0/signal):

| Probe | Result | Meaning |
|---|---|---|
| `futex_lock_pi` | exit 0 | FUTEX_LOCK_PI allowed for the app |
| `futex_wait_requeue_pi` | exit 110 (ETIMEDOUT) | syscall reached futex logic; zero-timeout wait path functional |
| `futex_cmp_requeue_pi` | exit 0 | FUTEX_CMP_REQUEUE_PI allowed |
| `pselect6` | exit 0 | allowed |
| `pipe_f_dupfd` | exit 0 | pipe + F_DUPFD(208) allowed |
| `posix_openpt` | exit 0 | /dev/ptmx open allowed for the app — root-stage wake path unblocked |
| `sched_setattr` | exit 0 | allowed on own thread |
| `socketpair_unix_stream`, `socket_unix_dgram` | exit 0 | AF_UNIX allowed — reclaim skb spray socket path unblocked |
| `readlink_self_exe` | exit 0 | /proc/self/exe readable |
| `exec_self_lib` | SIGSEGV in child (both runs) | child located packaged `libgxr_diagnostics.so` via `/proc/self/maps` and execved it; death is the .so failing to run as a program (expected ENOEXEC-adjacent failure), NOT `EACCES`. No execpolicy denial was observed: packaged native lib exec not blocked by policy before the binary-format stage. A purpose-built PIE exploit binary in the same dir remains to be proven (follow-up). |
| `proc_child_mem_open` | exit 2 (ENOENT) | **BLOCKER**: opening `/proc/<child>/mem` fails in app context; exploit stage-2 `mm_struct` spray (`open_memfd`, `util.c:392-396`) cannot run as-is |
| `ashmem_boot_path_open` | exit 2 in child probe (probe bug: boot_id read includes trailing newline; parent probe of the same `/dev/ashmem<boot_id>` path returned `open_allowed true errno 0`) | boot-specific ashmem `/dev/ashmem<boot_id>` open allowed for the app — stage-4 configfs primitive entry point unblocked |
| tracefs `tracing_on`, `sched_blocked_reason/enable`, `trace`, `per_cpu/cpu0/trace_pipe_raw` | denied errno 13 | **BLOCKER**: KASLR leak route (`slide.c`) not app-accessible; shell-group `readtracefs` is not available to `untrusted_app` |

Root verification in-app: `unverifiable` (no root daemon exists this boot) — expected.

## Verdict per stage

- Stage 3 write primitive (futex-PI + pselect): all syscalls allowed. CPU affinity: app restricted to CPUs 2,3 (this boot; earlier report 2-5) — the fixed `CORE 0` pin must change to an allowed CPU.
- Stage 2 page reclaim (mm_struct spray via `/proc/<child>/mem`): **blocked in app context**. Alternatives: spray via other order-2 slab objects reachable from an app (e.g. `struct file`, skbs, epoll) — none ported yet; requires exploit-side rework with its own live validation.
- Stage 4 configfs r/w via boot-specific ashmem fd: open allowed.
- Stage 6 UMH wake via `posix_openpt`: allowed.
- KASLR: **blocked**. No app-accessible kernel-address disclosure is known on this build. Candidate follow-ups (unvalidated): `/proc/self/syscall`-style disclosures, perf_event_open mmap page, any ioctl leaking pointers, secondary info-leak bug. Without a leak, APK-direct rooting cannot complete; slide must not be hardcoded or cached across boots.
- Exec of packaged native code: no policy denial observed; PIE exploit binary test still pending.
- Seccomp: mode 2 filter active; every probed exploit-needed syscall passed, so the filter does not block the probed set.

## Consequence

APK-direct rooting remains unproven and gated on two blockers: (1) app-accessible KASLR leak, (2) `/proc/<child>/mem` spray alternative. All other probed prerequisites pass in app context. External-bootstrap route (PC pushes exploit, APK integrates with resulting daemon) is unaffected by these blockers and remains the nearer path per `docs/BOOTSTRAP-INTEGRATION.md`.