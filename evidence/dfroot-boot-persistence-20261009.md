# DFRoot Start-at-Boot — reboot verification SUCCESS (2026-10-09)

Fresh boot `c71c5904-49b0-464d-8824-4aec0e16540b` (previous rooted boot was `611969ec…` — different, confirming a real restart; also earlier `d1d075c5…`/`d055f29e…` boots).

PC-verified on the new boot, no manual root action taken between reboot and check:

- `/dev/df`, `/dev/dfm0`, `/dev/dfm1`, `/dev/dfm2` exist — DFRoot boot receiver re-ran the exploit chain from the plain app (dfm2 present this time: farther progress marker than the manual run).
- `getenforce` = `Permissive` — module's `selinux_state` write re-applied.
- `/proc/kallsyms contains 131 `ksu` symbols — KernelSU LKM loaded again.

Conclusion: DFRoot's `Start at Boot` (`LOCKED_BOOT_COMPLETED`/`BOOT_COMPLETED`, `directBootAware`) automatically re-roots after restart with no PC, no wireless debugging, no user interaction. Root persistence goal met by DFRoot + KernelSU.

## Consequence for this project's own tooling

- The GhostLock (CVE-2026-43499) APK route (0.3.0–0.3.4) and its local-adb engine are superseded for daily use; kept only as a fallback if CVE-2026-43284 ever gets patched by an OTA while CVE-2026-43499 remains open (reverse unlikely — Samsung will patch both).
- The 0.1.2 status APK, verifier work and evidence chain remain valid as history.
- Watch OTA updates: any firmware update changing the kernel (`ro.build.fingerprint`) can break DirtyFrag, KernelSU module KMI match, and DFRoot's prebuilt .ko set. Re-check after every OS update before assuming root persistence.