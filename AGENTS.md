# Galaxy XR Root Manager (standalone repository)

Personal project for the owner's own Galaxy XR (SM-I610, `I610UEU2AZF3`, locked bootloader). No
warranty; the owner accepts the risk. The app roots the headset on-device with no PC and nothing
is flashed. Verified live 2026-10-09 — see `docs/RUNBOOK-0.3.4-ondevice.md`.

Extracted from `gxr-kernel/root-manager` on 2026-10-10 at version 0.3.5.

Rules:

- Never flash, remount, patch a boot image, unlock the bootloader, change AVB/slots, write a
  verified partition, manipulate an OTA, or change display settings.
- One attempt per boot, latched before launch. Never automatically retry after a partial failure;
  rearm manually and reboot for a fresh latch. Do not kill the exploit's retained allocation keeper.
- Exact-build gate: refuse any fingerprint other than
  `samsung/xrvst2ue/xrvst2:14/UML2.260301.001/I610UEU2AZF3:user/release-keys`.
- A missing or unreachable root daemon means root could not be verified — never proof that the
  device has no root. Bind root evidence to the live boot id.
- App access decisions bind to caller UID, package and signing certificate; reject shared UIDs,
  unknown callers and changed signers. Preview approvals never grant root capability.
- App-context diagnostics must not write tracefs, consume raw trace data, trigger the exploit,
  spray allocations, run root commands, or change SELinux.
- Preserve the exploit payloads and the receipts under `evidence/` unchanged.

Build, version and release:

- Version truth is `VERSION` in `tools/build_root.py`. `tools/release_policy.py` is its only
  writer; `tools/verify_release_version.py` fails the run when the manifest or a pushed tag
  disagrees.
- Build output goes to `<repository>-builds/build` beside the source tree, never inside it.
- The development signing key lives in `.local/` and is never printed, committed or distributed.
  CI restores it from the `GXR_DEBUG_KEYSTORE_BASE64` secret when that secret exists, otherwise it
  generates an ephemeral key. The keystore password is fixed at `android` by `tools/build_root.py`.
- Tags are immutable. `.github/workflows/release.yml` publishes only on `main`, on a matching `v*`
  tag, or on a dispatch that asked to publish; every other push and every pull request is a
  build-only dry run.
- CI runs no tests. The unit suite is the local gate instead: run `python -B tools/fetch_test_deps.py`
  once per machine, then `python -B -m unittest discover -s tests -v` with `JAVA_HOME` at JDK 17+ at
  the end of every task, and never push a tree whose suite fails. CI assumes each pushed commit
  already passed it.
