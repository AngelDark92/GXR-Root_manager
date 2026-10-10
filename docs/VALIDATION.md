# Read-only status milestone validation — 2026-10-08

Artifact relocation, 2026-10-08: build artifacts now live under `../../../builds/gxr-kernel/root-manager/build`; the retained reference-build directory lives under `../../../builds/gxr-kernel/root-manager/evidence/`. Historical JSON receipts remain unchanged. The relocation manifest `../../../builds/gxr-kernel/relocation-correction-20261008-181036.json` binds old/new locations, byte counts and SHA-256 hashes. Earlier validation below describes the source/builder at that time; it does not validate the build-path edits.

## Current 0.1.2 artifact and PC checks

- APK: `../../../builds/gxr-kernel/root-manager/build/GalaxyXR-Root-Manager-status-0.1.2.apk`; version `0.1.2-status`, code `3`; package `dev.galaxyxr.rootmanager`.
- Bytes: `41590`; SHA-256: `7cb9ec3d41821717df1ff16efafaee133064e05a9029d670ba07109db54e914b`.
- Development signer unchanged: certificate SHA-256 `89f9fb69cdd7ca670d5f7b2f74306887dc564e556a93849bb4f9a00bb77e8539`; Android v3 signature verified with official apksigner. Manifest, APK contents, source/tool hashes, packaged native library and JNI export were checked statically. All 22 original exploit files remain unchanged.
- `onResume()` automatically starts fresh verification on a worker; **Verify root again** supports checking after an external root attempt. Previous proof clears when a new check starts. The native status operation authenticates kernel-reported server UID `0` on the same socket before protocol traffic, requires the server's client authorization, and uses a fixed read-only command, bounded output and 1.5-second deadline.
- `RootStatus` reports `verified_root`, `root_server_app_denied`, `unverifiable` or `verification_failed`. Success requires protocol status `0`, command UID `0`, well-formed complete output and equal valid boot IDs observed before, after and by the server. Missing/inaccessible servers and failed checks never prove global absence of root. The original root daemon can authorize only its initiating shell UID `2000`, excluding the reported app UID `10244`; server authentication can succeed while manager access is denied.
- Current Windows project suite: 34 passed, 7 Linux-only tests skipped, 41 total. Production `RootStatus` passed 78 synthetic scenarios / 390 assertions. Existing firmware suite: 35 passed, 0 skipped. Synthetic JVM checks are not Android runtime tests.
- Refactored standalone CLI passed 6 Android negative checks in [the current device evidence](../evidence/verifier-device-checks-20261008-03.json). These cover 4 CLI rejections, nonroot peer rejection and zero client protocol bytes. Helpers were hash-checked and uploaded privately. This is standalone CLI evidence; no 0.1.2 APK installation or APK/JNI/Activity runtime validation occurred. Positive native UID-0 protocol tests remain skipped.
- No exploit payload, boot receiver, root execution, client root capability or startup restoration is present. No exploit, reboot or partition write occurred. API preview consent remains separate from root capability and cannot grant it.
- The 0.1.1 APK remains retained, with its receipts preserved as `../evidence/build-receipt-0.1.1.json` and `../evidence/artifact-validation-0.1.1.json`. Current build/artifact receipts describe 0.1.2, not earlier artifacts.

The [retained 0.1.2 validation summary](../evidence/root-status-apk-0.1.2-validation.json) binds these results to the exact APK. Cavecrew reviews reported no issues in the status/JNI and app/build scopes; neither review covers the unresolved exploit lifecycle.

To test, install/update 0.1.2, open for its automatic check, use **Verify root again** after an external root attempt, then share the report. This build cannot enable root after startup. Exact target binding and safe partial-failure allocation ownership remain unresolved; root execution remains gated. The previously delegated failure-lifetime audit was blocked by automated cyber review reporting `possible cybersecurity risk`; it did not run and was not retried.

## External-bootstrap preparation

The owner requested execution of the bootstrap/integration plan. The current standalone native read-only verifier compiled with NDK 27.2.12479018 for AArch64/API 34, `-Wall -Wextra -Werror`, PIE, stack protection and RELRO/NOW. Artifact: `../../../builds/gxr-kernel/root-manager/build/bootstrap-stage-5ewhks21/gxr-bootstrap-verifier`, 15,936 bytes, SHA-256 `e7dbd28352a2beaa0921eadaa5bdcb85db897567755d5fb6f08f1d5fdd8bea12`; source/compiler hashes and the build command are in that stage's `receipt.json`. Prior artifacts remain: `../../../builds/gxr-kernel/root-manager/build/bootstrap-stage-_iyl2ymm/gxr-bootstrap-verifier`, 15,704 bytes, SHA-256 `0d3cecf25ea3f3e17439caae9ef8c1fa6bf8c6f9e6de394136946379500655bf`, and `../../../builds/gxr-kernel/root-manager/build/bootstrap-stage-3t8dgkj5/gxr-bootstrap-verifier`, 15,640 bytes, SHA-256 `93d4ee20613b40bb0978a2516502fbda88dca9bb065a7a61d54bb5854ee46535`, each with its historical receipt. These standalone verifiers contain no exploit; 0.1.2 also packages the authenticated status implementation in its diagnostic/status JNI library.

At the prior external-bootstrap preparation checkpoint, the project suite passed 33 tests and skipped 7 native Linux tests; existing firmware suite passed 35 with 0 skipped. Current results appear above. Windows did not execute the Linux credential/protocol tests, and WSL was unavailable (`Wsl/CallMsi/REGDB_E_CLASSNOTREG`). Cross-compilation and independent Cavecrew review are not runtime proof.

The [historical preflight](../evidence/bootstrap-preflight-20261008-execute-01.json) recorded `unauthorized`; one local ADB server restart did not resolve it. After the owner revoked debugging grants and reauthorized this PC, [the authorized preflight](../evidence/bootstrap-preflight-20261008-authorized-01.json) reached serial `R3GYB09JA5E` as `device` using `../Tools/install/platform-tools/adb.exe`. Live fingerprint: `samsung/xrvst2ue/xrvst2:14/UML2.260301.001/I610UEU2AZF3:user/release-keys`. Shell UID `2000`, seccomp `0` and CPUs `0,1,2,3,4,5` differ from the supplied app's UID `10244`, seccomp `2` and CPUs `2,3,4,5`. SELinux was `Enforcing`; boot ID was `d055f29e-a994-4b88-a07b-b5a998f8faf1`. [Same-boot read-only observations](../evidence/bootstrap-readonly-observations-20261008-01.json) record empty slot suffix and `ro.virtual_ab.enabled`, both unknown; verified boot `green`, vbmeta `locked`, and denied `/sys/kernel/notes` access. The [historical kernel banner correlation](../evidence/target-correlation-20261008-01.json) also matches the live kernel release/version, but does not establish live kernel byte identity.

Hash-checked verifier and nonroot fixture helpers were uploaded into private device test directories. [The earlier Android checks](../evidence/verifier-device-checks-20261008-02.json) passed 6 cases: 4 CLI rejections, same-socket UID `2000` rejection, and fixture confirmation of zero client protocol bytes. The fixture used an isolated abstract Unix endpoint; [the earlier filesystem bind failure](../evidence/verifier-device-checks-20261008-01.json) is retained. Current refactored CLI checks are recorded above. Default `--probe` and `--status` returned `connect_failed`; the same-boot read-only observations record `/data/local/tmp/temp_su.sock` absent. No existing original daemon was verified; global device root status remains unestablished. These negative Android checks do not prove positive UID-0 protocol behavior, APK enrollment or broker integration.

No exploit, APK installation, firmware capture, reboot or partition write occurred. The original supervisor's timeout can kill allocation owners before the post-success keeper exists; this and exact target binding remain unresolved live-bootstrap gates. The separately delegated failure-lifetime audit was blocked by automated cyber review reporting `possible cybersecurity risk`; that audit did not run.

The [execution checkpoint](BOOTSTRAP-INTEGRATION.md) lists implemented preparation and pending integration. Personal-device scope and continuing authorization are recorded in `../AGENTS.md` and the project Cavecrew skill; pre-edit backups are retained under `../evidence/instruction-backups/` outside skill discovery directories.

## Historical corrected 0.1.1 artifact and PC checks

- APK: `../../../builds/gxr-kernel/root-manager/build/GalaxyXR-Root-Manager-diagnostics-0.1.1.apk`; version `0.1.1-diagnostic`, code `2`.
- Bytes: `37494`; SHA-256: `a437752302e516ccd6217f5f69df35c9a4104002a376275506705a741ca84307`.
- Product comparison corrected to `xrvst2ue`; legacy ARM32 helper removed as an active-route blocker. Full historical fingerprint gate remains unchanged; `UML2` still fails that comparison.
- Standalone PC build and official signature/artifact verification passed. No exploit payload packaged; all 22 original exploit files remain unchanged.
- At the 0.1.1 APK milestone, the project suite passed 26 tests, 0 skipped, including 15 policy assertions and 36 synthetic access scenarios / 207 assertions. The current suite result is recorded above.
- Original 0.1.0 APK retained; its prior receipts preserved under `../evidence/build-receipt-0.1.0.json` and `../evidence/artifact-validation-0.1.0.json`.
- The user ran 0.1.1 and supplied the latest app runtime report recorded below; no independent APK installation or app runtime test was performed. At that earlier checkpoint, ADB inventory, serial-specific `get-state` and a direct `host:devices-l` server query returned `unauthorized` for `R3GYB09JA5E` using the exact toolkit path confirmed by the user. A serial-specific `reconnect` refreshed the transport; inventory remained `unauthorized`, and no shell was reached then. Later authorization and native verifier runtime checks are recorded above.

## Historical original 0.1.0 artifact

The artifact and PC checks below describe the original 0.1.0 build. Their hashes and results retain that provenance and do not validate later source edits or a rebuilt APK.

- APK: `../../../builds/gxr-kernel/root-manager/build/GalaxyXR-Root-Manager-diagnostics-0.1.0.apk`
- Package: `dev.galaxyxr.rootmanager`
- Version: `0.1.0-diagnostic` / code `1`
- Minimum/target/compile Android API: `34` / `34` / `34`
- Architecture: `arm64-v8a`
- Bytes: `37494`
- SHA-256: `c1d1e0cae68f5ece7cef182625592dec7c96f8576a4030bd7e33df7b5da8f61c`
- Signer certificate SHA-256: `89f9fb69cdd7ca670d5f7b2f74306887dc564e556a93849bb4f9a00bb77e8539`
- Signature: Android v3 verified using the official apksigner tool. V1/V2 are not enabled; the minimum runtime is Android 14.
- Development signer only; private key retained locally and excluded by the project ignore rules.

## Historical original 0.1.0 PC checks

| Check | Result |
|---|---|
| Standalone Java 17 bytecode + NDK 27.2.12479018 native APK build | Passed |
| `python -B -m unittest discover -s root-manager/tests -v` | 26 passed, 0 skipped |
| Production access classes under JVM Android doubles | 36 scenarios, 207 assertions passed |
| Exact identity and disabled backend JVM checks | 12 passed |
| `python -B -m unittest discover -s tests -v` | Existing 35 passed, 0 skipped |
| Final official apksigner verification | Passed, v3 |
| AAPT2 manifest/package/ABI inspection | Passed; touchscreen/faketouch optional |
| Packaged entries and source/tool hash receipt | Passed |
| Compiled native library equals packaged native library | Passed |
| Native imports for mutation/process-trigger functions | None of the checked prohibited symbols |
| Original supplied exploit tree rehashed against source audit | All 22 files unchanged |
| Independent Cavecrew review after fixes | No remaining reported issues |

The access scenarios exercise production authorization code against synthetic Android APIs. They are not Android instrumentation or headset proof. Native import inspection and code review are static checks; they do not establish a runtime zero-risk guarantee.

Review fixes protect both fully and partially obscured consent touches, allow a manager-confirmed preview-ledger reset without deleting reports, and compile from frozen build inputs while detecting later source additions/removals/changes. Diagnostic metadata assets reject renamed binary data and malformed JSON.

## Original-source reference compilation

All 3 artifacts compiled from the original source into a separate evidence directory. No binary was executed, installed, or packaged into the diagnostic APK.

| Artifact | ELF | Bytes | SHA-256 |
|---|---|---:|---|
| `cve-2026-43499` | ELF64 AArch64 | 98792 | `fc05f578ff7783daddeda78bdd9ac11816b619255e0322293987102b50e3f307` |
| `cve-2026-43499-root` | ELF64 AArch64 | 18832 | `85ff78d40b87b375670865ad248d4b1d665044b2ffa8cb9e37269c48b7189f28` |
| `cve-2026-43499-32` | ELF32 ARM | 1732664 | `f3be32dbee62b1eade435cb9878e2bd66585757d369181b7c27a82e85e81e9f9` |

The machine/header classifications were checked at ELF offsets `0` and `18`; only header identity is claimed. The authoritative command/output/size/hash records are in `../evidence/source-audit.json`. Rebuilding with a different compiler is not a byte-identical reproduction of the supplied prebuilt files and does not prove app-context execution.

## Latest supplied 0.1.1 app report — 2026-10-08

The user replaced `../Diagnostics-root.txt` with a 0.1.1 report timestamped `2026-10-08T11:12:40.522Z`, preserved as [the exact raw snapshot](../evidence/diagnostics-0.1.1-20261008T111240Z.json). Raw-file SHA-256: `35ff1857732160d2ee82aecd71a64c851fe028cab8315c563d4d589da2887561`; boot ID: `d055f29e-a994-4b88-a07b-b5a998f8faf1`. This is user-supplied app-runtime evidence, not an independent live ADB capture.

- The product mismatch is gone: product `xrvst2ue`, device `xrvst2`. The full fingerprint remains `samsung/xrvst2ue/xrvst2:14/UML2.260301.001/I610UEU2AZF3:user/release-keys`, differing from the historical `UML.260301.001` profile.
- Kernel release `5.10.240-android12-9-perf-33775878-abI610UEU2AZF3`, page size `4096`, app UID/effective UID `10244` and context `u:r:untrusted_app:s0:c244,c256,c512,c768` remain unchanged. Matching strings do not establish binary/offset equivalence.
- Allowed CPUs remain `2,3,4,5`; the source's fixed `CORE=0` is absent. Tracefs control, trace and CPU 0 raw-trace opens still fail with errno `13`.
- Generic `/dev/ashmem` remains denied with errno `13`; `/dev/ashmemd055f29e-a994-4b88-a07b-b5a998f8faf1` opens successfully. No exploit ioctl was tested.
- Seccomp remains `2`, without proving any particular syscall outcome. This app's SELinux enforcing-state read remains denied with errno `13`; the later independent shell preflight observed `Enforcing` on the same boot.
- `root_backend_available=false`, `automatic_root_enabled=false` and `root_commands_available=false` describe this diagnostic implementation. They do not establish global device root status.

## Historical supplied 0.1.0 report summary — 2026-10-08

The earlier user-supplied report had timestamp `2026-10-08T10:49:11.785Z` and boot ID `81a1ffd5-3312-46df-9f4c-94654b1ae8c6`. Its filename was subsequently replaced by the latest report above; the values below preserve the earlier assessed summary, not a link to an available original raw report. It was user-supplied app-runtime evidence, not an independently verified live ADB capture.

- Model `SM-I610`, product `xrvst2ue`, device `xrvst2`; the original preview incorrectly compares product with the device value `xrvst2`.
- Fingerprint `samsung/xrvst2ue/xrvst2:14/UML2.260301.001/I610UEU2AZF3:user/release-keys` differs from the historical profile's `UML.260301.001`. Matching kernel release `5.10.240-android12-9-perf-33775878-abI610UEU2AZF3` and page size `4096` do not establish binary/offset equivalence.
- App UID/effective UID `10244`, context `u:r:untrusted_app:s0:c244,c256,c512,c768`; this app is not UID 0. Global device root status is not established.
- Allowed CPUs `2,3,4,5` omit the active source's fixed `CORE=0`.
- Tracefs control, trace and CPU 0 raw-trace opens fail with errno `13`; the current source's tracefs-based address discovery lacks required app access.
- Generic `/dev/ashmem` open fails with errno `13`, but `/dev/ashmem81a1ffd5-3312-46df-9f4c-94654b1ae8c6` opens successfully. No exploit ioctl was tested.
- Seccomp `2` confirms a filter, not the permission outcome for any particular syscall. SELinux enforcing-state read fails with errno `13`, so actual enforcing state is unknown from this report.

Source review corrects the earlier mandatory-ARMv7-helper claim: `exp_stack_once()` references that helper, but has no caller in the current pselect source route. The ARM32 binary remains a legacy reference artifact, not a demonstrated active dependency; this source finding does not establish supplied prebuilt behavior.

## Remaining gates

Root execution, client commands and restart restoration are hard-disabled in 0.1.2; its only authenticated root operation is fixed read-only status verification. It contains no exploit payload and has no boot receiver, root daemon or reboot action. The original APK artifact workflow performed no live device commands, APK install, permission changes, exploitation, flashing, remounting, AVB/slot changes, OTA manipulation or display changes. The user subsequently ran 0.1.1 and supplied the report above. Later authorized shell preflight and private native-helper uploads/checks occurred as recorded above; they did not obtain root. No independent APK/JNI/Activity headset test occurred for 0.1.2.

The next gates are exact firmware/artifact binding, app-accessible kernel-address discovery, scheduling on allowed CPUs, child-memory and specific syscall access, resource requirements and allocation-keeper lifetime. These must be established before adapting or running the exploit. A successful file open or matching fingerprint is insufficient; the supplied report does not validate an alternative to the blocked tracefs route.

Existing root could permit privileged prerequisite research, but success under root would not establish normal-app bootstrap after a restart. `root/ghostlock-usb-debug/01_EXPLOIT/src/root.c:132` captures the initiating UID; `src/su_daemon.c:646,652` obtains and checks the client's peer UID. If the initiating ADB shell were UID `2000`, it would not match the reported app UID `10244`. An authenticated broker integration remains necessary; this APK has none. Its backend flags remain compiled disabled-capability behavior, separate from 0.1.2's fresh read-only status proof. Neither unavailable capability nor failed verification proves global root absence. Never reuse a prior boot's kernel address or enable an automatic root retry loop.

Stopping/killing the historical keeper is not a proven removal method. A future root-removal flow must disable automation, deny new requests, preserve retained allocations through a normal reboot, verify the observed stock baseline, then offer Android uninstall. Current preview uninstall only removes this app's files and settings.

## Retained files and cleanup

Retain the final APK, build/artifact receipts, compiled verification stage, original-source audit, 3 separately compiled reference binaries, isolated Android SDK, JVM test dependency and local signing key. SDK/test dependencies/signing keys are excluded by the project ignore rules.

Removal of superseded diagnostic build-staging directories was deferred: automatic approval review rejected the guarded removal command with `blocked by policy` and supplied no more specific reason. No staging directory was deleted. Cleanup can be completed once deletion is permitted; preserve the current stage identified by `build-receipt.json` because artifact verification compares its native library with the APK.
