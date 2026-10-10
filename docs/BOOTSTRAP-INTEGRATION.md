# External bootstrap and APK integration plan

Artifact relocation, 2026-10-08: build artifacts now live under `../../../builds/gxr-kernel/root-manager/build`; the retained reference-build directory lives under `../../../builds/gxr-kernel/root-manager/evidence/`. Historical JSON receipts remain unchanged. The relocation manifest `../../../builds/gxr-kernel/relocation-correction-20261008-181036.json` binds old/new locations, byte counts and SHA-256 hashes. Earlier validation below describes the source/builder at that time; it does not validate the build-path edits.

Selected by the owner on 2026-10-08: plan a one-time external root bootstrap, then integrate the APK with the existing privileged session. This changes the earlier device-only restriction for initial setup. It authorizes planning, not an exploit run, deployment, reboot or partition modification. The current 0.1.1 APK remains diagnostic-only.

The owner subsequently requested execution of this plan on 2026-10-08. Necessary staged preflight, supervised temporary bootstrap and broker integration are now authorized when the gates below pass; the earlier planning-only statement records the original selection. That authorization does not waive exact-target or allocation-lifetime evidence, permit retries after partial failure, or make restart restoration available. The subsequent 0.1.2 APK adds read-only root verification on opening and manual recheck after external rooting; it does not implement the bootstrap or broker. See [current validation](VALIDATION.md).

## Execution checkpoint

- [Historical preflight](../evidence/bootstrap-preflight-20261008-execute-01.json) recorded `unauthorized`; no device shell was reached then. After the owner revoked debugging grants and reauthorized this PC, [the authorized preflight](../evidence/bootstrap-preflight-20261008-authorized-01.json) reached serial `R3GYB09JA5E` as `device` through `../Tools/install/platform-tools/adb.exe`.
- Live shell: UID `2000`, seccomp `0`, allowed CPUs `0,1,2,3,4,5`, SELinux `Enforcing`. Boot ID `d055f29e-a994-4b88-a07b-b5a998f8faf1` matches the latest supplied app report. [Same-boot read-only observations](../evidence/bootstrap-readonly-observations-20261008-01.json) record empty slot suffix and `ro.virtual_ab.enabled`, both unknown; verified boot `green`, vbmeta `locked`, and denied `/sys/kernel/notes` access.
- [Kernel metadata correlation](../evidence/target-correlation-20261008-01.json): historical `kernel-Image` is 48,745,844 bytes, SHA-256 `2bf9ede7f710ba7b873a33d427eee6d6eb390b2c7c8a1a3c7fd24a2197ff7f5a`. Its banner at offset `0x2204410` matches both the supplied app report and live shell's complete kernel release and `#1 SMP PREEMPT Fri Jun 12 05:47:10 UTC 2026` version. Live byte identity and full-fingerprint binding remain unverified.
- Source `src/preload.c` defaults to 16 attempts and a 90-second timeout; timeout kills the exploit child. Allocation children inherit parent-death SIGKILL, whereas the keeper clears that flag only after successful root. A timeout after partial kernel corruption can therefore release retained pages before the keeper exists. This is an unresolved launch gate; setting the attempt count to 1 alone does not address it.
- A separate `native/bootstrap_verifier.c` is implemented and cross-compiled for Android ARM64/API 34. It checks root peer credentials on the same socket and provides only `--probe` and fixed read-only `--status`, with bounded time and output. It neither launches nor replaces the original daemon and forwards no supplied commands/environment. It is not a general `-c` acquisition helper or an APK broker.
- [Android verifier checks](../evidence/verifier-device-checks-20261008-02.json): hash-checked helpers were uploaded into private test directories; 6 checks passed: 4 CLI rejections, same-socket UID `2000` rejection, and fixture confirmation that the client sent zero protocol bytes. The fixture used an isolated abstract Unix endpoint. [The earlier filesystem-socket fixture failure](../evidence/verifier-device-checks-20261008-01.json) is retained. Verifier artifact `../../../builds/gxr-kernel/root-manager/build/bootstrap-stage-_iyl2ymm/gxr-bootstrap-verifier`: 15,704 bytes, SHA-256 `0d3cecf25ea3f3e17439caae9ef8c1fa6bf8c6f9e6de394136946379500655bf`.
- Default `--probe` and `--status` returned `connect_failed`; the same-boot read-only observations record `/data/local/tmp/temp_su.sock` absent. No existing original daemon was verified; these observations do not establish global device root state. Positive UID-0 protocol proof remains unavailable.
- At this earlier checkpoint, the Windows project suite had 33 passed and 7 Linux native credential/protocol tests skipped. Existing firmware suite: 35 passed, 0 skipped. WSL returned `Wsl/CallMsi/REGDB_E_CLASSNOTREG`; the Android negative-peer result does not replace skipped positive credential/protocol tests. Independent Cavecrew source review reported no remaining issues in the verifier/tooling scope. The separately delegated failure-lifetime audit was blocked by automated cyber review reporting `possible cybersecurity risk`; that audit did not run. Later 0.1.2 checks are recorded in the current validation.
- The unchanged 0.1.1 APK's signature, hashes and contents were verified; all 22 original exploit files remain unchanged. No exploit, APK installation, firmware capture, reboot or partition write was performed. Broker enrollment, APK integration and restart restoration remain unimplemented. Personal-device scope and continuing authorization are recorded in `../AGENTS.md` and the project Cavecrew skill, with backups outside skill discovery directories.

PC commands:

```powershell
python -B root-manager/tools/build_bootstrap.py --ndk ../steamlink-patches/.android-sdk/ndk/27.2.12479018
python -B root-manager/tools/bootstrap_preflight.py --adb ../Tools/install/platform-tools/adb.exe --serial R3GYB09JA5E --app-report root-manager/evidence/diagnostics-0.1.1-20261008T111240Z.json --output root-manager/evidence/bootstrap-preflight-NEW.json
python -B -m unittest discover -s root-manager/tests -v
```

Each verifier build has a retained stage and hash receipt. Preflight outputs are never overwritten and always remain non-launching; passing connectivity alone cannot authorize exploitation.

## Current evidence

The exact user-supplied 0.1.1 report is preserved in [the immutable snapshot](../evidence/diagnostics-0.1.1-20261008T111240Z.json), timestamp `2026-10-08T11:12:40.522Z`, SHA-256 `35ff1857732160d2ee82aecd71a64c851fe028cab8315c563d4d589da2887561`.

- Model `SM-I610`, product `xrvst2ue`, device `xrvst2`, API 34, 4096-byte pages.
- Full fingerprint `samsung/xrvst2ue/xrvst2:14/UML2.260301.001/I610UEU2AZF3:user/release-keys`; historical target header says `UML.260301.001`. A historical transcription error is possible, but exact artifact/offset compatibility has not been established.
- App UID/effective UID `10244`, untrusted-app SELinux context, seccomp filter mode `2`, allowed CPUs `2,3,4,5`.
- Tracefs opens denied; boot-specific ashmem open succeeds. These observations describe the ordinary app, not an ADB shell or a root helper.
- The later authorized preflight independently confirmed this fingerprint through an ADB shell. Shell UID `2000`, seccomp `0` and CPUs `0,1,2,3,4,5` differ from the app observations above; shell access does not establish ordinary-app exploit compatibility.
- `root_backend_available=false` is compiled preview behavior. It does not prove that another tool has not rooted the device.

## 1. Establish the external bootstrap prerequisites

Use the exact toolkit ADB executable and explicit serial for every device command. Host authorization is resolved in the checkpoint above; require it again if the transport changes. Do not revoke debugging grants, replace keys, or change headset settings automatically.

Obtain unprivileged live model, complete fingerprint, kernel identity and security context, plus the shell's CPU affinity and resource limits. Check for an existing root session using the server-authenticated verification path described below; a verified existing session should be inspected rather than launching another exploit. Bind the selected exploit artifact to audited source and the exact target kernel. Resolve the `UML`/`UML2` discrepancy through exact matching firmware artifacts or verified original runtime evidence before execution. A matching incremental build or release string is insufficient; do not simply change the whitelist. Privileged evidence collected after rooting cannot retroactively justify an unsafe initial target choice.

Review the actual bootstrap path and its keeper/failure behavior. Preserve the supplied binaries and source; use audited copies if adaptation is needed. The original operator entrypoint is documented in [RUNBOOK.md](../../root/ghostlock-usb-debug/01_EXPLOIT/RUNBOOK.md), but its instruction to rerun after an unexpected reboot is not adopted here. The current active source route does not require the unused ARM32 helper.

Completion: an authorized device shell, an exact target/artifact evidence record, and a reviewed single-attempt procedure. An unresolved prerequisite stops the bootstrap stage. There is no claim that exploitation has zero crash or brick risk, or that possession of firmware images proves restoration works.

## 2. Perform one supervised temporary bootstrap

The owner's execution request authorizes this stage when its prerequisites pass. Record boot identity and an attempt marker before launch; permit at most 1 attempt in that boot, with no unattended watchdog retry or retry after partial failure. Missing or ambiguous boot identity prevents launch.

Collect logs and preserve failure evidence. Do not treat socket existence or a success string as proof of root. The original daemon authenticates its client, but the original client does not authenticate its server: `src/su_daemon.c:595-600` trusts an acknowledgement byte. Before accepting root evidence or provisioning anything, use an audited verification client that checks kernel-reported server `SO_PEERCRED` on its own connected socket and requires UID 0 before sending requests. Bind the verifier binary to its PC build hash; implement this in new project-local source or a copy, preserving the original files and protocol. Through that verified channel, confirm effective UID 0 and record context/boot identity. A separate socket probe followed by an unchecked reconnect is insufficient. Do not introduce a timeout that kills the allocation keeper, blindly kill the exploit after corruption may have occurred, or automatically reboot on failure. Establish how the supervisor and all child allocations behave before selecting the live procedure.

Keep stock boot images, verified partitions, AVB and slots intact. The existing exploit changes kernel state, including SELinux and `panic_on_oops`, for the current boot; record those effects rather than describing it as mutation-free. Do not add persistent permission changes as a shortcut to APK integration.

## 3. Capture privileged evidence through the existing helper

The implemented verifier supports only `--probe` and fixed `--status`; it cannot perform this stage's inventory or accept `-c`. Before broader inspection, implement and validate a separate bounded inspection client that requires UID 0 through `SO_PEERCRED` on each request's own connected socket before protocol traffic. Preserve the current verifier's restricted API. Use root only for a bounded, read-only inventory at this stage: root identity/context, full build/kernel, SELinux state, boot identity, slot mappings and OTA/snapshot state. Compare root-helper observations with app-context observations without substituting one for the other.

The firmware acquisition workflow begins only after root is established and acquisition is explicitly requested. Its `--root-helper` option requires an absolute helper implementing `-c`; neither the current verifier nor an unchecked original helper satisfies authenticated acquisition. A compatible, server-authenticated acquisition client must be implemented and validated before invoking that workflow. The acquisition tool does not install or start root. Check OTA/snapshot gates before image transfers. Select only artifacts needed for kernel and target verification; exclude userdata, identities, secrets and unique calibration. Preserve source mappings, sizes, hashes, original verified bytes and partial failures. Capture integrity does not establish a working restore procedure.

Completion: exact-build evidence and a description of the actual root session, including the original daemon and allocation keeper. Root-helper access must not be reported as ordinary-app exploit compatibility.

## 4. Add a separate authenticated root broker

The existing daemon is not directly adoptable by the preview APK. The source captures the initiating UID in `src/root.c:132` and checks `SO_PEERCRED` in `src/su_daemon.c:646,652`. A bootstrap initiated by shell UID 2000 authorizes that UID, whereas this installed manager uses UID 10244. Hardcoding either UID as a portable app identity is inappropriate.

Keep the original daemon, `/data/local/tmp/temp_su.sock` and allocation keeper intact. Do not run a replacement daemon against that pathname: its startup unlinks the original socket. The current verifier cannot provision a broker. First implement and validate a separate client for the bounded provisioning operations, authenticating the root peer on the same socket before every request. Then use that client to provision a separate broker with its own endpoint, owned files and lifecycle through the existing daemon. Do not widen the original daemon's UID check or make world-accessible files the authorization mechanism.

Implement the broker and JNI client inside `root-manager`, using new source and preserving the supplied exploit. Select the endpoint only after testing actual app/root SELinux and path access. Requirements:

- Authenticate both ends. The broker checks kernel-reported peer UID and a per-install capability or key enrolled through the trusted bootstrap; the APK verifies the enrolled broker identity. Bind enrollment to independently verified installed package/signing identity, not caller-provided package metadata. Reinstallation, UID reuse, changed signer or corrupt enrollment requires fresh enrollment.
- Bind each session and response to boot identity, enrollment epoch, protocol version and a fresh challenge. Fail closed on disagreement or replay. Boot binding prevents reuse of privileged session state across restarts.
- Bound message sizes, counts, execution time and returned data. Validate malformed/truncated messages, descriptor handling, disconnects and concurrent requests. Never parse diagnostic fields as shell commands.
- Initially expose only enumerated, read-only status/inspection operations. Arbitrary shell execution and third-party root commands remain unavailable until a later review and fresh explicit grants.
- Detect root with a verified response from the privileged broker. Report app UID and broker UID separately; updating a label or backend boolean is not root detection.
- A broker/client failure may close the broker connection, but must not free exploit-retained allocations or kill the original keeper. Reject further work on an ambiguous session.

Reuse the manager's trusted Android Binder caller/package/signer checks for app integration. Existing `diagnostic_preview` approvals never authorize root; introduce a new capability scope and fresh consent before enabling any privileged operation. Full client command execution requires its own explicit grant and should clearly disclose that the client can act outside manager safeguards.

## 5. Validate manual integration before expanding scope

PC tests exercise authentication, package/signer changes, UID reuse, stale boots, malformed protocol, replay, concurrent/disconnected clients and bounded outputs. Static build checks verify exact hashes, signatures and package contents. These checks do not replace separately authorized headset runtime tests.

Live tests begin with verified broker identity and read-only status. Then test manager relaunch, force-stop and update while confirming that the original keeper remains intact; perform lifecycle tests only after their allocation/liveness consequences are understood. Reject an unauthorized app and a changed signing identity. Check that preview approvals cannot execute broker operations. No root action becomes available merely because a socket exists.

Completion: the APK reliably manages a root session that was externally bootstrapped. Its interface must describe this state as requiring external bootstrap after a reboot until a standalone route is validated.

## 6. Treat restart restoration as a separate milestone

One-time external root enables inspection and integration. It does not establish that an unprivileged post-unlock APK can obtain root after a restart. Ordinary-app tracefs access, compatible scheduling, specific syscall/memory behavior, kernel address discovery and retained-allocation lifetime still need an app-context solution.

Do not cache a privileged kernel address for another boot, schedule automatic retry loops, or patch the boot chain to hide the missing bootstrap. Keep automatic restoration OFF. Implement a post-unlock receiver only after manual app-origin rooting and failure recovery have been validated on the exact firmware.

Removal first disables future restoration and new requests. Retain necessary allocations until a separately authorized normal reboot, then verify the observed stock baseline before uninstalling the manager and its owned broker files. Do not kill the keeper as cleanup, revoke existing root processes by merely changing a ledger, or remove files owned by other root tools.

## Remaining deliverable

Establish exact live target binding and address the supervisor's partial-failure allocation lifetime before a bootstrap attempt. Complete positive UID-0 credential/protocol tests on a suitable runner; the Android negative-peer checks above cover only rejection. Implement and validate the separate authenticated inspection/provisioning clients before their respective stages; acquisition additionally needs a compatible authenticated `-c` helper. Then implement and validate the read-only broker/client prototype and APK enrollment. Authorized shell access and verifier rejection checks are complete; temporary root and broker integration have not succeeded.
