# Standalone Galaxy XR root manager

The user explicitly chose this new folder inside `gxr-kernel` for the standalone APK. This overrides the ancestor APK routing rule for this folder only. Preserve all existing exploit files, firmware evidence, skills, and sibling projects.

Current milestone: a diagnostic APK and permission-controlled integration API. Root execution, automatic root restoration, root removal, and reboot are unavailable until exact-build app-context feasibility and safe kernel-allocation lifetime are established. Do not package an exploit or claim this milestone roots the device.

PC builds and synthetic tests are authorized. APK installation, device commands, exploitation, permission changes, and reboot need separately authorized live validation. Never flash, remount, change AVB/slots, or modify verified partitions.

Use the parent Cavecrew skill for bounded delegation. Builders own at most 2 files per task, are not alone in the codebase, use edit tools only, and do not execute tests. Parent runs verification. Investigators and reviewers remain read-only.

Diagnostics must not write to tracefs, consume raw trace data, trigger the vulnerability, spray allocations, run root commands, or change SELinux. Record unavailable observations explicitly. Positive permission probes do not establish exploit feasibility.

Keep app access decisions bound to Android caller UID, package and signing certificate. Reject shared UIDs, unknown callers, and changed signing identities. No API may enable root or automatic restoration in this milestone. Existing root sessions cannot be revoked merely by changing a permission record.

Build output belongs under this folder. Signing keys remain local under `.local`; never print passwords or key material. Preserve reports and original inputs. Do not initialize Git or publish/upload artifacts automatically.
