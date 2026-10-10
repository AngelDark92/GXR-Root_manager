---
name: cavecrew
description: Route bounded tasks to compressed Cavecrew investigator, builder or reviewer. Use for delegation, code location, 1-2 file edits and findings-only reviews; includes Galaxy XR firmware evidence routing.
---

# Cavecrew

Same roles and compressed contracts; no numerical savings claim without measurement. Use digits for quantities/ordinals. Preserve paths, symbols, commands and uncertainty exactly.

| Task | Agent |
|---|---|
| Locate definitions/callers/uses; no edits or fix proposals | `cavecrew-investigator` |
| Known bounded edit, maximum 2 files | `cavecrew-builder` |
| Review diff/file/branch, findings only | `cavecrew-reviewer` |
| Architecture, new feature, 3+ files, or explanatory review | Main thread / available general agent |
| Known 1-line answer | Main thread |

Builder edits existing files; create files only when explicitly asked. Locate before editing unknown sites. For broad lookup, delegate 2-3 investigators with distinct questions; consolidate once. Chain locate, bounded edit, review. Do not send 3+ files to builder or general feedback to reviewer. Use host-native agent names/tools; do not assume Claude `Explore` exists in Codex.

## Output contracts

Investigator, or `No match.`:
```
<Header>:
- path:line — `symbol` — short note
totals: <counts>.
```
Path first; exact line/symbol. One hit: no header/totals. Include totals for multiple hits.

Builder:
```
<path:line-range> — <change ≤10 words>.
verified: <re-read OK | mismatch @ path:line>.
```
Terminal refusals unchanged: `too-big.` / `needs-confirm.` / `ambiguous.` / `regressed.`. Re-read proves edits only, not test execution.

Reviewer, sorted file then line, or `No issues.`:
```
path:line: <emoji> <severity>: <problem>. <fix>.
totals: N🔴 N🟡 N🔵 N❓
```

## Firmware routing

Read [galaxyxr-firmware](../galaxyxr-firmware/SKILL.md) for acquisition/precision work; load only the relevant reference. Give delegated tasks exact capture identity and narrow evidence paths, not full raw dumps. Investigator/reviewer stay read-only; builder edits PC source/instructions only. No agent operates the headset under this skill. Main thread owns executed-test and capture verification claims.

For binary findings use a hashed artifact/file offset in an extracted report with a real source line; never invent line numbers in a binary. Keep unknown versus observed distinctions even in short notes. Use normal English for security, irreversible actions or ambiguous sequences.

For APK/Gradle changes only, read [Morphe](../morphe-patches/SKILL.md): ignored decoded inputs are not CI inputs; diagnostic classpaths are not Gradle/CI proof. Include exact failed/corrected SHA/run/job and executed/skipped counts; main thread verifies corrected CI.
