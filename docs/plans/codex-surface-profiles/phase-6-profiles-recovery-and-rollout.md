# Phase 6: Surface Profiles, Recovery, And Managed Rollout

Status: not started. Requires Phase 5 and explicit user approval.

## Purpose

Certify each Codex surface independently and make profile updates, restart,
MDM delivery, health reporting, and recovery deterministic.

## Current Baseline

Earlier phases will prove one pinned path. The repository currently has no
macOS profile registry, fleet rollout state, update quarantine, or Apple
coverage report.

## Scope

- versioned CLI/TUI, `codex exec`, VS Code, Desktop, and later IDE profiles;
- exact code identities, client/bundled versions, hook schema, requirements,
  extension, broker, macOS, and architecture fingerprints;
- effective MDM/system/cloud requirements inventory and conflict reporting;
- strict, prompt-governed, action-governed, degraded, cooperative, unavailable,
  and blocked states;
- update quarantine and revalidation;
- registration, route, process, hook, lease, flow, and policy-epoch restart
  behavior;
- sleep/wake, fast user switching, logout, upgrade, rollback, uninstall, and
  device-management removal;
- optional APFS checkpoint/restore feasibility and retention decision;
- fleet canary, rollback, diagnostics, and support evidence.

## Checkpoint

Run every promoted surface's complete prompt/tool/ES/NE fixture on each
supported macOS/architecture combination, then perform canary MDM install,
client update, helper/extension restart, rollback, and uninstall tests.

## Acceptance

- One surface's evidence never upgrades another surface.
- A new client or cdhash is unavailable until its fixtures pass.
- Existing runtimes keep their original session and health epoch.
- Restart never reconstructs an active hook, lease, ES event, flow, or PID-only
  binding.
- MDM strict and local cooperative posture are visibly distinct.
- Checkpoint support is advertised only after a real restore passes.
- Reports name every coverage gap and first failing boundary.

## Stop Point

Stop after the approved surface set and rollout verdict. Cloud workers,
Windows, private filesystem virtualization, and undocumented IDE transports
remain separate plans.

## Phase Result

Not done.
