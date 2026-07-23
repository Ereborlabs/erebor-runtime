# Phase 1: Apple Host, Package, And Trust Bootstrap

Status: not started. Requires an approved Phase 0 result and explicit user
approval.

## Purpose

Create the signed Apple delivery and privileged lifecycle foundation without
yet authorizing production Codex actions.

## Current Baseline

No production macOS application, Service Management owner, system extension,
Network Extension, hook installer, MDM artifact, or Apple packaging path exists.

## Scope

- approved `platform/macos/` Apple project and target ownership;
- host status application and current `SMAppService` launch-daemon lifecycle;
- Endpoint Security and Network Extension targets selected by Phase 0;
- exact Team ID, bundle identifiers, code requirements, entitlements, and
  hardened-runtime configuration;
- root-owned `/Library/Erebor/bin/erebor-codex-hook` installation and update;
- requirements template/hash generation and MDM payload artifacts;
- extension activation, health, policy epoch, uninstall, upgrade, and rollback;
- typed Apple-adapter IPC messages in `erebor-runtime-ipc`;
- code-signing, package tamper, wrong-Team-ID, and stale-version tests.

## Checkpoint

Install, activate, inspect, upgrade, and remove the signed development package
on the supported host. Prove every file, service, and extension has the expected
owner, permissions, signature, entitlement, and identifier.

## Acceptance

- Installation never leaves a user-writable managed hook path.
- Host/helper/extensions authenticate each other by approved code requirement.
- MDM and local profiles render deterministic requirements bytes and hashes.
- Unavailable or stale extensions report `unavailable`; no Codex effect is
  described as strict.
- Upgrade and rollback do not mix hook, requirements, IPC, or extension epochs.

## Stop Point

Do not register or allow production Codex execs until Phase 2 is approved.

## Phase Result

Not done.
