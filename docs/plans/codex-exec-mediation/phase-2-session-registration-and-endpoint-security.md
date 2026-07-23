# Phase 2: Session Registration And Endpoint Security Adoption

Status: not started. Requires Phase 1 and explicit user approval.

## Purpose

Route each supported Codex AUTH_EXEC event to exactly one active Erebor session
and register its process lifetime before allowing target code.

## Current Baseline

The current adoption resolver is Linux `/proc`-based. There is no macOS
audit-token registry, signed executable profile, or ES routing owner.

## Scope

- session-owned adoption registration lifecycle;
- normalized Team ID, signing id, cdhash, version, architecture, surface, and
  owner labels;
- deterministic specificity/priority/sequence/session-id ranking;
- stable route keys and cleanup;
- AUTH_EXEC event copying, deadline handling, non-cached dynamic responses, and
  executable-object validation;
- full audit-token/start identity process registry;
- parent and responsible audit-token facts;
- existing-process rejection and relaunch requirement;
- unsupported update quarantine;
- primary owner and approved safety-owner health protocol;
- typed adopted, denied, degraded, timeout, and coverage-gap audit events.

## Checkpoint

Run signed fake-target and real Codex launch fixtures for CLI, VS Code, copy,
rename, update, no registration, multiple registrations, concurrency, PID
reuse, helper loss, and ES owner loss.

## Acceptance

- No target first instruction runs before the allow decision.
- One stable registration wins without CWD, prompt, path spelling, or timing.
- No match and unsupported updates deny in strict mode.
- The runtime id binds the full process lifetime, never a reused PID.
- An existing unobserved Codex process is not promoted.
- Owner failure matches the Phase 0 fail-safe verdict.

## Stop Point

Adopted runtimes remain physical-effect default-deny. Do not enable prompt or
tool leases until Phase 3 is approved.

## Phase Result

Not done.
