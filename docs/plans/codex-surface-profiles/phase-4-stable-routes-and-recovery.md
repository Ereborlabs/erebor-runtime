# Phase 4: Stable Routes, Failure, And Recovery

Status: Not approved. Not started.

## Purpose

Keep adoption and attribution deterministic with multiple sessions, runtimes,
connections, failures, and daemon restarts.

## Current Baseline

The design defines stable label ranking and fail-closed broker loss. Production
code does not persist Codex adoption routes or recover durable native bindings.

## Scope

- Stable candidate route keys and deterministic winner reuse.
- Registration, namespace-owner, route, runtime, and broker lifecycle cleanup.
- Durable accepted prompt and native binding recovery.
- Explicit closure of failed live broker connections; no guessed partial-frame
  or pending-request recovery.
- Runtime restart, IDE App Server restart, reconnect, and stale-ticket handling.
- Coverage-gap audit and report behavior.
- Concurrent session, runtime, native thread, and child-agent stress fixtures.

## Checkpoint

- Persistence and restart unit tests.
- Multi-session selection and route-removal e2e tests.
- Broker/session owner death at every lifecycle boundary.
- Reconnect with reused wire request ids proves connection isolation.
- Full repository and live recovery verification.

## Acceptance

- Restart never changes an otherwise unchanged route winner.
- Existing runtimes never move to another session.
- Failed broker streams are closed, not resumed from guessed offsets.
- Recovered history can enrich reports but cannot retroactively authorize.
- No stale registration, connection id, request id, lease, or retry ticket is
  accepted.

## Stop Point

Stop after the pinned IDE profile survives supported restart scenarios. Wait
for Phase 5 approval.

## Phase Result

State: Not done.
