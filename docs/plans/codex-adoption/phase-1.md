# Phase 1: Session Adoption Registration And Enrollment

Status: Not approved. Not started.

## Purpose

Allow `erebor run codex` to register a live session that can deterministically
adopt later unchanged Codex runtimes before their first instruction.

## Current Baseline

Session launch and ptrace adoption exist in narrow forms, but there is no
fanotify owner, persistent Codex adoption registration, stable label route,
prepared shared mount-namespace owner, or one-time exec ticket.

## Scope

- Session-owned adoption registration lifecycle.
- Exact owner, executable fingerprint, version/profile labels, expiration,
  priority, registration sequence, and namespace identity.
- Deterministic winner ranking and stable route reuse.
- Minimal privileged fanotify permission owner and typed session-runtime IPC.
- Held candidate enrollment into the selected cgroup, process guard, and
  persistent session mount namespace.
- One-time helper/retry ticket and recursive-adoption protection.
- Final executable, argv, credentials, cwd, namespace, mount, and inherited-FD
  verification before resume.
- Cleanup when the session stops accepting work.

## Checkpoint

- Focused unit tests for registration, ranking, tickets, and route cleanup.
- E2e fixture with unrelated, unmatched, singly matched, and multiply matched
  candidate execs.
- Live first-instruction and shared-filesystem probe.
- Workspace fmt, check, tests, and clippy with warnings denied.

## Acceptance

- A later supported Codex launch enters exactly one intended session without
  changing its user-visible invocation.
- No match denies in strict mode; unrelated executables remain unaffected.
- Repeated equal candidates select the same live route.
- The first candidate instruction runs only after final session verification.
- Initial and adopted runtimes share the same session filesystem view.
- Stale registrations and retry tickets cannot be reused.
- Owner, worker, attach, namespace, and verification failures are fail-closed.

## Stop Point

Stop after adoption works without App Server parsing. Wait for Phase 2 approval.

## Phase Result

State: Not done.
