# Phase 5: Network Extension And Bypass Closure

Status: not started. Requires Phase 4 and explicit user approval.

## Purpose

Prevent Codex and bound descendants from bypassing session policy through
direct Internet, loopback, raw CDP, DNS, proxy, or alternate local network
paths.

## Current Baseline

The repository has socket decision contracts and governed CDP planning but no
Network Extension target, rule-distribution owner, or flow-to-audit-token
adapter.

## Scope

- Network Extension mode certified by Phase 0;
- source process/app audit token, signing identity, flow id, endpoints,
  direction, interface, and protocol mapping;
- bounded default-deny rule snapshots and policy epochs;
- new-flow session and effect-bound descendant decisions;
- IPv4, IPv6, DNS, literal IP, loopback, system proxy, and raw CDP fixtures;
- source process acting directly and system process acting on behalf of Codex;
- existing and pooled connection coverage classification;
- helper, control provider, data provider, rule update, sleep/wake, network
  change, and restart behavior;
- exact tool, session-only, degraded, and unavailable network attribution;
- optional governed model/MCP proxy evaluation when request-level identity is
  required.

## Checkpoint

Run the signed flow matrix for CLI, VS Code, Desktop, shell descendants,
browser helpers, direct OpenAI/model endpoints, raw CDP, local services, DNS,
IPv4/IPv6, existing connections, provider death, and stale policy epochs.

## Acceptance

- Unknown or stale source/policy identity denies for profiled Codex flows.
- Direct and loopback bypasses covered by the selected profile are blocked.
- Source audit-token mapping survives PID reuse and helper-mediated flows.
- A new command-descendant flow binds to its exact invocation when proven.
- Reused connections remain session-only unless a request handoff exists.
- Provider failure never becomes retrospective success or guessed attribution.

## Stop Point

Do not certify additional clients or managed rollout until Phase 6 is approved.

## Phase Result

Not done.
