# Phase 3: Managed Hook Broker And Scope Ingress

Status: not started. Requires Phase 2 and explicit user approval.

## Purpose

Authenticate the forced managed hooks and turn SessionStart,
UserPromptSubmit, PermissionRequest, subagent, and Stop events into exact Scope
Context facts.

## Current Baseline

Codex supports the required managed hook configuration, but Erebor has no
signed hook command, macOS peer-authenticated broker, effective-inventory
attestation, or Codex hook context adapter.

## Scope

- bounded hook stdin and output protocol;
- XPC or credentialed Unix transport chosen by Phase 0;
- peer audit-token, code requirement, enrolled ancestry, and hook-profile
  authentication;
- effective requirements and managed hook inventory attestation;
- SessionStart runtime/native-session binding;
- UserPromptSubmit pending, allowed, denied, cancellation, queue, steer,
  resume, clear, compact, and fork facts;
- permission request, SubagentStart/Stop, and Stop lifecycle;
- exact observation sequences and decision-time context refs;
- content retention, hashes, lengths, unavailable rich context, and audit;
- spoof, replay, duplicate native id, timeout, malformed JSON, and broker
  restart tests.

## Checkpoint

Run the pinned CLI, VS Code, and first approved Desktop hook fixtures with user
hooks disabled/enabled, project/plugin hooks present, competing managed sources,
two IDE windows, and deliberate spoof attempts.

## Acceptance

- User/project/plugin config cannot disable or replace the managed profile.
- Caller JSON is trusted only after process authentication.
- A prompt node exists before hook allow and later tools require its exact
  native session and turn ids.
- Later steers and results never authorize earlier events.
- Missing editor/attachment context remains unavailable.
- Hook failure returns exit 2 and leaves no physical-effect lease.

## Stop Point

Hooks may govern prompt continuation, but protected physical effects remain
default-deny until Phase 4 is approved.

## Phase Result

Not done.
