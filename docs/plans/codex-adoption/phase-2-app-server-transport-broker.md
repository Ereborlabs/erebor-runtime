# Phase 2: Shared App Server Transport Broker

Status: Not approved. Not started.

## Purpose

Use one byte-transparent App Server broker for an Erebor-launched App Server and
an automatically adopted VS Code stdio App Server.

## Current Baseline

The parent design specifies the FD topology and JSONL lifecycle. Production code
has no Codex App Server surface, FD splice owner, `SCM_RIGHTS` broker handoff,
direction-aware protocol tables, or pre-forward prompt gate.

## Scope

- Owned-launch attachment and adopted held-exec stdio-splice attachment.
- Explicit `StdioSpliceTransaction` in the Linux process guard.
- `pidfd_open`, `pidfd_getfd`, `PTRACE_O_EXITKILL`, injected syscall, scratch,
  descriptor-alias, and exec-retry platform owners.
- Authenticated four-endpoint `SCM_RIGHTS` handoff and readiness acknowledgement.
- Independent bounded JSONL relays with exact raw-byte forwarding.
- Complete-line parsing, partial buffering, maximum line size, short-write
  offsets, EOF, cancellation, and connection shutdown.
- Direction-aware request/response tables and session observation sequencing.
- Pinned schema fingerprint and complete method classification.
- Pending `turn/start`, `turn/steer`, and injected-context transactions before
  forwarding.
- JSON-RPC denial of certified sensitive direct-action requests.
- Remote-control and alternate-transport bypass prevention.

## Checkpoint

- Unit tests for framing, request ids, method classification, short writes,
  limits, EOF, and failure transitions.
- Process-guard tests for every splice transition and unexpected stop.
- E2e fake-IDE and real pinned VS Code App Server fixtures.
- Owned/adopted byte-stream parity fixture.
- Broker crash, alias, remote-control, and profile-drift negative fixtures.
- Full repository verification and live broker probe.

## Acceptance

- Owned and adopted attachments generate identical broker/context events for
  identical input.
- No prompt byte reaches Codex before its pending node is durable.
- Codex and the IDE receive exact original bytes once and in direction order.
- Reversed responses bind to their exact requests and native turns.
- Unknown action methods, alternate transports, and broker bypass fail closed.
- Broker loss cannot be reconstructed from guessed pipe state.

## Stop Point

Stop with live prompt ingress and native protocol identity, before managed hook
or physical action binding. Wait for Phase 3 approval.

## Phase Result

State: Not done.
