# Phase 5: CLI, Daemon, And Desktop Profiles

Status: Not approved. Not started.

## Purpose

Extend Codex coverage without pretending that all Codex surfaces expose the
same transport or prompt boundary.

## Current Baseline

The pinned VS Code target uses external stdio App Server JSONL. Current upstream
`codex exec` and TUI use an in-process App Server client; daemon control sockets
use WebSocket framing; Desktop requires a pinned launch/transport study.

## Scope

- `codex exec` argv and supported stdin prompt ingress.
- Structured output reconciliation without treating late output as ingress.
- Interactive TUI source investigation without requiring special user flags.
- Managed daemon Unix-socket HTTP Upgrade and WebSocket broker adapter.
- Pinned Desktop child discovery and transport attachment.
- Complete, degraded, action-only, and unavailable coverage states per surface.

## Checkpoint

- Versioned fixture per surface and input form.
- CLI quoting, stdin, image, resume, and promptless tests.
- Unix-socket framing, authentication, reconnect, and bypass tests.
- Desktop first-instruction and transport proof.
- Full repository verification for every promoted profile.

## Acceptance

- Every later supported process is action-governed after adoption.
- Strict prompt coverage exists only for a proven before-work boundary.
- TUI, daemon, stdio IDE, exec, and Desktop profiles do not inherit each
  other's coverage.
- No special user invocation is required merely to receive action governance.

## Stop Point

Stop after reporting each surface independently. Wait for Phase 6 approval.

## Phase Result

State: Not done.
