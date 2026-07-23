# Phase 4: Tool Leases And Endpoint Security Effects

Status: not started. Requires Phase 3 and explicit user approval.

## Purpose

Bind exact PreToolUse invocations to covered process and filesystem effects and
enforce the decision at Endpoint Security authorization events.

## Current Baseline

Erebor has generic process/file decision contracts and a Linux ptrace backend,
but no macOS invocation lease, ES effect adapter, audit-token lineage, or
operation coverage registry.

## Scope

- invocation key and lease owner keyed by runtime, native session, turn, and
  tool-use id;
- preparing, response-issued, armed, effect-bound, dispatch-complete, and
  closed transitions;
- hook-exit barrier proven by Phase 0;
- per-runtime exclusive unbound command and in-process mutation slots;
- AUTH_EXEC command-child binding and validated launch shape;
- fork, exec, background, reparent, exit, and descendant propagation;
- exact file-operation capabilities derived from structured tool input;
- first supported create/open/rename/unlink/truncate/link/mmap/metadata matrix;
- pre-opened and inherited descriptor handling;
- PostToolUse, cancellation, runtime exit, timeout, and stranded-lease cleanup;
- app-server approval facts separate from hook, Erebor, and final OS decisions;
- concurrent identical command and patch fixtures.

## Checkpoint

Run the complete Phase 0 operation matrix through production owners with two
native threads, identical commands, overlapping patches, background children,
fork-before-exec, pre-opened descriptors, symlink/path races, malformed hooks,
and policy-owner failure.

## Acceptance

- No protected effect proceeds without an armed exact lease.
- Hook child processes never consume command leases.
- Command strings validate but never select an invocation.
- Descendants preserve their original tool node after later prompts or tools.
- Codex-process mutations cannot borrow command-descendant associations or
  exceed exact operation/target capabilities.
- Unsupported file paths deny or keep the profile non-strict.
- Later PostToolUse or item results never repair an earlier missing lease.

## Stop Point

Do not claim network bypass closure or exact network attribution until Phase 5
is approved and passes.

## Phase Result

Not done.
