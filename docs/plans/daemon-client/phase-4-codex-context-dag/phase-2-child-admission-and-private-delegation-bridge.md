# Phase 2: Logical Child Scope Admission

Status: Done (revised 2026-07-24). Depends on completed nested Phase 1.

## Purpose

Admit a Codex child thread as a causal scope inside the already-running Erebor
session. A Codex turn, `spawn_agent`-style child, App Server thread, or nested
prompt is not an Erebor session, TTY, process guard, hook socket, package
installation, or daemon client.

One `erebor run … codex` creates one session and one guarded Linux process
tree. Logical scopes explain which Codex thread caused an effect in that tree.
They do not create containment that the existing process guard does not have.

## Scope

- Reuse `ContextOperationAdmission`, `ContextPin`, `ScopeRef`, and the existing
  daemon-owned `ContextDagCoordinator`; do not introduce a child-session
  admission model, bridge package field, secondary socket, ticket, or new
  identity.
- An authenticated `PreToolUse` `erebor_delegate` fact must contain bounded
  `child_thread_id`, `child_turn_id`, and an explicitly supported frozen
  context selection (`none`, `all`, or bounded `last_turns`). It is an adapter
  fact, not raw workload authority.
- The lease owner freezes the exact authenticated parent pin, asks the
  daemon's existing in-process operation-admission callback to create a
  `native-logical` child scope, and requests parent selection. The coordinator
  writes the immutable direct parent edge and child ref in the existing
  repository transaction.
- The lease owner binds the returned scope to exactly the declared child
  thread/turn. A second binding for the pair must be identical or is rejected.
  A child cannot choose a session namespace, parent ref, source commit,
  executable, package, policy, runner, socket, user, environment, or argv.
- The logical-fork hook completes after admission. It does not arm a physical
  bridge or wait for another process. The parent lane is released immediately.
- Later tool hooks from that exact child thread/turn select the child scope.
  A real `ls` or other descendant remains inside the original Linux guarded
  process tree; its invocation lease supplies physical attribution. It does
  not become a second session merely because its logical source is a child.
- A hook delivery from a normal child turn carries that exact source scope to
  the existing delivery coordinator. Thus child-to-parent communication uses
  the existing authenticated hook route and parent-owned receive/merge flow;
  no child session or delegation bridge participates.
- Generic App Server `thread/fork`, resume, historical-thread paths, and raw
  parent-thread claims remain observation-only until the adapter maps a
  source-proven collaboration action to this checked admission path.

## Removed Design

The earlier physical-child bridge design is intentionally removed from Phase 4:
there is no `ChildSessionAdmission`, package `child_delegation` contract,
bridge projection, child session creation, child guard, or child hook listener.
It made an internal Codex thread look like a separately launched agent and
violated the one-run/one-session model.

A future runner may define an explicitly requested, independently launched
agent session. That is a different product surface and must be designed and
approved separately; it must not be inferred from a Codex thread.

## Required Negative Cases

- A raw nested `codex`, shell `exec`, copied hook, PID, App Server thread ID,
  or `SubagentStart` observation cannot create a session, scope edge, delivery,
  or merge.
- Missing, malformed, overlong, duplicate, foreign-session, or conflicting
  child thread/turn identities fail closed.
- A logical child cannot address a sibling or ancestor as a delivery receiver,
  mutate a parent ref, select a different fork pin, or gain daemon control.
- A logical fork does not cause a second `session ps` row, TTY, hook socket,
  runtime guard, package load, or process-guard lifecycle bridge execution.

## Result

- `ContextOperationAdmission` can request that its supplied pin become the
  selected direct parent. The daemon creates the same-session
  `native-logical` ref through `ContextDagCoordinator`.
- `CodexContextDag` binds that admitted ref to the child thread/turn and rejects
  a conflicting binding.
- `CodexInvocationLeaseOwner` parses and validates the logical-fork contract,
  creates the scope edge, and releases the hook without a physical handoff.
  Subsequent delivery attribution resolves the exact child scope.
- The old physical bridge/session path and package schema were removed. The
  deterministic fixture's `fixture/delegate` now changes its active logical
  turn only; `fixture/command {"command":"ls"}` thereafter runs as a guarded
  descendant attributed to that child scope in the same session.

## Verification

- `rtk cargo test -p erebor-runtime-session agents::codex --lib`
- `rtk cargo test -p erebor-runtime-e2e --test codex_v1_fixture`
- `rtk cargo test -p erebor-runtime-daemon --lib` outside the restricted
  socket sandbox
- `rtk cargo clippy -p erebor-runtime-packages -p erebor-runtime-session
  -p erebor-runtime-daemon -p erebor-runtime-e2e --all-targets --all-features
  -- -D warnings`

## Stop Point

Phase 3 owns parent receives, repeated delivery merges, recovery, and policy
control. Phase 4 owns the full deterministic multi-branch fixture and public
graph view.
