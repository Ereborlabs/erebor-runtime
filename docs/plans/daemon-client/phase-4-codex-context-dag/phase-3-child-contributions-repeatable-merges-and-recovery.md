# Phase 3: Child Contributions, Parent-Owned Integration, Repeatable Merges, And Recovery

Status: Proposed. Depends on nested Phases 1–2 and explicit approval.

## Purpose

Deliver child-owned work to its fixed parent as authenticated, bounded,
repeatable candidate contributions. The direct parent decides whether a
candidate enters its context; then, and only then, the daemon coordinator makes
a checked two-parent Git merge. Child history is never copied wholesale into
the parent.

## Scope

- Define an immutable `ChildContribution` containing the child context node and
  edge, direct parent context node, execution binding, source identity where
  applicable, delivery sequence, contribution kind (`message`,
  `result`, `failure`, or `cancelled`), delivery mode (`queue` or
  `follow-up`), bounded selected bytes, and a validated pin to the exact child
  contribution commit.
- Let the child publish a contribution through its private delegated channel.
  The daemon verifies its family membership, fixed parent edge, active session
  state, contribution sequence, message bounds, selected child commit, and
  route before it appends the candidate to the direct parent's durable inbox.
  This leaves the parent ref unchanged.
- Define an immutable `IntegrationDecision` made by the direct parent or by
  the edge's predeclared parent policy. It names one inbox entry, the expected
  parent head, an `accept` or `reject` action, and its authority (`parent-turn`,
  `parent-client`, or named `auto-integrate` policy). The child cannot emit an
  integration decision or target a different parent.
- Add the context-family merge coordinator. It validates the integration
  decision, serializes the target parent scope, creates a parent result tree
  that preserves the parent tree and adds one receipt under a deterministic
  child/sequence path, then calls the checked two-parent merge API with the
  current parent head and selected child commit. The coordinator is the sole
  Git writer for this operation.
- Support multiple child messages, multiple final/intermediate contributions,
  and many concurrent children. The coordinator produces one ordered merge per
  accepted delivery because ContextRepository commits intentionally have at
  most two parents. It does not combine several children into an octopus merge
  or silently drop a stale delivery.
- Treat a child completion message as a child-originated contribution, not a
  mutation authority. A successful child may publish a final result; failed or
  cancelled children publish an explicit bounded terminal fact only when the
  profile and policy allow it. They never receive a success merge by inference.
  A Codex-style automatic completion is allowed to create an inbox entry and,
  only under an immutable parent `auto-integrate` policy, its associated
  parent-side acceptance.
- Persist delivery idempotency, inbox state, integration decision, pending
  merge state, source/parent pins, and recovery facts. Reopen either retains
  the completed merge or leaves both parent ref and delivery state unchanged;
  it never reconstructs from stdout, rollout history, a PID, or a remembered
  child status.
- Keep physical claims binding-aware. A daemon-physical child shell, `ls`, fork,
  reparent, and later descendant remain attributable to the child invocation
  even after one or more result merges into the parent. A native logical child
  may retain its own context evidence, but its physical effects remain
  attributable to the outer governed Codex invocation.

## Required Negative Cases

- Child B cannot contribute to parent C, a sibling, an ancestor other than its
  fixed parent, or a stale/replaced parent scope.
- A child cannot accept, reject, auto-integrate, or merge its own delivery. A
  parent cannot accept an inbox entry from a child it does not directly own.
- A `native-logical` edge cannot be upgraded to `daemon-physical` from a
  completion, hook, App Server event, thread ID, or process observation.
- A grandchild result is first an inbox entry for its direct parent. It cannot
  bypass that parent and merge into the root; the direct parent must publish a
  new contribution if its parent should receive a result.
- A duplicated sequence, replayed contribution, altered pin/blob, oversized
  result, out-of-order delivery, and parent-head race fail closed without a
  second merge.
- A parent merge cannot alter the child ref. A later child contribution is
  based on the child branch it actually owns, not the parent's merged tree.
- Daemon crash/restart before, during, and after a merge cannot create an
  unrecorded delivery or replace a newer parent head.

## Checkpoint

Two concurrent children each publish two contributions. The parent accepts
three and rejects one. The parent branch has three ordered two-parent merges;
each merge has the then-current parent head and the selected child contribution
commit as parents. The child refs retain their own later heads unchanged, and
the rejected inbox entry remains an auditable non-merge.

## Acceptance

The parent receives child context only because the verified child sent it and
the direct parent accepted it. Multiple child-to-parent merges are ordinary
operation, not an exceptional finalization step. The DAG records causality,
delivery, acceptance, and integration without guessing from agent text or
timing.

## Stop Point

Stop after the Phase 3 result and verification. Wait for approval before Phase
4.
