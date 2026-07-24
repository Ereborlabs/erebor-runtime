# Phase 3: Child Deliveries, Parent-Owned Receives, Repeatable Merges, And Recovery

Status: Proposed. Depends on nested Phases 1–2 and explicit approval.

## Purpose

Deliver child-owned work to its fixed parent as authenticated, bounded,
repeatable delivery blobs in the child scope. The direct parent decides whether
a delivery enters its context; then, and only then, the daemon coordinator makes
a checked two-parent Git merge. Child history is never copied wholesale into
the parent.

## Scope

- Write one schema-versioned delivery blob at a deterministic path in the child
  scope. It contains the checked direct-parent edge/pin, receiver scope,
  execution binding and source identity where applicable, sequence, kind
  (`message`, `result`, `failure`, or `cancelled`), delivery mode (`queue` or
  `follow-up`), bounded selected bytes, and the pin to its exact source commit.
- Let the child publish through its private delegated channel. The daemon
  verifies membership by walking existing edge blobs, active session state,
  sequence, message bounds, source commit, and route before it appends the
  delivery blob to the child scope. This leaves the parent ref unchanged. The
  direct-parent inbox is a derived query over those child-scope blobs.
- A direct parent receive or reject request names one delivery path/pin and the
  expected parent head; it is authorized by `parent-turn` or `parent-client`.
  No separate `IntegrationDecision` is persisted and a child cannot make this
  request or target a different parent.
- The daemon context coordinator validates the receive request, serializes the
  target parent scope, creates a result tree that preserves the parent tree and
  adds one deterministic receipt, then calls the existing checked two-parent
  merge API with the current parent head and selected child commit. A rejection
  is an ordinary one-parent append of a rejection receipt. The coordinator is
  the sole writer for these operations.
- Support multiple child messages, multiple final/intermediate deliveries,
  and many concurrent children. The coordinator produces one ordered merge per
  received delivery because ContextRepository commits intentionally have at
  most two parents. It does not combine several children into an octopus merge
  or silently drop a stale delivery.
- Treat a child completion message as a child-originated delivery, not a
  mutation authority. A successful child may publish a final result; failed or
  cancelled children publish an explicit bounded terminal fact only when the
  profile and policy allow it. They never receive a success merge by inference.
  A Codex-style automatic completion creates a delivery blob only; the direct
  parent later chooses whether to receive it.
- Persist idempotency through deterministic delivery paths, source/parent pins,
  merge receipts, rejection receipts, and the existing session/audit facts.
  Reopen either retains a completed merge/receipt or leaves the parent ref and
  delivery unchanged; it never reconstructs from stdout, rollout history, a
  PID, or remembered child status.
- Do not add a generic operation-result state machine. The adapter owns its
  live-process cache, while the daemon stores only operation-scope delivery
  blobs keyed by owner scope, source operation key, and sequence. A checked
  owner poll/receive names one exact delivery pin and produces the same
  parent-tree-preserving two-parent merge used for an agent-child result.
  Input-only process writes create no merge. Partial and final receives are
  independently ordered and cannot be replayed.
- Keep physical claims binding-aware. A daemon-physical child shell, `ls`, fork,
  reparent, and later descendant remain attributable to the child invocation
  even after one or more result merges into the parent. A native logical child
  may retain its own context evidence, but its physical effects remain
  attributable to the outer governed Codex invocation.

## Required Negative Cases

- Child B cannot deliver to parent C, a sibling, an ancestor other than its
  fixed parent, or a stale/replaced parent scope.
- A child cannot receive, reject, or merge its own delivery. A
  parent cannot receive a derived inbox item from a child it does not directly own.
- A `native-logical` edge cannot be upgraded to `daemon-physical` from a
  completion, hook, App Server event, thread ID, or process observation.
- A running operation cannot be received by an ancestor, sibling, later
  replacement invocation, or copied process ID. Completion after owner
  cancellation/session closure is retained only as the declared terminal audit
  fact or is terminated by policy; it is never reassigned or injected.
- A grandchild result is first a derived inbox item for its direct parent. It
  cannot bypass that parent and merge into the root; the direct parent must publish a
  new delivery if its parent should receive a result.
- A duplicated sequence, replayed delivery, altered pin/blob, oversized
  result, out-of-order delivery, and parent-head race fail closed without a
  second merge.
- A parent merge cannot alter the child ref. A later child delivery is
  based on the child branch it actually owns, not the parent's merged tree.
- Daemon crash/restart before, during, and after a merge cannot create an
  unrecorded delivery or replace a newer parent head.
- Daemon crash/restart during operation launch, output, exit, or receive cannot
  duplicate a delivery or merge, mistake PID reuse for completion, or merge
  output that the owner did not explicitly receive.

## Checkpoint

Two concurrent children each publish two deliveries. The parent receives
three and rejects one. The parent branch has three ordered two-parent merges;
each merge has the then-current parent head and the selected child delivery
commit as parents. The child refs retain their own later heads unchanged, and
the rejected delivery has an auditable parent-only rejection receipt.

In the same fixture, B starts a command that outlives its initial yield, then
appends another B fact. q emits one partial and one final delivery in q's child
scope. B polls and receives the partial, then later receives the final result;
each is a separate merge after B's then-current head and retains the original
launch pin. P receives none of the command output until B sends an ordinary
child delivery and P receives it.

## Acceptance

The parent receives child context only because the verified child sent it and
the direct parent explicitly received it. Multiple child-to-parent merges are
ordinary operation, not an exceptional finalization step. The DAG records
causality, delivery, receive decision, and integration without guessing from
agent text or timing.

## Stop Point

Stop after the Phase 3 result and verification. Wait for approval before Phase
4.
