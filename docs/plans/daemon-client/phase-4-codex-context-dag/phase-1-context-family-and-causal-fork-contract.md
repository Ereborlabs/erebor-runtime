# Phase 1: Context Scopes And Causal Fork Contract

Status: Proposed. Requires explicit approval before implementation.

## Purpose

Make a child scope a checked, contained fork inside the existing root session
context repository, from an exact parent decision pin rather than a new scope
from a session root or a mutable latest head. Establish that the parent owns its
ref; the child receives its own ref and can never write the parent's ref
directly.

## Scope

- Reuse the existing daemon-owned `ContextRepository`, top-level root
  `ScopeRef`, `ContextPin`, and child `ScopeRef`; no `ContextFamilyId`, graph
  scope, or new scope identity is introduced. `ContextRepository::fork_scope`
  already atomically creates a child ref and appends to its parent. Use that
  parent append to write one schema-versioned edge blob carrying the parent
  pin, child scope, depth, source identity where applicable, and execution
  binding. Membership is derived by walking those checked edge blobs to root.
- Treat that top-level root as the initial agent scope, not necessarily the
  repository's `ScopeRef::root(...)`. A physical child does begin at its own
  `ScopeRef::root(child_session_id)`; a native logical child uses a named scope
  in the already-running session.
- Add only `parent_context: Option<ContextPin>` to an otherwise ordinary child
  `SessionSpec`. This lets recovery locate the root repository through existing
  session records; the child scope remains `ScopeRef::root(child_session_id)`.
  A `native-logical` child has no SessionSpec or separate process guard; a
  `daemon-physical` child uses the existing session-admission path and does.
- Change the session registry accordingly: only the root session owns a
  `SessionContextArtifact`; a child with `parent_context` resolves that artifact
  recursively instead of creating a second per-session repository.
- Expose only a checked `ScopeRef` decode for the scope string retained in a
  `ContextPin`, so recovery can resolve the parent session without treating a
  raw ref string as authority. Do not add another identifier for that lookup.
- Replace the current per-session `output/codex-context` repository assumption
  with the root session's existing daemon-owned `SessionContextArtifact`
  repository. That one repository contains the direct scope refs for the parent
  and every admitted child session; it is not a second repository.
- Add one daemon-owned coordinator that creates the child ref with
  `ContextRepository::fork_scope` from the verified parent pin commit and
  atomically appends a bounded parent-side child-admitted fact. The coordinator
  is the only writer for scope topology and later parent integrations.
- Model the edge as containment, not shared mutation: an admitted descendant
  has exactly one direct parent and may never re-parent, promote itself to a
  root, or select an arbitrary scope ref outside the root subtree. A grandchild
  is admitted by its direct parent and remains inside that subtree.
- Add one schema-versioned delivery blob in the source child/operation scope
  for every bounded result. A parent turn or parent client explicitly receives
  or rejects it; a receive creates the normal parent merge with a receipt in
  that merge tree, while a rejection appends a parent-only rejection receipt.
  The inbox is derived from direct-child delivery blobs and receipts. There is
  no auto-integration and no separate contribution, decision, inbox, or ledger
  entity.
- Reserve `erebor/context-dag/` for edge, delivery, and rejection metadata;
  adapter prompt projection never selects it. A receive merge writes the
  selected bounded result at the adapter's declared model-visible result path
  and a receipt under that reserved metadata path in the same merge tree. A
  rejection writes metadata only, so it does not add rejected content to the
  parent's model context.
- Identify a command by its owner scope plus the adapter's bounded source
  operation key, launch `ContextPin`, existing invocation/lease evidence, and
  exact process identity. Its partial/final result is an ordinary `delivery`
  from an operation scope. Keep only the adapter's live-process cache in memory;
  persist delivery facts and merge receipts, not a second generic operation
  state machine.
- Keep execution and context provenance separate. A native logical child may
  prove a source relationship and own a context scope, but its process effects
  remain pinned to the outer session invocation. It must never acquire a
  child-session identity from an App Server event, a hook, a thread ID, or a
  later process observation.
- Keep session-local audit validation exact: a child physical-effect audit pin
  still names the child session's scope ref. Parent/child relationship evidence
  is an additional checked edge fact, never an exemption from pin validation.
- Extend the context crate only where needed to construct a safe result tree
  from an existing parent tree. Do not expose raw Git mutation or unchecked
  object IDs to the daemon, adapter, CLI, or fixture.
- Add crate-local tests for stale parent heads, wrong-root-scope pins, duplicate
  child refs, depth overflow, attempted parent-ref write, attempted re-parent,
  confused logical/physical bindings, failed atomic fork, reopen, and full
  graph verification.
- Add operation-contract tests for stale/forged owner, stale launch pin, PID
  reuse, duplicate delivery, partial-result ordering, duplicate receive, result
  receive after later owner appends, owner cancellation, and a result that tries
  to bypass its owner.

## Checkpoint

- One root scope can create two sibling child scopes and one grandchild.
- Each child head has the requested immutable parent commit as an ancestor.
- Parent-side child-admitted facts and refs change together or neither changes.
- The scope graph proves `P -> B`, `P -> C`, and `B -> D`; no direct edge or ref can
  make B a child of C or an independent root.
- The repository proves the same logical graph for both bindings, while audit
  evidence proves a separate child process only for `daemon-physical` edges.
- A completed operation leaves its owner's ref unchanged until a checked
  explicit receive; receiving one exact delivery merges it at the owner's
  current head while retaining the original launch pin and result artifact.
- Reopen reconstructs only durable scope/ref facts; it does not infer an edge
  from session history, a process tree, or an audit record.

## Acceptance

The repository proves a real directed Git topology through direct refs, the
atomic parent edge blob, and causal commit ancestry. The edge blob is not a
standalone JSON assertion: it must agree with the checked `fork_scope`
transaction and refs.
No child process is admitted or launched in this phase.

## Stop Point

Stop after the Phase 1 result and verification. Wait for approval before Phase
2.
