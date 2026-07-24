# Phase 1: Context Scopes And Causal Fork Contract

Status: Done (2026-07-23).

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
  repository's `ScopeRef::root(...)`. Every nested Codex child uses a named
  same-session scope. It has no SessionSpec or separate process guard.
- Assign each authenticated Codex App Server/collaboration thread a distinct
  named scope in that same repository. A thread ID remains a same-session
  routing key: a generic App Server `thread/fork` does not by itself create a
  trusted child edge or a child session. Only an authenticated source action
  plus the checked coordinator fork can do that.
- Only the one root session owns the `SessionContextArtifact`; all nested
  logical scopes live in that one repository.
- Expose only a checked `ScopeRef` decode for the scope string retained in a
  `ContextPin`, so recovery can resolve the parent session without treating a
  raw ref string as authority. Do not add another identifier for that lookup.
- Replace the current per-session `output/codex-context` repository assumption
  with the root session's existing daemon-owned `SessionContextArtifact`
  repository. That one repository contains the direct scope refs for the parent
  and every admitted logical child; it is not a second repository.
- Add one daemon-owned coordinator that creates the child ref with
  `ContextRepository::fork_scope` from the verified parent pin commit and
  atomically appends a bounded parent-side child-admitted fact. The coordinator
  is the only writer for scope topology and later parent integrations.
- Model the edge as containment, not shared mutation: an admitted descendant
  has exactly one direct parent and may never re-parent, promote itself to a
  root, or select an arbitrary scope ref outside the root subtree. A grandchild
  is admitted by its direct parent and remains inside that subtree.
- Reserve `erebor/context-dag/` for the edge metadata added here and the
  delivery/receipt metadata that Phase 3 will add; adapter prompt projection
  never selects it. Phase 3 owns writing model-visible received results and
  parent-only rejection receipts.
- Keep execution and context provenance separate. A native logical child may
  prove a source relationship and own a context scope, but its process effects
  remain pinned to the outer session invocation. It must never acquire a
  child-session identity from an App Server event, a hook, a thread ID, or a
  later process observation.
- Keep session-local audit validation exact: a logical child effect is pinned
  to its exact same-session scope and invocation lease. Parent/child
  relationship evidence is additional checked context, never an exemption from
  pin validation.
- Extend the context crate only where needed to construct a safe result tree
  from an existing parent tree. Do not expose raw Git mutation or unchecked
  object IDs to the daemon, adapter, CLI, or fixture.
- Add crate-local tests for stale parent heads, wrong-root-scope pins, duplicate
  child refs, depth overflow, attempted parent-ref write, attempted re-parent,
  confused logical/physical bindings, failed atomic fork, reopen, and full
  graph verification.
- Phase 3 owns operation-contract tests for stale/forged owner, stale launch
  pin, PID reuse, duplicate delivery, partial-result ordering, duplicate
  receive, owner cancellation, and owner-bypass attempts.

## Checkpoint

- One root scope can create two sibling child scopes and one grandchild.
- Each child head has the requested immutable parent commit as an ancestor.
- Parent-side child-admitted facts and refs change together or neither changes.
- The scope graph proves `P -> B`, `P -> C`, and `B -> D`; no direct edge or ref can
  make B a child of C or an independent root.
- The repository proves the same logical graph while audit evidence remains in
  the one root session process tree.
- Reopen reconstructs only durable scope/ref facts; it does not infer an edge
  from session history, a process tree, or an audit record.

## Acceptance

The repository proves a real directed Git topology through direct refs, the
atomic parent edge blob, and causal commit ancestry. The edge blob is not a
standalone JSON assertion: it must agree with the checked `fork_scope`
transaction and refs.
No child process is admitted or launched in this phase.

## Result

- Added a checked `ScopeRef::parse` path and `ContextPin` scope/commit decoders,
  so recovery never treats a serialized ref string as authority. Added safe
  checked helpers for reading one blob from an exact commit and for building a
  result tree from an exact parent commit.
- Added the daemon-owned `ContextDagCoordinator`. It serializes topology
  writes, validates the exact parent pin and root-subtree membership, creates
  the child ref with `fork_scope`, and appends the schema-versioned edge blob
  under `erebor/context-dag/edges/` in that same transaction. It proves depth,
  direct-parent uniqueness, and causal ancestry on reopen without process- or
  session-history inference.
- Session records retain one context artifact for the root session. The active
  daemon resolver uses that artifact and no longer derives a Codex repository
  from `output/codex-context`.
- Updated the Codex hook registration to receive the resolved daemon-owned
  repository. Each authenticated App Server thread continues to receive its
  own named scope, and prompt projection rejects the reserved context-DAG
  metadata path.
- Added focused tests for sibling/grandchild topology, exact causal pins,
  duplicate child refs, re-parenting, foreign roots, depth limits, root-artifact
  recovery, and distinct thread scopes. No child process, bridge, IPC message,
  hook registration, or daemon admission endpoint was added.

The delivery/inbox/receive/rejection mechanics described above remain Phase 3
work. This phase establishes their durable scope, edge, pin, and reserved-path
contract without adding the later child-delivery surface.

Verification:

- `cargo test -p erebor-runtime-context -p erebor-runtime-core --lib`
- `cargo test -p erebor-runtime-daemon context_dag::tests --lib`
- `cargo test -p erebor-runtime-session app_server_threads_have_distinct_scopes --lib`
- `cargo test -p erebor-runtime-core child_session_reuses_the_checked_parent_context_repository --lib`
- `bash .github/scripts/verify-rust-ci.sh`

## Stop Point

Stop after the Phase 1 result and verification. Wait for approval before Phase
2.
