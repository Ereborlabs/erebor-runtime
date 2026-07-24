# Phase 1: Context Family And Causal Fork Contract

Status: Proposed. Requires explicit approval before implementation.

## Purpose

Introduce the durable context-family owner and make a child scope a checked,
contained fork from an exact parent decision pin rather than a new scope from a
session root or a mutable latest head. Establish that the parent owns its ref;
the child receives its own ref and can never write the parent's ref directly.

## Scope

- Define a validated `ContextFamilyId`, immutable parent edge, child depth, and
  family membership facts in core. An edge also declares its execution binding:
  `native-logical` names a source-pinned agent identity inside an existing
  daemon session; `daemon-physical` names a separately admitted child session.
  Both record parent scope, fork-origin `ContextPin`, immutable child scope ref,
  and parent-selected integration policy. Only `daemon-physical` has a child
  `SessionSpec`, hook registration, or separate process guard.
- Move the current per-session `output/codex-context` repository assumption to
  a daemon-owned context-family repository. One family repository may contain
  direct scope refs for the parent and every admitted child session.
- Add one daemon-owned coordinator that creates the child ref with
  `ContextRepository::fork_scope` from the verified parent pin commit and
  atomically appends a bounded parent-side child-admitted fact. The coordinator
  is the only writer for family topology and later parent integrations.
- Model the edge as containment, not shared mutation: an admitted descendant
  has exactly one direct parent and may never re-parent, promote itself to a
  root, or select an arbitrary family ref. A grandchild is admitted by its
  direct parent and remains inside the same family.
- Define a first-class integration-policy identity on the edge: `manual` means
  the parent later accepts a delivery; `auto` names the exact bounded delivery
  classes which the parent pre-authorized at admission. The policy decides
  acceptance, not the child.
- Keep execution and context provenance separate. A native logical child may
  prove a source relationship and own a context scope, but its process effects
  remain pinned to the outer session invocation. It must never acquire a
  child-session identity from an App Server event, a hook, a thread ID, or a
  later process observation.
- Keep session-local audit validation exact: a child physical-effect audit pin
  still names the child session's scope ref. Parent/child relationship evidence
  is an additional checked family fact, never an exemption from pin validation.
- Extend the context crate only where needed to construct a safe result tree
  from an existing parent tree. Do not expose raw Git mutation or unchecked
  object IDs to the daemon, adapter, CLI, or fixture.
- Add crate-local tests for stale parent heads, wrong-family pins, duplicate
  child refs, depth overflow, attempted parent-ref write, attempted re-parent,
  confused logical/physical bindings, failed atomic fork, reopen, and full
  graph verification.

## Checkpoint

- A context family can create two sibling child scopes and one grandchild.
- Each child head has the requested immutable parent commit as an ancestor.
- Parent-side child-admitted facts and refs change together or neither changes.
- The family proves `P -> B`, `P -> C`, and `B -> D`; no direct edge or ref can
  make B a child of C or an independent root.
- The repository proves the same logical graph for both bindings, while audit
  evidence proves a separate child process only for `daemon-physical` edges.
- Reopen reconstructs only durable family/ref facts; it does not infer an edge
  from session history, a process tree, or an audit record.

## Acceptance

The repository itself proves a real directed Git topology with direct refs and
causal commit ancestry. It is not a JSON record that merely names a parent.
No child process is admitted or launched in this phase.

## Stop Point

Stop after the Phase 1 result and verification. Wait for approval before Phase
2.
