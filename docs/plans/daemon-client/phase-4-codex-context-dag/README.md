# Phase 4 Codex Context DAG And Child-Agent Delegation

Status: Proposed. This is a nested Phase 4 plan. No implementation phase has
started.

Parent plan: [Phase 4: Codex Adapter, Final CLI Cutover, And App Server Migration](../phase-4-codex-adapter-final-cli-cutover-and-app-server-migration.md)

## Goal

Make nested Codex work belong to a durable Git-shaped context family. Where an
approved pre-spawn bridge exists, make a separately trusted child an explicit
daemon-owned session; otherwise retain the native child only as a logical node
inside the outer session. Prove causal forks, sibling branches, nested branches,
frozen spawn inputs, routed inter-agent communication, parent-owned integration
decisions, repeatable merges, lifecycle control, and accurate physical-effect
attribution for each binding.

This is not a way for a raw `codex` descendant to become trusted. A raw nested
process remains only a governed descendant of the current invocation.

## Source-Grounded Direction

The checked-in Codex source has several distinct collaboration mechanisms. The
adapter must preserve their meaning rather than treating every new process or
every App Server thread as a child agent.

| Codex mechanism | What the source does | Erebor direction |
| --- | --- | --- |
| `spawn_agent` | Creates a directed internal Codex thread, carrying a parent thread, depth, canonical agent path, role/nickname, and open/closed lifecycle. A child has one persisted parent, but it is not a new operating-system process. | It provides native logical-DAG facts only. A separately governed daemon child requires an explicit pre-spawn Erebor delegation bridge; observing the native spawn afterward cannot create one. |
| `fork_turns` | Materializes the parent's history, copies a filtered frozen projection using `none`, `all`, or last *N* turns, and deliberately excludes internal tool traffic and inter-agent traffic. | The daemon creates a checked child scope from an exact parent `ContextPin`; a profile may select an equivalent bounded projection. It is never live sharing. |
| `send_message` | Queues a bounded inter-agent delivery without waking the recipient. | A sender creates a candidate delivery in the receiver's daemon-owned inbox. It cannot write the receiver's scope. |
| `followup_task` | Delivers a message and requests a target child turn. | The receiver's existing session receives a policy-checked follow-up request; only an allowed ancestor-to-descendant route may wake a child initially. |
| completion forwarding | Delivers a bounded child completion/result to the parent with `trigger_turn=false`. | A terminal delivery becomes a candidate contribution, subject to the parent integration policy; it is not an implicit Git mutation. |
| Legacy collaboration tools | The older tool family reports `spawn_agent`, `send_input`, `resume_agent`, `wait`, and `close_agent` activity. Its meanings differ from V2 messaging and status handling. | A profile chooses one source variant. Erebor maps only a source-proven, directionally safe equivalent; an unproved legacy action is reported or rejected, never silently normalized. |
| protocol-level multi-recipient/encrypted communication | The internal communication envelope has additional recipients and encrypted content fields beyond the single-target V2 tools. | Do not expose broadcast, opaque encrypted payloads, or arbitrary recipients until the daemon can authenticate every recipient and retain an inspectable bounded receipt. |
| `SubagentStart` hook | Runs only after Codex has created a thread and is explicitly context-injection-only; its output cannot stop the subagent. | It is authenticated observation/evidence, never child admission or a way to retroactively grant a child session. |
| App Server `collabToolCall` | Reports collaboration tool activity and resulting thread IDs/statuses to the App Server client after the native operation. | It is an adapter observation channel. It can populate a native logical-DAG record, but cannot be treated as a pre-spawn authorization boundary. |
| `list_agents` and `interrupt_agent` | Enumerates the live/persisted graph and can control a known non-root agent. | Expose a daemon-derived, family-scoped read view. Cancellation is restricted to the family owner or an ancestor over its descendant; no child may control an ancestor or sibling. |
| App Server peer-thread lifecycle | `thread/fork`, resume, rollback, archive, list/read, and historical-thread paths operate on App Server conversation threads. They are distinct from collaboration `spawn_agent` and do not establish the collaboration graph. | Keep peer-thread creation/reopening out of child admission. Phase 4 permits only the already-admitted session's exact App Server turn contract and rejects peer-thread operations until a separate daemon-owned peer-thread surface is designed. |

Codex also permits model, role, effort, service-tier, environment, and execution
policy choices around spawning. In Erebor those are not delegated authority:
the selected package profile and daemon policy choose a bounded child class.
The child cannot turn a source option into a different executable, policy,
workspace, caller identity, or daemon capability.

Erebor adopts the useful collaboration semantics while keeping the
`ContextRepository`—not Codex's SQLite thread graph, an App Server thread ID, a
hook payload, a PID, or a child-supplied parent ID—as the authoritative
provenance graph.

### Native And Physical Child Modes

The general Context DAG has two explicit execution bindings. They share the
same parent-edge, frozen-fork, inbox, and parent-integration semantics, but do
not make the same containment claim.

| Binding | Creation | Physical-effect attribution | Trust boundary |
| --- | --- | --- | --- |
| Native logical child | Stock Codex internally executes `spawn_agent`. Erebor observes source-pinned facts after creation. | Effects remain under the one outer governed Codex invocation; a per-thread process-guard claim is impossible. | No separate daemon session, no new socket/ticket/UID/process isolation, and no retroactive elevation. |
| Daemon physical child | An approved Erebor delegation bridge obtains admission **before** starting the child workload. | Effects are pinned to the child invocation, with its own session/guard/hook registrations. | Separately governed child, fixed parent edge, and no parent-branch write capability. |

Phase 4 may implement the native logical adapter only as evidence unless a
pinned pre-spawn bridge exists. The deterministic fixture must exercise the
physical-child contract. A real Codex profile may claim physical-child support
only after it supplies an audited, version-pinned bridge; neither a hook nor an
App Server notification is that bridge.

### Local Source Review Basis

This direction is based on the checked-out Codex source, not an assumed public
protocol: `agent-graph-store/src/store.rs` defines one persisted parent and
open/closed edge status; `core/src/agent/control/spawn.rs` materializes and
filters the frozen fork history; `core/src/tools/handlers/multi_agents_v2/`
implements spawn, list, messaging, follow-up, and interruption; and
`core/src/session/mod.rs` forwards terminal child completion to a parent. The
`core/src/hook_runtime.rs` dispatches `SubagentStart` only after native thread
creation, while `hooks/src/events/session_start.rs` states that it is
context-injection-only. The App Server separately exposes post-operation
`collabToolCall`, `thread/fork`, and `parentThreadId` / `forkedFromId`; that is
why this plan explicitly refuses to mistake any of them for a trusted
delegation edge.

## Who Initiates A Merge

The parent owns its branch. The child therefore **does not initiate a merge**;
it can only publish a bounded, authenticated delivery from its own scope. The
direct parent then accepts or rejects that delivery. Acceptance may come from a
live parent action or from an immutable `auto-integrate` rule selected when the
parent created the child. The daemon-owned context-family coordinator is the
only component that performs the Git write.

This yields four separate facts, each retained durably:

```text
parent P opens child B       -> immutable P -> B edge and checked B scope fork
child B sends a delivery     -> B contribution in P's inbox; P is unchanged
parent P / its policy accepts -> integration decision naming that exact delivery
family coordinator commits   -> one two-parent merge into P's scope
```

The automatic Codex completion notification maps to the second step, not the
fourth. A Codex-compatible profile may select parent-side auto-integration for
specified terminal or message deliveries, but the audit records that the
parent's policy—not the child—authorized the integration. A parent can continue
working while an inbox item waits. A grandchild integrates first into its direct
parent; nothing bubbles into an ancestor without that parent making a new
contribution of its own.

## Target Context Topology

This diagram shows the daemon-physical fixture. A native logical run has the
same context edges and inboxes, but each child has `P`'s one physical invocation
instead of its own guard/session binding.

```text
context family F, one shared ContextRepository
  parent session P / parent scope
    ├─ fork: child session B / child scope
    │    ├─ delivery -> P inbox -> P accepts -> coordinator merges into P
    │    ├─ prompt B-2 -> lease -> shell -> ls descendants
    │    └─ fork: grandchild D / grandchild scope
    │         └─ delivery -> B inbox -> B accepts -> coordinator merges into B
    └─ fork: child session C / child scope
         └─ cancelled: no contribution merge
```

Each child scope starts at the exact immutable parent decision pin that caused
its admission. The child then appends only to its own scope; it is contained by
the parent edge and family, not by sharing the parent's mutable ref. The direct
parent owns an inbox for its descendants and chooses which candidate deliveries
to integrate. The daemon-owned family coordinator serializes parent-head
updates, so several children may contribute concurrently without stale-head
replacement or an octopus commit. Each accepted delivery is one two-parent
merge: current parent head plus the selected child contribution commit. A child
may contribute many messages and a final result, producing many ordered parent
merges.

## Non-Negotiables

- A child has exactly one immutable parent edge, context family, depth, and
  admitted package/installation/adapter identity.
- A parent may create and control only its declared descendant subtree. A child
  cannot re-parent itself, address a sibling/ancestor as an integration target,
  or use an App Server thread fork as a delegation escape.
- The parent decision pin, not a current mutable branch head, is the fork
  origin. The daemon validates the pin before it creates the child scope.
- A child cannot choose another parent, an arbitrary source commit, an alias,
  an executable, a policy set, a runner, or a raw daemon-control operation.
- Child-originated does not mean child-authorized: the daemon verifies the
  child registration, edge, session state, bounded payload, selected child
  commit, policy, and parent before it records a delivery. A separate parent
  decision or predeclared parent policy is required before it merges.
- Every merge has two parents and a result tree containing only the parent
  state plus the selected bounded contribution receipt. The child branch never
  changes as a consequence of a parent merge.
- A raw nested process, copied ticket, inherited environment, direct hook,
  direct daemon-socket connection, or unleased `exec codex` cannot create a
  child session, scope, contribution, or merge.
- Parent and child continue independently. Cancellation, failure, expiry,
  daemon loss, or recovery cannot invent a contribution or merge from output,
  history, PID reuse, or a stale in-memory graph.
- This plan adds no caller `HOME`/`CODEX_HOME`, filesystem state projection,
  OCI/Notation, remote daemon, or arbitrary plugin capability.

## Existing Baseline

- `erebor-runtime-context` already owns checked `fork_scope` transactions and
  two-parent `append_pinned_merge` commits, but no Codex owner calls them.
- `CodexContextDag` currently creates a prompt scope from the session root and
  appends prompt and authenticated-hook facts linearly. It has no context
  family, child scope, or merge coordinator.
- `CodexInvocationLeaseOwner` binds kernel-observed process descendants to one
  exact lease and records context pins in audit evidence. It does not create a
  child agent context.
- The deterministic `codex-v1-fixture` proves package, hook, TTY, and App
  Server boundaries, but it has no collaboration spawn, contribution, or
  nested-context scenario.
- The local Codex source under `codex/codex-rs/` provides the behavioral input
  above. It is not an Erebor authority and its thread IDs are only authenticated
  adapter facts once the selected source profile has proved their schema and
  ordering.

## Target Ownership

```text
erebor-runtime-context
  checked context-family fork and parent-tree-preserving pinned-merge helpers;
  direct refs, object validation, and recovery invariants

erebor-runtime-core
  validated ContextFamilyId, parent-edge, child-admission, delivery, inbox,
  integration decision, depth, quota, routing, and policy facts; immutable
  SessionSpec copies

erebor-runtime-daemon
  context-family registry, serialized family coordinator, child-session
  admission, inbox/integration ownership, private delegation endpoint
  ownership, recovery, and audit

erebor-runtime-session/src/agents/codex
  authenticated native spawn, communication, completion, lifecycle, and
  App-Server-surface mapping; child hook registration, child context writes,
  and lease-to-physical-effect pins

erebor-runtime-ipc
  distinct bounded child-delegation and contribution messages; never daemon
  control or generic session-input bytes

erebor-runtime-e2e
  deterministic nested Codex fixture, graph inspection, two-UID, guard, and
  privileged Linux lifecycle evidence
```

## Phase Index

- [Lifecycle probe](lifecycle-probe.md)
- [Phase 1: Context Family And Causal Fork Contract](phase-1-context-family-and-causal-fork-contract.md)
- [Phase 2: Child Admission And Private Delegation Bridge](phase-2-child-admission-and-private-delegation-bridge.md)
- [Phase 3: Child Contributions, Parent-Owned Integration, Repeatable Merges, And Recovery](phase-3-child-contributions-repeatable-merges-and-recovery.md)
- [Phase 4: Deterministic DAG Fixture, Lifecycle, And Privileged Evidence](phase-4-deterministic-dag-fixture-and-privileged-evidence.md)

## Stop Point

Implement only one approved nested phase at a time. The first implementation
step is Phase 1. Do not begin Phase 5 merely because this plan exists.
