# Phase 4 Codex Context DAG And Child-Agent Delegation

Status: Proposed. This is a nested Phase 4 plan. No implementation phase has
started.

Parent plan: [Phase 4: Codex Adapter, Final CLI Cutover, And App Server Migration](../phase-4-codex-adapter-final-cli-cutover-and-app-server-migration.md)

## Goal

Make nested Codex work belong to a durable Git-shaped scope DAG. Where an
approved pre-spawn bridge exists, make a separately trusted child an explicit
daemon-owned session; otherwise retain the native child only as a logical node
inside the outer session. Prove causal forks, sibling branches, nested branches,
frozen spawn inputs, routed inter-agent communication, parent-owned integration
decisions, repeatable merges, lifecycle control, and accurate physical-effect
attribution for each binding.

The DAG has no new `ContextFamilyId`. Its identity is the daemon-owned
`ContextRepository` plus the top-level root `ScopeRef`; immutable direct-parent
edges make every child membership derivable from that root. A scope ref already
contains its session namespace, and a checked fork/merge already provides the
required commit identity. Adding a parallel identifier would create another
value that must be kept consistent with those facts.

Here “root scope” means the initial agent scope for this DAG—P's outer prompt
scope in the fixture—not necessarily the repository's `ScopeRef::root(...)`.
The latter is merely a session's default ref. A physical child starts at its own
`ScopeRef::root(child_session_id)` forked from the exact parent pin; a native
logical child uses a named scope in its existing session.

## Minimal Durable Model

Keep the durable model inside the existing scopes and repository:

- Reuse `ScopeRef` for the root, agent-child, and operation refs; reuse
  `ContextPin` for every exact fork source and received result; reuse existing
  `SessionAdmission` and `SessionSpec` for a physical child session.
- Add only an optional parent `ContextPin` to a child `SessionSpec`. It lets the
  daemon reopen the parent/root repository on recovery; the child root scope is
  already derivable from the child `SessionId`.
- Use `ContextRepository::fork_scope`'s existing parent append to write one
  schema-versioned edge blob into the parent scope atomically with creation of
  the child ref. A child or operation writes each bounded delivery blob only in
  its own scope. The parent inbox is the derived view of direct-child delivery
  blobs without a later parent receipt or rejection blob.
- A receive uses the existing two-parent merge and adds its receipt to that
  merge tree. A rejection is an ordinary parent-only context append containing
  the rejection receipt. There is no graph ledger, inbox ref, family registry,
  `ChildContribution`, `IntegrationDecision`, or separate operation-state
  entity.
- Treat agent results and command results as the same delivery shape. An
  operation is identified by its owner scope plus the adapter's bounded source
  operation key, and is bound to existing lease/effect evidence. Do not create
  a global `OperationId`.

The edge blob is the only added durable *relationship* fact because Git
ancestry alone cannot say which *scope* is the direct parent when several refs
name the same commit. Deliveries and receipts are ordinary bounded blobs in
existing scopes; all other identities already come from a scope, pin, session,
or lease.

All topology and rejection blobs live below the reserved
`erebor/context-dag/` path and are excluded from adapter prompt projection. A
receive merge additionally writes the selected bounded result at the adapter's
declared model-visible result path. This keeps the graph auditable without
turning child-admission or rejection metadata into model context.

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
| `send_message` | Queues a bounded inter-agent delivery without waking the recipient. | The daemon appends a candidate delivery in the sender's scope; the receiver derives it in its inbox query. It cannot write the receiver's scope. |
| `followup_task` | Delivers a message and requests a target child turn. | The receiver's existing session receives a policy-checked follow-up request; only an allowed ancestor-to-descendant route may wake a child initially. |
| completion forwarding | Delivers a bounded child completion/result to the parent with `trigger_turn=false`. | A terminal delivery becomes a candidate delivery. It is not an implicit Git mutation; the parent explicitly receives or rejects it. |
| unified exec / background terminal | After its initial yield, Codex retains the process by process ID, streams output and a terminal event, and expects a later `write_stdin` poll or input to return a model-visible tool result. | Model every long-running command as an owned non-agent child branch. Partial and final output are bounded deliveries; the owner explicitly receives a selected sequence point through the same two-parent merge coordinator. |
| Legacy collaboration tools | The older tool family reports `spawn_agent`, `send_input`, `resume_agent`, `wait`, and `close_agent` activity. Its meanings differ from V2 messaging and status handling. | A profile chooses one source variant. Erebor maps only a source-proven, directionally safe equivalent; an unproved legacy action is reported or rejected, never silently normalized. |
| protocol-level multi-recipient/encrypted communication | The internal communication envelope has additional recipients and encrypted content fields beyond the single-target V2 tools. | Do not expose broadcast, opaque encrypted payloads, or arbitrary recipients until the daemon can authenticate every recipient and retain an inspectable bounded receipt. |
| `SubagentStart` hook | Runs only after Codex has created a thread and is explicitly context-injection-only; its output cannot stop the subagent. | It is authenticated observation/evidence, never child admission or a way to retroactively grant a child session. |
| App Server `collabToolCall` | Reports collaboration tool activity and resulting thread IDs/statuses to the App Server client after the native operation. | It is an adapter observation channel. It can populate a native logical-DAG record, but cannot be treated as a pre-spawn authorization boundary. |
| `list_agents` and `interrupt_agent` | Enumerates the live/persisted graph and can control a known non-root agent. | Expose a daemon-derived, root-scope-scoped read view. Cancellation is restricted to the root owner or an ancestor over its descendant; no child may control an ancestor or sibling. |
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
same parent-edge, frozen-fork, derived-inbox, and parent-integration semantics,
but do not make the same containment claim.

| Binding | Creation | Physical-effect attribution | Trust boundary |
| --- | --- | --- | --- |
| Native logical child | Stock Codex internally executes `spawn_agent`. Erebor observes source-pinned facts after creation. | Effects remain under the one outer governed Codex invocation; a per-thread process-guard claim is impossible. | No separate daemon session, no new socket/ticket/UID/process isolation, and no retroactive elevation. |
| Daemon physical child | An approved Erebor delegation bridge obtains admission **before** starting the child workload. | Effects are pinned to the child invocation, with its own session/guard/hook registrations. | Separately governed child, fixed parent edge, and no parent-branch write capability. |

Phase 4 may implement the native logical adapter only as evidence unless a
pinned pre-spawn bridge exists. The deterministic fixture must exercise the
physical-child contract. A real Codex profile may claim physical-child support
only after it supplies an audited, version-pinned bridge; neither a hook nor an
App Server notification is that bridge.

## Asynchronous Command Results

A command is not an agent, but it is still a causal child of the context node
that issued it. The source starts a command, waits only for the requested yield
window, keeps an alive process in its terminal store, streams client events,
and later returns output when the same agent polls or writes to that process.
Its asynchronous terminal event is evidence, not a new model tool response.

Erebor gives the operation its own immutable child scope/ref and uses the same
parent-owned receive/merge protocol as an agent child:

```text
agent/node B starts command q
  -> fork operation q from B's exact launch pin; guarded process runs for q
  -> q appends bounded output delivery q:1; B may continue other work
  -> B explicitly receives q:1 -> coordinator merges q:1 into B's current head
  -> q appends q:2 / final q:n delivery; B explicitly receives any selected sequence
```

A poll that selects result output maps to
`receive(q, expected sequence/pin)`. An input-only `write_stdin`
records the checked process-input fact but creates no merge; the owner may
later poll and receive a bounded partial or final output. The coordinator
validates that receive request and creates one two-parent merge with B's
then-current head and the exact q delivery commit. Stream/end notifications
never perform this merge, and the adapter coalesces them into a policy-bounded,
monotonic delivery sequence rather than a Git commit per client delta. The
operation cannot choose its parent, advance B's ref, or send output directly to
P. If B needs P to know a result, B makes a normal bounded delivery and P
follows the same parent-owned receive/merge protocol above.

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
delegation edge. `core/src/unified_exec/process_manager.rs` retains an alive
command after its yield window and `unified_exec/async_watcher.rs` emits stream
and terminal events; `write_stdin` is the later model-visible poll/input path.

## Who Initiates A Merge

The parent owns its branch. The child therefore **does not initiate a merge**;
it can only publish a bounded, authenticated delivery from its own scope. The
direct parent explicitly receives or rejects that delivery. The daemon
coordinator is the only component that performs the Git write.

This yields four separate facts, each retained durably:

```text
parent P opens child B       -> immutable P -> B edge and checked B scope fork
child B publishes delivery   -> bounded blob in B's scope; P is unchanged
parent P receives/rejects    -> merge receipt or parent-only rejection receipt
daemon coordinator commits   -> one two-parent merge into P's scope on receive
```

This is deliberately one protocol with two sources. An agent child and a
command operation each append a bounded delivery blob in their own scope that
names the exact source pin and receiver scope. The owner's receive request
names that delivery and its expected current head; the coordinator creates the
same two-parent merge and receipt in either case. The only differences are the
source identity and execution binding: child session versus process capability.

The automatic Codex completion notification maps to the second step, not the
fourth. In this contract a parent must explicitly receive the selected delivery;
there is no automatic completion merge. A parent can continue working while a
derived inbox item waits. A grandchild integrates first into its direct parent;
nothing bubbles into an ancestor without that parent making a new delivery of
its own.

## Target Context Topology

This diagram shows the daemon-physical fixture. A native logical run has the
same context edges and derived inboxes, but each child has `P`'s one physical
invocation instead of its own guard/session binding.

```text
one daemon-owned ContextRepository, rooted at P's ScopeRef
  parent session P / parent scope (the DAG root)
    ├─ fork: child session B / child scope
    │    ├─ B delivery blob -> P derived inbox -> P receives -> merge into P
    │    ├─ prompt B-2 -> lease -> shell -> ls descendants
    │    └─ fork: grandchild D / grandchild scope
    │         └─ D delivery blob -> B derived inbox -> B receives -> merge into B
    └─ fork: child session C / child scope
         └─ cancelled: no delivery merge
```

Each child scope starts at the exact immutable parent decision pin that caused
its admission. The child then appends only to its own scope; it is contained by
the parent edge and derived root scope, not by sharing the parent's mutable ref.
The direct parent queries a derived inbox for its descendants and chooses which
candidate deliveries to integrate. The daemon coordinator serializes parent-head
updates, so several children may publish concurrently without
stale-head replacement or an octopus commit. Each received delivery is one
two-parent merge: current parent head plus the selected child delivery commit.
A child may publish many messages and a final result, producing many
ordered parent merges.

## Non-Negotiables

- A child has exactly one immutable parent edge, derived root scope, depth, and
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
  commit, policy, and parent before it records a delivery. An explicit parent
  receive is required before it merges.
- Every merge has two parents and a result tree containing only the parent
  state plus the selected bounded delivery receipt. The child branch never
  changes as a consequence of a parent merge.
- An asynchronous command has one immutable owner scope, launch pin,
  invocation/lease identity, adapter source-operation key, and operation scope
  ref. Partial and final results are delivery records until that owner explicitly
  receives them through a two-parent merge; no late stdout, PID, or terminal
  event may advance any context ref by itself.
- A command result never bypasses its owner. A child command cannot reach a
  parent/sibling context, and a command from a native logical child retains the
  outer invocation's physical attribution.
- A raw nested process, copied ticket, inherited environment, direct hook,
  direct daemon-socket connection, or unleased `exec codex` cannot create a
  child session, scope, delivery, or merge.
- Parent and child continue independently. Cancellation, failure, expiry,
  daemon loss, or recovery cannot invent a delivery or merge from output,
  history, PID reuse, or a stale in-memory graph.
- This plan adds no caller `HOME`/`CODEX_HOME`, filesystem state projection,
  OCI/Notation, remote daemon, or arbitrary plugin capability.

## Existing Baseline

- `erebor-runtime-context` already owns checked `fork_scope` transactions and
  two-parent `append_pinned_merge` commits, but no Codex owner calls them.
- `CodexContextDag` currently creates a prompt scope from the session root and
  appends prompt and authenticated-hook facts linearly. It has no scope DAG,
  child scope, or merge coordinator.
- `CodexInvocationLeaseOwner` binds kernel-observed process descendants to one
  exact lease and records context pins in audit evidence. It does not create a
  child agent context.
- The deterministic `codex-v1-fixture` proves package, hook, TTY, and App
  Server boundaries, but it has no collaboration spawn, delivery, or
  nested-context scenario.
- The local Codex source under `codex/codex-rs/` provides the behavioral input
  above. It is not an Erebor authority and its thread IDs are only authenticated
  adapter facts once the selected source profile has proved their schema and
  ordering.

## Target Ownership

```text
erebor-runtime-context
  existing checked fork and parent-tree-preserving pinned-merge helpers; direct
  refs, object validation, and safe helpers to add edge/delivery/receipt trees

erebor-runtime-core
  existing SessionAdmission/SessionSpec, with only an optional parent
  ContextPin for a child; no DAG ID, contribution/decision object, or
  operation ID

erebor-runtime-daemon
  a context coordinator that resolves the existing root session artifact,
  serializes scope writes, uses ordinary session admission, owns the private
  delegation endpoint, derives delivery queries/receives from scopes, and owns
  recovery/audit. No parallel registry or graph ledger.

erebor-runtime-session/src/agents/codex
  authenticated native spawn, communication, completion, lifecycle, and
  App-Server-surface mapping; source command/poll mapping, child hook
  registration, child context writes, and lease-to-physical-effect pins

erebor-runtime-ipc
  distinct bounded child-delegation and delivery messages; never daemon
  control or generic session-input bytes

erebor-runtime-e2e
  deterministic nested Codex fixture, graph inspection, two-UID, guard, and
  privileged Linux lifecycle evidence
```

## Phase Index

- [Lifecycle probe](lifecycle-probe.md)
- [Phase 1: Context Scopes And Causal Fork Contract](phase-1-context-family-and-causal-fork-contract.md)
- [Phase 2: Child Admission And Private Delegation Bridge](phase-2-child-admission-and-private-delegation-bridge.md)
- [Phase 3: Child Deliveries, Parent-Owned Receives, Repeatable Merges, And Recovery](phase-3-child-contributions-repeatable-merges-and-recovery.md)
- [Phase 4: Deterministic DAG Fixture, Lifecycle, And Privileged Evidence](phase-4-deterministic-dag-fixture-and-privileged-evidence.md)

## Stop Point

Implement only one approved nested phase at a time. The first implementation
step is Phase 1. Do not begin Phase 5 merely because this plan exists.
