# Phase 4 Codex Context DAG

Status: Done. The daemon-derived graph listing reads the Git
ContextRepository only, anchors an admitted native operation below its exact
source tool, and renders lease-validated physical effects, delivery/merge
facts, and source-authenticated agent controls. The checked-in deterministic
lane drives P/B/C/D/q through the public daemon/client path and validates Git
refs, pins, and causal ancestry. The privileged two-UID Linux
installed-product run now passes in the systemd-container lane. The broader
parent Phase 4 has its separately recorded foreground host-lab recovery
verification.

Parent plan: [Phase 4: Codex Adapter, Final CLI Cutover, And App Server Migration](../phase-4-codex-adapter-final-cli-cutover-and-app-server-migration.md)

## Goal

Make nested Codex work belong to a durable Git-shaped scope DAG inside one
daemon-owned Erebor session. One `erebor run … codex` creates one session, one
TTY, one hook registration, and one Linux guarded process tree. Codex threads,
turns, `spawn_agent` children, and asynchronous operations are named scopes in
that session, not separately trusted child sessions.

The DAG has no new `ContextFamilyId`. Its identity is the daemon-owned
`ContextRepository` plus the top-level root `ScopeRef`; immutable direct-parent
edges make every child membership derivable from that root. A scope ref already
contains its session namespace, and a checked fork/merge already provides the
required commit identity. Adding a parallel identifier would create another
value that must be kept consistent with those facts.

Here “root scope” means the initial agent scope for this DAG—P's outer prompt
scope in the fixture—not necessarily the repository's `ScopeRef::root(...)`.
The latter is merely the session's default ref. Every nested Codex thread and
operation uses a named scope in the same session namespace.

## Minimal Durable Model

Keep the durable model inside the existing scopes and repository:

- Reuse `ScopeRef` for root, logical child, and operation refs, and reuse
  `ContextPin` for every exact fork source and received result. A logical child
  has no `SessionSpec`, session admission, or separate runtime identity.
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
| `spawn_agent` | Creates a directed internal Codex thread, carrying a parent thread, depth, canonical agent path, role/nickname, and open/closed lifecycle. A child has one persisted parent, but it is not a new operating-system process. | It is a checked logical scope fork in the same Erebor session. Observing it cannot create a session, guard, hook socket, or separate process tree. |
| `fork_turns` | Materializes the parent's history, copies a filtered frozen projection using `none`, `all`, or last *N* turns, and deliberately excludes internal tool traffic and inter-agent traffic. | The daemon creates a checked child scope from an exact parent `ContextPin`; a profile may select an equivalent bounded projection. It is never live sharing. |
| `send_message` | Queues a bounded inter-agent delivery without waking the recipient. | The daemon appends a candidate delivery in the sender's scope; the receiver derives it in its inbox query. It cannot write the receiver's scope. |
| `followup_task` | Delivers a message and requests a target child turn. | The fixture profile emits a bounded source control through the existing authenticated hook. The daemon permits only an ancestor-to-descendant target, records only the follow-up content digest in the requester's scope, and returns an allow result before the source resumes the child. |
| completion forwarding | Delivers a bounded child completion/result to the parent with `trigger_turn=false`. | A terminal delivery becomes a candidate delivery. It is not an implicit Git mutation; the parent explicitly receives or rejects it. |
| unified exec / background terminal | After its initial yield, Codex retains the process by process ID, streams output and a terminal event, and expects a later `write_stdin` poll or input to return a model-visible tool result. | Model every long-running command as an owned non-agent child branch. Partial and final output are bounded deliveries; the owner explicitly receives a selected sequence point through the same two-parent merge coordinator. |
| Legacy collaboration tools | The older tool family reports `spawn_agent`, `send_input`, `resume_agent`, `wait`, and `close_agent` activity. Its meanings differ from V2 messaging and status handling. | A profile chooses one source variant. Erebor maps only a source-proven, directionally safe equivalent; an unproved legacy action is reported or rejected, never silently normalized. |
| protocol-level multi-recipient/encrypted communication | The internal communication envelope has additional recipients and encrypted content fields beyond the single-target V2 tools. | Do not expose broadcast, opaque encrypted payloads, or arbitrary recipients until the daemon can authenticate every recipient and retain an inspectable bounded receipt. |
| `SubagentStart` hook | Runs only after Codex has created a thread and is explicitly context-injection-only; its output cannot stop the subagent. | It is authenticated observation/evidence, never child admission or a way to retroactively grant a child session. |
| App Server `collabToolCall` | Reports collaboration tool activity and resulting thread IDs/statuses to the App Server client after the native operation. | It is an adapter observation channel. It can populate a native logical-DAG record, but cannot be treated as a pre-spawn authorization boundary. |
| `list_agents` and `interrupt_agent` | Enumerates the live/persisted graph and can control a known non-root agent. | Resolve only daemon-bound thread/turn identities from the durable scope tree. Listing returns strict descendants; interruption is restricted to an ancestor over its descendant. The hook payload never supplies a scope ref, and no child may control an ancestor or sibling. |
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

### Logical Child Scope Contract

The general Context DAG uses `native-logical` child scopes for Codex work. The
authenticated adapter supplies bounded child thread/turn IDs and a frozen
parent projection. The daemon creates the direct scope edge from that exact pin
and binds the returned scope to the declared thread/turn.

This records causal ownership without inventing operating-system containment:
all physical descendants remain in the root session's existing guarded process
tree. A command launched by logical child B is pinned to B's invocation lease,
but it is not a new session or another guard. There is no delegation bridge,
child session, child hook listener, or bridge package contract in this phase.

An independently launched agent session can be designed later as an explicit
user-facing runner feature. It must never be inferred from a Codex thread,
hook, PID, or App Server notification.

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

An operation scope is admitted when the authenticated adapter source declares
that the command is retained (`erebor_operation_key` in the current profile).
The daemon must not infer a new scope retrospectively merely because a later
command finds an earlier process still alive: that would race exits and rewrite
causal ownership after physical effects have happened. The guard's observed
fork/exec/exit lifecycle is evidence for the already-admitted operation; it
does not independently create a scope. A command that completes in its initial
turn, such as the fixture `ls`, remains an effect of B's existing scope.

Every graph activity is a durable Git blob in the owning `ContextRepository`.
Authenticated hooks live under `agents/codex/hooks/`; a lease-validated guard
observation lives under `agents/codex/physical-effects/` and retains the exact
source context pin, lease identity, observed PID/PPID, executable, argv, and
allow/deny decision. JSONL continues as a parallel operational audit sink, but
the graph command never reads it.

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
source scope and the existing invocation/operation lease that carries physical
attribution.

The automatic Codex completion notification maps to the second step, not the
fourth. In this contract a parent must explicitly receive the selected delivery;
there is no automatic completion merge. A parent can continue working while a
derived inbox item waits. A grandchild integrates first into its direct parent;
nothing bubbles into an ancestor without that parent making a new delivery of
its own.

## Target Context Topology

This diagram shows the single-session fixture. P, B, C, D, and q are scopes in
one daemon-owned repository and one guarded Linux process tree.

```text
one daemon-owned ContextRepository and one Erebor session, rooted at P's ScopeRef
  parent scope P (the DAG root)
    ├─ fork: logical child scope B
    │    ├─ B delivery blob -> P derived inbox -> P receives -> merge into P
    │    ├─ prompt B-2 -> lease -> shell -> ls descendants
    │    └─ fork: grandchild D / grandchild scope
    │         └─ D delivery blob -> B derived inbox -> B receives -> merge into B
    └─ fork: logical child scope C
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
  scope edge, delivery, merge, or second session.
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
  existing session identity and no nested-session extension; no DAG ID,
  contribution/decision object, or operation ID

erebor-runtime-daemon
  a context coordinator that resolves the existing root session artifact,
  serializes scope writes, admits same-session logical forks, derives delivery
  queries/receives from scopes, authorizes source-authenticated agent controls,
  and owns recovery/audit. No parallel registry, graph ledger, child-session
  lifecycle path, or workload-facing control listener.

erebor-runtime-session/src/agents/codex
  authenticated native spawn, communication, completion, lifecycle, and
  App-Server-surface mapping; source command/poll mapping, same-session child
  context writes, and lease-to-physical-effect pins

erebor-runtime-ipc
  the existing guard lifecycle event and normal hold/release/deny reply; never
  a child-delegation request, daemon control, or generic session-input bytes

erebor-runtime-e2e
  deterministic nested Codex fixture, graph inspection, two-UID, guard, and
  privileged Linux lifecycle evidence
```

## Phase Index

- [Lifecycle probe](lifecycle-probe.md)
- [Phase 1: Context Scopes And Causal Fork Contract](phase-1-context-family-and-causal-fork-contract.md)
- [Phase 2: Logical Child Scope Admission](phase-2-child-admission-and-private-delegation-bridge.md)
- [Phase 3: Child Deliveries, Parent-Owned Receives, Repeatable Merges, And Recovery](phase-3-child-contributions-repeatable-merges-and-recovery.md)
- [Phase 4: Deterministic DAG Fixture, Lifecycle, And Privileged Evidence](phase-4-deterministic-dag-fixture-and-privileged-evidence.md)

## Stop Point

Nested Phase 4 is complete. Do not begin Phase 5 without its separate approval
and scope. `erebor session context graph <session>` renders the daemon-derived
durable scope tree; its current HEAD and exact fork-parent pin make each
displayed branch auditable without client access to the repository.
