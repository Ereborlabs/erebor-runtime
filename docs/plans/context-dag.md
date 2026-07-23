# Scope Context Git Model

Status: design discussion draft.

This document defines the logical model for nested agent context. The model is
Git-like on purpose: immutable objects, parent pointers, and moving refs.
It is not a commitment to using Git itself as the storage engine.

## Nested Implementation Subplans

- [Current governed-surface integration](context-dag/current-governed-surface-integration.md)
  adds the recovered session-level decision-provenance phases.
- [Codex Attribution V1](context-dag/codex-attribution-v1.md) and its phase
  folder implement the recovered Codex Context DAG track.
- [Claude Attribution V1](context-dag/claude-attribution-v1.md) and its phase
  folder preserve the Claude Context DAG track; its original phase documents
  were not recovered.

## Git Shape Checked

The Git subset Erebor copies is small:

```text
object store:
  blob
  tree
  commit

refs:
  refs/heads/main -> commit id
```

A commit object points at a tree and zero or more parents:

```text
tree <tree-id>
parent <commit-id>
parent <commit-id>
author ...
committer ...

message
```

A tree lists named children:

```text
100644 blob <blob-id> README.md
040000 tree <tree-id> crates
```

A ref is just a moving pointer to an object id. The object stays immutable; the
ref moves.

That is the model to copy.

## Erebor Mapping

```text
Git commit  -> Context commit
Git tree    -> Context root containing evidence and actor-visible views
Git blob    -> Context blob / payload
Git ref     -> Scope head
```

Unlike a normal checked-out Git working tree, Erebor does not have one current
branch during a live run. It has many moving scope heads at the same time.

The live tracker is closer to:

```text
scope_heads:
  refs/scopes/session-8421/root -> ctx_root_p1
  refs/scopes/session-8421/scope/scp_0004 -> ctx_s4_p3
  refs/scopes/session-8421/scope/scp_0005 -> ctx_llm_a1
  refs/scopes/session-8421/scope/scp_0006 -> ctx_llm_b1
  refs/scopes/session-8421/scope/scp_0007 -> ctx_cmd_19_p1
```

An LLM request, command, process, browser operation, or MCP request starts as a
node in its parent scope. If that start can later produce a stream or terminal
result, the live tracker opens a node stream for it. It does not immediately
create a child scope.

If the node stream closes before the parent starts its next action, the later
nodes append to the same parent scope. If the parent starts its next action while
the earlier node stream is open, Erebor forks a generic child scope from the
earlier start node. Later nodes from that stream append to the child scope.

This rule uses only observed lifecycle state: open or closed when the next action
begins. It does not guess whether work is meaningful or infer a task boundary.
There is no global current branch used for live writes.

System prompts, user prompts, policy snapshots, config, and observed runtime
facts are not refs. They are content inside context commits. Every commit points
at a root tree with two logically distinct views:

```text
tree /
  evidence/       append-only facts Erebor captured
  views/actors/   exact context materialized for named actors
```

`evidence/` answers "what did Erebor observe by this durable watermark?" It is
append-only and may contain facts the actor never received. `views/actors/`
answers "what exact normalized, filtered, compacted, summarized, or redacted
context was available to this actor?" A later actor view may replace or omit
entries. The older tree remains immutable, just as an older Git commit keeps its
old checkout.

This separation is fundamental. Reachable evidence is not automatically actor
context, and a causal parent pointer does not grant visibility to the parent's
tree. Parent pointers preserve history; trees record state.

## Core Rule

Each scope is a branch.

Each context node is a commit.

When something happens in a scope, append a new commit whose first parent is the
current scope head, then move the scope ref to the new commit:

```text
P0 -- P1 -- P2 -- P3
                 ^
                 refs/scopes/parent
```

That is the main rule.

If it is later in the same scope, it is the child of the previous head.

Every new context node follows one of four simple cases:

```text
append:  an event continues one existing open scope
fork:    a new scope-open commit points to a causal parent but selects its own
         inherited actor-visible tree
deliver: a produced payload moves through sent and queued states
consume: a receiver appends a two-parent merge for the exact pinned delivery
```

No content-based intent, importance, or task decision is involved. The only fork
test for ordinary overlapping-action work is whether the earlier node stream is
open at the next action. Native agent runtimes may also expose explicit
scope-spawn events.

## Child Scopes And Node Streams

An action start that can later emit data opens a **node stream**. A node stream
records its start commit, the scope currently receiving its later nodes, and an
`open -> closed` lifecycle. It may emit zero, one, or many later nodes. It is a
live routing record, not a DAG object and not a promise of one terminal value.

If that stream closes before the next action begins, no child scope is needed:

```text
Parent: P0 -- P1 ---------------- P2 ---------------- P3
                 LLM A starts       LLM A closes        command B starts
```

`P1` opens node stream `ns_A`. `P2` closes it before `P3` begins, so all three
nodes remain on the parent scope.

"Before" is determined by the session sequence, not by comparing wall-clock
timestamps. If the closing node receives a lower sequence than the next action
start, it stays on the parent scope. If the next action start receives the lower
sequence, the still-open stream forks. A session sequence is unique, so there is
no tie.

If the parent starts another action while `ns_A` is open, create child scope
`scp_0005` with a new `scope_open` commit `A0`:

```text
Parent: P0 -- P1 ------------------------- P2
                 LLM A starts                command B starts
               \
Child A:        A0 -------- A1 ----------- A2
                 scope open   stream chunk   LLM A closes
```

The opening commit has `P1` as its causal parent, but it owns its own tree. That
tree records the exact context inherited by the child:

```text
commit A0:
  parent P1
  event scope_open
  scope-state open
  parent-scope scp_0004
  source-context-commit P1
  fork-window full
  fork-transform identity
  inherited-view-manifest <manifest-id>
  source-watermark <session-sequence>
  evidence-watermark <session-sequence>
```

The parent pointer preserves *why and where* the child began. The inherited view
manifest preserves *what the child could actually see*. They must not be
collapsed. `none`, `last-n`, filtered, summarized, or redacted inheritance can
therefore keep the same causal parent without pretending the omitted material
was actor-visible.

At the instant `P2` starts, Erebor creates:

```text
refs/scopes/session-8421/scope/scp_0005 -> A0
scope scp_0005:
  lifecycle = open
  parent scope = scp_0004
  causal parent = opening commit parent P1
  inherited actor view = <manifest-id>
  owns node stream ns_A
```

Then it changes `ns_A.receiving_scope` from the parent to `scp_0005`. Stream
chunks and the closing result append to that child. The child may remain open
after `ns_A` closes, may start more streams, and may produce multiple deliveries.

This is intentionally Git-shaped. Creating `A0` resembles creating a commit with
an explicit parent and a deliberately selected tree. The causal parent gives the
ancestry; the selected tree gives the checkout. An ancestor does not force its
entire tree into a descendant commit.

The ordinary overlapping-action fork is small enough to express directly:

```text
on_start_next_action(parent_scope, next_action):
  previous = parent_scope.latest_node_stream

  if previous exists and is open:
    flush source observations through a durable source watermark
    manifest = materialize inherited actor view using policy full
    child_scope = append scope_open with:
      parent = previous.start_commit
      inherited_view_manifest = manifest
      fork_window = full
      fork_transform = identity
      source_watermark = durable source watermark
    previous.receiving_scope = child_scope

  append next_action to parent_scope
```

If `previous` is already closed, the `if` does nothing and the next action
appends normally.

Native agent forks use the same opening shape. Fork selection is an ordered
policy rather than one ambiguous label:

```text
source window:
  none
  full
  last-n <count> <source-boundary-kind>

transform pipeline:
  identity
  filtered <filter-profile-and-version>
  summarized <summary-profile-and-version>
  redacted <redaction-profile-and-version>
```

`full` means the complete actor-visible view at `source-context-commit`, not all
observed evidence reachable from it. A runtime-native request such as `all` is
recorded alongside the normalized window and transform pipeline when the two are
not equivalent. The actual inherited-view manifest is authoritative; the policy
explains how it was derived.

Codex is the important example. Its `fork_turns` accepts `none`, `all`, or the
last N turns and defaults to `all`, but `all` is still filtered: the child keeps
prompts and final answers while operational rollout items are excluded. Codex
also flushes the parent rollout before selecting the fork. Erebor should record
that as, for example:

```text
adapter-request fork_turns=all
fork-window full
fork-transform filtered codex-agent-history/<adapter-version>
source-watermark <flushed-rollout-watermark>
inherited-view-manifest <exact-resulting-manifest>
```

This preserves Codex's requested policy without mislabeling its filtered actor
view as a raw-history copy. See the local Codex checkout's
[fork policy and default](../../../codex/codex-rs/core/src/agent/control/spawn.rs#L45),
[flush-before-snapshot path](../../../codex/codex-rs/core/src/agent/control/spawn.rs#L464),
and
[multi-agent spawn materialization](../../../codex/codex-rs/core/src/tools/handlers/multi_agents_v2/spawn.rs#L199).

Before taking any fork snapshot, an adapter must flush the source materialization
through the recorded watermark. If it cannot prove that boundary, it records the
inherited view or watermark as explicitly unknown rather than claiming a full
fork.

A scope has its own independent `open -> closed` lifecycle. Closing a scope
appends a final one-parent `scope_closed` commit and stops new scope-local
actions. The scope ref and immutable history remain. Delivery neither closes the
source scope nor deletes its ref, and a payload produced before closure may be
sent, queued, and consumed afterward.

The logical model therefore has no future abstraction for a scope. An
implementation may expose a handle that waits for closure, but the durable scope
is a branch with a lifecycle, not a one-shot value. The repeatable output channel
is the sequence of deliveries the scope produces.

## Delivery And Consumption

Scope lifetime and delivery lifetime are independent:

```text
scope:     open -> closed
delivery:  produced -> sent -> queued -> consumed by parent
```

A scope can produce and deliver zero, one, or many values while it remains open.
It may continue working after a delivery is consumed. Closing it does not
consume a delivery, and consuming a delivery does not close it. This is the
branch/merge distinction from Git: merging a commit does not delete or freeze
the source branch.

Every delivery has a stable `delivery_id`. At `produced`, Erebor pins:

```text
delivery id
source scope
source commit
payload manifest
payload window: full | last-n
payload transforms: identity | filtered | summarized | redacted
source materialization watermark
intended receiver, when known
```

The pinned source commit is the commit that produced the payload, not the
source scope's moving head at some later consumption time. The payload manifest
records exactly what crossed the boundary. The delivery selection uses the same
ordered window-and-transform shape as a fork. `full` means the source
actor-visible view selected for delivery before named transforms, never the
source's entire evidence history.

Each transition is durable observed evidence:

```text
produced: payload and immutable source commit are fixed
sent:     payload crossed the source boundary
queued:   receiver infrastructure accepted it, but the actor has not consumed it
consumed: receiver actor-visible context incorporated the payload
```

An adapter must not invent a timestamp for a transport boundary it cannot see.
It records a combined or unknown observation boundary explicitly while retaining
the logical state order. Failure, rejection, expiry, or loss is recorded as an
explicit terminal evidence fact and never treated as consumption.

These stages are linked facts in context commits, not a mutable delivery object
or delivery ref. `produced` normally appends on the source scope; `sent` and
`queued` append on the scope or session root that observes the boundary; and
`consumed` is the receiver merge. This allows a delivery produced before source
closure to finish transport afterward without reopening or advancing the closed
source ref.

`produced`, `sent`, and `queued` do not by themselves change the receiver's
actor-visible view. On consumption, append a new two-parent merge commit on the
receiver scope:

```text
Parent: P0 -- P1 -------- H -- Q -------- M -- P2
               \                         /
Child:          C0 -- C1 -- D ---------- C2 -- C3
                         produced
```

Here `D` is the pinned delivery source commit, `Q` records that the delivery is
queued, and `M` records consumption:

```text
tree <receiver-result-tree>
parent Q
parent D
event delivery_consumed
delivery <delivery-id>
delivery-stage consumed

receiver consumed the pinned child delivery
```

The first parent is always the receiver's current head at consumption. The
second parent is always the delivery's pinned source commit `D`, even if the
source ref has since advanced to `C2`, `C3`, or a closing commit. The child ref
is not moved or deleted.

The merge tree has the two logical views:

```text
evidence/       session evidence through M's watermark plus the consumed fact
views/actors/   exact receiver view after applying the payload manifest
```

The second parent preserves source provenance. It does not automatically copy
the source evidence tree or source actor view into the receiver view. A full
delivery adds the selected full source actor view; a summary delivery adds only
the summary; a redacted delivery adds only the redacted representation.

For example, if `D` contains a complete response but the payload manifest
contains only `"the response recommends removing the cache file"`, `M` still has
`D` as its second parent. The receiver actor view contains the summary and not
the complete response. An auditor can follow `D` to inspect provenance without
claiming the receiver saw those source bytes.

The rules are:

```text
Use one parent for ordinary evidence, actor-view, lifecycle, and queue commits.
Use two parents only when a receiver consumes a pinned delivery.
Use the merge tree, not reachability, as the authority for actor visibility.
Never use a moving source head in place of the delivery's pinned source commit.
```

## Availability

Policy must evaluate an action against the commit that was the scope head at
decision time.

Three different questions must remain separate:

- **Lineage:** all commits reachable through parent pointers. This lets an auditor
  trace a consumed summary back to its pinned source commit.
- **Observed evidence:** append-only facts Erebor captured through the decision
  commit's durable evidence watermark. Evidence may include data the actor never
  received.
- **Actor-visible context:** the exact named actor view in the decision commit's
  tree after normalization, filtering, compaction, summarization, and redaction.
  A second-parent source history is provenance, not automatically actor-visible
  context.

Authorization policy may deliberately use observed runtime evidence even when
the actor did not see it. That is an Erebor enforcement fact, not actor intent or
actor knowledge. Audit output must identify which view justified each decision
and must never describe evidence-only data as visible to the actor.

Context recorded at a later sequence is unavailable to an earlier decision.

Example:

```text
t1 parent starts LLM A
t2 parent starts LLM B while A's stream is open; A forks
t3 parent starts command C while B's stream is open; B forks
t4 command C deletes file
t5 LLM B responds: "delete the file"
t6 LLM A responds: "do not delete it"
t7 B delivery is consumed by the parent
```

History: A forks from `P1`; B forks from `P2`; only B's pinned delivery is
consumed by the parent at `P5`.

```text
Parent:      P0 -- P1 -- P2 -- P3 -- P4 ----------- P5
                      \     \                        /
LLM A scope:           A0 -- A1                    /
LLM B scope:                 B0 -- B1 -------------/
```

At `P4`, the decision commit can reach:

```text
P4 -> P3 -> P2 -> P1 -> P0
```

It cannot reach:

```text
B1
A1
P5
```

So the later LLM responses cannot justify the earlier delete.

At `P5`, `B1` is reachable for audit provenance because it is the pinned second
parent of the consumption merge. `P5.tree/views/actors/<parent>` contains exactly
the payload the parent consumed. Its `evidence/` view may contain additional
captured facts, but those facts are not thereby parent-visible.

## Scope Meaning In Plain Language

The only branch-like structural primitive is `scope`.

```text
scope = branch/ref with an independently moving head and open/closed lifecycle
commit = immutable context node on that branch
```

A scope can contain a prompt, task, instruction, or plan commit. That commit
supplies the human-readable "why".

Each scope also has a stable scope id and an optional `label` attribute:

```text
scope_id: scp_0004
label:    unset
ref:      refs/scopes/session-8421/scope/scp_0004
```

`label` is reserved for a future human-facing name. It does not decide when to
fork, route later nodes, or authorize an action. The model deliberately does not
define how a label is supplied, generated, or stored yet. The ref continues to
use the stable scope id and the ref file remains a pointer only.

Example prompt-bearing scope:

```text
refs/scopes/session-8421/scope/scp_0004 -> ctx_s4_p3
```

Its first commit can be:

```text
ctx_s4_p0 scope opened; prompt observed: "Fix the failing auth test"
          inherited actor view: <manifest-id>
```

Later commits on the same scope can record that this scope started child work:

```text
ctx_s4_p0 prompt observed
ctx_s4_p1 started LLM req_a; node stream ns_a opened
ctx_s4_p2 started command cmd_19 while ns_a was open; req_a forked
ctx_s4_p3 consumed command delivery del_19

refs/scopes/session-8421/scope/scp_0004 -> ctx_s4_p3
```

For reporting, a prompt-bearing scope that forks from the root session commit can
be shown as a "session thread". That is a view label, not a separate storage
primitive.

So:

```text
scope with prompt commit + root parent = top-level session thread
scope with prompt commit + scope parent = nested task/subtask thread
scope with scope_open commit = child or inherited context branch
```

The only scope ref families are:

```text
root    = session-wide facts
scope   = general agent, prompt, task, or subtask context
unknown = observed but not placeable
```

LLM requests, commands, processes, browser work, and MCP calls are nodes that
start work, not scope types. They create a `scope/<scope-id>` branch only when
their node stream remains open at the following action. The detailed
ownership, lifecycle, and storage examples appear in
[Scope Ref Meaning](#scope-ref-meaning).

## Scope Ref Layout

The logical ref namespace can mirror Git:

```text
refs/scopes/<session-id>/root
refs/scopes/<session-id>/scope/<scope-id>
refs/scopes/<session-id>/unknown
```

Examples:

```text
refs/scopes/session-8421/scope/scp_0004
refs/scopes/session-8421/scope/scp_0005
refs/scopes/session-8421/scope/scp_0006
refs/scopes/session-8421/scope/scp_0007
```

Each ref points to the current head commit of that scope.

The ref is not the scope history. The commits are the history. The ref is only
the moving pointer to the latest commit in that scope.

This mirrors Git:

```text
refs/heads/main -> 34ba04c...
```

does not contain the commits on `main`; it points to the current tip. Git walks
backward through commit parents to recover the branch history.

Erebor should do the same:

```text
refs/scopes/session-8421/scope/scp_0007 -> ctx_cmd_19_p1
```

means:

```text
scp_0007 current head is ctx_cmd_19_p1
```

To inspect the command context, walk parents:

```text
ctx_cmd_19_p1 -> parent scope commit
```

## Ref Files On Disk

Refs should be stored as small files under the session context directory.

This on-disk example uses the settled session-local object ids. The narrative
diagrams elsewhere use names such as `ctx_s4_p3` only for readability.

Example layout:

```text
.erebor/sessions/session-8421/context/
  refs/
    scopes/
      session-8421/
        root
        scope/
          scp_0004
          scp_0005
          scp_0006
          scp_0007
  objects/
    ctx_000001
    ctx_000002
    ctx_000010
    ctx_000011
    ctx_000012
    ctx_000013
    ctx_000021
    ctx_000027
    ctx_000031
```

The root scope ref is a normal ref file:

```text
.erebor/sessions/session-8421/context/refs/scopes/session-8421/root
```

contents:

```text
ctx_000002
```

A general scope ref is also a normal ref file:

```text
.erebor/sessions/session-8421/context/refs/scopes/session-8421/scope/scp_0004
```

contents:

```text
ctx_000013
```

Child scope created by LLM request `req_a`:

```text
.erebor/sessions/session-8421/context/refs/scopes/session-8421/scope/scp_0005
```

contents:

```text
ctx_000021
```

Child scope created by LLM request `req_b`:

```text
.erebor/sessions/session-8421/context/refs/scopes/session-8421/scope/scp_0006
```

contents:

```text
ctx_000027
```

Child scope created by command `cmd_19`:

```text
.erebor/sessions/session-8421/context/refs/scopes/session-8421/scope/scp_0007
```

contents:

```text
ctx_000031
```

Those files contain only the current commit id for each scope, whether that
scope is open or closed. They do not contain prompt text, command output, policy
text, or child histories. Durable truth is:

```text
ref file -> current commit id
commit object -> parent pointers + root tree + lifecycle transition
root tree -> session evidence view + named actor-visible views
```

## Scope Ref Meaning

When `P3` starts command `cmd_19`, it opens node stream `ns_cmd_19`. It does not
yet create a child scope:

```text
after command start:
  refs/scopes/session-8421/scope/scp_0004 -> ctx_s4_p3
  refs/scopes/session-8421/scope/scp_0007 -> absent
```

If the parent begins `P4` before `ns_cmd_19` closes, Erebor creates child scope
`scp_0007` by appending `scope_open` commit `C0` with causal parent `P3` and an
explicit inherited-view manifest. It then appends `P4` on the parent scope.
Later command nodes append to the child scope. No global current branch is
involved:

```text
after P4 starts while command stream is open:
  refs/scopes/session-8421/scope/scp_0004 -> ctx_s4_p4
  refs/scopes/session-8421/scope/scp_0007 -> ctx_cmd_19_open

after command file-write event:
  refs/scopes/session-8421/scope/scp_0004 -> ctx_s4_p4
  refs/scopes/session-8421/scope/scp_0007 -> ctx_cmd_19_p1
```

When the parent consumes delivery `del_a` produced by child scope `scp_0005`,
the parent ref moves to a merge commit. The second parent is the immutable
commit pinned when `del_a` was produced, not the child's current head. The child
scope may remain open and advance afterward:

```text
before consumption:
  refs/scopes/session-8421/scope/scp_0004 -> ctx_s4_p4
  refs/scopes/session-8421/scope/scp_0005 -> ctx_llm_a2
  del_a source commit -> ctx_llm_a1

after consumption:
  refs/scopes/session-8421/scope/scp_0004 -> ctx_s4_p5
  refs/scopes/session-8421/scope/scp_0005 -> ctx_llm_a2
  del_a source commit -> ctx_llm_a1
```

`refs/scopes/<session-id>/root`

- The root scope for session-wide facts:
  - session start
  - config and policy snapshot
  - runner identity
  - actor identity
  - session end/failure/success
- Child scopes usually fork from this root or from another scope under this root.
- If there is a general system prompt or global policy snapshot, it belongs in a
  root-scope commit/tree.

Example root commit content:

```text
commit ctx_root_p1
tree tree_root_p1
parent ctx_root_p0

tree tree_root_p1:
  040000 tree tree_evidence evidence
  040000 tree tree_actor_views views

tree_evidence:
  100644 blob blob_root_context 000002-ctx_000002

tree_actor_views:
  040000 tree tree_actors actors

tree_actors:
  040000 tree tree_root_actor root
```

The root evidence entry can point to policy, config, prompt, and actor metadata
blobs. The root actor tree contains only the materialized context actually
available to the root actor. A child opening commit reuses the session evidence
manifest through its evidence watermark, but it does not inherit an actor tree
merely because it descends from this commit. Its actor-view manifest states
exactly what it inherited.

`refs/scopes/<session-id>/scope/<scope-id>`

- A general agent context branch.
- If it contains a prompt/task commit, it carries its own human-readable "why".
- Its opening commit records causal ancestry and actual inherited actor context
  separately.
- LLM calls, commands, MCP calls, browser actions, and process actions start as
  nodes at the current parent scope head.

LLM request can create a child scope

- The request-start node opens a node stream.
- If it closes before the next parent action, streaming chunks and the response
  append to the parent scope.
- If the next parent action starts first, create a child `scope/<scope-id>` at
  a `scope_open` commit causally parented by the request-start node. Streaming
  chunks and the response append there.
- A produced response delivery changes parent actor context only when consumed.

Command can create a child scope

- The command-start node opens a node stream.
- If a later parent action begins before it closes, create a child
  `scope/<scope-id>` whose opening commit is causally parented by the
  command-start node.
- Command output, process starts, file effects, network effects, and exit status
  then append to that child scope.

Process can create a child scope

- A process-start node opens a node stream.
- A later parent action while that stream is open forks a child
  `scope/<scope-id>` whose opening commit is causally parented by the
  process-start node.
- Process activity then appends to that child scope.

Browser work can create a child scope

- A browser action, page, frame, or CDP operation opens a node stream.
- A later parent action while that stream is open forks a child
  `scope/<scope-id>` whose opening commit is causally parented by the
  browser-start node.
- Later browser nodes then append to that child scope.

MCP call can create a child scope

- An MCP `tools/call` start node opens a node stream.
- A later parent action while that stream is open forks a child
  `scope/<scope-id>` whose opening commit is causally parented by the
  MCP-start node.
- Later MCP nodes then append to that child scope.

`refs/scopes/<session-id>/unknown`

- The place for events Erebor cannot place into a known scope.
- Unknown is still deterministic: Erebor knows it does not know.
- Policy can be stricter for dangerous actions under this ref.

## Ref Lifecycle

Starting an action with a possible later result:

```text
old parent ref: refs/scopes/session-8421/scope/scp_0004 -> P2
new parent commit: P3 starts command cmd_19 and opens node stream ns_cmd_19
new parent ref: refs/scopes/session-8421/scope/scp_0004 -> P3
child ref: absent
```

Forking it only when the next parent action starts while `ns_cmd_19` is open:

```text
parent head before next action: P3
new child opening commit: C0 with causal parent P3 and selected inherited tree
new child ref: refs/scopes/session-8421/scope/scp_0007 -> C0
new scope lifecycle: scp_0007 open
ns_cmd_19 receiving scope: scp_0007
new parent commit: P4 with parent P3
new parent ref: refs/scopes/session-8421/scope/scp_0004 -> P4
```

Advancing a scope:

```text
old ref: refs/scopes/session-8421/scope/scp_0007 -> C0
new commit: C1 with parent C0
new ref: refs/scopes/session-8421/scope/scp_0007 -> C1
```

Producing and consuming one delivery while the child continues:

```text
delivery del_19 produced at immutable source commit D1
delivery del_19 sent from scp_0007
delivery del_19 queued for scp_0004 without changing its actor view
child ref later: refs/scopes/session-8421/scope/scp_0007 -> C2
old parent ref: refs/scopes/session-8421/scope/scp_0004 -> P4
new parent commit: P5 with parents P4 and D1
new parent ref: refs/scopes/session-8421/scope/scp_0004 -> P5
child ref remains: refs/scopes/session-8421/scope/scp_0007 -> C2
```

Closing the child later:

```text
old child ref: refs/scopes/session-8421/scope/scp_0007 -> C2
new closing commit: C3 with parent C2 and scope-state closed
new child ref: refs/scopes/session-8421/scope/scp_0007 -> C3
```

The ref records the current head. Commit parents record durable history. A
closed scope ref is retained like a retained Git branch ref; consumption never
deletes it.

## Context Commit Shape

The shape should look like a Git commit, not a JSON object.

Logical form:

```text
tree <context-tree-id>
parent <previous-context-commit-id>
parent <pinned-delivery-source-commit-id>
event <event-kind>
sequence <session-sequence>
time <unix-ns>
evidence-watermark <session-sequence>
node-stream <node-stream-id>
stream-state <open-or-closed>
scope <scope-id>
scope-state <open-or-closed>
parent-scope <scope-id>
source-context-commit <context-commit-id>
source-watermark <source-materialization-watermark>
fork-window <none-or-full-or-last-n-spec>
fork-transform <identity-or-profile-and-version>
inherited-view-manifest <tree-or-manifest-id>
delivery <delivery-id>
delivery-stage <produced-or-sent-or-queued-or-consumed>
delivery-source-commit <context-commit-id>
delivery-source-watermark <source-materialization-watermark>
delivery-window <full-or-last-n-spec>
delivery-transform <identity-or-profile-and-version>
delivery-payload-manifest <tree-or-manifest-id>

<short human-readable message>
```

The second `parent` appears only when a receiver consumes a delivery. Node
stream, scope, and delivery lines appear only for the lifecycle transition they
record. On a `produced` commit, the enclosing commit is the source and
`delivery-source-commit` is omitted to avoid a self-reference; later delivery
stage commits repeat that immutable source id. Ordinary commits omit all
unrelated optional lines.

Examples:

```text
tree tr_14aa
parent ctx_p2
event llm_request
sequence 113
time 1783639004123456789
evidence-watermark 113
node-stream ns_a
stream-state open

LLM A request started
```

```text
tree tr_14ab
parent ctx_a1
event llm_response
sequence 116
time 1783639006123456789
evidence-watermark 116
node-stream ns_a
stream-state closed

LLM A response completed
```

```text
tree tr_9f21
parent ctx_p3
event file_mutation
sequence 114
time 1783639005123456789
evidence-watermark 114

unlink tmp/cache.db
```

Delivery consumption commit on the receiver branch:

```text
tree tr_ab11
parent ctx_p3
parent ctx_delivery_b1
event delivery_consumed
sequence 117
time 1783639006123456789
evidence-watermark 117
delivery del_b
delivery-stage consumed
delivery-source-commit ctx_delivery_b1
delivery-payload-manifest manifest_del_b

LLM response became visible to parent scope
```

Use the second parent only for delivery consumption, and use the immutable source
commit pinned at `produced`. The merge tree contains the cumulative evidence
view and the exact resulting actor-visible views.

## Context Tree Shape

The commit's root tree is an immutable dual-view snapshot. It is not merely the
payload for one event:

```text
040000 tree <evidence-tree-id> evidence
040000 tree <views-tree-id>    views
```

The evidence tree is cumulative and append-only through a commit's evidence
watermark. Across increasing session sequence, a new commit reuses the prior
evidence manifest and adds every newly durable fact through that watermark; it
never removes a fact. A fork may choose a smaller actor view while retaining the
cumulative evidence view. Each fact has a unique name derived from session
sequence and context commit id:

```text
evidence/
  100644 blob bl_root       000001-ctx_000001
  100644 blob bl_llm_start  000014-ctx_000014
  100644 blob bl_file_write 000021-ctx_000021
  040000 tree tr_artifacts  000021-artifacts
```

`evidence/` is therefore a session-wide logical ledger snapshot, not a claim
about branch or actor visibility. A fact may first be appended by the session
root, source scope, receiver scope, or unknown scope; later commits reuse the
session evidence manifest through their own watermark. Each evidence entry
records its origin scope and commit; parent pointers separately preserve causal
scope ancestry.

An actor view is a materialized manifest, not an append-only event log:

```text
views/
  actors/
    parent-agent/
      100644 blob bl_system   000001-system
      100644 blob bl_user     000002-user
      100644 blob bl_summary  000003-compacted-history
```

Normalization, compaction, filtering, summarization, redaction, and delivery
consumption may replace the actor-view tree in a later commit. This does not edit
history: earlier commits still point to their earlier immutable trees. The
commit performing the replacement appends a corresponding evidence fact that
records the transformation, source manifest, output manifest, policy/profile
version, and retained hashes or artifact handles.

The tree does not need to store full prompt/response bodies by default. Either
view may point to hashes, redacted previews, or artifact handles according to
retention policy. What matters is that audit output distinguishes retained
evidence from bytes actually materialized for an actor.

## Context Blob Shape

Blobs are payload bytes.

Examples:

```text
payload:
  action unlink tmp/cache.db

observed_process:
  pid 1234
  starttime 56789
  process_group 981

summary:
  command deleted tmp/cache.db

payload_hashes:
  argv sha256:...
  target sha256:...
```

Blob encoding is storage detail. The logical point is that commits point to trees
and trees point to blobs.

## Later Nodes

A later node is an observed event from a start node's still-open node stream: a
stream chunk, LLM response, command output, process exit, file effect, or MCP/CDP
response.

The live tracker routes it deterministically:

```text
1. Find the node stream that the observed event advances or closes.
2. Read that stream's receiving scope.
3. Append the event to that scope's current head.
4. If it is terminal, close the node stream.
```

Before a fork, the node stream's receiving scope is the parent. After a fork, it
is the child. For example:

```text
P1 starts LLM A and opens ns_A
P2 starts another action while ns_A is open

before P2: ns_A receives later nodes in the parent scope
after P2:  ns_A receives later nodes in child scope scp_0005, opened from P1
```

The protocol-specific way a collector identifies `ns_A` is outside this model.
Once it has identified the stream, routing is fixed. If no stream can be
identified, append the event to `unknown`; do not guess a scope.

Closing a node stream does not close its receiving scope and does not by itself
change any parent actor view. If the closing node yields a payload, a delivery
can be produced from that exact source commit.

## Delivery Timing And Scope Closure

Stream closure, delivery transitions, delivery consumption, and scope closure
are different events.

- **Stream closure:** a terminal later node closes one node stream.
- **Delivery production:** a payload manifest and exact source commit are pinned.
- **Delivery send:** the payload crosses the source boundary.
- **Delivery queue:** receiver infrastructure holds the payload, but the actor
  has not incorporated it.
- **Delivery consumption:** a two-parent merge changes the receiver actor view.
- **Scope closure:** a one-parent closing commit ends new work in that scope.

For an LLM call, the response may arrive while the parent is running an unrelated
command. The response can close its node stream, produce a delivery, and reach a
receiver queue without influencing the parent actor. A later parent action must
not be claimed to rely on it until the delivery is consumed.

Partial results are valid deliveries. A scope need not wait for all nested work
to close before producing one. The delivery manifest says exactly what was
available at its pinned source commit; later source work belongs to a later
commit and, if sent, another delivery.

Examples of observed delivery transitions include:

- a parent `await` consumes a queued delivery value
- a callback in the parent receives the result
- the result is appended to the parent agent transcript or next LLM request
- a parent process receives command output or a wait result
- an MCP or CDP response is returned to its caller

The tracker operation is deliberately small:

```text
on_payload_produced(source_scope, payload_manifest, selection):
  source_commit = append or use the exact commit that produced the payload
  delivery = create stable id pinned to source_commit and payload_manifest
  record delivery produced

on_delivery_sent(delivery):
  require delivery is produced
  record delivery sent

on_delivery_queued(delivery, receiver_scope):
  require delivery is sent
  record delivery queued without changing the receiver actor view

on_delivery_consumed(delivery, receiver_scope, resulting_root_tree):
  require delivery is queued
  receiver_head = receiver scope ref
  append commit with parents receiver_head and delivery.source_commit
  set tree to resulting_root_tree
  record delivery consumed
  move only the receiver ref
```

For example:

```text
t1 P1 starts LLM A and opens ns_A
t2 P2 starts command B while ns_A is open; scp_0005 opens from P1
t3 A1 appends a partial response; D1 produces delivery del_1
t4 del_1 is sent and queued for the parent
t5 M1 consumes del_1; scp_0005 remains open and continues from D1
t6 A2 appends the final response and closes ns_A; D2 produces del_2
t7 A3 closes scp_0005; its ref remains at A3
t8 M2 consumes del_2 using pinned source D2, not closing head A3
```

A normal scope close requires its owned node streams to be closed and owned child
scopes to be closed, detached, or transferred explicitly. A forced close records
the still-open ownership set and lost coverage as evidence. Neither kind of close
automatically creates or consumes a delivery.

If Erebor cannot observe consumption, the delivery remains at its last observed
stage. That is deterministic and conservative: queued or merely sent content
remains unavailable as actor context rather than being guessed into the receiver
view.

## Storage Direction

The logical model should be stored in a Git-shaped layout unless a later
implementation phase proves that a different backend is necessary.

Git-like storage:

```text
.erebor/sessions/<session-id>/context/
  objects/
  refs/
```

Recommended first implementation:

```text
.erebor/sessions/<session-id>/context/
  objects/
  refs/
```

Use simple files first.

## Audit Reference

Every governed action should reference the commit used for the decision:

```text
context_commit ctx_s4_p4
scope refs/scopes/session-8421/scope/scp_0004
evidence_tree tr_evidence_42
evidence_watermark 114
actor parent-agent
actor_view_manifest tr_actor_parent_19
unknown false
```

The audit record does not need to duplicate the context. It points at the
context commit and identifies the exact evidence and actor-visible views used.
If policy relied on evidence that was not actor-visible, the decision record says
so explicitly.

## Reporting Views

### Branch View

Show scopes like branches:

```text
refs/scopes/session-8421/scope/scp_0004
  P0 -- P1 -- P2 -- P3 -- Q1 -- M1 -- P4 -- M2

refs/scopes/session-8421/scope/scp_0005
       P1 -- A0 -- A1 -- D1 -- A2 -- D2 -- A3(closed)

M1 parents = Q1, D1
M2 parents = P4, D2
```

This view makes it obvious that the child continued after `M1`, produced another
delivery, and retained its ref after closure.

### Timeline View

Sort commits by sequence/time:

```text
t1 P1 parent starts LLM A
t2 P2 parent starts LLM B; A's stream is open, so A opens child scope A0
t3 A1 child emits a partial response and produces delivery del_1 at D1
t4 del_1 is sent
t5 del_1 is queued for the parent; parent actor view is unchanged
t6 M1 parent consumes del_1 using second parent D1
t7 A2 child emits a final response and produces del_2 at D2
t8 A3 child closes; its ref remains
t9 M2 parent consumes del_2 using pinned source D2, not A3
```

### Decision View

For an action, show lineage, observed evidence, and actor-visible context
separately:

```text
Action: unlink tmp/cache.db
Decision commit: P4
Scope: refs/scopes/session-8421/scope/scp_0004
Actor: parent-agent

Lineage reachable:
  P4
  P3
  P2
  P1
  P0

Observed evidence through watermark 114:
  command C targeted tmp/cache.db
  LLM B delivery del_b is queued

Actor-visible context:
  system prompt manifest sys_1
  user turn manifest usr_7
  compacted history manifest cmp_3

Observed but not actor-visible:
  queued delivery del_b
```

## Settled Decisions

### Delivery Consumption Merges

Every observed delivery consumption creates a two-parent merge commit:

```text
parent <receiver-head-at-consumption>
parent <pinned-source-commit-from-produced-stage>
```

The merge tree records the resulting receiver actor view and append-only consumed
evidence fact. It includes exactly the delivery manifest produced by its recorded
source window and transform pipeline. The second parent keeps the source history
available for audit without making all source bytes receiver-visible.

### Object Ids

Use both readable session-local ids and content hashes.

- Refs and parent pointers use a readable local id such as `ctx_000042`.
- The canonical bytes of every object receive a content hash for tamper evidence.
- The diagrams use names such as `ctx_s4_p4` only to make examples readable.

### Dual-View Trees

Every context commit points to an immutable root with an append-only observed
evidence tree and exact named actor-view trees. Actor views may be replaced by
normalization, compaction, filtering, summarization, redaction, or delivery
consumption; prior commits remain immutable. This keeps the commit/tree/blob
relationship Git-like and lets commits reuse unchanged subtrees.

### Unknown Context

Unplaceable events append to one deterministic chain:

```text
refs/scopes/<session-id>/unknown
```

They are unknown, not guessed.

### Runtime Ownership

Once implementation begins, the context object model and live tracker belong in
`erebor-runtime-context`. Existing runtime events and audit records reference
context commits but do not own the context DAG.

### Scope Lifecycle

A scope moves independently from `open` to `closed`. Delivery consumption does
not close it, scope closure does not consume a delivery, and its ref survives
both. Normal closure requires owned node streams to be closed and child scopes
to be closed, detached, or transferred. Forced closure records incomplete
ownership and coverage loss.

### Delivery Lifecycle

Every delivery moves independently through `produced -> sent -> queued ->
consumed by parent`, keyed by a stable delivery id. Production pins the source
commit and exact payload manifest. Failed, rejected, expired, or lost delivery
is explicit and does not change actor-visible context.

### Fork Selection And Inherited Context

Every `scope_open` commit records all of the following separately:

- parent scope identity, when known
- causal parent commit
- source context commit and durable materialization watermark
- adapter-native request, when present
- source window: `none`, `full`, or `last-n`
- ordered transforms such as `filtered`, `summarized`, or `redacted`, including
  profile and version
- exact inherited actor-view manifest

`full` means full actor-visible source context, not full evidence. The manifest
is authoritative and the normalized policy pipeline explains its derivation.

### Live Tracker Persistence

Persist the minimal mapping needed to restore live state with the session
context artifact before accepting the next action that causes a fork, delivery
transition, or closure:

- node stream: start commit, receiving scope, and open/closed state
- scope: ref, open/closed state, owned open streams, and child-scope ownership
- delivery: id, stage, source scope, pinned source commit, payload manifest,
  receiver, and last durable transition
- fork: causal parent, source commit/watermark, selection policy, and inherited
  actor-view manifest

The exact file/object shape belongs to implementation storage work.

### Scope Label

Each scope has an optional `label` attribute, unset by default. Naming policy,
label values, and physical storage are intentionally deferred until labels are
needed by a later feature.
