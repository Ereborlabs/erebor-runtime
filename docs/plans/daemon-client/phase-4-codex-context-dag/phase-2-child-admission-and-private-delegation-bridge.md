# Phase 2: Child Admission And Private Delegation Bridge

Status: Proposed. Depends on nested Phase 1 and explicit approval.

## Purpose

Create one explicit, policy-governed path from an authenticated parent Codex
spawn intent to a separately admitted child session, and define the complete
Codex collaboration surface that may cross that bridge. Preserve the rule that
a raw nested executable is never a trusted child agent.

## Scope

- Reuse the existing daemon-internal `SessionAdmission` and `SessionSpec`
  construction for a physical child. The private request supplies only the
  checked parent `ContextPin`, declared child profile, and frozen-context mode;
  the daemon resolves package, installation, adapter, policy, runner, and
  command through the existing admission path. It never accepts raw argv, a
  path, an alias minted by the child, a caller UID, or a client-provided parent
  ID. Do not add a second generic child-admission model.
- Add a distinct private child-delegation endpoint. It is neither the daemon
  control socket, the Codex hook service, the runtime guard, nor generic
  terminal/App Server input. It authenticates the exact parent session,
  currently permitted parent invocation, private peer, one-use request, and
  bounded spawn intent. It extends the existing authenticated service/ticket
  machinery only where its binding is sufficient; it does not introduce a
  parallel registry or bearer-identity scheme.
- Establish the source boundary before implementing a physical Codex child.
  The reviewed stock Codex `spawn_agent` creates an internal thread before its
  `SubagentStart` hook, and that hook cannot stop it. Its App Server
  `collabToolCall` is also post-operation. The `codex-v1` adapter therefore
  maps those facts only to a `native-logical` edge; neither can enter generic
  child admission or repair an ungoverned child after the fact.
- Require a pinned, audited pre-spawn delegation bridge for a
  `daemon-physical` Codex child. The bridge must present the private one-use
  request before it starts a workload and must receive the daemon-created child
  identity before it creates the source child. It may be a source-integrated
  Codex extension or a package-declared Erebor delegation tool, but it cannot
  be a shell wrapper, hook output, App Server notification, environment
  convention, or PID observation. Until such a bridge is approved, physical
  child admission is unavailable for real Codex.
- Build and test a version-pinned adapter capability matrix rather than
  guessing from process output. The matrix distinguishes `spawn_agent`, the
  three `fork_turns` forms, `list_agents`, queued `send_message`, waking
  `followup_task`, `interrupt_agent`, automatic completion, and App Server
  peer-thread lifecycle. It separately identifies the older `send_input`,
  `resume_agent`, `wait`, and `close_agent` family. Every non-listed source
  operation, multi-recipient route, or opaque encrypted delivery fails closed.
- Treat Codex App Server `thread/fork`, `thread/resume`, historical-thread
  paths, and arbitrary thread metadata as peer-thread operations, not child
  delegation. The governed Phase 4 App Server bridge rejects those operations
  until a separately approved daemon-owned peer-thread plan exists. A native
  `parentThreadId` or `forkedFromId` is adapter observation only and cannot
  create or repair an Erebor parent edge.
- Admit the child through the ordinary daemon session path with a new session
  ID, package/installation/policy/runner identities, process guard, private
  hook registration, App Server registration where declared, and the optional
  existing parent `ContextPin` from Phase 1. The child reuses the root session's
  context repository; it does not receive a second store.
- Give the child a frozen, bounded spawn-context projection selected from the
  parent pin. Support explicit `none`, `all`, and bounded-last-turns modes only
  when the selected Codex profile exposes equivalent source facts. No live
  parent transcript, mutable state, credentials, daemon socket, or ambient
  environment is inherited.
- Map source options to a declared child class, never to unrestricted child
  configuration. A profile may permit named role/model/effort/service-class
  choices and frozen-context mode; it pins package entrypoint, policy,
  workspace, environment projection, execution policy, and resource limits.
  Child-provided argv, paths, socket paths, `HOME`, `CODEX_HOME`, arbitrary
  environment, model provider, or policy overrides are rejected.
- Provide daemon-mediated collaboration control with directional authority:
  the parent can list its root-scope subtree, queue a message to a direct child,
  request an allowed child follow-up turn, and cancel a descendant. A child
  can publish a message or terminal result to its direct parent. A child may
  request its own child only through the same admission path. Child-to-ancestor,
  child-to-sibling, sibling-to-sibling, and child-to-root control routes are
  rejected in this first contract; the common parent is the deliberate relay.
- Map source command lifecycle separately from collaboration. A Codex command
  launch creates an operation child scope from the owner/launch pin and binds a
  process capability. Source output deltas and terminal notifications are
  evidence; the daemon coalesces them into a policy-bounded, monotonic sequence
  of delivery blobs in the operation scope rather than one blob per raw client
  delta. A later source poll that selects output asks the owner to receive one
  exact delivery through the ordinary two-parent merge. An input-only
  `write_stdin` records process input without a merge. Only a receive makes the
  selected result model-visible in the owner's context. App Server output
  notifications never impersonate that receive.
- Enforce root-owned limits for depth, children per parent, live descendants,
  queued deliveries, follow-up turns, package/entrypoint allowlists, deadlines,
  and output/context bytes.

## Required Negative Cases

- Direct shell `exec` of the fixture or a copied child command is only a
  guarded descendant and creates no child session/ref.
- A stale, replayed, cross-session, cross-UID, wrong-peer, wrong-package, or
  wrong-parent delegation request is denied before launch.
- A request without the exact parent lease, after lease closure, or above a
  configured depth/fan-out limit is denied.
- A child cannot use inherited hook variables, tickets, socket names, or a
  parent context pin to impersonate its parent or sibling.
- A `thread/fork` request, a `parentThreadId` claim, an App Server resume, or a
  direct `send_message` to a sibling/ancestor cannot create an Erebor edge,
  session, message route, or merge.
- A stock `SubagentStart` hook or post-operation `collabToolCall` cannot claim
  a daemon-physical child, child guard, child socket/ticket, or per-child
  physical-effect pin.
- A command terminal event, output delta, PID, or copied process capability
  cannot receive a result, update an owner context scope, or deliver command
  output to a parent/sibling. Only the exact owning node and current daemon
  operation registration may poll or provide input.

## Checkpoint

The deterministic fixture's approved delegation bridge can request child B
from parent P through the private endpoint. The daemon creates B only after the
checked causal fork and records separate parent/child session, hook, and guard
identities. A stock-Codex fixture proves the distinct `native-logical` observer
path. P can issue one queued message, one follow-up, and one descendant
cancellation through typed daemon routes; B cannot reach the parent control or
daemon-control endpoint.

## Acceptance

One parent may continue while an independently governed physical child runs,
or while an observed native logical child runs within the outer invocation. The
physical child has no more authority than the explicitly admitted child contract
grants; the native logical child is never over-claimed as isolated; raw nested
Codex remains untrusted.

## Stop Point

Stop after the Phase 2 result and verification. Wait for approval before Phase
3.
