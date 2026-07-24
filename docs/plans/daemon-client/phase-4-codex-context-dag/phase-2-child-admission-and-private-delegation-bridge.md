# Phase 2: Child Admission And Guarded Delegation Bridge

Status: Done. Depends on completed nested Phase 1.

## Purpose

Create one explicit, policy-governed path from an authenticated parent Codex
spawn intent to a separately admitted child session, and define the complete
Codex collaboration surface that may cross that bridge. Preserve the rule that
a raw nested executable is never a trusted child agent.

## Scope

- Reuse the existing daemon-internal `SessionAdmission` and `SessionSpec`
  construction for a physical child. The authenticated hook lease retains the
  checked parent `ContextPin`, declared child profile, and frozen-context mode;
  the daemon resolves package, installation, adapter, policy, runner, and
  command through the existing admission path. It never accepts raw argv, a
  path, an alias minted by the child, a caller UID, or a client-provided parent
  ID. Do not add a second generic child-admission model.
- Use the existing runtime-guard socket and its `ProcessExec` lifecycle event
  as the sole pre-spawn trigger. The guard reports kernel-observed UID, PID,
  parent PID, executable, argv, and execution chain, then waits for its normal
  hold/release/deny reply. No workload opens a second daemon socket, sends a
  child-admission message, receives a ticket, or obtains daemon-control
  authority. The daemon matches the event to one armed lease and performs the
  semantic admission itself.
- Establish the source boundary before implementing a physical Codex child.
  The reviewed stock Codex `spawn_agent` creates an internal thread before its
  `SubagentStart` hook, and that hook cannot stop it. Its App Server
  `collabToolCall` is also post-operation. The `codex-v1` adapter therefore
  maps those facts only to a `native-logical` edge; neither can enter generic
  child admission or repair an ungoverned child after the fact.
- Require a pinned, audited pre-spawn delegation bridge for a
  `daemon-physical` Codex child. The exact package-declared bridge execution,
  following an authenticated delegation lease, is the request. The daemon
  creates the child before it releases that execution. The bridge may be a
  source-integrated Codex extension or a package-declared Erebor delegation
  tool, but it cannot be a shell wrapper, hook output, App Server notification,
  environment convention, or unauthenticated PID observation. Until such a
  bridge is approved, physical child admission is unavailable for real Codex.
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
- Stop at physical child admission. Phase 3 owns directional collaboration
  routes, child delivery blobs, parent receives/rejections, follow-up turns,
  cancellation, and command-output delivery/receive. Phase 2 must not invent a
  child-control RPC or a second transport merely to expose those later actions.
- Enforce the checked causal-depth limit at fork time. Root-owned fan-out, live
  descendant, delivery, follow-up, deadline, and output/context-byte limits
  belong with their Phase 3 durable delivery/control owners; do not hard-code a
  second limits registry here.

## Required Negative Cases

- Direct shell `exec` of the fixture or a copied child command is only a
  guarded descendant and creates no child session/ref.
- A stale, replayed, cross-session, cross-UID, wrong-package, or wrong-parent
  bridge execution is denied before launch.
- A bridge execution without the exact parent lease, after lease closure, or above a
  configured depth/fan-out limit is denied.
- A child cannot use inherited hook variables, daemon socket names, or a parent
  context pin to impersonate its parent or sibling.
- A `thread/fork` request, a `parentThreadId` claim, an App Server resume, or a
  direct `send_message` to a sibling/ancestor cannot create an Erebor edge,
  session, message route, or merge.
- A stock `SubagentStart` hook or post-operation `collabToolCall` cannot claim
  a daemon-physical child, child guard, or per-child
  physical-effect pin.
- A command terminal event, output delta, PID, or copied process capability
  cannot receive a result, update an owner context scope, or deliver command
  output to a parent/sibling. Only the exact owning node and current daemon
  operation registration may poll or provide input.

## Checkpoint

The deterministic fixture's approved delegation bridge execution can admit
child B from parent P through the existing guard lifecycle socket. The daemon
creates B only after the checked causal fork and records separate parent/child
session, hook, and guard identities. The same runtime-guard connection carries
the ordinary `ProcessExec` and lifecycle events; no child-admission request or
delegation socket exists. A stock-Codex fixture proves the distinct
`native-logical` observer path. Phase 3 adds the queued-message, follow-up, and
descendant-cancellation routes.

## Acceptance

One parent may continue while an independently governed physical child runs,
or while an observed native logical child runs within the outer invocation. The
physical child has no more authority than the explicitly admitted child contract
grants; the native logical child is never over-claimed as isolated; raw nested
Codex remains untrusted.

## Current Implementation Result (2026-07-24)

Status: Done. The implementation and its required privileged end-to-end matrix
pass.

Implemented so far:

- `CodexPackageDefinition` can declare one root-owned projected bridge and one
  bounded child profile. The profile pins the entrypoint and only admits the
  declared frozen-context modes; it accepts no child argv, path, policy,
  workspace, environment, credential, or daemon endpoint.
- An authenticated `PreToolUse` lease retains the exact `ContextPin`, declared
  profile, and frozen-context selection. The existing process guard must then
  observe the exact projected bridge executable and its one-element argv. A
  copied executable, raw argv, stale lease, wrong parent runtime, or unbound
  process is denied.
- The existing guard lifecycle route invokes the daemon's ordinary session
  admission owner in process. That owner revalidates the parent package and
  installation, forks the child scope from the checked pin, creates the child
  session, and starts it with its own guard and hook registration. It does not
  accept a workload request, client UID, parent ID, alias, or command.
- The deterministic fixture declares and executes the bridge; crate-local
  tests prove guard-bound admission facts and malformed bridge argv rejection.
  Its package profile and typed `fixture/delegate` input now accept exactly
  `none`, `all`, or `last_turns` from one through eight; malformed selections
  fail before any hook or bridge execution.
- The App Server boundary permits `thread/start` as a new same-session scope
  key, as Phase 1 requires. It rejects every other `thread/*` peer/history
  operation and recursive `parentThreadId`, `forkedFromId`, or
  `ancestorThreadId` claims before forwarding, binding a prompt, or creating a
  session edge.
- The delegation lease now derives a new immutable `ContextPin` containing
  exactly the selected `agents/codex/app-server/prompts/*` blobs at the
  authenticated causal commit. It excludes hook and DAG audit blobs. Ordinary
  daemon admission forks child B from a tree made from only those checked
  blobs.
- The existing authenticated hook broker is the model-visible delivery
  boundary. On B's `SessionStart`, its normal `HookResult` carries
  `hookSpecificOutput.hookEventName = "SessionStart"` and
  `hookSpecificOutput.additionalContext`. The latter is a checked JSON
  rendering of only the selected prompt requests. It is not a filesystem
  projection, argv/environment injection, caller state, or a second socket.
- The deterministic fixture forwards its actual hook result. Its child TTY
  prints `fixture-frozen-context=...` only for a non-empty projection. The
  privileged script binds `fixture-thread` through `turn/start`, exercises
  `none`, `all`, and `last_turns`, then checks the independently running child
  output.
- The existing privileged Linux/systemd probe now exercises all three fixture
  selections. For each it requires the bridge response and exactly two retained
  sessions, including separately running child B, before it removes those
  container-local test sessions. The probe is invoked by the existing ignored
  Rust `daemon_control_plane` test; it is not a new workload socket or a
  shell-based admission path.

The source-backed, model-visible projection is now complete through Codex's
existing `SessionStart` hook result. No new delegation request, socket, or
workload-to-daemon transport was added.

The Phase 3 delivery/control work remains intentionally deferred. It is not a
Phase 2 completion condition and must not be introduced through another
transport here.

Verification for the current implementation:

- `rtk cargo test -p erebor-runtime-session
  agents::codex::leases::tests::delegated_child_admission_uses_only_the_guard_bound_lease
  -- --exact` passed.
- `rtk cargo test -p erebor-runtime-e2e --test codex_v1_fixture` passed.
- `rtk cargo test -p erebor-runtime-session
  agents::codex::app_server::tests::peer_thread_operations_and_claims_are_denied_without_forwarding
  -- --exact` passed.
- `rtk cargo test -p erebor-runtime-session
  agents::codex::app_server::tests::new_app_server_thread_remains_a_same_session_scope_key
  -- --exact` passed.
- `rtk bash -n .github/scripts/daemon-codex-runtime.sh` passed.
- Focused tests for exact prompt selection/rendering, broker `SessionStart`
  result shape, selected child fork contents, and guard-bound admission passed.
- `rtk cargo test -p erebor-runtime-session --lib` passed outside the
  restricted sandbox: 132 tests.
- `rtk cargo test -p erebor-runtime-daemon --lib` passed outside the restricted
  sandbox: 37 tests, 5 ignored.
- `rtk cargo test -p erebor-runtime-e2e --test codex_v1_fixture` passed:
  3 tests.
- `rtk cargo clippy --workspace --all-targets --all-features -- -D warnings`
  passed.
- `rtk bash -n .github/scripts/daemon-codex-runtime.sh` and
  `rtk bash -n .github/scripts/daemon-systemd-control-plane.sh` passed.
- The rebuilt current-image privileged
  `codex_daemon_client_runs_in_systemd_container` test passed. It runs the
  installed-session baseline and then exercises `none`, `all`, and
  `last_turns` child projections through the daemon-owned bridge.
- The privileged repair keeps a bind-held copy of every admitted filesystem
  projection before the controller hides the host runtime. It then projects
  only those held objects into the private runtime. This preserves the exact
  root-owned managed hook while preventing the workload from resolving the
  host staging path after `/run/erebor` is replaced.
- The private runtime is `nosuid,nodev`, not `noexec`: an exact, read-only,
  root-owned hook projection is an admitted executable and must be runnable by
  the guarded workload. No caller-provided executable gains that exception.
- The Linux/container harness supplies explicit non-zero PTY geometry and
  waits for a new daemon main PID, socket, and successful control request after
  its intentional daemon-loss check. Those make the existing installed-session
  baseline deterministic before the Codex probe begins.

## Stop Point

Phase 2 is complete. Phase 3 remains out of scope.
