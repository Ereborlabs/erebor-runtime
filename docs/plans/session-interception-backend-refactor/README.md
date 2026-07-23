# Session Interception Backend Refactor Plan

Status: planning document. Phase 1 inventory and compatibility contract is
complete; implementation phases are not started.

Plan type: architecture, refactoring, implementation, and validation plan.

Related plans:

- [`docs/plans/session-hypervisor/README.md`](../session-hypervisor/README.md)
- [`docs/plans/process-interception-control-channel/README.md`](../process-interception-control-channel/README.md)
- [`docs/governed-browser-and-terminal-plan.md`](../../governed-browser-and-terminal-plan.md)
- [`docs/plans/erebor-agent-task-boundary-guard/README.md`](../erebor-agent-task-boundary-guard/README.md)

## Summary

Refactor interception so the low-level backend belongs to the governed session,
not to the terminal surface.

Today the Linux ptrace guard is wired as `surfaces.terminal.process_guard`.
That was enough for process execution governance, but it is the wrong long-term
boundary. The same backend can observe more than terminal commands. On Linux,
ptrace can observe `execve`, `openat`, `unlink`, `rename`, socket syscalls, and
other substrate effects. Those effects should be routed to the surface that owns
their semantics:

```text
session interception backend
  execve/execveat      -> terminal/process surface
  open/openat/read     -> filesystem surface
  write/unlink/rename  -> filesystem surface
  connect/sendto       -> network or endpoint surface
```

The backend should answer "what substrate operation happened, from which
session process?" The surface should answer "what does this mean, which policy
applies, how is it audited, and can it be mediated or reverted?"

## Current Coupling

The current implementation couples the Linux interception backend to terminal
semantics in several places:

- `surfaces.terminal.process_guard` selects and enables the Linux ptrace guard.
- `erebor-runtime-terminal` compiles process guard rules from terminal policy.
- `erebor-runtime-session` prepares the Linux process guard only while handling
  `SessionSurfaceDefinition::Terminal`.
- Linux-host adoption requires `surfaces.terminal.process_guard.enabled=true`.
- The guard writes audit records with `surface="terminal"` and
  `action="process_exec"`.
- The IPC and mediation path are named around process interception, even though
  the broker and surface mediation registry are already closer to a generic
  routing model.

This makes future filesystem, endpoint, and network enforcement look like
terminal subfeatures even when the terminal is only attribution context.

## Target Model

Introduce a session-owned interception layer:

```text
Session runner
  owns process membership, cgroup/container/adoption state, and backend launch

Session interception backend
  observes OS/session operations
  resolves operation -> session/process identity
  emits low-level interception events
  applies fast fail-closed decisions when needed

Interception router
  maps operation families to surfaces
  preserves pid/action attribution
  calls the owning surface policy path

Governed surfaces
  terminal/process: process execution, shell UX, command attribution
  filesystem: file reads, writes, deletes, metadata, revert layers
  network/endpoint: socket connects, raw CDP bypass, egress
  browser_cdp/MCP/SaaS/etc: mediated replacement authority where relevant
```

The first backend can remain the existing Linux ptrace guard. The refactor is
about ownership and routing first, not changing every enforcement primitive at
once.

## Terminology

- Interception backend: an OS or runner-specific mechanism that observes or
  authorizes substrate operations for a governed session. Examples: Linux
  ptrace, fanotify, BPF LSM, macOS Endpoint Security, Windows minifilter, or a
  container/overlay runner hook.
- Intercepted operation: a low-level operation such as `process_exec`,
  `file_open`, `file_write`, `file_delete`, `file_rename`, `metadata_change`,
  or `socket_connect`.
- Interception router: session-owned routing that maps intercepted operations
  to the governed surface that owns the semantic decision.
- Surface handler: surface-owned policy, enrichment, mediation, audit, and
  later revert logic for one operation family.
- Attribution context: session, actor, pid, parent pid, process tree, cwd,
  terminal action id, command, argv, and any task-contract metadata needed to
  explain why an operation happened.

## Design Principles

- Backend ownership belongs to the session hypervisor path because enforcement
  depends on session membership, runner capabilities, and OS support.
- Surface ownership belongs to the semantic effect. Terminal owns commands.
  Filesystem owns file authority. Network owns sockets and endpoint bypass.
- The same low-level backend may feed multiple surfaces.
- The active capability report must say which operation families the backend
  can enforce, observe, or cannot see.
- Existing terminal/process behavior must continue working while the ownership
  moves.
- Do not route every syscall through policy. Normalize only policy-relevant
  operation families and keep fast local allow paths for low-risk operations.

## Proposed Config Shape

Add a session-level interception config while preserving compatibility aliases
from the existing terminal config during migration:

```json
{
  "session": {
    "interception": {
      "enabled": true,
      "backend": "linux_ptrace",
      "operations": ["process_exec", "file_open", "file_mutation"]
    }
  },
  "surfaces": {
    "terminal": { "enabled": true },
    "filesystem": { "enabled": true }
  }
}
```

Compatibility requirement:

- Existing configs using `surfaces.terminal.process_guard.enabled=true` should
  continue to enable the Linux ptrace backend for `process_exec` during the
  migration.
- New config should prefer `session.interception`.
- Terminal process mediation config can remain surface-specific because browser
  launch mediation is process-exec semantics, not generic backend ownership.

## Event And Routing Shape

The backend should emit a low-level intercepted operation before the router
creates or enriches a `RuntimeEvent`.

Suggested internal shape:

```rust
pub enum InterceptedOperationKind {
    ProcessExec,
    FileOpen,
    FileRead,
    FileWrite,
    FileDelete,
    FileRename,
    MetadataChange,
    SocketConnect,
    Unknown,
}

pub struct InterceptedOperation {
    pub kind: InterceptedOperationKind,
    pub session_id: SessionId,
    pub actor_id: String,
    pub pid: u32,
    pub ppid: Option<u32>,
    pub cwd: Option<PathBuf>,
    pub process: ProcessRef,
    pub target: InterceptionTarget,
    pub raw: serde_json::Value,
}
```

Routing examples:

```text
ProcessExec   -> surface=terminal, action=process_exec
FileOpen read -> surface=filesystem, action=file_read
FileOpen write/create/truncate -> surface=filesystem, action=file_write
FileDelete    -> surface=filesystem, action=file_write or file_delete
SocketConnect -> surface=network or endpoint, action=network_request
```

The public event model may need a dedicated `ExecutionSurface::Filesystem` and
more precise file action kinds before the filesystem surface ships. That should
be done in the filesystem surface plan, not hidden inside terminal.

## Phases

### Phase 1 - Inventory And Compatibility Contract

State: Done.

Deliverables:

- Inventory all terminal/process guard names, config fields, audit payloads,
  IPC messages, environment variables, tests, and docs that imply the backend
  belongs to terminal.
- Define which names remain as compatibility aliases and which new names become
  canonical.
- Document the migration rule for existing configs.

Acceptance:

- The plan lists every compatibility behavior that must remain green.
- No existing terminal/process policy behavior is intentionally broken.

### Phase 1 Result - Inventory And Compatibility Contract

Phase 1 is complete as a planning/inventory phase. It does not move code. It
records the existing terminal/process coupling and establishes the migration
contract later phases must preserve.

#### Inventory: Config And Public Runtime Shape

Existing terminal-owned config that currently enables the interception backend:

- `surfaces.terminal.enabled`
- `surfaces.terminal.tty`
- `surfaces.terminal.policies`
- `surfaces.terminal.process_guard.enabled`
- `surfaces.terminal.process_guard.backend`
- `TerminalSurfaceLayerConfig`
- `TerminalProcessGuardLayerConfig`
- `TerminalProcessGuardBackend::LinuxPtrace`
- `TerminalSurfaceConfig::process_guard()`
- `TerminalProcessGuardConfig`

Existing process mediation config that should remain surface-specific:

- `surfaces.terminal.process_mediation`
- aliases: `process_interception`, `browser_launch_mediation`
- `TerminalProcessMediationLayerConfig`
- `TerminalProcessMediationMode::Shim`
- `ProcessMediationHandlerLayerConfig`
- `ProcessInterceptionDecision`
- type aliases:
  - `TerminalProcessInterceptionConfig`
  - `TerminalProcessInterceptionLayerConfig`
  - `TerminalProcessInterceptionMode`
  - `ProcessInterceptionHandlerConfig`
  - `ProcessInterceptionHandlerKind`

Current behavior that implies terminal ownership:

- Runtime validation requires terminal to be enabled before process mediation
  can be enabled.
- Runtime validation requires
  `surfaces.terminal.process_guard.enabled=true` before process mediation can
  be enabled.
- Linux-host adoption currently requires
  `surfaces.terminal.process_guard.enabled=true`.
- `SessionSurfaceDefinition::Terminal` is the branch that prepares the Linux
  process guard and injects guard environment.
- `erebor-runtime-terminal` compiles policy rules for the guard from terminal
  process-exec policy rules.

#### Inventory: Policy Shape

Existing terminal process policy shape:

```json
{
  "match": {
    "surface": "terminal",
    "action": "process_exec",
    "command_contains": "remote-debugging-port"
  },
  "decision": "deny"
}
```

Compatibility rule:

- Existing `surface=terminal` and `action=process_exec` policy rules must keep
  working.
- `command_contains` remains the preferred terminal/process matcher for
  process-exec rules.
- `payload_contains` remains a compatibility fallback.
- The refactor must not require users to rename existing process-exec policies
  while process execution remains a terminal/process surface event.

Canonical direction:

- Backend config becomes session-owned.
- Process-exec policy remains terminal/process-owned because process execution
  semantics belong to the terminal/process surface.
- Future file policies should target a filesystem surface, not terminal, even
  when the Linux backend that observes them is the same ptrace guard.

#### Inventory: Guard Environment Variables

Existing environment variables injected into guarded sessions or consumed by
the Linux guard:

- `EREBOR_SESSION_ID`
- `EREBOR_ACTOR_ID`
- `EREBOR_SESSION_RUNNER`
- `EREBOR_TERMINAL_SURFACE`
- `EREBOR_TERMINAL_TTY`
- `EREBOR_TERMINAL_PROCESS_GUARD`
- `EREBOR_PROCESS_GUARD`
- `EREBOR_GUARD_RULES`
- `EREBOR_GUARD_DENY_RULES`
- `EREBOR_GUARD_AUDIT_JSONL`
- `EREBOR_GUARD_AUDIT_TERMINAL_LEVEL`
- `EREBOR_GUARD_AUDIT_TERMINAL_DEBUG_COMMANDS`
- `EREBOR_GUARD_CGROUP_DIR`
- `EREBOR_GUARD_ADOPT_PID`
- `EREBOR_SESSION_CONTROL_PROTOCOL`
- `EREBOR_SESSION_CONTROL_TRANSPORT`
- `EREBOR_SESSION_CONTROL_PATH`
- `EREBOR_SESSION_CONTROL_TOKEN`
- `EREBOR_SESSION_CONTROL_TIMEOUT_MS`
- `EREBOR_PROCESS_INTERCEPTION`
- `EREBOR_PROCESS_INTERCEPTION_HANDLERS`
- `EREBOR_PROCESS_INTERCEPTION_SHIM_DIR`

Compatibility rule:

- Existing environment variable names must continue to work for the Linux
  process-exec path during migration.
- New generic names may be added in later phases, but they must be introduced
  alongside the old names until all guard code, examples, and tests have moved.
- `EREBOR_GUARD_AUDIT_TERMINAL_LEVEL` and
  `EREBOR_GUARD_AUDIT_TERMINAL_DEBUG_COMMANDS` remain terminal/process audit
  controls for process-exec records; do not reuse those names for filesystem
  audit filtering.

Canonical direction:

- Backend lifecycle variables should eventually use session/interception
  naming.
- Surface-specific variables should remain surface-specific. For example, TTY
  and terminal audit verbosity remain terminal concepts.

#### Inventory: IPC And Control Broker Names

Current IPC v1 message vocabulary:

- `Envelope`
- `GuardHello`
- `GuardHelloAck`
- `InterceptionRequest`
- `InterceptionDecision`
- `GuardEvent`
- `GuardGoodbye`
- `InterceptionSource`
- `DecisionKind`

Current `InterceptionRequest` fields are process-exec-oriented:

- `pid`, `ppid`
- `executable`
- `argv`
- `cwd`
- `selected_env`
- `requested_endpoint`
- `matched_handler_id`

Compatibility rule:

- IPC v1 names may remain for process-exec mediation. They are already generic
  enough at the envelope level.
- Later phases must not force file or network operations into
  `executable`/`argv` fields.
- If IPC v1 is extended in place, new operation-family fields must be optional
  and backward compatible.
- If a clean payload is easier, use a new message kind rather than changing the
  frame header.

Canonical direction:

- `GuardHello` and `InterceptionDecision` can stay generic.
- `InterceptionRequest` should either grow an operation-family envelope or be
  joined by operation-specific request payloads.
- The broker should route by operation family and surface owner, not by
  terminal/process assumptions.

#### Inventory: Audit Payloads And Session Review Labels

Current Linux process-exec audit shape:

- `surface="terminal"`
- `action="process_exec"`
- `payload.kind="agent_process_exec_attempt"` for direct process attempts
- `payload.kind="process_interception"` for shim/broker mediation
- `payload.terminal.surface="terminal"`
- `payload.terminal.tty=<bool>`
- `payload.terminal.interception_path="linux_ptrace"`
- `payload.working_directory`
- `payload.parent_process="linux-process-guard"`
- `payload.argv_summary`
- `payload.command`

Current session review backend labels:

- `linux_ptrace_process_guard`
- `terminal_process_guard`

Compatibility rule:

- Existing process-exec audit records must stay readable by session review.
- Existing historical audit records must keep describing process execution as
  terminal/process events.
- Process-exec final-effect wording such as
  `exec_denied_before_child_gained_authority` must keep working.
- New filesystem records must not be disguised as terminal/process records just
  to reuse current audit code.

Canonical direction:

- `linux_ptrace_process_guard` may remain a compatibility backend label for
  existing process-exec evidence.
- New capability/audit metadata should describe a session interception backend
  and the routed surface separately.
- Filesystem records should use a filesystem surface once that surface exists.

#### Inventory: Tests That Must Stay Green

Known test areas that exercise the current coupling:

- `erebor-runtime-terminal` terminal policy compilation tests.
- Core config tests for `terminal.process_guard`.
- Core config tests for `process_interception` /
  `process_mediation` aliases.
- Core command-plan tests that wrap Linux host commands with the process guard.
- `erebor-runtime-session` Linux process guard unit wrapper tests.
- Linux host runner tests for process guard launch/adoption.
- Session review tests that infer `linux_ptrace_process_guard` and
  `terminal_process_guard`.
- IPC contract tests that assert `InterceptionRequest` exists.
- Managed browser process mediation tests.

Compatibility rule:

- Phase 2 and later must keep these tests green or deliberately update them
  with an explicit compatibility assertion.
- Where tests are renamed to new canonical terms, add at least one old-config
  compatibility test.

#### Inventory: Docs And Examples That Must Be Updated Later

Docs and examples currently using terminal/process guard language:

- `docs/plans/session-hypervisor/README.md`
- `docs/governed-browser-and-terminal-plan.md`
- `docs/plans/process-interception-control-channel/README.md`
- `docs/plans/governed-openclaw-pilot/README.md`
- `docs/plans/agentic-incident-demo/README.md`
- `docs/plans/session-review-and-llm-governance/README.md`
- `examples/governed-openclaw-pilot/*`

Compatibility rule:

- Do not mass-rename docs before code supports the new shape.
- When Phase 6 updates docs, preserve a clear compatibility note for
  `surfaces.terminal.process_guard`.

#### Migration Rule

The migration must be additive before it is replacing:

1. Add `session.interception` as the canonical backend config.
2. Keep `surfaces.terminal.process_guard` as a compatibility input for
   process-exec interception.
3. Derive the same Linux ptrace process-exec backend launch plan from either
   the old or new config.
4. Keep process mediation under the terminal/process surface unless a later
   plan creates non-process mediation semantics.
5. Keep process-exec audit as terminal/process audit.
6. Add filesystem and network routing only after the router can preserve
   session, pid, process, cwd, and initiating terminal action attribution.
7. Only deprecate old names after docs, examples, tests, and migration warnings
   exist.

#### Canonical Names For Later Phases

Preferred new concepts:

- `SessionInterceptionConfig`
- `SessionInterceptionBackend`
- `SessionInterceptionBackendKind::LinuxPtrace`
- `SessionInterceptionOperation`
- `SessionInterceptionOperationKind`
- `SessionInterceptionRouter`
- `SessionInterceptionCapabilityReport`

Names that remain compatibility or surface-specific:

- `TerminalProcessGuard*`: compatibility and process-exec surface adapters.
- `TerminalProcessMediation*`: terminal/process mediation config.
- `ProcessInterception*`: compatibility names for process-exec mediation until
  IPC/control payloads are generalized.
- `EREBOR_TERMINAL_*`: terminal surface context only.
- `EREBOR_GUARD_*`: compatibility guard variables.

#### Phase 1 Verification

Verified by inspection and documentation update:

```sh
rg -n "process_guard|process_interception|process_mediation|TerminalProcess|ProcessInterception|EREBOR_PROCESS|EREBOR_TERMINAL|EREBOR_GUARD|linux_ptrace|linux-ptrace|process_exec" crates/erebor-runtime-core/src/config.rs crates/erebor-runtime-session/src/lib.rs crates/erebor-runtime-session/src/os/linux/process_guard.rs crates/erebor-runtime-session/src/os/linux/process_guard/interception.rs crates/erebor-runtime-ipc/proto/erebor/runtime/ipc/v1/control.proto crates/erebor-runtime-ipc/src/v1.rs crates/erebor-runtime-terminal/src/lib.rs
```

No Rust tests were run for Phase 1 because this phase changes the planning
document only.

### Phase 2 - Session-Level Interception Config

State: Not done.

Deliverables:

- Add session-owned interception config types in core.
- Add capability reporting for operation families such as `process_exec`,
  `file_read`, `file_mutation`, and `socket_connect`.

Acceptance:

- New configs can enable the Linux ptrace backend without declaring it under
  terminal.
- Existing configs still produce the same process-exec launch plan.
- Capability reports distinguish backend support from surface enablement.

### Phase 3 - Generic Backend Lifecycle

State: Not done.

Deliverables:

- Move guard preparation out of the terminal surface branch in session startup.
- Create a session interception backend lifecycle owned by the session runner
  side-resource path.
- Rename internal bundle concepts from process/terminal-specific names toward
  session interception backend names where doing so does not cause churn.

Acceptance:

- A session can start the Linux ptrace backend because session interception is
  enabled, not because the terminal surface happens to be present.
- Terminal remains able to consume process-exec events.
- Linux-host adoption depends on the session interception backend when adoption
  needs a backend, not specifically on terminal config.

### Phase 4 - Router For Process Exec

State: Not done.

Deliverables:

- Introduce an interception router that maps `ProcessExec` operations to the
  terminal/process surface.
- Preserve current terminal audit shape for process-exec decisions.
- Preserve current process mediation behavior for managed browser launch.
- Keep fast static allow/deny rules local where the guard already supports
  them.

Acceptance:

- Existing Linux process guard tests pass.
- Existing terminal policy tests pass.
- Existing managed browser launch mediation tests pass.
- Audit records for process execution remain readable by session review.

### Phase 5 - Prepare Multi-Surface Operation Families

State: Not done.

Deliverables:

- Extend the IPC/control payload vocabulary so future operations are not forced
  into process-exec fields.
- Add router extension points for filesystem and network operation families.
- Add tests proving unsupported operation families fail closed or are reported
  as unsupported according to backend capability.

Acceptance:

- The router can represent a file operation internally without labeling it as a
  terminal command.
- No filesystem guarantee is claimed until a filesystem surface handler exists.
- Unsupported operations are visible in capability reports and audit/status
  metadata.

### Phase 6 - Documentation And Naming Cleanup

State: Not done.

Deliverables:

- Update session-hypervisor, terminal/browser, and process-control-channel docs
  to use the new interception terminology.
- Keep compatibility notes for old `terminal.process_guard` naming.
- Make the terminal plan describe terminal/process as one routed consumer of
  interception, not the backend owner.

Acceptance:

- Docs consistently distinguish backend, router, and surface.
- Future filesystem and revert plans can reference the session interception
  backend without treating filesystem as a terminal subfeature.

## Non-Goals

- Do not implement filesystem revert in this refactor.
- Do not implement a complete filesystem surface in this refactor.
- Do not replace the Linux ptrace backend with fanotify, BPF LSM, Endpoint
  Security, or a Windows minifilter yet.
- Do not remove compatibility for existing terminal/process guard configs until
  a later explicit cleanup plan.
- Do not make the terminal surface responsible for file read/write semantics.

## Validation

Before claiming implementation complete:

```sh
cargo fmt
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Targeted checks while implementing:

- terminal policy compilation tests
- Linux process guard unit wrapper tests
- Linux host runner tests
- session review tests that read terminal/process audit records
- managed browser process mediation tests

Validation must prove:

- current terminal/process enforcement still works
- new session-level interception config works
- compatibility config still works
- process-exec audit remains associated with the terminal/process surface
- backend capability reporting does not claim filesystem or network guarantees
  before those surface handlers are implemented

## Open Decisions

- Exact config name: `session.interception`, `session.guard`, or
  `session.backends.interception`.
- Whether the first generic backend types live in `erebor-runtime-core` or in a
  new crate consumed by core and session.
- Whether IPC v1 should be extended in place or versioned when non-process
  operation payloads are added.
- Whether `ExecutionSurface::Filesystem` is added during this refactor or in
  the first filesystem surface plan.
- How much of the existing process guard environment variable naming should be
  preserved indefinitely for external debugging compatibility.

## Current Status

State: Phase 1 done; Phases 2 through 6 not done.

Phase 1 completed the inventory and compatibility contract. No code has been
moved yet. The current implementation remains terminal/process-config-driven:
the Linux ptrace guard starts from terminal surface config and emits
terminal/process audit records.

Latest verification:

- Done: inspected current config, guard wiring, environment variables, IPC
  payloads, audit labels, and tests through targeted `rg` and source reads.
- Done: `git diff --check -- docs/plans/session-interception-backend-refactor/README.md docs/plans/README.md`
  passed after the Phase 1 doc update.
- Not done: Rust tests were not run because Phase 1 changed only planning
  documentation.
