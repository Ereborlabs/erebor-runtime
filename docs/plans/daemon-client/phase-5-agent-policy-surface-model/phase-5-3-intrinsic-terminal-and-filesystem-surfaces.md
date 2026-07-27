# Phase 5.3: Intrinsic Terminal And Filesystem Surfaces

Status: Done (implemented 2026-07-27).

Parent plan: [Phase 5: Agent, Policy, And Surface Resource Model](README.md)

## Purpose

Implement `terminal` and `filesystem` as intrinsic Surfaces: daemon-provided
governance domains with no user-created Surface documents. This phase realizes
them through the daemon-owned `TerminalSurfaceRuntime` and
`LinuxOstreeOverlayFilesystemRuntime`; those types implement the Surfaces and
are not Surfaces themselves. It establishes the governed Linux-host foundation
for a real Codex TUI: shared terminal interception, a per-session filesystem
view, and private agent state without a live caller home directory, raw mount,
or policy bypass.

## How The Intrinsic Surfaces Are Realized

```text
intrinsic `terminal` Surface
  └── realized by one TerminalSurfaceRuntime
        └── per-session TerminalBinding
              ├── routing/token
              ├── PTY
              └── guard injection / environment

intrinsic `filesystem` Surface
  └── realized by one LinuxOstreeOverlayFilesystemRuntime
        └── per-session FilesystemBinding/View
              ├── one OSTree repository for that Session
              ├── lower/snapshot selection
              ├── upper/work/projection state
              ├── checkpoints
              └── session-scoped filesystem audit handler
```

The terminal Surface is realized by the shared terminal runtime:
`RuntimeGuardService` already demonstrates this shape, with one interception
server routing many Session registrations. This phase preserves that listener
and worker lifetime; it does not make terminal interception a per-Session
service. The filesystem Surface is realized by the long-lived
`LinuxOstreeOverlayFilesystemRuntime`. `FilesystemSessionStorage::prepare`
currently creates an OSTree repository under each Session directory. This
phase preserves **one OSTree repository per Session** and reuses
`FilesystemSessionStorage` as the storage owner for each `FilesystemBinding`.

The Session binding, not either runtime object, owns the temporary filesystem
view and audit attribution. `LinuxHostRunner` and future `DockerRunner` receive
the terminal and filesystem bindings; neither creates a runtime or bypasses
its policy/evidence owner.

## Scope

- Reuse the existing terminal broker, session-interception setup, ptrace guards,
  and Phase 4 PTY behavior wherever they meet the intrinsic terminal Surface
  contract. Phase 5.3 binds their per-Session outputs into that Surface; it
  does not add a second broker, guard injection path, or PTY implementation.
- Realize the intrinsic `terminal` Surface through the existing shared
  `TerminalSurfaceRuntime`. `RuntimeGuardService` owns one shared listener and
  worker set; an admitted Session adds one router/token registration and its
  own PTY/guard resources. Neither `LinuxHostRunner` nor a future DockerRunner
  creates terminal interception. Each consumes the resulting terminal binding.
- Realize the intrinsic `filesystem` Surface through the compiled-in,
  daemon-owned `LinuxOstreeOverlayFilesystemRuntime`. There is one runtime per
  daemon, not one runtime per Session and not a Runner. Each admitted Session
  receives its own filesystem binding and its own OSTree repository beneath the
  Session storage root, together with overlays, checkpoints, projection,
  recovery, and attribution state. The runtime and binding do not store Agent
  or PolicySet references as configuration; Session admission supplies those
  immutable identities.
- Preserve and reuse `FilesystemSessionStorage`; do not replace it with a new
  filesystem-storage abstraction. Each filesystem binding owns one existing
  `FilesystemSessionStorage` instance. Its `prepare` path continues to create
  the session's `filesystem/repo`, `filesystem/work`, and volume overlay layout
  through `SystemOstreeRepository`; its `open_existing` path remains the
  recovery/open path. `LinuxOstreeOverlayFilesystemRuntime` orchestrates those
  operations, policy evaluation, and daemon lifecycle around that owner. No
  storage-layout migration, duplicate repository planner, or new persistent
  store is in Phase 5.
- Do not create a named filesystem `Surface` document or a filesystem
  `surface create|start` lifecycle in Phase 5. Filesystem is always a governed
  intrinsic Surface. Its Phase 5 realization has no independent public
  configuration or lifecycle; the Session receives only its filesystem binding.
  A later independently retained/shared filesystem resource may justify a named
  Surface document only with a separately approved model.
- Move `erebor filesystem transactions|retention` and their direct
  workspace-registry/storage path behind typed daemon requests. The CLI cannot
  open a caller-selected registry or select a raw `--registry` root after this
  migration.
- Add a filesystem policy owner before every physical filesystem effect. It
  emits the existing `RuntimeEvent` values `surface: filesystem` with
  `file_open`, `file_read`, `file_write`, or `file_mutation`, then evaluates
  the Session's PolicySet packages in their immutable order. A denial prevents
  the effect; no match in a mandatory package fails closed. The current stored
  policy router only handles
  process execution, so this phase must add this filesystem owner rather than
  claiming that package rules already govern overlay effects.
- Define the compiled adapter's fixed state-projection contract. `codex-v1`
  requires its private projection at its fixed `CODEX_HOME` target; this is not
  an Agent schema field or user configuration. Neither CLI nor Session
  environment can replace it.
- Resolve a caller-owned state source once through the UID-dropped descriptor
  broker. Record its identity/content manifest, materialize a daemon-owned
  immutable lower snapshot, and give each admitted session a separate
  daemon-owned writable upper.
- Bind source class, access mode, refresh rule, lower snapshot, writable-upper
  policy, retention, promotion/export policy, rendered configuration, Agent,
  filesystem binding, PolicySet, and Session into the Session admission/evidence
  record.
  Revalidate every typed refresh and reject stale, replaced, symlinked,
  cross-UID, or policy-revoked sources.
- Render managed Codex configuration and hooks only in the projection. The
  workload receives no caller source path, daemon-control socket, or another
  UID's state; evidence records identities and decisions, never source content
  or credentials.

## Delivered Resource Schemas

Phase 5.3 realizes the intrinsic terminal/filesystem Surfaces and adds the
private-state projection result to Session status. There is intentionally no
terminal or filesystem `Surface` schema in this phase: no user-created document
exists to configure or name either intrinsic Surface. The Agent still has no
state-path field.

### `terminal`: intrinsic Surface binding

The session model gains no `Session.spec.terminal` field. `terminal` is an
intrinsic registered Surface selected by the admitted Codex path. At start, the
daemon registers that Session with the one shared runtime that realizes the
terminal Surface and creates only the per-session router/token/PTY/guard
resources. The binding is recorded in daemon evidence; its socket, token, and
guard paths are not Session configuration or workload-visible fields.

### `filesystem`: intrinsic Surface binding

The compiled registry selects the intrinsic `filesystem` Surface for every
admitted Session that requires filesystem governance.
`LinuxOstreeOverlayFilesystemRuntime` realizes that Surface and is
daemon-long-lived; its returned `FilesystemBinding` is session-scoped. That
binding retains exactly one existing `FilesystemSessionStorage` instance and
therefore exactly one OSTree repository for that Session, plus the established
lower/upper and projection state. The Runner receives only the resulting
filesystem view; it never opens a repository or becomes the enforcement owner.

### Session state projection

```json
{
  "apiVersion": "erebor.dev/v1",
  "kind": "Session",
  "metadata": { "name": "engineering-review-1" },
  "spec": {
    "agent": "local-codex",
    "policySet": "company-workspace"
  },
  "status": {
    "stateProjection": {
      "target": "/run/erebor/state/codex",
      "lowerSnapshot": "session-a31-state",
      "writableUpper": "upper-session-a31",
      "refresh": "explicit",
      "retention": "discard-on-session-removal"
    }
  }
}
```

| Field | Use and validation | Owner |
| --- | --- | --- |
| `apiVersion` | Selects the v1 Session inspection schema. Must equal `erebor.dev/v1`. | API contract |
| `kind` | Selects the Session validator. Must equal `Session`. | API contract |
| `metadata.name` | Daemon-assigned immutable handle for this concrete run. | Daemon |
| `spec.agent` | Resolved Agent input. Its compiled adapter fixes the in-session state-target convention but does not select a source. | Session admission |
| `spec.policySet` | Resolved governing PolicySet input. Every package named by its immutable `spec.packages` list must have `filesystem` and terminal rule coverage before the daemon creates this governed Codex Session. | Session admission |
| `spec.surfaces` | Optional JSON array with set semantics for named Surface records with independent configuration. It is absent here: filesystem and terminal are intrinsic bindings. | Session admission |
| `status` | Daemon-written runtime result only, not Session create input. | Daemon |
| `status.stateProjection` | The daemon-created private state view used by this Session. It proves the physical projection without exposing the caller source path or credentials. | Filesystem SurfaceRuntime |
| `status.stateProjection.target` | Fixed path inside the governed workload where the compiled adapter expects its state. For `codex-v1` it is the value assigned to `CODEX_HOME`; the caller cannot override it. | Compiled adapter contract / Filesystem SurfaceRuntime |
| `status.stateProjection.lowerSnapshot` | Opaque daemon identity for the read-only snapshot taken from an admitted state source. It lets evidence link a run to its input without exposing the source path or contents. | Filesystem SurfaceRuntime |
| `status.stateProjection.writableUpper` | Opaque daemon identity for this Session's writable overlay. It isolates run-time mutations from the lower snapshot and other Sessions. | Filesystem SurfaceRuntime |
| `status.stateProjection.refresh` | Refresh policy for the lower snapshot. `explicit` means the daemon refreshes only through a typed, revalidated operation; it never follows live caller state while the Session runs. | Filesystem SurfaceRuntime |
| `status.stateProjection.retention` | Cleanup policy for the writable overlay. `discard-on-session-removal` deletes that Session's mutable upper when the Session is removed. | Filesystem SurfaceRuntime |

## Examples

### The session receives a projection, not the caller's home

An inspection/evidence record describes the projection by durable identities
and a fixed target. It does not disclose or pass a source path to the workload:

The Session schema above is the inspection/evidence record for this example.

Inside Codex, `CODEX_HOME` is the fixed target above. The real caller source,
for example `/home/user/.codex`, is neither an environment value nor a visible
mount in the session.

### Raw state and mount overrides are rejected

These requests must fail rather than create a shortcut around the projection:

```text
erebor session run ... --env CODEX_HOME=/home/user/.codex
  -> error: CODEX_HOME is adapter-owned

erebor session run ... --mount /home/user/.codex:/run/erebor/state/codex
  -> error: raw mounts are not session inputs
```

## Non-Goals

- Do not build an Agent from Agentfile or accept Agentfile private-state,
  credential, host-path, mount, or policy instructions.
- Do not introduce generic Docker mounts, OCI volumes, a credential subsystem,
  or caller-home mutation.
- Do not claim a real Codex TUI result; that is Phase 5.5.

## Checkpoint

Add crate-local and daemon/client e2e coverage for:

- one shared terminal-interception runtime serving two Sessions, with distinct
  route/token registrations and PTY/guard resources; stopping one Session must
  not stop the shared listener or the other Session;
- one daemon-owned `LinuxOstreeOverlayFilesystemRuntime` serving two Sessions,
  reusing one separate `FilesystemSessionStorage` and OSTree repository,
  overlay view, checkpoints, and recovery record per Session plus two-UID
  artifact isolation; and
- preservation of the existing `FilesystemSessionStorage::prepare` and
  `open_existing` layout/recovery behavior, with no second repository planner
  or persistent filesystem store;
- filesystem event emission and PolicySet evaluation before open/read/write/
  mutation; a denied `.erebor-denied` write/mutation has no physical effect,
  while the allowed actions remain confined to the daemon-owned surface; and
- absence of direct client registry access after migration;
- a read-only lower snapshot, per-session writable upper, fixed private
  `CODEX_HOME`, and rejection of `HOME`, `CODEX_HOME`, raw mounts, and
  source-path session input;
- refresh/replacement/symlink/cross-UID/revocation rejection, caller-state
  non-mutation, daemon-socket/source-path absence, and redacted evidence; and
- exact filesystem binding, PolicySet, Agent, state, filesystem-operation, and
  Session identities in every retained artifact and receipt.

## Acceptance

- The daemon-owned runtime realizing the intrinsic terminal Surface, not a
  Runner, owns shared interception; the Session receives only its
  router/token/PTY/guard binding.
- The daemon-owned runtime realizing the intrinsic filesystem Surface, not an
  Agent, named document, PolicySet, Runner, or direct CLI path, owns filesystem
  state and private agent-state projection. A Session selects the compatible
  Agent/PolicySet combination and receives its session-specific filesystem
  binding and OSTree repository.
- An admitted workload sees only the fixed projected target and permitted agent
  endpoint. It cannot discover or modify caller state or daemon-control
  authority.
- Retention, refresh, promotion, rollback, export, and other physical effects
  occur only as typed, policy-governed filesystem operations with evidence.

## Stop Point

Record terminal-binding integration, filesystem migration, projection contract,
runner boundary, redaction boundary, e2e results, and verification evidence.
Stop before named Browser CDP lifecycle and terminal-to-Browser-CDP mediation;
those are Phase 5.4.

## Result

State: Done.

### Implemented

- `terminal` remains an intrinsic Surface realized by one daemon-owned
  `TerminalSurfaceRuntime`. It reuses the existing shared
  `RuntimeGuardService` listener and gives each Session only its own
  route/token/PTY/guard binding. Runners consume that binding; they do not
  create interception.
- `filesystem` is an intrinsic Surface realized by the daemon-owned
  `LinuxOstreeOverlayFilesystemRuntime`. It preserves the existing
  `FilesystemSessionStorage::prepare` and `open_existing` lifecycle, including
  one OSTree repository and one storage layout per Session. Removal discards
  only that Session's mutable overlay view.
- Codex admission creates the adapter-owned private-state projection at the
  fixed `CODEX_HOME` target. The runtime safely resolves the caller home
  through the UID-dropped descriptor broker, treats an absent `.codex`
  directory as an empty initial state, rejects unsafe state entries, copies a
  daemon-owned immutable lower snapshot, records a redacted identity/content
  manifest, and creates the Session writable upper/work view.
- The Linux controller projects the overlay only at the fixed target, hides
  the live caller home, and also masks the path inside a staged workspace when
  that workspace would otherwise expose the caller's `.codex` directory. The
  workload therefore cannot regain caller state merely by using its current
  workspace directory.
- Filesystem operations now have a stored immutable-PolicySet handler which
  emits filesystem events, evaluates mandatory layers before an effect, writes
  durable decisions, and fails closed for denied, approval-required, unknown,
  or unsupported mediated effects. The direct filesystem CLI registry path was
  replaced with typed daemon requests.
- Session inspection now reports the daemon-written opaque projection result;
  it contains the fixed target, lower snapshot identity, upper identity,
  explicit refresh mode, and discard-on-removal retention, without a caller
  path or state content.

### Verification

- `rtk cargo test -p erebor-runtime-core` — 80 passed.
- `rtk cargo test -p erebor-runtime-session` — 183 passed.
- `rtk env EREBOR_DAEMON_SYSTEMD_IMAGE=erebor-daemon-systemd:phase53-test cargo test -p erebor-runtime-e2e --test daemon_control_plane -- --ignored --nocapture` — passed. The privileged fixture seeds caller `.codex` state and proves
  `fixture-private-state=projected caller-state=hidden` while retaining the
  shared-terminal TTY and app-server coverage.
- `git diff --check`, `bash -n .github/scripts/daemon-codex-runtime.sh`,
  `rtk cargo check --workspace`, and
  `rtk cargo clippy --workspace --all-targets --all-features -- -D warnings`
  — passed.
- `bash .github/scripts/verify-rust-ci.sh` — passed after the final Rust edit.

The Docker acceptance gives `/var/lib/erebor` a test-only tmpfs because
Docker's own root OverlayFS cannot host a nested writable OverlayFS
upper/work pair. This does not select or configure a user-visible filesystem
Surface, and it does not change the daemon's production storage policy.
