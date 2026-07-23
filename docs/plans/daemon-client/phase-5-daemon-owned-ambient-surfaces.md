# Phase 5: Daemon-Owned Ambient Surfaces

Status: Not started. This is the final Linux daemon/client core phase. It does
not require OCI distribution, Docker runner parity, another agent adapter, or
release certification.

## Purpose

Replace the legacy foreground `erebor start` command with named,
daemon-owned ambient-surface objects. After this phase, `erebor` is a client
for every public command and `erebord` is the sole lifecycle, policy,
evidence, and endpoint owner on the Linux-host core path. `erebor start` is
removed, not retained as a compatibility wrapper or a configuration-driven
shortcut.

## Scope

- Remove the top-level `erebor start --config … --listen …` parser and its
  foreground `StartCommand`/`SurfaceLaunchRunner` path. It must not translate
  a runtime config into implicit surface creation, and it must not remain as a
  hidden client-side daemon launcher.
- Make the typed daemon-owned ambient-surface lifecycle the only public
  surface lifecycle:

  ```text
  erebor surface create|start|ls|inspect|logs|events|stop|rm
  ```

  `surface create` persists one named, immutable surface specification and
  returns its id. `surface start` starts that exact durable object. There is no
  ambiguous `surface run` shorthand for a resource that can outlive a client
  and be bound by more than one session.
- A future declarative reconciliation command may be designed only after it
  can state create/update/delete, identity, ownership, and recovery semantics.
  It is not part of this phase and cannot reuse the removed `erebor start`
  spelling.

- Move the legacy filesystem surface and `erebor filesystem transactions|retention`
  operations into that lifecycle. `surface create|start` owns the declared
  volume bindings, overlay/checkpoint storage, policy handler, audit/evidence,
  promotion, recovery, and teardown. The client uses typed daemon requests to
  list, commit, show, rename, roll back, and prune its resulting artifacts; it
  never opens a workspace-local registry or selects `--registry`.

- Persist an immutable surface specification before start: owner UID, kind,
  policy-set digest, upstream identity, listener policy, audit/evidence roots,
  resource limits, and supported daemon-loss mode. Aliases resolve to immutable
  surface ids.
- For a filesystem surface, the immutable specification additionally binds the
  admitted volume identities, backend, revert/promotion rules, and retention
  requirements before any overlay is prepared.

### Agent State Projections

- Make user agent state a filesystem-surface binding, not an adapter-specific
  environment escape hatch. A package may declare a logical state requirement
  and its fixed private target, but it never names a caller host path. For
  `codex-v1`, the adapter's fixed target is a private `CODEX_HOME` path such as
  `/run/erebor/state/codex`; the caller cannot supply `HOME`, `CODEX_HOME`, or
  an equivalent state path in `erebor run`.
- A state source is a bundle, not an implied home-directory bind. It may contain
  provider configuration, authentication material, and caches admitted by the
  source class, but package-specific managed configuration is rendered only in
  the daemon-owned projection. For Codex this includes the managed hook
  configuration and any required feature setting. Erebor never edits the
  caller's `.codex`, `config.toml`, `hooks.json`, shell aliases, or another
  live user-state file to make a governed session work.
- A filesystem-surface specification binds the allowed source class, access
  mode, snapshot/refresh rule, writable-upper policy, retention, and export
  policy. The root filesystem configuration limits which source classes and
  modes are available; the admitted policy set decides whether a session may
  use the binding. The exact user-facing surface command for creating a state
  binding must remain typed and named; it must not accept a free-form session
  environment variable or a raw mount request.
- A caller-owned source directory is resolved once through the UID-dropped
  descriptor broker and materialized as a daemon-owned, immutable lower
  snapshot with a recorded identity/content manifest. Do not bind a mutable
  caller path into the workload after a path-only check. A daemon-owned
  writable upper is per-session by default. It may retain only under the
  filesystem surface's explicit retention rule; any refresh, promotion, or
  export is a typed, policy-governed filesystem operation with evidence.
- The writable upper is necessary even when the lower is immutable: an agent
  may update its own aliases, cache, session data, or configuration while it
  runs. Those writes stay private to the daemon-owned upper. They neither
  modify the source directory nor become durable caller state unless an
  explicitly allowed typed retention, promotion, or export action succeeds.
- The runner projects only the resulting daemon-owned lower/upper view into
  the private session namespace and sets the package-declared fixed target.
  The workload never receives the daemon control socket, the source host path,
  another UID's state, or authority to change the projection. This generalizes
  to future agent configuration, authentication state, and tool caches; it is
  not a Codex credential subsystem.
- Persist the immutable state-binding identity, source snapshot manifest,
  access mode, and overlay/retention policy in the surface/session binding
  record. Revalidate source eligibility on every typed refresh; stale,
  replaced, symlinked, cross-UID, or policy-revoked state is unavailable until
  explicitly refreshed.
- Record only state identities, manifests, policy decisions, and rendered
  configuration identities in evidence; do not put source contents, tokens,
  or authentication material in logs, session output, or receipts.
- Store surface state beneath `/var/lib/erebor/users/<uid>/surfaces/` and live
  endpoints beneath `/run/erebor/surfaces/<uid>/`; no ambient listener shares or
  replaces daemon-control or runtime-guard endpoints.
- Replace the foreground `SessionSurfaceLauncher`, `SessionSurfaceSupervisor`,
  and `SurfaceServiceRunner` lifecycle stack with one daemon-owned ambient
  surface supervisor. It owns handles, health, restart classification, logs,
  evidence, stop, and shutdown. Current `erebor start` behavior must not be
  moved wholesale: Browser CDP becomes the first `surface` kind; the current
  terminal and filesystem configuration entries do not become fake standalone
  listeners.
- Keep browser CDP as the first listener-bearing ambient-surface kind. The
  filesystem surface is a non-listener surface whose daemon-owned artifact
  operations remain bound to its immutable surface/session identity. Bind CDP
  to a typed,
  observed browser process/endpoint identity; reject cross-UID loopback,
  stale-upstream, unsafe redirect, and unapproved-credential cases.
- Permit session-to-surface binding only when owner, kind, package/adapter
  requirements, and policy-set identity are compatible. Record the immutable
  surface id and policy digest in `SessionSpec`.
- Default to owner-mode Unix sockets. Loopback TCP/WebSocket listeners require
  root policy and per-connection authentication; agent namespaces never receive
  the daemon-control socket.

### Local Codex Enrollment And Real Host Walkthrough

- A local Codex launcher or installer layout is not a runtime discovery
  mechanism. It may be documented as a way for the user to identify a candidate
  for `erebor agent load … --from`, but the daemon follows the candidate through
  the descriptor broker, records the resolved final regular executable and its
  resolution provenance, verifies the declared version and digest, and stages
  that installation. A later session runs the staged installation; it does not
  rescan the caller's home or follow a mutable launcher/symlink.
- The Phase 5 Linux host walkthrough uses that explicitly enrolled, pinned
  executable and a typed state surface. It runs the actual `erebor run … codex`
  TUI through the Phase 4 controller-PTY contract: initial terminal geometry,
  controller-only resize/input, read-only observers, and detach/reattach of the
  same daemon-owned session.
- The walkthrough must prove the daemon socket and source-host path are absent
  from the workload, the fixed private `CODEX_HOME` is present, the managed hook
  works from the projection, and the caller's live Codex state remains
  unchanged. The deterministic Phase 4 fixture remains a fast regression
  harness; it is not presented as the real-Codex user experience.

## Non-Goals

- Do not add OCI packages, registry access, Notation, Hub discovery, or formal
  packaging. Those are later Phase 10.
- Do not require Docker parity, macOS, or new runner capabilities. Linux
  controller-PTY geometry and detach/reattach are already required Phase 4
  behavior and are consumed here; Docker-specific interactive parity is later
  Phase 6.
- Do not add arbitrary surface plugins, remote listeners, or session adoption.

## Checkpoint

Add crate-local surface lifecycle tests and daemon/client e2e coverage for:

- create/start/health/log/events/stop/recovery/remove and two-UID isolation;
- client exit while the daemon remains the only supervisor;
- CDP allowed/denied actions and durable evidence;
- compatible and incompatible session-to-surface binding;
- filesystem surface create/start/checkpoint/promotion/rollback/retention,
  including no caller-selected registry path and two-UID isolation;
- agent state projection with a read-only lower snapshot, per-session writable
  upper, rejected ambient `HOME`/`CODEX_HOME`, refresh/revocation behavior,
  no source-host-path or daemon-socket visibility, no mutation of caller state,
  redacted evidence, and two-UID isolation;
- a real local Codex executable enrolled from an explicit candidate with a
  recorded final-file/version/digest identity; a projected managed hook and
  private `CODEX_HOME`; and a real TUI walkthrough using the Phase 4 PTY
  controller/geometry contract;
- listener authorization, daemon-socket absence, and root-owned endpoint paths;
- daemon restart for each advertised surface failure mode; and
- rejection of `erebor start` without creating a listener, process, record, or
  daemon request; and
- retirement of every foreground surface lifecycle caller.

Run the Phase 5 section of `lifecycle-probe.md`. The privileged Linux-host
acceptance requires systemd/cgroup/root prerequisites; it does not require
Docker or an OCI registry.

```sh
rtk cargo fmt --all -- --check
rtk cargo test --workspace --all-targets --all-features
rtk cargo clippy --workspace --all-targets --all-features -- -D warnings
rtk git diff --check
```

## Acceptance

- Every public `erebor` command is a typed daemon client operation.
- `erebor surface` is the sole public ambient-surface lifecycle. `erebor start`
  is absent from the parser, help, protocol, examples, and compatibility paths.
- Long-lived surfaces have one daemon-owned lifecycle/evidence supervisor; no
  foreground surface runtime remains.
- Filesystem transaction and retention commands are typed daemon clients of
  their daemon-owned filesystem surface; no client opens legacy session state.
- Agent configuration/authentication state reaches a workload only through an
  admitted filesystem-surface projection with immutable source evidence and a
  daemon-owned private target; package, CLI, and session environment inputs
  cannot select an ambient host state path or modify caller state.
- A real local Codex walkthrough uses a descriptor-broker-verified, pinned,
  staged executable and the private state projection. It does not rely on
  `PATH`, live-home scanning, mutable launcher resolution, or a fixture TTY as
  a substitute for the real user experience.
- Linux-host sessions and ambient surfaces retain UID isolation, private
  endpoints, policy enforcement, output, and evidence.
- Unsupported runner, distribution, agent, and platform capabilities are
  reported as unavailable rather than inferred from the core path.

## Stop Point

Stop after the Phase 5 evidence and result update. Later Phases 6 through 10
each need separate approval.

## Phase 5 Result

State: Not started.
