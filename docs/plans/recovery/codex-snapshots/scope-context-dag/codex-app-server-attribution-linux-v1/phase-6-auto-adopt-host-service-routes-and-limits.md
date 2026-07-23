# Phase 6: Auto-Adopt Host Service, Routes, And Limits

Status: Proposed. Blocked on Phase 5 and explicit implementation approval.

## Purpose

Create the persistent privileged control plane required by Linux-host
`session auto-adopt`, including authenticated live-session coordination,
durable deterministic routes, explicit route lifecycle, and hard resource and
latency limits. Do not activate production held-exec admission in this phase.

## Scope

- Add a root-owned `erebor-runtime-host-service` managed by the host service
  manager. It is the future fanotify owner and the current owner of the trusted
  profile/template registry, durable auto-adoption routes, peer authorization,
  capacity accounting, and admission dispatch.
- Add versioned IPC for host-service hello, live-session registration and
  renewal, route add/list/remove, route status, held-candidate dispatch, and
  fresh-session worker lifecycle. Use a root-owned Unix socket and authenticate
  every CLI and worker peer with SO_PEERCRED plus pidfd/process-start identity.
- Add `session auto-adopt add`, `list`, and `remove` as CLI request wiring.
  `add` requires a validated config, `linux-host` runner, named Codex profile,
  and exactly one of `--join-session <id>` or `--create-per-exec`. It rejects a
  command position, Docker, `--pid`, and `--match`. `add` returns an opaque
  route id and effective limit summary.
- Treat the CLI-loaded `--config` as untrusted request input at the privileged
  boundary. The service accepts only canonical typed requests referencing a
  root-verified profile digest and fresh-session template id. It never opens or
  executes a caller-provided config, executable, hook, namespace, mount, or
  socket path and independently revalidates trusted references.
- Authorize a non-root caller only for its UID, routes it owns, and live
  sessions it owns. `--join-session` requires an authenticated live
  `session run` worker with compatible UID, profile epoch, namespace/cgroup,
  and health state. The service retains its pidfd and control endpoint rather
  than treating a durable session id as proof of liveness.
- For `--create-per-exec`, permit only a root-approved fresh-session template.
  The service starts and tracks a user-scoped session worker under the
  candidate UID; the request cannot substitute an arbitrary command or
  privileged resource.
- Persist default routes across CLI and service restarts until explicit removal
  or profile/template invalidation. Expire context routes with their joined
  session or captured launch-context root. After restart, revalidate defaults
  and rebuild context routes only from authenticated live-session workers.
- Reject duplicate context keys and overlapping default routes at registration
  rather than resolving ambiguity by priority, timing, or session id.
- Add root-owned per-UID/profile limits with these V1 defaults: 32 routes, 8
  pending held candidates, 2 concurrent fresh-session builds, 16 active
  auto-created sessions, and a launch token bucket of 12 per minute with burst
  4. A profile may tighten but not a CLI override these values.
- Add a 15-second total admission deadline, 3-second live-session control RPC
  deadline, and 10-second post-resume SessionStart deadline. Capacity, rate,
  queue, or deadline exhaustion produces a stable fail-closed reason and audit
  record.
- Keep production fanotify marks, held-exec decisions, namespace entry,
  derived-context collection, and any transport interposition out of this
  phase. The service and route states report `not-active` until Phase 7 passes.

## Tests

- Clap/parser tests keep `session run`, manual `session adopt`, and auto-adopt
  add/list/remove distinct and cover every rejected argument combination.
- IPC tests cover peer credentials, PID reuse, stale pidfd, UID/session-owner
  mismatch, replay, protocol version mismatch, disconnect, and worker death.
- Privilege-boundary tests reject arbitrary config/profile/template paths,
  caller-supplied namespace/socket handles, untrusted executable/hook paths,
  cross-UID routes, and incompatible joined sessions.
- Route tests cover add/list/remove ownership, duplicate/overlapping routes,
  context expiry, default persistence, profile invalidation, service restart,
  worker re-registration, and fail-closed recovery windows.
- Limit tests hit each route, pending-candidate, build, live-session, token
  bucket, RPC, and deadline boundary and prove the request cannot resume a
  candidate unmanaged.

## Checkpoint

```sh
cargo fmt
cargo test -p erebor-runtime-core --all-targets --all-features
cargo test -p erebor-runtime-ipc --all-targets --all-features
cargo test -p erebor-runtime-session --all-targets --all-features
cargo test -p erebor-runtime-cli --all-targets --all-features
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

## Acceptance

- A persistent privileged service, not a completed CLI invocation, owns every
  durable route and is the designated fanotify owner.
- Live session state remains owned by its worker and is usable only through an
  authenticated, lifetime-bound service registration.
- No privileged operation follows a user-controlled path or unverified
  profile/template reference.
- Route lifecycle and overload behavior are explicit, bounded, fail closed,
  restart-safe, and auditable.
- No plain external Codex launch is claimed auto-admitted yet.

## Stop Point

Stop after host-service and route-control verification. Wait for explicit
approval before Phase 7 activates fanotify or admits an external process.

## Phase Result

State: Not started.
