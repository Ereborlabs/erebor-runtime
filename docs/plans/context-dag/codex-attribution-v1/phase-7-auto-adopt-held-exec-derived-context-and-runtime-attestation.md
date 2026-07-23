# Phase 7: Auto-Adopt Held Exec, Derived Context, And Runtime Attestation

Status: Proposed. Blocked on Phase 6 and explicit implementation approval.

## Purpose

Activate Linux-host auto-admission so a verified later-launched plain Codex
image is held before userspace, deterministically joins an existing session or
receives one fresh session, enters the governed filesystem/runtime boundary,
and attests the managed profile before protected effects become eligible.

## Scope

- Activate the Phase 6 host service as the production Linux fanotify permission
  owner and add a narrow Codex held-exec adapter. Keep it separate from manual
  `/proc` adoption and `SessionAdoptionService`.
- Select no mechanism from Linux V0 by default. Re-run any held-exec,
  namespace-entry, descriptor, ptrace, or FD-splice candidate against the
  current Codex executable/profile and approve only the mechanism proven by the
  Phase 7 fixture. Record architecture as a profile fact; unsupported
  architectures report `unavailable` rather than inheriting x86-64.
- Verify the executable object/profile, UID/user namespace, pidfd lifetime,
  route/profile epoch, architecture/mechanism support, service health, and hard
  admission limits before doing privileged work.
- Derive only fixture-certified terminal, App Server, Desktop, or
  controller-owned-scope `LaunchContextId` values from process lifetime, PTY,
  descriptor topology, namespace, and controlled-scope evidence. Never select
  a strict route from a label, CWD, raw PID, argv text, environment variable,
  registration order, timing, or nearest session.
- Resolve one exact healthy context route first. A stale, unhealthy, or
  conflicting context route denies without default fallback. Only the absence
  of a context route may use one healthy default route to create one fresh
  session. No route or multiple valid routes deny.
- For `--join-session`, dispatch the candidate to the authenticated live worker
  registered in Phase 6. For `--create-per-exec`, start one user-scoped worker
  from the route's root-approved template. Revalidate all handles after each
  cross-process handoff.
- Enter the selected session's namespace/cgroup and dedicated filesystem before
  Codex can read configuration. Verify the read-only Erebor projection at
  `/etc/codex/requirements.toml` and the managed-hook path without changing the
  host-global Codex view.
- Apply only the descriptor and transport policy certified for the exact source
  profile. An auto-admitted App Server is brokered only when a currently
  approved pre-work interposition mechanism proves original byte ownership;
  otherwise report the honest hook-first, action-governed, or unavailable
  state.
- Register `process-admitted` state before the final resume. Require the Phase
  1 end-to-end authenticated SessionStart channel to reach
  `session-start-attested` within the profile deadline. Admission alone grants
  no protected effect.
- Deny before the target's first instruction on verification failure, route
  ambiguity, overload, timeout, host-service/session-worker/tracer loss, or an
  unsupported architecture/mechanism. If service-owner loss cannot be proven
  fail closed for a source profile, that profile cannot claim strict
  auto-adoption.
- Preserve manual `session adopt` as its existing non-strict compatibility path
  and never promote a preexisting process to strict.

## Tests

- Real held-exec fixtures prove no target first-instruction marker before the
  final verified allow and cover CLI, TUI, IDE App Server, and Desktop profiles
  separately.
- Context fixtures cover terminal/PTY, inherited App Server transport,
  desktop-root, and controlled-scope evidence plus raw PID, CWD, argv,
  environment-only, copied/renamed executable, changed image, and PID-reuse
  negatives.
- Route fixtures cover exact join, one fresh session per default-routed exec,
  stale/conflicting context denial without fallback, concurrent candidates,
  worker death, service restart, and route/profile epoch change.
- Namespace, cgroup, requirements projection, descriptor, transport,
  executable, architecture, and health-epoch mismatch tests deny.
- Every configured capacity, rate, RPC, admission, and SessionStart deadline is
  exercised while the target remains held or is denied.
- SessionStart tests prove `process-admitted` grants no effect and cover wrong
  shell/interpreter chain, pipe replacement, descendant-launched genuine hook,
  missing event, timeout, replay, and profile mismatch.
- At least one approved architecture/profile runs the full live fixture. A V0
  experiment result alone cannot satisfy any Phase 7 acceptance item.

## Checkpoint

```sh
cargo fmt
cargo test -p erebor-runtime-session --all-targets --all-features
EREBOR_REQUIRE_CODEX_LINUX_V1_PROBE=1 \
  cargo test -p erebor-runtime-e2e --test codex_linux_v1_lifecycle \
  adoption_and_attestation -- --test-threads=1 --nocapture
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

## Acceptance

- A plain matching Codex launch is held before userspace and routed only by an
  exact verified context or one root-approved default profile.
- The selected session view, physical guard, and profile-specific transport
  policy are verified before resume.
- Startup attestation uses the authenticated end-to-end hook channel and is
  required before any protected effect.
- Unsupported architectures, unapproved V0 mechanisms, ambiguous routes,
  overload, and owner loss cannot silently become unmanaged strict launches.
- Existing `session run` and manual `session adopt` semantics remain distinct.

## Stop Point

Stop after final auto-adopt verification. Wait for explicit approval before
widening automatic-adoption coverage or enabling another source profile,
architecture, or physical mechanism.

## Phase Result

State: Not started.
