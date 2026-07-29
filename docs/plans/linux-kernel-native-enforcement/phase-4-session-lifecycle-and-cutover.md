# Phase 4: Session Lifecycle Integration And Production Cutover

Status: Proposed. Requires Phase 3 and explicit approval.

Parent plan: [Linux Kernel-Native Effect Enforcement Master Plan](README.md)

## Purpose

Integrate the verified Linux kernel filesystem enforcer into normal daemon
Session admission, inspection, recovery, and teardown without confusing it
with the current ptrace compatibility backend or allowing an unsupported host
to downgrade silently.

## Scope

- Add the approved enforcement-tier/configuration contract at the portable
  Session boundary and a Linux implementation selection at daemon admission.
- Start order: validate host capability, resolve policy/filesystem view,
  compile image, create/bind cgroup, install kernel binding, start collector,
  then launch the workload. Any failure rolls back without starting an
  ungoverned workload.
- Teardown order: prevent new effects, wait for cgroup terminal state, drain
  and persist evidence, reconcile storage, seal the Session record, then
  remove pinned bindings/maps according to the approved retention policy.
- Report the actual backend, capability report digest, policy-image digest,
  enforcement health, evidence cursor/seal state, and residual risk through
  existing Session inspection/evidence paths.
- Define the explicit relationship with `linux_ptrace`: its supported developer
  or compatibility tier, admission label, evidence behavior, and prohibition on
  satisfying a kernel-enforced request.

## Non-Negotiables

- No automatic fallback from kernel enforcement to ptrace, seccomp user
  notification, filesystem observation, or a runner-only mount policy.
- No CLI-owned kernel business logic, artifact handling, or e2e harness.
- No removal of existing backend/configuration behavior without a separately
  approved deprecation/migration decision.
- Real workload acceptance must use an Erebor-owned fixture, not AgentSight or
  Codex as a tool or test dependency.

## Checkpoint

- End-to-end tests cover successful kernel-enforced Session admission, each
  preflight failure, collector failure fencing, normal teardown, abnormal
  workload exit, daemon recovery, and inspection/evidence rendering.
- The lifecycle probe passes in the supported Linux kernel test environment and
  reports a precise unsupported result on the current repository host.

## Acceptance

- A production kernel-enforced Session has one auditable admission-to-seal
  lifecycle with no ungoverned launch interval.
- `linux_ptrace` cannot be mistaken for the kernel-enforced tier in CLI output,
  API output, audit records, or Session review.
- All Rust verification and the privileged lifecycle probe pass against the
  final source state.

## Stop Point

This master does not authorize deleting the ptrace backend, changing default
tiers, or extending BPF LSM to terminal/network/browser Surfaces. Each needs a
new explicitly approved plan.

## Phase Result

Not started.
