# Phase 2: BPF LSM Filesystem Enforcer

Status: Proposed. Requires Phase 1 and explicit approval.

Parent plan: [Linux Kernel-Native Effect Enforcement Master Plan](README.md)

## Purpose

Implement the daemon-owned Linux BPF LSM enforcer that binds one admitted
kernel policy image to one Session cgroup and returns a kernel allow/deny result
at every approved filesystem effect hook.

## Scope

- Add the Phase 0-approved Linux-only enforcement owner. It loads verified
  Erebor BPF objects, owns pinned links/maps, installs/removes one Session
  binding, maps kernel errors to typed Erebor errors, and exposes no workload
  control socket or writable policy interface.
- Implement every Phase 1-supported filesystem action through the proven LSM
  hook matrix, including the relevant creation, topology, metadata, and
  descriptor-use paths. A syscall-number filter is not an implementation
  substitute.
- Enforce cgroup/Session identity before consulting the policy image. An
  unbound or stale identity fails closed when it reaches a governed view.
- Integrate with the existing Linux-host runner only at Session admission and
  teardown. Reuse `FilesystemSessionStorage` for COW/OSTree view ownership;
  do not create a second filesystem store.
- Add privileged e2e fixtures that exercise ordinary and adversarial filesystem
  paths: `openat2`, links/renames, symlinks, inherited/passed descriptors,
  `/proc` references, descendant processes, and async I/O where Phase 0
  declares support.

## Non-Negotiables

- No normal allowed filesystem effect calls a daemon policy RPC.
- No BPF map/program grants the workload BPF, cgroup, mount, or map-update
  authority.
- A missing/stale binding, unknown map result, unsupported action, or failed
  kernel event reservation returns a fail-closed result.
- Do not select this backend automatically. It is chosen only by an admitted
  production capability requirement whose preflight has passed.
- Do not remove `linux_ptrace`, rename it, or claim its tests verify this
  backend.

## Checkpoint

- Focused privileged e2e tests prove allowed effects succeed and denied effects
  have no physical mutation in the Session overlay.
- The exact effect matrix passes with every claimed syscall/path variant.
- Cross-cgroup attempts cannot observe or use another Session's policy image.

## Acceptance

- The BPF object, loader, maps, cgroup bindings, and error contracts have one
  named Linux enforcement owner.
- Tests prove before-effect denial for every supported action family and prove
  that unsupported action families are rejected at admission.
- Session teardown removes policy state only after its process/cgroup lifecycle
  has reached the Phase 2-defined terminal condition.

## Stop Point

Do not replace current durable decision recording with the kernel evidence path
until Phase 3 proves ordering, backpressure, and recovery.

## Phase Result

Not started.
