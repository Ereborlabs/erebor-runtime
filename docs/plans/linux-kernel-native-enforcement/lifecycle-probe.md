# Linux Kernel Enforcement Lifecycle Probe

Status: Proposed acceptance procedure. This probe is not a substitute for
crate-local and e2e Rust tests.

Parent plan: [Linux Kernel-Native Effect Enforcement Master Plan](README.md)

## Purpose

Prove one real Linux kernel-enforced filesystem Session from admission through
sealed evidence. The probe runs only in the Phase 0-approved isolated Linux
environment with BPF LSM active and the daemon's required BPF authority.

## Preconditions

- The feature report says BPF LSM is active, the exact Erebor program can
  attach, cgroup v2 is available, and the workload lacks BPF/cgroup/mount
  authority.
- The test uses a daemon-created Session, an immutable PolicySet, a declared
  filesystem view, and the existing session-owned COW/OSTree storage.
- The fixture is Erebor-owned and does not invoke AgentSight or Codex.

## Procedure

1. Start a kernel-enforced Session with an allowed workspace write and an exact
   denied create/mutation rule represented by the approved policy-image form.
2. Verify admission records the Session, cgroup, filesystem-view, PolicySet,
   capability-report, and kernel-policy-image digests before workload launch.
3. Perform allowed open/read/write/truncate operations and confirm the COW
   view changes as expected.
4. Attempt denied create, write, unlink, rename, link, and metadata operations
   that are in the supported hook matrix. Verify each returns the documented
   denial and causes no physical forbidden effect.
5. Repeat representative actions through `openat2`, a descendant process,
   symbolic/hard-link paths, a passed descriptor, `/proc` references, and an
   asynchronous path where supported. Verify no bypass.
6. Pause or terminate the evidence collector. Verify the documented bounded
   backpressure path fences subsequent effects and leaves a recoverable Session
   state.
7. Restore/restart the collector or daemon. Verify ordered ledger recovery,
   storage reconciliation, and an explicit seal or evidence-incomplete result.
8. End the workload, wait for cgroup emptiness, inspect the Session, and verify
   its sealed ledger contains every accepted effect with the right Session and
   policy-image identities.

## Required Result

The probe result records:

- kernel release, capability report, active LSM order, and test environment;
- commands/fixture actions and their observed return values;
- physical filesystem proof for each allowed and denied action;
- evidence ordering, cursor, fence, recovery, and seal state;
- exact unsupported capability reason when run on a host without BPF LSM.

Do not mark this probe passed on a host that falls back to ptrace or lacks BPF
LSM. That result is an expected unsupported-host report only.
