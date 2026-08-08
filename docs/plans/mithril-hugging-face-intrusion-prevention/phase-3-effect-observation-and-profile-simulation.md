# Phase 3: Effect Observation And Profile Simulation

Status: Proposed; depends on Phase 2 `Done`.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)
Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
Manual acceptance: [Phase 3 runbook](./manual-testing/phase-3-manual-acceptance.md)  
Environment setup: [shared setup guide](./manual-testing/environment-setup.md)

## Purpose

Implement the complete source-policy compiler and observe-only local effect
model. Prove that every future deny is paired with the real actor, object,
hook, state, and physical result before enabling policy enforcement.

## Scope And Design Coverage

Chapters 10-21 and 28-31; Appendices A.11-A.14.

## Deliverables

### D3.1 — Source policy and compiler in Mithril Control

Implement the closed parser, registries, selectors, roles, entries,
transitions, effects, bounded exceptions, dispositions, exact conflicts,
canonical bytes, signatures, anti-rollback, and deterministic lowering.
Unknown/duplicate/open fields reject. Policy names may be reused; generations
and signed content remain exact.

### D3.2 — Candidate generation and simulation

Build complete inactive map generations, read them back, run deterministic
simulation, and generate explanations without activating physical denial.
Non-path selectors expand to finite exact keys; hierarchical paths compile to
the bounded component graph and exact-object candidate stage.

### D3.3 — Meta canonical path and mount-view implementation

Implement the approved bounded `d_name` vector, state graph/wildcards,
mount-root index, lowest-`mnt_id_unique` selection, selected parent/mountpoint
walk, actor `MountSecurityViewV1`, topology snapshot, DIRTY state, and strict
unresolved result. The bind-alias fixture must resolve the original tracked
`/var/run/secrets/service/config.json`, not the later
`/work/input/job-42/config.json` target. Version 1 does not cache final
decisions. It also leaves resolved path-candidate caching disabled unless a
separate hostile alias-equivalence proof shows that every cache key preserves
the exact component/mount-chain match; a bare exact-file-object cache is not
sufficient for pre-existing hard-link aliases.

### D3.4 — Observe-only effect families

Using the shared Interceptor, attribute the Phase 0-qualified exec, executable
memory, file/create/mutate, credentials, delegated I/O, IPC/process-control,
socket/network, device/ioctl/derived-object, privilege, mount, and
self-protection paths. Each event carries exact actor/object/operation/stage and
whether the physical effect completed.

### D3.5 — Exact object and dynamic-state models

Implement mount/file/socket/channel/device/derived-capability generations,
opened-file provenance, immutable executable classification, mm/VMA snapshot
identity, persistent object state, relationship candidates, and dynamic floors
without claiming byte provenance.

### D3.6 — Honest observe semantics

`OBSERVE` may allow only a simulatable policy denial and emit `WOULD_DENY` or
`WOULD_REJECT`. Missing identity, corrupt generation, prior LSM denial,
emergency restriction, ambiguous topology, and unsupported physical boundary
retain their hard-safety result.

### D3.7 — Standing incident observe increment

Run the unchanged HF worker and legitimate controls. Produce stable simulated
decisions for the managed/local branches of `HF-002` through `HF-012`, with
special focus on the earliest complete `HF-008` file-object block, without
changing application behavior or claiming prevention. Pure in-memory and
outside-authority branches retain their honest non-prevention result.

## Checkpoint

One deterministic signed candidate generation simulates every Phase 4/5
fixture with exact actor/object/stage/result, and the bounded canonical path
matcher passes its hostile corpus. Policy denial remains physically disabled.

## Required Tests And Fixtures

- Policy/config/generation goldens and exact-conflict/exception tests.
- Observe/simulate the exact Phase 4 first-owned IDs:
  `ADMIN-EXEC-APPROVAL-001`, `DEVICE-DERIVED-001`,
  `FILE-CONTENT-RACE-002`, `FILE-FD-PASS-001`, `FILE-IDENTITY-001`,
  `FILE-MMAP-001`, `FILE-MMAP-SHARED-011`, `FILE-NAMESPACE-001`,
  `FILE-SA-TOKEN-OPEN-001`, `FILE-VMA-SNAPSHOT-001`, `HF-LOCAL-001`,
  `IPC-ASYNC-UNSUPPORTED-010`, `IPC-PEER-RACE-004`,
  `IPC-PROCESS-CHANNEL-009`, `IPC-RELATIONSHIP-ALLOW-003`,
  `IPC-RELATIONSHIP-UNMATCHED-005`, `LSM-DENY-SATURATION-001`,
  `MEM-EXEC-001`,
  `MEM-KERNEL-MAP-002`, `MOUNT-ATTR-001`, `MOUNT-CAS-002`,
  `MOUNT-PROPAGATION-003`, `MOUNT-SNAPSHOT-004`, `SELF-PROTECT-001`, and
  `STATE-PERSISTENT-FILE-LIFETIME-007`.
- Observe/simulate the exact Phase 5 first-owned IDs:
  `FILE-DELEGATED-EGRESS-001`, `HF-004-RESULT-001`,
  `HF-011-READ-RESULT-001`, `HF-NET-001`, `IPC-LOCAL-INET-008`,
  `NET-ACCEPT-PASS-001`, `NET-DNS-EXFIL-001`, `NET-NS-PASS-001`,
  `NET-RECV-001`, `NET-REWRITE-001`, `NET-SHARED-RESPONSE-002`,
  `NET-SOCKCTL-001`, and `NET-SOCKET-LIFE-001`.
- Path bind/rename/link/mount ambiguity, pre-existing hard-link alias cache
  equivalence, ordinary-subdirectory limits, and oldest-mount controls must
  accompany `MOUNT-SNAPSHOT-004`, `FILE-IDENTITY-001`, and
  `MOUNT-PROPAGATION-003`.
- Upstream-dossier regression tests for every adopted path/task/map pattern.

## Acceptance

- Every allocated local effect has exact actor/object attribution or an exact
  unsupported/unresolved result.
- The canonical path graph is verifier-qualified at declared bounds and passes
  the oldest-mount example.
- Compiler output is deterministic and cannot activate a partial generation.
- Observe mode never converts broken identity/state into allow.
- No product prevention claim is exposed.

## Excluded

Active local policy denial, final packet fencing, durable remote evidence,
distributed graphing, and response.

## Phase Result

```text
State: Not done.
Validated architecture revision/digest: not recorded.
Completed deliverable IDs: none.
Files and durable owners changed: none.
Upstream-adoption dossier IDs used: none.
Fixture cases and exact physical results: not run.
Commands and exact source state covered: none; this is a plan-only rewrite.
Platform/kernel/runtime manifests: none.
Performance/capacity results: none.
Unsupported/degraded paths: not yet measured.
Remaining work in this phase: all deliverables.
Next phase not authorized: yes.
```
