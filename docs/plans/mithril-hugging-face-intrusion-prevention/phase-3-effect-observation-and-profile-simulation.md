# Phase 3: Effect Observation And Profile Simulation

Status: Proposed; depends on Phase 2 `Done`.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)
Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)

## Purpose

Implement the complete source-policy compiler and observe-only local effect
model. Prove that every future deny is paired with the real actor, object,
hook, state, and physical result before enabling policy enforcement.

## Design Coverage

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
`/work/input/job-42/config.json` target.

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
decisions for all allocated local `HF-009` through `HF-012` effects without
changing application behavior or claiming prevention.

## Required Tests And Fixtures

- Policy/config/generation goldens and exact-conflict/exception tests.
- Observe instances of all Phase 4/5 effect fixtures in Appendix C.
- `MOUNT-SNAPSHOT-004`, path bind/rename/link/mount ambiguity variants,
  `FILE-IDENTITY-001`, `MEM-EXEC-001`, `DEVICE-DERIVED-001`, and network
  attribution controls.
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

State: Not done.  
Completed deliverables: none.  
Verification: not run; this is a plan rewrite.  
Next phase: not authorized.
