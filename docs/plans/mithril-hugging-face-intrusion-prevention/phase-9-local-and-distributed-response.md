# Phase 9: Local And Distributed Response

Status: Proposed; depends on Phase 8 `Done`.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)
Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)

## Purpose

Turn a finding into an authenticated, scoped, expiring physical response
transaction that re-resolves every target, discloses blast radius, and verifies
postconditions.

## Design Coverage

Chapters 24-25, 32, and 34; Appendices A.15.4-A.15.6.

## Deliverables

### D9.1 — Response authorization and simulation

Implement typed `ResponseAuthorizationV1` and plan revisions with issuer,
tenant/case/finding, exact target coordinates, permitted operation, expiry,
idempotency, dependencies, expected blast radius, approval requirement, and
physical postconditions. Simulation re-resolves targets and cannot actuate.

### D9.2 — Local node actuators

Implement only approved typed operations: restrict a process/native family,
freeze/kill an exact cgroup lineage, fence/destroy exact sockets/flows, apply an
emergency policy floor, and the approved read-only defender inspection path.
No arbitrary command or PID-only endpoint exists.

### D9.3 — Distributed/Kubernetes actuators

Implement exact workload/object operations only where a supported API provides
authoritative UID/resourceVersion/precondition behavior. Account for
controllers that recreate Pods and for broader workload/cgroup/socket impact.

### D9.4 — Durable transaction lifecycle

Persist `PREPARING`, `AUTHORIZED`, `DISPATCHED`, `APPLIED`, `VERIFYING`, and
terminal response state with idempotent retries, cancellation, expiry,
dependency failure, restart recovery, and one durable owner per transition.

### D9.5 — Blast-radius approval

Compute the actual shared process/native-state/socket/cgroup/workload impact
before authorization. Any operation broader than the requested target requires
explicit approval or returns unsupported; precision of attribution never hides
actuation breadth.

### D9.6 — Physical postcondition and healthy watch

Verify with authoritative readback plus a passive healthy interval. Production
verification never injects hostile actions into the compromised target.
Return only `verified`, `partial`, `failed`, or `unknown` with coverage and
remaining branches.

### D9.7 — HF response increment

Contain the local seed, established flows, distributed child workloads, and
replacement-controller behavior under stale/reused/late/duplicate/failure
variants without damaging unrelated controls.

## Required Tests And Fixtures

`HF-RESP-002`, `HF-RESP-BLAST-RADIUS-003`, response-root inheritance,
stale PID/UID/generation, shared socket/cgroup, controller replacement,
actuator timeout/retry/restart, readback contradiction, and applicable live
two-node response cases.

## Acceptance

- No raw shell, free-form provider call, or stale coordinate can actuate.
- Wider physical impact is calculated and approved before effect.
- Repeated/restarted requests do not duplicate or widen response.
- Verified status requires the named physical postcondition and healthy
  coverage interval.
- Unrelated worker/controller branches remain functional.

## Excluded

AWS/GitHub/mesh/connector-specific actuators, delivered in Phase 10.

## Phase Result

State: Not done.  
Completed deliverables: none.  
Verification: not run; this is a plan rewrite.  
Next phase: not authorized.
