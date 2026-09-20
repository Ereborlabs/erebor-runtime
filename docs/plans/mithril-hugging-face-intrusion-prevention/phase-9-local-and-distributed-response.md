# Phase 9: Local And Distributed Response

Status: Proposed; depends on Phase 8 `Done`.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)
Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
Manual acceptance: [Phase 9 runbook](./manual-testing/phase-9-manual-acceptance.md)  
Environment setup: [shared setup guide](./manual-testing/environment-setup.md)

## Purpose

Turn a finding into an authenticated, scoped, expiring physical response
transaction that re-resolves every target, discloses blast radius, and verifies
postconditions.

## Scope And Design Coverage

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
No arbitrary command or PID-only endpoint exists. `TerminateProcessPidfd`
requires the exact pidfd/task-cookie/start-time/cgroup binding, sends `SIGKILL`
through the revalidated pidfd, and returns `PROCESS_STOPPED_VIA_PIDFD` only
after `waitid` confirms that exact process exited. `ESRCH` is success only when
the same pidfd proves the target was already gone; replacement branches remain
open.

### D9.3 — Distributed/Kubernetes actuators

Implement exact workload/object operations only where a supported API provides
authoritative UID/resourceVersion/precondition behavior. Account for
controllers that recreate Pods and for broader workload/cgroup/socket impact.

### D9.4 — Durable transaction lifecycle

Use the state names in validated Chapter 24 and Appendix A.15.4:

```text
PROPOSED -> AUTHORIZED -> REVALIDATING -> APPLYING -> VERIFYING -> WATCHING
  -> VERIFIED | PARTIAL | FAILED | UNKNOWN | EXPIRED | CANCELLED
```

Persist each compare-and-swap transition with prior revision, principal,
reason, deadline, and per-action idempotency key. Retain applied effects during
cancellation or expiry. Recover unknown dispatch results at the actuator before
retry. ResponseCoordinator is the only plan-state writer; console and agent
tools consume the same state, not translated copies.

Bind the originating finding/graph revision and any supporting assessment
references. Publish committed result revisions to the shared Control read
projection. A replacement or late branch creates a new authorized plan revision;
it cannot widen the prior approval or change that plan's frozen scope.

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

Implement the local and Kubernetes portions of `HF-021`: contain the local
seed, established flows, distributed child workloads, and replacement-
controller behavior under stale/reused/late/duplicate/failure variants without
damaging unrelated controls. Provider-specific completion remains Phase 10.

## Agent and console integration

Follow the [combined Araphor order](../araphor-discovery-engine/README.md#combined-implementation-order).
Implement and test ResponseCoordinator and local/Kubernetes actuators before
exposing `plan_response` and `execute_response` through the existing
ConsoleHttpOwner and stdio MCP adapter. This phase owns that wiring; it is not
unfinished Discovery 5 work. Reuse the shared types, principal/grant checks,
finding references, and read projection.

Extend the existing investigation view with frozen targets, blast radius,
authorization, per-action state, readback, and open replacement branches.
Query/follow returns the same committed revisions to agents and the console.
No additional job-query API or client-owned response state is required.
Keep provider actions Unsupported until their Phase 10 qualification.

Run the Discovery 6 query/authorization/local-defender cases with real response
owners. Add revoked grants, stale findings, lost execution replies, concurrent
approval, PID/UID reuse, Control/client restart, and late replacement branches.
Require matching lightweight and physical state transitions, postconditions,
and healthy-watch results. A policy activation, process exit, or successful
tool reply cannot substitute for these response proofs.

## Checkpoint

An authorized finding drives only typed, exactly re-resolved local/Kubernetes
actions; every terminal result includes blast-radius approval and authoritative
postcondition plus healthy-watch evidence. Provider actuation remains absent.

## Required Tests And Fixtures

`HF-GRAN-CAPTURE-001`, `HF-GRAN-RESPAWN-001`, `HF-RESP-002`, and
`HF-RESP-BLAST-RADIUS-003`; response-root inheritance, stale PID/pidfd/task
cookie/start-time/cgroup and UID/generation, shared socket/cgroup, controller
replacement, actuator timeout/retry/restart, readback contradiction, and
applicable live two-node response cases.

## Acceptance

- No raw shell, free-form provider call, or stale coordinate can actuate.
- Wider physical impact is calculated and approved before effect.
- Repeated/restarted requests do not duplicate or widen response.
- Console and local defender reopen the same response revision after client or
  Control restart. Dropped replies cannot duplicate an action or hide a late branch.
- Verified status requires the named physical postcondition and healthy
  coverage interval.
- Unrelated worker/controller branches remain functional.

## Excluded

AWS/GitHub/mesh/connector-specific actuators, delivered in Phase 10.

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
Unsupported/degraded paths: provider-specific response remains Phase 10.
Remaining work in this phase: all deliverables.
Next phase not authorized: yes.
```
