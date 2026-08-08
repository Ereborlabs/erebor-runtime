# How To Manually Accept Phase 9

Status: Proposed runbook; no Phase 9 implementation or test has been run.

Phase: [Local And Distributed Response](../phase-9-local-and-distributed-response.md)  
Setup: [`TWO-NODE`](./environment-setup.md)

## Outcome

Prove that an authenticated, typed response re-resolves its exact target,
discloses and authorizes its real blast radius, survives retry/restart, and
reports success only after an authoritative physical postcondition and healthy
watch. No PID-only, raw-command, or free-form provider response is accepted.

## Automated Companion

```text
IMPLEMENTATION COMMAND REQUIRED: run Phase 9 response authorization,
simulation, local/Kubernetes actuator, transaction recovery, blast-radius,
postcondition, healthy-watch, and live two-node suites.
```

## Procedure

1. Complete the two-node setup and capture the exact task, process, pidfd,
   task-cookie, start-time, cgroup, Pod UID, object UID, resourceVersion, and
   controller generation used by each target.
2. Create a finding and response request, run simulation, and retain the
   re-resolved target set and calculated blast radius without actuating.
3. Authorize only the typed operation and exact target set. Change one target
   coordinate before dispatch in a separate run.
4. Dispatch the operation, restart the owning component at each durable state,
   and repeat the same idempotency key.
5. Inspect the kernel, socket, cgroup, Kubernetes API, and workload state
   directly. Do not use a Mithril event as the physical oracle.
6. Keep a passive healthy watch and prove unrelated worker/controller branches
   continue to function.

## First-Owned Fixture Matrix

| Fixture | Operator stimulus | Required oracle and control |
| --- | --- | --- |
| `HF-GRAN-CAPTURE-001` | attempt to contain a captured/stale process coordinate, then the exact live target | stale or replaced coordinate cannot actuate; exact authorized target reaches its named physical state; unrelated process continues |
| `HF-GRAN-RESPAWN-001` | contain a Pod/process managed by a recreating controller | plan exposes replacement blast radius and follows only the authorized workload/object contract; an unapproved replacement remains an open branch |
| `HF-RESP-002` | contain the local seed, established flow, distributed child, and controller replacement under retry/restart | every advertised branch has an exact verified, partial, failed, or unknown result; unrelated worker/controller remains healthy |
| `HF-RESP-BLAST-RADIUS-003` | request one target whose socket, cgroup, or workload scope is shared | simulation discloses the wider set and dispatch requires explicit approval; rejection causes no physical effect |

## Typed Local Actuator Checks

Run each advertised actuator against an isolated target and a legitimate
control:

| Operation | Required manual proof |
| --- | --- |
| restrict process/native family | new prohibited effect fails for the exact family; unrelated family remains allowed |
| freeze or kill exact cgroup lineage | exact cgroup task state changes; sibling cgroup continues |
| fence/destroy exact socket or flow | exact flow stops or cannot transmit; unrelated flow remains healthy |
| emergency policy floor | only the signed bounded floor becomes active and its generation reads back |
| defender inspection | operation is read-only, scoped, audited, and creates no arbitrary command path |

For `TerminateProcessPidfd`, capture the pidfd and all bindings before the
request. The actuator must revalidate the same pidfd, task cookie, start time,
and cgroup, send `SIGKILL` through that pidfd, and wait for that exact process.
Only then may it return `PROCESS_STOPPED_VIA_PIDFD`. An `ESRCH` result passes
only when the same pidfd proves the target was already gone; a PID-reuse or
replacement branch remains open.

## Kubernetes And Transaction Fault Matrix

Repeat a representative local and Kubernetes response with:

- changed Pod/object UID, resourceVersion, controller generation, PID, pidfd,
  task cookie, start time, and cgroup;
- duplicate dispatch, timeout before/after actuation, late result, cancellation,
  expiry, dependency failure, and owner restart at every durable state;
- readback contradiction and healthy-watch coverage loss; and
- a controller that recreates the target after the original postcondition.

The response must not duplicate or widen its effect. A stale Kubernetes
precondition must fail closed. `verified` is valid only when the exact named
postcondition and healthy interval are present; otherwise the result is
`partial`, `failed`, or `unknown` with remaining branches.

## Required Artifacts And Pass Rule

Retain authorization and simulation revisions, exact target coordinates,
blast-radius calculations/approvals, transaction state history, actuator and
authoritative readback envelopes, pidfd/wait evidence, Kubernetes object
preconditions, fault records, healthy-watch coverage, unrelated-control
results, and the sealed case bundle. All four exact fixtures and every
advertised actuator must agree with their physical oracle.

## Troubleshooting

- A process event after `SIGKILL` is not exit confirmation; inspect the exact
  pidfd wait result.
- Deleting one Pod is not workload containment when its controller recreates
  it; report the replacement branch unless it was explicitly authorized.
- If readback cannot distinguish replacement from the original target, return
  `unknown`; do not infer success from a dispatch acknowledgment.

