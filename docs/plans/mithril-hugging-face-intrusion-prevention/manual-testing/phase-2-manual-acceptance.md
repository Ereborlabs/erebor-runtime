# How To Manually Accept Phase 2

Status: Proposed runbook; no Phase 2 implementation or test has been run.

Phase: [Exact Native Identity](../phase-2-exact-native-identity.md)  
Setup: [`SINGLE-NODE`](./environment-setup.md)

## Outcome

Prove exact task/process/execution/native-family and runtime-root identity exists
before a protected effect and cannot be recovered through command equality,
restart, reparenting, movement, or identifier reuse.

## Automated Companion

```text
IMPLEMENTATION COMMAND REQUIRED: run Phase 2 task-storage, fork/clone/vfork,
exec/PONR, runtime-entry, replay, reference, restart, reuse, race, and
first-protected-effect suites.
```

The harness must generate concurrency and pre-wake timing. The operator reviews
the task/process/entry state transitions and physical first-effect result.

## Procedure

1. Start the unchanged worker, legitimate controller, and all configured
   initial/init/sidecar roots.
2. Create native children, threads, vfork children, external runtime roots,
   probes, lifecycle actions, and administrative-exec candidates with identical
   executable/argv variants.
3. Inspect task labels, process state, execution IDs, native-family state,
   entry classification, cgroup binding, and coordinate-finalization history.
4. Inject fork/exec allocation failures, concurrent exec, movement, metadata
   loss, restarts, and identifier reuse.
5. Attempt a harmless protected read from every incomplete/ambiguous task and
   inspect the fail-closed physical result.

## Entry Fixture Matrix

| Fixture | Operator action | Required oracle and legitimate control |
| --- | --- | --- |
| `ENTRY-BINDING-GAP-001` | delay/drop binding before first protected effect | unresolved effect denies and gap is recorded; qualified initial binding succeeds |
| `ENTRY-CONTAINERS-001` | run init, native sidecar, app, and shared-volume/network cases | independent execution sets remain distinct; declared sharing works through explicit relationships |
| `ENTRY-EPHEMERAL-001` | add an ephemeral container sharing PID namespace | new independent root/profile; shared namespace does not merge lineage |
| `ENTRY-EXEC-001` | run TTY/non-TTY `kubectl exec` and copy shape | restricted external root unless approved path completes; normal app child remains native |
| `ENTRY-EXEC-002` | run `crictl exec` with probe-identical argv | restricted external root, never fabricated probe purpose |
| `ENTRY-EXTERNAL-AMBIGUITY-001` | create indistinguishable external purposes concurrently | same permission intersection/restricted class; no timing/argv split |
| `ENTRY-LOSS-001` | drop runtime, audit, and entry evidence independently | protected unknown remains restricted and coverage reflects each loss |
| `ENTRY-MIGRATE-001` | move unlabeled/labeled tasks across protected cgroups/namespaces | movement never grants or clears task-first authority; valid placement control remains allowed |
| `ENTRY-NETPROBE-001` | run HTTP/TCP/gRPC probes | no fake in-container process root; application receive and host flow remain distinct |
| `ENTRY-POSTSTART-001` | race `PostStart` and entrypoint in both orders | initial and external roots remain distinct |
| `ENTRY-POSTSTART-002` | restart kubelet and repeat `PostStart` | fresh task/lifetime identity with same restricted budget; no stale reuse |
| `ENTRY-PRESTOP-001` | terminate during active restriction | cleanup cannot regain authority; approved safe cleanup control follows policy |
| `ENTRY-PROBE-001` | run concurrent startup/readiness/liveness exec probes | stock purpose remains unknown/restricted; qualified evidence only if interface supplies it |
| `ENTRY-PROBE-002` | app child runs identical probe bytes/cadence | native child keeps application lineage and cannot impersonate external root |
| `ENTRY-PROBE-IMPERSONATION-003` | race native child, probe, admin, and direct runtime roots with identical argv/TTY | only native creation or complete approval changes authority; ordinary identical roots stay restricted |
| `ENTRY-RESTART-001` | restart runtime, kubelet, and node during binding | live reconciliation opens exact gaps and reuses no stale role |
| `ENTRY-REUSE-001` | reuse PID, namespace, cgroup path/ID, Pod/container name | new cookies/nonces/live intervals prevent old authority/response attachment |
| `ENTRY-SLEEP-001` | execute lifecycle sleep action | lifecycle fact only; no invented process entry when no task exists |
| `ENTRY-START-001` | delay/drop configured start-hook metadata | first unresolved protected effect denies; measured start gap remains explicit |
| `ENTRY-STOCK-HOOK-FAILURE-002` | fail/timeout/mismatch the configured stock hook | exact documented failure result; no held-task or purpose claim |

## Native Identity Fixture Matrix

| Fixture | Operator action | Required oracle and legitimate control |
| --- | --- | --- |
| `AUTHORIZATION-REPLAY-004` | replay, retarget, expire, reboot, and mismatch signed authorization | every invalid envelope rejects; fresh exact envelope consumes according to contract |
| `EXEC-COMMIT-STATE-001` | run success, pre-PONR failure, and post-PONR fatal/unknown exec | success commits once; early failure keeps exact prior state; later failure never restores broad authority |
| `EXEC-CONCURRENT-002` | race execs across threads/non-leader de-threading | one serialized valid transition; no mixed image/role state |
| `ID-CGROUP-ESCAPE-001` | move a labeled task to host/unprotected placement | task storage still resolves and denies mismatch; unmoved allowed control works |
| `ID-CLONE-CGROUP-002` | clone into expected and changed placement | child state exists before effect and placement is verified |
| `ID-CLONE-CGROUP-FAIL-003` | force child allocation/finalization/placement failure | no unlabeled runnable child gains authority; normal clone succeeds |
| `ID-CREATOR-PARENT-007` | reparent/orphan child after native creation | immutable creator edge stays exact while real-parent interval changes |
| `ID-MOVED-PARENT-FORK-004` | move parent, then fork | child inherits actual task authority and placement floor, not cgroup-derived role |
| `ID-MOVED-TASK-EXEC-005` | move labeled task, then exec | task-first old identity and placement mismatch constrain transition |
| `ID-TASK-COORD-FINALIZE-006` | inspect task at allocation, pre-wake finalization, visibility, and exit | opaque state precedes effect; PID/TGID/start coordinates finalize later without granting permission |
| `NATIVE-STATE-REF-LIFETIME-001` | exit tasks/processes while sockets/objects/generations remain referenced | exact references/tombstones retain restrictions until final qualified release |
| `STATE-FORK-IPC-002` | fork with inherited IPC/file/socket state | native state inheritance is exact; communication does not merge independent roots |
| `STATE-THREAD-RACE-001` | race threads changing/using process and native restrictions | atomic monotonic result; no thread recovers earlier authority |

## Administrative Identity Partial Gate

Run the identity half of `ADMIN-EXEC-APPROVAL-001`: target node/container,
entry class, optional claim-slot identity, expiry, and replay state must bind.
Do not mark the fixture complete until Phase 4 proves Control approval,
admission, atomic consumption, exec commit, and physical effect behavior.

## Required Artifacts And Pass Rule

Retain per-task state traces, coordinate histories, entry/runtime facts,
authorization verification, cgroup/runtime manifests, failure injection logs,
and first-effect syscall results. Pass requires exact or conservative state
before every protected effect and zero command/timing/TTY-based role grants.

## Troubleshooting

- Missing PID fields at `task_alloc` are expected; missing preallocated
  fail-closed state is not.
- A task visible before coordinate finalization remains restricted; do not
  repair authority from userspace PID lookup.
- If stock CRI omits purpose, preserve `UNKNOWN` rather than adding heuristics.
