# How To Manually Accept Phase 8

Status: Proposed runbook; no Phase 8 implementation or test has been run.

Phase: [Kubernetes Distributed Causality](../phase-8-kubernetes-distributed-causality.md)  
Setup: [`TWO-NODE`](./environment-setup.md)

## Outcome

Prove `HF-XNODE-001` only through authenticated Kubernetes/runtime bridges and
physically reject or restrict the attacker-created privileged/unmatched
workload branch without inventing process ancestry or purpose.

## Automated Companion

```text
IMPLEMENTATION COMMAND REQUIRED: run Phase 8 Kubernetes source/coverage,
graph edge, fan-out/reuse/contradiction, admission/node-floor, purpose matrix,
HF-XNODE, and live two-node suites.
```

## Procedure

1. Complete the environment preflight and record different boot IDs for both
   workers.
2. Run the full runtime entry matrix on each advertised runtime configuration.
3. In an allowed-source variant, create an isolated owner object on node A and
   a child Pod scheduled to node B.
4. Inspect request/audit/object/controller/scheduler/Pod/container/root bridges
   and remove each one in separate runs.
5. Attempt privileged/hostPath/host-namespace/capability/device/unresolved-root
   objects through validating admission and the node hard floor.
6. Run exact signed bounded exceptions at N/N+1, expiry, concurrency, and
   restart.

## First-Owned Fixture Matrix

| Fixture | Operator stimulus | Required oracle and control |
| --- | --- | --- |
| `EDGE-K8S-SHARED-002` | two concurrent local actors share ServiceAccount while one creates object | object/API result exact; local task edge contextual unless unique proof; legitimate controller action succeeds |
| `HF-GRAN-CLUSTER-SHARED-001` | use one credential in two isolated clusters | each cluster operation exact; local cause remains contextual without per-request ID |
| `HF-GRAN-HOSTPATH-001` | submit harmless privileged/hostPID/host-root mount equivalent | admission rejects before persistence or qualified node floor restricts covered host effects; exact CSI/agent control succeeds |
| `NODE-FLOOR-EXCEPTION-002` | submit exact signed exception with expiry/uses, then mismatched/concurrent/N+1 variants | only matching bounded operation consumes; no generic privileged bypass; approved fixture succeeds within bound |
| `XNODE-PRIVILEGED-POD-001` | create isolated privileged child workload from node-A authority branch | physical API/runtime/workload absence or exact restricted-root result; no audit-only prevention claim |

## Exact Entry-Matrix Rerun

| Fixtures | Manual focus |
| --- | --- |
| `ENTRY-BINDING-GAP-001`, `ENTRY-START-001`, `ENTRY-STOCK-HOOK-FAILURE-002` | first-effect behavior when admission/binding evidence is missing or fails |
| `ENTRY-CONTAINERS-001`, `ENTRY-EPHEMERAL-001` | independent roots despite Pod/shared namespaces/resources |
| `ENTRY-EXEC-001`, `ENTRY-EXEC-002`, `ADMIN-EXEC-APPROVAL-001` | ordinary restricted external roots versus complete approved admin flow |
| `ENTRY-EXTERNAL-AMBIGUITY-001`, `ENTRY-PROBE-001`, `ENTRY-PROBE-002`, `ENTRY-PROBE-IMPERSONATION-003` | identical argv/TTY/timing never invents purpose |
| `ENTRY-NETPROBE-001`, `ENTRY-SLEEP-001` | network probe/lifecycle facts do not invent workload tasks |
| `ENTRY-POSTSTART-001`, `ENTRY-POSTSTART-002`, `ENTRY-PRESTOP-001` | lifecycle ordering/restart/containment cannot merge or widen roots |
| `ENTRY-LOSS-001`, `ENTRY-MIGRATE-001`, `ENTRY-RESTART-001`, `ENTRY-REUSE-001` | loss, movement, restart, and reuse remain conservative |

Each ID uses its full Phase 2 procedure; grouping here does not merge results.

## `HF-XNODE-001` Bridge Checklist

The operator must retain and inspect:

```text
node-A task/socket/credential fact
Kubernetes request proof or contextual boundary
audit ID and authoritative API result
object UID/resourceVersion
controller/owner/scheduler chain
Pod UID and node binding
node-B full container ID/runtime admission
node-B entry and Linux execution
```

Remove each bridge one at a time. The missing bridge must become a named open
branch. No graph revision may use a cross-node native parent edge.

## Required Artifacts And Pass Rule

Retain Kubernetes audit/object/watch/scheduler/admission/runtime envelopes,
source coverage, graph revisions, two-node manifests, entry matrix results,
API/object/workload physical results, exception receipts, and live-probe
bundle. Pass requires an exact or explicitly weaker cross-node result and a
physical privileged/unmatched branch result.

## Troubleshooting

- Kind on one host cannot prove independent node boot/root ownership.
- Kubernetes audit proves an API actor/result, not the originating Linux task.
- If neither admission nor runtime rejects mount setup, report only the exact
  BPF node-floor effects it actually prevents.
