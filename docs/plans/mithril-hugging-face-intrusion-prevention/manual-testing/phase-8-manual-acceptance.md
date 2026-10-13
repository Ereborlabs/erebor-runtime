# Platform Tests For Phase 8

Status: Required platform test coverage.

Phase: [Kubernetes Distributed Causality](../phase-8-kubernetes-distributed-causality.md)  
Setup: [`TWO-NODE`](./environment-setup.md)

## Outcome

Prove `HF-XNODE-001` only through authenticated Kubernetes/runtime bridges and
physically reject or restrict the attacker-created privileged/unmatched
workload branch without inventing process ancestry or purpose.

## Test implementation

Implement the behaviors below as small Rust scenarios in `crates/mithril-e2e`.
Follow the [scenario maintainability rules](../../../../crates/mithril-e2e/SCENARIO_MAINTAINABILITY_TODO.md#binding-acceptance-rules)
and the shared [platform test requirements](README.md#platform-test-shape).
Use the applicable platform cases from one test body. Keep the production
calls, action, assertions, and cleanup visible. The steps below specify Rust
test behavior; they are not a separate manual acceptance procedure.

## Scenario requirements

Require the bounded Phase 7.10 result before this procedure. Use installed
analysis packages for the graph checks. Recorded-input package results do not
replace live Kubernetes source or two-node proof.

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
7. Request a precompiled bounded file grant through the shared native gRPC
   client and gRPC-Web console. Verify independent approval, use-count
   consumption, expiry, revocation, and duplicate or lost replies. Test stdio
   MCP only if advertised. Keep this request separate from the signed
   privileged exceptions in step 6; it cannot create or approve them.

## First-Owned Fixture Matrix

| Fixture | Rust test action | Required oracle and control |
| --- | --- | --- |
| `EDGE-K8S-SHARED-002` | two concurrent local actors share ServiceAccount while one creates object | object/API result exact; local task edge contextual unless unique proof; legitimate controller action succeeds |
| `HF-GRAN-CLUSTER-SHARED-001` | use one credential in two isolated clusters | each cluster operation exact; local cause remains contextual without per-request ID |
| `HF-GRAN-HOSTPATH-001` | submit harmless privileged/hostPID/host-root mount equivalent | admission rejects before persistence or qualified node floor restricts covered host effects; exact CSI/agent control succeeds |
| `NODE-FLOOR-EXCEPTION-002` | submit exact signed exception with expiry/uses, then mismatched/concurrent/N+1 variants | only matching bounded operation consumes; no generic privileged bypass; approved fixture succeeds within bound |
| `XNODE-PRIVILEGED-POD-001` | create isolated privileged child workload from node-A authority branch | physical API/runtime/workload absence or exact restricted-root result; no audit-only prevention claim |

## Exact Entry-Matrix Rerun

| Fixtures | Required assertions |
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

The Rust test must retain and assert these links:

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

## Execution and results

Map each required case to its exact Rust test name, platform, and lifecycle.
Document its command and expected result under the shared
[command contract](README.md#command-contract).

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
