# Phase 8: Kubernetes Distributed Causality

Status: Proposed; depends on Phase 7 `Done`.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)
Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
Manual acceptance: [Phase 8 runbook](./manual-testing/phase-8-manual-acceptance.md)  
Environment setup: [shared setup guide](./manual-testing/environment-setup.md)

## Purpose

Join authenticated Kubernetes/runtime facts to node evidence, represent
cross-node causality without fake process ancestry, and close the attacker-
created privileged workload branch required for the full HF claim.

## Scope And Design Coverage

Chapters 7-8, 23, 25, and 30-31; Appendices A.9-A.10 and A.15.3.

## Deliverables

In the [combined Araphor order](phase-7-mithril-control-and-detection-packages/README.md#combined-implementation-order),
start after the bounded Phase 7.7 release. The existing query, assessment,
console, and policy workflow are inputs, not work to repeat.

### D8.1 — Kubernetes source adapters and coverage

Enrich the Phase 6.2 object, scheduler-binding, admission, runtime, and
node-binding facts with authenticated audit and object history. Preserve
source-specific IDs, actors, resource UID/resourceVersion, request/result,
timestamps, gaps, and proof quality. Do not invent probe/lifecycle purpose
missing from stock CRI. Extend the Phase 6.2 Kubernetes client and
source-coverage family. Do not create another policy desired-state owner,
rollout owner, graph owner, or uncoordinated object-watch cursor.

### D8.2 — Kubernetes graph contracts

Implement registered edges for API request to object revision, controller/
owner reference, scheduler binding, Pod/container/cgroup/runtime root, and node
observation. Preserve fan-out, retries, replacement controllers, deletion,
name reuse, late events, and contradictions as explicit branches.

### D8.3 — Cross-node causal package

Complete `HF-XNODE-001` from a credential/API action on node A to a workload
root/effect on node B. Shared ServiceAccount or timing remains shared-principal/
context unless exact request/object/binding identifiers close the join.

### D8.4 — Complete unmatched-workload and privileged-root floor

Extend the Phase 6.2 admission, retained containerd runtime gate, and BPF
incident floor from the exact hostile OCI shape to the complete
architecture-approved typed runtime matrix for privileged mode, host namespaces, dangerous
capabilities, hostPath/devices, unsafe security settings, and unresolved
roots. Normal OCI setup remains runtime-owned. Add signed, exact, expiring,
bounded-use, physically consumed, and separately audited exceptions.

### D8.5 — Root-purpose truth matrix

Qualify initial containers, init/native sidecars, probes, lifecycle, ordinary
and approved admin exec, `crictl exec`, ephemeral containers, moved/unmatched
tasks, and direct runtime roots with identical commands. Kubernetes audit
identifies API actors where available but never retroactively grants a task
role.

### D8.6 — HF multi-node proof

Prove the node-A-to-node-B privileged Pod/fan-out branch is rejected at an
advertised admission/node floor or reported with the exact weaker result. A
denial must have API/runtime/physical workload-absence or restricted-root
oracle, not only an audit event.

## Agent and console integration

After the source and graph owners pass their tests, add the new committed
records to the existing discovery context and query views. Preserve exact
request/object/binding references, cross-node branches, and coverage gaps.
Extend the existing investigation screens; add no separate incident store.

Add `request_exception(grant_id, target, bounds, reason)` through the shared
HTTP/MCP contract after the existing exception owner has a qualified public
request/approval method. The first adapter requests an exact precompiled
bounded file grant. It cannot create a privileged-root exception, approve
itself, or infer authority from an assessment. Keep D8.4's separately signed
privileged exceptions distinct. Bind requests to target, use count, expiry,
reviewer, and revocation state; follow the existing owner's result through
query. Reuse policy/exception reconciliation, not an agent-owned signer.

This phase owns the adapter, console review, and tests. Require tenant and
grant rejection, stale-target rejection, duplicate/lost-reply recovery,
independent approval, physical use-count consumption, expiry, and revocation.
Run the paired lightweight and physical cases with the same owner APIs.
Keep response execution unavailable until Phase 9. Do not mark this combined
increment Done with only graph schemas or an exception-request receipt.

## Checkpoint

`HF-XNODE-001` replays byte-identically from authenticated Kubernetes/runtime
facts, and the privileged/unmatched workload branch has a measured physical
admission or node-floor result on the two-node fixture.

## Required Tests And Fixtures

- `EDGE-K8S-SHARED-002`, `HF-GRAN-CLUSTER-SHARED-001`,
  `HF-GRAN-HOSTPATH-001`, `NODE-FLOOR-EXCEPTION-002`, and
  `XNODE-PRIVILEGED-POD-001`.
- Rerun the exact Phase 2 entry matrix: `ENTRY-BINDING-GAP-001`,
  `ENTRY-CONTAINERS-001`, `ENTRY-EPHEMERAL-001`, `ENTRY-EXEC-001`,
  `ENTRY-EXEC-002`, `ENTRY-EXTERNAL-AMBIGUITY-001`, `ENTRY-LOSS-001`,
  `ENTRY-MIGRATE-001`, `ENTRY-NETPROBE-001`, `ENTRY-POSTSTART-001`,
  `ENTRY-POSTSTART-002`, `ENTRY-PRESTOP-001`, `ENTRY-PROBE-001`,
  `ENTRY-PROBE-002`, `ENTRY-PROBE-IMPERSONATION-003`, `ENTRY-RESTART-001`,
  `ENTRY-REUSE-001`, `ENTRY-SLEEP-001`, `ENTRY-START-001`, and
  `ENTRY-STOCK-HOOK-FAILURE-002`; also rerun
  `ADMIN-EXEC-APPROVAL-001` for the approved administrative path.
- Kubernetes fan-out/reuse/contradiction variants and the complete live
  two-node lifecycle probe. `EDGE-MESSAGE-CONSUMER-006` is owned by Phase 10,
  not silently treated as Kubernetes evidence.

## Acceptance

- Cross-node edges use authoritative object/request/binding facts, never
  process parentage or time alone.
- Stock CRI ambiguity remains conservative under identical commands.
- Privileged/unmatched branches receive a physical rejection/restriction or an
  explicit unsupported result.
- Controller replacement and object/name/IP reuse cannot hide or retarget a
  branch.
- Legitimate controllers and ordinary workload scheduling still work.

## Excluded

Provider-specific audit semantics and response actuation.

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
