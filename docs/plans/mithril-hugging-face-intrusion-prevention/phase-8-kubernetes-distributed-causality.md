# Phase 8: Kubernetes Distributed Causality

Status: Not started.

Master plan: [Mithril Hugging Face Intrusion Prevention](./README.md)

## Purpose

Connect independently proven node-local process trees through authoritative
Kubernetes request, object, controller, scheduler, and CRI identities without
fabricating remote process parentage.

## Depends On

Phase 7 must be `Done`. Kubernetes audit and object-history read permissions,
source deployment, tenant/cluster binding, retention, and Secret-body exclusion
must receive explicit approval.

## Phase Scope

### Kubernetes Sources

Implement connectors under the Phase 0-approved Mithril Control tree:

```text
src/connectors/kubernetes/
  mod.rs
  audit.rs
  object_history.rs
  rbac_inventory.rs
  source_coverage.rs
  redaction.rs
```

Support explicit audit deployment paths:

- managed-cluster audit from provider logging;
- API-server audit webhook; and
- self-managed audit files collected by the same `mithril-node` on relevant
  control-plane nodes.

A normal Kubernetes watch is not called audit.

The audit connector preserves:

- cluster/authority identity;
- audit ID, stage, user/groups, source addresses;
- verb, URI, API group/resource/subresource;
- namespace/name plus exact object UID when available;
- result code/status;
- request/response object metadata needed for UID/resourceVersion joins; and
- source cursor/delivery/coverage.

It never retains Secret or TokenRequest response bodies.

The object-history connector records UID/resourceVersion live intervals,
owner-reference UIDs, controller state, scheduler binding/node assignment, Pod
UID, and watch/relist coverage. It does not collect Secret/ConfigMap bodies for
lineage.

### Effective Authority Inventory

Use authorized `SubjectAccessReview`/`SelfSubjectAccessReview` and binding
inventory to create `ExistingAuthorityExposure` facts for the current worker,
controller, CSI, and node principals:

- privileged/host-mounted workload writes;
- ServiceAccount token minting;
- Secret get/list/watch;
- exec/attach/ephemeral container;
- RBAC bind/escalate/impersonate;
- admission/webhook, CSR, node proxy, and workload identity; and
- review error/coverage.

This is deployment truth, not a claim Mithril removed permission.

### Typed Distributed Graph

Implement immutable:

- `SubjectRef`;
- `CausalEdge`;
- `DistributedLineageView`; and
- graph version/open-branch/contradiction state.

At minimum support:

```text
process_issued_api_request
api_request_created_or_mutated_resource
object_triggered_controller_reconcile
controller_reconcile_changed_resource
controller_owns_resource
pod_bound_to_node
container_started_for_pod
```

The direct Kubernetes path is:

```text
node 1 Linux process/socket
  → Kubernetes audit request ID
  → exact object UID
  → controller/reconcile or owner UID evidence
  → exact Pod UID and object version
  → scheduler binding
  → full CRI container ID
  → node 2 independently observed root process
```

Each arrow retains joining fields, raw observation IDs, proof class, time
interval, source coverage, and missing proof. Names, labels, selectors, source
IP, ServiceAccount name, and timestamps alone remain contextual.

### Deterministic Expansion

Implement `HF-XNODE-001` as bounded package state, not a universal recursive
graph query:

- tenant/authority/depth/edge/time bounds;
- one branch per exact object/Pod/native subject;
- idempotent retries/duplicates;
- fan-out and controller replacement;
- late/contradictory evidence creating new versions;
- outside-authority subjects; and
- response eligibility only for direct, revalidatable subjects.

The distributed lineage ID is a correlation handle, never a BPF target.

## Hugging Face Test Increment

Implement:

- the full `HF-XNODE-001` two-node path;
- dangerous workload and Secret API audit with actual result;
- controller/CSI/node authority exposure inventory;
- Deployment, DaemonSet, Job, and custom-controller fan-out;
- same-name deletion/recreation;
- ReplicaSet acquisition remaining contextual without stronger proof;
- concurrent same-ServiceAccount/source-IP workloads;
- each bridge source removed one at a time;
- audit delivered late and out of order; and
- unrelated OpenAI/external and Hugging Face authority domains never merging.

No response executes in this phase.

## Code-Backed Tests

- Kubernetes audit schema/stage/redaction/cursor and source-coverage tests;
- object watch, resourceVersion, relist/compaction, UID reuse, owner reference,
  binding, deletion/recreation, and fan-out tests;
- RBAC review allowed/denied/evaluation-error and aggregated-role changes;
- every typed edge direct/derived/contextual/contradicted rule;
- rejection of cross-node/cross-Pod `parent_process`;
- graph edge dedupe, late version, merge, split, contradiction, open branch,
  and outside-authority behavior;
- missing audit/object/owner/binding/CRI/root negative matrix;
- exact two-node live path and fixture replay;
- tenant/cluster identity collision and forged payload binding;
- response eligibility excludes contextual/ambiguous subjects; and
- scale budgets for audit rate, controller fan-out, graph expansion, and late
  recomputation.

## Live Probe

Run Probe D in full and with each bridge removed. Probe C must use real
Kubernetes audit. Retain raw source, coverage, edge, and lineage-version
artifacts.

## Checkpoint

Run the common repository gates, Kubernetes source/redaction/coverage tests,
typed-edge and graph-version property tests, every missing-bridge negative
case, and the live two-node Probe D. Compare replay and live lineage results.

## Acceptance

- Kubernetes audit and object history are authenticated, durable, redacted, and
  coverage-aware;
- existing effective authority is reported without mutation;
- no remote Linux process is represented as a native child;
- every direct cross-node edge has an authoritative stable identifier;
- names/labels/IP/time remain contextual;
- fan-out produces one exact branch per object/Pod/native subject;
- late/contradictory evidence creates immutable new versions;
- a missing bridge produces a named open branch and removes direct response
  eligibility;
- the live two-node fixture reconstructs every supported bridge;
- unrelated authority domains never merge; and
- graph latency/scale remain within approved budgets.

## Explicit Stop Point

Stop after distributed correlation passes. Do not terminate processes, fence
remote nodes, mutate controllers, or call provider APIs until the user approves
Phase 9's typed response classes, credentials, blast-radius rules, and
postconditions.

## Phase Result

State: Not started.

Record source deployment/RBAC, schemas, redaction, exact graph packages, live
edge evidence, missing-source matrix, scale results, gaps, and final state.
