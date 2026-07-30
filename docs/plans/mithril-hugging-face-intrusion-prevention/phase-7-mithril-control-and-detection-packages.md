# Phase 7: Mithril Control And Detection Packages

Status: Not started.

Master plan: [Mithril Hugging Face Intrusion Prevention](./README.md)

## Purpose

Create the central evidence, coverage, fleet, node-graph, deterministic
detection, investigation, profile-distribution, and authorization owner.

This phase proves the local Hugging Face credential/authority pivot packages.
It does not yet create cross-node Kubernetes causal edges or execute response.

## Depends On

Phase 6 must be `Done`, with durable node evidence, source identity, coverage
intervals, replay, and recovery.

## Phase Scope

### Service Ownership

Create the Phase 0-approved equivalent of:

```text
crates/mithril-control/src/
  main.rs
  lib.rs
  error.rs
  config.rs
  auth.rs
  intake/
  evidence/
  coverage/
  fleet/
  graph/
  detection/
  profiles/
  investigation/
  response/
  api/
```

`response/` in this phase owns request schemas, authorization/simulation
boundaries, and immutable state transitions only. It invokes no actuator.

### Authenticated Intake And Raw Evidence

Implement:

- node/source mTLS identity bound to tenant, cluster, node, and allowed source;
- append-only raw `SourceEnvelope` storage;
- hash and schema validation;
- unique source boot/sequence identity;
- acknowledgement of highest contiguous durable sequence;
- idempotent retries;
- out-of-order and clock-skew metadata;
- raw-object and normalized-row transactional linkage; and
- source capability/coverage ingestion.

An observation whose raw source object is missing or hash-invalid cannot enter
correlation.

### Evidence Objects

Keep these independently queryable:

- `SourceEnvelope`;
- `Observation`;
- `CoverageInterval`;
- native graph nodes/edges;
- later `CausalEdge`;
- `DistributedLineageView`;
- `Finding`;
- `DeploymentRiskFinding`;
- `HardeningProposal`;
- `Case`;
- `ResponseRequest`; and
- later `ResponseExecution`.

A case or model summary cannot mutate raw evidence, findings, or response
authorization.

### Node-Local Graph

Materialize the exact Phase 2 task/process/execution/effect graph from raw
observations. Rebuild it deterministically from a clean derived store and
compare digests. Tenant, cluster, node boot, label epoch, container, Pod,
cgroup, and policy generations must never cross-bind.

### Detection Package Runtime

Implement bounded deterministic packages with:

- versioned content/artifact digest;
- required source schemas and coverage;
- state key and bounded windows;
- typed predicates;
- direct/contextual/contradicted evidence;
- lateness and finding versioning;
- stable finding identity;
- replay corpus; and
- suggested response class with no authority.

Implement:

1. `HF-PROC-001` for attached native graph/effect deviations; and
2. `HF-DW-001` for credential access, authority channel, and Kubernetes/cloud
   authority behavior deviations.

Until Phase 8 sources exist, use schema-valid replay/live test audit input for
the semantic part. Keep expected controller token/API use negative.

### Profile Distribution

Mithril Control distributes signed immutable profile generations. Nodes
authenticate, validate, acknowledge installation/probe state, and report the
active generation. Read access to findings does not grant profile mutation.

### Agent-Native Investigation Boundary

Expose narrow read-only tools for humans and defensive agents:

- get exact subject and ancestry;
- get raw evidence references and coverage;
- explain a finding predicate and join strength;
- compare actual with expected profile;
- list eligible/ineligible response classes; and
- simulate a typed response request.

The tools provide no shell, BPF map access, raw Kubernetes/cloud credential, or
implicit response authority. Attacker-controlled evidence fields are data, not
instructions.

## Hugging Face Test Increment

Implement:

- deterministic replay of `HF-PROC-001`;
- `HF-CORR-001`/`HF-DW-001` for any source order and five-minute-late audit;
- expected controller credential/API behavior as a negative control;
- same-task, same-process/different-thread, descendant, socket, exact Pod, and
  Pod-only contextual joins;
- two concurrent Pods sharing a ServiceAccount without a false direct edge;
- a same-process semantic deviation that stands on authoritative audit even
  when local token/socket activity is expected; and
- coverage loss suppressing unsupported negative conclusions.

## Code-Backed Tests

- tenant/source certificate and payload-binding authorization;
- raw/normalized transaction, hash, dedupe, reorder, lateness, and replay;
- normalized-store deletion followed by deterministic rebuild;
- node-local graph hostile identity matrix;
- coverage prerequisite evaluation;
- package schema/content version/signature and unsupported predicate handling;
- stable finding identity and immutable version supersession;
- expected/benign control corpus;
- model/tool prompt-injection payloads cannot invoke mutation;
- read versus profile-write versus response-simulation authorization;
- `HF-PROC-001`, `HF-DW-001`, and `HF-CORR-001` replay/live tests; and
- intake/replay/query latency and scale budgets.

## Live Probe

Run Probes A, B, and C with real node intake. Rebuild the node-local graph from
raw evidence and compare its digest/result. Actuation remains disabled.

## Checkpoint

Run the common repository gates, authenticated intake/storage/rebuild tests,
package replay and negative controls, investigation/authorization security
tests, and live Probes A–C. Preserve raw/derived graph digests, finding
versions, coverage, and profile acknowledgements.

## Acceptance

- raw evidence is immutable, authenticated, hash-linked, and replayable;
- duplicate delivery does not duplicate observations/findings;
- node-local graph rebuild is deterministic;
- tenant/cluster/node/boot/epoch/workload generations cannot cross-bind;
- coverage gates every negative conclusion;
- `HF-PROC-001` and `HF-DW-001` produce stable evidence-backed versions;
- expected controller behavior does not trigger either package;
- late evidence creates a new finding version without editing the prior one;
- profile distribution is signed, separated from read access, and acknowledged;
- investigation tools expose evidence/uncertainty without shell or response
  authority; and
- performance meets the approved central intake/replay/query budgets.

## Explicit Stop Point

Stop after the local graph, packages, and investigation boundary pass. The user
must approve Kubernetes audit/object collection permissions and exact causal
schemas before Phase 8.

## Phase Result

State: Not started.

Record storage and wire choices, source/auth schemas, package artifacts, replay
corpus, tool authorization tests, live results, performance, and final state.
