# Phase 7: Mithril Control And Detection Packages

Status: Proposed; depends on Phase 6.2 `Done`.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)
Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
Manual acceptance: [Phase 7 runbook](./manual-testing/phase-7-manual-acceptance.md)  
Environment setup: [shared setup guide](./manual-testing/environment-setup.md)

## Purpose

Extend the Phase 6.2 policy and evidence service with one durable graph and
finding owner. Produce deterministic local incident findings, notifications,
and provider-neutral authority records. Preserve the exact policy provenance
and source coverage that limit every conclusion.

## Scope And Design Coverage

Chapters 8, 22-25, 30, 32, and 34-35; Appendices A.10 and A.15.

## Deliverables

### D7.1 — Accepted-evidence index and merged coverage

Consume only records committed by the Phase 6.2 `EvidenceIntakeOwner`. Build
bounded indexes and merged source views without changing the accepted
observation, intake cursor, or node coverage interval. An absent, delayed,
gapped, or offline source never becomes a clean interval. Index rebuild after
restart must produce the same package input set.

### D7.2 — Immutable graph and finding revisions

Implement canonical subjects/objects/observations/edges, proof-quality-aware
joins, contradiction branches, deterministic windows, finding revisions, and
byte-identical replay in the `GraphAndFindingOwner`. Process parentage never
crosses nodes; time alone never creates an exact edge. Keep graph state in the
Control durable store, not in CRDs or nodes. The graph schema, versioning, and
store are node-agnostic. Phase 8 extends this same owner with Kubernetes
cross-node edges; it does not add a second graph builder.

### D7.3 — Core detection packages

Implement `HF-PROC-001` and `HF-DW-001`, plus the schema, state machine, and
replay contract of `HF-XNODE-001`. Phase 8 completes `HF-XNODE-001` with its
Kubernetes sources and physical multi-node proof. Each package declares exact
inputs, coverage predicate, window, state machine, finding result, replay ID,
and no invented provider semantics.

### D7.4 — Notification router

Deliver sensitivity-filtered finding revisions with route authorization,
retry, dedupe, sink health, and failure evidence. Notification cannot mutate a
finding, policy, actor role, or response plan.

### D7.5 — Provider-neutral authority lease foundation

Implement approval/request/lease/audit-handle records and signed proof
validation without storing credential secrets. CLI names and process paths
grant no authority. Exact provider issuance/use joins remain Phase 10.

### D7.6 — Policy provenance and rollout-aware findings

Join each observation to its exact CRD source revision, signed candidate,
target snapshot, node-bound generation, and activation acknowledgement when
those records exist. Persist this join as
`PolicyObservationProvenanceV1`. A missing or mixed rollout state limits the
finding and negative claim. Graph and package code may read Phase 6.2 policy
inventory but cannot change desired state, sign or distribute a candidate,
update CRD status, or activate a node generation.

### D7.7 — Local HF package proof

Replay local credential, executable, file, network, and authority-pivot events
for `HF-001` through `HF-012` under loss/late/duplicate/contradiction variants.
Findings and uncertainty must be stable and explain the exact prevented,
allowed, payload-unobservable, contextual, or outside-authority stage.

### D7.8 — Durable graph lifecycle and tenant isolation

Persist immutable graph versions, finding revisions, package watermarks,
notification cursors, and provider-neutral authority records with bounded
retention and restart recovery. Compaction may remove data only through the
declared retention and evidence-reference rules. It cannot rewrite a retained
revision or convert missing input into absence. Enforce tenant separation at
ingest references, graph subjects, packages, notifications, and lease records.

## Checkpoint

Mithril Control deterministically replays the complete local package inputs to
identical graph/finding revisions, preserves their policy and coverage
provenance, and delivers notifications without granting physical authority.
Cross-node and provider packages remain explicitly incomplete.

## Required Tests And Fixtures

- Rerun `AUTHORIZATION-REPLAY-004`, `HF-LOCAL-001`,
  `HF-004-RESULT-001`, and `HF-011-READ-RESULT-001` through deterministic
  package replay under complete and gapped coverage.
- Byte-order/delivery-order graph determinism, contradiction, source-gap,
  index rebuild, graph-store restart/retention, notification
  secret/retry/dedupe, and authority-record restart tests.
- Source-revision, candidate, target, activation, observation, and finding
  provenance tests under complete, partial, stale, and mixed rollouts.
- Tenant-crossing graph, package, notification, and authority-record rejection
  tests.
- Phase 7 owns no new Appendix C fixture ID. Provider and cross-node fixture
  results remain incomplete until Phases 8 and 10; the Phase 7 result must say
  so rather than counting their schema-only package contracts as complete.

## Acceptance

- Control is a functioning secure service, not a late placeholder.
- Replaying the same bound inputs produces identical graph/finding artifacts.
- Proof quality and coverage mechanically limit findings.
- Every policy-dependent finding names the exact source, candidate, target,
  and active node generation that its evidence proves.
- Notifications and leases cannot grant node or provider authority by
  themselves.
- Node remains the sole local physical decision owner.
- Phase 7 has no policy watcher, compiler writer, rollout writer, evidence
  intake writer, or CRD status writer.

## Excluded

CRD reconciliation, policy compilation/distribution/activation, evidence
intake, Kubernetes cross-node source joins and physical proof, named provider
connectors, and response actuation.

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
Unsupported/degraded paths: provider and cross-node packages incomplete.
Remaining work in this phase: all deliverables.
Next phase not authorized: yes.
```
