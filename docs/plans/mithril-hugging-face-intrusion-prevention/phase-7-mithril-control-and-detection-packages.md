# Phase 7: Mithril Control And Detection Packages

Status: Proposed; depends on Phase 6 `Done`.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)
Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)

## Purpose

Turn the Phase 1 Control chassis into the durable policy/evidence/graph service
and produce deterministic local incident findings, notifications, and
provider-neutral authority records.

## Scope And Design Coverage

Chapters 8, 22-25, 30, and 34; Appendices A.10 and A.15.

## Deliverables

### D7.1 — Authenticated intake and source coverage

Persist node envelopes idempotently by source epoch/sequence and merge coverage
without changing node evidence. Reject wrong tenant/node, digest, schema,
generation, replay, and impossible sequence transitions. Node outage never
becomes a clean interval.

### D7.2 — Immutable graph and finding revisions

Implement canonical subjects/objects/observations/edges, proof-quality-aware
joins, contradiction branches, deterministic windows, finding revisions, and
byte-identical replay. Process parentage never crosses nodes; time alone never
creates an exact edge.

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

### D7.6 — Control policy ownership

Operate the Phase 3 compiler/signing owner, trust rotation/revocation,
anti-rollback floor, node policy distribution, acknowledgements, and generation
inventory over secure gRPC. Control never writes node BPF maps directly.

### D7.7 — Local HF package proof

Replay local credential, executable, file, network, and authority-pivot events
for `HF-001` through `HF-012` under loss/late/duplicate/contradiction variants.
Findings and uncertainty must be stable and explain the exact prevented,
allowed, payload-unobservable, contextual, or outside-authority stage.

## Checkpoint

Mithril Control deterministically replays the complete local package inputs to
identical graph/finding revisions, distributes policy over secure gRPC, and
delivers notifications without granting physical authority. Cross-node and
provider packages remain explicitly incomplete.

## Required Tests And Fixtures

- Rerun `AUTHORIZATION-REPLAY-004`, `HF-LOCAL-001`,
  `HF-004-RESULT-001`, and `HF-011-READ-RESULT-001` through deterministic
  package replay under complete and gapped coverage.
- Byte-order/delivery-order graph determinism, contradiction, source-gap,
  notification secret/retry/dedupe, and authority-record restart tests.
- Phase 7 owns no new Appendix C fixture ID. Provider and cross-node fixture
  results remain incomplete until Phases 8 and 10; the Phase 7 result must say
  so rather than counting their schema-only package contracts as complete.

## Acceptance

- Control is a functioning secure service, not a late placeholder.
- Replaying the same bound inputs produces identical graph/finding artifacts.
- Proof quality and coverage mechanically limit findings.
- Notifications and leases cannot grant node or provider authority by
  themselves.
- Node remains the sole local physical decision owner.

## Excluded

Kubernetes cross-node joins, named provider connectors, and response actuation.

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
