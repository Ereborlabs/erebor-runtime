# Phase 7: Mithril Control And Detection Packages

Status: Proposed; depends on Phase 6 `Done`.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)
Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)

## Purpose

Turn the Phase 1 Control chassis into the durable policy/evidence/graph service
and produce deterministic local incident findings, notifications, and
provider-neutral authority records.

## Design Coverage

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

Implement the architecture's three core packages, including
`HF-PROC-001`, `HF-DW-001`, and the cross-node-ready package contract. Each
package declares exact inputs, coverage predicate, window, state machine,
finding result, replay ID, and no invented provider semantics.

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
under loss/late/duplicate/contradiction variants. Findings and uncertainty must
be stable and explain the exact prevented/allowed stage.

## Required Tests And Fixtures

`HF-LOCAL-001`, local `HF-GRAN-*` cases allocated by the claim,
authorization replay, edge determinism, source gap, notification secret/retry/
dedupe, and graph replay fixtures. Provider and cross-node fixtures remain
incomplete until their phases.

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

State: Not done.  
Completed deliverables: none.  
Verification: not run; this is a plan rewrite.  
Next phase: not authorized.
