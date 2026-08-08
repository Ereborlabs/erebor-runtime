# Phase 6: Durable Evidence, Coverage, And Recovery

Status: Proposed; depends on Phase 5 `Done`.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)
Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)

## Purpose

Make local observations durable and loss-aware without coupling the already
decided physical deny to userspace delivery. Prove truthful restart and
generation recovery.

## Scope And Design Coverage

Chapters 9, 22, 31-33; Appendices A.3-A.7 and A.15.1-A.15.2.

## Deliverables

### D6.1 — Canonical local observations

Normalize every node source into `ObservationEnvelopeV1` with deterministic
ID, source epoch/sequence, task/object/policy coordinates, result stage, proof
quality, coverage interval, and bounded typed payload. Secret bytes and raw
administrative argv never enter normal telemetry.

### D6.2 — WAL and upload protocol

Implement ordered local WAL segments, integrity digests, fsync/batching bounds,
retention, acknowledgement cursors, replay, corruption handling, and secure
gRPC upload to Control. Ring reservation occurs only after a decision is fixed;
delivery failure cannot restore an allow or rewrite a deny.

### D6.3 — Coverage health owner

Implement source epochs, healthy/gapped intervals, exact loss/suppression
counters, reader/control delay, closure rules, and negative-claim eligibility.
Ring/map/WAL exhaustion or sole-reader death produces explicit degraded/gapped
coverage and the configured admission/effect safety result.

### D6.4 — Generation and object recovery

Recover immutable policy generations, retained references, task/native/object/
socket state, mount topology, pending exception consumption, response floors,
and active pointer truth across node/daemon/runtime restart. Never reconstruct
authority from a PID, name, stale userspace cache, or partial WAL.

### D6.5 — Interceptor and sole-owner health

Continuously read back program/link/map/pin manifests, exclusive owner lease,
capacity, boot/label epochs, and capability state. Missing/tampered kernel state
closes the affected claim before later evidence uses it.

### D6.6 — Deterministic local finding windows

Produce the coverage-qualified local input windows required by Phase 7 without
building distributed/provider conclusions. Late, duplicate, reordered, or
contradictory observations retain stable revisions.

## Checkpoint

The node can restart and replay an integrity-checked WAL to Control while
preserving installed restrictions and exposing every gap, loss, stale owner,
and unreconciled object. A negative conclusion cannot cross a bad interval.

## Required Tests And Fixtures

- `IPC-ENDPOINT-RESTART-006` and `IPC-RELATIONSHIP-LOSS-002`; rerun
  `LSM-DENY-SATURATION-001` through the completed WAL/coverage owner.
- Rerun `SOURCE-KA-READER-LOSS-003`, `SOURCE-KA-CAPACITY-005`, and
  `SOURCE-KA-PARTIAL-ATTACH-001` against the product owner rather than only
  the Phase 0 source/prototype boundary.
- Reader/ring/map/WAL saturation and corruption, source sequence gaps,
  upload outage/replay, restart/reuse, policy retirement, stale pin/link/map,
  sole-gatherer death, and applicable standing HF/live two-node cases.

## Acceptance

- Physical decisions remain correct while evidence health changes; the release
  claim changes with coverage.
- No gap can support a negative conclusion or be repaired by guess.
- Restart preserves restrictions and consumption while refusing stale
  authority.
- Control receives exactly replayable, integrity-checked observations.
- Every capacity and latency bound is measured with evidence enabled.

## Excluded

Distributed graph joins, notifications, provider connectors, and response.

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
