# Phase 10: Provider Connectors And Recovery

Status: Proposed; depends on Phase 9 `Done`.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)
Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
Manual acceptance: [Phase 10 runbook](./manual-testing/phase-10-manual-acceptance.md)  
Environment setup: [shared setup guide](./manual-testing/environment-setup.md)

## Purpose

Add separately qualified provider, mesh, connector, and artifact evidence/
authority modules and one narrow typed actuator per approved capability.

## Scope And Design Coverage

Chapters 23-26; Appendices A.10, A.15, and A.16.

## Deliverables

### D10.1 — Connector framework without generic authority

Implement authenticated source health, cursor/checkpoint, schema/version,
rate/backoff, replay/dedupe, coverage, proof quality, secret redaction, and
registered edge contracts. A generic connector cannot issue arbitrary provider
requests or claim an operation succeeded.

### D10.2 — AWS and Google authority/evidence modules

Bind login/issuance/session/audit identities, account/project/principal,
request/source evidence, expiry/revocation limits, and exact provider result.
Shared access-key or principal evidence stays shared unless stronger lease/
session/request proof exists. Secrets never enter evidence.

### D10.3 — GitHub/source-control module

Implement exact installation/repository/workflow/artifact/audit identities and
the provider-supported permission boundary. Direct TLS cannot distinguish
clone/push or arbitrary verbs; prevention uses provider capability or whole-
channel policy, otherwise audit is post-effect.

### D10.4 — Mesh, connector, and artifact modules

Represent mesh/network device identity, connector delegation, immutable
artifact handoff, attestation predicates, generated/executed bytes, and
alternate causal branches. A connector or artifact edge never becomes process
parentage or execution permission by itself.

### D10.5 — Typed provider actuators

For each advertised capability, implement one operation-specific request,
authorization, dry-run/simulation if real, idempotency, exact handle
re-resolution, provider response, authoritative readback, expiry, and recovery.
An audit token/hash is not assumed to be a revocation handle.

### D10.6 — Provider graph and HF expansion

Complete the `HF-013` through `HF-020` branches and the provider portions of
`HF-021` with exact, shared-principal, contextual, or contradiction edges as
supported. Prove granular AWS/GitHub/mesh/connector/artifact actions and
recovery without merging uncertain paths.

### D10.7 — CI/artifact foundation only

Implement reusable provider job/artifact/credential records required by
Appendix A.16 where they are already supplied by Phase 10 providers. Do not
claim named GitHub Actions/GitLab/Jenkins/Tekton step enforcement; those
adapters remain a Phase 12 allocation decision.

## Checkpoint

Every advertised provider/mesh/connector/message/artifact source has exact
coverage and graph limits, and every advertised provider response has one
typed actuator with authoritative readback. Named CI enforcement remains
unallocated.

## Required Tests And Fixtures

- `EDGE-ARTIFACT-CONSUMER-005`, `EDGE-AWS-SHARED-001`,
  `EDGE-CONNECTOR-FORWARD-004`, `EDGE-GITHUB-SHARED-003`, and
  `EDGE-MESSAGE-CONSUMER-006`.
- `HF-GRAN-AWS-DRYRUN-001`, `HF-GRAN-AWS-SPLIT-001`,
  `HF-GRAN-CONNECTOR-DIRECT-001`, `HF-GRAN-DEAD-DROP-001`,
  `HF-GRAN-GITHUB-MINT-001`, `HF-GRAN-GITHUB-REARM-001`,
  `HF-GRAN-GITHUB-REVOKE-001`, `HF-GRAN-GITHUB-TREE-PR-001`, and
  `HF-GRAN-HOST-LOC-001`.
- `HF-GRAN-MESH-ENUM-001`, `HF-GRAN-MESH-ROOT-001`,
  `HF-GRAN-MESH-SOCKS-001`, `HF-GRAN-OUTSIDE-001`, and
  `HF-GRAN-TOKEN-FORGE-001`.
- Issuance/replay/dry-run/readback, shared-principal, late/duplicate/cursor-gap,
  source-authentication, and provider-outage controls for every advertised
  AWS, Google, GitHub, mesh, connector, message, and artifact contract.

## Acceptance

- Every connector authenticates its real source and publishes exact coverage.
- Every direct edge follows a registered provider contract; weaker facts remain
  weaker branches.
- Every actuator is capability-specific, idempotent, and physically verified.
- Same-TLS semantic limits remain explicit.
- Provider outage or ambiguity cannot widen local authority or produce a false
  verified recovery.

## Excluded

Named CI runner adapters, arbitrary provider actions, TLS interception, and
Phase 12 optional surfaces.

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
