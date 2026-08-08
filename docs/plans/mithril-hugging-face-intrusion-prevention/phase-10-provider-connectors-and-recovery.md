# Phase 10: Provider Connectors And Recovery

Status: Proposed; depends on Phase 9 `Done`.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)
Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)

## Purpose

Add separately qualified provider, mesh, connector, and artifact evidence/
authority modules and one narrow typed actuator per approved capability.

## Design Coverage

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

Complete the `HF-013` through `HF-020` branches with exact, shared-principal,
contextual, or contradiction edges as supported. Prove granular AWS/GitHub/
mesh/connector/artifact actions and recovery without merging uncertain paths.

### D10.7 — CI/artifact foundation only

Implement reusable provider job/artifact/credential records required by
Appendix A.16 where they are already supplied by Phase 10 providers. Do not
claim named GitHub Actions/GitLab/Jenkins/Tekton step enforcement; those
adapters remain a Phase 12 allocation decision.

## Required Tests And Fixtures

Applicable `EDGE-AWS-*`, `EDGE-GITHUB-*`, `EDGE-CONNECTOR-*`,
`EDGE-ARTIFACT-*`, provider `HF-GRAN-*`, issuance/replay/dry-run/readback,
shared-principal, late/duplicate/cursor-gap, and provider-outage fixtures.

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

State: Not done.  
Completed deliverables: none.  
Verification: not run; this is a plan rewrite.  
Next phase: not authorized.
