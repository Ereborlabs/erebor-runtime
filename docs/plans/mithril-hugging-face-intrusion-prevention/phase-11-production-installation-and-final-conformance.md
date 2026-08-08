# Phase 11: Production Installation And Final Conformance

Status: Proposed; depends on Phases 0-10 `Done`.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)
Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)

## Purpose

Package, qualify, upgrade, scale, and sign the exact limited product claim for
each supported platform. This phase integrates existing capabilities; it does
not hide missing work behind installation.

## Design Coverage

Chapters 25, 30-33, and 37; Appendices A.4-A.7 and C.

## Deliverables

### D11.1 — Production package and least privilege

Finalize reproducible `mithril-node` image, one-container DaemonSet/Helm,
`mithril-control` deployment, ServiceAccounts/RBAC, trust/bootstrap, host
mounts/capabilities, network policy, storage, config validation, and uninstall.
No upstream daemon or second loader is installed.

### D11.2 — Exact platform qualification

Qualify each advertised architecture/kernel/BTF/LSM order, container runtime,
NRI/admission configuration, Kubernetes version, CNI/network order, provider
adapter, and Control mode. Unsupported combinations expose reduced/observe/
unsupported status, never an equivalent prevention claim.

### D11.3 — Upgrade, rollback, and disaster recovery

Prove node/control rolling upgrade, BPF link/map/ABI migration, policy/trust
rotation and rollback, WAL/cursor recovery, mixed-version rejection,
controller/node loss, stale pins, and interrupted installation without an
unmeasured allow window.

### D11.4 — Scale, capacity, and performance

Measure every qualified hot path and complete bundle with evidence enabled:
open/exec/network distributions, canonical path graph bounds, maps N/N+1,
tasks/sockets/policies/nodes, WAL/control/provider backpressure, CPU/memory,
and I/O-heavy workloads. A faster run that drops evidence fails correctness.

### D11.5 — Complete HF and legitimate-control conformance

Run every active Appendix C fixture, all standing acceptance branches, and the
live two-node lifecycle probe. Prove unchanged legitimate workers/controllers/
probes/admin flows work and no denied/contained branch reaches its prohibited
next stage.

### D11.6 — Ownership and security review

Prove one Interceptor owner, one writer per durable state, node/control mTLS,
trust/replay/anti-rollback, self-protection, secret handling, tenant isolation,
no arbitrary response, no direct-TLS semantic overclaim, and no active rejected
contract.

### D11.7 — Digest-bound release package

Produce platform manifest, capability bundle, exact-type closure, fixture
registry, case results, performance bundle, completion ledger, qualification
envelope, SBOM/provenance, and exact signed release claims bound by digest.
Any missing/degraded required record blocks that claim.

## Required Tests And Fixtures

Every active Appendix C fixture and criterion, the full HF acceptance document,
the full live two-node probe, upgrade/rollback/scale/security matrices, and the
repository CI procedure after the final source state.

## Acceptance

All eleven completion results in architecture Chapter 37 pass for every
advertised platform. The product reports exact unsupported/degraded paths and
does not depend on Phase 12.

## Excluded

Seccomp, L7 mediation, checkpoint/stream authority, host-agent enrollment,
named CI adapters, and optional upstream evidence adapters unless separately
approved and completed later.

## Phase Result

State: Not done.  
Completed deliverables: none.  
Verification: not run; this is a plan rewrite.  
Next phase: not authorized.
