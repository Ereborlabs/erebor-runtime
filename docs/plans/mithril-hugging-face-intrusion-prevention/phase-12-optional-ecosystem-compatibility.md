# Phase 12: Optional Ecosystem Compatibility

Status: Proposed evaluation phase. It may begin after Phase 0, but each
surface requires separate user approval and cannot satisfy Phase 11.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)
Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)

## Purpose

Evaluate every explicitly deferred surface and optional external evidence
adapter. Deliver a measured `ADOPT`, `DEFER`, or `REJECT` decision; an `ADOPT`
decision creates a separate approved implementation phase rather than silently
expanding this one.

## Design Coverage

Chapters 5, 7, 14, 21, 26, and 35.1; Appendices A.13.6 and A.16.

## Deliverables

### D12.1 — Deferred-surface allocation ledger

For every row below, record owner, security boundary, installation path,
contracts, exact hooks/APIs, failure result, fixtures, performance budget,
deployment change, and effect on existing claims. Missing information means
`DEFER`, not a permissive prototype.

### D12.2 — Seccomp compatibility/performance evaluation

Prototype direct-launch and qualified OCI/NRI installation separately. Prove
pre-user-code install, exact filter identity, TSYNC/thread scope, allowed and
denied controls, failure behavior, and workload latency/throughput with the
same evidence load as baseline. Run `SECCOMP-QUAL-001` only for an allocated
candidate. Adopt only if the measured cost is within the approved budget and
the layer adds material defense; otherwise keep Seccomp absent.

### D12.3 — Operator-owned L7 mediation evaluation

Define a distinct authenticated mediation owner only for a threat requiring
L7 prevention. Evaluate client/upstream identity, semantic policy, result,
failure posture, credential/CA handling, and deployment. Never silently inject
a proxy, redirect workload traffic, replace DNS, or install a workload CA.

### D12.4 — Host/developer/non-Kubernetes agent enrollment

Evaluate existing system-manager/cgroup/executable-integrity sources and prove
identity before first protected effect. Reuse the shared Interceptor and never
use userspace PID-delayed enrollment. Kubernetes/HF core remains independent.

### D12.5 — Checkpoint/restore and attach/port-forward

Evaluate existing stock authorization/runtime interfaces, task/object coverage,
store/stream semantics, and exact result limits. Do not patch CRIU/runtime,
insert a stream proxy, or claim rejection from audit-only evidence.

### D12.6 — Named CI adapters

Evaluate GitHub Actions, GitLab, Jenkins, Tekton, or another named platform one
at a time against Chapter 26/A.16: job/step/native/container/service identity,
official supported joins, artifacts/cache/OIDC/credentials/deploy/cleanup/
retry/debug/reuse, and physical lowering. No runner patch or invented step
identity is allowed.

### D12.7 — Optional external evidence adapters

Evaluate typed Falco, Tetragon, KubeArmor, Hubble/Cilium, EDR, SIEM, or provider
inputs. Preserve source-native IDs, policy/version, loss, health, and proof
quality. They feed Mithril Control as independent evidence only; they never
become the default node gatherer, native identity, prevention proof, or policy
authority.

## Required Tests And Fixtures

Only the exact fixture set activated for the approved evaluation:
`SECCOMP-QUAL-001`, checkpoint/restore, stream, CI, L7, host-agent, or
source-adapter cases. Each prototype includes a legitimate control, failure,
bypass, performance, and absence-of-adapter case.

## Acceptance

- Every evaluated surface has a reproducible evidence package and one explicit
  decision.
- Core Phase 11 claims remain unchanged when every optional component is absent.
- An `ADOPT` decision names a new owning implementation phase and cannot ship
  from this evaluation alone.
- No optional source creates a second loader or stronger proof than it emits.

## Excluded

Unapproved production implementation of any evaluated surface.

## Phase Result

State: Not done.  
Completed deliverables: none.  
Verification: not run; this is a plan rewrite.  
Next phase: not authorized.
