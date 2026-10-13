# Phase 12: Optional Ecosystem Compatibility

Status: Proposed evaluation phase. Allocation records may begin after Phase 0,
but each physical prototype requires its named prerequisite and separate user
approval. Nothing here can satisfy Phase 11.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)
Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
Platform tests: [Optional evaluation requirements](./manual-testing/phase-12-manual-acceptance.md)

Environment setup: [shared setup guide](./manual-testing/environment-setup.md)

## Purpose

Evaluate every explicitly deferred surface and optional external evidence
adapter. Deliver a measured `ADOPT`, `DEFER`, or `REJECT` decision; an `ADOPT`
decision creates a separate approved implementation phase rather than silently
expanding this one. Until a physical prerequisite exists, the only valid
intermediate result is `BLOCKED_ON_PREREQUISITE`, not a guessed decision.

## Scope And Design Coverage

Chapters 5, 7, 14, 21, 26, and 35.1; Appendices A.13.6 and A.16.

## Deliverables

### D12.1 — Deferred-surface allocation ledger

For every row below, record owner, security boundary, installation path,
contracts, exact hooks/APIs, failure result, fixtures, performance budget,
deployment change, and effect on existing claims. An absent physical
prerequisite means `BLOCKED_ON_PREREQUISITE`. After the required evaluation,
use `DEFER` when the evidence does not justify adoption. Missing information
does not authorize a prototype or a production capability.

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

Keep this evaluation separate from recorded-input conversion and analysis in
[Phase 7.5.8](phase-7-mithril-control-and-detection-packages/phase-7-5-graphs-findings-and-notifications/phase-7-5-8-discovery-engine-algorithms.md)
and [Phase 7.5.9](phase-7-mithril-control-and-detection-packages/phase-7-5-graphs-findings-and-notifications/phase-7-5-9-security-analytics-algorithms.md).
Reuse those package functions when their input contracts match. Evaluate the
remaining live collection, authentication, source identity, loss, and health
behavior. Required provider connectors remain in Phase 10. This optional
evaluation cannot defer or complete a required Phase 10 connector.

## Per-Surface Prerequisites

| Evaluation | Minimum completed prerequisite before physical prototype |
| --- | --- |
| Seccomp direct-launch/OCI/NRI | Phase 0 mechanism dossier; Phase 1 node/Interceptor for integrated tests; Phase 2 identity for scope/lifetime claims |
| L7 mediation | Phase 5 direct-TLS/network baseline, Phase 6.2 authenticated Control intake, and Phase 7 graph contracts |
| Host/developer/non-Kubernetes agent | Phases 1-2 shared Interceptor and first-effect identity |
| Checkpoint create/restore | Phases 2, 4, and 6 identity/effects/recovery |
| Attach/port-forward evidence | Phases 7-8 Control and Kubernetes source/graph contracts |
| Named CI adapter | Phase 10 provider/job/artifact/lease foundations |
| Optional external evidence adapter | Phases 6-7 coverage, intake, graph, and proof-quality owners |

An evaluation that needs a prerequisite cannot mark `ADOPT`, `DEFER`, or
`REJECT` from schema inspection alone; it records `BLOCKED_ON_PREREQUISITE`.

## Checkpoint

Each separately approved surface ends with one reproducible, prerequisite-aware
`ADOPT`, `DEFER`, or `REJECT` dossier, or explicitly remains
`BLOCKED_ON_PREREQUISITE`. `ADOPT` names a new implementation phase; this
checkpoint does not ship the surface or change a Phase 11 claim.

## Required Tests And Fixtures

Implement all acceptance scenarios in `crates/mithril-e2e`. Follow the
[scenario maintainability rules](../../../crates/mithril-e2e/SCENARIO_MAINTAINABILITY_TODO.md#binding-acceptance-rules).
Use small Rust platform tests and the shared fixture tooling. Keep setup,
production calls, actions, assertions, and cleanup visible. The linked test
guide defines coverage and execution instructions; it is not a second manual
acceptance suite.

- Seccomp, when allocated: `SECCOMP-QUAL-001`.
- Checkpoint/stream, when allocated: `CHECKPOINT-CREATE-001`,
  `ENTRY-RESTORE-001`, and `ENTRY-STREAM-001`.
- Named CI, when allocated: `CI-CACHE-001`, `CI-CONTAINER-001`,
  `CI-DEBUG-001`, `CI-DIND-001`, `CI-FANOUT-001`,
  `CI-GITHUB-TOKEN-001`, `CI-NATIVE-001`,
  `CI-OFFICIAL-STEP-JOIN-001`, `CI-OIDC-001`, `CI-OUTPUT-001`,
  `CI-POST-001`, `CI-PR-001`, `CI-RETRY-001`,
  `CI-RUNNER-REUSE-001`, `CI-STATE-001`, and
  `HF-GRAN-CI-BUILDRS-001`.
- L7, host-agent, and optional-source evaluations have no active Appendix C
  fixture IDs. Before an `ADOPT` implementation can be approved, the validated
  architecture, registry, criterion mapping, and new owning phase must add
  their exact IDs together.
- Every prototype includes a legitimate control, failure, bypass, performance,
  and absence-of-adapter case.

## Acceptance

- Every evaluated surface has a reproducible evidence package and one explicit
  decision.
- Core Phase 11 claims remain unchanged when every optional component is absent.
- An `ADOPT` decision names a new owning implementation phase and cannot ship
  from this evaluation alone.
- No optional source creates a second loader or stronger proof than it emits.

## Excluded

Unapproved production implementation of any evaluated surface.
