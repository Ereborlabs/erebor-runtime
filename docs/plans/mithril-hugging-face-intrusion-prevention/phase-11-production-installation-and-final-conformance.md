# Phase 11: Production Installation And Final Conformance

Status: Proposed; depends on Phases 0-10, including Phases 6.1, 6.2, and 6.3,
`Done`.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)
Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
Platform tests: [Phase 11 test requirements](./manual-testing/phase-11-manual-acceptance.md)

Environment setup: [shared setup guide](./manual-testing/environment-setup.md)

## Purpose

Package, qualify, upgrade, scale, and sign the exact limited product claim for
each supported platform. This phase integrates existing capabilities; it does
not hide missing work behind installation.

## Scope And Design Coverage

Chapters 25, 30-33, and 37; Appendices A.4-A.7 and C.

## Deliverables

### D11.1 — Production package and least privilege

Finalize reproducible `mithril-node` image, one-container DaemonSet/Helm,
`mithril-control` deployment, `WorkloadProtectionPolicy` and
`WorkloadProtectionException` CRDs and their conversion policy,
ServiceAccounts/RBAC, trust/bootstrap, host mounts/capabilities,
network policy, storage, config validation, and uninstall. Produce and verify
the advertised multi-architecture OCI artifacts and Helm package with
immutable digests, signatures, SBOM, provenance, and install/upgrade inputs.
Include the CLI, built console, and required analysis package artifacts. Record
their digests and supported execution targets. Include the optional Trace CRD
only when Observability 4 is qualified for this release. Qualify optional
Python and remote data placement only when advertised.

Keep one Interceptor owner. Permit the delegated bpftrace loader only through
the approved [observability contract](../araphor-observability/README.md).
Its lifecycle and interference requirements still apply. Install no upstream
daemon, independent enforcement loader, or node-side policy watcher.

Ordinary Helm removal retains the host runtime hooks, BPF protection, and
durable recovery state. Prove recovery through the retained integration.
Only an exact, independently signed node decommission authorization permits
the owner to remove its host resources. Verify removal by physical readback.
Retain decommission evidence under the approved retention policy. Test Helm
removal and authorized decommission as separate operations.

### D11.2 — Exact platform qualification

Qualify each advertised architecture/kernel/BTF/LSM order, container runtime,
retained containerd/OCI-hook and admission configuration, Kubernetes version,
CNI/network order, provider adapter, and Control mode. NRI is not a baseline
installation requirement. Test another integration only when separately
approved and advertised. Unsupported combinations expose reduced/observe/
unsupported status, never an equivalent prevention claim.

### D11.3 — Upgrade, rollback, and disaster recovery

Prove node/control rolling upgrade, BPF link/map/ABI migration, policy/trust
rotation and rollback, CRD storage-version conversion, API-watch relist,
Control leader failover, backup/restore, WAL/intake-cursor recovery,
mixed-version and stale-acknowledgement rejection, controller/node loss, stale
pins, and interrupted installation without an unmeasured allow window.

Specify Control leader election, writer exclusion, durable-state recovery,
and supported takeover behavior before the failover tests. Prove that a
replacement cannot write while the old writer retains authority. Preserve the
policy sequence and durable receipts during takeover. The optional data process
retains the [Phase 7.9 placement and transfer limits](phase-7-mithril-control-and-detection-packages/phase-7-9-remote-placement.md);
Control failover does not authorize automatic data-process failover.

A normal upgrade preserves the Control PVC, every Node state path, installation
identity, policy candidate chain, sequence high-water values, and unconsumed
evidence. The retained hook can admit a version-changed installer with the
retained command and host ownership shape. The installer changes integration
files and the recovery manifest only. Control, Node, and the BPF owner perform
their own supported migrations before they become ready. The next policy
candidate continues the retained sequence and predecessor chain. A failed or
unsupported migration keeps the original state intact and fails closed. A
fresh Control with retained Node policy state is a negative anti-replay case,
not an upgrade or recovery shortcut.

Name each supported source and destination version before testing migration.
Include AnalysisStore segments and metadata, package artifacts and dependency
revisions, checkpoints, derived state, and trace state and output in recovery.
Use each existing owner's backup, transfer, and recovery contract. Check
consistent references and replay positions across the restored owners. Reject
incomplete bundles and unsupported versions without discarding the original
state. A database-only copy is not a complete data backup. A fresh-store test
does not prove an upgrade. Support only the declared version transitions.

### D11.4 — Scale, capacity, and performance

Measure every qualified hot path and complete bundle with evidence enabled:
open/exec/network distributions, canonical path graph bounds, maps N/N+1,
tasks/sockets/policies/nodes, CRD watch/relist and status bounds, rollout fanout,
WAL/intake/graph/control/provider backpressure, CPU/memory, and I/O-heavy
workloads. A faster run that drops evidence fails correctness.

Include SQL/follow limits, graph traversal, package compilation and execution,
checkpoint recovery, and capture interference for the advertised capabilities.
Reuse the owning plans' workloads and limits. Obtain explicit approval for
the workload, runtime, and pass/fail limits before adding a performance test.
Correctness results do not close unqualified performance requirements.

### D11.5 — Complete HF and legitimate-control conformance

Run every active Appendix C fixture, all standing acceptance branches, and the
live two-node lifecycle probe. Prove unchanged legitimate workers/controllers/
probes/admin flows work and no denied/contained branch reaches its prohibited
next stage.

### D11.6 — Ownership and security review

Prove one Interceptor owner, one writer per durable state, node/control mTLS,
CRD and status RBAC, trust/replay/anti-rollback, self-protection, secret
handling, tenant isolation, status-is-not-authority, no arbitrary response, no
direct-TLS semantic overclaim, and no active rejected contract.

### D11.7 — Digest-bound release package

Produce platform manifest, capability bundle, exact-type closure, fixture
registry, case results, performance bundle, completion ledger, qualification
envelope, SBOM/provenance, and exact signed release claims bound by digest.
Any missing/degraded required record blocks that claim.

## Checkpoint

For each advertised platform, one signed qualification envelope binds all
twelve Chapter 37 results, exact active fixture equality, raw performance and
capacity evidence, install/upgrade proofs, and the limited release claim.

## Required Tests And Fixtures

Implement all acceptance scenarios in `crates/mithril-e2e`. Follow the
[scenario maintainability rules](../../../crates/mithril-e2e/SCENARIO_MAINTAINABILITY_TODO.md#binding-acceptance-rules).
Use small Rust platform tests and the shared fixture tooling. Keep setup,
production calls, actions, assertions, and cleanup visible. The linked test
guide defines coverage and execution instructions; it is not a second manual
acceptance suite.

For the [combined Araphor release](phase-7-mithril-control-and-detection-packages/README.md#combined-implementation-order),
require the bounded Phase 7.10 result and the adapter/console results owned
by Mithril 8–10. Rerun their required cases on the exact release revision;
earlier passes do not transfer. Include SQL admission, resource limits,
disclosure, tenant scope, policy approval/publication, critical escalation,
response readback, provider capability limits, and one complete
local-defender/console loop.
Pin client/model and runbook versions for every assisted claim. Test upgrades,
rebuilds, backup/restore, cursor expiry, and load with discovery enabled and
disabled. Local enforcement must remain independent of SQL and model health.

Use the [Phase 7 verification matrix](phase-7-mithril-control-and-detection-packages/verification.md),
the [package qualification](phase-7-mithril-control-and-detection-packages/phase-7-5-graphs-findings-and-notifications/phase-7-5-7-package-qualification.md),
the Phase 7.5.8 and 7.5.9 algorithm inventories, and the
[observability cases](../araphor-observability/README.md).
Freeze their required cases with the Appendix C cases in the combined release
manifest. Retain the existing Appendix C equality check. Additional required
package, algorithm, and `OBS-*` cases must also map to executable checks and
release results. Missing cases block the release. Optional cases apply only
when advertised; failed required cases cannot become optional after the run.
Use the approved in-process SQL execution contract. Do not claim OS process
isolation from its admission, cancellation, or quota tests.

`FIXTURE-REGISTRY-COMPLETE-001` must prove exact equality among Appendix C,
documentation markers, `fixtures.yaml`, executable tests, criterion mapping,
case results, and the master allocation. Then run every Appendix C fixture
whose criterion is active for the candidate claim, the full HF acceptance
document, the full live two-node probe, upgrade/rollback/scale/security
matrices, artifact-signature/install/uninstall tests, and the repository CI
procedure after the final source state.

## Acceptance

All twelve completion results in architecture Chapter 37 pass for every
advertised platform. The product reports exact unsupported/degraded paths and
does not depend on Phase 12.

## Excluded

Seccomp, L7 mediation, checkpoint/stream authority, host-agent enrollment,
named CI adapters, and optional upstream evidence adapters unless separately
approved and completed later.
