# Platform Tests For Phase 11

Status: Required platform test coverage.

Phase: [Production Installation And Final Conformance](../phase-11-production-installation-and-final-conformance.md)  
Setup: [`TWO-NODE`](./environment-setup.md), extended with every provider and
platform advertised by the candidate release

## Outcome

Prove the packaged candidate installs, operates, upgrades, rolls back,
recovers, scales, and preserves protection after ordinary Helm removal.
Prove that signed decommission removes only authorized host resources.
Verify these results on every advertised platform and prove that the
signed qualification envelope exactly binds all active fixtures and the
limited physical claims actually demonstrated. Phase 12 remains unnecessary.

## Test implementation

Implement the behaviors below as small Rust scenarios in `crates/mithril-e2e`.
Follow the [scenario maintainability rules](../../../../crates/mithril-e2e/SCENARIO_MAINTAINABILITY_TODO.md#binding-acceptance-rules)
and the shared [platform test requirements](README.md#platform-test-shape).
Use the applicable platform cases from one test body. Keep the production
calls, action, assertions, and cleanup visible. The steps below specify Rust
test behavior; they are not a separate manual acceptance procedure.

## Scenario requirements

1. Build the release artifacts once and retain their immutable digests,
   signatures, SBOM, provenance, source state, schemas, and fixture registry.
2. Build a run sheet from Appendix C and the candidate's active
   criterion mapping. Add the required Phase 7.10, package, algorithm, and
   observability cases from the owning plans. Exact Appendix C equality with
   documentation markers, `fixtures.yaml`, executable tests, case results,
   and master allocation is a prerequisite. Each additional required case must map to an executable
   check and a result. Run the lightweight case before its physical pair.
3. On a clean environment for each advertised platform vector, install only
   the signed package and run the unchanged legitimate baseline.
4. Run every exact Rust test mapped to an active row in its owning test guide.
   Record `pass`, `fail`, `blocked`, or `not-applicable`
   with the exact activation condition; no row may silently disappear.
5. Run upgrade, rollback, interrupted install, node/control loss, CRD
   conversion and relist, Control leader failover, mixed-version, stale-pin,
   policy/trust rotation, WAL/intake-cursor recovery, scale, capacity, and
   performance matrices. For an upgrade, retain the Control PVC and each Node
   state path. Record the policy sequence and predecessor before replacement,
   then prove that the new version continues both values. Use a separate
   negative case to prove that fresh Control state cannot replace retained Node
   policy state. Include the complete AnalysisStore and package/trace state.
   Record each supported version transition. Test Control writer exclusion
   and durable recovery during failover. Keep optional data-process transfer
   within the Phase 7.9 limits.
6. Run the complete Hugging Face acceptance contract and live two-node probe.
7. Remove Helm without decommission authorization. Inventory the retained
   hooks, programs, links, maps, pins, and durable state. Prove that retained
   protection remains active. Reinstall and prove recovery with the same
   installation identity and no rollback in the policy sequence.
8. Verify that a missing, expired, or mismatched decommission authorization
   cannot remove host protection. Then submit an exact, independently signed
   node decommission authorization.
   Observe the owning component remove only its authorized resources. Verify
   hook, link, map, and pin absence by physical readback. Retain the completion
   evidence. Remove the remaining release objects after the owner completes.
9. Assemble and verify the signed qualification envelope from the sealed raw
   artifacts. Rebuilding or editing any input invalidates the envelope.

## Complete Active-Fixture Run Sheet

Phase 11 first owns no new Appendix C attack fixture. It owns the complete
candidate rerun. For each active fixture, use its first-owner guide below; the
Phase 11 result must contain one row for every exact active ID.

Require the bounded Phase 7.10 release and its
[verification matrix](../phase-7-mithril-control-and-detection-packages/verification.md).
Add the required package-runtime, algorithm-corpus, and
[observability cases](../../araphor-observability/README.md) to this run sheet.
Include the Trace CRD, Python target, and remote placement cases only when
advertised. Keep the exact required set fixed during qualification.

| Owner | Test requirements |
| ---: | --- |
| Phase 0 | [feasibility, source, ABI, and registry](./phase-0-manual-acceptance.md) |
| Phase 1 | [node chassis and boot lifecycle](./phase-1-manual-acceptance.md) |
| Phase 2 | [exact native identity](./phase-2-manual-acceptance.md) |
| Phase 3 | [observation, simulation, and path compiler](./phase-3-manual-acceptance.md) |
| Phase 4 | [local pre-effect enforcement](./phase-4-manual-acceptance.md) |
| Phase 5 | [process-aware network plane](./phase-5-manual-acceptance.md) |
| Phase 6 | [evidence, coverage, and recovery](./phase-6-manual-acceptance.md) |
| Phase 6.1 | [gRPC service and IPC convergence](./phase-6-1-manual-acceptance.md) |
| Phase 6.2 | [Control policy and evidence convergence](./phase-6-2-manual-acceptance.md) |
| Phase 7 | [Control and detection packages](./phase-7-manual-acceptance.md) |
| Phase 8 | [Kubernetes distributed causality](./phase-8-manual-acceptance.md) |
| Phase 9 | [local and distributed response](./phase-9-manual-acceptance.md) |
| Phase 10 | [provider connectors and recovery](./phase-10-manual-acceptance.md) |

Phase 12 fixtures are included only if a separately approved implementation
phase has made the surface part of this candidate. An evaluation-only result
cannot expand the release claim.

## Installation And Platform Matrix

For every advertised architecture/kernel/BTF/LSM order, runtime, retained
containerd/OCI-hook and admission configuration, Kubernetes version, CNI order,
provider adapter, and Control mode:

- install from the immutable artifact and verify exactly one Interceptor owner;
- compare detected capability to direct kernel/runtime probes;
- verify full, reduced, observe-only, and unsupported states honestly;
- test least-privilege ServiceAccounts/RBAC, host mounts, capabilities,
  CRD/status access, network policy, storage, mTLS, bootstrap, and config
  rejection;
- check `WorkloadProtectionPolicy` and `WorkloadProtectionException`; check
  `Trace` only when Observability 4 is advertised;
- check CLI, console, package artifacts, and selected execution targets;
- upgrade and roll back BPF link/map/ABI, node/control, policy, and trust state
  without an unmeasured allow window; preserve the Control PVC, Node state
  paths, unconsumed evidence, sequence high-water values, and predecessor
  chain; recover the complete AnalysisStore, package artifacts, checkpoints,
  and trace state and output for each supported version transition;
- convert the CRD storage version, relist after watch compaction, fail over the
  Control writer, and prove that stale source, target, and node receipts cannot
  win;
- verify retained protection and recovery after ordinary Helm removal; and
- verify authorized decommission removes only owned resources and retains its
  completion evidence.

NRI is not required for the baseline installation. Include another integration
only when separately approved and advertised. The delegated bpftrace loader
must remain under the Interceptor owner and pass its lifecycle and interference
checks. No independent enforcement loader is permitted.

## Scale, Performance, And Correctness Matrix

Measure open, exec, and network latency distributions plus CPU, memory, WAL,
intake/graph/Control/provider backpressure, CRD watch/relist and status bounds,
rollout fanout, canonical path bounds, and maps at N and N+1. Use the same
evidence load and fixture correctness checks as baseline. Include I/O-heavy
workers, maximum advertised tasks/sockets/policies/nodes, source loss, and
recovery. A faster run that drops evidence, changes enforcement, or loses the
legitimate control fails.

Include SQL/follow limits, graph traversal, package compilation and execution,
checkpoint recovery, and capture interference. Use the owning plans' approved
workloads and limits. Obtain explicit workload, runtime, and pass/fail approval
before adding a performance test. A correctness pass does not qualify
performance or OS process isolation for the in-process SQL owner.

## Security And Release-Envelope Checks

Assert one Interceptor owner, one writer per durable state, node/
Control mTLS, CRD and status RBAC, tenant isolation, status-is-not-authority,
replay/anti-rollback, secret handling, self-protection, absence of arbitrary
response/provider calls, and the direct-TLS semantic limit. Recalculate every
digest referenced by the qualification envelope and verify its signature from
an independent verifier environment.

## Execution and results

Map each required case to its exact Rust test name, platform, and lifecycle.
Document its command and expected result under the shared
[command contract](README.md#command-contract).

## Required Artifacts And Pass Rule

Retain all twelve Chapter 37 result records, exact registry-equality output,
complete active-fixture run sheet, owner-guide artifacts, HF/two-node bundles,
platform manifests, installation and upgrade inventories, recovery records,
separate Helm-removal and decommission inventories, raw capacity/performance
results, security review, signed artifacts, SBOM,
provenance, and the final qualification envelope. Any missing, mismatched,
degraded-but-unreported, or post-signing input blocks the affected claim.

## Troubleshooting

- A successful Helm rollout does not prove kernel coverage or enforcement.
- Never merge results from different artifact digests or platform vectors.
- If one active fixture lacks an Rust test result, registry equality
  and final conformance fail even when all other rows pass.
