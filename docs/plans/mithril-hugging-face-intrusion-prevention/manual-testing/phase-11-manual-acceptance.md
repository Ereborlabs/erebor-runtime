# How To Manually Accept Phase 11

Status: Proposed runbook; no Phase 11 implementation or test has been run.

Phase: [Production Installation And Final Conformance](../phase-11-production-installation-and-final-conformance.md)  
Setup: [`TWO-NODE`](./environment-setup.md), extended with every provider and
platform advertised by the candidate release

## Outcome

Prove the packaged candidate installs, operates, upgrades, rolls back,
recovers, scales, and uninstalls on every advertised platform, and that its
signed qualification envelope exactly binds all active fixtures and the
limited physical claims actually demonstrated. Phase 12 remains unnecessary.

## Automated Companion

```text
IMPLEMENTATION COMMAND REQUIRED: run the final repository CI procedure,
fixture-registry equality check, every active fixture, full Hugging Face and
two-node suites, install/upgrade/rollback/recovery, platform, security,
capacity, performance, packaging, signature, SBOM, and provenance suites from
the final source state.
```

## Procedure

1. Build the release artifacts once and retain their immutable digests,
   signatures, SBOM, provenance, source state, schemas, and fixture registry.
2. Materialize a run sheet from Appendix C and the candidate's active
   criterion mapping. Exact equality with documentation markers,
   `fixtures.yaml`, executable tests, case results, and master allocation is a
   prerequisite.
3. On a clean environment for each advertised platform vector, install only
   the signed package and run the unchanged legitimate baseline.
4. Execute every active row from its owning manual guide and the corresponding
   automated fixture. Record `pass`, `fail`, `blocked`, or `not-applicable`
   with the exact activation condition; no row may silently disappear.
5. Run upgrade, rollback, interrupted install, node/control loss, CRD
   conversion and relist, Control leader failover, mixed-version, stale-pin,
   policy/trust rotation, WAL/intake-cursor recovery, scale, capacity, and
   performance matrices.
6. Run the complete Hugging Face acceptance contract and live two-node probe.
7. Uninstall, inventory remaining resources, and verify no active program,
   link, map, pin, credential, route, workload, or durable owner remains.
8. Assemble and verify the signed qualification envelope from the sealed raw
   artifacts. Rebuilding or editing any input invalidates the envelope.

## Complete Active-Fixture Run Sheet

Phase 11 first owns no new Appendix C attack fixture. It owns the complete
candidate rerun. For each active fixture, use its first-owner guide below; the
Phase 11 result must contain one row for every exact active ID.

| Owner | Manual procedure |
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

For every advertised architecture/kernel/BTF/LSM order, runtime, NRI/admission
configuration, Kubernetes version, CNI order, provider adapter, and Control
mode:

- install from the immutable artifact and verify exactly one Interceptor owner;
- compare detected capability to direct kernel/runtime probes;
- verify full, reduced, observe-only, and unsupported states honestly;
- test least-privilege ServiceAccounts/RBAC, host mounts, capabilities,
  CRD/status access, network policy, storage, mTLS, bootstrap, and config
  rejection;
- upgrade and roll back BPF link/map/ABI, node/control, policy, and trust state
  without an unmeasured allow window;
- convert the CRD storage version, relist after watch compaction, fail over the
  Control writer, and prove that stale source, target, and node receipts cannot
  win; and
- uninstall and compare the final inventory to the clean baseline.

## Scale, Performance, And Correctness Matrix

Measure open, exec, and network latency distributions plus CPU, memory, WAL,
intake/graph/Control/provider backpressure, CRD watch/relist and status bounds,
rollout fanout, canonical path bounds, and maps at N and N+1. Use the same
evidence load and fixture correctness checks as baseline. Include I/O-heavy
workers, maximum advertised tasks/sockets/policies/nodes, source loss, and
recovery. A faster run that drops evidence, changes enforcement, or loses the
legitimate control fails.

## Security And Release-Envelope Checks

Manually review one Interceptor owner, one writer per durable state, node/
Control mTLS, CRD and status RBAC, tenant isolation, status-is-not-authority,
replay/anti-rollback, secret handling, self-protection, absence of arbitrary
response/provider calls, and the direct-TLS semantic limit. Recalculate every
digest referenced by the qualification envelope and verify its signature from
an independent verifier environment.

## Required Artifacts And Pass Rule

Retain all twelve Chapter 37 result records, exact registry-equality output,
complete active-fixture run sheet, owner-guide artifacts, HF/two-node bundles,
platform manifests, install/upgrade/recovery/uninstall inventories, raw
capacity/performance results, security review, signed artifacts, SBOM,
provenance, and the final qualification envelope. Any missing, mismatched,
degraded-but-unreported, or post-signing input blocks the affected claim.

## Troubleshooting

- A successful Helm rollout does not prove kernel coverage or enforcement.
- Never merge results from different artifact digests or platform vectors.
- If one active fixture lacks an executable/manual result, registry equality
  and final conformance fail even when all other rows pass.
