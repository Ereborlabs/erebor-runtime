# Phase 6: Durable Evidence, Coverage, And Recovery

Status: Done for the qualified x86_64 single-node and two-node K3s tier.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)
Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
Manual acceptance: [Phase 6 runbook](./manual-testing/phase-6-manual-acceptance.md)  
Environment setup: [shared setup guide](./manual-testing/environment-setup.md)
Implementation review: [Phase 6 review guide](./phase-6-implementation-review.md)
BPF audit: [evidence and recovery audit](../../research/mithril-bpf-evidence-recovery-audit.md)

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

## Deliverable Closure

| Deliverable | Result | Durable owner and proof |
| --- | --- | --- |
| D6.1 | Done | Production BPF emits CPU-scoped ordered records after it fixes the decision. `ObservationCanonicalizer` validates bounded `ObservationEnvelopeV1` records and deterministic identifiers. |
| D6.2 | Done | `EvidenceWal` owns immutable hash-chained segments, synchronization, bounds, replay, and exact acknowledgement removal. `EvidenceIntakeOwner` validates and synchronizes Control records and cursors before acknowledgement. |
| D6.3 | Done | `CoverageHealthOwner` owns durable healthy and gapped intervals, counter equations, exact gap reasons, recovery transitions, and negative-claim eligibility. Physical saturation proves fixed decisions and explicit ring and WAL gaps. |
| D6.4 | Done | Existing policy, native identity, mount, socket, exception, and response-floor owners recover exact retained state. The physical restart probe preserves live restrictions and installs an exact post-restart fence. |
| D6.5 | Done | `KernelHostOwner` and `NativeSecurityStateOwner` verify the exclusive lease and live map, link, program, program-tag, boot, label, capacity, and reconciliation state. A mismatch closes readiness and coverage. |
| D6.6 | Done | `DeterministicLocalWindowOwner` accepts a window only when each sequence is present exactly once and eligible coverage spans the full fixed range. Duplicate and reordered input is stable; contradictions and gaps are not ready. |

## Phase Result

```text
State: Done for the qualified x86_64 single-node and two-node K3s tier.
Validated architecture revision/digest:
  22678b9c0379ff915fe595059f3da2789c3e32cdf54d61656c7257175263d14a.
Completed deliverable IDs: D6.1-D6.6.
Files and durable owners changed: Interceptor ABI and BPF effect accounting;
  Interceptor lease, manifest, host recovery, and bundled-object tests; node
  observation model, WAL, coverage, source epochs, deterministic windows,
  Control connector, startup, policy recovery, and native reconciliation;
  Control protocol, durable evidence intake, configuration, and service;
  current-source behavioral tests and VM physical probes; BPF audit, manual
  acceptance record, and implementation review guide.
Upstream-adoption dossier IDs used: none. The BPF evidence and recovery audit
  re-audited the checked-in production programs and local Cilium and Tetragon
  sources. Audit digest:
  0e83ba85185bacb24d46c8c1c0fbc58604e1b05ca67372fa7fd338a9c1244611.
Fixture cases and exact physical results: IPC-ENDPOINT-RESTART-006,
  IPC-RELATIONSHIP-LOSS-002, LSM-DENY-SATURATION-001,
  SOURCE-KA-READER-LOSS-003, SOURCE-KA-CAPACITY-005, and
  SOURCE-KA-PARTIAL-ATTACH-001 pass. The final single-node K3s harness passes
  native and Kubernetes identity, CRI OBSERVE and PROTECT, kernel
  qualification, effect observation, local enforcement, saturation, restart
  recovery, network enforcement, benchmark, cleanup, and legitimate-control
  checks. The final two-node K3s harness reports two Ready nodes and passes
  both directions.
Commands and exact source state covered: source commit df80630;
  `bash .github/scripts/verify-rust-ci.sh`; `cargo test --workspace
  --all-targets --all-features -- --skip
  verification_bundle_is_frozen_only_for_recorded_physical_surfaces`;
  `crates/mithril-e2e/harness/vm/run.sh --with-k3s
  --skip-administrative-exec --output-directory
  /tmp/mithril-phase6-physical-20260819-r12`; and
  `crates/mithril-e2e/harness/vm/two-node-network.sh --output-directory
  /tmp/mithril-phase6-two-node-20260819-r2`. The source-only suite passes 948
  tests, with 15 ignored and 5 filtered fixture lanes. The repository gate
  passes formatting, check, Clippy, and every ordinary test. Its only failure
  is the intentionally stale generated qualification-record assertion. The
  user prohibited committing generated CI/CD digest artifacts.
Platform/kernel/runtime manifests: Ubuntu 24.04, x86_64 Linux
  6.8.0-137-generic, cgroup v2, BPF filesystem, runtime BTF, active
  lockdown/capability/Landlock/Yama/AppArmor/BPF LSM order, K3s
  v1.35.5+k3s1, and two Ready Kubernetes nodes.
Performance/capacity results: each OPEN benchmark measures 1,000,000
  operations after 100,000 warmups. Baseline is 167,317 operations/s at one
  worker and 317,599 operations/s at 32 workers. Protected is 155,272
  operations/s at one worker and 297,459 operations/s at 32 workers. Each
  effect mode attempts 50,000 saturation opens, reports 42,293 lost ring
  records, validates a 256-record durable batch, opens ring and WAL gaps, and
  blocks a negative claim while deny and benign-allow controls remain correct.
Unsupported/degraded paths: physical qualification is not claimed beyond the
  recorded x86_64 tier. The source compiles against every checked-in target
  kernel header, but those targets do not have physical proof in this result.
  The generated checked-in qualification record remains stale by instruction;
  this source branch is not a green release branch until its release owner
  refreshes that separate artifact. Distributed graph joins, notifications,
  provider connectors, and response remain excluded.
Remaining work in this phase: none within the qualified tier. Claim expansion
  requires a new qualification result.
Next phase not authorized: yes.
```
