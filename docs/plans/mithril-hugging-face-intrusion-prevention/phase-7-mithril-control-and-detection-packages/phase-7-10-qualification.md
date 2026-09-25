# Phase 7.10: Qualification And Bounded Release

Prove the end-to-end review and publication path on the declared platform and
policy subset. Measure agent investigation quality, resource use, disclosure
controls, and operator outcomes before release.

## Intended end state

The release record names exact source versions, supported families, tested
platforms, known limits, and paired lightweight/physical results. It contains
no inherited pass or unsupported prevention claim.

## Implementation flow

```text
Engineer runs a reviewed qualification case
  -> lightweight case calls supported production owner APIs
  -> case records profile, proposal, review, source, and result fields
  -> paired physical harness runs the same decisions on the target platform
  -> comparison checks matching transitions and semantic result fields
  -> result records exact source revision, platform, and evidence artifacts

Physical case exposes a missing condition
  -> engineer first adds that condition to the lightweight case
  -> failing lightweight test captures the discrepancy
  -> approved implementation change corrects the owner behavior
  -> both layers run again

Resource, security, or operator gate fails
  -> release excludes the affected capability or stops
  -> prior active policies remain unchanged
  -> result states the exact remaining work and new approval boundary
```

## Scope and owners

Lightweight cases live in `crates/mithril-e2e/src`; command entry points live in
`src/bin`. Physical harnesses live in `crates/mithril-e2e/harness`; automated
inputs live in `fixtures`. Automated tests must not read `examples/`.
Control and console owners fix their own defects. Qualification does not add
an alternative implementation of those owners.

## Required changes

### Prerequisites and delivery boundary

Status: **Not done**. Require Phase 7.8 Done and valid Mithril 6.2/6.3 prerequisite results. Follow the [combined order](README.md#combined-implementation-order).
The first capability set includes discovery, CLI SQL/follow, bounded tracing, assessments,
deterministic findings, escalation, and exact policy review/publication with
activation results. It excludes exception requests, cross-node causality,
response execution, and provider actions. Test their Unsupported states.

Require Observability 3 for the query/trace client and execution contracts.
Rerun its applicable `OBS-*` cases on the release revision; do not inherit an
earlier physical pass. The optional Trace CRD is advertised only if
Observability 4 passes on that revision. Its absence does not block CLI release.

Freeze required capabilities and cases in the fixture manifest before running
tests. `--case all` must run all cases required by that declared set; it must
not infer a smaller set from unavailable services. A failed required capability
blocks this release. A deterministic-only release leaves assisted defense
unqualified; model absence cannot silently remove its cases.

Mithril 8, 9, and 10 reuse and extend these cases in their own result records
when they add exception, response, and provider capabilities. Mithril 11 reruns
the complete advertised set on its release revision. This phase can close its
bounded scope before those increments; it cannot claim their physical results.

1. Complete `crates/mithril-e2e/src/discovery.rs`, its
   `src/bin/mithril_discovery_test.rs` entry point, and
   `fixtures/discovery/manifest.json`. Map every required case in
   [verification.md](verification.md) to an executable assertion and expected
   result for the frozen capability set. Missing required cases fail the
   qualification summary. Later positive actuation cases remain assigned to
   their Mithril owner phase; unavailable-action rejection is required now.
2. Add `harness/vm/discovery.sh` using the existing owned two-node environment
   and cleanup contract. Reuse its images, OIDC fixture, and production Helm
   chart; do not add another VM provider. Require a passing lightweight result
   from the same revision before the physical case. Compare semantic fields;
   only environment identities and timestamps can differ.
3. Prove valid startup, probes, normal work, restart, shutdown, and approved
   maintenance for the stated fixture. Prove forbidden effects separately.
4. Run 7.9 embedded/remote parity and placement transfer if remote mode is
   advertised. Remote mode cannot pass by reusing an embedded-only result.
   Then measure engine and optional model cost while primary evidence and rollout
   work runs. Test noisy-neighbor quotas, a slow reader, native WAL growth, backup/restore, retention reclamation,
   append/replace follow replay, worker failure, and count recovery after termination.
5. Run the operator task study with raw-event review and deterministic recipes.
   Record task time, missing context, benign positives and wrong approvals.
   If an external-agent capability is advertised, compare that agent's SQL
   with and without exact context/runbooks on the same tasks. Report retrieval,
   supported claims, classification, suggestions, cost and failures separately.
   Specialized-read wrappers are not required. Fewer rows do not prove quality.
6. Add discovery operation instructions to the existing package/harness
   documentation: enable/disable derivation, query/follow, recover cursor expiry,
   inspect gaps, expire bundles, revoke export, resolve stale writes, and submit
   reviewed rollback or qualified response.
   Test upgrade from old records/state and restart during publication.
7. Add deterministic discovery checks and UI checks to `.github/workflows/ci.yml`.
   Keep physical qualification in its existing environment-dependent lane.
   Record the supported source/policy/platform matrix and results here.
8. Run disclosure and indirect-injection cases through CLI/native gRPC, browser
   gRPC-Web, and a recorded external client. Verify exact returned fields, limits, revocation, and
   fail-closed behavior before SQL evaluation. CI must not upload private traces.
   Measure live model quality only with an approved client and corpus.
9. Map every advertised protection/response tool to the master standing
   acceptance and qualified owner. Run unchanged-worker legitimate controls,
   in-process credential access, already-resident credentials, same-TLS semantic
   limits, existing-flow containment, replacements, and missing provider authority.
   Require actual readback/watch for containment claims. A source write, kill
   acknowledgement, query result, or synthetic graph is not physical proof.
10. Publish a capability result matrix: investigation, draft validation, local
    prevention, policy publication/activation, exceptions, causal findings,
    local/distributed response, and each provider action. Mark unsupported or
    unfinished dependencies explicitly. This discovery plan cannot inherit the
    master's complete Hugging Face conformance claim.

11. Run the complete recorded external-client case, not separate component
    demos. The client and console must cite identical subject/finding, assessment,
    approval, action, and result revisions. Interrupt the agent after submission
    and after an uncertain mutation reply. Resume from committed records; require
    no chat transfer and no duplicate effect.
12. Test mandatory criticality and human escalation with model refusal, benign
    misclassification, route failure, missing acknowledgement, restart, and late
    evidence. Measure source receipt to required notification, acknowledgement,
    authorized action, and verified result separately. Keep the configured
    deadlines and failures in the result. AI summary latency cannot hide a missed
    escalation deadline.
13. Only when local external-agent compatibility is advertised, prove that the
    operator-managed client reaches no hosted inference endpoint. Record actual
    network observations and known client/model versions. A recorded client
    proves API behavior, not inference location or useful model analysis.
    Araphor does not provision, host or manage the model.
14. Run a missing-measurement task through one foreground `araphor trace`
    command. Verify its source, target, output, limits, cleanup, and console
    result. SQL remains optional for later correlation. Test agent interruption,
    a quiet script, missing terminal output, stale target, denied host source,
    and enforced local expiry during a Control outage. Diagnostic failure must
    not disable prevention or mandatory escalation. Run optional MCP checks
    only if that adapter is part of the declared release.

Add `all` to the existing discovery binary. It must enumerate the frozen
required cases from verification.md, fail on unknown/missing cases, and report
nonzero assertion counts. Reuse `harness/observability/` for physical trace
cases; do not duplicate its backend lifecycle runner.

Complete this subphase after the required core Phase 7 gates pass. Phase 7.7
completion does not depend on a live model. Optional client compatibility
claims require their separate tests; they cannot replace a missing core gate.
This result closes Phase 7; it does not require a prior Phase 7 Done result.

## Acceptance and verification

- No mandatory case is omitted or converted from Unknown to Pass.
- Deterministic mode meets every required security and publication case.
- External agent configuration meets its measured adoption gate or remains unqualified.
- Disabled assistance cannot be reported as a completed agent investigation
  capability. Pin model, prompts, methods, runbooks, schemas, and context policy;
  changes require held-out evaluation and repeated task runs before qualification.
- The physical effect claim has the actual actor/kernel/provider evidence
  required by that source family, not only a successful API response.
- Run final Rust verification and all console checks after the last change.
- Pass `DE-QUERY`, `DE-FOLLOW`, `DE-PROTECTION`, `DE-DEFENDER`, `DE-ESCALATION`,
  and `DE-LOOP` for the frozen capability set. Notification and the
  policy-change loop require real owners. Response/provider success cases
  cannot pass by omission or substitute fixtures; retain their future
  allocation and prove Unsupported until their owner phase qualifies them.
- Store a bounded reproducible evidence bundle and its retention/expiry state.
- Document unsupported source families and policy semantics prominently.

Add these final entry points and record their output digests in this phase:

```sh
cargo run -p mithril-e2e --bin mithril_discovery_test -- \
  --case all --output-directory /tmp/araphor-discovery-lightweight
bash crates/mithril-e2e/harness/vm/discovery.sh \
  --environment /tmp/mithril-two-node/retained-environment.json \
  --lightweight-result /tmp/araphor-discovery-lightweight/result.json \
  --output-directory /tmp/araphor-discovery-physical
bash .github/scripts/verify-rust-ci.sh
```

The first two commands are proposed interfaces. The harness must validate
environment ownership before mutation and retain `result.json` plus cleanup
results on failure. Also run the package and UI commands from Phase 7.8 after
the final edit. No model adoption is required for the deterministic release.

## Exclusions and stop point

Do not add cloud/IAM mutation, external policy export, Wasm extensions, or new
agent enforcement to satisfy a release checklist. Each needs its own approved
implementation and qualification. Stop at the tested native scope.
