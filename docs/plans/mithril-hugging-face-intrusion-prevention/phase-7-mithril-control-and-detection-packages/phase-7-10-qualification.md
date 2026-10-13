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
  -> platform fixture runs the same Rust scenario on the target platform
  -> comparison checks matching transitions and semantic result fields
  -> result records exact source revision, platform, and evidence artifacts

Physical case exposes a missing condition
  -> engineer first adds that condition to the lightweight case
  -> failing lightweight test captures the discrepancy
  -> approved implementation change corrects the owner behavior
  -> both layers run again

Resource, security, or operator gate fails
  -> release stops if the failed case is required
  -> affected capability remains unqualified
  -> prior active policies remain unchanged
  -> result states the exact remaining work and new approval boundary
```

## Scope and owners

Acceptance scenarios live in `crates/mithril-e2e/src` and use the standard Rust
test harness. Follow the
[scenario maintainability rules](../../../../crates/mithril-e2e/SCENARIO_MAINTAINABILITY_TODO.md#binding-acceptance-rules).
Use small `platform_test` functions for the applicable environments. Keep
owner calls, actions, assertions, and cleanup visible in the test body.
The common platform fixture owns placement and lifecycle mechanics.
Harnesses in `crates/mithril-e2e/harness` prepare the environment and invoke
the exact Rust tests. Inputs live in `fixtures`. Do not add scenario logic to
shell scripts or new custom test dispatchers. Tests must not read `examples/`.
Control and console owners fix their own defects. Qualification does not add
an alternative implementation of those owners.

## Required changes

### Prerequisites and delivery boundary

Status: **Not done**. Require Phase 7.8 Done and valid Mithril 6.2/6.3 prerequisite results. Follow the [combined order](README.md#combined-implementation-order).
The first capability set includes discovery, CLI SQL/follow, bounded tracing, assessments,
deterministic findings, escalation, and exact policy review/publication with
activation results. It excludes exception requests, cross-node causality,
response execution, and provider actions. Test their Unsupported states.

Require the approved Phase 7.5 package runtime and algorithm results. Rerun
[7.5.7 package qualification](phase-7-5-graphs-findings-and-notifications/phase-7-5-7-package-qualification.md)
and the required 7.5.8 and 7.5.9 algorithm cases on the release revision.
Record package digests, execution targets, input coverage, and case results.
Include the approved SQL, Wasm, and native targets. Include Python only when
advertised. Package-runtime qualification alone does not complete the two
algorithm phases. Recorded-input results do not qualify live external sources.

Require Observability 3 for the query/trace client and execution contracts.
Rerun its applicable `OBS-*` cases on the release revision; do not inherit an
earlier physical pass. The optional Trace CRD is advertised only if
Observability 4 passes on that revision. Its absence does not block CLI release.

Freeze required capabilities and cases in the fixture manifest before running
tests. Map each required case to its exact Rust test names and platforms. Run
the complete required set; do not reduce it because a service is unavailable.
A failed required capability
blocks this release. A deterministic-only release leaves assisted defense
unqualified; model absence cannot silently remove its cases.

Mithril 8, 9, and 10 reuse and extend these cases in their own result records
when they add exception, response, and provider capabilities. Mithril 11 reruns
the complete advertised set on its release revision. This phase can close its
bounded scope before those increments; it cannot claim their physical results.

1. Implement small Rust scenarios in the existing `src/discovery/` family.
   Map every required case in [verification.md](verification.md) to its
   standard Rust test names, assertions, and expected result. Keep this mapping
   in `fixtures/discovery/manifest.json`; it records coverage, not test dispatch.
   Missing required cases fail qualification. Positive actuation cases remain
   with their owning phase; unavailable-action rejection is required here.
2. Reuse the shared VM and Kubernetes platform tooling. Keep image, OIDC,
   cluster, and binary preparation in the launcher. Use the production Helm
   chart. Keep actions and assertions in Rust. Run one lifecycle and platform
   per test process. Require the passing lightweight result from the same
   revision before Kubernetes. Compare decisions and semantic fields; only
   environment identities and timestamps can differ.
3. Prove valid startup, probes, normal work, restart, shutdown, and approved
   maintenance for the stated fixture. Prove forbidden effects separately.
4. Run 7.9 embedded/remote parity and placement transfer if remote mode is
   advertised. Remote mode cannot pass by reusing an embedded-only result.
   Then measure engine and optional model cost while primary evidence and rollout
   work runs. Test noisy-neighbor quotas, a slow reader, segment/catalog growth,
   metadata WAL growth, complete-bundle backup/restore, whole-segment pin cost,
   deletion recovery, sparse-target scan limits, and retention reclamation,
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
   Test fresh-store activation, rejection of unsupported stored formats, and
   restart during publication. Do not require old-state migration.
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

Use standard Rust test discovery to check the frozen required set. Fail on
missing or unknown mapped cases and zero executed tests. A compatibility
artifact writer may retain the existing result schema; it must not execute a
hidden scenario. Reuse shared observability fixtures for capture tests. Keep
backend actions and assertions in Rust, not in a second shell runner.

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

Build and list the standard tests before qualification:

```sh
cargo test -p mithril-e2e --lib --no-run
cargo test -p mithril-e2e --lib -- --list
```

Document each exact test command, platform, lifecycle, expected result, and
artifact path under the [shared command contract](../manual-testing/README.md#command-contract).
Run applicable Host, direct-runc, and Kubernetes tests in that order. The
launcher must validate environment ownership and retain failure diagnostics.
Build and list commands do not qualify a scenario. After the final Rust edit,
run `bash .github/scripts/verify-rust-ci.sh`. Also run the required package and
UI checks. No model adoption is required for the deterministic release.

## Exclusions and stop point

Include the approved Phase 7.5 execution targets and computation-only policy
candidate exports. Those exports do not apply policy to an external system.
Do not add cloud/IAM mutation, external policy application, new execution
targets, or new agent enforcement to satisfy a release checklist. Additional
capabilities need their own approved implementation and qualification. Stop
at the declared capability set and its tested limits.
