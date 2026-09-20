# Phase 6: Qualification And Bounded Release

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

Require Discovery 5 and Mithril 7 Done, including valid Mithril 6.2/6.3
prerequisite results. Follow the [combined order](README.md#combined-implementation-order).
The first capability set includes discovery, query/follow, assessments,
deterministic findings, escalation, and exact policy review/publication with
activation results. It excludes exception requests, cross-node causality,
response execution, and provider actions. Test their Unsupported states.

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
4. Measure engine and optional model cost while primary evidence and rollout
   work runs. Test noisy-neighbor quotas, a slow reader, WAL growth, index
   rebuild, query/follow replay, worker failure, and count recovery after termination.
5. Run the operator task study and record failures, not only successful paths.
   Compare raw-event review, deterministic recipes, context-only AI, specialized
   read wrappers, SQL, and SQL plus context/runbooks on the same tasks. Report retrieval recall, supported claims,
   counterevidence found, classification errors, useful suggestions, completion,
   calls/tokens/cost, time, and wrong approvals. Include missing context and
   benign positives. Fewer rows or longer summaries do not pass this gate.
6. Add discovery operation instructions to the existing package/harness
   documentation: enable/disable derivation, query/follow, recover cursor expiry,
   inspect gaps, expire bundles, revoke export, resolve stale writes, and submit
   reviewed rollback or qualified response.
   Test upgrade from old records/state and restart during publication.
7. Add deterministic discovery checks and UI checks to `.github/workflows/ci.yml`.
   Keep physical qualification in its existing environment-dependent lane.
   Record the supported source/policy/platform matrix and results here.
8. Run disclosure and indirect-injection cases through HTTP/MCP and a recorded
   external client. Verify exact returned fields, limits, revocation, and
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

11. Run the complete local-defender case, not separate component demos. The
    local agent and console must cite identical subject/finding, assessment,
    approval, action, and result revisions. Interrupt the agent after submission
    and after an uncertain mutation reply. Resume from committed records; require
    no chat transfer and no duplicate effect.
12. Test mandatory criticality and human escalation with model refusal, benign
    misclassification, route failure, missing acknowledgement, restart, and late
    evidence. Measure source receipt to required notification, acknowledgement,
    authorized action, and verified result separately. Keep the configured
    deadlines and failures in the result. AI summary latency cannot hide a missed
    escalation deadline.
13. Prove that local mode reaches no hosted inference endpoint after model
    provisioning. Record model/client versions and actual network observations.
    A stub proves schema behavior, not local inference or useful hostile-evidence
    analysis. Keep unsupported dependencies explicit in the end-to-end result.

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
results on failure. Also run the package and UI commands from Phase 5 after
the final edit. No model adoption is required for the deterministic release.

## Exclusions and stop point

Do not add cloud/IAM mutation, external policy export, Wasm extensions, or new
agent enforcement to satisfy a release checklist. Each needs its own approved
implementation and qualification. Stop at the tested native scope.

## Result

**Not done.** No qualification, operator study, performance measurement, or
release occurred in this planning change.
