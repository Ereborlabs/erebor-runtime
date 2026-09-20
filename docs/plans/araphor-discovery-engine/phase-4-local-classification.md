# Phase 4: Agent Investigation And Evidence-Backed Classification

Equip existing agents with context, query recipes, assessment validation, and
governed next steps. Compare simple interfaces on frozen tasks. Do not build a
Control-owned model runtime or provider gateway. The file path stays stable.

## Intended end state

An agent can investigate competing explanations, classify activity, and submit
a supported assessment with useful policy, test, or response suggestions.
The engine validates references and draft changes. A qualified local defender
uses a self-hosted model and the shared API; no report transfer is required.
A separately approved hosted client can use the same contract.
Classification is not grouping, authorization, or incident closure.

## Implementation flow

```text
Agent receives a scoped investigation
  -> query returns exact context, required checks, and source limitations
  -> agent queries missing facts with admitted SQL
  -> agent follows relevant revision records when new evidence is needed
  -> submit_assessment supplies conclusions, alternatives, citations, and next steps
  -> DiscoveryOwner validates report scope, revisions, references, and typed drafts
  -> ControlStore retains Suggested assessment and explicit validation errors

Required facts or export authority are absent
  -> query returns Unknown, omission, denial, or expiry
  -> assessment keeps the missing check visible
  -> no benign label, proposal, or response gains authority from absent evidence
  -> a later query has a new receipt; the old report does not change

Engineer compares interfaces
  -> frozen tasks run with specialized read wrappers, SQL, and SQL plus context
  -> the same model, evidence, and permissions apply to each variant
  -> evaluator records safety, task quality, cost, latency, and variance
  -> failed configurations remain unqualified
```

## Scope and owners

DiscoveryOwner owns query/export checks and assessment/suggestion validation.
ControlStore retains bounded query receipts and reports. External agents own
their loop, provider credentials, budgets, and model choice. Existing policy
and planned response owners retain execution authority; this phase cannot
implement their missing runtimes.

## Required changes

### Prerequisites and delivery boundary

Require Discovery 3 and Mithril 7 Done in the
[combined order](README.md#combined-implementation-order). Evaluate the local
client through the test harness and public Rust owner methods. The harness
must not reproduce query or assessment logic. No production HTTP/MCP listener
is required here: Discovery 5 connects that transport to the same methods.
Record real model evaluation separately from recorded-client contract tests.
Complete shared-record and escalation owner checks here; Discovery 5 and 6
must prove the supported deployment through the production API.

1. Add `src/discovery/assessment.rs` with
   `DiscoveryOwner::submit_assessment` and `AssessmentReport::validate`.
   Validate separate activity, detector-relative verdict, security disposition,
   impact, urgency, hypotheses, counterevidence, and missing facts. Check cited
   server receipts/evidence and exact revisions. Reject fabricated references.
   Preserve subject/finding and parent artifact references in every submission;
   the console must retrieve that same report, not a copied summary.
   Preserve Suggested versus HumanConfirmed and all mandatory review.
2. Store two versioned runbooks in the existing discovery fixture/catalog:
   credential access and deployment drift. Include exact columns, SQL recipes,
   required/optional checks, alternatives, and a stopping checklist. Use the
   context view for predictable lookups; do not requery unchanged facts.
3. Implement `DisclosurePolicyV1` at the query/export boundary: approved
   recipient/purpose, row/field scope, redaction, scoped pseudonyms, and expiry.
   Filter before evaluation so predicates/counts cannot leak hidden data.
   Fail closed. Revoke later reads; do not claim recall of prior exports.
4. Record server-known query receipts separately from client-reported model,
   checks, tokens, and cost. Bound report size and reject non-finite scores.
   Valid citations do not necessarily support a conclusion; retain reviewer
   errors and evaluate actual support. No hidden chain-of-thought collection.
5. Add `harness/discovery/evaluate.py` in `mithril-e2e`. Compare deterministic
   recipes, context-only AI, former specialized-read wrappers, one SQL tool,
   and SQL plus exact context/runbook. Wrappers are experiment-only adapters.
   Use identical workload/time splits, evidence budgets, model, and grants.
   Repeat held-out tasks at least five times; report per-task results/variance.
6. Include enforcement-oriented tasks: diagnose a missing active target,
   prepare a narrow credential-access policy, preserve a legitimate controller,
   identify an already-open socket, and request a bounded response with missing
   provider authority. Use master acceptance cases and explicit Unsupported
   owner states. A plausible response suggestion is not verified containment.
7. Report retrieval recall, supporting/refuting citations, classification
   confusion, abstention, useful suggestions, wrong approvals, completion,
   calls, bytes, tokens, cost, latency, and variance. Test prompt injection,
   poisoned history, omitted evidence, stale targets, and self-approval attempts.
   An LLM judge cannot be the sole oracle.
8. Test a simple typed classifier only where a recorded label task needs it.
   No training, embeddings, or native inference runtime is a prerequisite.
   Select a candidate only through local-intelligence.md gates. Live hosted
   experiments require approved public/synthetic data or separate disclosure
   permission. CI uses recorded client responses and makes no provider calls.

9. Qualify one existing local agent runtime and self-hosted model. Record their
   versions/artifact digests, endpoint, schema, hardware, and data policy in the
   existing manifest. Restrict test egress to Araphor and the in-network model
   endpoint. A local CLI backed by remote inference does not pass local mode.
   Include startup/unavailability and refusal; do not silently change provider.
10. Add bounded ClientDerived analysis attachments to AssessmentReport for
    static analysis of hostile fixture text. Retain original evidence digest,
    transform/version, output digest, and provenance. Apply size/redaction and
    inherited sensitivity rules before storing or rendering decoded text.
    Unverified analysis cannot create an authoritative graph edge. Never execute
    a recovered payload; dynamic analysis needs a separately approved lab.
11. Reopen the same committed investigation with a second client. It must find
    the report, missing checks, linked proposal, and owner result without the
    first client's chat. Test a critical finding with a benign model label and
    a refused analysis; neither can discharge mandatory routing or human receipt.

## Acceptance and verification

- Pass `DE-MODEL`, `DE-PACKET`, `DE-DETECT`, `DE-ASSESS`, `DE-AGENT`,
  `DE-DISCLOSE`, `DE-PROTECTION`, `DE-DEFENDER`, `DE-ESCALATION`, and
  `DE-LOOP` contracts, plus applicable limit/tenant cases.
- Credential access is not credential theft without result proof. A known
  token in memory cannot be made unread by a new file rule. Same-TLS traffic
  does not establish a provider verb.
- Query simplification must preserve required evidence and seeded security
  decisions, with no extra unsafe approvals. A lower tool count alone fails.
- Missing client/model capability does not stop deterministic review or local
  enforcement. Recorded replay makes no model call.
- Run focused owner/e2e checks and full Rust verification after Rust edits.

Proposed evaluator interface:

```sh
python3 crates/mithril-e2e/harness/discovery/evaluate.py \
  --manifest crates/mithril-e2e/fixtures/discovery/manifest.json \
  --methods deterministic,context-only,specialized-reads,sql,sql-context \
  --provider recorded --repetitions 5 \
  --output-directory /tmp/araphor-discovery-investigation
cargo test -p mithril-control discovery_assessment_ -- --nocapture
cargo test -p mithril-control discovery_disclosure_ -- --nocapture
```

Require nonzero tests, metrics, split manifest, query/report artifacts, and an
explicit Adopt/Keep unqualified result. Recorded responses prove contracts,
not live model quality or local deployment. Record the self-hosted run, network
policy evidence, model behavior, and exact shared record IDs separately here.
A recorded-only test cannot complete the local defender acceptance.

## Exclusions and stop point

No server agent loop, provider gateway, automatic closure, model self-approval,
new response actuator, or production test execution. Stop with a measured client
contract; authenticated API exposure and mutation adapters require Phase 5.

## Result

**Not done.** No client experiment, report validator, model call, or capability
integration was implemented or run in this planning change.
