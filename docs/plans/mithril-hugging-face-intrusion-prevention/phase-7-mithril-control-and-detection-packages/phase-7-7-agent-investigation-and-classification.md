# Phase 7.7: Agent Investigation And Evidence-Backed Classification

Equip existing agents with context, query recipes, assessment validation, and
governed next steps. Compare simple interfaces on frozen tasks. Do not build a
Control-owned model runtime or provider gateway.

## Intended end state

An agent can investigate competing explanations, classify activity, and submit
a supported assessment with useful policy, test, or response suggestions.
The engine validates references and draft changes. External agents use the
shared API; no report transfer is required. Operators own their local or hosted
models. Araphor does not train, load, host, update or roll back any model.
Classification is not grouping, authorization, or incident closure.

## Implementation flow

```text
Agent receives a scoped investigation
  -> query returns exact context, required checks, and source limitations
  -> agent queries missing facts with admitted SQL
  -> agent follows relevant revision records when new evidence is needed
  -> submit_assessment supplies conclusions, alternatives, citations, and next steps
  -> DiscoveryOwner validates report scope, revisions, references, and typed drafts
  -> AnalysisStore retains Suggested assessment and explicit validation errors

Required facts or export authority are absent
  -> query returns Unknown, omission, denial, or expiry
  -> assessment keeps the missing check visible
  -> no benign label, proposal, or response gains authority from absent evidence
  -> a later query has a new receipt; the old report does not change

Engineer compares interfaces
  -> optional client evaluations compare SQL with and without exact context
  -> the same model, evidence, and permissions apply to each variant
  -> evaluator records safety, task quality, cost, latency, and variance
  -> failed configurations remain unqualified
```

## Scope and owners

Shared Control query code enforces query/export checks. DiscoveryOwner owns
assessment/suggestion validation. AnalysisStore retains bounded query receipts
and reports. External agents own
their loop, provider credentials, budgets, and model choice. Existing policy
and planned response owners retain execution authority; this phase cannot
implement their missing runtimes.

## Required changes

### Prerequisites and delivery boundary

Require Phase 7.6. Implement and test assessment owner methods with recorded
inputs first. Require Observability 3 before client/model evaluation through
the real SQL/trace CLI. The harness calls supported owner methods; it must not
reproduce query, capture, or assessment logic.

Status: **Not done**. Observability 3 supplies authenticated query/trace APIs.
This phase adds `POST /v1/discovery/assessments` to that same listener and a
thin assessment client operation in the existing CLI/client tree. It must be
usable by the evaluated agent now. Phase 7.8 adds review/publication transport;
no second listener, model gateway or MCP dependency is required.
Mandatory completion covers the API, CLI, recorded-client contract tests,
disclosure and assessment validation. Real external-agent evaluation is a
separate compatibility result, not a prerequisite for Phase 7.8 or 7.10.
A local-defense or model-quality claim requires its actual measured result.

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
3. Extend the shared query/export enforcement from Phase 7.3 with `DisclosurePolicyV1`: approved
   recipient/purpose, row/field scope, redaction, scoped pseudonyms, and expiry.
   Filter before evaluation so predicates/counts cannot leak hidden data.
   Fail closed. Revoke later reads; do not claim recall of prior exports.
4. Record server-known query receipts separately from client-reported model,
   checks, tokens, and cost. Bound report size and reject non-finite scores.
   Valid citations do not necessarily support a conclusion; retain reviewer
   errors and evaluate actual support. No hidden chain-of-thought collection.
5. Add the optional external-client evaluator at
   `harness/discovery/evaluate.py` in `mithril-e2e`. Compare the deterministic
   baseline and the same external agent using SQL with and without exact
   context/runbooks. Use equal workload/time splits, budgets and grants.
   Repeat held-out tasks at least five times; retain failures and variance.
   Do not build specialized-read wrappers unless a measured compatibility
   question requires that separate experiment. They are not a release gate.
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
8. Keep inference, model artifacts, training, embeddings and provider access
   outside Araphor. Optional external classifier comparisons follow
   local-intelligence.md. Hosted experiments require approved public/synthetic
   data or separate disclosure permission. CI uses recorded client responses
   and makes no provider calls.
9. For an advertised external-agent compatibility claim, test the named client
   and operator-managed model. Record known versions, endpoint, hardware and
   data policy in the existing manifest; mark unknown provider facts unknown.
   A local-inference claim additionally needs restricted egress and observed
   model placement. Refusal and unavailability remain visible. These tests
   neither install a model in Araphor nor block the core phase completion.
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
12. Add a missing-measurement task through the
    [observability CLI](../../araphor-observability/README.md#cli-contract).
    The agent reads a reviewed script, runs one `araphor trace` command, and
    reads its terminal output without SQL or a custom job tool. It can use SQL
    afterward to compare retained measurements. Test denied arbitrary source,
    target replacement, incomplete output and a quiet trace. No absence or
    benign conclusion follows solely from empty stdout. A model cannot approve
    its own wider tracing authority.

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

Optional evaluator interface and required owner-test commands:

```sh
python3 crates/mithril-e2e/harness/discovery/evaluate.py \
  --manifest crates/mithril-e2e/fixtures/discovery/manifest.json \
  --methods deterministic,sql,sql-context \
  --provider recorded --repetitions 5 \
  --output-directory /tmp/araphor-discovery-investigation
cargo test -p mithril-control discovery_assessment_ -- --nocapture
cargo test -p mithril-control discovery_disclosure_ -- --nocapture
```

Core tests require nonzero assertions and retained query/report artifacts.
An optional client experiment also requires metrics, a split manifest and an
explicit Adopt/Keep unqualified result. Recorded responses prove contracts,
not live model quality or local inference. When a real-client capability is
advertised, record its run, network observations and shared record IDs separately.
A recorded-only test cannot establish live agent quality or local inference.
It can complete the mandatory Araphor client/assessment contract.

### End-to-end deliverable

Add `assessment-loop` to the existing discovery e2e binary. A recorded agent
uses production HTTP and query/trace CLI, cites server receipts, submits a report,
then exits. Another client reads the same report and missing checks. Test forged
citations, irrelevant support, stale targets, indirect injection, export
revocation, model refusal and unsupported response. Do not replace owner
validation with an evaluator helper. UI/API approval stays unavailable to
investigator credentials.

```sh
cargo run -p mithril-e2e --bin mithril_discovery_test -- --case assessment-loop --output-directory /tmp/araphor-assessment
```

Recorded-client contract tests are mandatory and determine this phase's Done
status. Real client/model measurements have separate compatibility results;
deterministic tests must not call a provider. A failed optional client result
does not block Phase 7.8 or 7.10 and cannot be reported as completed local defense.

## Exclusions and stop point

No server agent loop, provider gateway, automatic closure, model self-approval,
new response actuator, or production test execution. Stop with a measured client
contract; review/publication adapters belong to Phase 7.8.
