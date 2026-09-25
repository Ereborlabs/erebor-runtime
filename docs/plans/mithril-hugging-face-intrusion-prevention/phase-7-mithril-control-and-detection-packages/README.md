# Phase 7: Control Data, Discovery, And Detection

Build Araphor's retained-data and discovery functions inside Mithril Control.
Araphor is the combined product name for Mithril and Erebor. Keep current crate,
repository and API-group names.

Master: [Mithril implementation plan](../README.md).
Read [engine-design.md](engine-design.md) for shared contracts and
[verification.md](verification.md) for limits and test cases.

## Intended end state

One default Control deployment accepts Node evidence, stores retained data in
DuckDB, serves SQL and subscriptions, coordinates traces, derives behavior and
findings, and supports agents and the console. No external platform is required.
An optional deployment runs the complete data, discovery, graph and notification
component outside Control. CLI and console can connect directly to either
deployment. Remote trace and policy mutations retain Control's authority.

ControlStore retains policy, trust, rollout and authority state. AnalysisStore
retains events, context, trace output and analysis in DuckDB with its native WAL.
Node retains its delivery WAL. A source ACK follows the data commit, not receipt
in memory. Raw input can expire while bounded profiles, findings and exact
witnesses remain available. Summary retention is not full raw-history retention.

## Implementation flow

```text
Node produces evidence under installed local policy
  -> existing authenticated Control intake validates it
  -> AnalysisStore commits events, context, receipt progress and table revisions
  -> Control acknowledges the durable contiguous source position
  -> QueryOwner wakes interested readers
  -> DiscoveryOwner derives profiles, context, methods and draft changes
  -> GraphAndFindingOwner commits qualified findings
  -> NotificationRouter applies required routes and human-acknowledgement deadlines

Agent -> CLI -----------------+
Console ----------------------+-> Control APIs -> QueryOwner -> AnalysisStore
Optional Trace CRD -> adapter +-> TraceOwner -> Node -> Interceptor -> bpftrace
                                      ^                      |
                                      +---- results ---------+
                                               |
                                               v
                                          AnalysisStore
                                               |
                                        commit notification
                                               |
                                               v
                                           QueryOwner

Reviewer approves an exact proposal
  -> publication checks current authority, source and target revisions
  -> existing policy owners compile, sign, distribute and activate
  -> agent and console read actual per-target results
```

SQL and trace work when discovery is disabled. A trace command submits one
request and follows its own output; it needs no second SQL command. Follow is
one response stream driven by committed changes. It appends immutable rows or
replaces a complete bounded query result. It has no public read-job lifecycle.

## Owners and boundaries

| Owner | Owns | Must not do |
| --- | --- | --- |
| EvidenceIntakeOwner | Existing authenticated source validation and ACK contract | ACK before durable data commit |
| AnalysisStore | One DuckDB writer, data/revision transactions, backup and recovery | Change policy/control-state persistence |
| EvidenceRetentionOwner | Age, quota, required security progress and exact witness checks | Let optional discovery lag pin raw input or stop intake |
| QueryOwner | SQL admission, scope/disclosure, isolated execution and follow | Mutate policy or attach probes |
| DiscoveryOwner | Exact profiles, context, recipes, assessments and proposals | Infer authority from repetition or model labels |
| GraphAndFindingOwner | Evidence-qualified graph and finding revisions | Infer causality from time or similarity alone |
| NotificationRouter | Mandatory priority, retries and human receipt deadlines | Let AI silence required escalation |
| TraceOwner / Node / Interceptor | Authorized intent / exact local lifetime / supervised bpftrace and cleanup | Treat pod selection as arbitrary-script confinement |
| Policy and response owners | Their existing approval and physical-effect contracts | Treat source-write success as activation or containment |

Remote placement changes where the data component runs, not these authorities.
No DataFusion layer, mandatory broker, second raw-event database, model gateway,
model runtime or Control-owned agent loop is part of this design. A generic public producer API
remains outside scope; use the existing authenticated Node service contracts.

## Discovery algorithm

1. Validate exact source identity, lifetime, context and coverage. Deduplicate
   accepted identities; reject retained conflicting bytes.
2. Build exact atoms by cohort, role, operation, resource, decision and result.
   Use checked counts and immutable manifests. Grouping is not classification.
3. Compare exact reviewed baselines and lifecycle cases. Keep new release,
   changed result, missing evidence and drift separate.
4. Select pinned context by subject, method, validity and stable ID. Include
   policy health, counterevidence and missing facts. No future review leakage.
5. Evaluate versioned recipes with positive, negative and Unknown results.
   Graph findings require their separate proof-qualified owner.
6. Validate optional local/self-hosted/approved-hosted agent assessments.
   Check citations, alternatives and six typed suggestion kinds. Models cannot
   approve policy, hide required review or create physical proof.
7. Build exact native policy edits from declared requirements. Use existing
   compilation and simulation; show permission expansion and unknown effects.

Keep the detailed algorithms in [engine-design.md](engine-design.md) and
[local-intelligence.md](local-intelligence.md). Araphor owns no model runtime,
training, embeddings or model lifecycle. Operators own external agents and
models; client compatibility measurements do not block the core release.

## Combined implementation order

Entry: qualified Mithril 6.2 intake/policy delivery and 6.3 telemetry contracts.
Use their result records; this documentation change does not rerun their proof.
Each row is a bounded deliverable. The required test level appears below.

| Order | Phase | Deliverable and entry gate |
| --- | --- | --- |
| 1 | [7.1 Contracts and offline proof](phase-7-1-contracts-and-offline-proof.md) | Freeze schemas, corpus and DuckDB durability/isolation proof. |
| 2 | [7.2 Data store](phase-7-2-data-store.md) | Durable intake, context records, commit revisions, retention, backup and upgrade; needs 7.1. |
| 3 | [7.3 Query and follow](phase-7-3-query-and-follow.md) | Isolated SQL and commit-driven append/replace streams; needs 7.2. |
| 4 | [Observability 1](../../araphor-observability/phase-1-contracts-and-backend.md), then [2](../../araphor-observability/phase-2-owned-capture.md) | Backend proof can run alongside 7.1–7.3. Capture integration requires 7.2 and backend proof. |
| 5 | [Observability 3](../../araphor-observability/phase-3-cli-api-and-console.md) | Shared protobuf gRPC, SQL/trace CLI, gRPC-Web console views, and old client-route retirement; needs 7.3 and Observability 2. |
| 6 | [7.4 Profiles and context](phase-7-4-profiles-and-context.md) | Exact discovery, baseline differences and context; start after 7.2, close view/e2e work after 7.3. Can run alongside trace work. |
| 7 | [7.5 Graphs and notifications](phase-7-5-graphs-findings-and-notifications.md) | Local packages, provenance, mandatory routes and authority records; needs 7.4. |
| 8 | [7.6 Methods and preview](phase-7-6-methods-and-preview.md) | Deterministic recipes, typed suggestions, requirements and exact native preview; needs 7.3 and 7.5. |
| 9 | [7.7 Agent classification](phase-7-7-agent-investigation-and-classification.md) | Assessment owner/API, disclosure and recorded-client proof; optional external-agent measurements are separate; needs 7.6 and Observability 3. |
| 10 | [7.8 Console and publication](phase-7-8-console-and-publication.md) | Shared review, independent approval, conditional source write and activation display; needs 7.7 and console fixture work. |
| 11 | [7.9 Remote placement](phase-7-9-remote-placement.md) | Optional full data-component deployment and direct CLI/console access with identical contracts; needs 7.8. It is not needed for embedded operation. |
| 12 | [7.10 Qualification](phase-7-10-qualification.md) | Integrated unit/e2e/physical, performance, recovery and recorded-client proof; needs 7.8 and every advertised optional phase. |
| Optional | [Observability 4](../../araphor-observability/phase-4-declarative-captures.md) | Finite Trace CRD adapter after Observability 3. |

Recommended serial route: 7.1 → 7.2 → 7.3 → Observability 1 → 2 → 3 →
7.4 → 7.5 → 7.6 → 7.7 → 7.8 → 7.9 if selected → 7.10.
Independent work may use the entry gates in the table, not skip them.

Mithril 8 follows the bounded Phase 7 release and adds Kubernetes causality
and exception tools. Mithril 9 adds verified local/distributed response.
Mithril 10 adds provider evidence/actions. Mithril 11 qualifies the complete
release. Missing later owners remain Unsupported in Phase 7.

## Test level by phase

Component tests check each changed owner. Lightweight end-to-end tests call
production owners without Kubernetes; run a physical case only where listed.

| Phase | Component tests | End-to-end and physical tests |
| --- | --- | --- |
| 7.1 | Check schema bounds, exact derivation, DuckDB recovery and SQL isolation. | Run `offline-exact` and `storage-contract` through production owners; no physical case is required. |
| 7.2 | Check transactions, receipts, retention, backup and upgrade failures. | Run `data-store-recovery` through Node mTLS, `data-store-upgrade` on fixtures and the paired physical storage/partition case. |
| 7.3 | Check SQL admission, scope, worker isolation, follow frames and cursor limits. | Run `query-follow` against AnalysisStore and QueryOwner; physical qualification follows in 7.10. |
| 7.4 | Check exact atoms, context selection, comparison and deterministic replay. | Run `context-roundtrip` and `profile-restart` from Node WAL through mTLS and DiscoveryOwner; physical qualification follows in 7.10. |
| 7.5 | Check graph, finding, provenance and routing decisions under gaps and retries. | Run `graph-notification` through intake, graph and router owners, then run the paired physical incident case. |
| 7.6 | Check method matches, suggestion validation and exact preview counterexamples. | Run `detection-context`, `proposal-preview` and `poisoned-window` through production owners; physical policy proof follows in 7.8 and 7.10. |
| 7.7 | Check assessment citations, disclosure, abstention and grant rejection. | Run `assessment-loop` with a recorded agent through CLI and gRPC; no live model or physical effect is required. |
| 7.8 | Check gRPC authorization, approval, publication and accessible UI states. | Run `review-publish` through production owners, browser gRPC-Web tests on built assets and the paired physical publication case. |
| 7.9, if selected | Check placement, delegation, cursor and retry rules. | Run `remote-placement` with separate Control and data processes, then run its paired two-node physical case. |
| 7.10 | Rerun component tests for every advertised capability. | Run the linked lightweight release case and its paired physical case; compare transitions and physical effects. |

## Acceptance and implementation status

Status: **Not done** for this target design. Reuse source and tests that meet
these contracts. A prior test on another persistence contract is not proof of
DuckDB recovery, subscriptions or remote placement.

Each implementation updates its phase with Done, Not done or Blocked; exact
revision, commands, nonzero test counts, result paths and remaining limits.
Do not create separate gap-review documents. Run crate-local unit tests and
production-owner cases in mithril-e2e in each phase, not only at the end.
Run the lightweight case before its paired physical case. No test helper may
replace a production transaction, authorization decision or execution owner.

## Supporting documents

- [Engine design](engine-design.md): data, subscriptions, algorithms and failure behavior.
- [Intelligence](local-intelligence.md): classification, model experiments and test selection.
- [Console and API](console-and-api.md): shared RPCs, grants and review behavior.
- [Verification](verification.md): case matrix, resource limits and release gates.
- [Research](research-and-demand.md): source studies and demand.
- [Manual acceptance](../manual-testing/phase-7-manual-acceptance.md): operator checks.
- [Implementation review](implementation-review.md): source reading, not target-design completion.
