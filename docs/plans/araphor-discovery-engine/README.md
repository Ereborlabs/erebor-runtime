# Araphor Discovery Engine Plan

This plan adds the discovery and defender workflow to one Araphor system.
The console and a local, self-hosted, or approved hosted agent use the same
evidence, findings, assessments, approvals, and action results. Existing owners
enforce and verify changes. Event grouping and model output support that loop;
neither is the final protection result.

## Intended end state

An agent or operator can answer these questions for an exact workload revision:

- What behavior did the available sources record?
- Why did a detection match, and which alternative explanation fits the facts?
- Is this expected activity, a configuration fault, suspected abuse, or unknown?
- Which evidence supports or contradicts that assessment?
- What behavior does the application owner require?
- What would the proposed policy change, and what remains unknown?
- Which test would resolve an important unknown?
- Who approved this revision, where is it active, and what changed afterward?

The deterministic core supplies qualified facts, bounded queries, detection
evaluations, revision comparisons, and validation. Agents use these methods
through the same owner as the console. Local, self-hosted, or hosted models can
investigate competing explanations and propose classifications and next steps.
Deployment location is a data-disclosure choice, not a correctness guarantee.
Model output remains a versioned assessment; it cannot grant authority, erase
evidence, close an incident, or publish a change. Deterministic mode remains
useful, but label-only assistance does not meet the agent investigation goal.

The first delivery equips existing agents with documented query/follow reads,
assessment submission, and governed policy proposal/publication tools. Response
and exception tools use their own qualified owners and separate grants.
One query tool is an example of simple investigation, not the whole product.
The local defender is a supported deployment, not a report-import workaround.
Its agent runtime and model can run inside the operator's network. It submits
assessments and follows results through the same API as the console. Control
does not need another model runtime, case database, or workflow service.

The first supported policy output is the existing typed workload policy family.
Agent sessions use the same review concepts, but retain their own action and
authorization contracts. Shared navigation does not imply shared enforcement.

## Implementation flow

```text
A protected workload attempts an effect
  -> Node applies the installed signed policy without an AI or SQL round trip
  -> accepted evidence records identity, decision, physical result, and coverage
  -> Control updates the shared bounded projection and discovery context
  -> qualified detection packages create immutable findings from that evidence
  -> NotificationRouter applies the approved severity floor and escalation deadline

A local defender or operator opens the workload or finding
  -> the shared query returns the same scoped owner records and exact revisions
  -> the defender tests hypotheses and submits a cited assessment through the API
  -> the console shows that assessment without a report export/import step
  -> missing checks and model refusal remain visible
  -> mandatory escalation continues even if the model suggests benign activity

A reviewer selects a suggested protection or response change
  -> the owning policy or response validator freezes inputs and affected targets
  -> preview states known effects, unknowns, and shared blast radius
  -> independent approval or exact preauthorization permits only the named change
  -> the execution owner revalidates targets and records the operation durably
  -> policy activation or response readback returns through the same owner views
  -> the defender and console follow that operation's actual revision

Late evidence or a replacement workload appears
  -> existing finding and response owners record a new linked revision
  -> the old approval cannot authorize the changed target or wider action
  -> the same investigation view shows the open branch and missing authority
  -> containment remains Partial or Unknown until its postconditions are proved

A client, model, or query becomes unavailable
  -> local enforcement and deterministic escalation continue
  -> another authorized client reopens committed records without private chat state
  -> uncertain mutation results are reconciled at their owner before retry
  -> a disconnected client does not cancel an applied restriction

Control restarts or retained input is incomplete
  -> each existing owner restores its own durable checkpoint
  -> the shared projection is rebuilt from retained authoritative records
  -> gaps and unavailable owners remain explicit
  -> discovery never advances another consumer's retention watermark
```

## Status and source baseline

- Plan status: In progress, 2026-09-21. The approved Now work is complete.
- Implementation result: Phase 1 **Done**. The offline contracts, frozen
  synthetic corpus, source-extension review, and native SQLite selection pass.
  Phase 2 is **Done** at implementation source `eff08be`. See the
  [offline result](phase-1-contracts-and-offline-proof.md#result) and
  [durable implementation result](phase-2-durable-behavior-profiles.md#result).
- Completed assignment: Discovery 1 and 2. The user assigns Mithril 6.2 to
  another agent and accepts that prerequisite as complete for sequencing.
  Its qualification record remains with that agent. This work does not repeat
  the Mithril qualification or start Mithril 7 or Discovery 3. The next work
  in the combined order is Mithril 7, then Discovery 3. New approval is required.
- Plan location: `worktrees/mithril-ui`, branch `codex/mithril-ui`.
- Phase 1 source baseline: main `36cf6449`. The rebased implementation commits
  include `ef00f8ce` (offline foundation), `e9494488` (reference checks),
  `d037b61a` (native SQLite proof), and `6aa98343` (frozen corpus). The final
  validity checks and source review are recorded in the phase result.
- The planning-only UI snapshot was
  `bc090201c1d2bd96b1b098d2f7bd6c104867b4db`, with main at
  `787c03233ea1cf1593fd487b086c2e467e855a21`.
- Primary `main` was previously inspected at `fc5bce3b`; the prior review recorded HEAD
  `ca695560d7e2dae07ec3675297f0ebc0d870419e`. The prior review includes BPF test
  changes such as `df198b60`. Do not infer a present test gap from the
  console plan's older source snapshot. Reconcile source before implementation.
- The implementation review used both `main:.agents/planning.md` and the
  primary checkout's current `.agents/planning.md`. The latter adds the
  required end-state and event-flow format. That user change was not edited.
- The phase files assign each verified implementation gap to concrete source
  changes and tests.
- The sequencing review inspected primary `main` at
  `e5c80932c92d929f5b46ed4101ce500a335d01ae`, including its working changes.
  Mithril 6.3 is recorded Done. Control reconciliation, durable evidence intake,
  approval reservation, late argument checks, and running-container recovery
  exist. Older 6.2 closure text is not a current list of missing code.
  The focused review passed 38 telemetry, logging, evidence, and reconciliation
  tests; it did not rerun full CI or physical qualification or close 6.2.
- Discovery Engine clone: `0b5b73425c5aec89b803e737b188b2a331d0e218`, dated
  2023-09-12, remote `https://github.com/accuknox/discovery-engine`.
- The clone was read, not run or changed. Its date does not establish the
  status of AccuKnox's other products or private development.
- Kubewarden `adm-controller` clone:
  `2e0f9ef5f1e0437b017879755ec6636aecb2eba5`, dated 2026-09-14. Shared evaluation,
  context replay, audit limits, and artifact verification informed the design.

Product text uses Araphor. Repository, crate, protocol, and CRD names retain
their existing identifiers. This plan does not rename the repository.

## Read order

1. [Research and demand](research-and-demand.md): source trace, operator reports,
   other projects, and requirements derived from them.
2. [Engine design](engine-design.md): owners, data contracts, algorithms,
   persistence, security, and publication.
3. [Investigation and intelligence](local-intelligence.md): agent workflow,
   classification, local/hosted execution, disclosure controls, and evaluation.
   The file path stays unchanged to preserve links.
4. [Console and API](console-and-api.md): operator journeys, proposed requests,
   permissions, and failure states.
5. [Verification](verification.md): test corpus, physical qualification,
   resource limits, and release gates.

## Product decision

Build one evidence-to-action workflow. Measure detection-to-escalation time,
investigation quality, approval correctness, action postconditions, and operator
work. An assessment is useful only if the next owner can consume its exact
references and return a result to the same view. A smaller event list, a fluent
summary, or a tool-call success cannot substitute for that result.

Keep facts, assessments, requirements, and changes separate:

| Artifact | Meaning | Cannot establish |
| --- | --- | --- |
| BehaviorSnapshot | What named sources recorded for a pinned scope | Required or authorized behavior |
| ContextPacket | Facts, source health, rule/runbook context, and reviewed history for one question | Complete knowledge or permission to disclose data to a provider |
| DetectionAssessment | A versioned method's matches, counterevidence, and coverage | Causality or an authoritative incident finding |
| ClassificationAssessment | Suggested disposition, impact, hypotheses, and cited reasons | Confirmed fact, incident closure, or authorization |
| Suggestion | A typed next step with preconditions, risks, and validation state | Permission to execute or publish |
| RequirementSet | What an authorized owner says must work, with reasons and tests | That the implementation enforces it |
| DiscoveryProposal | A specific native policy change with provenance and preview | Approval, activation, or physical prevention |

The `TestRequest` output identifies a missing case. It is a request,
not an executable command. This lets discovery improve qualification instead
of treating a longer production observation period as the only way to learn.

## Protection is more than investigation

The [master-plan integration](engine-design.md#protection-boundary-and-master-plan-integration)
binds this design to local prevention, causal findings, bounded exceptions,
distributed containment, provider recovery, and physical verification.
Installed protection denies prohibited effects without waiting for AI or SQL.
Agents help inspect coverage, prepare changes, and use separately authorized
tools; they are not the synchronous enforcement boundary.

The first discovery slice does not complete the Hugging Face master plan.
Its graph/response/provider owners are explicit dependencies. Keep their
unavailable operations visible with reasons; do not replace missing containment
with an assessment or a policy-write acknowledgement. Do not amend the master
owner allocation or implement those dependencies without separate approval.

## Existing owners and dependencies

| Owner | Role in this plan |
| --- | --- |
| `EvidenceIntakeOwner` | Authenticate, validate, and persist accepted evidence. No duplicate collector. |
| `EvidenceRetentionOwner` | Govern disposal. Discovery cannot advance a shared consumption watermark on behalf of other consumers. |
| `ControlStore` | Persist authoritative heads and immutable artifacts; own one rebuildable embedded database selected by the storage experiment. No new database service. |
| Proposed `DiscoveryOwner` | Derive context, method results, assessments, suggestions, proposals, and review records. Own bounded query execution and draft validation, not the agent loop. Cannot sign or activate policy. |
| Proposed source publication adapter | Conditionally replace an existing authorized Kubernetes policy resource. The present reconciler is not a source-write API. |
| Existing policy compiler, signer, reconciliation owners | Process accepted typed sources, compiled artifacts, desired state, and rollout. |
| Mithril Node and shared Interceptor | Retain physical identity, activation, effect, and evidence ownership. |
| Planned `GraphAndFindingOwner` | Own causal graph and finding revisions over the shared accepted-evidence read contract. No second incident graph. |
| Planned `NotificationRouter` | Own deterministic routing, delivery retries, escalation deadlines, and human acknowledgement. Model output cannot silence a mandatory route. |
| Planned `ResponseCoordinator` and typed actuators | Own approved response, exact target revalidation, physical readback, and healthy watch. Agent and console use the same records. |
| Araphor console | Render and submit scoped operations. Browser state is not policy authority. |

Read the existing [Control and detection plan](../mithril-hugging-face-intrusion-prevention/phase-7-mithril-control-and-detection-packages.md)
before adding accepted-evidence indexes or retention consumers. Its graph owner
is planned, not an available implementation dependency. The first discovery
slice can consume bounded accepted-evidence exports without an incident graph.
This plan owns the bounded accepted-evidence reader. Detection can reuse it.
Discovery copies retained inputs into bounded immutable bundles. It does not
register a second consumption watermark or depend on the planned graph owner.
Existing `FindingSpecV1` and `DetectionDispositionRuleV1` are policy-source
contracts, not a general investigation-query API. Discovery adds bounded
SQL reads and qualified query recipes now. Authoritative incident graphs, detector
notifications, and response execution stay with their existing or planned
owners. A matching temporal sequence is not a new causal edge.

The existing [architecture](../mithril-hugging-face-intrusion-prevention/policy-and-protection-algorithm-architecture-readable.md)
requires review-only learning and rejects purpose inferred from argv or timing.
This plan preserves those requirements. It extends the
[console plan](../araphor-console/README.md); it does not silently connect its
sample controls to production services.

## Ordered implementation

The user approved Phases 1 and 2. Both are **Done**; Phases 3 through 6 remain
**Not done**. This approval does not include Phase 3 or later work.

| Phase | Output | Stop condition |
| --- | --- | --- |
| [1 — Contracts and feasibility](phase-1-contracts-and-offline-proof.md) | Evidence/query contracts, HF capability map, corpus, SQL isolation and SQLite/DuckDB experiment | Resolve input ownership, isolation, and one store before durable implementation. |
| [2 — Durable evidence and context](phase-2-durable-behavior-profiles.md) | Continuous bounded export, exact aggregates, versioned context, durable revision feed | No policy publication or model calls. |
| [3 — Detection methods and validated suggestions](phase-3-proposals-and-preview.md) | SQL/query-follow owner, recipes, typed suggestions, exact policy preview | No model-dependent authority or live publication. |
| [4 — Agent investigation and classification](phase-4-local-classification.md) | First-class local defender, shared assessment records, and client/model evaluation | No server model loop or unqualified assessment method. |
| [5 — Agent API, console, and publication](phase-5-console-and-publication.md) | Shared investigation, escalation, and governed policy tools | Response and exception execution adapters are delivered with Mithril 8–10, not required to close this phase. |
| [6 — Qualification and bounded release](phase-6-qualification.md) | Local-defense loop proof, escalation failures, and master-aligned physical claims | Do not claim full HF protection from investigation or policy-preview tests. |

```text
1 contracts, frozen investigation corpus, and storage experiment
  -> 2 durable facts and scoped context retrieval
  -> 3 deterministic methods and suggestion validation
  -> 4 client-owned investigation and checked assessment reports
  -> 5 shared agent/console API and authorized publication
  -> 6 task evaluation, physical qualification, and release decision
```

The core can be released without a model, but that does not complete the
assisted defense acceptance cases. Phase 4 tests owner methods and the local
client contract. Phase 5 connects the same records to console and execution.
Phase 6 proves the complete available-owner loop, not a set of unrelated demos.
Console fixture work can start after Phase 1; live requests require Phase 5.
Implementation approval remains per phase.

### Combined implementation order

This table sets the order across the three existing plan families. Discovery
phase numbers and console phase numbers are not Mithril phase numbers.
Mithril 0–6.1 are prerequisite work; do not repeat their implementation.
Mithril 6.3 is already recorded Done. Finish and reconcile the remaining
Mithril 6.2 qualification against current code, not its older missing-code list.
The user approved the Now work after this order was recorded. Start Discovery
2 only after Discovery 1 is Done. This approval does not authorize deployment
or the later API, response, and console work.

| Order | Work | Entry gate | Required output before the next dependent work |
| --- | --- | --- | --- |
| 1 | Discovery 1; continue Mithril 6.2 closure separately | Reconcile the implementation checkout with current main and preserve working changes | Freeze evidence, query, shared-reference, and owner-extension contracts. Select one store from measured SQLite/DuckDB tests. |
| 2 | Discovery 2 | Discovery 1 Done | Add bounded ControlStore reads, compatible Node context, durable profiles, one derived store, and a committed revision feed. Test continued intake and rollout during discovery failure. This development can overlap 6.2 closure; keep discovery disabled by default. |
| 3 | Mithril 7 | Mithril 6.2 and 6.3 Done; Discovery 2 Done | Reuse the reader and derived store. Add deterministic graph/finding packages, provenance, and NotificationRouter records and owner methods. Do not wait for the public console API. |
| 4 | Discovery 3, then Discovery 4 | Mithril 7 Done; each preceding discovery phase Done | Add isolated query/follow, recipes, suggestions, policy preview, assessment validation, and local-client evaluation. Test real finding and notification records through owner APIs. No production HTTP/MCP exposure yet. |
| 5 | Discovery 5 | Discovery 4 Done; console fixture phases 1–4 Done | Connect authenticated HTTP/MCP and the existing console. Deliver query, assessment submission, policy proposal/publication, and notification reads/human acknowledgement. Keep response and exception execution unavailable. |
| 6 | Discovery 6: first bounded release | Discovery 5 Done and current prerequisite qualification valid | Prove the local investigation, escalation, approved policy change, and activation loop. Record deterministic and assisted results separately. Do not claim cross-node containment or full HF conformance. |
| 7 | Mithril 8 plus its console/tool integration | Mithril 7 and the bounded discovery release Done | Extend the same graph, context, and query views with qualified Kubernetes causality. Add the qualified bounded-exception request adapter. Response execution remains unavailable. |
| 8 | Mithril 9 plus its console/tool integration | Mithril 8 Done | Implement ResponseCoordinator and local/Kubernetes actuators first. Then connect plan_response and execute_response, shared result views, and physical readback/watch tests. |
| 9 | Mithril 10, then Mithril 11 | Each preceding Mithril phase Done | Qualify each provider source/action and extend the same views/tools in 10. In 11, rerun integrated discovery, defender, console, upgrade, performance, and complete HF conformance on the release revision. |

Console fixture phases 1, 2, 3, and 4 run in their existing order after
Discovery 1 freezes the records. They can run alongside Discovery 2 through 4
and Mithril 7. They have no live connection and must finish before Discovery 5
connects those screens. Do not build a second shell or repeat the fixture plan
inside Discovery 5.

If Mithril 6.2 closure is delayed, approved Discovery 1 and 2 work and console
fixtures can continue. Do not mark Mithril 7 ready or release discovery against
an unqualified prerequisite. Read-only development is not a production claim.
Revalidate affected evidence/context contracts if closure changes their source.

### Ownership and completion gates

- Discovery 1 freezes the shared contracts; Discovery 2 implements the bounded
  reader and derived storage once. Mithril 7 adds graph/finding records and
  package checkpoints to that store. It does not create another raw-event DB.
- Mithril 7 completes its owner methods and committed projections before
  Discovery 3. Discovery 5 supplies HTTP/MCP and console access. This avoids a
  dependency cycle between findings and the public API.
- Discovery 5 closes on investigation, assessment, notification, and exact
  policy publication. Mithril 8 owns exception request integration; Mithril 9
  owns local/Kubernetes response tools; Mithril 10 owns provider extensions.
  Their future work must not keep Discovery 5 or 6 permanently Not done.
- Each later Mithril phase includes its adapter, console, authorization, and
  paired physical proof in its own result. Reuse Discovery 6 cases; do not
  create another integration phase or inherit an earlier physical pass.
- Discovery 6 can record a bounded release Done while later capabilities stay
  Unsupported with named owner phases. A missing mandatory case for the
  bounded release blocks it. A model-free result cannot complete assisted
  defense, and neither result completes Mithril 11.

The first live slice updates an existing `WorkloadProtectionPolicy` for
declared roles and exact, source-bound file/execute selectors. It does not
discover arbitrary paths from opaque IDs or bootstrap a policy for an
unbound workload. Such observations remain visible as unresolved items.
Dynamic exception authority and unrecorded runtime state cannot receive an
exact preview claim from the static simulator. Broader source support needs
its own qualified inputs before it can produce publishable output.

## Explicit non-goals and later decision gates

- Do not fork or deploy Discovery Engine as a new Araphor service.
- Do not add Kafka, a vector database, a distributed stream processor, a GPU
  requirement, or a second eBPF collector for the first release.
- Do not learn actor authority from command names, predicted intent, or
  frequency. Do not learn provider API verbs from encrypted connections.
- Do not replace the existing compiler or `PolicySimulator` with Cedar, an
  LLM, or a new generic authorization language.
- Do not auto-deploy, auto-remove unused grants, or auto-expand a baseline.
- Do not attach a classifier to a synchronous kernel authorization path.
- Do not implement a second response owner. Expose response tools only through
  the master's qualified coordinator and capability-specific actuators.

Later candidates are network-policy exports, signed portable behavior
artifacts, new agent/tool evidence-source adapters, and
capability-limited Wasm analyzers when a third-party analyzer is required.
Each requires a named consumer, supported semantics, qualification, and a
separate approval. They are design extensions in the supporting documents,
not prerequisites for useful native discovery.

## Implementation decisions and remaining gates

| Decision | Proposed default | Resolve before |
| --- | --- | --- |
| Missing decision context | Preserve existing ABI fields and bounded Node-owned context in the existing evidence path; reuse Control workload facts | Phase 2 wire compatibility and replay tests |
| Shared evidence reader and retention | Bounded export; no discovery acknowledgement of the shared watermark | Phase 2 retention-race tests |
| Aggregation and database | SQLite selected with pinned `rusqlite` 0.40.2 and bundled SQLite 3.53.2; native memory, isolation, crash, disk-full, and repeat-run gates passed | Phase 2 durable integration is Done. Live overhead and enablement limits are recorded in its result; qualify deployment-specific latency before enablement. |
| Noise reduction | Exact groups plus rule intent, workload context, counterevidence, reviewed history, and tested suggestions; no automatic exceptions or incident closure | Phase 3 methods and Phase 6 task study |
| Intelligence methods | Deterministic methods first; compare typed classification and one existing agent on documented SQL/context on the same tasks | Phase 4 measured adoption decision |
| Model location | Local, self-hosted, or hosted. Require an explicit export/recipient policy; the external client owns model execution | Before the first model request |
| Agent access | One query/follow read plus narrow draft, policy, and qualified response tools; separate investigator and defender grants | Discovery 5 for investigation/policy; Mithril 8–10 for exception/response adapters |
| Training data | Tenant-local, reviewed labels; no cross-tenant sharing by default | First model training |
| Publication permissions | Configured issuer/subject grants bound to tenant, cluster, namespace UID, and operation; default deny | Phase 5 permission and revocation tests |
| Source writer | Conditional update of an existing Kubernetes resource; no Git writer or source creation in the first slice | Phase 5 crash and conflict tests |
| Privilege-increasing changes | Independent approver required for every first-slice widening | Phase 5 review tests |
| Resource budgets | Fixed initial count and byte quotas in verification; measure on stated hardware | Phase 6 release qualification |

## Planning verification

Source and public-document review informed this plan. No engine, classifier,
benchmark, or deployment was run. Documentation checks and their result are
recorded in [verification.md](verification.md#planning-change-checks).
