# Engine Design

This design defines the proposed discovery domain inside Mithril Control.
Symbols with a `Discovery`, `Behavior`, or `Requirement` prefix below are new
contracts, not claims about existing APIs. Product text uses Araphor.

## Current source constraints

Read these source owners before implementation:

| Source | Existing behavior | Design consequence |
| --- | --- | --- |
| [Evidence model](../../../crates/mithril-control/src/evidence/model.rs) | `ObservationEnvelopeV1` carries source, epoch, sequence, coverage, generation, and typed effects. Kernel effects include exact object/destination IDs and operation/result fields. | Preserve these identities. The envelope does not supply general path, image, argv, or HTTP semantics. |
| [Evidence owners](../../../crates/mithril-control/src/evidence.rs) | Intake and retention have durable cursor and coverage contracts. `EvidenceConsumptionWatermarkV1` has no independent discovery consumer ID. | Do not reuse a watermark as if multiple independent readers were already safe. |
| [Control store](../../../crates/mithril-control/src/store.rs) | One owner lock, checked state format, atomic persistence, separate immutable evidence segments, and a 64 MiB state-file limit. | Keep authority and small heads here. Add a rebuildable embedded query database under the same persistence owner, not another policy store. |
| [Policy modules](../../../crates/mithril-control/src/policy/mod.rs) | Source validation, compilation, signing, reconciliation, and simulation already exist. | Discovery produces typed source proposals, not a second policy evaluator. |
| [PolicySimulator](../../../crates/mithril-control/src/policy/simulation.rs) | Evaluates exact `StaticDecisionKeyV1` cells. Missing cells are unresolved. Simulation does not attempt physical effects. | Historical preview needs retained exact compile inputs and attribution. Unsupported reconstruction stays Unknown. |
| [Workload policy types](../../../crates/mithril-control/src/policy/kubernetes.rs) | File, execution, network, capability, process, and other rule families have explicit operations and roles. | Preserve operation and role boundaries. Start with a qualified subset, not every serializable field. |

The input gap is a trustworthy join from an observed object ID to the policy
resource expression. The ABI already emits role, state, binding, entry, and
exact object fields; the current durable normalization drops some of them.
Preserve them with bounded Node-owned context in the existing evidence record.
Reuse `NodePolicyGenerationOwner` maps and Control `WorkloadTargetFactV1`.
Keep the original kernel sequence separate from the durable transport cursor.
Do not recover an old path from a current PID, mount table, or matching Pod
name. An unknown selector remains unresolved. No parallel probe is needed.

## Owner boundary

```text
Installed policy -> Node pre-effect decision
  -> authenticated evidence intake -> shared Control projection
  -> discovery context and qualified graph/finding owners
  -> deterministic notification/escalation
  -> local defender and console read the same revisions
  -> checked assessment and policy/response proposal
  -> exact authorization -> existing execution owner
  -> activation/readback/watch -> same evidence and owner views
```

Proposed implementation home: `crates/mithril-control/src/discovery/`. Create
modules only as an approved slice needs them. Keep policy compilation in
`policy/` and persistence in `ControlStore`. The query credential has no source-write,
signing, Kubernetes, response, or model-provider authority. The external agent
owns model execution. Control applies export policy before query evaluation.
No Control-owned model loop, provider gateway, or agent-job registry is required.
Query is one read tool, not a product-wide tool limit. Policy and response retain
their distinct typed mutation and authorization contracts.

An incident graph remains owned by the planned `GraphAndFindingOwner`.
Discovery's behavior rows are aggregates over observations, not causal edges.
Reuse a qualified graph read later; never infer cross-node causality from
matching timestamps or classifier similarity.

### Shared records, not a second case system

Use existing owner-qualified subject IDs and immutable references throughout:
tenant, subject lifetime, evidence manifest, optional finding/graph revision,
and parent artifact references. Context, assessments, policy proposals, response
plans, and results must carry those references in their existing schemas.
A name, timestamp, model conversation ID, or new universal case ID cannot
replace them. A routine workload review starts without a finding; a later
finding links to it only through qualified evidence.

One Control API applies current grants and invokes the responsible owner.
Console and MCP are clients of that API, not parallel business implementations.
Use one ControlStore for durable heads/artifacts and the one derived SQL store.
The graph owner reuses the accepted-evidence read/projection contract; it does
not add another intake path or duplicate raw-event database.

A submitted assessment is immediately queryable from the same subject/finding
view. Its suggestions link to the exact policy proposal or response plan made
from them. Those owners return immutable result references to that view.
Do not require file transfer, manual ID copying, or importing a separate agent
case. Report import remains an optional offline path.

Each owner commits only its own transition and emits a revision record after
commit. Use that owner's request ID for idempotency. A cross-owner timeout is
reconciled by that ID and the exact artifact digest; do not add a global workflow
transaction or claim atomicity across Control, Kubernetes, and providers.
A later finding revision cannot rewrite an approved response's frozen scope.

The shared view is a projection of independent facts: source health, mandatory
priority, delivery/acknowledgement, assessment, approval, activation, response
postconditions, and open branches. Do not store a second “case complete” flag.
Notification delivery is not human acknowledgement; acknowledgement is not
approval; approval is not an applied effect; a model conclusion is not closure.

### Local defender and mandatory escalation

A local defender runs an existing agent runtime against a self-hosted model and
the same scoped MCP/HTTP contracts. It receives no direct DB, node, Kubernetes,
or provider credentials. Model placement changes the disclosure profile, not
the evidence, action schemas, or authorization rules. A hosted client can replace
it without transferring private conversation state; committed records suffice.

The planned NotificationRouter owns delivery and escalation. Approved routing
rules set a minimum priority, responsible route, acknowledgement deadline, and
bounded retry/escalation behavior for qualified findings. Those rules run even
when the model refuses, times out, or proposes a lower priority. A critical
finding must not wait for an AI-generated explanation before routing. Approved
routes can also send an unconfirmed model concern for human review; routing
does not promote that assessment into a proved finding or permit response.

Keep source severity, required routing priority, suggested model priority, and
human disposition separate. An authorized reviewed routing change can alter
future handling; classification feedback cannot silently do so. Dedupe repeated
delivery by finding/revision/route without losing its unacknowledged deadline.
Persist delivery failure and deadline state; restart must not reset the clock.
Source loss is an explicit health/escalation condition, not a clean interval.

Agent acknowledgement may record that the agent read a finding, but cannot
satisfy a route that requires human acknowledgement. NotificationRouter exposes
its existing revision/receipt contract through the shared views. It does not
become another pager inside DiscoveryOwner. Qualified preauthorized response
can proceed independently of model inference, within its exact authority.

## Protection boundary and master-plan integration

The [Hugging Face master plan](../mithril-hugging-face-intrusion-prevention/README.md)
owns prevention, causal findings, and verified response. Discovery supplies
qualified context and review artifacts; it does not replace those capabilities
with query access or AI classification. The master's historical initial-source
description is not current implementation status. Its detection, distributed
response, and provider phase results remain Not done in this worktree.

The attacking workload need not use Araphor tools. Giving a defender agent
query access does not constrain the attacker. Prevention must run at the
protected effect boundary without an agent or SQL round trip. A signed local policy can deny a prohibited file, exec, or network
effect while Control or the model is unavailable. Detection adds explanation;
it cannot retroactively prevent an already completed effect.

| Required protection case | Existing/planned owner and agent use | Required proof or limit |
| --- | --- | --- |
| In-process credential access | Node/Interceptor applies the existing exact role/object policy. Agent proposes and previews protection before deployment. | HF-LOCAL-001: prohibited bytes not returned; legitimate conversion/controller access still works. No fabricated exec event. |
| Credential already resident in memory | Local network/effect policy plus qualified API audit. | A file deny cannot revoke old bytes. Same-process permitted TLS cannot reveal the remote verb. Report later denial or detected-after-effect honestly. |
| API/IMDS and privileged workload pivot | Local network controls, existing hostile-Pod/runtime gates, and the master's Kubernetes source owners. | HF-NET-001 and HF-XNODE-001: prove denied delivery or exact audit/object/binding chain. Admission is not prevention of Secret reads. |
| Compromised process, existing sockets, and replacement workloads | ResponseCoordinator and authenticated node/Kubernetes actuators; agent plans a bounded response and requests authorized execution. | HF-RESP-001/002: re-resolve lifetime/UID, disclose shared impact, check restrictions, retain late/replacement branches. Kill acknowledgement alone is insufficient. |
| Stolen cloud, mesh, connector, or source-control authority | One qualified provider actuator per capability, never generic HTTP or shell. | HF-PROV-001: distinguish key deletion from enrolled-device removal, exact token revoke from wider suspension, and audit identity from a usable revocation handle. |
| Recovery and continuing risk | Existing graph/finding/response owners; query/follow exposes their revisions. | Healthy watch and every required postcondition; Partial or Unknown for missing authority, coverage, or open branches. |

Use the [standing acceptance](../mithril-hugging-face-intrusion-prevention/hugging-face-adversarial-acceptance.md)
as the oracle, including unchanged workloads and legitimate controls. Do not
claim that discovery's exact file/execute preview completes this matrix.

The [response plan](../mithril-hugging-face-intrusion-prevention/phase-9-local-and-distributed-response.md)
owns ResponseCoordinator, target revalidation, authorization, durable
transitions, readback, and watch. Use the same lifecycle as Chapter 24 and
Appendix A.15.4 of the validated architecture; do not create a console or
discovery-specific response state machine.
The [provider plan](../mithril-hugging-face-intrusion-prevention/phase-10-provider-connectors-and-recovery.md)
owns capability-specific evidence and actuators. These are dependencies, not
permission to implement them within a discovery phase.

Tool boundaries follow effects: query; submit assessment; propose/preview
policy; publish an approved policy; request a bounded exception; plan response;
execute an authorized response. The
[API contract](console-and-api.md#agent-tool-contract) assigns grants and gates.
No fixed tool count, universal action endpoint, model self-approval, or raw
actuator handle supplied by SQL. Default investigators cannot publish or contain.
A separately authorized defender can use qualified mutation tools.

Read status through query/follow. The query catalog lists owner readiness and
supported operations, including Unsupported, OutsideAuthority, and missing
approval. Add `findings`, `branches`, `responses`, notification/acknowledgement, and exception/activation views
only when their authoritative owners supply qualified reads. Unavailable owners
are capability states, not empty healthy tables. Discovery does not write them.

A response plan pins graph revision, exact targets, permitted typed actions,
blast radius, expiry, idempotency keys, and postconditions. Preauthorization can
permit an immediate narrow seed fence; it cannot authorize later wider branches.
Publishing a new policy cannot remove a response restriction. Production
verification uses authoritative non-invasive readback and a healthy watch;
hostile probes belong only in isolated qualification.

## Data contract

All persistent records have schema version, tenant, immutable ID, revision,
creation time, producer version, and canonical content digest. Request IDs
identify retries; content digests identify equal artifacts. Avoid secrets in
IDs, logs, metrics, and classifier features.

| Record | Required content |
| --- | --- |
| `DiscoveryCheckpoint` | Configured scope and sources; bounded interval/build ID; export and aggregation positions; inventory/coverage revisions; limits; status and partial reason. Internal progress, not an agent-created job. |
| `BehaviorCohort` | Runtime family; environment; controller UID where available; container kind and declared role; image digest and platform; relevant configuration/mount identity; policy generation; attribution quality. Missing fields are explicit. |
| `ResourceBinding` | Evidence source and lifetime; exact resource ID; policy expression; object/mount or destination context; validity interval; owner/proof kind; catalog revision. |
| `BehaviorAtom` | Cohort; source lifetime; actor/entry identity; declared role/state; operation; exact resource binding; source decision; physical/result class; proof kind; evidence references; first/last source position; count; coverage; source attribution quality. |
| `BehaviorSnapshot` | Sealed input manifest; source cursor vector; cohort and resource catalogs; ordered atoms; excluded and unresolved counts; lifecycle matrix; gap intervals; transformation version. |
| `RequirementSet` | Exact cohort and revision; required actions; forbidden guardrails; owner; reason; linked test IDs; expiry where relevant. Observed, declared, and inferred origins remain separate. |
| `DiscoveryProposal` | Snapshot and requirement digests; base source UID/resourceVersion/digest; proposed typed source or typed edit; target snapshot; transform receipts; unresolved items; validation and preview references. |
| `ContextDocument` | Tenant, kind, source/owner, revision, validity interval, sensitivity, trust class, payload reference, and approval for use. Supported kinds: runbook, workload ownership, deployment change, reviewed assessment, and supplied threat reference. |
| `ContextPacket` | Question/trigger; authorized scope and purpose; frozen evidence/catalog revisions; entity/lifetime facts; policy and source health; rule/runbook references; relevant reviewed history; conflicts, missing facts, and bounded evidence references. Each item retains provenance, freshness, and disclosure class. |
| `DetectionAssessment` | Method ID/version, typed parameters, input digests, window/order basis, matched/not-matched/unknown result, supporting and contradicting record IDs, coverage, and unsupported predicates. Not an incident graph revision. |
| `ClassificationAssessment` | Context and method-result digests; taxonomy; activity and security disposition; impact/priority reasons; competing hypotheses; claims with support/refutation references; missing facts; method/model provenance; score semantics and abstention. Human confirmation is a separate revision. |
| `Suggestion` | Kind, exact scope/target revision, rationale claim IDs, typed payload, preconditions, risks, expected effect, validation/test references, required permission, and Draft/Rejected/Validated state. Validation does not authorize execution. |
| `QueryReceipt` | Principal/export-policy revision; query digest; view/schema version; input manifest/read revision; result digest; limits and coverage. No model execution state. |
| `AssessmentReport` | API-submitted or imported classification/suggestions; subject/finding and input revisions; cited query receipts/evidence IDs; parent reports; completed/missing checks; client model/version/cost, marked unverified; validation errors. No separate case or agent-run state. |
| `PreviewArtifact` | Proposal/target/compiler versions; proof kind and execution mode; evaluated key set; per-case old/new disposition; unknown reasons; guardrail failures; valid-work failures; source coverage; context replay manifest. |
| `TestRequest` | Missing behavior or ambiguity; expected evidence contract; approved fixture ID if one exists; scope; expected resource cost; approval needed. No free-form command execution. |
| `ReviewDecision` | Reviewer and authorization context; proposal/preview/source/target digests; decision; reason; expiry; independence check; publication precondition. |
| `PublicationReceipt` | Idempotency key; exact submitted source digest; source owner result and revision; candidate and target references when supplied. Never synthesizes an activation acknowledgement. |

An entry role comes from the existing owner. A classifier label such as
`probable_health_check` is not a role and cannot fill an absent role field.
Replica facts can share a cohort only when all required identities match.
Cross-environment comparisons remain comparisons, not merged authority.

### Outcome classes

Use separate fields, not one overloaded success value:

- `source_decision`: allow, audit allow, would deny, deny, or unknown, as
  supplied by the source contract;
- `physical_result`: performed, prevented, failed for another reason, not
  attempted, or unknown, only where the owner proves that result;
- `requirement_state`: unreviewed, required, forbidden, or unresolved;
- `classification`: suggested activity, security disposition, and impact,
  separate from both the observed outcome and an authorization decision.

Preserve the original result fields. A post-hook observation may not establish
the final actor result. A provider HTTP success does not prove a filesystem
effect. A simulator always reports that no physical action was attempted.

## Qualification and aggregation algorithm

1. Authenticate the read scope. Read only committed accepted evidence. Reject
   tenant-crossing references before fetching resource content.
2. Freeze an input manifest. Include source identity, boot/epoch, cursor,
   coverage revision, schema, capability, and relevant inventory revisions.
   Use source ordering; do not invent a global total order from wall clocks.
3. Verify resource and actor joins. A join must refer to the same lifetime.
   An absent, ambiguous, stale, or contradictory join becomes an unresolved
   item. A metadata correction produces a new snapshot, not an edited history.
4. Partition cohorts. Keep application, init, sidecar, external entry, and
   administrative roots distinct according to the supported identity model.
   Keep new image/config revisions distinct even if labels are unchanged.
5. Form exact atoms. Include operation and result class in the key. Deduplicate
   by accepted evidence identity. The same identity with different bytes is
   an intake contradiction, not two examples.
6. Aggregate counts and bounded evidence references. Store the complete input
   manifest for replay, subject to declared retention. A small display sample
   must not be described as the complete input set.
7. Record exclusions with counts and reasons. Filtering noise does not remove
   its coverage cost or erase the evidence. A configured sample rate prevents
   claims of complete observation.
8. Seal canonical ordered output. Equal manifests and algorithm versions must
   produce equal deterministic artifacts. Arrival order cannot change them.

### Exact counts, display groups, and windows

The accepted-record key is `(tenant, source, boot/epoch, stream/CPU, durable
cursor)`. Preserve the kernel sequence separately. Two records with equal
keys and equal canonical bytes count once. Equal keys with different bytes
stop that source with an integrity error. Two independent observations of the
same operation count twice. Do not use approximate membership filters for
deduplication.

The atom key contains cohort, source lifetime, actor/entry identity, declared
role/state, operation, exact resource binding, source decision, physical
result, and proof kind. Missing values are explicit variants, not empty strings
that match qualified values. Coverage is retained by source interval; it is
not averaged into a confidence score. Use checked integer counts, deterministic
ordering, and a versioned canonical encoding. Hashes index keys; retain the
full key and reject conflicting content instead of merging it.

A display group can combine atoms with the same qualified cohort, declared
role, exact policy expression, operation, outcome, and proof class. It keeps
all member IDs and their coverage. PID or resource-instance differences can
then disappear from the initial table without disappearing from the evidence.
Unresolved bindings stay in separate groups. A text template, embedding, or
path prefix cannot form an authority-bearing group.

Each input belongs to exactly one primary disposition: included, unresolved,
or excluded. Their counts sum to unique accepted input; duplicate deliveries
are a separate transport counter. A record can have several reason tags, but
those tags must not inflate the disposition count. Display accepted-record
counts, upstream-reported multiplicity, and physical-effect counts separately.
Unknown upstream sampling or aggregation prevents an exact activity-rate claim.
Source loss is separate from accepted input; an unknown lost count must remain
unknown. Multiple records can describe one physical action. Report unique
physical effects only when the source supplies a qualified effect identity
and count contract; otherwise show records with a performed result.

Freeze per-source end cursors and coverage revisions, not a wall-clock cutoff
alone. The first timeline uses five-minute buckets of retained Control intake
time and is labeled **observations received**, not action rate. Missing intake
time has an Unknown bucket; replay never assigns today's time. Preserve source
times for inspection without inventing cross-node causality. An event that
arrives after sealing belongs to a new snapshot, even if its source time is
older. Late context or coverage corrections also produce new revisions.

Canonical content digests exclude run IDs, wall-clock creation time, database
row IDs, and optional model annotations. Input identity, retained times,
context, coverage, transformation version, and deterministic output remain
bound. Replay with different page sizes, thread scheduling, and arrival order
must produce the same content digest. Statistical experiments use explicitly
ordered feature sequences; they do not change this deterministic result.

Record context used by each derivation: request key, catalog/source revision,
returned value or error, and validity interval. Replaying a sealed bundle uses
these records only. A missing or mismatched context read fails that derivation;
it cannot query the current cluster. Include every context record in the input
digest and expose incomplete replay explicitly. Reuse the same production
derivation owner methods and simulation API in an offline entry point.

Live collection is optional for the first experiment. A sealed accepted-input
bundle is enough to prove grouping, review, and native policy preview.

### Readiness is a matrix

Show observation health, attribution, resource binding, lifecycle coverage,
target compatibility, and review separately. Do not calculate one security
confidence percentage from unrelated axes.

Lifecycle rows include startup, steady operation, readiness/liveness, restart,
rollout, graceful shutdown, error recovery, scheduled work, and approved
maintenance. Each row is Recorded, Declared only, Missing, Not applicable with
reason, or Unsupported. Time elapsed does not fill a missing row. A complete
matrix applies only to the declared case set, not all possible application
behavior.

Keep proof kinds separate: observed runtime event, recorded-input replay,
synthetic case, and present-configuration scan. A synthetic request can check
a schema or a declared case; it cannot recover historical caller identity,
earlier object state, admission ordering, or a physical result. Count skipped
and unsupported checks separately from passed checks.

## Context retrieval and investigation methods

Build context for a question, not a dump of all retained events. Resolve exact
tenant, workload lifetime, image/configuration revision, declared role, and
time/cursor bounds first. Include policy state and observation health even
when a text or similarity search would rank them low. Select rule-specific
runbooks by exact method/rule ID; select prior reviewed assessments by scope,
rule version, and validity. Never use future decisions in a historical replay.

Start with structured filters and deterministic relevance order: exact subject,
exact method/revision, valid time overlap, then stable document ID. Cap each
source independently. Return selected/available counts and omission reasons.
Unreviewed text and prior model prose remain untrusted context, not approved
instructions or labels. Conflicting owner statements remain separate. Imports
are operator-supplied bounded records through DiscoveryOwner; no live Jira,
GitHub, SIEM, or threat-feed connector is required for the first delivery.

A packet contains a small summary and evidence handles. A handle binds tenant,
artifact/revision, byte range, content digest, and permission; it is not an
arbitrary URL. Fetching it rechecks current access. Later reads return their own
read and packet revisions. They do not alter the initial evidence. Expired or
absent evidence produces an explicit gap, not a fabricated answer.

Use SQL over documented views for exact matches, revision differences, counts,
and qualified within-subject sequences. Store these four starting methods as
versioned query recipes in `catalog`, not a four-variant RPC language. Each
recipe states required columns, identity joins, order, coverage, parameters,
positive/negative fixtures, and a stopping checklist. An agent can write a new
admitted SELECT without a new tool or method registration.

A `DetectionMethodSpecV1` contains a SELECT recipe, required facts and coverage,
method version, and expected result interpretation. Apply the same query gate
to operator and agent drafts. Validate and replay positive/negative fixtures;
query cannot install or schedule a detector. Reuse the planned detection owner
for authoritative findings. Policy-source `FindingSpecV1` is not that owner.

`DetectionAssessment` records Matched, NotMatched, or Unknown only when a
qualified recipe checks its preconditions. A positive match can exist in a
partial window. A negative needs the stated fields and coverage. An arbitrary
SELECT that returns no rows cannot prove that an attack or operation did not
occur. SQL joins and time windows do not create causal edges. Retain query
receipts and input revisions for replay without the model.

The initial investigation checks a denied credential read after a new workload
entry. It tests attack, declared maintenance, changed deployment, and missing
attribution as competing explanations. It must not infer credential theft from
a denied read, provider abuse from TLS traffic, or a causal chain from timing.
When the necessary provider audit or entry proof is absent, it recommends a
specific evidence request rather than inventing a verdict.

## Suggestion validation

Support `GatherEvidence`, `AskOwner`, `RunReviewedTest`, `PolicyChange`,
`DetectionDraft`, and `ResponsePlan`. The first three identify a bounded query,
question, or approved fixture. PolicyChange uses the proposal algorithm below.
DetectionDraft uses the method schema and held-out replay. ResponsePlan is a
reviewable recommendation with an existing owner link or Unsupported; it is
not an execution API. Do not put runnable shell text in a typed payload.

Validation checks schema, tenant, supplied references, target revision, and
method-specific preconditions. It distinguishes structurally valid, supported,
tested, and reviewer-approved states. A valid citation can still fail to support
a claim; that remains an assessment error for review and evaluation. Keep
risks, counterexamples, and remaining uncertainty with each suggestion.

## Proposal algorithm

Start with an exact native rule subset: qualified file and execution operations
for an already declared actor role. Add network and other native families
only after their resource binding and effect semantics pass the same tests.

1. Load the pinned base policy and requirement set. The existing source owner
   still requires a single applicable base policy. Do not combine overlapping
   workload policies with a new precedence scheme.
2. Associate each proposed action with exact evidence or an explicit declared
   requirement. Successful activity can seed an unreviewed suggestion; it does
   not approve that action. Denied, failed, unknown, and would-deny cases go
   to separate review groups.
3. Produce exact resource/operation edits. Do not infer write from read, execute
   from open, a directory from sibling count, a CIDR from nearby addresses, or
   a provider operation from a TCP destination.
4. Apply declared forbidden guardrails. A conflict remains visible even if
   the operation is frequent, required by one owner, or high-scoring.
5. Optionally propose a generalization as a separate edit with an expansion
   receipt. It cannot replace the exact version without explicit review.
6. Validate through the existing native schema and compiler. Reuse canonical
   serialization and source restrictions. Unknown syntax is rejected, not
   copied through a YAML escape field.
7. Evaluate the pinned case set with the existing simulator where exact keys
   can be reconstructed. Record Unknown elsewhere. Run held-out fixtures
   separately from examples used to construct the proposal.
8. Seal the proposal and its preview. Editing any semantic field invalidates
   the prior preview and approval.

The first slice updates an existing source. Static replay excludes dynamic
exception authority and unrecorded runtime conditions. A matching compiled
Allow cell does not prove that a live binding or consumable exception exists.
Report those cases as Unknown instead of expanding the simulator's claim.

### Permission expansion receipt

Each transform records old expressions, new expression, observed members,
currently matching unobserved members, future-match behavior, operation/role
changes, assumptions, and a counterexample where one exists. The receipt also
states the domain over which any equivalence claim was checked.

Example: four observed reads of `/srv/cache/a` through `/srv/cache/d` do not
justify recursive reads of `/srv/cache/`. The console must show that a future
`/srv/cache/token` would match the proposed directory rule. It must also show
that the exact four-file option remains available. If a path resolver cannot
prove mount and symlink semantics, permission impact is Unknown, not equivalent.

Do not claim a finite enumeration proves equality over an unbounded path
space. Use structural checks for the supported grammar; reject or explicitly
mark unsupported comparisons. Add an SMT solver only if a defined supported
case cannot be checked adequately with the existing compiler and simple rules.

## Test-guided discovery and drift

The test planner compares required lifecycle cases, available evidence, and
proposal assumptions. It ranks missing cases by affected authority, number of
unresolved requirements, and estimated cost. A deterministic ranking exists
before ML ranking. The output explains which question each test can answer.

The first version links to existing reviewed qualification fixtures. Running
a fixture is an independent, explicitly authorized operation in an isolated
environment. No generated test text can become a shell command. Production
traffic replay, credential use, and destructive provider operations are out of
scope without their own approved execution contract.

After publication, compare new snapshots against the reviewed snapshot:

- Separate a new image/configuration from a same-revision behavior change.
- Show newly observed operations, vanished observations, changed results,
  changed coverage, and changed resource bindings independently.
- Group exact repeated changes. Preserve raw counts and evidence access.
- A missing operation does not prove its grant is unused. Propose a removal
  review only with declared lifecycle coverage and an explicit owner decision.
- Drift does not overwrite the baseline, restart training, relax policy, or
  declare an incident by itself. Incident findings remain another owner's work.

The review unit is a changed exact behavior or permission, not each event.
Repeated observations update counts without creating repeated review items.
An unchanged reviewed requirement can be referenced only within its exact
scope, source/target revisions, guardrails, and expiry. New resources, outcomes,
entry classes, source health failures, or widened permissions remain visible.
An acknowledgement can record that the operator saw an item; it cannot suppress
evidence, disable a detector, or approve a policy change. Notification delivery
is outside this engine. Its read contract exposes new/changed group IDs so a
later notification owner need not page once per event.

This engine does not replace broad detector rules with learned exceptions.
It supplies the context and tested proposal needed for a separate authorized
change. Stable exact grouping, revision comparison, and lifecycle coverage are
the first noise controls; optional classification is not a release dependency.

## Embedded database and query contract

Select one embedded working/query database in the offline feasibility phase.
DuckDB is the analytical candidate; SQLite is the transactional baseline.
The current Rust dependency set has no SQL binding. Add only the selected
pinned Rust binding and reviewed native library after the measured decision.
Do not add an ORM, two production databases, or a generic storage-driver layer.

| Option | Decision |
| --- | --- |
| Existing state image and artifact scans only | Keep them for authority and immutable payloads. Repeated full scans do not meet bounded filtered console reads. |
| SQLite | Baseline for transactional progress, point lookup, and filtered pages. Measure analytical joins and revision comparisons. |
| DuckDB | Candidate for batched ingestion, context joins, comparison, and aggregation. Measure small reads, transaction conflicts, memory, spill, and recovery; OLAP speed alone does not select it. |
| ClickHouse or a database service | Defer until measured fleet volume or multi-writer requirements justify a separate service and ownership design. |

The [research comparison](research-and-demand.md#storage-and-aggregation-comparison)
states the upstream evidence and limits. A database is needed here for indexed
aggregates and transactional progress, not because AI needs a vector database.

Initial tables use explicit schema versions, composite tenant keys, foreign
keys, and checked values. Keep raw payloads in immutable bundles:

| Table | Key and stored fields |
| --- | --- |
| `source_progress` | Tenant, build, source lifetime, stream; next expected cursor, durable page reference/digest, coverage revision. |
| `input_record` | Tenant, build, accepted-record key; payload digest, bundle offset, atom ID or unresolved/excluded reason. Enforce uniqueness. |
| `behavior_atom` | Tenant, profile/build ID, atom ID; full exact key, checked count, first/last source positions, retained intake-time buckets, evidence references. |
| `profile_index` | Tenant, snapshot ID; committed manifest digest, cohort, source/coverage revision, summary counts, transformation version, build state. |

Use relational bucket rows if needed; never grow an unbounded JSON array in an
atom row. Annotations and proposal lists refer to existing artifact/head IDs;
add a derived index only for an implemented query. Full raw events and approved
policy sources do not move into the query database. Add `context_document`
metadata and subject/revision lookup rows when context retrieval is implemented;
keep document bodies and submitted reports in bounded immutable artifacts.

Qualify physical layout for tenant/profile/atom lookup and the actual recipes.
Do not assume SQLite B-tree plans transfer to DuckDB ART indexes. Check the
committed manifest before returning a profile. Report `Indexing` or
`IndexUnavailable` when projection and authoritative digests differ.

### One query contract

Use `query(sql, follow=false, cursor?)` for investigation reads. HTTP, MCP, and
console reads call `DiscoveryOwner::query`. No action enum, start, stop,
subscribe, get-job, or separate schema tool. Initial tool documentation names
the common views and a catalog query.

| View | Purpose and contract |
| --- | --- |
| `catalog` | Authorized tables, columns, join keys, units, null meanings, SQL examples, runbooks, stopping criteria, and owner/tool availability with reasons. No internal catalog exposure. |
| `events` | Append-only retained observation and derived-revision records: event ID, record kind, subject lifetime, entity/revision, source positions, result/proof class, and evidence references. Derived changes are not additional observed actions. |
| `context` | A bounded packet per subject/method/revision: identity, policy, source health, exact rule guide, reviewed history, conflicts, omissions, and references. Fetch common context in one query. |
| `behaviors`, `coverage` | Exact atoms and separate coverage intervals. Counts retain their denominator and source contract. |
| `policies`, `assessments`, `suggestions` | Committed policy/review records and submitted reports, linked by exact subject/finding/input references. Keep current and historical revisions distinct. |

Add columns and recipes only for a named consumer. No semantic-layer service,
vector store, hidden model summary, or duplicate graph. Context selection is
deterministic; token reduction cannot conceal counterevidence.

Normal mode evaluates one bounded read-only SELECT at a committed read
revision. Support projections, filters, nonrecursive CTEs, qualified equijoins,
grouping, and bounded window functions required by the recipes. Pin the engine
dialect; do not implement another language or promise all SQL. Reject multiple
statements, writes, recursion, volatile functions, arbitrary table functions,
and unapproved relations/functions. Use explicit stable ordering. LIMIT bounds
output, not scan cost.

Return columns/rows, read revision, query receipt, evidence references, coverage,
projection freshness, omissions, and output-limit state. Authenticate the bounded
receipt; do not allocate a durable Control head for every read or empty follow.
Assessment submission validates and retains cited receipts with their input
references under existing quotas. An expired input is not replayable proof. Normal mode has no
server-held result session or generic pagination cursor. Above 200 rows/1 MiB,
mark output limited and require a narrower query. An aggregate evaluates all
selected admitted input or fails. Historical pages use stable keys and pinned
artifact revisions, not OFFSET over changing data.

Follow accepts only projection/filter SELECTs over `events` with stable
predicates. Reject joins, aggregation, DISTINCT, windows, caller ORDER BY/LIMIT,
and relative-time functions with `UnsupportedFollowShape`. Use normal queries
for analysis and follow revision records to know when to query again. Do not
build continuous aggregate maintenance or a per-client SQL result cache.

The first follow call reads matching retained events from the retained floor.
It captures the committed projection high-water mark and returns batches in publication
order. After draining retained input, wait at most 20 seconds for new commits,
then return rows or an empty batch and an opaque cursor. Absolute-time and
subject filters limit history. Coverage states what predates retention.

The authenticated cursor binds principal scope, export-policy revision, SQL
digest, schema/view version, projection epoch, and last scanned publication
position. Use a reviewed encoding library. Recheck authorization per call and
before returning a waited result. Changed query/scope requires a fresh cursor;
expiry returns 410, never a silent reset. A cursor neither grants access nor
pins history.

Reuse Control's commit index plus a stable artifact-record ordinal for feed
positions. Retain this mapping in immutable exported manifests and committed
derived artifacts; rebuild preserves it. This is delivery order, not kernel
action order. Late evidence and corrected context/coverage append revisions
with replacement links where applicable; do not edit old feed records.
Advance the projection high-water mark only through a contiguous processed
prefix of eligible committed artifacts. Never skip an artifact that will become
visible later. Index lag must not advance a follow cursor past that artifact.

Advance through scanned nonmatching rows, including empty batches. When output
is full, stop before the next unreturned match. Retrying a cursor can repeat
rows; deduplicate by event ID. Do not promise exactly-once delivery. Retention
past the cursor returns expiry. A rebuild that cannot preserve positions
invalidates its projection epoch.

Release transactions and store locks before waiting or client I/O. A bounded
notification can wake a waiter; committed positions make lost notifications
recoverable. Recheck after wait registration to avoid a lost wake-up.
Disconnect cancels only this read; ingestion continues. No per-client queue,
durable subscription, or job registry.

### Query isolation

Read-only SQL is not a sandbox. DuckDB's
[security guidance](https://duckdb.org/docs/current/operations_manual/securing_duckdb/overview)
requires isolation for untrusted SQL. SELECT-capable functions can access files,
extensions, and network resources.

The trusted Control adapter resolves approved view/column references and applies
row scope, field grants, and disclosure redaction before evaluation. Filtering
only final output would leak through predicates, counts, joins, and errors.
Use a maintained parser/binder, not regex or a SQL-prefix check.

Run admitted SQL in a disposable unprivileged worker with only bounded authorized
relation batches. Use the selected engine in memory, without opening Control's
live DB or adding a durable database. Give it no Control credentials, production
mounts, inherited sensitive descriptors, or network. Enforce OS memory/CPU/process
limits, a deadline, and restricted filesystem/syscall access. Engine external
access, extension, and configuration locks are additional safeguards.

Control uses fixed prepared statements to extract the referenced authorized
columns and required rows. If the complete projection exceeds admission limits,
reject and request a narrower scope; never truncate COUNT or join inputs.
The worker compiles/evaluates SQL. Validate bounded output and attach server-known
coverage/provenance. Query results cannot authorize publication.

Phase 1 must prove parser/binder support, interruption, sandbox compatibility,
and projection cost. No qualifying isolation means no agent-SQL release, not
permission to execute it in credentialed Control. Reuse a qualified isolation
helper if available at implementation time; none was found in the inspected
Control/core paths. No shell or general code-execution tool is exposed.

Use one writer and at most two reader connections in one Control process.
Run blocking SQL outside the async runtime and ControlStore lock. Use a
qualified local filesystem, not NFS or a shared multi-node PVC. SQLite requires
verified WAL/FULL settings, foreign-key checks, and a maintained WAL-reset-fixed
build. DuckDB requires a pinned stable embedded release, explicit transaction
and checkpoint tests, bounded threads/memory/temp space, and no remote extension
autoload. Neither option requires a multi-process writer protocol.

Keep export pages at 256 records/1 MiB. Allow one apply transaction to combine
durably exported pages up to 4,096 records/8 MiB, within the working budget.
Tune this bound from the experiment, not from the engine name. Prepare context
before the transaction. A batch commits uniqueness, counts, and all affected
progress together. Retry the same batch on a classified transient conflict;
never retry indefinitely. Readers materialize one API page and close before
client I/O. Enforce read deadlines, disk reservations, and checkpoint limits.

Use explicit ORDER BY and canonical ordering inside nested aggregates. Counts
use checked integers. Floating-point reductions and model scores never enter
the deterministic fact digest. DuckDB memory settings are not a process RSS
limit; measure total native allocation and spill. A candidate that cannot meet
the admission, interruption, or recovery contract fails selection.

## Durable lifecycle and recovery

Configured derivation runs continuously over bounded input intervals. Internal
build states are Reading, Sealing, Complete, Partial, or Failed. Checkpoints
resume after restart; no caller creates or cancels a build. Disablement stops
new derivation and retains artifacts. A sealed snapshot never returns to
Reading. The next interval or corrected context creates a new revision.

Proposal states: `Draft -> Validated -> InReview -> Approved | Rejected`.
Approved can become `Publishing -> Published | PublishFailed | Stale`.
Expiry produces `Expired`. A source or target change produces Stale before
publication. A published proposal retains its receipt; later drift creates a
new proposal rather than changing its history.

Use bounded immutable discovery artifact files under the existing Control
store owner. Store small heads, references, and transaction state in its
versioned state. Specify migration and maximum retained heads before adding
fields; an append-only list in the 64 MiB state image is not acceptable.

Commit order is artifact write, checksum, file sync, durable installation,
then reference/checkpoint commit under ControlStore. Notify readers only after
the reference is durable. Crash tests cover each boundary. Unreferenced files
can be reclaimed after recovery; a referenced missing file yields an integrity
failure. Never acknowledge a checkpoint whose artifact is not durable.

The SQL and Control state commits are not one transaction. Use this protocol:

1. Copy and durably install an input page. Commit its reference and export
   progress in the build manifest through ControlStore before aggregation.
2. In one SQL transaction, check `source_progress`, insert unseen input keys,
   apply checked count increments, and advance aggregation progress. Native
   UPSERT applies only to validated distinct input. A repeated record must
   match its retained digest before it is skipped. Reject cursor jumps unless
   the manifest contains the explicit source gap. Export progress and
   aggregation progress are separate fields.
3. After a crash, apply committed exported pages that are not yet aggregated.
   A SQL progress value ahead of the exported manifest is an integrity error.
   If SQL is lost, rebuild from the exported pages. A build with unavailable
   input cannot pretend to resume successfully.
4. Seal canonical atoms and manifest into immutable artifacts. Sync and install
   them, then commit the snapshot head in ControlStore. Only this head makes
   the snapshot authoritative. SQL working rows are not a completed snapshot.
5. Mark the index visible only for that committed snapshot/digest. A crash
   before this step requires projection repair, not another policy revision.
   Rebuild completed indexes from sealed snapshots; rebuild unfinished builds
   from their retained exported input. Review and publication load authoritative
   artifacts and exact heads, not unchecked query rows.

Version the derived SQL schema separately. Build a replacement index within
reserved quota and check counts and digests against artifacts. Quiesce readers
and writers, use the selected engine's checkpoint procedure, then close all
connections before durable installation. Never replace a live DB file or omit
its uncheckpointed WAL. Preserve the prior
index until validation succeeds. Do not migrate policy/trust state through SQL.
Keep query service unavailable during replacement; no HA claim is made.
Corruption, disk full, or rebuild failure disables affected discovery work,
not primary evidence intake, policy reconciliation, or the entire Control
process. Rebuild only retained data; expired history remains explicitly expired.

Use bounded immutable exports for both offline and live derivation. Discovery never
acknowledges the current shared consumption watermark. Freeze a retained range
and copy bounded pages; a reclaimed range makes the snapshot Partial. After
copying, replay depends on the discovery bundle, not source-segment retention.
A permanent independent retention consumer is outside this slice.

Review and replay references have byte and age limits. Pin the bounded evidence
bundle needed by a pending review. If the pin cannot be retained, reject the
new review or expire the old one with an explicit reason. Do not stop primary
evidence intake to preserve unlimited discovery history. An expired evidence
bundle leaves the review audit record, but disables a claim of full replay.

Query/follow reads durable revisions without retaining a transaction during
client I/O. A slow reader must resume within retention or receive expiry. It
cannot block evidence or policy work.

## Publication and rollback

The proposed source publisher is a narrow Kubernetes update adapter. The
current reconciler reads sources; it is not a source-write API. Update an
existing resource only, with exact UID, namespace UID, generation, spec digest,
and a conditional write using its current opaque resourceVersion. No source
creation or Git writer is included. The adapter is not a signer or desired-state
authority. Existing policy owners process the accepted source normally.

Persist publication intent before the external source write. On a lost reply,
read the exact source identity and submitted content digest before retrying.
Same request and same digest returns the stored receipt. Same request with
different content rejects. An intervening source edit requires a new review.
This is recoverable idempotency, not a claim of a cross-system transaction.

Approval binds the proposal, preview, base source, target snapshot, guardrails,
and expiration. Publication rechecks user authority and every precondition.
Every widening requires an independent reviewer in the first slice.
Approval of a suggested category or an entire queue is not sufficient.

Track existing rollout IDs and per-target acknowledgements. A canary uses
explicit targets through the existing rollout owner, only where that contract
supports it. Stop conditions include rejected targets, required-case failures,
missing observation health, and changed target identity. Do not invent an
atomic cluster-wide activation.

Rollback is a new validated source operation through existing rollback and
reconciliation owners. It can change security and availability. It needs its
own target check and result evidence; deleting a discovery record cannot
retire active protection.

## Threat model and failure behavior

| Threat or failure | Required behavior |
| --- | --- |
| Compromised workload behaves maliciously during learning | Preserve events, keep unreviewed requirements separate, test forbidden cases, and never auto-authorize. |
| Slow baseline poisoning | Freeze reviewed baselines; keep independent labeled holdouts and guardrails; require explicit new revision. |
| Workload floods unique paths or labels | Enforce cardinality/byte quotas before expensive work; mark Partial; never turn overflow into a wildcard. |
| Stale Pod name, PID reuse, changed mount, or DNS answer | Require lifetime-bound resource joins; otherwise Unknown. |
| Root-compromised node | Authenticated node evidence can still be false. State this trust limit; do not call its signature proof of uncompromised execution. |
| Attacker controls filenames, logs, tool descriptions, or model text | Treat them as bounded data; escape rendering; no instructions or executable output. |
| Model unavailable, stale, malformed, or over budget | Disable assistance; deterministic profiles, review, and enforcement remain available. |
| User changes tenant in a URL or artifact reference | Reject before reading content; audit without leaking the other tenant's existence. |
| Concurrent review or policy edit | Compare immutable revision and source preconditions; reject stale publication. |
| Coverage loss or clock jump | Preserve gap and source ordering; no clean-window or absence claim. |
| Disk full or service restart | No committed partial artifact; recover checkpoint; retain existing active policy. |

## Later source families

Agent/tool adapters must carry a source-owned session, action, target, action
schema revision, delegation/approval context, result, and coverage. They may
classify an action as a likely build or deployment step, but cannot infer user
permission from that class. Prompt and tool descriptions are untrusted.

Provider adapters need actual API audit/action/resource data. A shared TLS
endpoint cannot distinguish allowed and forbidden remote methods. Network
exports need explicit CNI/version semantics and applicable-policy inventory.
Kubernetes NetworkPolicy cannot receive a silently dropped deny rule.

A portable behavior artifact can bind profile, image, configuration, tests,
source manifest, and algorithm digests. Signatures and OCI distribution are
optional later transport choices, not permission to trust another environment's
baseline. An import starts as unreviewed and records all missing local bindings.
