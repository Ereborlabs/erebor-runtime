# Engine Design

This design defines discovery in `crates/araphor-data`. Mithril 7 owns shared
processing and the discovery backend. Discovery methods produce review artifacts;
they do not own evidence intake, physical enforcement, or response execution.

## Input and persistence contracts

Use accepted `ObservationEnvelopeV1` records and their exact source, epoch,
CPU, coverage, durable cursor, and optional kernel sequence. Node-owned context
supplies qualified role, state, entry, binding, object, and selector facts.
Control supplies versioned workload and policy facts. Missing context remains
unresolved. Do not recover historical identity from a current PID, path, or Pod
name. Do not infer application verbs from opaque network effects.

AnalysisStore owns one segment store for raw events and diagnostic output.
DuckDB stores the segment catalog, receipts, context, and derived state. It
also runs isolated SQL queries over bounded authorized input. Raw payloads
are not copied into DuckDB or discovery archives. Durable segment acceptance
precedes each source acknowledgement; catalogue publication does not delay it.
ControlStore keeps policy, trust, rollout,
and approval authority in its existing format. Node keeps its existing delivery
WAL. Neither store replaces the other's authority.

The default deployment embeds the `araphor-data` crate in Control: AnalysisStore,
EvidenceRetentionOwner, QueryOwner, DiscoveryOwner, GraphAndFindingOwner and
NotificationRouter. Discovery can be disabled without disabling intake, query,
or tracing. Optional remote placement moves this complete component and its
complete data directory. CLI and console can use either deployment's authenticated API.
Policy authority, publication and trace dispatch remain in Control.
No generic public producer or Ingest API is part of this plan.

## Owner boundary

The [CLI and observability plan](../../araphor-observability/README.md) extends
this design with new measurements. It does not recover missing historical
facts. `araphor sql` calls the query owner below; `araphor trace` calls a
separate diagnostic execution owner and prints its own output. Both use the
console's authenticated API. Trace results use the same storage and disclosure
owners. Arbitrary scripts do not inherit pod confinement from target selection.
Interceptor supervises the delegated diagnostic loader; capture requires its
qualified lifecycle and interference limits.

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

Data implementation home: `crates/araphor-data/src/`. Put AnalysisStore in
`analysis/`, QueryOwner in `query/`, and portable discovery in `discovery/`.
Create modules only as an approved slice needs them. Keep policy compilation,
source authentication, trace authorization and dispatch in `mithril-control`.
Control may call data owners but the data crate must not import Control.
`EvidenceIntakeIdentityV1` and storage limits live in the data crate and are
re-exported by Control. Control authenticates the Node and validates the wire
record before calling a data owner. The data owner computes a source key from
the exact identity fields and checks receipt, duplicate, gap, and size rules.
It must not accept client-supplied tenant or source keys as authority.
Mithril 7 owns data recovery, query evaluation, and retention. Observability 3
adds production client SQL admission and isolation to the same data owner.
Discovery analysis and Control's TraceOwner use those facilities independently. The
query credential has no source-write,
signing, Kubernetes, response, or model-provider authority. The external agent
owns model execution. Control applies export policy before query evaluation.
Araphor has no model runtime, provider gateway, training pipeline, or agent-job
registry. The optional remote data process has the same restriction.
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

One shared API implementation applies current grants and invokes the responsible
owner. Control and the optional remote deployment expose the same protobuf RPCs.
CLI, console and an optional MCP adapter use these RPCs, not parallel business
implementations. Remote access follows the delegation contract below.
Use one AnalysisStore for durable data and analysis. Keep control authority in
ControlStore; export versioned policy facts through the policy owner's read API.
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

A local defender runs an existing agent runtime against an operator-managed
model and the same scoped CLI/gRPC contracts. The external client owns model
credentials and inference. It receives no direct DB or Node credentials.
Araphor does not train, load, host, select, update or roll back models.
Model placement changes the disclosure profile, not
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

The [Hugging Face master plan](../README.md)
owns prevention, causal findings, and verified response. Discovery supplies
qualified context and review artifacts; it does not replace those capabilities
with query access or AI classification. Mithril 7 implements discovery methods and assessment validation alongside
graph/finding processing. Mithril 8–10 supply their qualified source and response
extensions; clients expose only operations whose owners pass their gates.

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

Use the [standing acceptance](../hugging-face-adversarial-acceptance.md)
as the oracle, including unchanged workloads and legitimate controls. Do not
claim that discovery's exact file/execute preview completes this matrix.

The [response plan](../phase-9-local-and-distributed-response.md)
owns ResponseCoordinator, target revalidation, authorization, durable
transitions, readback, and watch. Use the same lifecycle as Chapter 24 and
Appendix A.15.4 of the validated architecture; do not create a console or
discovery-specific response state machine.
The [provider plan](../phase-10-provider-connectors-and-recovery.md)
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
| `DiscoveryCheckpoint` | Configured scope and sources; interval/build ID; processed store position and source cursor vector; context/coverage revisions; method version; limits and partial reason. Internal progress, not an agent-created job. |
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

## Embedded storage and query contract

Use one AnalysisStore in `araphor-data`. Reuse the existing segment codec,
checksums, bounded append, and reader from Control. Retain the pinned DuckDB
binding for file lifecycle state, derived-state transactions,
and isolated SQL workers. Raw acceptance uses the original segment writer
inside `araphor-data`; it does not commit DuckDB per raw batch.
Do not add SQLite, DataFusion, a broker, an ORM, or a storage-driver framework.

### Storage owner and schema

```text
data/control/             existing policy, trust, rollout, and authority state
data/analysis/
  segments/               the only retained raw event and trace payloads
  analysis.duckdb         catalog, receipts, context, results, and progress
  analysis.duckdb.wal     native recovery for that metadata and derived state
  backups/                complete, manifest-bound store copies
  tmp/                    bounded query and maintenance spill
```

AnalysisStore owns the directory lease, one serialized writer, and at most
two trusted extraction readers. Control bounds active intake with configurable
global and per-Node slots. Full slots cause asynchronous waiting, not rejection.
The Node queue precedes the global queue. Storage uses its existing writer
mutex without a second fixed writer-slot limit. Internal workers bound their
own work. Source-binding and ACK-receipt lookups use this writer mutex, not
the query-reader pool. Neither ControlStore nor DiscoveryOwner opens
a second raw writer. Blocking storage work runs outside Tokio executor threads
and outside ControlStore locks. Compute results outside the writer guard.

Use existing per-source segment rotation and size bounds. Keep tenant/source
binding and stream kind exact. Trace output uses separate diagnostic streams
and quotas under the same owner. Seal an idle active segment at the next
retention sweep when necessary; do not keep expired input forever because no
new batch arrives. Enforce open-file and source-count limits.

Every tenant-owned metadata key includes tenant identity. Validate reference
ownership, checked integers, schema versions, and canonical digests. Use these
relations; create later result families only in their owning phase.

| Relation | Key and content |
| --- | --- |
| `store_meta`, `relation_revisions` | Store UUID, schema, recovery epoch, commit revision, and last change for each exposed relation. |
| `tenant_usage` | One row per tenant with logical bytes and coverage, context, and result counts. Metadata publication and derived mutations commit their charges in the same transaction. Raw admission includes unpublished charges under the writer lock. Startup and backup validation reject totals that differ from retained data. Physical disk checks remain separate. |
| `segments` | One lifecycle row per file: source, file ID/name, accounted byte end, and Live/Deleting state. This row supports quota accounting, bundle backup, and durable deletion intent. It contains no batch offsets or event offsets. |
| `events` | A logical query relation decoded from committed segment ranges. Derived revision notices have distinct kinds and are not sensor actions. No persisted raw-event table. |
| `source_receipts`, `coverage` | Source/session binding, contiguous ACK position, bounded pending ranges, explicit expiry/loss intervals, and coverage revisions. Kernel sequence stays separate. |
| `context_versions` | Exact owner/lifetime/revision, validity, sensitivity, bounded body, and digest. |
| `processor_progress`, `evidence_refs`, `context_refs` | Processor/version/scope, consumed position, exact dependencies, reason, expiry, and required input floor. A raw witness stores source, cursor, and segment ID, not a raw-frame digest. |
| `expired_ranges` | Source, tenant, segment ID, exact expired cursor interval, and commit revision. The segment ID binds the interval to its deletion intent. This relation contains no byte offsets. |
| `replay_floors` | One greatest deleted raw store position per tenant. Commit it with deletion intent. It bounds append replay, not ordinary retained-witness reads. |
| `profiles`, `behavior_atoms`, `behavior_buckets` | Derived counts, keys, manifests, lifecycle coverage, and method version. Working rows are separate from sealed results. |
| `relationships`, `findings`, `notifications` | Owner-qualified revisions, references, route attempts, and deadlines. |
| `assessments`, `requirements`, `proposals`, `reviews`, `publications` | Bounded immutable bodies, parent references, expected revisions, request digests, and owner state. |
| `traces` | Immutable request source, exact execution bindings, bounded Control authority, and revision-checked cancellation/read revocation. Source bytes occur once per request. |
| `trace_receipts` | One diagnostic receipt per execution: exact identity, last frame sequence, byte count, bounded terminal summary, retained floor and commit revision. It does not contain raw output frames or offsets. |
| `trace_output`, `trace_measurements` | Segment-backed raw frames and reviewed derived measurements. Observability 3 registers their scoped query relations; raw frames are not copied into DuckDB. |

Raw batch headers store cursor ranges, event end offsets, CPU, intake time,
and commit/ordinal positions. The segment owner reconstructs one compact
directory entry per range at startup. It loads event offsets with the selected
batch. Raw pages, historical extraction, and witness lookup use this owner.
DuckDB contains no `batch_ranges` table. CRC32C checks raw bytes. Do not compute
or store SHA-256 for raw batches or raw witnesses. Exact references identify
the source, cursor, and containing segment; segment IDs cannot be reused.
Keep metadata proportional to batches/segments and bounded sources. Do not
add a per-event ART index, full-text index, custom B-tree, compactor, or
persistent raw query cache.

An active file contains a checked source header followed by length-prefixed
batches. Each batch has metadata, event bytes, and CRC32C. The next batch starts
after that batch's declared length. A sealed file retains this layout. No
footer is required for this implementation. Recovery reads complete batches,
checks CRC32C and metadata bounds, and reconstructs the directory. Recovery
can trim only an incomplete active tail above recorded committed boundaries.
A committed corruption is an error. A sealed directory footer requires a
separate measured need and is outside this change.

`StorePositionV1` remains `(commit_revision: u64, ordinal: u32)`.
The serialized data owner assigns one revision and distinct ordinals to newly
committed records. A raw segment commit persists those positions. Derived
transactions persist their positions in DuckDB. Catalogue publication keeps
the original raw positions. An exact retry changes neither revision nor notification.
Source cursor, kernel sequence, and store position remain separate. Revisions
order commits, not cross-node causality. Ordinary restart keeps the store UUID
and epoch; restore changes the recovery epoch.

Query visibility follows durable commit, not the contiguous source ACK.
If cursors 11–20 arrive first, query returns those rows with a missing 1–10
range. ACK remains zero. When 1–10 arrive, they receive new store positions;
follow appends them once and reports corrected coverage. It does not replay
11–20 at new positions. Ordered processors still use contiguous source reads.
Coverage is a separate revision, not a mutable field in an immutable event.

Store result bodies and canonical manifests in DuckDB. References identify
segment records by exact source/cursor/segment identity; they do not copy their payloads.
A retained summary cannot answer arbitrary queries over expired raw input.
Recovery of results needs their database, not a rebuild from incomplete history.

Control projects bounded policy, trust, and rollout facts through exact owner
revisions and digests. Preserve revision zero. Read at most 16 entries per
one-second tick, release the Control lock, then commit each projection.
Limit each body to 32 KiB. Missing exact versions stay Unknown. Use null
validity bounds when the source cannot prove an interval. Do not infer
activation from a projection or claim a transaction across Control and data.

### Commit and acknowledgement

```text
Authenticated Node submits a batch
  -> EvidenceIntakeOwner validates source, wire format, sizes, and grants
  -> AnalysisStore reserves segment, metadata, and recovery capacity
  -> writer checks source ranges and retained duplicate bytes
  -> writer appends complete self-contained raw commits through the original segment owner
  -> writer syncs affected segment files and any new directory entries
  -> writer publishes the durable raw receipt and committed revision
  -> Control returns the durable contiguous source cursor

A processor submits calculated results
  -> writer checks expected progress, input availability, and exact references
  -> one metadata transaction commits results, progress, and reference pins
  -> writer publishes the new revision
```

Synced segment commits make raw bytes visible. Each commit carries source
binding, CPU, cursor ranges, offsets, intake time, and store positions. Reuse
the original framed checksum and active/sealed recovery rules. Complete valid
commits survive restart even if ACK or catalogue publication did not occur.
Only an incomplete active tail can be discarded. Corrupt complete frames,
missing referenced files, and invalid sealed tails stop data readiness.
Never reuse file IDs or delete unknown files as a repair.

Raw receipt and replay lookups do not query DuckDB. Keep compact descriptors
and checked admission totals in the serialized owner, not decoded history.
Raw quota checks include commits that are not yet in the database catalogue.
Derived mutations update required-progress, witness, and quota state under
that same coordinator. No stale projection can authorize deletion or intake.

Publish file byte totals and source receipts to DuckDB in bounded groups outside
the raw ACK operation. Do not publish batch ranges or event offsets.
Before a derived transaction, retention decision, or metadata snapshot needs
new input, publish the required file and receipt state. The existing maintenance
owner also advances this state. Read deadlines and scan bounds still apply;
return an explicit error instead of an incomplete result. Metadata failure
cannot roll back a raw ACK. Backups include all durable raw commits.

Create a store only in an empty leased directory. The lease file can remain.
If the metadata database is missing while other store entries remain, reject
startup without creating a replacement database. Restore the complete bundle.
Raw segments can rebuild descriptors, but cannot rebuild required progress,
witness pins, or derived results that were stored only in that database.

If a raw sync outcome is uncertain, stop writes and recover the segment owner
before retry. A recovered complete commit is a duplicate on replay. If a
derived metadata commit is uncertain, recover that database transaction
before accepting further dependent mutations. Keep data readiness false if
recovery fails. Node retains unacknowledged input.

Start group limits at 4,096 records, 4 MiB encoded input, or 50 ms, whichever
comes first. Existing wire limits still apply. The retained duplicate path
reads the bounded committed batch and compares exact bytes.
Conflicting bytes reject. Below the retained raw floor, return
AlreadyAcceptedExpired, not a claim that unavailable bytes match.
Preserve pending-gap bounds and authenticated coverage rules. Reject capacity
before ACK; no new delivery journal or dual-write raw path is required.

Keep derived work outside transactions. Commit results, progress, and exact
references together with expected-progress comparison. A failed transaction
advances none of them; replay must not double counts. A bounded read lease
protects input during extraction. At result commit, recheck that each required
record is still available; expiry returns an explicit conflict/gap.

### Retention, capacity, backup and restore

Use the existing pilot ages: raw input 24 hours, profiles 30 days,
finding/review records 90 days, and pending-review witnesses 7 days.
An age is an expiry target, not permission to erase required evidence.

Keep two processor classes:

- Optional discovery/enrichment/advisory progress does not pin raw history.
  Resume retained input or commit an explicit missing range before continuing.
- Required security packages protect their unprocessed accepted input.
  Failure raises health immediately. Stop affected intake at its protected
  age/byte bound; only authorized retirement can release that obligation.
  Disabling discovery does not disable required security packages.

References stay event-exact, but the first implementation retains whole
segments. A live reference protects its containing segment, not its whole
source stream. Charge the full distinct protected segment bytes to the witness
budget, once per tenant, plus retained context. Report referenced payload bytes
and extra retained segment bytes separately. Reject new optional pins before
their quota; required work reports unhealthy/backpressure rather than losing
its witness. Do not silently weaken the evidence requirement.

```text
Retention selects a sealed segment
  -> writer verifies age/byte eligibility for every contained batch
  -> writer checks required progress, pending input, exact pins, and read leases
  -> metadata transaction marks it Deleting and commits exact expired ranges
     and relation revisions
  -> new reads and result pins cannot acquire that segment
  -> owner unlinks that exact file and syncs its directory
  -> metadata cleanup removes the pending-delete entry

The process restarts during deletion
  -> recovery completes only catalog-recorded deletions
  -> an already absent Deleting file is an idempotent success
  -> a missing Live file is corruption, not normal expiry
```

Serialize pin registration and retirement through the same writer. Keep read
leases bounded by the extraction deadline; release them before network I/O.
A query cursor or external consumption ACK never pins history. Holes caused by
expiry remain explicit even when an older witness segment survives. Never hide
such a retained witness behind a single contiguous floor.

For append replay, persist the greatest deleted raw store position per tenant
with the deletion intent. A checkpoint below this floor returns CursorExpired,
even when its filter might have excluded the deleted records. This conservative
rule needs no per-query retention index. Report unavailable replay, not proof
that a matching record was lost. Keep exact expiry intervals for coverage and
keep retained witnesses readable. Backup and restore include the replay floor.

Initially reclaim whole segments only. No row-level raw deletion, background
compaction, or selective witness archive. If measured pin amplification or
query scans cannot meet the unchanged budgets, stop and propose the smallest
change for approval. Do not build a custom storage engine to force this choice.

Charge raw frames once, batch/segment metadata, derived rows, pending appends,
native WAL, temporary work, and complete/incomplete backups. Retain the 8-GiB
store, 2-GiB tenant, 512-MiB witness, and 25-percent maintenance allowances from
verification.md. Protect separate Control policy capacity and trace terminal
reserve. Raw bytes inside pinned segments are not freed capacity.
Check actual file/free-space use after unlink and metadata checkpoint; a
logical expiry does not prove physical recovery. If capacity stays exhausted,
reject diagnostics first and backpressure uncommitted intake.

Backup pauses admission, drains work and read leases, seals/syncs segments,
checkpoints/closes the metadata DB, and copies the complete directory state.
The manifest lists schema, store/epoch/revision, exact segment files and
committed sizes/digests, and the metadata database digest. No active native
WAL is omitted. Resume only after validated reopen; keep the lease throughout.
Managed backups use unique subdirectories under backups/, never overwrite or
auto-delete old copies, and count all files against capacity. Reserve total
copy size plus 25 percent, manifest bytes, and the actual file-entry count.
An external completed bundle is a valid restore source.

Restore to an empty owned directory under its lease. Sync restore.pending
before copy. Validate metadata, every listed segment, receipts, progress,
and references. Commit a new recovery epoch, then remove the marker and sync
before readiness. On failure, leave the destination unavailable and preserve
the source bundle. A retry uses another empty directory; do not remove the
marker to bypass checks. Never restore only the database or only the segments.

After an older restore, Node can have discarded already acknowledged input.
Use the existing authenticated NodeEvidence.ReportFloor contract to commit
exact recovery gaps. It is not an evidence ACK and cannot advance receipts
or processor progress. Report Partial recovery; do not invent missing records.

### Reader and rotation locking

AnalysisStore keeps the existing writer coordinator, segment-protection
guard (`maintenance`) and raw-directory mutex (`raw`). The protection guard
keeps selected files stable during reads; rotation can rename an active file.
No writer may hold the raw-directory mutex while waiting for exclusive
segment protection.

When `commit_evidence` requires rotation:

1. Keep the writer coordinator so another writer cannot change the planned write.
2. Release the raw-directory mutex before waiting for exclusive protection.
3. Acquire exclusive protection after existing readers finish.
4. Reacquire the raw-directory mutex, then rotate and commit.

Readers can thus finish directory lookups and release protection while
rotation waits. Keep the coordinator until the write finishes. Preserve the
segment format, snapshot boundary and durable ACK rules. Do not remove file
protection or hold the writer coordinator throughout a query scan.

In `extraction.rs`, use the existing `AnalysisReadControl::lock` for directory
access in `selected_ranges` and `check_selected_source`. Those waits must
observe cancellation and the read deadline. A DuckDB interrupt does not
interrupt a blocking Rust mutex acquisition.

Implement this correction first in 7.3, before building QueryOwner on the
reader. Its required regression case uses barriers: pause extraction after
it obtains protection and releases the coordinator; start a write that needs
rotation; then resume the reader. Both operations must finish. The first read
keeps its original snapshot, and a later read includes the new commit.

### Read snapshot and selection

Capture source membership, coverage, the metadata snapshot, store revision,
committed byte ends, and bounded segment read leases under the writer
coordinator. Release the coordinator
before scanning. Readers see only those committed ends; later appends cannot
enter the snapshot. Keep context/result reads at the same metadata snapshot.
Cancel and release leases at the deadline, before waiting on the caller.

Use source/cursor ranges and conservative per-batch intake-time bounds to skip
files. Null, unknown, nonmonotonic, or unproved bounds cannot exclude input.
Use exact target/context checks during decode unless a qualified batch summary
proves exclusion. A sparse result can still require a large scan. Bound both
scanned bytes and extracted bytes; return an explicit limit, not a partial
aggregate. Query workers receive decoded authorized batches, never segment
paths or the persistent database.

### Portable records and query input

The data crate owns the shared evidence protobuf messages and one bounded
decoder. Generate each shared message once; Control imports or re-exports it.
Keep the wire package, field numbers and segment format. Control keeps source
authentication and policy checks. Move only the record definitions and decoder,
not the full Control validation model. Discovery reuses the decoder in 7.4.

Decode selected records into temporary typed pages. Map identities, integer
positions, enums, optional context, bytes and timestamps to documented SQL
columns. Preserve exact integer timestamp units; SQL timestamp conversion
must state its precision. Unknown enum values and absent fields remain explicit.
`received_at` means Control intake time, not Node boot-relative event time.
No raw-event table, second archive or persistent query cache is created.

AnalysisStore selects and decodes bounded input, then releases storage guards.
Temporary conversion and evaluation buffers are required; they are not a
durable raw replica. Release them on success, error and cancellation.
Observability 3 sends authorized input to an isolated worker, which has no
segment access. Remote placement runs the same extractor beside its segments;
no query depends on Control-local files.

### Built-in DuckDB input adapter

Implement one internal table-function adapter in `araphor-data/src/query/`.
Use the pinned DuckDB Rust binding's `VTab` trait and its registration API.
Expose logical relations such as `events` as SQL views over bounded typed
input. Map fields to ordinary SQL columns; do not add custom SQL types,
a loadable extension, a plugin registry, or a new stored event format.

```text
AnalysisStore selects committed segment records
  -> shared decoder produces bounded typed input
  -> storage readers and leases close
  -> internal table function supplies DuckDB execution chunks
  -> SQL returns a bounded result
  -> evaluation connection and input are released
```

Register query-owned input through `register_table_function_with_extra_info`.
Each scan has its own position; repeated references and joins must not share
one consumed iterator. Keep input alive through evaluation, then release it
on success, error or cancellation. Do not use the pinned binding's
`arrow_recordbatch_to_query_params` process-lifetime batch registry for this
path. Input ownership must not grow with the number of follow evaluations.

The internal function accepts no client-supplied pointer, segment path or
storage handle. Only owner-created views can invoke it. Client SQL still
passes the closed admission rules. DuckDB vectors and execution buffers are
temporary; no raw-event table or persistent query copy is created. Conversion
can copy values, so this contract does not claim zero-copy execution.

Phase 7.3 uses this adapter for trusted internal evaluation. Observability 3
reuses it inside the isolated worker over transferred authorized input; the
worker does not read segment files. Embedded and remote data hosts use the
same decoder and adapter. AnalysisStore remains the only segment owner.

### One query contract

Use `query(sql, follow=false, cursor?, parameters?, scope?)`. CLI and console
call the same API at the selected deployment. Caller scope only narrows
authenticated scope.
No read-job, subscription-registration, start/status/stop protocol is required.

This public contract is delivered in Observability 3. Phase 7.3 delivers its
trusted internal evaluator and follow engine only. A trusted plan contains a
code-owned SQL template and checked typed parameters, not caller SQL. Public
admission, disclosure, authenticated cursors and OS isolation must pass before
any client can submit SQL. The earlier offline proof is not that release gate.

| View | Contract |
| --- | --- |
| `catalog` | Authorized relations, columns, units, join keys, null meanings, recipes, runbooks, target kinds and owner readiness. |
| `events`, `coverage` | Immutable observation/revision rows and explicit source/retention gaps. Record counts are not physical-action counts. |
| `context`, `behaviors` | Versioned context packets and exact profiles. Discovery-disabled state is explicit. |
| `policies`, `findings`, `assessments`, `suggestions`, `notifications` | Qualified owner revisions. Unavailable owners are not empty healthy tables. |
| `traces`, `trace_output`, `trace_measurements` | Capture state, bounded raw frames, and measurements with units, reset epoch and coverage. SQL cannot attach a probe. |

Normal mode evaluates one admitted SELECT against a committed snapshot.
Support projection/filter, nonrecursive CTEs, qualified equijoins, aggregates
and bounded window functions used by the reviewed recipes. Require explicit
stable ordering where output order matters. Reject writes, multiple statements,
recursion, unapproved catalogs/functions, loadable extensions and direct
client calls to table functions. The owner-created input views use only the
built-in adapter above.
LIMIT limits output, not work. Freeze the authorized relation set before binding.

Return schema, rows, read revision, receipt, coverage, owner lag and limits.
Normal results above 200 rows or 1 MiB have an explicit limited state. Never
truncate aggregate or join input to make a query fit. A receipt binds principal,
disclosure revision, SQL/parameters, target snapshot, schema, store identity,
input revision and result digest. Retain cited receipts with assessments,
not a durable per-reader job. Expired evidence limits replay.

### SQL-derived input bounds

Use [sqlparser-rs](https://docs.rs/sqlparser/0.63.0/sqlparser/) with
[DuckDbDialect](https://docs.rs/sqlparser/0.63.0/sqlparser/dialect/struct.DuckDbDialect.html).
Phase 7.1 pins a compatible parser/engine pair and tests the admitted subset.
The parser supplies an AST, not authorization, name binding or a sandbox.
Observability 3 extends the existing syntax/relation guard with production
column binding against the authorized schema. The current guard is not that
binder. Phase 7.3 uses declared bounds in reviewed templates, not this public
SQL admission path.
Do not build a second SQL parser or a general query optimizer.

The SQL predicate is the source of the time bound. No duplicate window flag
or separate time argument is required. The optional target scope still narrows
the caller's grant. For the first extraction optimization, accept one direct
time-bearing base relation with an optional alias and top-level WHERE
conjunctions. Match direct received_at comparisons against typed UTC timestamp
literals/parameters, BETWEEN, or CURRENT_TIMESTAMP minus a literal integer
second interval. Preserve inclusive/exclusive endpoints and SQL null behavior.
Convert only checked bound values into fixed parameterized extraction statements.
Keep the complete predicate in the worker query.

Do not infer a global window from a branch of OR, NOT, HAVING, an outer join,
a computed/renamed timestamp, or a nested/CTE predicate. Multiple references
to the same relation need separate proof; do not filter all aliases from one
alias's predicate. For these unoptimized shapes, extract the complete authorized
input within budget or return InputTooLarge. Unsupported SQL still rejects.
A missing bound does not imply an undocumented default window. A narrower
range is an optimization only when it cannot change the SQL result.

Example:

```sql
SELECT operation, COUNT(*)
FROM events
WHERE received_at >= CURRENT_TIMESTAMP - INTERVAL '600 seconds'
GROUP BY operation;
```

Extract permitted columns and rows in that recognized lower range, not the
tenant's complete history. Freeze one UTC evaluation instant for both extraction
and the worker AST parameter. Bind the original SQL, parameters, inferred bounds,
binder version and read revision to the receipt. Report any unavailable history.
Do not apply an event-time filter to the creation date of a referenced policy
or context record; preserve its exact identity and validity.

The proposed 64-MiB extraction budget applies after safe scope/column/range
selection. Qualify it with measurements; it is not a DuckDB capacity claim. Reject
overflow before returning any aggregate. Use existing exact behavior buckets
for supported historical summaries; do not claim raw-query equivalence for
dimensions those buckets do not retain.

### Commit-driven follow

Follow is one server-streaming gRPC call with typed protobuf frames. QueryOwner
selects the result operation and declares it in the opening metadata:

- `append`: projections and fixed predicates over immutable `events` or
  `trace_output`. Scan by commit/ordinal, not event time. No mutable joins,
  aggregate, DISTINCT, relative time, or caller LIMIT in this mode.
- `replace`: other admitted bounded SELECTs, including aggregates, joins and
  mutable finding/status views. Recompute the complete bounded result when a
  dependency changes. A replace frame replaces the prior table; it is not a
  count increment. Intermediate database revisions can be coalesced.

The user still supplies one SQL statement and `--follow`; no mode choice or
second query is required. Unsupported SQL returns UnsupportedFollowShape.
No general incremental SQL engine or persistent result cache is required.

```text
Client requests follow
  -> QueryOwner validates grants, SQL and dependencies, then registers watch
  -> trusted reader captures one metadata snapshot, committed segment ends, and revision
  -> worker evaluates the initial retained range or complete bounded snapshot
  -> QueryOwner emits metadata, result frames and a committed checkpoint
  -> all segment leases, DB readers, and workers close before client backpressure
  -> relevant commit or supported time-window expiry marks the query dirty
  -> one evaluation runs; concurrent changes set one coalesced dirty flag
  -> QueryOwner rechecks dependencies after evaluation and before waiting

Client disconnects
  -> current read/evaluation is cancelled within its deadline
  -> collection and trace execution continue
  -> reconnect validates the last completely received checkpoint
  -> append replays later retained positions; replace emits a fresh snapshot
```

Use Tokio watch for the latest committed revision, not a queue of raw rows.
Bind actual table dependencies, including CTEs, joins, context and coverage.
After registration and each evaluation, compare durable relation revisions
before sleeping. A missed/coalesced wake-up cannot skip committed input.
An unrelated relation change does not rerun the query. A heartbeat checks
current auth, storage health and revisions; it does not rerun unchanged SQL.

Use a 15-second maximum heartbeat and a 500-ms minimum replacement interval.
Admission also limits active evaluations; continuous writes cannot create an
unbounded task queue. An authorization-change signal stops affected readers
immediately; expiry deadlines also wake them. Check grants before each frame.
When authorization state is unavailable, do not disclose data.

Support moving windows only in replace mode. Initially accept the proven
single-relation lower bound from the SQL AST on received_at using
`CURRENT_TIMESTAMP - INTERVAL '<N> seconds'`,
with integer N from 1 to 86,400. Bind CURRENT_TIMESTAMP to one server evaluation
instant. Compute the earliest admitted row expiry and wake there, rounded up
to the one-second window resolution. State that resolution in metadata.
Reject other volatile expressions and unsupported moving predicates, including
a moving range whose extraction proof fails. SQL parsing does not make every
time expression a supported subscription. Normal fixed-range queries can use
the complete-input fallback above.
No traffic is needed for an old row to leave a window.

The [window contract](#intake-time-windows) adds fixed buckets over this same
bounded evaluator. Both window forms use complete replacement results.

Each frame has schema version, operation, store epoch, read revision, frame ID,
coverage and bounded payload. Append checkpoints carry the last scanned
position, including nonmatching rows. A full frame stops before the next
unreturned match. Replacement output must fit 200 rows and 1 MiB in one
complete frame or fail ResultTooLarge; do not send a partial replacement.
Use stable frame IDs for append retries. Consumers can deduplicate repeats;
delivery is at least once, not exactly once.

A cursor binds SQL/parameters, target snapshot, current scope, disclosure,
view version, store UUID/epoch and position. It grants no permission and pins
no history. Changed bindings reject. An append checkpoint below the tenant
replay floor returns gRPC `OUT_OF_RANGE` with authorized expiry information.
This conservative rejection does not prove a matching record was lost.
Replacement resumption promises current
state, not all intermediate states; metadata states this contract. Query errors
are error frames followed by stream close, never empty successful results.
Keep at most one outgoing frame per reader; on a 10-second blocked write,
close with the last completed checkpoint when transport permits.

This uses the useful pattern in the local Mangroves
`src/sql/src/execution/subscribe.rs`: dependency notification, evaluation,
then batches on the same stream. Durable positions, bounded replacement
semantics, failure propagation and access checks are Araphor contracts.
DuckDB executes SQL; Mangroves and DataFusion are not runtime dependencies.

The shared protobuf stream envelope has one typed message per frame. Metadata
precedes data. Frame operations are append, replace, checkpoint, health, error
and terminal. Trace-specific payloads follow the observability contract.
The CLI can render these frames as JSONL on stdout. A closed gRPC stream does
not prove trace cleanup.

Freeze the version-one protobuf payloads as follows. Every frame carries
`schema_version`, operation, store UUID and recovery epoch, read revision,
stable frame ID, coverage summary and one typed payload. The coverage summary
contains its revision, completeness state and authorized missing ranges. Do
not put an untrusted SQL expression or a secret in a frame ID.

| Payload | Required fields and meaning |
| --- | --- |
| Metadata | Selected `append` or `replace` operation; authorized column names, types, null meanings and units; query receipt; dependency revisions; row/byte limits; owner readiness. Include the one-second resolution for a moving window. |
| Append | Ordered rows with their store positions. A row belongs to this frame only after its complete bytes are sent. A retry uses the same frame ID for the same rows and cursor binding. |
| Replace | One complete ordered result, row count and result digest. The client replaces its prior table only after this frame is complete. An oversized result is an error, not a partial table. |
| Checkpoint | Opaque resume cursor and last completely scanned store position for append, or the read revision for replace. A nonmatching row can advance an append checkpoint. |
| Health | Current relation revisions, owner readiness and lag. It has no result rows and does not mark missing evidence complete. |
| Error | Typed code, bounded safe reason and last complete checkpoint if available. Close the stream after this frame. |
| Terminal | Terminal reason and last complete checkpoint if available. A trace terminal also contains its execution and cleanup result; transport closure alone has neither meaning. |

### Intake-time windows

Implement moving intake-time windows and fixed intake-time buckets in 7.3.
Use trusted templates there. Observability 3 admits their SQL forms through
the public query boundary. Both deployments use the same QueryOwner and
DuckDB adapter. No new window flag, service or subscription database is needed.

A moving window answers a current question, such as the number of records
received during the last five minutes:

```sql
SELECT COUNT(*) AS event_count
FROM events
WHERE received_at >= CURRENT_TIMESTAMP - INTERVAL '300 seconds';
```

For records received at 10:01, 10:04 and 10:07, this query returns 2 at 10:08
and 1 at 10:10. Freeze one evaluation instant for extraction and SQL. Evaluate
on relevant commits and row-expiry timers, including when no traffic arrives.
Send a complete replacement, then release input before waiting. The client
replaces 2 with 1; it does not add the counts. Use the existing one-second
expiry resolution and report clock changes.

Fixed buckets answer a history question, such as the number of records in
each five-minute interval. Use DuckDB's existing
[`time_bucket`](https://duckdb.org/docs/current/sql/functions/timestamp)
with UTC and an explicit origin:

```sql
SELECT time_bucket(INTERVAL '5 minutes', received_at,
                   TIMESTAMP '1970-01-01 00:00:00') AS window_start,
       COUNT(*) AS event_count
FROM events
WHERE received_at >= $1 AND received_at < $2
GROUP BY window_start
ORDER BY window_start;
```

For a 10:00–10:10 input range, the same records give 2 in the 10:00 bucket
and 1 in the 10:05 bucket. Bucket starts are inclusive and ends are exclusive;
a record at 10:05 belongs only to the second bucket. Validate a positive
fixed-duration width. The WHERE predicate bounds extraction; the bucket
expression only groups the selected input. Apply the same scan, input and
output limits. Do not truncate input or send a partial bucket result.
Do not add empty buckets unless a later approved query requires them.

For fixed bounds, follow replaces the complete bucket result when a relevant
commit or retention change affects it. The passage of a bucket boundary alone
does not change that fixed-input query. This differs from moving-window expiry.
Keep coverage and retention gaps visible; exact counts of retained records
do not prove complete capture or physical-action counts.

Keep intake time separate from source event time. An action at 10:04 that
arrives after an outage at 10:20 belongs to the 10:20 intake-time bucket.
Preserve its source timestamp and clock domain separately. Do not relabel
intake time as action time. Do not discard accepted evidence because it
arrived after a window grace period, or claim complete event-time results
because a clock interval ended. Event-time finality requires qualified
timestamps, clock relationships, source progress and coverage.

[ksqlDB](https://docs.confluent.io/platform/current/ksqldb/concepts/time-and-windows-in-ksqldb-queries.html)
distinguishes overlapping windows, sessions, grace and final output. These
distinctions do not require a Kafka dependency. Defer overlapping windows and
sessions until a reviewed detection method needs their separate behavior:

- Five-minute windows starting every minute can contain the same record
  more than once. Do not sum their counts as independent events. A moving
  five-minute count already serves a current burst-count query.
- With a 40-second inactivity gap, records at 10:01:00 and 10:02:00 form two
  sessions. A late record at 10:01:30 can merge them. A session method needs
  an exact grouping identity, such as a process lifetime, and correction rules.

Recompute complete bounded input for these initial window queries. This can
repeat extraction work; it is not an incremental-throughput claim. No
persistent per-query aggregates, second raw archive or general streaming SQL
engine is part of this work. If a required workload cannot meet its budget,
report that workload and obtain approval before adding maintained state.
New performance measurements require separate user approval.

### Query isolation

Observability 3 implements and qualifies this production boundary before
public SQL access. Phase 7.3 must not claim it from an in-process evaluator.

Read-only SQL is not a sandbox. Follow [DuckDB security guidance](https://duckdb.org/docs/current/operations_manual/securing_duckdb/overview).
QueryOwner uses a maintained parser plus a closed relation/function binder.
Resolve aliases, nested expressions, CTEs and star expansion against authorized
schemas. Reject unsupported syntax; do not use regex or a SELECT-prefix test.

Trusted bounded extraction applies tenant, lifetime, row scope and
field disclosure before evaluation. Hidden fields cannot be used in predicates,
joins, aggregates or errors. Add only the proven SQL-derived time bounds above.
Export complete bounded authorized relation batches and needed columns from one
metadata/segment snapshot. Over-limit extraction fails and requests a narrower SQL predicate or
target scope; do not execute arbitrary client expressions in the persistent DB.

A disposable unprivileged worker evaluates those batches in an in-memory
DuckDB instance. It has no production credentials, mounts, persistent database
handle, inherited sensitive descriptors or network. Apply OS memory/CPU/process
limits and a deadline. Disable engine external access, extension installation/
autoload and configuration changes. These settings supplement OS isolation.
Worker failure cannot terminate Control or change a receipt/progress record.
No SQL worker remains alive merely to wait for a follow notification.

Use validated data-owned QueryLimits in both placements. Configure scan,
input and output bounds, deadlines, concurrency and stream count. Reserve
aggregate buffer capacity before extraction; individual query limits alone
do not bound concurrent allocations. The defaults in verification.md are
provisional, not measured capacity. Observability 3 also applies the worker
OS budget. New performance workloads or pass limits require user approval.

Pin the engine dialect, explicit ordering and canonical integer reductions.
Floating-point/model scores do not enter deterministic fact digests.
Measure native RSS and spill; engine memory settings are not an RSS limit.
If isolation or full authorized-input extraction cannot meet the limits,
reject that query shape. Do not fall back to credentialed in-process SQL.

## Durable lifecycle and recovery

Configured derivation uses Reading, Sealing, Complete, Partial or Failed
intervals. Sealed snapshots are immutable. Corrections create a new revision.
One data transaction commits checked outputs, exact references and progress.
No transaction spans model execution, network I/O or a client wait.

Proposal states are Draft, Validated, InReview, Approved or Rejected.
Approved proposals can enter Publishing, Published, PublishFailed or Stale.
Expiry produces Expired. Any semantic edit needs a new preview and approval.
Publication intent and result are durable data records; exact source and
authority are checked through their existing Control owners.

Development schema changes require a fresh data store and fresh Node source
identities. Reject every unsupported schema without modifying it. Do not add
migrations or old-store imports. Backup and restore support the current format.
No automatic destructive repair or empty-database fallback is permitted.
Policy/control-state bytes and Node
WAL formats remain governed by their existing owners. Portable replay uses
an explicitly retained manifest and records; it never fetches current facts
to fill a historical gap.

### Optional remote placement

Run `araphor-data` in the optional data process instead of linking it into
Control's process. AnalysisStore, EvidenceRetentionOwner, QueryOwner,
DiscoveryOwner, GraphAndFindingOwner, NotificationRouter and trace-output reads
use the same crate, segment files, and local metadata transactions in either placement.
The shared decoder, query input and query limits are portable from 7.3;
discovery algorithms are portable from 7.4. Phase 7.9 adds deployment and
delegation, not a second implementation of these owners.
Graph/finding/progress commits and notification recovery do not cross RPC.
Control retains policy/trust/approval authority, source publication, TraceOwner,
Node authentication and dispatch. External agents retain model execution.

Both Control and the remote deployment can expose the same `ClientGrpcOwner`
service. The CLI selects one TLS gRPC endpoint through --endpoint or its configured
profile. SQL, trace, assessment, publication and later qualified operations
keep the same schema, result, idempotency and permission contract. The console
can use either endpoint through gRPC-Web. No redirect, second user command, remote-specific
tool set or privileged generic execute route is required.

The remote endpoint validates TLS and the client's service token or browser
session through shared authentication code. Control owns grants: require a
current Control authorization check for each request and before each emitted
stream frame. Unavailable authorization stops disclosure. Bind internal mTLS
delegation to principal, tenant, operation, request digest, grant revision,
expiry and permitted scope. An internal service identity alone is not caller
authority. Never forward a client-supplied identity header as proof.

Queries, discovery drafts and notification acknowledgements run at their data
owners. Trace submit/cancel, publication, and later exception/response commands
go to the existing Control owner. That owner rechecks current grants, exact
targets and approvals. Preserve the original request key and bytes across both
placements. Trace reads/output come from the shared store. The CLI follows them
automatically at the selected endpoint. No Node credential, signing key or
general Kubernetes mutation credential moves to the data process. Only
NotificationRouter receives its configured, scoped sink credentials; SQL workers
receive none.

Node evidence and output still enter authenticated Control intake. Forward
bounded batches; acknowledge only the remote durable receipt. Use private
protobuf gRPC domain operations for accepted evidence, owner-qualified context, trace
intent/output/result, and shared query/discovery requests. These operations
validate schema, scope and owner before the local raw or derived commit protocol. Do not export
table CRUD, SQL writes or begin/commit RPCs. TraceOwner waits for durable intent
before dispatch. A lost reply is reconciled by request key and content digest;
retry cannot duplicate a capture or source write.

During a partition there is no local raw mirror or extra delivery log. Node
retains bounded unacknowledged data. New trace/publication operations fail
closed when the Control owner or data store is unavailable. Active traces
expire locally. A reachable data endpoint does not bypass unavailable
authorization or invent a successful action. Pending notification attempts keep
their original obligations and deadlines.

External read-only consumers use query/follow at either endpoint. They require
no broker, retention ACK or deployment change. Expired cursors report a gap.

Placement change uses planned downtime: stop new work, finish or expire traces,
drain, seal segments, checkpoint metadata and close the sole writer, then transfer
and validate the complete segment/database bundle, fence the former deployment, then start the new writer. Preserve store
identity and committed positions for a lossless move. Backup rollback changes
the recovery epoch. Do not support live dual writers or automatic split-brain
failover. Policy authority and installed Node enforcement remain in place.

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
