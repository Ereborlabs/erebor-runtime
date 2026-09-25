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

AnalysisStore owns retained events, context, diagnostic output, and analysis
records in DuckDB. Its native WAL provides crash recovery. A durable commit
precedes each source acknowledgement. ControlStore keeps policy, trust, rollout,
and approval authority in its existing format. Node keeps its existing delivery
WAL. Neither store replaces the other's authority.

The default deployment embeds the `araphor-data` crate in Control: AnalysisStore,
EvidenceRetentionOwner, QueryOwner, DiscoveryOwner, GraphAndFindingOwner and
NotificationRouter. Discovery can be disabled without disabling intake, query,
or tracing. Optional remote placement moves this complete component and its
one database. CLI and console can use either deployment's authenticated API.
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
Mithril 7 owns data recovery, query admission, and retention. Discovery analysis
and Control's TraceOwner use those facilities independently. The
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

## Embedded database and query contract

Use the pinned DuckDB Rust binding. Use no ORM, storage-driver framework,
DataFusion layer, external database service, or second raw-event store.
Qualify the version in 7.1. The [concurrency contract](https://duckdb.org/docs/current/connect/concurrency)
permits the embedded design; it is not a multi-process writer protocol.

### Storage owner and schema

The default layout is:

```text
data/control/             existing policy, trust, rollout, and authority state
data/analysis/
  analysis.duckdb         authoritative retained data
  analysis.duckdb.wal     managed only by DuckDB
  tmp/                   bounded query and maintenance spill
```

AnalysisStore owns one writer queue and at most two trusted extraction readers.
Only that owner opens the persistent database. All blocking engine work runs
outside Tokio executor threads and outside the ControlStore lock. Expensive
derivation runs outside write transactions. Query workers receive bounded
authorized data; they cannot open the persistent file.

Every table key includes tenant where the record is tenant-owned. Validate
cross-table tenant/reference consistency before commit. Use explicit primary
keys, checked integer values, schema versions, and canonical digests. The first
schema contains these logical relations; do not create unused indexes.

| Relation | Key and content |
| --- | --- |
| `store_meta`, `relation_revisions` | Store UUID, schema version, recovery epoch, monotonically increasing commit revision; last changed revision for each exposed relation. |
| `events` | Stable source identity, epoch, stream/CPU and source cursor; immutable canonical payload and digest; commit/ordinal position; retained intake time; target lifetime; kind and result. Derived revisions have distinct kinds and are not sensor actions. |
| `source_receipts`, `coverage` | Authenticated source/session binding, contiguous acknowledged position, bounded pending ranges, retained floor, gaps and coverage revisions. Kernel sequence stays separate. |
| `context_versions` | Exact owner, entity/lifetime, revision, validity, sensitivity, bounded body and digest. Policy projections retain the authoritative owner's revision. |
| `processor_progress`, `evidence_refs` | Processor/version/scope, consumed position, coverage/context positions, required input retention; exact witness/context dependencies, reason and expiry. |
| `profiles`, `behavior_atoms`, `behavior_buckets` | Sealed manifests, full exact atom keys, checked counts, outcomes, lifecycle matrix and method version. Mutable working rows are separate from sealed revisions. |
| `relationships`, `findings`, `notifications` | Qualified graph/finding revisions and notification attempts/deadlines. Only their named owners can write these records. |
| `assessments`, `requirements`, `proposals`, `reviews`, `publications` | Bounded immutable content, parent references, expected revision, request digest and owner state. A query row cannot authorize a mutation. |
| `traces`, `trace_output`, `trace_measurements` | Accepted source/grant/target digests, execution state, deduplicated output and reviewed typed measurements. Host-sensitive output keeps its wider read restriction. |

Store canonical manifests and bounded bodies in DuckDB, not parallel
authoritative artifact files. Export bundles are optional portable copies.
A retained summary cannot reproduce arbitrary queries over expired raw input.
A restored database, not a rebuild from incomplete raw history, recovers
retained findings, profiles and reviews.

Policy/control facts cross the store boundary by owner-qualified revision and
digest. A reconciler reads committed ControlStore facts and inserts them
idempotently into context_versions. Report pending or missing context. Do not
claim an atomic transaction across the two stores or infer activation from a
projection. Recheck the authoritative policy owner before a policy mutation.

### Commit and acknowledgement

```text
Authenticated Node submits an evidence batch
  -> EvidenceIntakeOwner validates source identity, schema, sizes and continuity
  -> AnalysisStore reserves capacity and checks retained duplicate digests
  -> one transaction inserts new events, context, coverage and receipt progress
  -> the same transaction assigns commit positions and relation revisions
  -> durable commit completes
  -> writer publishes the latest revision to an in-process watch channel
  -> EvidenceIntakeOwner returns only the durable contiguous source position

Processor reads a bounded committed interval
  -> processor freezes input, context, method and coverage revisions
  -> processor computes outside a write transaction
  -> one transaction checks expected progress and commits outputs, references,
     revision records and new progress
  -> commit notification wakes dependent readers
```

Start intake batches at 4,096 records, 4 MiB encoded input, or 50 ms, whichever
comes first. These are tuning defaults, not measured capacity. Keep decoded
input and queue limits from verification.md. Return retryable backpressure
before ACK if the writer cannot accept a batch. Node keeps unacknowledged input
under its bounded delivery contract; exhaustion produces explicit source loss.

A retained duplicate with equal identity and bytes has no second effect.
Conflicting bytes reject the batch. Below the retained digest floor, return
AlreadyAcceptedExpired for an already acknowledged position; do not insert it
or claim to compare unavailable bytes. A new unproven gap cannot advance ACK.
Preserve the existing authenticated coverage/gap acknowledgement rules.

Rollback changes neither receipt nor processor progress. A crash after commit
but before ACK causes a safe duplicate retry. A processor retries from its
committed progress; counts cannot double. Commit order is delivery order, not
cross-node causal order. Restart reads durable revisions before publishing
readiness. Every mutation, including expiry and deletion, updates dependencies.

### Retention, capacity, backup and restore

Use independent age and byte budgets: initial raw retention 24 hours, profile
windows 30 days, finding/review records 90 days, and pending-review witnesses
7 days. These are configurable pilot defaults. Charge exact witness/context
pins to their own bounded quota; do not pin an entire raw stream for one finding.

EvidenceRetentionOwner checks age, capacity, required processing and exact
witness references in one transaction. It advances retained floors with the
deletion. Keep context while retained output references it.

There are two fixed processor classes, not a user-defined processor framework:

- Optional: discovery profiles, context enrichment and advisory methods.
  Their progress does not pin raw input or stop intake. Disablement preserves
  committed results and progress. On restart, process the retained backlog.
  If the retained floor passed progress, commit an explicit missing range and
  a new incomplete interval before resuming. Never mark skipped input processed.
- Required: enabled deterministic security packages in GraphAndFindingOwner.
  Record each package's source scope and starting floor before intake depends
  on it. Failure raises an unhealthy state immediately. Unprocessed accepted
  input remains protected within the configured raw age/byte budget.
  NotificationRouter retains pending finding/route records and their exact
  witnesses; it does not pin unrelated raw input.

Lag alone raises health warnings; it does not stop intake at an arbitrary
one-hour threshold. Stop affected intake when required unprocessed input
reaches its protected age bound or exhausts its byte reservation. Retain that
existing input until processing or authorized retirement. Raw age is a
reclamation target, not permission to delete protected input. A shared physical
capacity failure can stop all data intake. Keep installed enforcement and
policy/control-state commits independent. Disabling discovery does not disable
security packages. Retiring a required package requires an authorized explicit
change with its cutoff and missing coverage; do not auto-retire it on failure.
No bounded store guarantees both unlimited intake and unlimited recovery.

Review/finding witness pins have their own age and byte budgets. Admission
reserves exact dependencies, not the whole source stream. Optional computation
uses bounded work leases while it commits result references; cancel or restart
expired work instead of keeping an indefinite pin. External readers have no
retention pins or processor ACKs. Required package dependencies must not include
an optional profile processor.

Example: with 24-hour raw retention, discovery can resume an eight-hour backlog.
After two days disabled, it records the expired range and resumes at the retained
floor. In both cases intake continues unless a separate required obligation or
physical capacity limit blocks it. Full replay of expired raw input stays
unavailable even when a retained profile is readable.

Account for database, native WAL, temporary files, backup/maintenance space,
queued writes and terminal trace reserve. Reserve separate filesystem capacity
for policy/control-state commits before admitting data work. At the high-water
mark, remove
eligible data, checkpoint, and check actual free bytes. SQL DELETE alone is
not a disk-space guarantee. [DuckDB checkpoint behavior](https://duckdb.org/docs/current/sql/statements/checkpoint)
requires measured reclamation. If capacity is still insufficient, stop new
diagnostic work first and backpressure uncommitted intake. Keep local Node
enforcement and Control policy authority independent. A corrupt authoritative
data store blocks data ACK and dependent reads; it is not a disposable index.

Use a maintenance window for a consistent backup: pause new data writes,
drain bounded accepted work, checkpoint, close connections, copy the database,
sync the copy and its manifest, reopen, then resume. Never copy only a live DB
file while omitting its WAL. Restore into an empty owned directory; validate
schema, digests, references, receipts and processor progress before activation.
A restore uses a new recovery epoch so pre-restore query cursors fail explicitly.
Keep the previous valid copy until the restored store passes checks.

After restore, a source may already have discarded input acknowledged after
the backup. The Node's retained floor and the restored receipt expose that gap.
Do not invent those records or rewind Node ACK state. Record backup revision,
known missing ranges, and Partial recovery. Qualify this case before release.

### One query contract

Use `query(sql, follow=false, cursor?, parameters?, scope?)`. CLI and console
call the same Control API. Caller scope only narrows authenticated scope.
No read-job, subscription-registration, start/status/stop protocol is required.

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
recursion, unapproved catalogs/functions, extensions and table functions.
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
Use the existing closed binder to resolve permitted columns and aliases.
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
  -> trusted reader captures one database snapshot and its revision
  -> worker evaluates the initial retained range or complete bounded snapshot
  -> QueryOwner emits metadata, result frames and a committed checkpoint
  -> all DB readers and workers close before waiting or network backpressure
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

Each frame has schema version, operation, store epoch, read revision, frame ID,
coverage and bounded payload. Append checkpoints carry the last scanned
position, including nonmatching rows. A full frame stops before the next
unreturned match. Replacement output must fit 200 rows and 1 MiB in one
complete frame or fail ResultTooLarge; do not send a partial replacement.
Use stable frame IDs for append retries. Consumers can deduplicate repeats;
delivery is at least once, not exactly once.

A cursor binds SQL/parameters, target snapshot, current scope, disclosure,
view version, store UUID/epoch and position. It grants no permission and pins
no history. Changed bindings reject. A lost retained append range returns
gRPC `OUT_OF_RANGE` with authorized missing bounds. Replacement resumption promises current
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

### Query isolation

Read-only SQL is not a sandbox. Follow [DuckDB security guidance](https://duckdb.org/docs/current/operations_manual/securing_duckdb/overview).
QueryOwner uses a maintained parser plus a closed relation/function binder.
Resolve aliases, nested expressions, CTEs and star expansion against authorized
schemas. Reject unsupported syntax; do not use regex or a SELECT-prefix test.

Trusted prepared extraction statements apply tenant, lifetime, row scope and
field disclosure before evaluation. Hidden fields cannot be used in predicates,
joins, aggregates or errors. Add only the proven SQL-derived time bounds above.
Export complete bounded authorized relation batches and needed columns from one
snapshot. Over-limit extraction fails and requests a narrower SQL predicate or
target scope; do not execute arbitrary client expressions in the persistent DB.

A disposable unprivileged worker evaluates those batches in an in-memory
DuckDB instance. It has no production credentials, mounts, persistent database
handle, inherited sensitive descriptors or network. Apply OS memory/CPU/process
limits and a deadline. Disable engine external access, extension installation/
autoload and configuration changes. These settings supplement OS isolation.
Worker failure cannot terminate Control or change a receipt/progress record.
No SQL worker remains alive merely to wait for a follow notification.

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

Schema changes require a validated backup and bounded maintenance. Reject an
unsupported newer schema without modifying it. No automatic destructive repair
or empty-database fallback is permitted. Policy/control-state bytes and Node
WAL formats remain governed by their existing owners. Portable replay uses
an explicitly retained manifest and records; it never fetches current facts
to fill a historical gap.

### Optional remote placement

Run `araphor-data` in the optional data process instead of linking it into
Control's process. AnalysisStore, EvidenceRetentionOwner, QueryOwner,
DiscoveryOwner, GraphAndFindingOwner, NotificationRouter and trace-output reads
use the same crate and local database transactions in either placement.
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
validate schema, scope and owner before one local transaction. Do not export
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
drain, checkpoint and close the sole writer, transfer and validate the complete
store, fence the former deployment, then start the new writer. Preserve store
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
