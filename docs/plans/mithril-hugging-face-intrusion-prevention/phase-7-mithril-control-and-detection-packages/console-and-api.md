# Console And API Contract

This record extends the [Araphor console](../../araphor-console/README.md) within
its planned five workspaces. It defines target contracts, not deployed endpoints. Sample data remains visibly marked until the live connection passes
authentication, authorization, and failure tests.

## Operator journeys

### One investigation shared with the defender

Activity > investigation opens a question, trigger, workload revision, and
source-health limits. Protection > Behavior can open the same view without an
alert. Do not add a sixth workspace or make chat the only investigation path.

Show Facts, Assessment, Alternatives, and Next steps. Facts link to exact
evidence and method results. Assessment shows suggested security disposition,
activity, impact, and urgency separately from source severity. Alternatives
show supporting/refuting evidence and missing checks. Next steps show typed
suggestions, preconditions, risks, and validation state. Expected activity is
not an instruction to close an alert or allow an operation.

Show context selection, omissions, stale facts, and contradictions. Assessment
reports link to server query receipts and evidence. Mark client-reported model,
cost, and checks as unverified until checked. Missing checks keep the assessment
incomplete. Do not display hidden chain-of-thought.

A local defender is a first-class external client. The operator manages its
runtime/model outside Araphor. It submits assessments through the same API as
the console.
Report import is for offline work, not the normal integration. Show model
location, approved data scope, current assessment, mandatory priority, and
delivery/human-acknowledgement state. No new chat workspace is required.

Open either a workload lifetime or an existing finding revision. Query, assessment,
suggestion, approval, policy activation, response result, and late branch all
retain that root and their immutable parent references. A user must not copy IDs
between disconnected screens. A second authorized agent can reopen the same
record without the first agent's chat.

Keep an attention item until its owning notification/review/response obligation
is satisfied. The model cannot lower a mandatory route priority or treat its own
acknowledgement as human receipt. An unavailable model, unacknowledged critical
finding, failed delivery, stale approval, or open response branch stays visible.
Do not combine these states into one AI confidence or Case complete badge.

### Start with one workload revision

Protection > workload > Behavior shows image/configuration revision, declared
roles, active policy, source health, and the most recent sealed profile.
Configured derivation runs continuously. Select a retained scope or revision;
no observation-job form is needed. Show available fields before policy choices.

Do not use a countdown that promises readiness after a fixed learning period.
Show the lifecycle matrix and input health. If startup was missed, say so.
A sealed interval can contain partial data; sealing does not mean protection is ready.

### Review the smallest meaningful change

Policies > Suggestions lists proposals, not individual syscalls. Group by
workload revision and native source change. Show unresolved items, added and
removed grants, broadening, required-case failures, and source age.

The review has four linked sections:

```text
Scope and evidence      Requirement           Policy difference       Preview
exact cohort            owner and reason      exact typed changes     known impact
source intervals        required/forbidden    expansion receipt       unknown cases
gaps and missing cases  unreviewed items       raw source available    next useful test
```

Every preview identifies its proof kind: recorded-input replay, synthetic
case, or present-configuration scan. Live effect evidence is a separate link.
Show evaluated, skipped, unsupported, and error counts. A background scan must
not appear as proof that a historical admission request or runtime action was
blocked.

Selection in one section highlights corresponding records in the others.
Keep the default view concise, but make every rule's source evidence reachable
without leaving the review. A model annotation has a distinct Suggested label,
model version, and Why link. It is not styled as a confirmed fact.

Offer Accept into draft, Edit requirement, Reject with reason, and Request
test. These operations do not affect active policy. Editing recomputes a new
proposal revision. Approval is a separate operation after preview.

### Show permission expansion explicitly

For four exact file reads becoming one directory rule, display both versions,
the newly matching scope, future matches, and the unknown impact where the
resolver cannot prove it. The exact option remains selectable. No small green
diff count may conceal a larger grant.

For selectors, show currently affected and unobserved targets plus future
membership behavior. For an unsupported network export, show the exact lost
semantics and disable that export. Do not label incomplete conversion Success.

### Ask for a missing test

Protection > Behavior and Policies > Preview show a shared test-request card:
question, applicable workload/platform, expected evidence, approved fixture,
estimated cost, and execution approval needed. First delivery supports Create
request and View result. Run test remains unavailable until a qualified test
execution owner exists. The discovery API never accepts arbitrary shell text.

### Publish and inspect actual state

The final confirmation shows exact source revision, target snapshot, grants
added/removed, unresolved claims, approver, and expiry. Publication reports:
Approved, Source submitted, Source accepted, and per-target activation as
separate states. A request accepted by Kubernetes cannot produce an Active
badge without the existing target acknowledgement.

On a stale source, show the competing revision and require a refreshed diff.
On partial rollout, keep old and requested generations visible. On uncertain
publication after a timeout, show Checking source result; do not encourage a
blind second write. Rollback links to a new validated operation.

### Review drift without losing the baseline

Activity shows changed behavior linked to the profile and active policy at the
time. Protection compares old and new image/configuration revisions. Policies
offers a new proposal; it never silently updates the reviewed baseline.
Evidence retains the original observation and review bundle. System shows
projection, source, query, quota, and retention health.

### Explain reduction without hiding loss

Behavior shows a count trail: accepted records, included/unresolved/excluded
records, exact atoms, and review groups. Duplicate deliveries have a separate
counter. Each group can expand to its exact members and source intervals.
Show the grouping key and reasons; a small evidence sample is labeled Sample.
The initial table groups repeated behavior, not similar-looking permissions.

Default review order is guardrail conflict, added authority, missing proof,
then other changes, with stable ID tie-breaking. Frequency can be displayed
without becoming a safety score. New entry classes, changed outcomes, and
lost coverage remain visible even when their command or path looks familiar.
Show Previously reviewed only with the exact scope/revision and decision link.
It is not a global exception or a detector-disable action.

Separate comparison filters for new behavior, changed outcome, changed
coverage, and changed workload revision. Rate charts use retained intake-time
buckets labeled Observations received. Unknown source multiplicity stays
unknown. Show processor Pending/Unavailable and query-data revision apart from
source health. No partial query result can appear as Nothing to review.

## Proposed API operations

### CLI-first reads and diagnostic capture

The [observability contract](../../araphor-observability/README.md) owns
`araphor sql`, `araphor trace`, their CLI behavior, trace RPCs, target
resolution, source inspection, limits, and optional Trace CRD. Agents use
their existing terminal tool. Trace prints its own output; SQL is not a
required monitoring step. The CLI receives a single response stream and resumes only after transport loss.
Console code uses the same API directly, never a shell or server-side CLI.

Observability 3 delivers authentication and the query/trace API foundation
before Phase 7.7. Phase 7.7 adds assessment submission. Phase 7.8 adds review/publication
to that same owner.
There is no extra listener, read-job registry, or transport-specific authority.
MCP remains optional. Trace cancellation does not change installed protection.

Use the shared optional TLS listener for native gRPC and browser gRPC-Web in
Control or the remote deployment. CLI --endpoint/profile selection uses the
same protobuf service. Remote authority operations forward to Control under the
[placement contract](engine-design.md#optional-remote-placement), not a broader
service grant. Static assets and OIDC browser redirects still use HTTPS;
neither exposes Araphor data as REST/JSON. These are proposed contracts, not
deployed endpoints.

### One investigation read

`AraphorClientService.Query` accepts the same strict protobuf schema as the
query tool:

```text
query(sql, follow=false, cursor?, parameters?, scope?)
```

This simplifies reads; it is not the complete Araphor tool surface. Normal SQL
retrieves context, evidence, differences, counts, and owner state. One-shot
and follow return one server-streaming RPC. QueryOwner appends retained immutable rows or
replaces a complete bounded result on relevant commits. Metadata declares
the operation, schema, scope and time-window resolution. Checkpoint frames
support reconnect; no client polling loop is required.

Examples use proposed columns and fixture IDs. These are protobuf request
fields, not JSON/HTTP bodies:

```text
QueryRequest { sql: "SELECT * FROM context WHERE subject_id = 'workload-123' AND method_id = 'credential-access'" follow: false }
QueryRequest { sql: "SELECT operation, COUNT(*) AS records FROM events WHERE subject_id = 'workload-123' AND record_kind = 'observation' GROUP BY operation" follow: false }
QueryRequest { sql: "SELECT event_id, record_kind, entity_id, revision FROM events WHERE subject_id = 'workload-123'" follow: true }
```

Resume a broken stream with its last complete checkpoint. Closing the read
stops waiting, not collection. COUNT counts records, not physical actions.
Coverage, omissions and owner lag accompany every result. An aggregate with
follow=true uses replace frames; never add successive counts together.

Use the [query contract](engine-design.md#one-query-contract) for retention,
cursor expiry, late input, supported SQL, and isolation. SQL-derived bounds use sqlparser-rs DuckDbDialect and the proven-safe AST
subset in that contract. A window in SQL needs no duplicate flag. Parsing
alone does not prove safe extraction. No query jobs, subscription registry,
WebSocket requirement, or separate streaming service.

Console tables use fixed parameterized queries. A Live switch follows that
query and applies append or replace frames. Cancel stale streams on scope change;
their replies cannot update the new scope. An SQL editor has no extra authority.
Show lag, gaps, expiry, and limited output instead of an empty healthy view.

### Shared contract for every client

Every read or mutation binds authenticated tenant and owner-qualified subject
references. Reports and changes also bind input/evidence revisions and their
parent finding/proposal/response IDs. The service resolves and validates those
references; the browser or model cannot declare their authority.

Use the same request/response types, grants, idempotency keys, errors, and owner
methods for CLI, console, and optional MCP. Execution results commit owner revisions to the
shared data store. A lost reply is resolved by the original request ID before
retry. Revocation applies to subsequent reads and mutations, not just login.

Notification delivery and human acknowledgement use NotificationRouter's
authorized API when that owner is qualified. Acknowledgement records the exact
finding revision, route, and human principal. It does not approve a response,
close a finding, or remove policy. Query exposes its receipt and deadline.
Do not add a discovery-owned notification state machine or agent-only case DB.

### Governed changes

SQL does not mutate policy, submit assessments, or execute response.

| Proposed `AraphorClientService` RPC | Contract |
| --- | --- |
| `SubmitAssessment` | Validate a bounded assessment/suggestion report; create Suggested drafts, not confirmed facts or authority. |
| `CreateProposal` | Build and preview a policy proposal from pinned requirements/base/targets; return its immutable revision and Pending or validated result. |
| `ReviseProposal` | Create an edit with an expected parent revision; invalidate old approval. |
| `PreviewProposal` | Re-evaluate exact inputs; track bounded work on the proposal, not a generic job. |
| `ReviewProposal` | Human approval/rejection binds exact digests, expiry, and reviewer independence. |
| `PublishProposal` | Check separate publication authority and approved digests; conditionally update the existing source. |
| `CreateTestRequest` | Record a scoped question and fixture reference; no execution. |
| `SubmitClassificationFeedback` | Scoped correction, not automatic training or promotion. |
| `ImportContextDocument` | Import versioned context with trust, sensitivity, and validity. |

Read proposal, publication, and assessment state through query. Preserve the
existing policy-owner boundaries; do not turn these writes into SQL procedures.

All mutation RPCs are unary and use typed protobuf requests, bounded replies,
and idempotency keys where retries could duplicate work. Reads of their owner
state use `Query`; no parallel REST representation exists.

Response and exception interfaces belong to their own owners, not DiscoveryOwner.
Expose them only after the readiness gates below. Their RPC/schema definitions
must follow those owners' qualified types. A missing owner returns Unsupported
and is not advertised as an executable tool.

## Authentication and permissions

### Agent tool contract

Use the CLI over authenticated owner APIs for terminal-based agents. An
optional thin stdio MCP adapter can expose the same contracts when a client
needs it. Generate client types from the same protobuf definitions as gRPC. Operation count
follows authority boundaries, not a fixed minimum. Do not hide a large
operation switch inside `query` or add tracing side effects to SQL.

| Proposed tool | Owning behavior | Release gate |
| --- | --- | --- |
| `query(sql, follow=false, cursor?)` | Shared Control query code reads authorized views, including capability and protection state. | Query isolation, scope, replay, and follow tests. |
| `submit_assessment(report)` | DiscoveryOwner validates classifications, counterevidence, and typed suggestions as drafts. | Draft grant; cited evidence and revision validation. |
| `propose_policy(requirements, base_revision, targets)` | DiscoveryOwner builds and previews; native policy owners validate/compile. | Qualified exact policy subset; no publication side effect. |
| `publish_policy(proposal_id, approval_id)` | Publication adapter submits the exact approved source. | Separate publish grant, valid independent approval, stale-target checks, durable intent. Not in default investigator credentials. |
| `request_exception(grant_id, target, bounds, reason)` | Existing exception workflow resolves one precompiled bounded grant. | Qualified public request/approval seam; exact target, expiry, use count, and revocation proof. Until then, show the owner handoff only. |
| `plan_response(finding_revision, targets, desired_postconditions)` | ResponseCoordinator freezes branches, resolves targets, and shows feasible typed actions, blast radius, missing authority, and simulation. | Master response owner and graph inputs qualified; no effects. |
| `execute_response(plan_id, authorization_id)` | ResponseCoordinator revalidates and dispatches approved typed node/provider actions. | Exact operation grant, signed scope/expiry, physical readback, healthy watch, and recovery. Each provider capability qualifies separately. |

These are initial intent-level boundaries, not a promise that all seven tools
exist or must ship together. No general shell, arbitrary provider call, model
self-approval, or guessed graph-to-PID actuation. Test execution remains a
separate qualified owner capability, not implicit in a TestRequest.

The [combined implementation order](README.md#combined-implementation-order)
assigns delivery: Observability 3 owns query/trace CLI and API access.
Phase 7.7 adds assessment submission. Phase 7.8 adds policy and
notification/human-acknowledgement adapters on the same foundation. Mithril 8 owns the bounded-exception request
adapter. Mithril 9 owns local/Kubernetes response planning and execution;
Mithril 10 extends those tools for each qualified provider action. Each phase
includes its console integration and tests. Later adapters do not block the
first investigation and policy release.

Default investigators receive query and optional draft submission. A separately
authorized defender can receive publication/response tools. Humans approve
widening; an existing signed preauthorization can permit only the exact bounded
response it names. The model cannot mint or enlarge it. Tool metadata and
retrieved runbooks do not grant authority.

Read status and postconditions through query/follow; do not add get-job tools
for each operation. Unlike reads, policy and response mutations retain their
owner's durable lifecycle, cancellation, expiry, and reconciliation. Simplify
the client without deleting that state. A response cancellation needs the
response owner's qualified authorized operation; ceasing reads is not cancellation.

### Identity and grants

Reuse OIDC validation from the existing administrative workflow, but add console sessions and
authorization separately. Existing administrative-exec credentials do not
establish console membership. Require tenant and object scope on
every lookup, mutation, artifact download, and evidence link. Do not trust a
browser-supplied tenant claim without authenticated membership.

| Permission | Allows | Does not allow |
| --- | --- | --- |
| `discovery.read` | Profiles and proposals within scope | Raw sensitive evidence outside the caller's evidence permission |
| `discovery.draft` | Requirements and proposal revisions | Approve or publish |
| `discovery.review` | Approve/reject permitted changes | Bypass reviewer independence or current source restrictions |
| `discovery.publish` | Submit an approved exact change to an authorized source | Sign arbitrary artifacts, select another tenant, or mutate Node state |
| `discovery.context.manage` | Import or approve context/runbook revisions | Publish policy or turn observed text into trusted instructions implicitly |
| `discovery.export` | Return filtered context to an approved external recipient and purpose | Export all raw evidence or bypass disclosure policy |

Configure grants by exact issuer and subject, tenant, cluster, namespace UID,
and permitted operations. Default deny applies. These are permission names,
not mandatory platform roles. Recheck current grants on each request and
before publication. Raw evidence needs a separate evidence-read grant. Every
widening requires distinct authorized drafter and reviewer identities.
Use server-side sessions with a 15-minute maximum lifetime and a 256-session
process limit. Restart and logout invalidate sessions. Cookie authentication
requires Secure, HttpOnly, SameSite, CSRF tokens, and exact origin checks.

Agent clients use a configured OIDC service principal, the Control API audience,
short-lived bearer tokens, and explicit scoped grants. Reuse issuer/signature/
audience/expiry validation; do not add an identity provider. Administrative-exec
tokens and browser cookies are not agent identities. The default investigator profile
permits reads, approved export, and optional draft assessments. Publication and
response require separately configured operation grants and exact approvals.
Recheck grants before query evaluation and response, including after a follow
wait. Only a separately configured tenant administrator can approve export
recipients and data classes.
HumanConfirmed classifications and reusable reviewed-case context require
`discovery.review`; an agent's draft or feedback cannot set those states.
Context approval also needs `discovery.context.manage`. Neither operation
creates a policy approval without the separate exact proposal review.

## Streaming result contract

Use the canonical [stream contract](engine-design.md#commit-driven-follow)
and [trace payloads](../../araphor-observability/README.md#shared-apis-and-output).
Clients replace a displayed result only after the complete replacement arrives.
Deduplicate append frames and save only complete checkpoints. A trace result
reports its actual cleanup state; gRPC stream closure is not execution proof.

## Errors, concurrency, and audit

- `INVALID_ARGUMENT`: malformed schema or unsupported input fields.
- `UNAUTHENTICATED`/`PERMISSION_DENIED`: absent identity or insufficient scope. Avoid tenant enumeration.
- `ABORTED`: stale source, target, proposal revision, or reused idempotency key with
  different content. Return authorized conflict details.
- `OUT_OF_RANGE`: retained artifact or read revision expired. Do not invent empty data.
- `FAILED_PRECONDITION`: valid request with unsupported semantics or missing mandatory proof.
- `RESOURCE_EXHAUSTED`: quota exhausted, with a bounded retry hint.
- `UNAVAILABLE`: owner unavailable. Never represent it as an empty healthy profile.

Bound preview work is tracked on its proposal revision; reads create no job.
Response retains its own durable transaction. Cancellation does not undo an
already submitted source write or an applied response. Publication uses
the durable intent and reconciliation contract in [engine-design.md](engine-design.md).

Audit exact request identity, caller, tenant, input digests, preconditions,
decision, and source receipt. Redact secrets. Do not log full feature vectors
or raw event text by default. A denied cross-tenant request cannot emit the
other tenant's object details in the audit visible to the requester.

## Required fixture states

| Fixture | Visible behavior |
| --- | --- |
| Complete recorded scope | Known preview results with the exact lifecycle/case limit |
| Missed startup and gapped interval | Partial profile; missing cases cannot be collapsed into a green score |
| Repeated denied credential reads | Separate denied-attempt group; no automatic allow proposal |
| Four files generalized to a directory | Expansion receipt and exact alternative |
| New image under unchanged labels | Separate cohort and explicit revision comparison |
| Classifier abstains or times out | Unknown classification; deterministic review remains usable |
| Stale source during approval | Conflict and refreshed review; no optimistic success badge |
| Partial target activation | Old and requested generations plus per-target reasons |
| Expired replay evidence | Audit retained; full replay unavailable |
| Foreign-tenant artifact reference | Generic authorization failure; no leaked metadata |
| Repeated controller work plus one forbidden new action | One stable repeated group; the forbidden action remains separately visible |
| Database recovery or processor lag | Unavailable/Pending, not an empty list or a complete count |
| Late evidence after review | New snapshot comparison; old reviewed revision is unchanged |
| Suspicious credential access with absent provider audit | Supported observations, alternatives, and a precise evidence request; no invented exfiltration claim |
| Benign positive after deployment | Separate predicate match, suggested disposition, release context, and human confirmation |
| Malicious context or forged citation | Rejected request or unsupported claim; no authority change |
| Export denied or external agent unavailable | Evidence review remains usable; no automatic provider fallback |
| Imported hosted-model report | Export recipient, query receipts, and unverified client model/cost fields |
| Quiet followed stream or expired cursor | Health/checkpoint frames or explicit expiry; never automatic incident closure |
| Local model refuses a critical investigation | Failed check remains visible; deterministic priority and on-call route continue |
| Agent submits an assessment, then exits | Console and replacement agent reopen the same report and outstanding obligations |
| Notification delivered but not acknowledged by a human | Delivery receipt and acknowledgement deadline stay separate; configured escalation continues |
| Preauthorized seed fence with missing remote authority | Local result plus open remote branches; no full containment claim |
| Process stopped but controller replaces it | Original exit proof and a new response revision; incident remains open |
| Shared token or process target | Actual affected participants and explicit widening approval |

## Accessibility and performance

Use semantic tables for exact permission differences. Provide text for each
status and keyboard access to evidence, conflict, and approval controls. Do
not encode trust or unknown states by color alone. Restore focus after dialogs
and validation errors. Announce asynchronous status updates without repeatedly
moving focus. Preserve draft state across authorized navigation.

Page behavior rows and virtualize only when measured row counts require it.
Do not load all evidence to draw one chart. Display filtered and total counts
separately. A graph is optional; a table with linked provenance is the initial
review surface. Keep route and selected revision shareable without placing
secret values in URLs.
