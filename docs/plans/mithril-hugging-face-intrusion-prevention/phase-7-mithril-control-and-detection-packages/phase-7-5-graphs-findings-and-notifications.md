# Phase 7.5: Graphs, Findings, And Notifications

Implement deterministic local detection, policy provenance, mandatory routing,
and provider-neutral authority records inside Mithril Control.

## Intended end state

The same accepted inputs produce the same graph and finding revisions.
Every conclusion retains its coverage and policy limits. Notification retries
and human-acknowledgement deadlines survive restart. No finding or lease record
grants policy or physical authority.

## Implementation flow

```text
The shared reader returns committed evidence and frozen coverage
  -> GraphAndFindingOwner validates exact identities and package inputs
  -> graph joins retain proof quality and contradiction branches
  -> qualified packages commit immutable finding revisions
  -> NotificationRouter commits route, deadline, and delivery state
  -> shared query projections expose committed owner records

Late evidence or a source gap arrives
  -> the graph owner creates a linked revision without changing retained facts
  -> incomplete negative results remain Unknown
  -> routing preserves required action and human-acknowledgement obligations

Control restarts or a notification sink fails
  -> each owner restores its committed checkpoint
  -> deterministic replay deduplicates retained input
  -> routing resumes with its original deadline
  -> intake continues within required-processing retention bounds
  -> installed enforcement remains independent
```

## Entry gate and owners

Require Phase 7.4. GraphAndFindingOwner owns graph and finding revisions;
NotificationRouter owns delivery state; the authority owner owns signed
provider-neutral records. AnalysisStore owns durable data.
Use shared reads, transactional results, and retention from Phase 7.2.
Enabled security packages are required processors. They use accepted evidence
and owner-qualified context without waiting for optional discovery profiles.
Their failure raises unhealthy coverage; their protected retention bounds,
not a separate lag timer, govern intake backpressure.
Implement these owners inside `crates/mithril-control`; no second service,
incident graph, source collector, or query database is required.

Status: **Not done**.

Implement `GraphAndFindingOwner` under proposed `src/graph/` and
`NotificationRouter` under proposed `src/notification/` in mithril-control.
Reuse policy provenance and authorization-proof owners. Each graph result
transaction commits its input manifest, revisions, witness references and
processor progress through AnalysisStore. Compute outside the transaction.

## Required changes

### Immutable graph and finding revisions

Implement canonical subjects/objects/observations/edges, proof-quality-aware
joins, contradiction branches, deterministic windows, finding revisions, and
byte-identical replay in the `GraphAndFindingOwner`. Process parentage never
crosses nodes; time alone never creates an exact edge. Keep graph state in
AnalysisStore, not in CRDs or nodes. The graph schema, versioning, and
store are node-agnostic. Phase 8 extends this same owner with Kubernetes
cross-node edges; it does not add a second graph builder.

### Core detection packages

Implement `HF-PROC-001` and `HF-DW-001`, plus the schema, state machine, and
replay contract of `HF-XNODE-001`. Phase 8 completes `HF-XNODE-001` with its
Kubernetes sources and physical multi-node proof. Each package declares exact
inputs, coverage predicate, window, state machine, finding result, replay ID,
and no invented provider semantics.

### Notification router

Deliver sensitivity-filtered finding revisions with route authorization,
retry, dedupe, sink health, and failure evidence. Notification cannot mutate a
finding, policy, actor role, or response plan.

Use the same accepted-evidence references and finding revisions as discovery,
the local defender, and the console. NotificationRouter owns routing state;
neither DiscoveryOwner nor an agent may create a parallel escalation queue.
Approved routing configuration sets a minimum priority, human-acknowledgement
deadline, bounded retry policy, and escalation route for qualified findings.
Model priority is advisory and cannot reduce that floor or defer delivery.
An approved advisory route can also request human review of a submitted model
concern. It must identify that concern as unconfirmed; it cannot create a
proved finding or response authorization.

Persist the finding/revision/route key, routing-policy revision, delivery
attempt/result, deadline, and authorized human acknowledgement. Agent receipt
and sink acceptance do not satisfy human acknowledgement. Restart retains the
deadline; duplicate delivery does not create a second obligation. Route failure
and overdue acknowledgement remain visible until handled by the configured
policy. Revisions with a new required action get their own obligation.

Implement scoped reads and the human-acknowledgement operation on this owner.
Phase 7.8 exposes those methods through the shared Control API.
Acknowledgement is not finding closure, response approval,
or policy authority. No model call is required to route a critical finding.

### Provider-neutral authority records

Implement approval/request/lease/audit-handle records and signed proof
validation without storing credential secrets. CLI names and process paths
grant no authority. Exact provider issuance/use joins remain Phase 10.

### Policy provenance

Join each observation to its exact CRD source revision, signed candidate,
target snapshot, node-bound generation, and activation acknowledgement when
those records exist. Persist this join as
`PolicyObservationProvenanceV1`. A missing or mixed rollout state limits the
finding and negative claim. Graph and package code may read Phase 6.2 policy
inventory but cannot change desired state, sign or distribute a candidate,
update CRD status, or activate a node generation.

## Acceptance and verification

Replay local credential, executable, file, network, and authority-pivot events
for `HF-001` through `HF-012` under loss/late/duplicate/contradiction variants.
Findings and uncertainty must be stable and explain the exact prevented,
allowed, payload-unobservable, contextual, or outside-authority stage.

- Replay duplicate, late, reordered, gapped, and contradictory input. Preserve
  canonical graph/finding digests and exact package input manifests.
- Persist graph versions, finding revisions, package checkpoints, routing
  cursors, and data references in AnalysisStore. Keep signed authority records with
  their Control authority owner and project exact revisions into context.
  Reopen the data store without changing retained IDs or source positions.
- Test complete, partial, stale, and mixed policy rollout joins.
- Test foreign-tenant references, signed-proof mismatch, expiry, and replay.
- Test route failure, duplicate delivery, missing human acknowledgement,
  restart, model refusal, and a benign model label on a critical finding.
  None may reset or discharge the required escalation deadline.
- Rerun `AUTHORIZATION-REPLAY-004`, `HF-LOCAL-001`,
  `HF-004-RESULT-001`, and `HF-011-READ-RESULT-001` through package replay.
- Use the [Phase 7 runbook](../manual-testing/phase-7-manual-acceptance.md)
  for the graph, provenance, routing, and authority checks.
- Run focused `control_graph_`, `control_notification_`, and
  `control_authority_` tests, then `bash .github/scripts/verify-rust-ci.sh`.
  Test names are implementation requirements; require nonzero case counts.

### End-to-end deliverable

Add `graph-notification` to `mithril_discovery_test` and implement it under
`crates/mithril-e2e/src/discovery/`. Use production intake, graph and router
owners. A test double can supply the external notification sink and clock,
not finding construction or routing decisions. Commit evidence, generate a
finding, fail the first delivery, restart, retry, and pass the human deadline.
Require one obligation with the original deadline. Compare canonical findings
after duplicate/reordered delivery. A benign model report cannot lower priority.

```sh
cargo run -p mithril-e2e --bin mithril_discovery_test -- --case graph-notification --output-directory /tmp/araphor-graph
```

Run the matching physical incident case only after this lightweight result.
Store graph/finding IDs, evidence digests, route attempts, deadline, human
receipt and source coverage in result.json.

## Exclusions and stop point

No new Appendix C fixture ID, cross-node physical claim, provider issuance
binding, source publication, or response actuation. Mithril 8 extends this
graph with Kubernetes causality; Mithril 10 supplies provider bindings.
Stop before the detection-recipe and proposal work in Phase 7.6.
