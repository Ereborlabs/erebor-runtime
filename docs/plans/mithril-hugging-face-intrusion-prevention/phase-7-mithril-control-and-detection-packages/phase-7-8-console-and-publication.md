# Phase 7.8: Agent Tools, Console Review, And Governed Changes

Connect discovery to the planned five-workspace console with scoped authorization and
explicit policy, exception, and response authority boundaries. Query is one
investigation tool, not the full product interface.

## Intended end state

An authorized agent can retrieve context, evaluate methods, and submit drafts
through the same owners as the console. A separately authorized defender can
publish a reviewed policy and use qualified response capabilities. An operator
can inspect assessments, review proposals, request tests, approve a pinned
revision, and inspect activation and physical postconditions. Stale or
unauthorized operations fail without changing active policy.

## Implementation flow

```text
Operator opens workload behavior
  -> Control authenticates the request and checks tenant/object scope
  -> console renders bounded profiles, limitations, and suggested categories
  -> operator creates a requirement or proposal revision
  -> preview resolves exact inputs and displays unsupported cases

External agent calls a discovery tool
  -> Control validates service identity, API audience, scope, and disclosure grant
  -> query evaluates scoped reads; draft tools validate assessments or policy proposals
  -> result includes provenance, coverage, limits, and available next operations
  -> investigator credentials cannot approve, publish, or execute response

Reviewer approves a revision and publisher submits it
  -> review checks digest, expiry, scope, and required independence
  -> publisher rechecks current source and target preconditions
  -> AnalysisStore records publication intent
  -> publication adapter conditionally updates the existing Kubernetes source
  -> existing reconciliation owner reads the accepted source
  -> receipt records source acceptance or failure
  -> existing rollout reads supply per-target acknowledgement state

Write conflicts or its reply is lost
  -> publication reconciles exact source identity and content
  -> retry with the same request cannot duplicate a source change
  -> intervening edits require a new review
  -> browser never invents a successful activation
```

## Scope and owners

Control owns scoped APIs and review records. A narrow publication adapter owns
the Kubernetes write; existing policy owners retain compilation, signing, and
activation authority. `ui/mithril-console` owns rendering and request state. Reuse
existing authentication components without inheriting administrative-exec
authority. Read [console-and-api.md](console-and-api.md) before implementation.

## Required changes

### Prerequisites and delivery boundary

Require Phase 7.7's core client/assessment contract, Observability 3, and console fixture phases 1–4 Done in the
[combined order](README.md#combined-implementation-order). This phase reuses assessment submission and delivers
propose_policy and separately granted publish_policy. Status: **Not done**.
Query transport and the SQL/trace CLI already belong to Observability 3 and
must be reused. It also connects NotificationRouter reads and human
acknowledgement. Complete items 1–7 and 11, capability reporting in item 9,
and policy/unsupported-response display in item 10 before Phase 7.10.

Item 8 is an integration contract for Mithril 9 and 10, not an execution
adapter to implement here. Mithril 8 owns the bounded-exception request adapter
in item 9. Mithril 9 owns the response display in item 10; Mithril 10 extends
it for providers. Those owner phases include shared APIs, console, and physical
tests in their own deliverables. Their absence must pass explicit Unsupported
tests here, not keep this phase open until Mithril 10.

1. **Authentication — Control `src/client_grpc.rs`,
   `src/administrative_http.rs`, `src/config.rs`, `src/main.rs`.** Do not add
   another client API owner. Reuse Observability 3's `ClientGrpcOwner` and extend
   it for these mutations. Reuse extracted OIDC issuer/audience/nonce/PKCE
   validation; do not reuse administrative-exec activation tokens. Existing
   auth is an exec workflow, not console membership. Use server-side sessions,
   Secure/HttpOnly/SameSite cookies, CSRF tokens, and exact origin checks.
   Cap sessions at 256/process and 15 minutes; restart/logout invalidates them.
2. **Permissions — same owner.** Extend configured grants keyed by issuer and
   subject, bound to tenant, cluster, namespace UID, and named operations from
   the API design. No grant means deny. Check every object lookup, evidence
   link, and mutation; recheck grants at publication. Raw evidence requires
   separate permission. No browser tenant claim or exec role creates a grant.
3. **API — `ClientGrpcOwner` and `DiscoveryOwner`.** Reuse the bounded `Query`
   RPC and add mutation RPCs in [console-and-api.md](console-and-api.md).
   No read-job API. Limit results to 200 rows/1 MiB; normal overflow is explicit,
   and follow cursors bind SQL, scope, schema, export policy, and position.
   Use the qualified isolated query worker and committed digest checks. Return
   Pending/Unavailable on owner lag, not an empty list. Close DB readers
   before gRPC output; verify cursors survive ordinary database restart.
   Serve assets and gRPC/gRPC-Web on the shared optional Control TLS listener.
   Discovery methods stay disabled until configured with their own grants.
   Do not expose Node credentials through this listener. The separate
   administrative gRPC service retains its own authority on Control only.
   Reuse service-principal bearer validation with a dedicated API audience and
   export-scoped grants for native clients. Browser gRPC-Web calls use the
   bounded session cookie, CSRF metadata, and exact origin check from item 1;
   neither identity inherits administrative-exec authority.
   An optional `src/bin/mithril_discovery_mcp.rs` stdio adapter can use the
   same gRPC contracts and generated protobuf clients; it is not required for CLI
   agents or phase completion. Expose submit_assessment, propose_policy, and
   separately granted publish_policy through the shared API. Proposal construction
   includes native validation/preview; query reads pending/result revisions.
   If MCP is later selected, pin one maintained SDK after schema/transport
   review; no new remote MCP auth service or business owner.
4. **Review — Control approval with data references.** Bind approval to proposal, preview,
   base source, target facts, guardrails, reviewer, and expiry. Require an
   independent reviewer for every widening in this slice. Any semantic change
   requires a new preview/review. Commit publication intent before network I/O.
5. **Source write — `crates/mithril-control/src/discovery/publication.rs` (new).** The current
   `PolicyDesiredStateOwner` watches sources; it is not a write API. Add one
   adapter that updates an existing `WorkloadProtectionPolicy` through the
   Kubernetes client. Fetch and check UID, namespace UID, generation, spec
   digest, and target preconditions; use the fetched opaque resourceVersion
   for the conditional write. Do not compare resourceVersions numerically.
   Same idempotency key/digest returns one receipt; different content rejects.
   After a lost reply, read exact identity/content before any retry. An
   intervening source edit requires review. No source creation or Git writer.
6. **UI — `ui/mithril-console/src/Console.tsx`, `App.tsx`, `consoleData.ts`,
   plus a small `discoveryApi.ts` backed by the generated gRPC-Web client.**
   Current code has eight fixture routes, not
   the planned five workspaces. Coordinate the shell change with the console
   plan; do not build a second shell. Add Behavior, Suggestions, test requests,
   evidence links, projection health, and capability availability. Keep fixture mode separate from live errors.
   Use query/follow, semantic tables, keyboard controls, and explicit
   Unknown/Partial/Expired states. Cancel stale reads when scope changes.
   Show count conservation, grouping reasons, model provenance, and separate
   new-behavior/outcome/coverage filters. No global learned exception button.
   Add the shared investigation view: facts, assessment, alternatives, and
   typed next steps. Show counterevidence, missing checks, disclosure destination,
   query receipts, incomplete checks, and unverified client model/cost fields.
   Classification confirmation is separate
   from policy review. UI and agent calls must produce the same owner artifacts.
7. **Package — `packaging/mithril/Dockerfile`, Helm `values.yaml`,
   `templates/control-deployment.yaml`, `templates/control-rbac.yaml`.** Build
   the UI with its lockfile and copy static output into the existing Control
   image. Reuse Observability 3's optional listener/TLS configuration and
   Service port; do not add another client listener. Grant
   policy update permission only in configured publication namespaces; no new
   secret-read, exec, or wildcard privilege. Preserve read-only container state
   and existing admission/Node mTLS services. Test discovery-disabled rendering.
   Put the embedded DB on the existing single-owner persistent store with a
   qualified local filesystem. Reject an unsupported shared/network filesystem;
   reserve database, native WAL, temporary and backup space. No external DB Service is added.
   Package the query worker with qualified OS isolation and no production
   credentials/mounts/network. No inference-provider secret is required.
   If an optional stdio adapter is delivered, package it as a CLI artifact,
   not another service.

8. **Later integration contract — Mithril 9 and 10.** Before
   adding response endpoints, require the master response/graph owner's qualified
   API and the canonical Chapter 24 lifecycle. Bind plan_response and
   execute_response to ResponseCoordinator; never implement them in DiscoveryOwner.
   Use exact graph/target revisions, existing ResponseAuthorizationV1, typed
   actions, expiry, blast-radius approval, idempotency, and postconditions.
   Each provider action additionally requires its qualified actuator.
9. **Exceptions and unavailable capabilities.** Implement availability reads
   here; implement the request adapter with Mithril 8. Inspect the existing exception
   reconciliation and administrative approval paths. Expose request_exception
   only after a qualified request/approval seam exists for an exact precompiled
   grant. Do not infer permission from a classification. Derive tool availability
   from owner support and grants; no generic plugin registry. Query reports
   Unsupported/OutsideAuthority reasons for missing owners. Hide executable
   adapters until qualified; fixture records cannot enable them.
10. **Protection and response UI.** Show requested policy versus per-target active
    generation, capability gaps, exact affected participants, and proposed versus
    applied response. After a qualified response, follow readback/watch revisions
    and open branches. Process exit, Pod deletion, and provider API success cannot
    produce a Contained badge by themselves. A replacement branch needs a new
    authorized plan revision. Keep response restrictions independent of policy.
11. **Shared investigation and escalation.** ClientGrpcOwner resolves the same
    subject/finding/input references used by the local defender. Show submitted
    assessments, proposals, approvals, results, and branches in that view without
    manual import or copied IDs. Query exposes NotificationRouter's delivery,
    deadline, and human-acknowledgement records. Route acknowledgement to that
    owner under a human grant; it does not close a finding or approve an action.
    Use the master notification rules and tests, not a discovery-owned pager.
    Client loss and model refusal cannot remove an unacknowledged critical item.

Response and exception execution work remains with the named Mithril phases.
Record those capabilities as Unsupported with the owner phase and missing
qualification. They are not unfinished deliverables of this first API phase.
Notification integration is mandatory here because Phase 7.5 is a prerequisite.
Do not substitute a fixture for a missing notification owner or action result.
Do not implement later backend owners to finish this phase without approval.

## Acceptance and verification

- Pass `DE-AUTH`, `DE-REVIEW`, `DE-PUBLISH`, `DE-TENANT`, `DE-CONSOLE`, `DE-INDEX`, `DE-NOISE`, and `DE-MODEL`
  fallback cases.
- No unauthorized or stale write reaches the source owner.
- Lost replies and duplicate requests reconcile to one exact source result.
- The UI cannot approve a revision whose semantic fields changed after preview.
- An external model outage does not disable review or local enforcement.
  A source/actuator outage is unavailable, not an empty healthy result.
- Pass `DE-AGENT`, `DE-ASSESS`, and `DE-DISCLOSE` through gRPC and the client
  path used by the defender. Run MCP adapter checks only if that optional
  adapter is delivered. Tool annotations cannot bypass grants. An investigator cannot
  publish or act; a defender requires exact separate authority. Neither can
  retrieve forbidden fields or use foreign evidence/approval handles.
- Pass `DE-QUERY`, `DE-FOLLOW`, `DE-DEFENDER`, `DE-ESCALATION`, `DE-LOOP`,
  and available-owner `DE-PROTECTION` cases.
  Self-approval, stale approval, wider response, reused PID, and false readback
  must fail through the same API used by clients. Unsupported owners stay explicit.
- Run UI type checks, unit tests, build, and browser tests with accessibility
  checks. Run focused Control/e2e tests and final Rust verification.
- Record screenshots and exact revision/case IDs for partial and failure states.

Add `discovery_grpc_` and `discovery_publish_` owner tests, plus the lightweight
`review-publish` case. Test bad OIDC audience, CSRF, grant removal, foreign
evidence IDs, UID replacement, lost replies, and retained old generations.
Require existing administrative-exec tests to pass after auth extraction.
Add protocol tests for each delivered adapter and a recorded external-client
task against the production gRPC owner. Browser tests must use generated
gRPC-Web clients for reads, streaming, and mutations. These tests require no model runtime.

```sh
cargo test -p mithril-control discovery_ -- --nocapture
bash packaging/mithril/helm/tests/verify.sh
```

Implement `review-publish` in `crates/mithril-e2e/src/discovery/` and register
it in `src/bin/mithril_discovery_test.rs`. Use production gRPC, proposal,
approval, publication and rollout owner APIs. The Kubernetes API double can
lose a reply or change resourceVersion; it cannot make the approval decision.
Require one conditional source change, the exact reviewed digest, and distinct
source-accepted versus per-target-active states. Test denied self-approval,
source UID replacement, stale preview, lost reply and partial activation.
Run this lightweight case before the paired physical publication test.

```sh
cargo run -p mithril-e2e --bin mithril_discovery_test -- --case review-publish --output-directory /tmp/araphor-publication
```

From `ui/mithril-console`, run `npm run check`, `npm test`, `npm run build`,
and `npm run test:e2e`. Browser tests must cover keyboard-only review, a scope
change during streaming, stale approval, and partial activation. Test the built
assets through Control, not only through the Vite development server.

## Exclusions and stop point

No new top-level workspace, arbitrary test execution, general data-source connector,
model-authorized response, or blanket approve-all operation. Stop before a
production release until matched physical and operator qualification passes.
