# Phase 7.6: Detection Recipes, Suggestions, And Exact Preview

Implement detection recipes and typed suggestions, including review-only
native policy changes. Reuse existing compiler and simulation owners.

## Intended end state

An operator can distinguish observed behavior, declared requirements, proposed
grants, permission expansion, and unknown impact. Every proposed rule has a
source or an explicit owner declaration. An agent can test hypotheses with
reproducible method results and explicit Unknown states. No suggestion changes
active policy or creates an authoritative incident finding.

## Implementation flow

```text
Configured discovery method evaluates a pinned context
  -> DiscoveryOwner validates the reviewed method, parameters and input revision
  -> QueryOwner evaluates its admitted SQL and returns a receipt without mutation
  -> DiscoveryOwner checks coverage and records support, counterevidence or Unknown
  -> AnalysisStore commits the method result and its exact input references

Caller submits a typed suggestion
  -> DiscoveryOwner checks current draft permission, cited receipts and preconditions
  -> validator returns Draft, Rejected or Validated with explicit reasons
  -> AnalysisStore commits the suggestion without an execution effect

Owner submits a scoped requirement set
  -> DiscoveryOwner validates source, cohort, and requirement revision
  -> exact-rule generator produces typed edits for supported operations
  -> guardrail checker records forbidden or conflicting requirements
  -> permission comparison produces an expansion receipt
  -> native compiler validates and expands the proposed source
  -> PolicySimulator evaluates exact reconstructable keys
  -> test planner identifies missing approved cases
  -> AnalysisStore commits proposal and preview artifacts

Edit broadens a resource or cannot be simulated
  -> preview shows added authority or Unknown with its reason
  -> exact alternative and unsupported cases remain visible
  -> unsupported output cannot enter a ready-to-publish state

Owner edits the proposal or source changes
  -> engine creates a new immutable revision
  -> previous preview cannot approve the new revision
  -> recomputation uses new pinned inputs
```

## Scope and owners

Discovery owns deterministic proposal construction and test requests. Existing
policy validation, compiler, and `PolicySimulator` own policy meaning. The
scope starts with qualified exact file/execute rules under declared roles.
The test planner only references reviewed fixtures; it cannot execute them.
`GraphAndFindingOwner` retains incident graph ownership. Existing
policy finding/disposition source types do not implement this query catalog.

## Required changes

### Prerequisites and delivery boundary

Require Phase 7.3 query and Phase 7.5 findings. Status: **Not done**.
Use QueryOwner and AnalysisStore; do not implement another SQL path.
Observability 3 can already expose query/trace without these algorithms.

1. In `crates/araphor-data/src/discovery/`, add
   `DiscoveryOwner::{evaluate_method,create_requirement_set,build_proposal,request_test}`.
   In AnalysisStore, add revision-checked immutable proposal records.
   A proposal binds snapshot, requirements, base UID/generation/spec digest,
   target facts, compiler version, and every context digest.
2. Build typed edits to an existing `WorkloadProtectionPolicy.spec`. Control
   owns exact native preview and calls the data owner for frozen proposal
   inputs; the data crate does not import the policy compiler. Reuse
   `lower_kubernetes_policy`, `PolicyCompiler::compile`, and
   `canonical_kubernetes_policy_spec_digest` from the existing policy modules.
   Retain the base object identities needed for lowering. Do not serialize an
   internal `PolicyDocumentV1` as if it were the public Kubernetes resource.
3. Start with exact file/execute selectors and existing declared roles. Keep
   successful observations unreviewed until an owner adds a requirement.
   Preserve denied, failed, unknown, and would-deny groups. Reject overlapping
   base sources, guardrail conflicts, and unsupported edits. No inferred roles.
4. Add `PermissionDeltaV1`: added/removed grants, role/operation changes,
   selector scope, and future-match behavior. Keep exact edits by default.
   Directory/selector broadening is a separate manual edit with an expansion
   receipt; unknown mount semantics cannot become an equivalence claim.
5. Add a context-to-`StaticDecisionKeyV1` adapter at Control's preview boundary. Require
   every selector, scope, role, state, entry, object, and binding-lifecycle
   input. `PolicySimulator` searches static cells; it does not check live
   exception consumption or all runtime hard-safety state. Dynamic exceptions,
   absent runtime conditions, and unresolved keys return Unknown, not Allow.
   Do not change the simulator to conceal this limit.
6. Preview base and proposed sources against the same frozen case set. Report
   evaluated, unknown, excluded, required-failure, and guardrail-failure counts.
   Record physical result as Not attempted or Unknown. A new edit creates a
   new revision and invalidates the old preview. Replay has no cluster client.
7. Store the reviewed test catalog in
   `crates/mithril-e2e/fixtures/discovery/manifest.json`. Rank applicable cases
   by missing facts, authority impact, and cost. A `TestRequest` contains a
   catalog ID or an unsupported reason, never executable shell text. Compare
   snapshot revisions without changing the reviewed baseline. Use the fixed
   greedy test order and stable ID tie-break in local-intelligence.md. Repeated
   observations update one exact review group; new outcomes, resources, entry
   classes, or coverage failures remain visible. Load authoritative artifacts
   for previews, not unchecked SQL query rows or model labels.
8. Register method views and the four reviewed recipes with QueryOwner.
   Use its isolation, receipts, dependency revisions and append/replace follow.
   Store method definitions under `src/discovery/investigation.rs`; extend
   `context.rs` and add a focused proposal module when needed. Load complete
   pinned inputs through owner reads, not unverified client query rows.
9. Add qualified recipe evaluation and `DiscoveryOwner::validate_suggestion`.
   A DetectionAssessment binds query/input revisions, coverage preconditions,
   field availability, and expected interpretation. Positive matches can
   survive partial input; incomplete negatives remain Unknown. Arbitrary SQL
   results cannot create findings, causal edges, or a detector installation.
10. Validate the six Suggestion kinds through one shared owner path. Evidence
   requests use bounded SQL or catalog recipe IDs; tests use reviewed fixture IDs; policy edits use
   the existing proposal path. A DetectionDraft is an admitted SELECT recipe with explicit preconditions with positive/negative replay before shadow evaluation, not executable
   code or a detector install. A ResponsePlan records the responsible owner
   and required approval; execution stays unavailable. Retain validation errors
   and missing preconditions rather than dropping an unsupported suggestion.

## Acceptance and verification

- Pass `DE-OUTCOME`, `DE-WIDEN`, `DE-PREVIEW`, `DE-POISON`, `DE-REPLAY`, `DE-NOISE`, and
  `DE-TEST-REQUEST`.
- Pass `DE-QUERY`, `DE-FOLLOW`, `DE-DETECT`, and `DE-ASSESS` with fixed expected matches, counterexamples,
  and suggestion validation states. Replay must not depend on database row order.
- Four observed siblings never become a recursive grant without a separate
  transform and review requirement.
- Missing operation, result, resource, or actor identity cannot be filled by
  a classifier or command-name heuristic.
- Unsupported provider semantics and lossy external export return explicit
  unsupported results. They cannot be silently omitted.
- A byte-identical replay returns the same deterministic proposal/preview;
  model annotations are not part of policy evaluation.
- Run focused Control/e2e tests and final full Rust verification.

Add `discovery_proposal_` tests for each transform and the dynamic-exception
counterexample and `discovery_detection_` tests for the method catalog. Add
lightweight cases `query-follow`, `detection-context`, `proposal-preview`, and
`poisoned-window`. Query tests cover a hidden-column predicate, a foreign-row
aggregate, external table functions, expensive joins, output limits, late
coverage, empty filtered batches, cursor replay, expiry, and grant revocation.
The case output must include source/spec digests, old/new dispositions,
unknown reasons, permission delta, and test-request IDs. Proposed commands:

```sh
cargo test -p mithril-control query_ -- --nocapture
cargo test -p mithril-control discovery_detection_ -- --nocapture
cargo test -p mithril-control discovery_proposal_ -- --nocapture
cargo run -p mithril-e2e --bin mithril_discovery_test -- \
  --case proposal-preview --output-directory /tmp/araphor-discovery-preview
```

## Exclusions and stop point

Status becomes Done only after unit tests and the lightweight cases pass with
nonzero counts and retained result digests. Run the query-follow case again
when method views change query dependencies.

No model runtime, detector installation, live source mutation, automatic rollback, or external
network-policy enforcement. Stop with reproducible review artifacts before
the optional assistance and live review work.
