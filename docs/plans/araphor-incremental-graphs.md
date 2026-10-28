# Incremental builtin Graph packages

This plan implements the [recorded Graph requirement](araphor-production-dataflow-simplification.md#incremental-builtin-graph-updates).
A subscription selects data and an optional window. The builtin Graph package
owns Graph derivation and the decision to update or rebuild its result.

**Direction: Approved by the user. Concrete plan: Approved by the independent Sol 6.1 reviewer. Implementation: Not done.**

## Intended end state

An ordinary append of 10 events to 940 retained events computes the 10 new
contributions and any affected older correlations. It does not derive all 950
Graph contributions again. Different input batches produce the same typed
Graph as a complete evaluation of the same authorized input cut.

Keep the three pinned builtin calls and their individual package attribution.
Each builtin produces resolved, compact Graph rows with their proof and
provenance. Analysis validates and publishes those rows. It does not run a
second semantic Graph builder after package execution.

A query can define a time window or have no time window. A detector's explicit
correlation rule is separate from the subscription window. Do not insert an
implicit 300-second input cutoff for a query without a window.

The existing native execution path remains:

Native SQL parser
  -> native logical planner
  -> native optimizer
  -> physical planner
  -> package execution

## Current code and gaps

| Owner | Current behavior | Required change |
|---|---|---|
| `araphor-analysis/src/graph/feed.rs` | Drives Graph programs from query subscription streams. | Keep the reactive owner. Carry the selected optional window. |
| `araphor-analysis-builtins/src/graph/contract.rs` | Reads a label-only checkpoint, then discards it and evaluates the selected records. | Restore declared state and update affected contributions. |
| `araphor-analysis/src/graph` | `from_input`, `apply_output`, and `finish` derive resolved subjects, edges, proof, provenance, findings, and branches from candidate selections. | Move pure semantic derivation into the shared builtin Graph module. Keep authorization and publication in Analysis. |
| `araphor-data/src/analysis/managed/model.rs` | `ManagedPrior::state` applies the declared continuation policy. Ordinary packages still require matching input revisions and coverage. | Enable continuation in each builtin only when its update algorithm is complete. |
| `araphor-data/src/analysis/managed/model.rs` | `ManagedPrior.retained` supplies the exact saved output through `Evaluation.previous_outputs`. | Use those rows in the builtin update algorithm. Keep current-input admission unchanged. |
| `araphor-data/src/analysis/progress/graph.rs` | Uses the existing managed transaction for result, state, references, and progress. | Keep this single atomic commit owner. |

The compact storage changes are implemented. They remove repeated manifests,
expanded Graph JSON commit buffers, copied edge endpoints, and repeated
manifest columns. They do not prove incremental Graph execution.

## Execution flow

A subscription receives a relevant data or window change
  -> Query fixes the authorized input cut through its existing subscription
  -> physical execution binds selected data and the call's exact captured prior output
  -> the builtin validates its checkpoint and stable event identities
  -> the builtin identifies additions, removals, and affected prior correlations
  -> the builtin updates its resolved Graph contribution
  -> Analysis validates image identity, output contracts, lineage, and captured inputs
  -> Data commits output, checkpoint, Graph rows, references, and progress together
  -> existing subscription streams receive the committed change

A relevant policy or coverage value changes
  -> the builtin updates the affected contributions or selects a complete rebuild
  -> the result preserves the proof for the captured input cut
  -> Data commits the result through the same transaction

An event leaves a selected window
  -> the builtin removes its current contribution
  -> the builtin updates correlations and findings that used that contribution
  -> Data retains the earlier immutable result under the existing retention rules

Execution fails before commit
  -> Data publishes neither new state nor new Graph progress
  -> a retry uses the same captured input and retained-result references

The process restarts
  -> the existing managed owner restores the last committed call and checkpoint
  -> physical execution binds that call's exact captured prior output
  -> the builtin continues from the committed state

## Ownership and state

Use the existing shared builtin Graph model for pure domain types and
algorithms. Data can re-export shared types. Builtins must not depend on Data.
Do not create another graph engine, coordinator package, scheduler, or store.

Retain resolved prior output through the existing managed output datasets.
Do not copy the complete prior Graph into a second checkpoint dataset.
The checkpoint stores only required progress and correlation indexes.
Read only the exact prior contribution. Do not rebuild a chain of older Graphs.
Use current captured records for evidence and direct source witnesses. Preserve
historical replay references without treating saved output as fresh authority.

Checkpoint identity uses stable source, CPU, and durable cursor values.
Saved row ordinals are not event identities. Rebind evidence references to the
current authorized inputs before output validation. A checkpoint alone cannot
authorize old evidence or renew expired witnesses.

The first implementation can retain complete selected input and output
contracts. This can still scan and serialize unchanged rows. Record that cost
separately from Graph derivation. Do not claim that detector-only caching or
compact serialization completes this plan. A later change to delta-only input
must retain explicit authorized inputs for every referenced older event.

Do not create a self-dependency through an `OutputRef`. Bind prior output from
the captured `ManagedPrior.retained` value. Do not reopen `managed_input` or
add a source provider for saved output. Preserve
exact retained-result reuse and `CallResult` matching for retries.

## Deliverables

1. **Compact representation.** Finish the approved typed Graph storage and
   native query changes. Preserve observations, history, scope, proof, native
   traversal, projected reads, and configured bounds. Run the affected tests
   and measure the unchanged backlog case before committing this deliverable.
2. **State and retained inputs.** Define the narrow checkpoint continuation
   policy and bind exact prior output through `ManagedPrior.retained`. Use the same
   policy in Query execution, Data commit validation, and replay. Prove that
   ordinary packages retain exact-input behavior. For the captured prior result,
   permit its older immutable output as retained state. Declare continuation in
   `CheckpointSpec`; ordinary packages keep exact-input behavior. Supply prior
   output datasets through the evaluation state, using the existing output
   names and schemas. Only current inputs can supply evidence links. Preserve the current
   grant, call, generation, lineage, and expiry checks. Preserve `Unknown`
   coverage for expired evidence; saved state cannot renew proof. Reject foreign
   prior results. Do not weaken current-input freshness checks. Commit the
   passing change.
3. **Builtin Graph ownership.** Move resolved Graph derivation into the existing
   builtin Graph module. Replace candidate instructions with typed resolved
   contributions. Remove the corresponding Analysis semantic reconstruction.
   Keep host validation of subjects, effects, evidence, provenance, and proof
   limits against qualified captured input and the pinned package. Valid output
   schema alone does not establish authority. Keep atomic publication. Prove complete-result parity
   before committing the change.
4. **Incremental builtin updates.** Reuse retained contributions and compute
   additions plus affected correlations. Handle window removal, late arrivals,
   context and coverage changes, and incompatible state. Prove equivalence to
   complete evaluation for each builtin. Commit the passing change.
5. **Integrated proof and measurement.** Prove retry, restart, rollback, window
   and no-window behavior through production owners. Run the same backlog
   workload and report timing, logical Graph bytes, actual store size, and peak
   process memory. Update the result record and source review guide. Commit the
   deliverable only after independent review.

## Required checks

- The same events, supplied in different batches, produce equal typed results.
- A new network or authority fact can complete an earlier credential read.
- Duplicate input and exact retry create no duplicate Graph contribution.
- Window removal changes only the required current contributions and findings.
- No-window input has no implicit selection cutoff.
- Policy and coverage changes do not reuse stale proof.
- Retained inputs preserve their original authority, source cut, and expiry.
- A failure between result and checkpoint preparation publishes neither one.
- Restart resumes the last committed state and preserves historical results.
- Existing native traversal, finding, notification, replay, and recovery tests
  retain their checks. Consolidate tests only when the same behavior is proven.

Use only relevant tests while iterating. Keep the existing backlog workload,
assertions, and deadlines unchanged. Do not add a new benchmark workload.
Compare runs with the same event volume and report changes in the number of
committed Graph versions. Separate logical payload size from DuckDB file
allocation and reusable blocks. A smaller payload does not prove a faster run.

## Review and completion

The implementer proposes types, owners, data flow, deletions, and checks.
The independent Sol 6.1 change reviewer must agree before each deliverable's
implementation and review its concrete diff before commit. Use existing
DataFusion and dependency facilities where they apply. Escalate a new product
or scope decision to the user; do not infer approval.

**Result: Not done.** The requirement is recorded and the source audit is
complete. The compact representation passes its relevant checks. The same
backlog case retains the same four Graphs, 6,619 edges, and 277 findings. Graph
column and header payload decreases from 10.99 MB to 3.69 MB. Both baseline
and compact runs fail the existing deadline. The first memory comparison is
invalid because executable hashing contaminated the runner's high-water mark;
the corrected interpretation is in the [review guide](../guides/araphor-graph-commit-review.md#first-matched-backlog-measurement).

Resolved builtin ownership, incremental algorithms, and final measurements
remain open. The independent Sol 6.1 reviewer approved this
concrete plan on 2026-10-28. Each deliverable still needs a review of its code
and test results. The compact storage result does not complete this plan.

### State handoff implementation

`CheckpointSpec.resume_input_changes` is false by default. A package that sets
it receives its exact saved output beside its checkpoint. Query execution,
Data commit validation, and replay use the same `ManagedPrior::state` method.
Replay reads one prior result. It does not read a chain of older evaluations.
The existing attempt stores the prior reference; no second state table or
copy of the saved Arrow output is added.

SQL uses the existing relation slots for `previous_<output>`. Wasm and native
execution use the existing evaluation transport. Package fixtures store prior
datasets in OCI layers. Only current input datasets can supply evidence links.
The current grant, image, call, parameters, rebuild, and schema checks remain.
The separate `reusable` flag preserves the stricter Graph result-reuse checks.
Failed work can resume the last successful state but cannot reuse its result
as a successful new evaluation.

SDK validation and transport checks pass in 76 cases. Focused Data checks pass
for continuation, exact prior values, failure, rollback, replay, reopen, and
ordinary checkpoint behavior. Query checks pass for SQL and Wasm continuation,
state admission, evidence separation, replay, cancellation, and memory limits.
OCI fixture, qualification, and Graph reuse checks pass. Source-built native
continuation, failure cleanup, and fixture qualification checks pass. Scoped
formatting, patch whitespace, and affected-crate Clippy with warnings denied
pass. These are relevant checks, not full workspace or physical qualification.
Verification records are in
`/tmp/araphor-package-qualification-active/compact-graph/continuation`.

**State handoff result: Done.** Builtin Graph declarations still keep
continuation disabled.
This state transport does not implement incremental Graph derivation.
