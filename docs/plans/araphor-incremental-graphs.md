# Incremental builtin Graph packages

This plan implements the [recorded Graph requirement](araphor-production-dataflow-simplification.md#incremental-builtin-graph-updates).
A subscription selects data and an optional window. The builtin Graph package
owns Graph derivation and the decision to update or rebuild its result.

**Direction: Approved by the user. Concrete plan: Approved by the independent Sol 6.1 reviewer. Incremental additions: Done. Backlog deadline qualification: Not done.**

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
| `araphor-analysis-builtins/src/graph/contract.rs` | Uses the same Computation to derive new and affected contributions through State dataset 0 and native Progress dataset 1. | Relevant owner checks pass. The measured backlog deadline remains unmet. |
| `araphor-analysis/src/graph` | Qualifies captured inputs, validates resolved contributions, and structurally merges their values. | Keep independent authorization, proof validation, expiry, and atomic publication. No second semantic builder remains. |
| `araphor-data/src/analysis/managed/model.rs` | `ManagedPrior::state` applies the declared continuation policy. Ordinary packages still require matching input revisions and coverage. | Continuation is enabled for the three Graph builtins after complete-result parity checks. |
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

A relevant old policy or coverage value changes
  -> the initial incremental path selects a complete rebuild
  -> the result preserves the proof for the captured input cut
  -> Data commits the result through the same transaction

An event leaves a selected window
  -> the initial incremental path selects a complete rebuild
  -> the complete result excludes removed contributions and updates affected findings
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
4. **Incremental builtin updates.** Reuse retained contributions for additions
   and affected correlations through State dataset 0 and native Progress dataset 1.
   Use stable-ID maps and exact per-record fact zippers. Use complete rebuilds
   for removal/window exit, changed old proof/facts/order/window, and valid but
   unusable state. This slice makes no incremental-removal claim. Prove complete
   evaluation equality for each builtin before enabling continuation and commit.
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

**Result: Not done.** The requested incremental implementation and measurement
are complete. Backlog deadline qualification remains open. The compact
representation passes its relevant checks. Its first matched run retained
four Graphs, 6,619 edges, and 277 findings. Graph
column and header payload decreases from 10.99 MB to 3.69 MB. Both baseline
and compact runs fail the existing deadline. The first memory comparison is
invalid because executable hashing contaminated the runner's high-water mark;
the corrected interpretation is in the [review guide](../guides/araphor-graph-commit-review.md#first-matched-backlog-measurement).

Resolved builtin ownership and incremental algorithms pass their relevant
runtime and static checks. The final measurement below records the remaining
deadline failure and storage costs. The independent Sol 6.1 reviewer approved this
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
continuation disabled at this deliverable.
This state transport does not implement incremental Graph derivation.


### Builtin ownership result

The existing builtin Computation produces resolved native subjects, relationships, findings, branches, and package metadata. The three pinned calls remain separate.
Analysis validates exact captured inputs, source and fact anchors, package metadata, complete-input watermarks, effects, provenance limits, evidence, reasons, and branch projection. Its remaining Graph owner merges, remaps, and sorts the checked values. The existing Data transaction remains the atomic publication owner. Retained expiry still reduces proof.
The ten detached Analysis semantic files are removed after parity checks: 1,348 lines. Exact originals remain in compact-graph/d3-host/deletion-review.
Relevant builtin, example, Data, typed baseline/domain, host-validation, opaque-reason, native/SQL/Wasm adapter/pressure, and captured-source checks pass. Exact-port, credential-join, extra-export, configured allocation, and atomic conversion-failure/retry checks also pass. Records in compact-graph/builtin-ownership keep each tested source and artifact identity, including earlier corrected fixture failures.
The [current source review route](../guides/araphor-graph-commit-review.md#builtin-ownership-of-resolved-graph-rows) links the production owners and tests.
**Builtin ownership result: Done.** Scoped formatting, patch whitespace, and seven-crate Clippy pass with warnings denied. Runtime evidence precedes the reviewed borrow/import-only cleanup; final Clippy covers that cleanup. Source and verification records are in `/tmp/araphor-package-qualification-active/compact-graph/builtin-ownership`.
At this deliverable, builtin continuation remains false. The later sections record the incremental implementation and measurement. No execution-time gain or timeout fix is claimed.

### Approved initial incremental scope

Keep the aggregate State label in checkpoint dataset 0. Add one private native Progress dataset 1 with each prior record's qualified-observation digest and optional last state assignment. Keep the current version values.
Match prior and current stable record IDs once. Preserve old relative record order; allow new CPU-0 records before retained CPU-1 records. For each matched record, compare its ordered facts by exact key, sensitivity, value, and multiplicity, then zip their global indices. Do not require a prefix append or add a fact matcher.
Reuse only when the qualified Observation digest and explicit correlation window match. Rebind subject, relationship, fact, and evidence indices through these maps. Current inputs remain the sole evidence authority.
Process derives new records and new Context facts in the existing phase order. Kubernetes derives new Kubernetes facts. Credentials derives new records and old seeds affected by the broad correlation time window of new network, Channel, or AuthorityUse inputs. Do not narrow that seed prefilter by principal, object, task, or binding.
Reduce saved and new record-state assignments in current order, including repeated equal assignments and suppressed candidates. Use the shared finalizer for current package watermarks, reasons, evidence links, branches, and sensitivity. Preserve the complete-result semantics.
Use a complete rebuild for record removal or window exit; changed old qualified observations, proof, context, or ordered facts; changed correlation window or old record order; and valid but unusable algorithm state. Invalid envelopes and schemas still fail admission. This initial slice does not claim incremental removal.
Prove complete/continued equality and actual derivation counts with ordinary existing-owner tests before enabling builtin continuation. Full input decode, digesting, matching, and output serialization can still scan the cut. These counts establish no timing or memory result.


### Incremental builtin implementation result

The three builtins now declare resume_input_changes=true and use State dataset 0 plus private native Progress dataset 1. The existing Computation owns complete and incremental work; the native reactive DataFusion path remains.
Stable record-ID maps and exact per-record fact zippers admit normal additions without a prefix assumption. Broad time-window updates re-evaluate affected credential seeds. State reduction, current sensitivity, and minimum compatible valid paired anchors preserve complete-result parity. Removal, changed old proof/facts/order/window, or unusable valid progress uses a full rebuild. No incremental-removal claim is made.
Analysis keeps generic State/version support, SDK authority for extra checkpoint ports, current-input evidence checks, and atomic publication. The [source route](../guides/araphor-graph-commit-review.md#incremental-builtin-contributions) links implementation and ordinary tests.
The focused-v2 record passes 25 builtin Graph cases plus host/example groups. Four SQL/Wasm adapter/pressure cases and two fresh source-built native cases pass. Mechanical source cleanup keeps the reviewed runtime evidence identities. Final v4 Clippy, formatting, and whitespace pass.
All six final owner cases pass in graph-owners.json: enhanced Wasm subscription, failure/reuse separation, unchanged-notice reuse, atomic conversion failure, retained replay, and committed-state Wasm restart. Final source: source-final-rust-v4.json, SHA-256 d893f2a052dd24b9ba043846e80635b2e6d272ecb03062f0308b9a5eb49eed51; Analysis ELF 750d627311c15539f28a92d5b584abcf6fdbf7c7052151631f683deb4077f9df.
**Incremental implementation result: Done.** The following section records integration and matched measurement. The overall deadline qualification remains Not done.
The records are in compact-graph/incremental-root. Full input/output scans can remain. Derivation-count proof is not an elapsed-time, storage, or process-memory result.

### Integrated measurement result

The relevant subscription, retry, atomic failure, replay, and committed-state
restart checks pass. SQL, Wasm, and native adapters pass. The final integration
build found one missing `GraphValidate` trait import in Mithril Control after
the shared Graph model move. The import restores the existing validation call;
it does not change the validation. Scoped Control Clippy passes with warnings
denied. The first failed build remains in the measurement record.

The existing backlog workload ran once with unchanged assertions and deadline.
It failed after 124.420 seconds. The earlier compact run failed after 121.776
seconds. This is failed-run wall time, not completion throughput. At timeout,
the observer had actor cursor 941 and background cursor 639. Later diagnostics
and the closed store reached 950 and 642. They do not prove pre-deadline progress.
The selected actor notification remained absent. Both runs have stale-current-
finding reference conflicts; the logs do not identify the dominant cost.

The final two Graphs retain 11 subjects, 3,323 edges, and 139 findings. Their
logical columns and headers occupy 1,855,803 bytes, versus 1,854,958 bytes in
the compact run. The actor revision now has five coverage entries instead of
three. All retained Graphs occupy 4,482,156 bytes across five versions. The
compact run retained four versions and 3,687,217 bytes. The extra cursor-941
version accounts for 794,094 bytes; history totals are not an equal-shape ratio.

Saved package and definition IPC grows from 6,302,800 to 10,657,552 bytes.
Resolved outputs, continuation state, and extra retained history contribute
to this increase. Progress occupies 508,920 bytes across all retained calls.
The database file grows from 59,518,976 to 76,034,048 bytes. These are measured
drawbacks. The [measurement record](../guides/araphor-graph-commit-review.md#incremental-integration-measurement)
separates current/history payloads, package artifacts, and database allocation.

The current process peak is 1,048,372 KiB. Historical runner peaks are invalid,
so no memory comparison is made. Dependency features and build profiles match
the baseline. Source and executable identities are fixed; the retention-only
fixture edit was restored before execution. Read-only inspection leaves store
file contents unchanged. Records are in
`/tmp/araphor-package-qualification-active/compact-graph/incremental-integration`.

**Implementation and measurement: Done. Backlog deadline qualification: Not done.**
Full input decode, validation, matching, and output encoding remain. Changes
to old proof, facts, order, or window and event removal use complete rebuilds.
No full workspace CI or physical qualification ran. This result
does not claim that the overall performance goal is complete.
