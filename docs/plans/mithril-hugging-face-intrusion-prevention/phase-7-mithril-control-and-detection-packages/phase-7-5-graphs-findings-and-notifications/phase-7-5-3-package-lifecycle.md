# Phase 7.5.3: Package Lifecycle

Current command status, 2026-10-19: The old Analysis owner and its qualification
harness have been removed. The cases `analysis-packages`
are no longer accepted by `mithril_discovery_test`. The commands and results
below remain historical proof for their recorded source. They do not qualify
the current replacement. Read the [current plan](../../../araphor-package-jobs.md)
for the supported path and remaining work.

Install, compose, inspect, update, and remove analysis packages through one
owner. Parent: [7.5](README.md). Require 7.5.2 and the authenticated client API
from [Observability 3](../../../araphor-observability/phase-3-cli-api-and-console.md).
Use SQL to prove the lifecycle before adding component and native execution.
The 7.5.2 entry gate includes current algorithm conversion, production adapters,
and equivalence through trusted Rust calls. The portable SDK result alone does
not satisfy this gate.

## Intended end state

An operator installs a local built file or directory under an authorized scope.
Araphor resolves its locked dependencies without a network service. Eligible
exports start under the grant. Missing inputs and unsupported targets remain
visible. An agent uses the same descriptor and operations as the CLI.

## Implementation flow

```text
Operator installs a package through Control
  -> Control validates the current grant and configured bundle trust pin
  -> AnalysisPackageOwner checks the descriptor, artifacts, and dependency closure
  -> AnalysisStore records one admitted immutable revision
  -> the package owner activates eligible exports within the granted scope

An input revision or recorded clock tick changes
  -> the package owner resolves an acyclic graph of named model dependencies
  -> the extractor returns complete bounded authorized inputs and closes readers
  -> the selected evaluator computes outside the store transaction
  -> the domain owner validates outputs and evidence references
  -> AnalysisStore commits each model result, checkpoint, progress, references, and quota together
  -> dependent models select those exact committed result revisions

Evidence arrives late or a source window is replaced
  -> the package owner marks affected dependent results stale
  -> stateful evaluation replays from a valid checkpoint or rebuilds from retained inputs
  -> a replacement result removes prior contributions for that window
  -> missing retained input produces incomplete coverage

Operator upgrades or rolls back a package
  -> the package owner checks dependencies, grants, parameters, and scope
  -> the evaluator prepares a bounded retained-input rebuild
  -> AnalysisStore switches the active revision only with a valid prepared state
  -> failed preparation preserves the previous active revision and its checkpoint

Grant is revoked or an operator removes the package
  -> the package owner stops new runs and cancels work under that grant
  -> AnalysisStore rejects commits under the invalid activation lifetime
  -> retention keeps historical results and required evidence references
  -> the package owner releases artifacts after their last installation, history, or dependency reference
```

## Scope and owners

Add `AnalysisPackageOwner` in focused `araphor-data` modules. Control supplies
validated authority; AnalysisStore is the only durable owner of package records,
activation revisions, result datasets, and checkpoints. Reuse QueryOwner's
admitted SQL evaluation and extraction. CLI and APIs call these owners.
Extend the existing Control `ClientGrpcOwner` and CLI for package operations;
do not wait for the later review console or add another listener. Installation
and activation require their explicit mutation grant. Investigate permission
alone does not authorize executable installation.

- Treat a named output as a typed dataset. Query views and downstream models use
  the same authorized committed result. Reject dependency cycles and incompatible
  schemas. Lock the full closure; a tag or a mutable directory is not a revision.
- Bind each evaluation to one complete set of dependency revisions. Expose stale
  outputs with their old references and freshness state until replacement commits;
  do not present them as current. Atomicity applies to each model commit, not the
  complete dependency graph. A downstream run cannot mix uncommitted revisions.
- Keep one active revision per installed export and scope. Compare activation
  and checkpoint revisions at commit to reject stale concurrent evaluations.
  An identical retry returns the original receipt; a changed retry fails.
- Record the selected artifact, dependency revisions, input revisions, evaluation
  context, and resource limits. Stage output under bounded quotas. Release all
  temporary data after success, failure, cancellation, and restart.
- Recheck authorization at extraction and commit. Validate evidence against the
  selected inputs. Route discovery and graph results through their current
  owners. Incomplete negative results remain Unknown. NotificationRouter retains
  mandatory routes. Required security processors retain protected progress and
  backpressure rules even when optional discovery is disabled.
- Do not run installation hooks or package downloads during evaluation. Run
  executable fixtures only through an admitted bounded test operation. Static
  admission and publisher signatures do not prove detector correctness.
- Generate inspect output from the admitted descriptor: schemas, parameters,
  dependencies, supported targets, readiness, coverage, tests, and structured
  errors. Add no separate agent schema or agent-only execution path.

Only SQL exports become executable in this phase. Prove checkpoint commits and
upgrade rebuilds with SQL models that consume explicit prior-state rows and
return declared next-state rows. Reject activation of unavailable targets.
Current algorithms continue through the shared built-in Rust calls from 7.5.2.
Executable component and native conversion functions arrive with their runtime
phases; this phase must not use a test-only executor to simulate them.

## Acceptance and verification

Use the [source review guide](package-lifecycle-review.md) to follow admission,
execution, authorization, state commits, and retention. The guide distinguishes
current SQL table execution from the later installed domain dispatch.

Add Rust owner tests and a lightweight `analysis-packages` case in `mithril-e2e`.
Cover offline install, SQL dependency chains, denial, cycles, missing inputs,
restart, same and changed retries, stale commits, revocation, late input, empty
replacement, failed upgrade, rollback, and referenced-artifact removal. Check
that state and outputs never disagree after a crash. Run the shared Rust gate.

## Exclusions and stop point

No new database, service, collector loader, policy activation, or AI model runtime.
OCI distribution can later use the existing registry owner under its own plan;
do not implement another registry, credential store, or download cache here.
Stop after the production lifecycle works with SQL and shared runtime dispatch.

## Result

**Done.** The local SQL package lifecycle, authenticated operations, focused
Rust checks, production command-line qualification, and final shared Rust
procedure pass. The result below states the exact source and limits.

### Implementation checklist

The approved goal requires these deliverables in the primary checkout:

- [x] Admit built local files and directories with a complete locked dependency
  closure. Check immutable content, schemas, targets, mutation authority, and
  configured bundle trust before activation.
- [x] Add the package owner and durable records under the existing Data owners.
  Keep one API and descriptor for the CLI and agents.
- [x] Evaluate SQL models with exact inputs and dependency revisions. Commit
  results, checkpoints, progress, references, and quota charges together.
- [x] Verify late input, empty replacements, stale results, restart, cancellation,
  revocation, concurrent runs, failed upgrades, rollback, and artifact retention.
- [x] Add Rust owner tests and the production `analysis-packages` case. Run the
  final shared Rust procedure. Record its exact source and results.
- [x] Review the implementation for correctness, small owner modules, and shared
  validation. Update the source review guide and commit each deliverable.

### Verification record

Source: `83a5e3093ab27f54c33f05a5d2086362bb50418f`, Linux x86-64,
2026-10-11. Read the [operator guide](package-operations.md) for package format,
trust configuration, commands, and limits.

The production `analysis-packages` command returned zero and recorded `PASS`:

```sh
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo build --workspace --all-features --bin mithril_discovery_test
target/debug/mithril_discovery_test --case analysis-packages --output-directory /tmp/araphor-package-qualification-final
```

Result: `/tmp/araphor-package-qualification-final/result.json`.
SHA-256: `1676a027502dece433a86e7d373837e968e1d9fccf5ba886175dc1dde682c2e1`.

The case uses `ClientAuth`, `ClientGrpcOwner`, `AnalysisPackageOwner`,
`QueryOwner`, and `AnalysisStore`. It proves local directory admission,
dependent SQL execution, automatic source replacement, stale-result reporting,
restart, original retry receipts, failed upgrade, rollback, revocation, and
historical reads after removal. The checkpoint run count is `2` before restart,
`2` after retry, and `1` after the correction rebuild. The repeated-denial row
is removed when its source changes from three events to two. Empty incomplete
input retains Unknown coverage.

The final shared Rust procedure returned zero after the last Rust edit:

```sh
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 bash .github/scripts/verify-rust-ci.sh
```

Log: `/tmp/araphor-package-rust-ci-proof.log`.
SHA-256: `0d452dcd765bedd74a8b357f56aaf12e3e89b84e84799b6c5af6beb0ffed0646`.
Formatting, workspace check, strict Clippy, and all workspace test targets pass.
The affected and adjacent library suites report:

| Suite | Passed | Ignored |
| --- | ---: | ---: |
| Shared analysis algorithms | 12 | 0 |
| Analysis SDK | 33 | 0 |
| Araphor CLI | 62 | 0 |
| Araphor Data | 467 | 3 |
| Runtime client | 5 | 0 |
| Mithril Control | 188 | 1 |
| Mithril E2E | 172 | 526 |
| Mithril Node | 282 | 1 |

There are no failed tests. Ignored tests supply no qualification. The E2E count
excludes separate subprocess summaries. This serial run establishes functional
correctness for the executed checks; it makes no performance claim.

### Implementation and review

- `495ce319`: local bundle admission, package ownership, bounded SQL evaluation,
  atomic storage, recovery, and retention.
- `3d7e3355`: authenticated Control operations, shared client requests, and CLI.
- `020e8356`: the production package qualification case and command entry.
- `512f030a` and `83a5e309`: CLI command-list and transport-routing checks.

The review checked shared validation, small owner modules, input limits,
authorization, retry identity, stale updates, and artifact retention. It fixed
artifact cycles that could retain unused packages, query-capacity errors that
could mark valid results stale, and stale notices from older readers that could
invalidate a newer head. Rust regressions cover all three conditions. No new
worktree or shell test harness was added.

### Qualified boundary

Only installed SQL models with table outputs execute. Current discovery and
graph algorithms continue through the shared trusted Rust calls from 7.5.2.
Installed Wasm, native, Python, domain output adapters, and OCI distribution
remain later work. No policy is activated by a package operation.

New stores use schema 19. Schema 18 stores are rejected without writes under
the parent plan's fresh-data requirement. The existing checked schema 17 graph
migration remains supported. Package inputs must fit their bounded extraction;
this result does not qualify inputs larger than memory limits.

The restart test reopens durable stores and production owners, retains the
authorization owner, and renews the request grant. It does not prove client
session recovery after an identity-provider restart. Physical prevention,
cross-node behavior, and performance are not qualified by this result.

## End scope and example

Complete when an authorized operator or agent can install, inspect, run, update,
roll back, and remove local SQL packages through the production API. Dependency
selection, result/state commits, stale-result reporting, and recovery work.
Current algorithms already use the SDK through trusted Rust calls. Installed
Wasm execution and the production dispatch change remain in 7.5.4.

Example at completion: install two SQL models. `denials.count` groups distinct
denied-open events by exact subject and resource. `denials.repeated` selects
counts of at least three. Three matching events produce one row with count `3`.
A corrected source window with two events removes that row after replacement.
Restart retains the committed state; retry returns the original receipt.


## Native redesign review on 2026-10-25

Result: **Done** for the required native replacement.
Read the [current owner map](../../../araphor-component-redesign.md#required-native-redesign-result)
and [focused proof](../../../araphor-analysis-migration.md#one-managed-graph-execution-route).
Earlier commands, versions, results, and limits apply to their recorded source.
