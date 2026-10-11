# Phase 7.5.3: Package Lifecycle

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
  -> Control validates the current grant and publisher trust requirements
  -> AnalysisPackageOwner checks the descriptor, artifacts, and dependency closure
  -> AnalysisStore records one admitted immutable revision
  -> the package owner activates eligible exports within the granted scope

An input revision changes
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
  -> the package owner checks dependencies, grants, and checkpoint compatibility
  -> the evaluator prepares a bounded state conversion or retained-input rebuild
  -> AnalysisStore switches the active revision only with a valid prepared state
  -> failed preparation preserves the previous active revision and its checkpoint

Grant is revoked or an operator removes the package
  -> the package owner stops new runs and cancels work under that grant
  -> AnalysisStore rejects commits under the invalid activation lifetime
  -> retention keeps historical results and required evidence references
  -> the package owner releases artifacts after their last active reference
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

**Not done.** Package admission, activation, and the new e2e case are planned.

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
