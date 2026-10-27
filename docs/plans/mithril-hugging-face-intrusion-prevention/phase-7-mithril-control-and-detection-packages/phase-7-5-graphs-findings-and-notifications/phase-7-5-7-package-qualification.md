# Phase 7.5.7: Package Qualification

Prove installation of new algorithms and detectors through production owners.
Keep detection, correlation, and prevention claims separate. Parent:
[7.5](README.md). Require 7.5.1–7.5.5, plus 7.5.6 if Python is advertised.
Use the [current native redesign](../../../araphor-component-redesign.md#required-native-redesign-result).
This phase qualifies the existing execution path and closes specific proof gaps.

## Intended end state

An operator can install, inspect, run, and update a new detector without an
Araphor rebuild or a new probe when its inputs exist. Reusable algorithms work
through the same package interface. Recorded results show exact inputs, selected
implementation, evidence, coverage, state, and notification outcomes.

OCI installation and definition admission start no Discovery. An explicit
Instance start opens a Query subscription. Package calls use DataFusion SQL
parsing, logical planning, optimization, physical planning, and execution.
Existing owners retain authorization, lifecycle, validation, atomic publication,
and restart recovery.

## Implementation flow

```text
The implementer maps the acceptance matrix to current tests and retained proof
  -> each row identifies its exact owner, assertions, source, and result
  -> an uncovered assertion becomes a specific qualification task
  -> the reviewer checks the proposed calls, data flow, and reused fixtures

The Rust case installs an OCI image under an explicit test grant
  -> Package validates the image and locked dependency interfaces
  -> Data retains the immutable image revision
  -> installation starts no Discovery

The case admits a SQL or PRQL Discovery definition
  -> Query plans its package calls through DataFusion
  -> admission starts no Discovery
  -> authenticated evidence intake supplies the selected cases
  -> an explicit start opens the existing Instance Host and Query subscription
  -> Query captures initial input, relevant changes, and declared window deadlines
  -> the physical package operator calls the declared evaluator
  -> existing domain validators check evidence, coverage, and current authority
  -> Data atomically commits results, state, references, and progress
  -> existing Notification processing preserves routing and acknowledgement duties

The case injects late data, loss, restart, or an execution failure
  -> existing owners preserve the retry and coverage contracts
  -> cancellation joins execution before resources are released
  -> the case checks complete results, replacements, state, and cleanup
  -> the case rejects unsupported causal conclusions
  -> incomplete input cannot establish a clean negative result

The lightweight incident case passes
  -> the common physical harness runs the paired case through production owners
  -> the case checks the protected-open denial, benign read, and retained evidence
  -> a mismatch becomes a lightweight regression before implementation changes
```

## Scope and owners

Keep acceptance scenarios in `crates/mithril-e2e/src`. Follow the
[scenario maintainability rules](../../../../../crates/mithril-e2e/SCENARIO_MAINTAINABILITY_TODO.md#binding-acceptance-rules).
Use standard Rust tests and the existing `platform_test` and platform fixtures
for supported physical cases. Keep public production calls and assertions
visible. Test doubles supply only external inputs. Keep physical harnesses and
fixtures in their existing directories. Reuse the existing VM harness when a
case needs a VM. Add no custom test runner, long shell test program, external
source-tree edit, linked worktree, or additional host matrix.

Package owns OCI admission and immutable interfaces. Query owns source capture
and native DataFusion planning and execution. Package Runtime owns Wasm and
native evaluation. Analysis Instance and Host own lifecycle and continuation.
Existing domain validators retain graph and Discovery proof checks. Data owns
atomic storage, state, receipts, and progress. Existing Notification owners
retain delivery, retries, and human acknowledgement deadlines. Tests must call
the supported production APIs instead of reproducing these owners' internal
operation sequence.

All package and Discovery execution is reactive. Query subscriptions supply
input changes and declared query deadlines. Reuse existing authority, capacity,
cancellation, and completion events. Add no polling loop or second execution
owner. Reuse DataFusion operators and existing dependencies before adding code.
Quotas remain configurable and disabled by default. Test explicit quotas and
disabled defaults without restoring mandatory SDK or package caps.

Verify every current `AR-*` algorithm converted to the SDK in 7.5.2 and switched
to installed execution in 7.5.4. Use the shared source, production packages,
and contract fixtures delivered by 7.5.2 through 7.5.5. This phase adds only
missing integrated proof and regression cases. It does not first implement an
algorithm required by its entry gate. Full Discovery Engine development
belongs to [7.5.8](phase-7-5-8-discovery-engine-algorithms.md); full Security
Analytics development belongs to [7.5.9](phase-7-5-9-security-analytics-algorithms.md).
Neither upstream phase is a prerequisite for this runtime qualification.

| Case | Required proof |
| --- | --- |
| Install a detector | A built OCI layout or archive adds a detector over existing evidence. CLI and agent inspection show the same descriptor. Installation and definition admission start nothing. Invalid grants and missing inputs remain visible. |
| Start and stop an Instance | Explicit start, inspect, progress, stop, and reopen use the existing Host. Captured inputs and declared windows drive execution. Stop joins execution and releases resources. Restart restores running intent; explicitly stopped instances stay stopped. |
| Reuse an algorithm | The migrated behavior-atom result feeds display grouping and baseline comparison. Verify typed, named dependency interfaces, configured output limits, and reuse of one committed dataset. Full path-tree development is in 7.5.8. |
| Correlate evidence | Use the migrated HF-DW-001 credential and local-channel cases. Include unrelated identities, wrong node lifetimes, late input, and missing proof. Full Security Analytics joins are developed in 7.5.9. |
| General computation | Exercise graph traversal, multiple inputs, variable output counts, and a native dependency. Check SQL and PRQL definitions and exact captured source text. Record which algorithms are covered; do not claim whole-product parity. |
| Dispatch declared targets | The same Rust source passes installed Wasm/native output, evidence, checkpoint, cancellation, and replay fixtures. SQL uses the native DataFusion path. Python parity applies only if advertised. There is no silent target fallback. Core checks run with Python absent. |
| Recover and update | Interrupt before and after commit. Check identical receipts, changed-retry rejection, state/output agreement, empty replacements, failed upgrade, rollback, and expired rebuild input. Exclusive reopen settles interrupted native attempts through the existing Data recovery path. |
| Enforce the selected execution boundary | Wasm rejects undeclared reads and external effects through its allowed import boundary. Native runs in Araphor's process without isolation and uses cooperative cancellation. Check malformed outputs, configured resource failures, grant revocation, returned errors, worker join, and cleanup through real adapters. Fatal native faults require host restart and preservation of the last complete durable commit. Python uses only its separately approved and qualified boundary. |
| Preserve mandatory detection | Disable optional discovery, fail a required package, and restore it. Check protected progress, coverage, retention, notifications, and unchanged human deadlines. |
| Hugging Face incident | Run the existing incident fixtures through the installed detector. Map each claimed observation and pre-effect guard to its acceptance case. Assert physical prevention only where the enforcement owner blocks the action before its effect. |

### Existing proof and remaining work

The [native redesign result](../../../araphor-component-redesign.md#required-native-redesign-result)
records the required 7.5.1–7.5.5 replacement as Done. The
[managed Graph result](../../../araphor-analysis-migration.md#one-managed-graph-execution-route)
records 21 final passing cases and 17 prerequisite passing cases on their
separately pinned source states. These sets are not a claim of 38 distinct
tests or a completed integrated matrix. The
[startup recovery result](../../../araphor-analysis-migration.md#interrupted-native-execution-recovery)
retains the separate interrupted-attempt and host-restart proof.

Use these registered source routes when mapping the matrix:

| Existing route | Assertions to reuse and compare |
| --- | --- |
| [Image admission](../../../../../crates/mithril-e2e/src/discovery/packages/images.rs) | `discovery::packages::images::image_install_roundtrip`: authenticated installation and inspection, idempotence, reopen, and no managed-instance start. |
| [Definition admission](../../../../../crates/mithril-e2e/src/discovery/packages/definitions.rs) | `discovery::packages::definitions::definition_file_admission_roundtrip`: SQL, PRQL, captured files, exact image bindings, and inert admission through Control. |
| [Instance lifecycle](../../../../../crates/araphor-analysis/src/instance/host/tests/lifecycle.rs) and [version history](../../../../../crates/araphor-analysis/src/instance/tests/version.rs) | Explicit start/stop, current authority, joined guests, stopped intent, update/rollback, retained results, and declared targets. |
| [Managed Graph restart](../../../../../crates/araphor-analysis/src/graph/native/tests/managed/restart.rs) and [Control capture](../../../../../crates/mithril-control/src/store/graph/tests/retained.rs) | Exact source cuts, current authority, atomic recovery, retained history/evidence/context, and Control proofs. Use the recorded selectors for their passing source. |

Source links identify current code; they do not claim that every listed test
ran in this plan update. Map all matrix duties, including the remaining SDK,
Query, Runtime, Data, Notification, and public CLI/client checks, to exact
registered selectors and source-bound results before adding tests. Add only
missing assertions or a production API path not covered by those checks.

The current [Discovery registration](../../../../../crates/mithril-e2e/src/discovery.rs)
registers package, roundtrip, and storage tests. The
[Discovery CLI](../../../../../crates/mithril-e2e/src/bin/mithril_discovery_test.rs)
does not register `analysis-packages` or `graph-notification` cases. The
unregistered Graph qualification files are comparison material. Their filenames
do not make them runnable checks. Preserve their required assertions through
current owners; do not restore retired helpers or an old executor to run them.

The remaining work is to complete the matrix mapping, qualify uncovered public
lifecycle and cross-owner assertions, and qualify the paired physical incident
on the resulting source. Existing proof remains valid for its recorded source
and duties. It does not qualify changed code, a missing integration route, or
a new physical result. Do not repeat unchanged checks solely to create another
passing count.

The historical physical record proves a protected file-open denial and a benign
read through kernel, Node, Control, graph, and notifications on its recorded
source. It does not qualify the redesigned path or prove every Hugging Face
attack step, all in-process actions, or cross-node prevention. Retain those
limits. New algorithms cannot supply missing sensors, identity bindings,
policy, or enforcement paths.

## Acceptance and verification

Before a later implementation deliverable, propose its exact production calls,
data flow, reused tests, and missing assertions. The Sol 6.1 change-approval
reviewer must check necessity, ownership, reuse, and the simplest complete
implementation. Reach technical agreement before implementation. An unapproved
design or scope decision requires explicit user approval; stop until it is
given. This document update authorizes no implementation or qualification run.

After implementation is authorized, use exact standard Rust test selectors in
the existing scenario families. The reviewer checks each concrete deliverable.
Run only relevant tests, formatting, and affected-crate checks after its final
edit. Broaden or repeat checks only when changed source, failures, or missing
proof require them. Commit each approved deliverable within the authorized work.

Run the lightweight incident before the paired physical case through the common
platform fixture. Keep the same state transitions, result fields, and decisions.
A physical mismatch must become the exact lightweight regression before a
production fix or physical rerun. Record source, commands, nonzero assertions,
image revisions and digests, definition identity, selected targets, result paths,
coverage, effects, and cleanup. Complete the mapping and result for every matrix
row. Run required native cases with real qualified artifacts. Record artifact
identity and the host target. Skipped and unregistered tests are not passes.

Performance is **UNQUALIFIED**. Before adding benchmarks, obtain separate
approval for the workload, runtime, and pass/fail limits. Include compilation,
startup, batch copies, state commits, and memory when that work is approved.
Do not label native or Wasm faster from correctness tests. Existing physical
diagnostic latency limits remain separate; diagnostics stay disabled. This
phase does not authorize a diagnostic polling or transport redesign.

## Exclusions and stop point

No new incident fixture ID, policy publication, automatic response, provider
binding, cross-node physical claim, or second execution/test owner. Those
functions remain with their existing owners. Close the core package scope only
after every required child and this matrix pass, including the paired physical
incident. Python can remain Not done if the release does not advertise it.
This closes the package runtime and current migration scope only. Completion of
7.5 also requires the upstream algorithm phases and their coverage inventories.

## Result

**Plan update: Done. Integrated qualification: Not done.** The required native
replacement and the focused results above remain recorded proof. The complete
matrix and paired physical incident through the redesigned path remain open.
This update runs no Rust, physical, or performance qualification and claims no
new runtime result.

## End scope and example

Complete when the current migration, OCI/definition/Instance lifecycle,
SQL/Wasm/native targets, and paired incident case pass through production owners.
Include Python only if advertised. This qualifies the platform for new algorithm
packages. Full Discovery Engine and Security Analytics coverage remains in
7.5.8 and 7.5.9.

Example at completion: install and admit a migrated detector without starting
it. Explicitly start its Instance. Query captures its input and calls the
package through native physical execution. Interrupt after output computation
but before commit. Restart leaves neither a partial finding nor an advanced
checkpoint. Retry commits one complete result. Another identical retry returns
that receipt. Required notification processing resumes without resetting the
human deadline. Explicit stop joins execution and survives reopen. The paired
physical incident verifies the existing protected-open denial and benign read.


## Public client Instance qualification

**Public SQL start/stop and receipt retry: Done. Complete matrix: Not done.**
The new ordinary Rust cases use the existing Denials OCI fixture. They call
Control through the authenticated AraphorClient transport. The fixture obtains
the shared Host from public ControlConfig::into_parts. It starts and joins
that Host. Production owners and interfaces do not change.

[public_instance_reacts](../../../../../crates/mithril-e2e/src/discovery/packages/lifecycle.rs)
checks exact image and definition bindings, named dependency calls, inert
admission, explicit start, changed-input publication, atomic call results and
checkpoint revisions, joined stop, and stopped intent after exclusive reopen.
Data revision notifications wake the assertions. The test adds no interval.
A changed input revision resets prior state under the existing contract. The
test checks that reset and reads the earlier result to prove that its context,
output, checkpoint, and commit revision remain intact as retained history.

[public_receipt_reopens](../../../../../crates/mithril-e2e/src/discovery/packages/lifecycle.rs)
executes one finite attempt through the same client. An identical request
returns the original receipt before and after exclusive reopen. The metadata
revision stays unchanged. Both call results, selected output, and checkpoint
remain at the same atomic commit.

Evidence directory:
[/home/navid/mithril-test-hosts/araphor-package-qualification-verification](/home/navid/mithril-test-hosts/araphor-package-qualification-verification).
Execution records contain the command, source manifest, exit status, and
elapsed time. Test records also contain the binary hash. Their adjacent logs
retain the libtest results. Build, Clippy, and formatting logs retain the
respective tool output.

| Record | Result and source limit |
| --- | --- |
| d1-reactive-final.json | One reactive lifecycle case passed with d1-final-source.json. |
| d1-new-tests.json | The finite receipt case passed with d1-source.json. The reactive case failed on an incorrect expected checkpoint counter. Keep that failure record. The finite case and its used helpers remain unchanged. |
| d1-admission-regression.json | Both image and definition admission cases passed with d1-corrected-source.json. Later edits affect only the reactive test helper. |
| d1-final-build.json, d1-clippy-final.json, d1-fmt-final.json | The relevant library build, Clippy with warnings denied, and formatting passed with d1-final-source.json. The initial lint failure remains in d1-clippy.json. |

The final source manifest contains 1,246 file hashes. Its SHA-256 is
3356b4063d7eaaa0001c8ce9dd18eadd17368862f48e8a39320a0d5aff436370.
The final reactive test binary SHA-256 is
ee82b8a25efa22a046c29a8139d606018882813430d0e7e45f5e8f461bdf476e.
The test processes used PATH=/nonexistent. These cases exercise SQL packages;
they add no new native, Wasm, Python, BPF, performance, or physical claim.
The required detector failure and repair path, the paired physical incident,
and the remaining matrix mapping stay open. Full workspace CI was not run,
as the user requires relevant checks only.


## Kernel coverage counter boundary

**Counter boundary correction: Done. Complete matrix: Not done.** The kernel
increments next_sequence before it assigns that value to an event. Node sends
the same counter in its coverage report. The native SQL and Data interval
checks previously required a greater closing counter. An interval with correct
counters could therefore remain Unknown.

The [native SQL](../../../../../crates/araphor-analysis-builtins/src/discovery/sql/coverage_ranges.sql)
and [Data interval check](../../../../../crates/araphor-data/src/discovery/profile.rs)
now accept a closing counter equal to the last interval sequence. Existing
state, source, opening counter, loss, regression, and accounting checks remain.
Kernel, Node, wire fields, versions, and configured limits do not change.

The [counter regression](../../../../../crates/araphor-analysis/src/package/tests/sql/coverage.rs)
checks both SQL output and the Data predicate. It covers HEALTHY and CLOSED
intervals at sequence 10 and u64::MAX. Each boundary has an exact counter, a
stale counter, and invalid accounting. The test computes no MAX+1 value.
The earlier closing-counter negative case now uses 9 for a last sequence of 10.
Its rejection assertion remains. Existing overflow, loss, missing-counter,
regression, source identity, cursor hole, and SQL scope assertions remain.

Evidence is in
[/home/navid/mithril-test-hosts/araphor-package-qualification-verification](/home/navid/mithril-test-hosts/araphor-package-qualification-verification).
coverage-red.json and its log retain the initial failure: SQL returned UNKNOWN
and the Data predicate returned false for an exact healthy tail. After the
correction, coverage-fixed-tests.json records all eight cases in the affected
coverage module passing with coverage-fixed-source.json. The library build
passed in coverage-fixed-build.json. Clippy with warnings denied and scoped
formatting passed in coverage-clippy-final.json and coverage-fmt-final.json
with d2-wait-source.json. The later source changes affect only private E2E
fixtures and their pending detector case. The three counter files remain equal.

The source manifest SHA-256 for coverage-fixed-source.json is
6b8e6e9b7bb88648c90b4396af8d4a80847adb56996c45e0ef1674770d2f2820.
The passing coverage test binary SHA-256 is
25d83f10ce9925452abe4c44d245e24134802b69b65df4152b50f192c90594a8.
Each record retains its exact command and source boundary. The pending
required-detector case and its failed attempts remain separate evidence.
No full CI, benchmark, physical qualification, or complete matrix pass is
claimed by this correction.


## Required Graph failure status

**Health correction: Done. Integrated required detection: Not done.**
A failed managed Graph Instance already retains its failure in Data. Processor
health previously read a separate context and memory flag. That flag had no
live writer. Health could report Lagging after a required package failed.

[managed_graph_failed](../../../../../crates/araphor-data/src/analysis/managed/status.rs)
now reads current failed Instances from the same health snapshot. It checks
the requested tenant and exact source. Both Evaluate and Expire failures apply.
Custom Instance names and finite Instances are supported. A successful sibling
does not hide a failure. The existing successful commit clears its own failure.
Removal excludes that Instance. Existing Instance and failure validators check
the stored data. Prepared versions do not replace the current destination.

The unused graph_set_health API, its context reader, and its memory set are
removed. Historical context rows remain stored. This change adds no schema,
index, cache, clock, polling loop, or execution owner. Each health read scans
current failed candidates for the requested tenant. This result makes no
performance claim.

The [Data regressions](../../../../../crates/araphor-data/src/analysis/managed/tests/health.rs)
check custom Evaluate and Expire IDs, nonrunning failures, exclusive reopen,
sibling removal, exact source lifetimes, tenants, destinations, and prepared
versions. The [conversion regression](../../../../../crates/araphor-analysis/src/graph/native/tests/managed.rs)
keeps its real conversion error, sibling success, terminated-request conflict,
and repair of the same Instance. It now checks ProcessingFailed until that
repair succeeds, then Current with complete coverage.

Evidence is in
[/home/navid/mithril-test-hosts/araphor-package-qualification-verification](/home/navid/mithril-test-hosts/araphor-package-qualification-verification).

| Record | Result and source limit |
| --- | --- |
| health-data-red.json, health-conversion-red.json | Two new Data cases and the conversion case fail on the missing failure status. Exact logs, source, and binary hashes remain stored. |
| health-data-fixed.json | Ten relevant Data cases pass with health-fixed-source.json. The cases include both new regressions, processor health, and the existing failure, corruption, authority, and recovery checks. |
| health-conversion-fixed.json | The real conversion and same-Instance repair case passes with health-fixed-source.json. |
| health-renamed-final.json | The destination regression passes after its name changes to graph_health_current_destination. Its body is unchanged. This repeats one Data case. It does not add a distinct case. |
| required-final-build.json, required-clippy-final.json, required-fmt-final.json | The relevant library build, Clippy with warnings denied, and formatting pass with required-final-source.json. |
| required-final-tests.json | The pending integrated detector case fails with retained Graph call attestation. This failure does not qualify required detection or the complete matrix. |

health-fixed-source.json has 1,248 source hashes. Its SHA-256 is
28e2251bb027f6280bcecccd8aab4ddedb3ed5eda0b71eccf5878430215bc83a.
The later required-final-source.json has 1,250 hashes. It changes the pending
E2E test layout and one Data test name. Its SHA-256 is
3f4fb64028bfa42d4355ef9a8d50b0106930e062df8179aee45a522b7dfba7fa.
The test processes use PATH=/nonexistent. The pending E2E files remain outside
this health deliverable. The integrated case, paired physical incident, and
complete matrix remain Not done. No full CI or benchmark ran.


## Required detector recovery and retained call history

**Required detector failure and recovery: Done. Complete matrix: Not done.**
[required_detector_recovers](../../../../../crates/mithril-e2e/src/discovery/packages/required.rs)
uses the shared Host and Graph subscriptions returned by public ControlConfig.
Optional Discovery is disabled. The external Node fixture sends authenticated
WAL frames and coverage through the production connection. Data revision
notifications wake the read assertions. No package execution loop is added.

The case captures a Confirmed Process finding, its atomic three-call receipt,
Wasm target and artifact metadata, output, checkpoint, and notification state.
An exclusive reopen sets the Wasm fuel budget to one. An independent source
then fails with Limit. Its required progress stays at zero. Health reports
ProcessingFailed and incomplete input. An explicit retention step under the
one-nanosecond age budget keeps both unconsumed frames with their exact bytes.
The earlier Graph and all call outputs remain readable. The original
notification obligation keeps its first_seen and human deadline.

After both failed-stage owners join and all assertions pass, the case removes
the fuel limit and the artificial age budget. Both settings are None during
repair. A third source event then triggers the subscription. The new atomic
receipt covers all three retained events. Required progress reaches three,
lag reaches zero, and health becomes Current with complete input. Earlier
results and state remain unchanged. The notification deadline does not reset.
SinkUnavailable remains an explicit delivery outcome; this case does not
claim successful external notification delivery.

A separate read defect blocked the retained-output assertions. A valid native
SQL gate can publish an empty projection while its prior call references
remain stored. [retained_call_from](../../../../../crates/araphor-data/src/analysis/managed/read.rs)
previously rejected that missing call as an invalid attestation. It now checks
the latest receipt and selected header, then the original call header, before
it falls back to the original capture. A different reference remains invalid.
An old result does not gain current status from an empty publication.

[empty_gate_keeps_history](../../../../../crates/araphor-analysis/src/graph/native/tests/managed/history.rs)
uses native SQL COUNT with a real Wasm Graph subscription. Event four makes
the gate empty. All three prior references, contexts, output bytes, and commit
revisions remain available with current=false. A damaged latest selected
header still causes an error. The existing unchanged-input reuse case also
passes. No parser, planner, evaluator, state store, or quota default changes.

Evidence is in
[/home/navid/mithril-test-hosts/araphor-package-qualification-verification](/home/navid/mithril-test-hosts/araphor-package-qualification-verification).

| Record | Result and source limit |
| --- | --- |
| required-final-tests.json | The integrated case fails on retained Graph call attestation before the read correction. |
| attestation-red-tests.json | The focused empty-gate case reproduces that error before the correction. The later corruption-check suffix is not present in this red source. |
| attestation-analysis-fixed.json | The empty-gate case with its corruption check and the existing unchanged-input reuse case pass with attestation-fixed-source.json. |
| attestation-data-fixed.json | Nine relevant output, selected-reference, corruption, permission, and expiry cases pass with attestation-fixed-source.json. |
| attestation-required-fixed.json | The case correctly receives ResourceExhausted while the test still keeps the one-nanosecond age budget during repair. Production admission is unchanged. |
| required-repair-tests.json | The complete required-detector case passes with required-repair-source.json after the repair configuration removes that age budget. |
| required-fixture-final.json | All four shared image, definition, public lifecycle, and receipt cases pass with required-final-source.json. That result precedes the Graph-only read correction. Their bodies are unchanged. |
| required-repair-build.json, required-repair-clippy.json, required-repair-fmt.json | The relevant build, Clippy with warnings denied, and scoped formatting pass on the final source. |

Both attestation-fixed-source.json and required-repair-source.json contain
1,251 source hashes. The second manifest changes only the private repair-test
configuration. Their respective SHA-256 values are
b82317f56f12ea9fe7ea21492ef2fc635ddf2ef051bb97c7865b080810b42308 and
dd3486471b23832d724e55f6302eeefe2f63e89e9a8cf93a242b6faabe41a28e.
The passing integrated test binary SHA-256 is
51eef075aaca1da829b7a38cf10898a733cd34891c1de4e1101d06f1b8dd278a.
The test process uses PATH=/nonexistent. Each execution record retains its
exact command, binary hash, source, result, and adjacent log.

This result qualifies the recorded lightweight Wasm path and its native Query
integration. It adds no native-artifact, Python, performance, or physical
claim. The complete requirement map and the paired physical incident remain
Not done. Full workspace CI and benchmarks were not run.


## Acceptance proof reconciliation

**Mapped component proof: Done. Paired current physical incident: Not done.**
The current source closes the identified component proof gaps. The following
assignments preserve the limits of each retained result. They do not establish
a complete integrated matrix or extend a supported platform.

| Duty | Source-bound proof and limit |
| --- | --- |
| Installation and inspection | The four public image, definition, lifecycle, and receipt cases pass. Four current CLI cases check shared requests, tenant scope, archive input, and exact JSONL metadata. CLI and RPC equality is compositional. No launched CLI or exact Table-render equality is claimed. |
| Instance lifecycle | The public lifecycle and receipt cases join the retained Host, window, cancellation, and recovery proof. Installation and admission stay inert. |
| Reusable algorithms | Seven current corpus cases check recorded input, merge, comparison, distinct keys, schema, and duplicate projection. Retained native parity and executed locked SQL dependencies cover their separate boundaries. |
| Correlation | Seven current Context cases, three Graph baselines, and seven domain cases preserve approval, lifetimes, unrelated identities, conflicting credentials, partial Kubernetes stages, and retained policy ACK checks. Retained credential integration supplies its original installed-execution proof. |
| General computation | Retained traversal, limits, bindings, and history checks combine with captured SQL/PRQL and actual native physical execution. Native SQL planning and native ABI execution remain separate claims. |
| Declared targets | Retained Wasm/native cases keep their recorded artifacts, source, and host target. SQL uses native DataFusion execution. Python is not advertised or qualified. |
| Recovery and update | Retained version checks keep their original failed aggregate run and isolated passing retry. The recovery record contains 28 distinct cases across 32 executions. The current public receipt and required-detector cases add their recorded integration proof. |
| Execution boundary | Two current Wasm checks prove the allowed import contract and malformed-output rejection. The native loader check proves sealed dependency linkage and entrypoint execution, then rejects a null ABI. It does not prove a valid dependent Arrow model. Existing native cancellation, fault, join, and durable-commit proof keeps its original scope. |
| Mandatory detection | The current required-detector case checks failure, retention, repair, state, progress, and the same human deadline. SinkUnavailable is explicit. External notification delivery is not claimed. |
| Physical incident | Open. Run the protected-file denial and benign read through the current deployed Control, shared Host, installed detector, and query subscriptions. Historical physical results and unregistered retired-executor files do not close this duty. |

The new records are matrix-analysis.json (24 passed), matrix-cli.json
(4 passed), matrix-wasm-boundary.json (2 passed), and
matrix-native-dependency.json (1 passed). All 31 executions pass without a
source change. matrix-source.json has 1,251 hashes and SHA-256
dd3486471b23832d724e55f6302eeefe2f63e89e9a8cf93a242b6faabe41a28e.
Each record retains its exact selectors, binary hashes, environment, and log in
[/home/navid/mithril-test-hosts/araphor-package-qualification-verification](/home/navid/mithril-test-hosts/araphor-package-qualification-verification).

The Context, corpus, Graph, CLI, and Wasm processes use PATH=/nonexistent.
The loader check uses the inherited PATH to compile two test-owned Rust shared
libraries. Installed execution does not require that compiler. No claim is made
that Python is absent from the filesystem. Retained traversal and native parity
results are in data-lifecycle-owner-retirement-verification. Managed Graph and
startup results are in graph-direct-publication-retirement-verification. Version
and immutable-content results are in immutable-package-content-verification.
historical-source-comparison-v2.json records the published pin comparison;
changed-path pins do not cover every dependency or create a current passing run.
No full CI, benchmark, new runtime, or physical execution is part of this result.


## Reactive incident subscription proof

**Paired lightweight subscription: Done. Current physical incident: Not done.**
[follows_cpu_streams](../../../../../crates/mithril-e2e/src/discovery/packages/required/incident/lightweight.rs)
uses the configured Control policy owner, shared Host, authenticated Node
connection, and public Query Follow API. It uses no manual Graph executor or
client status timer. Optional Discovery is disabled.

The case verifies the configured signer and the exact prepared and downloaded
policy bundle. The same Node connection acknowledges activation at generation
eight and sends both WAL inputs and coverage. CPUs three and two have different
source IDs with the same task lifetime. The query captures each exact accepted
frame and waits for each source's Graph cut and healthy coverage.

The case requires one Confirmed Process finding with a Prevented EACCES effect
and Exact policy provenance. It excludes the benign record from every current
finding. The retained decision includes reason, limits, severity, required
action, effect proof, and policy states and limits. Missing ancestry remains
explicit. The notification refers to that finding and Graph result. Finding
and failure-escalation attempts both report SinkUnavailable. No human ACK or
external delivery is claimed. All three query streams complete their
checkpoints before the case uses their rows.

The new fixture first exposed three reader/setup errors: a second exclusive
Control store open, text reads of binary JSON columns, and the Exec family
value in a file-read filter. The corrected fixture uses the policy owner from
ControlConfig, the Arrow binary values, and shared ABI enum parameters.
Its service grant lasts 300 seconds, within the existing token lifetime.
The 90-second observation watchdog, production auth checks, and notification
deadlines do not change. Failure diagnostics use bounded cached metadata.
The original errors and all earlier failed runs remain stored.

The existing signed-catalog helper now accepts its owner and time. Its other
caller keeps the same fixed time, inputs, and assertions. The DataStore test
module moves to a separate file without a module or selector change. This
change adds no production API, executor, scheduler, schema, quota, or version.

Evidence is in
[/home/navid/mithril-test-hosts/araphor-package-qualification-verification](/home/navid/mithril-test-hosts/araphor-package-qualification-verification).
follow-filter-pair.json records one passing case.
follow-filter-regressions.json records six passing affected cases: signed
catalog bounds, image and definition admission, public Instance lifecycle,
receipt reopen, and required-detector recovery. The relevant build, Clippy
with warnings denied, and scoped formatting pass. The test processes use
PATH=/nonexistent. No full CI, benchmark, or physical case ran.

follow-filter-source.json has 1,257 hashes, including the two consumed test
key files. Its SHA-256 is
78f52a3fdc08a123372224704a51597e5945a005fe00da8602d1a06abab89706.
The passing E2E binary SHA-256 is
a222f8f46f718dead0b1a920484794c5695ac456dfdaa11a062d19a0b7219118.
incident-lightweight.json preserves the full passing report for the physical
comparison. Its SHA-256 is
98beec5b9de151b2f10fe53e6a106e3e3b3c06e97bc979c7c6b51d6c8fc1659e.
The paired current physical case and the complete matrix remain Not done.


## Deployment image build inputs

**Deployment image build: Done. Current physical incident: Not done.**
The existing production Docker recipe omitted the vendored DuckDB source. Its
Rust base also preceded the locked dependencies' required compiler. The build
now copies vendor, uses Rust 1.97.1, and installs wasm32-unknown-unknown for the
existing built-in component build. The runtime stages do not change.

vm-preparation.json retains the missing-vendor failure before VM creation.
vm-preparation-retry.json records the corrected Node and Control image build
through the existing VM harness. It passed in 1,908.546 seconds with
image-build-source.json. This elapsed time includes cold image preparation; it
is not a test runtime or benchmark. image-load-checks.json records successful
ldd, --help, and binary SHA-256 checks for both images. vm-artifacts.json records
the image IDs, imported guest IDs, archive hash, and original source boundary.
The records remain in the qualification evidence directory above. These build
and load checks do not establish an integrated physical incident pass.


## Captured source invalidation and empty reads

**Focused capture checks: 23 pass. Controlled arrivals: Done.
Complete matrix and current physical incident: Not done.**

The intended result is reactive execution from a valid captured source cut.
The [capture review](../../../../guides/araphor-discovery-definition-review.md#capture-scope-and-reactive-source-changes)
gives the five changed production files, reading flow, lifecycle, and tests.
Data seals relation guards from the incoming scope after Query pruning.
Resolved rows retain authorization, exact references, witnesses, and input limits.
An empty selected Graph read retains its guards against a later Graph commit.

Data distinguishes source invalidation from owner or state conflicts.
Reactive subscriptions settle the typed source error as Cancelled.
Finite execution retains Failed(Conflict). Trace revocation retains AnalysisConflict.
Cancellation preserves earlier Instance failure, output, checkpoint, and progress.
Resume excludes the cancelled attempt's frontier. The terminal completion
revision can advance without advancing Instance progress.

[capture-final-tests.json](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/capture-final-tests.json) records 23 passes and the original controlled 30-second failure.
The capture-final-source.json SHA-256 is db61ac21a562959d142efe32c1c66cf8d6c4117ad8d91be82b56c4d645fa3170.
[capture-lint-final-test.json](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/capture-lint-final-test.json) records the normal controlled pass in 66.718 seconds.
The capture-lint-final-source.json SHA-256 is 48e54ce2ce06b4c483105a03f6ddfc9b99b65a2faa40cca5725477c272c22409.
Only private feed.rs and feed/arrivals.rs differ between these manifests.
All production file bytes are identical. Records retain commands, executable hashes, and logs.

The private observe_for helper keeps existing observe callers at 30 seconds.
The new case uses 90 seconds for three Evaluate and three Expire subscriptions.
It keeps exact Graph cuts, Current health, and current Expire frontiers with future deadlines.
[late-observation-test.json](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/late-observation-test.json) retains the diagnostic and its original failed outcome.
That diagnostic reaches the same strict predicate at 49.166 seconds without new inputs.
[arrival-final-clippy.json](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/arrival-final-clippy.json) retains the earlier expect lint failure.

[capture-lint-final-clippy.json](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/capture-lint-final-clippy.json) records passing Clippy for Data, Query, and Analysis with warnings denied in 22.410 seconds.
[capture-lint-final-fmt.json](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/capture-lint-final-fmt.json) records passing scoped formatting in 0.665 seconds.
These final checks cover capture-lint-final-source.json. They establish no performance result.
Existing Data transactions, Query, native DataFusion execution, and Host owners remain in use.
No scheduler, store, polling path, quota, or version is added.


## Paired incident fixture qualification and retained physical failure

**Current lightweight fixtures and affected checks: Done.
Current physical incident and complete matrix: Not done.**

The deliverable changes 15 E2E source paths: the prior 14 paths and backlog.rs.
It adds no production runtime correction. The original multi-source case remains.
The same-source case uploads CPU 1 prefix groups 256/256/256/172, then records
941, 942–949, and 950. Each upload checks its bounds, ACK, and canonical source.
Both selected records retain the shared decision, coverage, notification, and receipt checks.
The fixture does not emulate physical 100 ms batching or continuous Node coverage scheduling.

[backlog-same-source.json](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/backlog-same-source.json) records follows_wal_backlog passing in 56.497 seconds.
[backlog-multi-source.json](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/backlog-multi-source.json) records follows_cpu_streams passing in 116.787 seconds.
Each normal case reports one pass, zero failures, and zero ignored cases.
The 1,430-file backlog-current-source.json SHA-256 is 2b8c31af3ba75c967bcfd1d8363943a9905f90fa968bd8724ea2b5d8eab6d03b.
The actual executable SHA-256 is bba1ca71062957d1642f6a2c1cf6634de6b42c66eef4a7ad2fac64cfcab5fa31.
The [same-source report](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/backlog-current-report.json) SHA-256 is 327b846efb89aa4de68df5a5bf07c332a213eba21671bfc517ce390c3b716dda.
The [multi-source report](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/incident-lightweight-backlog.json) SHA-256 is 7f1b6fd67ebbb5b16bc68f1067a8feabe2d82eb6edb05389e7ac4b478112f1db.

[backlog-clippy.json](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/backlog-clippy.json) records warnings-denied Clippy passing in 17.633 seconds.
[backlog-fmt.json](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/backlog-fmt.json) records the final three-path formatting pass in 0.038 seconds.
The other Rust paths retain [e2e-core-fmt.json](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/e2e-core-fmt.json), the prior 13-path check in 0.114 seconds, on their unchanged bytes.
The unchanged OIDC fixture retains the passing [Python syntax check](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/e2e-core-python-syntax.json).

[physical-core-incident.json](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/physical-core-incident.json) and its raw log retain exit 101 in 210.419 seconds.
Libtest reports zero passes, one failure, and zero ignored cases in 164.08 seconds.
Both guarded read assertions pass. The observer then times out before a complete result.
This run uses image-core-build-source.json, E2E source 48e54ce2ce06b4c483105a03f6ddfc9b99b65a2faa40cca5725477c272c22409,
and executable b34e1d01ee4ac67c717892ef8c6f9fa8a6e2a062055809e01b390f9104b12570.
Its two native Pod manifest identities match the freshly imported production images.
[image-core-reuse-stop.json](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/image-core-reuse-stop.json) retains the earlier empty-repoDigests verifier stop.
The [read-only identity diagnosis](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/image-core-identity-diagnosis.json) verifies manifest-to-config mapping without reimport or retagging.
The selected records share CPU 1 and one source at cursors 941 and 950.
The cached Graph belongs to CPU 0 at cursor 139. Notifications are empty.
Producer failure versus Follow observation remains unproved. The other source's missing ACK is not a root-cause finding.
[physical-core-failure-collection.json](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/physical-core-failure-collection.json) verifies normal owned-resource absence.
The owned VM remains retained. The case produces no physical PASS result JSON.

The [incident review](../../../../guides/araphor-discovery-definition-review.md#current-paired-incident-reading-route) gives the source reading route.
Prior failures and their source limits remain recorded. These results establish
no performance, full-incident, Python package execution, or external-delivery qualification.


## Shared public failure diagnostics

**Shared diagnostic collection: Done. Physical incident and complete matrix: Not done.**
The six private E2E paths replace the direct-store progress helper and two failure wrappers with one public-client collector before cleanup.
The original 90-second wait, result assertions, and returned error remain unchanged. Collection has one separate five-second bound.
[client-diagnostic-light.json](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/client-diagnostic-light.json) records follows_wal_backlog passing in 53.036 seconds: one pass, zero failures, and zero ignored cases.
[Clippy](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/client-diagnostic-clippy.json) passes with warnings denied in 16.784 seconds. [Scoped formatting](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/client-diagnostic-fmt.json) passes in 0.043 seconds.
The 1,430-file client-diagnostic-source-v3.json SHA-256 is a45557e8e0de070260e0ed92fc4f8206e125bd0c8603b26bee82e4345b6ed248.
The executable SHA-256 is 589e08f0e65907f4dad202d93054d70b3e9959555f2b9296f52c5c8274cfc33b. The [paired report](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/client-diagnostic-light-report.json) SHA-256 is eb3bbc3b60ebb9e18a2359b532a0333d60edd91436b79d08a40ae5e8b82b0731.
The 2,035-file client-diagnostic-full-source.json SHA-256 is 064bb950d494ffe3ae8fe382addf95bd18ac40c72ccca2a02e9c4fd1a474cbc1.
The [image-source comparison](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/client-diagnostic-image-source-comparison.json) finds only six private E2E source differences. The image build source remains separately pinned.
[physical-client-diagnostic.json](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/physical-client-diagnostic.json) and its log retain exit 101 in 214.643 seconds. Libtest reports zero passes, one failure, and zero ignored cases in 168.18 seconds.
Both physical read assertions pass. The complete incident result still times out. Actual Node and Control Pod manifest identities match the imported production images.
The collector finishes within its five-second bound. One marker retains nine projected diagnostic records, including independent RPC errors.
The finite graph_state query completes without a limited result at read revision 169: accepted cursor 754, consumed cursor 745, processor present, and not retired.
Its head is graph:b3d937dd-2229-489d-83c6-01908d04721f. The cached actor Graph is graph:cde2f2f8-6956-49a4-b956-b435d0f5d4e3 at cursor 745; selected CPU 1 records are 721 and 730. Notifications are empty.
Evaluate inspection returns Unavailable. Independent Evaluate history reads retain successful receipts at commit revisions 106 and 93.
Expire is running and Ready with progress 90. Its history has empty call projections at commits 90, 60, and 54. These revisions are store commits, not source cursors.
The public reads and the held Follow cache are separate snapshots. They do not place head replacement before or after the observation deadline.
The first eight cached findings concern unrelated cursors 100–107. Selected-record input membership, exact coverage matching, finding state, and policy remain unknown.
The [reading route](../../../../guides/araphor-discovery-definition-review.md#shared-public-failure-diagnostics) states the projections and their limits. No later physical rerun, production correction, watchdog increase, or automatic repair is recorded.
Prior failures remain retained. No complete matrix, physical PASS, performance, full-incident, Python package execution, or external-delivery qualification is claimed.


## Selected-record diagnostics and runtime binding gap

**Selected-record diagnostics: Done. Runtime policy match and physical incident: Not done.**
The cached failure projection selects findings by the observed records before it applies its output bound.
It records Graph input membership, exact interval coverage, selected finding policy, and linked notification attempts.
It adds no RPC, production owner, polling path, or change to the original wait and result criteria.
[Build](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/cached-selected-build.json>) passes in 33.878 seconds.
[Clippy](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/cached-selected-clippy.json>) passes with warnings denied in 18.046 seconds; scoped formatting passes in 0.030 seconds.
These checks cover cached-selected-source.json, 1,430 pins with SHA-256 237d2bff0922796997ced8a88f59144e6f4535c2dcb6267007255af41bd2aa1a.

The [runtime-input probe](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/runtime-backlog-probe.json>) reuses follows_wal_backlog and its production owners.
The signed target keeps its scheduled authority and container placeholder. Only Node input gets the derived runtime binding and concrete container ID.
The fixture checks the target digest, distinct identities, decoded uploaded catalog, and ACTIVE ACK before the unchanged observer wait.
Its build passes in 34.708 seconds. The one test fails in 111.687 seconds: zero passes, one failure, zero ignored cases.
The [selected facts](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/runtime-backlog-probe-facts.json>) show Graph cursor 950 with records 941 and 950 in its manifest and matching healthy coverage without gaps.
The selected HF-PROC-001 finding is Confirmed. Its policy provenance is Missing with ActivationAcknowledgementMissing.
Its linked notification exists with two SinkUnavailable attempts. The strict observer requires Exact policy provenance and times out.
This result is a composed Node-input policy-match gap. It does not prove the physical timeout cause or execute the private full runtime resolver.
The temporary four-path input variant is retained as runtime-catalog-backlog-probe-candidate and restored after the test.
Its 1,430-pin source SHA-256 is 2caa29b0924899536735b7b514f4afbada7b7122d3bf8c1556c5048280486097; its executable SHA-256 is 6f35b840d7c4ff7864b1566c5d59b833e3aa33b112312b350320a959be64d81d.
Source restoration does not change that executable. The prior normal pass remains bound to its recorded source and executable.
The [earlier probe](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/runtime-catalog-probe.json>) did not compile: E0599, because discovery_context is a test-only Control module. It established no runtime result; its inputs were restored.

The [latest physical attempt](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/physical-cached-selected.json>) fails during actor setup in 102.767 seconds, before subscriptions or physical read assertions.
It emits no native image, cached incident, or producer marker and gives no new incident qualification.
The [read-only collection](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/physical-cached-selected-image-absence.json>) confirms owned namespace, pin, socket, and lock absence.
Its bounded journal records image GC at 17:37:29 UTC: 92 percent use, an 85 percent threshold, and removal of the exact Python image.
At collection, three retained test executables used about 6.6 GB. DiskPressure=False did not negate the separate image-GC threshold.
The [approved VM recovery](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/cached-selected-gc-recovery-continuation.json) removes only two obsolete executable copies after hash checks and restores the exact Python image through the existing harness.
Nominal removed bytes are 4,397,007,520. Recorded free space rises from 2,790,641,664 bytes before cleanup to 7,187,443,712 bytes after cleanup; final use is 65 percent after image recovery.
The latest executable, reports, logs, and archive remain. Node and Control image identities are unchanged. No physical case is rerun.
The [runtime evidence proposal](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/runtime-binding-proof-proposal.md>) requires explicit user approval before production metadata or trust checks change.
No such production change, complete matrix, physical PASS, benchmark, Python package execution, or external-delivery result is recorded.


## Runtime binding metadata verification

**Runtime metadata and affected lightweight checks: Done. Current physical incident: Not done.**
The user approved the two-field metadata contract after the retained failing probe.
Data now owns EvidenceRuntimeBindingV1 with container_id and signed_target_digest as one complete optional catalog group.
The digest identifies the signed workload fact. Node saves the group for a verified running binding.
An absent group retains exact binding equality and the previous encoding. A null, partial, malformed, or invalid present group is rejected without a direct-match fallback.
The shared KubernetesWorkloadIdentityV1 owns the unchanged authority and runtime identity calculations and container-ID grammar.
Control checks the group against the retained signed target and keeps its workload digest, Node, boot, label, profile, generation, execution, scope, ACK, and unique-target checks.
Node ID stays in the evidence stream and signed target; it is not duplicated in the catalog group.
The existing test-only discovery reader uses the same binding predicate. It is not a production API.

[Build](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/runtime-link-build.json>) passes for the four affected owners in 238.243 seconds.
The 2,038-pin runtime-link-source.json SHA-256 is 169c5f5adf3a3259e5bbb21b48311fdda53b3311da6b8ff8f04a9691b5cc30ec.
The E2E executable SHA-256 is b92efb52b950c3e95f740bd400d37647df8d26658326223eeb3c657be31cb8cd.
[Data checks](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/runtime-link-data-tests.json>) pass nine cases for identity vectors, existing grammar, catalog fields, invalid groups, target matching, and absent-group bytes and digest.
[Node and Control checks](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/runtime-link-owner-and-backlog-tests.json>) pass 21 owner cases, including generation, arbitrary binding, wrong runtime link, wrong Node, and wrong boot rejection.
The same record includes the runtime backlog case passing in 59.059 seconds, with one pass, zero failures, and zero ignored cases.
The strict observer now requires and obtains Exact policy provenance for the composed Node runtime input; its finding, notification, coverage, and atomic receipt checks remain.
[Scheduled-input checks](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/runtime-link-scheduled-tests.json>) pass data_context_bounds in 3.278 seconds and follows_cpu_streams in 107.671 seconds.
Each reports one pass, zero failures, and zero ignored cases. These records cover 33 distinct focused cases in total.
The fixtures derive the real scheduled authority before signing. They keep the signed placeholder and use the concrete container only in Node input.

[Clippy](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/runtime-link-clippy-final.json>) passes for the four affected owners with warnings denied in 114.167 seconds.
[Scoped formatting](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/runtime-link-fmt-final.json>) passes in 0.266 seconds. Source pins stay unchanged through these checks.
The existing Protobuf catalog_json field carries the new JSON metadata group.
No version, Protobuf field, SDK ABI, quota, polling loop, executor, scheduler, store, or DataFusion operator is added.
Node and Control must use the changed catalog contract together. No mixed-version or independent container-attestation result is claimed.
The current-source production images and paired physical incident remain to be qualified. These test times are not benchmark results.


## Runtime image result and independent failure reads

**Image build and diagnostic checks: Done. Paired physical incident: Not done.**
The [image build](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/runtime-link-image-build.json) passes on source 169c5f5a with the earlier 2,038 pins.
The [archive](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/runtime-link-image-archive-metadata.json) contains the exact Node and Control manifest-to-config links.
The [VM preparation](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/runtime-link-vm-preparation.json) verifies these links, the mounted b92efb52 executable, the paired lightweight input, and the unchanged actor image.
It uses the retained VM and copies no test executable.

The [physical case](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/runtime-link-physical.json) fails with zero passes, one failure, and zero ignored cases.
Libtest takes 173.52 seconds; the provider process takes 218.101 seconds.
Both physical read assertions pass before the incident wait: protected EACCES with zero bytes, and benign errno zero with the complete fixture length.
The native Pod marker binds Node to manifest 63a5936a and Control to manifest 9af46295.
The later native snapshot comparison and atomic receipt checks do not run.
The [retained facts](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/runtime-link-failure-facts.json) show CPU1 records 443/452 on source 7753bb72.
The only cached Graph is from source cfc0d1f8 at cursor 639 and has 138 findings. It contains neither selected record; the notice cache is empty.
This other Graph does not establish the selected source's policy, coverage, or publication state.

The separate five-second producer collection opens graph_state but receives no frame.
Its sequential Instance status and history reads never start. This is an incomplete read, not an empty-state result or a proven producer failure.
Owned namespace, process, pin, socket, and lease absence checks pass.
The [exact CRI log collection](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/runtime-link-failure-cri-collection.json) records both service log paths as absent after normal cleanup.
No successful result.json exists. No physical retry is made.

The failure-only collector now drives its five existing reads independently for each deduplicated source.
Existing futures_util::future::join_all drives one finite graph_state query and Evaluate/Expire status and history requests.
A borrowed Mutex retains each started marker and received result through the unchanged five-second cancellation boundary.
Poison recovery preserves the original wait error. No lock crosses an await.
The successful incident assertions and 90-second watchdog do not change.

The [configured public-RPC test](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/runtime-link-independent-diagnostic-test-v4.json) passes in 7.734 seconds: one pass, zero failures, zero ignored cases.
Two external record IDs share one source. The actual collector emits five starts, retains all four correlated NotFound results, and completes the empty finite Graph query.
The fixture enables Graph through the existing Control configuration. It does not upload or decode the empty record bodies.
The [earlier fixture observation](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/runtime-link-independent-diagnostic-test-v3.json) returned Unimplemented because Fixture::open leaves that relation unavailable; it is not a production query failure.
[Build](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/runtime-link-independent-diagnostic-build-v4.json) passes in 34.940 seconds, [Clippy](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/runtime-link-independent-diagnostic-clippy-v4.json) in 16.980 seconds, and [scoped formatting](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/runtime-link-independent-diagnostic-fmt-v4.json) in 0.031 seconds.
These checks cover 2,039 pins, SHA-256 03fb10a05da4987b3546cb3e38a10e04cb03f44ea17095c032827c03c9223b1a.
The executable SHA-256 is cad458aa8f2bd16568aac18aee169cb483b51dbb1dfc7058a6fa02b2a48c0329.
This test proves public-RPC wiring, source deduplication, and independent result retention. It does not hold one request pending or prove a physical cause.
The current production source remains unchanged. The physical incident, additional input qualification, and final VM removal remain Not done.


## Captured input and notice publication

**Core implementation and focused tests: Done. Busy WAL, current physical incident, and full qualification: Not done.**
The user approved publication of each valid captured Graph input snapshot while later input waits.
Analysis selects Follow explicitly. Finite runs and version operations keep strict source freshness.
Query keeps input cut C separate from publication revision P and preserves intervening input for the next run.
Data retains authority, lifecycle, generation, saved-state, Graph-head, consumed-cursor, evidence, revocation, and expiry checks.
The existing Data transaction saves findings, state, progress, and the receipt together.
The [reading route](../../../../guides/araphor-discovery-definition-review.md#captured-graph-input-publication-reading-route) identifies the capture, getter, commit, and Query owners.

The [red notice regression](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/graph-notice-red-test.json) records notice revision 19 for captured C=16 after an intervening context arrival.
It fails in 25.966 seconds: zero passes, one failure, zero ignored cases.
The correction stamps C for explicit Graph Follow and keeps P for finite publication.
The [qualified ledger](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/graph-notice-qualified.json) records eight passing affected cases.
The first seven pass in graph-notice-green-tests.json on source 249a53f7745dfaeaecd02b1a1571da6c018664f003a5996a3e7ec21629367ed6.
The finite immutable_facts_precede_guests case passes in graph-notice-final-test.json in 134.675 seconds.
Its two expected health fields now match the existing finite-failure contract: ProcessingFailed and incomplete=true.
That test correction changes no production byte. The original eighth-case failure remains retained.
The behavioral source is graph-notice-final-source.json, SHA-256 de601481c2616dd4293199feea7923b5fe3fbe7bfbd8539992fd81719bb08afc.
The earlier 21 focused owner passes retain their separate recorded sources and assertion limits.

The [temporary WAL probe](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/graph-wal-trace-facts.json) fails in 121.011 seconds: zero passes, one failure, zero ignored cases.
Actor publication at C=78/P=83 precedes the failure cache print; the later public producer read reports accepted=consumed=950.
The client cache still has actor Graph P44/cursor940 and background Graph P47/cursor639.
The background producer read reports accepted642 and consumed640. Notifications are empty.
These observations do not establish the timeout cause. The three temporary source files are restored to the normal source pins.
Four pending E2E files remain outside this bounded core deliverable.

[Matrix reconciliation](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/matrix-reconciled-v2.json) retains the accepted assignments and 31 component executions on source dd348647.
Public admission, lifecycle, mandatory detection, native, Wasm, traversal, recovery, and version proof keeps each original source, artifact, target, failure, and retry limit.
CLI equality remains compositional. The native loader check does not prove a valid dependent Arrow model.
No new matrix work, runtime owner, store, scheduler, polling loop, or quota is added.

[Strict Clippy](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/graph-core-final-clippy.json) passes for the Data, Query, and Analysis library and test targets in 22.357 seconds.
[Formatting](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/graph-core-final-fmt.json) passes for the 32 changed core Rust files.
The final core source is graph-core-final-source.json, SHA-256 427f4bf37e8ebb54b3bf4a2e65f83c0537f4bd10825de750bde0dab5646be347.
It changes only one test comparison to borrowed slices after the behavioral proof; production bytes and comparison values are unchanged. The earlier Clippy failure remains retained.
This bounded core result does not complete qualification. No full CI or benchmark ran.
PENDING: normal-source busy-WAL proof, current deployment images, paired physical result, and owned-resource absence.
PENDING: final evidence retention, document status, and owned VM removal. No current physical PASS is claimed.
The Analysis idle observation covers 50 milliseconds; Query uses its existing clock notification for deterministic idle checks.
Performance, full incident reproduction, Python execution, upstream algorithm ports, and external delivery remain outside this result.


## Ordinary Follow replacement delivery

**Native Query replacement proof: Done. Busy WAL, gRPC replacement, load, and current physical proof: Not done.**
The existing [manifest_replacement_rebinds case](../../../../../crates/araphor-analysis/src/graph/native/tests/managed/notices/snapshot.rs) uses the same graph_manifest SQL as the incident observer.
One production Instance publishes Graph 1–3. Ordinary tenant-wide Follow reads its full snapshot.
The fixture then accepts record 4, and the same Instance publishes Graph 1–4. No record 5 or other write follows.
Follow must return one Replace row with the new result ID, exact receipt revision, full evidence IDs, and previous-result link. The old Graph must remain unchanged.
Metadata-only updates can arrive inside the existing 30-second stream bound. The observer joins cleanup on error or panic.
The [exact case record](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/public-manifest-test-test.json) reports one pass, zero failures, zero ignored cases, and 13.219 seconds.
The test executable SHA-256 is d6648b312f752724bf0ab6c7e602a26719fbf085890d42cc810ed0ac7618ea26.
The 2,042-file source manifest is public-manifest-test-source.json, SHA-256 d472139186991809b92b6934caef6f2bf2d808ce2ff96c4f9e1546316fab1116.
The [Analysis build](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/public-manifest-test-build.json), [strict Clippy](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/public-manifest-clippy.json), and [one-file formatting](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/public-manifest-fmt.json) pass. No unchanged behavioral case is repeated.
This test adds no production owner or behavior. It does not establish the busy-WAL timeout cause, gRPC delivery, concurrent load behavior, or physical qualification.


## Batched result references

**Shared reference writes and focused Data checks: Done. Busy WAL and complete qualification: Not done.**
The [Data diagnostic](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/reference-probe-facts.json>) separates reference writes from transaction commit.
The first actor publication saves 4,700 evidence references and 43 context references for five result owners.
The reference intervals total 3.856 seconds inside a 5.704-second writer interval. The transaction commit takes 65 milliseconds.
These are parent-reader observations from one failing test. They include scheduling and are not benchmark results or proof of the sole timeout cause.
The diagnostic test fails in 122.123 seconds. Both temporary Data files return to their original hashes before the production change.

Data now uses its existing DuckDB appender pattern in insert_references.
Each table has one scoped appender and an explicit checked flush. All reference rows, values, witness/segment pairs, and empty-input guards remain.
The caller keeps the writer and transaction. The appenders close before later quota and publication checks.
The [review route](../../../../guides/araphor-discovery-definition-review.md#batched-result-reference-writes) links the three call sites and rollback proof.

The [focused build](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/references-bulk-build.json>) passes in 232.182 seconds.
The [test record](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/references-bulk-tests.json>) retains five passing Data cases and one failing WAL case.
The new context_failure_rolls_back case requires a context flush error after evidence flush, complete rollback, retained captured context, and successful retry after schema restoration.
Existing checks retain exact 8,193 evidence and 257 context references through retention and reopen, atomic context publication, final-authority rollback, and Graph appender constraint rollback.
The unchanged busy-WAL case fails in 121.286 seconds. Its actor cache remains at cursor 940 and its background cache at 639.
The selected record cache is empty. Both producer-state queries open but return no frames before the common five-second diagnostic limit.
The [failure facts](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/references-bulk-wal-facts.json>) do not establish current producer cursors or acceptance times for records 941 and 950.
No end-to-end speed improvement or complete incident result is established.

[Data Clippy](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/references-bulk-clippy.json>) passes with warnings denied in 270.843 seconds.
[Two-file formatting](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/references-bulk-fmt.json>) passes in 0.034 seconds.
These checks cover references-bulk-source.json with 2,042 pins and SHA-256 91b85d207dc04140cd35ef87b2d0f235cc7847ff58e120b4b937f8737743d381.
The Data executable SHA-256 is 888677d04ed70d8c11ba0f8756dd9b72b374fba107c1d9a0bdd94fc31d69d752.
The E2E executable SHA-256 is c20a7896b309a1a468ccc4e91e752dc42152faab7b6e5ff3f622c8fbfb8c67c2.
Source and executable hashes remain unchanged through the checks. No full CI or benchmark runs.
PENDING: busy-input completion, current images, paired physical result, resource absence, final records, and owned VM removal.


## Physical projections for subscription dependencies

**Dependency correction and focused owner checks: Done. Busy WAL and complete qualification: Not done.**
Query admission retains relation names before physical planning. Native physical scans already add the required column indices for capture.
Subscription dependency checks previously used only the admission map. A graph_manifest relation with no known projection therefore included mutable notice revisions for a query that selected only saved result fields.
Data already has the required column rules. Query now retains the same physical request map and supplies it to the existing Data dependency API.
All admitted relation keys remain. Prephysical, resume, and recovery checks keep the conservative admission map.
The [reading route](../../../../guides/araphor-discovery-definition-review.md#physical-projection-dependencies) links native collection, retained ownership, and the existing guards.

The [test-only RED](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/projection-notice-red-facts.json>) fails at the intended cursor comparison in 10.157 seconds.
After a facts-only notice, the unchanged three-column query advances from cursor revision 11 to 12. The notice-sensitive query and unchanged head/body checks pass first.
The RED source SHA-256 is 000cd2b66ff884d2c6ff9deb49205b03653e452b6477514251772a4fa2c07d81. Its Analysis executable SHA-256 is 6a02ac36ba44f068c3e1940afd8d0b4935362d42cae79ec9be9b2e9553667539.
The [GREEN case](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/projection-requests-green-test.json>) passes in 13.917 seconds.
It now checks two consecutive notices. The three-column cursor stays unchanged, the notice-sensitive filter reacts each time, and the real fourth-record replacement retains every prior assertion.

CapturedRequests owns the exact map and its DataFusion memory reservation. Admission checks include both owner and map bytes before the reservation is split.
ArrowSnapshot and Runtime share this owner. Metadata updates can replace the old snapshot while the map and its charge remain together.
The [focused record](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/projection-requests-checks.json>) has 15 passing Query cases and four passing Analysis cases.
These checks cover charge lifetime, existing input bounds, witness and binary scratch accounting, projection, filters, joins, windows, restart, limited pages, Graph notices, captured-input catch-up, and expiry.
The new lifetime case proves that the old snapshot is freed, Arc clones add no charge, and the final owner drop releases the charge. Existing test limits are unchanged.
Together with the GREEN case, these records contain 20 distinct passing cases on the corrected source.

The same record retains the unchanged busy-WAL failure in 121.691 seconds: zero passes, one failure, zero ignored cases.
Both selected records are visible, but the cached actor Graph remains at cursor 940 and excludes them. The background Graph remains at 639 with 138 findings; notifications are empty.
The [failure facts](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/projection-requests-wal-facts.json>) keep the separate status/history responses and incomplete producer-state queries. Current producer heads and consumed cursors remain unknown.
This correction does not establish the full timeout cause or an end-to-end speed improvement.

[Clippy](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/projection-requests-clippy.json>) passes for Query and Analysis with warnings denied in 70.084 seconds.
[Formatting](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/projection-requests-fmt.json>) passes for the eight changed Rust files in 0.088 seconds.
The corrected source is projection-requests-source.json, with 2,042 pins and SHA-256 7c0d2f9f65e4056e43f2ef9af5a4af3aee5d3fcc93e6580f24eb93401bb9fdd9.
The [build record](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/projection-requests-check-build.json>) binds the Query and E2E executables; the [GREEN build](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/projection-requests-green-build.json>) binds the Analysis executable.
The [integrity record](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/projection-requests-check-integrity.json>) confirms unchanged source, executables, and excluded files. No full CI, benchmark, or physical case runs.
PENDING: busy-input completion, current images, paired physical result, final records, resource absence, and owned VM removal.


## Shared notification Graph reads

**Graph read reuse and six focused Data cases: Done. Busy WAL and complete qualification: Not done.**
The [capture diagnostic](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/capture-boundary-postcommit-probe-facts.json>) records two notification captures with 5.593-second and 6.749-second materialization intervals.
These intervals include scheduling and other capture work. They do not identify the sole timeout cause.
Source inspection finds one complete finding read and Graph validation for each obligation that references a finding, even when several obligations reference the same saved Graph.

The existing Data capture now retains each permitted Graph and its checked revision in a local sorted vector.
The first read keeps the full finding validation, selected-source check, and binding authorization. Each obligation keeps its result reference, finding filter, context reference, and route checks.
Later obligations borrow their finding from that checked Graph. The capture closure owns and releases the vector.
Existing input-budget methods admit its key and vector capacity. The Graph allocation retains the existing charge for each actual read.
The [review route](../../../../guides/araphor-discovery-definition-review.md#shared-notification-graph-reads) links these owners and checks.

The [deterministic RED](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/notification-graph-reuse-red-facts.json>) passes all exact row and reference checks before its scan assertion fails: 43,485 bytes instead of 18,547 bytes.
Three obligations reference one real Graph. The expected scan adds only the two new serialized context bodies to the original capture.
The [GREEN case](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/notification-graph-reuse-green-test.json>) passes in 1.778 seconds, including that assertion and exact notification IDs for allowed bindings, denied bindings, an excluded source, and a missing Graph.
The missing Graph remains visible as unavailable to an unscoped query and is excluded from the scoped query.
The [five further Data checks](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/notification-graph-reuse-checks.json>) pass for Graph integrity, tenant separation, cancellation, extraction limits, and allocation bounds.

The unchanged normal busy-WAL case still fails in 121.951 seconds: zero passes, one failure, zero ignored cases.
Its actor cache contains records 941 and 950, but its Graph remains at 940. The background Graph remains at 639 with 138 findings; notifications are empty.
The [failure facts](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/notification-graph-reuse-wal-facts.json>) preserve the incomplete producer queries. Current producer heads and accepted or consumed cursors remain unknown.
The repeated-read correction does not establish an end-to-end speed improvement or complete incident result.

[Strict Data Clippy](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/notification-graph-reuse-clippy.json>) passes in 16.767 seconds. [Two-file formatting](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/notification-graph-reuse-fmt.json>) passes in 0.122 seconds.
The corrected source is notification-graph-reuse-source.json, with 2,042 pins and SHA-256 611c0f41c7fea729d49260b2597859091ac0570e35719320b8361b6d5ee46a9c.
The [normal build](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/notification-graph-reuse-check-build.json>) binds Query and E2E executables; the [GREEN build](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/notification-graph-reuse-green-build.json>) binds the Data executable.
The [integrity record](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/notification-graph-reuse-check-integrity.json>) confirms unchanged source, executables, and excluded files. No full CI, benchmark, or physical case runs.
PENDING: busy-input completion, current images, paired physical result, final records, resource absence, and owned VM removal.


## Reactive read admission

**Shared admission correction and focused Data proof: Done. Busy WAL and complete qualification: Not done.**
The capture trace records one read that retains the writer coordinator during a 5.218-second reader wait.
The [deterministic RED](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/capture-wait-red-facts.json>) isolates this condition with both real reader slots held.
The public read completes after release. Only the saved writer-availability assertion fails. The test uses the existing lock event and one availability check.

Data now uses one private coordinated_reader method for table capture and dependency reads.
If both reader slots are busy, it releases the maintenance lease and writer, waits for the selected reader, releases that probe, and retries writer acquisition and raw projection.
One admission permit and one reader ordinal remain with the operation. Both callers retain their existing SQL snapshot, metadata, selection, and coordinator-release points.
The [review route](../../../../guides/araphor-discovery-definition-review.md#reactive-read-admission) links the owners, lock order, and tests.

The [unchanged GREEN regression](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/coordinated-reader-green-test.json>) passes in 0.361 seconds on its recorded source ff369732.
The [direct state case](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/coordinated-reader-state-test.json>) passes in 1.144 seconds.
It accepts new input while both readers remain held. After release, the queued capture returns its exact new revision, source receipt, and event cursor without another write.
Its second scenario cancels the queued read before reader release and verifies the returned permit. Both scenarios restore all three configured permits and free the locks.
This state case adds one test to the first GREEN source; production and the first regression remain unchanged.
The [eleven existing Data cases](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/coordinated-reader-checks.json>) also pass. They cover admission, release events, cancellation, deadlines, poison, rotation, snapshot maintenance, and dependency selection.

The unchanged normal busy-WAL case still fails in 121.050 seconds: zero passes, one failure, zero ignored cases.
The failure cache has actor Graph 941 at revision 100, background Graph 639 with 138 findings, and no event rows or notices. Selected finding and policy checks are not projected.
During collection after the wait error, the actor state query returns accepted=consumed=950 and a newer Graph head at read revision 162.
The [failure facts](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/coordinated-reader-wal-facts.json>) retain that later snapshot separately. It does not establish publication before the deadline or the full final Graph body.
The background state query returns no frames. Its current head and accepted or consumed cursors remain unknown. The complete timeout cause and end-to-end speed remain unproven.

[Strict Data Clippy](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/coordinated-reader-clippy.json>) passes in 16.391 seconds. [Three-file formatting](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/coordinated-reader-fmt.json>) passes in 0.134 seconds.
The final source is coordinated-reader-state-source.json, with 2,042 pins and SHA-256 616d357c963872017dc51ffb7276da100b0fd575285b51c6273741cc02a3e57f.
The [normal build](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/coordinated-reader-check-build.json>) binds Query and E2E executables; the [state build](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/coordinated-reader-state-build.json>) binds the Data executable.
The [integrity record](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/coordinated-reader-check-integrity.json>) confirms unchanged source, executables, and excluded files. No full CI, benchmark, or physical case runs.
PENDING: busy-input completion, current images, paired physical result, final records, resource absence, and owned VM removal.


## Reuse canonical Graph snapshots

**Canonical byte reuse and focused checks: Done. Busy WAL and complete qualification: Not done.**
The full Graph read already creates canonical JSON to check the stored byte length.
Native snapshot projection previously serialized the same Graph twice more: one count pass and one output pass.
Data now retains the first buffer in its existing CanonicalGraph value.
The native Binary builder copies the validated bytes into its existing Arrow buffer.
The public schema and canonical bytes remain the same.

The existing two-times-snapshot input charge remains.
Capture also charges the retained Vec capacity before Arrow output allocation.
Header-only reads do not serialize a snapshot.
Traversal supplies no retained buffer and encodes its selected Graph only when the snapshot column is requested.
Partial and modified traversal values still validate.
The [reading route](../../../../guides/araphor-discovery-definition-review.md#reuse-canonical-graph-snapshots) identifies the buffer, projection, and guard owners.

The [focused record](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/canonical-snapshot-reuse-checks.json) contains ten passes and one failing busy-WAL case.
Nine Data checks and ordinary Follow replacement pass.
The extended graph_snapshot_deadline case checks exact full bytes, fresh zero-hop traversal bytes, native schema, witnesses, and the result reference.
All earlier assertions remain.
The build passes in 165.734 seconds.
The source manifest is canonical-snapshot-reuse-source.json, SHA-256 593704df1deeaee2d92d2cd5f3542667a693a22c1c99f22d6c31afb3f0ffdd2a, with 2,042 pins.
[Data Clippy](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/canonical-snapshot-reuse-clippy.json) passes with warnings denied in 17.230 seconds.
[Six-file formatting](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/canonical-snapshot-reuse-fmt.json) passes in 0.135 seconds.

The [normal busy-WAL case](/home/navid/mithril-test-hosts/araphor-package-qualification-verification/canonical-snapshot-reuse-wal-facts.json) fails in 122.868 seconds.
Its cache contains records 941 and 950, actor Graph cursor 940, background Graph cursor 639 with 138 findings, and zero selected notifications.
A later actor graph_state read reports consumed cursor 950 and a new head at read revision 156.
That later read does not establish publication before the wait expired or delivery of the final Graph.
The background state query returns no frame within the existing failure collector.
Source and executable hashes remain unchanged through the checks.
The removed serialization passes are source-proven; an overall execution-time improvement is not established.
PENDING: busy-input completion, current images, paired physical result, final evidence records, resource absence, and owned VM removal.


## Source-specific Graph progress dependencies

**Progress dependency correction and focused Data proof: Done. Busy-input and complete qualification: Not done.**
A graph_state subscription with exact source A previously used the global processor_progress revision.
Registration of unrelated source B changed that dependency even after A had a published Graph.
Data now reads the current required Graph head for each original exact source within the existing SQL snapshot.
It uses the maximum head revision only when every source has a matching active required processor and stored result.
All-source, empty, mixed discovery_state, absent, unpublished, optional, and retired selections retain the global fallback.
The global processor_gaps dependency remains in every case. Source, coverage, expiry, recovery, context, and other result dependencies also remain.
Query retains its native DataFusion source capture and subscription execution. No schema, index, cache, scheduler, clock, quota, or public API is added.
The [reading route](../../../../guides/araphor-discovery-definition-review.md#source-specific-graph-progress-dependencies) identifies the owner and guards.

The [corrected RED](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/scoped-graph-progress-red-v2-facts.json>) fails at the intended assertion: unrelated registration changes dependency 5 to 6.
The first test-only attempt fails earlier because the fixture retains its old Graph lease; that failure is not production RED proof.
The corrected fixture releases that lease before it acquires the exact-source lease. Existing ownership checks remain.
The [GREEN regression](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/scoped-graph-progress-green-checks.json>) passes in 2.545 seconds.
It checks unrelated registration, a published head replacement at the same consumed cursor, global fallbacks, a real global gap, selected retirement without a gap, idempotence, and reopen.
Its optional-source scenario has no published head. It does not independently test an optional published head or inject a missing stored result.
The [four existing dependency checks](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/scoped-graph-progress-checks.json>) pass on the same source.
The Data build passes in 52.746 seconds; the E2E build passes in 138.895 seconds.
[Data Clippy](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/scoped-graph-progress-clippy.json>) passes with warnings denied in 17.036 seconds.
[One-file formatting](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/scoped-graph-progress-fmt.json>) passes in 0.039 seconds.
The source manifest is scoped-graph-progress-green-source.json, SHA-256 765c178e07d30811201dfe6eb93455ecf5d9c8fb72a751c631856d2aaa5ec5e6, with 2,042 pins.

The unchanged [busy-WAL case](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/scoped-graph-progress-wal-facts.json>) still fails in 120.706 seconds: zero passes, one failure, zero ignored cases.
The client cache contains records 941 and 950, actor Graph cursor 940, background Graph cursor 641 with 138 findings, and zero selected notifications.
A later finite actor state query reports consumed cursor 950 at read revision 86.
That read does not prove publication or full Graph delivery before the wait expired. The remaining delay and overall speed improvement are unproven.
[Integrity checks](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/scoped-graph-progress-check-integrity.json>) confirm unchanged source, executables, and excluded files.
No full CI, benchmark, image build, or physical case runs.
PENDING: busy-input completion, current images, paired physical result, final evidence records, resource absence, and owned VM removal.


## Native physical planning execution

**Native planning and focused owner checks: Done. Busy-input completion, current physical result, and complete qualification: Not done.**
The [temporary diagnostic](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/publication-phase-probe-facts.json>) records a native physical-planning interval of up to 13.01 seconds.
The [interval record](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/publication-phase-probe-intervals.json>) uses parent line-reader arrival times. These intervals include scheduling and nested preparation; they are not CPU measurements or a benchmark.
The diagnostic keeps its original source and executable limits. It does not establish the complete busy-WAL cause.

Native planning now runs as an async task on the Query engine's existing runtime.
[Engine::plan_physical and join_worker](../../../../../crates/araphor-query/src/execution.rs) retain the engine, operation control, result, and task lease through completion or cancellation.
Blocking work uses the same result-join owner. Logical optimization and package preparation keep their existing blocking workers.
No new executor, runtime, store, scheduler, or timeout is added.
The blocking-parent proposal was rejected: nested package preparation can need the same blocking pool, so a parent that holds its sole worker can prevent progress.

The [corrected native-scan RED](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/native-planning-red-fixed-facts.json>) fails in 6.014 seconds with AnalysisReadDeadline before the current-thread test can release its synchronous scan gate.
Gate release and bounded cleanup run before the failure is returned. This proves the native-planning liveness condition; it does not prove the sole busy-WAL cause.
The [earlier cleanup attempt](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/native-planning-red-invalid-facts.json>) polls a completed future again and panics. That result remains invalid RED evidence.

The [Query build](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/native-planning-green-check-build.json>) passes in 51.942 seconds.
The [focused Query record](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/native-planning-green-checks.json>) contains twelve passing executions, each with one pass, zero failures, and zero ignored cases.
These checks cover native-scan cancellation and joined cleanup, Notify-only cancellation without release, package preparation, abandoned result and lease order, clock changes, and SQL/Wasm execution with one caller blocking worker.
The existing clock assertions and SQL/Wasm accumulation assertions remain.
[Query Clippy](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/native-planning-clippy.json>) passes with warnings denied in 69.105 seconds.
[Four-file formatting](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/native-planning-fmt.json>) passes in 0.072 seconds.
The source is [native-planning-green-source.json](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/native-planning-green-source.json>), SHA-256 ff4beae2a829c76b6aaa8baee47bb3aba48d56478d677c53a5ec426068a971bb, with 2,042 pins.

The fresh [E2E build](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/native-planning-incident-check-build.json>) passes in 140.493 seconds.
The unchanged [busy-WAL case](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/native-planning-incident-facts.json>) fails in 119.482 seconds: zero passes, one failure, zero ignored cases.
The client cache contains actor Graph cursor 950 at commit revision 91 and background Graph cursor 642 at commit revision 93. Records 941 and 950 are present.
The actor finding is Confirmed with Exact policy. Background CPU 0 has matching healthy coverage and the selected cut member.
The selected notification is absent. The completion predicate still waits for that notification; the strict assertions after the wait do not run.
A later finite state query reports consumed cursors 950 and 642 at read revision 104. That later query does not establish when those results were published.
The selected notice field does not establish whether a stored obligation exists or whether routing failed.
The [integrity record](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/native-planning-incident-check-integrity.json>) confirms unchanged source, executable, and excluded files.
PENDING: current deployment images, the paired physical result, final evidence records, owned-resource absence, and owned VM removal.
The whole qualification matrix and current physical result remain Not done. Existing matrix records retain their original source, artifact, and assertion limits.
No overall speed improvement, full CI, benchmark, full incident reproduction, Python execution, upstream algorithm port, or external notification delivery is qualified by this result.


## Current finding checks for notification routing

**Current-reference correction and focused owner checks: Done. Busy-input completion, complete qualification, and current physical result: Not done.**
The [temporary routing trace](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/notification-owner-probe-facts-v2.json>) has 1,571 markers and no truncation.
At captured revision C56, the batch has 138 finding references and zero delivery keys.
Its routing loop takes 42.859 seconds. Eleven routes succeed; 127 references then fail the current-result check.
Those 127 current-finding reads take 22.224 seconds in total before the stale references are rejected.
The later batch has 139 references and eleven delivery keys. It stops before an individual delivery starts.
Eighteen saves comprise eleven new obligations and seven updates. They do not represent eighteen obligations.
The [intervals](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/notification-owner-probe-intervals.json>) use parent line-reader arrival times.
They do not measure CPU cost, prove the sole incident timeout cause, or establish an execution-time gain.

[AnalysisStore::notification_finding](../../../../../crates/araphor-data/src/analysis/graph/findings.rs) validates the tenant and both reference identifiers before a read.
It returns the existing Notification Invalid error with the finding reference field for invalid input.
Within one read snapshot, it selects the current key through the existing selection query.
An absent key returns Notification Denied for current finding scope.
A different result returns Notification Conflict for current finding reference before materialization.
A matching result uses the existing header, index, stored-byte, and finding checks through preflight and collection.
Both [SQL ranking stages](../../../../../crates/araphor-data/src/analysis/graph/findings/selection.rs) remain unchanged. The expected result is not a ranking filter.
[NotificationRouter::route_finding](../../../../../crates/araphor-analysis/src/notification/routing.rs) keeps the router mutex and the now greater than zero check.
Data now owns the existing tenant and reference guards. Analysis still reads fresh routes and calls NotificationRouter::schedule.
Per-item checks, scheduling, delivery order, and checked persistence remain. No cache, batch owner, or new execution owner is added.

The [old-order RED record](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/notification-current-read-red-facts.json>) has a passing build in 59.555 seconds and the intended failing case in 2.144 seconds.
The test restores the saved CBOR header before both corruption assertions.
The old read rejects the corrupt current header before it can return the expected stale-reference Conflict.
The matching-corrupt assertion passes before that intended failure. Later empty-replacement assertions are not reached in RED.
The exact regression is analysis::graph::findings::tests::notification_finding_checks_current in RED and GREEN.
The current [GREEN source manifest](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/notification-current-read-green-source.json>) is SHA-256 41cd011d8b9ca639c8feabf0ca2a633afbcddc81c1e1373dc69398b635a4acd0.
The [Data/Analysis build](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/notification-current-read-green-check-build.json>) passes in 175.084 seconds.
The [focused record](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/notification-current-read-green-facts.json>) has twelve passes, zero failures, and zero ignored cases.
The unchanged new regression passes in 1.377 seconds and reaches the empty-replacement assertions.
RED Data has no Cargo features; the combined GREEN build enables test-fixtures. The read and regression have no feature conditional. The runs are not feature-identical.
[Four-file formatting](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/notification-current-read-fmt.json>) passes in 0.034 seconds.
[Data/Analysis Clippy](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/notification-current-read-clippy.json>) passes with warnings denied in 70.646 seconds.

The fresh [normal E2E build](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/notification-current-read-incident-check-build.json>) passes in 148.569 seconds.
The unchanged [busy-input case](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/notification-current-read-incident-facts.json>) still fails in 120.380 seconds: zero passes, one failure, zero ignored cases.
Its cache contains actor Graph cursor 950 at publication 88 and background Graph cursor 642 at publication 85.
Records 941 and 950 are present. The selected finding is Confirmed with Exact policy evidence. Its notice is absent.
The background Graph has healthy matching CPU 0 coverage and one selected cut member.
Strict assertions after the wait do not run. Later finite state reads retain their later-snapshot limits.
The [integrity record](</home/navid/mithril-test-hosts/araphor-package-qualification-verification/notification-current-read-incident-check-integrity.json>) confirms unchanged source, executable, and excluded files.
The remaining notification cause and an overall execution-time gain are not established. No new physical case or benchmark runs.
PENDING: current deployment images, paired physical result, final evidence records, owned-resource absence, and owned VM removal.
The whole qualification matrix remains Not done. Earlier matrix records retain their original source, artifact, and assertion limits.
