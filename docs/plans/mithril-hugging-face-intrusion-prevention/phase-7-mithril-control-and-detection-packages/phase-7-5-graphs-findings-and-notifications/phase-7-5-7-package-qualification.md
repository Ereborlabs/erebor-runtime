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
