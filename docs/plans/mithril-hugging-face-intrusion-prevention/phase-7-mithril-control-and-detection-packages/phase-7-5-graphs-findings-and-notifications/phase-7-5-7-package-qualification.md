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
