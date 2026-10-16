# Araphor Performance Simplification TODO

Implement the 17 audit items that the user approved on 2026-10-15. The source
basis is `aa390d9f647c304ef212396433824a6b9c560982`. Remove repeated production
work in all Araphor crates. Keep the existing durable and authorization owners.
The user approves the quota-unit change in item 17 with the other items.

This file extends the
[production data flow plan](araphor-production-dataflow-simplification.md).
Earlier source and verification records in that plan remain historical.

## Approved deletion work

The user requires at least 6,000 net deleted nonblank production Rust lines.
Tests and documents do not count toward this target. Report both `7b7b407a` and
`aa390d9f` as comparison points. Do not count blank-line removal, code movement,
or compressed formatting as simplification. Consolidated tests must retain
every distinct input, fault, boundary, and assertion.

| Owner | Required deletion |
| --- | --- |
| Query | One table registration and SQL execution path. Keep the existing native adapter and remove duplicate plan classification. |
| Package | One input/freshness comparison. Remove optional admitted-bundle loading and per-export task handoff. Wait on changes and actual deadlines. |
| SDK and built-ins | One checked computation entry. Keep standalone, import, and host boundary checks. |
| Control context | The authoritative transaction application identifies changed keys. Remove the second transaction interpreter. |
| Capture | One retained execution entry owns dispatch, cursor, and optional worker. |
| Storage | One selected-set cleanup validates expiry, synchronizes removal, and commits quota changes. Remove per-segment global scans. |
| Documentation | One current source route per contract. Remove repeated implementation and verification prose. |

The benchmark remains on hold. The user requires relevant builds and tests
for each iteration. This instruction replaces the general full-workspace CI
rule for this work.

### Component redesign

The user accepts the deletion work and requires simpler complete components.
Documentation and test consolidation do not establish that result.

| Component | Required replacement | Result |
| --- | --- | --- |
| Control context | One ordered source index and one replay cursor replace separate change maps and domain cursors. Preserve distinct-source conflicts, bounded replay, and retry after a failed durable write. | Not done |
| Package transport | SDK wire types own datasets, inputs, reasons, outputs, and checkpoints. Remove Data's second wire model. Keep each boundary's current limits and error classes. | Not done |
| Raw storage | The raw journal owns its physical segments, append decision, and recovery scan. Remove the generic segment owner and second frame decode. Keep acknowledgement before SQL publication, sealed length checks, leases, pins, quota, and recovery after database loss. | Done |
| Discovery and graph values | The existing built-ins crate owns shared pure values. Data retains source qualification and host output checks. Remove mirrored values and field conversion owners. Execute the selected installed artifact. | Done |
| Follow positions | SQL views expose position aliases from existing columns. Remove copied hidden values from each input row. Keep position type checks, repeat-call denial, bounds, and source cleanup. | Done |
| Native graph rows | Append from canonical graph values and decode native cells into those values. Remove buffered row DTOs and their byte formulas. Keep native schema, result-scoped charges, explicit flushes, rollback, bounds, and corruption checks. | Done |
| SQL admission | Use the production parser for the former offline proof cases. Remove the unused parser. Keep fixed-bound disjunction parity, source scope, parameter bounds, and moving-clock denial. | Done |
| Discovery page admission | Reuse the admitted snapshot and input-byte total. Remove the second detector execution, merge, and input-size pass for an accepted page. Keep candidate bounds, context references, progress, and commit authorization. | Done |
| Package result contract | Store `PackageCommitV1` as the canonical contract. Remove the cloned metadata DTO and duplicate dependency JSON column. Keep native index checks, full retry identity, authorization, dependency references, and exact charges. | Done |
| Query transport | Move owned values into transport output. Remove the scalar wrapper and text, binary, column, and context-key clones. Keep output leases through the next poll or drop. | Done |

Do not replace native pointer checks with IPC copies or remove the supported
graph traversal contract to obtain a line count. Reuse must remove an owner or
representation without moving the same duplicate implementation elsewhere.

## Intended end state

Owners check relevant changes and due deadlines before they load payloads.
One operation prepares common inputs once. Existing owners retain immutable
declarations, verified artifact identities, and cursor positions for their
actual lifetimes. Query input preparation uses the admitted relations and
columns. Storage charges current encoded bytes. Current-format recovery,
tenant isolation, evidence, exact revisions, deadlines, and cleanup remain.

DuckDB remains the execution engine. Arrow contracts remain independent of
that engine. This work adds no service, broker, provider framework, engine
pool, or DataFusion dependency. It adds no older-format reader or migration.

## Implementation flow

An owner starts or recovers
  -> the existing store validates current durable state
  -> the owner reconstructs its immutable inputs and cursor state
  -> the owner registers existing change subscriptions and required deadlines

A relevant commit or due deadline occurs
  -> the owner checks current authorization and exact metadata
  -> the owner selects affected work
  -> the owner prepares required inputs once
  -> the existing execution owner computes the result
  -> the existing store validates and commits the result
  -> the owner publishes the committed change

An operation fails, expires, or loses authority
  -> the current control cancels active work
  -> the owner releases handles, inputs, and reservations
  -> the store retains only committed state
  -> recovery or retry checks current exact state

## Accepted items

`Not done` means that implementation or required verification remains.
Change an item to `Done` only after its source and functional checks pass.

| ID | Status | Change and owner | Required proof |
| --- | --- | --- | --- |
| 1 | Not done | Package owner groups reconciliation by installation, reuses immutable closures, and checks relevant dependency changes before source preparation. Remove repeated orphan scans and unconditional input reconstruction. | Upgrade orphan repair, activation changes, authority revocation, required clock ticks, exact dependency revisions, restart, and unchanged-input behavior. |
| 2 | Not done | Graph owner checks headers, notices, exact heads, and witness deadlines before it loads retained graph rows. | Notice changes, expiry without new data, overlap replacement, package changes, restart, and exact result parity. |
| 3 | Not done | Store owner maintains owned file and segment totals at file changes. Remove a full directory walk from each raw batch. Rebuild totals during recovery. | Capacity denial, disk reserve, rotation, deletion, database growth, restart, and ACK after durable commit. |
| 4 | Not done | Graph derivation prepares common records, facts, revision, coverage, and datasets once per window. | Native and Wasm parity, per-model bounds, original input revisions, evidence ordinals, and exact outputs. |
| 5 | Not done | Built-in graph computation indexes original facts by record once per evaluation. | Missing and conflicting facts, original ordering, exact evidence references, and detector parity. |
| 6 | Not done | Follow retains its checked store revision and dependency selection. Remove dependency history scans when both remain unchanged. | Append replay, moving-window expiry, coverage changes, quiet revocation, and unrelated commits. |
| 7 | Not done | Query owner constructs required event columns and applies supported simple predicates during extraction. Keep a complete fallback for complex statements. | Full row mapping, query parity, scope denial, evidence capture before pruning, empty append progress, and joins, ordering, and aggregate semantics. |
| 8 | Not done | Installed package owner retains verified identities with immutable bundles. Authority checks current trust membership without rebuilding OCI layouts. | Changed-content denial, trust revocation, exact installed exports, native closure identity, and commit authorization. |
| 9 | Not done | Retention uses the existing source index and removes a bounded eligible set per visit. Remove repeated global entry scans. | Current pin and required-progress checks, pressure, replay floors, recovery, and physical reuse. |
| 10 | Not done | Capture owner retains verified immutable dispatches after recovery or admission. Remove intent file reads from idle diagnostic polls. | Durable intent before spawn, duplicate rejection, lease expiry, retirement floors, and recovery without a second spawn. |
| 11 | Not done | Capture owner retains the verified spool cursor byte offset. Rebuild the offset once after reopen. | Replay, cursor changes, sequence denial, torn tails, and upload of the synced prefix only. |
| 12 | Not done | Operation owners observe authority changes through events and reuse deadline monitoring. Remove per-read thread creation and authority polling. | Direct synchronous calls, shorter stage deadlines, cancellation, closed authority channels, cleanup, and commit checks. |
| 13 | Not done | Query owner registers admitted built-in relations only. Store provenance methods return empty values for empty references after validation. | Hidden-source denial, alias provenance, cleanup, exact nonempty references, and empty input results. |
| 14 | Not done | Built-ins reuse immutable declarations and their ports. Remove schema generation during computation. | Canonical descriptor and schema metadata, wire round trips, and native and Wasm parity. |
| 15 | Not done | Guest invocation reuses validated inputs internally. Remove repeated contract passes inside one invocation. | Framing and FFI validation, checked standalone APIs, host output checks, evidence validation, cleanup, and error precedence. |
| 16 | Not done | Control context owner projects committed changes and serializes a new record once. Retain startup replay. | Exact retries, failed-write retry, bounded replay, current revisions, and restart. |
| 17 | Not done | Package store charges actual current encoded bytes. Remove decimal JSON size counting, its retained frame field, and obsolete quota bookkeeping. | Current format integrity, quota accounting, identical install retry, native dependencies, corruption, backup, restore, and recovery. |

## Verification and result

Use owner-local functional tests and build the affected callers for each
iteration. Qualify current source-built native packages and the installed native detector
through the existing proof route. Preserve all current format and ABI checks.

No new performance test or benchmark is approved. Do not infer speed gains
from changed test-suite durations. Record removed work from the final source.
Measure latency only after approval of a specific workload and its limits.

Result: **Not done**. The current source removes 2,137 nonblank production Rust
lines from `7b7b407a` and 984 from `aa390d9f`. The package contract and transport
changes remove 18 from `6509fa70`. Another 3,863 must be removed to meet the target.
Continue component refactoring. Documentation and test deletion do not close
this result.

The package contract and transport iteration passed the affected Data,
Control, and end-to-end test build in 179.37 seconds. All 83 selected Data
tests passed. Of the 29 selected Control tests, 25 passed on the first run.
Four cases lost their 60-second fixture session during concurrent setup.
Those four cases passed unchanged in a sequential run. No assertion or
deadline was removed. All 112 selected functional cases have passing results.
Strict Clippy passed for these three crates and their test targets in 87.87
seconds. Formatting and `git diff --check` passed. Source and test binary
hashes stayed fixed. The records are `/tmp/araphor-contract-build3.json`,
`/tmp/araphor-contract-tests1.json`, `/tmp/araphor-contract-failed-tests1.json`,
and `/tmp/araphor-contract-clippy2.json`.

Six native libraries were built from the current locked source in 42.18
seconds. All 12 native Data cases and the installed native detector end-to-end
case passed. The latter ran with `PATH` empty. Source, artifact, and test binary
hashes stayed fixed. These checks cover Linux, `x86_64-unknown-linux-gnu`, and
glibc 2.39. They do not qualify other targets. The records are
`/tmp/araphor-deletion-native-build.json` and
`/tmp/araphor-deletion-native-qualification.json`. This qualification covers
the shared values, direct graph storage, and package contract changes.

The current count record is `/tmp/araphor-contract-syntax-counts2.json`.
The count also excludes code that is available only through the
`test-fixtures` or `test-support` features. Other feature code remains
production code. This correction changes the earlier `aa390d9f` comparison
from 963 to 966 deleted lines before this iteration. It does not change the
earlier 2,119-line comparison with `7b7b407a`.

The direct-storage iteration passed the affected test build in 353.74 seconds,
strict Clippy, and all 130 selected tests: 18 built-in cases, 95 Data cases,
and 17 SQL admission cases. The Data cases include native graph bytes,
borrowed-column faults, cancellation, quota isolation, backup, restore,
traversal, extraction bounds, page resume, Discovery limits, follow, and model
source cleanup. Source and test binary hashes stayed fixed. The records are
`/tmp/araphor-direct-build1.json`, `/tmp/araphor-direct-clippy1.json`,
`/tmp/araphor-direct-tests1.json`, and
`/tmp/araphor-direct-admission-tests1.json`.

The direct-storage count record is `/tmp/araphor-direct-syntax-counts2.json`. The
extraction change reduces stored pipeline and operation-closure symbols from
51 to five in the Data test binary. That compiled-code reduction does not
count toward the source target and does not measure production latency.
The records are `/tmp/araphor-extraction-symbols-before.json` and
`/tmp/araphor-extraction-symbols-after.json`.

The count uses Rust syntax spans to exclude test items, parameters, fields,
expressions, local bindings, and match arms. A test-only parameter does not
exclude its function body. Added shared type files are included, so code moves
cancel. The count records are `/tmp/araphor-components-syntax-counts1.json`
and `/tmp/araphor-components-syntax-head-counts.json`. These records replace
the earlier regular-expression counts.

The affected Data and built-ins test build passed in 386.61 seconds. All 18
built-in tests and 391 selected Data tests passed. The selected tests include
raw append, quota, recovery after database loss, truncation, backup, restore,
leases, graph and Discovery outputs, SQL positions, and source cleanup. Source
and test binary hashes stayed fixed during the test run. The records are
`/tmp/araphor-components-build2.json` and
`/tmp/araphor-components-tests1.json`.

Strict Clippy passed for the two affected libraries after two local lint fixes:
use `?` for an optional atom key, and import test-only names under `cfg(test)`.
The record is `/tmp/araphor-components-clippy3.json`. The native qualification
above uses rebuilt native and Wasm packages. Shared value changes require
these current artifacts; an older artifact is not current proof.
All 18 built-in tests passed again after the lint fixes. Their record is
`/tmp/araphor-components-builtins-tests2.json`. Formatting passed for both
affected crates.

Commit `238e3ff9` passed the workspace test build, strict Clippy, and all
170 selected functional cases. Its source did not change during these checks.
The records are `/tmp/araphor-deletion-build5.json`,
`/tmp/araphor-deletion-clippy2.json`, and
`/tmp/araphor-components-focused2.json`. The broader CI run was interrupted
at the user's request to use relevant checks per iteration. It is not a passing
CI receipt. The current native qualification is recorded above.

The previous check at `7b7b407a` ran on 2026-10-15. The source manifest contains 1,401 input
files. Its SHA-256 is:

`0f23272581240d3a2e1cb92ac9421ff10b4fec95136bca3f1d642f3a35a62612`

- `bash .github/scripts/verify-rust-ci.sh`: formatting, compilation, Clippy,
  and tests passed. All 90 test harnesses completed: 2,172 passed, zero failed,
  and 568 ignored. Araphor Data passed 653 tests with 19 ignored. Control
  passed 191 tests with two ignored. The end-to-end crate passed 191 tests
  with 528 ignored.
- Six native libraries were built from the current locked source. Their
  98 build inputs still matched the final checkout. All 12 native Data
  cases passed. These cases include parity with current source-built Wasm
  components. The installed native detector end-to-end case also passed
  with `PATH` empty, no host rebuild, exact evidence, and replay equality.
- Source, native libraries, and test binary hashes did not change during
  qualification. Native qualification covers Linux, `x86_64-unknown-linux-gnu`,
  and glibc 2.39. It does not qualify other native targets.

The local evidence records are
`/tmp/araphor-performance-final-ci4.json`,
`/tmp/araphor-performance-final-ci4-report.json`,
`/tmp/araphor-performance-native-build.json`, and
`/tmp/araphor-performance-native-qualification.json`.
The [review guide](../guides/araphor-performance-simplification-review.md)
links each changed owner to its functional checks.

No benchmark or physical Kubernetes qualification was run. The functional
results do not measure production latency or claim a speed increase.
