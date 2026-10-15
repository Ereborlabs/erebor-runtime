# Araphor Performance Simplification TODO

Implement the 17 audit items that the user approved on 2026-10-15. The source
basis is `aa390d9f647c304ef212396433824a6b9c560982`. Remove repeated production
work in all Araphor crates. Keep the existing durable and authorization owners.
The user approves the quota-unit change in item 17 with the other items.

This file extends the
[production data flow plan](araphor-production-dataflow-simplification.md).
Earlier source and verification records in that plan remain historical.

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
| 1 | Done | Package owner groups reconciliation by installation, reuses immutable closures, and checks relevant dependency changes before source preparation. Remove repeated orphan scans and unconditional input reconstruction. | Upgrade orphan repair, activation changes, authority revocation, required clock ticks, exact dependency revisions, restart, and unchanged-input behavior. |
| 2 | Done | Graph owner checks headers, notices, exact heads, and witness deadlines before it loads retained graph rows. | Notice changes, expiry without new data, overlap replacement, package changes, restart, and exact result parity. |
| 3 | Done | Store owner maintains owned file and segment totals at file changes. Remove a full directory walk from each raw batch. Rebuild totals during recovery. | Capacity denial, disk reserve, rotation, deletion, database growth, restart, and ACK after durable commit. |
| 4 | Done | Graph derivation prepares common records, facts, revision, coverage, and datasets once per window. | Native and Wasm parity, per-model bounds, original input revisions, evidence ordinals, and exact outputs. |
| 5 | Done | Built-in graph computation indexes original facts by record once per evaluation. | Missing and conflicting facts, original ordering, exact evidence references, and detector parity. |
| 6 | Done | Follow retains its checked store revision and dependency selection. Remove dependency history scans when both remain unchanged. | Append replay, moving-window expiry, coverage changes, quiet revocation, and unrelated commits. |
| 7 | Done | Query owner constructs required event columns and applies supported simple predicates during extraction. Keep a complete fallback for complex statements. | Full row mapping, query parity, scope denial, evidence capture before pruning, empty append progress, and joins, ordering, and aggregate semantics. |
| 8 | Done | Installed package owner retains verified identities with immutable bundles. Authority checks current trust membership without rebuilding OCI layouts. | Changed-content denial, trust revocation, exact installed exports, native closure identity, and commit authorization. |
| 9 | Done | Retention uses the existing source index and removes a bounded eligible set per visit. Remove repeated global entry scans. | Current pin and required-progress checks, pressure, replay floors, recovery, and physical reuse. |
| 10 | Done | Capture owner retains verified immutable dispatches after recovery or admission. Remove intent file reads from idle diagnostic polls. | Durable intent before spawn, duplicate rejection, lease expiry, retirement floors, and recovery without a second spawn. |
| 11 | Done | Capture owner retains the verified spool cursor byte offset. Rebuild the offset once after reopen. | Replay, cursor changes, sequence denial, torn tails, and upload of the synced prefix only. |
| 12 | Done | Operation owners observe authority changes through events and reuse deadline monitoring. Remove per-read thread creation and authority polling. | Direct synchronous calls, shorter stage deadlines, cancellation, closed authority channels, cleanup, and commit checks. |
| 13 | Done | Query owner registers admitted built-in relations only. Store provenance methods return empty values for empty references after validation. | Hidden-source denial, alias provenance, cleanup, exact nonempty references, and empty input results. |
| 14 | Done | Built-ins reuse immutable declarations and their ports. Remove schema generation during computation. | Canonical descriptor and schema metadata, wire round trips, and native and Wasm parity. |
| 15 | Done | Guest invocation reuses validated inputs internally. Remove repeated contract passes inside one invocation. | Framing and FFI validation, checked standalone APIs, host output checks, evidence validation, cleanup, and error precedence. |
| 16 | Done | Control context owner projects committed changes and serializes a new record once. Retain startup replay. | Exact retries, failed-write retry, bounded replay, current revisions, and restart. |
| 17 | Done | Package store charges actual current encoded bytes. Remove decimal JSON size counting, its retained frame field, and obsolete quota bookkeeping. | Current format integrity, quota accounting, identical install retry, native dependencies, corruption, backup, restore, and recovery. |

## Verification and result

Use owner-local functional tests during implementation. Run
`bash .github/scripts/verify-rust-ci.sh` after the final relevant source edit.
Qualify current source-built native packages and the installed native detector
through the existing proof route. Preserve all current format and ABI checks.

No new performance test or benchmark is approved. Do not infer speed gains
from changed test-suite durations. Record removed work from the final source.
Measure latency only after approval of a specific workload and its limits.

Result: **Done**. All 17 changes are implemented and verified.

The final check ran on 2026-10-15. The source manifest contains 1,401 input
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
