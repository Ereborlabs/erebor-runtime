# Araphor Data Test Runtime Reduction

Reduce the time to run the complete `araphor-data` test suite. Remove repeated
fixture and preparation work first. Preserve the production owner calls,
assertions, workloads, durability checks, and deadlines that establish correctness.

## Intended end state

The complete Data suite runs faster on the same host and with the same build
profile and test concurrency. A retained report identifies the cost of fixture
lock waits, package preparation, store creation, recovery, and evaluation.
Every existing test remains in the required inventory. Timing improvements do
not replace functional proof.

The user approves ordered changes 1 through 5, then F1 through F7, including
independent fixture owners and the selected four-versus-eight-thread comparison.
The later [production plan](araphor-production-dataflow-simplification.md) and
[performance TODO](araphor-performance-simplification-todo.md) own subsequent
architecture changes. This plan adds no test framework or alternate runner.

## Implementation flow

An engineer starts the approved diagnostic run
  -> record the source, test binary, host, profile, and selected test names
  -> distinguish lock wait from fixture setup and actual evaluation
  -> record parent and child costs without counting child time twice
  -> rank repeated work by measured cost

An engineer changes one read-only fixture
  -> reuse the existing installed snapshot and compiled code facilities
  -> retain each original computation, input variant, and assertion
  -> keep mutable lifecycle and cold-start cases on their original paths
  -> run the affected existing cases before another full workspace run

A fixture change passes focused verification
  -> select the next correction from the measured cost report
  -> retain separate authorization, memory accounting, and durable-state owners
  -> stop if the correction requires a new ownership or trust-boundary design

The approved implementation is ready for qualification
  -> run the repository Rust CI procedure after the last covered edit
  -> obtain the new Data duration from that run
  -> compare the complete test inventory, results, and configuration
  -> record the measured improvement and any remaining slow cases

## Original approved corrections

| Order | Proposed change | Verification and stop point |
| --- | --- | --- |
| 1 | Measure the selected existing cases below. Separate lock wait, setup, bundle preparation, schema checks, recovery, SQL setup, and computation. | Obtain explicit approval for the diagnostic workload and runtime allowance. Produce a cost report before choosing larger changes. |
| 2 | Pin one installed snapshot when each read-only Discovery or graph fixture is initialized. Use the existing `InstalledAnalysis::snapshot` method. | Review every fixture caller. Exclude update, revocation, cache freshness, historical selection, and lifecycle cases. Preserve all evaluations and charged leases. Start with this small pilot. |
| 3 | Reuse the first graph snapshot already produced by `CommitFixture::new` when traversal builds window zero. Decode the corpus seed once per case and clone it for each record. | Preserve the traversal witness deadline adjustment, new request fields, and every commit. Static targets are nine redundant derivations, or 27 detector calls, and 10,312 redundant seed decodes. These counts are not time estimates. |
| 4 | Remove unused interface generation from runtime descriptor encoding. Reuse immutable builtin descriptor/schema templates where the measured report justifies it. | Preserve serialization bounds, canonical ordering, descriptor JSON bytes, artifact digests, validation errors, and owned copies for callers that modify descriptors. Author builds still generate complete WIT and headers. This reaches SDK and builtin owners and needs its own focused review. |
| 5 | Cache only successfully derived immutable expected graph schema data from the same SQL and DuckDB version. | Retain actual-schema comparison, column order/type/nullability, primary keys, unique constraints, corruption rejection, and failure behavior. Do not cache a transient initialization error, actual store validation result, or retained data. |
| 6 | Give independent cases separate execution owners and query budgets before narrowing or removing fixture mutexes. Reuse existing compiled code and eligible immutable package inputs. | Do not remove a mutex from a shared mutable owner or increase quotas to avoid Busy errors. Measure fresh-owner cost against lock wait. Preserve authority state, checkpoints, guest stores, and cleanup. |

Row 6 was approved as F7. The later rows below define its isolation rules.
The original source findings and diagnostic records remain at
`7b7b407adf347d389984553a4d212bfce37b75b5:docs/plans/araphor-data-test-runtime-reduction.md`.
The original Data suite has 633 tests: 614 passed and 19 ignored. Its recorded
run took 2,157.82 seconds with four test threads. Long-test warnings include
mutex wait; they are not CPU measurements and are not additive suite costs.

## Approved follow-up corrections

| ID | Implemented change | Boundary and proof |
| --- | --- | --- |
| F1 | Compile Data and SDK tests at optimization level 1. | Keep debug assertions, overflow checks, features, workloads, and ignore status. Guest compilation stays unchanged. There is no serialization or hashing dependency override. |
| F2 | Reuse the admitted immutable bundle for final Run inspection. | Match exact root and revision; retain current activation, authority, freshness, dependency order, and replacement handling. Add no persistent cache. |
| F3 | Stream encoding into size or hash sinks when callers discard bytes. | One canonical serializer retains order, digest, exact limits, partial-write behavior, overflow checks, and flush errors. The later OCI and actual-byte storage decisions replace the earlier JSON counting path. |
| F4 | Compare an identical installed revision before encoding its candidate again. | Keep semantic equality, immutable collision checks, validated content, and transaction decisions. The user subsequently removes package caps and their cap-only error tests. |
| F5 | Prepare durable packages in the Discovery crash parent; compile only the required library in each child. | Keep six real exits: two sealing modes and three crash points. Keep package references, synchronization, cold reopen, recovery, and dedicated cold-install/compiler/cache cases. No native substitute or machine-code cache is added. |
| F6 | Pin eligible read-only fixture packages. | Keep update, authority, historical, expiry, and cache-freshness cases unpinned. Separate tenant snapshots. The shared fixture constructor remains unpinned. |
| F7 | Give independent cases separate stores, execution owners, grants, query budgets, guest state, and checkpoints. Share immutable compiled code only. | A clone still shares budget; it cannot justify removing a mutex. Do not raise quotas to avoid Busy. Preserve cleanup and every original window computation. |

### F1: Test build profile

The approved nine-case comparison uses four threads. Both sources pass every
case with identical 633-test inventories. The recorded durations are 473.97
and 442.83 seconds. The selected profile retains debug assertions and overflow
checks. A temporary JSON dependency override started a DuckDB C++ build and
was removed before tests. No clean build-cost comparison is established.

### F7: Approved thread comparison result

Both runs pass the same nine cases at `e31b033e`, with one binary. Four threads
take 360.39 seconds; eight take 394.92 seconds. Each run stays within its approved
900-second allowance. There is no speed pass/fail threshold. The configuration
retains four threads. Other host load and filesystem caches are uncontrolled.
The record is `/tmp/araphor-f7-comparison.json`, with matching `-4.log` and
`-8.log` files. No timing test or alternate runner is added to the repository.

## Complete Data qualification

### Final functional qualification

The final repository procedure passed with exit 0 at
2026-10-14 21:22:34.631003 UTC. The covered Rust source is commit
`e31b033ebf95224e8210c73cec5abed4e8149def`. All 1,392 covered Rust, Cargo,
and CI file hashes remained unchanged. Formatting, workspace checking, strict
clippy, and all workspace test harnesses passed.

The 90 parent harnesses reported 2,122 passed, zero failed, and 568 ignored.
Data passed 621 cases with the same 19 ignored cases. Its complete inventory
contains all 633 original cases and seven added regressions. SDK has three
added writer regressions. No original case or assertion was removed.

| Recorded run | Data seconds | Data inventory |
| --- | --- | --- |
| Original qualified source | 2,157.82 | 633 |
| Earlier preparation corrections | 1,390.41 | 633 |
| Current qualified source | 1,471.15 | 640 |

The current Data duration is 24 minutes 31.15 seconds. The complete procedure
took 2,679.10 seconds: 44 minutes 39.10 seconds. Workspace checking took
54.57 seconds. Strict clippy took 246 seconds. The cached test build took
1.21 seconds. Host load and file-system caches were not controlled between
the complete runs. Their difference does not establish that a source change
makes production execution slower or faster. No causal saving is claimed.

Read `/tmp/araphor-f-final-ci-source.json`, `/tmp/araphor-f-final-ci.log`,
and `/tmp/araphor-f-final-report.json` for terminal and inventory evidence.
The four/eight thread comparison remains the selected nine-case result above.
A clean build-cost comparison remains unmeasured. Temporary diagnostics and
comparison wrappers are not repository test infrastructure.

| Deliverable | Code commit |
| --- | --- |
| F1 | `d1b4b507` |
| F2 | `b2522b4e` |
| F3 | `c405170d` |
| F4 | `245e3527` |
| F5 | `7a67f700` |
| F6 | `98bf337a` |
| F7 | `e31b033e` |

**Done** for all seven approved implementations, focused proof, the approved
thread comparison, and final functional qualification. A controlled complete
production performance comparison is **Not done**. The user now requests
structural simplification in production. That work requires its own concrete
architecture and qualification scope.

The [review guide](araphor-data-test-runtime-review.md) owns the current fixture
source route. Current deletion work requires its own qualification; the source
receipts above cannot qualify later edits. No controlled complete production
performance result is established.
