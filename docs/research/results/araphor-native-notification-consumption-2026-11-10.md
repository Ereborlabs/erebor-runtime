# Native notification CDC completion

Result: **Done for optional native notification CDC completion and Host concern
delivery**. Production replacement remains **Not done**. Production still uses
DuckDB. No native incident speedup is measured.

The native Host starts its notification SQL definition through the existing
Subscription. The Session binds the actual running consumer. Progress registers
the optimized plan's input requests and durable saved position. Original Fjall
and raw journals supply matching unconsumed positions.

Data reads rows and seals NotificationCapture at one published view. The token
contains the actual instance and existing InputCapture. Consumer data is charged
before decode. The Router commits Pending batches before external delivery.
The final Data transaction saves remaining context versions, their exact
references, consumed progress, and one current completion receipt together.
Data publishes that view before it advances in-memory delivery. The sink then
acknowledges the actual execution receipt.

An exhaustive read can complete with zero SQL result rows. Partial coverage
does not complete. Input after the captured cut remains pending. A repeated
completed capture makes no receipt-only commit. A guard, lifecycle, or reference
failure rolls back the final batch. Interruption after Pending preserves the
same attempt and subject for restart.

Native format 7 adds the completion receipt. Reopen checks actual instance
lifecycle, consumer identity, the declared committed receipt, and immutable
context references at retained Data cuts. It does not open completed historical
WAL files. Completion and checkpoint writes alone do not wake a subscription.
Earlier native formats are rejected. DuckDB conversion is not implemented.

The shared Query worker now returns its value with its Engine and tracking
lease in one ordered tuple. Cancellation destroys an abandoned result before
it releases the lease. The existing DataFusion task owns that lifetime. A
deterministic gated test fails on the prior code and passes on the changed code
for both started and unpolled cancellation. Four test callers now use current
Session and package-runtime signatures. Their assertions and timeouts remain
unchanged.

## Verification

The [machine record](araphor-native-notification-consumption-2026-11-10.json)
freezes source hashes, engine commits, unchanged incident inputs, commands, and
logs. Formatting, default and native Analysis library checks, native Query
Clippy, and native Analysis Clippy pass. Clippy reports warnings; these are not
warnings-denied workspace checks.

The native runtime gate passes **139 tests in eight suites**, with no failed,
ignored, or filtered cases: 113 Data, nine Query, four Instance, and 13
notification cases. Five new notification cases cover following SQL input,
post-capture input, empty results, repeated completion, partial coverage,
reference rollback, lifecycle rejection, filtered traffic, checkpoint stability,
compaction, Pending interruption, corrupt receipts, and actual Host restart.
The Host case joins shutdown, immediately reopens the store, resumes its saved
consumer, and delivers new input without repeating the prior effect.

Data Clippy fails at two unchanged legacy Graph `expect` calls in
`analysis/managed/graph/projection/publish.rs:90` and
`analysis/managed/reader/committed/graph.rs:213`. Its failure is recorded.

Eleven targeted shared Query cases pass: three cancellation cleanup cases, six
progress cases, one guest lease case, and one prepared guest identity case.
These commands select their stated cases from the larger library suite.
The broader execution module has 48 passes and one failure. Its unchanged
registry assertion compares Engine with bare DataFusion defaults. The only
difference is Engine's existing `araphor_temporal_coverage` function; common
signatures match. The assertion and production registry remain unchanged.
The full native Query test compile check fails with 195 errors from SQL-bound
fixtures and missing native APIs, including trace storage. No native Query
library test pass is claimed. The separate native integration suite passes its
nine cases.

The unchanged production incident passes one selected case, with 694 other
cases filtered by its exact name. The harness takes **14.29 seconds**; the
process takes **14.354 seconds**. Its public subscription samples take
**491.102 ms**, **792.043 ms**, and **849.714 ms** from the unchanged test's
submit start. These samples do not measure collector receipt to durable
notification creation. The build takes 175.233 seconds. The machine record
includes the binary identity and build profiles. The restricted sandbox first
denies setup before the workload starts. The same binary passes outside that
sandbox with local test IPC enabled; both logs remain in the record.

The [prior cleanup failure](../../../output/araphor-fjall-migration-20261110/notification-run-lifetime-default-regression.log),
its [source preimage](../../../output/araphor-fjall-migration-20261110/notification-run-regression-sources.json),
the [cleanup pass](../../../output/araphor-fjall-migration-20261110/native-notification-consumption-final-worker-cancel.log),
and the [registry difference](../../../output/araphor-fjall-migration-20261110/notification-registry-failure.json)
support the shared failure explanations. The machine record includes their
hashes and the current native compile diagnostic.

This is a DuckDB correctness regression check. No native incident pass, matched
performance comparison, sub-100 ms durable creation, or 100-fold gain is claimed.

## Remaining work

These notification cases use concerns. They do not qualify actual Source/finding
delivery through the native Host. Affected-key reads, complete Source providers,
configured capacity, retention, collection, trace storage, backup, public Data
cutover, DuckDB removal, and both incident targets remain **Not done**. Full CI
does not run for this increment. No workload, assertion, or timeout in the
selected incident changes.
