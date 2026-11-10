# Native lifecycle and activation, 2026-11-10

Result: **Done for native Data lifecycle and original-log activation**.
Production Control and Analysis still use DuckDB. Their native binding,
remaining storage owners, notification delivery and acknowledgement,
configured capacity, retention, backup, cutover, DuckDB removal, and both
incident performance targets remain **Not done**.

Native Data now supports renewal, suspension, admission-failure recording,
version preparation, removal, recreation, and history reads. The operations
use the existing native transaction records. Pending-work guards preserve
the existing error contracts. Exact retries run the caller guard and do not
advance the Data revision. Exact version retries verify retained Graph
mappings without repair.

Activation subscriptions drive the shared original journal reader. The reader
decodes instance records at committed batch snapshots. A lifecycle equal to
that batch's Data revision advances the activation position. Raw input,
context commits, ordinary result progress, and diagnostic failures do not
cause activation. Input registration and rewind preserve unread activations.
No producer sends activation messages. No new worker, journal, or durable
activation table is added. Package input positions remain durable; host
bootstrap reads current membership at its captured cut.

Public native Data tests qualify actual version promotion and rollback to an
older retained generation. Lifecycle and progress advance during rollback.
The tests also qualify guard rollback, pending-work behavior, removal,
recreation, retained history, consumer retirement, and reopen. Recovery checks
exact current progress and call heads against successful receipts. The
pending-only history authorization case uses a separate stored-record fixture;
normal scope-changing APIs do not produce that case.

The final frozen-source gate passes **120 tests in 11 suites**. No test fails,
is ignored, or is filtered. The test command takes **42.542 seconds**, including
build work. Selected-file formatting and the default Query library check pass.
All 18 source hashes match before and after the gate. Both selected workload
hashes remain unchanged. The test log SHA-256 is
`fbf3706dc80d9d603a8a90075c5195010729d7830b1fd5788b44f05eef41439f`.

Read the [machine record](araphor-native-lifecycle-2026-11-10.json) for commands,
source hashes, engine commits, and log paths. Read the
[source guide](../../guides/araphor-native-data-review.md#native-lifecycle-and-activation)
for the review route. The
[test log](../../../output/araphor-fjall-migration-20261110/native-lifecycle-tests.log)
contains all suite results.

This gate does not qualify the production Analysis host or sink. The selected
incident is not rerun. No native production speedup is measured. Full CI does
not run.
