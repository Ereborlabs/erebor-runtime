# Native subscription startup and version changes, 2026-11-10

Result: **Done for optional native subscription startup and version changes**.
Production Control and Analysis still use DuckDB. Production host and sink
binding, notification delivery, remaining storage owners, capacity, retention,
backup, cutover, DuckDB removal, and both incident targets remain **Not done**.

Finite Query execution uses temporary input registration. It does not create
or acknowledge a durable consumer. Version promotion and rollback restore the
target generation's source state. A following execution waits at its saved
cursor only when durable completion covers that cursor.

First following execution after finite processing can have no completed input.
An older generation can also retain completion before a later finite cursor.
Query restores the existing historical source index in both cases. Data records
the complete contiguous restoration in the same input handle. The temporary
replay head contains one result reference and position. It contains no raw
payloads or Arrow batches. No new durable record, worker, archive, or scan is
added. Normal restoration skips this observation when durable completion
already covers the final parent.

Data checks exact input demand and source scope. A complete initial frame
establishes coverage. A change frame extends coverage from its exact parent.
Duplicate, older, and gapped frames do not allocate proof memory. Record decode
and retained proof use the caller budget. Historical observation never advances
durable progress. Only complete successful live publication advances progress,
with the package results and Graph changes in the existing Data transaction.

Six new Query cases qualify finite versions, indexed versions, finite execution
between following executions, first following execution, old-generation
revival, and failed bootstrap retry. The retry case checks guard rejection and
a real stale-completion admission conflict. The latter case resumes through
`SourceRecovery` with the same prepared plan and memory owner. Both retry paths
leave post-capture raw cursor 3 outside the first consumed cut at cursor 2.
The first-follow case closes and reopens the store, verifies saved completion,
and consumes the next matching input after the temporary replay head is gone.
One new Data case checks full and partial coverage, real contiguous and gapped
source chains, old frames, and memory failure.

The frozen-source gate passes **127 tests in 11 suites**. No test fails, is
ignored, or is filtered. The test command takes **138.555 seconds**, including
build work. Selected-file formatting and the default Query library check pass.
All 20 source hashes match before and after the gate. The incident and default
definition hashes remain unchanged. The test log SHA-256 is
`49eb092ae77856121caca85c6d898f1ca950fbf6955aa99d49908364f0d51a11`.

Read the [machine record](araphor-native-startup-2026-11-10.json) for source
hashes, commands, engine commits, and log paths. Read the
[source guide](../../guides/araphor-native-data-review.md#native-subscription-startup-and-version-changes)
for the review route. The
[test log](../../../output/araphor-fjall-migration-20261110/native-startup-tests.log)
contains all suite results.

A separate production Analysis check enables `araphor-query/native-store`.
The command fails with 30 compiler errors. The errors identify concrete host
and sink type changes, activation-handle changes, capacity waiting, Discovery
processor operations, frozen Graph reads, and Graph/profile commit methods.
The [binding log](../../../output/araphor-fjall-migration-20261110/native-analysis-binding-check.log)
records these errors. This check confirms that native Query qualification does
not qualify production Analysis.

The production incident does not run for this increment. No native production
speedup is measured. Full CI does not run.
