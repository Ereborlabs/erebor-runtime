# Raw Event Storage: Selected Segment Design

**Decision: Option 2 approved.** Raw events and trace output live once in
segments. The original segment writer runs inside `araphor-data`, not Control.
Synced segments are authoritative for raw acceptance and replay. DuckDB holds
a rebuildable raw catalogue and transactional derived state and runs
isolated queries over bounded authorized input. The implementation belongs to
[7.2](phase-7-2-data-store.md); shared contracts are in
[engine-design.md](engine-design.md#embedded-storage-and-query-contract).

## Why this choice

Removing discovery's duplicate raw archive does not require a raw database.
Discovery reads committed segments and commits results, progress, and exact
evidence references together. Reuse the existing segment codec and bounded
reader in araphor-data. Do not leave the raw owner in Control or create a
separate discovery archive.

The selected design must meet query and evidence-retention requirements
without becoming a custom storage engine. Start with batch-range metadata,
whole-segment deletion, and bounded extraction. No per-event raw index,
background compactor, witness archive, dual write, or backend framework.

## Benefits and costs

| Choice | Benefit | Cost or limit |
| --- | --- | --- |
| Selected: original segment writer plus transactional derived state | One raw copy; reuse append/read/recovery code inside araphor-data; no database transaction per raw ACK; one embedded or remote data component. | Rebuildable catalogue publication, pin/delete coordination, complete backups, and scan bounds need proof. One witness can retain a whole segment. |
| Raw and derived rows in DuckDB | One database transaction can coordinate raw rows and results; logical retention can select individual rows. | The tested implementation had lower raw throughput and failed its capacity memory gate. SQL alone does not require this raw format. |
| Change only old discovery | Removes the duplicate archive with the narrowest algorithm change. | The old consumption-based deletion contract does not provide historical retention, witness protection, portable ownership, or bounded query selection. |

The [release comparison](raw-event-store-decision.md) supports raw segments as
a candidate; it does not qualify the combined design. Catalogue updates use
bounded groups outside raw acceptance. Measure the complete owner before
claiming the required latency and throughput. Do not replace DuckDB with SQLite
or move the raw owner back into Control.

## Acceptance boundary

7.2 must prove durable ACK, tail recovery, result/progress atomicity, bounded
whole-segment pin cost, complete backup/restore, and bounded authorized input
extraction. 7.3 proves SQL and follow over those reads. 7.4 removes the old
copied raw export while converting discovery. Observability 2 uses the same
raw-output storage protocol; optional 7.9 moves the whole component.

If scan or pinned-space limits fail, report the workload and failed limit.
Request the smallest design change before adding an index or compaction.
Do not silently revert to DuckDB raw rows or claim that safe query rejection
satisfies the required bounded-window case.

## Implementation status

**Not done.** The database-independent raw ACK path requires implementation.
Complete-bundle backup and guarded recovery are
implemented. Bounded extraction is implemented. The old Control raw writer and
its callers are removed. The complete workspace gate and paired disk-full case
pass for this source. Release measurements and Kubernetes qualification remain
incomplete. See the current 7.2 result.
Use fresh development state; no compatibility import or migration is required.
Tests use temporary stores. This decision does not authorize removal of
existing deployment data.
