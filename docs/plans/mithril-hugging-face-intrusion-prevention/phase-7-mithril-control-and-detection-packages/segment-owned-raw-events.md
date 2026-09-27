# Raw Event Storage: Mid-Implementation Choice

**Status: Open.** This note does not change the implementation plan. Compare
the work left from the current source tree, not the work that either design
would have required before implementation began.

## Current state

`ControlConfig::into_parts` already opens `AnalysisStore` and rejects a Control
store with accepted raw evidence. `EvidenceIntakeOwner` commits raw events and
source receipts to DuckDB. If the data owner cannot open, Control keeps the
policy service available but does not fall back to segment intake. The old
segment writer and reader still exist in code; their retirement is unfinished.

`araphor-data` already has raw intake, result/progress/reference transactions,
retention, recovery, backup, and restore. The new query and discovery owners
are not implemented there yet. The old discovery code reads Control segments
and writes export artifacts that include raw records; it is not the consumer
of configured DuckDB intake. Removing that archive remains part of the later
discovery conversion, whichever raw store we choose.

## Options from this point

| Path | Advantages from today's code | Work and risk still ahead |
| --- | --- | --- |
| Finish the DuckDB raw owner in 7.2 | Keep the configured intake and the implemented receipts, result/progress/reference commits, row retention, recovery, and backup. Raw rows and generic results share one transactional database. The planned remote mode can move the same data owner. | The full-capacity test exceeded the 256-MiB process gate. Full-capacity gRPC, load, physical qualification, and old-writer retirement remain open. Direct raw-store throughput and memory were worse than the old segment path in a small test. Physical space reclamation needs proof. |
| Replace DuckDB raw storage with a segment-backed data owner | Reuse lessons and code from the old segment writer and reader. A direct release test shows a raw write/read advantage. Keep one raw copy and use DuckDB for derived state or isolated SQL if it remains useful. | This reverses configured intake work. Adapt or move segment ownership into `araphor-data` to preserve the approved embedded/remote boundary. Rework source receipts, coverage, retention, witness pins, backup, recovery, and capacity. Specify how result/progress commits and segment deletion remain crash-safe. Measure selective SQL extraction and pinned-segment space. Qualify the replacement against the same gates. |

Keeping the old Control segment writer unchanged and changing only discovery is
not a third complete option. It would reverse the configured intake path while
leaving consumption-based raw deletion, historical queries, and exact witness
retention unsolved. A segment backend need not remain in Control; the remote
read penalty in the earlier note applied only to that one placement choice.

## Evidence and decision gate

The [direct-store comparison](raw-event-store-decision.md) used matched release
inputs and favored old segments for raw writes and reads. Removing the DuckDB
raw-event index did not close that gap. The test called different production
owners and omitted retention, discovery, SQL, mTLS, and concurrent load. It
cannot rank completed systems. The [current phase result](phase-7-2-data-store.md)
records a failed full-capacity DuckDB memory gate. It does not qualify a
segment-backed replacement at that capacity.

The next useful step is bounded: identify whether the current DuckDB owner can
meet the unchanged memory gate without weakening durability or retention; in
parallel, specify the smallest segment-backed `araphor-data` change that meets
the same retention, witness, query, and crash contracts. Compare the remaining
implementation work and run the same end-to-end limits before choosing. Do not
build two complete raw owners or add a dual-write path to make this decision.
Count remaining work, risk, and qualified behavior. Do not count sunk work as
a reason to keep DuckDB.
