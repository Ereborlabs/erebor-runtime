# Raw Event Store Alternatives

**Status: Open.** The target needs one durable raw-event copy, direct discovery
derivation, historical evidence access, scoped SQL, and bounded retention.
Removing discovery's duplicate raw archive does not decide which store owns the
remaining copy.

| Approach | Benefits | Costs and gaps |
| --- | --- | --- |
| Keep the current segment store unchanged; change only discovery | Smallest change to remove discovery's raw archive. Reuses intake, ACK, replay, and segment reads. | The current consumption watermark can reclaim raw input. A derived count cannot recover a purged command or policy decision. Historical query and witness retention remain unmet. |
| Evolve the segment store as the sole raw owner; keep derived state and SQL in the data crate | Reuses the existing durable intake path. Direct release tests favor segment writes and reads. Discovery can derive from committed pages without another raw archive. DuckDB can still evaluate bounded SQL. Embedded mode needs no new service. | Results, progress, and witness references commit in a separate store from raw input. Reclamation needs a crash-safe protocol. One witness may pin a whole segment. Selective historical queries may require costly scans or new segment metadata. Optional remote data placement needs a read/replay contract with Control. |
| Make DuckDB the sole raw and derived-data owner, as the current plan proposes | Raw rows, receipts, progress, results, and witness references can share transactions. Row-level expiry and bounded extraction use one data owner. The complete data component can move to the optional remote process. | Direct raw writes and reads are slower in the measured workload, with higher process memory. Checkpoint and physical reclamation need qualification. The intake and recovery cutover is a larger rewrite. Row deletion does not guarantee immediate disk reuse. |

Keeping the old purge rule and changing only discovery is not a complete
solution. The two viable designs both need age and byte limits, protection for
required processors, exact witness retention, and explicit gaps after expiry.
Both can remove discovery's duplicate raw archive. Neither needs a second raw
event store. The current [query plan](phase-7-3-query-and-follow.md) already
extracts bounded, authorized input before SQL execution, even when DuckDB owns
the raw rows.

## Provisional test order

Test the evolved segment design first. It keeps the existing intake owner and
avoids a raw-storage cutover while preserving DuckDB for derived data and SQL.
The [direct store comparison](raw-event-store-decision.md) supports its raw
throughput advantage, but does not measure a complete system. Removing the
DuckDB raw-event index did not close that gap in a separate release run.

Two risks could reverse this recommendation:

1. **Retention and recovery:** Commit each result, processor cursor, and exact
   reference together. Prove that segment reclamation cannot race those commits
   or lose a required witness after restart. Measure bytes retained when a
   small number of cited events pin segments. If this needs extensive
   compaction or another raw copy, the segment advantage may disappear.
2. **Query and placement:** Run the same authorized historical queries and
   follow cases through bounded segment extraction and the isolated SQL worker.
   Measure scanned bytes, latency, memory, and remote-read cost. If selective
   queries need a large secondary index or cannot meet the existing limits,
   DuckDB raw ownership may be simpler overall.

Compare both designs under the same intake, query, retention, restart, memory,
and disk limits. Testing segments first does not select a raw owner, approve a
replacement, or change the current implementation plan.
