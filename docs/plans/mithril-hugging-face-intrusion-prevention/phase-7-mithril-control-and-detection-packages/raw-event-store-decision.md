# Raw Event Store Comparison

The current data plan proposes DuckDB as the durable owner of raw events. This
proposal needs a direct comparison with the existing Control segment store.
The goal is one durable copy of each raw event, direct discovery reads,
durable results and progress, scoped SQL, and bounded retention.

## Existing behavior

The Control store writes raw event bytes to segment files. It keeps batch ranges,
source cursors, and frame offsets to find those bytes. The current discovery
path reads the segments and copies raw records into discovery export artifacts.
The DuckDB intake path writes each event once to the `events` table. Intake
selects either writer; it does not write each event to both. The old discovery
consumer still reads Control segments. The planned consumer conversion is not
complete.

The `events` primary key creates a DuckDB ART index on `(stream_key,
durable_cursor)`. The Rust writer also checks retained retries for identical
bytes or conflicting content. The ART index gives a second uniqueness check,
but it is not needed to calculate discovery results. A large checkpoint failed
while DuckDB rebuilt this index. A larger native memory target then exceeded
the 256 MiB process memory gate. Neither result compares the two store designs.

## Alternative to test

Keep the existing segment writer as the only raw event owner. Make discovery
read committed segment pages and store only derived results, processing
progress, and references to selected raw events. Execute authorized SQL over
bounded records read from the segments. Keep the SQL worker separate from
the raw writer.

This choice still needs an explicit retention contract. Consumption alone
cannot delete an event that a required processor or a retained witness needs.
Result and progress commits must survive restart together. Segment reclamation
must preserve referenced events. Queries need bounded reads by source, time,
and scope. Measure the cost of scans and any segment metadata before adding
new indexes or a second raw archive.

## Decision test

Use identical framed records, batch sizes, source identity, and storage device.
Run each store in a separate process. Measure durable write rate and batch
latency, bounded read rate, restart time, peak process memory, and physical
bytes. Compare at more than one retained event count. State whether the run
includes gRPC, discovery, retention, and concurrent readers. Record failure
limits as well as successful rates.

Choose a raw owner only after the same workload meets the intake, query,
retention, witness, and recovery contracts. A small throughput win cannot
replace those checks. Keep the current phase plan in force until this choice
is reviewed.

## Direct store comparison

The ignored `store::raw_bench::raw_event_store_comparison` test feeds the same
framed records to each production store API. Each batch has 256 records. One
source sends consecutive batches. The test prepares records before timing,
measures each durable store call, closes and reopens the store, then reads and
decodes every record in pages. It checks each record's cursor. The legacy read
uses `begin_evidence_read` and `read_evidence_page`. The DuckDB read uses
`read_page` and decodes the returned frames. One store runs per process.

The test ran in the owned VM `mithril-runtime-qualification-2249801`: four
virtual CPUs, Linux 6.8.0-142, ext4, no swap. It used release builds, default
store limits, no allocator override, and no concurrent benchmark. DuckDB used
the current 160 MiB engine target and 16 MiB checkpoint threshold. The final
test executable SHA-256 was
`34824977af630a4dcdc1ec4673b7e02800a959db6407a46a2bd03712ce6f913b`.
Both stores accepted and returned all records after reopen.

| Store | Events | Write events/s | Write p95 ms/batch | Read events/s | Reopen ms | Peak RSS KiB | Allocated bytes after reopen |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Segments | 16,384 | 92,318 | 3.209 | 573,085 | 11.135 | 17,944 | 2,310,144 |
| DuckDB | 16,384 | 17,046 | 16.914 | 95,239 | 58.308 | 59,336 | 4,468,736 |
| Segments | 262,144 | 99,163 | 2.963 | 577,597 | 130.070 | 81,528 | 37,466,112 |
| DuckDB | 262,144 | 10,797 | 30.960 | 62,202 | 243.424 | 189,336 | 30,945,280 |

The 262,144-event input contained 37,445,318 framed bytes in both runs.
Before close, the segment files occupied 37,466,112 allocated bytes and
DuckDB occupied 42,061,824. DuckDB fell to 30,945,280 after its close and
checkpoint. These counts use each file's allocated ext4 blocks. The earlier
release executable, before the allocated-block counter was added, repeated
the large case in both run orders. It measured 85,456 to 95,392 write
events/s for segments and 9,608 to 10,364 for DuckDB. The direction of the
gap did not depend on run order.

This workload favors the segment writer by about nine times for direct writes
and reads at 262,144 events. DuckDB used about 17 percent fewer allocated
bytes after close at that size. The experiment does not include mTLS, multiple
sources, concurrent readers, context, coverage, retention, discovery, SQL,
or power-loss recovery. The prior full-capacity DuckDB memory failures remain
separate evidence.
The store choice is still open until the query, retention, witness, and
recovery work for the segment alternative is estimated and tested.

## Unindexed raw table check

A second release executable removed only the `events` primary key and its
index. Its SHA-256 was
`5036e94a2500986eef59e0208ceae09119dde5f7cf268eb39ac0903a2699d68f`.
Both store modes ran from that executable on the same VM with 262,144 events.
Two runs in reverse order measured 78,644–97,091 write events/s and
550,045–592,725 read events/s for segments, versus 10,216–11,192 write
events/s and 63,490–70,725 read events/s for unindexed DuckDB. An indexed
DuckDB release rerun on that VM measured 11,499 write events/s and 65,274 read
events/s. Removing the raw index did not close the direct-store gap. It also
removed the database uniqueness constraint. The schema change was restored
after the benchmark. This run still excludes SQL, discovery, retention, and
crash recovery.
