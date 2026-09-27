# Raw Event Store Decision

The current data plan makes DuckDB the durable owner of raw events. This choice
needs a direct comparison with the existing Control segment store. The goal is
one durable copy of each raw event, direct discovery reads, durable results and
progress, scoped SQL, and bounded retention.

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
