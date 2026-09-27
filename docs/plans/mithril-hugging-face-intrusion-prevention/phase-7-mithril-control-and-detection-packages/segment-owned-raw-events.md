# Segment-Owned Raw Events: Decision Note

**Accept for evaluation:** Keep one raw segment store, let discovery derive
directly from it, and add the retention and query contracts the product needs.
**Reject:** Keep the old consumption-based purge rule and change only discovery.
The segment design could have avoided much of the raw-storage rewrite, but its
full-system performance and complexity are not proven.

These are separate decisions:

1. Remove discovery's second raw-event archive. Discovery can read committed
   segment pages and store derived results instead of copying every event.
2. Retain and query evidence after discovery consumes it. A derived count
   cannot recover a purged command, its arguments, or its policy decision.
3. Choose the durable raw-event owner. The first two decisions do not require
   DuckDB to own raw events. SQL can run over authorized, bounded segment input.

The segment design keeps the current authenticated intake, durable ACK, and
segment reader. Discovery commits each result, processing cursor, and exact
evidence reference in one results transaction. On restart, it resumes from
that committed cursor. Retention must bound history by age and size, then
check required-processor progress and live references before it reclaims raw
input. Consumption alone is not a deletion boundary.

The choice remains open until we prove four costs:

- **Crash safety:** Coordinate result commits with segment reclamation across
  the two durable owners. A crash must neither skip a result nor delete an
  event still needed by a processor or witness.
- **Witness retention:** One cited event may pin a whole segment. Measure that
  cost before choosing whole-segment retention, compaction, or extraction.
- **Queries:** Measure how many segment bytes must be read and decoded for
  bounded searches by tenant, source, workload, and time. DuckDB can be the
  query worker without being the raw-event store.
- **Whole-system cost:** Compare intake, query and follow latency, retention,
  restart, memory, and disk under the same workload. A raw write/read benchmark
  alone does not select the architecture.

The current plan still selects DuckDB. This note does not change that plan.
See the separate [storage comparison](raw-event-store-decision.md) for measured
raw-store results and their limits.
