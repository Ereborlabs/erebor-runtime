# Segment-Owned Raw Events: Design Alternative

This note records an architecture alternative. It does not change the current
implementation plan or select a raw-event store. The storage comparison is in
[raw-event-store-decision.md](raw-event-store-decision.md).

## Separate the decisions

Removing discovery's duplicate raw archive, retaining evidence for later
investigation, and choosing DuckDB as the raw-event store are three different
decisions. The first two do not require the third. The existing Control segment
store should have been assessed as the baseline before a raw-storage rewrite.

## Segment-owned design

```text
Authenticated Node intake -> Control commits one raw copy in segments -> ACK
                           -> discovery reads committed segment pages
                           -> one results transaction commits derived state,
                              processing progress, and exact evidence references
                           -> retention checks progress and references
                           -> scoped SQL reads bounded segment input
```

Discovery must not copy every raw event into another archive. It can replay
committed pages from its last committed cursor after a crash. The results store
must commit each derived change with the cursor and evidence references that
justify it. Otherwise, a saved cursor could skip a missing result. The segment
reader and the results store remain separate durable owners; this design needs
an explicit protocol between result commits and segment reclamation.

## Contracts this design still needs

- Consumption is not permission to delete raw input. Retention must bound
  history by age and size, protect unprocessed required input, and retain exact
  events cited by findings or review. A derived count cannot reconstruct a
  purged command, its arguments, or its policy decision. Optional discovery
  lag must not pin all raw input.
- The retention owner must not remove a segment based on stale progress or
  references. It needs a stable eligibility decision across the raw and result
  owners, plus recovery after a crash during reclamation.
- One retained event may keep an entire segment. Segment compaction or witness
  extraction could reduce that cost, but each adds code and recovery work.
  Select and measure a policy before claiming fine-grained retention.
- SQL can run in an isolated DuckDB worker over authorized, bounded records
  extracted from the segments. A bounded DuckDB table-function adapter is
  another option, but Araphor would own that adapter. DuckDB need not own the
  raw records. Historical selection by workload or time may scan and decode
  too much input; measure that cost before adding metadata or an index. The
  existing [query plan](phase-7-3-query-and-follow.md) already separates input
  selection from SQL execution.

## Decision boundary

Reading segments directly is enough to remove discovery's raw-event
duplication. It is not enough to leave the old consumption-based purge rule
unchanged. DuckDB can make row retention and result transactions easier, but
SQL support alone does not require it to own raw events. Neither a DuckDB index
failure nor a direct store benchmark settles the full query, retention,
witness, and crash-recovery contracts. Keep both designs open until those
contracts have implementation and end-to-end proof.
