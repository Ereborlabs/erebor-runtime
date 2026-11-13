# Batch keyspaces, metadata, and native codecs

Source: `b9776e57d`. Result: **Done** for this benchmark-only investigation. All 32 measured runs, four CLI smoke runs, and four focused tests pass. Production and both engine forks are unchanged.

The results support small changes to a future table layout. They do not justify a complex production metadata rewrite for performance. Native compression gives the clearest initial space reduction. Production already uses the RawCommit codec that this experiment compares with the older table PoC codec.

## Intended end state

Measure simpler keys, receipts, state, and batch encoding in the existing Fjall table PoC. Keep all event bytes, positions, two durable commit boundaries, saved references, history checks, and original-journal resume. Report suggestions before any production change.

## Source review and flow

[Tables::append](../../../crates/araphor-data/src/analysis/native/benchmark/tables.rs) accepts a prepared 256-record batch
  -> [Tables::receipt](../../../crates/araphor-data/src/analysis/native/benchmark/tables/metadata.rs) reads the same source ACK, CPU, coverage, and retained floor.
  -> [Tables::append](../../../crates/araphor-data/src/analysis/native/benchmark/tables.rs) checks source identity, epoch binding, and contiguous input.
  -> [Tables::append](../../../crates/araphor-data/src/analysis/native/benchmark/tables.rs) commits the batch, receipt, and state in one native SyncAll transaction.
  -> [Store::consume](../../../crates/araphor-data/src/analysis/native/benchmark.rs) reads the input and commits the common result, reference, and consumed cut in another transaction.
  -> [Tables::consume](../../../crates/araphor-data/src/analysis/native/benchmark/tables.rs) preserves the consumed-cursor comparison before commit.

[Tables::replay](../../../crates/araphor-data/src/analysis/native/benchmark/tables.rs) starts at a saved original-journal cursor
  -> The reader selects the requested source and events keyspace.
  -> The reader checks the event revision against the head in that same committed journal batch.
  -> [raw_owner_bench](../../../crates/araphor-data/examples/raw_owner_bench.rs) verifies original bytes, positions, history, reopen, and continued input.
  -> The separate collection scenario acknowledges only the durable saved cut, collects an old journal, and verifies history and later input again.

## Layouts

| Item | Existing compact batch PoC | Packed metadata variants |
| --- | --- | --- |
| Event key | Source ID 8 + first cursor 8 | Same 16-byte key |
| Source receipt key | Full 73-byte identity key | Source ID 8 |
| Receipt value | Identity, CPU, ACK, coverage, floor | CPU, ACK, coverage, floor; identity remains in the catalogue |
| State | Six live keys | One row with head, events revision, receipt revision, binding revision, consumed cursor, next source ID |
| Intake and result commits | Separate SyncAll boundaries | Same boundaries |
| Epoch and source ID bindings | Persisted and checked | Same bindings and checks |

All variants keep seven real keyspaces: events, source_receipts, source_epochs, source_ids, sources, benchmark_state, and benchmark_results. The experiment does not combine tables into key prefixes or create a branch per table. Source/cursor identity stays outside native engine revision encoding. A numeric source ID is registered in the same transaction as its first input.

The metadata condition keeps the existing table MessagePack batch codec. The frame condition then uses the existing production RawCommit frame, CRC, protobuf decode, canonical re-encoding, and validation. It does not remove canonical validation or promise zero-copy reads. The final condition changes only public data/index block compression policies to all-level LZ4. The WAL remains at its unchanged default LZ4 threshold 4096; no engine patch or second binary is used.

## Matched measurements

Each condition uses the existing 16,384 or 262,144 events, 256 events per transaction, and the same 32-byte result body. The large input has 37,445,318 original framed bytes in every run. Four balanced orders run at each count. One frozen release binary runs 32 fresh processes. All samples remain; no run is excluded or replaced.

| Core events N | Layout | Intake events/s | Cycle events/s | Initial allocated MiB | After collection, MiB |
| ---: | --- | ---: | ---: | ---: | ---: |
| 16,384 | Existing compact batch PoC | 327,597 | 190,581 | 3.523 | 0.695 |
| 16,384 | Packed metadata | 344,166 | 199,474 | 3.500 | 0.695 |
| 16,384 | Packed metadata + RawCommit | 349,384 | 209,110 | 3.480 | 0.684 |
| 16,384 | Same + native SST/index LZ4 | 343,864 | 199,368 | 1.699 | 0.629 |
| 262,144 | Existing compact batch PoC | 330,866 | 193,700 | 53.277 | 8.070 |
| 262,144 | Packed metadata | 335,454 | 197,065 | 52.938 | 8.059 |
| 262,144 | Packed metadata + RawCommit | 351,441 | 203,332 | 52.648 | 7.957 |
| 262,144 | Same + native SST/index LZ4 | 344,829 | 200,309 | 23.646 | 7.887 |

Intake rate uses summed acceptance times per run. Cycle rate also includes capture, input read, and result/reference/progress commit. Rates are medians of four per-run rates. Initial allocation is measured at N events after forced maintenance and before first reopen. Collection measurements contain N+512 events in every condition; the extra batches are outside the timed core.

Do not attribute the entire initial-to-final decrease to collection. Reopen, further appends, and flush occur before the before-collection snapshot. Native table lifecycle cleanup can occur in that interval. The separate before/after values below measure collection at the same event count.

| Layout at N=262,144 | Before collection MiB | After collection MiB | Cycle p50 / p95 ms | Maximum ms |
| --- | ---: | ---: | ---: | ---: |
| Existing compact batch PoC | 16.324 | 8.070 | 1.380 / 1.565 | 6.520 |
| Packed metadata | 16.090 | 8.059 | 1.364 / 1.560 | 7.247 |
| Packed metadata + RawCommit | 15.891 | 7.957 | 1.331 / 1.496 | 6.830 |
| Same + native SST/index LZ4 | 15.820 | 7.887 | 1.351 / 1.522 | 6.558 |

Packed metadata changes median intake by 1.39% and cycle rate by 1.74%. The fourth pair is slower for both. After collection, it saves only 12 KiB. These results do not establish a useful production throughput gain.

RawCommit changes median intake by 4.77% over the metadata condition, with higher intake in all four pairs. One cycle pair is slower. Reopened scans are lower in all four pairs. This is a tradeoff between existing codecs, not a production speed claim.

Native SST/index LZ4 changes initial allocation from 52.648 to 23.646 MiB. At the post-collection boundary, its extra saving over the same frame layout is 72 KiB. Median intake and cycle rates are lower. Treat this policy as a measured space option.

## Logical writes and bytes

At 262,144 events, decoded original-journal KV items decrease from 8,197 to 5,123. State writes decrease from 5,122 to 2,048. Receipt writes remain 1,024. Non-event decoded key/value bytes decrease from 371,633 to 201,479. These are decoded logical totals. They exclude compressed WAL framing, filesystem blocks, device writes, and physical write amplification.

The live receipt key decreases from 73 to 8 bytes, and its value from 73 to 9 bytes at the final core cursor. Event entries remain 1,024 and event key bytes remain 16 KiB. RawCommit event values total 38,152,548 bytes versus 38,253,062 for the table MessagePack codec. This 100,514-byte change preserves every original event frame.

## Reads and maintenance at 262,144 events

| Layout | Reopened scan, million events/s | Point p50 / p95 µs | Post-collection scan, million events/s | Flush / major compaction ms |
| --- | ---: | ---: | ---: | ---: |
| Existing compact batch PoC | 5.991 | 25.213 / 28.915 | 6.013 | 68.772 / 56.621 |
| Packed metadata | 6.007 | 24.724 / 28.147 | 6.142 | 67.009 / 57.759 |
| Packed metadata + RawCommit | 5.771 | 26.959 / 33.105 | 5.954 | 67.492 / 55.744 |
| Same + native SST/index LZ4 | 5.692 | 26.959 / 30.521 | 5.748 | 52.206 / 59.691 |

Scans include exact-byte and position verification. Point clocks include lookup, decode, and result construction; exact-output verification follows the clock. Points follow full scans and are not cold reads. The new untimed journal-accounting scan precedes the initial owner reopen in every condition. That scan can affect OS cache state. CPU and RSS include this scan and all other untimed work. Full resource and per-run rate records are in the JSON.

Maintenance is outside the foreground cycle. Explicit flush and major compaction run. Background compaction counters remain zero during that maintenance interval; the counter does not include synchronous major compaction. The benchmark does not measure sustained natural compaction.

## Suggestions

1. Keep batch storage and the existing production RawCommit codec. Do not add the PoC MessagePack batch format to production. The codec reuse reduces the number of formats that engineers must maintain.
2. Do not change the production metadata format only for these timing results. Packed state and compact receipts reduce logical writes, but the measured speed gains are small and inconsistent. The post-collection saving is 12 KiB at the large count.
3. Consider native keyspace compression when the first post-maintenance footprint matters. It needs no custom codec or WAL patch. The measured initial saving is substantial; the post-collection saving and throughput benefit are small or absent.
4. Keep real keyspaces as table boundaries. Keep source plus first cursor as the logical event key. With 1,024 batches, the current compact event keys total 16 KiB. The earlier long-key PoC uses 81 KiB. Do not add another ID catalogue or narrower ID format only to pursue that 65 KiB difference. Reuse an existing durable source ID when the table design provides one.
5. Preserve original-journal CDC and durable saved progress. Keep the measured safe collection behavior. Report event data, retained journals, and table lifecycle allocation separately before making a storage decision.

These are suggestions for review. No production collector, keyspace, branch, storage limit, format, or engine policy changes in this work.

## Verification and limits

The four focused tests check split input at record 17, unaligned and historical pages, original positions, multi-source registration and reopen, collection, saved resume, and later append. The packed metadata test checks all six state fields, all four receipt fields, and a rejected repeated consumed cursor. Four CLI smoke runs and all 32 measured processes pass the original and post-collection checks. Changed Rust formatting and Python syntax pass. Existing library warnings remain. Full CI is not run, as requested.

The recorded host is `Linux navid-laptop 6.8.0-149-generic #149-Ubuntu SMP PREEMPT_DYNAMIC Fri Oct 23 13:21:10 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux`. The exact filesystem output, compiler, 149 source hashes, engine commits, binary hash, and run orders are in the evidence. No build or other benchmark runs during measurement. Other host activity is not controlled.

The baseline is the existing compact-batch PoC, not current production. Prior production measurements are historical context and are not matched against these runs. The PoC retains immutable event rows and filters saved logical cuts. It does not qualify native historical table updates, branches, overlapping retry, gap filling, expiry, witness retention, multiple consumers, power loss, full collector transactions, DataFusion, packages, or notification latency. Production span and global position indexes are not removed.

## Reproduce and evidence

```sh
rtk proxy cargo test -p araphor-data --release --features test-fixtures --example raw_owner_bench
rtk proxy cargo build -p araphor-data --release --features test-fixtures --example raw_owner_bench
rtk proxy python3 scripts/benchmark_record_storage.py output/araphor-batch-layout-repeat --batch-layout
```

[Structured measurements](araphor-batch-layout-2026-11-13.json) and [all raw samples and verification logs](araphor-batch-layout-2026-11-13.samples.json.gz) preserve the result. The frozen binary is output/araphor-batch-layout-20261113/raw_owner_bench. The [earlier compact-key evidence](araphor-compact-storage-2026-11-13.md) and [production codec owner](../../../crates/araphor-data/src/analysis/native/events/intake.rs) support the source-specific suggestions.
