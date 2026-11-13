# Natural source keys and one source metadata row

Source: `dbd4a8fb3`. Result: **Done** for this benchmark-only schema. The final 36 processes, three CLI smoke runs, and six focused tests pass. Production and both engine forks are unchanged.

The simpler schema uses two data keyspaces, events and sources. The benchmark also retains result and global revision keyspaces for the unchanged processing checks. It removes application source IDs, both ID mappings, the ID allocator, the separate epoch table, and the duplicate consumed frontier.

## Intended end state

Store each accepted batch under its natural source epoch and first cursor. Keep one source metadata row. Use the existing production RawCommit codec and original-journal CDC. Compare the simpler schema against the existing compact-ID PoCs before a production change.

## Stored keys and values

| Fjall keyspace | Key | Value |
| --- | --- | --- |
| events | Source epoch tuple + batch first cursor | Existing RawCommit frame: Data revision, CPU, intake, frame boundaries, original bytes, CRC |
| sources | Source epoch tuple | Existing AnalysisSourceReceiptV1: full identity, CPU, ACK, coverage revision, retained floor |
| benchmark_results | Source epoch tuple + last consumed cursor | Existing Progress: source, input reference, original input cut and journal cursor, result body |
| benchmark_state | head | Global Data revision and events, receipts, bindings revisions |

The source epoch tuple is tenant, node name, source ID, and source epoch. The existing epoch_key encoder stores this tuple in 42 bytes plus the UTF-8 node-name length. The fixture node-a uses 48 bytes. Adding one eight-byte cursor gives 56-byte event and result keys. No table name is embedded in these keys.

For example, one input batch has these logical entries:

```text
events[(tenant T, node A, source S, epoch 7, first cursor 1001)]
  = RawCommit containing the original batch and its frame boundaries
sources[(tenant T, node A, source S, epoch 7)]
  = {full identity, CPU, ACK, coverage revision, retained floor}
```

The source row supplies both the receipt and immutable epoch binding. The full identity includes boot and label fields that are not in the key. Open validates that binding before the owner can expose input. Admission checks it again in the write transaction. An unbound owner returns no input until valid admission binds it. Reads do not add a source lookup per page.

## Source review and flow

[Natural::append](../../../crates/araphor-data/src/analysis/native/benchmark/natural.rs) receives one prepared batch
  -> The owner checks identity, CPU, intake, and contiguous cursors.
  -> The owner prepares the existing RawCommit frame.
  -> One SyncAll transaction commits event, source row, and global state.

[Natural::consume](../../../crates/araphor-data/src/analysis/native/benchmark/natural.rs) receives the completed input cut
  -> The same write transaction reads the latest source-prefixed result through the native ordered index.
  -> Its accepted cursor supplies the consumed-cursor comparison. No second frontier row exists.
  -> The owner advances the current global head and preserves the original input cut.
  -> The owner commits result and global state atomically in that SyncAll transaction.

[Natural::replay](../../../crates/araphor-data/src/analysis/native/benchmark/natural.rs) resumes a durable saved cursor
  -> The native journal feed selects the event keyspace and bound source prefix.
  -> Each event revision must match the global head in that same original committed batch.
  -> [raw_owner_bench](../../../crates/araphor-data/examples/raw_owner_bench.rs) checks exact bytes, positions, retained cuts, reopen, and later input.

## Final matched results

The final release executable runs all six condition permutations at each existing event count. Each process uses a fresh store. Every transaction still has 256 events. The large input has 37,445,318 original framed bytes in every condition. Native engine policies are unchanged.

| Core events N | Schema | Intake events/s | Complete cycle events/s | Initial allocated MiB | After collection MiB |
| ---: | --- | ---: | ---: | ---: | ---: |
| 16,384 | Compact batch PoC | 346,725 | 207,151 | 3.523 | 0.695 |
| 16,384 | Compact IDs + RawCommit | 347,542 | 199,896 | 3.480 | 0.684 |
| 16,384 | Natural source keys | 348,050 | 200,741 | 3.387 | 0.656 |
| 262,144 | Compact batch PoC | 334,453 | 195,734 | 53.277 | 8.070 |
| 262,144 | Compact IDs + RawCommit | 347,752 | 200,936 | 52.648 | 7.957 |
| 262,144 | Natural source keys | 343,099 | 195,163 | 52.758 | 7.949 |

Rates are medians of six per-run rates. Complete cycles include intake, cut capture, input read, and durable result/reference/progress commit. Initial allocation is at N events after forced maintenance and before first reopen. The after-collection measurement has the same N+512 events in every condition. Extra collection and continuation batches remain outside the timed core.

The final two large processes, compact-frame and compact-batch in repetition six, have much higher latency. Natural runs before those two processes. All samples remain. Their cause is unmeasured. Do not interpret pooled tail differences as a natural-key latency guarantee. The JSON includes all per-run rates and maximums.

At the large count, natural keys use four keyspaces instead of seven and one source metadata row instead of four. They reach 195,163 complete-cycle events/s versus 200,936 for the compact-ID RawCommit layout. After collection they use 7.949 versus 7.957 MiB. These results support a simpler schema with similar performance and space, not a speed or storage-size breakthrough.

## Structural differences at 262,144 events

| Item | Compact IDs + RawCommit | Natural source keys |
| --- | ---: | ---: |
| Real keyspaces | 7 | 4 |
| Live source metadata rows | 4 | 1 |
| Application source-ID allocator | 1 | 0 |
| Separate consumed frontier | 1 | 0 |
| Event key bytes | 16 KiB | 56 KiB |
| Result key bytes | 8 KiB | 56 KiB |
| Event rows | 1,024 | 1,024 |
| Result rows | 1,024 | 1,024 |

Natural keys are wider. They remove mappings and allocation state in exchange for repeated source tuple bytes. Both layouts write three rows per normal input transaction and two per result transaction. First-source registration differs. RawCommit event value bytes are identical between these two conditions. Logical key and value totals do not measure physical device write amplification.

| Schema at N=262,144 | Reopened scan, million events/s | Point p50 / p95 µs | Before / after collection MiB |
| --- | ---: | ---: | ---: |
| Compact batch PoC | 6.015 | 25.632 / 28.565 | 16.324 / 8.070 |
| Compact IDs + RawCommit | 5.871 | 27.168 / 31.917 | 15.891 / 7.957 |
| Natural source keys | 5.733 | 27.937 / 31.988 | 16.062 / 7.949 |

Scans include exact-byte and position verification. Point clocks stop before exact-output verification. Point phases run in all three conditions, follow full scans, and are not cold reads. The frozen raw reports retain an older generic limit label that mentions two PoCs; this final comparison measures three. All conditions also run the untimed native-journal accounting scan before first reopen; that scan can affect cache state. Process resource measurements include all untimed work. Maintenance remains forced flush and major compaction. Natural sustained compaction is not measured.

## Suggestions

Use this natural-key source row as the simpler input-storage candidate for review. It removes three keyspaces and the numeric source-ID lifecycle. Keep batch payloads and the existing RawCommit codec. Do not add ID maps only to shorten batch keys.

Keep input ACK and processing progress separate. The source row owns ACK. In this append-only PoC, the latest result owns consumed progress. That latter choice depends on retaining the latest result. Result deletion, multiple consumers, and repeated publication at the same frontier are not qualified. Do not replace production progress retention with this assumption without its own review.

The benchmark state and result tables preserve the existing global revision and processing checks. This work does not select the production table abstraction or migrate collectors. Treat the measured performance as comparable; select the schema for its smaller set of concepts.

## Verification and source correction

Six focused tests pass: stream_partial_history, compact_sources_reopen, consumed_journals_reopen, packed_metadata_reopen, natural_sources_progress, and natural_pending_cut. They cover partial batches, original positions, source isolation, wrong boot/label rejection, independent source results, retained cuts, monotonic global revisions, and continued CDC after collection. Three corrected CLI smoke runs and all 36 final measured processes pass. Release build, changed-file Rust formatting, and Python syntax pass. Existing library warnings remain. Full CI is not run, as requested.

Review found a pending-cut bug in the first new owner: consuming A's older input after B committed could set the global head to 2 instead of 4. The regression fails before the fix and passes afterward. The corrected owner advances the current head while retaining A's original input cut. Its forward range is also constructed lazily, as in the baseline. The first matrix and binary are retained as pre-fix evidence and are not used for final conclusions.

The recorded host is `Linux navid-laptop 6.8.0-149-generic #149-Ubuntu SMP PREEMPT_DYNAMIC Fri Oct 23 13:21:10 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux`. Filesystem, compiler, all source hashes, engine commits, binary identity, and run order are retained in the JSON. No agent build or other benchmark runs during measurement. Other host activity is not controlled.

The comparison is between PoCs. It does not qualify production overlap, gaps, expiry, witness retention, historical source metadata updates, result deletion, multiple consumer retention floors, power loss, full collector transactions, DataFusion, Graph, packages, or notification latency. Production and its indexes are unchanged.

## Reproduce and evidence

```sh
rtk proxy cargo test -p araphor-data --release --features test-fixtures --example raw_owner_bench
rtk proxy cargo build -p araphor-data --release --features test-fixtures --example raw_owner_bench
rtk proxy python3 scripts/benchmark_record_storage.py output/araphor-natural-source-repeat --natural
```

[Structured final measurements](araphor-natural-batch-storage-2026-11-13.json) and [all final and pre-fix samples and verification logs](araphor-natural-batch-storage-2026-11-13.samples.json.gz) preserve the evidence. The final frozen binary is output/araphor-natural-schema-20261113/raw_owner_corrected. The earlier raw_owner_bench in that directory is the pre-fix binary.
