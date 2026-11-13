# Native compression and consumed journals: measured results

Source: `40f476504`. All 32 process runs pass. Both builds pass three focused tests. Production still stores event payloads in batches. Production settings and committed engine source are unchanged.

After collection at 262,656 retained events, the combined record policy uses 12.102 MiB and the combined batch policy uses 7.996 MiB. Record storage remains 1.51 times the batch allocation. The four-run intake medians are 242,241 and 337,281 events/s. Three late runs have higher latency; all samples remain in the results.

## Intended end state

Measure native compression and safe journal reclamation in the existing table proofs of concept (PoCs). Keep the original timed workload, bytes, positions, and assertions. Measure reclamation only after a consumer durably advances beyond the old journal. Do not change production storage or install an engine API.

## Source review and flow

[Tables::open](../../../crates/araphor-data/src/analysis/native/benchmark/tables.rs) opens compact-source-ID tables with default or all-level native data/index LZ4
  -> [raw_owner_bench](../../../crates/araphor-data/examples/raw_owner_bench.rs) runs the original N-event intake/read/progress workload and all older replay/history/reopen/continuation checks.
  -> [Store::rotate](../../../crates/araphor-data/src/analysis/native/benchmark.rs) seals the old journal.
  -> [raw_owner_bench](../../../crates/araphor-data/examples/raw_owner_bench.rs) accepts and consumes one further 256-record batch in the new journal.
  -> [Store::collect](../../../crates/araphor-data/src/analysis/native/benchmark.rs) verifies the supplied cut equals durable consumed progress, then acknowledges that cursor and collects through native Fjall.
  -> [raw_owner_bench](../../../crates/araphor-data/examples/raw_owner_bench.rs) measures actual file and allocated-block removal at N+512 events.
  -> [raw_owner_bench](../../../crates/araphor-data/examples/raw_owner_bench.rs) reopens, verifies saved logical history and CDC resume, then accepts another batch and verifies continued replay.

The cursor inside the newest journal survives. The native [journal manager](../../../fjall/src/journal/manager.rs) keeps a journal whose last sequence reaches the acknowledged floor, or whose data is not fully persisted. A saved cursor inside the sole old journal would not permit that journal to be removed. The extra accepted/consumed batch moves the durable consumer into the new journal.

## Conditions and experimental build

Each timed core has 16,384 or 262,144 original events, in 256-record transactions. Every condition uses compact 16-byte event keys, the same values and validation, and two SyncAll stages per prepared batch. The combined policy enables native LZ4 for data and index blocks at every level, and lowers the per-value journal threshold from 4,096 bytes to one byte. This measures the combined policy; it does not isolate each setting.

The threshold has no public setter. The [unapplied one-line patch](../../../crates/araphor-data/examples/raw_storage/wal-small-values.patch) is used only to compile a frozen experimental benchmark binary. The Fjall file is restored in a try/finally build script with interruption handlers. The original file hash and clean checkout are verified after the build. No other agent build runs while patched. Both builds run the same three tests. The default benchmark executable is restored after both binaries are frozen. No patch is applied during the matrix.

One binary runs both default layouts. The second binary runs both combined layouts. They use the same benchmark source and release settings. The build manifest records both binary hashes, original and experimental engine-file hashes, exact patch text/hash, and restored state. The sample archive retains that manifest and all build/test logs. Both engine forks remain clean and unchanged.

The existing four balanced orders run all four conditions once per position at each size, for 32 fresh processes and stores. The OS page cache stays enabled. No build runs during measurement. The source hashes, engine commits, compiler, host, filesystem, binaries, and orders are in the JSON provenance. The recorded filesystem is 100% used with 3.3G available. This does not establish the cause of the late latency increase.

## Timed core at N events

Intake rate is events divided by summed acceptance time per run, then the median of four rates. Cycle rate also includes cut capture, input reads, and result/reference/progress commits. Initial allocation is measured after forced maintenance and before the first reopen. It is not a steady-state post-reopen footprint.

| Events | Layout | Intake events/s | Cycle events/s | Initial allocated MiB |
| ---: | --- | ---: | ---: | ---: |
| 16,384 | Default batch | 338,076 | 199,359 | 3.523 |
| 16,384 | Default record | 241,440 | 140,648 | 6.773 |
| 16,384 | Combined batch | 344,108 | 200,729 | 1.723 |
| 16,384 | Combined record | 230,436 | 136,951 | 3.664 |
| 262,144 | Default batch | 336,222 | 195,511 | 53.277 |
| 262,144 | Default record | 242,784 | 142,721 | 107.125 |
| 262,144 | Combined batch | 337,281 | 197,089 | 24.098 |
| 262,144 | Combined record | 242,241 | 144,877 | 56.406 |

## Journal collection at the same N+512 events

All original assertions complete first. The original continuation adds 256 events. The separate GC anchor adds another 256 events in a new journal and commits consumed progress. Flush completes before the before-GC measurement. Collection then removes one old journal in every run. The next 256-event append verifies post-GC continuation; it occurs after the space measurement.

| Core events N | Layout | Before GC, MiB | After GC, MiB | Journal before / after, MiB |
| ---: | --- | ---: | ---: | ---: |
| 16,384 | Default batch | 1.215 | 0.695 | 0.527 / 0.012 |
| 16,384 | Default record | 4.121 | 1.000 | 3.168 / 0.051 |
| 16,384 | Combined batch | 1.152 | 0.637 | 0.523 / 0.012 |
| 16,384 | Combined record | 2.883 | 0.910 | 2.000 / 0.031 |
| 262,144 | Default batch | 16.324 | 8.070 | 8.262 / 0.012 |
| 262,144 | Default record | 62.500 | 12.355 | 50.191 / 0.051 |
| 262,144 | Combined batch | 16.168 | 7.996 | 8.180 / 0.012 |
| 262,144 | Combined record | 44.141 | 12.102 | 32.070 / 0.035 |

Before and after GC contain the same event count and the same event values. In every large run, the reduction in total allocated bytes equals the reduction in journal allocated bytes plus 4,096 bytes. These measurements use filesystem blocks, not preallocated journal file length.

The much larger initial N-event snapshot already decreases before explicit GC, during the intervening read/reopen/append/flush sequence. For example, default record allocation is initially 107.125 MiB, later 62.500 MiB before GC, then 12.355 MiB after GC. Only the 62.500-to-12.355 MiB decrease is measured across collection. Do not attribute the entire 107.125-to-12.355 MiB change to WAL reclamation.

Native code permits [deferred table deletion](../../../lsm-tree/src/version/mod.rs), [unlink on last table drop](../../../lsm-tree/src/table/inner.rs), and [orphan-table cleanup during open](../../../lsm-tree/src/tree/mod.rs). The experiment does not capture a complete file inventory between these stages. Those mechanisms do not establish which files caused the earlier decrease. That decrease remains unattributed.

## Reads after GC and reopen

These scans read N+512 events. Point clocks include snapshot, lookup, CRC/canonical decode, and result construction. They exclude exact-output verification. Point phases follow full scans and do not represent cold disk reads. Scan clocks include exact-byte and original-position verification.

| Core events N | Layout | Scan, million events/s | Point p50 / p95, µs |
| ---: | --- | ---: | ---: |
| 16,384 | Default batch | 5.827 | 13.271 / 20.115 |
| 16,384 | Default record | 1.533 | 3.282 / 5.238 |
| 16,384 | Combined batch | 6.000 | 19.625 / 21.861 |
| 16,384 | Combined record | 1.494 | 3.282 / 5.169 |
| 262,144 | Default batch | 5.516 | 26.261 / 33.315 |
| 262,144 | Default record | 1.485 | 4.330 / 7.543 |
| 262,144 | Combined batch | 5.864 | 26.470 / 34.363 |
| 262,144 | Combined record | 1.487 | 4.330 / 7.613 |

## All large per-run rates

The final three large-workload processes have higher write latency: default batch, combined batch, and default record in repetition four. Their cause is unmeasured. No sample or run is removed or replaced. Pooled p95 values include these runs; do not interpret their differences as a compression-induced tail-latency guarantee.

| Repetition | Layout | Intake events/s | Cycle events/s |
| ---: | --- | ---: | ---: |
| 1 | Default batch | 338,904 | 198,331 |
| 1 | Default record | 257,084 | 150,773 |
| 1 | Combined batch | 338,928 | 197,049 |
| 1 | Combined record | 242,385 | 144,319 |
| 2 | Default batch | 338,512 | 196,721 |
| 2 | Default record | 242,322 | 142,758 |
| 2 | Combined batch | 337,807 | 197,129 |
| 2 | Combined record | 247,243 | 147,543 |
| 3 | Default batch | 333,932 | 194,301 |
| 3 | Default record | 243,245 | 142,684 |
| 3 | Combined batch | 336,755 | 197,267 |
| 3 | Combined record | 242,096 | 145,436 |
| 4 | Default batch | 87,024 | 44,921 |
| 4 | Default record | 60,472 | 31,985 |
| 4 | Combined batch | 66,772 | 34,371 |
| 4 | Combined record | 239,440 | 143,849 |

## Verification and limits

Both builds pass three tests. The partial-history test covers eight backends. The source-ID test covers all four compact conditions. The journal-collection test checks actual removal, saved historical event reads, reopen, no repeated consumed input, and subsequent append/replay. All 32 process runs pass both their original assertions and new post-GC checks. The default and experimental builds pass with existing library warnings. Changed Rust files pass formatting. The Python runner compiles and completes the matrix. Full CI is not run, as requested.

The GC scenario has one declared benchmark consumer. It does not qualify production coordination among multiple durable consumers. The PoCs retain immutable event rows and use logical saved-cut filtering. Native table history, historical receipt updates, deletion/expiry, arbitrary retry, multi-source global commit ordering, witness retention, power-loss recovery, packages, and notification latency remain unqualified. Process CPU and RSS include all untimed GC setup, extra reads, and verification.

Production still uses batch payloads. No production configuration, collector, branch, or engine API changes. The engine patch is an unapplied build artifact. The earlier [compact-key report](araphor-compact-storage-2026-11-13.md) remains historical evidence of its stated measurement boundary.

## Reproduce

Build the benchmark source once with the original engine and once with the archived threshold patch. Run the same focused test and release build in each state. Freeze both executables. Restore and verify the engine file before the matrix. The build manifest must record and match both binary hashes and engine-file hashes.

```sh
python3 scripts/benchmark_record_storage.py output/araphor-compression-storage-20261113/matched \
  --compression \
  --binary output/araphor-compression-storage-20261113/raw_owner_default \
  --experimental-binary output/araphor-compression-storage-20261113/raw_owner_experimental \
  --build-manifest output/araphor-compression-storage-20261113/build-manifest.json
```

[Machine-readable results](araphor-compression-storage-2026-11-13.json) and [all raw samples/build evidence](araphor-compression-storage-2026-11-13.samples.json.gz) retain the measurements. Both frozen binaries and the build manifest remain under `output/araphor-compression-storage-20261113/`.
