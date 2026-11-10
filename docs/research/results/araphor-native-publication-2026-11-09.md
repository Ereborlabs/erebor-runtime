# Native selected-result publication qualification

Result: **Done for the optional native Selected publication boundary**.
Production cutover, original-log subscription routing, and the incident latency
targets remain **Not done**. Read the
[source review guide](../../guides/araphor-native-data-review.md#native-selected-result-publication).
The [machine record](araphor-native-publication-2026-11-09.json) contains source,
engine, workload, binary, and evidence hashes.

## Implemented boundary

Packages stage actual journals through generic Araphor Graph. Dependent calls
can read staged changes from the same attempt. Data prepares the journals and
canonical evidence outside its writer, then rechecks the actual attempt and
context authority under the writer.

One Data batch saves actual call and selected receipts, checkpoints, context
imports, raw/context/dependency references, Graph layers and origins, finding
references, call heads, completion, and consumed progress. Data publishes the
exact committed view, then promotes prepared execution state before it sends
the existing availability wake. Original raw segments remain the payload owner.

Cross-writer relationship and finding checks read native properties through
references. They add no property archive. Stable finding tokens can refer to an
original producer that no longer has a live member. Current authority comes
from the live group at the saved publication cut.

Recovery checks the actual receipt owners, captured progress and prior heads,
derived import authority, source proofs at captured receipts, exact reference
sets, Graph origins and consumed rows, opening properties, canonical tokens,
and publication chains. Native revision units stay separate from Data revisions.

## Focused verification

The eight Data integration targets pass 70 tests, with zero failures, ignored,
or filtered tests. The process takes 39.633 seconds. All 46 recorded Rust source
hashes are unchanged during the gate and match the reviewed source.

The added cases check successful rollback, same-batch Graph/results/progress,
dependent journals, source attribution, checkpoint resume after each restart,
historical cuts, compaction, and reopen. A real domain fixture imports a
canonical fact and a proof parent that it actually read. It submits qualified
subjects, a relationship, and a provisional finding through the package APIs.
It proves canonical-token reuse after producer removal. Fourteen fault branches
check projection, import, proof CPU, and Graph proof report authority. Two more
branches reject zero and stale successful progress.

```sh
cargo test --offline -p araphor-data --features native-store,test-fixtures \
  --test native_extraction --test native_context --test native_managed \
  --test native_packages --test native_raw --test native_store \
  --test raw_index --test store_schema \
  --config /tmp/araphor-storage-release-override.toml -- --nocapture
```

The selected-file format check passes. Library clippy stops in unchanged
`araphor-graph/src/read.rs:124` on a forbidden `unwrap`. It does not reach the
Data crate. This record does not claim a clean clippy result. Full CI does not
run during this iteration.

## Unchanged production incident

The exact incident passes with one test and 694 filtered tests. The harness
takes 15.88 seconds; the process takes 15.925 seconds. The rebuild takes
372.825 seconds. The Data artifact has `test-fixtures` and has no `native-store`
feature. It therefore checks the shared validation changes on production DuckDB.
The binary uses debug optimization level 0 and debug information level 2.

| Boundary | Episode 1 | Episode 2 | Episode 3 |
| --- | ---: | ---: | ---: |
| Collector receipt to first durable notification | 508.979 ms | 817.669 ms | 859.141 ms |
| Public notification receipt | 555.050 ms | 907.598 ms | 948.468 ms |

The existing boundary parser checks all 18 input receipts and three first
durable notifications against the actual result cuts. The unchanged bulk
workload contains 16,384 rows and takes 2.495 seconds to reach publication.
This is one correctness run. It is not a paired performance comparison and
establishes no native production speedup.

## Remaining work

Graph and Profile destinations, source-publication selection, production
providers, original-log routing, notification batches, configured capacity,
retention, backup, production activation, and DuckDB removal remain **Not done**.
Native live publication rejects retained Graph returns before staging; the
existing live evaluator supplies fresh journals, and retained calls belong to
historical replay. General retained Graph publication is not qualified here.
