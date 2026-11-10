# Native finding provenance reads, 2026-11-10

Result: **Done for optional native finding provenance reads**. Production
notification preparation, delivery batches, durable notification consumption,
retention, backup, cutover, DuckDB removal, and both incident targets remain
**Not done**.

`NativeStore::graph_finding_batch` uses the existing grouped response shape.
The reader resolves only requested finding groups at the saved publication
cut. The reader opens each member at its selected writer cut. The actual
member's origin supplies the producing call, saved result, attempt, and
definition version. A canonical value token supplies no producer authority.

The native reader checks immutable Selected and call result ownership and
their retained evidence references. The reader compares the original raw
metadata with the saved reference and expiry. No raw payload read is needed
for this check. An absent reference with an expired witness remains allowed,
as in the existing read procedure. The Selected cache checks the exact result
revision, instance, and attempt on a cache hit and a cache miss.

Historical parent traversal uses actual saved Graph read rows and result
references. A parent member must have the saved opening revision. Its revision
must precede the consuming member. The reader merges evidence, coverage proof,
missing ranges, minimum witness expiry, and exact context references through
one shared `FindingBasis` accumulator. The DuckDB reader uses the same
accumulator. Each concrete reader keeps its storage and cancellation checks.

Context references use the existing reference index, immutable context, and
canonical fact index. The reader loads the context body once through its known
ID. Fact association uses the checked compact `FactRecord`. The reader does
not reload the context or construct another full Graph fact for association.
Variable identity bytes are charged before owned copies. Finite notification
preparation remains **Not implemented** on the native owner.

The frozen-source gate passed **100 tests** across ten suites in **24.303
seconds**, including build work. No test failed, was ignored, or was filtered.
The four new cases cover removed producers, old publication cuts, compaction,
restart, true historical parent traversal, missing witnesses and coverage,
context references, raw references, live and expired missing references,
missing Selected results, and a receipt rebound to another valid Selected
result. The last case checks both Selected cache paths.

```sh
cargo test --offline -p araphor-data --features native-store,test-fixtures \
  --test native_notification --test native_inputs --test native_extraction \
  --test native_context --test native_managed --test native_packages \
  --test native_raw --test native_store --test raw_index --test store_schema \
  --config /tmp/araphor-storage-release-override.toml -- --nocapture
```

The [source guide](../../guides/araphor-native-data-review.md#native-finding-provenance-reads)
gives the review route. The [machine record](araphor-native-provenance-2026-11-10.json)
records all 12 source hashes, engine commits, build override, workload hashes,
and evidence hashes. Selected-file formatting and the feature-off library
check pass. The incident workload and definition remain unchanged. Full CI
does not run. No matched native performance improvement is established.

## Unchanged production incident

The exact incident passes with one test and 694 filtered tests. The harness
takes **12.21 seconds**. The process takes **12.247 seconds**. The build takes
**341.811 seconds**. The initial restricted run stops with `Operation not
permitted` before the workload. The same binary passes with the required test
permissions. Both attempts remain in the evidence record.

| Boundary | Episode 1 | Episode 2 | Episode 3 |
| --- | ---: | ---: | ---: |
| Collector receipt to first durable notification | 404.578 ms | 476.234 ms | 497.010 ms |
| Public notification receipt | 439.683 ms | 676.007 ms | 724.162 ms |

The boundary record joins all 18 committed input receipts, the actual captured
cuts, and the three first durable notification writes. The unchanged bulk
workload has 16,384 rows. It takes 1.816 seconds to reach package publication.
The binary hash and Cargo artifact profiles are in the machine record. The
Data artifact has `test-fixtures` and has no `native-store` feature. Production
therefore still uses DuckDB. This run checks the shared accumulator change.
It is not a matched performance comparison. Neither incident target is met.
