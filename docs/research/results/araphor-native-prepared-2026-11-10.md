# Native notification preparation, 2026-11-10

Result: **Done for optional native notification preparation**. Production
router binding, delivery batches, durable notification consumption, configured
capacity, retention, backup, cutover, DuckDB removal, and both incident targets
remain **Not done**.

`NativeStore::prepare_notifications` captures one committed native/raw view.
The method returns the existing `PreparedNotificationBatch`. Both storage
readers use the same constructor, request charge, state decoder, and error
policy. No backend trait, parallel batch model, or new durable index is added.

The native reader selects requested finding groups through the captured tenant
Graph catalogue and exact publication heads. The winner order stays
`(publication revision, result ID)`. The reader opens actual members at saved
writer cuts. Canonical tokens supply changed-value comparison only. Actual
producers and saved read rows supply provenance.

Current routes and obligation heads use the ordered context catalogue and
notification lookup indexes. Pending attempts load the exact
`attempt.context_revision`. Referenced routes load their exact owner revision.
Later commits do not change prepared values. No context-history scan or SQL
projection is used.

Finding values and their proof have separate deferred errors. Missing live
witness references fail the historical proof method while the finding value
remains available. Cancellation and memory failures abort preparation. They do
not become deferred owner errors. Context payloads, retained package reads,
and artifact decode use the same budget. The reader checks caller cancellation
around proof validation. Ordinary context owners receive no package-proof
allowance.

The five new public API cases cover removed and replaced producers, equal and
changed values, pending subjects, old routes, compaction, reopen, missing
subjects, separate proof and state errors, a concurrent later commit, finite
memory, and cancellation. A matched allocation case uses the same installed
large package and Graph path. Only package-context attribution changes. The
historical bases prove that difference. Preparation charges the retained
artifact; a finite budget above the measured ordinary path fails at proof load.
This allocation check is not a latency benchmark.

The frozen-source gate passes **105 tests** in ten suites. No test fails, is
ignored, or is filtered. Elapsed time is **35.458 seconds**,
including build work. All 16 changed Rust source hashes
match before and after the gate. The log SHA-256 is
`a39819cfa793727172e7946fb6f6d773b8283b1ff41a7862e90f27fafab6c9b7`.

```sh
cargo test --offline -p araphor-data --features native-store,test-fixtures \
  --test native_notification --test native_inputs --test native_extraction \
  --test native_context --test native_managed --test native_packages \
  --test native_raw --test native_store --test raw_index --test store_schema \
  --config /tmp/araphor-storage-release-override.toml -- --nocapture
```

Selected-file formatting and the feature-off library check pass. Read the
[source guide](../../guides/araphor-native-data-review.md#native-notification-preparation)
and [machine record](araphor-native-prepared-2026-11-10.json) for source, engine,
build, command, and evidence hashes. The selected incident and default definition
hashes remain unchanged.

No production incident is rerun for this increment. The
[previous production result](araphor-native-provenance-2026-11-10.md#unchanged-production-incident)
uses DuckDB and takes 12.21 seconds. Its three durable notification creation
intervals are 404.578, 476.234, and 497.010 milliseconds. Those measurements do
not qualify this source or a native production path. No matched native speedup
is established. Full CI does not run.
