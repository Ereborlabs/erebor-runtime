# Durable native input consumption, 2026-11-10

Result: **Done for optional native managed input consumption**. Production
binding, collection floors, retention, notification batches, backup, DuckDB
removal, and both incident targets remain **Not done**.

Data saves one consumer record per managed instance generation. The record
contains the exact interest, a stable binding version, one native/raw scan cut,
and the completed input position. An existing registration keeps its cut.
A new registration requires an initial full capture. Filtered scan progress
does not satisfy that requirement. No receipt without a sealed input token
becomes an input acknowledgement.

`subscribe_managed_inputs` registers the saved interest with the shared original
log readers. `read_managed_subscribed` uses the existing Arrow capture procedure
and seals its token at the same pinned Data view. A completed, exhaustive
publication stages consumed progress in the result and Graph transaction.
Data promotes the in-memory completed position only after view publication.
Failed, cancelled, incomplete, metadata-only raw, and narrowed reads do not
acknowledge omitted input. Valid projected reads can still publish results.

Ordinary commits coalesce filtered scan cuts. A pending matching input stops
that advance. The explicit `checkpoint_inputs` API saves filtered progress for
maintenance. Raw append adds no checkpoint sync. Writes without durable
consumers do not run synchronous CDC replay. Coordinator records do not create
new source work or an acknowledgement loop, including after reopen.

Recovery restores interests and exact retained cuts. The existing attempt scan
checks each completed position against the maximum successful exhaustive
capture for that consumer binding. Old acknowledged attempts need no retained
journal for this check. Queued positions at or below completed progress do not
wake a package. Stop/start preserves pending input for the same generation.

The focused gate passed **90 tests** in **97.694 seconds**, including build
work. All nine suites have zero failed, ignored, or filtered tests. Nine new
cases use the real native owner. They cover rejection, atomic success, restart
after compaction, filtered traffic, checkpoint restart, missing completion
authority, partial coverage, stop/start, queued wakes, and Graph publication
with later raw input. That Graph case acknowledges the captured input and
preserves the later input.

The [source review guide](../../guides/araphor-native-data-review.md#durable-native-input-consumption)
gives the owners and event flow. The [machine record](araphor-native-consumption-2026-11-10.json)
records the exact command, build override, 21 unchanged source hashes, engine
commits, and evidence hashes. Selected-file formatting and the feature-off
library check pass.

The command runs only the nine named Data integration suites:

```sh
cargo test --offline -p araphor-data --features native-store,test-fixtures \
  --test native_inputs --test native_extraction --test native_context \
  --test native_managed --test native_packages --test native_raw \
  --test native_store --test raw_index --test store_schema \
  --config /tmp/araphor-storage-release-override.toml -- --nocapture
```

Production query coverage mapping remains incomplete. A physically narrowed
capture does not yet prove complete logical consumption for a retained query.
Native managed update/remove callers, collection-floor release, bootstrap
retention enforcement, and configured recovery memory also remain incomplete.
This increment does not change DataFusion operators or introduce a second
payload archive. The incident workload and definition stay unchanged. No
incident, matched performance comparison, or full CI runs for this increment.
Production still uses DuckDB. No speedup is established.
