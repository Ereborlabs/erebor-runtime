# Native notification storage, 2026-11-10

Result: **Done for optional native notification storage**. Production
notification preparation, finding provenance, delivery batches, durable
notification consumption, retention, backup, cutover, DuckDB removal, and both
incident targets remain **Not done**.

Native contexts retain their immutable versions and current head records.
An ordered persistent tree maps context identities to head keys. Data shares
the tree root across captured views and restores the tree during the existing
context validation scan. The tree contains no body or head version. Pages
read exact heads from the captured snapshot. Pages do not sort or scan old
versions. Historical views ignore candidate identities that have no visible
head. Future collection must keep identities required by retained views.

Finding and concern lookup indexes reuse the existing `NotificationKeys`
codec. The existing interner stores long identities. Each membership key
contains a numeric scope and a 16-byte notification ID. A head advance removes
prior membership and adds current membership in the same transaction.
Historical inserts and exact retries do not change current membership.
Recovery checks the exact lookup set against current heads.
Physical format 4 requires these indexes. Earlier prototype formats are
rejected. The native owner does not convert earlier prototype stores or repair
missing indexes during recovery.

`commit_contexts_checked` accepts ordered versions with an expected head for
each version. The batch checks values, stages each immutable version, runs the
caller's guard, and commits once. A failed check drops the entire transaction.
An exact retry returns the original references without a new commit. The batch
retains intermediate subjects and pending attempts. An attempt's subject stays
available at its exact context revision after compaction and restart.

The frozen-source gate passed **96 tests** across ten suites. It took
**47.250 seconds**, including build work. No test failed, was ignored, or was
filtered. The six new cases cover context page ordering and limits, long
identities, historical cuts, batch rejection, retries, retained subjects,
pending attempts, changed lookup membership, tenant scope, historical inserts,
compaction, restart, missing-index recovery failure, and old-format rejection.

```sh
cargo test --offline -p araphor-data --features native-store,test-fixtures \
  --test native_notification --test native_inputs --test native_extraction \
  --test native_context --test native_managed --test native_packages \
  --test native_raw --test native_store --test raw_index --test store_schema \
  --config /tmp/araphor-storage-release-override.toml -- --nocapture
```

The [source review guide](../../guides/araphor-native-data-review.md#native-notification-storage)
gives the owners, calls, and tests. The [machine record](araphor-native-notification-2026-11-10.json)
records the command, engine commits, build override, source hashes, and evidence
hashes. Selected-file formatting and the feature-off library check pass.

This gate does not execute the production notification router. The incident
workload and definition remain unchanged. No incident run, matched performance
comparison, or full CI forms part of this qualification. Production still uses
DuckDB. No speedup is established.
