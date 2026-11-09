# Native package catalogue qualification

Date: 2026-11-09. Source parent: `b447c7142`. The commit that adds this record
contains the qualified source. Result: **Done for native package/image and
definition admission and reads**. Production cutover, collection, uninstall
reclamation, capacity accounting, and incident performance remain **Not done**.
The [source record](araphor-native-catalogue-2026-11-09.json) contains source
hashes, engine commits, gate exits, and the frozen PoC identity.

Read the [source guide](../../guides/araphor-native-data-review.md#package-and-definition-catalogue).
The native owner stores the existing artifact and definition types. It does
not add a backend trait, SQL adapter, job controller, or activation path.

## Admission and read behavior

An image installation stages missing immutable artifacts, checks their locked
dependencies through indexed reads, and saves the installed image and latest
pointer. A resolved definition requires exact installed image pins. Data saves
its existing canonical bytes and latest pointer. The callback must succeed
before either operation commits. An identical retry runs the callback, returns
the original revision, and adds no batch. An older retry does not change the
latest pointer.

Latest definition retries use a point read before any history scan. Older
retries scan only that tenant and definition name. Semantic identity fragments
use the existing engine key width. No content hash selects changes. Definition
names receive no new length limit. Manual artifact installation uses the same
validator as the current production owner. Checked image admission retains its
existing contract, without the manual installation length limits.

Captured native snapshots supply package versions, installed or retained pinned
images, and exact or latest definitions. Recovery checks artifact contracts,
dependencies, digests, pins, unique canonical definitions, and the exact latest
pointer sets. Native record tags cannot exceed the metadata head, even when
later raw-only input has advanced the public Data revision.

The common `Records` owner now serves physical contexts, sources, and the
catalogue. Its binary MessagePack setting matches the existing package codec.
Tests decode actual context, package, and coverage records in both the binary
and previous integer-array encoding. Fixed identity arrays and the store UUID
survive reopen. Identity encoding and canonical definition bytes stay unchanged.

## Focused checks

The final command passes 24 cases: eight catalogue cases and the existing
16 native raw, native transaction, shared raw-index, and strict schema cases.
The feature-off build passes. Selected changed Rust files pass formatting.

```sh
cargo test --offline -p araphor-data --features native-store,test-fixtures \
  --test native_packages --test native_store --test native_raw \
  --test raw_index --test store_schema \
  --config /tmp/araphor-storage-release-override.toml
cargo check --offline -p araphor-data --no-default-features --lib \
  --config /tmp/araphor-storage-release-override.toml
cargo clippy --offline -p araphor-data --features native-store,test-fixtures \
  --lib --no-deps --config /tmp/araphor-storage-release-override.toml
```

The catalogue cases check denied callbacks, immutable conflicts, missing
dependencies, checked retries, exact pins, cancellation, tenant isolation,
long semantic keys, raw/metadata revision order, historical reads, compaction,
and reopen. Injected faults check missing and stale pointers, duplicate
definitions, and native records tagged beyond the metadata head.

The first build overlapped source edits. It passed seven catalogue cases and
failed the duplicate-definition expectation. The settled-source rerun passes
all eight catalogue cases and all 16 regressions. The earlier log remains
separate; it does not qualify the final source.

Clippy stops on the same two unchanged `expect` calls in
`analysis/managed/graph/projection/publish.rs:90` and
`analysis/managed/reader/committed/graph.rs:213`. It reports no new native
catalogue or record-helper error. Full CI does not run during iteration, as the
user requires. Gate logs use `native-catalogue-` under
`output/araphor-fjall-migration-20261109/`.

## Existing Graph and CDC PoCs

The unchanged combined workload passes all 64 cycles. The unchanged stable
workload passes 128 primary cycles, 640 historical package evaluations, and
320 historical views. The existing summary scripts accept both reports.
The workloads retain their original assertions, traversal, rollback, history,
compaction, reopen, saved CDC resume, and continued input.

The final optimized binary is 95,877,072 bytes. Its SHA-256 is
`5ed4eb5d79b8ad73384e2d156f23e416c30170a219c29a824387923383582fcb`.
It remains at `output/araphor-fjall-migration-20261109/native-catalogue-poc`.
The source record contains the exact build and run commands. These runs check
correctness. They are not a paired performance comparison and do not measure
the production notification path.

## Limits

Production still uses DuckDB. The native catalogue does not yet supply
qualified context/fact admission, managed lifecycle, collection, uninstall
reclamation, configured capacity, subscription routing, retention, or backup.
The public API does not expose an incomplete uninstall operation. Installing
an image or admitting a definition creates no running subscription.

The incident test does not run again for this optional catalogue increment.
Its last [qualified run](araphor-native-raw-2026-11-09.md#unchanged-incident)
still uses production DuckDB. This increment establishes no incident gain,
creation below 100 milliseconds, or 100-fold improvement.
