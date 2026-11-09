# Shared raw index qualification

Date: 2026-11-09. Source parent: `ed8b54f67`. The commit that adds this
record contains the qualified source. Result: **Done for shared raw metadata**.
The complete DuckDB replacement and incident performance targets remain
**Not done**.

`RawJournal` now holds one persistent ordered index. Append prepares the next
root before file I/O and publishes the root after the existing durable checks.
Source-range readers capture that root and release the raw lock before scans.
The change adds no payload archive, journal, or Fjall commit. Captured metadata
does not retain raw files. Read the
[source guide](../../guides/araphor-native-data-review.md#shared-raw-metadata).

## Focused checks

All commands use offline dependencies and
`/tmp/araphor-storage-release-override.toml`. This local file links the existing
static DuckDB build at
`target/release/build/libduckdb-sys-e073672aa6bffaa9/out`.

```sh
cargo test --offline -p araphor-data --features native-store,test-fixtures \
  --test store_schema --test raw_index --test native_store \
  --config /tmp/araphor-storage-release-override.toml
cargo check --offline -p araphor-data --no-default-features --lib \
  --config /tmp/araphor-storage-release-override.toml
cargo clippy --offline -p araphor-data --features native-store,test-fixtures \
  --lib --no-deps --config /tmp/araphor-storage-release-override.toml
```

The nine integration cases pass: five native transaction cases, three raw-index
cases, and one strict schema reopen case. The feature-off build passes.
The raw cases check captured roots, out-of-order input, duplicate/conflicting
retries, coverage, original positions, page resume, rotation, retention, reopen,
and append failure. The fixture exposes actual roots only under `test-fixtures`.

Clippy fails on two unchanged `expect` calls in
`analysis/managed/graph/projection/publish.rs:90` and
`analysis/managed/reader/committed/graph.rs:213`. The changed raw-index source
has no Clippy error. Formatting passes for the new modules and tests and the
changed `raw_segments.rs` and `test_support.rs` files. No full-workspace
formatting or CI result is claimed. Linux-filtered offline metadata succeeds
for both standalone PoCs. All-platform Neon metadata needs uncached `block2`.

Logs remain under `output/araphor-fjall-migration-20261109/`:
`raw-index-final-qualified.log`, `raw-index-final-feature-off.log`, and
`raw-index-final-clippy.log`.

## Unchanged incident qualification

The exact test passes with its existing definition, workload, assertions, and
timeouts:

```text
discovery::packages::required::incident::incremental::follows_incremental_sources
```

The test executable uses Rust optimization level 0, debug information level 2,
and debug assertions. Its size is 2,932,395,720 bytes. Its SHA-256 is
`68becbe9ed3d654e5714590af362c75d1ab33b95f9aecbc61b1459016c0abd63`.
The executable is retained locally at
`target/araphor-notice-comparison-20261109/raw-index`.

The harness takes 23.90 seconds. Process time is 23.958539 seconds. The existing
boundary parser checks 18 collector receipts and three first durable creations.

| Episode | Collector receipt to creation | Committed input to creation | Graph publication to creation | Public notification receipt |
| --- | ---: | ---: | ---: | ---: |
| 1 | 683.475 ms | 668.144 ms | 117.422 ms | 732.802 ms |
| 2 | 1,161.203 ms | 1,152.190 ms | 178.128 ms | 1,284.340 ms |
| 3 | 1,432.475 ms | 1,422.684 ms | 299.945 ms | 1,582.317 ms |

Bulk completion for 16,384 background logical records takes 3.172428 seconds.
The runtime log and existing boundary parser output remain at
`raw-index-incident-native.log` and `raw-index-incident-boundary.json` in the
output directory above. The binary, command, profile, and process records use
the same filename prefix.

This is one correctness qualification. The older frozen control links a
different DuckDB build. These runs do not establish a speedup or isolate a
raw-index performance effect. Production still uses DuckDB. Notification
creation below 100 milliseconds and the requested 100-fold result remain
**Not done**. No new benchmark or performance workload is added.
