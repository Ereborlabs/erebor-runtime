# Native raw view qualification

Date: 2026-11-09. Source parent: `f05f444e2`. The commit that adds this record
contains the qualified source. Result: **Done for the default-limit native raw
view and Evidence/coverage storage**. Production cutover and the incident
performance targets remain **Not done**.
The [source record](araphor-native-raw-2026-11-09.json) contains the changed
source hashes, engine commits, gate exits, and frozen PoC binary identity.

Read the [source guide](../../guides/araphor-native-data-review.md#combined-native-and-raw-view).
`NativeStore` now owns the actual raw journal. Raw-only appends use its existing
format and durable sync. They publish an exact shared root without a Fjall
batch. A metadata write saves pending raw controls in its existing native batch.
No payload archive, copied CDC log, or extra sync per raw append is added.

## Revision example

| Operation | Public Data revision | Metadata head | Selected raw cursor |
| --- | ---: | ---: | ---: |
| Open | 0 | 0 | Absent |
| Append cursor 1 | 1 | 0 | 1 |
| Save coverage revision 7 | 2 | 2 | 1 |
| Append cursor 2 | 3 | 2 | 2 |
| Commit metadata | 4 | 4 | 2 |

`read_at(1)` reports Data revision 1 and uses the initial metadata cut.
`read_at(3)` reports Data revision 3 and uses the metadata cut for revision 2.
Both views share an index root and enforce their immutable revision bound.
Historical receipts use native baselines and original ranges through that
bound. A later gap fill cannot advance an earlier receipt.

## Focused checks

The final command passes 16 integration cases: seven native raw cases, five
native transaction cases, three shared raw-index cases, and one strict schema
case. The feature-off build passes. These checks use the existing static DuckDB
link override at `/tmp/araphor-storage-release-override.toml`.

```sh
cargo test --offline -p araphor-data --features native-store,test-fixtures \
  --test native_raw --test raw_index --test native_store --test store_schema \
  --config /tmp/araphor-storage-release-override.toml
cargo check --offline -p araphor-data --no-default-features --lib \
  --config /tmp/araphor-storage-release-override.toml
cargo clippy --offline -p araphor-data --features native-store,test-fixtures \
  --lib --no-deps --config /tmp/araphor-storage-release-override.toml
```

The cases check original record positions, exact historical cuts, out-of-order
input, retries, CPU and epoch conflicts, joint coverage/control publication,
coverage change bounds, malformed change values, failed append and commit,
compaction, reopen, and corrupt raw controls. No existing assertion is removed.
The native tests close captured snapshots before reopen. Live snapshots retain
the engine handle; closing only `NativeStore` does not close those snapshots.

Clippy stops on the same two unchanged legacy `expect` calls recorded in the
[raw-index qualification](araphor-raw-index-2026-11-09.md). The new source has
no Clippy error. Changed native modules, the shared page owner, and integration
tests pass formatting. Existing formatting elsewhere remains outside that claim.
Full workspace CI does not run during iteration, as the user requires.

The final gate commands and exits remain in
`output/araphor-fjall-migration-20261109/native-raw-final-gates.json`.
Corresponding logs use `native-raw-final-*.log` in that directory.

## Existing package PoC

The existing combined runner passes all 64 package cycles. The existing stable
runner passes 128 primary cycles, 640 historical package evaluations, and 320
historical views. No requested retained view is unavailable. These runs keep
their original package calls, assertions, history, rollback, compaction, reopen,
saved CDC resume, and continued input. They add no new workload.

The optimized PoC binary is 93,622,864 bytes. Its SHA-256 is
`fe9a8cc97240e1d760379920ac2842041476a0877508a40f9a775b1cd1313c31`.
It remains at `output/araphor-fjall-migration-20261109/native-raw-poc`.
The previous qualified binary is retained separately as `native-raw-prior-poc`.
The unchanged commands are `native-raw-poc <report> combined` and
`native-raw-poc <report> stable`. The existing summary scripts check both reports.
The reports, summaries, and command exits use the `native-raw-` prefix in that
output directory. These are correctness qualifications, not paired performance
comparisons. The PoC's synthetic source records do not exercise the real raw
segments; the seven native raw cases provide that owner proof.

## Unchanged incident

The exact incident test passes with its existing definition, workload,
assertions, and timeouts:

```text
discovery::packages::required::incident::incremental::follows_incremental_sources
```

The harness takes 15.70 seconds. Process time is 15.741013 seconds. The existing
boundary parser verifies 18 collector receipts and three first durable
notification creations against their actual incident input revisions.

| Episode | Collector receipt to creation | Committed input to creation | Graph publication to creation | Public notification receipt |
| --- | ---: | ---: | ---: | ---: |
| 1 | 552.131 ms | 542.484 ms | 116.139 ms | 599.471 ms |
| 2 | 821.473 ms | 813.460 ms | 127.341 ms | 915.505 ms |
| 3 | 1,030.054 ms | 1,025.443 ms | 162.295 ms | 1,116.084 ms |

Bulk completion for 16,384 background logical records takes 2.438849 seconds.
This is one correctness qualification of the shared paging path. The incident
still uses the production DuckDB owner. These values are not a paired comparison
and do not establish a performance gain from the native owner or shared paging.

The binary uses Rust optimization level 0, debug information level 2, and debug
assertions. Its size is 2,932,297,008 bytes. Its SHA-256 is
`34e5f7d8845b902fc13b726d18a174c90325a726bae5ed1d981d2019e46f994f`.
The binary is retained at `target/araphor-notice-comparison-20261109/native-raw`.
The focused build command is:

```sh
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=6 cargo test --offline -p mithril-e2e \
  --lib discovery::packages::required::incident::incremental::follows_incremental_sources \
  --no-run --message-format=json \
  --config /tmp/araphor-storage-release-override.toml
```

The emitted executable runs with `--exact <test> --nocapture` and the same
`RUST_LOG` filters as the earlier control. Local sockets require execution
outside the sandbox. No Cargo build holds the target directories during this
run. Build, binary, process, runtime, and checked boundary records use the
`native-raw-incident-` prefix in the output directory above.

## Limits

This native owner does not yet provide configured capacity, required-input or
witness accounting, diagnostic admission, complete managed authority, lifecycle,
CDC routing, retention, or backup. Production still uses `AnalysisStore` and
DuckDB. No runtime backend selector or dual writes are added. History protection
currently retains the initial native cut through future writes. Local engine
path dependencies still require clean-checkout delivery work.

No incident speedup, creation below 100 milliseconds, or 100-fold result is
established by these owner checks.
