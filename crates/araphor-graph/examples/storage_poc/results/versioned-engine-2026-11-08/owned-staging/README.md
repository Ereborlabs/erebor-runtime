# Consume owned transaction staging

Result: **Done for measured ordinary apply CPU work; Not done for complete performance**.
Accepted source: Fjall `bdb1843` and `lsm-tree` `1918e262`.
The [patch](consume.patch) consumes a staging memtable through the existing
native `SkipMap` owning iterator when `Arc::try_unwrap` succeeds. A held
iterator keeps an `Arc` and uses the existing borrowed iteration path.
Both paths use one append closure with the same latest-key selection and
`Item::new` checks. Owned key/value fields move into the batch. The remaining
owned keyspace handle moves into the set used for maintenance after publication.
No new index, overlay state, durable format, or API is added.

## Untraced elapsed results

Each combined report has 28 ordinary fixed-key samples. Restart remains
separate. p95 uses nearest rank, sample 27 of 28. Stable values are medians
of four existing eight-cycle runs. Units are milliseconds.

| Pass | Side | Combined median | p95 | Maximum | Stable median |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Before | 4.606 | 7.048 | 7.284 | 25.698 |
| 1 | After | 4.734 | 7.322 | 7.837 | 25.879 |
| 2 | Before | 4.808 | 7.314 | 8.032 | 26.679 |
| 2 | After | 4.774 | 6.947 | 7.247 | 25.860 |

All eight existing summaries pass. Full reports match after removing only
the source label and timing fields; physical CDC positions also match.
Fixtures, engine order, caches, values, `SyncAll`, assertions, and timing
boundaries remain. No build, test, profiler, large hash, or archive job runs
during these calls. Results remain mixed. Both candidate medians exceed
the recorded 4.370082 ms target; both maxima and stable medians reach their
8.717326 ms and 26.985 ms targets. No repeatable elapsed gain is proved.

## Complete apply CPU result

The collector runs the unchanged combined driver with the same frozen
executables. All profiled timings are excluded. Each side has 72 actual
one-entry/return apply dumps: 64 primary calls and eight rollback calls.
Analysis selects 28 ordinary fixed-key output transactions. Raw headers,
totals, exclusive sums, and exact incoming root costs agree in all 144 dumps.
Residual and worker dumps collect zero instructions. Domain work and all
non-time report fields, including cursors, match. Both summaries pass.

| Scope | Before instructions | After instructions | Actual calls |
| --- | ---: | ---: | ---: |
| Complete ordinary output apply | 194,219,131 | 192,247,610 | 28 |
| Nested entered `WriteSet::into_batch` | 4,214,989 | 2,462,194 | 28 |

Complete ordinary apply uses 1.015% fewer instructions. The nested scope
overlaps the complete owner; do not add these counts. Every reachable nested
node balances. Disappearance of a standalone iterator symbol does not count
the unique and shared paths, because the compiler can inline calls. The source
and held-iterator test prove those paths. The reviewer independently checks
the full profile accounting and report equality.

## Source checks and reproduction

`consume_staging` checks unique ownership and a real held native prefix
iterator. It checks latest strong and weak deletion types, empty values,
overwritten values, and a commit across two keyspaces. Held rows retain their
earlier values after commit. A held rollback row remains readable after the
transaction is discarded, while the database has no committed rollback row.
Existing branch, receipt, history, and recovery cases remain in the suites.

Fjall CDC/without CDC pass 128/87 cases, with one existing ignored case each.
The production check without default features, library clippy, formatting,
and release build pass. Existing clippy warnings remain. Native `lsm-tree`
source is unchanged. Full workspace CI is not run during iteration, as the
user requires.

- [Verification, measurements, and archive identity](verification.json).
- [Source patch](consume.patch), [binary identity and build commands](consume-binary.json), and [gate commands/results](consume-gates.json).
- [Build](build.py), [gates](gates.py), and [balanced comparison](compare.py).
- Complete apply [collector](profile.py) and [strict analysis](analyze.py).
- [Raw reports, profiles, logs, commands, and detailed CPU counts](raw-evidence.tar.zst).
- [Archive builder](publish.py), [tool identity](tool.json), [earlier environment observation](environment.json), and [release override](release-override.toml).

The archive builder compares every member byte with its original file and
reproduces all ten summaries. The environment file keeps an earlier host and
tool observation with its original timestamp; it does not establish host load
or build environment during these measurements. Build commands and binary
hashes identify the measured executables.

Extract with `tar --zstd -xf raw-evidence.tar.zst`. Restore `callgrind/` files
under `/tmp/araphor-callgrind/` and `reports/` files under
`output/storage-engine-baseline-20261108/`. Run saved scripts from the
repository root with the recorded tool and frozen executables. Move existing
reports or the evidence directory before rerunning scripts that refuse to
overwrite them. Production input, notification delivery, and a 100x incident
test gain remain outside this PoC proof. Complete performance remains **Not done**.
