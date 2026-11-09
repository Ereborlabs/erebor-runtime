# Native Data metadata qualification

Date: 2026-11-09. Result: **Done for the optional metadata owner and its existing
package PoC caller. Production migration and incident performance are not done.**
Read the [source review guide](../../../../../../docs/guides/araphor-native-data-review.md).

## Source and behavior

[Source identity](native-data-source.json) records Runtime parent `78e909526`,
Fjall `cceaa84`, the native tree `2e1b5df34ffc`, changed source hashes, and the
frozen binary. The control is the prior native Graph participant. Its binary
SHA-256 is `f307cc30a7de1ef4a664f903754e293f0727a5e6f3e78b81dbe16486fcf1a2c3`.
The candidate is `output/araphor-fjall-migration-20261109/native-data-poc`.
Both binaries use release settings and the [same link override](release-override.toml).

Data now owns the native database, private directory lease, branch, Data
revision allocation, exact cut index, and published metadata view. Every native
PoC source, package output, and checkpoint write uses that owner. Graph borrows
the transaction. Physical context versions replace the PoC's separate `S`, `T`,
and `H` records. The PoC's logical Graph cuts map to allocated Data revisions.
Those fixture coordinates do not control Data's allocator.

Initialization publishes Data revision 0 at an exact native cut. The first
ordinary write gets revision 1. This preserves the existing Data API. An earlier
candidate initialized revision 1. Its superseded source, binary, and evidence
remain in `output/araphor-fjall-migration-20261109/native-data-initial-r1/`.

## Correctness

The [public integration target](native-data-r0-integration.log) passes five cases.
The cases check immutable retries, expected heads, rollback, initial revision
0, first reference revision 1, captured readers during a write, long binary
keys, joint Graph/context/progress batches, exact stamps, commit failure and
reopen, compaction, cut corruption, and interrupted initialization. Reopen
rejects replacement history protection that covers only the latest cut.

The [stable report](native-data-stable.json) and
[checked summary](native-data-stable-summary.json) pass 128 primary cycles,
640 historical package evaluations, and 320 historical views. Exact results
survive compaction and reopen. No requested retained view is unsupported.
The native target keeps 186 Graph membership keys and two context heads.
Immutable context version records have no fixed total count.

All eight paired combined runs pass the original 64-cycle assertions. Source
and Graph wakes walk original journals. Saved positions resume and continue
after reopen. Package calls, source frontiers, state, evidence, findings,
historical views, rollback, and membership-key checks retain their assertions.
The source workload, logical Graph revisions, and timeouts do not change.

## Measured comparison

The [driver](compare.py) runs four alternating pairs after compiler jobs stop.
[Commands and exits](native-data-pairs.json) record every run and frozen binary
hash. [Pooled results](native-data-pair-summary.json) contain 112 ordinary native
target samples per version. The p95 uses inclusive linear interpolation.

| Source write through result inspection | Prior Graph owner | Data owner |
| --- | ---: | ---: |
| Median | 7.371 ms | 7.225 ms |
| p95 | 12.702 ms | 13.049 ms |
| Maximum | 14.584 ms | 13.258 ms |

These small mixed differences do not establish a repeatable performance gain.
The candidate includes Data publication and physical context records.
`output_sync_s` includes Data commit and publication. It does not isolate the
durable sync call. The complete comparison boundary retains all result-read
work. The stable run supplies correctness evidence; it ran before the paired
comparison and has no separate speed claim.

## Verification limits

[Gates](gates.json) record the final integration target, release build,
changed-file formatting, feature-off check, and known failed checks.
The earlier Data `--lib` command cannot build its unchanged legacy test target.
That target refers to stale fixture paths, removed detector APIs, duplicate
fixture methods, and removed fields. No existing assertion is disabled.

Clippy stops on unchanged legacy Graph `unwrap` and Data `expect` calls.
The dependency-free attempt also reports existing warnings. The check is not
clean. Full workspace CI is not run, as the user requires during iteration.
Retained log copies remove trailing whitespace. Original logs remain in
`output/araphor-fjall-migration-20261109/`.

This result does not qualify production raw publication, managed authority,
qualified contexts, memory budgets, all result and reference families,
DataFusion input capture, notification batching, retention, or backup.
Fork dependencies still use local paths. Clean-checkout delivery is not
qualified. Production still uses DuckDB. The incident test, creation below
100 ms, and the requested 100-fold gain remain **Not done**.
