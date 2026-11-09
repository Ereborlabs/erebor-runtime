# Journal and history simplification

Result: **Done for the four approved changes on the observed PoC workload**.
The implementer and reviewer agree on each direction before editing. The
reviewer checks each final source change and the complete verification record.
Public APIs, persistent formats, native storage ownership, `SyncAll`, and the
existing PoC workloads remain.

## Source changes and proof

| Commit | Change | Existing or added native proof |
| --- | --- | --- |
| `13b04ae` | Store sealed segments in an ordered `VecDeque`. Feed transitions use binary search on numeric segment IDs. Collection removes the front without shifting other entries. | `retained_segment_order`: empty rotations, collection, append, saved-offset replay, expiry, and reopen. |
| `6b62b16` | Publish pin protection only when a range first appears or its final owner leaves. Admission still runs for every pin. | `shared_pins_preserve_cuts`: duplicate point/future pins, head advancement, partial/final release, and an unavailable interior cut. |
| `d8a4613` | Each policy or fork owns its projected interval in each affected tree. Runtime changes visit that source's ancestry. Recovery derives all contributions from the durable catalogue before workers start. | `contributions_keep_their_owners`; `changes_skip_other_branches`, which holds an unrelated history lock while fork/policy/reclamation operations complete. Existing compaction, retention-release, and nested-fork cases remain. |
| `a042865` | Prepare branch writes under a brief catalogue lock, then release it before sync and backpressure. Capture and publish through the existing signal boundary. `History` owns the runtime branch head. Remove the cached `Clock.published` field. | `captures_skip_pending_sync`; `publication_failure_stays_invisible`; `cut_survives_empty_journal`; existing exact-receipt, failed-sync, rollback, and combined lifecycle cases. |

Final source is Fjall `a0428657063727739e2b1688984b690e96046674` and
`lsm-tree` `2e1b5df34ffc5db3275010f4bd5832518453b121`. Both trees are clean.
The comparison starts from Fjall `bdb1843` with the same `lsm-tree` source.
The exact sequential patches are [A](a.patch), [B](b.patch), [C](c.patch), and
[D](d.patch). [verification.json](verification.json) records their identities.
The [source review guide](../../../../../../../docs/guides/fjall-versioned-storage-review.md)
gives the owner and lock reading route.

The sync-pause hook exists only in test builds. After release, the test calls
the real native `SyncAll`. During the pause, a reader captures the previous
complete revision and exact cursor. The reader can inspect branch metadata
and route an already-buffered durable batch. A concurrent raw writer then
gets its own exact later receipt. Held views retain their earlier values.
Recovery also opens retained branch state at a nonzero revision when its
journal payload is gone; its cursor is absent.

## Focused verification

All 11 [final commands](final-gates.json) exit successfully:

- Native default/LZ4 libraries: 244/247 cases pass; two existing cases remain ignored in each configuration.
- Eight selected native integrations: 19 cases pass; one existing case remains ignored in each configuration.
- Fjall CDC/without CDC libraries: 135/87 cases pass; one existing case remains ignored in each run.
- Native/Fjall documentation: 23/86 cases pass.
- Production without default features, library clippy, and formatting pass. Existing clippy warnings remain.

The archive contains every gate log. It also retains the initial format-only
failure before correction; all final format checks pass. Full workspace CI
is not run, as the user requires.

## Unchanged PoC comparison

The existing combined and stable drivers each run four times per binary.
The outer before/after order is balanced in two repeated comparisons. Their
fixtures, inner engine order, cycle counts, values, caches, durability,
assertions, timing boundaries, and summary functions remain. No build, test,
profiler, archive, or large hash job runs during timing calls.

All 16 summaries pass. Each before/after pair has identical complete reports
after removal of only the top-level source label and timing fields ending in
`_s`. Physical CDC cursors match. Historical requests after writes, compaction,
and reopen remain supported with exact result checks.

Each combined pass has 28 ordinary fixed-key samples. Restart remains separate.
p95 uses nearest rank, the 27th ordered sample. Values below are milliseconds.

| Pass | Before median / p95 / maximum | After median / p95 / maximum | Before stable median | After stable median |
| --- | --- | --- | ---: | ---: |
| 1 | 4.680 / 8.387 / 9.174 | 4.621 / 7.940 / 8.103 | 28.516 | 27.856 |
| 2 | 4.701 / 7.510 / 7.771 | 4.995 / 7.605 / 7.797 | 28.199 | 28.857 |
| 3 | 4.657 / 8.056 / 11.852 | 4.528 / 7.281 / 8.171 | 28.413 | 29.101 |
| 4 | 4.606 / 7.587 / 8.245 | 4.259 / 7.668 / 7.814 | 29.419 | 28.071 |

Pooling the same 112 ordinary samples per side gives median/p95/maximum
4.672/8.056/11.852 before and 4.655/7.668/8.171 after. The median of the
16 existing stable eight-cycle runs per side is 28.413 before and 28.321 after.
The pooled values do not replace the individual passes above. Individual
passes are mixed. No consistent regression is observed. No repeatable latency
gain or universal performance guarantee is established. The cause of higher
individual maxima is not established.

## Evidence and reproduction

- [Binary hashes and source commits](binary.json), [build command](build.json), [release override](release-override.toml), and dependency locks: [Fjall](fjall.Cargo.lock), [native tree](lsm-tree.Cargo.lock), [PoC](poc.Cargo.lock).
- Exact outer commands: [first comparison](commands.json) and [repeat](commands-2.json). Measured values: [first comparison](measurements.json) and [repeat](measurements-2.json).
- Full work/cursor checks: [first comparison](work-check.json) and [repeat](work-check-2.json).
- Reproduction scripts: [build](build.py), [compare](compare.py), and [archive builder](publish.py). The comparison script runs with no argument for passes 1/2, then argument `2` for passes 3/4.
- [Raw reports, logs, gate commands, patches, and source records](raw-evidence.tar.zst). All 96 archive members are compared byte for byte with their originals. All 16 standalone summaries reproduce exactly.
- [Environment observation](environment.json) is taken after the calls. It does not establish host load during timing.

Extract the archive with `tar --zstd -xf raw-evidence.tar.zst`. Restore its
`reports/` files under `output/storage-engine-simplify-20261109/`. The frozen
executables remain at the paths in `binary.json`. Run the scripts from the
repository root. Move existing report files before a rerun; the scripts refuse
to overwrite them.

Native tests cover retained backlog replay, nested forks, and updates that
skip unrelated history. Large backlog/depth performance is not separately measured.
Historical sequence-bound lookup remains linear because empty seals have no
ordered sequence bound. Structural metadata operations retain catalogue
serialization. Production Araphor integration and notification latency remain
outside this proof.
