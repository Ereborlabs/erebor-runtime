# Final engine acceptance

Result: **Done for the approved engine scope**, 2026-11-09. The implementer and
independent reviewer read the complete [storage plan](../../../../../../../docs/plans/fjall-versioned-storage.md)
and found no missing planned API or required lifecycle proof. The engine code
needed no further change. The user accepted the current benchmark and requested
completion. This acceptance replaces the remaining numeric performance gate.
It does not prove the original combined median target or a repeatable latency gain.

## Source

Both native trees were clean during final verification:

- Fjall: `bdb1843574f00ed9153233b547d2e2fd055c266a`.
- `lsm-tree`: `2e1b5df34ffc5db3275010f4bd5832518453b121`.

The [review guide](../../../../../../../docs/guides/fjall-versioned-storage-review.md)
gives the public API owners, recovery order, lock order, and source reading route.
[source.json](source.json) records the exact engine commits.

## Required behavior and proof

| Contract | Source and existing proof |
| --- | --- |
| Durable mode, catalogue, revision and identity counters | [Mode and recovery tests](../../../../../../../fjall/src/versioned/tests.rs) check interrupted initialization, journal recovery, published clocks, and deleted physical IDs. |
| Exact receipts and atomic caller state | [Receipt tests](../../../../../../../fjall/src/commit.rs) check empty and aborted writes, cross-keyspace state, legacy buffering, and concurrent writers. [Branch tests](../../../../../../../fjall/src/versioned/branch_tests.rs) check data, head, and progress in the same batch. |
| Durable historical point, prefix, and range reads | [Native history tests](../../../../../../../lsm-tree/tests/retained_history.rs) check compaction, restart, exact retention, and per-tree reclamation. [Read-view tests](../../../../../../../lsm-tree/tests/read_view.rs) check deletion state, native overlays, held guards, and blob lifetimes. |
| Sparse branches and fixed ancestor cuts | [Branch tests](../../../../../../../fjall/src/versioned/branch_tests.rs) check nested forks, zero copied parent rows, inherited deletes, reverse scans, retained gaps, name reuse, and collection after reader release. |
| Original-journal CDC and combined lifecycle | `branch_history_and_original_cdc_continue_together` in [branch tests](../../../../../../../fjall/src/versioned/branch_tests.rs) checks concurrent bootstrap/floor registration, compaction/reopen, exact cursors and branch IDs, output/progress rollback and atomic commit, commit-driven waiting, name reuse, policy release, and continued resume. [Feed tests](../../../../../../../fjall/src/cdc.rs) check one-batch streaming, cancellation, partial consumption, rotation, and failure. |
| Lazy historical cursor lookup | [Snapshot tests](../../../../../../../fjall/src/versioned/read.rs) check exact lookup, absent cursors after journal collection, readable retained values, and decoder failures. |
| Sealed recovery and retired identities | [Segment tests](../../../../../../../fjall/src/journal/segment/tests.rs) check persisted-payload skipping, metadata fallback, interrupted rotation, and reader leases. [Retirement tests](../../../../../../../fjall/src/versioned/retire/tests.rs) check journal/history protection and cleanup retry. |

All four implementation increments in the plan are complete. Native keys have
no application revision suffix. Native SST and WAL entry formats remain. The
engines contain no package, Graph, SQL, or DataFusion semantics.

## Final verification

All 11 commands in [gates.json](gates.json) exit successfully. The file records
the exact commands, timestamps, log names, and SHA-256 hashes.

| Check | Result and raw log |
| --- | --- |
| Native default library and eight selected integrations | [244 library + 19 integration cases pass](native.log); two library and one integration case remain ignored. |
| Native LZ4 library and the same integrations | [247 library + 19 integration cases pass](native-lz4.log); the same existing cases remain ignored. |
| Native library clippy | [Pass](native-clippy.log), with existing warnings. |
| Native formatting | [Pass](native-format.log). |
| Fjall CDC library | [128 pass](cdc.log), one existing ignored case. |
| Fjall library without CDC | [87 pass](default.log), one existing ignored case. |
| Fjall production without default features | [Pass](no-default.log). |
| Fjall CDC library clippy | [Pass](clippy.log), with existing warnings. |
| Fjall formatting | [Pass](format.log). |
| Native documentation tests | [23 pass](native-doc.log). |
| Fjall CDC documentation tests | [86 pass](fjall-doc.log). |

All ten saved PoC reports reproduce their committed summaries exactly with the
unchanged summary functions. [summary-checks.json](summary-checks.json) records
the report and summary hashes. These are eight untraced reports and two CPU
profile reports; profiled timings remain excluded. This final check runs no
new benchmark. The original reports remain in the
[borrowed-lookup archive](../borrowed-lookup/raw-evidence.tar.zst).

## Accepted measurements

These are the existing current-source measurements, in milliseconds:

| Pass | Combined median | p95 | Maximum | Stable eight-cycle median |
| --- | ---: | ---: | ---: | ---: |
| 1 | 4.653 | 7.187 | 8.332 | 25.042 |
| 2 | 4.568 | 7.080 | 7.223 | 25.939 |

Each combined result uses 28 ordinary fixed-key samples. p95 uses nearest
rank, the 27th ordered sample. Maintenance/restart remains separate. Workloads,
assertions, execution order, values, caches, durability, and timing boundaries
remain. [The earlier comparison](../borrowed-lookup/README.md) preserves the
controls, CPU counts, raw evidence, and original target misses.

## Limits

Full workspace CI was not run, as the user requires. Existing ignored cases
and clippy warnings remain. The known upstream test build error without default
features was not changed or rerun; the production check above passes.

Araphor production integration, DataFusion input, notification delivery, branch
merge, shared-SST writable forks, and distributed storage remain outside scope.
The PoC does not establish a production sub-100 ms notification path or a 100x
incident-test gain. [verification.json](verification.json) records this boundary
and the identity of the retained benchmark archive.
