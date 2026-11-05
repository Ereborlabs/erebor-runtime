# Araphor durable storage investigation

Source and API review, 2026-11-05. Repository source: `0948da8f4`.
Investigation: **Done**. Engine selection, implementation, and measured gain:
**Not done**. This record supports the
[storage option in the active plan](../plans/araphor-reactive-execution-latency.md#6-select-the-durable-storage-engine).
It does not approve or implement a storage migration.

Investigate **redb first**, with **Fjall** as the log-structured alternative.
Replace SQL storage requests with direct typed access in one Data transaction.
Keep native DataFusion execution, generic Araphor Graph, and the existing raw
segments. Do not build a new transaction-log engine as the first option.
These are engineering recommendations. No candidate has run this workload.

## Intended end state

Data supplies one exact committed view to the saved native DataFusion plan.
A package stages changes through its existing transaction scope. Data commits
the complete step and publishes matching CDC progress after durability.
Readers keep their selected view while later writes proceed.

The replacement must remove the expensive SQL storage request path. It must
preserve captured-cut execution, stable identities, historical reads, exact
replay, quotas, evidence retention, backup, and recovery. It must not retain
DuckDB and a second engine as independent authorities for one atomic step.
Packages must not open or commit the selected engine.

## What the measurements establish

The final later managed commit has these medians across five runs of the
unchanged incident case:

| Stage | Milliseconds | Relationship |
| --- | ---: | --- |
| Complete managed commit | 960.515 | Includes preparation and durable publication |
| Private preparation | 118.467 | Inside complete commit |
| Transaction work | 786.845 | Inside complete commit |
| Publication-row preparation | 266.034 | Inside transaction work |
| Graph journals | 366.222 | Inside transaction work |
| Native Graph layer application | 277.772 | Inside Graph journals |
| Final durable `COMMIT` call | 51.528 | Inside complete commit, after transaction work |

Do not add nested intervals. These probes do not separate all DuckDB CPU,
filesystem time, and application work. The complete creation medians are
1.659962, 3.041402, and 3.300817 seconds. A preceding captured step can still
be in flight when the final incident input arrives.

Replacing only the final sync cannot meet 100 milliseconds. Replacing DuckDB
can also remove SQL planning, temporary relations, joins, row conversion, and
repeated lookups in the preceding work. That larger gain is plausible but
unmeasured. No speed factor or candidate commit latency is established.

Evidence:
`/tmp/araphor-recorded-follow-pairs-20261105/{summary,audit,final-warm-breakdown}.json`.
The [current handoff](../plans/araphor-execution-handoff.md#follow-transactions-use-the-recorded-input-cut-2026-11-05)
records the passing test and the recorded-cut performance regression.

## Current storage boundaries

| Owner and source | Current behavior | Replacement requirement |
| --- | --- | --- |
| [Raw append](../../crates/araphor-data/src/analysis/raw.rs), `commit_raw` | Appends and syncs a native journal record, then publishes its input position. Raw acceptance can precede SQL catalogue projection. | Keep this durable input log. Do not add another raw payload archive or require another database commit for each input without measured need. |
| [Catalogue projection](../../crates/araphor-data/src/analysis/raw_catalog.rs), `RawJournal::project` | Reconciles committed raw entries into metadata in revision order. | Keep the exact raw prefix and receipt meaning when metadata persistence lags. |
| [Snapshot coordination](../../crates/araphor-data/src/analysis/connection.rs), `coordinated_reader` | Acquires the Data writer coordinator before opening the reader. Pending raw catalogue work can be projected at this boundary. | A database snapshot alone is insufficient. Publish one view that binds metadata to the exact durable raw prefix. Remove the read-side writer gate only after that view is correct. |
| [Managed commit](../../crates/araphor-data/src/analysis/managed/commit.rs), `commit_managed_projection` | Commits results, call state, dependencies, evidence/context references, Graph changes, progress, completion, and revision metadata together. | Move the whole atomic family to one selected engine. Keep final live authority and expected-state checks. |
| [Generic Graph](../../crates/araphor-graph/src/store.rs) and [native members](../../crates/araphor-graph/src/committed.rs) | Stores stable identities, properties, layers, and historical membership. Native pending owners roll back if Data does not commit. | Keep Graph values and adjacency in Araphor Graph. Replace its SQL storage operations with transaction access supplied by Data. Add no package rules or independent Graph commit owner. |
| [Notification state](../../crates/araphor-analysis/src/notification/store.rs) | Saves the decision, pending attempt before the effect, and outcome after the effect through Data contexts. | Preserve these atomic saves and attempt identities. Graph publication and later notification decisions do not have to become one transaction. |
| [CDC registration](../../crates/araphor-data/src/analysis/inputs/mod.rs) | Registers matching interests before capture. Publishers advance committed input positions after successful writes. | Retain `StorePositionV1`, including raw-only commits and ordinals. An engine sequence number or WAL offset is not a substitute. |

The [attempt-first replacement in the plan](../plans/araphor-reactive-execution-latency.md#2-replace-attempt-first-publication-with-one-atomic-change-commit)
also removes the normal durable pre-execution attempt for pure package
computation. The current `register_managed_attempt` still commits that attempt
before result publication. An engine investigation must count this transaction
and the later notification transactions, not only the final Graph sync.
This investigation changes none of those behaviors.

## Candidate comparison

| Candidate | Fit | Work and limits to assess | Recommendation |
| --- | --- | --- | --- |
| redb | Embedded Rust database with ordered tables, one writer, and concurrent readers. Atomic changes can cover the metadata and Graph tables together. | Define compound keys and secondary indexes. Preserve history and external file leases. Account for reader-pinned pages, file reuse, backup, and crash recovery. | First candidate for the typed metadata transaction. It is already named in the plan. |
| Fjall | Embedded Rust LSM engine with a journal, ordered keyspaces, snapshots, and transactions across keyspaces. | Require durable transaction sync. Account for background flush/compaction, disk reserve, read amplification, snapshot lifetime, and supported key/value sizes. | Concrete log-structured alternative to compare with redb. |
| RocksDB | WAL-backed LSM engine with snapshots and atomic batches across column families in one database. | Adds a C++ storage dependency and its maintenance configuration. Read-check-write validation must still use Data's serialized writer or the engine's transaction API. | Secondary reference. Add it to qualification only if the Rust candidates fail a concrete requirement. |
| Custom append-only transaction log | Could store one typed change set per Data commit. | Requires a commit protocol, recovery, read indexes, historical roots, checkpoints, reclamation, quotas, and backup. Raw framing alone supplies none of the complete metadata transaction. | Do not select first. Reuse a storage engine unless measured requirements rule out the existing engines. |
| Keep DuckDB | Retains current durable tables and recovery behavior. | The same replacement snapshot and transaction shape is still needed. Keeping the current request sequence preserves its overhead. | Comparison control, not proof that DuckDB can or cannot meet the target. |

### redb

The reviewed API reports redb 4.4.0. Its database supports concurrent read
transactions while one write transaction runs. `Durability::Immediate` makes
a successful commit durable. Use the engine's direct table and range access
for storage; leave SQL computation in DataFusion.
[Database API](https://docs.rs/redb/latest/redb/struct.Database.html),
[durability API](https://docs.rs/redb/latest/redb/enum.Durability.html).

The storage uses copy-on-write B+trees. Reader roots retain old pages until
they are released. Database MVCC is useful for an active query, but it does
not replace retained application result versions after restart.
[Storage design](https://github.com/cberner/redb/blob/master/docs/design.md).

The write API documents a tradeoff between default checksum-based recovery
and quick repair with two-phase commit. Quick repair adds commit work. The
engine choice must include a recovery policy and its cost, not only the
fastest sync setting. No policy is selected here.
[Write transaction API](https://docs.rs/redb/latest/redb/struct.WriteTransaction.html).

### Fjall

The reviewed API reports Fjall 3.1.13. Its single-writer transaction database
fits Data's existing serialized commit owner. Use one transaction across
keyspaces for the complete step. A batch with no protected read-check-write
scope does not replace current expected-head validation.
[Transaction database](https://docs.rs/fjall/latest/fjall/struct.SingleWriterTxDatabase.html).

Set transaction durability explicitly. `PersistMode::SyncAll` uses `fsync`;
`Buffer` does not guarantee persistence after power loss. The write transaction
is not `Send`; keep it inside the synchronous Data commit scope.
[Transaction API](https://docs.rs/fjall/latest/fjall/struct.SingleWriterWriteTx.html),
[persistence API](https://docs.rs/fjall/latest/fjall/enum.PersistMode.html).

Fjall supplies engine-owned background maintenance. Its snapshots preserve a
consistent view across keyspaces. They also retain old data while held.
Data retention must decide when evidence and historical results can expire;
an LSM compaction filter must not make that business decision independently.
[Engine source](https://github.com/fjall-rs/fjall),
[snapshot API](https://docs.rs/fjall/latest/fjall/struct.Snapshot.html).

The transaction API documents a 64 KiB key limit and a value limit of 2^32
bytes. Check current context and Graph keys and Arrow value layouts before
selection. Do not impose new public limits, truncate keys, or serialize a
complete Graph into one value to fit an engine.
[Key/value API limits](https://docs.rs/fjall/latest/fjall/struct.SingleWriterWriteTx.html#method.insert).

Both reviewed package manifests require Rust 1.90. They are not dependencies
of the current workspace. No dependency build is claimed.
[redb manifest](https://github.com/cberner/redb/blob/master/Cargo.toml),
[Fjall manifest](https://github.com/fjall-rs/fjall/blob/main/Cargo.toml).

RocksDB also needs explicit synchronous WAL writes for durable acknowledgement.
Its atomic batch must remain within one database; separate databases do not
provide cross-family atomicity.
[WAL behavior](https://github.com/facebook/rocksdb/wiki/WAL-Performance),
[atomic batch scope](https://github.com/facebook/rocksdb/wiki/RocksDB-FAQ).

## What log-based storage would mean

The existing raw journal stores accepted evidence. A storage-engine WAL
protects database mutations. A CDC position identifies committed application
input. A retained Graph layer identifies Graph membership at a result cut.
These are related records with different owners and retention rules.

Fjall and RocksDB already combine a log with indexed storage and recovery.
Selecting one does not require a new application WAL. Keep Data's logical
commit revision stable across engine maintenance. Subscriptions read retained
application journals and history, not the engine WAL. The engine can reclaim
its WAL when its own durable storage permits it. Data retains application
history until its input cursors, result references, and retention rules permit
removal.

A custom log must do more than append a Graph delta. It must make Graph
membership, properties, package state, expected heads, evidence references,
and progress recover as one complete change. It must distinguish a torn tail
from committed records, rebuild or restore indexes, retain historical cuts,
and reclaim files without removing pinned evidence. Those duties would become
our storage-engine code. A sequential append alone is not a complete proposal.

The checked-out TerminusDB adapter at `f9b4791815aad4f80251c252e1553f846a48a32f`
separates building a layer from changing a named Graph head:
[builder commit](https://github.com/terminusdb/terminusdb/blob/f9b4791815aad4f80251c252e1553f846a48a32f/src/rust/terminusdb-store-prolog/src/builder.rs)
and [head operations](https://github.com/terminusdb/terminusdb/blob/f9b4791815aad4f80251c252e1553f846a48a32f/src/rust/terminusdb-store-prolog/src/named_graph.rs).
Use the immutable layer and indexed adjacency lessons in Araphor Graph.
Do not give that adapter independent commit authority over package progress.
An immutable Graph page, if used, must be prepared and durable before Data
atomically publishes its reference. Its orphan and retention rules must be
defined. This is a design requirement, not an implemented page store.

## Proposed snapshot and commit flow

The following flow is a proposed common contract for engine evaluation.
It is not a new public API or an implemented cache.

```text
A raw input commits at Data revision R
  -> The existing raw owner makes the append durable.
  -> Data publishes a committed view with the exact raw prefix through R.
  -> The view keeps the matching metadata snapshot and raw file leases.
  -> Data advances only matching subscription input positions.

A subscription consumes input after its saved position
  -> Query pins one committed view without acquiring the Data writer.
  -> Native providers supply selected Arrow data from that view.
  -> The saved DataFusion plan executes the declared package calls.
  -> Packages stage Graph and other changes in their transaction scope.

A package step is ready
  -> Data checks live authority and its expected mutable state heads.
  -> Data validates retained evidence and the recorded input cut.
  -> Data writes all changes for the step in one engine transaction.
  -> The selected engine completes the durable commit.
  -> Data publishes the matching native owners and committed view.
  -> Data advances matching CDC positions.
  -> Input committed after the captured cut stays pending.

A commit fails or its durable outcome is uncertain
  -> Data does not acknowledge new input or publish unconfirmed owners.
  -> Data recovers the durable state and exact attempt outcome.
  -> Retry starts from the recorded committed cursor and state.
```

Raw-only commits can reuse an unchanged metadata root. They must not require
a second payload copy or a forced key-value commit solely to open a snapshot.
A later metadata commit must publish a root that includes the correct raw
prefix. The serialized Data commit owner can order publication; readers must
not acquire that writer merely to pin the published view. Do not copy the
whole catalogue or Graph on each root publication.

The concrete publication mechanism, raw prefix pinning, and retained-memory
cost are unresolved implementation work. Prove raw-only commits between
metadata commits, concurrent capture, and retention before removing the
current coordinator. An engine snapshot by itself does not close this gap.

## State and indexes to move together

Use existing typed binary and Arrow representations. Store changed values
and retained references; do not add durable full input or output archives.
The storage replacement needs these access paths:

| State | Direct storage access needed |
| --- | --- |
| Store and instance metadata | Identity and recovery epoch; instance, generation, grant, lifecycle, progress, and completion heads |
| Call state and results | Exact tenant/result/revision lookup; call heads; immutable state and replay references; dependency edges |
| Contexts and evidence | Exact version lookup; owner/entity ranges; evidence pins; source ranges and expiry records |
| Generic Graph | Stable value dictionaries; property coordinates; versioned membership; incoming/outgoing adjacency; writer and parent heads |
| Finding projection | Actual result membership and typed finding columns available to native SQL |
| Notification state | Obligation identity; expected state revision; pending attempt; retry/deadline access; saved outcome |

Engine snapshots protect live transactions. Durable historical reads still
need application revision keys or membership intervals. Keep those histories
until Data's existing retention rules permit removal. Do not create an engine
savepoint for every Graph result or rely on an engine's transient MVCC history.

DataFusion keeps SQL parsing, optimization, joins, aggregation, windows, and
package-call execution. Existing providers change their storage reads and
continue to supply Arrow batches. Generic Graph keeps graph operations and
contains no package, detector, or notification routing rules. These boundaries
use DataFusion's supported provider extension surface.
[Native provider contract](https://datafusion.apache.org/library-user-guide/custom-table-providers.html).

## Removal and verification boundary

A selected implementation must replace Data's DuckDB read/write operations,
the SQL-based Graph persistence path, raw catalogue reconciliation, and the
DuckDB-specific backup/recovery code that depends on those records. Update
schema validation, quotas, retention, tracing, and exact replay with that
owner. Do not retain a general permanent multi-engine framework or an old
authoritative fallback path.

[Recovery](../../crates/araphor-data/src/analysis/connection.rs) must restore
the durable outcome before native owners or CDC become visible.
[Backup](../../crates/araphor-data/src/analysis/backup.rs) must capture one
metadata cut plus exact committed raw file ends and their leases.
[Retention](../../crates/araphor-data/src/analysis/retention.rs) must preserve
pins, nonprefix expired ranges, source floors, and recoverable file deletion.
Engine compaction does not supply these application rules.

The next useful implementation decision is the exact snapshot and typed
change transaction, followed by redb versus Fjall qualification of that same
transaction. Compare full request work and durable acknowledgement, not just
sync calls. Use the existing incident inputs, assertions, and timeouts for
the end-to-end result. Keep history, backup, and recovery correctness evidence
separate from the latency claim. No new performance workload is added here.

No production code, dependency, storage format, fixture, or test changed in
this investigation. No candidate was compiled or timed. Independent reviewer
findings: `/tmp/araphor-storage-options-review-20261105.json`.
