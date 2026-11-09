# Fjall durable history, branches, and CDC

Extend the Fjall fork with generic versioned storage. Applications decide what
keys mean, which history to retain, and how to use journal changes. The engine
has no Araphor Graph, package, finding, SQL, or DataFusion dependency.

Status: **Done for the approved engine scope**. Final review: 2026-11-09.
The user accepted the current benchmark on 2026-11-09. See
[final verification](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/finalization/README.md).
The original combined median target is not proved. Earlier measurements and
their qualification results remain below.
The four approved follow-up simplifications are complete at Fjall `a042865`
and `lsm-tree` `2e1b5df3`. Their [verification record](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/simplification/README.md)
includes the unchanged PoC comparisons and all focused checks.

## Intended end state

Stable user keys support indexed historical reads after compaction and restart.
A branch stores its identity, name, parent, fork revision, and head. Forks copy
no parent records. Child changes and deletions override a fixed parent view;
ordered scans work in both directions. Durable commits return their exact
revision and original-journal cursor. CDC resumes from that cursor and waits
for log publication. Applications select matching subscriptions.

This covers the required [Neon branching semantics](https://neon.com/docs/introduction/branching):
fork retained current or past state, isolate writes, and share unchanged data.
The implementation uses native KV versions rather than PostgreSQL page redo.
Neon-equivalent branch scale and latency are not established.

Use [araphorlabs/fjall](https://github.com/araphorlabs/fjall), checked out in
[`fjall/`](../../fjall/), and [araphorlabs/lsm-tree](https://github.com/araphorlabs/lsm-tree),
checked out in [`lsm-tree/`](../../lsm-tree/). Record both source commits.
Keep upstream crate names and existing flat APIs. Araphor adapters and
production storage migration are separate work.

Implementation goal: deliver these two engine forks
with durable history policies, indexed historical reads, writable branches,
and resumable original-journal CDC on stable user keys. Completion requires
the public API and combined lifecycle proof below. The original performance
criterion was to match or improve the existing Fjall PoC benchmark with the
same workloads, timing fields, and measurement conditions. The user accepted
the current measured benchmark in place of that remaining criterion.

## Implementation flow

```text
Caller retains a revision range or forks a retained revision
  -> Fjall protects the required cuts against concurrent maintenance.
  -> One journaled transaction saves the policy or branch descriptor.
  -> Fjall publishes the new handle after durable completion.

Caller reads branch B at revision R
  -> Fjall captures one revision, ancestor chain, and retention protection.
  -> Native indexes select B's visible value or strong deletion marker.
  -> A missing override reads the parent at min(R, B's fork revision).
  -> Native ordered iterators merge child and ancestor results.

Caller commits changes through a branch transaction
  -> The existing single writer allocates one commit sequence.
  -> One batch contains changes, branch heads, and caller-supplied state.
  -> SyncAll completes before visibility, receipt, and CDC publication.
  -> The caller receives that batch's revision and cursor.

Caller opens a journal feed after its saved cursor
  -> The application's floor coordinator protects that consumer's start.
  -> The reader seeks the original journal file and byte offset.
  -> The native decoder returns one complete durable batch at a time.
  -> The application saves consumed progress with its resulting writes.
  -> The application advances the log floor to its minimum saved consumer cursor.

Caller removes a branch name and later requests journal collection
  -> One journaled transaction removes the public name and prevents new writes.
  -> The journal manager reclaims acknowledged and persisted segments.
  -> Fjall keeps identities required by readable CDC, children, policies, or views.
  -> One journaled transaction removes unreferenced branch descriptors.
  -> Native metadata removes orphan trees; recovery retries interrupted cleanup.

Process restarts, or an operation fails
  -> Recovery opens current manifests and replays only required recovery data.
  -> Recovery restores branch records and retention before maintenance starts.
  -> Expired history or log positions return an error.
  -> Aborted and empty writes publish no change; uncertain I/O stops publication.
```

## Original APIs and source findings

Reviewed Fjall 3.1.13 at `87006048139bfe1b072bbc29a5a92bf1f97628e3`, with
the existing [CDC patch](../../crates/araphor-graph/examples/storage_poc/cdc-bench/fjall.patch).
The initial local `lsm-tree` fork was version 3.1.10 at
`9ba4f247b440774f9904febfdb25f7fc27159af4`.
Earlier PoC results used registry source at
`9812163ae144213b6bb576a147fda066e7ab4ab1`, not the new checkout.
The intervening source changes add a small-cache warning and change tests,
diagnostics, and documentation; they do not change read or compaction rules.
Fjall now uses the local dependency at `../lsm-tree`. The frozen control uses
Fjall `aba9e7651d3b0123ad982d43255a4f364fab908e` and this `lsm-tree` commit.
Keep the fresh control separate from the earlier recorded source states.

The table records the source before this implementation. The public contract
below describes the implemented APIs.

| Original API or owner | Original behavior and required change |
| --- | --- |
| [`Database::snapshot`, `SingleWriterTxDatabase::read_tx`](../../fjall/src/tx/single_writer/mod.rs) | Current views only; no durable historical opener or writable fork. |
| [`Readable::{get, prefix, range, iter}`](../../fjall/src/readable.rs), [`Snapshot`](../../fjall/src/snapshot.rs) | Indexed reads and snapshot-owning iterators; reuse their native access paths. |
| [`write_tx`, `insert`, `remove`, `commit`, `rollback`](../../fjall/src/tx/single_writer/write_tx.rs) | Single writer; commit returns `()`. |
| [`WriteBatch`](../../fjall/src/batch/mod.rs) | Atomic cross-keyspace writes; sequence allocation occurs under the journal lock. |
| [`MetaKeyspace`](../../fjall/src/meta_keyspace.rs) | Catalogue ingestion bypasses WAL. Branch heads and policies need a private journaled catalogue. |
| [`SnapshotTracker`](../../fjall/src/snapshot_tracker.rs), [flush](../../fjall/src/flush/worker.rs), [compaction](../../fjall/src/compaction/worker.rs) | One active-snapshot GC watermark; no durable per-tree history policy. |
| [`journal_cdc`, `journal_feed`, `journal_head`, `retain_after`, `Feed::{read, wait, cancellation}`](../../fjall/src/cdc.rs) | Local opt-in patch, not upstream APIs. Wake/resume works in the PoC; `read` collects the backlog into a vector. |

Recovery opens `CURRENT`, not the old in-memory `SuperVersion` chain.
Historical reads must pin a current structure and apply a separate retained
value cut. Keep retained values reachable from `CURRENT`; create no manifest
per revision. See [tree reads][tree], [structural versions][versions], and
[manifest recovery][recovery].

Native reads hide tombstones. Branch merging needs `Missing / Value / Deleted`.
Reuse strong tombstones without a value envelope or new deletion format.
Preserve inherited-delete overrides during compaction. Keep the merge path's
existing disabled sequence zeroing. See [merge rules][merge].

## Public API contract

The implementation status below records which methods exist.
`Revision` wraps an exclusive native visibility cut:
values have `sequence < cut`. The engine owns conversion from batch sequences.

| Owner | Addition |
| --- | --- |
| Database builder | `versioned()` enables the new storage mode for a new database. Reopen restores the mode from its durable marker. |
| `SingleWriterTxDatabase` | `create_branch(name)`, `branch(name)`, `branch_by_id(id)`, `branches()`, `delete_branch(id)` |
| `Branch` | `id()`, `info()` with parent/fork/head; `fork(name, revision)` |
| `Branch` | `snapshot()`, `read_at(revision)` returning a pinned `BranchSnapshot` |
| `BranchSnapshot` | `revision()`, `cursor() -> Result<Option<Cursor>>`, `get(key)`, `prefix(prefix)`, `range(bounds)`, `iter()` |
| `Branch` | `retain_history(range) -> RetentionId` |
| `SingleWriterTxDatabase` | `history()` lists policies and branch IDs; `release_history(id)` works after a branch name is deleted. |
| `Branch` | `write_tx()` with read-your-writes, point/range reads, `insert`, `remove`, `rollback`, and `commit -> Option<Commit>` |
| Branch write transaction | `commit_stamped(keys) -> Option<Commit>` saves the exact native revision at caller keys in the same batch. Fjall `cceaa84` adds this API for the approved Data migration. |
| Existing batch and single-writer transaction | `commit_receipt() -> Option<Commit>`; existing `commit() -> ()` remains |
| `Commit` | The exact committed `revision` and `cursor`; `None` means no batch was written |
| Existing CDC extension | Keep `journal_feed`, `journal_head`, `retain_after`, wait, and cancellation. Replace bulk `read` with `next_batch -> Option<Batch>`. |
| CDC batch and items | `Batch::revision()` matches the commit receipt. Managed items expose durable `BranchId`; raw keyspace items retain their existing identity. |

History uses standard Rust `RangeBounds<Revision>`: `r..=r` protects one view;
`r..` also protects future commits. Policies survive restart until explicit
release. Expired state cannot be retained retroactively. Forks and active
readers keep their own protection when a caller releases a policy.
Default retention is the current head plus active views and required fork bases.
Call `retain_history(branch.info().head..)` before the first data write to keep
all subsequent history. Pre-fork history requests protect the corresponding
ancestor ranges; each ancestor lookup uses the smaller requested and fork cut.

A current `snapshot()` captures its revision, lineage, and exact CDC start
cursor together. A historical `read_at(R)` exposes R; its cursor can be absent
after journal reclamation and must never be replaced with today's head cursor.
History retention and journal retention are independent. Keep both when CDC
catch-up needs historical queries at each batch revision.

Historical cursor lookup runs only when the caller requests the cursor. It
selects a retained segment by its native sequence bounds, then uses the original
decoder to find the exact batch. An expired position or a cut with no exact batch
returns `None`. Journal read and decoder errors return an error. Historical
point and range reads do not decode the journal.

Snapshot and feed handles do not themselves pin the journal. During bootstrap,
the caller's floor coordinator must prevent advancement until the new consumer's
snapshot cursor is registered. Persist consumed cursors before advancing that
minimum floor. Forking emits actual catalogue changes, not copied ancestor data.

Branch trees stay private and support puts and strong deletes. Raw `clear`,
weak deletes, ingestion, FIFO deletion, and rewrite filters are not exposed
through branch handles. Existing raw APIs and their durability stay unchanged.
Branch commits and receipt APIs require `SyncAll`. Logical reset is excluded.

Before a history, branch, or CDC-retention promise, persist an incompatible
database version marker atomically and durably. Old or feature-unaware openers
must reject it before recovery cleanup. Native SST/WAL entry formats stay
unchanged; ordinary flat databases keep their existing path. See the current
[database version check](../../fjall/src/db.rs) and [format header](../../fjall/src/version.rs).

Deletion removes the public name. Keep descriptors, trees, and identity mapping
while children, retained views, readers, or CDC need them. Reused names get new IDs.
`branch_by_id` resolves retained deleted identities for historical reads after
restart; name reuse must not redirect an old CDC batch to the new branch.

## API examples

These examples use pseudocode for the implemented APIs. They are not executable
Rust. Error handling is omitted. Each nonempty commit below returns a receipt.

Create a branch and retain history before writing. Fork an old revision, then
change the child without changing its parent:

```text
db = SingleWriterTxDatabase.builder(path).versioned().open()
main = db.create_branch("main")
retention = main.retain_history(main.info().head..)

tx = main.write_tx()
tx.insert("color", "blue")
blue = tx.commit()

tx = main.write_tx()
tx.insert("color", "green")
green = tx.commit()

experiment = main.fork("experiment", blue.revision)
tx = experiment.write_tx()
tx.insert("color", "red")
red = tx.commit()

assert main.read_at(blue.revision).get("color") == "blue"
assert main.snapshot().get("color") == "green"
assert experiment.snapshot().get("color") == "red"
```

Save `main.id()` and `blue.revision`. After all handles close, reopen the same
database. The mode and history policy survive; no new retention call is needed:

```text
db = SingleWriterTxDatabase.builder(path).open()
main = db.branch_by_id(saved_branch_id)
assert main.read_at(saved_blue_revision).get("color") == "blue"
```

Resume CDC after a saved cursor. This example processes one matching put to
`color`; the application owns matching and stores its result and cursor together:

```text
feed = db.journal_feed(saved_cursor)
loop:
    batch = feed.next_batch()
    if batch is absent:
        feed.wait()
        continue
    if batch does not include main's watched "color" put:
        continue
    at = main.read_at(batch.revision())
    tx = main.write_tx()
    tx.insert("derived/color", at.get("color"))
    tx.insert("consumer/cursor", encode(batch.cursor))
    tx.commit()
    break

db.retain_after(minimum_durably_saved_consumer_cursor)
```

For a new consumer, hold the caller's floor coordinator while obtaining
`view = main.snapshot()` and registering `view.cursor()`. Then open the feed
from that cursor. The retained range above permits historical batch reads.
The feed's scan cursor alone is not an acknowledgement. Use the last saved
consumer cursor after restart; use the minimum across consumers for reclamation.
Advance that minimum only after a successful output commit. A failed commit
leaves the saved input cursor unchanged for retry.
To release the example's history policy, call `db.release_history(retention)`;
forks and active views retain their own required state.

## Native changes and implementation order

| Order | Owner and change | Required proof before the next change |
| --- | --- | --- |
| 1 | Fjall commit/recovery: format marker, journaled catalogue, exact receipts, revision and identity high-water marks, policy loading, private trees | Abort, empty commit, interrupted publication, reopen, and concurrent-writer receipts are exact. Published revisions and IDs are never reused. An old opener rejects marked databases before any mutation. |
| 2 | `lsm-tree` flush/merge/blob GC: retained intervals, their predecessor versions, exact fork cuts, and native deletion visibility | Old/middle/head reads survive flush, major compaction, and reopen. After range release, an old fork retains only required versions in its ancestor tree; it does not retain all intermediate versions there or in unrelated trees. |
| 3 | Fjall branches: one tree per branch, fixed ancestor cuts, transaction overlays, lazy ordered merging, and safe deletion | Parent/child isolation, nested forks, inherited deletes, reverse scans, held views, and name reuse pass. Fork copies zero parent records. |
| 4 | Fjall journal: streaming feed and durable sealed-segment metadata; update existing PoC feed calls | Saved-offset resume, rotation, acknowledgement, cancellation, unrelated writes, and restart continuation pass without a shadow change table. |

Required combined lifecycle proof: retain history, fork at a past revision,
change both branches, and delete an inherited key. Check views before and after
the fork, then flush, rotate, compact, and reopen. Resume the saved CDC cursor
with exact branch IDs and revisions; commit output/state and consumed progress
atomically, then continue with new changes. Check rollback, concurrent bootstrap
and floor advancement, parent-name deletion, and child reads after caller
retention release and another compaction/reopen. All parts must pass together.
Reuse a deleted name and resolve old CDC batches through their original BranchId.

Current [sealed-journal recovery](../../fjall/src/recovery.rs) decodes every
retained segment before skipping persisted writes. Save segment end cursors
and per-keyspace watermarks at rotation. Recovery can then register fully
persisted segments for CDC without decoding their payload. Rebuild missing
segment metadata from the original journal; replay unpersisted data normally.
This metadata contains no copied values or second change log.
Account for recovery-pending and CDC-retained bytes separately. Restore revision,
branch-ID, and keyspace-ID high-water marks before allocating another identity
or revision. Skipped recovery payload must not permit ID reuse that relabels
retained journal items.

## Performance end state and proof

Use the existing [PoC workloads, commands, and timing definitions](../../crates/araphor-graph/examples/storage_poc/README.md).
Keep their fixtures, cycle counts, engine orders, durability, and measurement
boundaries. The original criterion required the completed engine to match or
improve the recorded Fjall PoC performance and pass the functional checks.
The user accepted the current benchmark on 2026-11-09. The measurements below
remain the original comparison targets. Report measured values with the
existing report fields and summary calculations.

The [combined driver](../../crates/araphor-graph/examples/storage_poc/cdc.rs)
and [summary checks](../../crates/araphor-graph/examples/storage_poc/summarize_cdc.py)
run four balanced revision-key/fixed-key pairs: eight runs and 64 package
cycles. Each layout has 28 ordinary samples, including 12 later-append
samples, and four separate maintenance/restart samples. Each eight-cycle run
makes 42 Graph SDK calls and produces eight source wakes and eight Graph wakes.
Keep the full source write → original-journal wake → package Graph work →
atomic Graph/cursor commit → output wake → result-read interval.

The recorded fixed-key [combined result](../../crates/araphor-graph/examples/storage_poc/results/combined-2026-11-08/summary.json)
uses source `beea72d9d08acaf16a6c5df26a930c1e6eb29519`:

| Existing measurement | Recorded fixed-key result |
| --- | ---: |
| One ordinary source-write through result-read cycle, median / maximum | 4.370 / 8.717 ms |
| Later-append cycle, median / maximum | 6.951 / 8.717 ms |
| Source write through subscription wake, median | 0.582 ms |
| Package execution including Graph reads, median | 2.033 ms |
| Complete Graph write, median | 1.304 ms |
| Graph write through output wake, median | 1.742 ms |
| Result read, median | 0.404 ms |
| Saved-cursor catch-up, median / maximum | 0.252 / 0.277 ms |
| Maintenance, reopen, and pending-input cycle, measured range | 16.051–16.957 ms |

These nested intervals and medians are not additive. Keep restart results
separate. The recorded journal work is 27 batches and 329,812 bytes per
fixed-key eight-cycle run. The target checks 24 available historical views
across four runs and records 40 unsupported requests after reopen.

Use the existing [stable-key driver](../../crates/araphor-graph/examples/storage_poc/stable.rs)
and [summary checks](../../crates/araphor-graph/examples/storage_poc/summarize_stable.py)
for historical package replay. It runs four balanced rounds of the existing
four layouts, with eight package cycles per run. Replay the same eight cuts
backward and forward after writes, Fjall compaction, and reopen. Keep each
stage and its supported or unsupported results explicit.
The recorded fixed-key Fjall [stable result](../../crates/araphor-graph/examples/storage_poc/results/neon-opt-2026-11-08/summary.json)
uses source `d339ed08f6a5c82afd9b1a1e70aac60fe38020a0`:

| Existing measurement | Recorded fixed-key Fjall result |
| --- | ---: |
| Complete eight-cycle package run, median | 26.985 ms |
| Sixteen historical package evaluations after writes, median total | 29.669 ms |
| Sixteen historical package evaluations after compaction, median total | 29.102 ms |
| Reopen, median | 7.584 ms |
| Unsupported historical requests after reopen across four runs | 60 |

These measurements define the benchmark to reach. They are not results for
the new fork. Freeze control and candidate binaries. Compare the same existing
PoC runs on the same host with matching release settings, `SyncAll`, caches,
values, and assertions. Save source commits, local patches, dependency locks,
commands, environment, raw reports, and existing summaries. If host variation
prevents a conclusion, record **Not done**. Do not apply or revert a change
based on one small timing difference.

Make the existing retained-history requests succeed through exact result
comparisons; do not drop requests or weaken assertions. Keep unsupported
control results explicit. Branch lifecycle, retention reclamation, and recovery
rules need the functional proof above. They have no measured performance
result yet; do not assign estimated timings or a new performance workload.
The PoC uses prepared Arrow and synthetic source-frontier metadata. It does
not measure production DataFusion input or notification delivery.

Keep existing package fixtures and assertions. Engine tests use generic opaque
keys and values. Run focused Fjall and `lsm-tree` checks plus the existing PoC;
do not run full workspace CI during iteration. Commit each accepted change and
its evidence separately. The production sub-100 ms notification path and 100x
incident-test target require later Araphor integration and remain **Not done**.

## Approval boundary

The active user goal approves the engine API, implementation scope, and existing
PoC comparison. It requires agreement with the reviewer before code changes.
No production migration, Graph processing changes, branch merge, shared-SST
writable forks, distributed storage, or automatic retention policy is included.

## Implementation status

### Approved follow-up simplification: 2026-11-09

Result: **Done for the four approved changes on the observed PoC workload**.
The user requests all four review findings without performance loss. The
implementer and reviewer agree on each direction before code changes and
review each committed result. Public APIs, formats, `SyncAll`, workloads,
assertions, and native storage ownership remain.

| Change | Implementation and proof |
| --- | --- |
| Ordered journal bookkeeping | Fjall `13b04ae` uses numeric segment IDs, binary search, and `VecDeque` front removal. `retained_segment_order` checks empty rotations, collection/append, exact resume, expiry, and reopen. Historical sequence-bound lookup stays linear because empty seals have no ordered sequence bound. |
| Shared pin publication | Fjall `6b62b16` publishes only when an active range first appears or its final owner leaves. Admission runs on every pin. `shared_pins_preserve_cuts` checks duplicate point/future pins, head advancement, release, and expired admission. |
| Affected ancestry updates | Fjall `d8a4613` replaces anonymous durable intervals with policy/fork contributions at each existing per-tree History owner. Runtime changes visit that source's ancestry. Recovery derives the full maps from durable records before maintenance. Tests check overlapping owners and successful metadata changes while unrelated history remains locked. |
| Capture outside writer I/O | Fjall `a042865` releases catalogue protection before ordinary branch sync and backpressure. The existing signal boundary captures a committed revision and optional exact cursor. One private publication callback advances the existing History head before visibility and wake. `Clock.published` is removed. Tests cover capture during pending SyncAll, buffered feed routing, raw writer receipts, failed publication, and nonzero retained state without journal payload. |

All 11 final focused commands pass: native default/LZ4 libraries 244/247;
eight selected integrations 19 in each configuration; Fjall CDC/without CDC
135/87; native/Fjall documentation 23/86. Production without default features,
library clippy, and formatting pass. Existing ignored cases and clippy warnings
remain. Full workspace CI is not run, as the user requires.

The [complete comparison](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/simplification/README.md)
retains four unchanged combined and four unchanged stable calls per binary.
All 16 summaries pass. Each complete before/after report matches after removal
of only its top-level source label and timing fields. Physical cursors match.
The pooled 112 ordinary samples per side have median/p95/maximum values
4.672/8.056/11.852 before and 4.655/7.668/8.171 ms after. The median of
16 stable eight-cycle runs per side is 28.413 before and 28.321 ms after.
Individual comparisons are mixed. No consistent regression is observed;
no repeatable latency gain or universal performance guarantee is established.
The previous completion record and its measured target misses remain below.

### Recorded implementation results

The entries below preserve results for their recorded source states. The final
acceptance record follows the latest source comparison.

| Work | Result and evidence |
| --- | --- |
| Preserve original CDC implementation | **Done.** Fjall commit `a41eb8c` matches the existing patch. Five native CDC tests pass. |
| Use the local `lsm-tree` fork | **Done.** Fjall commit `aba9e76`; the same five tests pass with the local dependency. |
| Exact durable commit receipts | **Done.** Fjall commit `a17f65d` adds core `Revision`, `Cursor`, and `Commit`, batch and single-writer receipts, and `Batch::revision()`. Legacy commit buffering stays unchanged. Reviewer source review passes. |
| Receipt checks | **Done.** `cargo test --manifest-path fjall/Cargo.toml --features journal-cdc --lib --locked --offline`: 85 passed, one existing ignored. Without the CDC feature, `cargo test --manifest-path fjall/Cargo.toml --lib commit::tests --locked --offline`: three passed. `cargo check --manifest-path fjall/Cargo.toml --no-default-features --lib --locked --offline` and formatting pass. |
| New local control measurements | **Done.** [Source and binary identity](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/control.json), [combined summary](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/combined-summary.json), and [stable summary](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/stable-summary.json). Combined ordinary median/maximum: 5.605/12.170 ms. Stable eight-cycle median: 28.711 ms. Existing summary assertions pass. These control observations do not prove a change in performance. |
| Durable mode and private catalogue | **Done.** Fjall commit `9d640ae` persists the mode, restores it before recovery, and restores the journaled catalogue before maintenance starts. The catalogue stays outside public keyspace access and application compaction filters. Native checks: 95 passed with CDC, 81 passed without CDC, one existing ignored in each run. The no-default-features production check passes. The actual pre-change `aba9e76` engine rejects all three new modes without file mutation; see [compatibility evidence](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/old-opener.json). |
| Durable revision and keyspace counters | **Done.** Fjall commit `bc203ce` adds one fixed-key catalogue clock item to each versioned native journal batch, within its original checksum and sync. Raw puts, strong and weak deletes, clears, and batches use the same path. Physical metadata ingestion preserves the next keyspace ID. Recovery rejects missing or malformed established counter state and restores counters before allocation. The exact published batch cut stays separate from maintenance sequence numbers. |
| Counter recovery checks | **Done.** Native CDC suite: 100 passed, one existing ignored. Without CDC: 81 passed, one existing ignored. No-default-features production check and formatting pass. Checks cover rotation, compaction, deleted-ID reclamation, empty commits, and failed sync. An internal recovery check removes fully persisted sealed payload through the journal manager, leaves an empty active journal, and checks the next receipt after reopen. This internal check bypasses the CDC floor only for removal; the public API still retains the segment that contains its newest acknowledged batch. |
| Native retained value collection | **Done.** `lsm-tree` commit `1488f307` adds `Retention::replace` and `Config::retain_versions`. Native flush and compaction preserve per-tree cut intervals and their predecessor versions. Obsolete versions remain subject to reclamation; protected deletion records remain visible to the storage layer. Configured trees read retained cuts from the current structure. Fjall does not yet enable this owner or persist its policies. |
| Native retention checks | **Done.** Default library suite: 241 passed, two existing ignored. LZ4 library suite: 244 passed, two existing ignored. Three new integration cases pass in both configurations. Existing snapshot compaction, flush eviction, and blob reclamation cases pass. Checks cover ordinary and blob values, exclusive cuts, deletion and re-addition, historical point/prefix/range/reverse reads, compaction, reopen, exact-pin reclamation, and a separate flat tree. A blocked merge checks policy snapshot ownership. Flush has a blocked-stream unit check and source review of capture order; no concurrent flush integration check is claimed. Native clippy exits successfully with existing warnings. [Native dependency lock](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/lsm-tree.Cargo.lock). Fjall's 100-test CDC suite also passes with this native change. |
| Native pinned read views | **Done.** `lsm-tree` commit `d1c99d0a` adds `AbstractTree::read_view(cut)` and `ReadView::{get, prefix, range, iter}`. A point result distinguishes a missing key, a deletion, and an empty value. Scan guards expose keys and deletion state before blob reads. Each guard retains its tree and captured disk version. Existing reads still hide deletions. The caller must protect the cut and admit available history. |
| Pinned view checks | **Done.** Default native library: 241 passed, two existing ignored. LZ4 library: 244 passed, two existing ignored. The new ordinary/blob case passes in both configurations. It checks held views through policy release and compaction, forward/reverse/mixed scans, excluded bounds, and a detached guard read on another thread after the view, iterator, and other tree handles close. Reopen follows guard release. Existing retained-history, point snapshot, range, and weak-delete cases pass. Fjall's 100-test CDC suite passes with the changed lookup path. Native clippy and formatting pass, with existing clippy warnings. |
| Native transaction reuse | **Done.** Fjall `c8b13bd` shares the existing native write staging. `lsm-tree` `5cd55428` adds captured native overlays; `b555031f` exposes normalized interval coverage. Default native library: 241 passed, two existing ignored. LZ4 library: 244 passed, two existing ignored. Read-view cases: two passed; retention cases: three passed in each configuration. Fjall CDC: 100 passed, one existing ignored. Formatting and the production build without default features pass. |
| Durable retention and sparse branches | **Done for the branch API and native reads.** Fjall `9a28f8d` adds persistent branch identities, exact creation/head stamps, range policies, per-tree pins, sparse forks, native transaction overlays, and lazy ordered merging. Recovery restores policies before maintenance. New branch trees copy zero parent records. The full CDC lifecycle remains **Not done**. |
| Branch checks | **Done.** Fjall CDC library: 106 passed, one existing ignored. Without CDC: 81 passed, one existing ignored. The feature-unaware format checks also pass after the final assertion change. Checks cover nested forks, inherited deletions, empty values, captured local iterators, mixed forward/reverse scans, rollback, gap admission, current and historical fork cuts, compaction, reopen, deleted-name reuse, retained IDs, atomic output/progress/head writes, orphan cleanup, and missing committed trees. Physical version counts confirm per-tree collection: the parent keeps three versions with a held reader, then two after release; an unrelated branch keeps one. Managed views open no global snapshot nonce. |
| History format fence | **Done.** Versioned initialization and ready state use FJL5. Flat FJL3 and journal FJL4 behavior remain. Earlier FJL4 versioned prototypes are rejected; no migration is provided. The frozen `bc203ce` mode-aware engine rejects both FJL5 states without changing any of the 17 fixture files. See [history opener evidence](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/history-opener.json). The fixture has retained history and a branch. |
| Private tree boundary | **Done.** The undocumented `SupervisorInner.keyspaces` field is now crate-private. Direct external dictionary access no longer compiles. Public flat keyspace APIs remain. Metadata policy changes currently rebuild the per-tree protection unions; ordinary data commits update only their own tree's head. |
| Original-byte checksum verification | **Done.** Fjall `01e9ea9` hashes original Item/Clear bytes through the native decoder. It removes per-item encoding, allocation, and LZ4 recompression from checksum verification. The LZ4 fixture uses valid stored bytes that differ from the compressor's output. The existing 106-test CDC suite passed before that fixture; the final journal selection passed 19 cases. Without CDC: 82 passed, one existing ignored. The production build without default features and formatting pass. No performance gain is claimed yet. |
| Streaming original-journal CDC | **Done.** Fjall `b75e68f` replaces production `Feed::read` with `next_batch`. One fixed-boundary native reader returns one complete batch at a time. File open occurs under journal/manager protection; decoding and branch routing occur after those locks are released. Active-boundary extension reopens at the consumed cursor. Items expose their permanent branch identity. Existing tests retain a test-only drain helper; production has no backlog collector. |
| Existing PoC feed caller | **Done.** The Fjall adapter returns zero or one decoded batch in its existing wrapper. Home behavior, workload, assertions, and timing endpoints remain. Native `read_s` and first-decode diagnostics now measure one batch instead of a complete backlog. The existing Neon/CDC PoC release build passes with the recorded release override. The frozen control SHA remains `953f7fd0f4189f50779838026de82505346090d2940b36707636dd6583ab99a8`. No candidate timing is claimed. |
| Combined branch and CDC checks | **Done for native replay recovery.** The final CDC library suite passes 110 cases, with one existing ignored. A combined case retains history, forks, deletes inherited data, compacts, reopens, resumes a saved cursor, commits output and consumed progress atomically, waits for another commit, deletes/reuses a name, releases caller history, and compacts/reopens again. Old and new journal items keep their original branch IDs. A direct streaming case checks partial consumption, active-file extension, empty sealed segments, and saved-offset continuation. Failed sync leaves branch head, output, and progress unchanged. Focused clippy exits successfully with existing warnings. |
| Historical cursor lookup | **Done.** Fjall `b766e3b` adds lazy exact lookup through sealed and active native segments. The captured current cursor needs no lookup. The new prototype API returns `Result<Option<Cursor>>` so read failures stay visible. The native CDC suite passes 119 cases, with one existing ignored; focused clippy and formatting pass. Checks cover structural gaps, rotation, reopen, retained values after journal reclamation, and decoder failure without file mutation. |
| Retired branch collection | **Done.** Fjall `305b566` collects deleted descriptors after explicit `collect_journals`. Active and retained journal segments, live reader leases, children, policies, and views protect required identities. One durable native batch removes catalogue records before native physical cleanup. Recovery and repeated collection retry orphan cleanup. Permanent keyspace counters prevent ID reuse. CDC library: 122 passed, one existing ignored. Without CDC: 82 passed, one existing ignored. The production build without default features, formatting, and library clippy pass. |
| Sealed-segment recovery metadata | **Done.** Fjall `a0f09ac` saves the original end cursor, actual first/last sequences, and physical-keyspace watermarks at rotation. Recovery skips payload only when current SST watermarks prove all writes persisted. Missing metadata is rebuilt with the original decoder; invalid metadata fails. A durable seal prevents reopening the same file for append after interrupted successor creation. Recovery-pending bytes exclude persisted segments retained for CDC. Reader leases keep unlinked segment metadata alive. |
| Sealed recovery checks | **Done.** Final CDC library: 116 passed, one existing ignored. Without CDC: 82 passed, one existing ignored. The production build without default features, formatting, and focused clippy pass; clippy reports existing and advisory warnings. Checks cover skipped payload, missing and invalid metadata, interrupted rotation, exact fallback byte accounting, pending-data selection, and an active reader through unlink. Successful raw clear completion provides runtime reclamation proof; restart replays clear when no SST watermark proves it. |
| Sealed format fence | **Done.** Journal and versioned modes now use FJL6; flat databases remain FJL3. Earlier FJL4/FJL5 prototypes have no migration. The frozen `b75e68f` engine rejects all three FJL6 modes without changing the 19 fixture files. The fixture contains retained history, a fork, and a sealed journal. See [opener evidence](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/seal-opener.json). |
| Native maintenance access | **Done.** Fjall `a25c464` adds `Database::flush_memtables` and `major_compact`. Both call existing native maintenance for the current live trees, including private branch and catalogue trees. They release the dictionary lock before native work. The skipped-payload recovery check uses these public calls. CDC library: 116 passed, one existing ignored. Without CDC: 82 passed, one existing ignored. The production build without default features, formatting, and focused clippy pass. |
| Versioned PoC adapter | **Done.** The `cdc-poc` build runs `fjall-stable` through one retained records branch. It uses exact encoded commit revisions for historical reads and carries these opaque references across the driver's existing reopen. Source and acknowledgement writes do not change the Graph revision map. The ordinary registry-Fjall example keeps its existing API and passes a focused release check. Workloads, key shapes, order, durability, primary timing boundaries, and calculations remain. Candidate history requests use exact Oracle and package replay checks. |
| Candidate PoC qualification | **Done for the current adapter.** The [combined report](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/before-scan-combined.json) passes all 64 package cycles. The candidate checks all 64 historical views, with zero unavailable requests. The [stable report](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/before-scan-stable.json) passes 128 primary cycles across four layouts. All candidate replay stages pass after writes, compaction, and reopen. The reopened rollback check at revision 88 remains. See [source and binary identity](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/before-scan.json). |
| Initial candidate PoC performance | **Not done.** The initial [combined summary](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/before-scan-combined-summary.json) records 4.859 ms median and 8.628 ms maximum; the [stable summary](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/before-scan-stable-summary.json) records 31.025 ms median. The earlier trial records 4.660/8.832 ms and 27.136 ms. Both observations remain in the evidence directory. The frozen control passes the same current summary scripts without changed results. These observations do not prove the performance target or a gain. |
| Single native scan | **Done for correctness.** Fjall `843f04b` forwards a single native iterator without the branch winner-selection loops. Multi-ancestor merging is unchanged. Native CDC: 117 passed, one existing ignored. Focused clippy and formatting pass. The new check covers empty values, deletions, mixed scan directions, held transaction views, compaction, and reopen. The [frozen comparison](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/scan-comparison/single-scan.json) retains two complete before/after reports for each existing PoC. All assertions pass. Round ranges overlap; no performance gain is proved. |
| Decoded standard scan guards | **Done for correctness.** `lsm-tree` `b9f6cfda` retains decoded key/value slices in standard record guards. Blob guards retain the existing tree and version owners. Default native library: 241 passed; LZ4 library: 244 passed; two existing ignored in each configuration. Two read-view and three retained-history cases pass in both configurations. Fjall CDC: 119 passed, one existing ignored. Library clippy and formatting pass with existing warnings. Before/after timings overlap; no performance gain is proved. |
| Native staged point reads | **Done for correctness.** Fjall `66d821e` shares the existing memtable lookup across raw and branch transactions. Branch point reads no longer create an overlay view. Local deletion stops ancestor fallback; an empty value remains present. Range overlays remain. CDC library: 123 passed, one existing ignored. Without CDC: 83 passed, one existing ignored. The production build without default features, formatting, and library clippy pass. Existing PoC comparisons pass all assertions; the performance target remains **Not done**. |
| Concurrent CDC bootstrap proof | **Done.** Fjall `e2c23cb` extends the combined lifecycle case. A caller-held coordinator protects snapshot capture and exact cursor registration while another thread commits input and attempts floor advancement. The registered cursor preserves its segment. After durable output and consumed-progress publication, floor advancement reclaims the old segment; the consumed cursor still resumes at the exact output. The focused case, full 123-case CDC library suite, and formatting pass. No engine API or performance workload changes. |
| Native read comparisons | **Not done for performance.** The [complete comparisons](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/native-read-comparison/README.md) retain every guard, retirement, and point-read report with source IDs, summaries, and logs. All existing assertions pass. Point-read combined medians are 4.350 and 4.813 ms; maxima are 7.698 and 8.234 ms. Stable medians are 27.885 and 28.203 ms. One combined pass reaches the target; the other combined pass and both stable passes exceed their median targets. No complete gain is proved. |
| Active-only native scan | **Done for correctness.** `lsm-tree` `4088a934` removes merge-heap work only when the active memtable is the sole source. The same native MVCC stream and deletion filter remain. All table, sealed-memtable, and transaction-overlay paths keep the existing merger. Default native library: 241 passed; LZ4 library: 244 passed; two existing ignored in each run. Three read-view and three retained-history cases pass in each configuration. Fjall CDC: 123 passed; without CDC: 83 passed; one existing ignored in each run. The production build without default features, native library clippy, and formatting pass. Performance qualification remains **Not done**. |
| Direct native point lookup | **Done for correctness.** `lsm-tree` `4aeaf8d4` calls the existing Crossbeam `lower_bound` instead of constructing a range iterator for one entry. The owned lower key, exclusive cut, exact-key check, and deletion result remain. Default native library: 241 passed; LZ4 library: 244 passed; two existing ignored in each run. Three read-view and three retained-history cases pass in each configuration. Fjall CDC: 123 passed; without CDC: 83 passed; one existing ignored in each run. The production build without default features, native library clippy, and formatting pass. Performance qualification remains **Not done**. |
| Accumulated native comparison | **Not done for performance.** The [retained comparisons](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/native-read-comparison/README.md) include both complete passes against the original frozen control. Candidate combined medians/maxima are 4.328/7.094 and 4.771/8.079 ms. Stable medians are 26.155 and 28.384 ms. The first pass reaches both recorded targets; the second pass exceeds both median targets. All correctness assertions pass. The result is not yet repeatable. |
| Direct branch scan ownership | **Done for correctness.** Fjall `3f684ab` keeps a single native scan without lookahead buffers or a second iterator vector. The existing multi-ancestor merge, deletion filtering, record resolution, and snapshot ownership remain. CDC library: 123 passed; without CDC: 83 passed; one existing ignored in each run. The production build without default features, library clippy, and formatting pass. Both existing PoC comparisons pass all assertions. Combined medians/maxima are 4.859/8.411 and 4.668/8.318 ms. Stable medians are 28.921 and 29.287 ms. The performance target remains **Not done**. |
| Native journal byte positions | **Done for correctness and syscall removal.** Fjall `8cb06c8` uses `BufReader<Take<File>>` to obtain the exact decoded offset without a seek after each entry. Decoder, checksum, captured end, cursor format, and recovery remain. CDC library: 124 passed; without CDC: 83 passed; one existing ignored in each run. The production check without default features, library clippy, and formatting pass. [All comparisons and diagnostics](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/reader-position/README.md) remain available. Traced file-position calls decrease from 27,710 to 3,382 across the unchanged combined driver. Untraced output-CDC read medians decrease in both comparisons. Complete performance qualification remains **Not done**. |
| Native point-index ownership | **Done for correctness.** `lsm-tree` `29549fd7` borrows full, volatile, and two-level native index blocks for point reads. Sequence-aware search, cache, error behavior, and owned lazy range iterators remain. Default library: 241 passed; LZ4 library: 244 passed; two existing ignored in each run. Three read-view and three retained-history cases pass in each configuration. Fjall CDC: 124 passed; without CDC: 83 passed; one existing ignored in each run. The production check without default features, library clippy, and formatting pass. [Both unchanged PoC comparisons](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/native-index-compression/README.md) pass all assertions. Complete performance qualification remains **Not done**. |
| Combined rollback and inherited-history proof | **Done.** Fjall `f2034d0` extends the existing combined lifecycle case. The case rolls back actual output and its consumed cursor before the successful commit. Head, journal, output, and progress remain unchanged after rollback. Both reopen stages check the inherited parent value at a retained cut before child creation. The focused case and formatting pass; the final full CDC suite also includes this case. No engine API or performance workload changes. |
| Direct native journal compression | **Done for correctness.** Fjall `42be11f` compresses into the existing writer buffer and removes the temporary compressed vector, shrink operation, and copy. Byte comparisons cover both codecs, reused buffers, empty values, and incompressible data. Codec, threshold, stored bytes, and generic entry interface remain. The writer can retain the largest uncompressed compression bound until rotation. CDC library: 125 passed; without CDC: 84 passed; one existing ignored in each run. The production check without default features, library clippy, and formatting pass. [The comparisons](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/native-index-compression/README.md) remain mixed; no overall gain is proved. |
| Current accumulated comparison | **Not done for performance.** [All 24 raw reports and reproduced summaries](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/native-index-compression/README.md) remain available with exact source patches and verified binary hashes. Current candidate combined medians/maxima are 4.836/7.039 and 4.551/7.869 ms. Stable medians are 26.240 and 25.748 ms. Both maxima and stable medians reach the recorded targets; both combined medians exceed their target. Ordinary p95 values are 6.969 and 7.416 ms, versus 8.600 ms in the original recorded PoC. Each percentile uses 28 samples and the nearest-rank method; restart remains separate. Earlier higher maxima have no established cause. No sustained latency bound or complete gain is proved. |
| Native parser compiler visibility | **Done for measured query CPU work; Not done for complete performance.** `lsm-tree` `aed3e47a` adds five `#[inline]` attributes to existing parser methods. Bodies, interfaces, search rules, and stored bytes remain. [The retained evidence](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/parser-inlining/README.md) checks 28 ordinary fixed-key evaluations and 92 neighbor calls. Complete query instructions decrease from 144,417,138 to 136,189,231, or 5.70%. Presence collects no instructions; all profiled timings are excluded. The code section decreases by 1,728 bytes. Native default/LZ4: 241/244 passed, two existing ignored each; three read-view and three history cases pass in each configuration. Fjall CDC/without CDC: 125/84 passed, one existing ignored each. Production without default features, library clippy, and formatting pass. All unchanged PoC assertions pass. Current combined medians/maxima are 4.550/7.680 and 4.483/6.769 ms; stable medians are 25.670 and 26.764 ms. Wall-time changes remain mixed. Both combined medians exceed their target; no overall latency gain is proved. |
| Buffered native checksum reads | **Done for measured feed CPU work; Not done for complete performance.** Fjall `f72bd21` uses the existing buffered bytes for complete checksum reads. The standard fallback preserves partial-read checksums, interruption retries, and errors. [The retained evidence](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/checksum-buffered/README.md) checks identical work across both layouts and all workers: 216 calls and batches, 14,264 items, 3,046,976 bytes, and 64 source plus 64 Graph wakes. Feed instructions decrease from 61,885,118 to 56,262,749, or 9.085%. All profiled timings are excluded. CDC/without CDC: 126/85 passed, one existing ignored each. Production without default features, library clippy, formatting, and release build pass. Both unchanged PoCs pass. Combined median/p95/maximum values are 4.448/7.257/7.308 and 4.419/6.946/7.057 ms. Stable medians are 25.663 and 25.879 ms. Both combined medians exceed their target; no sustained latency gain is proved. |
| Native Item header reads | **Done for measured feed CPU work; Not done for complete performance.** Fjall `ee3ea07` reads the four fixed fields in one 18-byte stack buffer, then uses the existing decoder. Tags are checked first; stored bytes, checksums, and APIs remain. [The retained evidence](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/header-group/README.md) checks identical work across both layouts and all workers. Feed instructions decrease from 56,262,749 to 49,143,165, or 12.654%. All profiled timings are excluded. CDC/without CDC: 127/86 passed, one existing ignored each. Production without default features, library clippy, formatting, and release build pass. Both unchanged PoCs pass. Combined median/p95/maximum values are 4.517/7.143/7.189 and 4.990/6.788/7.090 ms. Stable medians are 26.194 and 26.502 ms. Both combined medians and both stable medians increase in these comparisons. No sustained latency change is proved; both combined medians exceed their target. A separate writer diagnostic confirms that the existing buffer combines writes; no writer change is added. |
| Initialized native encoding buffer | **Done for measured apply CPU work; Not done for complete performance.** Fjall `04c304a` uses a private standard cursor to retain initialized storage and a stack Item header built with the existing encoders. Writes, hashes, and counts use only the logical prefix. Stored bytes, per-Item bounds, errors, and durability remain. [Both draft comparisons and profiles](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/journal-buffer/README.md) are retained. Complete apply instructions decrease from 450,974,505 to 444,525,190, or 1.430%, across the same 72 calls in both layouts, including rollback. Compression counters and reported domain work match. All profiled timings are excluded. CDC/without CDC: 127/86 passed, one existing ignored each. Production without default features, library clippy, formatting, and release builds pass. Both unchanged PoCs pass. Final combined median/p95/maximum values are 4.561/7.094/7.162 and 4.597/7.312/7.357 ms. Stable medians are 25.816 and 25.175 ms. Both combined medians exceed their target; wall-time changes remain mixed. No sustained latency gain is proved. |

The [direct native point-read result](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/point-decoder/README.md)
is **Done for measured point-read CPU work; Not done for complete performance**.
`lsm-tree` `5c005a47` uses the existing decoder directly and removes the
point-read iterator positioning loop. Complete native point-read instructions
decrease from 341,999,812 to 321,338,731, or 6.041%, across the same 105,692
calls in both layouts and all stages. This scope includes verification and
history; it is not ordinary-cycle CPU. All profiled timings are excluded.
Native default/LZ4 libraries pass 242/245 cases, with two existing ignored
cases each. Eight selected native integration suites pass 19 cases, with one
existing ignored case, per configuration. Fjall CDC/without CDC pass 127/86
cases, with one existing ignored case each. Production without default
features, library clippy, formatting, and the release build pass. All eight
unchanged PoC summaries pass. Combined median/p95/maximum values are
4.751/7.066/7.091 and 4.709/7.130/7.805 ms. Stable medians are 26.278 and
25.630 ms. Both combined medians increase in these calls and exceed their
target. No ordinary latency gain or sustained regression is established.

The [unapplied index-seek experiment](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/index-end-experiment/README.md)
retains its patch, all raw reports, reproduced summaries, and profiles.
The reviewer and implementer agree to remove it. Query instructions decrease
by 0.593%, but their median increases and the code section grows by 8,256 bytes.
Combined medians decrease; both stable medians increase. No general gain is
proved. Source remains at `lsm-tree` `aed3e47a` and Fjall `42be11f`.
Fresh retained-source combined median/p95/maximum values are
4.876/7.041/7.316 and 4.826/7.516/7.720 ms. Each set has 28 ordinary samples;
restart remains separate. Complete performance qualification remains **Not done**.

The [unapplied visibility-aware point-seek experiment](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/sequence-seek-experiment/README.md)
uses the same native binary search with an exclusive value cut. All native and
unchanged PoC checks pass. Complete query instructions increase by 1.66%;
their median increases by 2.00%. Every collected revision median increases.
The reviewer and implementer agree to remove the experiment. Its exact patch,
source and binary identity, nine reproduced summaries, and raw profiles remain.
Accepted engine commits remain unchanged. Complete performance qualification
remains **Not done**.

The [unapplied cached-index experiments](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/cached-index-experiment/README.md)
retain both exact patches, all 17 reproduced summaries, and raw profiles.
Complete query instructions change by +0.00444%; wall-time changes are mixed.
The draft adds metadata memory and cold construction work. One additional
compiler attribute changes no standalone native or query-method code bytes.
The reviewer and implementer agree to remove both drafts. Accepted engine
commits remain unchanged. Complete performance qualification remains **Not done**.

The [ordinary execution comparison](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/ordinary-gap/README.md)
retains a fresh balanced original-control/current pair and three exact CPU
diagnostics. All eight untraced and six profiled summaries pass. Current
combined median/p95/maximum values are 4.590/7.112/7.269 and
4.839/7.214/7.535 ms. Stable medians are 25.989 and 26.386 ms. Both combined
medians exceed their target. The selected 28 ordinary fixed-key samples use
3.519% fewer neighbor-query instructions, 8.115% fewer result-inspection
instructions, and 1.725% fewer complete-package instructions than the
original control. The query count is nested inside the package count.
Profiled timings are excluded. Extra package elapsed time remains unexplained.
The hardware counter probe is blocked by `perf_event_paranoid=4`; host
settings remain unchanged. No production edit is justified by these counts
alone. Complete performance remains **Not done**.

The [native execution cost diagnostic](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/execution-cost/README.md)
checks the same 28 ordinary package evaluations. Instructions decrease by
1.754%, atomic operations by 36.878%, and indirect branches by 6.314% against
the original control. Simulated cache events do not establish hardware
penalties. A separate standard CPU sampler records 787 and 824 whole-driver
stack samples. That scope includes unequal historical support and does not
prove an ordinary latency change or unbiased worker CPU coverage. All four
unchanged summaries pass. All profiled timings are excluded. No engine source
changes follow from this evidence. Complete performance remains **Not done**.

The [checked point-block result](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/checked-handles/README.md)
is **Done for measured native CPU work; Not done for complete performance**.
`lsm-tree` `1918e262` borrows checked block handles at three point-read loads.
Bounds checks precede loading; the terminal comparison uses checked bytes.
Complete package instructions decrease by 0.316%; nested entered native
lookup instructions decrease by 2.099% across the same 14,096 calls in 28
ordinary evaluations. All 144 profile dumps conserve root and native counts.
Profiled timings are excluded. All 16 untraced summaries pass. Corrected
combined median/p95/maximum values are 4.211/6.674/7.126 and
4.950/6.800/9.635 ms. Stable medians are 25.509 and 25.764 ms. The second
combined pass exceeds both targets. Native default/LZ4 libraries pass
243/246 cases; the other focused checks pass. The superseded unchecked
draft and excluded method-only profiles remain in the evidence. No repeatable
elapsed gain is proved.

The [owned staging result](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/owned-staging/README.md)
is **Done for measured ordinary apply CPU work; Not done for complete performance**.
Fjall `bdb1843` consumes unique staging through the native owning iterator;
held iterators keep the existing shared path. Both paths keep native checks
and latest-key selection. Ordinary output apply instructions decrease by
1.015% across 28 transactions. All 144 raw dumps conserve counters; profiled
timings are excluded. The new test checks both ownership paths, latest value
types, two keyspaces, commit, and rollback. CDC/without CDC pass 128/87 cases;
other focused gates and the release build pass. All eight untraced summaries
pass. Combined median/p95/maximum values are 4.734/7.322/7.837 and
4.774/6.947/7.247 ms. Stable medians are 25.879 and 25.860 ms. Both combined
medians exceed their target. No repeatable elapsed gain is proved.

The [borrowed point-lookup result](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/borrowed-lookup/README.md)
is **Done for measured ordinary package CPU work; Not done for complete performance**.
`lsm-tree` `2e1b5df3` borrows a composite search key through Crossbeam's native
lookup. Stored-key ordering, validation, exclusive cuts, and returned fields
remain. Complete ordinary package instructions decrease by 1.289% across
28 evaluations, including the added comparison-dispatch work. All 144 raw
dumps conserve counters; profiled timings are excluded. A linear oracle checks
four result fields, key-length limits, binary keys, cuts, and deletion types.
Native default/LZ4 libraries pass 244/247 cases; Fjall CDC/without CDC pass
128/87. Other focused gates and the release build pass. All eight untraced
summaries pass. Combined median/p95/maximum values are 4.653/7.187/8.332 and
4.568/7.080/7.223 ms. Stable medians are 25.042 and 25.939 ms. Both combined
medians exceed their target and their fresh controls. No repeatable elapsed
gain or sustained regression is established.

Source at the original acceptance was Fjall `bdb1843` and `lsm-tree` `2e1b5df3`.
Use the borrowed point-lookup record above for that comparison. Earlier records
describe their recorded source states. The whole-cycle CPU attempt is excluded
because its reset function was inlined in one executable.

### Original acceptance: 2026-11-09

Result: **Done for the approved engine scope**. The implementer and reviewer
read the complete plan and found no missing API or required lifecycle proof.
No further engine change was required. The user accepted the current benchmark
and requested completion. This acceptance replaces the remaining numeric
performance gate; it does not prove the original combined median target or
a repeatable latency gain.

Final source is Fjall `bdb1843574f00ed9153233b547d2e2fd055c266a` and
`lsm-tree` `2e1b5df34ffc5db3275010f4bd5832518453b121`. Both trees were clean.
All 11 [final focused commands and their logs](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/finalization/README.md)
pass. Native default/LZ4 libraries pass 244/247 cases; eight selected integration
suites pass 19 cases in each configuration. Fjall CDC/without CDC libraries
pass 128/87 cases. Documentation tests pass 23 native and 86 Fjall cases.
The production check without default features, library clippy, and formatting
pass. Existing ignored cases and clippy warnings remain. All ten saved PoC
summaries reproduce exactly; no new benchmark was run.

Accepted combined median/p95/maximum values are 4.653/7.187/8.332 and
4.568/7.080/7.223 ms. Stable eight-cycle medians are 25.042 and 25.939 ms.
The source links, API proof map, commands, and limits are in the final record.
Full workspace CI was not run, as the user requires. Production Araphor
migration and notification latency remain outside this engine implementation.

The [timestamped journal diagnostic](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/header-group/waits.md)
matches all 128 saved source and output cursors to unique journal commits.
For the 28 ordinary fixed-key samples, source/output `fsync` medians are
0.567/0.666 ms and maxima are 2.718/1.692 ms. Each matched commit has one
journal sync. All traced timings are excluded from performance acceptance.
Syscall duration includes tracing and scheduling. This diagnostic does not
explain the earlier 13.984 ms maximum or establish a safe sync removal.

The no-default-features test build fails in the existing
`keyspace/options.rs:709` test: `with_kv_separation` receives a value instead of
`Some(value)`. The same line exists in upstream commit `8700604`. The production
no-default-features build passes; this unrelated test was not changed.
The focused clippy command now exits successfully after the streaming change.
It reports existing warnings; no check with all warnings denied is claimed.
The broader point-read clippy invocation with `--tests` fails on 65 existing
test lints. The library-only clippy invocation passes with existing warnings.
See the [source review guide](../guides/fjall-versioned-storage-review.md) and
the retained comparison logs for the exact verification scope.

[tree]: ../../lsm-tree/src/tree/mod.rs
[versions]: ../../lsm-tree/src/version/super_version.rs
[recovery]: ../../lsm-tree/src/version/recovery.rs
[merge]: ../../lsm-tree/src/compaction/worker.rs
