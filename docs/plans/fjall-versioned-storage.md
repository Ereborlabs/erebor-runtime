# Fjall durable history, branches, and CDC

Extend the Fjall fork with generic versioned storage. Applications decide what
keys mean, which history to retain, and how to use journal changes. The engine
has no Araphor Graph, package, finding, SQL, or DataFusion dependency.

Status: **Approved; implementation in progress**. Source review: 2026-11-08.
Complete implementation and performance qualification: **Not done**.

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
the public API and combined lifecycle proof below, plus performance that
matches or improves the existing Fjall PoC benchmark. Use the same workloads,
timing fields, and measurement conditions. The active user goal authorizes
implementation and the existing PoC comparison.

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

Process restarts, or an operation fails
  -> Recovery opens current manifests and replays only required recovery data.
  -> Recovery restores branch records and retention before maintenance starts.
  -> Expired history or log positions return an error.
  -> Aborted and empty writes publish no change; uncertain I/O stops publication.
```

## Current APIs and source findings

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

| Current API or owner | Present behavior and required change |
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
| `BranchSnapshot` | `revision()`, `cursor() -> Option<Cursor>`, `get(key)`, `prefix(prefix)`, `range(bounds)`, `iter()` |
| `Branch` | `retain_history(range) -> RetentionId` |
| `SingleWriterTxDatabase` | `history()` lists policies and branch IDs; `release_history(id)` works after a branch name is deleted. |
| `Branch` | `write_tx()` with read-your-writes, point/range reads, `insert`, `remove`, `rollback`, and `commit -> Option<Commit>` |
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

These examples are proposed API pseudocode, not executable Rust. Error handling
is omitted. Each nonempty commit below returns a receipt.

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
boundaries. The completed engine must match or improve the recorded Fjall PoC
performance while passing the required functional checks. Report measured
values using the existing report fields and summary calculations.

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
| Remaining branch lifecycle work | **Not done.** Historical cursor lookup and physical deletion of retired descriptors remain with the CDC owner below. Deleted identities are retained conservatively. |
| Sealed-segment recovery metadata | **Done.** Fjall `a0f09ac` saves the original end cursor, actual first/last sequences, and physical-keyspace watermarks at rotation. Recovery skips payload only when current SST watermarks prove all writes persisted. Missing metadata is rebuilt with the original decoder; invalid metadata fails. A durable seal prevents reopening the same file for append after interrupted successor creation. Recovery-pending bytes exclude persisted segments retained for CDC. Reader leases keep unlinked segment metadata alive. |
| Sealed recovery checks | **Done.** Final CDC library: 116 passed, one existing ignored. Without CDC: 82 passed, one existing ignored. The production build without default features, formatting, and focused clippy pass; clippy reports existing and advisory warnings. Checks cover skipped payload, missing and invalid metadata, interrupted rotation, exact fallback byte accounting, pending-data selection, and an active reader through unlink. Successful raw clear completion provides runtime reclamation proof; restart replays clear when no SST watermark proves it. |
| Sealed format fence | **Done.** Journal and versioned modes now use FJL6; flat databases remain FJL3. Earlier FJL4/FJL5 prototypes have no migration. The frozen `b75e68f` engine rejects all three FJL6 modes without changing the 19 fixture files. The fixture contains retained history, a fork, and a sealed journal. See [opener evidence](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/seal-opener.json). |
| Candidate PoC performance | **Not done.** The new complete engine has not been benchmarked. |

The no-default-features test build fails in the existing
`keyspace/options.rs:709` test: `with_kv_separation` receives a value instead of
`Some(value)`. The same line exists in upstream commit `8700604`. The production
no-default-features build passes; this unrelated test was not changed.
The focused clippy command now exits successfully after the streaming change.
It reports existing warnings; no check with all warnings denied is claimed.

[tree]: ../../lsm-tree/src/tree/mod.rs
[versions]: ../../lsm-tree/src/version/super_version.rs
[recovery]: ../../lsm-tree/src/version/recovery.rs
[merge]: ../../lsm-tree/src/compaction/worker.rs
