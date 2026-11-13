# Data storage and collector investigations

Investigate each item in order. This file keeps the findings and approval
boundary for each item. It can accept more numbered items. The current request
authorizes item 1. The user then explicitly required benchmark development
and execution. The user now approves replacement of kernel-evidence segments
with the existing Fjall database. The approved scope is below. Earlier
benchmark sections record the approval boundary at their publication time.
Items 2 and 3 remain unapproved.

## Intended end state

Each item has a source-backed explanation, applicable measurements, a concrete
proposal, and a user decision before implementation. Item 1 must establish the
cost of storing and reading the same raw event payloads in the current segments
and the versioned Fjall fork. A storage choice requires matched results.

| Item | Request | Current state |
| --- | --- | --- |
| 1 | Compare raw log segments with Fjall | Raw-only pilot and production transaction comparison complete: 16 measured process runs each. Production replacement and sustained compaction remain unqualified. |
| 2 | Define the abstraction for tables on Fjall | Deferred. No API or implementation proposed. |
| 3 | Define how to add collectors | Deferred. Inventory collectors before confirming whether only BPF intake exists. |

## Item 1: raw segments against Fjall

“Log segments” means Data's existing raw evidence and diagnostic segments.
Fjall means the local versioned Fjall/lsm-tree forks used by production Data.
This item concerns raw payload placement. Graph and ordinary metadata already
use Fjall. This investigation does not select a table API for item 2.

### Measured pilot, 2026-11-12

The user explicitly required implementation and execution of the benchmark.
The [measured record](../research/results/araphor-raw-storage-2026-11-12.md)
contains the source route, exact conditions, samples, environment, and limits.

Four alternating pairs ran at each existing dataset size. All 16 final process
runs pass byte/cursor checks, retained-cut reads, owner reopen, saved positions in
original logs, and continued replay. At 262,144 records, median write rates
are 210,646 records/s for segments and 373,741 for Fjall. Pooled append p95 is
1.264 versus 0.737 ms per 256-record batch. Paged-read rates are 5,572,239 versus
4,920,938 records/s. Allocated space after forced maintenance is 36.40 versus
52.96 MiB. These are pilot measurements, not complete Data replacement proof.

The implemented fixture compares RawJournal directly with a versioned Fjall
branch. Both use the same RawCommit codec and in-memory range index. The
candidate persists entry metadata and receipts with its payload. The pilot
covers disjoint contiguous inputs. It does not implement overlapping retry,
expiry/witness parity, killed-process recovery, or sustained natural compaction.
Reopen integrity work differs and is stated in the record. The later proposal
below retains the wider qualification work as unimplemented scope.

### Production path comparison, 2026-11-12

The user requests a second comparison. Include the current segment append and
the later Fjall metadata commit. Compare that path with events held in Fjall
and source/cursor references. Keep the earlier pilot and its measurements.
The benchmark implementation and execution are approved. Production migration
and items 2 and 3 remain outside this request.

```text
The benchmark submits one prepared 256-record batch
  -> The hybrid condition calls NativeStore.accept_validated_batch.
  -> The Fjall condition commits payload, receipt, and input metadata together.
  -> Each condition returns its durable event acceptance.
  -> The benchmark captures the accepted input cut.
  -> Each condition resolves the same source/cursor input reference.
  -> Each condition commits the same result body, reference, and consumed cut.
  -> The hybrid DataWrite also commits the pending raw metadata anchors.

The benchmark reopens each store after native flush and compaction
  -> Each condition reads its result and consumed cut from committed storage.
  -> Each condition resolves the saved source/cursor reference.
  -> Each condition walks original committed input after the saved cut.
  -> Each condition accepts another batch and resumes without repeated input.
```

Measure event acceptance, cut capture, result/reference/progress commit, and
the combined cycle separately. Both conditions have two durable stages.
Use the same 16,384 and 262,144 records, four alternating pairs, original
framed bytes, and 256-record read pages as the earlier comparison. Timings
remain report-only. Exact bytes, source cursors, positions, saved references,
retained cuts, and resumed input are correctness gates.

The Fjall condition uses native predecessor and range reads. It has no raw
segment files, segment offsets, RawEntry records, or in-memory range index.
The result record belongs to the benchmark. This condition does not implement
or qualify managed-result, processor, Graph, notification, or witness-retention
semantics. Close/reopen is not a power-loss test. Forced maintenance is not a
sustained compaction workload.

The [measured result and source review](../research/results/araphor-raw-owner-2026-11-12.md)
record all 16 passing process runs. At 262,144 events, hybrid and all-Fjall
cycle medians are 1.878 and 1.061 ms; p95 values are 2.018 and 1.391 ms.
Median cycle rates are 134,385 and 222,738 events/s. The all-Fjall rate is
1.657 times the hybrid rate across this condition. Reopened reads and resumed
log reads are slower in the candidate. Allocated space is 37.94 versus
53.69 MiB. Both conditions preserve the measured input, history, references,
and resumed output.

Result: **Done** for the requested transaction comparison. Production
replacement and complete lifecycle qualification remain **Not done**.

### Read access investigation, 2026-11-12

The user requests investigation of Fjall read performance. The
[measured access-path record](../research/results/araphor-raw-read-2026-11-12.md)
contains two finite experiments, source review, and complete samples.
Each experiment uses four alternating pairs at both existing counts.

The point-lookup experiment gives mixed results and is removed. The independent
page implementation stays unchanged. A separate native continuous-scan mode
holds one snapshot and source-prefix iterator per query. At 262,144 events,
reopened median rates are 4,427,753 events/s for independent pages and
4,813,199 events/s for the native stream. The four paired stream rates improve
by 5.9% to 12.5%. Both modes use the same release binary and output checks.
This is a modest bulk-query gain. It does not establish lower latency for
independent requests or notifications.

The stream is a benchmark access path. The focused partial-page/history test,
both-backend smoke checks, and all 32 measured process runs pass. Production
storage, DataFusion integration, and the general table abstraction do not
change. Result: **Done** for the requested read investigation. Production
integration remains **Not done**.

### Approved kernel-evidence storage replacement

Replace the Control kernel-evidence intake storage used by the benchmark.
Data remains the durable owner. Use its existing versioned Fjall database and
branch. Do not create another database, input archive, collector framework, or
general table abstraction. Diagnostic output and node retry spools keep their
current owners.

#### Intended end state

Kernel-evidence payloads have no Data segment files or segment references.
One native transaction commits original event bytes, source receipt, epoch
binding, accepted-span indexes, Data position indexes, and the exact Data cut.
Public source/cursor references and logical Data revision/ordinal positions
remain stable. DataFusion reads use native indexed state. Input subscriptions
walk original Fjall journals from their durable saved positions.

```text
Control submits one validated kernel-evidence batch
  -> Data checks identity, CPU, epoch, expiry, and overlapping original bytes.
  -> Data accepts only the new cursor spans.
  -> Data stores one original RawCommit payload under source and batch-first cursor.
  -> Data stores one native span pointer for each accepted span.
  -> Data stores an ordered Data-position index to the same payload.
  -> Data commits payload, indexes, receipt, and Data cut in one native batch.
  -> Data publishes the committed view and signals input readers.

An input subscription advances from its saved native cursor
  -> Data reads the original committed Fjall batch.
  -> Data routes each original evidence payload once by source and logical position.
  -> Data ignores supporting span and receipt writes as duplicate event triggers.
  -> The package reads changes and native indexed state from its captured view.
  -> Data commits package output, references, and consumed progress atomically.

A retained read selects evidence
  -> Data finds source/cursor spans or the ordered position index.
  -> Data checks current expiry authority before it returns historical payloads.
  -> Data validates the immutable batch against its source and index metadata.
  -> Data merges evidence and diagnostic ranges in original Data-position order.

Evidence expires after required consumers and witnesses release it
  -> Data commits expiry, source floor, removal metadata, and payload tombstones together.
  -> Current and old application views cannot return expired payloads.
  -> Fjall reclaims physical versions when its history and journal policies permit.

Data reopens or restores a backup
  -> Data admits native format 12.
  -> Data rejects older formats and mixed legacy evidence files. It does not convert or delete their payloads.
  -> Data validates live payloads, indexes, receipts, references, and saved progress.
  -> Evidence comes from the native checkpoint.
  -> Only diagnostic payloads use the external segment inventory.
```

The position index contains metadata and pointers. It is not a second payload
archive or CDC log. Data revisions in this ordered index represent input
positions; native engine revisions remain outside payload application keys.
Arbitrary overlaps can produce several new spans in one accepted payload.
Do not substitute the benchmark's contiguous-only admission rule.

Evidence pins use native batch references and public source/cursor identity.
Diagnostic pins retain their segment identity. Do not invent native segment
IDs. Usage counters distinguish logical referenced payload bytes from database
allocation. Native expiry does not promise immediate physical erasure:
unrelated retained package, context, or catalogue roots can retain old evidence
versions indefinitely. Diagnostic file removal retains its current behavior.

Verification must cover overlap, conflicting retry, CPU/epoch identity,
out-of-order input, source pagination, complete/changed/metadata reads,
DataFusion extraction, original-log wake and restart, witness pins, logical
expiry through old views, maintenance, backup/restore, and diagnostic behavior.
Use focused checks during iteration. Keep the ignored incident disabled.
Use the existing finite benchmark inputs for performance evidence; do not
infer the earlier prototype timings for the production replacement.

The [implementation review](../guides/araphor-kernel-evidence-storage-review.md)
gives the source route. The focused release run passes 293 Data integration
tests, 14 native Query tests, and two public Control intake tests. The existing
owner example passes its partial history test and its native production smoke
run. The paired production comparison is pending.

The Data library target reports 80 compile errors in old DuckDB and
`graph_rows` tests. The Control library target reports 36 compile errors in old
Graph and activation tests. The final shared CI procedure stops at formatting
in 123 files outside this change. Changed Rust files pass formatting.

Result: **Done** for the collector storage replacement and focused owner
qualification. **Not done** for the paired production comparison and the
repository-wide qualification blockers above.

### Event flow before replacement

```text
Data receives one validated evidence batch
  -> NativeStore takes its writer and raw-owner locks.
  -> RawJournal checks source identity, cursors, retries, and retained ranges.
  -> RawJournal builds one RawCommit with metadata and original framed bytes.
  -> SegmentFile writes the commit at the expected file offset.
  -> RawJournal calls syncfs on the segments filesystem.
  -> Data publishes the new raw index and Data revision.
  -> Data signals the committed revision to input readers.

A native metadata transaction follows raw appends
  -> Data stages source receipts and committed segment ends in that transaction.
  -> Fjall commits those anchors with the metadata changes.
  -> The published Data view binds one native snapshot to one raw prefix.

A reader requests a retained event range
  -> Data selects committed entries from the captured raw index.
  -> RawRead reads the containing commit frame.
  -> RawCommit checks length, CRC, protobuf decode, and canonical re-encoding.
  -> RawRead copies the requested original record slices.
  -> The common extraction path can decode records into Arrow columns.

A retry overlaps accepted input
  -> RawJournal reads the overlapping stored commits.
  -> It compares original bytes and rejects conflicting content.
  -> An identical retry does not append another payload.

A write fails after an uncertain durable operation
  -> Data prevents further publication and requires recovery.
  -> Recovery validates retained segments and rebuilds their raw index.
```

### Verified costs and differences

| Area | Current raw segments | Versioned Fjall candidate |
| --- | --- | --- |
| Commit unit | One framed batch: metadata, original bytes, length, CRC. The usual rotation target is 16 MiB; oversized batches can exceed it. | The initial comparison should use one key/value per newly accepted RawCommit. Native revisions remain outside application keys. |
| Durable completion | Positional write, then filesystem-wide `syncfs`, then index publication. Ordinary append does not call a separate file `fsync`. | Branch receipt commits write the journal and use `SyncAll`, then apply memtables and publish. Buffered inserts are not an equivalent baseline. |
| Payload writes | No Fjall payload write or Fjall transaction for each raw-only append. Later metadata commits save raw anchors. | Payload enters Fjall's journal and memory tables, then native flush and compaction. Measure foreground return and later maintenance. |
| Read granularity | Selected records still require validation of their containing batch frame. A small selection can decode more bytes than it returns. | Batch values keep comparable granularity. A per-record layout changes the number of keys, write cost, and read cost; it needs a separate declared comparison. |
| Selection | Persistent in-memory indexes select source/cursor ranges. The position-based extraction selector also filters chronological entries by source and time. | Ordered native point/range reads are available. Their benefit depends on the declared keys and requested range. |
| Restart | Open reads retained segment files, checks commits, and rebuilds the raw index. | Native recovery uses manifests, tables, and recovery journals. A complete Data owner can add validation work. |
| Reclamation | Whole-segment deletion must preserve unconsumed input and witnesses. One retained event can keep its containing segment. | Deletes and retained snapshots/history affect when compaction can reclaim bytes. Logical deletion is not physical reclamation. |

The scope of `syncfs` is confirmed by the
[Linux manual](https://man7.org/linux/man-pages/man2/sync.2.html).
It can include unrelated dirty files on that filesystem. This is a candidate
cost to isolate, not a measured cause of a slowdown. A narrower synchronization
scheme would require separate durability and crash-recovery proof. No such
change is approved here. File synchronization alone also does not establish
durability of a new directory entry; see
[fsync](https://man7.org/linux/man-pages/man2/fsync.2.html).

### Existing evidence and its limits

- The [raw-store comparison](mithril-hugging-face-intrusion-prevention/phase-7-mithril-control-and-detection-packages/raw-event-store-decision.md)
  compared earlier segments with raw DuckDB. It explicitly excludes the current
  segment-plus-metadata design. Its rates do not answer segments versus Fjall.
- The [current raw harness](../../crates/mithril-control/src/store/raw_bench.rs#L133)
  prepares 256-record batches, times durable acceptance, reopens, and verifies
  decoded pages. It currently accepts only the production `analysis` mode.
  There is no Fjall-payload comparison mode.
- The [native raw qualification](../research/results/araphor-native-raw-2026-11-09.md)
  proves aspects of the shared raw/native view. Its Graph PoC did not exercise
  real raw segments, and its incident timings do not isolate raw storage.
- The [Graph storage PoC](../../crates/araphor-graph/examples/storage_poc/main.rs#L318)
  compares Graph workloads and explicitly excludes raw ingestion. Its timings
  cannot be reused as raw-event storage timings.

**Initial review result:** no matched current raw-segment-versus-Fjall result
was found in those earlier sources. The new measured pilot above supplies the
first comparison in this investigation. No performance is inferred from the
older DuckDB or Graph workloads.

### Measurement design and remaining qualification

The approved pilot implements the shared codec, raw/Fjall backends, and runner
under the existing `test-fixtures` feature. It reuses the raw harness record
shape and uses temporary storage. The wider checks below remain necessary
before production replacement.
Do not replace production storage or copy live payloads into a second archive.

The benchmark belongs with `araphor-data`. The first candidate stores one newly
accepted `RawCommit` per key formed from its source and first newly accepted
cursor, in a native versioned branch. The initial disjoint workload has one
commit per input batch. An overlapping retry can have multiple new spans; preserve the accepted commit
boundary and do not store accepted bytes twice. Keep the same original framed
bytes, validation, receipt semantics, and retained cuts. No revision is encoded
into application keys. Add the accepted-span lookup metadata needed to locate
records across overlapping input ranges; include its writes and space in the
results. A batch-start key alone is insufficient when a commit has several
spans. This is an experiment layout, not the production table abstraction.

| Measurement | Required comparison |
| --- | --- |
| Durable append | Same prepared inputs, 256 records per batch, and retained counts of 16,384 and 262,144 from the existing raw comparison. Time through durable acceptance and publication. Include encoding done by the storage owner. |
| Reads | Complete paged read after reopen; source/cursor range reads; one-record selection within an accepted batch. Verify exact bytes and order. Separate storage read, frame decode, and Arrow conversion time where measured. |
| Retry and failure | Identical retry, conflicting retry, out-of-order input, partial tail, and failure before publication. Preserve durable accepted bytes and original positions. |
| Saved positions | Walk each backend's original committed log, stop at a saved position, reopen, resume, and continue after another append. Keep input matching and durable progress semantics equal. |
| History and retention | Read a retained cut after later writes and reopen. Protect a witness and unconsumed input. Report logical expiry separately from physical reclaimed bytes. |
| Maintenance | Include native flush and actual compaction before choosing a backend. A fresh-memory-table result cannot qualify sustained storage. Use the existing engine settings; report completed maintenance and foreground stalls. |
| Full owner cost | Report native metadata anchoring/checkpoint separately from raw acceptance. Raw-only segment writes currently do not commit Fjall; a bare Fjall put cannot stand in for all Data work. |

Run release binaries in separate processes on the same device and filesystem.
For each of the two core dataset sizes, the pilot ran four pairs with orders AB, BA,
AB, BA: 16 finite process runs in total. Record the binary/source identities,
engine settings, prepared input bytes, page/cache conditions, and actual elapsed time.
Run without concurrent builds or benchmarks. Report median, p95, p99, maximum,
throughput, CPU, peak memory, logical/allocated bytes, and maintenance work.
Retain samples rather than only rounded summaries.

The pilot runtime and process resource samples are in the measured record.
The plan sets no invented elapsed-time estimate or performance threshold. The core runs stop after their declared inputs and read
checks. The retained counts are benchmark datasets, not production quotas.
The user required the finite pilot to run. A sustained
compaction extension needs a concrete run size/runtime proposal based on that
pilot. Do not keep growing a database without an approved stop
condition. If compaction is not exercised, mark that coverage **Not done**.

Correctness is a pass/fail gate: exact records, logical source cursors, retained
contents, retry results, and resumed output must agree. Physical file offsets
and native engine revisions can differ across backends. Protect native history
and original journal positions separately; a retained snapshot alone is not a
CDC retention policy. Timing is report-only until the user selects acceptance
criteria from measured results. No existing
test workload, assertion, or timeout changes. The ignored incident stays ignored.

### Recommendation and approval boundary

Keep the current production owner until the user approves a replacement. The
batch-shaped pilot above is measured. A per-record Fjall layout is a separate
experiment if the batch results leave selective-read cost unresolved. Do not
select a replacement from the old DuckDB or Graph PoC numbers.

The source/evidence investigation and bounded matched pilot are **Done**.
Complete performance/recovery/retention qualification and the production storage
decision are **Not done**. Benchmark authorization does not approve production
migration or items 2 and 3. No full CI or ignored incident run was made.

### Source reading route

- [Raw acceptance and publication](../../crates/araphor-data/src/analysis/native/source/raw.rs#L223)
- [Raw batch encoding, rotation, and append](../../crates/araphor-data/src/analysis/raw_segments.rs#L166)
- [Positional file writes](../../crates/araphor-data/src/analysis/segment_file.rs#L254)
- [Raw read and record selection](../../crates/araphor-data/src/analysis/raw.rs#L570)
- [Extraction selection](../../crates/araphor-data/src/analysis/raw.rs#L850)
- [Raw index](../../crates/araphor-data/src/analysis/raw/index.rs#L14)
- [Metadata anchoring](../../crates/araphor-data/src/analysis/native/source/raw.rs#L528)
- [Checkpoint](../../crates/araphor-data/src/analysis/native/backup/mod.rs#L21)
- [Fjall durable commit](../../fjall/src/batch/mod.rs#L136)
- [Fjall journal sync](../../fjall/src/journal/writer.rs#L269)
- [Fjall indexed reads](../../fjall/src/versioned/read.rs#L38)

## Additional items

Append new numbered requests to the table. Investigate the next item only after
the user selects it. Do not start implementation from a draft entry.
