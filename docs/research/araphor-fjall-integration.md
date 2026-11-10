# Replace DuckDB with versioned Fjall

Research date: 2026-11-09. Result: **Research complete; production migration not done**.
This record proposes the production integration of the completed engine forks.
The optional native Graph participant and its existing package PoC caller are
now [qualified](../../crates/araphor-graph/examples/storage_poc/results/native-graph-2026-11-09/README.md).
The comparison records a slowdown. Production Data integration and the incident
performance targets remain **Not done**.
The optional native Data metadata owner now commits and publishes the existing
PoC's source, Graph, context state, and checkpoint writes. Its
[qualification](../../crates/araphor-graph/examples/storage_poc/results/native-data-2026-11-09/README.md)
passes five integration cases and the unchanged package workloads. The small
mixed timing differences establish no repeatable performance gain. The complete
production transaction and raw-view migration remain **Not done**.
The existing raw owner now publishes a shared persistent metadata root after
its durable append. Nine focused integration cases and the unchanged incident
pass. The [qualification](results/araphor-raw-index-2026-11-09.md) records the
source and limits. This does not establish a speedup. The combined raw/native
production Data view and cutover remain **Not done**.
The default-limit native owner now combines its exact raw prefix and native
snapshot. Actual Evidence and coverage storage passes 16 focused cases with
the existing transaction and schema regressions. Read the
[native raw qualification](results/araphor-native-raw-2026-11-09.md).
Production admission, routing, remaining transaction families, retention,
backup, and cutover remain **Not done**. No incident speedup is established.
Native package/image and definition admission and reads now pass 24 focused
cases with the existing storage regressions. Read the
[catalogue qualification](results/araphor-native-catalogue-2026-11-09.md).
At that catalogue qualification, collection, uninstall reclamation, capacity
accounting, qualified context/fact admission, managed lifecycle, and production
routing were **Not done**.
The native context owner now admits guarded batches, checked values, and
qualified interned values with the existing retained proof and fact decoder.
Thirty-four focused cases pass, including a current-owner shared-helper case.
Read the [context qualification](results/araphor-native-context-2026-11-09.md).
Context providers, managed results, notification lookups/effects, configured
capacity, collection, and production routing remain **Not done**.
Native managed admission and ordinary start/stop now use the existing manifest,
grant, retained-pin, and lifecycle contracts. New Graph mappings and declarations
share the admission transaction. Exact retries stage no writes. Read the
[managed qualification](results/araphor-native-managed-2026-11-09.md).
Attempt-dependent lifecycle, capture, result publication, consumed progress,
production activation, CDC routing, and notification batching remain **Not done**.
Native Arrow extraction now reads actual Evidence, coverage, and context rows
from one captured native/raw view. Body-free context indexes bound change and
owner reads. The shared raw scanner and Arrow builders preserve existing rows,
positions, witnesses, and references. Read the
[extraction qualification](results/araphor-native-extraction-2026-11-09.md).
At that extraction qualification, managed sealing and attempts were **Not done**.
Native managed capture now seals actual Arrow inputs. Native attempts preserve
live claims, pending indexes, terminal outcomes, failure status, and interrupted
frontier settlement. Read the
[attempt qualification](results/araphor-native-attempts-2026-11-09.md).
Shared publication validation now passes the unchanged incident. Read the
[shared validation qualification](results/araphor-shared-publication-2026-11-09.md).
That qualification checks the DuckDB production path. At that source state,
native successful publication was **Not done**; no matched gain was established.
The optional native Selected boundary now saves actual results, checkpoints,
Graph changes, findings, references, and consumed progress in one Data batch.
It restores actual priors and checks captured receipts and Graph authority on
reopen. Seventy focused Data tests pass. The unchanged production incident also
passes for the shared proof/import checks. Read the
[publication qualification](results/araphor-native-publication-2026-11-09.md).
This still uses DuckDB in production and establishes no native speedup.
Other destination owners, production providers, original-log routing, indexed
source-header maintenance, notifications, capacity, retention, backup, cutover,
and removal remain **Not done**.
Native result metadata and historical replay now use one captured view and
actual saved checkpoints. Indexed raw predecessors preserve historical
freshness after later appends and reopen. Seventy-three focused Data tests pass.
Read the [result-read qualification](results/araphor-native-result-reads-2026-11-09.md).
Production provider binding, cutover, and both performance targets remain
**Not done**.
Native finding and manifest tables now use saved publication cuts, visible
producer authority, and stable canonical tokens. A shared tenant index avoids
foreign publication reads without a durable format change. Seventy-four focused
Data cases pass. Read the
[finding-read qualification](results/araphor-native-finding-reads-2026-11-09.md).
Production provider binding, original-log routing, notifications, cutover, and
both performance targets remain **Not done**.
Optional native input routing now walks the original Fjall batches and raw
entries after a committed Data view. Shared readers stop at the published cut,
route matching positions, and replay after a saved view. Eighty-one focused
Data cases pass. Read the
[input-routing qualification](results/araphor-native-input-routing-2026-11-09.md).
At the input-routing qualification, durable consumer records, atomic
acknowledgement, collection floors, query resume parity, production binding,
cutover, and both targets were **Not done**.
Optional native managed subscriptions now save their exact interest and log
cut. Exhaustive completed captures advance consumed progress in the result and
Graph transaction. Recovery checks the actual successful capture. Ninety
focused Data cases pass. Read the
[consumption qualification](results/araphor-native-consumption-2026-11-10.md).
Result: **Done for optional native managed input consumption**. Production
query coverage mapping, collection floors, retention, notification batches,
backup, cutover, removal, and both incident targets remain **Not done**.
Native notification storage now supplies indexed finding/concern lookups,
ordered context pages, and checked batches of immutable versions. Historical
inserts and exact retries preserve current lookup membership. Read the
[notification storage qualification](results/araphor-native-notification-2026-11-10.md).
Result: **Done for optional native notification storage**. At that qualification, finding provenance,
prepared notification reads, production delivery batches, durable notification
consumption, retention, backup, cutover, DuckDB removal, and both incident
targets were **Not done**.
Native finding batches now read requested groups at saved publication cuts.
They use actual opening producers, retained historical parents, and one shared
witness, proof, and context accumulator. One hundred focused Data cases pass.
Read the [provenance qualification](results/araphor-native-provenance-2026-11-10.md).
Result: **Done for optional native finding provenance reads**. At that
qualification, native notification preparation, delivery batches, production
binding, retention, backup, cutover, DuckDB removal, and both incident targets
were **Not done**.
Native notification preparation now captures one view and returns the existing
prepared batch. Charged indexed reads supply current findings, routes,
obligations, exact pending subjects, and historical routes. Actual producers
supply proof; canonical values supply comparison only. One hundred and five
focused Data cases pass. Read the
[preparation qualification](results/araphor-native-prepared-2026-11-10.md).
Result: **Done for optional native notification preparation**. Production router
binding, delivery batches, durable notification consumption, retention, backup,
cutover, DuckDB removal, and both incident targets remain **Not done**.
Optional native Query now binds the existing DataFusion plans, source indexes,
package Graph journals, and managed subscriptions to native Data. The combined
gate passes 112 tests in 11 suites. Read the
[Query qualification](results/araphor-native-query-2026-11-10.md).
Result: **Done for optional native Query binding**. Production Control and
Analysis still use DuckDB. Production sink and router binding, delivery
batches, durable notification consumption, remaining storage owners, capacity,
retention, backup, cutover, removal, and both incident targets remain **Not done**.
Native Data now supports the remaining managed lifecycle operations and history
reads. Activation subscriptions walk lifecycle records through the shared original
journal reader. The final gate passes 120 tests in 11 suites, including actual
version promotion, rollback, recreation, consumer retirement, and reopen. Read the
[lifecycle qualification](results/araphor-native-lifecycle-2026-11-10.md).
Result: **Done for native Data lifecycle and original-log activation**. Production
Analysis host and sink binding, remaining storage owners, notification delivery,
capacity, retention, backup, cutover, DuckDB removal, and both incident targets
remain **Not done**. Production still uses DuckDB. No native gain is established.
Native Query now separates finite execution from durable input consumption.
First following execution and revived older generations restore complete source
coverage before they consume live changes. Guard rejection, stale admission,
restart, and post-capture input remain covered. The gate passes 127 tests in
11 suites. Read the [startup qualification](results/araphor-native-startup-2026-11-10.md).
Result: **Done for optional native subscription startup and version changes**.
Production binding, remaining storage owners, notification delivery, capacity,
retention, backup, cutover, DuckDB removal, and both incident targets remain
**Not done**. No native production speedup is measured.
The active user goal now approves that integration. No benchmark is added. Read the
[storage design](../plans/araphor-log-graph-storage.md),
[engine contract](../plans/fjall-versioned-storage.md), and
[latest incident result](../plans/araphor-execution-handoff.md#follow-transactions-use-the-recorded-input-cut-2026-11-05)
with this record. Earlier measurements do not describe a completed migration.

Source: Runtime `d30dceaba`, Fjall `a04286570637`, and `lsm-tree` `2e1b5df34ffc`.
Both engine checkouts use `feat/versioned-storage`. Unrelated working changes
are outside this research.

## Intended end state

Data owns one versioned Fjall database and its commit boundary. Its live branch
contains table state, Graph records, package state, results, evidence references,
notification state, and consumed input positions. Raw event payloads remain in
the existing append-only segments. There is no second event payload archive.

One published Data view binds an exact native snapshot to an exact raw prefix.
Native DataFusion plans read that view and the required changes. Package
definitions start subscriptions. A package decides whether to use Graph and
which Graph changes to stage. Data commits those changes with package state
and input progress. Packages cannot commit the transaction.

Data reads original committed logs to select subscription wakes. An unrelated
transaction cannot cause a package source wake. A failed step cannot acknowledge
its input. Retained historical reads and branches survive compaction and reopen.
Graph semantics remain in Araphor Graph; engine branches contain no package
or Graph knowledge.

The performance goals remain notification creation below 100 milliseconds and
the requested 100-fold improvement. Neither result follows from engine selection.
Use the same incident workload and measurement boundaries to prove them.

## Measured starting point

The latest qualified incident result passes. Its workload includes four evidence
streams on two nodes, 16,384 background logical records, 16,402 total raw records,
and three notifications. The definition calls the Causal package's `index` and
`detect` exports. The partial incident must produce no finding. See the
[test](../../crates/mithril-e2e/src/discovery/packages/required/incident/incremental.rs#L695)
and [default definition](../../packages/default-definitions/causal.yaml).

| Existing measured boundary | Recorded result |
| --- | ---: |
| Collector receipt to first durable notification creation, three episode medians | 1,659.962 / 3,041.402 / 3,300.817 ms |
| Graph publication to notification creation, same episodes | 334.079 / 486.592 / 559.939 ms |
| Final later managed commit, median | 960.515 ms |
| Private preparation inside that commit | 118.467 ms |
| Transaction work inside that commit | 786.845 ms |
| Final durable commit call inside that commit | 51.528 ms |
| Publication-row preparation inside transaction work | 266.034 ms |
| Graph journal work inside transaction work | 366.222 ms |
| Native Graph application inside Graph journal work | 277.772 ms |

These intervals are nested. Do not add child intervals to their parents.
They do not give a complete, disjoint breakdown of collector-to-creation time.
The final later commit, its SQL storage requests, and notification processing
are concrete replacement targets. Source capture and package input processing
also remain on the path. Replacing only the 51.528 ms commit call cannot meet
the complete latency goal. The
[handoff](../plans/araphor-execution-handoff.md#follow-transactions-use-the-recorded-input-cut-2026-11-05)
records the paired runs; their original JSON remains at
`/tmp/araphor-recorded-follow-pairs-20261105/`.

The completed engine's unchanged PoC has an ordinary combined median of
4.655 ms, p95 of 7.668 ms, and maximum of 8.171 ms across 112 samples.
This interval includes source write, original-journal wake, package Graph work,
atomic Graph/progress commit, output wake, and result read. It excludes production
DataFusion input capture and notification processing. The
[reviewed evidence](../../crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/simplification/README.md)
does not establish an incident speedup or large-history performance.

## Required runtime flow

```text
Control accepts a raw-only event batch
  -> Data completes the existing raw segment append and durable sync.
  -> Data publishes the new raw prefix with the unchanged metadata snapshot.
  -> Data signals its raw log reader that committed data is available.
  -> The reader walks actual committed raw entries after its saved position.
  -> The reader routes matching source positions to existing subscription interests.

A context, table, Graph, or finding mutation commits
  -> One Fjall batch saves the rows and their indexes.
  -> SyncAll completes and returns the exact native revision and journal cursor.
  -> Data publishes the matching snapshot and native owners.
  -> Data's journal reader decodes the committed batch.
  -> Data routes only matching input changes after the subscriber's consumed position.

A package subscription receives matching input progress
  -> Query captures one Data view and the interval after its saved input position.
  -> Providers supply changed keys and the declared before and after Arrow inputs.
  -> The saved native DataFusion plan performs the declared SQL and package calls.
  -> Package code reads indexed Graph data only when its algorithm needs Graph.
  -> Package code stages the changes that it selects.

The package step is ready
  -> Data checks existing authority, state heads, evidence, and recorded input cut.
  -> Araphor Graph adds prepared membership, property, and adjacency changes.
  -> One branch transaction saves all outputs, state, result references, and input progress.
  -> Data completes SyncAll and publishes one matching Data view.
  -> Journal routing wakes subscribers to the changed output.
  -> Later input remains pending after the consumed input cut.

Notification input changes
  -> The saved notification plan selects changed findings and affected obligations.
  -> The router prepares the required obligations and pending delivery attempts.
  -> Data saves the batch and the router's consumed input position atomically.
  -> Delivery performs the existing live authority check outside the write transaction.
  -> Data saves delivery outcomes through the same notification owner.

Execution fails, or a durable commit outcome is uncertain
  -> Data does not publish unconfirmed output or acknowledge its input.
  -> An uncertain commit stops new captures and writes until recovery.
  -> Recovery restores durable state, history protection, and saved consumer positions.
  -> Retry reads from the last committed input position.
```

First-source admission can require a metadata commit before the raw-only path.
That commit follows the metadata flow above. It must not start Graph analysis;
the running package definition owns that work.

## Parts that must change

| Current source owner | Replacement and removal |
| --- | --- |
| [Data store](../../crates/araphor-data/src/analysis/mod.rs#L108), [connections](../../crates/araphor-data/src/analysis/connection.rs#L412), and [read control](../../crates/araphor-data/src/analysis/read.rs#L257) | Own the versioned database, live branch, typed keys, and published views. Remove DuckDB writer/read connections, SQL transactions, and native query interrupt plumbing. Keep leases, cancellation, admission, and uncertain-commit behavior. |
| [Raw journal](../../crates/araphor-data/src/analysis/raw.rs#L557), [segment I/O](../../crates/araphor-data/src/analysis/raw_segments.rs#L230), and [SQL projection](../../crates/araphor-data/src/analysis/raw_catalog.rs#L607) | Keep durable raw bytes, receipts, and exact cursor ranges. Publish a shared immutable index of committed raw entries. Remove lazy raw-to-SQL projection and reader dependence on `project_raw`. No Fjall payload copy or extra Fjall sync is required for each raw-only append. |
| [Input registration and publication](../../crates/araphor-data/src/analysis/inputs/mod.rs#L43) and [interest matching](../../crates/araphor-data/src/analysis/inputs/interest.rs) | Keep actual native-plan interests. Replace producer calls to `inputs.publish` and `inputs.metadata` with log-reader routing. Index interests by branch, tenant, and relation, with existing source/owner selectors. Do not scan all subscribers for every changed row. |
| [Managed commit](../../crates/araphor-data/src/analysis/managed/commit.rs#L156), [Graph commit](../../crates/araphor-data/src/analysis/managed/graph/commit.rs#L438), and [source state](../../crates/araphor-data/src/analysis/managed/source.rs) | Replace SQL joins/appends with indexed typed reads and one write set. Preserve the complete atomic result/state/Graph/progress boundary. Prepare private Arrow values before the writer scope. Reuse retained call state; do not restore all earlier outputs on each wake. |
| [Graph storage](../../crates/araphor-graph/src/store.rs#L27), [layers](../../crates/araphor-graph/src/layers.rs#L28), [dictionaries](../../crates/araphor-graph/src/dictionary.rs), [properties](../../crates/araphor-graph/src/properties.rs), and [read views](../../crates/araphor-graph/src/read/view.rs#L13) | Replace SQL dictionaries, membership intervals, endpoint joins, and reconstruction with stable keys, native historical snapshots, and direct/reverse adjacency. Keep opaque Graph/writer/owner IDs and typed Arrow values. Use Data's supplied transaction; Graph does not open a database or commit. |
| [Data Graph rows](../../crates/araphor-data/src/analysis/graph_rows/store/mod.rs), [native relations](../../crates/araphor-data/src/analysis/graph_rows/store/relations.rs), and [finding reads](../../crates/araphor-data/src/analysis/extraction/graph/native.rs) | Store result membership, producers, finding projections, provenance, and evidence indexes in the same live branch. Remove duplicate SQL membership preparation. Data retains package attribution; generic Graph retains no detector rules or package definitions. |
| [Table extraction](../../crates/araphor-data/src/analysis/extraction.rs#L1767) and [Arrow table builders](../../crates/araphor-data/src/analysis/extraction/tables/mod.rs) | Read exact key/prefix/range selections from a pinned view. Build requested Arrow columns. Reuse immutable Arrow chunks. Remove SQL staging and complete-table reconstruction from ordinary change reads. |
| [Query sources](../../crates/araphor-query/src/sources/mod.rs), [change contracts](../../crates/araphor-query/src/definition/package/changes.rs#L9), [progress](../../crates/araphor-query/src/stream/progress.rs), and [saved execution](../../crates/araphor-query/src/stream/physical/runtime.rs) | Bind the new views, log positions, and affected-key reads to existing providers. Keep native plans, package-call operators, joins, filters, windows, and declared change contracts. A CDC signal does not make arbitrary SQL incremental. |
| [Notification processing](../../crates/araphor-analysis/src/notification/reactive.rs), [saves](../../crates/araphor-analysis/src/notification/store.rs#L133), [attempts](../../crates/araphor-analysis/src/notification/attempt.rs), and [Data notification indexes](../../crates/araphor-data/src/analysis/notification.rs) | Replace per-obligation context commits and repeated lookup cycles with one bounded preparation and batch save. Keep route selection, retry, escalation, ordering, and pending-before-effect behavior. Route changes must reevaluate their affected existing findings. |
| [Contexts](../../crates/araphor-data/src/analysis/context.rs), [packages](../../crates/araphor-data/src/analysis/packages/mod.rs), [definitions](../../crates/araphor-data/src/analysis/definitions.rs), [progress](../../crates/araphor-data/src/analysis/progress.rs), and [trace](../../crates/araphor-data/src/analysis/trace.rs) | Replace their SQL records and indexes, including exact version references, installation, lifecycle, coverage, trace intent, and completion. Preserve existing artifact and raw-file ownership. |
| [Retention](../../crates/araphor-data/src/analysis/retention.rs), [capacity](../../crates/araphor-data/src/analysis/capacity.rs), [validation](../../crates/araphor-data/src/analysis/schema.rs), [backup](../../crates/araphor-data/src/analysis/backup.rs), and [recovery](../../crates/araphor-data/src/analysis/connection.rs#L288) | Replace database-specific operations and accounting. Coordinate native history, CDC floors, evidence pins, file deletion, branch deletion, and reopen. A native snapshot alone is not a complete Data backup. |
| [Cargo dependencies](../../Cargo.toml), [Graph feature](../../crates/araphor-graph/Cargo.toml), and [storage fixtures](../../crates/mithril-e2e/src/discovery/data_store.rs) | Pin both forks. Remove DuckDB dependencies and vendor patches once no caller requires them. Replace database-file inspection and SQL corruption fixtures with equivalent native checks. Keep the selected incident's workload and assertions. |

The native Graph PoC in
[native.rs](../../crates/araphor-graph/examples/storage_poc/native.rs) supplies
an indexed layout and package parity evidence. Move its useful storage work to
the production owners. Do not ship its multi-engine benchmark dispatch, fixture
assumptions, full-prefix collection helpers, or unrestricted property cache.

Current Graph traversal already uses
[native committed memory indexes](../../crates/araphor-graph/src/committed.rs#L283).
DuckDB still supplies metadata, durable writes, and recovery. Preserve useful
indexed reads and shared Arrow buffers within the published view. Moving every
warm read to disk does not establish an improvement.

Update the published raw index by sharing unchanged tree paths. Do not copy the
complete source catalogue on each append. Keep the finite read/file lease;
an inactive subscription or historical engine snapshot must not hold every raw
file open or prevent evidence retention.

The current [attempt registration](../../crates/araphor-data/src/analysis/managed/commit.rs#L25)
also commits before execution. Fold ordinary step bookkeeping into the final
atomic write after retry and recovery parity is proved. Keep installation,
grants, activation, and lifecycle at their existing durable boundaries.

## Storage, revisions, and Graph history

Use one live engine branch for the complete atomic Data state. Separate key
families by record kind and tenant. Do not create a storage branch per package,
Graph, writer, or table: the existing branch transaction writes one branch.
Graph writer IDs and layer IDs retain their current meanings.

Mutable rows and adjacency postings use stable keys. Native versions retain
their earlier values and strong deletions. Immutable context versions, result
IDs, and layer IDs remain semantic identities where current APIs reference them.
An immutable revision-to-cut index is control metadata, not a revision suffix
on every mutable key.

Keep three coordinates distinct:

- Data revision and ordinal identify the public committed input order.
- Native `Revision` selects a retained metadata/Graph view.
- Physical raw positions and Fjall `Cursor` values identify resumable log progress.

The engine returns its exact native revision only after commit. Data
needs that cut in a durable index in the same batch. Fjall `cceaa84` adds the
consuming `BranchWriteTransaction::commit_stamped(keys)`.
It uses the existing private
[batch revision stamps](../../fjall/src/batch/mod.rs#L69). Each supplied key
receives the exact native revision of this batch. Duplicate keys and collisions
with staged puts/removes are errors. Stamps are writes; a stamps-only commit is
nonempty. There is no provisional revision read. Empty or over-width stamp keys
return an invalid-input error before sequence allocation. This API is **Done**;
its production Data caller and the production migration remain **Not done**.

Data stamps `cut/<Data revision>` and required `layer-cut/<layer ID>` records.
To open Data revision R, seek the greatest metadata cut-index entry at or before
R, then call `branch.read_at(cut)`. Combine it with raw entries through R.
Create an initial cut-index entry before admitting source input. A raw-only
revision reuses the prior metadata cut and needs no extra database transaction
or raw-format change. Do not obtain a historical cut by sampling today's head
or rebuilding an index from journals that can be reclaimed.

The ordinary Graph view selects each writer's latest layer at the common Data
cut. A request that explicitly selects older writer layers needs the retained
native view for each selected writer. Put writer identity in membership and
adjacency prefixes, read each prefix at its selected cut, and merge through
existing Graph ownership rules. Enumerating only today's adjacency loses edges
that existed at an older selected layer. Keep the opened Data revision in member
values for existing origin/provenance behavior.

Use the TerminusDB principles already selected in the storage design: immutable
layer identity and parent, dictionary reuse, membership additions/removals,
indexed traversal, and separate head publication. Native MVCC replaces manual
storage-version intervals. It does not replace Graph ownership or package
analysis. Encode durable property chunks once with the existing Arrow IPC path;
reuse live Arrow buffers and charge them to existing memory owners. Preserve
valid long binary keys and property values through engine-width fragmentation.

A database checkout or fork uses `read_at` or `fork` on a retained native cut.
A full Data checkout must also bind its historical raw prefix and evidence
availability. Fjall does not fork or retain external raw files. A storage fork
does not activate package jobs or notification delivery. Branch merge is outside
the implemented engine contract.

History policy changes have separate durable engine commits. Install an
open-ended retained range before the first source write. Advance its lower
bound during maintenance from committed result, replay, and evidence references.
Protect the replacement range before releasing the old policy. Do not add one
policy commit per package step and claim that publication still needs only one
sync. This simple range retains intermediate revisions too; measure that storage
cost before proposing finer retention.

## CDC and incremental execution

The current [input owner](../../crates/araphor-data/src/analysis/inputs/mod.rs#L43)
is selective, but its producers publish change descriptions after their own
commits. It does not walk Fjall's original journal. Replace the producer route,
not the subscription API. Use one Data-owned reader per log domain and fan out
matched progress; do not open a journal reader for each package.

Fjall supplies `journal_feed`, `next_batch`, `wait`, cancellation, and
`retain_after`. Its
[items](../../fjall/src/cdc.rs#L13) contain branch/keyspace identity, key, new
value, and deletion. They have no query, tenant, finding-selection, or package
semantics. Data decodes its own typed keys and applies the existing input
selectors. Auxiliary index changes must not create duplicate source work.
An internal log-reader wake for available bytes is distinct from a package
source wake. `Feed::wait` blocks; keep it on the blocking owner and bridge
matched progress into existing async watches.

The current raw log remains the CDC source for event payloads. Walk its durable
entry positions and spans. A wake carries a high-water position, not the only
copy of the delta. Coalesced wakes must consume the complete required interval.
Data must not route a Fjall batch before the corresponding Data view is visible.

Registration must capture the view and both log starts under the floor
coordinator before collection can advance. A feed or snapshot handle does not
retain the journal. Save consumed positions with the step's output before
advancing the durable minimum floor. Keep physical scan progress separate from
completed matching work. Filtered traffic can advance a consumer's safe scan
position without calling its package; persist that progress before using it for
collection. Never skip pending matched input or create an acknowledgement loop
from the coordinator's own records.

Bind a saved scan position to the same subscription interest and job generation.
Coalesce filtered progress with ordinary commits. If only filtered traffic stops
collection, save a metadata-only checkpoint through Data. Save the decoded input
cursor, not a sampled head or the checkpoint's own cursor. Exclude coordinator
records from application source matching. Stop before the first matching batch
whose processing has not committed. A shared reader's scan head alone cannot
authorize collection for its consumers.

Native CDC contains no old values. Preserve required native history so providers
can obtain before and after values for the affected keys. Preserve raw references
when changes can remove evidence. History retention, journal retention, and raw
evidence retention have separate owners and floors. Releasing one does not
release the other two. Expired history must be reported; do not silently replace
it with current state.

Retain the saved native plan. Bind each execution to the exact view and changed
key interval. Push projection, key, prefix, and range selection into providers
when this avoids storage reads. Keep other expressions in native DataFusion.
This follows the official
[provider contract](https://datafusion.apache.org/library-user-guide/custom-table-providers.html).
Its current documentation is guidance; the checked-out dependency remains
DataFusion 55.0.0.

An input delta is not a complete incremental join result. Reuse the package's
declared affected/before/after contracts and native join operators. A new event
may require an older Graph neighbor or table row. The package can request that
indexed state; do not send only new rows and lose the earlier evidence. Existing
finite snapshot SQL keeps its complete semantics and measured cost. Unsupported
incremental plans remain an explicit implementation gap. A full evaluation on
each wake does not qualify as the incremental end state. The selected incident
definition must consume changes and indexed state on its ordinary update path.
This migration adds no custom join, aggregate, SQL evaluator, or automatic
incrementalization framework.

Materialize distinguishes readable history from completed input progress and
requires a consistent logical time across sources. That distinction supports
the proposed Data view and separate retention/consumption positions; it is not
evidence that Fjall supplies a Materialize execution engine. See
[source frontiers](https://materialize.com/docs/sql/explain-timestamp/).

## Delivery, recovery, and removal order

The current router decodes a batch but still saves individual state transitions
through context commits. Replace that storage procedure with batch preparation
and a durable outbox. Preserve each required pending-before-effect boundary.
Do not promise exactly-once external delivery; an effect and a local commit are
not one transaction. Keep current attempt identity and retry behavior.

Implementation should proceed in this order, with reviewer agreement before
each code change:

1. Add and qualify exact cut stamping. Keep engine APIs generic. This API is
   complete at Fjall `cceaa84`; no production migration is complete yet.
2. Replace native Graph storage through Data-supplied native snapshots and write
   transactions. Use the existing package PoC as the first caller. Replace its
   duplicate storage algorithm with the production owner. Freeze its old control
   before changing the adapter. Keep workloads and logical assertions.
3. Add the Data view and typed transaction boundary with that real Graph
   participant. Replace every Data record in the atomic result boundary, including
   contexts, packages, state, evidence pins, results, and progress. Prove raw-only
   revision mapping, old readers during SyncAll, and rollback. Build the complete
   replacement before switching a running store. Do not split authoritative Graph
   and progress between two engines.
4. Connect raw and Fjall log readers, interest routing, native providers, and
   retained change-input execution. Remove producer-supplied source publications
   and raw-to-SQL projection when the replacement covers their callers.
5. Replace notification row commits with the batch outbox and changed-key reads.
   Run the unchanged incident path, then remove the old notification storage path.
6. Complete retention, capacity, validation, recovery, and backup/restore parity.
   Use a closed/quiescent native copy if no safe native backup API is available;
   copying live SST/WAL files is not a snapshot protocol. Restore native history
   and consumer floors before maintenance or collection. Check both external raw
   segments and referenced immutable artifacts.
7. Remove DuckDB schemas, connections, appenders, SQL-only fixtures, dependencies,
   and unused vendor overrides. Preserve the existing supported Data APIs and
   equivalent failure tests. Do not leave a permanent dual-backend framework.

No in-place conversion or legacy decoder is proposed here. Never open an existing
DuckDB directory as a new empty Fjall store. Use a separate new-format directory;
deployment migration of existing retained databases needs its own explicit scope.

## Proof and performance acceptance

Use the existing combined/stable PoCs as engine regression checks. Use only
`discovery::packages::required::incident::incremental::follows_incremental_sources`
for the incident performance comparison. Preserve its definition, data volumes,
partial-chain check, finding/evidence assertions, history checks, and timeouts.

Before and after binaries need matched release settings and source/lock records.
Use the existing paired-run procedure with no concurrent build. Report initial
creation, both later creations, bulk completion, public notification receipt,
and whole-test time separately. Attribute collector receipt and creation to the
actual incident input, not a later metadata commit. Keep successful complete-run
comparisons separate from the earlier failed 347.854-second run and older,
different workloads. Compute a 100-fold ratio only for the same boundary and
workload. Three notifications do not establish a production p99.

Reuse existing correctness cases for atomic failure, retry/reopen, raw retention,
Graph multi-owner membership, endpoint removal, exact historical results, source
selection, windows, revocation, delivery attempts, backup, and recovery. Add only
the missing regression checks at their owners. In particular, check registration
during commit, filtered traffic, pending input during collection/restart, and
before-images after compaction. A source wake must require matching unconsumed
input. Lifecycle and declared clock events retain their own wake reasons.

Record stage timings and work counts from the same successful incident runs.
If a stage still scans unchanged history or saves each row separately, replace
that procedure before tuning engine settings. Small changes within host variation
are not improvement evidence. Do not invent stage budgets or forecast a speedup
from the PoC. Keep full CI out of iteration, as requested. Production cutover,
sub-100 ms creation, and the 100-fold result remain **Not done** until measured.
