# Shared native Graph storage

The user requires about 90% less stored Graph payload for the existing
1,592-event backlog case. The current Graph packages reuse derivation work,
but Data writes complete Graph rows and complete package inputs and outputs
for each result. Store Graph nodes and relationships once, and record which
ones exist at each result revision. Do not shrink repeated snapshots into a
new compact snapshot format. Remove the repeated storage.

[Neo4j's store model](https://neo4j.com/docs/operations-manual/current/database-internals/store-formats/)
uses unique node and relationship IDs. A relationship holds its source node,
target node, type, and properties. Use that ownership shape in Data's DuckDB
tables. Keep Data as the only durable store.
[DuckDB's property graph support](https://www.duckdb.org/docs/2.0/guides/sql_features/graph_queries)
defines a graph over existing node and edge tables. It does not replace those
tables with a durable Graph store. No query extension or second database is
required for this storage change.

## Existing graph designs checked

[DuckPGQ](https://duckdb.org/docs/current/guides/sql_features/graph_queries)
defines a property graph over existing vertex and edge tables. The bundled
DuckDB build does not include DuckPGQ, and the current Data owner disables
extension autoload. DuckDB permits explicit extension loading; this build has
not tested it. Keep the native tables as the durable owner. Test extension
compatibility before replacing traversal SQL with SQL/PGQ. DuckPGQ's
[view test](https://github.com/cwida/duckpgq-extension/blob/main/test/sql/create_pg/create_pg_on_view.test)
rejects property graphs whose vertex or edge source is a view. Our historical
Graph selects version membership through views. Do not copy each selected
version into new physical tables merely to use SQL/PGQ. DuckPGQ's
[path query guide](https://duckpgq.org/documentation/sql_pgq/) documents
`ANY SHORTEST` path selection. Our Graph walk returns the bounded set of
reachable subjects and relationships for an exact result. A replacement must
prove the same results and proof scope. DuckDB already provides the
[`USING KEY` recursive CTE](https://duckdb.org/docs/1.5/sql/query_syntax/with)
used by the current walk.

[GraphAr](https://graphar.apache.org/docs/specification/format/) uses internal
vertex IDs within each vertex type and separates edge adjacency from edge
properties in files such as Parquet. Use our own stable IDs across Graph
versions and Arrow batches at the query boundary. GraphAr files do not provide
this store's per-result atomic commit and historical membership.

[Kùzu](https://github.com/kuzudb/kuzu/issues/1474) stores adjacency in a
dedicated graph engine. Adding that engine would require a second durable
transaction owner. Keep one DuckDB transaction for Graph values and version
membership. Convert stable IDs to result-local ordinals only when reading the
public Graph contract. Traverse the stable IDs after selecting the requested
version, so a traversal does not rebuild every historical ordinal map.

[TerminusDB](https://terminusdb.com/docs/graphs-explanation/) records Graph
changes as additions and deletions in immutable layers. Its version model
confirms that a result should reference changed Graph facts, not rewrite every
fact. A chain of result deltas would make an old or recent result read earlier
layers. Our interval membership lets Data select one result revision directly.

**Status at the start of the native row rewrite: Not done.** The user approved
the direction and implementation.

Native evidence identities, historical input membership, shared subject
values, historical subject membership, and shared finding values are
implemented. Finding rows use native subject and evidence IDs. The Graph
header and complex finding fields use typed MessagePack. Shared relationship
values and historical membership are implemented. Branches and package
contributions remain open. The changed store has not met the 90% target.

Builtin Graph finding IDs now hash typed binary identity fields. Provider and
Kubernetes subject keys use typed binary identity fields. The Analysis owner
checks the same fields. This removes JSON text from these identities. It does
not make package output or Graph membership incremental.

Graph checkpoint state now uses the existing native Arrow state row. The
builtin, custom detector example, and Analysis owner use one typed state
contract. Generic managed attempt envelopes still use JSON storage. The
Graph contribution work remains open.

## Intended end state

For the same four Graph result cuts, reduce logical Graph columns and headers
from 10,990,951 bytes to at most 1,099,095 bytes. Preserve each result ID and
its exact historical Graph, finding, proof, source cut, and package attribution.
The latest integrated run has a fifth result. Compare equal cuts and report
the extra version separately. Report DuckDB file bytes and used blocks, saved
Arrow bytes, and OCI artifacts as separate measurements.

The Graph numerator includes every stable identity row, native row value,
result membership, package contribution membership, per-call binding, and
Graph-only state record. Count each unique row reachable from the four
selected results, even if another result first created it. Do not count only
the rows inserted while those four results ran.

Query remains the native SQL parser, logical planner, optimizer, physical
planner, and execution path. A query subscription invokes the builtin Graph
packages. Data keeps the only durable Graph state and atomic commit. Do not
add a polling loop, a Graph engine, or a second state store.

## Measured gap

| Stored payload in the latest five-result run | Bytes |
| --- | ---: |
| Graph header input positions | 1,244,674 |
| Graph header input manifest | 1,095,180 |
| Graph header branches | 174,316 |
| Native edge rows | 1,112,372 |
| Native finding rows | 831,266 |
| All Graph columns and headers | 4,482,156 |
| Saved managed Arrow payloads | 10,657,552 |
| Exact repeated managed Arrow payloads | 4,986,688 |

For the four matching Graph cuts, the current Graph uses 3,688,062 bytes.
Input positions and manifests consume 1,804,033 bytes of that total. The
older edge and finding copies account for at most another 843,028 bytes that
can be shared. The native membership rows and shared branch and finding
values must also fit the 1,099,095-byte limit. These are logical payload
figures. They do not predict DuckDB file allocation.

The installed OCI package artifacts total 14,852,608 logical bytes in the
latest run. A 90% reduction of the entire database file is a separate goal.
Graph-only changes cannot prove that result.

On 2026-10-29, the unchanged 1,592-event backlog test reached only the
cursor-940 and cursor-639 Graph results before its deadline. The two results
used an estimated 1,568,619 logical Graph bytes, including headers and native
call rows. Saved managed Arrow payloads used 8,637,250 bytes; output payloads
used 5,924,480 of those bytes. The backup database file used 77,344,768 bytes,
with 219 used blocks and 76 free blocks. Installed OCI artifacts used
15,241,216 bytes. Peak resident memory was 1,018,028 KiB. The test failed;
its 183.09-second wall time includes the diagnostic backup. This two-result
run does not measure the four-result target.

Native per-call subject, edge, finding, and progress membership is **Done**
as a storage and recovery slice. Data restores the exact prior call state for
replay and reopen. The 47 focused Data Graph row tests passed. The Analysis
retained-call test passed after direct store reopen, and the six Graph call
corruption cases passed. Public GraphSnapshot assembly, saved raw managed
output, and generic JSON result envelopes remain. The four-result size target
and backlog deadline are **Not done**.

The later four-cut diagnostic used 1,653,551 logical Graph bytes. The old
four-cut value was 10,990,951 bytes. This is about 85% less, and it remains
554,456 bytes above the 90% target. The same diagnostic saved 12,061,622
managed Arrow bytes, used a 97,792,000-byte DuckDB backup with 257 used
blocks and 116 free blocks, and retained 15,241,216 OCI artifact bytes.
These measures have different owners and must not be added to the Graph
numerator. The backlog test still reached its 90-second observation deadline.
Both expected Graph cuts and the target finding were committed, but the
target notification had not reached the subscription.

The first 256-hash-page trial reduced the 1,880-edge write stage from 5.86
seconds to 0.49 seconds. It was replaced because DuckDB scanned all stored
edge values once per page. The current lookup appends deduplicated hashes to
one temporary relation, joins candidates once, compares complete typed
values, and removes the temporary relation. On the saved four-cut database,
the candidate lookup took 39 ms for 1,880 hashes, including table creation
and append. DuckDB planned one sequential scan and one hash join; the lookup
is not indexed or fully incremental. Appending rows for the three Graph calls
reduced their combined write stage from 9.89 seconds to 0.19 seconds. These
are measured stages from separate runs, not an end-to-end speedup claim.
Measure the one-scan cost on a larger history before treating lookup scaling
as complete.

The one-scan source passed 48 focused Data Graph row tests and the Analysis
call-state rollback and restart tests. The backlog case still failed: it took
135.86 seconds, with 1,089,852 KiB peak resident memory. Both Graph cuts and
the target finding existed, but the target notification was absent at the
deadline. This run does not prove an end-to-end speedup.

The four-cut store has 4,776 call-progress rows and 1,592 distinct digests.
Its edge values use 461,202 logical bytes, call progress uses 307,471 bytes,
finding values use 214,702 bytes, and call-edge membership uses 132,920
bytes. Exact duplicate managed Arrow payloads account for 2,871,272 input
bytes, 1,521,552 output bytes, and 163,344 selected bytes. Preserve each
call's exact progress and replay output while removing these repeated values.
All 3,323 edge values share one proof value, package ID, and cause; coverage
has two distinct values. Two Graph headers each repeat the same 60,872-byte
list of 138 branches. Finding policy and effect values are unique across the
139 findings, so sharing those complete fields would not reduce this case.

Native source references are **Done** as a storage encoding. Data stores each
Graph source key and tenant once and uses a numeric source reference in each
evidence row. Historical reads, selected findings, retained calls, and reopen
checks reject missing or foreign sources. The 48 focused Data Graph row tests
and the Analysis restart test passed. On the prior four-cut row counts, this
layout would save 103,286 logical bytes: 1,592 copies of a 73-byte key become
8-byte references, with two 97-byte source rows. The projected Graph total is
1,550,265 bytes, still 451,170 bytes above the target. This is a calculation,
not a new four-cut database measurement. The backlog result remains open.

Shared native edge properties are **Done** as a storage encoding. Each edge
keeps its stable endpoints, evidence, time, and full-value hash. An immutable
property row owns its type, package, cause, proof, and coverage. A private
DuckDB view restores the typed edge columns; the public Graph view is
unchanged. Data checks exact property values before reuse. The 48 focused Data
Graph row tests, the two-batch property reuse test, and the Analysis restart
test passed. The prior four-cut store held 195,362 bytes of repeated edge
properties. Replacing them with 3,323 eight-byte references and at most 12
property rows projects a saving of at least 167,554 logical bytes. Together
with source references, the projected Graph total is at most 1,382,711 bytes.
The 90% target, actual four-cut size, and backlog deadline remain open.

The unchanged backlog test on the edge-property commit failed after 134.59
seconds and used 1,099,644 KiB of peak resident memory. The two expected
Graph cuts and the target finding were committed. The target notification did
not arrive before the test deadline. This run did not save a four-cut database,
so it does not measure the new Graph size.

Shared native call progress values are **Done** as a storage encoding. Data
stores each exact evidence ID, digest, and optional state once. Each package
call stores a versioned reference. Reopen checks reject a missing value,
foreign tenant, duplicate value, or two active values for the same record.
The earlier four-cut store had 4,776 progress membership rows and 1,731
distinct values. At those row counts, the new layout projects 237,727 logical
bytes instead of 307,471, a saving of 69,744 bytes. Combined with the source
and edge-property changes, the projected Graph total is at most 1,312,967
bytes. That estimate exceeds the target by 213,872 bytes. It uses prior row
counts, not a measurement of the new database. The 49 focused Data Graph
row tests, three Analysis call rollback and corruption tests, and Analysis
restart test passed. Format and diff checks passed. The 90% target, package
output duplication, and backlog deadline remain **Not done**.

The next unchanged 1,592-event backlog run failed its 90-second observation
deadline. A Data backup taken after that failure contained exactly four Graph
cuts. Their logical Graph columns and headers used **1,312,327 bytes**. This is
88.1% less than the original 10,990,951-byte four-cut baseline, but 213,232
bytes above the 1,099,095-byte target. The probe summed each native column's
payload and charged each nullable interval endpoint as eight bytes. It
reproduced the earlier 1,653,551-byte diagnostic exactly before measuring
this backup. The four result IDs and revisions were:

| Result ID | Revision | Header bytes |
| --- | ---: | ---: |
| `graph:e0825b4c-abba-470e-a45f-2ec5ca7030f6` | 44 | 2,420 |
| `graph:64a6a988-23a8-4798-9ac9-6e6e2f0356f7` | 50 | 63,297 |
| `graph:5f97e30b-e2c2-4473-9788-587cbb895527` | 80 | 63,863 |
| `graph:8c24d54a-fe68-4558-a583-430640d164e1` | 89 | 6,663 |

Edge values used 292,424 logical bytes and shared edge properties used 584.
Finding values used 214,702. Call progress values and memberships used
237,727. Call-edge membership used 132,920. Graph headers used 136,243. The
database file used 97,267,712 bytes, with 259 used blocks and 114 free blocks.
Saved managed Arrow payloads used 12,007,688 bytes: 4,208,928 input,
6,908,032 output, 577,840 selected,
303,576 reason, and 9,312 checkpoint. Three OCI artifacts used 15,241,216
bytes. These totals have different owners and must not be added to the Graph
numerator.

The test took 193.47 seconds including a 72.905-second backup and a
0.069-second copy of the completed database. Time excluding backup and copy
was about 120.5 seconds, including setup, observation, diagnostics, and
teardown. Peak resident memory was 1,066,580 KiB for the whole run, including
backup. The observed Graph contained the target finding, but Follow had not
delivered its notification at the deadline. The database measures the four
committed cuts at backup time, after that deadline. The benchmark result
remains **Not done**.

Finding policy, effect, and reason payloads now use typed MessagePack sequences
instead of repeated struct field names. The strict decoder, typed value hash,
native finding columns, and historical membership are unchanged. All six
focused `araphor-graph` tests passed, including nested payloads, declared
Arrow reasons, reopen, hash reuse, and damaged values. The 49 focused Data
Graph row tests passed. This change has no matched four-cut size or backlog
time result yet. The 90% target and deadline remain **Not done**.

Shared branch values are **Done** as a storage encoding. Data stores each
distinct branch once for a tenant. Ordered validity membership selects exact
branches for each Graph result, including repeated values. Graph headers keep
the branch count. Reopen checks every stored branch value, reference, tenant,
and membership interval. The 52 focused Data Graph row tests and the Graph
extraction test passed. The Analysis Graph restart test passed. The matched
four-cut size, backlog time, and incremental package computation remain
**Not done**.

Current finding head batching is **Done** for notification routing. One Data
snapshot selects the heads for a batch of finding IDs. A stale reference with
a different current result fails before its per-row route. Current, absent,
and invalid references still use the existing route check. The focused Data
finding test and 14 Analysis notification tests passed. In matched quiet
backlog runs, the case failed after 139.54 seconds before this change and
140.31 seconds after it. These results do not show a backlog speed gain. The
three-record Graph update still spent 1.31 seconds in native Graph insertion,
about 0.13 seconds in Analysis Graph application, and about 0.3 seconds per
package call in input collection. Incremental Graph computation and the
backlog deadline remain **Not done**.

The next unchanged backlog run measured the native Graph write by stage. On a
cut that added three records and six edges, Data revisited 642 evidence rows,
1,422 edges, 138 unchanged findings, and 138 unchanged branches. Input
membership took 189 ms, subjects 12 ms, edges 171 ms, findings 732 ms, and
branches 294 ms. The write took about 1.40 seconds. The test still failed its
observation deadline after 141.34 seconds. These timings show that the current
writer repeats finding and branch work when their values do not change. The
temporary timers were removed after this run.

Exact managed Graph publication binding is **Done**. A selected Graph step now
records the Graph result that it published or reused in its receipt, in the
same Data transaction as the managed rows. Selected reads check the receipt,
step dependency, Graph header, source, and revision against that exact result.
The focused Data publication corruption test and Analysis no-op reuse and
profile version tests passed on 2026-10-29. This binds the next incremental
write to a proven base. Incremental computation and the 100-fold speed target
remain **Not done**.

Unchanged finding and branch retention is **Done** for managed Graph Evaluate
calls that keep the same supported package pins and publish no finding changes.
Data checks the prior selected receipt and Graph result before it writes. It
keeps the existing finding and branch membership intervals open while new
inputs, subjects, and edges use the current writer. A direct Data test checked
the value IDs, open intervals, both Graph versions, and file reopen. A real
managed Graph update published a new result with three inputs and nine edges;
the temporary writer trace confirmed that the three old findings and branches
skipped their writers. The trace was removed. The matching Analysis test passed
again on final source in 115.09 seconds. These runs did not measure a stage or
end-to-end speed gain.
Changed findings, changed calls, rebuilds, and other Graph commits still use
the complete writer. The 100-fold target remains **Not done**.

The integrated run used a 76,034,048-byte DuckDB file and 10,657,552 bytes
of saved managed Arrow payloads. The earlier compact run used 59,518,976
and 6,302,800 bytes, respectively. The integrated case failed after 124.42
seconds. It has one more Graph result and other source differences, so these
figures do not isolate the cause of the growth or prove throughput.

## Execution flow

A subscription selects a changed authorized input cut
  -> Query captures the source and exact prior managed result
  -> the builtin computes new and affected Graph contributions
  -> Analysis checks each contribution against current captured input and proof
  -> Data commits changed contributions, Graph version, state, and references in one transaction
  -> Query and notification subscriptions receive the committed revision

A Graph version is committed
  -> Data identifies its source window and previous result
  -> Data reuses stable subject and evidence IDs across source windows
  -> Data stores new nodes, relationships, findings, and branches as native rows
  -> Data changes membership for rows added or removed at this revision
  -> Data records separate membership for the Graph and each package call
  -> unchanged values keep one physical row across the result revisions

A caller selects a historical Graph result ID
  -> Data selects only the native rows valid for that exact result
  -> Data maps stable IDs to the public result-local subject and evidence ordinals
  -> Data reconstructs the existing GraphSnapshot and original order
  -> Data checks the manifest, evidence, row counts, and result scope

A process restarts or a managed call retries
  -> Data restores the exact committed package contribution and checkpoint
  -> Query binds that state to the same captured call without a self OutputRef
  -> the builtin emits changes relative to that state
  -> Data rejects a foreign call, stale reuse, or expired witness

An input leaves a window or old proof changes
  -> the builtin can rebuild its contribution
  -> Data records the resulting row changes through the same transaction
  -> valid changed proof produces a new Graph value
  -> older Graph result IDs still select their old rows and proof

Validation or commit fails
  -> Data rolls back row membership, result, checkpoint, and progress together
  -> a retry reads only the last committed state

## Owners and implementation order

`araphor-graph` owns native finding values, validity membership, and the
historical `graph_findings` view. Data passes its borrowed transaction, lineage,
revision, and validated findings to that crate. The crate does not open a store
or commit. Data checks the tenant, input manifest, row count, and references.
Query reads the selected Graph rows through its existing DataFusion table
provider. It does not need a new parser, planner, or provider.

Finding values move before relationships because `finding_id` gives each
result a stable sort key. A view can derive the public ordinal after selecting
the result. Relationship sharing must first map result-local subject and
evidence ordinals to stable identities. Both row families use validity
membership. They do not use a chain of Graph layers or a rollup task.
This finding slice shares complete `FindingV1` values. Subject and evidence
references use native IDs. Provenance and effect values use typed MessagePack.
They are not yet separate shared rows.

1. **Store input membership as native rows.** Remove full evidence and
   position lists from each Graph header. The Graph scope already owns the
   exact source identity in `source_receipts`. Store each record's CPU and
   durable cursor once across windows. Store its membership and each captured
   position with validity by result revision. Preserve position order and
   repeated occurrences. Reconstruct the exact manifest and positions on
   historical read. Preserve gaps, source epoch, coverage, context, and proof.
   Charge the native rows and expanded read values. Do not add a compact
   metadata codec, a legacy decoder, or a version bump during development.
2. **Store Graph nodes and relationships once.** `araphor-data` owns stable subject
   and evidence identities across source windows. An evidence identity names
   the exact source, CPU, and cursor. A subject identity names the exact
   tenant, authority, kind, and identity key. The existing `source_receipts`
   row owns the full source identity. Qualified proof and coverage remain in immutable row
   values; an ID does not assert current proof. Physical edge and finding rows
   refer to stable identities, not result-local sorted ordinals. A source
   window is the scope of temporal membership, not value identity. Separate,
   ordered memberships select each historical merged Graph and each package
   contribution. Read maps stable IDs back to the public result-local ordinals
   and charges expanded selected values. A changed proof creates a new row
   value; an unchanged row is shared. Preserve direct
   SQL traversal, finding lookup, projections, backup, reopen, corruption
   checks, and atomic rollback. Keep the existing public result IDs and
   GraphSnapshot values. Use DuckDB native columns and transactions. Do not
   add a parallel Graph database.
3. **Emit and retain only changed package contributions.** The three builtin
   Graph calls return changed rows and progress through the existing
   physical package call. Analysis validates the changed rows and retained
   contribution against the current captured cut. Data stores each package's
   ordered contribution membership in the same native Graph row owner and
   binds its exact prior contribution on retry or restart. The Graph result is
   the checked merge of those contributions. A merged Graph alone cannot
   recover package-local subjects, facts, or an expiry-reduced contribution.
   Keep the package contribution as a membership over shared row values, not a
   second row copy. The Graph-only normalized prior state differs from the raw
   update used for exact replay. Bind every update to its base call, result,
   revision, and image. Reuse of an unchanged call must not apply its old
   update twice. Keep ordered operation references for exact replay. Do not
   persist a second complete Graph package output for these calls. Ordinary
   packages keep their current exact raw-output state contract. Current saved
   inputs can provide the exact record and fact basis when reconstructing a
   transient prior native dataset. Remove the old Graph-only full-output path
   after parity proof.

The current Graph merge uses result-local subject and evidence ordinals. Those
ordinals can change when a new record or subject sorts before an old one. Row
sharing must use stable identities and remap to public ordinals on read. A
row's package owner, proof, evidence, and valid result set must remain exact.
The current Graph contract uses one exact evidence source per Graph scope.
Do not add multi-source Graph storage to solve this task.
Do not treat a content hash or an old saved output as fresh authority.

After the three changes, measure exact duplicate saved Arrow payloads again.
Use a shared payload table only if duplication remains material and the native
Graph owner cannot remove it. Do not add a general content pool preemptively.
Measure native branch reuse and repeated result or package keys before the
final row layout. Keep branch and finding properties in the same shared Graph
owner. If they keep payload above the target, remove repeated values and keys
there. Do not add a second snapshot encoding.

## Proof and stop point

Use focused Data Graph storage, history, query, notification, replay, recovery,
and managed package tests. Preserve all existing assertions. Add only tests
that exercise exact historical reconstruction, changed proof, inserted earlier
subject and evidence IDs, window removal, crash and rollback, and resumed
package contribution. Run the existing backlog workload with unchanged
events, assertions, and deadline after the focused checks pass.

Measure Graph logical bytes on the four matching result cuts. The change is
not done until they use at most 1,099,095 bytes and the same current and
historical Graph values. Record any extra result cut separately. Measure
DuckDB file size, used and free blocks, Arrow payloads, OCI artifacts, elapsed
time, and process peak memory without treating one as a proxy for another.
The current backlog deadline failure remains open until the test passes.
Run only relevant checks during implementation. Commit each independently
reviewed deliverable. The independent Sol 6.1 reviewer checks the owner,
data flow, deletion, source diff, and proof before each commit.

**Result: Not done.** Native evidence and input-position rows replace repeated
header lists. Subject and finding values now have stable IDs and historical
membership. Shared relationships have native values and historical
membership. Branches, package contribution membership, and the measured
target remain open.

Immutable finding-value sharing is **Done** as a storage encoding. Focused
Graph, Data, Query, and Analysis tests pass on this source. The
[review guide](../guides/araphor-graph-commit-review.md) lists the commands and
results. The package backup/reopen case took 434.21 seconds.

Native finding references and typed Graph header metadata are **Done** as
storage encodings. A selected finding read resolves only the subject and
evidence IDs in that finding. The finding writer splits new rows into bounded
Arrow batches. Focused native Graph, Data header, history, selection, schema,
and rollback tests pass. The matched workload and full workspace procedure
have not run on this change.

Indexed immutable finding-value lookup is **Done** as a storage step. The
finding owner hashes a typed, canonically ordered value with its native
subject and evidence IDs. The schema creates a single-column hash index for candidate
lookup. The owner still compares the full typed value before reuse. Focused
native history, metadata-order, collision, and rollback tests pass. The Graph
result writer still reads complete active finding membership, so incremental
Graph storage and the measured reduction remain **Not done**.

Incremental Graph production and storage are **Not done**. Shared edge values
and interval membership remove complete per-result relationship rows. The
writer still visits each current edge and active edge membership. The public
view maps stable subject and evidence IDs to result ordinals at read time.
The builtin
detectors restore and emit complete package outputs in the committed product
path. Managed calls save those complete Arrow outputs. Graph assembly creates
a complete snapshot. The finding writer still visits all current findings and
active membership to infer changes. It filters prior value candidates by a
typed hash. The complete membership work grows with retained state.
The matched 1,592-event storage and time target is still open.

The required path takes changes from the query subscription, selects affected
prior package rows by stable keys, and makes each detector emit only added,
changed, and removed contributions. Data applies those operations to indexed
membership and saves the package state in the same transaction. An unchanged
call writes no Graph values. A retry checks its base call and ordered
operations without reading a complete old Graph. Restart reads the committed
package contribution directly. Exact replay reproduces the original ordered
update. Query reads current and historical Graph
rows through the existing DataFusion table provider. Remove the complete
managed Graph output, snapshot comparison, and finding-history scan only after
these paths pass the focused tests and the unchanged workload.

## Event-anchored credential findings

**Done:** A new network or authority-use event creates a finding anchored to
that event when the selected proof qualifies. An earlier event's finding stays
unchanged when its selected facts, coverage, and global disclosure floor stay
unchanged. The builtin uses the captured Data store position to order events
across CPUs. It retains prior findings and edges for unchanged input records.
It selects the credential reads and proof facts that can support the new event.

An existing anchor can require recomputation when its selected facts, coverage,
or disclosure floor change, when supporting evidence leaves a window, or when a
newly selected record has an earlier store position. An appended
`HostRestricted` fact can raise the global disclosure floor and emit replacement
values for earlier findings. An ordinary network append with no such change
does not revise an older finding. The rebuild path preserves exact historical
results.

The builtin Graph tests, baseline snapshots, native capture, subscription
replay, and restart checks are the focused proof for this slice. Full input
capture, reconstruction of complete current contributions, and the writer's
complete active finding scan remain. The 100-fold speed target and the matched
backlog deadline are **Not done**.

## Native row replacement result

**Graph storage result: Done.** The old Graph publication, storage, and read
files are removed from production. Data now stores stable native subject,
edge, finding, evidence, and progress values once. Versioned membership
records which values each package call and Graph result selects. Data commits
the selected values, managed state, progress, and references in one
transaction. Query reads selected Graph families through its DataFusion table
provider. The public Graph snapshot is built only when a caller selects it.
The stored Graph rows do not use JSON.

The fixed 1,592-event incident workload used for this measurement series
passed its unchanged 90-second observation deadline and assertions on the
native row path. Its complete test took 119.79 seconds,
including setup and shutdown. The same four Graph cuts, at revisions 40, 49,
114, and 116, used 1,069,907 logical Graph column bytes and 11,796 header
bytes. The total was 1,081,703 bytes, 90.16% below the old 10,990,951-byte
path and below the 1,099,095-byte target. The complete DuckDB file was
101,199,872 bytes. That file also contains non-Graph data, saved Arrow values,
and package artifacts; its size is separate from the logical Graph byte count.

The 66 Data Graph row tests, seven Data finding-read tests, 15 reactive
notification tests, six native finding-row tests, detector example test, and
context-head integrity tests passed. The notification tests keep the live
finding and route checks, exact retry state, and both cancellation points.
The required `CARGO_INCREMENTAL=0 bash .github/scripts/verify-rust-ci.sh`
passed formatting, workspace check, and all-target Clippy on this source.
`cargo test --workspace --all-targets --all-features` stopped during linking
with `error: linking with cc failed: exit status: 1` after the host filesystem
reached zero free space. The full workspace test result is **Blocked**.

**100-fold speed result: Not done.** The passing whole-test time does not
measure a 100-fold reduction in Graph computation. An earlier probe-free run
missed the same deadline. Native finding-key and context-head reads removed
repeated payload and per-route lookups without changing the save, deliver, then next
notification order. Measure the Graph computation and notification transaction
cost separately before claiming a speed factor.

## Shared package proof result

**Package proof reuse: Done. 100-fold speed target: Not done.** Data keeps one
in-memory proof for each tenant and installed package revision. The proof
contains the current hashes of the stored descriptor, OCI artifact, and
dependency list. It records the exact identity and builtin Graph support of
each Wasm export. A managed capture or new Graph producer reads the current
hashes before it uses the proof. A changed or missing revision fails. A cold
lookup decodes the OCI artifact and checks that the selected Wasm export has
one executable implementation. Context validation uses the same proof.
Store reopen starts with an empty proof cache.

In the unchanged 1,592-event incident case, the warm baseline made 18 extra
OCI decodes in Graph classification. Those qualification checks took 6.69
seconds, including 6.33 seconds to decode OCI artifacts.
The instrumented cache run made zero extra OCI decodes in that classifier.
Context admission still decodes and validates package bundles. One warm whole
test took 104.25 seconds before this change and 103.06 seconds after it. Four
Graph stages took 3.78 and 3.79 seconds in those runs. These measurements do
not prove a Graph-stage or end-to-end speed gain. The 100-fold speed target
remains **Not done**.
