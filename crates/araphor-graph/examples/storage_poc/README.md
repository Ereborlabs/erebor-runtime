# Causal package Graph scenario comparison

This proof of concept (PoC) runs the existing causal package against current
DuckDB GraphStore, redb, Fjall, and a local append-only store. It measures the package's dependent Graph
traversal and staged changes through one durable commit. The production store
and the incident test stay unchanged.

## Intended end state

Compare the actual Graph work in
`discovery::packages::required::incident::incremental::follows_incremental_sources`.
Use the same package code, source fixtures, read semantics, and durability for
all engines. The complete production target remains receipt to notification
creation below 100 milliseconds and a 100-fold gain. This PoC does not measure
that complete path.

## Implementation review flow

[Incident::index_input](incident.rs) supplies resolved Arrow inputs for one incident increment.
  -> [Engine::capture](main.rs) captures one Graph view for that input cut.
  -> [package::evaluate](package.rs) checks the real Causal descriptor and binds the example host.
  -> [Causal::compute](../../../araphor-analysis-builtins/src/causal/mod.rs) calls the existing index export.
  -> [Edits::frontier](../../../araphor-analysis-builtins/src/causal/state.rs) repeatedly requests neighbors in both directions.
  -> [Host::read](package.rs) reads the selected keys and applies the native Journal overlay.
  -> [Index::compute](../../../araphor-analysis-builtins/src/causal/index.rs) clears affected owners and stages node and edge changes.
  -> [Incident::detect_input](incident.rs) supplies records and audits selected by the returned frontier.
  -> [Detect::compute](../../../araphor-analysis-builtins/src/causal/detect.rs) checks the causal chain and stages actual FindingMember values.
  -> [Step::new](fixture.rs) exposes the actual package journals to the measured store path.
  -> [Duck::apply](duck.rs) prepares and applies the production GraphStore layers.
  -> [Native::apply](native.rs) applies the same native Graph record algorithm on redb, Fjall, or the local store.
  -> [Database::write](kv.rs) durably commits Graph, head, state, progress marker, and change references together.

[main](main.rs) completes the measured package cycle.
  -> [Oracle::check](main.rs) compares exact member identities, endpoints, versions, and Arrow values.
  -> [Reference](main.rs) compares exact traversal key sequences, returned counts, frontiers, and finding values across engines.
  -> [verify_metadata](native.rs) checks exact writer heads and parent/captured commit records outside timing.
  -> [Engine::inspect](main.rs) checks all earlier views after the later commits.
  -> [Engine::apply](main.rs) stages revision 88 and rolls the transaction back.
  -> [Engine::open](main.rs) reopens the database and restores the property cache.
  -> [Oracle::check](main.rs) checks retained history and rollback state again.
  -> [TempDir](main.rs) removes that round's database files after close and size measurement.

The example owns its test database and transaction. Production Data ownership
does not change. Generic Graph receives opaque relations and identities. The
package owns the traversal and detector rules. The PoC calls the same
`Causal::compute` implementation as the builtin component. It uses SDK input
and output validation and the actual `Journal` preparation and overlay.

## Incident and Graph operations

The fixture follows the incident test's credential-pivot scenario. Four
streams on two nodes provide six linked actions for each episode:

1. An actor attempts credential access and is denied.
2. The actor obtains credentials from an IMDS response.
3. The actor uses those credentials to request a different Kubernetes token.
4. That token authorizes a privileged pod with a writable host-root mount.
5. A scheduling record places the pod on the other node.
6. A runtime record confirms the corresponding container admission there.

The denial is supplemental evidence. The successful credential, token, pod,
scheduling, and admission chain supplies the finding. The fixture uses the
existing public audit, proof, observation, context, and finding types.

The first increment supplies five actions and must produce no finding.
The next increment supplies the missing admission and must produce one
confirmed finding. Coverage-only increments revisit the retained Graph and
update the finding. Two later episodes must produce two and three findings.
Each finding must contain six evidence records from four streams and two
nodes. The raw background events are outside this Graph-storage measurement.
Their coverage advances appear as the corresponding resolved inputs.

The package connects source, record, actor, credential, request, pod, and
binding nodes. Links retain their actual audit record, context version,
revision, and restriction properties. A traversal follows outgoing and
incoming adjacency. Each returned edge supplies endpoint keys for the next
frontier. The package's source-label rule prevents traversal back through a
source origin. The benchmark does not copy this algorithm.

| Publication | Captured input | Frontier records | Neighbor rounds | Keys in each round | Returned rows in each round |
| --- | --- | ---: | ---: | --- | --- |
| 26 | 24 | 5 | 0 | Initial reset | Initial reset |
| 29 | 27 | 6 | 3 | 9, 6, 3 | 9, 18, 7 |
| 44 | 36 | 6 | 4 | 4, 6, 5, 3 | 6, 16, 21, 7 |
| 46 | 44 | 6 | 4 | 4, 6, 5, 3 | 6, 16, 21, 7 |
| 62 | 48 | 6 | 4 | 4, 6, 5, 3 | 6, 16, 21, 7 |
| 64 | 62 | 12 | 4 | 18, 6, 5, 3 | 6, 16, 21, 7 |
| 85 | 71 | 12 | 4 | 4, 12, 10, 6 | 12, 32, 42, 14 |
| 87 | 85 | 18 | 4 | 18, 12, 10, 6 | 12, 32, 42, 14 |

These are observed package requests. They are not configured limits. One
edge can occur in multiple rounds. The complete eight-step run inserts 194
versions, closes eight versions, and retains 186 live contributions. Both
writer heads advance at every commit, including empty writer journals.
The first index and detect calls use the production reset path.

## Storage and timing

DuckDB uses the production GraphStore, GraphReadView, presence checks, layer
preparation, dictionaries, properties, member storage, endpoint validation,
and native cache publication. The example supplies small metadata tables for
state, progress, commits, and change references. DuckDB uses two threads and
the production unlimited memory setting.

redb, Fjall, and the local store share one native record algorithm through [Database](kv.rs).
Binary dictionaries map identities to stable numeric references. Historical
member intervals and relation, entity, owner, outgoing, incoming, and label
indexes select members. The read view holds one physical snapshot while the
package runs. Native reads use the selected indexes and construct Arrow
batches before the package consumes them. Presence checks use the actual
captured writer, owner, entity, and revision.

The replay implements this package's clear-before-Add journals. A scope or
owner clear closes only that writer's actual contributions. The replay is
not a general production Journal executor. Arbitrary edit sequences,
branching, retention, and fragmentation are outside this fixture.

Native writes encode the actual property batches as Arrow IPC inside the
measured write work. Live reads share retained Arrow values. Reopen decodes
the durable chunks and restores the cache. Current GraphStore also retains
native Arrow values. Application revision keys retain logical history;
internal engine snapshot history is not the retained Graph history.

`scenario_s` is one uninterrupted interval:

```text
Capture the Graph view
  -> Run actual index traversal, owner clears, presence checks, and staging
  -> Resolve detect inputs from the actual returned frontier
  -> Run actual detection and finding staging
  -> Normalize the package journals
  -> Prepare and durably commit Graph and synthetic metadata
  -> Publish native property caches
```

Shared source Arrow for the index is prepared before timing. Frontier-driven
detect input construction stays inside timing and has its own `resolve_s`
field. The fixture supplies resolved inputs; native DataFusion source-query
execution is outside this PoC. The post-commit all-member verification read,
result comparisons, Oracle work, and metadata-only checks are outside the
primary scenario interval. Their read times are recorded separately.

Each sample records capture, index, resolver, detect, normalization, write,
and total scenario intervals. It also records each explicit Graph read and presence probe's
operation, relation, key count, returned rows, and elapsed time. Clear and
stage calls stay in the package interval but have no separate call record. Exact key
vectors remain in memory for comparison. Traversal time is nested inside
index time. Component medians are not additive.

redb uses `Durability::Immediate`. Fjall uses transaction
`PersistMode::SyncAll`. DuckDB uses durable on-disk `COMMIT`. The local store
uses one transaction frame and `sync_all` per commit. The existing engines
keep their default cache and compression settings. Eight rounds balance each
engine position and each ordered predecessor pair twice. Each engine has 64
measured package cycles and 64 commits. The summarizer computes paired ratios
from complete round totals. Eight samples per revision do not establish a
tail bound. The older three-engine results below use six rounds.

## Local append-only store

[Home::open](home.rs) opens `home.log` and acquires an exclusive file lock.
  -> [Home::open](home.rs) checks the version header and each complete transaction frame.
  -> [Home::open](home.rs) replays the final put and delete for each key into an ordered in-memory index.
  -> [Home::open](home.rs) truncates an incomplete final header or payload and syncs the truncation.
  -> [Home::open](home.rs) rejects a complete frame with an invalid checksum or payload.

[Home::read](home.rs) clones the immutable index root for one read scope.
  -> [Index](home.rs) serves exact keys, ordered prefixes, and revision-floor reads.

[Home::write](home.rs) copies the index into one private transaction.
  -> [Transaction](home.rs) applies staged changes and records the final put or delete for each changed key.
  -> [Home::write](home.rs) encodes that delta with the existing MessagePack codec.
  -> [Home::write](home.rs) appends one length-delimited frame with header and payload CRC32C checksums.
  -> [Home::write](home.rs) syncs the file before it publishes the new immutable index root.

[Home::write](home.rs) aborts before append.
  -> [Transaction](home.rs) drops the private index and changes without file writes.

[Home::write](home.rs) receives an append or sync error.
  -> [State::check](home.rs) refuses new read scopes and writes until reopen.

This backend is an ordered in-memory key/value index with a durable transaction
log. It has no embedded database dependency. Keys and values use shared byte
buffers. A write copies all index entries once. The copy, delta recording,
encoding, checksums, append, sync, and publication stay inside the measured
scenario. CRC32C checks file integrity; it does not detect source changes.
The generic Graph record layout still owns revision history and change records.
Physical log offsets do not replace application input positions.

The store keeps all current physical keys and values in memory. These keys
include retained Graph history. Write copy cost grows with the full index.
The log has no compaction, reclamation, or checkpoint. Reopen replays the full
log before the native Graph owner restores Arrow property chunks. This small
experiment does not qualify large Graphs or power-loss recovery. An incomplete
tail check is not a power-loss test. No DataFusion operator or production path
changes.

[transactions_and_snapshots](home.rs) checks read-your-writes, an older active
snapshot across a later commit, key deletion, empty values, ordered prefix and
floor reads, exclusive open, abort without append, and reopen.
[incomplete_tail_and_corruption](home.rs) checks every byte cut in the final
frame, a commit after recovery, and complete header or payload corruption.
[failed_append_requires_reopen](home.rs) uses a read-only file handle to check
the failed-append state. These checks are outside scenario timing.

## Commands

Run from the repository root. Use the same local on-disk parent directory for
all engines. The executable creates and removes temporary databases beside
the output file. A value or traversal mismatch fails the process. There is no
latency pass limit. After build, one eight-round run takes less than two minutes
on the recorded host.

```sh
rtk proxy env CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=6 POC_SOURCE_REVISION=65d655ec8 \
  cargo build --release -p araphor-graph --example storage_poc --features store
rtk proxy target/release/examples/storage_poc /tmp/araphor-causal-poc/release.json
rtk proxy python3 crates/araphor-graph/examples/storage_poc/summarize.py \
  /tmp/araphor-causal-poc/release.json
```

Build the bundled DuckDB dependency in release. A release Rust executable
linked to the old cached `-O0` DuckDB archive is a mixed-profile result.
The recorded optimized comparison excludes that mixed diagnostic.

## Qualification boundary

The debug run at source `65d655ec8` passes all 18 engine runs. It proves exact
cross-engine frontiers, traversal requests and counts, finding values,
Graph deltas, state and captured-revision markers, history, rollback, and
clean reopen for this scenario. Formatting passes. The debug build has one
existing unused-import warning in production causal `io.rs`.

A gain against current GraphStore includes the native Graph owner rewrite
and the physical engine. redb, Fjall, and the local store share the same Graph record
algorithm. The PoC does not run Control intake, raw ingestion, native
DataFusion input queries, full Data authority/evidence checks, finding
projection publication, or notification creation. It also does not qualify
large data, steady compaction, cache pressure, backup, retention, or power loss.

The earlier generic storage screen remains in
[its result directory](results/2026-11-05/environment.json) at source
`dcf84a041`. Those figures are not the package scenario's result.

## Recorded scenario result: 2026-11-05

Actual package scenario implementation and comparison: **Done**.
Production replacement and complete incident latency qualification: **Not done**.
The measured Rust source is `65d655ec8`. The
[environment record](results/causal-2026-11-05/environment.json) identifies
the host, commands, versions, and optimized archive. The
[compiler samples](results/causal-2026-11-05/cpp-release-provenance.json)
show `-O3` and `NDEBUG` for the bundled DuckDB dependency. No C++ compiler or
IDE Cargo check was active at the process check before this run. The host
remains shared.

All table values are milliseconds. Each value is the median of six complete
round totals. A round contains eight package cycles and 27 dependent neighbor
reads. Traversal time is part of the complete scenario. Write time includes
preparation, mutation, durable commit, and native publication. The separate
component medians are not additive.

| Measured interval | Current GraphStore | Native Graph on redb | Native Graph on Fjall |
| --- | ---: | ---: | ---: |
| Complete eight-cycle scenario | 448.29 | 35.92 | 35.39 |
| 27 neighbor reads | 2.32 | 2.87 | 3.88 |
| Eight view captures | 10.20 | 0.062 | 0.069 |
| Eight writes | 421.59 | 17.57 | 14.96 |
| Index package work, including traversal | 7.41 | 7.79 | 9.09 |
| Frontier-driven detect input construction | 1.32 | 1.29 | 1.37 |
| Detect package work and finding staging | 7.73 | 8.01 | 8.63 |

Median paired complete-scenario gains over current GraphStore are 12.54
times for redb and 12.73 times for Fjall. The complete-scenario ranges are
416.51 to 558.67 milliseconds for GraphStore, 32.21 to 45.06 for redb, and
30.02 to 38.99 for Fjall. Paired ratios use complete totals from the same
round. They differ from a ratio of separate medians.

The measured traversal is faster in the current GraphStore. Its native
member cache already serves this small Graph from memory. The native KV
replay fetches member metadata through its indexes and retains Arrow
properties in memory. The main observed gain comes from mutation and view
capture. This result does not support a claim that KV storage alone makes
Graph traversal faster.

Fjall has lower write totals in all six rounds. Its median paired write
advantage over redb is 1.20 times. The complete-scenario comparison is much
closer: a median paired ratio of 1.047, a range of 0.911 to 1.346, and four
of six rounds with a lower Fjall total. This run does not establish a
meaningful overall performance winner between redb and Fjall.

The final cycle at revision 87 takes a median of 67.36 milliseconds on
GraphStore, 6.75 on redb, and 6.54 on Fjall. That interval ends at the Graph
commit. It does not include notification creation.

[Raw optimized results](results/causal-2026-11-05/release.json) contain all
144 measured package cycles and the recorded read/probe counts. The
[summary](results/causal-2026-11-05/summary.json) reproduces with
`summarize.py`. The
[final debug run](results/causal-2026-11-05/debug.json) is separate evidence.
The executable checks exact traversal key vectors in memory. Raw JSON
retains their counts, returned row counts, and frontier indices. It does
not retain those complete key vectors or finding payloads.

All 18 optimized engine runs pass the runtime exact-key, frontier, finding
value, original evidence, delta, history, rollback, and reopen checks.
Each round has 194 additions, eight closures, 27 neighbor reads, and 15
presence probes. Independent review reproduces the summary and confirms
the retained counts and timing sums. Formatting and guide-link checks pass.

The focused command below stops on six existing Graph library lint errors
before it checks the example. The errors concern type complexity and map
iteration in `src/layers/prepared.rs`, type complexity in `src/layers.rs`,
and argument count and `unwrap` use in `src/read.rs`.

```sh
rtk proxy env CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=6 \
  cargo clippy -p araphor-graph --example storage_poc --features store \
  --config /tmp/araphor-native55-duckdb-override.toml -- -D warnings
```

Full workspace CI does not run, as the user requests. The production
incident test does not run again because the PoC changes no production
path. The complete 100-fold and sub-100-millisecond notification targets
remain unproven.
