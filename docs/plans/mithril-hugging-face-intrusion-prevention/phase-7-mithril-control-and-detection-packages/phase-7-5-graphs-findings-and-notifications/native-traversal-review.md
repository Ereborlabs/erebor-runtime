# Native Graph Traversal Review

This guide covers the native traversal source in the primary checkout. Read the
[storage and traversal plan](phase-7-5-1-native-graph-storage.md) for the approved
scope. The storage baseline is commit `91afc657`. Review result: **Done** for
the native storage and bounded traversal scope. The recorded source passes the
focused, full lightweight, paired physical, and final shared Rust checks.

## Intended end state

An authorized caller selects exact subjects across current source-window heads
or retained result versions. DuckDB computes bounded traversal. The caller can
query the selected native rows without loading the complete retained graph.
Each result retains version references, evidence, proof, and traversal limits.
Later algorithm packages can use this host read path. This change stops before
SDK or package execution work.

## Linked implementation flow

The following flow uses the events from the approved traversal plan. Source
links identify the implemented owners. Qualification records are below.
Header bytes use Concise Binary Object Representation (CBOR).

[ClientGrpcOwner::query_request](../../../../../crates/mithril-control/src/client_grpc/query.rs) An authorized client submits exact seeds and traversal limits.<br>
-> [QueryPlan::client_graph](../../../../../crates/araphor-data/src/query/plan.rs) QueryOwner validates the request under the existing investigate grant.<br>
-> [AnalysisStore::resolve_selection](../../../../../crates/araphor-data/src/analysis/extraction.rs) AnalysisStore pins current source-window heads or exact retained results.<br>
-> [AnalysisStore::traversal_versions](../../../../../crates/araphor-data/src/analysis/extraction/graph/traversal/versions.rs) AnalysisStore checks each complete version before traversal.<br>
-> [TraversalVersion](../../../../../crates/araphor-data/src/analysis/extraction/graph/traversal/versions.rs) AnalysisStore retains validated headers, revisions, and sensitivity within the input limit.<br>
-> [GraphWalk::query](../../../../../crates/araphor-data/src/analysis/graph/traversal/sql.rs) DuckDB traverses narrow full subject keys through fixed recursive SQL.<br>
-> [GraphRows::selected_subjects](../../../../../crates/araphor-data/src/analysis/graph_rows/subjects.rs) AnalysisStore reads only selected subject payloads.<br>
-> [AnalysisStore::traversal_header](../../../../../crates/araphor-data/src/analysis/extraction/graph/traversal/versions.rs) AnalysisStore decodes the saved CBOR header for each participating version.<br>
-> [GraphRows::selected_edges](../../../../../crates/araphor-data/src/analysis/graph_rows/relationships.rs) AnalysisStore reads only selected relationship payloads.<br>
-> [AnalysisReadControl::run](../../../../../crates/araphor-data/src/analysis/read.rs) AnalysisStore closes the durable snapshot before client SQL runs.<br>
-> [GraphTraversalReceiptV1](../../../../../crates/araphor-data/src/graph/traversal.rs) The result records version references, row counts, and the hop boundary.

[GraphWalk::summary](../../../../../crates/araphor-data/src/analysis/graph/traversal/read.rs) Traversal exceeds a work, row, byte, or time limit.<br>
-> [QueryErrorCode](../../../../../crates/araphor-data/src/query/frame.rs) The read fails with a structured error.<br>
-> [QueryOwner::evaluate](../../../../../crates/araphor-data/src/query/mod.rs) Client SQL receives no truncated aggregate input.<br>
-> [AnalysisReadControl::run](../../../../../crates/araphor-data/src/analysis/read.rs) The read owner closes handles and releases temporary state.<br>
-> [QueryOwner::query_client](../../../../../crates/araphor-data/src/query/mod.rs) A retry captures a new read revision.

## Owners and lifetime

| Owner | Input and state | Output and lifetime |
| --- | --- | --- |
| [GraphTraversalV1](../../../../../crates/araphor-data/src/graph/traversal.rs) | Exact seed keys, result IDs, direction, edge types, and bounds. | A checked request. Unknown JSON fields and duplicate keys fail validation. |
| [ClientGrpcOwner](../../../../../crates/mithril-control/src/client_grpc/query.rs) | Existing authenticated query request and investigate scope. | Existing query stream. No new listener or permission. |
| [QueryOwner](../../../../../crates/araphor-data/src/query/mod.rs) | A checked plan, current authorization, and shared capacity. | Detached SQL input and charged output. Current authorization is checked before disclosure. |
| [AnalysisStore](../../../../../crates/araphor-data/src/analysis/extraction/graph/traversal.rs) | One durable read revision, selected immutable result IDs, and charged CBOR headers. | Selected rows and a receipt. Header bytes remain temporary read state. Native statements and the durable read close before client SQL evaluation. |
| [GraphWalk](../../../../../crates/araphor-data/src/analysis/graph/traversal/read.rs) | Authorized result IDs and full seed keys. | Minimum hop depths and native edge ordinals. Temporary state ends with the read. |
| [InputProjection](../../../../../crates/araphor-data/src/query/graph.rs) | Selected native rows and minimum depths. | Existing VTab rows. Ordinary graph reads use null `traversal_depth`. |
| [WireFrame](../../../../../crates/mithril-control/src/client_grpc/wire.rs) | Charged QueryResult. | Protobuf Rows with the same receipt. Transport retains the result owner while it discloses the frame. |
| [CLI](../../../../../crates/araphor-cli/src/cli/araphor/args.rs) | SQL and one bounded graph JSON file. | Existing table or JSONL output. The CLI owns no graph algorithm. |

AnalysisStore retains the authoritative native graph rows. Traversal adds no
durable graph copy or traversal checkpoint. Store reopen and restore reuse the
existing native rows. The traversal path attaches no BPF program and starts no
collection backend.

[InputProjection::graph_rows](../../../../../crates/araphor-data/src/query/graph.rs)
encodes its six shared metadata columns once per version, on the first eligible
row. The temporary cache has an explicit heap charge. Each emitted row owns a
clone and keeps its existing allocation charge. An empty or denied projection
creates no cache. This rule applies to ordinary graph reads and traversal reads.

```mermaid
sequenceDiagram
    participant C as Client
    participant Q as QueryOwner
    participant S as AnalysisStore
    participant D as DuckDB
    C->>Q: SQL, exact seeds, and scope
    Q->>S: Capture one read revision
    S->>S: Check complete versions; retain charged headers
    S->>D: Fixed bounded traversal SQL
    D-->>S: Subject keys, depths, edge ordinals
    S->>S: Decode saved headers; read selected payloads
    S-->>Q: Selected rows and receipt; durable read closed
    Q->>D: Evaluate admitted SQL over detached VTab input
    D-->>Q: Bounded query result
    Q-->>C: Authorized Rows and receipt
```

### Version and authorization rules

An empty `result_ids` list selects the latest version of each selected source
window. A replacement version supplies that window's current rows. An omitted
relationship cannot return from the replaced version. A nonempty list selects
the exact retained versions. Unknown, foreign-tenant, or source-out-of-scope
result IDs return the same denial class. Binding-ineligible versions are
excluded and can produce an empty successful read.

The preflight checks the complete version before it selects rows. It preserves
tenant, source, Node, binding, and sensitivity rules.
[AnalysisStore::traversal_versions](../../../../../crates/araphor-data/src/analysis/extraction/graph/traversal/versions.rs)
reads headers in bounded batches through
[GraphRows::visit_headers](../../../../../crates/araphor-data/src/analysis/graph_rows/headers.rs).
The shared `traversal_scope` checks source scope and reads whole-version
sensitivity once. It loads complete findings when the request has binding
scope. The preflight transfers validated CBOR bytes, the commit revision, and
the sensitivity into `TraversalVersion` for each authorized version.

After the walk, `traversal_header` decodes the saved bytes for versions with
selected rows. The read uses the same captured revision and sensitivity. A
binding scope loads complete findings again and checks the exact finding count
before the existing graph and evidence projection rules run. This load remains
inside the same durable read revision.

In a binding scope, `permits_graph` requires an authorized effect proof for each
manifest record. In addition, every finding has nonempty effects, and every
effect has an authorized binding. The owner checks these rules before edge-type
filters or row reduction. A version that fails these rules is excluded as a
complete version. Native subject selection then checks membership proof in that
version, including zero-hop seeds. A proof edge can authorize a subject without
appearing in the selected edge types. An isolated copy in another version does
not inherit that version's binding proof.
Full-source grants skip this membership SQL filter after whole-version
authorization. Both seed selection and subject reads use the same filter owner.

The walk joins complete subject keys. Native keys retain the Node, boot ID,
label epoch, kind, and identity. Provider, Kubernetes, and external keys retain
their own authority. The keyed recursive query visits each key once and keeps
its minimum distance from any seed. DuckDB materializes one filtered narrow
edge relation for traversal, selected-edge keys, and the hop-boundary check.
This relation retains result IDs, ordinals, and complete endpoint keys within
the native read. Direction controls reachability. Returned relationships keep
their original direction and version.

Traversal SQL must read `graph_subjects` or `relationships`. It can join
`catalog`. Use the ordinary catalog command for catalog-only inspection.
Follow, bookmarks, and other relations return `Unsupported`. Client recursive
SQL remains outside the admitted SQL subset. The host controls the fixed
recursive query.

## Request and result example

First read an exact seed through the existing query route:

```sh
araphor sql --output jsonl --node node-a "SELECT graph_result_id, subject_id FROM graph_subjects WHERE subject_kind = 'TASK' ORDER BY graph_result_id, subject_id LIMIT 1" > seed.jsonl
```

Read the `query_replace` record in `seed.jsonl`. Its Rows payload contains the
selected row. The first value's `kind.Text` is the result ID. The second value's
`kind.Binary` is a UTF-8 JSON byte array. Decode the byte array and parse its JSON
object. Put that complete object in `seeds`. Put the result ID in `result_ids` to
use the same retained version. Keep every authority and lifetime field. The
following `graph.json` shows the format. Replace the example key and result ID
with these values:

This initial query uses the ordinary graph read path. Its SQL `LIMIT` bounds
output; it does not select one durable row. The ordinary path can reach its
input limit. A caller can also supply an exact key from retained evidence or
an existing snapshot. The traversal request then selects native rows.

```json
{
  "seeds": [
    {
      "tenant_id": [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
      "authority": {
        "authority": "NATIVE",
        "node_id": "node-a",
        "node_boot_id": [2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2],
        "label_epoch": 1
      },
      "kind": "TASK",
      "identity": [0, 0, 0, 0, 0, 0, 0, 9]
    }
  ],
  "result_ids": ["graph-result-from-first-query"],
  "direction": "OUTGOING",
  "edge_types": [],
  "max_hops": 2,
  "max_subjects": 100,
  "max_relationships": 200
}
```

Read the selected nodes and their minimum distances:

```sh
araphor sql --graph graph.json --node node-a "SELECT graph_result_id, subject_id, traversal_depth FROM graph_subjects ORDER BY graph_result_id, traversal_depth, subject_id"
```

Use `max_hops: 0` to read only exact seeds. Use `INCOMING` or `BOTH` to change
direction. An empty `edge_types` list accepts all edge types. For example,
`["NATIVE_PARENT"]` limits reachability and returned relationships to native
parent edges. An empty `result_ids` list selects current heads in the authorized
scope. A seed absent from these versions returns an empty selection.

Use the same file to inspect proof through exact version joins:

```sh
araphor sql --graph graph.json --node node-a "SELECT r.graph_result_id, r.edge_type, r.evidence, r.proof_quality, s.traversal_depth AS from_depth, t.traversal_depth AS to_depth FROM relationships r JOIN graph_subjects s ON r.tenant_id = s.tenant_id AND r.graph_result_id = s.graph_result_id AND r.from_subject_id = s.subject_id JOIN graph_subjects t ON r.tenant_id = t.tenant_id AND r.graph_result_id = t.graph_result_id AND r.to_subject_id = t.subject_id"
```

Each Rows frame includes the typed `graph_traversal` receipt. The table format
prints its fields after the rows. JSONL retains the same fields:

| Receipt field | Meaning |
| --- | --- |
| `result_ids` | Authorized immutable versions examined by this read. |
| `unique_subject_count` | Distinct reached full subject keys. |
| `versioned_subject_count` | Selected native subject rows across the versions. The same key can occur in more than one version. |
| `relationship_count` | Selected native edge rows, identified by version and ordinal. |
| `max_hops` | Requested reachability bound. |
| `hop_boundary` | A permitted filtered neighbor exists beyond the requested hop bound. |

The qualification helper checks individual relationships through SQL output
chunks of at most 200 exact key parameters. Each query traverses the complete
selected immutable version and must return the same receipt. The union of
returned keys must equal the complete expected relationship set. This is a
qualification method; it adds no paging contract to the public graph API.

These counts describe traversal input. SQL filters, joins, aggregates, distinct
selection, and output limits can change the number of returned SQL rows.
`hop_boundary: false` does not prove incident coverage. A positive-hop read
returns filtered relationships between reached subjects. A zero-hop read
returns no relationships.

## Limits and errors

The model sets hard bounds. The query owner also applies its configured limits.
The following values are the current defaults and model maxima:

| Limit | Default | Bound and owner |
| --- | --- | --- |
| Graph JSON | One supplied file | 1 MiB; CLI input and GraphTraversalV1 decoding. |
| Seeds | Required | 1 through 64 complete, distinct keys. |
| Exact result IDs | Empty selects current heads | At most 1,024 IDs. The shared selected-key limit can reduce this bound. |
| Hops | 1 | 0 through 64. |
| Subjects | 2,048 | 1 through 65,536. The limit applies to both unique keys and total selected versioned subject rows. |
| Relationships | 4,096 | 1 through 131,072 selected versioned edge rows. |
| Scan bytes | 256 MiB | QueryLimits; headers, narrow work, and selected payload bytes. |
| Input bytes | 64 MiB | QueryLimits; retained CBOR headers, vector capacity, bounded read buffers, and detached input. |
| Extraction time | 1 second | QueryLimits; includes native traversal. |
| SQL evaluation time | 1 second | QueryLimits; separate evaluation stage. |
| Output | 200 rows and 1 MiB | QueryLimits; client maxima. Receipt allocations count toward the byte limit. |
| Shared evaluations | 2 global, 1 per tenant | QueryBudget; reservations remain held through native cleanup. |

The preflight charges each retained header capacity, result ID capacity, and
vector capacity before insertion. The cumulative charge remains part of the
input limit during traversal and projection. The owner also keeps the existing
decoded-header buffer bound. The preflight checks its header batch and twice
the declared snapshot byte count against the remaining input limit. Saved
headers contain metadata only. These headers exclude native subjects,
relationships, and findings. A binding scope loads findings only for
authorization and projection.

Row, work, or input-byte overflow returns `InputTooLarge`. It does not feed a
truncated graph to SQL. A deadline returns `DeadlineExceeded`. Cancellation
returns `Cancelled`. Output-byte failure returns `ResultTooLarge`. A snapshot
can return `limited: true` when its SQL output reaches the row limit; its receipt
still describes the complete bounded traversal input. Busy shared capacity
returns `Busy`.

The limits do not promise unlimited graph size. The materialized edge relation
uses native temporary memory under the existing DuckDB limit. It can contain
more edges than the reached neighborhood. DuckDB settings are not a hard
process-memory or process-crash boundary. No performance threshold is part of
this functional qualification.

## Proof route and qualification

The following tests are implemented. The plan Result records the focused run
results. The fresh full lightweight and paired physical cases pass on the
metadata source record. The final shared Rust procedure also passes. The exact
source, logs, and receipts are recorded below.

| Contract | Source-backed checks |
| --- | --- |
| Request and plan | [Traversal contract tests](../../../../../crates/araphor-data/src/query/traversal_tests.rs): `graph_traversal_definition_bounds`, `graph_traversal_plan_scope`. |
| Remote route | [Control tests](../../../../../crates/mithril-control/src/client_grpc/tests/graph_traversal.rs): `graph_traversal_grpc_contract`, `graph_traversal_grpc_receipt`. |
| CLI | [Argument tests](../../../../../crates/araphor-cli/src/cli/araphor/args.rs): `graph_traversal_cli_bounds`; [output tests](../../../../../crates/araphor-cli/src/cli/araphor/output.rs): `graph_traversal_cli_receipt`. |
| Header reuse | [Header tests](../../../../../crates/araphor-data/src/analysis/graph_rows/tests/headers.rs): `native_header_batch_bounds` checks the transferred byte length and header reconstruction. |
| Topology and selection | [Traversal tests](../../../../../crates/araphor-data/src/graph/tests/traversal.rs) and their fixture cover exact keys, minimum depths, directions, replacements, and historical versions. |
| Bounds and control | [Limit tests](../../../../../crates/araphor-data/src/graph/tests/traversal/limits.rs) cover high fanout, row and byte limits, pre-cancelled controls, and expired controls. |
| Binding scope | [Binding tests](../../../../../crates/araphor-data/src/graph/tests/traversal/bindings.rs) cover zero hops, excluded proof-edge types, and an isolated copy in another version. |
| Recovery | [Recovery tests](../../../../../crates/araphor-data/src/graph/tests/traversal/recovery.rs) cover reopen and backup/restore with unchanged result IDs and receipt values. |
| Incident caller | [Existing qualification extension](../../../../../crates/mithril-e2e/src/discovery/graph_notification/traversal.rs) uses QueryOwner::query_client and checks exact version joins, evidence, proof, coverage references, and receipt fields. |
| Mixed window | [Window qualification](../../../../../crates/mithril-e2e/src/discovery/graph_notification/replay/window.rs) uses one task, 64 records, 32 allowed and 32 denied events, missing initial health, and a fresh query before and after reopen. |
| Captured physical window | [Window qualification](../../../../../crates/mithril-e2e/src/discovery/graph_notification/replay/window.rs): `graph_notification_physical_window` uses 185 records, three subjects, 370 relationships, one denial, no contexts, and at least 59,070 manifest bytes. It checks bounded output chunks and equal data after reopen. |
| Dense retained store | [Density qualification](../../../../../crates/mithril-e2e/src/discovery/graph_notification/replay.rs) queries one exact version before notification routing in a store with 257 findings across 33 source windows, then compares the result after reopen. |

The incident case calls `QueryOwner::query_client` with a fixed qualification
grant. Separate focused tests cover RPC request validation and receipt transfer.
The RPC receipt fixture has an empty graph. CLI tests cover parsing and output.
These tests do not qualify a populated remote physical traversal.

Active cancellation during an in-progress traversal is not qualified by the
pre-cancelled control test. The large multiwindow fixture does not establish
physical multiwindow or cross-node causality. The existing paired physical case
does not establish a throughput or latency result. Full incident prevention,
provider effects, performance, and later package execution remain outside this
result.

Source record: storage baseline `91afc657` and traversal commits through
`adf4d14b`, with the qualification changes in the primary checkout. Read
`source-state-metadata.json` in `/tmp/araphor-native-traversal.OC49oX`. It covers
1,348 files with SHA-256
`ecd499969fcfc73ccf162ee92f8f68934ba42dd5611fc5c155e0be7ca9114b40`.
The full lightweight result has SHA-256
`a104a944a5895de35035aa3dc6e9ce701029ed08dbaca0475f750a3fcf786f6b`.
The paired physical result has SHA-256
`31f718d784080127bb9177729939a6bb16600845a7cf1ebe75ccb0f3f00528a7`.
It checks all 374 relationships from 187 records through two bounded output
queries. The complete traversal value remains equal after reopen. The native
receipt retains three unique and versioned subjects, 374 relationships, one
requested hop, and no hop boundary. Resource and VM cleanup pass. The cleanup
receipt has SHA-256
`4420341fcb678aada147024abd471a22b311f8439c5eb219dba45ec80361bf23`.
The final shared Rust procedure passes with exit code 0:

```sh
env RUST_TEST_THREADS=1 CARGO_BUILD_JOBS=2 bash .github/scripts/verify-rust-ci.sh
```

It checks formatting, the workspace build, strict Clippy, and all workspace
targets and features. The data suite passes 391 tests with three existing
ignored qualifications. The Mithril e2e suite passes 171 tests with 526 existing
ignored cases. The paired physical case passes
separately. No suite fails. All 1,348 covered source files match before and
after the procedure. Read `rust-ci-metadata.log`, with SHA-256
`6f6e2bfde05ad50d633a33bb54ea317c923835cf1a852c98f20f66c16e8b3a57`,
and `rust-ci-metadata-receipt.json`, with SHA-256
`17557083614419ccecf1345208ae8e4ce8c9cbbb7e6216ef56d28762ec8a2b9b`.
