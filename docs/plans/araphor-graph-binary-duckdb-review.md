# Graph Binary and DuckDB Representation Review

This research compares production graph representations. The user approves
the recommended typed handoff, metadata-only header, and DuckDB appender.
The user also directs removal of backward compatibility. Current-only source
is implemented. Focused qualification and the final Rust procedure pass.
No benchmark is approved.

## Baseline representation at `9191ddcc`

[GraphRows](../../crates/araphor-data/src/analysis/graph_rows/mod.rs)
already stores subjects, relationships, and findings in three native DuckDB
tables. Each row has a result ID and ordinal. The
[schema](../../crates/araphor-data/src/analysis/graph_rows/schema.rs)
retains primary keys and a unique finding key. Some nested evidence fields are
binary values. This is not one complete JSON graph stored as a database blob.

At the baseline, `GraphHeader` used a seven-field CBOR envelope. Header creation
parsed the complete canonical graph JSON before it removed row arrays.
`JsonLayout` retained exact noncanonical source bytes. Those layout and old
header paths are removed from the current source.

## Current representation

[CanonicalGraph](../../crates/araphor-data/src/analysis/graph_rows/mod.rs)
keeps a validated typed snapshot and its canonical body in private fields.
The graph owner prepares the body once before the size check and context
effects. The store consumes the pair and empty-body commit metadata. Shared
validation checks manifest, witnesses, scope, and progress before row storage.

[GraphHeader](../../crates/araphor-data/src/analysis/graph_rows/header.rs)
serializes required metadata without a complete row tree. The current CBOR
header has six fields: version 2, three row counts, canonical byte length, and
metadata bytes. Current canonical results have a 16 MiB bound. The byte entry
still validates untrusted input and requires exact canonical JSON bytes.
The current format has no layout tape, `graph_encoding` column, separate
source byte length, old header decoder, or migration path.

[Graph reads](../../crates/araphor-data/src/analysis/graph_rows/read.rs)
check header indexes and charged row bytes. Row reconstruction checks ordinal,
counts, canonical size, and snapshot validity. Recovery also checks exact body
reconstruction. Traversal reads native graph columns; a whole-graph Protobuf
blob must not replace those columns.

## How DuckDB handles data

DuckDB executes typed column vectors grouped into data chunks. Its default
chunk contains 2,048 tuples. Database storage uses compressed row groups.
The database owner, not this application, controls that physical format.
[Execution format](https://duckdb.org/docs/current/internals/vector),
[storage format](https://duckdb.org/docs/current/internals/storage).

`STRUCT` fields have a fixed schema and typed child columns. A nested typed
field can remain available to SQL without decoding an application blob.
Changing existing graph fields to STRUCT or LIST requires a schema and
quota decision. It is a separate choice from removing an internal JSON
handoff. [STRUCT documentation](https://duckdb.org/docs/current/sql/data_types/struct).

The pinned Rust `duckdb` and `libduckdb-sys` packages are both `1.10505.0`.
Data already enables `appender-arrow`. The local binding offers
`Connection::appender`, `Appender::append_rows`, and `append_record_batch`.
The Arrow method converts batches into DuckDB data chunks sized for its vector
capacity. This conversion is not a general zero-copy guarantee.

DuckDB appending is an input path, not a new durable format. Keep the appender
on the existing transaction connection. Explicitly flush and check its error
before commit. The pinned Rust binding warns that constraint errors can occur
at flush and that Drop discards those errors.
[Appender API](https://duckdb.org/docs/current/clients/c/appender).

## Comparison

| Choice | Work removed | Added contract and limit |
| --- | --- | --- |
| Typed Rust snapshot to native rows; retain current CBOR envelope | Complete internal graph JSON decode; repeated serialization; full graph tree used for metadata extraction | Typed and byte entries must produce equal current canonical bytes, headers, rows, charges, and receipts. Reject noncanonical input. No new transport schema is required. |
| Protobuf between graph owner and store | JSON text and decimal byte-array transport | Adds message encoding, decoding, schema evolution, presence/enum rules, and a second model mapping within one process. It does not remove conversion into DuckDB columns. |
| Protobuf for small metadata only | Small JSON metadata parse | Requires a versioned header contract. It does not address full-graph preparation or individual SQL inserts. |
| Arrow batches or appender to existing tables | One prepared-statement execution per stored subject, edge, or finding | Adds bounded batch preparation and explicit flush/error handling. Existing columns, keys, ordinals, charges, and transaction remain. |
| Complete graph in a Protobuf BLOB | Native row preparation | Removes native SQL graph visibility and selective traversal. Reject this choice for the current product contract. |

Protobuf is useful at a real transport boundary. Its serialization is not
canonical, even when deterministic settings are used. Do not replace current
byte identities or retry equality with hashes of newly serialized messages.
Keep a defined application identity and unknown-field policy if Protobuf is
selected. [Protobuf canonicalization limits](https://protobuf.dev/programming-guides/serialization-not-canonical/).

DuckDB database backward compatibility is not an application serialization
contract. A newer database can use a storage format an older reader cannot
read. Do not store DuckDB internal vectors or private serialized objects as
an application wire format. Use its supported table and input APIs.
[Storage compatibility](https://duckdb.org/docs/current/internals/storage).

## Approved decision

Keep native graph columns. Pass typed data inside the process. Encode only
required metadata in the current six-field header. Keep the validated byte
entry and reject noncanonical input. Remove old header and layout readers.
Use the existing Rust appender to fill the same tables in the existing
transaction. The appender buffers typed rows. This first change does not build
a second Arrow representation. Add Arrow batches only after a separate need
and approval. This removes a representation boundary and per-row execution
without changing query ownership. No speed improvement is established yet.

Prove typed-versus-byte current body/header/row parity, noncanonical rejection,
all byte and memory
bounds, context and package references, witness expiry, immutable retry,
constraint rejection at flush, rollback after a failed batch, cancellation,
quota charges, crash-before/after commit, backup/restore, and notifications.
Use [native storage tests](../../crates/araphor-data/src/graph/tests/native_storage.rs),
[encoding tests](../../crates/araphor-data/src/analysis/graph_rows/tests/encoding.rs),
[graph crash tests](../../crates/araphor-data/src/graph/tests.rs),
and [backup/recovery tests](../../crates/araphor-data/src/analysis/graph_rows/tests/recovery.rs).

**Done** for explicit architecture approval and current-only source
implementation, focused qualification, and the final Rust procedure. The
[graph review guide](../guides/araphor-graph-commit-review.md) records the
source head, tests, and final procedure evidence.

## Future query engine change

The typed Rust handoff keeps graph logic separate from DuckDB insertion. A
future query owner can expose Arrow batches to DataFusion. DataFusion provides
`MemTable` for existing batches and `TableProvider` for a custom source. This
is an architecture inference, not a qualified migration.
[Table provider API](https://datafusion.apache.org/library-user-guide/custom-table-providers.html).

Moving query execution and replacing durable storage are separate changes.
A replacement storage owner must preserve transactions, recovery, backups,
quotas, and exact result bytes. Add no DataFusion dependency or general backend
trait for the current change.
