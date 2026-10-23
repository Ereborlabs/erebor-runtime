# Scoped DuckDB interruption

These local copies retain the existing DuckDB dependency at version
`1.10505.0`. Araphor uses DataFusion for query planning and execution. DuckDB
remains the durable storage owner.

DuckDB normally clears an interrupt when a statement starts. That reset can
erase a cancellation or deadline event delivered between two statements in
one Data read. The local patch adds a native interrupt scope. A scope keeps
that event active until the Data operation releases its interrupt sources.
The Data deadline worker can then send one interrupt and wait for an event.

## Source and changes

The 99 upstream files contain 8,179,916 bytes before local changes. The copies
retain the upstream licenses and tests. The source archive is unchanged.
Copied third-party source is separate from authored changes and from Araphor
production Rust reduction counts.

The unchanged generated `libduckdb-sys/src/bindgen_bundled_version_loadable.rs`
retains the upstream final blank line. The Git whitespace check excludes only
that byte-identical file. All authored changes pass the check.

| Input | SHA-256 |
| --- | --- |
| `duckdb-1.10505.0.crate` | `970e05eedd3f55c435194d9104f90a9b4a79a80d6e73251bc9ff43e178130c4e` |
| `libduckdb-sys-1.10505.0.crate` | `6cb514dab5e271e849235c1cb98bd65a2ae107fbd619a6740219319c54a71d95` |
| `libduckdb-sys/duckdb.tar.gz` | `e11f1209cdbb2a99b2ea2d348de21bdfb01dc494b55d1271df94b09c52bf229c` |

[The build patch](libduckdb-sys/interrupt_scope.rs) applies strict replacements
to the pinned native source before bindings and compilation. A changed match
count stops the build. The bundled cc backend patches its extracted source.
The CMake backend uses its required CMake executable to copy source into the
build directory before patching. Neither backend modifies an external source
checkout.

The native context has one atomic scope state: inactive `0`, active `1`, or
cancelled `2`. Public interruption changes an active scope to cancelled before
the normal interrupt. All seven native reset sites use `ClearInterrupt`,
which preserves a cancelled scope. Initial cleanup rejects a new statement
inside a cancelled scope. A failed nested scope does not change the outer
scope. Ordinary interruption outside a scope keeps its previous behavior.

The [Rust guard](duckdb/src/inner_connection.rs) starts and ends the scope
under the existing interrupt-handle mutex. Data stops the deadline source,
unregisters cancellation and releases the native scope before rollback or
connection reuse. Non-bundled and loadable-extension modes do not expose the
new guard. Cargo excludes both local dependencies from workspace membership.

The native change adds two C entry points and no query executor or result
decoder. Existing DataFusion planning and existing DuckDB transactions retain
their owners. No contract or package version changes.
