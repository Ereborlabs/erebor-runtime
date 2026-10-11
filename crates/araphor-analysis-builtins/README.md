# Built-in analysis algorithms

This crate contains the current discovery and graph computations. Production
owners in `araphor-data` and local SDK fixtures call the same Rust code. The crate
depends on the analysis SDK. It has no Control, DuckDB, or host-store dependency.

`discovery::Discovery::package()` declares four exports: `atoms`, `merge`,
`groups`, and `compare`. `graph::Detector::descriptor()` declares `detect` for
`HF-PROC-001`, `HF-DW-001`, or `HF-XNODE-001`. Call `evaluate` with an SDK
`Evaluation`. Each call checks inputs and outputs against its descriptor.

The host supplies exact record references, selected context, and qualified
facts. Graph outputs contain subject selections, relationship candidates,
finding candidates, evidence references, reasons, and checkpoint state. The
host constructs and validates domain identities, proof, findings, and stored
results. A candidate cannot grant authority or perform a preventive action.

The built-in row types use one Arrow binary value per typed row. `Rows::port`
puts the type, JSON encoding, and generated JSON schema in field metadata.
`Rows::encode` and `Rows::decode` check schemas and row, batch, and byte bounds.
Integer values retain their exact widths. This format does not put a complete
graph in one row. SDK authors can also use ordinary Arrow columns directly.

Graph computation receives the fields needed for its decisions. The host keeps
the complete original records and maps returned row references to them. Each
graph call replays a complete retained window; a prior checkpoint does not
replace missing evidence. Discovery retains exact host keys for comparison and
uses host ordering ranks for bounded evidence samples.

Run the standalone computation tests with:

```sh
cargo test -p araphor-analysis-builtins --lib
```

The production adapters and captured output checks are in `araphor-data`.
These direct calls execute trusted built-in code. Package installation, Wasm
execution, and native worker isolation are separate work.
