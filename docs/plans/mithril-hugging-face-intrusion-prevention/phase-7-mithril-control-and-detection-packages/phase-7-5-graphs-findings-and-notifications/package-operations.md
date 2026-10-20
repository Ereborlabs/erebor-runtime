# Local Analysis Packages

Current operation status, 2026-10-19: The old package owner has been removed.
Use `image` to retain code and `definition` to admit SQL, PRQL, or a YAML call.
Installation and admission start no Discovery. The
[current plan](../../../araphor-package-jobs.md)
records finite execution and the remaining running-instance work.

These image commands are current:

```sh
araphor image digest ./denials
araphor --profile ./operator.json image install ./denials
araphor --profile ./operator.json image inspect denials.repeated --revision 1
```

The old `package` command group is unavailable. Its `run`, `query`, `update`,
`rollback`, `test`, and `remove` operations have no current CLI replacement.
Image installation accepts no scope, input selection, or parameters. Put input
bindings and parameters in the definition. Running instances, automatic source
replacement, and durable instance retry and checkpoint recovery remain
**Not done**.

The old owner procedure and results below are retained as historical material.
Its schema 21, archive cap, compiler process, activation, and durable result
statements do not describe the current image path. Current images have no
mandatory archive-size cap. Wasmtime compiles inside the host process. A
configured compiler address-space quota returns Unsupported.

Use these operations with the existing authenticated
[Araphor client](../../../araphor-observability/phase-3-cli-api-and-console.md).
The CLI and agents call the same package owner. Read the
[implementation limits](wasm-execution-review.md#limits-and-proof)
before selecting an input scope.

New analysis stores use schema 21 and the current binary package records.
Use fresh development stores. The
[schema owner](../../../../../crates/araphor-data/src/analysis/mod.rs) validates
the current format. There is no schema conversion or compatibility reader.

## Built package

A built package is an OCI layout directory or an OCI-layout tar archive.
The directory contains `oci-layout`, `index.json`, and content-addressed files
under `blobs/sha256/`. Its Araphor config contains the SDK descriptors, SQL,
implementation metadata, fixtures, and dependency locks. Executable code,
native dependency code, and fixture Arrow IPC are typed raw layers. The
canonical Araphor manifest and config identify the exact content. The complete
archive has a 32 MiB limit, including headers and padding. Installation works
offline. The installer does not run
an author compiler, hooks, or dependency downloads. The package owner compiles
admitted Wasm components in its bounded host compiler process.

The [compiled detector example](../../../../../crates/araphor-detector-example/README.md)
supplies an OCI folder with declarations, a manifest, and the raw component
layer. Install that detector in scope `analysis`. The graph owner supplies
its authorized inputs and validates its findings and checkpoint. The operator
does not need a Rust compiler.

Wasm qualification is **Not done**. The runtime keeps Wasmtime and the generated
WebAssembly Interface Types (WIT) interface. It adds no Extism dependency.
The six optional Wasm quotas default
to unset. Compiler, cache, SDK, shared query, caller, and commit guards remain.
Read the [open production gates](phase-7-5-4-wasm-execution.md#historical-records)
before using this implementation.

Configure these quotas in `client.investigation.query.package.wasm` in the existing
Control configuration. The
[Control configuration](../../../../../crates/mithril-control/src/config.rs),
[client listener](../../../../../crates/mithril-control/src/client_listener.rs),
and [query configuration](../../../../../crates/mithril-control/src/client_grpc.rs)
use this path. This fragment shows the default values; retain the other fields
in the complete configuration:

```json
{
  "client": {
    "investigation": {
      "query": {
        "package": {
          "wasm": {
            "fuel": null,
            "memory_bytes": null,
            "data_bytes": null,
            "timeout": null,
            "allocation_bytes": null,
            "host_calls": null
          }
        }
      }
    }
  }
}
```

An omitted or `null` quota remains unset. `fuel` counts instruction fuel units.
`memory_bytes` limits guest linear memory. `data_bytes` adds a data-byte ceiling.
`timeout` adds a guest timeout within the caller deadline; its JSON value uses
`secs` and `nanos`. `allocation_bytes` limits approximate allocation fuel for
canonical application binary interface (ABI) copies. `host_calls` limits calls
to the WIT `cancelled` import.
These quotas do not measure total process resident memory. Read the
[remaining guards](wasm-execution-review.md#limits-and-proof) and current
qualification status before setting quotas.

The [two-model fixture](../../../../../crates/mithril-e2e/src/discovery/packages/bundle.rs)
is a complete example of the format through its Rust constructors. Its root is
`denials.repeated` at revision `1`. It locks `denials.count` at revision `1`.
The descriptor owns schemas and bindings. SQL owns the computation:

```sql
-- denials.count: input table denials, output table counts
SELECT subject, resource, CAST(COUNT(DISTINCT event) AS UBIGINT) AS count
FROM denials
GROUP BY subject, resource
ORDER BY subject, resource
```

```sql
-- denials.repeated: input table counts, output table rows
SELECT subject, resource, count
FROM counts
WHERE count >= 3
ORDER BY subject, resource
```

The dependency binds `counts` to the committed `counts` output of the first
model. It does not repeat the grouping expression. The qualification fixture
uses explicit versioned source facts. A production package must bind its source
SQL to the intended authorized query views.

## Authorize and install

The commands in this section are historical. Use the image commands above for
the current installation and inspection path.

First compute the OCI manifest digest:

```sh
araphor package digest ./denials
```

In the existing Control client-auth configuration, grant the authenticated
subject investigation permission and package mutation permission for the same
tenant. Add the returned digest to `package_trust`. These fields are a fragment
of that configuration:

```json
{
  "investigators": [{
    "subject": "operator",
    "tenant_id": "11111111-1111-1111-1111-111111111111"
  }],
  "package_managers": [{
    "subject": "operator",
    "tenant_id": "11111111-1111-1111-1111-111111111111"
  }],
  "package_trust": [{
    "tenant_id": "11111111-1111-1111-1111-111111111111",
    "bundle_digest": "sha256:<64lowerhex>"
  }]
}
```

Replace `sha256:<64lowerhex>` with the exact returned value: `sha256:` followed
by 64 lowercase hexadecimal characters. A bare hexadecimal digest is invalid.
The digest pins exact content. It is not a publisher signature. Control rejects
an unpinned bundle and a caller that has only investigation permission.
Remote registry and publisher-verification work remains deferred under the
[existing OCI plan](../../../daemon-client/phase-10-oci-registry-trust-hub-and-packaging.md).

```sh
araphor --profile ./operator.json package --scope demo install ./denials
araphor --profile ./operator.json package --scope demo inspect denials.repeated
araphor --profile ./operator.json package --scope demo run denials.repeated --evaluation-id review-1
araphor --profile ./operator.json package --scope demo query denials.repeated repeated 'SELECT * FROM rows'
```

Use the same input-selection flags on operations for that installation. A
`scope` names an installation. It does not grant access to evidence. Inspection
returns the admitted descriptor, target support, dependency locks, readiness,
coverage, and exact result receipts. An agent receives the same fields.

Model parameters use package and export names. For a descriptor that declares
`minimum` on `denials.repeated/repeated`, the installation argument is:

```text
--parameters '{"denials.repeated":{"repeated":{"minimum":3}}}'
```

The host checks the declared Arrow type. Unknown keys, fractional integer
values, missing required values, and integer overflow fail admission. A run can
repeat installed parameters; it cannot change the active configuration.

## Corrections, retries, and history

Three distinct denials for the same subject and resource produce one report
row. Replace that source window with two denials. Inspection marks the old
report stale. The next successful run of both models removes the report row.
An empty source with incomplete coverage remains `unknown`.

Repeat `review-1` to retrieve its original receipt. Use a new evaluation ID to
request another run. The same ID with a changed artifact or parameter binding
fails. Restart retains committed results and checkpoints.

Use the `result_id` from a receipt to read retained output:

```sh
araphor --profile ./operator.json package --scope demo query denials.repeated repeated 'SELECT * FROM rows' --result-id RESULT_ID
```

Historical reads retain the original input-scope check. The current caller must
have access to the complete result scope. A later narrow installation cannot
make a broad historical result readable under a narrow grant.

## Update, rollback, test, and remove

Pin the new built bundle before an update. Keep the old pin when rollback must
remain available. A SQL or source-bound Wasm export switches after its prepared
result and checkpoint pass validation. A host-prepared export switches after
component and adapter admission. Its next domain result uses the new exact
package references. Atomicity applies to each export, not the entire dependency
graph.

```sh
araphor --profile ./operator.json package --scope demo update ./denials-v2
araphor --profile ./operator.json package --scope demo rollback denials.repeated 1
araphor --profile ./operator.json package --scope demo test denials.repeated
araphor --profile ./operator.json package --scope demo remove denials.repeated
```

`test` runs declared fixtures through the admitted evaluator. A bundle with
no fixtures returns an empty test list. Fixture success does not prove physical
prevention. Removal retains referenced history and dependencies used by other
installations. Expired or revoked authority stops execution. Reinstall under a
current grant to establish a new execution lifetime.

SQL and source-bound Wasm exports support table outputs. Installed discovery
and graph components use the existing host adapters. An unsupported adapter
returns an explicit status. Native execution, Python execution, and OCI
distribution are later work. No package operation activates kernel policy.
