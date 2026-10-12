# Local Analysis Packages

Use these operations with the existing authenticated
[Araphor client](../../../araphor-observability/phase-3-cli-api-and-console.md).
The CLI and agents call the same package owner. Read the
[implementation limits](wasm-execution-review.md#limits-and-proof)
before selecting an input scope.

New analysis stores use schema 20. The
[schema owner](../../../../../crates/araphor-data/src/analysis/mod.rs) applies
checked conversions from schemas 19 and 17. Schema 18 remains unsupported and
is rejected without changes. Read the
[notice conversion](wasm-execution-review.md#commit-and-recovery) before updating
a deployment.

## Built package

A built package is one JSON file. A directory supplies the same file as
`package.json`. The file contains the SDK descriptor, SQL implementations or
Wasm components, fixtures, and every locked dependency artifact. The complete
file has a 32 MiB limit. Installation works offline. The installer does not run
an author compiler, hooks, or dependency downloads. The package owner compiles
admitted Wasm components in its bounded host compiler process.

The [compiled detector example](../../../../../crates/araphor-detector-example/README.md)
supplies a built folder with a component, declarations, and the complete
manifest. Install that detector in scope `analysis`. The graph owner supplies
its authorized inputs and validates its findings and checkpoint. The operator
does not need a Rust compiler.

Wasm qualification is **Not done**. The runtime keeps Wasmtime and the generated
WebAssembly Interface Types (WIT) interface. It adds no Extism dependency.
The six optional Wasm quotas default
to unset. Compiler, cache, SDK, shared query, caller, and commit guards remain.
Read the [open production gates](phase-7-5-4-wasm-execution.md#goal-deliverable-review)
before using this implementation.

Configure these quotas in `client.investigation.query.wasm` in the existing
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

First compute the complete bundle digest:

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
    "bundle_digest": "REPLACE_WITH_THE_64_CHARACTER_DIGEST"
  }]
}
```

The digest pins exact content. It is not a publisher signature. Control rejects
an unpinned bundle and a caller that has only investigation permission.

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
