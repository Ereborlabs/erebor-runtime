# Native Query binding, 2026-11-10

Result: **Done for optional native Query binding**. Production Control and
Analysis still use DuckDB. Production sink binding, notification delivery
batches and durable acknowledgement, remaining storage owners, configured
capacity, retention, backup, cutover, DuckDB removal, and both incident
performance targets remain **Not done**.

The Query feature selects concrete native Data and Graph types at build time.
Existing DataFusion plans, providers, source indexes, and package operators
keep their ownership. The feature adds no storage trait or runtime dispatch.
Managed subscriptions register the actual execution instance. Current captures
carry that subscription into the existing atomic result transaction.
Historical reference reads do not consume input.

Native append pages use the existing capture, cursor, and raw scanner. The
first capture fixes the file end and Data cut. Later pages keep those limits
and return current store metadata separately. Failure, cancellation, scope,
and memory behavior remain qualified. Native health uses actual usage and
history protection with default limits. Readiness loss signals the existing
control watch. Native trace reads remain unsupported.

The three Query integration tests use actual native transactions through the
public managed-publication and Data-sink interfaces. They prove saved physical
plans, package inputs and outputs, selective CDC wakes, exact consumed cuts,
restart, and input received after capture. The Causal package owns actual Graph
links. A failed publication changes neither those links nor consumed progress.
The retry uses the first committed call as its base, keeps reset disabled, and
reads one affected audit row. Three old links remain beside three new links.
This proof does not qualify the production Analysis sink or notification router.

The frozen-source gate passes **112 tests in 11 suites**. No test fails, is
ignored, or is filtered. The test command takes **309.434 seconds**, including
build work. Selected-file formatting and the default Query library check pass.
All 35 source and manifest hashes match before and after the gate. The test
log SHA-256 is
`0db36d71f87cda104ef004e1185ee1b921bbee4b4235b2890ba99021812b3a4a`.

Read the [machine record](araphor-native-query-2026-11-10.json) for exact commands,
source hashes, engine commits, and log paths. Read the
[source guide](../../guides/araphor-native-data-review.md#optional-native-query-binding)
for ownership and the review route. The
[retained test log](../../../output/araphor-fjall-migration-20261110/native-query-tests.log)
contains all suite results. Full CI does not run.

An earlier direct SQL union fixture failed strict field-metadata equality.
The final mixed-owner case uses two normal package calls with a declared output
schema and checks actual route values and changes. This increment does not
fix that direct-union shape. A planned live-call-cache assertion was removed
after source review showed that ordinary follow creates a new call context.
No new cache or relaxed output assertion was added.

The selected incident and default definition hashes remain unchanged.
This increment does not rerun the production incident or measure a native
speedup. The [last production result](araphor-native-provenance-2026-11-10.md#unchanged-production-incident)
passes on DuckDB in 12.21 seconds. That earlier source takes 404.578 to 497.010
milliseconds from collector receipt to first durable notification creation.
Those measurements do not qualify this source or the native Query path.
