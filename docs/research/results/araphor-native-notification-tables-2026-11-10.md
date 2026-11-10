# Native notification Arrow reads

Result: **Done for optional native notification snapshot reads and finite SQL
delivery**. Production replacement remains **Not done**. Production still
uses DuckDB. No native incident speedup is measured.

The provider reads one captured Data view. All-obligation requests use the
current context-name and head indexes. Exact requests read the requested
immutable owner revision. Neither path scans the obligation version history.
The shared Arrow row builder retains the schema, retry times, deadlines, and
next-change behavior.

FindingRead resolves Source and Definition publication owners and canonical
finding tokens. One compact owner cache serves all requested findings and
obligations for a result. The cache retains a Source identity or Definition
grant. It contains no Graph revision or second property body. Permission is
checked for each request. Whole Source revisions and raw payloads are not read.

A healthy non-Graph result ID gives an unavailable finding. A missing required
Source header or rebound publication remains an error. A Source outside the
selection is filtered before the existing binding capability check. Current
finding identity and canonical value identity stay separate.

Retry calculation reads the exact approved route revision from the same Data
view. A later route does not replace it. A clock-only read can change readiness
at the same committed cut. Route and obligation body decode allocations are
charged before decode.

## Verification

The [machine record](araphor-native-notification-tables-2026-11-10.json) freezes
the source, unchanged incident workload, engine revisions, commands, and logs.
The frozen runtime gate passes **131 tests in eight suites**, with no failed,
ignored, or filtered cases. All 101 source hashes remain unchanged through the
gate. The engine checkouts are clean at their recorded commits. Formatting and
default and native Analysis library checks pass. All 507 local links in the
changed documentation resolve.

Three new Data cases cover Source and Definition findings, held views, current
canonical values, exact old Source obligations, compaction, reopen, exact route
retries, same-cut time changes, scope, concerns, unavailable findings, healthy
Call and processor IDs, a healthy foreign Call ID, budgets, and cancellation.
The scope cases retain the existing whole-package and filtered-read rules.

One public Analysis case executes the actual `NotificationRouter::SQL` through
native DataFusion and a finite Subscription. The Subscription holds the supplied
logical plan. The emitted Update names the actual obligation. Router.consume
uses the existing delivery algorithm. The sink reads durable Pending, its
immutable subject, and the approved route before the effect. The case then
checks the accepted durable outcome. It does not prove plan reuse across later
notification wakes.

Early fixture runs exposed missing owner activation, a module path, an Arrow
decode type, and invalid scope assumptions. The fixtures were corrected. No
production scope rule, incident assertion, workload, or timeout was relaxed.
The final frozen record supplies the qualified results.

The first broader gate finds an obsolete test that requires notifications to
be unsupported. The updated case requires owner-unavailable before activation,
success after activation, and strict Unsupported for the unported trace owner.
The machine record retains the failed gate. Data Clippy fails on two unchanged
legacy `expect` calls at `analysis/managed/graph/projection/publish.rs:90` and
`analysis/managed/reader/committed/graph.rs:213`. It is not a passing lint gate.
Native Analysis library and notification-test Clippy pass with warnings. This
is not a warnings-denied workspace gate.

## Remaining work

Notification execution still uses finite snapshot rows. This provider does not
supply an affected-key change view. Durable notification CDC completion,
notification write batches, native Host notification admission, configured
capacity, retention, backup, production cutover, DuckDB removal, and both
incident targets remain **Not done**. Source binding reads retain their existing
unsupported boundary. The selected incident and full CI do not run for this
increment.
