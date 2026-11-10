# Native notification router qualification

Result: **Done for the optional native Router binding and concern delivery**.
Production replacement remains **Not done**. Production Control still uses
DuckDB. No native incident speedup is measured.

The existing `NotificationRouter` now uses the concrete storage type selected
by `araphor-analysis/native-store`. It reuses native context versions, checked
writes, notification indexes, and `PreparedNotificationBatch`. It adds no
backend trait, second delivery algorithm, or second notification archive.

Native Data now supplies exclusive notification ownership and the existing
control-change signal. Drop releases ownership. The native limits accessor
returns the actual default limits held by the store. Native open still accepts
no configured limits. Configured capacity remains **Not done**.

The existing attempt sequence is unchanged. Data commits Pending before the
sink effect and commits the outcome after the effect. A pending attempt retains
its exact subject context and approved route version. The native Host
notification constructor remains unavailable until the connected provider and
durable-consumption work is complete.

## Verification

The [source and command record](araphor-native-router-2026-11-10.json) freezes
the source, unchanged incident inputs, engine commits, commands, and log hashes.
The gate passes **17 tests in four suites**, with no failed, ignored, or
filtered cases:

- Four public native Router cases.
- Four existing native Instance cases.
- Three native Data notification cases.
- Six native Data store cases.

The new public cases check owner exclusivity and control signals, route and
concern retries, page scope, human acknowledgement, and reopen. The sink reads
actual durable Pending, the immutable subject revision, and the approved route
before it records the effect. An unwind after the effect interrupts outcome
persistence. Reopen and retry preserve the complete delivery request. This is
an interrupted-effect test, not process-crash or power-loss proof.

A competing context write occurs after batch preparation and before Pending.
The stale checked Pending write fails, no sink call occurs, and only the
competing version survives reopen. Another case checks a failed Finding-kind
concern attempt, failure escalation, reopen, retry numbering, and retained
outcomes. These cases use concerns. They do not qualify actual finding routing.

Formatting, default and native Analysis library checks, and native Analysis
library plus new-test Clippy pass. Clippy reports existing library warnings
and two large-error warnings in the new test. Warnings are not denied in this
focused gate. An earlier test compile failed because its native open call did
not borrow a path. The fixture call was corrected before the frozen gate.

## Remaining work

Per-transition notification commits still need replacement with batches.
Durable notification CDC consumption, native notification Arrow extraction,
Source finding readers and revisions, configured capacity, retention, backup,
production cutover, DuckDB removal, and both incident performance targets
remain **Not done**. The selected incident and full CI do not run for this
increment. The workload, assertions, and timeouts are unchanged.
