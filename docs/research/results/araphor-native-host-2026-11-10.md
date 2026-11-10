# Native Analysis host and sink, 2026-11-10

Result: **Done for optional native Selected/copy host binding**. Production
replacement remains **Not done**. Production Control still uses DuckDB.

The `araphor-analysis/native-store` feature selects the existing native Data
commit, return, lease, and activation types. The existing DataFusion sink uses
these types. No second execution path or storage trait is added. Host lifecycle
changes use the original-log activation coordinator. Each cloned activation
handle keeps its own observed position.

Native reads have no SQL reader pool. Membership and suspension each perform
one native read. SQL builds retain the exact reader-busy retry rule and
cancellation-aware capacity wait. Shared memory and package-capacity waits
remain in both builds.

Native builds exclude `InstanceHost::with_notifications`. The notification
router still owns DuckDB. A native host cannot attach that router. Native
notification integration remains **Not done**. The exposed revision watch is a
coalesced availability hint. Tests re-read committed state after each hint.
The watch is not a durable or selective input subscription.

Four new tests call the public Instance and Host APIs with real native Data.
They check finite publication, retained replay after later input, denied
authority and retry, host start/stop, restart, renewal, metadata update,
rollback, removal, recreation, and retained history after reopen. Rollback
restores the retained generation. Lifecycle and commit revisions still advance.
These tests use the SQL copy package. Graph and Profile sink destinations
compile but are not qualified at runtime by these four cases.

The final frozen gate passes **96 tests in four suites**, with no failed,
ignored, or filtered tests. The existing managed, input, and Query regression
command passes 92 cases in **54.067 seconds**, including build work. The new
public API command passes four cases. Selected-file formatting, default and
native Analysis library checks, and native Analysis library Clippy pass.
Clippy reports existing warnings; this is not a warnings-denied workspace gate.
Source and unchanged incident workload hashes, commands, logs, and engine
revisions are in the [machine record](araphor-native-host-2026-11-10.json).
Read the [source guide](../../guides/araphor-native-data-review.md#native-analysis-host-and-publication-sink).

Source finding providers, native notification integration, configured capacity,
retention, backup, production cutover, DuckDB removal, and both incident
performance targets remain **Not done**. The selected incident and full CI do
not run for this increment. No native production speedup is measured.
