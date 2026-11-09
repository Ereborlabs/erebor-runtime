# Native managed admission qualification

Result: **Done for native managed admission and ordinary start/stop**.
Production replacement, managed execution, and incident performance remain
**Not done**. Source parent: Runtime `6087cbe9f`. The
[evidence record](araphor-native-managed-2026-11-09.json) contains the exact
source hashes, engine revisions, commands, logs, and binary identity.

## Implemented boundary

`NativeStore::admit_managed` uses the existing `ManagedSpec`, grant, and retained
package contracts. One Data transaction stages immutable specification/scope
records, mutable authority/lifecycle, empty call heads, Data's opaque Graph
mappings, and generic Graph declarations/writers. The callback runs before
commit. A borrowed caller can stage contexts in that same transaction. The
original journal test checks all these record families in one commit receipt.

Exact retries check retained definition/image/export/implementation pins and
return the current instance. An exact retry writes no records and performs no
repair. New instances require installed images. The test changes installation
state directly to check retained-pin behavior; no native uninstall or
reclamation API is qualified.

Start/stop preserves the existing lifecycle CAS, stale no-op rejection, current
no-op callbacks, and stop identity checks. A never-started instance receives a
new stop fence. Active reads use a native index and report the captured global
Data revision. The host lease retains the store and its directory lease.

Recovery checks versions, admission scopes, current authority, call heads, the
active index, and Graph mappings against retained manifests. Araphor Graph's
read-only installation check validates declarations, endpoints, writer
ownership, and the exact Graph-local indexes. Writer and relation IDs remain
separately unique, as the old primary keys require. This check does not
qualify complete layer/member recovery.

`ManagedSpec::check_images`, `ManagedCall::contract`, and
`ManagedSpec::graph_declarations` are shared with the current DuckDB caller.
The native readers use admitted descriptor bytes instead of decoding an OCI
artifact a second time. No storage trait, SQL emulator, extra payload archive,
or branch per instance is added.

## Verification

- Final focused Data tests: **43 pass**. Counts are context 10, managed 9,
  catalogue 8, raw 7, native transaction 5, raw index 3, and strict schema 1.
- Native Graph tests: **7 pass**, including the installation corruption matrix.
- Feature-off Data library build: **pass**.
- Native Graph library Clippy: **pass**.
- Data library Clippy: **Not done**. The command stops on the same two existing
  forbidden `expect` calls in `managed/graph/projection/publish.rs:90` and
  `managed/reader/committed/graph.rs:213`. It reports 88 existing warnings.
  No diagnostic names the new native managed modules.
- Selected-file formatting: **pass**. The record identifies the four existing
  managed files excluded from the complete-file formatting claim.
- Full workspace CI does not run during iteration, as the user requires.

The first managed test run had two passes and six failures. Native immutable
versions used positional struct encoding. The actual definition `Source` enum
requires named fields. The current owner passed the shared-helper test in that
run. The correction uses the existing MessagePack configuration with named
fields only for new immutable managed versions. The strict decoder and existing
native record encodings stay unchanged. The later runs pass history and reopen
with those actual DTOs. The failed log is retained.

The rebuilt release binary passes the unchanged combined and stable package
PoCs. Combined checks cover 64 cycles and 128 requested historical views, with
zero unavailable views. Stable checks cover 128 primary cycles, 640 historical
package evaluations, and 320 historical views. No request is unsupported after
reopen. The existing parsers accept both reports. These are correctness checks.
No paired incident or performance improvement follows from these APIs.
The PoC reports retain their existing `unrecorded` source label. The external
source hashes and frozen binary manifest supply the exact source identity.

## Remaining work

Renewal, candidate version admission, removal, failure/resume, captured
attempts, results, checkpoints, references, and consumed progress remain
**Not done**. They require the actual attempt and result owners. No placeholder
pending-attempt predicate is added.

Production activation, original-log routing, retained DataFusion provider
binding, notification batching, configured capacity, retention, backup,
DuckDB removal, and cutover remain **Not done**. The incident test does not run
for this optional admission change. The unchanged test and default definition
remain the acceptance workload. Notification creation below 100 ms and the
100-fold result remain **Not done**. No new performance measurement is claimed.
