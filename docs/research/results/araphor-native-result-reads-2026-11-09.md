# Native result reads, 2026-11-09

Result: **Done for optional native result reads**. Production provider binding,
original-log routing, notification batches, cutover, DuckDB removal, and both
incident performance targets remain **Not done**.

The native owner now returns the existing result and historical attempt DTOs
from one captured Data view. It checks caller scope before result integrity.
Selected `current` uses that view's actual successful progress. Call `current`
uses actual call heads, exact dependencies, source heads, deadlines, witnesses,
and immutable context references. Stale results remain readable. Metadata reads
do not load checkpoints or raw payloads.

Historical replay reads the original capture revision. It restores actual prior
checkpoints before the shared extraction budget admits Arrow rows. It retains
the original capture contract. Source-frame restore requires the original
request time; changes also require the exact saved parent position. The page
uses the captured data and the current physical recovery epoch for source proof.

An in-memory persistent index supplies bounded raw evidence and source-birth
predecessors. Recovery derives births from the first original raw append and
the first immutable coverage position. It preserves raw-first and coverage-first
order after later metadata commits and reopen. It adds no durable raw archive.

The focused command passed **73 tests**, with no failures, ignored tests, or
filtered tests. The process took **35.950 seconds**, including build work. The
eight suites are `native_context`, `native_extraction`, `native_managed`,
`native_packages`, `native_raw`, `native_store`, `raw_index`, and `store_schema`.
The command uses `--offline -p araphor-data --features native-store,test-fixtures`
and the existing local DuckDB build override. Read the
[machine record](araphor-native-result-reads-2026-11-09.json) for the exact command,
12 unchanged source hashes, engine commits, format check, and log hashes.

The managed suite checks held and reconstructed historical views, stale caller
instances, scope before corrupt-result checks, metadata reads with an invalid
checkpoint body, and both source-birth orders after reopen. The checkpoint case
restores the actual saved value `71` after a later value `72` commits. It checks
the exact parent, one real changed event, a different request time, and combined
prior/page accounting at the measured byte limit. The one-row bound checks
accounting; it does not isolate the former allocation-order defect.

The unchanged incident workload and default definition hashes still match the
prior qualification. This increment did not rerun the production incident or
full CI. Production still uses DuckDB. No speedup is established. Native trace
and source-publication owners remain unported.
