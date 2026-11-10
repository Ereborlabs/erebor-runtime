# Native Graph source publication, 2026-11-10

Result: **Done for optional native source publication and retained input reads**.
Production replacement remains **Not done**. Production still uses DuckDB.

One native Data write stores the Selected result, source membership, package
Graph journals, context pins, processor progress, and consumed input. The Graph
receipt names the same Selected result. No second result body or raw payload
archive is added. Shared preparation preserves the original frame, proof,
append prefix, base, count, gap, and expiry checks.

Stable member keys contain input positions and origin identities. Separate fact
and proof postings contain context identities and revisions. Retained Fjall
snapshots supply old membership after replacement and compaction. Frozen subset
reads use member points and posting prefixes. Historical reference admission
checks the original source, exact context pins, and record association.

Expiry checks the final staged Graph values. A retained healthy relationship or
finding rejects the complete write. Package-selected degraded values commit
with the source expiry and progress. The no-journal path uses the same guard.

Original journal batches route source headers with their exact source identity.
The native processor view supplies captured `graph_state` rows. An absent
processor has null state fields. Unported tables remain explicitly unsupported.

The frozen focused gate passes **144 tests in 11 suites**, with no failed,
ignored, or filtered tests. The command takes **192.408 seconds**, including
build work. Selected-file formatting and the default Query library check pass.
Nine source cases cover rollback, append with retained proof, historical fact
and proof imports, replacement, damaged records, empty gates, window winners,
selective CDC, captured state, compaction, and restart. The first CDC test used
one future poll and did not wait for asynchronous routing. The corrected test
uses the existing bounded-await pattern and also checks unrelated input absence.
The incident workload, assertions, and timeouts do not change.

The native Analysis binding check fails with **14 compiler errors**. Remaining
errors include commit and lease types, activation handles, and SQL reader
capacity branches. Read the
[binding log](../../../output/araphor-fjall-migration-20261110/native-source-binding.log).
The [machine record](araphor-native-source-2026-11-10.json) contains source and
workload hashes, exact commands, logs, engine revisions, and check results.
Read the [source guide](../../guides/araphor-native-data-review.md#native-graph-source-publication-and-retained-input).

Source finding providers and notification revision construction remain
**Not done**. Those native paths reject source publications with `Unsupported`.
Recovery scans membership at each retained publication. Long append chains can
make recovery work quadratic. Bounded recovery cost is not proved.

Production binding, remaining storage owners, notification delivery, configured
capacity, retention, backup, cutover, DuckDB removal, and both incident targets
remain **Not done**. The selected incident and full CI do not run for this
increment. No native production speedup is measured.
