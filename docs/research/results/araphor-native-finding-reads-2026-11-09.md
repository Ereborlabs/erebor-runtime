# Native finding reads, 2026-11-09

Result: **Done for optional native finding and manifest reads**. Production
provider binding, original-log routing, notifications, capacity, retention,
backup, cutover, DuckDB removal, and both incident targets remain **Not done**.

The native table owner now reads the existing `findings` and `graph_manifest`
Arrow shapes. It resolves a selected result to its actual publication and saved
writer cuts. Araphor Graph scans visible owned members at those cuts. Data uses
each visible member's opening producer for scope and restriction checks. The
canonical token supplies value identity; it does not supply producer authority.
Manifest counts deduplicate relation/key pairs across owners and writers.

Data publishes a shared persistent tenant-to-Graph index with its native view.
Admission updates only the transaction's index root. Rollback drops that root.
Recovery rebuilds the index during the existing ownership check. Historical
reads use the current index as a candidate superset and resolve heads only in
the captured snapshot. This keeps the original durable format and sole head
authority. Reads do not decode another tenant's publications.

The existing full authority scope stays separate from the projected row
selection. The strict `check_scope` contract is unchanged. Nested result,
attempt, retained-version, Graph mapping, publication, and origin records use
the same read budget before decoding. The existing Arrow builders retain row,
reference, finding-ID, and allocation accounting.

The focused gate passed **74 tests**, with no failures, ignored tests, or
filtered tests. It took **60.119 seconds**, including build work. The eight
suites are the same as the previous result-read qualification. Format checking
also passed. Read the [machine record](araphor-native-finding-reads-2026-11-09.json)
for the exact command, 18 unchanged source hashes, engine commits, and evidence
hashes.

The new case uses the existing real two-writer domain fixture. It checks a
removed producer, an equal replacement, stable tokens, unique manifest counts,
held and reconstructed historical views, compaction, rollback, and reopen. A
foreign tenant must return an empty page within the exact byte budget measured
before the publication existed. Projected scope succeeds; an unsupported
filtered selection retains its existing denial.

The unchanged incident and default-definition hashes still match. This increment
did not rerun the production incident or full CI. It establishes no speedup.
Source-publication selection and other unported table owners remain explicit
errors.
