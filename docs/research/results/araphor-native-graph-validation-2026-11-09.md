# Native Graph snapshot validation qualification

Result: **Done for native Graph snapshot validation and read-only iterators**.
Data publication, recovery, production replacement, and performance remain
**Not done**. Source parent: Runtime `d0f2ae7c7`. The
[source record](araphor-native-graph-validation-2026-11-09.json) contains the six
source hashes, focused command, and evidence hashes.

`Graph::validate` checks one native snapshot. It checks declarations, writers,
layer chains, native commit cuts, dictionary links, property chunks, member
references, live endpoints, and exact member index sets. Logical revisions and
native commit cuts remain separate values. The property pass decodes each chunk
once. It retains row requirements and releases each decoded Arrow chunk before
it reads the next chunk. Closed property history and unused dictionary entries
remain valid.

`Graph::layers` returns writer, layer, parent, and logical revision through a
fallible iterator. The validator uses the same checked layer decoder. Three
existing Journal iterators now have public visibility. Their algorithms and
feature gates do not change. The engine receives no package policy.

The focused native Graph command passes **12 tests**. This includes **27 corrupt
record/index cases**, standalone layer errors, empty properties, self-loops,
empty and fragmented identities, deletion, retained property history, branch
isolation, and compaction. All six source hashes match before and after the
recorded run. Selected-file formatting and scoped whitespace checks pass.

This check covers the supplied snapshot. Data must separately check retained
publication cuts and historical read receipts. The native Data transaction work
is outside this commit. Production still uses DuckDB. This optional-path change
adds no incident timing or performance claim. Full CI does not run during
iteration, as the user requires.
