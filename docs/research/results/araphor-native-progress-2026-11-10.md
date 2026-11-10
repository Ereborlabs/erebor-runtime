# Native processor results and Profile publication, 2026-11-10

Result: **Done for native processor registration, immutable results, retirement,
and typed managed Profile publication**. Production replacement remains
**Not done**. Native expired-range proof and optional resume remain incomplete.
Production Control and Analysis still use DuckDB.

One native Data write now publishes managed package results, typed Profiles,
captured contexts, reference pins, processor progress, and consumed input.
A rejected projection or caller guard leaves the whole write uncommitted.
A current processor head and a historical interval head remain separate.
A historical repair does not replace a newer current interval. A close-only
seal preserves the original producing call and witnesses.

Profile metadata and the immutable body use separate keys. A metadata-only
Discovery state request does not load the body. Indexed interval heads supply
historical winners. Notices overlay maximum facts and coverage revisions
without replacing the Profile body. Compatibility uses the actual target
package version, including a prepared candidate. Producer qualification reuses
the Profile already decoded by the caller.

Native format 5 uses one global result-name dictionary identity for managed
and processor results. Both writers reject collisions. Reference resolution
rejects two payload owners. Native format 4 stores are rejected. This change
does not migrate production DuckDB directories.

Recovery reads processor and notice versions from retained Fjall values.
Each declared revision must contain its exact value. The value at revision
minus one supplies the preceding update. Raw-only revisions can separate
updates. Recovery also checks immutable bodies, interval winners, source
bounds, retirement gaps, and the exact shared reference index.

Eight new focused cases exercise actual native managed operations. These
cases cover guard rollback, captured contexts, close-only evidence from an
older capture, interval repair, historical extraction, notice overlays,
candidate compatibility, stale-input rejection, both result-name writer
orders, dual-owner corruption, selective journal replay, compaction, and
restart. Separate damaged-record cases reject invalid intermediate processor
states, missing or extra gaps, extra body fragments, and changed result bodies.
An opaque Discovery result remains valid. An unproved new Profile gap rolls
back the package publication and progress.

The frozen native gate passes **135 tests in 11 suites**. No test fails,
is ignored, or is filtered. The command takes **56.668 seconds**, including
build work. Selected-file formatting and the default Query library check pass.
Source and workload hashes are in the [machine record](araphor-native-progress-2026-11-10.json).
Read the [source review guide](../../guides/araphor-native-data-review.md#native-processor-results-and-profile-publication).

The additional shared-progress library test command fails before test execution
with **134 compiler errors**. The errors include obsolete Graph test paths,
duplicate and missing fixture methods, and missing test imports. All 31
reported source files or test modules match the preceding committed source.
This result does not qualify the shared library tests. Read the
[compile log](../../../output/araphor-fjall-migration-20261110/native-progress-shared-progress.log).

The production Analysis binding check still fails, with **24 compiler errors**.
The errors identify host and sink types, activation handles, capacity waiting,
frozen Graph reads, and Graph publication. Read the
[binding log](../../../output/araphor-fjall-migration-20261110/native-progress-binding-check.log).
The preceding binding check had 30 errors. This count is integration evidence;
it is not a performance measurement.

Production binding, remaining storage owners, notification delivery and
consumption, configured capacity, retention, backup, cutover, DuckDB removal,
and both incident targets remain **Not done**. The selected incident does not
run for this increment. No native production speedup is measured. Full CI does
not run.
