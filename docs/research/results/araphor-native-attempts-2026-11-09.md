# Native capture and terminal attempt qualification

Result: **Done for native capture and terminal attempts**. Production replacement,
successful result publication, and incident performance remain **Not done**.
Source parent: Runtime `5db2df64c`. The
[source record](araphor-native-attempts-2026-11-09.json) contains exact hashes,
commands, and evidence paths. Read the
[owner guide](../../guides/araphor-native-data-review.md#native-capture-and-terminal-attempts).

## Implemented boundary

The native capture API reads actual Arrow inputs from one native/raw Data view.
It uses the existing capture and source-frame sealing contracts. It reads saved
call heads and completed outcomes. It does not invent prior results or a parent.
Requested unported result, dependency, and source-parent owners return
`Unsupported`.

Registration saves an immutable capture/request and its pending index in one
Data transaction. A live claim belongs to the opened store. A loaded pending
attempt cannot finish that execution. Exact completed retries check the caller's
callback and stage no writes. Multiple manual pending attempts retain the
existing behavior; frontier registration checks pending work in its generation.

Terminal commit saves the outcome, removes pending state, and advances completion
indexes together. A qualifying failure saves failure status. Denied can suspend
the instance in that same transaction. Successful consumed progress remains
separate and is not advanced by a terminal outcome. The caller must stop and
join execution before terminal commit.

Recovery checks authority, versions, lifecycle, ordered references, exact indexes,
and required failure records. It validates captured completion against outcomes
at or before the captured revision. Startup cancels current-generation pending
frontier attempts in one genuine Data commit. Manual and older-generation pending
attempts retain their current behavior.

Physical native format 3 adds saved relation heads for capture checks. Logical
schema 41 and recovery epoch 1 remain. Context and coverage heads share their
existing commit. Event and new-binding heads come from original raw entries.
Coverage-first binding recovery merges native receipts before it examines the
later raw tail. No raw payload copy, second CDC log, or extra raw-append sync is
added. These freshness heads do not replace original-log subscription positions.

## Verification

The final focused command passes **62 Data tests**: context 10, extraction 8,
managed 18, catalogue 8, raw 9, native transaction 5, raw index 3, and schema 1.
The feature-off library build and selected-file formatting pass.

The new cases check actual Arrow/source rows, rollback callbacks, live claims,
parallel pending attempts, captured cuts, nonzero historical completion, failure
and Denied status, one-commit restart settlement, missing indexes, invalid
captured contracts, deleted failure records, and coverage-first raw recovery.

Initial new-test runs exposed fixture permission/projection and MessagePack
editing errors. They also found a production prefix collision: the first
outcome index used `e`, which overlapped existing source-epoch keys. The corrected
index uses disjoint `E`. Exact-set recovery validation remains active. The source
record preserves the failed logs and their final passing replacement.

Data library Clippy remains **Not done**. It reports the same two existing
forbidden `expect` calls and 88 warnings. No diagnostic names the new native
modules. Full CI does not run during iteration, as the user requires.

The incident and engine PoCs are not rerun for this optional-path increment.
Existing production callers gain only derived RawIndex heads; shared helper
changes are visibility and a borrowed-descriptor `Copy` implementation. This
qualification makes no incident timing or performance claim. The preceding
[unchanged incident result](araphor-native-extraction-2026-11-09.md#unchanged-incident)
is separate evidence for its own source state.

## Remaining work

Successful results, checkpoints, Graph journals/findings, retained references,
consumed progress, prior-result restore, production provider binding, original-log
routing, notification batching, retention, configured capacity, backup, and
cutover remain **Not done**. Production still uses DuckDB. Sub-100 ms creation
and the 100-fold improvement remain **Not done**.
