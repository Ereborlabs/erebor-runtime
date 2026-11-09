# Native Arrow source extraction qualification

Result: **Done for native Evidence, coverage, and context Arrow extraction**.
Production replacement, managed execution, and incident performance remain
**Not done**. Source parent: Runtime `cc35d1c67`. The
[source record](araphor-native-extraction-2026-11-09.json) contains exact source
hashes, engine revisions, commands, and evidence paths. Read the
[source guide](../../guides/araphor-native-data-review.md#native-arrow-source-extraction).

## Implemented boundary

`NativeStore::read_tables_at` reads one captured native/raw Data view. It reuses
the current raw decoder, filters, page limits, cancellation, Arrow builders,
positions, witnesses, and reference DTOs. Source headers contain actual receipts,
coverage reports, and pending gaps. Raw bytes remain in the existing segments.

Body-free context headers have tenant and scoped-owner indexes. One transaction
stages each immutable context and both headers. Change reads bound the native
range by Data revision. Exact keys use direct lookups. Complete reads sort the
semantic key; changes sort revision and then semantic key. Retained package
proofs use the existing per-read cache. Generic context reads add no fact lookup.
Recovery checks both exact index sets and their context identities.

Physical native format 2 persists logical schema 41 and recovery epoch 1.
Ordinary reopen preserves the recovery epoch. Older prototype formats are
rejected. No DuckDB directory conversion is implemented.

Payload reads admit the declared assembled size before allocation. Temporary
headers and prefixes release their charges after use. Vector slots and their
owned heaps are charged separately. The test supplies a nine-byte manifest for
a 4 GiB payload with no fragments and a 1 MiB budget. The read
returns the input-budget error before assembly or a missing-fragment error.
Another test checks equal final memory accounting for all-context and exact-key
reads after subtracting their different selection storage.

## Verification

The final focused command passes **51 Data tests**: context 10, extraction 8,
managed 9, catalogue 8, raw 7, native transaction 5, raw index 3, and schema 1.
The feature-off library build and selected-file formatting pass. The evidence
record lists existing files outside the complete-file formatting claim.

Data library Clippy remains **Not done**. It reports the same two existing
forbidden `expect` calls in `managed/graph/projection/publish.rs:90` and
`managed/reader/committed/graph.rs:213`, with 88 existing warnings. No diagnostic
names the new native extraction modules. The initial library-test attempt
cannot compile unchanged Graph fixture paths and removed fixture fields.
The focused integration tests provide the allocation checks. Full CI does
not run during iteration, as the user requires.

The new comparison first failed because it required equal source header
revisions. The current SQL projection stamps every changed source with the
last revision of its projection group. The native source header uses that
source's actual last raw or coverage commit. The corrected new case checks
native revisions exactly: source `a` is 4, source `b` is 2, and unrelated context
admission advances the captured head to 5. The current projection revision
must be between the native source revision and that head. Arrow rows, consumed
positions, source receipts, gaps, coverage, witnesses, and references keep their
equality assertions. The original incident test is unchanged.

The rebuilt release PoC passes its unchanged combined and stable workloads.
Combined checks cover 64 cycles and 128 historical views, with zero unavailable
views. Stable checks cover 128 primary cycles, 640 historical evaluations, and
320 historical views. No view is unsupported after reopen. Both existing
summary scripts accept the reports. These runs check correctness; they are
not paired performance comparisons. The report's existing `unrecorded` source
label is supplemented by the external source hashes and frozen binary identity.

## Unchanged incident

The exact `discovery::packages::required::incident::incremental::follows_incremental_sources`
test passes: one pass, 694 filtered cases, and no changed workload, assertion,
definition, or timeout. The harness takes **17.59 seconds**. Process time is
**17.635150 seconds**. The existing boundary parser checks 18 collector receipts,
three first durable creations, and their actual incident input revisions.

| Episode | Collector receipt to creation | Committed input to creation | Graph publication to creation | Public notification receipt |
| --- | ---: | ---: | ---: | ---: |
| 1 | 568.371 ms | 553.224 ms | 105.346 ms | 612.875 ms |
| 2 | 1,055.229 ms | 1,040.016 ms | 178.337 ms | 1,125.396 ms |
| 3 | 1,048.703 ms | 1,042.853 ms | 157.364 ms | 1,150.901 ms |

Bulk completion for 16,384 background logical records takes 2.443701 seconds.
This is one correctness qualification of the shared extraction code. Production
still uses DuckDB. The binary uses optimization level 0, debug information
level 2, and debug assertions. No paired release comparison or performance
improvement is established. The source record identifies the build, retained
binary, process, raw log, and checked boundary report. No build runs during
the incident execution. The sub-100 ms and 100-fold targets remain **Not done**.

## Remaining work

Managed capture sealing, prior-result restore, attempts, result/checkpoint
publication, atomic consumed progress, production providers, and original-log
routing remain **Not done**. Requested unported table owners return
`Unsupported`; they do not return empty success.

The source-header and gap checks still scan source range metadata. This result
does not establish indexed steady-state performance. Native retention has no
mutation API yet; expired and removed raw ranges are not qualified here.
Configured capacity, retention, backup, and complete Graph recovery remain
**Not done**. Production still uses DuckDB. No sub-100 ms or 100-fold result
is established.
