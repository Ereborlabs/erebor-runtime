# Native execution performance handoff

## Compiled component reuse result, 2026-11-05

The existing Wasm code cache now identifies one admitted implementation across
its exports. `model_code` first selects the requested export's implementation.
It uses that implementation's first declared export only for the cache key.
The bundle digest and package identity remain in the key. Distinct Wasm
implementations cannot share this export in an admitted package. Raw-byte
cache behavior, compiler admission, resource checks, charging, and eviction
keep their existing owners. There is no new cache or serialized code archive.

Prepared calls and evaluations retain their actual export. Package admission,
Graph access, transaction staging, and Data commit keep their existing owners.
The test-only cache inspection API now takes the admitted bundle and uses the
same selector. Its callers retain the same assertions. The exact incident test
and its workload, limits, and timeouts are unchanged.

The diagnostic exact test passes in 33.39 seconds. It compiles the same
4,882,989-byte component twice. Cold preparation takes 2.230095 seconds for
`index` and 2.435177 seconds for `detect`. `Component::new` accounts for
2.104438 and 2.305019 seconds. The enclosing physical-planning timer includes
this preparation. It does not measure DataFusion planning alone.

The final focused build passes in 208.008811 seconds. A preceding exact run
passes in 29.61 seconds and records one compilation. That single test time is
not a speed comparison. Five alternating pairs then run the unchanged exact
incident test. All ten runs pass.

| Pair | First executable | Baseline test, seconds | Shared component test, seconds | Process time saved, seconds |
| --- | --- | ---: | ---: | ---: |
| 1 | Baseline | 33.22 | 30.61 | +2.6150 |
| 2 | Shared component | 33.41 | 30.49 | +2.9199 |
| 3 | Baseline | 33.72 | 31.31 | +2.4177 |
| 4 | Shared component | 34.00 | 31.16 | +2.8525 |
| 5 | Baseline | 34.20 | 31.59 | +2.6075 |

All five whole-process comparisons are lower. The paired median saving is
2.614963 seconds, or 7.86 percent. The paired reduction ranges from 7.16 to
8.73 percent. Every baseline compiles `index` and `detect`; every candidate
compiles one shared component. Summed cold preparation has medians of
4.515685 and 2.264546 seconds. Its paired median reduction is 49.87 percent.
The enclosing physical-planning totals have medians of 5.399321 and
3.164047 seconds. These nested costs are not added to the whole-test saving.
The statistical units are five paired run totals. Initial, warm, and bulk
differences are mixed. No separate notification or bulk gain is claimed.

Every run retains 16,402 public records, five managed publications, three
source-change restart mentions, 61 authority checks, and twelve Graph append
batches. Graph apply work, projection result IDs, and publication cut/revision
pairs are equal in every pair. Bulk work stays at 64 pages, 16,384 rows,
60 retained pages, 262,144 physical frame rows, and 53,401,792 body bytes.
No source edit, build, debugger, or other test runs during the comparison.

Result: **Done** for shared component compilation and this comparison.
Millisecond notification latency and the 100-fold target remain **Not done**.
Full CI and other test cases were not run. Finite cache pressure, distinct
implementation selection, and the migrated inspection tests have source review
only under this qualification.

The capture probes also separate coordinator admission, snapshot metadata,
selection, source setup, trace setup, raw work, and the remaining work. Source
setup includes the extraction envelope, replay floor, managed capture, source
receipts, gaps, raw state, and coverage. It is not a pure receipt query timer.
The next capture investigation must separate those owners before replacement.
Unexecuted probe stages remain zero. Initial preflight work remains in the
complete elapsed time only. Overlapping capture spans are not added as a
whole-test saving. No storage engine change is selected.

Proof: `/tmp/araphor-build-component-reuse-20261105-a.log`,
`/tmp/araphor-live-component-reuse-20261105-a.log`, and
`/tmp/araphor-component-reuse-pairs-20261105/{settings,results,summary}.json`,
with ten run logs. Baseline: `907cedb4a` plus the reviewed capture and component
timing probes and the standard telemetry dependency. Its patch is
`/tmp/araphor-capture-phases-baseline-20261105.patch`. Retained executables are
`target/araphor-notice-comparison-20261105/capture-phases` and
`component-reuse`. Earlier executables were removed for space; logs remain.
The diagnostic build passes in 251.793178 seconds. Its first build failed
because the runtime crate did not declare the telemetry dependency. The final
source uses the repository telemetry owner.

## Native finding publication result, 2026-11-05

Data now uses one read-scoped Arrow property dictionary for finding
publication. It replaces the old finding conflict query, missing-map query,
and canonical-value INSERT query. Araphor Graph supplies all actual property
rows and the added and closed members from its existing pending-layer guard.
These generic APIs contain no package or finding rules. Data owns the fixed
finding protocol and actual emitted IDs. Native Arrow sort and partition
kernels group complete values. There is no new execution runtime, persistent
cache, finding-value DTO decode, or serialized value archive.

The dictionary includes property-only rows. Equality uses `properties.value`
and excludes the anchor. Current conflicts include every alias of each
changed tenant/finding ID, including IDs from closed members. Mapping applies
only to current rows opened at this publication revision that lack a mapping.
Candidates retain the existing order: effective canonical property reference,
then candidate relation. Output uses the existing canonical relation/reference
when present. The recognized finding schema has no float leaves. Its declared
reason details remain binary IPC. No general float-equality result is claimed.
The pending guard remains armed through Data commit. Existing relationship
publication and transaction rollback keep their owners. Existing preparation
reservations cover the new scratch. Exact-coordinate deduplication limits
conflict materialization; the original current rows retain mapping eligibility.

The final focused build passes in 254.975033 seconds. Five alternating pairs
run the unchanged exact incident test. All ten runs pass with 16,402 records,
five managed publications, three source-change restart mentions, 61 authority
checks, and twelve Graph append batches per run. Projection result IDs,
publication cut/revision pairs, and Graph apply work are equal in every pair.
No source edit, build, debugger, or other test runs during the comparison.

| Pair | First executable | Baseline test, seconds | Native dictionary test, seconds | Process time saved, seconds |
| --- | --- | ---: | ---: | ---: |
| 1 | Baseline | 33.12 | 32.80 | +0.3205 |
| 2 | Native dictionary | 34.44 | 33.11 | +1.3274 |
| 3 | Baseline | 35.10 | 34.35 | +0.7561 |
| 4 | Native dictionary | 34.84 | 33.71 | +1.1300 |
| 5 | Baseline | 34.73 | 33.61 | +1.1237 |

All five pairs are faster. The paired whole-process median is 1.123713 seconds
lower, or 3.23 percent. The paired reduction ranges from 0.97 to 3.85 percent.
Both warm notification intervals are lower in every pair. Their medians fall
from 4.068349 to 3.861763 seconds and from 4.503582 to 4.299611 seconds.
Initial differences are mixed. Bulk intervals are lower by 0.07 to 0.21 seconds;
no large separate bulk gain is claimed. Notification capture counts are
24/25, 24/24, 25/24, 24/25, and 26/24 for baseline/candidate.

All 25 matched complete projection spans are lower. Summed projection time
has medians of 1.059270 and 0.246690 seconds, with a paired median reduction
of 77.26 percent. Complete Graph publication medians are 1.181071 and
0.369012 seconds, with a paired median reduction of 68.78 percent. These
child costs are not added to the whole-process saving. The statistical units
are five paired run totals. The old `findings_s` field measures one conflict
query; the new field measures the complete dictionary. Only complete
projection/publication boundaries are compared across these implementations.

Both variants retain the same 64 bulk pages, 16,384 bulk rows, 60 retained
pages, 262,144 physical frame rows, and 53,401,792 body bytes. Raw capture
and raw-read differences are mixed. No separate raw-read gain is claimed.
Result: **Done** for the finding publication replacement and this focused
comparison. Millisecond notification latency and the 100-fold target remain
**Not done**. Full CI and other test targets were not run. Property-only,
null, cross-relation canonical, rollback, recovery, and finite-budget edge
cases have source review only under this qualification.

Proof: `/tmp/araphor-build-finding-dictionary-20261105-a.log` and
`/tmp/araphor-finding-dictionary-pairs-20261105/{settings,results,summary}.json`,
with ten run logs in that directory. The baseline is `d694c9882` plus the
reviewed timing fields in
`/tmp/araphor-graph-publication-timing-baseline-20261105.patch`. Retained
executables are `target/araphor-notice-comparison-20261105/graph-publication-timing`
and `finding-dictionary`. Earlier executables were removed to free space;
logs and source records remain. The preceding exact test passes in 32.33
seconds. That single run is not a speed comparison.

The diagnostic build passes in 242.581530 seconds, and its exact test passes
in 33.93 seconds. Its publication projection totals 1.039943 seconds:
0.424933 seconds for finding conflicts, 0.096943 seconds for the missing-map
probe, and 0.517978 seconds for canonical insertion. Native layer preparation
totals 0.435063 seconds. This attribution selected the replaced owner. The
next investigation must use the remaining measured Graph costs; no storage
engine change is selected here.


## Bounded append reader result, 2026-11-05

Each Append Runtime now owns a Data reader with a resolved source header and
one immutable journal range. Fresh page evaluations use the saved native
DataFusion plan and the existing 256-row input boundary. One raw scanner serves
ordinary and retained reads. It seeks from the emitted output position, so a
partial output page does not skip captured rows. Data opens a short read for
current store metadata, replay floor, and trace read authority. Its maintenance
lease remains active through Arrow construction. DataFusion reservations cover
retained metadata before allocation. Finite input limits keep their existing
admission path.

Retention applies to projected events and trace-output requests. A changed
selection, projection, event range, or journal range opens the ordinary read
boundary. Mixed, measurement, and header-only requests use the ordinary reader.
These fallbacks add no error. The reader retains no frame bodies or database
connection. The old raw loop is removed from the extraction owner.

The final focused build passes in 210.750102 seconds. Five alternating pairs
run the unchanged exact incident test. All ten runs pass with 16,402 records,
five managed publications, three source-change restart mentions, 61 authority
checks, and twelve Graph append batches per run. Matched Graph apply revisions,
writers, inserted rows, and closed rows are equal in every pair. No source edit,
build, debugger, or other test runs during the comparison.

| Pair | First executable | Baseline test, seconds | Retained reader test, seconds | Process time saved, seconds |
| --- | --- | ---: | ---: | ---: |
| 1 | Baseline | 36.54 | 34.68 | +1.8546 |
| 2 | Retained reader | 37.68 | 34.93 | +2.7460 |
| 3 | Baseline | 37.32 | 35.02 | +2.3037 |
| 4 | Retained reader | 37.70 | 34.92 | +2.7749 |
| 5 | Baseline | 37.95 | 35.15 | +2.8058 |

All five pairs are faster. The paired whole-process median is 2.745986 seconds
lower, or 7.28 percent. The paired reduction ranges from 5.07 to 7.38 percent.
The complete bulk interval is lower in every pair. Its medians are 7.503524
and 4.756654 seconds; its paired median reduction is 36.35 percent. Initial
and warm notification differences are mixed. No separate arrival gain or tail
latency result is claimed. Notification capture counts are 25/25, 25/22, 25/25,
25/25, and 24/24 for baseline/candidate.

Each bulk interval still reads 64 pages and emits 16,384 rows. Each candidate
uses the retained reader for 60 pages; each baseline uses it for zero pages.
Summed capture time has medians of 6.305653 and 1.491186 seconds. Its paired
median reduction is 76.05 percent. The statistical units are the five paired
run totals, not the 64 pages. Physical work stays at 262,144 frame rows and
53,401,792 body bytes per run. Summed raw-read medians are 0.356238 and
0.383343 seconds. There is no raw-frame read gain. Capture and bulk intervals
overlap other work; their savings are not added to the whole-process saving.

Result: **Done** for the bounded reader and this focused comparison.
Millisecond notification latency and the 100-fold target remain **Not done**.
Full CI and other test targets were not run. Bounded-memory, trace-output,
retention, cancellation, and mixed-request fallback cases have source review
only under this qualification.

Proof: `/tmp/araphor-build-append-reader-20261105-c.log` and
`/tmp/araphor-append-reader-pairs-20261105/{settings,results,summary}.json`,
with ten run logs in that directory. The baseline is `b065516ba` plus seven
capture timing lines. Its patch is
`/tmp/araphor-append-capture-timing-baseline-20261105.patch`. Retained executables
are `target/araphor-notice-comparison-20261105/append-capture-timing` and
`append-reader`. Earlier executables were removed to free space; logs remain.
The preceding exact test passes in 34.75 seconds. That single run is not a
speed comparison. An earlier draft failed with `InputTooLarge` in 12.80
seconds because unlimited input starts with a zero-byte reservation. The
final reader grows that native reservation before transfer. The test and its
limits were not changed.

The diagnostic records five managed commits with 5.289147 seconds of total
elapsed work. Their transaction work is 3.292142 seconds and preparation is
1.553976 seconds. These are nested totals, not one notification interval.
The next investigation must isolate the largest remaining Graph publication
owner before another replacement.


## Source index continuation result, 2026-11-05

The managed subscription now transfers its committed SourceIndex through the
existing source recovery handle. Host first cancels and joins the failed
subscription, checks its owner, and waits for the existing recovery signal.
The next subscription uses the index only with the same Memory owner and the
same saved native physical plan. Independent planning, a different memory
owner, or a fresh rebuild uses cold restoration. These choices add no error
or admission rule. DataFusion plan resets retain the source key identities.

The transfer contains the existing committed Arrow buffers, indexes, and their
reservations. Failed source views, package call contexts, attempts, Graph
resources, and operation controls keep their existing cleanup path. Existing
source scope, parent, projection, call receipt, retention, and commit checks
remain. There is no new cache, archive, serialized input, or polling path.

The final focused build passes in 201.408305 seconds. Five alternating pairs
run the unchanged exact incident test. All ten runs pass with 16,402 records,
five managed publications, three source-change restart mentions, 61 authority
checks, and twelve Graph append batches per run. Matched Graph apply revision,
writer, inserted-row, and closed-row counts are equal in every pair. No source
edit, build, debugger, or other test runs during the comparison.

| Pair | First executable | Baseline test, seconds | Continued index test, seconds | Process time saved, seconds |
| --- | --- | ---: | ---: | ---: |
| 1 | Baseline | 38.59 | 36.80 | +1.7859 |
| 2 | Continued index | 39.90 | 37.10 | +2.7969 |
| 3 | Baseline | 39.63 | 37.54 | +2.0964 |
| 4 | Continued index | 39.26 | 37.10 | +2.1669 |
| 5 | Baseline | 39.34 | 37.85 | +1.4886 |

The paired whole-process median is 2.0964 seconds lower, or 5.28 percent.
All five pairs are faster. The paired reduction ranges from 3.78 to 7.00
percent. Both warm notification arrivals are lower in every pair. Their
medians fall from 5.155959 to 4.047017 seconds and from 5.530882 to 4.458398
seconds. Initial and bulk differences are mixed; no separate gain is claimed.
Notification capture counts are 26/25, 25/25, 25/25, 25/25, and 25/24 for
baseline/candidate. These five pairs do not establish tail latency.

Every baseline run restores three source points and reads 32,852 restored
frame rows. These rows include all restored datasets, not only raw events.
The median summed restoration time is 2.769270 seconds. Every candidate run
has zero cold restorations. This child cost is not added to the whole-test
saving. The existing three source-change restarts still occur.

Result: **Done** for source index continuation and this focused comparison.
Millisecond notification latency and the 100-fold target remain **Not done**.
Full CI and other test targets were not run. Independent-plan and rebuild
fallbacks, cancellation, and the other recovery callers have source review
only under this qualification.

Proof: `/tmp/araphor-build-source-continuation-20261105-a.log` and
`/tmp/araphor-source-continuation-pairs-20261105/{settings,results,summary}.json`,
with ten run logs in that directory. The baseline is `414538360` plus the
reviewed restoration timing fields. Its patch is
`/tmp/araphor-source-restore-timing-baseline-20261105.patch`. Retained executables
are `target/araphor-notice-comparison-20261105/source-restore-timing` and
`source-continuation`. Older executables were removed to free space; logs
remain. The preceding diagnostic build passes in 198.647779 seconds, and its
exact test passes in 38.06 seconds. That single run is not a speed comparison.

The next investigation is repeated snapshot and journal frame work for the
256-row event pages in the bulk interval. No page replacement is implemented
or qualified here.


## Graph dictionary batch result, 2026-11-05

Araphor Graph now resolves owners, entities, endpoints, and labels across all
prepared rows in one transaction batch per dictionary kind. Public intern APIs
use the same core. The two old insert implementations are removed. Existing
tables, sequences, namespaces, scope checks, and ordinal/count checks remain.
Borrowed key groups exist only during interning. Owned ID vectors and ranges
end with apply. Existing Scratch accounting precedes allocation, and its
cancellation check follows each group during import and result processing.
Data still commits or rolls back the only durable transaction.

The final focused build passes in 247.593942 seconds. Five alternating pairs
run the unchanged exact incident test. All ten runs pass with 16,402 records,
five managed publications, three source-change restart mentions, 61 authority
checks, and twelve append batches per run. The five matched apply spans have
identical revision, writer, inserted-row, and closed-row counts in every pair.
No source edit, build, debugger, or other test runs during the comparison.

| Pair | First executable | Baseline test, seconds | Batched dictionary test, seconds | Process time saved, seconds |
| --- | --- | ---: | ---: | ---: |
| 1 | Baseline | 38.46 | 38.69 | -0.2238 |
| 2 | Batched dictionary | 39.93 | 39.31 | +0.6231 |
| 3 | Baseline | 40.45 | 39.78 | +0.6837 |
| 4 | Batched dictionary | 39.60 | 40.13 | -0.5217 |
| 5 | Baseline | 39.60 | 39.74 | -0.1372 |

Whole-process time has a paired median increase of 0.1372 seconds, or 0.35
percent. Three pairs are slower and two are faster. The paired reduction ranges
from -1.32 to +1.69 percent. These mixed and small differences establish no
overall gain or regression. Notification capture counts are 24/25, 25/23,
26/25, 25/25, and 25/25 for baseline/candidate. No separate arrival or bulk gain
is claimed.

All 25 matched Graph apply spans are lower. The paired reductions in summed
apply time are 27.14, 28.13, 27.12, 27.29, and 26.99 percent. Their median is
27.14 percent. The final apply median falls from 332.529 to 233.842 milliseconds.
The median summed dictionary time falls from 652.738 to 286.903 milliseconds,
a 56.05 percent reduction. These child spans do not establish a whole-test gain.

The baseline measures dictionaries inside relation appends. The candidate
measures the batch before those appends with `dictionaries_s`. Its apply
`members_s` excludes that batch. The complete apply elapsed boundary and log
filters are the same. Do not compare the candidate's `members_s` alone with
the baseline's value. The complete apply spans include property writes, member
writes, endpoint validation, native index seal, and existing control checks.

Result: **Done** for the dictionary replacement and this focused comparison.
The retained change has direct Graph apply evidence. Millisecond notification
latency and the 100-fold target remain **Not done**. Full CI and other test
targets were not run. Public empty-group, rollback, and reopen behavior have
source review only under this qualification.

Proof: `/tmp/araphor-build-graph-dictionaries-20261105-a.log` and
`/tmp/araphor-graph-dictionary-pairs-20261105/{settings,results,summary}.json`,
with ten run logs in that directory. The baseline is `6fc96adc9` plus the
reviewed Graph timing fields. Its patch is
`/tmp/araphor-graph-apply-timing-baseline-20261105.patch`. Retained executables
are `target/araphor-notice-comparison-20261105/graph-apply-timing` and
`graph-dictionaries`. Older comparison executables were removed to free space;
their logs remain. The preceding diagnostic build passes in 249.596766 seconds,
and its exact test passes in 38.23 seconds. That single run is not a speed
comparison.

The next investigation is cold SourceIndex restoration after a subscription
retry. The log shows a read of 16,396 historical event rows before the six-row
current capture. This read precedes BeforeReplay. The complete restore cost
is not isolated. No retry handoff change is implemented or qualified here.


## Source freshness reader result, 2026-11-05

Data now reads the requested relation versions once in each freshness check.
The old path issued one query per captured source. The replacement uses one
query in the same database snapshot, then compares the original captured pairs
in their original order. Missing versions remain zero. Duplicate pairs and
cancellation checks retain their behavior. The Graph follow bypass and the
source-change versus trace-conflict decisions remain at their existing callers.
There is no validation cache across snapshots.

The final focused build passes in 239.192546 seconds. Five alternating pairs
run the unchanged exact incident test with identical authority timing fields.
All ten runs pass with 16,402 records, five managed publications, three
source-change restart mentions, and 61 authority checks per run. No source edit,
build, debugger, or other test runs during the comparison.

| Pair | First executable | Baseline test, seconds | Batched source test, seconds | Process time saved, seconds |
| --- | --- | ---: | ---: | ---: |
| 1 | Baseline | 38.57 | 38.82 | -0.2471 |
| 2 | Batched source | 40.84 | 39.12 | +1.7292 |
| 3 | Baseline | 41.13 | 40.08 | +1.0470 |
| 4 | Batched source | 41.26 | 40.17 | +1.0853 |
| 5 | Baseline | 41.28 | 40.42 | +0.8559 |

The paired whole-test median is 1.0470 seconds lower, or 2.54 percent. Four
pairs are faster and one is slower. The paired reduction ranges from -0.64 to
+4.23 percent. This small sample does not establish a certain overall gain.
Notification capture counts are 25/24, 25/23, 26/25, 25/25, and 25/25 for
baseline/candidate. No separate bulk gain is claimed.

Each warm notification arrival is lower in its matched pair. The second
notification median falls from 5.532953 to 5.231377 seconds. The third falls
from 5.932907 to 5.685007 seconds. The initial median is 3.419560 versus
3.197956 seconds, but the final pair differs by only 5.2 milliseconds.
Bulk medians are 7.679154 versus 7.575193 seconds.

In the final index call, the median source/trace validation time falls from
238.994 to 82.294 milliseconds. Complete authority validation falls from
395.672 to 256.803 milliseconds. Each version performs twelve checks there.
These spans are children of package execution; do not add them to its time.
The diagnostic run and all paired runs have no captured context or dependency
checks in this owner. A context-validation rewrite is not supported by this
case's measurements.

Result: **Done** for source-version batching and this comparison. The direct
validation cost is lower. Millisecond latency and the 100-fold target remain
**Not done**. Full CI and other test targets were not run. Other freshness
callers and the existing recovery, backup, and retention limits have source
review only under this qualification.

Proof: `/tmp/araphor-build-source-versions-20261105-a.log` and
`/tmp/araphor-source-versions-pairs-20261105/{settings,results,summary}.json`,
with ten run logs in that directory. The baseline is `a2cb8bd9b` plus the
reviewed authority timing fields. Its patch is
`/tmp/araphor-authority-timing-baseline-20261105.patch`. The retained executables
are `target/araphor-notice-comparison-20261105/authority-timing` and
`source-versions`. Older comparison executables were removed to free link space;
their logs remain. The preceding diagnostic build passes in 237.211338 seconds,
and its exact test passes in 39.98 seconds. That single run is not a speed
comparison.


## Graph origin preparation result, 2026-11-05

Graph preparation now shares one committed `OwnerRead` across its journals.
The runtime origin path no longer reconstructs immutable producer contracts.
Origin identity, requested scope, selected instance, actual call, live witness
pins, reference equality, and final parent/origin/disclosure checks retain
their behavior. Profile replay and recovery keep their existing full validator.

The final focused build passes in 239.029790 seconds. Five alternating pairs
run the unchanged exact incident test with identical preparation timing fields.
All ten runs pass with 16,402 records, five managed publications, and three
source-change restart mentions per run. No source edit, build, debugger, or
other test runs during the comparison.

| Pair | First executable | Baseline test, seconds | Native origin test, seconds | Process time saved, seconds |
| --- | --- | ---: | ---: | ---: |
| 1 | Baseline | 37.59 | 39.24 | -1.6496 |
| 2 | Native origin | 40.55 | 39.46 | +1.0951 |
| 3 | Baseline | 41.04 | 40.73 | +0.3134 |
| 4 | Native origin | 40.87 | 40.72 | +0.1506 |
| 5 | Baseline | 41.01 | 40.41 | +0.6043 |

The whole-test paired median is 0.3134 seconds lower, or 0.76 percent.
The paired reduction ranges from -4.38 to +2.70 percent. These mixed and small
results do not establish an overall gain or regression. Capture counts are
25/23, 25/25, 25/24, 25/25, and 25/25 for baseline/candidate.
No separate arrival or bulk gain is claimed.

Every nonzero origin loop is faster in its matched pair. In the last warm
episode, its median falls from 254.104 to 105.720 milliseconds, a 58.4 percent
reduction. The median complete prewriter preparation falls from 574.387 to
432.947 milliseconds, a 24.6 percent reduction. Origin timing is part of Graph
preparation timing. Do not add it to that parent span. The retained change
has direct evidence for this boundary; it has no established whole-test gain.

Result: **Done** for native origin preparation and this comparison.
Millisecond notification latency and the 100-fold target remain **Not done**.
Full CI and the legacy Data library-test target were not run. The preceding
recovery, backup, and retention runtime qualification limits still apply.
The next named cost is Graph work inside final publication. One final warm
transaction spends about 677 milliseconds in Graph journals and publication,
including about 353 milliseconds in Graph layer application and 263 milliseconds
in Data publication. Those included spans must not be added twice.

Proof: `/tmp/araphor-build-native-origin-20261105-a.log` and
`/tmp/araphor-native-origin-pairs-20261105/{settings,results,summary}.json`,
with ten run logs in that directory. The baseline is `9731f1cc2` plus the same
reviewed preparation timing fields. The retained executables are
`target/araphor-notice-comparison-20261105/publication-timing` and `native-origin`.
Older completed comparison executables were removed to free link space;
all paired logs remain. Diagnostic build A failed at link while the disk was
full. The unchanged diagnostic build B passed after cleanup, and its single
38.49-second test run is not a speedup comparison.


## Committed authority reader result, 2026-11-05

Data now retains the final typed selected-result and call metadata at commit.
`OwnerRead` uses those handles after the existing tenant, processor, result,
and revision query proves visibility in its database snapshot. It no longer
decodes and reconstructs the immutable contracts. Existing scope checks stay
at their callers. Selected-result and actual-call witness checks still run
once per reader. Missing evidence pins remain permitted only after their saved
expiry according to the database snapshot clock.

The final focused build passes in 252.818794 seconds. Three alternating pairs
run the unchanged exact incident test. All six runs pass with 16,402 records,
five managed publications, and three source-change restart mentions per run.
No source edit, build, debugger, or other test runs during the comparison.

| Pair | First executable | Shared reader test, seconds | Committed authority test, seconds | Process reduction |
| --- | --- | ---: | ---: | ---: |
| 1 | Shared reader | 44.10 | 40.48 | 8.20 percent |
| 2 | Committed authority | 46.06 | 40.78 | 11.44 percent |
| 3 | Shared reader | 46.12 | 41.33 | 10.35 percent |

The median paired reduction is 10.35 percent, or 4.7792 seconds. All three
pairs also have lower initial and warm arrival times. The median measurements
are:

| Boundary | Shared reader, seconds | Committed authority, seconds |
| --- | ---: | ---: |
| Initial notification | 3.988862 | 3.393343 |
| Background records to package publication | 7.611097 | 7.469857 |
| Second notification | 6.558421 | 5.601720 |
| Third notification | 7.412637 | 6.117422 |

The bulk difference is small and does not establish a separate bulk gain.
Notification capture counts are 24/26, 24/25, and 23/25 for baseline/candidate.
Median summed capture time falls from 7.664434 to 3.310242 seconds. These child
spans can overlap other work; do not add them to wall time. The sample provides
no confidence-interval or p99 claim.

The commit owner moves the actual final Step and Record values after proof
assignment and SQL insertion. It retains no checkpoint, input/output batch,
journal, or preparation reservation. Data seals the handles before database
COMMIT. Failure removes them before writer release. Successful COMMIT keeps
them before the revision wake. Initial open restores typed handles after the
existing full recovery validation. Explicit recovery replaces both native
owners before readers reopen. Backup reopening also restores Graph registration
on the new connection. Immutable validation remains in recovery and other
existing integrity owners. This change adds no new policy, validation rule,
limit, subscription, timeout, workload, or durable archive.

Result: **Done** for committed authority ownership and this comparison.
Millisecond latency and the 100-fold target remain **Not done**. Full CI and
the legacy Data library-test target were not run. Recovery, backup, and retention
transitions have source review only; this append test does not qualify them.
The next measured delivery cost is final preparation plus commit, approximately
1.5 seconds in the last warm episode. Its preparation substeps need separate
timing before another rewrite is selected.

Proof: `/tmp/araphor-build-committed-owners-20261105-b.log` and
`/tmp/araphor-committed-owner-pairs-20261105/{settings,results,summary}.json`,
with six run logs in that directory. Baseline source is `e13642aae`.
The retained executables are
`target/araphor-notice-comparison-20261105/shared-owner` and `committed-owners`.
The older `4fb390924` comparison executable was removed to free build space.
Its paired logs remain available. The `native-layers` executable is retained.


## Standalone finding reader result, 2026-11-05

Each public finding read now uses one `OwnerRead` for its database snapshot.
Current heads, publication authority, finding values, and provenance use that
owner. Batch and history reads also share it across their requested results.
The replaced fresh-owner wrappers are removed. The external extraction helper
keeps its existing lifetime. Package execution, subscription capture, proof
checks, reference checks, legacy behavior, and errors retain their behavior.

The final focused build passes in 240.437556 seconds. Five alternating pairs
run the unchanged exact incident test. All ten runs pass with 16,402 records,
five managed publications, and three source-change restart mentions per run.
No source edit, build, debugger, or other test runs during the comparison.

| Pair | First executable | Native reader test, seconds | Shared owner test, seconds | Process time saved, seconds |
| --- | --- | ---: | ---: | ---: |
| 1 | Native reader | 46.31 | 45.89 | 0.4246 |
| 2 | Shared owner | 47.54 | 46.36 | 1.1829 |
| 3 | Native reader | 47.80 | 46.40 | 1.3979 |
| 4 | Shared owner | 47.22 | 45.01 | 2.2078 |
| 5 | Native reader | 47.31 | 46.46 | 0.8499 |

Every pair has lower candidate process time. The median paired reduction is
2.49 percent, or 1.1829 seconds. The reduction ranges from 0.92 to 4.67 percent.
This supports a modest standalone read improvement. The small sample provides
no confidence-interval or p99 claim. Pair 1 has 23 baseline notification
captures and 25 candidate captures. All other runs have 24 captures.

Median arrival times are 4.011697 versus 4.002755 seconds initially,
6.584442 versus 6.591742 seconds for the second notification, and 7.541165
versus 7.432977 seconds for the third. Median bulk time is 7.548405 versus
7.585560 seconds. These differences do not establish an arrival or bulk gain.
Complete test time includes standalone point and history verification.

Result: **Done** for shared finding read ownership and this comparison.
Millisecond latency and the 100-fold target remain **Not done**. Full CI and
the legacy Data library-test target were not run, as in the preceding record.

Proof: `/tmp/araphor-build-shared-finding-owner-20261105-b.log` and
`/tmp/araphor-shared-owner-pairs-20261105/{settings,results,summary}.json`,
with ten run logs in that directory. The baseline source is `6b59e7767`.
The retained executables are
`target/araphor-notice-comparison-20261105/native-layers` and `shared-owner`.


## Native Graph reader result, 2026-11-05

The final focused build passes in 258.773250 seconds. Three alternating pairs
run the unchanged exact incident test with the same debug profile and log
filters. All six runs pass with all 16,402 records. Every run has five managed
publications, 24 notification captures, and three source-change restart mentions.
No source edit, build, debugger, or other test runs during the comparison.

| Pair | First executable | Baseline test, seconds | Native reader test, seconds | Process time reduction |
| --- | --- | ---: | ---: | ---: |
| 1 | Baseline | 70.51 | 47.62 | 32.45 percent |
| 2 | Native reader | 71.87 | 47.68 | 33.64 percent |
| 3 | Baseline | 71.87 | 47.44 | 33.98 percent |

The median paired speed factor is 1.507. This result supports a gain for this
complete rewrite. It does not provide a confidence-interval or p99 claim.
The median arrival measurements are:

| Boundary | Baseline, seconds | Native reader, seconds |
| --- | ---: | ---: |
| Initial notification | 6.070693 | 3.992181 |
| Background records to package publication | 7.812768 | 7.644887 |
| Second notification | 8.983028 | 6.717021 |
| Third notification | 9.847955 | 7.609041 |

The background difference is small. It does not establish a separate gain for
bulk intake. Complete test time includes point and history verification after
notification arrival. Do not attribute its full reduction to delivery latency.
The earlier 45.74-second run is diagnostic. It precedes the final cancellation
correction and is excluded from the paired result.

`araphor-graph` now owns shared native Arrow property batches, member row
addresses, keyed adjacency indexes, and historical visibility intervals.
Package reads and presence checks use those indexes. Data finding reads,
notification scalars, extraction, provenance, and retained domain reads use
the same members. The former wide finding reconstruction helper is removed.
Data still owns publication pins, producers, grants, and canonical finding
value identities. The Graph engine has no package or incident rules.

Data seals native additions and closes before database COMMIT. Readers select
them through database snapshot writer heads. Failure removes the tentative
additions and closes before the writer is released. Successful Data COMMIT
disarms that cleanup, then publishes the existing revision signal. Installation
restores native rows once from the existing validated durable Graph tables.
The native owner retains Graph state, not inputs, outputs, journals, attempts,
or preparation scratch. Arrow take selects result rows. No new subscription,
validation rule, limit, timeout, workload, or durable archive is added.

The existing raw legacy point fixtures use their unchanged relational keyed
reader. Real-store fixtures pass their store's Graph engine. This changes no
assertion. The legacy Data library-test target and full workspace CI were not
run. Rollback injection and durable restoration have source review only; this
append test does not qualify those runtime cases.

Result: **Done** for the native Graph reader and this paired comparison.
Millisecond latency and the 100-fold target remain **Not done**. The next
source review concerns repeated standalone finding owners during point and
history verification. No further gain is measured or forecast here.

Proof: `/tmp/araphor-build-native-layers-20261105-e.log` and
`/tmp/araphor-native-layer-pairs-20261105/{settings,results,summary}.json`,
with six run logs in that directory. The retained executables are
`target/araphor-notice-comparison-20261105/baseline` and `native-layers`.
The completed key-lookup trial executable was removed to free build space.
Its earlier paired results remain in `/tmp/araphor-notice-pairs-20261105`.


## Paired notification lookup trial, 2026-11-05

Five pairs ran the exact incident test. Each pair ran the baseline and the
candidate in sequence. Pair order alternated. Both executables used the same
debug profile, workload, assertions, timeouts, test arguments, and log filters.
No build, debugger, or other test ran during this comparison. Source files did
not change between runs. All ten runs passed.

The baseline Rust source is commit `4fb390924`. Commit `f7315d20` changes only
documents. The candidate changed only
`crates/araphor-data/src/analysis/extraction/notifications/native.rs`.
It encoded finding IDs from existing notification references as native Graph
keys and joined those keys to member identities. Packages still chose the IDs.
The trial did not change publication, producer, grant, or canonical-value checks.

| Pair | First executable | Baseline test, seconds | Candidate test, seconds | Candidate minus baseline process, seconds |
| --- | --- | ---: | ---: | ---: |
| 1 | Baseline | 71.17 | 73.82 | +2.6454 |
| 2 | Candidate | 75.24 | 75.33 | +0.0830 |
| 3 | Baseline | 75.35 | 75.61 | +0.2663 |
| 4 | Candidate | 76.99 | 76.81 | -0.1869 |
| 5 | Baseline | 76.22 | 76.17 | -0.0446 |

The median paired process difference is +0.0830 seconds, or +0.1103 percent.
Baseline process times range from 71.2083 to 77.0312 seconds. Candidate process
times range from 73.8537 to 76.8443 seconds. This small sample does not establish
a gain or a clear regression. It provides no confidence-interval claim.
Single-run comparisons such as 72.96 versus 77.35 seconds do not establish a
performance change. The 77.35-second run also used diagnostic sampling.
Earlier single-run speed factors in this document are reference ratios only.
They do not prove that the source change caused the timing difference.

Every run has five managed publications and three source-change restart
mentions. Pair 4 has 23 baseline notification captures and 24 candidate
captures. All other runs have 24 captures. Do not treat summed child spans as
a controlled operator comparison or add them to test wall time.

Result: **Not done** for a measured gain. The baseline remains in source.
The candidate has no performance commit. Millisecond latency and the 100-fold
target remain **Not done**.

Proof: `/tmp/araphor-notice-pairs-20261105/settings.json`, `results.json`,
`summary.json`, and the ten run logs in that directory. The executables used
`target/araphor-notice-comparison-20261105/baseline` and `candidate`.


## Rejected managed Follow experiment

A destination-independent Follow mode passed the focused build in 300.542283
seconds. The exact incident test passed in 89.78 seconds (89.834356 seconds
for the process). Initial notification arrival took 6.838329807 seconds.
Later arrival took 11.986557737 and 13.522251567 seconds. Background records
reached publication in 10.532505173 seconds. The workload, assertions, and
timeouts did not change.

The experiment removed three subscription restarts. It increased complete
managed publications from five to eight and notification scalar captures
from 24 to 27. It completed intermediate cuts that the prior freshness guard
had rejected. Removing the restarts did not improve this workload.

Three public Data integration checks passed: both append race windows kept
the old input cut; finite registration rejected a changed source; and Follow
publication rejected a physically retired consumed witness without partial
results, pins, or progress. The legacy Data library-test target did not build.
Its errors include references to the removed Process detector and old Graph
types. The integration result does not qualify that target.

Result: **Rejected** for this performance task. All experiment source and test
changes were removed. The Rust source is restored to commit `4fb390924`.
The current qualified result remains 72.96 seconds. The experiment patch is
`/tmp/araphor-rejected-follow-20261104.patch`. Build and run proof is in
`/tmp/araphor-build-follow-20261104-a.log`,
`/tmp/araphor-live-follow-20261104-a.log`, and
`/tmp/araphor-check-follow-integration-20261104-b.log`.

## Package input result, 2026-11-05

The focused build passes in 263.059719 seconds. The exact incident test passes
with all 16,402 records in 72.96 seconds (73.006447 seconds for the process).
Initial notification arrival takes 6.519495118 seconds. Later arrival takes
8.891147814 and 11.002154184 seconds. Background records reach package
publication in 7.993375462 seconds. The workload, assertions, and timeouts
are unchanged from the preceding passing workload.

The causal index now consumes audit and coverage changes. It uses Graph
adjacency to select affected references. The detector still reads exact
canonical records and checks their coverage. Native SQL and the existing
package execution path remain in use. Package code owns the Graph changes.
Data commits the changes and progress atomically.

At the same bulk publication, index evidence pins fall from 16,384 to zero.
Detector pins fall from 16,396 to 12. The conservative live reservation in
`PreparedMemory` falls from 380,210,812 to 22,796,472 bytes, a 16.68-fold
reduction. This value is charged retention, not measured heap use or RSS.
The matched managed commit takes 1.1491 seconds, compared with 2.3882 seconds.
These samples do not show that removed inputs caused every timing difference.

The full test is 1.48 times faster than the first passing 108.11-second run.
The third arrival is 1.91 times faster than the first passing
21.057280225-second arrival. The complete test improves from the preceding
75.14-second run to 72.96 seconds. Millisecond latency and the 100-fold target
remain **Not done**. Nonprefix retirement, recovery, source absence, and
re-registration have source review only; this append test does not qualify
those runtime boundaries.

Proof: `/tmp/araphor-build-audit-input-20261105-a.log` and
`/tmp/araphor-live-audit-input-20261105-a.log`.

Result: **Done** for the package input replacement and this focused passing
comparison. Earlier edits have no exact saved intermediate source trees.
The current passing tree is one checkpoint. Each subsequent improvement must
have its own measured result and commit.

## Shared Graph reader result, 2026-11-05

The focused build passes in 222.141052 seconds. The exact incident test passes
with all 16,402 records in 75.14 seconds (75.186893 seconds for the process).
Initial notification arrival takes 5.256934836 seconds. Later arrival takes
12.411722364 and 11.344435649 seconds. Background records reach package
publication in 10.194023103 seconds. The workload, assertions, and timeouts
are unchanged.

Each Data read now uses one `OwnerRead` for selected owners, actual producers,
publication proofs, and tenant relation SQL. Graph extraction, notification
scalars, and provenance use that owner in the same read transaction. The router
uses its existing bounded owner for heads, values, comparisons, and basis reads.
The replacement removes fresh origin/provenance owner helpers, repeated grant
copies, and a duplicate context-pin temporary table. Producer validation still
checks exact pins and canonical contexts. Requested records, coverage, parent
evidence, scope checks, and live authority checks remain.

The run has 23 notification scalar captures with 9.684 seconds of summed child
time. The prior header-read run has 23 with 19.411 seconds. Other stages also
vary between runs. These child times can overlap and must not be added to the
complete test time. The full result is 1.44 times faster than the first passing
108.11-second workload. The third arrival is 1.86 times faster than the first
passing 21.057280225-second result. This result does not establish a 100-fold
gain or millisecond latency.

Proof: `/tmp/araphor-build-graph-reader-20261105-b.log` and
`/tmp/araphor-live-graph-reader-20261105-a.log`.

Result: **Done** for the shared reader and this focused passing comparison.
Millisecond latency and the 100-fold target are **Not done**. The next review
concerns package input expansion: the bulk index receives 16,384 unrelated raw
keys and passes their pins into later metadata. The reviewed replacement uses
audit changes and exact coverage/retirement metadata. It retains exact raw
record lookup in the detector. That replacement has no build or timing result.


## Subscription header read result, 2026-11-05

The focused build passes in 265.223068 seconds. The exact incident test passes
with all 16,402 records in 113.97 seconds. A repeat with the same executable
passes in 103.38 seconds. The process times are 114.014713 and 103.429036 seconds.
Both runs are slower than the prior 84.77-second result. This change has no
established end-to-end latency gain.

| Measurement | First run, seconds | Repeat, seconds |
| --- | ---: | ---: |
| Initial notification arrival | 8.067256799 | 7.123391425 |
| Background records to publication | 16.048446969 | 14.636573815 |
| Second notification arrival | 18.891071178 | 17.650308497 |
| Third notification arrival | 16.182285557 | 15.701787926 |

The subscription now reads current source, trace, and store headers for an
unrelated health update. It reserves input memory before copying the header
selection and demand names. The read keeps the prior evaluated snapshot,
cursor, requests, and deadline. A pending relevant commit remains pending.
The full metadata API remains available for cursor recovery and other callers.
The workload, assertions, and timeouts are unchanged.

The first run has 23 notification scalar captures, compared with 32 in the
prior run. Their summed durations are 19.411 and 18.370 seconds. These child
intervals can overlap. Fewer captures do not prove a latency gain. Other stages
also take longer. The cause of the whole-run difference is not established.

Proof: `/tmp/araphor-build-envelope-20261105-b.log`,
`/tmp/araphor-live-envelope-20261105-a.log`, and
`/tmp/araphor-live-envelope-20261105-b.log`.

Result: **Done** for the passing header-read implementation. **Not done** for
a measured latency gain, millisecond latency, and the 100-fold target. The next
review concerns one Graph authority owner for each Data read snapshot. Current
Graph, notification, and provenance helpers recreate that owner inside the same
read transaction. No implementation or gain is qualified for that replacement.


## Graph invocation authority result, 2026-11-05

The exact incident test passes with all 16,402 records in 84.77 seconds
(84.815178 seconds for the process). The focused build took 239.554337 seconds.
Notification arrival took 5.967355599 seconds for the first incident and
14.455638287 and 12.829723364 seconds for the later incidents. Background
records reached package publication in 12.126782958 seconds.

The third index invocation takes 1.681420 seconds after input preparation,
down from 2.529724 seconds in the prior passing run. Data binds immutable Graph
invocation authority before package execution. Each operation keeps fresh
lifecycle, grant, completion, source, trace, context, dependency, and expiry
checks. Historical producers receive full validation on first use. Each later
use checks the exact canonical result and Graph origin tuple. Freeze drops
these temporary certificates. Final preparation and commit keep full guards.

Proof: `/tmp/araphor-build-graph-authority-20261105-a.log` and
`/tmp/araphor-live-graph-authority-20261105-a.log`.

Result: **Done** for this passing comparison. The index segment is 1.50 times
faster than the prior run. The full test is 1.28 times faster than the first
108.11-second passing run. The third arrival is 1.64 times faster than the first
passing 21.057280225-second result. Millisecond latency and the 100-fold target
are **Not done**. The next source review concerns metadata-only subscription
updates that rebuild notification finding information without result rows.


## Historical input owner result, 2026-11-05

The exact incident test passes with all 16,402 records in 87.16 seconds
(87.201019 seconds for the process). The focused build took 205.567243 seconds.
Notification arrival took 6.177745667 seconds for the first incident and
15.085794891 and 13.769834277 seconds for the later incidents. Background
records reached package publication in 12.413882136 seconds.

The invocation now validates its historical call once. The invocation captures
all declared Before inputs together. Each input uses the saved native plan with
separate mutable source state. The reference, receipt, source view, and Arrow
buffers remain shared. The workload, assertions, and timeouts are unchanged.

Proof: `/tmp/araphor-build-before-owner-20261105-a.log` and
`/tmp/araphor-live-before-owner-20261105-a.log`.

Result: **Done** for this passing run. The full test is 1.24 times faster than
the first 108.11-second passing run. This result remains far below the target.
Millisecond latency and the 100-fold target are **Not done**.

The next measured owner is Graph invocation authority. The third index call
still takes 2.529724 seconds after input preparation. Historical producer
validation repeats across Graph traversal waves. The reviewed replacement keeps
one invocation authority owner and fresh short reads for live guards. Its source
review is in progress. It has no build or measured gain yet.


## Latest qualified run, 2026-11-05

The exact incident test passes with all 16,402 records in 88.71 seconds
(88.748188 seconds for the process). The focused build took 236.315785 seconds.
Notification arrival took 6.307454291 seconds for the first incident and
16.159269708 and 14.802440057 seconds for the later incidents. The workload,
assertions, and timeouts are unchanged from the prior complete passing run.

The notification router now prepares one bounded Data read batch. It shares
validated owners, exact historical subjects, route versions, and finding basis
inside one read snapshot. Live delivery checks and pending-state writes remain
at the effect boundary. Router preparation and processing take about 1.8 seconds,
down from about 4.8 seconds. The full test remains close to the prior 89.33-second
run. These results do not prove another end-to-end latency gain.

Proof: `/tmp/araphor-build-notice-batch-20261105-b.log` and
`/tmp/araphor-live-notice-batch-20261105-a.log`.

Result: **Done** for this passing run. **Not done** for millisecond latency and
the 100-fold target. The reviewed historical-input replacement uses one capture
for each package invocation and separate mutable state for each input plan.
Its build and runtime qualification are in progress. That draft has no measured
gain yet.


## Verified result, 2026-11-05

The exact incident test passes with all 16,402 records. The focused build took
245.239602 seconds. The test took 89.33 seconds (89.373337 seconds for the
process). The prior passing run took 108.11 seconds. This is a 1.21× total
improvement on the same workload. The third notification took 11.881951101
seconds, down from 21.057280225 seconds (1.77×). The first notification took
5.949980932 seconds. The second took 16.412318569 seconds.

The third detector read emits 18 historical events, down from 16,402. Its call
retains 36 pins, down from 16,420. The native join treats each package call as
an opaque output when it selects the indexed source side. Data shares validated
selected owners and actual producers inside each read transaction. Each actual
producer still checks its own pins, proof, dependencies, and grant.

Proof: `/tmp/araphor-build-lookup-owner-20261105-a.log` and
`/tmp/araphor-live-lookup-owner-20261105-a.log`.

Result: **Done** for this passing comparison. **Not done** for millisecond
latency and the 100× target. A prepared notification read batch is in progress.
That draft has no build or performance qualification yet.


Work resumed after the stop on 2026-11-03. The replacement workload now has
one complete passing invocation. The performance target is **Not done**.
Do not report a 100-fold gain or production qualification.

## Resumed work on 2026-11-03

### Current causal replacement on 2026-11-04

#### First complete run on 2026-11-05

The single test passes with 16,402 raw records, three complete incident chains,
one incomplete-chain check, and 16,384 unrelated records. It checks exact
six-record finding evidence, two nodes, four coverage sources, notification
references, point reads, revision reads, and atomic call publication revisions.
Builtin startup uses the ordinary Definition in the default folder.

The focused build passes in 245.524082 s. The live test passes in 108.11 s;
the wrapper records 108.148275 s. The logs are
`/tmp/araphor-build-pins-20261105-a.log` and
`/tmp/araphor-live-pins-20261105-a.log`.

| Measurement | Seconds |
| --- | ---: |
| Initial trusted audit ingestion to notification arrival | 5.942138124 |
| Background records to package publication | 13.435312799 |
| Second incident ingestion to notification arrival | 20.125573400 |
| Third incident ingestion to notification arrival | 21.057280225 |

The prior run with the same records and batch fixture fails in 129.11 s.
Its public Graph and finding readers do not reach the bulk publication before
the existing 90 s wait ends. Each reader checks about 16,390 witness pins with
one SQL query per pin. Three query threads consume CPU during that check.
The replacement removes that loop and the nested linear membership searches.
One batched check verifies exact pins, live segments, and canonical context
versions. Missing pins remain valid only after their expiry. Raw context
revisions remain at or before the capture cut. Each producing call retains
its own exact pin check. Selected-owner validation with more than 16,000
witnesses takes 0.090 to 0.125 s in the passing run. These measurements do not
establish a complete-test speed factor.

The largest repeated arrival segment is Graph publication to notification
arrival: 6.778 s for the second incident and 9.118 s for the third. Graph
apply takes about 0.37 s inside the common commit. Notification extraction,
routing, and public reads repeat owner and finding validation. The next
replacement must remove that repeated work and preserve current heads,
canonical values, original grants, state compare-and-set checks, and durable
pending state before delivery. The implementer and reviewer must agree before
that implementation starts. Millisecond latency and the 100-fold target are
**Not done**.

**Not done.** The user rejected the denial-event workload and authorized its
replacement with a recorded Hugging Face incident chain. Failed attempts and
successful effects must remain separate evidence. A denial alone must not
produce the attack finding.

The process detector and the Kubernetes placeholder are removed from the
builtin source, component build, and default Definition calls. Their old
qualification results below do not qualify the replacement. Generic Graph
storage, identity, SDK transport, and transaction fixtures remain in scope.

The implementer and reviewer agreed on one ordinary managed Definition for
each admitted tenant and source scope. Native DataFusion change inputs drive
the package. Package code uses the common Araphor Graph transaction and keyed
traversal. Data commits the package changes, findings, and progress together.
The Graph engine has no package or detector rules. No shared-view schema or
cross-instance access path is required.

The new package source is `crates/araphor-analysis-builtins/src/causal`.
`HF-CAUSAL-001` has two dependent exports. `index` stages opaque entity and
link keys and returns canonical evidence keys. `detect` reads those exact
records and contexts with native DataFusion queries. It stages a finding for
credential acquisition, identity issuance, privileged Pod creation, scheduling,
and container admission on another node. Each request names its exact prior
completion or issuance result. Each runtime record names its exact scheduling
result. A successful acquisition requires a completed file read or network receive.
The incident fixture uses the EC2 metadata response. Its denied file open is
an added negative control, not an observed incident action. The created container name must match the admitted
container name. The same container must have privilege and the host-root mount.

Private Graph properties contain proof references and disclosure flags. They
do not contain raw event or context bodies. Ordinary updates use entity keys.
Coverage changes can refresh the graph-connected evidence for a source.
Removed records and records at or below the retained floor are not staged
again. Conflicting request, lease, Pod, binding, or admission claims prevent a
confirmed finding. The declared result is remote privileged-workload expansion.
It does not prove a completed host-root operation or a remote deletion.

The focused Control library check passed in 132 s after the ordinary startup
and source-neutral reader changes. This check preceded the collector adapter
and replacement test. Control now admits one ordinary `Selected` instance with
the stable ID `mithril-control-causal`. Instance Host owns its subscription and
restore. The separate Graph task and per-source fanout owner are removed.
Stored stopped or removed instances remain stopped or removed. Instance Host
rejects the retired per-source Graph destination.

The Control collector adapter accepts structured observations without proof
fields. Its configured role limits the action class. It checks the durable
node session, source identity, CPU, and retained cursor. It derives measurement
proof and writes the context through Data. The lightweight fixture supplies
the external collector observations. No physical provider collector is qualified.

Data stores compact coverage proof with the actual call metadata. Point and
notification readers use the actual finding origin. Missing historical proof
cannot become an empty complete revision. A current publication grant does
not authorize older retained member origins. Readers check those origins.

The replacement test source uses four streams on two authenticated nodes. It
retains a failed credential read, requires the remote runtime link, and rejects
an incomplete chain. It adds 16,384 unrelated records and two later full chains.
The total is 16,402 raw records. Before the batched validation replacement,
the focused build passes in 245.181177 s. That live run passes the
incomplete-chain check and the first complete chain.
The first notification arrives in 6.541158876 s. The exact six-record revision,
four-source coverage, and notification point reads pass. The run is stopped
after 176.492040 s because bulk setup uses 16,384 singleton durable WAL writes.
The test thread waits for a filesystem journal commit before upload. The
fixture must use the existing Node ingestion worker batch path with the same
records and counts. No Data or Graph speed factor follows from this fixture
correction. Bulk drain and later chains remain unqualified.

The logs are `/tmp/araphor-build-scope-20261105-a.log` and
`/tmp/araphor-live-scope-20261105-a.log`. Earlier admission failures exposed
three signed integer fields from untyped SQL literals and unsupported binary
`octet_length` calls. Typed integer sentinels and native binary `NULLIF` calls
correct those contracts. The SDK validation remains unchanged.

The live run also exposed a reader scope error. Table projection removed
parts of the original authorized scope before the Graph grant check. Query
now passes that scope separately to Data. Graph and notification readers keep
the full producer grant check. Unchanged notification values can retain an
older result reference only when the current canonical value is equal.
The source is not ready for production use. No complete workload or speed
factor is qualified.

The user requires builtin startup through Definition files. The default file is
`packages/default-definitions/causal.yaml`. The generic folder loader uses the
existing Definition reader and normal image trust checks. The Control build
captures the default folder. The `package_definitions` setting selects an
operator folder. The loader has no package ID, export-count rule, or incident
rule. The first live chain uses this ordinary Definition startup path.

The recorded incident chain is node credential use, CSI identity issuance,
a privileged host-mounted Pod, and its remote runtime effect. The source is
the [Hugging Face technical timeline](https://huggingface.co/blog/agent-intrusion-technical-timeline).
The test must use exact credential, request, object revision, Pod, container,
and native actor links. It must retain failed branches. It must reject joins
based only on time, shared principals, paths, or task-cookie equality.

Required production replacements are the per-source Graph startup and
capture, single-source evidence validation, policy-based finding construction,
and source-only public findings and notification readers. Ordinary managed
source frames already support multiple sources. Ordinary Graph journals
already use the host transaction. The new path is not qualified.

The last unchanged workload build passed in 239.690349 s. Its live run failed
in 218.337689 s during `CoverageService.Report` with `Cancelled: Timeout
expired`. Eleven nonempty Graph receipts completed. Four source heads reached
1281, 1281, 1281, and 257 members before teardown. The logs are
`/tmp/araphor-build-shared-fill-20261104.log` and
`/tmp/araphor-live-shared-fill-20261104.log`. The Shared future repair removed
the observed parked input fill. The server-side cause of the coverage RPC
timeout remains unproved. No complete workload speed factor is established.

The real incident replacement changes the workload. Measure its baseline and
final source with the same new workload before reporting a speed factor.
The passing-test requirement and 100-fold target remain **Not done**.

### Current Graph boundary correction on 2026-11-04

#### Current qualification before Status

The corrected metric build passes in 210.283027 s. The unchanged live case
fails in 355.522293 s with `Unauthenticated: Client authentication expired
or failed.` The wrapper records 355.681367 s. Twenty-one nonempty Graph
publications complete before teardown. The last source heads reach 1793,
2049, 2305, and 2561 members. Bulk drain and the eight later arrivals remain
unqualified. The logs are `/tmp/araphor-build-status-metrics-20261104.log`
and `/tmp/araphor-live-status-metrics-20261104.log`.

The corrected native counters show a full current payload branch before
selected-key qualification. At cut 210, the Status header takes 15.859990 s.
Its root join builds 3329 rows and returns 1024 rows. The root join's
7.807786 s compute interval includes child work. The largest reported local
aggregate takes 2.456017 s over 3329 rows. Another aggregate takes 1.029980 s;
a projection takes 0.929326 s over 3329 one-row batches. Do not add those
values to the root or header. This proves unnecessary old-row work. It does
not assign the complete header delay to one operator. The row-count ratio
is about 3.25 for that branch, not an end-to-end speed factor.

The reviewer agrees with a replacement of the current qualification step.
It first selects changed or complete canonical identities, then uses the
existing native keyed lookup to qualify current payloads. The current raw
event and context providers have an explicit After image. Changed, Control,
Prefix, and header image rules retain their existing owners. Complete
identity enumeration uses the admitted canonical event driver. It does not
resolve policy facts to enumerate keys. Status and dirty processing have
separate demand-specific bindings. A failed append proof can still select
the complete current target. LEFT joins retain missing keys and control
rows. Package Records and Facts keep their historical exact-key fallback.

The focused Query and Analysis library check passes in 38.93 s. The exact
target build passes in 208.161715 s. The unchanged live case fails in
250.916525 s with `Elapsed(())`; the wrapper records 251.052821 s. The error
does not identify which acknowledgement expired. The logs are
`/tmp/araphor-build-keyed-status-20261104.log` and
`/tmp/araphor-live-keyed-status-20261104.log`.

Four initial notices pass in 8.976192 to 15.215405 s. Thirteen nonempty
Graph publications complete before teardown; a fourteenth completes during
teardown. Healthy source heads reach 769, 769, 769, and 2049 members.
Bulk drain and the eight later arrivals do not complete. A healthy Status
header takes 23.169358 s. These failed runs do not establish a speed factor.

The numeric `source_lookup_shape` events show four keyed After event
readers. However, at cuts 91, 104, and 105 the resolver returns all 769
current rows for 512 selected keys. Internal canonical joins can supply
those key slots. Their presence alone does not prove the external demand
reaches the payload reader. The current qualification remains incomplete.

The reviewer agrees with a native join-direction correction. SourceJoin
gives an explicitly keyed Port priority over a plain retained row reader.
It uses native HashJoin input swapping before distribution enforcement.
Opaque ports keep their existing boundary. Equal priorities keep the native
choice. SourceLookup must then bind the external keys before internal joins.
The focused check passes in 30.90 s. The exact build passes in 215.017859 s.
The unchanged live case fails in 345.660874 s on client authentication
expiry. The wrapper records 345.829557 s. Twenty-two nonempty Graph
publications complete before teardown. A twenty-third completes during
teardown. The healthy source heads reach 2049, 1793, 1281, and 1025 members.
Four initial notices pass in 9.453052 to 16.115407 s. Bulk drain and later
arrivals do not complete. The logs are
`/tmp/araphor-build-ranked-lookup-20261104.log` and
`/tmp/araphor-live-ranked-lookup-20261104.log`.

At cut 87, the resolver still reads 513 current rows for 256 selected keys.
The largest healthy Status header takes 19.801407 s at cut 196. Its full
branch builds 2817 rows. A separate native fallback branch builds 2817
one-row batches and returns no rows. Native parent compute and build
metrics include child work; do not add those intervals.

The reviewer agrees with a further native binding correction. HashJoin
output projections no longer stop key traversal. SourceLookup maps the
native output indices back to the complete join columns before it applies
the existing preserved-side rules. The join, projection, filter, null
rules, and output schema remain native. Static bind-outcome events and a
numeric projected-join count support the next live check. The focused
check passes in 32.19 s. The exact build passes in 219.815549 s. The live
case fails in 345.157697 s on client authentication expiry; the wrapper
records 345.334290 s. Twelve nonempty Graph publications complete before
teardown. Healthy heads reach 1025, 769, 1281, and 1281 members. Initial
notices pass in 10.358972 to 17.500671 s. The logs are
`/tmp/araphor-build-projected-lookup-20261104.log` and
`/tmp/araphor-live-projected-lookup-20261104.log`.

At cut 101, actual Status and package payloads now read the selected ranges:
512 rows at cursors 258 to 769, or 768 rows at cursors 258 to 1025.
This proves external demand on those payload branches. It does not prove
that every branch avoids old rows. The false full fallback still builds
769 or 1025 one-row batches and returns no rows. The largest healthy
Status header takes 63.841803 s; source selection takes 73.945485 s and
includes dependent work. A Facts worker does 0.650100 s of work, then takes
44.540863 s to return through cleanup and asynchronous resumption. Do not
attribute this whole delay to SQL or to the one fallback operator.

The current correction replaces complete fallback qualification. Each
metadata-only condition uses an existing native source Port with no keys.
An INNER scope join builds that gate before it probes current identities.
An empty native build can finish without reading the identity probe.
Current identities now project the unchanged identity expression from the
original admitted event selection, before full payload qualification.
The original window, expiry, predicates, and selection remain in that plan.
Candidate identities grant no source receipt or proof. Every requested
payload still uses the unchanged multiplicity and canonical event validator.
Status and dirty keep separate gates and demand-specific bindings.

The reviewer agrees with this correction. The focused check passes in
13.10 s. The exact build passes in 167.362110 s. The unchanged live case
fails in 340.604655 s on client authentication expiry. Eleven nonempty
Graph publications complete before teardown. Healthy source heads reach
1025, 1025, 1025, and 257 members. Four initial notices complete in
10.757 to 17.109 s. Bulk drain and later arrivals remain unqualified.
The logs are `/tmp/araphor-build-gated-fallback-20261104.log` and
`/tmp/araphor-live-gated-fallback-20261104.log`.

The user requires a complete passing run before further performance work.
The current correction addresses repeated native input execution. In the
projected lookup run, the first four 257-row windows use 148 resolver
executions and 96 Facts callbacks. The earlier ranked run uses 8 resolver
executions and 4 Facts callbacks for those windows. The projected binding
prevents partial input reuse and repeats equivalent requests.

The existing SourceSnapshot binding owner now separates complete inputs
from exact partial demands. A partial match requires the same physical
expressions, native RowConverter and type identities, and exact native row
keys within the same source image and snapshot. Before fallback and
non-shareable ports retain their existing behavior. One optimizer invocation
shares native converters for equal ordered key types. Cancellation, memory
charges, schema checks, and input lineage remain in force. No second input
store is added. The reviewer finds no source blockers. The focused Query
and Analysis library check passes in 37.41 s. The exact build passes in 237.560929 s. The build log is
`/tmp/araphor-build-scoped-binding-20261104.log`.
The unchanged live case fails in 317.646154 s; the wrapper records
317.756361 s. Four initial notices complete in 10.301214 to 17.309578 s.
Five nonempty Graph publications complete. Facts executes once per input
instead of 24 times, but three sources stop before their first bulk commit.
At cut 203, event intake reaches cursor 4096. Source 33 still has Graph
publication 20 at cursor 1. The existing subscription progress check fails.
The log is `/tmp/araphor-live-scoped-binding-20261104.log`.

Call 1 does not complete at cuts 71, 73, 81, and 118. Its sibling calls
complete. The source cause of this wait is not yet proved. The reviewer
agrees with numeric key-producer and shared-binding lifecycle diagnostics.
These events add no row values, expressions, queries, or changed timeouts.
The diagnostic build passes in 265.892248 s. Its unchanged live case fails
in 351.163505 s on client authentication expiry; the wrapper records
351.304189 s. Seven nonempty publications complete before teardown.
The log is `/tmp/araphor-live-binding-lifecycle-20261104.log`.

The trace shows that immediate key demands finish before the stalled input
waits. Some input fills remain retained until teardown. Package lookup inputs
are collected in sequence. A native join can retain a pending input future.
The old Tokio OnceCell permits only the first reader to drive that fill.
Later readers can then wait without driving the retained work.

The binding owner now uses the existing weak Shared-future pattern. Every
active waiter can drive the same fill. A successful fill records its read ID.
The cache holds a weak pending future, so it adds no ownership cycle or
spawned task. An abandoned fill can restart. Complete and exact partial
scopes remain separate. Controls, schema checks, lineage, and Before rules
remain in force. Fill and waiter metadata charges stay with the captured
snapshot before allocation or polling. The reviewer finds no source blocker.
The final focused Query and Analysis library check passes in 33.80 s.
The exact build is in progress in
`/tmp/araphor-build-shared-fill-20261104.log`. No live result covers this
repair. The test, millisecond path, and 100-times target remain **Not done**.

#### Managed change preparation on 2026-11-04

The current source has an opaque, consumed `PreparedManagedCommit`. The
tracked commit worker prepares it before `authorize_actions_for`. Data uses
one controlled reader transaction. The token retains no connection.

Preparation validates the actual attempt and immutable package rows. It
prepares call records without result revisions, canonical context slots,
source membership keys and counts, and native Graph layers at captured
writer heads. Context slots preserve fixed historical references and the
per-call import flag. Source and Graph buffers use the same commit-worker
control and DataFusion memory owner. Temporary decode reservations are
released after use. No input or output payload archive is added.

The final Data transaction checks the store, recovery epoch, attempt, live
grant, instance state, source parent, Graph parents, writer identities, and
historical origin identities before context or result writes. It binds the
new revision and rechecks exact immutable context bodies and fact indexes.
An identical context committed after capture can be reused. Graph endpoint
and public-domain conflict checks stay in this transaction. Data promotes
retained state and wakes revision subscribers only after COMMIT.

The old inline managed preparation and `PendingGraph::apply_journals` path
are removed. Packages still choose their commands. The generic Graph owner
contains no package or finding rules and has no commit method. Final domain
counts and durable COMMIT remain under the Data writer. This change does
not prove that those costs meet the latency target.

The focused Query and Analysis library check passes in 37.97 s. The exact
target build, with the final origin guard and metadata charges, passes in
255.382395 s. Its log is `/tmp/araphor-build-prepared-managed-20261104.log`.
The unchanged live case fails in 249.617853 s with `Elapsed(())`. The wrapper
records 249.758111 s. The log is
`/tmp/araphor-live-prepared-managed-20261104.log`. The error does not identify
which acknowledgement expired. Do not label it as a unary RPC timeout.

Four initial notices pass in 9.269059, 13.973294, 15.017714, and 15.727428 s.
Fifteen nonempty Graph publications commit; fourteen complete before
teardown. Four more commit logs have no Graph result. The healthy source
heads reach 1025, 1537, 2049, and 2049 members. The last publication completes
during teardown. Bulk drain and the eight later arrivals do not complete.
This farther partial workload does not establish a speed factor against the
earlier failed case.

The largest healthy Status header takes 13.842859 s. Source selection takes
17.309752 s and includes dependent work. These intervals must not be added.
Healthy publication 186 holds the writer for 10.819473 s: transaction work
is 5.178177 s and actual COMMIT is 5.641296 s. Native Graph apply takes
2.610845 s; domain counts take 1.058726 s. The last COMMIT crosses teardown
and is excluded from healthy comparisons.

The native metric reader uses the wrong accessor for built-in compute,
row, batch, and spill counters. `sum_by_name` excludes those variants.
Their logged zeros are unread values. Custom join timings remain valid but
include child work. The correction uses native `MetricsSet::sum` with the
public metric name. Its exact build is in progress in
`/tmp/araphor-build-status-metrics-20261104.log`. No live result covers that
correction. The unchanged test and the 100-times target remain **Not done**.

#### Current implementation continuation

The continuation now has a native source selection receipt and publication
catalog in Data. Schema version 41 stores input identities, positions,
coverage references, exact source proofs, and immutable owner references.
It does not store raw event copies or package input and output batches.
Semantic facts remain in the canonical context owner.

The active host commit no longer interprets Contribution output. Data
applies explicit package journals and source progress in one transaction.
Native scalar finding and notification adapters now read those publications.
Dependency checks use native publication revisions. Finding provenance uses
actual member introduction calls and exact context pins. The latest
unchanged live case passes four initial notifications and commits four first
bulk windows with 257 source members each. Bulk drain, later arrivals, and
complete public readers remain unqualified.

The source admission adapter reads Data inventory and lifecycle notices.
It uses the existing Definition host. The separate source-query subscription
and production host expiry execution path are removed. The same Definition
now receives a Data-authenticated expiry input. Builtin package code reads
its own native rows before it stages explicit proof-loss updates. Data checks
the final claims. Package code still has no commit operation.

A required native source port records the input receipt before package
execution. An empty control result skips its dirty input header. An active
control result retains one gate row even when no records remain. Native
finding provenance follows exact finding-row read pins to original witnesses.
It does not import unrelated rows from an origin call.

The unused private root relation is removed. No production reader uses its
Unit, support, or state copies. Builtin code still validates roots, selects
causal support, runs all three detectors, and stages explicit domain edits.
The owned-read guard now uses the existing operation-specific SDK schema.

The focused Query and Analysis library check passes in 40.41 s before these
last deletions. The exact target builds pass in 277.577845 s and 316.030355 s.
The second build includes the owned guard and private-root removal. Its
unchanged live case fails in 149.504977 s. The first source notification
expires after 90.229616 s. The first Graph execution at cut 18 returns the
masked error `Graph host`. No Graph publication completes. Configuration
takes 58.110861 s; startup takes 58.649845 s. The logs are
`/tmp/araphor-build-owned-expiry-20261104.log` and
`/tmp/araphor-live-owned-expiry-20261104.log`.

The diagnostic target build passes in 285.564122 s. Its unchanged live case
fails in 149.010167 s. The first notification expires after 90.209927 s.
No Graph publication completes. The host cause is now retained:
`AnalysisBusy: read control` at `analysis/read.rs:337`. Three parallel
package calls share one native interrupt slot through `CallContext.control`.
The log is `/tmp/araphor-live-graph-cause-20261104.log`.

Query now creates one operation control for each actual package invocation.
The runtime and its Graph callbacks share that control. Parallel calls have
separate native interrupt slots. Runtime cancellation can still interrupt an
active Graph callback. The reviewer agrees with this change. Its exact build
passes in 232.123725 s. The unchanged live case fails in 150.865488 s.
All three package calls complete. Their reported intervals are 147.160 ms,
154.909 ms, and 337.761 ms. The first native Graph commit then rejects
`range(UBIGINT)` during property identity allocation. No publication completes.
The first notification expires after 90.237370 s. The log is
`/tmp/araphor-live-call-control-20261104.log`. The native read overlap guard
remains in force.

Property allocation now checks the Arrow row count with `i64::try_from`
before it binds the native signed range argument. The identity count and
nonzero checks remain in force. The reviewer agrees with this correction.
Its exact target build passes in 296.944431 s. The unchanged live case
fails in 364.822259 s. Four initial notifications complete in 12.614454 s,
22.647062 s, 41.350293 s, and 43.668153 s. Four native Graph publications
complete. No bulk publication completes. The first native projection takes
1.628140 s; its complete commit takes 2.019670 s. The largest initial
projection takes 2.583 s. These are one-row results, not a bulk comparison.
The run ends with `Unauthenticated: Client authentication expired or failed`.
The log is `/tmp/araphor-live-property-count-20261104.log`.

Continuing capture repeatedly rejects the native source publication at
`managed/commit.rs:597`. Generic Definition freshness recursively checks
the prior Graph publication's original inputs. Its own publication changes
those inputs. The recovery loop repeats work and delays later notifications.

Managed freshness now treats native source publications as immutable input
leaves. It first checks the exact tenant, result, revision, registered attempt,
generation, and captured cut through `native_source_cut`. A malformed source
publication fails closed. Ordinary Definition and call freshness checks stay
in force. Current source guards and publication parent checks still protect
new work. The reviewer agrees with this correction. Its exact build passes in
299.954965 s. The unchanged live case fails in 171.718207 s. The first
notification completes in 14.521128 s. The second source has its event, Graph
publication, and finding, but its notification expires after 90.268920 s.
The freshness recovery loop does not recur. The log is
`/tmp/araphor-live-source-leaf-20261104.log`.

The notification subscription stops with `the current notification Graph
index is absent`. An idle Definition step publishes a Graph head without a
fresh Graph journal or a source receipt. The finding-head query selects that
head, but the source notification index has no source metadata for it. The
publication owner now skips a new Graph head when both the fresh Graph
journal and sealed source selection are absent. A fresh empty or read-only
Graph journal still publishes. A new source selection still publishes when
all package calls are retained. Recovery requires the publication for actual
Graph results or an exact source publication. The reviewer agrees with these
paired changes. The exact build passes in 279.133830 s. The unchanged live
case has finished in `/tmp/araphor-live-idle-graph-20261104.log`.

The unchanged live case fails in 336.747302 s. Four initial notifications
complete in 12.340655 s, 21.347495 s, 28.487721 s, and 36.086261 s.
Four nonempty native Graph publications complete at the initial cursor only.
No bulk package call or publication completes. Data receives all 4,096 events
for the first source. The idle projection now takes 9 to 11 microseconds;
this result does not prove an improvement for the complete workload.

Bulk execution fails before package code. The log has repeated
`the before source image differs` and `conflicting Graph capture header`
errors. The old selection query combines Before roots with the current
`graph_window`. Selection takes 21.168 s at cut 228, including 18.882 s in
its header. These intervals contain nested work and must not be added.
The log is `/tmp/araphor-live-idle-graph-20261104.log`.

The replacement input path is under review. It will remove full Unit support
aggregation and the frozen support-fact scan. Historical roots will use exact
source membership identities. Package Lookup SQL will request canonical
records through native DataFusion joins with private candidate metadata.
The same invocation Graph transaction will serve those reads and package
code. Actual predecessor inputs must complete before Graph binding. The
replacement has no build or live proof. The complete workload and the
100 times target remain **Not done**.

The flat input replacement now passes the focused Query and Analysis library
check in 34.77 s. The exact unchanged test target build passes in 294.975564 s.
Its log is `/tmp/araphor-build-flat-input-20261104.log`. The unchanged live case
has finished in `/tmp/araphor-live-flat-input-20261104.log`.

The flat-input live case fails in 134.893773 s. The first notice expires after
90.203996 s. No package call or Graph publication completes. Startup takes
44.482158 s, including 44.039886 s for configuration. The managed subscription
rejects the new Graph provider with `a retained source subscription requires
a reusable native plan`. This result gives no bulk performance comparison.

The retained-plan owner now recognizes that exact provider. The provider
retains only call identity, relation, schema, and source family. Each execution
gets its actual host from the TaskContext and resets the read identity. Other
provider and expression reuse checks remain in force. The reviewer agrees
with this correction. Its exact build passes in 222.217538 s. The build log is
`/tmp/araphor-build-graph-lookup-reuse-20261104.log`. The unchanged live case is
finished in `/tmp/araphor-live-graph-lookup-reuse-20261104.log`.

The corrected provider build passes in 222.217538 s. Its unchanged live case
fails in 331.131550 s. Four initial notices pass in 11.244687 s, 18.262584 s,
29.806101 s, and 30.672545 s. The run has 20 source-backed Graph publications;
only nine stage Graph edits. These include the four initial results, four
old-root evaluations, and one 512-root bulk result. Raw source 33 reaches
cursor 4,096, but its latest Graph publication reports cursor 1. Later
source-backed publications can have zero changed roots. The failure is the
existing subscription-progress assertion. It is not an authentication error.
The log is `/tmp/araphor-live-graph-lookup-reuse-20261104.log`.

The old Before-image and capture-header errors do not recur. This does not
prove complete incremental processing. Selection reaches 16.459418 s at cut
227, including a 14.896947 s header. The 512-root publication at cut 99 takes
6.003124 s for row work; its combined Graph and source publication stage
takes 4.796571 s. That stage includes Graph journal application, domain
publication, and the source callback. It does not isolate one Graph owner.
A separate commit waits 6.076051 s for the writer. These overlapping
intervals must not be added.

The root After driver now uses native source imaging. SourceLookup can map
keys through a native CrossJoin only when every expression belongs to one
child. It preserves the lifecycle child and native join execution. The
reviewed diagnostics report selected and frozen window bounds, source
progress, source publication bounds, and the parts of the combined commit
interval. They add no queries or per-row logs. The focused Query and Analysis
library check passes in 37.54 s. The reviewer accepts the native imaging,
CrossJoin key mapping, and timing boundaries. The exact target build passes
in 243.739724 s. The unchanged live case fails in 347.315088 s with client
authentication expiry. Four initial notices pass in 11.421090 s, 18.238251 s,
28.511040 s, and 29.763973 s. The logs are
`/tmp/araphor-build-source-window-20261104.log` and
`/tmp/araphor-live-source-window-20261104.log`.

The run has 24 source publications. Seven stage Graph edits; each inserts
eight rows. No new-root bulk mutation completes. At cut 71, source 33 selects
window 1 to 1 while its header reports consumed cursor 1 and contiguous
cursor 257. At cut 80, it selects window 1 to 257, but publication 99 retains
one record and selects zero new records. The source image parent has already
advanced past those new rows. Later Inserted inputs cannot recover them.
The internal Control branch inputs still need diagnosis.

The largest source count interval is 1.161726 s for a zero-row selection.
The largest journal apply interval is 0.928771 s for an old-root evaluation.
These intervals do not qualify bulk Graph performance. A Graph SQL read can
also overlap the same invocation's guest transfer. The run has one
`Graph transfer overlap` error.

Graph SQL reads, guest execution, and freeze now share one per-call gate.
The tracked worker retains that gate until it exits. The reviewer accepts
this change. The entered-key correction reads actual identity rows through
the existing source cursor index. Native SQL adds the newly covered identities
to the shared changed-key relation before status and package input selection.
Canonical keyed reads remain the proof authority. Arbitrary selections retain
the complete invalidation path. The final focused library check passes in
12.32 s. The port rejects unsupported delta images. A checked native Arrow
memory bound covers encoding before allocation. The final cancellation check
also covers an empty result. The reviewer accepts the final code. The exact
target build passes in 205.355698 s. Its unchanged live case fails in
343.495093 s with authentication expiry. Four initial notices pass in
10.786400 s, 17.377505 s, 27.340496 s, and 29.306023 s. Twenty Graph and source
publications have commit receipts. All retain cursor 1 and one record.
A later row-work result at cut 225 has no commit receipt and is excluded.
The logs are `/tmp/araphor-build-entered-keys-20261104.log` and
`/tmp/araphor-live-entered-keys-20261104.log`.

The native source header rows and actual Capture resume flags are current.
At source 34 cut 97, Control None selects 1 to 769; Control After selects
1 to 1 for the same base and captured cut. At source 35 cut 174, None selects
1 to 2,561; After selects 1 to 1. The strict capture-header guard rejects
both attempts. No Graph transfer overlap occurs in this run. No extended
window publishes, so the entered-key recovery still has no live proof.

The native Control arbitration query now uses one CASE selection. The old
work UNION and priority sort are removed. Exact head joins retain expiry and
notice metadata. A filtered eligibility relation precedes the retained-event
probe. Control opts in to the current port for its After image. This preserves
its prepared plan, source family, current binding, clock, and lineage. Before
and the strict capture-header guard stay in force. The reviewer accepts this
replacement. The exact target build passes in 208.276888 s. Its log is
`/tmp/araphor-build-case-control-20261104.log`. The unchanged live case fails
in 155.200669 s. Four initial notices pass in 10.762951 s, 17.563189 s,
27.800547 s, and 29.091419 s. Each source selects window 1 to 257. All four
bulk publications have Graph commit receipts and 257 source members. No
capture-header or Graph overlap error occurs. The run log is
`/tmp/araphor-live-case-control-20261104.log`.

The failure is a 15 s upload acknowledgement timeout. The log does not
identify EvidenceAck or CoverageAck. Bulk Graph apply takes 1.288 to
1.351 s. The first two writer holds take 5.480 s and 4.856 s. The last
bulk commit waits 14.003 s for the writer. Two bulk commit receipts occur
after teardown starts. These receipts do not prove that bulk drain passes.
Input and guest work also remain slow. No warm arrival completes.

The reviewer agrees to replace the Graph journal replay. The journal now
retains its first base assertion across edits and clears. The commit owner
checks the touched open membership after writer-head checks. It validates
every original staged relation and command schema. It persists only final
surviving properties and members. The old SQL edit ordering, state replay,
and alternate public edit API are removed. Data retains domain checks,
provenance, and the only transaction commit. The generic Graph commit
receives the existing per-writer budget through a callback. It checks
cancellation and reserves scratch memory before native Arrow allocation.
The base owner reserves from actual sparse row counts and key lengths.
It verifies those bounds before each key copy. The final focused Query and
Analysis library check passes in 42.91 s. The exact target build passes in
259.022666 s. The build log is
`/tmp/araphor-build-native-reduction-20261104.log`. Its unchanged live case
fails in 151.482379 s. The failure is `ControlRpc: Cancelled: Timeout expired`
at `mithril-node/src/control.rs:812`. Four initial notices pass in 10.505221 s,
17.132293 s, 27.103592 s, and 29.131767 s. All four first bulk source
publications have 257 members. The fourth commit completes during teardown.
No new base, schema, capture-header, or overlap guard fails. The run log is
`/tmp/araphor-live-native-reduction-20261104.log`.

For the same 257-record first bulk windows, Graph apply takes 1.009 to
1.064 s, against 1.288 to 1.351 s in the prior run. Complete writer holds
take 4.314 to 4.770 s. This is a bounded stage reduction. It does not prove
complete bulk drain or the 100 times target.

The remaining input path reads one owned candidate relation 12 times per
source frame. Those worker intervals total 2.335 to 3.094 s per bulk frame.
They are aggregate intervals, not total CPU time. The reviewer agrees to
reuse the full canonical Input through the existing SourceSnapshot binding
before per-scan projection. SQL input access closes under the existing
GraphService gate at guest entry and journal freeze. Direct SDK Graph reads
stay current. Host and source controls still check each read. The final
focused Query and Analysis library check passes in 29.88 s. The reviewer
accepts the input binding and phase guards. The exact build passes in
212.962373 s. Its log is `/tmp/araphor-build-owned-input-reuse-20261104.log`.
The unchanged live case fails in 209.808713 s with `ControlRpc:
DeadlineExceeded: Control unary RPC timed out` at `control.rs:811`.
The run log is `/tmp/araphor-live-owned-input-reuse-20261104.log`.

All four initial notices pass in 9.898918 s, 16.733534 s, 22.630665 s,
and 28.987879 s. Each frame now has one owned Graph input worker, against
12 in the prior run. No input-phase, overlap, or capture-header guard fails.
Twelve Graph publications have commit receipts: four initial windows,
four 257-record windows, and four append windows through cursor 1,025.
The append windows select 768 new records. The last receipt completes
during teardown. Bulk drain and later arrivals remain unqualified.

The fourth notification capture still takes about 11.669 s before its
sink callback. In the prior run, that interval grows from 0.239 s with
zero old obligations to 11.452 s with three old obligations. Data capture
completes only 7 to 11 ms before the routing callback starts. Thirteen
logical scans do not prove thirteen database reads. The notification
capture loop reads original, current, and previous Graph headers and
full finding properties for each obligation. It reloads global admitted
relation shapes for each native finding read.

The largest source selection interval is 15.707727 s at cut 104. It
includes a 14.185242 s header interval. These intervals are nested and
must not be added. Repeated frozen metadata reads and worker scheduling
still need separate attribution. The next owner replacement is under
review. No complete-workload or 100 times improvement is proved.

The reviewer agrees to replace native notification capture with one
read-scoped scalar relation. Selected notification contexts decode once.
One tenant catalog load supplies current-head and pinned-membership queries.
Current heads keep the existing tenant-wide legacy and native ordering.
Source and Graph filters apply after head selection. Original availability
uses the pinned original membership, independent of the current head.
Native publication ownership uses SOURCE_OWNER, source identity, revision,
and instance checks. Canonical finding value IDs remain nonzero.

Ordinary native notification capture no longer reconstructs original,
current, and previous full findings. It registers the same finding and
result references. Native revision equivalence remains exact result ID
equality. Binding filters and requested Graph manifests retain canonical
evidence reads. Route, deadline, retry, and actual delivery behavior stay
at their existing owners. No persistent index, payload archive, query
operator, or Graph domain dependency is added. The reviewer accepts the
replacement. The focused Query and Analysis library check passes in 38.01 s.
The contract reader checks the complete MessagePack structure before typed
schema decoding. It charges a conservative structural allocation bound and
checks the retained SDK schema allocation. Selected states retain the context
key and decoded obligation. They do not retain the raw context body.
The exact target build passes in 245.901805 s. The unchanged live case fails
in 169.173813 s with `Elapsed(())`. This error does not identify the ACK
boundary. Initial notifications pass in 8.722233 s, 12.439740 s, 14.124106 s,
and 15.324871 s. Twelve Graph publications commit. One last append publication
commits during teardown. The later windows reach cursor 769 for one source
and cursor 1,025 for the other three sources. Bulk drain and the eight later
arrivals do not complete. The logs are
`/tmp/araphor-build-scalar-notifications-20261104.log` and
`/tmp/araphor-live-scalar-notifications-20261104.log`.

For source 36, notification evaluation to router entry falls from 11.669007 s
to 3.741663 s. Actual routing remains 3.5967 s. This comparison does not
isolate SQL execution from capture and scheduling. The new scalar captures
range up to 1.575014 s during bulk work. The largest Status header takes
8.010002 s. The largest complete commit takes 19.294852 s, including
12.647064 s for writer acquisition, 4.181085 s for transaction work, and
2.465930 s for durable commit. These nested intervals must not be added.
No Graph phase, transfer overlap, or source-header guard error recurs.
The full workload and the 100 times target remain **Not done**.

The next replacement moves complete managed-change preparation before writer
acquisition. The reviewer agrees with this direction. Data prepares frozen
evidence, revision-free result templates, validated context inputs, domain
checks, source deltas, and retained memory. Araphor Graph prepares final Arrow
rows and exact historical close identities at each captured writer layer.
Preparation retains no connection. The final transaction binds result IDs
and numeric references. It rechecks the current attempt, authority, instance,
call heads, source parent, and Graph parents. It resolves concurrent immutable
context reuse. Endpoint and public-key conflict checks remain in that
transaction until a complete consulted-head proof can replace them. Limits
and deadline checks remain before COMMIT. Promotion remains after COMMIT.

The common memory owner now has a `ManagedBudget` seam. Commit preparation
uses the actual commit-worker read control. Graph and non-Graph commits use
the same control and allocation rules. The Status diagnostic uses native
DataFusion counters. It reports the twelve largest numeric operator costs
and total node counts. It adds no query execution. This continuation is in
progress. No completed target build or live run covers this source yet.
The complete workload and the 100 times target remain **Not done**.



The active Unit schema now contains only record identity, window duration,
and disclosure configuration. The old support aggregation SQL, frozen support
port, and fact-key aggregation view are removed. The root port reads exact
prior membership identities and scalar metadata for Before. It has no event,
fact, Window, Control, or GraphRun dependency in that image. The After image
uses canonical current records and the native lifecycle gate.

Package Lookup SQL can read `graph.<relation>` for a relation declared by
that model. This first source uses the invocation writer's owned metadata.
Native DataFusion executes the joins and canonical record requests. The source
has no equality lookup optimization; do not claim one. Graph-independent
actual inputs complete before one invocation transaction is bound. Graph
inputs and guest code share that transaction. The new source rejects an
unresolved package dependency in its Graph-dependent input closure. Existing
package compositions do not acquire that new source by default.

The credential package retains only candidate matching fields and canonical
record IDs in its private relation. It retains competing and negative
candidates. Rust still checks time, position, lifetime, and conflicts. It
stages metadata for current roots in one batch after explicit clears. It does
not retain event, Fact, Unit, or support payloads in that relation. All three
existing actual package calls remain in the Definition.

Generic Graph-call replay and the old example Contribution output path remain
unqualified. Old Unit support test fixtures still need migration. The exact
incident test has no source change. The full workload and the 100 times
target remain **Not done**.


This change prevents new idle heads; it does not repair old persisted idle heads. No bulk execution
or overall speed improvement is proved.

Complete public readers, obsolete code removal, historical candidate input
work, and migration of old expiry test helpers remain unfinished. The full
workload and the 100 times target remain **Not done**.

The next rewrite is in progress. The builtin detector now stages explicit
Graph clears and native node, edge, finding, and private root-state batches
through the common package API. Empty roots retain private package state.
Ordinary subject output remains for the existing Definition SQL. The old
host projection still expects Contribution output. It must be removed with
the public and notification reader replacement. The current source is not
a complete runnable replacement.

Data now validates recognized domain additions from the frozen journal.
It checks command identities, canonical call input, full fact anchors,
coverage, disclosure, package attribution, and declared reasons. A frozen
journal carries a Query memory budget and cancellation checks. Generic
relations do not enter this domain adapter.

The native publication owner now checks touched public finding and edge
keys across final live owners and relation aliases. It maps equal complete
finding values to a stable native identity. It excludes the anchor from
value equality. Recovery checks the map and every pinned finding property.
These SQL paths have no live proof. The schema version is 40.

Data also retains exact record-to-proof associations in native metadata
pins. Raw journal metadata now supplies checked record positions without
body reads. The source publication adapter, public readers, package-driven
expiry, and removal of the old host mutation path remain unfinished. No
new exact target build or live result covers these changes. The full
workload and the 100 times target remain **Not done**.

Canonical coverage now uses the authenticated typed report, source receipt,
and gap metadata from the captured Data page. The existing snapshot shares
one checked report with the source frame. Coverage checks no longer depend
on projected SQL columns. The focused Query and Analysis library check
passes in 39.74 s before the next metadata charge and proof-pin checks.
No live test covers this replacement.

Query now supplies the same optional Graph service to the shared package
runtime. The service binds the actual registered attempt and call. Data
owns the mutable journal, read provenance, callback closure, and frozen
journal. Query carries the frozen journal in `CallResult` and
`ManagedReturn`. The common Definition commit checks journal authority
before it writes new call heads. It applies all writer layers together
before optional destination projection. Retained calls carry no journal.
Declared predecessor calls supply exact frozen journal identities in
manifest order. Package code has no commit method.

Generic journal conversion, owner clears, property writes, dictionaries,
and final endpoint checks stay in `araphor-graph`. Data records actual
result attribution and historical read provenance in `managed_graph_*`
tables. Query uses existing tracked blocking workers for factory and
freeze SQL. Native Arrow buffers retain input-pool claims. Callback scratch
ends with the transfer. Journal memory remains charged until publication.
The existing request input limit also bounds Graph transfers.

Data retains canonical source cells with checked row indices and memory
leases. Query records native read lineage through shared port bindings and
attributes input reads to actual calls. Data now owns the read-only
`EvidenceBasis` checks. Portable domain relation codecs stay in
`araphor-analysis-types`. Data adds an identity-only fact-to-record index
in the context transaction and checks that index during recovery. The
store schema version is 38.

Native source bindings carry sealed Data handles beside their Arrow
values. Shared bindings retain the same handle. At each actual call,
Data checks raw rows and derived parents together before it records the
call input. Data compares framed record bytes, identities, and positions.
The existing frozen Graph reader supplies a separate sealed historical
proof. A Before read cannot import pending values into the current call.

The common commit imports pending canonical contexts after the captured
state checks and before call heads change. Captured context refs keep the
captured-cut rule. Separate derived refs record imported values and exact
historical parents. Data records import receipts and historical origin
pins in native metadata tables. Historical pins do not become freshness
dependencies. Recovery checks the call refs, selected union, native pins,
and canonical fact-to-record index.

The sealed-source target build passes in 254.443156 s. Its unchanged live
case fails in 133.756738 s. The first Graph evaluation rejects logical call
ID 0 at cut 24. The existing initial-notification assertion then expires
for source 33 after 90.200630 s. Query assigns logical calls from zero;
Graph writer and layer IDs use separate nonzero identities. Source
attribution now accepts call 0. Logs are
`/tmp/araphor-build-sealed-source-20261104.log` and
`/tmp/araphor-live-sealed-source-20261104.log`.

The next target build passes in 239.610333 s. Its unchanged live case fails
in 133.967616 s. The first Graph evaluation rejects the derived context
transaction at cut 24. The installed DuckDB Rust binding implements
`is_autocommit()` as a constant `true`. The guard therefore rejects an
active transaction. Graph and context mutation entry points now require a
borrowed `duckdb::Transaction`; they do not use that stub. Data keeps commit
and rollback ownership. Logs are
`/tmp/araphor-build-native-source-20261104.log` and
`/tmp/araphor-live-native-source-20261104.log`.

Each call result now stores its own raw source evidence and declared
ancestor input evidence. The selected Definition result keeps all source
reads. Data aligns each call's witness pins to the already resolved segment
IDs. Recovery checks the ordered subset and exact native pins. Graph views
include only successful fresh predecessor journals that were complete when
the view was bound. A skipped static call does not require a return. Recovery
also accepts logical call 0 and keeps nonzero engine identity checks.

The focused Query and Analysis library check passes in 38.53 s. The exact
target build passes in 253.654040 s. Its unchanged live case fails in
347.226456 s with expired client authentication. Four initial notifications
pass in 10.665387 s, 11.481966 s, 12.369625 s, and 14.429271 s. No bulk Graph
publication completes. Twenty DEBUG failures report `historical source
frame`. Historical Before execution uses a metadata capture without a new
source frame. Its nested local After ports incorrectly request a current
import seal. The build and run logs are
`/tmp/araphor-build-call-evidence-20261104.log` and
`/tmp/araphor-live-call-evidence-20261104.log`.

The reviewed correction uses the actual bound historical reference. All
such reads use the existing guarded frozen-value reader and return no new
import handle. Current attempts still require the sealed factory and source
frame. Data now checks derived coverage against original captured coverage
batches. The checks use full source identity, report revision, CPU, epoch,
counters, raw temporal fields, and source gaps. They decode only requested
current-epoch intervals. Missing required proof columns fail closed. A
native metadata fallback at the exact cut remains unfinished.

Data now records a source-neutral Graph publication for the Definition's
selected result. Native scalar pins retain all writer heads visible at that
publication, including unchanged writers. This catalog does not require a
Graph destination or evidence source. Recovery checks publication ownership,
the previous-publication chain, and complete exact writer-layer pins. The
store schema version is now 39. Canonical finding-value refs and native
public domain projection remain unfinished. No exact build or live result
covers these later corrections and catalog changes yet.

The current draft uses native batch context lookup, immutable conflict
checks, absent-row inserts, and ledger appenders. Joined reference checks
read canonical bytes and check the identity index, witnesses, import
receipts, historical membership, and captured source/context grants. The
fact index includes source identity and cursor columns for native joins.
Focused library checks cover the batch code. Its SQL and performance do
not have live proof yet.

**Integration: Not done.** The builtin packages still emit the old Unit
and Contribution outputs. Their Graph capability is not enabled. The old
Graph projection, inventory subscription, and host expiry path still run.
The canonical domain validator, direct native domain projections, package
state migration, and historical Graph replay remain unfinished. The new
service path has focused library checks only. The incident case does not
yet exercise it. No 100-times result is proved.

The last exact target build passes in 243.060148 s. The unchanged live
case fails in 347.387118 s with expired client authentication. Four initial
notifications pass in 11.183885 s, 12.026720 s, 12.928681 s, and 14.964266 s.
The run completes 25 nonempty bulk Graph publications. It does not complete
the workload. In the slowest completed row transaction, projection takes
5.982609 s of 6.685837 s. One affected-input driver takes 6.051651 s. These
intervals can overlap. Logs are
`/tmp/araphor-build-graph-catalog-20261104.log` and
`/tmp/araphor-live-graph-catalog-20261104.log`. The later source changes
above do not have an exact target build or live result yet.


#### Earlier foundation state

The latest user correction supersedes the earlier Graph ownership text.
`araphor-graph` is a package-independent processing engine. The engine has
opaque graph, writer, relation, owner, and entity identities. The engine
has native Arrow properties, ordered edits, owner clears, and staged read
indexes. Package identity, admission, grants, finding contracts, evidence,
and package attribution stay outside the engine. Builtin, Wasm, and native
packages use the same engine API inside a supplied transaction. A package
cannot commit that transaction. Data commits the complete Definition.

The working tree moves portable observation, fact, finding, checkpoint,
and Arrow contracts to `araphor-analysis-types`. Data now holds the typed
storage and projection adapter in `analysis/graph_rows/store`. The generic
engine has no SDK, detector, package, or finding dependency. The SDK declares
Graph relation schemas and edge endpoint relations. The shared runtime path
checks those declarations for both native and Wasm callbacks.

**Integration: Not done.** Query still passes no Graph invocation service.
The builtin models still use the old contribution output path. Data still
interprets that path through `Detector::supports_units`. Data installs the
generic engine schema, but the journal and final layer writer are not
installed in the package publication path.
The named test therefore does not yet prove package-owned Graph mutations.
The test does use real OCI/Wasm packages and the production saved native
Definition subscription. These facts do not prove the corrected mutation
architecture or a speed improvement.

Focused library checks pass for the moved Data adapter and for the generic
Graph engine. The exact target build passes in 343.507598 s in
`/tmp/araphor-build-graph-boundary-20261104.log`. The unchanged live test
fails during planning in 7.723330 s with
`NotImplemented("Graph support fact delta image")`. No event processing or
notification runs. The log is `/tmp/araphor-live-graph-boundary-20261104.log`.
This early failure proves no speed improvement.

Query eagerly creates all four image aliases for each complete input before
it plans the package SQL. The builtin queries use Before and After. The
unused Inserted and Removed images reach an unsupported support callback.
The reviewed correction resolves complete input images in the existing
native `ContextProvider` only when SQL requests an image. The retry build
passes in 343.739126 s. The unchanged case fails during physical planning
in 9.393989 s. DataFusion rejects `EXISTS` in the prefix projection. No
event processing runs. The logs are
`/tmp/araphor-build-graph-lazy-images-20261104.log` and
`/tmp/araphor-live-graph-lazy-images-20261104.log`.

The reviewed correction uses two native one-row aggregates and a cross
join. The qualified prefix aggregate preserves false for an empty input.
The coverage aggregate preserves true when no excluded kind is present.
The source also binds the exact registered `Arc<ManagedAttempt>` to the
current execution before package work starts. Data uses the same capture
normalization for registration and binding. Historical replay keeps a
separate reference. The focused build is in progress in
`/tmp/araphor-build-graph-admitted-20261104.log`.

That build passes in 236.819293 s. The unchanged live case fails in
134.437902 s. The first notification gate expires after 90.185894 s.
The Graph subscription first fails at captured revision 24 because the
support callback returns dataset name `facts`; the registered port requires
`__graph_support_facts`. The reviewed correction changes the returned name
and keeps the exact port schema check. The run log is
`/tmp/araphor-live-graph-admitted-20261104.log`.

Data now installs one generic Graph storage adapter per database. The
schema version is 35. Data registers native Arrow property tables from
admitted package descriptors. Package and call metadata stay in Data's
`managed_graph_*` tables. The engine stores only opaque identities and
native properties. Writer identity stays stable across Definition
generations. The invocation checks its current generation and captured head.
The engine checks keyed read references and normalizes only compatible
native Arrow types. It rejects property types that its storage adapter
cannot preserve without loss. No property value archive or IPC is added.

The focused Data library check passes. The next exact target build is in
progress in `/tmp/araphor-build-graph-catalog-20261104.log`. Query service
binding, frozen journal delivery, builtin migration, native finding
projection, and the performance target remain **Not done**.
Integration, the full workload, and the 100-times target remain **Not done**.

The user resumed implementation after the handoff below. The nullable
StructArray failure is corrected. The grouped Graph staging draft is now
applied. Its focused builds and correctness checks pass. Full runtime
qualification remains **Not done**.

The earlier focused build passes in 283.806963 s. The unchanged live case
fails in 348.557070 s with
`Unauthenticated: Client authentication expired or failed.` No bulk Graph
publication completes. Four initial notifications pass in 14.256900 s,
15.463520 s, 16.687549 s, and 19.025972 s. The complete workload,
millisecond latency, and 100-times target remain **Not done**. The logs are
`/tmp/araphor-build-linear-credential-edge-20261103.log` and
`/tmp/araphor-live-linear-credential-edge-20261103.log`.

The subsequent shared-source build passes. The isolated live run fails in
183.793047 s at the unchanged Control unary RPC timeout. It records 96
native event reads for the first initial check, against 242 before the
change. The four initial notifications take 13.863268 s, 15.150845 s,
16.602653 s, and 19.213600 s. No bulk Graph publication completes. The
run log is `/tmp/araphor-live-shared-port-20261103.log`. The target remains
**Not done**.

The complete-driver binding and batched native decoder builds pass. The
focused checks cover source binding, real managed key demands, memory,
nullable driver runs, canonical facts, record binding, and credential SQL.
The unchanged live case fails in 163.639195 s with
`Cancelled: Timeout expired` from Control transport. Initial notifications
take 10.499888 to 14.817532 s. Three bulk Graph publications commit, each
with roots 2 through 257. A fourth projection finishes row work but has
no commit receipt before teardown. The complete workload and performance
target remain **Not done**. The run log is
`/tmp/araphor-live-driver-decoder-20261103.log`.

The next reviewed changes retain active package proofs across empty
commits, reset eligible saved Before inputs through native DataFusion,
and remove repeated base-support subtrees from native policy selection.
Five package-proof checks, three decoder checks, and both native support
SQL regressions pass. The named-Before check exposes a missing lookup
binding error. A debugger locates that error in DataFusion's global
scalar-subquery execution before package inputs are bound. The attempted
source-walk change is removed. The reviewed correction uses the native
scalar-subquery-to-join optimizer option. Its focused and live checks
clear the binding error. The named-Before case then fails its unchanged
restored-order check. The reviewed correction declares native input-order
requirements at `PackageExec`. Its rerun and live qualification remain
**Not done**. The native input-order build then passes in 318.275160 s.
The named-Before case passes in 20.328811 s with its original order and
replay assertions. Ten Query checks and seven more Analysis checks pass.
The original-feature live build passes in 370.915105 s. The unchanged
live case fails in 172.779654 s at the coverage unary timeout. All 12
historical input selections reuse saved plans. Warm Graph preparation
takes 0.115 to 0.165 s. Graph staging still takes 2.10 to 2.40 s.
Only bulk publications 129 and 130 have matching commit and subscription
completion evidence. The reviewed next change batches the old metadata
member lookup through one native join. Build and run only the named case.
The performance target remains **Not done**.

The metadata batch build passes in 281.530664 s. The unchanged live case
fails in 325.752935 s with Control transport `Cancelled: Timeout expired`.
Four initial notifications pass in 11.661743 to 16.354282 s. The first
bulk metadata stage takes 0.189 to 0.238 s, against 0.749 to 0.986 s.
All four first bulk publications have matching receipts and subscription
completion. The next completed Graph heads reach cursors 769, 769, 769,
and 513. No bulk drain or later arrival completes. All 24 historical
input selections reuse saved plans. Historical record callbacks reach
30.280015 s. The reviewed next change replaces three per-record frozen
metadata queries with three native joins over the exact requested keys.
Its build and live qualification remain **Not done**. The run log is
`/tmp/araphor-live-metadata-unit-join-20261103.log`.

The frozen-join build passes in 277.813300 s. The unchanged live case
fails in 342.751252 s when client authentication expires. Twelve bulk
Graph publications have matching receipts and subscription completion.
All four sources reach cursor 1281. No bulk drain or later arrival
completes. All 36 historical input selections reuse saved plans. The
largest historical record callback takes 8.215026 s, against 30.280015 s
in the preceding run. Header-only control reads still take up to
9.576387 s. The next investigation checks the reader wait for newer raw
journal projection. Preserve the captured-cut and recovery checks.
The performance target remains **Not done**. The run log is
`/tmp/araphor-live-frozen-metadata-joins-20261103.log`.

The narrow frozen-reader build passes in 276.121812 s. Its live run
fails in 359.858935 s with Control transport `Cancelled: Timeout expired`.
All four sources reach cursor 1025. No bulk drain or later arrival
completes. Header-only control callbacks still take up to 7.198205 s;
the reader change does not prove a clear latency improvement. The next
reviewed edit adds reader, owner-check, and native query phase timings
before another optimization. The target remains **Not done**. The run
log is `/tmp/araphor-live-frozen-snapshot-reader-20261103.log`.

The user rejects the retained header draft. That unbuilt draft is removed.
On 2026-11-04, the user directs a complete Graph relation replacement in
`araphor-graph`, with DataFusion execution and Data's atomic transaction.
The implementer and reviewer agree on scoped heads, historical projection,
indexed changes, and producer plus metadata application. DuckDB resource
settings remain unchanged. Engine replacement is conditional. The latency
plan records the measured boundaries and the code removal scope. The
replacement and performance target remain **Not done**.


The first replacement build passes in 235.600379 s. Its unchanged live
case fails in 267.578013 s at the Control unary deadline. Four initial
notifications pass in 11.139087 to 14.383215 s. Four initial and eight bulk
Graph publications commit. Their last completed input cursors are 769,
769, 769, and 513. No bulk drain or later arrival completes. The run log
is `/tmp/araphor-live-relations-frozen-20261104.log`. The source now also
contains reviewed memory-accounting corrections and two timing summaries
that separate reader wait, owner checks, snapshot reads, and Graph work.
The named build for that source is in progress in
`/tmp/araphor-build-relations-timing-20261104.log`. Direct native Arrow
projection, the complete Graph owner, and the performance target remain
**Not done**.


The accounting and read-timing build passes in 260.173809 s. The unchanged
live case fails in 381.545955 s when client authentication expires. Before
shutdown, 252 successful frozen reads have a maximum total of 1.080929 s.
Reader acquisition remains below 0.000055 s. The outer callbacks still take
several seconds. The next reviewed diagnostic separates source-worker queue,
operation, cleanup, and asynchronous return. It changes no runtime setting.
Its named build is in progress in
`/tmp/araphor-build-source-dispatch-timing-20261104.log`. The full workload,
complete replacement, and performance target remain **Not done**.

The dispatch-timing build passes in 239.417268 s. Its unchanged live case
fails in 135.254775 s at the Control transport timeout. Initial notices
take 11.790104 to 15.645787 s. During bulk processing, a 0.070171-second
Graph worker operation takes another 3.388672 s to return to its caller.
Queue wait is below 0.000074 s for that operation. The source still polls
native subscription execution on the caller runtime. The proposed next
replacement moves each pull, with its state and reservations, to Query's
existing runtime through native DataFusion task ownership. Review agreement
is required before implementation. No speed factor is proved. The run log
is `/tmp/araphor-live-source-dispatch-timing-20261104.log`.

The implementer and reviewer approve one native task boundary at
`SubscribeExec::execute_committed`. It transfers each Runtime pull to
Query's existing runtime, with its Engine reference and outer worker token.
It adds no Arrow queue or prefetch. Existing execution checks retain error
snapshots, cancellation, deadlines, and joins. The first build is stopped
after source review finds an extra cancellation select. The select is
removed. The corrected named build is in progress in
`/tmp/araphor-build-subscription-owner-20261104b.log`. No live result covers
this source yet. The performance target remains **Not done**.

The corrected native-task build passes in 224.452313 s. The exact live case
is in progress in `/tmp/araphor-live-subscription-owner-20261104.log`, with
no concurrent build or debugger. Its result must cover the complete workload
before any qualification or speed claim.

The native-owner run fails in 288.512691 s at one of the unchanged
15-second upload ACK waits. The log does not identify which ACK. Initial
notices take 10.940545 to 19.360525 s. Before shutdown, 13 nonempty Graph
publications commit. Confirmed input frontiers are 513, 1793, 513, and 513.
Bulk drain and later arrivals remain **Not done**. Source-worker returns
still reach 5.522833 s. A selected cut spends about 85 s before its final
10.310135-second transaction. Native Graph input and support execution
is the larger measured interval. The next diagnostic samples only Query
threads during bulk execution of the same binary and unchanged case.
Its log is `/tmp/araphor-bulk-query-20261104.log`. Debugger timing does not
qualify performance. The complete Graph owner and target remain **Not done**.

The [latency plan](araphor-reactive-execution-latency.md#resumed-nullable-context-investigation)
records the resumed changes and each measurement. The
[review guide](../guides/araphor-retained-execution-review.md) gives the
current source reading order and correctness evidence. The remaining
sections below record the earlier stopped state.

The bulk diagnostic finishes with six stack snapshots. Repeated nested
group-key conversion, DISTINCT list aggregation, and policy resolution
occupy the Query worker observations. Debugger pauses total 20.577583 s.
The Rust test fails its original progress gate; GDB exit zero is not a
test pass. The diagnostic does not qualify latency.

The implementer and reviewer agree on the complete resolved-input
replacement. Graph now owns native SQL that groups candidate material
before the event join. It preserves canonical event collapse, full-value
DISTINCT, SQL NULL matching, and existing conflict checks. Query now supplies
the resolution and coverage plan through `SourcePort::native`. It uses the
existing captured Arrow binding, transparent receipt origins, and actual
physical bounds. Keyed drivers and source images retain separate authority.
The old per-event Control resolution SQL is removed. The named build is
in progress in `/tmp/araphor-build-resolved-input-20261104.log`. Runtime
qualification, the complete Graph owner, and the target remain **Not done**.

The resolved-input build passes in 278.513541 s. The unchanged live case
fails in 344.596022 s when client authentication expires. All four initial
notices pass in 12.154233 to 20.758886 s. Twenty nonempty publications have
matching commit and subscription completion before shutdown. Confirmed
frontiers are 1537, 1537, 1793, and 1793. Bulk drain and later arrivals
remain **Not done**. The log is
`/tmp/araphor-live-resolved-input-20261104.log`. The current binary is
`target/debug/deps/mithril_e2e-cfe060249db4abfd`. The obsolete
`mithril_e2e-083c80067163a1fd` executable is removed to release disk space.

The largest completed input interval still takes 76.426214 s. It captures
512 changed rows but qualifies 1793 current records and rebuilds historical
support. The next review addresses this complete native Unit input
operation. No new implementation starts before reviewer agreement. The
full workload, complete Graph owner, and 100-times target remain **Not done**.

The implementer and reviewer agree on the complete native Unit support
replacement. Graph now owns causal support SQL and pinned support facts.
Builtin Unit SQL aggregates Graph membership. Query has a declared scoped
Current query and keeps the complete reset target. A committed input proof
permits new-root execution only after native coverage qualification and
exact source, Graph, and lifecycle checks. Full invalidation includes prior
Graph keys and removes records absent from the current selection. The old
builtin credential support SQL is removed. The corrected named build is
in progress in `/tmp/araphor-build-support-rewrite-20261104c.log`. No live
result covers this replacement. Runtime qualification and the 100-times
target remain **Not done**.

The user corrects package ownership on 2026-11-03. OCI images are packages.
Definitions contain subscription SQL and package pins. A called export owns
analysis, including Rust analysis. The earlier draft that put causal
selection in Graph SQL is superseded. Its final build passes in
250.950756 s, but no live result covers that draft.

The current source removes the causal credential SQL and detector-specific
Graph support relations. Native SQL binds roots, typed facts, and keyed
records. Package Rust code selects causal support and returns exact
`Contribution.support` dependencies. Graph validates those dependencies and
output ownership. Data stores every configured call and the Graph projection
in one transaction. A canonical Graph contract selects the Graph call subset.
The generic Graph path no longer requires three fixed Mithril package IDs.
Control keeps its same three-image Definition. Graph checkpoints still
permit only one Graph-producing call per package ID.

The single named test uses this production OCI and Definition path. It
observes four public Follow streams. It does not qualify SQL-only analysis
Definitions, mixed Graph and non-Graph outputs, a YAML loader, repeated Graph
calls from one package, or external notification delivery.

The first ownership build fails in 60.129853 s at a missing support field in
the example detector. The corrected build is in progress in
`/tmp/araphor-build-package-owners-20261104b.log`. No live result covers the
current source. The previous `mithril_e2e-cfe060249db4abfd` and
`mithril_e2e-818fdedfe072a5f1` executables are removed to release disk space.
Build and run only the named case. The full workload and 100-times target
remain **Not done**.

The user further corrects the transaction boundary on 2026-11-03.
The package requests its inputs and chooses its analysis, incremental
strategy, and exact Graph additions, updates, and removals. It operates
inside the supplied transaction and cannot commit. Data commits or rolls
back the complete Definition transaction. The canonical Unit contract
above is not the accepted generic package interface.

The implementer and reviewer agree to replace host-inferred Graph writes
with explicit package mutation commands through the existing Arrow output
transport. Ordinary output rows have no Graph side effect. Empty commands
preserve the prior state. Builtin Unit and contribution logic stays private
to those packages. Graph values, codecs, validation, and the transaction
builder move to a guest-safe Graph core. Native storage remains optional.
There is no new host import or package commit method. This replacement is
**Not done**. Implementation must remove the old generic Unit inference.

The earlier ownership build passes in 254.215715 s in
`/tmp/araphor-build-package-owners-20261104c.log`. That build does not cover
this corrected transaction design. No live result covers either change.
The unchanged named test and 100-times target remain **Not done**.

## Test and target

Run only this existing Rust test:

```text
discovery::packages::required::incident::incremental::follows_incremental_sources
```

Owner: [incremental.rs](../../crates/mithril-e2e/src/discovery/packages/required/incident/incremental.rs).
The workload has four sources, 4,096 initial events per source, and eight
later events: 16,392 events in total. Preserve the workload, all assertions,
10-second Control unary timeout, separate 15-second ACK waits, 90-second
progress gate, and debug profile. The case
checks real WAL intake, authenticated Control, central journal data, native
Query subscriptions, package execution, Graph and finding changes,
notification subscriptions, ordering, isolation, and incremental work.
The notification check proves availability through a subscription. It does
not separately prove delivery to an external sink.

The required path is:

```text
Event arrives
  -> Data commits the central journal
  -> Query wakes the existing subscription
  -> the saved DataFusion plan executes
  -> the plan calls the package
  -> Data commits Graph/finding changes and progress atomically
  -> a notification subscription receives the finding
```

Use the native DataFusion SQL parser, logical planner, optimizer, physical
planner, and execution. Use table providers for tables. Keep package calls
inside the physical pipeline. Compute and store changes incrementally.
The user requires at least a 100-times speed improvement and an event path
in milliseconds. Neither result has been proved.

## Current source

- Query retains the complete prepared native executable. New invocations
  receive a fresh task context. The two large planning passes after event
  arrival are removed.
- Native journal positions drive change detection. Per-call source points
  use call ID, publication revision, journal position, and context revision.
  Empty progress receipts preserve calls that did not run. Twenty-one
  continuing commits in the preceding run report `reset=false`.
- Query retains indexed Arrow blocks in RAM. The existing `RetainedCall`
  also holds last-call input/output Arrow references in RAM. This is not
  a durable input/output archive. Durable call records hold references,
  metadata, and optional package checkpoints. Graph changes are durable.
- Source and replay database operations have separate interrupt controls.
  Native task tracing preserves the invoking dispatcher and span.
- Source-header and notification readers use native Arrow columns. They
  do not deserialize intermediate row lists.
- DataFusion is 55.0. Arrow is 59.2. The vendored native physical optimizer
  contains the recorded upstream statistics correction. The DuckDB native
  library is unchanged. See the latency plan for the migration history.
- The current private Graph control SQL uses native aggregates and
  `UNNEST`. It uses no lambda, private dialect, or custom parser. Source
  review passes; the latest bulk run still panics.

Reading route:

1. [Prepared execution](../../crates/araphor-query/src/definition.rs).
2. [Subscription runtime](../../crates/araphor-query/src/stream/physical/runtime.rs).
3. [Source index](../../crates/araphor-query/src/sources/index.rs) and
   [Before capture](../../crates/araphor-query/src/sources/rows/before.rs).
4. [Package execution and receipt](../../crates/araphor-query/src/definition/physical.rs).
5. [Analysis publication](../../crates/araphor-analysis/src/instance/sink.rs).
6. [Managed Data commit](../../crates/araphor-data/src/analysis/managed/commit.rs).
7. [Graph publication](../../crates/araphor-data/src/analysis/graph_rows/publication.rs)
   and [Graph contributions](../../crates/araphor-data/src/analysis/graph_rows/store/contributions.rs).
8. [Current control SQL](../../crates/mithril-control/src/service/packages/graph-control.sql).

## Latest measured state

The last focused build passes in **191.591930 s**. The last live process
fails in **347.853963 s**, exit 101. Its log is
`/tmp/araphor-live-native-control-aggregate-20261103.log`.

| Completed boundary | Previous run | Latest run |
| --- | ---: | ---: |
| Configuration | 55.198427 s | 47.286763 s |
| Native physical planning, inside configuration | 44.984633 s | 37.528233 s |
| Listening | 0.084568 s | 0.086028 s |
| Subscription setup | 0.061748 s | 0.061942 s |
| Policy setup | 0.241958 s | 0.229682 s |
| Inclusive startup | 55.601662 s | 47.681283 s |
| Initial notification, source 33 | 17.283643 s | 15.768149 s |
| Initial notification, source 34 | 18.495476 s | 16.780978 s |
| Initial notification, source 35 | 19.622795 s | 17.868428 s |
| Initial notification, source 36 | 20.996588 s | 19.717617 s |
| External process, failed | 284.597287 s | 347.853963 s |

The latest first-source execution records 5,045 reads and 4,908 rows,
against 9,275 reads and 7,728 rows before the SQL correction. These are
native Arrow/source reads. They are not counts of DuckDB queries.
The four initial source checks pass. The eight later arrivals do not run.
Startup includes its setup sections. Planning is inside configuration.
Concurrent or nested internal spans must not be added as wall time.
Both whole runs fail at different boundaries. Their totals do not prove
a completed-workload speed factor.

The current failure is an Arrow panic during the first bulk work:

```text
arrow-array-59.2.0/src/record_batch.rs:857
Cannot convert nullable StructArray to RecordBatch
left: 1
right: 0
```

The first panic is at 14:20:52 UTC. The final error contains the resulting
`JoinError::Panic` at `araphor-analysis/src/instance/host.rs:395`. The case
continues to accept journal data, then fails during shutdown at 14:24:34.
The final elapsed time therefore includes waits after the background
panic. No Rust backtrace was enabled. The exact caller of the invalid
conversion is **not isolated**. Do not label this run as an RPC timeout.
The preceding 284.597287-second run did fail at a bulk-upload RPC timeout.

Before the SQL change, the first Graph conversion took 13.356 ms. Its
managed write spent 2.925956 s in transaction work and 45.938 ms in metadata
commit. Notification work processing took 2.674356 s. Under bulk input,
writer acquisition reached 12.360090 s. That accessor also performs catalog
preparation and capacity checks; it is not pure lock wait. Raw intake uses
the same writer owner. Current timers use `writer_acquire_s`; older logs
use `writer_wait_s` for that same accessor interval.

The latest Port timings show 312 Graph capture callbacks in the first cut.
Their median awaited callback duration is about 50.5 ms. Those callbacks
read a bounded in-memory header but pass through blocking task dispatch.
There are 661 total Port completions in that cut, including nested calls.
Do not sum those inclusive spans or call those values CPU time.

All six latency proposals and further coherent native rewrites are approved
when they improve performance. Each implementation still needs a concrete
owner/data-flow proposal and review for simplicity, native reuse, and
preserved guards. A source approval is not a passing runtime result.

## Commands and evidence

Use `rtk` for shell commands. Only the named case is authorized during this
performance work. Do not run full workspace CI or a different test matrix.

```sh
rtk proxy env CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=6 cargo test -p mithril-e2e --lib   discovery::packages::required::incident::incremental::follows_incremental_sources   --no-run --message-format=short
```

The linked [runner](araphor-execution-handoff/run-live.py) records external
elapsed seconds, exit status, the exact case, and process ID. Its build
mode currently uses `/tmp/araphor-native55-duckdb-override.toml`. A saved
[override](araphor-execution-handoff/duckdb-cache.toml) points to the existing
unchanged native DuckDB archive. Use it only while that exact archive,
headers, and bindings exist. A normal Cargo build remains the fallback.
Do not delete the archive to clean old build output.

```sh
rtk proxy env RUST_BACKTRACE=1 RUST_LOG=info,mithril_e2e=debug,araphor_query=debug,araphor_analysis=debug,araphor_data=debug   target/debug/deps/mithril_e2e-a9e3c78154ebcf6e   discovery::packages::required::incident::incremental::follows_incremental_sources   --exact --nocapture --test-threads=1
```

The executable name can change after a dependency or target change. Use the
executable from the focused build. The saved
[timing evidence](araphor-execution-handoff/timing-evidence.txt) records the
last runs and actual owner spans. Raw logs remain under `/tmp`. The
[summarizer](araphor-execution-handoff/summarize-live.py) and
[boundary reader](araphor-execution-handoff/summarize-boundaries.py) read
those logs; they do not replace the Rust test.

Current documents:

- [Latency plan](araphor-reactive-execution-latency.md): approvals, six
  proposals, source history, timing history, and unfinished results.
- [Implementation review guide](../guides/araphor-retained-execution-review.md):
  actual owners, source links, retention, control, and receipt checks.

## Prohibited shortcuts

- No time-based polling. Timer wakes may represent actual query-window or
  expiry boundaries. Source changes use journal positions and subscriptions.
- No hashing for identity or change detection. Do not add repeated hashing
  or serialization to this path. Keep native Arrow values as Arrow.
- No durable copies of package inputs, output batches, selected relations,
  or source captures. Use central-journal references. Materialized Graph
  changes and explicit package checkpoints retain their approved owners.
- No private parser, dialect, planner, cache, or executor to replace a
  feature that DataFusion or an existing crate provides.
- No arbitrary caps or default quotas. Do not add a scan budget or revive
  stored-package or OCI package limits.
- No contract-version bumps or backward-compatibility layers during this
  development work.
- Do not weaken assertions, change the workload, extend timeouts, change
  the debug profile, or substitute a different benchmark.
- Do not claim 100 times from a failed, interrupted, or partial run.
- Do not discard source or replace a crate before its behavior has a
  checked replacement. Preserve unrelated user files and external trees.

The user stopped the implementation. No agents or test runs remain active.
The paused editor process was resumed. No new feature work was performed
for this handoff. The grouped staging draft remains a review artifact.
