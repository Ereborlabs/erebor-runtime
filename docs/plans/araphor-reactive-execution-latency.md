# Araphor reactive execution in milliseconds

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


## Current workload replacement on 2026-11-04

**Not done.** The user rejected local denial detection and authorized a real
Hugging Face incident workload for the single incremental test. The process
detector and Kubernetes placeholder are removed from source and default calls.
The [current execution handoff](araphor-execution-handoff.md#current-causal-replacement-on-2026-11-04)
records the agreed multi-source Definition, package-owned causal graph work,
remaining production changes, and last failed live run. Failed attempts and
successful effects are both required evidence. No policy denial is required.
Historical results below do not qualify the replacement or a 100-fold gain.

The first complete replacement run passes on 2026-11-05 in 108.11 s. Initial
notification arrival takes 5.942 s. The later arrivals take 20.126 and 21.057 s.
The handoff records the exact workload and logs. Batched evidence validation
removes the bulk reader timeout. The latency target remains **Not done**.


Replace repeated source capture, saved-state reconstruction, and per-row
transactions with one retained DataFusion subscription and atomic writes of
changes. This plan records the measured costs and proposes the replacement.

## Handoff on 2026-11-03

### Current package-independent Graph correction

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


#### Agreed native publication replacement

The implementer and reviewer agree on these owner changes before code
changes. This section is the next implementation direction. It is not a
completed result.

Data will keep one source-neutral publication catalog per Definition Graph.
A publication will refer to the existing selected result, Graph identity,
commit revision, and previous publication. A second table will pin the exact
writer layers visible at that publication. A skipped call will retain its
previous writer head. Only actual successful fresh journals will advance
writer heads. Generic publication will not require a Graph destination,
evidence source, or a return from every static call.

Data will project recognized subject, relationship, and finding properties
from native memberships and property structs. It will combine recognized
relation aliases before it checks public-key conflicts. Several owners may
use one public key only if their complete public values agree. Anchor values
will not affect public-value equality. Data will check this final state after
all journals apply in the same transaction.

A scalar map will connect each finding property ref to a canonical property
ref. Data will compare the complete native finding value for the same public
key. It will retain the earlier ref when the values agree. It will use the
new ref when the value changes. It will not use hashes or copy finding bodies
into another value archive. The canonical ref will prove equality only.
Actual visible membership and read origins will still prove authority and
disclosure.

Builtin package code will choose its own reset, owner clears, nodes, edges,
findings, and private state. It will use the same Graph capability as every
other package kind. Data will validate recognized Add and Update properties
against canonical per-call evidence before it applies writer layers. Data
will not infer Remove or Clear commands from Unit or Contribution output.
The old host mutation interpreter and no-package expiry writer will be
removed from the production path.

Current proof checks will use the original Data coverage batches retained
in the source frame. These batches precede Definition SQL. The checks will
retain the full source identity, CPU, report revision, interval, counters,
raw temporal flag, original sequence, and source-gap proof ceilings. Missing
projected proof columns require a native metadata read at the exact captured
cut. Historical evidence requires exact origin-call pins and keyed raw reads;
the selected Definition read set is not call authority.

Native extraction and notification lookup will change together. Scalar
finding subscriptions will select only requested fields from native
properties. Point routing will decode only the requested finding. An explicit
GraphSnapshot API may construct its DTO at that boundary. Source-specific
GraphManifest metadata will be an optional domain adapter. It will not govern
the generic Graph engine or journal commit.


#### Earlier foundation state

The user corrects the owner boundary on 2026-11-04. This correction
supersedes earlier proposals that put package or finding metadata in
`araphor-graph`. The engine holds generic Graph data and processing only.
Data, Query, the SDK, and the runtime hold package identity, admission,
grants, invocation lifetime, evidence checks, and Definition publication.
Every package kind uses the same Graph API. A package chooses explicit
edits inside the supplied transaction. Data commits or rolls back the
complete Definition. Ordinary output rows have no Graph mutation authority.

The implementer and reviewer agree on this split before implementation.
The working tree moves portable domain contracts to
`araphor-analysis-types`. The typed native storage adapter moves to Data.
The generic Graph engine has declared Arrow relation schemas, ordered
staged edits, owner clear barriers, and indexes for staged keyed reads.
The pending Graph writer borrows the existing transaction. The writer
checks all requested heads and applies the successful journals together.
Data remains the only durable commit owner.

**Result: Not done.** Query still supplies no Graph invocation service.
Builtin models and Data still use the old contribution interpretation.
Data installs the new generic schema. The journal is not yet installed in
the package publication path.
Focused library checks pass. The unchanged named target build passes in
343.507598 s. Its live run fails during planning in 7.723330 s with
`NotImplemented("Graph support fact delta image")`. No event processing
runs. The run proves no speed improvement. Logs are
`/tmp/araphor-build-graph-boundary-20261104.log` and
`/tmp/araphor-live-graph-boundary-20261104.log`.

Query eagerly builds Before, After, Inserted, and Removed aliases even when
the package SQL does not use an alias. The unused support delta reaches
the callback rejection. The reviewed correction supplies the complete
pair plans to the existing native `ContextProvider`. Query resolves an
image only when SQL requests that image. Actual unsupported image requests
retain their error. The retry build passes in 343.739126 s. The unchanged
case fails during physical planning in 9.393989 s because DataFusion
rejects `EXISTS` in the prefix projection. No event processing runs.
The logs are `/tmp/araphor-build-graph-lazy-images-20261104.log` and
`/tmp/araphor-live-graph-lazy-images-20261104.log`.

The reviewed correction uses native prefix and coverage aggregates with
a cross join. The empty-input and null behavior stays the same. Query
also binds the exact registered `Arc<ManagedAttempt>` before package work
starts. Data checks the normalized capture, complete instance, source and
execution identities, and incomplete attempt state. Query checks the
invocation and offered frontier. Historical replay uses a separate
reference. The focused build is in progress in
`/tmp/araphor-build-graph-admitted-20261104.log`. Integration and the
100-times target remain **Not done**.

The registered-attempt build passes in 236.819293 s. The unchanged run
fails in 134.437902 s. Its first notification gate expires after
90.185894 s. The Graph subscription rejects the support callback's dataset
name `facts`; its port requires `__graph_support_facts`. The reviewed
correction sets the required returned name and preserves strict port
validation. See `/tmp/araphor-live-graph-admitted-20261104.log`.

Data now installs the generic engine schema and one native property schema
adapter. Store schema version 35 rejects an older incompatible store.
Data admits relation contracts from the stored package descriptor and binds
the actual registered attempt, call, current generation, and captured
writer head. Logical writers stay stable across generations. Package
metadata remains in Data. Generic property storage and keyed reads use
native Arrow batches. The adapter rejects property types that cannot make
a lossless native round trip. It adds no input or output archive.

The Data library check passes. The exact target build is in progress in
`/tmp/araphor-build-graph-catalog-20261104.log`. Query still supplies no
Graph service. Frozen journal delivery, builtin mutation migration,
native finding projection, the complete workload, and the 100-times target
remain **Not done**.

The user stopped implementation and requested a committed handoff. The
latest focused build passes in 191.591930 s. The same live case fails in
347.853963 s at an Arrow nullable-Struct conversion panic during bulk
processing. Its four initial notifications take 15.768149 s, 16.780978 s,
17.868428 s, and 19.717617 s. Startup takes 47.681283 s. The complete
workload and 100-times target remain **Not done**. See the
[handoff](araphor-execution-handoff.md) for the exact error, current source,
commands, pending draft, measurements, and prohibited shortcuts.

### Resumed nullable-context investigation

The unchanged binary reproduces the panic with `RUST_BACKTRACE=1` at
`mithril-control/src/store/graph/native.rs:238`. A left join supplies a
null candidate context. The resolver converts the complete struct before
its existing padding checks. The diagnostic process is interrupted after
the backtrace at 197.800930 s. This partial run does not qualify throughput.

The correction uses native Arrow slices after the existing null checks.
Candidate key mismatches remain errors. Raw candidate and event arrays
reject nulls before conversion. Graph input conversion also slices the
checked event and resolved row before conversion.

The focused build passes in 165.815919 s. The unchanged live test then
fails in 211.526321 s at the existing bulk-upload RPC gate. No nullable
struct panic occurs. The complete workload and 100-times target remain
**Not done**. Four initial notifications take 16.370882 s, 17.219675 s,
18.789018 s, and 21.755397 s. Inclusive startup takes 49.274625 s.
Configuration takes 48.789778 s. These startup intervals are nested.
The bulk Status port reaches 12.984297 s, including its 6.262103-second
header and 6.722094-second callback. Other port intervals can overlap.

The next source change applies the reviewed grouped Graph staging draft
and removes blocking dispatch for in-memory Capture and Window callbacks.
Control and Status database reads retain blocking dispatch. Source checks,
task permits, cancellation, deadlines, and worker tokens have one shared
validation owner. The first draft build fails in 9.193026 s because a
local record-index map shadows the stored-position input. A local rename
corrects that build error. Build and runtime qualification of this combined
change remain **Not done**.

The combined build retry passes in 233.106215 s. Its live diagnostic is
interrupted at 332.009710 s during slow bulk reads. Initial notifications
take 16.141075 s, 17.224624 s, 18.817237 s, and 21.019806 s. Configuration
takes 50.058089 s. Inclusive startup takes 50.553717 s. The first Graph
transaction work takes 2.720714 s, against 3.056601 s in the null-only run.
These nested transaction and port timings must not be added to test time.
This interrupted run establishes no completed-workload speed factor.

The next reviewed changes use `graph_window.window_ns` for the three
credential support joins that do not consume Status sensitivity. Final
unit selection retains the dynamic sensitivity check. Frozen Graph reads
skip point queries for cursors beyond the validated prior Graph header.
Actual historical rows retain the existing checks. The source also records
separate preparation, verification, call-write, Graph, and completion
durations. These changes add no polling, cache, hash, limit, or stored input.
Their build and runtime qualification remain **Not done**.

The window and historical-bound build passes in 327.370464 s. The unchanged
live test fails in 386.893326 s with `Unauthenticated`: client
authentication expired during bulk processing. No nullable-struct panic
occurs. Initial notifications take 15.203800 s, 16.025288 s, 17.219505 s,
and 24.075662 s. Startup takes 49.144308 s, including 48.626780 s for
configuration. The complete bulk workload and later arrivals remain
**Not done**. This failed run proves no performance factor.

The first Graph row transaction takes 3.023618 s. Its Graph projection takes
2.862906 s, including 0.796422 s for grouped staging. A later expiry row
transaction takes 1.633881 s, including 1.604074 s for verification. These
intervals are nested. Bulk staging reaches 7.895485 s during failed
transactions. These attempts do not establish committed throughput.

The next reviewed source change retains native package admission proofs in
the existing `ManagedExecution` owner. Each transaction compares current
descriptor, artifact, and dependency rows with the retained rows. A mismatch
uses full native validation. Each context still checks its identity, root,
digest, package, export, and output. A successful commit retains only the
roots used by that transaction. Failed commits do not promote proofs.
Owner memory accounting includes retained rows and native bundle data.
Focused correctness and live qualification of this change are **Not done**.

The two provenance checks and three retained-execution checks pass. The
Graph check group completes in 493.931628 s: 60 pass and six fail because
their partial database fixtures omit `context_versions`. The reader and
history validator already require that table in the prior source. The
fixture correction uses the production schema constant and keeps all
assertions. Its rerun remains **Not done**.

The admission-proof focused build passes in 307.855314 s. Its unchanged
live test fails in 396.060782 s at the bulk RPC timeout. Initial
notifications take 15.139561 s, 16.357261 s, 17.907681 s, and 20.200227 s.
Repeated warm expiry verification takes approximately 0.088 to 0.136 s,
against approximately 1.7 to 2.3 s in the preceding run. These verification
times are local intervals. They do not prove a completed-workload factor.

Bulk unit staging attributes 2.444756 s and 2.996654 s to Process edge
interning for 256 units. A later attempt under load takes 12.927247 s in
that segment. State interning has no bulk values in these attempts.
Grouped membership application takes 1.009541 s and 0.947010 s in the first
two intervals. These nested, in-flight timings do not establish committed
throughput. Logs are `/tmp/araphor-data-focused-proof-20261103.log`,
`/tmp/araphor-build-admission-proof-20261103.log`, and
`/tmp/araphor-live-admission-proof-20261103.log`.

The next reviewed SQL change expresses credential support through one
candidate, authority, and channel join chain. Native `UNNEST` emits the
support IDs. The candidate stage removes duplicates before the later joins.
The existing final support set removes result duplicates. All task,
process, principal, socket, position, and time predicates remain. Authority
and channel time bounds still start at the original read. A root without
credential support still contributes itself. Build, focused SQL checks,
and live qualification of this SQL change are **Not done**.

The production credential input query passes its focused native SQL check.
The check uses encoded Observation, Fact, and Window batches. It uses the
production SDK normalization before strict Unit decoding. Its expected
support sets cover roots without facts, duplicate triggers, principal and
socket matches, zero task cookies, an out-of-window read, and authority
time after the root time. The test is
`graph::tests::binding::credential::credential_support_keeps_optional_and_temporal_matches`.
The six corrected Graph fixture cases also pass. Two thin history fixtures
require the existing context-reference table as well as the context-version
table. Their checks pass in
`/tmp/araphor-data-history-fixture-retry-20261103.log`. Earlier successful
retries are in `/tmp/araphor-data-fixture-retry-20261103.log` and
`/tmp/araphor-data-fixture-tail-20261103.log`.

The next reviewed write change stages unique edge value keys in a temporary
DuckDB table. One native join reads all matching stored edges. Each match
retains the typed-value, key, zero-ID, duplicate-key, and input-ordinal
checks. The existing allocator and native append path write missing edges.
The temporary table is removed after success or error. Property interning
is unchanged. Six native value checks and 19 contribution checks pass in
`/tmp/araphor-graph-batched-edge-checks-20261103.log`. The checks include
duplicate and zero stored edge IDs, repeated failure on the same writer,
rollback, and exact ID reuse. Full live qualification remains **Not done**.

The focused build with the credential query and batched edge lookup passes
in 283.806963 s. The unchanged live case fails in 348.557070 s with
`Unauthenticated: Client authentication expired or failed.` No bulk Graph
publication completes. The run does not measure the batched bulk edge path.
Initial notifications take 14.256900 s, 15.463520 s, 16.687549 s, and
19.025972 s. Startup takes 43.355679 s, including 42.814826 s for
configuration. Each initial check records 242 native source reads. A bulk
affected-input port reaches 48.053414 s, including 29.379104 s for its
driver and 15.583474 s for its header. These intervals are nested and can
overlap. Full workload, millisecond latency, and the 100-times improvement
remain **Not done**. Logs are
`/tmp/araphor-build-linear-credential-edge-20261103.log` and
`/tmp/araphor-live-linear-credential-edge-20261103.log`.

The next reviewed source change shares one checked, unkeyed source binding
inside its existing captured execution. The public source capability
defaults to false. Only Graph metadata and the complete affected-unit port
permit sharing. Provider family, image, and statement clock identify a
binding. A provider that was already imaged cannot share. Native keyed
record and fact reads remain separate. Each consumer checks its context,
permit, worker lease, cancellation, and deadline. The captured-input owner
accounts for the binding registry and retains the same Arrow buffers,
revision, and coverage. It publishes no binding after initialization fails.
The change adds no cross-cut state, change hash, SQL evaluator, or archive.

Focused Query test compilation exposes 32 older DataFusion API calls in
test fixtures. The reviewed correction removes obsolete `as_any` trait
methods, uses native plan and provider downcasts, and supplies the existing
higher-order function registrations to `TaskContext::new`. It preserves
all assertions. Build, focused binding checks, and live qualification of
the shared-binding change remain **Not done**.

The five native binding checks pass. Both existing input-memory checks
also pass after their fixture reservations include the separate request
metadata. Both fixtures retain the same capacity, intended 1,024-byte
headroom, and assertions. The combined focused build passes in
290.791496 s. The check log is
`/tmp/araphor-shared-port-fixture-checks-20261103.log`. This correctness
result is not a latency measurement. The original live-case build and
runtime qualification remain **Not done**.

The original live-case build passes in 538.947575 s, including its wait
for the combined test build. The isolated live case fails in 183.793047 s
at the unchanged 15-second Control unary RPC gate. The error is
`DeadlineExceeded: Control unary RPC timed out` at
`mithril-node/src/control.rs:811`. Initial notifications take 13.863268 s,
15.150845 s, 16.602653 s, and 19.213600 s. Startup takes 47.285435 s,
including 46.713265 s for configuration. No bulk Graph conversion or
publication completes. No nullable-struct panic occurs.

The first initial check records 96 native event reads, against 242 in the
preceding source. The same cut still executes 24 Records callbacks and
17 Facts callbacks. Bulk callback intervals reach 35.809078 s for Records
and 35.905515 s for Facts. These intervals include nested waits and are
not separate CPU measurements. The change reduces repeated metadata
execution but does not meet the event-latency target. Full workload,
millisecond latency, and the 100-times improvement remain **Not done**.
Logs are `/tmp/araphor-build-shared-port-live-20261103.log` and
`/tmp/araphor-live-shared-port-20261103.log`.

The next reviewed changes share complete-driver Records and Facts within
the same source capture. SourceLookup clears sharing when it applies a
key demand. The focused regression uses real journal rows and a managed
source view to check full, key-1, key-2, and empty demands in one capture.
Graph driver decoding also uses one native affected-ID and resolved-row
decode for each contiguous run with matching non-null presence. Native
canonical, identity, payload, fact, proof, removal, and coverage checks
remain. Mixed-run and corruption regressions are added. Build, focused
checks, and live qualification of these changes are **Not done**.

The combined focused build passes in 354.668514 s. The final test-source
build passes in 224.864988 s, including its queue wait. Three decoder
regressions and the existing production credential SQL regression pass.
Both memory checks and four binding checks pass. The managed key-demand
check fails because its fixture does not pass the admitted requests to
capture. The correction passes the native preparation result through the
production request projection. Assertions and production code are
unchanged. Its rerun and live qualification remain **Not done**. Logs are
`/tmp/araphor-build-driver-decoder-20261103.log`,
`/tmp/araphor-build-driver-decoder-final-20261103.log`,
`/tmp/araphor-driver-decoder-analysis-checks-20261103.log`, and
`/tmp/araphor-driver-decoder-query-checks-20261103.log`.

The admission-fixture build retry passes in 232.892912 s, including its
queue wait. All five binding checks pass in 8.723559 s. The original-feature
live build passes in 372.578288 s, including its queue wait. The unchanged
live case starts after a host process check finds no active Rust build.
Its result remains **Not done**. Logs are
`/tmp/araphor-build-key-demand-admission-20261103.log`,
`/tmp/araphor-key-demand-admission-checks-20261103.log`, and
`/tmp/araphor-build-driver-decoder-live-20261103.log`.

The unchanged live case fails in 163.639195 s with
`Cancelled: Timeout expired` from Control transport at
`mithril-node/src/control.rs:812`. No nullable-struct panic occurs. Initial
notifications take 10.499888 s, 11.600972 s, 13.456593 s, and 14.817532 s.
Startup takes 40.976276 s, including 40.450166 s for configuration.

Records and Facts callbacks execute once for each source image. The first
bulk affected callback takes 2.879023 s, against 26.087557 s in the prior
run. Its complete port takes 7.404461 s. Process edge staging takes
0.048503 to 0.070271 s for 256 units. Three bulk Graph publications commit
at revisions 145, 150, and 151, each with roots 2 through 257. A fourth
projection completes row work at revision 152 but has no commit receipt
before teardown. Bulk Graph row work takes approximately 4 s. Writer
acquisition reaches 6.128921 s. These intervals are nested or concurrent.
The complete workload, millisecond latency, and 100-times improvement
remain **Not done**. The log is
`/tmp/araphor-live-driver-decoder-20261103.log`.

Logs are `/tmp/araphor-build-window-pruning-20261103.log` and
`/tmp/araphor-live-window-pruning-20261103.log`.

Logs are `/tmp/araphor-live-backtrace-20261103-resume-host.log`,
`/tmp/araphor-build-null-guard-20261103.log`,
`/tmp/araphor-live-null-guard-20261103.log`, and
`/tmp/araphor-build-grouped-inline-20261103.log`.

### Active proofs and saved Before inputs

The preceding transport failure is the coverage-report RPC. During bulk
upload, `upload_on` calls `send_coverage_report`, which awaits
`NodeCoverage.Report` through `bounded_response`. The native Control unary
timeout is 10 s. The separate evidence and coverage ACK waits in the test
are 15 s. All these limits remain unchanged. A reusable readiness-renewal
error is retried and does not propagate this status to the test. Coverage
intake acquires the same writer as managed publication. The logs do not
measure coverage admission or writer acquisition, so lock wait at that
request remains an inference.

The next reviewed changes retain active-manifest package proofs across
empty commits. The owner still checks the exact tenant, instance, store,
schema, recovery state, and all stored package rows. Two provenance checks
and three execution checks pass in 40.700816 s. The log is
`/tmp/araphor-empty-proof-checks-20261103.log`.

Native unit selection now reads each base support subtree once. A native
left join, array concatenation, and `UNNEST` add policy observations. The
existing distinct support set and final qualified join retain duplicate
and absent-record behavior. The native policy regression, credential
regression, and three decoder checks pass. The log is
`/tmp/araphor-before-policy-analysis-checks-20261103.log`.

Eligible Before inputs use native `reset_plan_states` on the saved child.
The guard rejects clocks, runtime windows, package calls, local tables,
mutable or unsupported providers, dynamic filters, and scalar-subquery
state. Each replay retains its historical reference checks and fresh
source snapshot. Ineligible inputs use the existing native planning path.

The named-Before regression exposes an unbound lookup input. The scoped
source walk does not enter its named view. The reviewed correction uses
the existing recursive source walk only in the historical binding loop.
The call-binding filter remains. Its rerun is **Not done**. Graph row
timers also separate context, stage, publication, and reference work.

The first combined build fails in 279.790712 s at a test-only Arrow result
type. The corrected retry runs out of disk during linking. The user frees
one completed test executable and permits build-artifact cleanup. The
retry after cleanup passes in 227.459783 s. All six native port checks
pass in 11.482162 s. They include concurrent reset of the same saved plan
against separate source cuts, key demands, and cancellation controls.
This build precedes the local named-view binding correction. Its rebuild
is in progress. No live performance result covers these changes. The
full workload and target remain **Not done**. The logs are
`/tmp/araphor-build-before-proof-policy-space-retry-20261103.log` and
`/tmp/araphor-before-reset-query-checks-20261103.log`.

The named-view binding build passes in 274.946822 s. Six native port checks
and two input-memory checks pass in 14.963501 s. The named-Before case
still fails in 2.694299 s. A debugger identifies Port 23 under a native
`ScalarSubqueryExec` during the subscription read, before historical
replay. Native DataFusion 55 collects the package body's scalar subqueries
across its logical children and executes them before the package binds
its input ports. The attempted source-walk change is removed.

The reviewed correction sets the native
`enable_physical_uncorrelated_scalar_subquery` option to false in Engine
configuration. DataFusion's existing `ScalarSubqueryToJoin` rule then
retains the calculation in its child plan. No custom SQL rewrite or
executor is added. Scalar SQL, named-Before, and live qualification of
this correction remain **Not done**. The debugger log is
`/tmp/araphor-before-binding-gdb-stack-20261103.log`.

The native scalar-scope build passes in 274.612956 s. Ten Query checks
pass in 43.426964 s. They cover SQL and Wasm accumulation, SQL body scope,
six source checks, and two input-memory checks. Seven Analysis checks
pass in 17.714143 s. They cover parameter reset, concurrent change bases,
three decoder cases, and both support queries. The named-Before case
clears the missing-port error but fails its unchanged restored-order
assertion: `[4, 5]` differs from `[5, 4]`.

The native output-order helper stops at the affected-key semi join.
The join preserves its ordered probe input, but the package does not
declare that order as a required input. The reviewed correction records
each child's native ordering in `PackageExec` and returns the native hard
`OrderingRequirements`. Existing replacement and reset retain these
requirements. No custom sort, ordinal, or SQL rewrite is added. The
corrected order check and live qualification remain **Not done**. Logs are
`/tmp/araphor-native-scalar-query-checks-20261103.log`,
`/tmp/araphor-native-scalar-analysis-tail-20261103.log`, and
`/tmp/araphor-native-scalar-analysis-checks-20261103.log`.

The native input-order build passes in 318.275160 s. The named-Before case
passes in 20.328811 s with its original `[5, 4]`, source isolation, input
coverage, eligibility, and replay checks. Ten Query checks pass in
52.578568 s. Seven additional Analysis checks pass in 24.185028 s. These
times include concurrent build work and are correctness results only.
The new credential test name is shortened to
`credential_support_keeps_matches` to meet the local naming rule. Its
query and assertions are unchanged. The renamed test rebuild is pending.
The original-feature live build is in progress. Full live qualification
and the performance target remain **Not done**. Logs are
`/tmp/araphor-build-native-input-order-20261103.log`,
`/tmp/araphor-native-order-before-check-20261103.log`,
`/tmp/araphor-native-order-query-checks-20261103.log`, and
`/tmp/araphor-native-order-analysis-checks-20261103.log`.

### Next exact-test iteration

The original-feature build passes in 370.915105 s. The renamed credential
check also passes. The unchanged live test then fails in 172.779654 s at
the existing coverage unary timeout. All 12 historical input selections
reuse saved native plans. Four initial notifications pass in 13.274354 s,
14.504954 s, 15.548538 s, and 18.594066 s. Startup takes 47.815582 s.
Only bulk publications 129 and 130 have matching commit and subscription
completion evidence. Row work at 131 and 132 does not prove a commit.

Warm Graph preparation takes 0.115 to 0.165 s. Graph staging takes 2.10
to 2.40 s. Its metadata segment takes 0.749 to 0.986 s. The metadata
difference currently executes one old-members query for each touched unit
and one sensitivity query for each selected context key. The measured
bulk batches have no sensitivity keys, so only the unit lookup changes.

An affected Graph batch reaches the existing Data transaction
  -> GraphRows stages the distinct requested unit IDs in a native temporary table
  -> native joins read only the corresponding stored metadata
  -> the existing row, anchor, duplicate, sensitivity, and arithmetic checks apply
  -> the existing expected-base, producer, metadata-version, and atomic commit owners remain
  -> the temporary table is removed on success or error

The reviewer checks the diff before the next build. Build and run only
`discovery::packages::required::incident::incremental::follows_incremental_sources`.
Preserve its workload, assertions, debug profile, and all timeout gates.
Measure the same stage and end-to-end boundaries after the change. The
complete workload and 100-times target remain **Not done**. The current
run log is `/tmp/araphor-live-before-proof-policy-20261103.log`.

### Native frozen metadata iteration

The metadata batch build passes in 281.530664 s. The unchanged live test
fails in 325.752935 s with Control transport `Cancelled: Timeout expired`
at `mithril-node/src/control.rs:812`. Startup takes 41.690192 s. Initial
notifications pass in 11.661743 s, 12.807437 s, 13.842430 s, and
16.354282 s. No bulk drain or later arrival completes.

The first bulk metadata stage takes 0.189 to 0.238 s, against 0.749 to
0.986 s. The complete contribution stage takes 1.233 to 1.428 s, against
2.096 to 2.396 s. These intervals are nested. All four publications
135, 137, 138, and 139 have all three package receipts and subscription
completion. The next confirmed Graph heads reach cursors 769, 769, 769,
and 513. A journal read through cursor 3585 does not prove Graph progress.
All 24 historical input selections reuse saved native plans.

The largest Graph status callback takes 19.280482 s. Historical record
and fact callbacks take up to 30.280015 s and 29.597993 s. These intervals
can include waits and concurrent work. Source inspection finds three
per-record query loops in `GraphRows::frozen_facts`. Even an empty fact
or proof selection executes a query for each stored record.

A source callback requests frozen Graph records
  -> the existing reader transaction receives exact record keys and ordinals in a temporary table
  -> one native join selects metadata units at the existing scope and historical cut
  -> the existing source, CPU, shape, and duplicate checks validate each unit
  -> a second temporary table receives only the accepted units
  -> native fact and proof joins return the original record ordinal
  -> the existing grant, canonical value, byte, revision, and provenance checks apply
  -> both temporary tables are removed on success or error
  -> the existing reader transaction rolls back before the reader returns to the pool

The implementer and reviewer agree on this direction before the edit.
The legacy path without a stored restricted count remains unchanged.
The input is the exact requested set. No new size cap, cache, archive, or
serialization format is added. Build and run only the named live test
after diff review. The build, complete workload, millisecond latency, and
100-times target remain **Not done**. The completed run log is
`/tmp/araphor-live-metadata-unit-join-20261103.log`.

The frozen-join build passes in 277.813300 s. The unchanged live case
fails in 342.751252 s with `Unauthenticated: Client authentication expired
or failed.` Startup takes 41.376314 s. Four initial notifications pass in
11.413294 s, 12.517279 s, 13.747897 s, and 15.966269 s. Twelve bulk Graph
publications have all three call receipts and subscription completion.
All four sources reach cursor 1281 at cut 193. No bulk drain or later
arrival completes. All 36 historical input selections reuse saved plans.

The maximum Status callback takes 9.279844 s, against 19.280482 s. The
maximum historical record callback takes 8.215026 s, against 30.280015 s.
These maxima use different captured cuts and request sets. They do not
prove a fixed speed factor. Even a header-only Graph control callback
takes 9.576387 s. The next investigation checks its common reader wait.
The general reader projects pending journal data before it opens a SQL
snapshot. A frozen Graph read uses an existing captured cut and reads
only committed SQL metadata. Source review must prove which projection
waits it needs before that behavior can change. The complete workload
and performance target remain **Not done**. The run log is
`/tmp/araphor-live-frozen-metadata-joins-20261103.log`.

Source review confirms that the frozen Graph callback reads only SQL
metadata. Source extraction projects the journal before it fixes the
captured revision. Managed publication also projects the journal before
it commits Graph rows. Later pending journal records are already durable;
their SQL projection does not change that committed Graph reference.
The implementer and reviewer agree on the following narrow change and
approve the actual diff.

A validated frozen Graph request reaches Data
  -> `frozen_reader` obtains the existing reader permit and maintenance lease
  -> `AnalysisReadControl::run` opens the existing native SQL snapshot
  -> the existing store, schema, recovery, captured revision, Graph, and proof checks apply
  -> the reader transaction rolls back before the connection returns to the pool

The general `reader_wait` journal projection gate remains unchanged.
Raw fsync, source capture, Graph commits, and recovery retain their
existing owners. Only `graph_frozen_facts` uses `frozen_reader`. The
focused build and exact live qualification are in progress. The target
remains **Not done**.

The frozen-reader build passes in 276.121812 s. The unchanged live case
fails in 359.858935 s with Control transport `Cancelled: Timeout expired`.
The internal total is 359.691381 s. It includes 20.014251 s of pipeline
shutdown. Twelve bulk Graph publications have matching call receipts
and subscription completion. All four sources reach cursor 1025.
All 39 historical input selections reuse saved native plans. No bulk
drain or later arrival completes.

The largest header-only control callback still takes 7.198205 s.
The reader change does not establish a clear latency improvement. The
reviewed next edit adds timing only: reader acquisition, captured-owner
checks, frozen queries, and the complete read snapshot. The frozen query
timer separates header, unit, fact, context, and proof work. Empty record
requests also emit the header timer. These intervals are nested; do not
add them to callback time. No validation, cancellation, workload, timeout,
or optimization changes accompany the diagnostic. Build and run only the
named live case after diff review. The complete workload and performance
target remain **Not done**. The completed run log is
`/tmp/araphor-live-frozen-snapshot-reader-20261103.log`.

### Complete Graph relation replacement on 2026-11-04

The user rejects the retained header draft. That draft is removed before
build. The earlier frozen-reader source remains. The user directs a complete
replacement of the largest measured operation. Graph behavior must belong
to `araphor-graph`. DataFusion remains the query engine. Do not use a DuckDB
setting change as the performance solution. Section 6 still governs engine
selection. A new durable engine is conditional on the replacement transaction.

The last run gives these disjoint initial-notification intervals. Package
execution overlaps the capture-to-transaction interval. Configuration is
separate and takes 41.676863 s inside startup of 42.144113 s.

| Source | Total | Before Graph capture | Capture to transaction | Atomic transaction | Commit to notice |
| --- | ---: | ---: | ---: | ---: | ---: |
| 33 | 11.670806 s | 3.565299 s | 0.701705 s | 2.992500 s | 4.411302 s |
| 34 | 12.832875 s | 3.855807 s | 0.819620 s | 3.209587 s | 4.947861 s |
| 35 | 14.102357 s | 4.107387 s | 1.014256 s | 3.194802 s | 5.785912 s |
| 36 | 16.489026 s | 4.339621 s | 1.157631 s | 3.339037 s | 7.652738 s |

Graph row work occupies 2.766037 s of source 33's 11.670806 s. Removing
all that row work would give at most 1.31 times improvement. The complete
Graph read, change, and publication path must be addressed. The intervals
outside the transaction include other work; they are not a measurement of
Graph conversion alone. The complete workload has no successful denominator.
No 100-times forecast is proved.

A debugger run of the unchanged named case shows package image admission
holding Data's writer while a subscription dependency read waits. The
sampled admission is inside the second source's first arrival, after startup.
This is a cold source cost. It does not establish the cost of later arrivals.
Debugger stops alter latency. This run fails with a closed evidence stream
and does not qualify performance.

A separate unchanged-case diagnostic forwards and times every libc
`malloc_trim` call. It fails at the existing Control timeout in 309.230367 s.
Its aggregate intervals are diagnostic evidence, not an acceptance result.
The allocator path is a minority of elapsed time. No native resource setting
is changed. The log is `/tmp/araphor-trim-named-case-20261104.log`.

The implementer and reviewer agree on one complete `araphor_graph::Relations`
owner. It has four operations: scoped current heads, exact historical
projection, indexed additions and removals, and producer plus metadata
application. The current native adapter borrows Data's transaction.

A committed source change wakes the existing subscription
  -> Query pins the exact source and Graph cut
  -> Graph selects stable value IDs and membership through the bound indexes
  -> Graph supplies requested native Arrow columns and explicit membership changes
  -> DataFusion executes the saved native plan and package calls
  -> Graph prepares only changed values, membership, and adjacency
  -> Data checks current authority, source cuts, context proofs, and expected state
  -> Graph applies producer and metadata changes through Data's transaction
  -> Data commits Graph, findings, state, progress, and replay references together
  -> Data publishes committed changes to dependent subscriptions

A check or transaction fails
  -> Data rolls back all changes
  -> Graph publishes no new head or retained state
  -> a retry uses the same committed parent and input position

Graph owns schema, stable identity, values, adjacency, version membership,
projection, and change application. Data retains source and recovery cuts,
generic grant and context checks, package proofs, durable transaction,
progress, outbox, and commit publication. Analysis retains admission and task
lifecycle. Query retains native parsing, planning, joins, windows, aggregates,
key demands, and execution. No crate dependency cycle is permitted.

The reference patterns are TerminusDB's bound index selection in
`src/rust/terminusdb-store-prolog/src/layer.rs`, explicit layer additions and
removals, and guarded named-head publication. Reuse those data access rules.
Do not add content hashes, a second head store, layer archives, or rollup work.

Remove the old Data Graph row interpretation and GraphSnapshot-to-Arrow
extraction paths after all callers use the replacement. This includes frozen
package inputs, public Graph relations, and Graph reads for notifications.
Keep exact historical cuts, Before ownership, unchanged metadata behavior,
row order and multiplicity, canonical checks, reservations, cancellation,
source isolation, and notification recovery. Do not keep an old fallback or
add a retained-view registry. A file move alone does not complete the work.

Build and run only the named unchanged test. Compare the same initial,
bulk-drain, later-arrival, and atomic commit boundaries. Full workload,
replacement implementation, millisecond latency, and 100-times improvement
are **Not done**.


#### Replacement source result

**Changes and frozen-input source replacement: Done. Complete Graph owner
and runtime qualification: Not done.** The working tree now has the Graph
schema, public value validation, compact header, manifest, exact snapshot,
indexed Changes, and Apply at `araphor-graph`. Data keeps authorization,
context and package proof checks, source cuts, state, progress, and COMMIT.

The old Data frozen-input algorithm is removed. The replacement uses a
native requested-key relation and separate joined fact and proof queries.
It removes two temporary tables and the per-fact length and context reads.
The Data bridge decodes the joined generic context row and checks authority.
Graph retains unit, source, canonical value, duplicate, and historical checks.
The metadata and input reconstruction owners also move to Graph. Public
Graph-to-Arrow extraction and the remaining Data Graph adapters are not yet
replaced. A source move alone does not qualify the complete owner.

The focused build passes in 235.600379 s. It emits
`target/debug/deps/mithril_e2e-083c80067163a1fd`. The named live diagnostic
starts with no build or debugger. Its log is
`/tmp/araphor-live-relations-frozen-20261104.log`. The source then receives
a reviewed memory-accounting correction. That correction removes the extra
proof set and charges actual encoded key and retained opening ID buffers.
The running binary does not include this correction. The corrected source
requires a new named build and qualification. No speed factor is claimed.


The diagnostic fails in 267.578013 s at the unchanged Control unary deadline.
The internal total is 267.436258 s and includes 9.437094 s of pipeline shutdown.
Initial notifications pass in 11.139087 s, 11.682928 s, 12.490703 s, and
14.383215 s. Twelve nonempty Graph publications commit: four initial and
eight bulk. The last completed Graph input frontiers are 769, 769, 769,
and 513. No bulk drain or later arrival completes. A shorter failed run
does not prove higher throughput or the requested speed factor.

The largest completed managed commit takes 18.741758 s. Its writer wait is
13.586797 s. Transaction work takes 3.837622 s and durable commit takes
1.316830 s. These are disjoint parts of that commit. They do not identify
the operation that holds the writer during the wait. There are 53 managed
commits, including empty work, and 12 nonempty Graph publications. The
largest header-only Graph callback takes 5.248251 s. Existing callback
measurements do not separate dispatch, reader wait, owner checks, and SQL.

The implementer and reviewer agree on two timing summaries inside the
replacement. The outer read separates preflight, reader acquisition,
owner and store checks, Graph work, native transaction execution, and
reader return. The inner bridge separates snapshot decoding from relation
projection. The timing summaries change no operation, limit, or assertion.
They include the reviewed memory-accounting correction. The named build
is in progress in `/tmp/araphor-build-relations-timing-20261104.log`.
The complete owner, workload, and performance target remain **Not done**.


The accounting and read-timing build passes in 260.173809 s. Its unchanged
live run fails in 381.545955 s when client authentication expires. Initial
notifications take 11.512860 s, 12.734631 s, 13.494459 s, and 20.222344 s.
The internal total is 381.376076 s, including 19.010059 s of pipeline shutdown.
The log is `/tmp/araphor-live-relations-timing-20261104.log`.

Before shutdown starts, 252 successful frozen reads have a median total of
0.179901 s and a maximum total of 1.080929 s. Reader acquisition has a
median of 0.000019 s and a maximum of 0.000054 s. The maximum owner-check
time is 0.307614 s. The maximum Graph-row time is 0.952801 s. These maxima
can describe different requests. Do not add them or treat the medians as
an event latency. The matching source callbacks still take several seconds.
The read-pool wait does not explain that gap in this run.

The implementer and reviewer agree to measure `SourceSnapshot::blocking`
before another replacement. The existing worker returns its operation result
and start and finish times through the existing channel. The summary
separates context checks, worker queue, operation, and return. Return includes
worker lease cleanup, worker completion, and asynchronous resumption. All
errors, cancellation, and join ownership remain unchanged. The named build
is in progress in `/tmp/araphor-build-source-dispatch-timing-20261104.log`.
No runtime setting or execution owner changes in that build.

The dispatch-timing build passes in 239.417268 s. The unchanged live case
fails in 135.254775 s at the Control transport timeout. Initial notices
take 11.790104 s, 12.724231 s, 13.512624 s, and 15.645787 s. The internal
total is 135.148596 s, including 0.547998 s of pipeline shutdown. The log
is `/tmp/araphor-live-source-dispatch-timing-20261104.log`.

The bulk phase exposes a different cost from the initial phase. One
`read_status` operation takes 0.070171 s in its worker, then 3.388672 s
to return to the asynchronous caller. One `read_bound` operation takes
0.090819 s in its worker, then 3.198142 s to return. Queue waits for these
operations are below 0.000074 s. Return includes worker lease cleanup and
caller scheduling; the timer does not measure CPU use. These observations
do not prove an end-to-end speed factor.

All 112 Graph port worker operations before shutdown use 16.051014 s of
aggregate operation intervals and 67.390027 s of aggregate return intervals.
The operations overlap. These sums are not disjoint parts of test elapsed
time. The diagnostic also takes a captured-snapshot lock after its return
timestamp to obtain the log cut. That log-only access is outside the reported
return interval and must move to preflight before a comparison run.

The source polls the native subscription on its caller. The named case uses
a current-thread Tokio caller. Query has a separate execution runtime, but
only planning and synchronous execution use it explicitly. The proposed
replacement gives native subscription pulls to that existing Query runtime.
Each pull moves its current state into a native DataFusion `SpawnedTask` and
returns the same state and result. It adds no batch queue or prefetch. The
outer subscription tracker must own the task so cancellation can join all
work. A call tracker cannot own it because `calls.finish()` would wait for
its own task. The implementer and reviewer must agree on the complete seam
before code changes. The workload and performance target remain **Not done**.

The implementer and reviewer agree on the single physical subscription seam
at `SubscribeExec::execute_committed`. `Runtime::next` transfers its owned
state to Query's existing runtime. This covers Follow and direct native
subscription execution. Remove the old caller-polled closure. Keep cursor
and recovery bookkeeping at Follow. First-open physical planning already
uses the Query runtime.

The task holds the Engine and an explicit outer subscription worker token.
It must not use `Session::token`, which can select a call tracker. Native
task drop aborts the task. The existing pending-read guard cancels the root
control when the pull is dropped. Tracked blocking callbacks retain their
tokens until they stop. `cancel_and_join` still waits for all tracked work.
On normal completion, return the same Runtime and its exact nested result.
The task boundary adds no root cancellation select. Existing execution
checks retain cancellation, deadline, recovery, and snapshot behavior.
Only runtime or native task failures become errors without a snapshot.
No extra task belongs in Follow, input collection, or replay. This source
replacement is applied and under review. Runtime qualification is **Not done**.

The corrected native-task source passes the named build in 224.452313 s.
The log is `/tmp/araphor-build-subscription-owner-20261104b.log`. The exact
live case starts with no concurrent build or debugger. Its log is
`/tmp/araphor-live-subscription-owner-20261104.log`. The qualification and
performance target remain **Not done** until the case completes.

The native-owner run fails in 288.512691 s with `Elapsed(())`. The internal
total is 288.335188 s, including 22.375830 s of pipeline shutdown. The error
comes from one of the unchanged 15-second upload ACK waits. The current
log does not identify EvidenceAck or CoverageAck. Initial notices take
10.940545 s, 11.981753 s, 13.166027 s, and 19.360525 s. No bulk drain or
later arrival completes. Before shutdown starts at 02:29:20.883163 UTC,
13 nonempty Graph publications commit. Their confirmed input frontiers
are 513, 1793, 513, and 513 for sources 33 through 36. Later row work is
shutdown work and does not establish a committed frontier.

There are 383 completed source-worker summaries before shutdown. Median
return time is 0.039458 s. The largest return is 5.522833 s after a
0.036102-second operation. The native task boundary moves execution from
the caller, but it does not remove the bulk scheduling delay. This run
reaches different frontiers from the preceding run. Their maximum return
times do not establish a speed factor.

The largest completed cut, 224, captures 1280 journal rows at 02:27:37.810
UTC. Affected input completes at 02:27:57.150. Facts After completes at
02:28:06.440. Status After completes at 02:28:26.330; its native header
takes 12.847026 s. Final Records input completes at 02:28:58.846. Package
work ends at 02:29:02.847. The final transaction completes at 02:29:14.260.
Approximately 85 s of this 96.45-second interval is before the writer.
The native Graph input and support operation is the largest measured
interval in this cut.

The final transaction takes 7.552695 s of row work and 2.755886 s to
commit. Graph stage takes 2.825068 s and publication takes 3.726845 s.
These scopes are nested in transaction work. Removing the complete final
writer operation would give at most 1.12 times improvement for this cut.
It cannot establish the 100-times target. The proposed Graph-owned native
preparation and final compare-and-apply split remains a valid architecture
candidate. It is not selected ahead of the larger input interval.

The next diagnostic uses the same built binary and unchanged test. It
samples only Query thread stacks after all initial notices and the first
bulk capture. It records each debugger pause. No source or timeout changes
accompany the diagnostic. Its log is
`/tmp/araphor-bulk-query-20261104.log`. Stack samples are diagnostic evidence;
their run does not qualify performance. The full workload, complete Graph
owner, and performance target remain **Not done**.

### Resolved input replacement on 2026-11-04

The bulk diagnostic records six snapshots of the two Query async workers.
The twelve worker observations contain three nested group-key conversions,
three DISTINCT list accumulator initializations, three policy resolver
stacks, two aggregate decoders, and one deep Arrow slice or join. These
observations identify repeated nested aggregation and policy resolution.
They are not CPU percentages. They do not select event validation alone.

The debugger stops execution for 20.577583 seconds in total. The unchanged
test fails its original progress gate. Raw input reaches cursor 4096 for
source 33, but its Graph cursor is 1025. The internal duration is 274.399339
seconds. The debugger wrapper reports exit zero because GDB finishes; the
Rust test fails. This diagnostic does not qualify performance. The stack
record is `/tmp/araphor-bulk-query-20261104-stacks.jsonl`.

The implementer and reviewer agree to replace the complete resolved-input
operation. Review requires native execution, exact key demands, separate
Before and image authority, existing receipts, and selected evidence.
The replacement has these source changes:

- `araphor-graph::ResolvedInput` owns native resolution SQL. It groups full
  candidate and acknowledgement values by the five binding fields before
  joining events. It preserves full-value DISTINCT and SQL NULL matching.
  A missing group produces typed empty lists. Existing resolver validation
  still rejects conflicting context versions and incorrect candidate keys.
- A native record-key aggregate collapses repeated canonical events. The
  event driver still checks selected multiplicity and journal equality.
  It returns the same canonical event for each record key. The new query
  removes the old full-event grouping and per-event list aggregation.
- `SourcePort::native` supplies the completed resolution and coverage plan
  through the existing captured Arrow binding. Status, Dirty, Records, and
  Facts use this relation. Native source origins stay transparent to scoped
  receipt collection. Physical input bounds and nested custom-port metadata
  retain their existing owner. No default revision or coverage is created.
- The existing binding family, image, and statement clock select shared
  Arrow buffers. A key-rewritten driver stays unshared. A failed initializer
  publishes no binding. Native reads keep the existing context, permit,
  worker lease, cancellation, and memory checks. This intermediate relation
  retains no Graph evidence; actual selected Records and Facts still do.

The old Control `native/resolved.sql` is removed. Control retains signed
policy interpretation. Graph opens no store. There is no new archive,
registry, evaluator, prefetch queue, engine setting, or workload change.
The named build is in progress in
`/tmp/araphor-build-resolved-input-20261104.log`. Source replacement is
applied. Runtime qualification and the 100-times target are **Not done**.

The replacement passes the named build in 278.513541 seconds. The unchanged
test fails in 344.596022 seconds when client authentication expires. The
internal duration is 344.387227 seconds, including 5.865063 seconds of
pipeline shutdown. Initial notices take 12.154233, 13.521931, 14.390450,
and 20.758886 seconds. Configuration takes 37.632941 seconds. Inclusive
startup takes 38.194264 seconds. These startup intervals are nested.

Twenty nonempty Graph publications have matching commit and subscription
completion before shutdown starts at 03:07:04.733531 UTC. The confirmed
input frontiers are 1537, 1537, 1793, and 1793 for sources 33 through 36.
No bulk drain or later arrival completes. The test log is
`/tmp/araphor-live-resolved-input-20261104.log`. Its binary is
`target/debug/deps/mithril_e2e-cfe060249db4abfd`.

The first 256-row publication per source has the same cursor-257 boundary
in both unprofiled runs. Capture-to-commit seconds are:

| Source | Before resolved input replacement | After replacement |
| --- | ---: | ---: |
| 33 | 12.108882 | 10.212423 |
| 34 | 15.394398 | 14.132673 |
| 35 | 16.059558 | 14.311156 |
| 36 | 19.249472 | 16.946736 |

These rows compare completed local boundaries under the same workload.
They do not establish a complete-workload speed factor. Initial notices
regress. The 100-times target remains **Not done**.

The last completed cut 253, publication 332, captures 512 new rows. Its
current Records and Facts inputs each contain 1793 rows. Input and package
work takes 76.426214 seconds of the 86.071929-second capture-to-commit
interval. The final writer takes 5.943249 seconds of transaction work and
COMMIT, plus 3.217571 seconds of writer acquisition. Before support queries
still reconstruct historical input for all three package calls. The current
native Unit query restricts affected roots after its complete support
subtree. The next review must replace this operation at its owner and
preserve support changes, removals, late input, reset, and exact replay.
No source change for that review is applied yet.

## Current approval on 2026-11-03

All six proposals and further component rewrites are approved when they
remove unnecessary work, use the native DataFusion architecture, and
improve performance. This approval supersedes the earlier approval limits
in this file. Preserve those older records as history. The overall
100-times target remains **Not done** until comparable completion of the
same workload proves the improvement.

The qualification owner is
`discovery::packages::required::incident::incremental::follows_incremental_sources`.
The workload has four sources, 4,096 initial events per source, and eight
later arrivals: 16,392 events in total. Run only this live test during the
performance work. Preserve its inputs, assertions, progress gates, native
finding identities, notification references, and source isolation.

Use the native DataFusion SQL parser, logical planner, optimizer, physical
planner, and execution. Keep subscriptions reactive. Use committed journal
positions for change detection. Compute and store changes incrementally.
Preserve authorization, attribution, atomic commits, and recovery. Remove
unnecessary hashes, serialization, repeated planning, and data copies from
this path. A crate replacement is permitted when this path requires it.

Record actual elapsed seconds for each measured section after each run.
State the source change and compare the same before and after boundaries.
Identify nested or concurrent intervals and any unmeasured time. Counts,
partial runs, and build times do not prove the 100-times target.

### Scoped Graph support replacement on 2026-11-04

**Earlier draft. Superseded by the package ownership correction below.** The
implementer and reviewer agree to replace the complete native Unit support
operation. The largest completed cut spends 76.426214 seconds in input and
package work out of 86.071929 seconds from capture to commit. Removing that
interval alone cannot prove the complete 100-times target.

Graph now owns causal support selection, policy-observation expansion, and
selected support membership. Builtin Unit SQL only aggregates the Graph
support relation. The old builtin credential support SQL is removed.
Potential credential, authority, and channel support starts from pinned
Graph fact membership with a captured dirty-fact overlay. Native joins then
select record IDs before a record lookup. Saved facts and incoming facts
keep the existing merge and conflict checks. The actual package Records
and Facts lookups still retain evidence.

`ChangeInput.current` declares the native scoped current query. The complete
after query remains the reset target. Query keeps the final affected-key
semijoin, native schema checks, source receipts, and dependency order.
Before queries select affected roots before support aggregation. Source
image hooks retain explicit delta plans instead of converting Inserted
and Removed inputs to complete After inputs.

A compact Graph input proof records complete sequence bounds and counts
per source, CPU, and effective interval. The existing managed commit owner
retains this proof only after COMMIT. Its source basis, Graph head,
instance, generation, store, schema, and recovery scope must match. A
Prefix metadata port checks both sequence bounds through the existing
native coverage qualification SQL. It reads no historical event. A missing
proof, a changed old record, a gap, a nonlocal policy reference, an unstable
event selection, or a sensitivity zero crossing uses full invalidation.
Full invalidation includes current roots and pinned prior Graph record
keys. It marks prior records absent from the current set as removed.

The first build rejects an optional kernel sequence used as a scalar.
The correction requires a present, nonzero sequence. The second build
rejects a shadowed variable in proof retention. The later builds pass in 283.247107 s and 250.950756 s. Their logs are
`/tmp/araphor-build-support-rewrite-20261104d.log` and
`/tmp/araphor-build-support-rewrite-20261104e.log`. No live
result covers this replacement. The workload and timeouts stay unchanged.
The full workload, complete Graph owner, and target remain **Not done**.

### Package analysis ownership correction on 2026-11-03

The user corrects the execution model. An OCI image is a package. A
Definition contains subscription SQL, configuration, and package pins. Its
SQL can call zero or more package exports. The export implementation owns
analysis. It can use Rust, Wasm, native code, or an admitted SQL implementation.
A called export can use Graph data and operations. Other exports need no
Graph integration.

The implementer and reviewer agree on this replacement:

```text
A Definition subscription receives a committed source change
  -> Query executes the saved native DataFusion plan
  -> PackageExec invokes each configured OCI export
  -> native inputs supply roots, typed facts, and keyed record lookups
  -> package Rust code selects causal support and computes results
  -> each Graph contribution declares its exact support records and facts
  -> Graph validates output ownership, proof, evidence, and membership
  -> Data commits every call return, Graph changes, findings, and progress
  -> the notification Definition receives the committed finding
```

The causal credential SQL and the detector-specific Graph support relations
are removed. Generic input SQL binds data and explicit policy references.
It does not match task, process, principal, time, or socket causality.
`CredentialIndex` performs that analysis inside the package. It builds once
per invocation. `Contribution.support` declares sorted, unique dependencies.
The Graph writer checks output anchors and evidence against those declared
dependencies before it stores immutable membership.

`araphor_graph::UnitContract` identifies the canonical Graph change contract
by typed ports and declared source kinds. It does not compare package IDs,
detector enums, or input SQL. Graph publication selects only those call IDs.
The same Data transaction validates and stores all other configured calls.
Control keeps its fixed three-detector Definition and exact OCI pins.
Graph checkpoints still permit one Graph-producing call per package ID.
This change does not qualify two Graph call sites of the same package.

The unchanged named test starts real Control and Node owners. Control
installs the three OCI images and starts its saved Definition. The test
observes public Follow streams for events, Graph heads, findings, and
notifications. It does not inject detector results or call a test-only
Graph evaluator. It does not cover a YAML loader, a SQL-only analysis
Definition, mixed Graph and non-Graph call outputs, or external delivery.

The first build fails after 60.129853 s because the example detector needs
the new support field. That initializer is corrected. The focused build is
in progress in `/tmp/araphor-build-package-owners-20261104b.log`.
No live result covers this source yet. The complete workload, millisecond
latency, and 100-times target remain **Not done**.

### Package mutation transaction boundary on 2026-11-03

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

### Live physical planning measurement

**SQL dependency reduction: Done. First finding and 100-times target:
Not done.**

Both runs use the same live test and debug filters. The second run changes
only the Graph unit selection SQL. It joins grouped fact keys at the final
support aggregate. Credential support does not use those keys. The earlier
join caused native planning to repeat the unused fact subtree in each
credential support branch. The final join preserves the native record key,
left-join behavior, empty fact list, support values, and final ordering.

| Boundary | Before | After | Reduction |
| --- | ---: | ---: | ---: |
| External test process | 700.392 s | 568.844 s | 18.8% |
| Configuration | 276.179 s | 224.314 s | 18.8% |
| First large physical plan | 264.533 s | 213.609 s | 19.3% |
| First-event observation (failed) | 422.111 s | 342.397 s | 18.9% |
| Second large physical plan | 412.305 s | 333.745 s | 19.1% |
| Pipeline shutdown | 1.506 s | 1.525 s | 1.3% increase |

The internal total changes from 700.340 s to 568.792 s. Inclusive startup
changes from 276.721 s to 224.869 s. Listening changes from 0.240439 s to
0.240901 s; subscription setup, 0.067043 s to 0.067145 s; policy setup,
0.220392 s to 0.230873 s; and OIDC shutdown, 0.000213 s to 0.000218 s.
Startup includes configuration, listening, subscription setup, and policy
setup. The internal total includes all test sections.

The first physical plan is inside configuration. The second physical plan
is inside first-event observation. Do not add these nested values to the
process time. The two large physical plans do not overlap. Both runs fail
before the first Graph publication, finding, and notification. The bulk
events and eight later arrivals do not run. These results do not establish
completed-workload throughput or event latency.

The measured source includes the connected native record-identity changes.
The separate SQL commit applies the same join movement to its parent
record-row keys. It does not commit those unrelated identity changes.

The logs are `/tmp/araphor-live-baseline-20261103.log` and
`/tmp/araphor-live-fact-keys-20261103.log`. Their paired `-timing.txt` files
record external process time. The builds take 198.762 s and 242.366 s.
Build time is outside both test measurements.

A separate debugger run of the exact same test samples native physical
planning. The active Query thread computes join statistics inside native
`EnforceDistribution`. The stack contains 829 frames. DuckDB is idle in
that sample. This sample identifies active work; it does not measure the
whole duration of that work. The source and summary are in
`/tmp/araphor-live-fact-keys-gdb-exact-20261103.log` and
`/tmp/araphor-live-fact-keys-stack-summary-20261103.txt`.

### Native optimizer checkpoint on 2026-11-03

**Native interface migration: Builds. Live qualification and performance
target: Not done.**

The next connected source uses DataFusion 55.0 and Arrow 59.2. Source-header
feeds read native Arrow columns. They no longer deserialize `SourceState`
rows. Both feeds retain complete-frame validation before lifecycle effects.

Native `named_struct` declares nullable children. DataFusion 55 rejects the
old SQL cast that narrows those fields to the strict package identity.
Remove that private SQL cast. Use checked native Arrow casts at the existing
Control and Graph identity readers. The existing row encoder retains its
selected key types with its converter. It checks compatible array metadata
at encoding. Strict package schemas and actual null, journal, source,
multiplicity, and position checks remain.

The first live run stops at that SQL cast after 8.650 s. It does not prove a
speed improvement. After the boundary correction, the same test completes
the following sections:

| Boundary | SQL change on DataFusion 53.1 | DataFusion 55.0 |
| --- | ---: | ---: |
| External process | 568.844 s | 727.010 s |
| Internal total | 568.792 s | 726.963 s |
| Configuration | 224.314 s | 292.889 s |
| Listening | 0.240901 s | 0.254352 s |
| Subscription setup | 0.067145 s | 0.070532 s |
| Policy setup | 0.230873 s | 0.228978 s |
| Inclusive startup | 224.869 s | 293.460 s |
| First-event observation, failed | 342.397 s | 431.808 s |
| Pipeline shutdown | 1.525 s | 1.694 s |
| OIDC shutdown | 0.000218 s | 0.000215 s |
| First large physical plan | 213.609 s | 281.581 s |
| Second large physical plan | 333.745 s | 422.938 s |

The connected change is a regression. Both tests fail before the first Graph
publication, finding, and notification. Neither test reaches bulk events
or the eight later arrivals. The large plans are inside configuration and
first-event observation. Startup includes its setup sections. Internal
total includes every section. Do not add these nested values together.

Time outside the two large physical plans is 21.490 s before and 22.492 s
after. This remainder includes other setup, smaller plans, and shutdown.
Its remaining internal costs are not measured separately.

The logs are `/tmp/araphor-live-native55-20261103.log` and
`/tmp/araphor-live-native55-record-20261103.log`. Their paired timing files
record external process time. The successful native-interface build takes
192.679 s. The boundary-fix build takes 187.699 s. Both builds are outside
the test durations. The earlier build stops after 640.530 s while it
rebuilds unchanged C++ source. A cached-artifact build fails after 255.463 s,
including an editor build-lock wait. Its API retry fails after 52.906 s.
These build durations do not measure event latency.

#### Native statistics pass result

**Upstream distribution fix: Applied. Live qualification and 100-times
target: Not done.**

The published DataFusion 55.2 optimizer still creates a fresh statistics
context for each child. The working source retains 55.0 and applies the
two production-file changes from
[upstream PR 25098](https://github.com/apache/datafusion/pull/25098), commit
`dcd385e3e1770cf2ee0d0ffd7e70f0d2175dd247`. One statistics context serves
the distribution pass. A plan change clears the cache before the old plan
reference is dropped. Native sorting, statistics, and final checks remain.
The native crate retains its license and notice. Araphor adds no optimizer
or statistics cache. The public native function keeps its prior behavior.

| Boundary | Before backport | After backport |
| --- | ---: | ---: |
| External process | 727.010 s | 653.602 s |
| Internal total | 726.963 s | 653.550 s |
| Configuration | 292.889 s | 264.418 s |
| Listening | 0.254352 s | 0.248845 s |
| Subscription setup | 0.070532 s | 0.069501 s |
| Policy setup | 0.228978 s | 0.268686 s |
| Inclusive startup | 293.460 s | 265.069 s |
| First-event observation, failed | 431.808 s | 386.754 s |
| Pipeline shutdown | 1.694 s | 1.726 s |
| OIDC shutdown | 0.000215 s | 0.000227 s |
| First large physical plan | 281.581 s | 252.890 s |
| Second large physical plan | 422.938 s | 378.007 s |

The same test, workload, filters, gates, and assertions apply. No compilation
runs during either test. The build before this run takes 256.774 s.
Both tests fail before the first finding. Bulk events and later arrivals
do not run. The backport reduces this failed attempt by 10.1 percent.
It does not prove completed-workload performance. The nested intervals have
the same scope as the preceding table. Time outside the two large plans is
22.705 s after the backport, including the external wrapper and other work.
The log is `/tmp/araphor-live-native-statistics-20261103.log`.

The next change calculates distribution-order satisfaction only when its
result can affect a replacement. Native sorting and final sanity checks
remain. The first large plan takes 253.668 s, against 252.890 s before.
Configuration takes 265.085 s; listening, 0.254317 s; subscription setup,
0.073497 s; policy setup, 0.238808 s; and inclusive startup, 265.666 s.
The build takes 236.384 s outside the test. The operator stops this attempt
after 556.405 s while the second large plan is unfinished. The first-event
observation and shutdown do not complete. This partial run proves no speed
improvement or completed workload. The log is
`/tmp/araphor-live-lazy-ordering-20261103.log`.

Source review then finds an extra Araphor pass that imposes ordering inside
every retained join. The actual package argument already has native output
requirements. The two supported source callbacks consume checked scalars
or canonical keyed rows. They do not consume join row order. Remove this
second join pass. Keep native package, query, window, and final ordering
requirements. Completed-workload qualification remains **Not done**.

#### Retained join ordering measurement on 2026-11-03

The same live case runs for 425.979 s before an external interrupt during
its second plan construction. The first physical plan falls from 253.668 s
to 223.212 s. Configuration falls from 265.085 s to 235.006 s. Total setup
takes 235.576 s. Configuration includes the first physical plan; setup
includes configuration. These intervals must not be added together.
The second plan has no completed timing. No finding is produced. No bulk
or warm-arrival result is available.

The paired completed setup stages are: configuration 265.085 s to
235.006 s; listening 0.254317 s to 0.254086 s; subscriptions 0.073497 s to
0.070954 s; and policy 0.238808 s to 0.229004 s. Inclusive startup falls
from 265.666 s to 235.576 s. The externally interrupted totals are
556.405 s and 425.979 s. These totals do not compare completed tests.
The second-plan, event-observation, and shutdown durations are unknown.

The source change removes the second `SourceJoin` traversal and its blanket
ordering requirements. `PackageExec` still adds native output requirements
at each real package argument. Native SQL ordering requirements remain.
The first traversal still selects the retained join side. The isolated
commit preserves that traversal from its parent revision. The measured
working tree also contains the recorded native optimizer and identity
changes; this measurement does not qualify the isolated commit alone.

The focused build takes 189.707 s. The external test log is
`/tmp/araphor-live-join-order-20261103.log`. The stopped attempt is a partial
measurement, not a test pass or a 100-times performance result.

### Native table-provider boundary on 2026-11-03

**Implementation: In progress. Live qualification and the 100-times target:
Not done.**

The last first-plan trace constructs 2,756 source operators for seven Graph
input roles. The counts are: capture 1,591; control 895; status 51; facts 75;
records 138; window 3; and affected records 3. These counts describe repeated
plan construction. They do not count distinct events or prove execution
counts.

A native SQL plan scans a Graph input
  -> the existing `SourcePort` table provider prepares its driver and header with DataFusion
  -> the provider checks each native physical schema against its logical schema
  -> the existing `PortExec` owns those prepared inputs and exposes its output reader
  -> native filters, projections, and limits select the provider output

A subscription executes or resets that plan
  -> source inventory follows both provider-owned inputs and the output reader
  -> key binding checks the outer join before it prepares inner lookups
  -> replay and before-key binding use the same complete source inventory
  -> native reset clears both owned plans and the visible reader

This change removes `PortPlan`, source lowering, and their custom logical
node equality, ordering, and hashing. It adds no operator or cache type.
The provider retains source demand, image, clock, window, schema, and key
checks. Real package arguments retain native output requirements. A scan
can still occur once for each table reference. This change does not yet
prove one construction or execution per Graph input.

The source reviewer approves the exact eight-file change. The focused build
passes in 193.004 s. The connected first physical plan takes 218.309 s,
compared with 223.212 s before the boundary replacement. Configuration
takes 229.559 s. Listening takes 0.252998 s, subscriptions take 0.071547 s,
and policy takes 0.230702 s. Inclusive startup takes 230.130 s. The first
plan is inside configuration; configuration is inside startup. The attempt
stops after 298.721 s during the next source plan. No finding is produced. The log is
`/tmp/araphor-live-port-provider-20261103.log`.

This change removes a custom planner extension, but the measured first-plan
reduction is about two percent. Repeated provider-input preparation remains.
The second plan, bulk workload, and warm arrivals have no completed result.
No completed-workload speed factor is claimed. No workload, assertion,
acknowledgement gate, or progress gate is changed.

### Retained native provider inputs on 2026-11-03

**Implementation: In progress. Live qualification: Not done.**

The provider retains its two native input plans when the existing reuse
check succeeds, the input has no package calls, the clock count is zero,
no runtime window exists, and no local table is used. The existing provider
owns its constructor planning state and one native preparation cell. This
change adds no registry, cache key, result comparison, or serialized data.

A definition prepares a reusable provider
  -> the provider prepares its driver and header once with DataFusion
  -> canonical preparation disables native dynamic filters and defers source lookup
  -> each scan resets ordinary native state and assigns fresh physical read identities
  -> each nested provider receives independent input plans and an independent output binding
  -> the outer source lookup binds that scan's keys after instantiation

An input image or clock changes
  -> the provider creates a separate preparation cell for that variant
  -> package-free sealing retains the existing immutable provider
  -> package-dependent, local, volatile, and runtime-window inputs keep incoming-state planning

A warm subscription advances
  -> the existing native reset keeps its read identities stable
  -> the current source snapshot supplies new journal positions and rows

Instantiation rejects a prepared key reader or key producer. The stored
pair precedes key binding. Each output reader must retain the expected port
origin before the new scan remaps that origin. Logical families, schemas,
and native ordering remain. The source reviewer approves the exact change.
The same live case fails after 161.072 s. The build passes in 189.140 s,
after a 14.080 s compiler failure at the extracted reader call. That failure
is build time, not execution time.

| Completed interval | Seconds | Scope |
| --- | ---: | --- |
| First physical plan | 47.761607 | Inside configuration |
| Configuration | 58.189235 | Inside startup |
| Listening | 0.246326 | Inside startup |
| Public subscriptions | 0.061579 | Inside startup |
| Policy | 0.230003 | Inside startup |
| Startup | 58.742683 | Includes the preceding setup stages |
| First source admission physical plan | 69.238193 | Inside the first-notification wait |
| First-notification wait | 90.146457 | Fails at the unchanged progress gate |
| Pipeline teardown | 12.128534 | Includes cancellation and worker completion |
| OIDC teardown | 0.000535 | Separate teardown stage |
| Internal total | 161.019302 | Includes startup, observation, and teardown |
| External total | 161.071990 | Includes the process wrapper |

The log is `/tmp/araphor-live-port-retained-20261103.log`. No finding is
produced. The source journal cursor reaches 1. The Graph result remains
absent. The run reaches an empty expiry commit, but this commit is not a
Graph detector result. No bulk or warm-arrival result is available.

First-plan construction falls from 218.309 s to 47.762 s. Configuration
falls from 229.559 s to 58.189 s. These are measured planning reductions,
not completed-workload speed factors. The 100-times target is **Not done**.

A separate parent-debugger run samples the remaining CPU work. Its active
stack is `PortExec::instantiate` -> native child replacement ->
`ProjectionExec::compute_properties` -> equivalence projection. The walk
changes physical read identities but uses native property recomputation.
Native DataFusion provides `ChildrenPropertiesMode::Keep` for unchanged
properties. The proposed next change uses that native mode during
instantiation. The debug run is stopped and is not timing evidence.

The native `Keep` change is implemented in the existing instantiation
method. It keeps schema, expressions, ordering, distribution, and statistics
while it assigns new read identities. Native reset still clears execution
state. The existing parser stack guard protects recursive visits.
The focused build passes in 189.356 s. The same live case fails after
130.920 s. The completed stages are:

| Interval | Seconds | Scope |
| --- | ---: | --- |
| First physical plan | 28.064326 | Inside configuration |
| Configuration | 38.428425 | Inside startup |
| Listening | 0.249351 | Inside startup |
| Public subscriptions | 0.062256 | Inside startup |
| Policy | 0.227493 | Inside startup |
| Startup | 38.982375 | Includes the preceding setup stages |
| Source-admission physical plan | 40.385921 | Inside first-notification wait |
| First-notification wait | 90.149156 | Fails at the unchanged gate |
| Subscription physical plan | 39.016039 | Starts inside observation and completes during teardown |
| Pipeline teardown | 1.725127 | Includes the end of subscription planning |
| OIDC teardown | 0.000548 | Separate teardown stage |
| Internal total | 130.858216 | Includes setup, observation, and teardown |
| External total | 130.919515 | Includes process wrapper |

The log is `/tmp/araphor-live-port-keep-20261103.log`. No finding is
produced. A parent-debugger sample then identifies native projection
property recomputation inside `SourceLookup::optimize`. The source
reviewer approves use of native `Keep` at the four existing key-binding
child replacements. The change preserves binding choices and key checks.
The source-key change builds in 189.349 s. The same live case fails after
128.445 s. The first plan takes 25.617536 s. Configuration takes 35.744582 s;
listening takes 0.244901 s; subscriptions take 0.061240 s; policy takes
0.225705 s. Inclusive startup takes 36.291744 s.

Source-admission planning takes 37.646755 s. The later subscription plan
takes 36.226225 s. Both occur inside the first-notification observation.
That observation fails at 90.274181 s. Pipeline teardown takes 1.782505 s;
OIDC teardown takes 0.000591 s. The internal total is 128.350022 s. The
external total is 128.444935 s. The log is
`/tmp/araphor-live-lookup-keep-20261103.log`.

No finding is produced. The small reduction does not complete the target.
The remaining event path still builds the same program at source admission
and again at subscription execution. The next replacement must retain the
complete prepared program before events arrive. Source lookup and native
input preparation alone do not finish proposal 1.

### Complete native program retention on 2026-11-03

**Implementation: In progress. Live qualification: Not done.**

The remaining measured duplication is source admission at 37.647 s and
subscription planning at 36.226 s after the first event. The replacement
retains the complete native program before events arrive.

Graph program preparation
  -> Analysis builds continuation and the control gate before Query seals the program
  -> Query preserves resolution-time source access and adds the final plan dependencies
  -> Analysis checks image authority and installs the context initializer
  -> Query prepares native execution once and retains the executable with its real Engine owner

A new source appears
  -> Analysis validates the prepared Engine and facts owner
  -> Analysis creates a fresh source session and binds the saved definition revision
  -> the original instance admission checks remain
  -> Query attaches a new native publication sink and subscription wrapper to the retained program
  -> native local sanity checks validate new wrappers
  -> execution uses fresh capture, source-index, call, and task state

The logical plan has no public mutable field. A replay-selected logical
output has no copied executable. Foreign Engine owners and ineligible
clock, window, or local-table plans retain valid compilation paths. No
hash key, opaque plan leaf, new execution owner, or polling loop is added.
The [source review](../guides/araphor-retained-execution-review.md#complete-native-graph-program-on-2026-11-03)
states each implemented owner and the remaining native-library readiness
limit. The same live case must provide the timing and delivery result.

#### Complete-program live measurement

The source review passes for the combined Query and Analysis change. The
focused build takes 195.684241 s. The same live case then fails in
147.091725 s. Its internal total is 147.008740 s.

| Measured section | Time | Scope |
|---|---:|---|
| Configuration | 55.628746 s | Includes the initial native plan |
| Initial native physical plan | 45.127513 s | Inside configuration |
| Listening | 0.086593 s | After configuration |
| Notification subscriptions | 0.060285 s | After listening |
| Policy setup | 0.281208 s | After subscriptions |
| Complete startup | 56.127551 s | Includes the preceding setup sections |
| First notification wait | 90.199012 s | Fails at the unchanged gate |
| Pipeline stop | 0.680285 s | After the failed wait |
| OIDC stop | 0.000666 s | After pipeline stop |

The two large physical planning passes after event arrival are absent.
This is a measured reduction in repeated planning. It is not a completed
workload result. The evaluate invocation at cut 21 reports 8,404 source
reads and 6,984 rows for one event. Its input log contains 31 record reads,
14 status reads, and 11 fact reads. It publishes no Graph result or finding.
The next work must explain that missing result and remove the repeated
input computation. The log is
`/tmp/araphor-live-complete-ready-20261103.log`.

A later diagnostic run adds one DEBUG event at the existing Analysis
subscription error boundary. The focused build takes 155.255537 s. The
same case fails in 146.553355 s: startup 55.604068 s, including configuration
55.125569 s and its native plan 44.852088 s; notification wait 90.195073 s;
pipeline stop 0.669189 s; OIDC stop 0.000550 s. Listening takes 0.082868 s,
subscription setup 0.060299 s, and policy setup 0.271537 s, all inside startup.
The error is `the materialized input is absent: Port(26)`. Derived-input
metadata uses a logical port identity that is absent from the actual
physical input. Execution stores port data under physical read identities.
The log is `/tmp/araphor-live-ready-failure-20261103.log`. This diagnostic
run does not prove a performance change.

The derived-input guard correction passes source review. Its focused
build takes 191.000634 s. The unchanged case starts in 55.439231 s:
configuration 54.946314 s, including native physical planning 44.487436 s;
listening 0.085854 s; subscriptions 0.061374 s; policy 0.281124 s. The process
package completes in 69.503 ms and the cross-node package in 46.557 ms.
These package spans exclude input preparation. Credentials input preparation
then fails because another physical port was not materialized. The failure
occurs about 10.316 s after startup. The diagnostic run is interrupted after
that known failure at 78.865103 s, with exit -2. No complete-workload timing
or speed factor is claimed. The log is
`/tmp/araphor-live-physical-input-metadata-20261103.log`.

The optional executed-input metadata correction passes source review. Its
focused build passes in 190.540733 s. The same case starts in 55.731831 s:
configuration 55.237538 s, including native physical planning 44.737835 s;
listening 0.088084 s; subscriptions 0.061592 s; policy 0.271398 s. All three
package evaluators complete: process 61.043 ms, credentials 31.723 ms, and
cross-node 48.820 ms. These spans exclude input preparation. Publication
then rejects `graph canonical affected roots`, about 10.213 s after
startup. The run stops after that known failure at 104.308969 s, exit -2.
There is no complete-workload result. The log is
`/tmp/araphor-live-executed-input-metadata-20261103.log`.

The duplicate Graph target registry is removed. Source review passes; the
focused build takes 153.080634 s. The same case starts in 54.607899 s:
configuration 54.226778 s, including native physical planning 44.371843 s;
listening 0.063004 s; subscriptions 0.063979 s; policy 0.238888 s. The first
source completes the event, package, Graph, finding, and notification path
in 17.320844 s. Graph publication 26 stages 66 support rows and inserts 31
rows. Evaluator times are process 106.676 ms, credentials 31.025 ms, and
cross-node 56.471 ms, excluding inputs.

The full case fails in 163.056577 s. Internal total is 162.954116 s;
pipeline stop takes 1.022289 s and OIDC stop 0.000595 s. The next completion
check waits for 90 s because cut 21 commits Graph publication 26 but reports
publication zero to the subscription. An extra empty execution at cut 26
publishes 32. The static feedback flag forces the first publication to be
incomplete merely because its SQL reads Graph metadata. This is the next
concrete progress defect; no complete-workload speed factor is established.
The log is `/tmp/araphor-live-native-input-ownership-20261103.log`.

The source-frontier completion change removes the static feedback flag.
Source review passes and the focused build takes 154.163885 s. The same
case starts in 55.261421 s: configuration 54.849944 s, including native
physical planning 44.633894 s; listening 0.089263 s; subscriptions 0.063313 s;
policy 0.243617 s. The first finding and notification arrive in 17.396065 s.
Subscription completion now correctly reports publication 26 at cut 21.

The case fails in 73.719834 s at `unit committed without this execution`.
All three package events and all three matching commit events are present
in the global log. The native partition receiver starts tasks with a
no-op tracing hook, so package events do not reach the scoped collector.
The test and its assertion remain unchanged. A stateless implementation
of DataFusion's native tracing hook passes source review. Its build and
runtime proof are pending. This failed run is not a speed factor.
The log is `/tmp/araphor-live-graph-frontier-completion-20261103.log`.

#### Native task and source-control measurements

The native DataFusion task hook now carries the invoking tracing dispatcher
and span. The unchanged execution-to-commit assertion passes for all four
initial sources. The focused build takes 191.812096 s. The run stops after
confirmed bulk read-control failures at 213.426846 s. Startup takes
55.042500 s: configuration 54.651384 s, including native physical planning
44.629743 s; listening 0.082292 s; subscriptions 0.060604 s; and policy
0.233551 s. Initial event-to-notification sections take 17.122480 s,
18.044350 s, 19.221436 s, and 20.423512 s. The log is
`/tmp/araphor-live-native-task-tracing-20261103.log`.

Each source callback then receives an operation-local database control.
It inherits cancellation and deadlines. The focused build takes
193.326576 s. The run stops after confirmed false resets and a remaining
replay-control failure at 277.443348 s. Startup takes 54.762609 s:
configuration 54.358287 s, including native physical planning 44.165963 s;
listening 0.086375 s; subscriptions 0.060715 s; and policy 0.239189 s.
The four initial event-to-notification sections take 17.324471 s,
18.303430 s, 19.612635 s, and 20.877165 s. All four initial source checks
pass. Bulk processing starts and commits more results. It still fails.
The log is `/tmp/araphor-live-source-operation-control-20261103.log`.

These are interrupted runs of the same case. Startup includes its setup
sections; configuration includes planning. Initial notification sections
run in sequence. Package evaluator spans exclude input preparation and
can overlap. Neither process duration proves completed-workload speed.
The workload, assertions, and timeout gates are unchanged.

#### Call-point live result

**Focused build: Done. False-reset correction: Observed. Complete workload
and performance target: Not done.**

The connected build passes in 217.434504 s. The unchanged live case fails
after 284.597287 s. Its actual error is `Control unary RPC timed out`
during a bulk upload. The six Analysis cancellation messages occur during
shutdown. No `read control` collision occurs before shutdown. All 21
continuing call commits retain their actual prior results and report
`reset=false`. The eight later arrivals do not run.

| Boundary | Elapsed |
| --- | ---: |
| Configuration | 55.198427 s |
| Native physical planning, inside configuration | 44.984633 s |
| Listening | 0.084568 s |
| Subscription setup | 0.061748 s |
| Policy setup | 0.241958 s |
| Inclusive startup | 55.601662 s |
| Initial notification, source 33 | 17.283643 s |
| Initial notification, source 34 | 18.495476 s |
| Initial notification, source 35 | 19.622795 s |
| Initial notification, source 36 | 20.996588 s |
| Pipeline shutdown | 6.915048 s |
| OIDC shutdown | 0.000210 s |
| Internal total | 284.164726 s |
| External process | 284.597287 s |

The first Graph conversion takes 13.356 ms. Its managed commit takes
2.972047 s: evidence preparation 0.008 ms, writer acquisition 0.082 ms,
transaction work 2.925956 s, metadata commit 45.938 ms, and promotion and
wake 0.062 ms. The first notification handler takes 2.718678 s: native
column decoding 0.017 ms, head resolution 44.305 ms, and work processing
2.674356 s. Notification processing includes its existing routing,
storage, and delivery calls. These internal costs are not isolated yet.

During bulk input, one managed write spends 12.360090 s acquiring its
writer and 1.636474 s in transaction work. Other writes spend
3.595286–4.226579 s in transaction work. Metadata commits for these
samples take 17.355–84.455 ms. Writer acquisition includes the existing
writer-owner preparation; this measurement does not isolate lock wait
from catalog projection and capacity checks. The intervals are disjoint
within one write. Concurrent writes and notification work can overlap.
Do not add their durations to derive wall time.

The first source execution records 9,275 native source reads for one
event. Later cuts still record thousands of reads. Initial notification
time does not materially improve in this correction. The next targets
are repeated input execution and repeated work while the writer is held.
Journal uploads use that same writer owner. Preserve the workload and
RPC timeout when those owners change. The log is
`/tmp/araphor-live-call-points-native-boundaries-20261103.log`.

#### Native control query factoring

The first factored control query passes its source review and focused build
in 234.509284 s. The unchanged case fails during logical admission after
3.980711 s. Native planning reports that lambda variable `h` is absent.
The configured native generic SQL dialect does not parse that expression
as a lambda. Startup, package execution, Graph publication, bulk input,
and notification delivery do not complete. This short failure is not a
performance result.

The correction uses native conditional aggregates and `UNNEST`. It adds
no dialect-specific parser path, custom planner, or input/output storage.
Source review and the same live case must qualify the corrected query.
The failed log is `/tmp/araphor-live-native-control-linear-20261103.log`.

#### Retain the actual call source point

**Design review and implementation: Done. Initial and continuing calls:
Observed. Cold recovery and complete live qualification: Not done.**

A progress-only publication advances the subscription's selected result.
It does not replace a package call that did not run. The current code
compares those different result revisions and resets the package. For
example, a call result at publication 26 remains valid when a later empty
publication advances the subscription to 32. The bulk trace incorrectly
shows a new reset and a repeated root at cursor 1.

Retain each actual call's source point in the existing source index.
Use the checked native attempt and receipt to identify the point. Pin
its existing indexed Arrow blocks before old versions can be removed.
Only calls present in the committed receipt replace their prior points.
An empty receipt advances subscription progress but retains call points.
The existing Before view reads the exact retained point. It does not
read the old journal prefix again. Reserve point metadata before Data
commits. Use the actual receipt for the source-view acknowledgement.

On recovery, validate the exact chain of selected results and call points.
Read the central journal once at the earliest required point, then apply
its committed changes to the current head. A missing chain, expired
reference, or invalid source point is an explicit error. Do not silently
rescan old input during a warm call or reset its state. Replay database
operations also require separate operation controls with inherited
cancellation and deadlines.

The historical approval record below predates the current approval at the
start of this file. All six proposals and necessary native DataFusion
reworks are now approved. Completed event delivery and the 100-times
performance target remain **Not done**.

**Measurement record: Done. Proposals 1 and 5: Approved; implementation in
progress. Proposals 2, 3, 4, and 6: Not approved; implementation Not done.**
The user approves retained execution state, change inputs, contribution
ownership through `araphor-graph`, measurement with the existing workload,
and commits. Completion requires measured reductions in input/package work
and Graph application work. This approval does not include the other
proposals or a storage engine change.

The parent designs are [component ownership](araphor-component-redesign.md),
[packages and jobs](araphor-package-jobs.md), and
[native Graph storage](araphor-graph-storage-reduction.md). The native Graph
storage record already proves its logical payload reduction. This plan
addresses execution and delivery latency.

## Multi-source incremental qualification

**User request: Approved. Implementation and qualification: Not done.**

The user removes the old 1,592-event backlog test. Its Rust file and its
private backlog helpers are removed. The recorded results below remain
historical evidence. They do not qualify the replacement test.

The replacement is a normal Rust test in
`crates/mithril-e2e/src/discovery/packages/required/incident/incremental.rs`.
It uses four sources with 4,096 initial events per source. Each source first
receives one denied event. Its work is observed before the source grows.
Two later rounds append one denied file-read event to each source.
Most initial events have different process and task identities. A new event must not require the
complete source history as causal support.

Node appends an event to its WAL
  -> authenticated Control intake commits the event to the central journal
  -> Query notifies the subscriptions that depend on the changed data
  -> the subscription creates its task context for the committed source cut
  -> DataFusion executes the prepared native plan with that context
  -> native affected-key and support queries select the required rows
  -> the package computes the affected Graph contributions
  -> Data commits changed contributions, references, and progress together
  -> the Follow streams expose the Graph, finding, and notification

The test sends events through the real Node WAL and authenticated intake.
It receives event rows, small Graph header rows, finding rows, and notification
rows through public Follow subscriptions. It does not call a journal point
reader, a Graph getter, managed history, or the notification Router. Journal
reads belong to the running native subscription plan. The test compares the
ordered event stream with the exact uploaded bytes and journal positions.
It checks stable native finding value IDs and source isolation. It does not
subscribe to a complete serialized Graph payload.

A stored notification reference can remain at its original publication when
the finding value does not change. Each new finding must arrive through the
notification subscription with its actual publication reference.

The test checks the actual source and Graph input work. A small guest input
does not prove that Query avoided a complete source scan. Continuing calls
must use their exact prior result as the change base. An unrelated source
must keep its committed Graph head. Stored contributions for untouched units
must keep their existing membership intervals.

Use native DataFusion metrics and normal structured debug events for work
counts. Preserve the current trace dispatcher across existing task and
blocking boundaries. The test uses a local telemetry subscriber. Do not add
a host getter, a durable input or output copy, a second Graph state owner,
or timer polling. No new elapsed-time pass/fail limit is part of this
functional test.

The working replacement uses native logical children for affected records,
facts, and scalar window state. The old six-query capture and complete Graph
reconstruction are removed from that path. The obsolete whole-input
`GraphFacts::facts` callback is removed. The domain fact resolver remains.

The replacement is **Not done**. The frozen coverage merge must preserve
each required report and its qualification. Finding and notification reads
still expand complete provenance. The replacement must select the actual
finding's owning units. Native source read counts must be bounded. A small
returned batch does not prove bounded work.

The test waits for the exact Graph publication, its captured revision, the
completed source reads, and the completed subscription execution. It checks
changed package units and native membership writes. It also checks the
complete journal frame's record count and body bytes against the actual
single-event upload. The test does not accept an arbitrary multiple of the
cold work count.

Source checkpoint on 2026-11-01:

- `cargo check -p mithril-control --tests --message-format=short`: passed
  without warnings. This check covers Query, Data, Analysis, Control, and
  Control tests at that checkpoint. It does not cover the later source fixes
  or the Mithril end-to-end test.
- Data `historical_call_members_require_unit_anchors`: passed.
- Data `graph_reopen_`: both selected-call recovery and corruption rejection
  passed. The corruption case rejects incorrect native captured revisions.
- Control `managed_captures_control_proofs`: failed before execution because
  the coverage adapter tried to replace the protected `events` source. The
  working correction uses a private view and a native SQL CTE. Qualification
  of that correction is **Not done**.
- The four-source end-to-end test has not passed. No new latency or speed
  improvement is proven.

Source checkpoint on 2026-11-02:

- `cargo check -p araphor-analysis -p mithril-e2e --tests --message-format=short`
  passed without warnings before the later test and diagnostic edits. This
  result does not qualify the current four-source test.
- The focused Analysis run passed `native_projection_keeps_policy_values`.
  `keeps_frozen_coverage` failed during native SQL planning. The fixture now
  uses equivalent explicit join conditions. The retry passes that point, but
  fails at the source-port key schema check.
- The same retry built the Control test executable. Its direct
  `managed_captures_control_proofs` run also failed at the source-port key
  schema check. No Graph execution or coverage result is proven by these
  failed runs.
- The four-source subscription test remains **Not done**. Native coverage
  invalidation, frozen report reads, and the work bounds remain **Not done**.
  No new end-to-end latency, speed factor, or millisecond result is proven.

The next connected run built the selected Analysis, Control, and Mithril
end-to-end test executables in 3 minutes 3 seconds. The projection case passed.
Initial Graph preparation then used one CPU core for more than 12 minutes.
The run was stopped for diagnosis. The other selected cases did not run.

Two debugger samples of the same focused case identify repeated native-plan
work before package execution. One sample traverses native physical-plan
invariant checks. The other hashes nested `SourcePort` children while
`prepare_on` prepares `graph-settings`. The DuckDB worker is idle in the
physical-plan sample. The samples are in
`/tmp/araphor-frozen-child-stack-20261102.log` and
`/tmp/araphor-frozen-caller-20261102.log`. A working correction carries
resolved rows through coverage qualification and removes the second resolver
subtree and its identity join. Runtime qualification is **Not done**.

The native prepared-query probe now executes all five corrected point
queries. The finding queries required an equivalent derived join because
DuckDB rejected a correlated subquery in their outer join. Indexed member
candidates read the requested identity's history. Evidence, source-version,
and context-reference joins still read unrelated rows. This probe uses
synthetic native rows. It does not qualify Rust authority checks or complete
incremental execution. The exact SQL, plans, failures, and correction are
recorded in `/tmp/araphor-five-point-query-review.md`.

## Journal positions for change detection

**User request: Approved. Implementation and qualification: Not done.**

Change detection must use committed journal positions and explicit change
records. Do not hash input rows, output rows, or state to find changes. Do
not create object IDs from content hashes. Hashing is prohibited unless a
specific operation requires it.

Data appends records and commits the journal position
  -> Query receives the commit notification
  -> Query reads changes after the subscription's last committed position
  -> the saved native DataFusion plan consumes those changes
  -> the package returns changed contributions
  -> Data commits those contributions and the new progress position together

Execution or commit fails
  -> the subscription keeps its previous committed progress position
  -> retry reads the same journal range
  -> Data preserves the existing transaction and duplicate-call checks

Working changes remove Query result fingerprints, managed result hash IDs,
Graph member hash keys, and Graph input content revisions. The end-to-end
test compares exact bytes received through subscriptions. Source-key
lookups, generic input receipts, and native value interning still require
completion and focused qualification. No complete hash audit or new speed
improvement is proven at this checkpoint.


### Current change audit on 2026-11-02

Native Query output delivery no longer hashes result rows. Managed result
IDs use the committed publication and call positions. Discovery instance
identity uses its existing source key. Native Graph property and edge
values use exact native keys. Finding values use indexed candidates and
full typed equality. Package context keys use native package metadata.
The retained package-validation cache and its content fingerprints are
removed. These changes have focused owner checks. They do not qualify
complete incremental Graph execution.

The unused Node fixed-sequence window owner and its content-derived
observation and revision IDs are removed from the working source. Node
keeps kernel CPU and sequence coordinates. `EvidenceWal` allocates a
separate durable cursor. The historical ownership and current deletion
checks are in the
[dated evidence review update](mithril-hugging-face-intrusion-prevention/phase-6-implementation-review.md#journal-position-update-on-2026-11-02).

Remaining hash removals include Graph package state, public finding IDs,
Discovery definition revisions, and derived workload and source IDs. OCI
blob validation, signed policy and catalog integrity, and WAL corruption
checks have separate integrity requirements. An integrity check must not
be used as a change detector. The complete hash audit is **Not done**.

A 90-second diagnostic run of `keeps_frozen_coverage` records 135 native
Control-source compilations and 55 Status-source compilations during
initial preparation. The run ends at its diagnostic cutoff. Control header logical optimization takes 7.549 seconds
in total. Status header logical optimization takes 14.726 seconds. These
are observations from one partial run, not a work bound or event latency.
Nested physical-planning scopes overlap and must not be added together.
The trace is `/tmp/araphor-cdc-source-plan-profile-20261102.log`.
Complete Graph preparation and the four-source subscription test remain
**Not done**. No new end-to-end speed factor is proven.

## Intended end state

### Native identity checkpoint on 2026-11-03

**Native Graph state, Node source IDs, and executable cache keys: Done.
Complete hash removal and incremental Graph qualification: Not done.**

The Graph state pool uses native fact references and exact typed keys.
Its independent qualification passes 31 Graph cases in 18.46 seconds
and 65 Data Graph-row cases. The Data aggregate time was not measured. The grouped 8,193-witness case remains unqualified. That run uses
a 180-second observation limit. Its exact elapsed time and internal stage
times were not recorded. These results do not measure event latency.

Node allocates CPU source and interval IDs at its existing durable coverage
owner. Reopen checks those IDs against native WAL streams before it saves
coverage state. Its existing snapshot path now contains strict MessagePack.
All 52 Node observation cases pass in 4.21 seconds. The
[native source review](mithril-hugging-face-intrusion-prevention/phase-6-implementation-review.md#native-source-identity-update-on-2026-11-03)
records the exact owner and proof boundaries.

Wasm compilation reuses the checked OCI image identity and exact model.
The public raw-code cache uses exact executable bytes. It computes no new
code digest. The initial Wasm run takes 76.02 seconds, with 29 passes and one obsolete
fixture failure. The corrected default-quota fixture passes in 9.18 seconds.
Together those runs cover all 30 owner cases. Ten focused Query cases pass, including
clock isolation, input receipts, native view behavior, warm preparation,
and checkpoint capacity. The
[cache review](../guides/araphor-retained-execution-review.md#native-executable-cache-keys-on-2026-11-03)
records the code and verification flow.

Remaining application hashes include public finding IDs, definition
revisions, workload and exact-file-object IDs, decision-catalog checksums,
and Observability request, target, execution, and source hashes. Private
cursor request binding requires a separate exact-request review. Required
OCI and signature checks remain separate from change detection.

The latest Graph diagnostic runs for 120.07 seconds. Its first large
physical-planning pass completes in 62.85 seconds. Four smaller completed
passes take 0.12 seconds together. The remaining 57.09 seconds include
setup, work between passes, and a second unfinished large planning pass.
Those parts were not measured separately. The five completed planning
spans do not overlap. The displayed values are rounded. The source change removes the
temporary Graph wrapper and Status dependencies from raw input readers.
Earlier 120-second runs did not finish the first large planning pass.
These partial runs do not establish a whole-path speed factor. The trace
is `/tmp/araphor-cdc-local-reader-frozen-20261103.log`. The full Graph,
Control, and four-source path remains **Not done**.

Each new test report must state the actual elapsed time, measured section
times, the source change, and a comparable prior result when one exists.
State which sections overlap and which sections were not measured. A
cutoff statement alone is not a timing report. Build time and functional
verification time do not establish event-processing latency.

### Prepared packages for running jobs

**User requirement: Approved. Implementation and qualification: Not done.**

A running job must retain its prepared package executables before it waits
for subscription events. Event delivery must not load a native library or
compile a Wasm component.

The operator starts or recovers a job
  -> Analysis checks the saved definition and current authority
  -> Query prepares the native plan and its selected package calls
  -> Package runtime loads and retains the selected executables
  -> Query starts the subscription with those prepared executables
  -> Analysis completes the existing start or recovery acknowledgment

An event commits
  -> Query wakes the existing subscription
  -> the native plan calls the retained package executable
  -> Data commits the returned changes and progress

Preparation fails
  -> Analysis does not report the job ready
  -> the existing owner releases its preparation resources

The operator stops the job
  -> Query cancels and drains the existing subscription
  -> Package runtime releases its executable references after calls finish

Image installation and definition admission start no job.

Current source has these gaps:

| Owner | Current behavior |
| --- | --- |
| `Runtime::prepare` | Prepares Wasm code. The native branch validates limits and returns no prepared executable. |
| `PackageExec::new` | Calls runtime preparation during physical planning. This does not prove readiness before the subscription waits. |
| `Runtime::evaluate_reserved` | Loads the native shared library inside each invocation. |
| `WasmExecution::invoke_reserved` | Creates a store, component instance, and interrupt worker for each invocation. Compiled code uses the existing cache. |

Use the existing Query, Analysis, and package runtime owners. Native library
reuse must preserve its file, dependency, ABI, and release-callback lifetime.
The current native ABI has no reentrancy guarantee. Do not add unsafe shared
access to make the library reusable. Review its existing worker ownership
before implementation. Preserve Wasm invocation isolation and explicit SDK
saved state. Retained code does not authorize shared guest globals. Use the
existing job lifecycle and acknowledgment; add no Ready state or public API.
Measure preparation and invocation costs separately.

### Central journal references

The user requires removal of saved package input, output, selected-result,
and source-capture payloads. A call records its package revision and source
time. Source time identifies the committed data visible to the call. It does
not identify the call's complete input. SQL determines that input.

Data commits a source event
  -> the subscription receives the committed source position
  -> native DataFusion executes the admitted SQL at that source position
  -> the package consumes the query result
  -> Data commits the call reference and its canonical produced data
  -> the subscription advances after the commit succeeds

A caller requests replay or restart recovery
  -> Data checks the retained call, package, source, and authority references
  -> Query reads the referenced central journal and immutable context versions
  -> native DataFusion reconstructs the inputs at the recorded source time
  -> execution reconstructs required prior state through recorded calls
  -> replay returns data without publishing a second result

Required source data is no longer retained
  -> replay reports the missing or expired source range
  -> replay does not substitute current data

Remove `managed_arrow` and its payload writers, readers, source IPC records,
and payload accounting. Do not move those copies into another table or blob.
Preserve the existing canonical Graph, finding, notification, package, and
context owners. Their committed data can be referenced by a call.

**Journal-reference replacement: Done.** The user
authorizes this work after the checkpoint at `ef8024ed7`. The payload-based
replay and recovery results later in this document describe the old
implementation. They do not define the new storage requirement.

The checked metadata lookup is implemented by `AnalysisStore::managed_reference`.
It returns the recorded request, source cut, call ID, receipt, and historical
definition. The lookup does not read an Arrow payload or admit publication.
The lookup does not execute a package.

The source removes `managed_arrow`, saved evaluations, saved outputs,
selected payloads, source IPC records, and their accounting. Each call stores
one optional declared checkpoint as its canonical state. Each selected result
stores its receipt, row count, and dependencies. Its body is
empty. Temporary Arrow batches remain in live execution and Replay memory.
They do not persist after a process restart.

Remove the unused source metadata cache and the saved projection contract.
The native query derives its projection from the recorded grant. Keep the
source cut, row identity, schema, and authority checks. The change must remove
production Rust in total. Count production and test code separately. Exclude
blank lines. Use existing execution, restart, replay, and expiry tests. Do not
add a test that only calls a helper with an invented result reference.

Retire the unused host output aliases and local result wrapper. Their earlier
saved-output contract is superseded by reference-only Inspect and explicit
Replay. Remove the automatic producer-replay bridge added for those aliases.
Keep native SDK output dependencies and the local stream used by the context
owner. Keep real lifecycle, replay, source expiry, and permission checks.

Replay uses the original native query, package pins, source cut, invocation
time, and seed. Native source, processor, result-notice, and trace histories
provide administrative values at that cut. Current revocation checks still
apply. Retired event headers preserve acceptance and retention metadata. The
headers do not replace missing event bytes.

**Payload-removal qualification: Done.** Existing Data tests cover source
history, metadata, scope, atomic publication, checkpoints, and empty selected
bodies. Existing Query tests cover the original journal cut, source witnesses,
notification deadlines, and reactive windows. Existing Analysis tests cover
SQL, Wasm, native execution, previous outputs, restart, expiry, and revocation.
The Graph reset Replay case passes with the original input revisions and
coverage for all three detectors. The
[verification record](../guides/araphor-retained-execution-review.md#qualification)
states the source boundaries and exact results.

Final scoped formatting and Clippy pass for the nine affected crates. Clippy
denies warnings and includes their test targets. The full workspace procedure
is not run under the user's relevant-test instruction. No new event latency
or storage-size result is claimed. The Graph functional check takes
2,683.70 seconds; it does not prove millisecond execution.

The complete change from `3f9bbd3a4` removes 10 nonblank production Rust lines
and 607 nonblank test lines. These are separate totals. They include the
necessary history and replay code, the retired storage APIs, and the removed
host aliases. Blank lines do not contribute to either total.

The user approves reference-only Inspect operations. Inspect returns the call
and source references. Explicit replay uses Run permission and reconstructs
data from the journal. Inspect does not execute package code. Remove the
Inspect query operation that reads saved output rows. Keep one metadata read
owner for call and selected references. This approval does not permit current
administrative state to replace missing historical source state during replay.

Data accepts source data
  -> Query wakes the affected subscription
  -> the retained native DataFusion plan reads one committed source cut
  -> the package receives changed Arrow rows and its committed state
  -> Data commits output changes, state, and progress together
  -> affected query and delivery subscriptions receive the committed changes

Use the native SQL parser, logical planner, optimizer, physical planner, and
execution path. Use the same SDK and publication contract for builtin and
installed packages. Keep Data as the only durable owner.

Proposed performance acceptance targets are:

| Work after the job is ready | Proposed target |
| --- | ---: |
| Data receives a normal source update through durable result commit and local notification handoff | p99 at or below 100 ms |
| Initial Graph build for the existing 1,592-event workload, after admission | At or below 500 ms |
| Prepare and complete the existing 130-row local notification update | At or below 50 ms |

These are proposed verification targets. They are not runtime limits,
quotas, timeouts, or reasons to discard work. They require approval before a
new performance test is added. Millisecond behavior is **Not done**.

Record latency from Data arrival and from the committed source signal.
Record kernel capture and network transit separately when physical tests
measure those boundaries. The current trace starts at the source signal.
A declared SQL window can delay execution until its boundary. Measure
execution latency from that boundary. Remote connector response time is
external to local queue handoff; record success, failure, and unresolved
delivery without claiming an external effect before it occurs.

Admission prepares package code and query plans before a job becomes ready.
Cold image installation and job startup have separate timings. A normal
source update must not compile a component or restore the whole job.

## Proposed event flow

Data commits new source rows or a relevant context change
  -> Data publishes the changed tables, sources, keys, and committed revision
  -> Query wakes subscriptions whose native plans use those inputs
  -> each subscription pins the committed source cut and state references
  -> DataFusion executes input SQL over changed Arrow batches
  -> package physical execution computes changed outputs and tentative state
  -> Data checks authority and the expected committed state at publication
  -> Data commits output changes, state, progress, and replay references once
  -> Query adopts the committed state and publishes the output changes

A declared window closes, or selected rows leave a window
  -> the existing Query window stream emits that semantic change
  -> the same physical execution receives inserted and removed rows
  -> the package changes only affected state and Graph membership
  -> Data uses the same atomic publication path

An invocation fails or its authority changes
  -> Query cancels the invocation and releases its pinned inputs
  -> Data rejects publication of an invalid or stale result
  -> tentative output and state do not become committed state
  -> a retry starts from the last committed cursor and package state

The process restarts
  -> Data opens and checks the committed store
  -> Query restores each active job's cursor and saved state once
  -> Query prepares its plan and runtime before it reports ready
  -> the subscription resumes from the durable change position

The notification query receives new findings or relevant route changes
  -> DataFusion selects routes from one authorized snapshot
  -> Data commits a batch of durable delivery obligations and attempt IDs
  -> the delivery stream sends those prepared attempts in the required order
  -> the live authority check applies immediately before each effect
  -> Data commits completed, failed, or unresolved results as a batch
  -> a restart resumes the same durable attempts under the existing retry rules

No polling loop, periodic discovery clock, artificial batching delay, memory
quota, or package-size cap is introduced. A batch consists of available
committed changes. A real window deadline remains a Query processing event.

## Current incremental requirement

**Query, execution, and Graph changes: Not done.** The user requires
incremental computation and storage throughout proposals 1 and 5. Reading
the complete current input and then computing its difference does not meet
this requirement. The complete-target flows and their results below record
earlier implementations. They do not define the required final behavior.

The local TerminusDB source supplies these concrete lessons:

- [Layer queries](../../terminusdb/src/rust/terminusdb-store-prolog/src/layer.rs)
  use stable value IDs and separate addition and removal iterators. Bound
  subject, predicate, or object keys select the corresponding index.
- [Layer builders](../../terminusdb/src/rust/terminusdb-store-prolog/src/builder.rs)
  apply additions and removals against a parent layer.
- [Query compilation](../../terminusdb/src/core/query/woql_compile.pl)
  compiles addition and removal queries to these change readers. It does
  not discover changes by comparing two complete query results.

Reuse these rules with Arrow, native DataFusion plans, and Data's existing
transaction. Do not add a second durable store or a second SQL engine.

Data receives changes after the last committed input cut C
  -> Data captures changed raw, context, proof, and coverage inputs through R
  -> Query prepares a candidate over the retained indexed view at C
  -> native SQL selects affected keys from old and new dependencies
  -> native SQL reads only the changed roots and required indexed support
  -> the same package executor receives exact before, after, and support rows
  -> Data commits typed changes, Graph membership, and input cut R together
  -> Query promotes the candidate view only after that commit is acknowledged

A window closes or removes selected rows
  -> the existing Query window stream supplies the affected keys
  -> the same candidate and publication path applies those changes

Publication fails or the process restarts
  -> failed publication leaves input cut C and its indexed view unchanged
  -> restart loads the committed base and typed change records once
  -> execution resumes with changes after the recovered committed input cut

The input cut differs from the output commit revision. Later arrivals stay
outside R. Concurrent captures must not combine different cuts. Do not
promote a source cursor or mutable input index before publication succeeds.
Retain row counts, reservations, and dependency indexes. A normal update must
not rebuild complete witness lists, input hashes, target Arrow payloads, or
Graph metadata. Preserve exact replay through typed base and change records.

Affected keys include prior dependents and new join candidates. Late input
can create a new match that no prior unit referenced. Use stable record and
context keys at the index boundary. Use local Arrow row indexes only within
the selected package input. A global proof or sensitivity change can affect
all units; an unrelated append does not justify reading all prior records.

Ordinary SQL subscriptions and package inputs must use the same source-change
machinery. Native joins, groups, outer joins, aggregates, and windows must
retain their SQL meaning. An unsupported incremental plan must remain an
explicit implementation gap. A complete-query fallback does not qualify as
incremental execution. Finite snapshot queries retain their native results
and output order.

The first implementation prerequisite is a managed read of the existing raw
change journal. This prerequisite does not complete the context and coverage
feed, indexed native execution, Graph integration, or either proposal. The
reviewer must approve the concrete next source contract and state lifetime
before implementation. Proposals 2, 3, 4, and 6 remain unapproved.

### Managed raw-change read result

**Managed raw-change read prerequisite: Done. Complete incremental Query and
Graph execution: Not done. Proposals 1 and 5: Not done.** This change follows
`516c1fdd`. The
[review route](../guides/araphor-retained-execution-review.md#committed-raw-changes)
links the current owners and tests.

Data accepts a managed `Changes` read after a complete committed input
position. The existing raw journal selects additions and retirement ranges
through the captured revision. The same transaction checks the instance,
grant, generation, lifecycle, call heads, and replay floor. The returned
capture keeps its exact source interests and witnesses. Reading does not
advance durable progress or execution state.

The read rejects relations and explicit input selections that its early
change return cannot supply. Current source metadata remains current
metadata. A dependency-only context request does not read context rows.
An unselected all-context scope is pruned before key resolution. Its original
source interest remains in the sealed capture. The read does not introduce a
new cursor, storage engine, quota, format version, or polling task.

Four new managed journal tests and ten existing raw-change, managed-owner,
and retained-state tests pass. The managed tests cover arrivals after a fixed
snapshot, late gap repair, idle reads, unsupported requests, stale owners,
cancellation, retirement, replay floors, and reopen. The context regression
uses the existing optional key configuration to prove that unrequested
context keys are not resolved. It adds no default limit or performance test.
The proof log is `/tmp/araphor-managed-journal-final-20261031.log`.
Data clippy passes with tests and warnings denied. Scoped formatting,
whitespace, and document-link checks pass. The clippy log is
`/tmp/araphor-managed-journal-clippy-20261031.log`. Full workspace CI was
not run. The user requires relevant checks only.

The Graph caller still uses complete captures. Context and coverage change
feeds, the shared explicit delta-source contract, indexed native execution,
commit-only candidate promotion, and changed Graph metadata remain open.
This prerequisite proves no reduction in incident latency. The recorded
243.94-second diagnostic remains the latest full incident measurement.

### Context-version change read result

**Context-version change read: Done. Complete incremental Query and Graph
execution: Not done. Proposals 1 and 5: Not done.** This change follows
`e80f918fd`. The
[review route](../guides/araphor-retained-execution-review.md#committed-context-changes)
links the reader and its tests.

Data receives a managed or ordinary change read after committed input cut C
  -> Data resolves source keys without expanding the context history
  -> the native revision index selects new context key headers through captured cut R
  -> Data checks tenant, owner, and exact-key scope before it reads a value
  -> the existing verified context reader fetches each selected value by its unique key
  -> Data checks the key, header revision, value revision, and package provenance
  -> Data returns every selected immutable version and its exact reference

The reader uses the same captured transaction for headers and values. Future
arrivals remain outside R. Versions with past or future validity remain in
the change feed. Native SQL can select the required validity later. Reading
does not advance durable progress. Failed reads and cancellation leave the
committed input cut unchanged.

The revision index is installed at store open. The value lookup reuses the
existing decoder and provenance owner. The change adds no storage format,
engine setting, input cap, cache, or timer. The configured key count includes
source, trace, and binding keys. Temporary decoded values release their
memory charge after Arrow and references retain their own allocations.

Seven context tests pass. The tests include both native index statements,
six selected keys in reverse exact-scope order, excluded invalid values,
fixed cuts, validity, corruption, cancellation, enabled limits, and reopen.
The index proof covers the tested source state. DuckDB retains its native
access-path choice. The proof log is
`/tmp/araphor-context-changes-final-20261101.log`.

Fourteen related raw-change, managed-owner, and retained-state tests pass.
Data clippy passes with tests and warnings denied. Its log is
`/tmp/araphor-context-clippy-20261101.log`. Scoped formatting, whitespace,
and 78 local document links pass. Full workspace CI was not run. The user
requires relevant checks only.

The Graph caller still reads complete inputs before it computes differences.
Coverage changes, the explicit delta-source contract, indexed native Query
execution, and Graph integration remain open. This reader alone proves no
incident latency improvement.

### Managed input-frontier result

**Exact binary input frontier: Done. Incremental source execution: Not done.
Proposals 1 and 5: Not done.** This change follows `ad4aad54b`.

A managed subscription captures input through transaction revision R
  -> Query stores input position `(R, u32::MAX)` in the offered frontier
  -> the existing Data publication can acknowledge output commit P
  -> Query emits input position R and publication revision P as separate fields
  -> a live or resumed subscription reads input progress from R

This rule applies to Graph and Selected destinations. The previous generic
managed path used P for consumed input. An arrival between R and P could
then appear to be consumed. The resume checks, runtime initialization, and
runtime progress now use the same input rule. Window acknowledgement keeps
its separate publication-revision check.

Cursor storage and source-scope fingerprints use MessagePack through the
existing workspace dependency. Decoding rejects trailing bytes, unknown
fields, invalid versions, invalid window identities, and inconsistent
positions. No JSON fallback or version change is added.

Twenty-six focused Query tests pass: four cursor tests, seventeen managed
capture tests, and five fixed-window tests. The publication test covers
Graph and Selected destinations in live execution and restart from both the
saved frontier and emitted cursor. A context commit after the last raw
arrival precedes R. Another arrival and a context commit occur during the
held publication. The returned input position remains R. The next execution
processes the pending arrival.

The logs are `/tmp/araphor-input-frontier-codec-final-20261101.log`,
`/tmp/araphor-input-frontier-managed-final-20261101.log`, and
`/tmp/araphor-input-frontier-windows-20261101.log`. Query clippy passes with
tests and warnings denied. Its log is
`/tmp/araphor-input-frontier-clippy-20261101.log`. Full workspace CI was not
run. The user requires relevant checks only.
Scoped formatting, whitespace, and 86 local document links pass.

This change supplies a correct input cut for the change reader. It does not
replace the complete Query or Graph capture and proves no latency gain.

### Coverage change read result

**Coverage change reader: Done. Incremental source execution: Not done.
Proposals 1 and 5: Not done.** This change follows `b2df26330`.

Data receives a coverage change read after complete input cut C
  -> the existing reader transaction fixes committed revision R
  -> the native revision index selects coverage headers after C
  -> Data checks tenant, node, and source scope before it reads a report
  -> a native equality lookup reads each selected immutable report through R
  -> Data returns the report bytes and exact source, revision, and position

Each accepted report has its own global commit revision and ordinal zero.
The existing writer inserts one report per transaction. A unique index on
that revision supplies both native access paths. The report decoder and
coverage writer remain unchanged. A standalone historical read checks the
exact reference and its captured revision. Reading does not advance managed
progress.

Five focused tests pass. They cover fixed cuts, later arrivals, scope checks
before report reads, invalid references and stored rows, cancellation,
idempotence, reopen, backup, restore, and native index use. The index test
uses the production statements and default engine settings. The test log is
`/tmp/araphor-coverage-changes-fixed-20261101.log`. Data clippy passes with
tests and warnings denied. Its log is
`/tmp/araphor-coverage-clippy-20261101.log`. Full workspace CI was not run.
The user requires relevant checks only.
Scoped formatting, task whitespace checks, and 94 local document links pass.

The shared source view and Graph runtime do not use this reader yet. Managed
execution still requests `Read::Snapshot`, executes complete target inputs,
and compares those targets. That path does not satisfy the incremental
requirement. No incident latency reduction is claimed for this reader.

### Native source-view replacement

**Concrete source-record and input-contract implementation: Not done.**
The change reviewer approves the source-record and model flow for
implementation. The approved flow has these requirements:

- Reuse one managed `Step` for the shared source basis. Link its parent to
  the prior selected result. Retain the source cut, projection, typed Arrow
  additions, removal ranges, and exact metadata references once per step.
  Reuse `managed_arrow` for payloads. Remove per-call complete target IPC.
- Data seals the actual read mode, prior selected result, lower input cut,
  and projection in the attempt contract. Initial capture requires no prior
  basis or an explicitly authorized rebuild. Continued capture names the
  exact committed basis. A source-parent edge retains history without
  turning old witnesses into current input dependencies.
- Store the first projected source basis once. Later steps store changes.
  Restart validates the same instance, generation, store, schema, and epoch,
  then restores the indexed view once. Parent result commits are strictly
  older. Equal source cuts remain valid for window transitions.
- Add an `affected` reference to each existing SDK change pair. The reference
  names a typed query input port. Existing native query ports supply before,
  after, and Lookup rows from invocation-local source views. The declaration
  does not introduce another SQL parser, join implementation, or guest ABI.
- Keep the committed index at C in Query. Each invocation reads a candidate
  through R. Promote the exact candidate after its own acknowledgement.
  Failure after COMMIT must adopt that candidate or invalidate the local
  index and restore the committed basis.
- Native DataFusion joins execute the queries. A transparent build-stream
  adapter can expose exact Arrow join keys to the indexed probe provider.
  The provider must not scan all retained keys to evaluate an opaque native
  hash filter. A key wait must not depend on its own probe. Reused and
  concurrent plans require fresh task-local key and filter state.
- Internal Graph facts use stable record and context identities. Local guest
  row ordinals are assigned only after selected support is known. Remove
  global row numbering and complete Graph reconstruction from normal updates.

The first complete slice must execute installed SQL, Wasm, and native
packages through real Selected publication. Its proof must cover changed
inputs, indexed support, failed publication, acknowledgement, and restart.
Coverage integration, Graph migration, ordinary incremental SQL plans, and
window transitions remain required parts of the full goal.

#### Source-record working state

**Shared source records: Partial. Native runtime integration: Partial.
Proposals 1 and 5: Not done.** The working tree follows `29d7a356b`.

Data seals the source read mode, exact committed parent, input position,
selection, and projection. The existing managed transaction stores source
Arrow payloads once on the selected `Step`. A separate source edge retains
the parent without changing ordinary input freshness. Each source metadata
change is an initial state or accepted ranges. Receipt replacement, new
gaps, and exact coverage references use the same captured revision.

Source frames share a proof cell. Data checks the cell before COMMIT and
fills the cell after COMMIT. Cold restoration reads the existing Step proof
and loads one payload frame at a time through a callback. Arrow frames do
not retain cumulative source membership. Data retains current membership in
the existing capture, attempt, and committed execution state.

Zero-batch table headers require zero rows. These headers store no Arrow
payload. Nonempty headers map to contiguous payload slots. Explicit empty
batches retain their payload and exact batch count.

The managed change path now supplies an initial or continued source read.
Query retains indexed Arrow blocks and stages each candidate without
changing the committed index. Native DataFusion joins select matching old
rows by hash key. The existing native join checks key equality. The SDK
change pair names its affected query port. Package execution binds each
input once in dependency order. Complete-target comparison and target IPC
storage are removed from the working code.

The source subscription test passes for three successive context changes.
Each execution delivers one new row. Source history contains three one-row
frames. A new runtime restores the committed frames before it reads the
next change. The selected-key Graph test checks missing current rows,
missing retired rows, duplicates, foreign streams, and cursor zero. These
two tests pass in `/tmp/araphor-native-source-subscription-4.log`.

The order test now reads Arrow rows directly. Its earlier assertion used
an existing helper that sorts values and could not qualify delivery order.
Native query planning retains the caller's query AST and outer scope.
Native physical output requirements preserve the probe input's sort.
The key provider accepts a native sort without a fetch limit. Native joins
still execute the restriction. No replacement parser or sort evaluator is
added. The SQL and Wasm tests restore a new runtime, consume only the two
new context rows, and deliver `[5, 4]`. These checks and the Graph selection
and direct-run checks pass in
`/tmp/araphor-native-source-subscription-9.log`.

The same counter case passes with the source-built native Rust library.
The log is `/tmp/araphor-native-source-native.log`. The complete native test
takes 102.49 seconds with a 171 MiB debug library. This test result does not
measure the latency of an admitted source update. The native test cost
still needs investigation. Multicolumn, outer CTE, inner CTE, explicit SQL
limit, and native duplicate-name checks pass in
`/tmp/araphor-native-source-cte-4.log`. CTE shadowing has the same rejection
as an equivalent query in a plain native DataFusion session.

Data now creates opaque row handles for captured Arrow blocks. Query records
only the old rows that an indexed read selects. Data adds their exact evidence
to the new call and Step. The source record stores compact origin references
and indices. Cold validation reads those named origin headers. It does not
scan their Arrow payloads. A focused SQL subscription check passes with one
new context row and one matching old context row per update. The saved proof
contains only those two context versions. The same check restores a new
runtime before the next update. This test took 3.11 seconds. This duration
covers the complete test, not one source update.

Sixteen focused Data checks pass after the evidence changes. They cover
source records, metadata, replay, and retention. The source evidence test
checks selected old rows, rejected publication, a frozen retry, exact evidence
expiry, invalid support indices, and reopen. These checks took 49.56 seconds.

Cold restoration now borrows IPC bytes and uses the existing SDK decoder.
A caller reserves the decode bound before allocation. Query transfers the
decoded buffers to its existing memory owner before indexing. A failed
restoration discards the partial local index. The final six Analysis checks
pass for SQL and Wasm source changes, indexed support with restart, input
order, native CTE behavior, and selected Graph roots. They took 6.64 seconds.
`cargo check -p araphor-analysis --tests`, formatting for the five changed
crates, and the staged whitespace check also pass. Partial-restoration failure
and incomplete-commit wake behavior still lack their required focused proof.
The full regression suite and incident workload were not run.

Complete Graph integration, general native incremental SQL, and semantic
window transitions remain Not done. The old source metadata loop also remains.
The focused source checks do not qualify complete Graph execution or windows.
There is no new incident latency result.

**Checkpoint and stop: Requested by the user.** The user requires a commit of
the current work and an architecture explanation before work stops. The
checkpoint includes unfinished code. It does not complete this slice or
proposals 1 and 5. The user has rejected the current complexity. The separate
block and table containers, repeated evidence and scope records, and custom
version leases require design review before further implementation.

Native wiring must also reserve the source proof before COMMIT. The proof
cell is empty when the current capture size is measured. The current cached
size does not include the proof vectors that publication adds later. This
memory accounting remains Not done.

Before the native runtime edits, six focused source-record tests passed.
They check shared payloads across two
calls, rejection before COMMIT, exact committed proof, fixed input cuts,
reopen, cancellation, malformed payloads, source order, and empty tables.
Seven existing managed-state tests also passed. Data clippy passed with tests
and warnings denied. The logs are
`/tmp/araphor-source-frames-final-20261101.log`,
`/tmp/araphor-source-basis-regressions-20261101.log`, and
`/tmp/araphor-source-basis-clippy-20261101.log`. These results cover the Data
source-record path before the native edits. They do not qualify the current
working tree, complete native Query integration, or incident
latency. Full workspace CI was not run. The user requires relevant checks.
The six source-record checks also pass after the native input edits in
`/tmp/araphor-source-frames-integrated.log`.

## Measured baseline

The source was `2d7d4164b9c2`. The existing
`discovery::packages::required::incident::backlog::follows_wal_backlog` test
used 950 events from one source and 642 from another. It ran the three OCI
Wasm Graph packages through the current physical execution path.

One final instrumented run passed in **121.13 seconds** with
`RUST_LOG=warn`. Data, Query, and the SDK used the existing test profile's
optimization level 1. This is not a release benchmark. Native DuckDB C API
timers separated SELECT, writes, preparation, appends, and transaction
commands. These are wall times inside API calls, not separate CPU or disk
measurements. Rust time includes conversion, checks, allocation, scheduling,
and probe overhead. Child timings are included in their parent timings.

The diagnostic observation cap was 300 seconds. Observation completed in
84.48 seconds, within the original 90-second cap. The diagnostic cap and
all probes were removed. Forty files were restored from exact copies. A
calibration of 100,000 empty calls with four nested scopes took 307 ms.
No estimated overhead was subtracted. Earlier diagnostic runs must not be
combined with the final run.

### Cursor 950

Data published revision 81 at test time 60,873.318 ms. The prior Graph result
selected cursor 941. The invocation for the next result was
`12ef88f3-6d23-4944-985b-1befd85b6c36`.

| Boundary after Data's source signal | Elapsed time |
| --- | ---: |
| Next Graph evaluation starts | 5,603 ms |
| First package runtime starts | 10,608 ms |
| First Wasm function starts | 10,630 ms |
| Graph result commit completes | 13,746 ms |
| Client Follow receives the Graph result | 16,069 ms |

| Sequential work | Time | Measured cause |
| --- | ---: | --- |
| Finish the previous Graph run | 5,603 ms | The subscription is still executing the prior cut |
| Session and physical plan setup | 26 ms | Physical planning itself takes 1.3 ms |
| Capture source and saved calls | 3,663 ms | 1,952 ms writer wait, 1,059 ms DuckDB, about 652 ms other work |
| Register the attempt | 659 ms | 315 ms DuckDB, 325 ms writer wait, about 19 ms other work |
| Input SQL and Arrow work before the first runtime call | 658 ms | Native DataFusion input execution and argument preparation |
| Three package runtime calls | 255 ms | Runtime intervals overlap |
| Finish and convert output | 69 ms | Host processing |
| Final result commit | 2,815 ms | 2,048 ms DuckDB and 766 ms other work |

The direct Wasm calls took 49 ms, 63 ms, and 64 ms. Their complete runtime
calls took 97 ms, 113 ms, and 135 ms. The final Graph input projection took
150 ms within input preparation.

`coordinated_reader` takes the writer mutex before opening the snapshot.
The reader waited behind the other source's Graph commit. Pending raw
projection took less than 0.01 ms at that boundary. Inside source capture,
restoring three saved calls took 1,475 ms: 884 ms DuckDB and 590 ms Rust.
That nested operation executed 105 SELECT statements. The complete captured
read executed 134 SELECT statements.

### Final Graph commit

| Native operation | Count | Time |
| --- | ---: | ---: |
| SELECT execution | 97 | 688 ms |
| INSERT and UPDATE execution | 94 | 327 ms |
| Parse and prepare | 176 statements | 179 ms |
| Append operations, including 29 flushes | 53,080 C API calls | 233 ms |
| CREATE and DROP execution | 22 | 37 ms |
| Transaction commands | 3 | 549 ms |
| Bind, fetch, and other native operations | — | 35 ms |

COMMIT itself took 547 ms. Appender flushes took 134 ms within the append
total. Rust work outside native API calls took 766 ms. Thus the operation
called Graph publication does substantial reading and preparation as well as
writing. Each call's `apply_output` interns records from the complete Graph
input manifest again.

### Notification processing

One 130-row update took **41,091 ms**: **38,316 ms inside DuckDB** and
**2,774 ms outside it**.

| Operation | Count | Time |
| --- | ---: | ---: |
| SELECT execution | 3,529 | 14,943 ms |
| INSERT and UPDATE execution | 2,600 | 12,521 ms |
| Transaction commands | 6,642 | 8,885 ms |
| Parse and prepare | 803 statements | 877 ms |
| Fetch, bind, and other native operations | — | 1,091 ms |
| Rust work outside native calls | — | 2,774 ms |

This update made 650 durable metadata commits, five per selected row. COMMIT
calls took 5,208 ms. One row caused about 27 SELECT executions and 20 write
executions. The first nonempty 138-row update took another 14,342 ms:
7,791 ms DuckDB and 6,552 ms other work. These intervals overlap other
subscriptions and must not be added to total test time.

Across the complete test, the owners made 769 durable metadata commits,
1,459 subscription dependency checks, and 1,477 source captures. A metadata
commit broadcasts a revision to other subscriptions. The native Graph
function is not the largest measured cost.

| Whole-test milestone | Time from start |
| --- | ---: |
| Fixture, policy, and node setup ready | 12.978 s |
| Both initial source uploads complete | 32.795 s |
| Client subscriptions open | 32.813 s |
| Cursor 950 source signal | 60.873 s |
| Cursor 950 Graph result committed | 74.619 s |
| Cursor 950 Graph result received | 76.943 s |
| Complete incident result observed | 117.297 s |
| Owners stopped | 121.100 s |
| Test finished | 121.130 s |

## Expected effect of the six proposals

The earlier plan gave targets without estimating each saving. The table
below separates measured work from provisional replacement costs. Estimates
apply to the existing incident workload after job admission. They are
engineering assumptions, not measured speed gains or a validated p99.

| Proposal | Measured work addressed | Provisional cost after the full change | Estimated reduction in that work |
| --- | ---: | ---: | ---: |
| 1. Retain execution state and consume Arrow changes | 2,456 ms for saved-call restore, input preparation, package runtimes, and conversion | 10–80 ms | About 2.38–2.45 s |
| 2. Use one atomic change commit | 659 ms attempt registration plus 2,815 ms result commit | 10–50 ms combined | About 3.42–3.46 s |
| 3. Use a batch outbox | 41,091 ms for the 130-row update | 50–250 ms | About 40.84–41.04 s |
| 4. Use independent snapshots and selective change signals | 1,952 ms writer wait during capture | Remove that gate wait; at most 1 ms assumed for the replacement pin | About 1.95 s in this captured read |
| 5. Apply Graph changes through araphor-graph | 1,333 ms Graph row application inside the result commit | 5–20 ms | About 1.31–1.33 s, already included in proposal 2 |
| 6. Select the durable storage engine | 547 ms for the final Graph COMMIT call | 5–20 ms is a feasibility requirement; no engine has proved it | A conditional 527–542 ms, already included in proposal 2 |

Do not add these savings. Proposal 5 is inside proposal 2. Proposal 6 affects
the transactions in proposals 2 and 3. Shorter earlier executions also reduce
the measured 5,603 ms queue wait and some of the 2,323 ms commit-to-Follow
delay. Neither queue reduction has a separate measured saving yet.

Proposal 1 assumes that a normal invocation receives only changed query rows,
keeps checked state ready, and avoids encoding the full source for every
call. Fixed Wasm call and exchange costs are not yet isolated on the proposed
small input. Proposal 5 requires a new change application algorithm. Moving
code between crates without that algorithm has **zero established saving**.

Proposal 3 requires the complete read and write rewrite. It is not a claim
that transaction batching alone changes 41 seconds to 50 ms. The 650 COMMIT
calls used 5,208.487 ms. Two calls at the same observed average would use
16.026 ms. If all other work stayed unchanged, the update would still use
**35,898 ms**. The 3,529 reads, 2,600 writes, repeated read transactions,
and host work must also be replaced. The 50 ms target is at the aggressive
end of the provisional range and remains unproved.

Proposal 2 also depends on real commit latency. If the 547 ms COMMIT time
stayed unchanged, a 100 ms complete path would be impossible even if every
other step became free. This measured COMMIT is not proof of a fixed engine
or device minimum. Less written data and a different transaction model can
change it. The replacement must measure that result with full durability.

Removing the measured Graph queue, source capture, attempt registration,
and final commit would still leave **1,007 ms** of session, Arrow input,
package runtime, and result conversion work. Thus the Data and notification
changes alone do not establish a millisecond Graph path. Proposal 1 must
also reduce the work passed through the packages and their host exchange.

### What the 100 ms target requires

This is one allocation of the target. It states what must be proved; it is
not a prediction. The values are verification targets, not runtime caps.

| Required stage | Proposed maximum in the reference workload |
| --- | ---: |
| Data intake and durable source append | 10 ms |
| Wake and pin the committed source and state | 5 ms |
| DataFusion input SQL and Arrow arguments | 5 ms |
| Combined package execution and exchange on the critical path | 20 ms |
| Validate and durably commit Graph output, state, and progress | 15 ms |
| Route the changed findings and commit the outbox | 20 ms |
| Local handoff and durable delivery outcome | 20 ms |
| Remaining scheduling and handoff allowance | 5 ms |
| Total | 100 ms |

The joint end-to-end measurement must pass. Separate stage percentiles do
not establish the percentile of their sum. Current source-signal timing also
does not measure Data intake before the signal. Retain that distinction.

The first feasibility checks must prove the small durable transaction, the
small Arrow/Wasm input path, and the complete 130-row notification rewrite.
If these checks cannot meet the required stage costs, revise the design or
storage choice before completing the replacement. Do not claim success from
fewer statements or moved code alone.

### The 121-second test is a different interval

The complete test spends 32.81 seconds before client subscriptions open and
about 3.82 seconds after the complete result is observed. If those parts
stayed unchanged, even zero processing time between them would leave about
**36.64 seconds**. Some upload and setup work can also benefit from Data
changes, but its reduction has not been estimated separately.

The six estimates therefore do not justify **121.13 seconds to 100 ms** for
the whole test. The 100 ms proposal applies to a normal event through durable
result and local notification after the job is ready. The initial 1,592-event
Graph build has a separate 500 ms target, also without a validated estimate.
Keep setup, package preparation, source upload, initial Graph build, normal
event latency, and shutdown visible in every later report.

## Recommended replacement

### 1. Retain the execution state and consume changes

Query retains the admitted logical plan and reusable physical execution.
Data owns durable state. A running physical operator holds references to the
last committed state, source cut, package revision, and checked context. It
loads this state once at start or recovery. A normal source update supplies
inserted, removed, or changed Arrow rows and changed context references.

Retain an optimized plan and a physical template where DataFusion permits
reuse. Use its reset or plan creation APIs when an operator has consumed
mutable execution state. Each concurrent invocation has its own task context.
Do not reuse one consumed join or aggregate state across concurrent calls.

Change input means changes to the input query's result. New source rows alone
do not give a correct result for every SQL join, aggregate, or window. Preserve
native SQL semantics. Use existing DataFusion operators and accumulators;
do not add a second incremental SQL engine. Rewrite the builtin input queries
and package state contract to expose the required incremental work. A query
for a finite snapshot keeps its native complete selection. A managed
incremental query must consume changes. A complete-query fallback does not
meet the incremental requirement.

Remove whole prior-call reconstruction from normal `capture_managed` work.
Remove repeated progress-map expansion, copying, and whole-input hashing.
Use a durable input position and package state to identify completed input.
Keep indexed state for records still needed by a window or a future match.
An unwindowed job can retain required indexed state without scanning all of
its history on each event. A proof change or late input still changes every
affected contribution; it does not permit stale evidence.

The SDK must declare and validate change inputs and outputs for any package
that uses this mode. Data must not infer support by matching builtin package
IDs. Native and Wasm packages use the same input, state, and commit contract.
Native execution can borrow Arrow buffers. Wasm encodes the changed input at
the component boundary. Share immutable encoded input when several calls use
the same batch. Do not encode the complete 950-row source for each call.

**Removal:** repeated capture and reconstruction on every event, per-record
progress verification over unchanged input, and builtin-only resume paths.
**Required proof:** append, late input, proof change, window expiry, exact
replay, restart, and native/Wasm behavior remain correct.

#### Retained-state result

**Retained committed state: Done. Change-only package inputs: Not done.
Proposal 1: Not done.** This result covers the working tree based on
`80e0a0b`. The [source review guide](../guides/araphor-retained-execution-review.md)
links the owners and lifetime rules.

Each managed subscription owns one opaque `ManagedExecution`. Data retains
the last committed call inputs, output, checkpoint, and checked Graph
progress. Data checks the current instance, exact call heads, store identity,
recovery epoch, and current package bytes before reuse. A mismatch uses the
existing cold read. Data prepares the candidate in the publication
transaction and promotes the candidate only after COMMIT succeeds. Failed
publication leaves the last committed state unchanged.

The retained evaluation omits its previous checkpoint and previous outputs.
This rule prevents a chain of earlier evaluations. The retained state holds
no source snapshot, task context, database connection, or exchange permit.
Existing Arrow reservations retain their buffer charges. Analysis accounts
for retained metadata through its memory owner. Failure of an enabled
optional reservation drops the cache after a successful durable commit.

The existing incident workload ran twice with temporary probes and a
300-second diagnostic observation cap. The final run removed duplicate
package validation from retained candidate preparation. All 41 affected
source files were restored from exact copies after measurement.
The measurement precedes one mechanical change that groups the retention
argument in the existing `OutputMode`. The final Data tests and clippy cover
that grouping.

| Measurement | Earlier baseline | Final retained-state run |
| --- | ---: | ---: |
| Complete instrumented test | 121.13 s | 143.55 s |
| Observation interval | 84.48 s | 101.36 s |
| Cursor 950 signal to Graph commit | 13,746 ms | 13,661 ms |
| Restore three saved calls | 1,475 ms; 105 SELECT statements | About 300–475 ms on warm reads; 12 SELECT statements |
| Prepare retained candidate | Not present | At most 0.295 ms; no DuckDB calls |
| Graph computations | 3 | 5 |
| Guest calls | 9 | 15 |

The state read is faster. The complete test is slower. These separate runs
do not establish a causal speed factor. The final observation exceeds the
original 90-second cap. Thus this diagnostic run does not qualify the
unmodified incident acceptance test. Complete input selection, encoding,
Graph publication, and notification work remain. No overall speed gain or
millisecond execution is claimed.

Focused verification used these existing production-owner tests:

- Five Data tests passed with the `execution` filter. These tests cover
  failed commit, retry, current package bytes, changed heads, recovery epoch,
  reopen, and tentative-progress cleanup.
- Four serial Graph cases passed: failed-Graph reuse, restart frontier,
  version-flush rollback, and managed rechecks. The empty-history and
  conversion-failure cases also passed separately.
- Clippy passed for Data, Query, and Analysis tests with warnings denied.
- The exhaustive Graph corruption sweep was stopped before completion. Its
  cases remain unchanged. No complete corruption-sweep pass is claimed.
- Full workspace CI was not run. The user requested relevant tests only.

Two existing Graph fixtures required corrections. The conversion fixture
now uses the declared two-column `SubjectChange` schema and still requires
the same terminal failure and absent receipt. The failed-Graph fixture now
compares the produced Complete checkpoint with the saved Complete checkpoint.
It also checks that the resumed Progress checkpoint survives wire decoding.

Local measurement files are in `/tmp/araphor-retain-final-20261030/`:
`run.log`, `detail.txt`, `summary.txt`, `scopes.csv`, and `api.csv`.
The source contains no diagnostic probes or changed observation cap.

#### Declared change-input result

**Generic change inputs: Done. Builtin Graph migration: Not done. Proposal 1:
Not done.** This change follows `621665a6a`. The
[review guide](../guides/araphor-retained-execution-review.md#declared-change-inputs)
shows the SDK declaration, native plans, storage, and replay path.

An opted-in model names ordinary before, after, and reset ports. Query
prepares native row-number windows and anti joins at admission. Execution
reads each target once, binds immutable old and current Arrow batches, and
executes those prepared difference children. NULL rows and duplicate counts
remain correct. Snapshot models retain their complete input behavior.

Data retains the committed full target separately from the delivered input.
Data stores the exact delivered before, after, and reset batches for replay.
The historical base must equal the captured call head. A continuing result
has a complete input basis and a base. A reset has neither. A parameter or
support change resets all pairs and clears prior state. Output evidence
cannot cite historical before rows or the reset flag.

The input identity for a managed after port uses its exact invocation, call,
port, store cut, selected provenance, and window. This path avoids encoding
the full target to obtain its identity. Direct producer inputs retain the
producer revision. Metadata hashing in this input path uses the existing
MessagePack encoder. Unpaired support and Snapshot ports retain row-based
identity. No ABI layout, contract version, quota, or polling loop changes.

Focused verification passed:

- Six Analysis cases cover SQL, Wasm, and native execution; NULL duplicate
  insertion and removal; exact replay; restart; parameter reset; and
  concurrent captures of one plan. All six passed in 74.10 seconds.
- A seventh Analysis case first proves continuation with unchanged support.
  It then changes only support and checks a complete reset, empty before
  rows, cleared prior state, no saved base, and exact replay. This case
  passed separately in 3.97 seconds.
- Six Data cases cover retained-state guards and a changed base/input-basis
  mutation. All six passed in 9.06 seconds.
- Two SDK cases cover invalid declarations, reset rules, evidence rules,
  wire round trips, and state restoration.
- Clippy passed for SDK, Data, Query, Analysis, and the component fixture,
  including tests, with warnings denied.

The native case used the existing source-built component fixture on
`x86_64-unknown-linux-gnu`. Debug sections were removed from a copy of its
library. This reduced that qualification artifact from 178 MiB to 16 MiB.
The unstripped qualification run was stopped before completion. No native
performance factor is claimed from that change.

Native input SQL still selects the current complete target. Native windows
and joins then compute the row difference. Data still encodes the full
target for cold recovery, and Wasm still encodes saved checkpoint values.
These costs remain. The builtin Graph ports still use coupled record/fact
ordinals. Their migration requires stable, complete change units, current
support evidence, and retained contribution indexes. Independent differences
of the present ports would corrupt those references. This result does not
claim a Graph speed gain or completion of proposal 1.

The final instrumented incident run used the same 1,592 source events. The
builtin Graph jobs still use Snapshot inputs. Thus this run measures the
remaining Graph path, not the cost of executing Graph packages on changes.

| Measurement | Earlier baseline | Final change-input source |
| --- | ---: | ---: |
| Complete instrumented test | 121.13 s | 155.52 s |
| Observation interval | 84.48 s | 112.52 s |
| Cursor 950 source signal to Graph commit | 13,746 ms | 15,600 ms |
| Graph computations | 3 | 5 |
| Guest calls | 9 | 15 |
| Prepare retained candidate | Not present | At most 0.303 ms; no DuckDB calls |

The cursor 950 signal occurs at 75,084.871 ms. Its Graph commit completes
at 90,684.507 ms. That commit takes 2,891 ms: 1,824 ms inside DuckDB API
calls and 1,067 ms outside them. The last notification update selects 138
rows and takes 58,090 ms. It makes 690 durable metadata commits. These
notification and Graph intervals overlap; do not add them.

The complete test is slower. The different execution cuts and notification
selections do not establish the cause of that difference. No overall speed
gain is proved. The 112.52-second observation exceeds the original
90-second cap. The diagnostic run uses a temporary 300-second observation
cap and does not qualify the unmodified incident acceptance test. The
temporary cap and probes are removed. All 41 source paths match their exact
copies from before measurement. Scoped formatting and whitespace checks
pass after restoration.

Local measurement files are in `/tmp/araphor-changes-measure-20261030/`:
`run.log`, `detail.txt`, `summary.txt`, `scopes.csv`, and `api.csv`.

Local proof logs are `/tmp/araphor-change-integration-final.log`,
`/tmp/araphor-change-data.log`, `/tmp/araphor-change-sdk.log`, and
`/tmp/araphor-change-clippy.log`. The support proof is in
`/tmp/araphor-change-support.log`. Final Analysis clippy is in
`/tmp/araphor-change-analysis-clippy-final.log`. Full workspace CI was not
run. The user requested relevant tests only.

#### Native lookup and stateless result

**Prepared lookup inputs and stateless continuation: Done. Builtin Graph
migration: Not done. Proposals 1 and 5: Not done.** This result follows
`6a61cd89a` and the earlier generic change-input delivery.

The SDK's `InputSource::Lookup` declares native SQL that executes after the
input difference. Query prepares those children at admission and binds the
delivered before, after, reset, and earlier lookup rows during physical
execution. Raw dependencies use the same captured source cut. Admission
rejects caller overrides, cycles, and early queries that depend on late
inputs. Bound ports retain their actual input revisions and coverage.

Data stores actual lookup rows for replay. Lookup rows do not enter the
retained target or force a complete reset when their source changes. A
stateless consumer uses the committed target and exact historical base.
It needs no guest checkpoint. Stateful consumers keep their existing rules.
No ABI, version, timer, quota, or engine changes are added.

Eight Analysis change-input cases passed, including native and Wasm, in
100.32 seconds. Three SDK cases passed. The new lookup checks cover empty
main differences, raw-source updates, cold restart, exact replay, historical
before-row provenance, caller override rejection, and phase rejection.
The first phase-rejection assertion inspected only the outer error text.
That assertion failed. The corrected assertion checks the exact rejection
field in the error chain; the case passed in 3.17 seconds. No production
behavior was changed to satisfy that assertion.

Final SDK, Query, Data, and Analysis clippy passed with tests and warnings
denied in 37.60 seconds. Scoped formatting and whitespace checks passed.

Proof is in `/tmp/araphor-lookup-integration.log`,
`/tmp/araphor-lookup-sdk.log`, `/tmp/araphor-lookup-final.log`, and
`/tmp/araphor-lookup-phase.log`. The final clippy log is
`/tmp/araphor-lookup-clippy-final.log`. This result adds no speed claim. Final
Graph timing requires the builtin unit migration and old-path removal.

#### Choice for the remaining Graph work

**Combined design: Approved; implementation Not done.** The user approves
proposals 1 and 5 together. Graph packages remain pure functions. Data owns
contribution membership through `araphor-graph`. Do not add package-owned
whole-Graph checkpoints or a second membership history.

The approved flow is:

Native input SQL selects complete Graph change units
  -> each unit has a stable record key and canonically ordered support keys
  -> prepared native difference plans select affected units
  -> prepared current lookup queries select their support from the same cut
  -> the package computes Graph values for those units
  -> Data replaces each affected unit's contribution in its transaction
  -> shared members remain active while another unit still owns them
  -> Data commits Graph membership, input base, and progress together

For example, two events can own the same process subject. When one event
leaves a window, Data removes that event's ownership. The other event keeps
the subject active. A package output with no Graph values explicitly clears
that unit's contribution. An untouched unit keeps its contribution.

The present [GraphStage::apply](../../crates/araphor-data/src/analysis/graph_rows/stage.rs)
keys active members by producer scope and member identity. The member has
one anchor. That anchor does not identify all contributing units. A new
per-unit ownership index changes the storage algorithm and schema. The
change belongs to proposal 5 even when Data keeps the same transaction.

The proposed owners and changes are:

| Owner | Proposed change |
| --- | --- |
| Query and SDK | Declare current lookup ports and prepare their native SQL after the difference step. Store their delivered inputs for exact replay. Do not compare lookup results as complete support state for reset. Permit a change consumer without a guest checkpoint; Data still retains its committed target and base. |
| Builtin packages | Replace independently indexed record/fact inputs with stable units and current support. Compute only affected contributions. Remove whole-selection progress reconstruction after equivalent proof passes. |
| araphor-graph | Add contribution application keyed by the existing producer scope and stable unit key. Reuse native value identities and shared-member indexes. Do not open or commit a store. |
| Data | Validate the exact source cut, authority, and expected base. Supply its transaction to contribution application. Retain one authoritative versioned membership history. Treat counts as an index over that history. |

Scope each unit by the existing tenant, source, definition, and call pin.
Do not use a bare call number or row ordinal as the durable key. Preserve
current rejection of conflicting values or authority. Select a surviving
anchor from surviving owners without changing its provenance.

The credential input query must update affected old units on removal, late
input, window exit, and proof or context change. A query that selects support
only for new events is incomplete. Native SQL must determine the complete
current unit value before the difference step. Current lookup inputs must
retain the same captured cut and permission checks.

This option removes package-owned whole-Graph checkpoints and their normal
restore path. It must not add another snapshot normalizer or a second
membership history. The existing tests for shared subjects, historical
reads, late input, expiry, evidence, rollback, replay, and restart must pass.
The existing incident workload must measure the result. No saving is proved
for this option yet.

### 2. Replace attempt-first publication with one atomic change commit

An invocation prepares output in memory. Data performs one final authority
and expected-state check, then commits output changes, saved state, progress,
and replay references in one transaction. A crash before this transaction
leaves the prior cursor and state. A retry reuses the existing deterministic
invocation identity and committed input position.

Remove the durable pre-execution attempt write from the normal pure package
path. Keep job lifecycle and failure inspection at their existing owner.
Package computation does not make an external effect; notification delivery
uses the separate durable obligation described below.

Validate immutable package code and schemas at installation or admission.
Retain checked references in the invocation. At commit, check changed keys,
live authority, and expected state versions. An unrelated notification write
must not force a Graph invocation to restore or reject its full input cut.

Stage Arrow changes once and apply table changes in sets. Remove per-call
temporary DDL and repeated metadata SELECT statements. Prepare reusable
storage statements outside normal event execution. Store replay changes once
and refer to retained source segments; do not save another full input copy.

**Removal:** the extra attempt transaction, repeated metadata reads, temporary
tables per Graph step, and full-manifest interning for each call.
**Required proof:** atomic rollback, authority revocation, stale state,
corruption checks, exact replay, and crash recovery remain correct.

### 3. Replace per-row notification transactions with a durable outbox

Use native DataFusion SQL to select new notification obligations from finding
changes and the relevant route snapshot. Resolve the required finding,
policy, route, and destination metadata as a batch. Commit all prepared
obligations and their stable attempt IDs together before delivery.

The transport consumes the durable outbox as a stream. It preserves required
per-key order and performs the live authority check before each effect.
Commit completed, failed, and unresolved attempt results together. This
changes 650 commits for the measured 130-row update to **two notification
batch commits**. The Graph result has its own single atomic commit. These
counts are design targets, not a measured speed factor.

The two-commit target applies to the measured local sink, which returns
immediately. For slow external effects, persist available completed groups
without waiting for another destination. Do not add a timer to fill a batch.

A crash after an effect but before acknowledgement follows the existing
ambiguity and retry rules. Preserve the attempt identity and body. Do not
claim exactly-once external effects. Do not hold Data's writer while calling
a transport. A slow destination must not hold up Graph execution or unrelated
delivery streams. Use existing async streams and task ownership.

An optional later composition can include outbox preparation in the result
transaction when one native query already produces both outputs. Do not add
Graph-specific routing SQL inside Data's storage callbacks merely to save
that transaction.

**Removal:** per-row finding reads, repeated route reads, repeated durable
state transitions, and a synchronous delivery loop on the Graph work path.
**Required proof:** save before effect, cancellation at both existing points,
revocation, ordered delivery, retry, failure, and restart remain correct.

### 4. Open committed snapshots without the writer gate

Data publishes a consistent committed view that includes source positions,
metadata versions, and package state references. Query pins that view.
Opening a read must not take the writer mutex or project raw data into a
catalog before the read can start. Raw segments remain immutable and pinned
for the selected cut. Concurrent writes cannot alter the view's meaning.

Use the storage engine's snapshot support and existing immutable Arrow
ownership. Do not copy the entire catalog or Graph to publish a new view.
Check the source cut, state, evidence, and metadata together. A reader must
not combine old raw positions with new mutable metadata. Prove this before
removing the current coordination gate.

**Removal:** `coordinated_reader`'s writer acquisition and raw projection on
read. **Required proof:** simultaneous source commits, package calls,
retention, authority changes, and historical reads keep an exact snapshot.

#### Publish changes to actual query dependencies

Derive table and source interests from the native logical plan and registered
providers. A result acknowledgement wakes consumers of that result state;
it does not wake an unrelated event-to-Graph subscription. A Graph result
wakes queries that consume the changed Graph relations.

Use existing notification primitives and the durable change position.
Signals can coalesce, but a subscription must read every required change
since its committed cursor. Do not use a replaceable watch value as the only
copy of an input delta. Remove no-op commits and their revision broadcasts.
Keep declared window events in the same Query stream.

Replace separate Graph Evaluate and Expire jobs with the same subscription
execution and semantic window events. Analysis owns start, inspect, stop,
and recovery. It does not own a second Graph scheduler.

**Removal:** global revision rechecks for unrelated changes, metadata feedback
loops, empty expiry publication, and separate Graph lifecycle machinery.
**Required proof:** no lost change, source retirement, context update,
historical query, resume, and window behavior remain correct.

### 5. Apply Graph changes through araphor-graph

The crate currently owns native finding values and selected finding views.
Data still owns most subject, edge, producer, and version code. In the
replacement, araphor-graph owns stable Graph identities, typed node and edge
values, adjacency access, and version membership. It applies explicit changes
through a transaction borrowed from Data. It opens no store and commits no
transaction itself.

Retain the existing native shared values and historical results. Store only
changed facts and membership. Reuse the TerminusDB lesson of immutable facts
and versioned additions and removals. Do not rebuild, compare, or serialize a
complete Graph during publication. A public snapshot is assembled only when
selected. Do not add another parser, planner, aggregate implementation, or
query execution owner. Existing DataFusion providers expose current and
historical Graph relations.

**Removal:** split Graph storage rules, package identity switches in Data, and
complete contribution reconstruction. **Required proof:** selected historical
Graphs, traversal, stable finding identity, exact replay, and reopen remain
correct. This is an ownership and algorithm change; a file move alone does
not satisfy it.

#### Membership owner result

**Membership mutation owner: Done. Builtin unit integration: Not done.
Proposals 1 and 5: Not done.** This result follows `b19b0c89a`.

`araphor_graph::Contributions::apply` changes the existing versioned member
history through Data's transaction. Each member names an interned event unit.
The history has no second contribution table. An empty replacement removes
one unit. An absent unit remains unchanged. Identical rows keep their open
intervals. Shared members remain present until the last owner is removed.
The owner checks conflicts across retained and replacement owners. Counts
change from presence transitions for touched keys.

Data's direct, metadata, and Snapshot adapters use this owner. Data retains
producer pins, expected bases, authority checks, and COMMIT. Recovery checks
unit-scoped intervals, historical conflicts, source ownership, and logical
counts. Historical results retain their existing exact producer cuts.

Fourteen focused Graph tests and eleven focused Data tests pass. The Data
checks include shared values, historical conflicts, unchanged intervals,
canonical anchors, metadata, branch order and duplicates, rollback, retry,
schema integrity, and reopen. Graph and Data clippy pass with warnings
denied. Scoped formatting and whitespace checks pass. Data proof is in
`/tmp/araphor-graph-membership-data.log`.

The transitional unit-zero adapter merges its full prior contribution.
Builtin event-unit publication must bypass this adapter before completion.
No timing reduction is claimed for this ownership change alone. Native
value ownership, builtin change inputs, and final measurements remain open.

#### Unit integration result

**Builtin unit inputs and native value ownership: Done. Combined timing
proof for proposals 1 and 5: Not done.**

Builtin packages now declare native SQL for their target units and lookup
inputs. Query computes the input differences with native DataFusion plans.
The package receives changed units and their current records and facts.
SQL, Wasm, native, and the custom Burst package use the same contract.
Data changes only the affected unit membership through `araphor-graph`.
Subject, relationship, finding, and state values have shared native owners.
Data keeps the transaction, authority checks, progress, and replay records.

The old Graph-call reconstruction, progress rows, sparse resume, and builtin
classification by artifact bytes are removed from production. Data still
checks the current installed package bytes. An empty change keeps the
state of active units. Cold recovery checks historical anchors against the
exact saved call and owning unit. It reuses the evaluation that recovery
already decodes. It does not reconstruct a complete prior Graph.

Standalone package query programs keep their native query roots through
SQL planning. Native DataFusion output requirements preserve their final
ordering. Araphor delivers the resulting batches without changing their
values, row order, or batch order. Simple event subscriptions preserve
committed arrival order across pages, resumed cursors, and combined wakes.

Verification includes 73 builtin and Burst checks, 62 Data Graph-row checks,
29 Graph-owner checks, 16 Query checks, exact-order and replay checks for
quoted exports, and 11 input-binding checks. The added historical-anchor
regression applies 27 mutations to existing closed rows. The original
managed corruption matrix, source backlog, state recovery, unchanged
notices, and final-authority denial checks pass. Scoped formatting and
six-crate clippy checks pass with warnings denied. These are correctness
results; their test runtimes are not event-processing measurements.

Complete target queries and source captures remain. The existing incident
workload must still measure input/package work and Graph application work
against the recorded baseline. No combined speed factor is claimed here.

#### Unit measurement result

**Diagnostic measurement: Done. Original observation deadline: Failed.
Proposals 1 and 5: Not done.**

The source was `209cb8297` with temporary probes. The existing 1,592-event
incident test completed in **243.94 seconds**, against the recorded
**121.13-second** baseline. No compilation ran during this measurement.
The fixture reached `policy_ready` at 104.977 seconds. Observation took
115.086 seconds. Observation exceeded the original 90-second deadline.
The diagnostic run used a temporary 300-second observation cap. This cap
does not change acceptance. All 43 probe paths were restored from exact
copies and checked with SHA-256.

The following rows compare the selected cursor-950 invocation with the
same baseline boundary. They are not totals for the complete test or
guaranteed execution times. Child scopes are included in parent scopes.

| Selected-cut boundary | Baseline | Unit implementation | Change |
| --- | ---: | ---: | --- |
| Saved-call capture | 1,474.773 ms | 215.101 ms | 85.4% lower |
| Attempt ready to first package worker | 657.889 ms | 18,272.531 ms | 27.8 times higher |
| Graph publication, `graph_result_rows` | 1,332.962 ms | 1,592.164 ms | 19.4% higher |
| DuckDB API time inside Graph publication | 930.511 ms | 1,446.965 ms | 55.5% higher |
| Time outside DuckDB APIs inside Graph publication | 402.451 ms | 145.199 ms | 63.9% lower |
| Complete Data result commit | 2,814.612 ms | 2,480.537 ms | 11.9% lower |

The selected invocation delivered 10 changed units and 10 lookup records
to each package. The Process package produced 31 subjects, 21 edges, and
one finding. The other two packages produced no Graph values. Each package
still retained a complete target of 950 rows and 275,424 Arrow memory
bytes. Changed guest input does not prove that target query work is
incremental.

The three package-worker intervals covered 130.473 ms. Their complete
span was 2,197.335 ms. The 2,066.862 ms between these intervals remains
part of execution latency. Do not omit this time from the comparison.
Input preparation before the first worker is the largest measured
regression. Current probes do not identify the exact input operator that
causes this cost. The startup interval also needs a separate source-level
measurement.

The retained state reduces saved-call capture. Graph publication spends
less time outside DuckDB APIs, but more time inside those APIs. The whole
test is slower. Both approved proposals remain incomplete until input
execution and Graph publication show measured reductions with the same
behavior checks. No millisecond or overall speed improvement is proved.

The diagnostic log is
`/tmp/araphor-unit-measure-20261031-quiet.log`. Selected-cut scopes, API
counts, and source-log hashes are in
`/tmp/araphor-unit-analysis-20261031/quiet/focus.json`. The selected commit
scope is 4478. Its invocation is
`f7aa2fbb-3f1a-4c9b-b5fc-fb98e4f4ca13`.

### 6. Select the durable storage engine

Changing the engine alone leaves thousands of requests in place. First
define the replacement snapshot and atomic change transaction. Then compare
the same change transaction with durable settings on the candidate engines.
Do not weaken durability to meet the timing target.

| Candidate | Proposal | Required evidence |
| --- | --- | --- |
| DuckDB | Retain it only if set writes, retained metadata, and independent snapshots meet the latency target | Exact snapshots across raw and derived state; no writer gate for reads; one small durable commit in milliseconds |
| redb | Evaluate a direct Rust transactional store for canonical Data metadata, Graph, state, progress, and outbox | Snapshot reads during writes, atomic multi-table changes, durable reopen, indexed historical reads, and measured commit latency |

DuckDB documents MVCC and concurrent work within one process. Its support
does not justify our application-level writer gate for all reads. The trace
measures the cost of our requests; it does not establish an irreducible
engine cost. See [DuckDB concurrency](https://duckdb.org/docs/1.5/connect/concurrency).

redb documents a pure Rust store with copy-on-write B+trees and concurrent
read transactions during writes. It still has a single writer. Its APIs and
durability model are candidates, not proof of this workload's speed. See the
[redb design](https://github.com/cberner/redb/blob/master/docs/design.md),
[database API](https://docs.rs/redb/latest/redb/struct.Database.html), and
[durable transaction API](https://docs.rs/redb/latest/redb/struct.WriteTransaction.html).

An engine replacement moves every record that must commit atomically to the
chosen store. Do not split authoritative state and progress across DuckDB
and a key-value store. DataFusion remains the SQL engine. OCI artifacts and
raw segments can remain immutable files referenced by the transaction. Reuse
existing typed binary and Arrow formats; add no JSON storage, legacy decoder,
development version bump, or application compaction task as a latency fix.

## Ownership after the replacement

| Owner | Responsibility |
| --- | --- |
| araphor-query | Native SQL stages, retained physical execution, change inputs, windows, and result streams |
| araphor-package-runtime and SDK | One package contract, Arrow exchange, explicit saved state, native/Wasm adapters |
| araphor-graph | Native Graph values, adjacency, changes, and historical membership through Data's transaction |
| araphor-data | Source cuts, the only durable transaction, state, progress, outbox, and committed change publication |
| araphor-analysis | Job admission, lifecycle, subscription task collection, and transport wiring |
| Control and the existing authority owners | Admission and live effect authority; final commit and delivery checks |

## Work order and approval

1. Review the complete flow, transaction contents, SDK changes, and code to
   remove. Record every changed owner and the DataFusion or dependency API
   used. Resolve snapshot consistency and delivery recovery before code.
2. Propose the release qualification workload, runtime, and pass/fail values
   for approval. Use normal Rust tests and existing Mithril E2E owners.
3. Prove the small durable transaction, changed Arrow/package input path,
   and 130-row local notification path. Record their measured costs against
   the required stage values. Select one engine before production ownership
   is changed. Revise the design if these checks cannot support the target.
4. Replace source capture, package state exchange, and Graph publication with
   the retained plan and atomic change path. Include selective notifications.
5. Replace notification processing with the batch outbox path. Its measured
   41-second cost makes this the first user-visible result to qualify.
6. Remove each old path only after its replacement preserves the existing
   correctness tests. Record removed production code and remaining duplicates.
7. Run the original incident behavior checks and approved release timing
   qualification. Stop when the targets and feature preservation both pass.

Before each implementation deliverable, the implementer proposes its types,
owners, data flow, removed code, and reused native APIs to the change reviewer.
The reviewer must challenge unnecessary work and duplicate implementations.
Implementation starts after agreement and the user's required approval.
Agreement does not make the unapproved proposals in this file approved.

Arbitrary user SQL and arbitrary package code can require work proportional
to their selected data or output. Preserve those queries and report their
cost. The builtin incident jobs must use incremental inputs and indexed
state. Do not claim constant-time execution by dropping input, hiding backlog,
changing window behavior, or weakening tests.

## Evidence and current result

The durable measurement record is the baseline tables in this file. Local
trace and source probe artifacts are:

- `/tmp/araphor-measure-20261030-complete.log`
- `/tmp/araphor-measure-20261030-complete-detail.txt`
- `/tmp/araphor-measure-20261030/scopes.csv`
- `/tmp/araphor-measure-20261030/api.csv`
- `/tmp/araphor-measure-20261030/probes.patch`

The probe patch passed `git apply --check` after exact source restoration.
The current code does not contain the probes. No release result or measured
speed factor is claimed for the proposed replacement.

**Recorded measurements: Done. Retained committed state: Done. Proposals 1
and 5: Approved and Not done. Millisecond execution: Not done. Proposals 2,
3, 4, and 6: Not approved and Not done.**
