# Native Source finding reads and revisions

Result: **Done for optional native Source finding and revision reads**.
Production replacement remains **Not done**. Production still uses DuckDB.
No native incident speedup is measured.

The native reader now supplies Source finding values, provenance, scalar
manifests, and whole Graph revisions. A winner key contains the tenant,
source, instance, and first cursor. Independent instances retain separate
windows. Replacement changes only the matching instance and window. Exact
old result reads remain valid after later writes, compaction, and reopen.

SourceRead checks the saved Selected owner, successful attempt, captured cut,
and exact Graph receipt. Any Graph publication must bind to that same result
and instance. A missing required Source header is an error. It cannot select
the Definition path. Empty Source results can have no Graph journal.

Whole revisions use membership at the saved publication cut. Each member
resolves its actual append origin. Fact and proof postings supply exact
retained context references. No raw body or full Graph fact is read for this
metadata. Scalar reads skip record and proof vectors during decode. They still
read encoded result bytes and decode the saved attempt. Notification
preparation shares one whole revision per Source result through `Arc`.

The existing Arrow capture builder supplies manifests. Findings-only requests
also retain Graph coverage and result attribution. Current finding heads
combine Definition publications and per-instance Source windows. Finding
groups use the saved publication view, including older active windows.

Native format 6 adds the winner index. Recovery checks its exact set against
the retained results. Older native formats are rejected. No conversion of
native or DuckDB directories is added.

## Verification

The [machine record](araphor-native-source-reads-2026-11-10.json) freezes source,
workload, engine revisions, commands, and log hashes. The focused managed suite
passes 86 cases. The complete runtime gate passes **117 tests in seven suites**,
with no failed, ignored, or filtered cases. All 96 frozen source hashes remain
unchanged through the final gate. New cases cover real Source findings, append origins, empty
results, multiple instances and windows, replacement, finding removal,
historical Pending subjects, expiry, compaction, reopen, damaged headers and
publication bindings, finite budgets, and cancellation.

Formatting and default and native Analysis library checks pass. Data Clippy
fails on two unchanged legacy `expect` calls at
`analysis/managed/graph/projection/publish.rs:90` and
`analysis/managed/reader/committed/graph.rs:213`. It is not a passing lint gate.
The first broader runtime command found an old format-5 test expectation.
The corrected test requires format 6 and rejects format 5. The machine record
links that earlier command and failure.

The first Query link fails with `No space left on device` before tests run.
The machine record retains that failure. Removal of inactive build caches
allows the same frozen Query source to pass nine cases. The two Analysis
suites pass four cases each. Engine checkouts remain clean at their recorded
commits. All 498 local links in the changed documentation resolve.

## Remaining work

Full Source snapshots, metadata bodies, binding-scoped reads, mutable Graph
notices, and bounded recovery cost remain **Not done**. Long append chains can
still make recovery work quadratic. Current-window selection does not prove
that change reads skip all unchanged windows. Actual finding delivery through
the Router is not qualified by these Data tests.

Native notification extraction, durable completion, write batches, configured
capacity, retention, backup, production cutover, DuckDB removal, and both
incident performance targets remain **Not done**. The selected incident and
full CI do not run for this increment. Its workload, assertions, and timeouts
are unchanged.
