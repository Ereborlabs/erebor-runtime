# Phase 7.3: Scoped Query And Commit-Driven Follow

Provide one read operation for retained and live data.

## Intended end state

QueryOwner returns authorized SQL results and one bounded subscription stream.
Simple immutable queries append rows. Aggregate and mutable-view queries replace
the full bounded result. Entry: 7.2. Status: **Not done**.

## Implementation flow

```text
Caller supplies SQL, parameters, scope and optional follow/cursor
  -> QueryOwner checks current grants and binds permitted relations and fields
  -> binder derives only proven-safe time bounds from the SQL AST
  -> AnalysisStore extracts complete bounded authorized input at one revision
  -> isolated DuckDB worker evaluates admitted SQL
  -> QueryOwner checks output and creates an authenticated receipt

Follow is requested
  -> QueryOwner registers dependency notifications before the initial snapshot
  -> owner sends metadata, initial result and a checkpoint on one stream
  -> relevant commits mark one evaluation dirty
  -> append reads new committed positions; replace evaluates a complete snapshot
  -> supported time-window expiry also triggers replacement without new input
  -> owner closes all DB readers and workers before waiting

Reader is slow, revoked or disconnected
  -> owner stops this bounded read; source intake continues
  -> retry checks current grants and the last complete checkpoint
  -> expired append history returns an explicit gap, never a silent reset
```

## Changes in implementation order

1. Add `QueryOwner::{query,follow}` under `crates/araphor-data/src/query/` and
   the isolated query-worker entry point under its `src/bin/`. Reuse 7.1 admission
   and sandbox proof. Do not expose a storage handle or arbitrary SQL to
   credentialed Control. Fixed prepared extraction runs inside AnalysisStore.
2. Implement typed request/result/frame/cursor records and documented
   `catalog`, `events`, `coverage` and context-version reads. Bind scope,
   redaction and export policy before evaluation. Use sqlparser-rs DuckDbDialect
   and the single-relation bound rules in engine-design.md. No window flag is
   required. Preserve the full predicate after trusted extraction. Unproven
   fixed-range shapes use complete input or fail explicitly at the budget.
   Add later views only when
   their owners exist; return Unsupported for unavailable owner capabilities.
3. Implement normal SELECT and the two follow operations exactly as specified
   in engine-design.md. A replace snapshot must fit one 200-row/1-MiB frame.
   Reject complete-input overflow rather than calculate a partial aggregate.
   No second SQL request is needed to refresh a followed aggregate.
4. Bind dependencies through CTEs and joins, including context and coverage.
   Register watch before snapshot capture. Read snapshot data and revision
   consistently. Recheck durable table revisions before sleep. Permit one
   active evaluation and one dirty flag per stream; no unbounded task list.
5. Implement stable append ordering, nonmatching scan progress, frame IDs
   and checkpoint binding. Replacement resumes with the latest complete
   snapshot; it does not promise every intermediate state. A cursor does not
   pin history. Store epoch/schema/scope changes reject mismatched cursors.
6. Implement the specified moving-window subset with a controllable clock.
   Compute row-expiry deadlines; reject unsupported volatile expressions.
   Bind the evaluation time through a checked AST parameter, not string
   replacement. Test forward/backward wall-clock changes and report them.
   Use heartbeat for health/auth checks, not unconditional SQL polling.
7. Close readers before response writes. Enforce worker limits, one queued
   frame, 10-second stalled-output timeout, grant revocation, stream lifetime
   and shutdown cancellation. Emit a typed terminal/error state when possible.
   A query error is never an empty success.
8. Add fixed recipes for exact match, revision difference, counts and qualified
   within-subject sequence. Recipes describe required fields and limitations;
   detection interpretation remains 7.6. gRPC/CLI wiring belongs to
   Observability 3; no second query implementation is needed there.

## Unit tests and end-to-end proof

Unit tests `query_admission_`, `query_scope_`, `query_follow_` must cover
nested forbidden functions, hidden-column predicates, cross-tenant aggregates,
external access, input/output N/N+1, worker timeout and sandbox failure.
Use deterministic commit barriers, not sleep-based race tests. Compare each
optimized result with full authorized-input execution in the pinned DuckDB.
Include an OR branch with older matching rows, two aliases of events, CTE reuse,
outer joins, quoted/shadowed names, timestamp offsets, nulls and bound endpoints.
Unsupported moving predicates reject; no parser success implies safe pushdown.

Add `query-follow` to `mithril_discovery_test`. Use actual AnalysisStore
commits and QueryOwner streams. Verify initial snapshot/commit race, empty
filters, replay, coalesced notifications, unrelated commits, full batches,
late events, correction, retention expiry, failed worker and restart.
For `SELECT operation, COUNT(*) ... GROUP BY operation`, verify each replace
equals a normal query at the same revision, never the sum of prior snapshots.
Use a tenant history larger than the extraction budget with a small matching
SQL-derived window. Require a correct count and bounded extraction, then add a
matching batch and require a complete replacement. Expire a moving-window row
with no new traffic. Revoke access during a quiet
stream. Prove reader cancellation leaves intake and policy work active.

```sh
cargo test -p mithril-control
cargo run -p mithril-e2e --bin mithril_discovery_test -- --case query-follow --output-directory /tmp/araphor-query-follow
bash .github/scripts/verify-rust-ci.sh
```

## Completion gate

Pass DE-QUERY, DE-FOLLOW, DE-DISCLOSE, DE-TENANT and DE-LIMIT. Record schema,
operations, read revisions, receipts, checkpoints, worker RSS and latency.
A model, discovery profile, public API or durable subscription registry is not
required. External readers use this same contract through Observability 3.
