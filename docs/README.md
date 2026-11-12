# Recovered Documentation Index

This tree was rebuilt from `recover/` after the original uncommitted
documentation directory was lost. The raw recovery set remains untouched; this
tree contains only named, no-clobber copies selected during triage.

## Start Here

- [Plans](plans/README.md) contains recovered master plans, phase trees, and
  explicitly named recovery indexes.
- [DuckDB retirement](research/araphor-fjall-integration.md#current-replacement-work-2026-11-10)
  owns the current native storage worklist. Commit `abdc4694e` replaces the
  production SQL owner. The synthetic incident was removed on 2026-11-12.
  Its prior results are historical. Complete storage parity,
  obsolete fixture ports, and the 100-fold timing proof remain **Not done**.
- [Research](research/README.md) contains market, interview, compliance, and
  generated-research documents.
- [Recovery notes](plans/recovery/README.md) explain the evidence, duplicate policy,
  external-document quarantine, and known gaps.
- [Designs](designs/) contains product and evidence-demo design material.
- [Guides](guides/), [How-to documents](how-to/), [examples](examples/), and
  [integrations](integrations/) contain recovered product-facing material.
- [OCI image and binary package storage review](guides/araphor-binary-package-storage-review.md),
  [Discovery definition review](guides/araphor-discovery-definition-review.md),
  [SQL operation review](guides/araphor-sql-operation-review.md), and
  [graph commit review](guides/araphor-graph-commit-review.md) give the source
  reading routes for the approved production changes.
- [Performance simplification review](guides/araphor-performance-simplification-review.md)
  gives the source route and verification limits for the approved repeated-work
  changes.
- [Retained execution state review](guides/araphor-retained-execution-review.md)
  gives the current saved-state reuse flow, commit checks, and remaining input
  work.
- [Native Data transaction review](guides/araphor-native-data-review.md) gives
  the qualified native metadata owner, exact cut publication, context storage,
  and package PoC caller. Its qualification precedes the current production draft.
- [Fjall versioned storage review](guides/fjall-versioned-storage-review.md)
  gives the native history, branch, journal, recovery, and collection source
  route. The approved engine scope is complete. The user accepted the current
  benchmark. The four approved journal/history simplifications pass focused
  checks and unchanged PoC comparisons. The original combined median target
  remains unproved.

## Important Status Rule

The recovered plan files preserve their original text, including status and
verification claims. They are historical evidence, not a statement that their
status still matches the checked-out source tree. Reconcile an individual plan
with current code before treating it as authoritative for new implementation.

The previously referenced `/tmp/erebor-doc-recovery/docs/plans` directory was
not available in this workspace during recovery.
