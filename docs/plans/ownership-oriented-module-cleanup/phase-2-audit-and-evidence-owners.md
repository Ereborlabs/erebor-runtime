# Phase 2: Audit Review And Evidence Owners

Status: Done.

## Purpose

Make audit review and evidence trace code read like owned pipelines: source
resolution, summary building, rendering, redaction, hashing, and sinks should
not be mixed in one file.

## Scope

Touch only `crates/erebor-runtime-audit` unless Phase 1 left an approved core
follow-up.

Primary files:

- `src/session_review.rs` - 1,366 lines.
- `src/evidence_trace.rs` - 1,227 lines.
- `src/filter.rs` - 310 lines.

Target modules:

- `session_review.rs` as a thin root with public review types and re-exports.
- `session_review/source.rs` with `SessionReviewSource` and registry path
  resolution.
- `session_review/summary.rs` with `SessionSummaryBuilder`.
- `session_review/decisions.rs` with decision summary construction.
- `session_review/timeline.rs` with timeline item construction.
- `session_review/render.rs` with `SessionReviewRenderer`.
- `session_review/artifacts.rs` with policy/config proof artifact hashing.
- `evidence_trace.rs` as a thin root with public request/report types.
- `evidence_trace/source.rs` with `EvidenceTraceSource`.
- `evidence_trace/render.rs` with `MarkdownEvidenceTraceRenderer`.
- `evidence_trace/artifacts.rs` with artifact lookup and hash owners.
- `evidence_trace/redaction.rs` with an evidence redactor owner shared inside
  the crate.
- `evidence_trace/sink.rs` with `EvidenceTraceSink` and file sink.
- `filter.rs` as a thin root with `AuditFilter` owning logging config.

## Ownership Rules

- Rendering functions that repeatedly need records, artifacts, policy, or
  config should be methods on renderer/source owners.
- Hashing and redaction belong to named owners when they carry policy, config,
  artifact, or output context. Only tiny pure transforms may remain private
  local helpers.
- `AuditFilter` owns signal/debug matching and validation. Do not leave
  unowned filter matcher or `validate_*` functions.
- Real defaults use `Default` impls or derives. Do not add `default_*` audit
  helper functions unless a private serde/protocol hook delegates to
  `Default`.
- Avoid decorative `with_*` APIs on request, renderer, sink, and filter types.
  Use constructors for complete values and `add_*`/`set_*` methods for
  accumulated options.
- Keep audit family modules consistent: review code under `session_review/`,
  evidence code under `evidence_trace/`, and filter code under `filter/` if it
  splits further.
- Tests for renderers, redactors, hashers, sinks, and filters should live
  beside those owners. A shared test prelude may contain imports only.
- Do not move CLI rendering into the CLI crate. CLI commands should keep calling
  audit-owned APIs.

## Required Tests

Required code-backed tests live beside audit owner modules for source lookup,
summary building, rendering, artifact hashing/redaction, sinks, and filters.
Use `erebor-runtime-e2e` fixture owners if a follow-up changes CLI-visible
review or evidence-trace behavior across a session registry.

```sh
cargo test -p erebor-runtime-audit --all-targets --all-features
cargo test -p erebor-runtime-cli --all-targets --all-features --no-run
cargo fmt
git diff --check
```

Run the live lifecycle probe if any audit artifact path, session review source,
or filter behavior changes:

```sh
docs/plans/ownership-oriented-module-cleanup/lifecycle-probe.md
```

## Acceptance

- Touched Rust files are split only where ownership/readability improves. Any
  touched file that remains above the 300-line guideline must have a concrete
  readability reason in the phase result.
- Existing session review and evidence trace output is unchanged unless a
  difference is explicitly approved and tested.
- Add or retain tests proving redaction, artifact lookup, JSON/text rendering,
  and filter signal/debug behavior.
- Phase 2 cannot be marked done without committed Rust tests for each changed
  audit pipeline owner; lifecycle or manual probes only supplement those tests.
- CLI review/evidence commands still compile through the public audit API.
- Focused item inventory shows remaining production free functions are private,
  stateless, local to owners, and justified in the phase result.
- No `default_*` or `with_*` API remains unless the phase result documents why
  the exception is necessary.

## Stop Point

Stop after Phase 2 verification. Wait for user approval before Phase 3.

## Phase Result

State: Done.

Completed on 2026-07-05.

### Implementation Summary

- Split `erebor-runtime-audit` into thin roots and owner modules:
  - `session_review.rs` now re-exports the public review surface and contains no
    production free functions.
  - `session_review/source.rs` owns registry-backed review source lookup.
  - `session_review/summary.rs` owns session grouping and summary building.
  - `session_review/decisions.rs` owns key-record selection and decision
    summaries.
  - `session_review/timeline.rs` owns timeline item construction.
  - `session_review/render.rs` owns text/JSON review rendering and path-backed
    rendering, with `session_review/render/table.rs` owning table/JSON output.
  - `session_review/artifacts.rs` owns runtime-config-backed artifact loading
    and policy/config hash attachment.
  - `session_review/record.rs` owns per-record labels, target redaction,
    controlled-path inference, and raw-payload hash projection.
  - `evidence_trace.rs` is now a thin evidence root.
  - `evidence_trace/source.rs` owns registry-backed evidence path lookup.
  - `evidence_trace/request.rs` owns evidence request construction.
  - `evidence_trace/report.rs` owns report and receipt types.
  - `evidence_trace/sink.rs` owns the file sink.
  - `evidence_trace/redaction.rs` owns redaction and markdown-cell escaping.
  - `evidence_trace/artifacts.rs` owns artifact JSON/file loading and hashing.
  - `evidence_trace/render.rs` owns session selection and report hashing, with
    `evidence_trace/render/{sections,rows,labels}.rs` owning markdown body,
    tables, and per-record labels.
  - `filter.rs` is now a thin root with `AuditFilter` and `FilteredAuditSink`.
  - `filter/matcher.rs` owns signal/debug token matching.
  - `filter/surfaces.rs` owns per-surface audit logging decisions.
- Moved owner tests beside owners:
  - summary grouping in `session_review/summary/tests.rs`
  - review rendering and redaction in `session_review/render/tests.rs`
  - registry source lookup in `session_review/source/tests.rs`
  - evidence hashing/redaction/render/sink tests beside evidence owners
  - filter signal/debug behavior in `filter/tests.rs`
  - JSONL read/write tests remain in the crate test root because they exercise
    `jsonl.rs`.
- Replaced the hand-rolled SHA-256 implementation with the mature `sha2`
  crate. `EvidenceHasher` remains as the audit-domain owner, but it delegates
  hashing to `sha2::Sha256`.
- Follow-up default cleanup removed default-registry free wrappers and the
  unused fluent `EvidenceTraceRequest::with_session_id` API:
  - removed `render_session_*_from_default_registry`
  - removed `EvidenceTracePaths::from_default_session_registry`
  - removed `session_audit_path`
  - CLI call sites now use `SessionReviewSource::default()` and
    `EvidenceTraceSource::default()` directly.
- Public filtering moved from free helpers to `AuditFilter::new(...).should_record(...)`.
  The old `should_record_audit_record` and `should_record_with_surface_logging`
  helpers were removed.
- Added an explicit `.agents/engineering.md` rule requiring mature crates for
  standard primitives such as hashing, crypto, parsing, codecs, protocol types,
  URL handling, and time.

### Files Changed

- `.agents/engineering.md`
- `Cargo.toml`
- `Cargo.lock`
- `crates/erebor-runtime-audit/Cargo.toml`
- `crates/erebor-runtime-audit/src/lib.rs`
- `crates/erebor-runtime-audit/src/session_review.rs`
- `crates/erebor-runtime-audit/src/session_review/*`
- `crates/erebor-runtime-audit/src/session_review/render/*`
- `crates/erebor-runtime-audit/src/evidence_trace.rs`
- `crates/erebor-runtime-audit/src/evidence_trace/*`
- `crates/erebor-runtime-audit/src/evidence_trace/render/*`
- `crates/erebor-runtime-audit/src/filter.rs`
- `crates/erebor-runtime-audit/src/filter/*`
- `crates/erebor-runtime-audit/src/tests.rs`
- `crates/erebor-runtime-cli/src/cli.rs`

### Line Counts

Original oversized files:

| File | Before | After |
| --- | ---: | ---: |
| `src/session_review.rs` | 1,366 | 25 |
| `src/evidence_trace.rs` | 1,227 | 26 |
| `src/filter.rs` | 310 | 65 |
| `src/tests.rs` | 279 | 98 |

New owner/test files:

| File | Lines |
| --- | ---: |
| `src/session_review/artifacts.rs` | 91 |
| `src/session_review/decisions.rs` | 101 |
| `src/session_review/record.rs` | 240 |
| `src/session_review/render.rs` | 269 |
| `src/session_review/source.rs` | 107 |
| `src/session_review/summary.rs` | 284 |
| `src/session_review/test_support.rs` | 128 |
| `src/session_review/timeline.rs` | 37 |
| `src/session_review/render/table.rs` | 51 |
| `src/session_review/render/tests.rs` | 106 |
| `src/evidence_trace/artifacts.rs` | 103 |
| `src/evidence_trace/redaction.rs` | 71 |
| `src/evidence_trace/render.rs` | 150 |
| `src/evidence_trace/report.rs` | 73 |
| `src/evidence_trace/request.rs` | 109 |
| `src/evidence_trace/sink.rs` | 92 |
| `src/evidence_trace/source.rs` | 83 |
| `src/evidence_trace/test_support.rs` | 95 |
| `src/evidence_trace/render/labels.rs` | 132 |
| `src/evidence_trace/render/rows.rs` | 208 |
| `src/evidence_trace/render/sections.rs` | 261 |
| `src/filter/matcher.rs` | 170 |
| `src/filter/surfaces.rs` | 143 |
| `src/filter/tests.rs` | 184 |

All audit Rust files are under 300 lines.

### Public API Changes

- Added public owner types:
  - `AuditFilter`
  - `SessionSummaryBuilder`
  - `SessionReviewRenderer`
  - `SessionReviewSource`
  - `EvidenceTraceSource`
- Removed public helper APIs that duplicated owner/default behavior:
  - `should_record_audit_record`
  - `should_record_with_surface_logging`
  - `session_summaries`
  - `review_session`
  - `render_session_list`
  - `render_session_show`
  - `render_session_describe`
  - `render_session_show_from_paths`
  - `render_session_describe_from_paths`
  - `render_session_list_from_default_registry`
  - `render_session_show_from_default_registry`
  - `render_session_describe_from_default_registry`
  - `session_audit_path`
  - `EvidenceTracePaths::from_default_session_registry`
  - `EvidenceTraceRequest::with_session_id`
- Explicit-record and explicit-path review behavior now lives on
  `SessionSummaryBuilder` and `SessionReviewRenderer`.

### Copy And Clone Audit

- Evidence trace rendering now borrows selected records instead of cloning
  them for markdown rendering.
- Session summary building for a selected session now borrows selected records
  instead of cloning them into a temporary `Vec<AuditRecord>`.
- Existing output/table rendering still allocates owned strings where user
  output requires them.
- `sha2::Sha256::digest` replaces the previous hand-rolled hashing code; no
  new long-lived copies were introduced for hashing.

### Exception Inventory

- `session_review.rs` contains no production free functions.
- Public review behavior lives on `SessionSummaryBuilder`,
  `SessionReviewRenderer`, and `SessionReviewSource`.
- Remaining local helper functions in `session_review/record.rs`,
  `evidence_trace/render/labels.rs`, and `evidence_trace/render/rows.rs` are
  private or module-local pure label/format transforms used by their owner
  modules.
- No production `with_*` APIs remain in `erebor-runtime-audit`.
- No production `default_*` or `validate_*` helpers remain in
  `erebor-runtime-audit`.
- Default registry behavior now lives on `Default` owner instances:
  `SessionReviewSource::default()` and `EvidenceTraceSource::default()`.

### Verification

- `cargo test -p erebor-runtime-audit --all-targets --all-features`: passed,
  20 tests.
- `cargo test -p erebor-runtime-cli --all-targets --all-features --no-run`:
  passed.
- `cargo fmt`: passed.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`:
  passed.
- `git diff --check`: passed.
- Lifecycle probe:
  - Sandboxed attempt was blocked by host permissions:
    `runtime interception broker I/O failed: Operation not permitted (os error 1)`.
  - Escalated host run passed.
  - Allowed command printed `erebor-lifecycle-allowed`.
  - Denied command failed closed with exit code 126.
  - Probe workspace:
    `/tmp/erebor-ownership-lifecycle.JQEYBb`.
  - Audit evidence contained both `"type":"deny"` and `deny-raw-cdp`.
