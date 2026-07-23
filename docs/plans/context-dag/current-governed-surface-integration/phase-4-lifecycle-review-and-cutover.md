# Phase 4: Lifecycle, Review, And Cutover Evidence

Status: Not started.

## Purpose

Prove that the integrated CDP and filesystem paths work through the real
session lifecycle, retain verifiable pins across restart, and have an honest
cutover boundary. This phase closes the first current-surface integration; it
does not expand into process or prompt attribution.

## Scope

### 1. Add a session-backed cross-surface e2e fixture

Add `crates/erebor-runtime-e2e/tests/context_current_surface_integration.rs`
and reusable support only where existing fixtures cannot express the lifecycle.
The scenario must create a real session registry artifact, start the same
session-side resources used by `SessionExecutionService`, and exercise the
current governed decision owners rather than constructing an arbitrary
`ContextPin` in the test.

Use the existing deterministic mini CDP upstream for default coverage. A real
Chrome run remains a supplementary acceptance probe, not a reason to skip the
deterministic lifecycle proof.

The fixture must prove all of the following:

1. a session-backed CDP command produces a valid pin and is only forwarded
   after its durable audit record;
2. a denied or failed-audit CDP command never reaches the mini upstream;
3. a paused Fetch request produces a valid pin and is failed rather than
   continued on an audit/context error;
4. a filesystem operation through the actual interception router is pinned and
   denied before an effect when context/audit fails;
5. concurrent CDP and filesystem decisions retain every accepted root commit,
   with each JSONL record validating against the reopened repository; and
6. `SessionReviewSource::render_describe(...)` continues to validate and render
   the pin references after session completion and restart.

If a single host cannot run the ptrace-backed filesystem effect, split the
deterministic router fixture from the required live lifecycle probe. State the
host restriction precisely; do not call the phase complete solely from a mocked
kernel effect.

### 2. Prove compatibility paths intentionally remain unpinned

Add regression tests for:

- standalone `erebor start` browser CDP: normal legacy behavior and no attempt
  to discover a session repository;
- session adoption: no fabricated registry/context path;
- ungoverned CDP traffic: transparent forwarding and no synthetic context
  decision; and
- CDP state-recovery maintenance audits: retained legacy audit shape with no
  invalid or misleading `ContextPin`.

These are not gaps hidden by the test suite. They are the documented boundary
of this plan and protect later work from silently turning runtime-scoped ids
into session-owned provenance.

### 3. Verify retention, review, and no-second-store properties

For a completed fixture session:

- reopen the repository using `SessionRegistry::open_context_repository`;
- validate every non-null audit `ContextPin` against its recorded commit and
  selected blob;
- assert that all referenced commits remain reachable through ordinary root
  history and that no extra retention ref exists;
- inspect the context tree only through `ContextRepository`; and
- assert JSONL contains references, never a duplicate selected blob payload.

Continue using session review's existing generic pin projection. Do not add CDP
or filesystem byte decoders to `erebor-runtime-audit`; surface-specific content
rendering requires a separate approved review/retention plan.

### 4. Complete the operational probe and status handoff

Run [lifecycle-probe.md](./lifecycle-probe.md) after the focused and workspace
checks. The final phase result must distinguish the deterministic mini-upstream
result, the Linux guard result, and any real Chrome result. A Chrome sandbox
failure or an unavailable ptrace host is an environmental limitation, not a
claimed successful browser/file enforcement run.

Update this README and every completed phase result with exact files, focused
tests, full commands/results, retention facts exercised, and a final `Done`,
`Not done`, or `Blocked` state.

## Files And Owners

- `crates/erebor-runtime-e2e/tests/context_current_surface_integration.rs` and
  narrowly scoped support fixtures: cross-crate/session lifecycle proof.
- Existing owner-local tests in context, core, CDP, and session crates: focused
  failure, compatibility, and serialization behavior.
- `docs/plans/scope-context-dag/context-model-current-surface-integration/`:
  phase-result and lifecycle evidence updates only; do not rewrite parent
  design documents to make a future direction look implemented.

## Checkpoint

- The normal session lifecycle produces root commits and durable pinned JSONL
  records for each supported current-surface decision.
- Reopened session review validates every recorded pin after the runtime and
  original in-memory journal are gone.
- Context/audit failure tests show no CDP forward, no Fetch continuation, and
  no allowed filesystem effect.
- Concurrent supported surfaces retain all accepted commits with no stale-head
  retry, path collision, duplicate audit append, or pin mismatch.
- Every intentionally context-free path is covered by a regression test.
- Focused checks, workspace test suite, formatter, Clippy, and the live probe
  have recorded results or an exact host block.

## Acceptance

- Session-backed CDP commands, paused Fetch decisions, and filesystem
  operations are genuinely integrated into the completed Git context model.
- The evidence chain is verifiable after restart:

  ```text
  audit ContextPin -> session-owned repository -> immutable commit -> selected adapter blob
  ```

- The first integration has no untracked compatibility change, no duplicate
  audit writer, no second durable context store, and no claim beyond
  session-level provenance.
- The plan/status documents state the actual verification state and the next
  explicit stop point.

## Not In Scope

- follow-up prompt/process/scope tracker work;
- human-readable decoding of adapter bytes in session review;
- support for standalone `start`, adoption, browser responses, terminal exec,
  socket/network interception, or approval completion;
- ref deletion, garbage collection, retention redesign, or power-loss claims.

## Stop Point

Stop after the acceptance evidence is recorded. Any next proposal must choose
one new source of stronger context—such as process-exec attribution, a prompt
ingress surface, or CDP client/process binding—and receive separate approval.

## Phase Result

State: Not started.

No implementation or verification has been performed for this draft.
