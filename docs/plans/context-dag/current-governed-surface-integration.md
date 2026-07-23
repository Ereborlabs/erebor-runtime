# Current Governed-Surface Context Integration Plan

Status: Draft — awaiting review and explicit phase approval.

Parent design: [Context DAG](../context-dag.md)

Completed prerequisite: [Context Model Git Repository Implementation Subplan](context-model-git-repository.md). Its Phase 6 decision-pins document was not recovered.

Related design: [Process And Surface Attribution](../process-and-surface-attribution.md)

## Goal

Make the completed session-owned Git context repository participate in the
current, real enforcement paths without claiming prompt attribution or adding a
universal adapter schema.

The first integration records the exact surface-defined decision input for each
supported action, pins the newly accepted immutable commit, evaluates the
existing `PolicyEvaluator`, and durably appends the pinned audit record before
the action can proceed.

```text
session-backed decision input
        |
        v
surface-owned opaque v1 blob + root-scope append
        |
        v
validated PinnedContext
        |
        v
existing PolicyEvaluator(RuntimeEvent)
        |
        v
durable JSONL audit containing ContextPin
        |
        +--> allow / mediate / hold / deny at the existing enforcement boundary
```

The initial context is session-level provenance only. It must not say that a
browser or filesystem action came from a user prompt, terminal command, process,
or agent turn unless a later approved source proves that association.

## Research Conclusion And Scope Boundary

The repository is already created for every `erebor session run` lifecycle, but
no current surface appends to it or calls `enforce_with_context(...)`:

| Current path | Existing owner | First-plan treatment |
| --- | --- | --- |
| Governed CDP client command | `erebor-runtime-cdp` `CdpCommandEnforcer` and `CdpClientConnection` | Context-aware, pinned, durable-audit decision. |
| `Fetch.requestPaused` network decision | `erebor-runtime-cdp` `PausedFetchHandler` | Context-aware, pinned, durable-audit decision. |
| Filesystem open/read/mutation interception | `erebor-runtime-session` `FilesystemFileOperationHandler` | Context-aware, pinned, durable-audit decision. |
| CDP browser-state recovery audit | CDP observer | Remains a non-decision maintenance audit in this plan; it receives no invented pin. |
| Terminal/process-exec guard | `erebor-runtime-terminal` and session IPC broker | Deferred. It does not yet construct a `RuntimeEvent` or use the durable engine/audit boundary. |
| `erebor start` standalone browser service | CLI/start surface runner | Remains context-free. It creates a synthetic runtime session id rather than a registry-owned session artifact. |
| Session adoption | session adoption path | Deferred. It has no prepared session registry/context owner. |

This is deliberately narrower than the long-term process-and-surface attribution
design. It creates trustworthy decision provenance for surfaces that already
have both a session artifact and a synchronous enforcement point; it does not
pretend to solve online scope routing, prompt capture, delivery consumption, or
process identity.

## Current-Code Baseline

- `SessionRegistry::start_session(...)` creates
  `.erebor/sessions/<session-id>/context/`, and `PreparedSession` retains its
  `ContextRepository`, but the handle is only checked at session completion.
- `BrowserCdpSurface` creates `LocalEnforcementEngine<PolicySet>` with the
  default `NoopAuditSink`. `CdpAuditRecorder` separately performs a best-effort,
  non-durable JSONL append after CDP command or paused-Fetch enforcement.
- `FilesystemFileOperationHandler` directly evaluates `PolicySet` and separately
  performs the same best-effort audit append.
- `LocalEnforcementEngine::enforce_with_context(...)` correctly fails closed on
  durable-audit failure, but it resolves approval immediately. Current CDP and
  filesystem decisions preserve `RequireApproval` as a held surface outcome, so
  a deferred context-aware engine path is required before either surface can
  switch.
- CDP command event ids are currently derived from the client JSON-RPC `id`.
  Different WebSocket clients may reuse that id, so context artifact names and
  audit event identity need a server-assigned connection component without
  changing client-visible CDP protocol ids.

## Target Ownership

```text
SessionRegistry
  -> owns only session-id-to-artifact-path authority and bare repository init/open

SessionExecutionService / PreparedSession
  -> initializes one root scope before eligible surfaces start
  -> owns and shares one in-process root-scope journal for this session

ContextScopeJournal (erebor-runtime-context)
  -> serializes one authorized scope's append + exact-commit pin operation
  -> accepts caller-owned Snapshot, paths, bytes, and selections opaquely
  -> does not parse CDP, filesystem, RuntimeEvent, policy, or audit schemas

erebor-runtime-cdp
  -> owns CDP decision-input v1 bytes, client identity, command/fetch placement,
     and the CDP enforcement result

erebor-runtime-session filesystem surface
  -> owns filesystem decision-input v1 bytes and file-interception result

erebor-runtime-core
  -> owns context-aware deferred approval and durable-audit enforcement behavior

erebor-runtime-audit
  -> durably writes and later validates ContextPin references; it does not decode
     adapter bytes into a second context model
```

`ContextScopeJournal` is a storage/lifecycle owner, not a tracker. Its public
operation accepts opaque caller-owned tree edits and selected paths, appends them
to one direct scope ref, then validates selections against the exact commit
returned by that append—not a later reread of the moving ref. It returns that
repository-validated `PinnedContext` before another in-process append may
advance the ref. A per-session mutex is appropriate for this one active writer;
the repository's compare-and-swap remains the cross-process correctness
boundary.

## Surface Content Contract

The context repository continues to see only caller-defined paths and bytes.
This plan names two adapter contracts; neither is a universal event schema:

| Adapter owner | Example retained blob | Pin selection | Explicitly excluded |
| --- | --- | --- | --- |
| Session runtime | `erebor/session/bootstrap-v1.json` | None; it establishes the root only. | Launch command, workspace contents, policy source, or raw prompt. |
| CDP | `browser_cdp/decisions/<connection>/<ordinal>.json` | The one blob that canonically represents the normalized command or paused Fetch decision input. | Browser responses, page content, unselected browser state, and a guessed prompt link. |
| Filesystem | `filesystem/decisions/<ordinal>.json` | The one blob that canonically represents the normalized file decision input. | File contents, preimages, terminal text, and a guessed process link. |

The exact adapter serialization must be versioned and deterministic. It must
contain every field used to construct the `RuntimeEvent` that policy receives,
including the source-specific identity and normalized target. A surface may
retain less than its raw wire request, but it cannot pin a summary that omits
policy-relevant fields. The surface-owned codec, not the context repository,
performs any serialization or decoding.

All initial decisions append to `ScopeRef::root(session_id)`. That branch means
"known governed session" only. Commit ancestry records accepted journal order;
it is not asserted to be a total order of external events, and it is not a
prompt-bearing scope.

## Non-Negotiables

- The Git repository remains the only authoritative context graph. This plan
  adds no event table, action table, delivery table, database projection, or
  mutable side journal.
- `SessionRegistry` remains the only owner of session-id-to-context-path
  authority. It does not become an adapter decoder or action router.
- `ContextScopeJournal` may not reserve an adapter tree layout or parse adapter
  bytes. CDP and filesystem schemas remain in their existing surface owners.
- A context-enabled decision may proceed only after: the adapter blob is
  appended and pinned, policy has returned, and the pinned audit record is
  durably accepted. A context, pin, or durable-audit error is fail-closed at
  that action boundary.
- The context-aware path must preserve current `RequireApproval` behavior:
  record the pending decision durably, then hold the CDP request or return the
  existing filesystem approval outcome. It must not silently convert approval
  into an allow or a denial merely to reuse an API.
- Pinned records are written exactly once by the engine's durable audit sink.
  Do not retain the current second best-effort recorder for the same decision.
- Existing context-free routes remain behavior-compatible and explicitly
  context-free: standalone `start`, adoption, and ungoverned CDP messages must
  not manufacture a context repository or pin.
- Do not add prompt, response, terminal, process, browser-response, file-byte,
  or page-content capture. Do not infer a source actor from proximity, target,
  CWD, recency, or an event-loop's last request.
- Scope refs remain retained. This plan adds no ref deletion, pruning, `git gc`,
  repacking, retention refs, or rollback behavior.

## Planned Progression

```text
Phase 0  decision-input contract, identity, privacy, and regression fixtures
Phase 1  generic serialized root-scope journal and session bootstrap
Phase 2  CDP command and paused-Fetch pinned decisions
Phase 3  filesystem pinned decisions
Phase 4  session lifecycle proof, review validation, and cutover evidence
```

## Recovered Phase Files

- [Phase 0: decision-input contract](current-governed-surface-integration/phase-0-decision-input-contract.md)
- Phase 1: generic serialized root-scope journal and session bootstrap (phase
  document not recovered)
- [Phase 2: CDP decision pins](current-governed-surface-integration/phase-2-cdp-decision-pins.md)
- [Phase 3: filesystem decision pins](current-governed-surface-integration/phase-3-filesystem-decision-pins.md)
- [Phase 4: lifecycle, review, and cutover](current-governed-surface-integration/phase-4-lifecycle-review-and-cutover.md)
- [Lifecycle probe](current-governed-surface-integration/lifecycle-probe.md)

Each phase ends at an explicit stop point. Approval of this plan does not
approve implementation; the user approves one phase by name.

## Verification Shape

No command below has been run for this draft. Each implemented phase must first
run its focused checks and then the workspace gates:

```sh
cargo fmt --all
cargo test -p erebor-runtime-context --all-targets --all-features
cargo test -p erebor-runtime-core --all-targets --all-features
cargo test -p erebor-runtime-cdp --all-targets --all-features
cargo test -p erebor-runtime-session --all-targets --all-features
cargo test -p erebor-runtime-e2e --test context_current_surface_integration --all-features
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

The live lifecycle probe is specified in [lifecycle-probe.md](./lifecycle-probe.md).
It is required after Phase 0 whenever the host can run the relevant Linux
session guard and browser fixture. A blocked host must report the exact command
and error; fixture tests do not replace the probe.

## Not In Scope

- prompt ingress, LLM request/response capture, transcript parsing, or Codex,
  Claude, MCP, or OpenClaw adapter schemas;
- process identity, terminal input/output, process-exec context decisions,
  filesystem-to-process routing, or socket/network collector work outside the
  existing paused-Fetch decision;
- browser-state history, target/frame replay, CDP response delivery, or
  client-consumption merges;
- policy predicates that decode Git blobs or a generic `RuntimeEvent` context
  adapter;
- exposing context repository administration through CLI;
- converting standalone `erebor start` or adoption into a registered session;
- retention, ref deletion, archival refs, pruning, garbage collection, or
  power-loss claims beyond the completed repository plan.

## Approval And Stop Point

Review the Phase 0 contract before implementation. It fixes the only
cross-surface choices that would otherwise become accidental architecture:

1. the exact CDP and filesystem adapter bytes retained by default;
2. the unique CDP connection/decision identity format;
3. the root bootstrap fields and their privacy boundary; and
4. the fail-closed response for a context or durable-audit failure.

Stop after each approved phase. Do not begin terminal/process attribution,
prompt integration, or standalone-runtime sessionization from this plan.

## Phase Index

- [Phase 0: Current-Surface Decision Contract And Fixtures](./phase-0-decision-contract-and-fixtures.md)
- [Phase 1: Session Root Journal And Context-Aware Deferred Enforcement](./phase-1-session-root-journal.md)
- [Phase 2: CDP Command And Fetch Decision Pins](./phase-2-cdp-decision-pins.md)
- [Phase 3: Filesystem Decision Pins](./phase-3-filesystem-decision-pins.md)
- [Phase 4: Lifecycle, Review, And Cutover Evidence](./phase-4-lifecycle-review-and-cutover.md)
