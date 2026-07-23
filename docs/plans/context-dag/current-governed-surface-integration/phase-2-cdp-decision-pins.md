# Phase 2: CDP Command And Fetch Decision Pins

Status: Not started.

## Purpose

Use the Phase 1 session root journal for every current CDP enforcement decision
that can actually forward or block a browser effect: governed client commands
and `Fetch.requestPaused`. Preserve normal CDP wire behavior while making the
decision's adapter bytes, immutable pin, and durable audit one fail-closed
operation.

## Scope

### 1. Make CDP decision identity connection-safe

Add a server-assigned client connection identity in the CDP server/connection
family. It is an Erebor-local identifier, not a CDP protocol field. Combine it
with a per-connection command ordinal to produce:

- a unique internal `RuntimeEvent.id` for governed client commands;
- an unambiguous adapter-tree path; and
- audit/review correlation that does not collide when two clients both use
  JSON-RPC id `1`.

Retain the original CDP message id, target-session id, method, and params in the
existing normalized payload. Do not rewrite the source payload forwarded to
Chrome and do not require client changes.

For `Fetch.requestPaused`, use an observer-owned ordinal in addition to Chrome's
request id. Preserve the request id in the adapter input and `RuntimeEvent`
payload, but do not treat it as globally unique over reconnects.

### 2. Add a CDP-owned context decision preparation owner

Add a cohesive owner in the CDP message/server family, for example
`CdpContextDecision`, that:

1. normalizes the command or paused-Fetch event using the existing CDP state and
   target resolution;
2. serializes the approved `browser_cdp decision-input v1` bytes;
3. appends the opaque blob through the injected `ContextScopeJournal`;
4. selects exactly that blob from the accepted commit; and
5. returns the `RuntimeEvent` paired with its validated `PinnedContext`.

The normalized event sent to `PolicyEvaluator` must be the same decision input
represented by the selected adapter blob. The writer must include the existing
policy-relevant page/target context when it is available, but it must not add
browser response content, a snapshot of unrelated targets, or an inferred
prompt/agent association.

Keep the owner below `erebor-runtime-cdp`; it may depend directly on
`erebor-runtime-context` for the journal and pin types. Do not make the session
crate decode CDP messages and do not add a core trait that turns the CDP schema
into a universal runtime-event store.

### 3. Use one explicit CDP decision service per runtime mode

Replace the implicit combination of a `NoopAuditSink` engine plus optional
`CdpAuditRecorder` with an explicit CDP decision owner:

```text
session-backed context mode
  ContextScopeJournal + CDP codec
  + LocalEnforcementEngine<PolicySet, ..., FilteredAuditSink<JsonlAuditSink>>
  -> context-aware deferred enforcement -> one durable pinned audit record

legacy mode
  existing context-free engine + optional CdpAuditRecorder
  -> preserve standalone start and direct test behavior
```

The type split may be an enum or another narrow owner, but it must keep the
server, client connection, browser observer, and lazy mediated browser on one
clear call path. Avoid `Option` branches that can accidentally create a pin and
then route the same record through the legacy recorder.

Pass the session journal from `PreparedSession` through
`BrowserCdpSurface`, `BrowserSessionManager`, `CdpProxyServer`, client
connections, and the browser/page observer paths. The lazy browser-CDP
mediation capability must receive the same optional journal when it is launched
inside a prepared session; it must remain legacy when no prepared session exists.

### 4. Govern the current action boundaries fail-closed

For a governed client command:

```text
decode -> prepare context decision -> enforce_with_context_deferred_approval
  allow/mediate       -> update provisional CDP state and forward exact source
  deny                -> reply with the existing CDP error shape
  require approval    -> durable pinned audit, then hold as today
  context/audit error -> reply with a stable internal-error reason; do not forward
```

For `Fetch.requestPaused`:

```text
observe -> prepare context decision -> enforce_with_context_deferred_approval
  allow/mediate       -> Fetch.continueRequest
  deny/approval/error -> Fetch.failRequest(BlockedByClient)
```

Only these two action boundaries switch in this phase. State-recovery audit
records, passive browser events, bootstrap traffic, and ungoverned CDP messages
remain on their current non-context paths. In particular, do not create a pin
for a background event merely because it arrived near a governed command.

### 5. Preserve audit and policy compatibility

Context-backed records are durably appended by the engine and bypass audit
filtering as required by Phase 6. Remove the duplicate
`CdpAuditRecorder::record_optional(...)` call for those records. Legacy mode
continues to use the current recorder and its existing filtering/error behavior.

Do not change policy matching semantics, CDP method classification, client
target-state tracking, or the response shape for an ordinary policy denial.
Approval remains deferred rather than using the existing immediate-approval
context method.

## Files And Owners

- `crates/erebor-runtime-cdp/src/server.rs`, `server/connection.rs`, and
  `server/client_text.rs`: CDP connection identity and explicit decision-mode
  ownership.
- `crates/erebor-runtime-cdp/src/message/command.rs`, `message/event.rs`, and a
  focused sibling module if needed: context decision preparation and the
  context-aware command/event enforcement entry points.
- `crates/erebor-runtime-cdp/src/server/fetch.rs`: fail-closed pinned paused-Fetch
  action boundary.
- `crates/erebor-runtime-cdp/src/browser.rs` and `runtime.rs`: accept/pass the
  optional session journal without discovering paths themselves.
- `crates/erebor-runtime-session/src/session_side_resources.rs` and
  `src/surfaces/terminal/browser_cdp_process_mediation.rs`: inject the prepared
  session's journal into normal and lazy CDP surfaces.
- CDP unit and mini-upstream tests plus a cross-crate e2e fixture under
  `erebor-runtime-e2e`; do not use a real Chrome launch as the only proof.

## Checkpoint

- Two live client connections can reuse a CDP message id and produce distinct
  event ids, tree paths, commits, and audit records without modifying either
  protocol response id.
- A command pin resolves to the exact serialized adapter blob and the audit
  record's event equals the decision represented by that blob.
- A later command or Fetch event cannot alter the earlier pin's selected blob.
- An allowed command is not forwarded, and an allowed Fetch request is not
  continued, until the durable pinned audit operation succeeds.
- A durable-audit failure, context append failure, or pin failure blocks the
  corresponding browser effect and does not emit a duplicate legacy record.
- Denied and approval-required commands retain their current externally visible
  CDP behavior while gaining a valid durable pin.
- `erebor start` and CDP unit callers without an injected journal retain the
  existing context-free behavior and do not fabricate a session repository.

## Acceptance

- Every supported session-backed CDP decision has one exact immutable context
  pin and one durable audit record before its effect boundary proceeds.
- The CDP crate remains the owner of CDP schema, connection identity, browser
  state use, and protocol behavior.
- Background browser observation is not overclaimed as actor-visible context.
- No source-specific path, blob, or ref is decoded by core, audit, or session
  registry code.

## Not In Scope

- browser response capture, page-content capture, CDP response-delivery
  consumption, or a prompt-to-client binding;
- context pins for state-recovery maintenance audits or passive browser events;
- terminal/process context integration, filesystem integration, standalone
  sessionization, or approval completion.

## Stop Point

Stop after CDP focused tests, the mini-upstream e2e scenario, and the Phase 2
lifecycle probe. Wait for Phase 3 approval before changing filesystem behavior.

## Phase Result

State: Not started.

No implementation or verification has been performed for this draft.
