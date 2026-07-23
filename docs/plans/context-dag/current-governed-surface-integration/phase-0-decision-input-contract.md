# Phase 0: Current-Surface Decision Contract And Fixtures

Status: Not started.

## Purpose

Freeze the observable contract for the first context-enabled decisions before
changing a running surface. The contract must prove that each pin describes the
same input passed to policy, while retaining only the minimum current-surface
facts and preserving all existing context-free behavior.

## Scope

### 1. Specify the two surface-owned adapter codecs

Document and test deterministic, versioned representations owned by the
surface that already owns each decision:

```text
browser_cdp decision-input v1
  source kind: client_command | fetch_request_paused
  source identity: connection + command ordinal, or observer + fetch ordinal
  normalized RuntimeEvent decision fields
  exact CDP method / target / relevant session-state facts already present in payload

filesystem decision-input v1
  source kind: file_open | file_read | file_mutation
  source identity: existing handler sequence
  normalized RuntimeEvent decision fields
  normalized path and resolved device/inode when available
```

The codec may use canonical JSON for the current implementation, but the
surface must own its concrete type and version label. `erebor-runtime-context`
only accepts the resulting path and bytes. It does not deserialize, validate,
or reserve either layout.

The fixture must prove byte-for-byte determinism for the same decision input and
prove that a changed policy-relevant field changes the selected blob. It must
also prove that no raw file content, browser response body, page body, terminal
text, prompt, workspace path, launch argv, or policy source is included.

### 2. Define event and artifact identity

Current CDP client messages use the client JSON-RPC id as `RuntimeEvent.id`.
That id is only unique within one client connection. Define an internal
connection id allocated by `CdpProxyServer` and a monotonic per-connection
decision ordinal. The final internal event id and context path use those values;
the original JSON-RPC id remains in the CDP payload and response unchanged.

Define a separate observer sequence for `Fetch.requestPaused`. A CDP request id
may be reused across navigations or observer reconnects, so it is evidence, not
the context artifact's uniqueness boundary.

The fixture matrix must cover:

- two simultaneous CDP clients that both send JSON-RPC id `1`;
- two paused Fetch events with the same request id across an observer reconnect;
- a filesystem sequence restarting only in a different session id;
- a malformed or unsupported CDP message, which remains unrecorded and is not
  converted into a context decision; and
- an ungoverned CDP method, which remains transparent and gets neither a pin nor
  a synthetic audit record.

### 3. Freeze the root bootstrap and placement claim

Specify the session-owned bootstrap blob written before a surface starts. Its
only fields are the schema label, session id, actor identity, runner kind, and
enabled surface names. It intentionally excludes the launch command, workspace,
policy source, and all agent or user content.

Every first-plan decision appends to `refs/scopes/<session-id>/root`. Tests and
review wording must call this a session-level root, never a prompt scope,
command scope, or causal actor association.

### 4. Specify failure and approval behavior

Create test doubles at the real surface seams for:

- root creation failure before a session surface starts;
- context append or pin validation failure before policy evaluation;
- durable JSONL write, flush, and sync failure after policy evaluation;
- `Allow`, `Deny`, `Mediate`, and `RequireApproval` outcomes; and
- legacy context-free audit failure, which retains its existing non-fatal
  behavior.

For context-enabled actions the required result is fail-closed:

```text
CDP command append/pin/audit failure  -> CDP error reply; do not forward upstream
paused Fetch append/pin/audit failure -> Fetch.failRequest; do not continue request
filesystem append/pin/audit failure   -> deny interception decision; do not permit effect
```

`RequireApproval` is not an error. It must be durably recorded with its pin and
then return the current held/approval-required surface result. This phase does
not implement later approval completion or a second decision; that is a separate
approval-lifecycle concern.

## Files And Owners

- Add codec tests beside the owners:
  `crates/erebor-runtime-cdp/src/message/tests/` and
  `crates/erebor-runtime-session/src/surfaces/filesystem/tests/`.
- Add cross-crate fixtures and the eventual lifecycle scenario under
  `crates/erebor-runtime-e2e/tests/`; do not put a runtime fixture in CLI tests.
- Keep this plan's contract examples in this directory. Do not add an adapter
  schema document to `erebor-runtime-context` as though it were generic storage
  behavior.

## Checkpoint

- Tests demonstrate unique CDP artifact identities despite duplicate client
  protocol ids, with no client-visible CDP id change.
- Each adapter codec exactly represents the normalized event passed to policy
  and excludes the explicitly prohibited content.
- The root bootstrap is minimal, deterministic, and contains no adapter bytes.
- Failure fixtures show no context-aware allow or forward reaches an action
  boundary when append, pin, or durable audit fails.
- Approval fixtures preserve an approval-required decision and durable pin.
- Legacy standalone/runtime and adoption fixtures remain context-free rather
  than constructing an invented repository path.

## Acceptance

- The selected pin path and blob have an unambiguous, surface-owned explanation.
- Duplicate source ids cannot overwrite or ambiguously identify a context
  artifact in one session.
- The plan's retention claims are testable and no broader than the existing
  policy input.
- No production context writer, surface wiring, registry change, or CLI change
  is introduced in this phase unless a fixture needs a narrowly scoped test-only
  seam that is also used by a later approved production phase.

## Not In Scope

- implementing the journal, root scope, or context-aware engine path;
- writing any CDP, filesystem, process, or browser-state observation to Git;
- approval completion, prompts, process attribution, or context policy
  predicates.

## Stop Point

Stop after the contract and fixture checkpoint. Wait for Phase 1 approval before
adding a production writer or changing session startup.

## Phase Result

State: Not started.

No implementation or verification has been performed for this draft.
