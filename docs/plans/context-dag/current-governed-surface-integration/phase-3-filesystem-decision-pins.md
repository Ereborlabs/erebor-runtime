# Phase 3: Filesystem Decision Pins

Status: Not started.

## Purpose

Move the existing synchronous filesystem interception decision onto the same
session-owned root journal and durable pinned-audit boundary, without recording
file contents or claiming that a file operation belongs to a terminal command or
prompt.

## Scope

### 1. Add a filesystem-owned decision-input codec

Keep the codec beside `FilesystemFileOperationHandler` in
`crates/erebor-runtime-session/src/surfaces/filesystem/`. It serializes the
approved `filesystem decision-input v1` representation using only fields that
the handler already normalizes for policy:

```text
schema/version
handler-local operation ordinal
operation kind
session and actor identity
normalized target/path and source cwd
pid and ppid as observed facts only
resolved device/inode when available
risk and timestamp
```

It must represent the exact `RuntimeEvent` sent to policy. The event path uses
the handler ordinal rather than an untrusted input path or PID. No file bytes,
preimages, directory enumeration, terminal text, process ancestry claim,
prompt, or workspace source is added.

PID and PPID remain ordinary observed values. This phase does not treat them as
stable process identities and does not route events into a command scope.

### 2. Replace split policy/audit handling only in context-backed sessions

Refactor `FilesystemFileOperationHandler` around an explicit decision owner.
In session-backed context mode it receives both the shared
`Arc<ContextScopeJournal>` and a `FilteredAuditSink<JsonlAuditSink>` created
from the prepared session's audit path. For each intercepted operation it:

1. builds the existing normalized filesystem `RuntimeEvent`;
2. appends and pins its one adapter blob;
3. calls the Phase 1 deferred context-aware engine operation; and
4. translates the returned policy outcome through the existing
   `SurfaceInterceptionDecision` mapping.

When the context resource is absent, retain the current context-free policy and
best-effort audit path. This preserves adoption and other callers that do not
yet have a session artifact rather than making up a repository path.

Do not replace `FilesystemMediationDocument` parsing or alter the existing
allow/deny/approval/mediate mapping. It remains the filesystem surface's
responsibility after policy returns.

### 3. Fail closed at the synchronous interception boundary

Map context construction, append, pin validation, engine, or durable-audit
failure to a stable deny decision owned by the filesystem surface. The denial
must reach the existing IPC response before the guard permits the kernel effect.
It must preserve enough structured/logged error context for diagnosis without
putting sensitive adapter bytes in the reason returned to the intercepted
process.

An approval-required policy decision is valid: audit it durably with its pin,
then return the current `SurfaceInterceptionDecision::require_approval(...)`.
The phase does not pretend that an approval was resolved or create an effect
lease.

### 4. Wire only from the prepared-session side-resource owner

In `start_session_side_resources_from_start_plan(...)`, pass the active journal
and durable sink material only from `PreparedSession`. Keep the filesystem
handler independent from `SessionRegistry`; the handler must never resolve a
session id to a path on its own. Preserve the existing session interception
router and guard IPC request/decision shapes unless a typed failure needs to be
translated at that owner boundary.

## Files And Owners

- `crates/erebor-runtime-session/src/surfaces/filesystem.rs` and a focused
  `surfaces/filesystem/context.rs` sibling if it improves readability:
  filesystem codec, decision owner, and error-to-deny mapping.
- `crates/erebor-runtime-session/src/session_side_resources.rs`: inject the
  prepared context journal and durable audit sink material.
- `crates/erebor-runtime-session/src/runtime_interception_broker/handlers.rs`
  only if an existing typed interception response needs an additional safe
  surface reason; do not move filesystem policy into the broker.
- Filesystem unit tests beside the handler, core engine tests only for shared
  engine behavior, and a session/e2e fixture for the actual broker boundary.

## Checkpoint

- File open, read, and mutation fixtures each produce a pinned record whose
  selected blob reconstructs the exact event evaluated by policy.
- Normalized relative paths and resolved file identities are retained exactly as
  the existing policy envelope sees them; raw file bytes are absent from both
  the pin and JSONL record.
- A later filesystem append cannot change an earlier selected blob or pin.
- An allow is returned only after successful durable audit. Context or durable
  audit failure produces a deny and the fake/real guarded operation observes no
  permitted effect.
- Deny, approval-required, and valid mediation behavior stay compatible with
  current `SurfaceInterceptionDecision` tests.
- Concurrent file requests sharing one session journal do not lose a root
  commit, return a mismatched pin, or overwrite a context path.
- Context-free handler construction retains legacy behavior and never creates a
  context artifact.

## Acceptance

- Every supported session-backed filesystem decision is backed by the exact
  immutable surface input and one durable JSONL record before the guard can
  permit the effect.
- Filesystem context data is minimal and does not turn an observed PID into a
  causal process or prompt relationship.
- The shared root journal provides correct per-session commit history without a
  new mutable action store.

## Not In Scope

- process-exec context, PID-reuse handling, process tracker/replay, terminal
  input, socket/network interception, or Linux collector changes;
- file-content or preimage capture, filesystem retention changes, or policy
  access to context blob contents;
- CDP changes, standalone sessionization, or approval completion.

## Stop Point

Stop after filesystem focused tests, a broker-bound e2e scenario, and the Phase
3 lifecycle probe. Wait for Phase 4 approval before declaring the integrated
surface work complete.

## Phase Result

State: Not started.

No implementation or verification has been performed for this draft.
