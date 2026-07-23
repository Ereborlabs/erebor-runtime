# Phase 2: Prompt Ingress And Transport Broker Reconciliation

Status: Done — implemented, reviewed, and verified on 2026-07-15 for the
explicitly brokered `session run` App Server stdio profile. This does not
authorize a hook-first source, an IDE-owned inherited transport, or any
physical effect.

## Purpose

Create one policy-bearing prompt/node stream per native Codex input while
combining Linux's pre-work App Server broker with the common managed hook
events.

## Scope

- Add an owned App Server transport broker for a normal `session run` path whose
  child transport Erebor creates directly, with complete JSONL framing, exact
  byte preservation, request/response pairing, bounded buffering, and
  sensitive client-method policy. Phase 7 may reuse this owner only after a
  current auto-admitted App Server profile proves an approved pre-work
  transport interposition mechanism.
- For a certified brokered source profile, write a durable pending prompt node
  before forwarding every `turn/start` or `turn/steer` request to Codex. Linux
  V0 FD-splicing is historical evidence, not a Phase 2 dependency or V1
  mechanism selection.
- Bind exact App Server session/thread/turn/item facts from the matching
  response/notification into the Scope Context DAG.
- Add authenticated SessionStart and UserPromptSubmit handlers.
- Reconcile broker and hook observations using exact runtime/session/turn and
  profile evidence. One original input yields one scope/context node.
- Make UserPromptSubmit the selected prompt source only for profiles without a
  certified brokered transport, after Phase 0 ordering proof.
- Record rich IDE context, attachments, model-visible request content, and
  unavailable fields separately. Do not fabricate them from output/history.
- Govern or deny sensitive App Server client methods such as direct shell,
  process, filesystem, injection, and realtime paths before forwarding.
- Add native child-agent bindings from authenticated hook and App Server facts.
- Keep transport reconnection/history as reconciliation evidence, never as a
  replacement for a missed live ingress boundary.

## Tests

- JSONL fragmentation, coalescing, invalid framing, duplicate IDs, backpressure,
  cancellation, reconnect, and stdout/stderr separation.
- Broker-before-forward proof for prompt and sensitive-method denial fixtures.
- Broker/hook exact match, missing hook, wrong turn, duplicate hook, steer,
  queued input, resume, subagent, and concurrent IDE-window fixtures.
- Hook-first CLI/TUI prompt tests prove the certified ordering and explicit
  degraded state when before-model proof is absent.

## Checkpoint

```sh
cargo fmt
cargo test -p erebor-runtime-session --all-targets --all-features
EREBOR_REQUIRE_CODEX_LINUX_V1_SESSION_RUN=1 \
  EREBOR_CODEX_LINUX_V1_CLI=<pinned-codex> \
  cargo test -p erebor-runtime-e2e --test codex_linux_v1_session_run \
  brokered_app_server_prompt_ingress --all-features -- --test-threads=1 --nocapture
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

## Acceptance

- Brokered IDE profiles have a pre-work prompt boundary.
- Hook-first profiles have only the ordering claim actually proven.
- No duplicate scope or late history record becomes policy authority.

## Stop Point

Stop after prompt-ingress verification. Wait for Phase 3 approval.

## Phase Result

State: Done.

### Implemented ownership

- `erebor-runtime-core` owns the opt-in
  `codex.profiles[].app_server_transport.enabled` profile fact. It defaults to
  false and rejects unknown transport configuration, so a managed hook profile
  never becomes a brokered prompt profile by implication.
- `erebor-runtime-session/src/agents/codex/transport.rs` owns the direct-child
  stdio broker. It accepts only `codex app-server --stdio`, frames JSONL across
  fragmented/coalesced reads, retains and forwards the original frame bytes,
  bounds incomplete frames and in-flight IDs, and pairs only matching responses.
  Client stderr stays inherited while the broker alone handles App Server
  stdout JSONL. A failed child-output validation wakes the input relay, stops
  all further client forwarding, terminates the direct child, and reaps it; it
  never waits for the client to close stdin after that failure.
- Before forwarding a `turn/start` or `turn/steer` frame, the broker creates a
  session context root if necessary, creates the exact thread scope, and
  commits one pending prompt node containing the original JSONL, request ID,
  model-visible input, observed rich IDE context/attachments, and explicit
  `unavailable` markers. Response and notification facts update that same node;
  they cannot create a second original input.
- `command/exec` (including submethods), `process/*`, `fs/*`,
  `thread/shellCommand`, `thread/inject_items`, `thread/realtime/*`,
  `injection/*`, and `realtime/*` are denied with an Erebor JSON-RPC error
  before they are written to child stdin.
- `CodexPromptReconciliation` records only hook events accepted by the
  authenticated hook broker. In Codex's pinned `UserPromptSubmit` schema,
  `session_id` is its native App Server thread identifier; it corroborates a
  brokered node only when that thread ID and the native turn ID match exactly.
  The authenticated broker remains session/profile scoped. Missing or
  differently-shaped native identifiers remain `unmatched`; prompt text,
  timing, CWD, and history are never used as a fallback. `SessionStart` is
  recorded as authenticated profile evidence but cannot create a prompt node.
- The durable prompt record stores Codex's `additionalContext` as rich IDE
  context. It records non-text App Server `input` items (such as image and
  local-image inputs) as observed attachments when no dedicated `attachments`
  field is present; no model-visible field is invented.
- An App Server `thread/started` notification binds a child thread only when
  its `parentThreadId` equals exactly one existing parent prompt thread. The
  node separately reports matching authenticated subagent-hook evidence. No
  heuristic child attribution exists.

### Deliberate boundary

This phase certifies only a new child whose stdio Erebor owns from launch. The
stdio broker has no reconnect/replay mode: disconnecting it ends that child
transport, and history is never replayed as ingress. IDE-owned inherited
transport and hook-first CLI/TUI sources remain unavailable as prompt sources
until their own profile-specific ordering/interposition evidence is approved.
The broker records prompt provenance; it grants no invocation lease and no
process, filesystem, or network authority. Those controls begin in Phase 3.

### Review remediation

The post-implementation review found that the first deny matcher used generic
`injection/*` and `realtime/*` prefixes rather than Codex's actual
`thread/inject_items` and `thread/realtime/*` names, and that a child-stdout
protocol failure could leave the input relay blocked on client stdin. Both are
fixed and covered by crate-local tests plus the pinned live fixture. The review
also aligned reconciliation with Codex's documented hook thread/turn facts and
aligned rich IDE context capture with App Server `additionalContext`.

### Verification

Executed successfully:

```sh
cargo fmt --all -- --check
# clean
cargo test -p erebor-runtime-core --all-targets --all-features
# 80 passed
cargo test -p erebor-runtime-session --all-targets --all-features
# 117 passed
EREBOR_REQUIRE_CODEX_LINUX_V1_SESSION_RUN=1 \
  RUST_LOG=erebor_runtime_session=warn \
  EREBOR_CODEX_LINUX_V1_CLI=/home/navid/.vscode/extensions/openai.chatgpt-26.707.71524-linux-x64/bin/linux-x86_64/codex \
  cargo test -p erebor-runtime-e2e --test codex_linux_v1_session_run \
  brokered_app_server_prompt_ingress --all-features -- --test-threads=1 --nocapture
# 1 passed; 1 filtered out; proves exact UserPromptSubmit reconciliation and
# Erebor-originated denials for thread/shellCommand, thread/inject_items, and
# thread/realtime/appendText
cargo test --workspace --all-targets --all-features
# passed
cargo clippy --workspace --all-targets --all-features -- -D warnings
# clean
git diff --check
# clean
```

The live fixture uses the pinned local Codex 0.144.2 binary and its local mock
responses server. It proves both the durable brokered context node and an
Erebor-originated `-32003` denial for `thread/shellCommand`; no paid or remote
model is used.
