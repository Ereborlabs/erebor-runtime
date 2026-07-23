# Session Review And LLM Governance Plan

Status: planning document.

Plan type: product UX, audit architecture, implementation, and validation plan.

Related roadmap:

- [`docs/development-plan.md`](../../development-plan.md)
- [`docs/governed-browser-and-terminal-plan.md`](../../governed-browser-and-terminal-plan.md)
- [`docs/plans/session-hypervisor/README.md`](../session-hypervisor/README.md)
- [`docs/plans/governed-openclaw-pilot/README.md`](../governed-openclaw-pilot/README.md)
- [`docs/plans/semantic-classification/README.md`](../semantic-classification/README.md)

## Goal

Make governed sessions the primary review object for Erebor.

The user-facing object should be:

```text
erebor session ls
erebor session show <session-id>
erebor session describe <session-id>
```

not:

```text
cat audit.jsonl | jq ...
```

The audit JSONL remains the source of truth, but the product UX should explain
one governed run in the language a reviewer actually needs:

- what ran
- who or what acted
- which runner and surfaces were active
- what the agent attempted
- what Erebor allowed, denied, held, or mediated
- which rule made each important decision
- which controlled path enforced the decision
- what proof shows the final effect

The second goal is to define an LLM-provider governance surface, starting with
an OpenAI-compatible Erebor proxy that agent tools can use through
`openai_base_url`-style configuration.

## Why This Track Exists

Warp's run/session UX is useful because it makes agent work inspectable: prompts,
plans, commands, logs, output, artifacts, status, parent/child runs, and usage
are all reviewable as one run.

Erebor should learn the UX lesson without copying the trust model.

Warp can show what happened in a run. Erebor should show:

```text
what the agent attempted, what was governed, what rule decided it, what
controlled path enforced it, and what evidence proves the final effect.
```

The current repo already has the important raw material:

- `RuntimeEvent` carries session, actor, surface, action, target, payload, risk,
  and timestamp.
- `AuditRecord` carries the event plus policy and final decisions.
- CDP and process surfaces already emit JSONL audit records.
- Evidence traces already render buyer-readable markdown from audit, policy, and
  config artifacts.

What is missing is a session-first product surface and consistent proof metadata
across surfaces.

## Non-Goals

- Do not replace JSONL audit logs. They remain the append-only source of truth.
- Do not move session UX under `erebor audit`. `audit` is for raw logs, export,
  evidence traces, and debugging. `session` is the product view.
- Do not claim full LLM-call governance from configuration alone. A configured
  `openai_base_url` is cooperative until direct provider egress is blocked.
- Do not store prompt or response bodies by default. LLM audit must have an
  explicit privacy mode.
- Do not make an LLM refusal, classifier, or agent self-report the security
  boundary.

## Product Model

### Governed Session

A governed session is the product boundary.

It is the unit a user reviews after the run:

```text
session-8421
```

It groups:

- root agent process or adopted process tree
- actor identity
- runner
- workspace
- policy package
- runtime config
- active surfaces
- governed endpoints
- audit records
- transcript and artifacts when available
- capability and residual-risk reports

### Session Review

A session review is the human-facing summary derived from source artifacts.

It answers:

- Did the session run in enforced, adopted, or cooperative mode?
- Which surfaces were governed?
- Which risks were attempted?
- Which events changed authority or risk?
- Which policy rules were decisive?
- Which effects were actually blocked, allowed, or mediated?
- Which artifacts prove this?

### Audit Record

An audit record remains the source-of-truth event:

```text
RuntimeEvent + policy_decision + final_decision
```

This plan extends it with optional proof metadata, but does not make the session
UX depend on a new storage backend before it can ship.

### Transcript

A transcript is the agent narrative:

- prompt
- plan
- tool calls
- commands
- command output
- browser actions
- generated artifacts
- model/tool messages where available

Transcripts are not the enforcement source of truth. They help reviewers
understand intent and context. Audit records prove governance.

## CLI Shape

### `erebor session ls`

List known sessions.

```text
erebor session ls
```

Example output:

```text
SESSION       STATUS     ACTOR      RUNNER       SURFACES             ALLOW DENY MEDIATE RISK    START
session-8421  complete   openclaw   linux-host   browser,terminal     18    2    1       high    18:03:01
session-9130  complete   codex      docker       terminal,llm,network 42    0    0       medium  18:12:44
```

Columns:

- `SESSION`: `record.event.session_id`
- `STATUS`: inferred initially, explicit after session lifecycle records land
- `ACTOR`: most common `record.event.actor.id`
- `RUNNER`: from session registry or config
- `SURFACES`: distinct surfaces with records
- `ALLOW`, `DENY`, `MEDIATE`: counts from `final_decision`
- `RISK`: maximum risk level across records
- `START`: earliest event timestamp

The table should sort by newest session first by default.

### `erebor session show <session-id>`

Show a concise buyer-readable summary.

```text
erebor session show session-8421
```

Example output:

```text
Session session-8421
Actor: openclaw
Runner: linux-host
Mode: enforced with residual host-network risk
Surfaces: browser_cdp, terminal
Verdict: governed run with 2 denied high-risk actions

Summary
OpenClaw navigated to a GitHub OAuth consent flow. Erebor allowed the navigation
and page inspection, then denied the local OAuth callback handoff before the
callback service received the grant.

Key Decisions
18:03:07 allow   browser_navigate  GitHub OAuth authorize page
18:03:11 allow   browser_click     Authorize button
18:03:12 deny    network_request   local OAuth callback
18:03:14 allow   process_exec      grep diagnostic logs

Most Important Rule
deny-oauth-callback-network-request
OAuth callback handoff must not reach the local callback without operator approval.

Proof Summary
- Browser action path was Erebor-governed CDP.
- Callback was failed by the CDP Fetch observer.
- Policy and config artifacts are hashable and included in the evidence trace.
```

`show` should avoid dumping every record. It should prioritize authority
transitions:

- denied events
- approval-required events
- mediated events
- high-risk allowed events
- browser navigations
- network requests
- process launches
- semantic authority/data events after semantic classification lands

### `erebor session describe <session-id>`

Show the deep proof view.

Example output:

```text
Denied Event
Action: network_request
Surface: browser_cdp
Target: http://127.0.0.1:5105/oauth/callback?code=redacted&state=redacted
Risk: high
Rule: deny-oauth-callback-network-request
Policy decision: deny
Final decision: deny

Controlled Path
Mode: enforced
Backend: browser_cdp_proxy
Observer: Fetch.requestPaused
Final effect: Fetch.failRequest / BlockedByClient
Upstream reached: false
Private upstream exposed to agent: false

Proof
Audit record id: evt-...
Raw payload sha256: ...
Policy sha256: ...
Config sha256: ...
Evidence trace sha256: ...
```

For process execution:

```text
Denied Event
Action: process_exec
Surface: terminal
Target: google-chrome
Command: google-chrome --remote-debugging-port=9222
Rule: deny-unmanaged-chrome-cdp

Controlled Path
Mode: enforced
Backend: linux_ptrace_process_guard
Final effect: exec denied before child gained authority
Exit code: 126

Proof
Session id: session-8421
Actor: openclaw
Process guard backend: ptrace
Session membership: cgroup:/erebor/session-8421
```

`linux_ptrace_process_guard` and `Process guard backend` are low-level backend
labels preserved for audit compatibility. The architecture owner is
`session.interception`; the terminal surface owns the `process_exec` semantic
decision and audit surface.

`describe` should support filtering:

```text
erebor session describe session-8421 --event evt-123
erebor session describe session-8421 --denied
erebor session describe session-8421 --surface browser_cdp
erebor session describe session-8421 --rule deny-oauth-callback-network-request
```

## Session Registry

The first implementation can work directly from explicit file paths. That keeps
the feature small and immediately useful.

The product should then add a local registry:

```text
.erebor/sessions/
  session-8421/
    session.json
    audit.jsonl
    policy.json
    config.json
    transcript.jsonl
    evidence-trace.md
    artifacts/
```

`session.json`:

```json
{
  "schema_version": 1,
  "session_id": "session-8421",
  "actor": {
    "id": "openclaw",
    "kind": "agent"
  },
  "runner": "linux-host",
  "workspace": "/repo",
  "status": "complete",
  "started_at": "2026-06-21T18:03:01Z",
  "ended_at": "2026-06-21T18:05:44Z",
  "audit_path": "audit.jsonl",
  "policy_path": "policy.json",
  "config_path": "config.json",
  "transcript_path": "transcript.jsonl",
  "evidence_trace_path": "evidence-trace.md",
  "policy_sha256": "...",
  "config_sha256": "...",
  "capabilities": {
    "browser_cdp": "enforced",
    "process_exec": "enforced",
    "network_egress": "deferred"
  },
  "residual_risks": [
    "preexisting_fds",
    "preexisting_sockets",
    "network_not_enforced"
  ]
}
```

Registry rules:

- `session run` writes a registry entry when the session starts.
- `session run` updates status and end time when the session exits.
- Surfaces append audit records to the session's audit path.
- Evidence trace generation can write back the report path and hash.
- `session ls/show/describe` read from the registry.

## Proof Envelope

### Current Shape

Current audit record:

```json
{
  "event": {},
  "policy_decision": {},
  "final_decision": {}
}
```

This is enough to answer:

- what event was evaluated
- what policy said
- what final decision was applied

It is not enough to consistently answer:

- through which controlled path was the event enforced
- whether the upstream target was reached
- whether the raw endpoint was hidden from the agent
- which policy/config artifacts were in force
- what exact final effect happened on the substrate

### Target Shape

Add optional fields with serde defaults:

```json
{
  "event": {},
  "policy_decision": {},
  "final_decision": {},
  "control_path": {
    "mode": "enforced",
    "backend": "browser_cdp_proxy",
    "governed_endpoint_id": "cdp-127.0.0.1-3740",
    "private_upstream_exposed_to_agent": false,
    "runner": "linux-host",
    "session_membership": {
      "kind": "cgroup",
      "id": "/sys/fs/cgroup/erebor/session-8421"
    }
  },
  "evidence": {
    "raw_payload_sha256": "...",
    "policy_sha256": "...",
    "config_sha256": "...",
    "matched_rule_id": "deny-oauth-callback-network-request",
    "final_effect": "fetch_fail_request",
    "upstream_reached": false
  }
}
```

### Control Path Fields

`mode`:

- `enforced`: substrate boundary actively enforces future effects
- `adopted`: future effects are governed, but pre-existing authority is residual
  risk
- `cooperative`: SDK/config/proxy integration guides behavior but cannot prevent
  bypass
- `observed`: audit only

`backend` examples:

- `browser_cdp_proxy`
- `browser_cdp_observer`
- `linux_ptrace_process_guard`
- `docker_network_namespace`
- `llm_openai_compatible_proxy`
- `mcp_gateway`

`governed_endpoint_id` examples:

- `cdp-127.0.0.1-3740`
- `llm-127.0.0.1-4317`
- `mcp-unix-/tmp/erebor-session-8421.sock`

`private_upstream_exposed_to_agent`:

- `false` is the desired hard-boundary claim.
- `true` should be treated as a warning or residual risk.

### Evidence Fields

`raw_payload_sha256`:

- Hash of raw CDP command, process argv, network request summary, LLM request,
  or MCP/tool payload.
- Lets Erebor prove what was evaluated without storing sensitive content.

`policy_sha256` and `config_sha256`:

- Hash the exact artifacts used by the session.
- Allows reproducibility and tamper-evident evidence traces.

`matched_rule_id`:

- Duplicates the rule id in the decision for easier indexing.
- Should match `final_decision.rule_id` when present.

`final_effect` examples:

- `forwarded_to_upstream`
- `blocked_before_upstream`
- `fetch_fail_request`
- `exec_denied_before_child_started`
- `approval_held_no_effect`
- `mediated_to_governed_endpoint`
- `llm_request_forwarded`
- `llm_request_denied`

`upstream_reached`:

- `true`, `false`, or absent when not applicable.
- Especially important for browser network, LLM provider, SaaS/API, and MCP
  gateway events.

## Transcript Correlation

Erebor should pair the agent narrative with the enforcement timeline.

Reviewer view:

```text
Timeline

18:03:01 prompt      user asked OpenClaw to debug OAuth callback
18:03:04 command     allow   openclaw run ...
18:03:07 browser     allow   navigate github.com/login/oauth/authorize
18:03:11 browser     allow   click Authorize
18:03:12 network     deny    callback to 127.0.0.1 blocked
18:03:13 command     allow   grep oauth logs
```

The transcript explains why the agent acted. The audit record proves what Erebor
allowed or denied.

Initial correlation can use:

- timestamp proximity
- surface/action/target
- CDP command id
- process pid and argv
- command block text

Target correlation should use explicit ids:

```json
{
  "correlation_id": "tool-call-abc",
  "transcript_ref": "transcript.jsonl:42",
  "audit_record_id": "evt-123"
}
```

Correlation ids should be carried by:

- browser/CDP commands where the client can provide metadata
- process guard events where the parent tool call is known
- MCP/tool gateway calls
- LLM proxy requests
- session runner lifecycle records

## LLM Provider Governance

### Product Goal

Govern LLM provider calls as a session surface.

The first version should be an OpenAI-compatible local proxy:

```text
Codex / OpenClaw / custom agent
        |
        | OpenAI-compatible request
        v
Erebor LLM proxy on 127.0.0.1:<port>
        |
        | policy-approved upstream request
        v
OpenAI / Anthropic / custom provider
```

The important distinction:

- `openai_base_url` configuration is the adoption path.
- Network egress control is what turns it into a hard boundary.

### Why `openai_base_url`

Many agent tools already know how to call OpenAI-compatible endpoints. Codex can
be configured with an `openai_base_url`-style setting. Erebor should use that
instead of creating a custom SDK path.

Example session-injected Codex config:

```toml
openai_base_url = "http://127.0.0.1:4317/v1"
```

The agent still thinks it is calling an OpenAI-compatible provider. Erebor gets
an enforcement point.

### Runtime Config

Example:

```json
{
  "surfaces": {
    "llm": {
      "enabled": true,
      "listen": "127.0.0.1:4317",
      "compatibility": "openai",
      "providers": {
        "openai": {
          "upstream": "https://api.openai.com/v1",
          "env_key": "OPENAI_API_KEY"
        },
        "anthropic": {
          "upstream": "https://api.anthropic.com/v1",
          "env_key": "ANTHROPIC_API_KEY"
        }
      },
      "audit": {
        "store_prompts": false,
        "store_responses": false,
        "store_hashes": true,
        "store_token_usage": true
      }
    }
  }
}
```

The first implementation should support OpenAI-compatible request/response
shapes. Anthropic can be added either through an OpenAI-compatible adapter or a
native Anthropic-compatible proxy later.

### LLM Runtime Event

Add an LLM/API-oriented action shape. The exact enum naming can be decided
during implementation, but the audit event should represent:

```json
{
  "surface": "network",
  "action": "llm_completion",
  "target": {
    "label": "openai:gpt-5.4",
    "uri": "https://api.openai.com/v1/chat/completions"
  },
  "payload": {
    "provider": "openai",
    "model": "gpt-5.4",
    "endpoint": "/v1/chat/completions",
    "request_hash": "...",
    "response_hash": "...",
    "prompt_stored": false,
    "response_stored": false,
    "tokens_in": 4120,
    "tokens_out": 820
  },
  "risk": {
    "level": "medium",
    "reasons": [
      "external_llm_provider",
      "possible_data_egress"
    ]
  }
}
```

For the first implementation, prefer the existing network surface with a new
LLM-specific action:

```text
ExecutionSurface::Network
ActionKind::LlmCompletion
```

If the event taxonomy review decides not to add an LLM-specific action yet, use
the closest existing surface/action pair:

```text
ExecutionSurface::InternalSystem
ActionKind::ToolInvoke
```

Avoid adding a one-off enum without checking the semantic classification plan.

### LLM Policy Examples

Allow approved models:

```json
{
  "id": "allow-approved-llm-models",
  "match": {
    "surface": "network",
    "action": "llm_completion",
    "target_contains": "openai:gpt-5.4"
  },
  "decision": "allow",
  "reason": "approved provider and model"
}
```

Require approval for sensitive model egress:

```json
{
  "id": "review-sensitive-llm-egress",
  "match": {
    "surface": "network",
    "action": "llm_completion",
    "risk_at_least": "high"
  },
  "decision": "require_approval",
  "reason": "high-risk LLM egress requires review"
}
```

Deny unapproved provider:

```json
{
  "id": "deny-unapproved-llm-provider",
  "match": {
    "surface": "network",
    "action": "llm_completion",
    "target_contains": "unknown-provider"
  },
  "decision": "deny",
  "reason": "LLM calls must use approved providers"
}
```

### Privacy Modes

Default:

- do not store prompt body
- do not store response body
- store request hash
- store response hash
- store model/provider/endpoint
- store token usage when available
- store policy decision and final effect

Optional debug mode:

- store redacted prompt excerpt
- store redacted response excerpt
- never store secrets without explicit opt-in

The session review should clearly display privacy posture:

```text
LLM audit privacy: hashes and token usage only; prompt and response bodies not stored.
```

### Direct Provider Egress Blocking

The LLM proxy is only a hard governance boundary if direct provider egress is
blocked.

Docker runner target:

```text
agent container -> Erebor LLM proxy: allowed
agent container -> api.openai.com: denied
Erebor proxy -> api.openai.com: allowed
```

Linux host target:

- use cgroup membership to attribute governed processes
- use cgroup/eBPF socket hooks or network namespace routing where available
- deny direct connects to provider hosts from governed process tree
- allow only the Erebor proxy process to reach upstream provider hosts

Bypass audit example:

```json
{
  "surface": "network",
  "action": "network_request",
  "target": {
    "label": "api.openai.com:443",
    "uri": "tcp://api.openai.com:443"
  },
  "payload": {
    "kind": "direct_llm_provider_egress",
    "process": "codex",
    "session": "session-8421"
  },
  "policy_decision": {
    "type": "deny",
    "reason": "LLM provider egress must use Erebor LLM proxy",
    "rule_id": "deny-direct-llm-provider-egress"
  },
  "final_decision": {
    "type": "deny",
    "reason": "connect denied by network guard",
    "rule_id": "deny-direct-llm-provider-egress"
  }
}
```

## Implementation Phases

### Phase 1: Read-Only Session Summaries

Add read-only session commands backed by the session registry:

```text
erebor session ls
erebor session show <session-id>
erebor session describe <session-id>
```

Implementation:

- Add `Ls`, `Show`, and `Describe` variants to `SessionCommand`.
- Add argument structs for session ids and optional output format.
- Add `erebor-runtime-audit` summary types:
  - `SessionSummary`
  - `SessionDecisionSummary`
  - `SessionReview`
  - `SessionTimelineItem`
- Add rendering helpers:
  - table renderer for `ls`
  - concise text renderer for `show`
  - detailed text renderer for `describe`
- Reuse `read_audit_records`.
- Reuse existing hash helpers or introduce local SHA-256 helpers in audit crate.

Acceptance criteria:

- `session ls` prints one row per registered session.
- Decision counts match fixture records.
- Risk level is the maximum event risk in the session.
- `session show` includes the most important denied/mediated events.
- `session describe` includes rule id, policy/final decision, target, surface,
  action, and proof artifact hashes resolved from session metadata.

Current status:

- State: `Done`.
- Implemented `erebor session ls/show/describe` against
  `.erebor/sessions/<session-id>/session.json` plus `--format text|json`.
- Kept CLI as wiring only: session-review file loading, runtime config parsing,
  policy/config hashing, JSON/text rendering, summaries, timeline, and proof
  details live in `erebor-runtime-audit`.
- Added read-only review objects in `erebor-runtime-audit`: `SessionSummary`,
  `SessionDecisionSummary`, `SessionReview`, and `SessionTimelineItem`.
- Added proof output for controlled path/backend, final effect, upstream
  reached where known, raw payload sha256, policy sha256, and config sha256.
- Added e2e coverage in `erebor-runtime-e2e` that drives the real
  `erebor-runtime` binary, runs a governed `session diagnose` on a normal
  Linux-host process, then verifies `session ls/show/describe` text and JSON.
- Corrected follow-up: removed public `--audit --policy --config` review mode
  after the registry became first-class. The CLI now takes session ids and the
  audit crate resolves the registry-owned artifacts.

Verification:

- `cargo test -p erebor-runtime-audit session_review -- --nocapture`
- `cargo test -p erebor-runtime-cli session_ -- --nocapture`
- `cargo test -p erebor-runtime-e2e --test session_review -- --nocapture`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-targets --all-features`

### Phase 2: Session Registry

Persist session metadata under `.erebor/sessions/<session-id>/`.

Implementation:

- Add `SessionRegistry` to a suitable crate, likely `erebor-runtime-core` or
  `erebor-runtime-session`.
- Use fixed `.erebor/sessions` under the session workspace or command working
  directory. Do not expose per-session registry/audit path configuration.
- When `session run` starts, create the session directory and `session.json`.
- Copy or symlink policy/config artifacts into the session directory.
- Point audit output to the registry-owned session audit path. Runtime config
  controls filtering, not audit storage.
- On session exit, update status, end time, and final run outcome.

Acceptance criteria:

- `erebor session run ...` creates `.erebor/sessions/<session-id>/session.json`.
- `erebor session ls` works after a session run.
- `erebor session show <session-id>` resolves audit/policy/config from registry.
- CLI commands do not accept audit JSONL or registry path overrides.

Current status:

- State: `Done`.
- Added `SessionRegistry` in `erebor-runtime-core` with default registry path
  `.erebor/sessions` under the session workspace or command working directory,
  per-session `session.json`, copied config artifacts, copied policy artifacts,
  registry listing/loading, and status/end/outcome updates.
- Added session registry activation in `erebor-runtime-session` for
  `session run` and `session diagnose`. The session-local
  `.erebor/sessions/<session-id>/audit.jsonl` is the only runtime audit path
  for governed sessions; it is derived from registry metadata, not config.
- Added registry-aware review source handling in `erebor-runtime-audit`.
  `session ls`, `session show <id>`, and `session describe <id>` can now read
  from the registry. Low-level renderer tests can still render explicit paths,
  but the public CLI no longer exposes explicit audit/policy/config inputs.
- Removed config-level audit JSONL storage. `audit.surfaces` remains for
  per-surface audit filtering.
- Removed config-level registry path selection. Session storage is always
  derived as `.erebor/sessions/<session-id>/`.
- Kept `erebor-runtime-cli` as wiring only: it parses commands, calls the
  audit/session crates, and prints the result.
- Added e2e coverage in `erebor-runtime-e2e` that runs a normal Linux-host
  process under governance, verifies `.erebor/sessions/<session-id>/session.json`
  and copied artifacts, then verifies `session ls/show/describe` without
  artifact or registry path flags.
- Consulted the local Warp source where available. The open-source client code
  reinforces the compact session navigation/metadata lesson, but the proprietary
  server-side Oz agent harness is not present in the local source tree.

Verification:

- `cargo test -p erebor-runtime-core session_registry -- --nocapture`
- `cargo test -p erebor-runtime-audit session_review -- --nocapture`
- `cargo test -p erebor-runtime-cli session_ -- --nocapture`
- `cargo test -p erebor-runtime-e2e --test session_review -- --nocapture`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-targets --all-features`

### Phase 3: Proof Envelope

Extend audit records with optional proof metadata.

Implementation:

- Add `ControlPathMetadata` and `EvidenceMetadata` structs.
- Add optional fields to `AuditRecord` with serde defaults.
- Update CDP enforcement to fill:
  - backend
  - governed endpoint id when available
  - upstream exposure flag
  - raw payload hash
  - final effect
  - upstream reached status
- Update session interception/process-exec audit to fill:
  - backend
  - low-level process guard backend where the Linux ptrace implementation is
    active
  - session membership when available
  - final effect
  - exit code for denied commands
- Ensure old audit fixtures still deserialize.

Acceptance criteria:

- Old JSONL audit logs still parse.
- New CDP denied events include `final_effect`.
- New process denied events include process guard backend and denied-before-exec
  effect.
- `session describe` prefers proof fields over inference when present.

### Phase 4: Transcript Correlation

Add transcript and timeline support.

Implementation:

- Define transcript artifact metadata in `session.json`.
- Add optional `correlation_id` to audit proof or event payload.
- Add a transcript reader abstraction that can start with simple JSONL entries.
- Add `session show --timeline` and `session describe --timeline`.
- Initially support timestamp-based correlation when explicit ids are missing.

Acceptance criteria:

- A fixture with transcript plus audit records renders a single chronological
  timeline.
- Denied events link to nearby transcript/tool/command entries.
- Missing transcript does not degrade session review.

### Phase 5: LLM Proxy MVP

Add an OpenAI-compatible local LLM proxy as a governed session surface.

Implementation:

- Add an LLM surface config section.
- Start local HTTP listener for OpenAI-compatible endpoints.
- Normalize requests into runtime events before upstream call.
- Evaluate policy before forwarding.
- Forward approved requests to configured upstream provider.
- Stream responses back to the client.
- Capture model/provider/endpoint/token usage where available.
- Store prompt/response hashes by default.
- Do not store prompt/response bodies unless explicitly configured.

Acceptance criteria:

- Codex configured with `openai_base_url` can call the Erebor proxy.
- The proxy emits an audit record for each LLM call.
- Policy can allow or deny by provider/model/endpoint.
- Prompt and response bodies are not stored in default privacy mode.

### Phase 6: Direct Provider Egress Blocking

Make LLM governance enforceable by blocking bypasses.

Implementation:

- Docker: run agent with network posture that can reach Erebor proxy but not
  provider hosts directly.
- Linux host: integrate with the planned cgroup/eBPF or namespace network
  backend when available.
- Add policy rules and audit records for direct provider egress attempts.
- Add capability reporting so sessions clearly say whether direct-provider
  blocking is enforced, deferred, or unavailable.

Acceptance criteria:

- In enforced Docker mode, direct `curl https://api.openai.com/v1/models` from
  the agent session fails.
- The same request through Erebor LLM proxy succeeds when policy allows it.
- `session show` reports LLM governance as enforced only when direct egress is
  blocked.
- `session describe` shows direct-egress bypass attempts in the same session
  timeline.

## Display Rules

`session show` should use buyer-readable language:

- "denied before callback reached local service"
- "mediated unmanaged Chrome launch into governed CDP endpoint"
- "held for approval; no upstream effect occurred"
- "allowed low-risk diagnostic command"

Avoid requiring the user to understand raw CDP method names unless they ask for
`describe`.

`session describe` should include raw-ish details:

- CDP method/event
- process argv
- target URL
- rule id
- policy/final decision
- backend
- final effect
- proof hashes

## Output Formats

Initial text output is enough.

Add structured output early because this will feed a UI:

```text
erebor session ls --json
erebor session show session-8421 --json
erebor session describe session-8421 --json
```

JSON output should use stable field names and avoid terminal-only formatting.

## Testing

Unit tests:

- group records by session id
- compute decision counts
- compute max risk
- choose key events
- render `ls` table
- render `show` text
- render `describe` text
- deserialize old audit records without proof fields
- deserialize new audit records with proof fields

Fixture tests:

- use existing governed OpenClaw pilot audit fixtures
- add a multi-session JSONL fixture
- add a proof-envelope JSONL fixture
- add an LLM proxy audit fixture

CLI tests:

- `accepts_session_ls_with_audit`
- `accepts_session_show_with_audit_policy_config`
- `accepts_session_describe_with_audit_policy_config`
- `session_ls_rejects_missing_audit_or_registry`
- `session_show_rejects_unknown_session`

End-to-end tests:

- governed CDP denial appears in `session show`
- process denial appears in `session describe`
- LLM proxy emits an audit record
- direct provider egress is reported as deferred until network enforcement lands

## Documentation Updates

When Phase 1 lands:

- update governed OpenClaw pilot README with `erebor session show`
- update evidence trace docs to explain relationship:
  - `session show`: quick review
  - `session describe`: detailed proof
  - `audit evidence-trace`: portable report artifact
  - `audit tail`: raw log/debugging

When LLM proxy lands:

- document Codex `openai_base_url` setup
- document privacy modes
- document enforcement tiers for LLM calls
- document direct-provider bypass limitations per runner

## Open Decisions

- Should the registry live under `.erebor/sessions` in the workspace or under a
  user-level Erebor state directory?
- Should `session describe` default to all key events or require `--event` for a
  single deep proof block?
- Should LLM calls use `ExecutionSurface::Network` with a new action, or a new
  `ExecutionSurface::Llm`?
- Should policy/config hashes be stored on every audit record or once in a
  session-start record plus referenced by session id?
- How much transcript ingestion should ship before a UI exists?

## Recommended First Slice

Ship this first:

```text
erebor session ls
erebor session show <session-id>
erebor session describe <session-id>
```

Use registry-owned session records and infer proof where necessary.

That creates immediate product value:

- buyer-readable session review
- no new enforcement risk
- clear demo flow
- foundation for registry, proof envelope, transcript correlation, and LLM
  proxy governance
