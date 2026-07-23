# Latch Core and Erebor: coding-agent control plane, enforcement, and evidence

Date: 2026-07-13
Status: research note; static source review, not a security audit, compatibility
test, or legal opinion

## Executive assessment

Latch Core is a compelling **desktop control plane for coding agents**. It
combines an Electron terminal UI, harness launching, Git worktrees, policy
configuration, approval UI, session replay, checkpoints, proxying, secrets,
and cryptographic-looking session receipts into a product a developer can use
immediately. That product coherence—and its support for several harnesses—is
materially ahead of Erebor's current end-user experience.

The security model is much weaker and more uneven than its broad product
language suggests. Latch mostly generates harness configuration and local hook
or plugin code, runs a localhost authorizer, and supervises terminal prompts.
Those are useful policy integration points, but they are not a durable,
agent-resistant execution boundary. The exact posture varies by harness:

- **Claude Code:** a local `PreToolUse` hook can hard-deny reported calls, but
  it fails open if the localhost service cannot be reached. Non-denied actions
  are mediated by screen-scraping Claude's terminal approval prompt and typing
  `yes`/`no` into the PTY. The default `auto-accept` setting makes generic
  destructive confirmations auto-approved.
- **OpenClaw:** its generated `before_tool_call` plugin is the strongest
  integration in the reviewed source; it blocks when the authorizer errors or
  times out. It remains a plugin in an agent-writable project configuration,
  not a kernel boundary.
- **Codex:** the generated configuration uses Codex's own sandbox/approval
  settings and static prefix rules, but the local authorizer only receives a
  turn-complete `notify` event. It is **not** consulted before each Codex tool
  call. Latch then launches Codex with `--full-auto`.
- **OpenCode:** native permission configuration is generated, but the reviewed
  runtime plugin's error handler swallows ordinary Latch denials unless their
  message begins with a marker that the Latch authorizer does not supply. The
  plugin path therefore appears fail-open for ordinary policy denials.

Latch also contains promising but incomplete sandbox, proxy, checkpoint, and
attestation work. The actual gateway launch path does not use its richer
Seatbelt/Bubblewrap profile generators; if no sandbox is found it still starts
successfully; and its receipt can state `networkForced: true` and default a
missing backend to `seatbelt`. Those facts make the current receipt unsuitable
as proof that a session was sandboxed or that all network traffic was forced
through the proxy.

Erebor should regard Latch as a serious adjacent product and an excellent UX
reference, not as a substitute for an enforcement runtime. Latch's best ideas
are worktree-first sessions, harness adapters, a visible approval/replay flow,
service-aware credential brokering, and compact session handoff artifacts.
Erebor's defensible difference is a controlled execution and effect path:
isolated filesystem changes, governed promotion/rollback, surface-native
evidence, and—once implemented—the immutable context graph that can answer
why an action was legitimate. That difference must remain honest about
Erebor's own current process-guard and platform gaps.

## Review scope and confidence

The Latch review is pinned to the local checkout of
[`latchagent/latch-core`](https://github.com/latchagent/latch-core), commit
[`9fd0ccc17c7332bcff506e24a09327267f1e653d`](https://github.com/latchagent/latch-core/tree/9fd0ccc17c7332bcff506e24a09327267f1e653d)
(`2026-03-05`, package version `0.1.2`). The checkout was clean at review time.
The relevant source owners reviewed were:

- [`README.md`](https://github.com/latchagent/latch-core/blob/9fd0ccc17c7332bcff506e24a09327267f1e653d/README.md),
  [`AGENTS.md`](https://github.com/latchagent/latch-core/blob/9fd0ccc17c7332bcff506e24a09327267f1e653d/AGENTS.md),
  and [`package.json`](https://github.com/latchagent/latch-core/blob/9fd0ccc17c7332bcff506e24a09327267f1e653d/package.json);
- the local [authorization server](https://github.com/latchagent/latch-core/blob/9fd0ccc17c7332bcff506e24a09327267f1e653d/src/main/services/authz-server.ts),
  [policy enforcer](https://github.com/latchagent/latch-core/blob/9fd0ccc17c7332bcff506e24a09327267f1e653d/src/main/services/policy-enforcer.ts),
  [PTY manager](https://github.com/latchagent/latch-core/blob/9fd0ccc17c7332bcff506e24a09327267f1e653d/src/main/lib/pty-manager.ts),
  and [terminal supervisor](https://github.com/latchagent/latch-core/blob/9fd0ccc17c7332bcff506e24a09327267f1e653d/src/main/services/supervisor.ts);
- [gateway orchestration](https://github.com/latchagent/latch-core/blob/9fd0ccc17c7332bcff506e24a09327267f1e653d/src/main/index.ts),
  [sandbox manager](https://github.com/latchagent/latch-core/blob/9fd0ccc17c7332bcff506e24a09327267f1e653d/src/main/lib/sandbox/sandbox-manager.ts),
  [Bubblewrap backend](https://github.com/latchagent/latch-core/blob/9fd0ccc17c7332bcff506e24a09327267f1e653d/src/main/lib/sandbox/bubblewrap-gateway.ts),
  [Seatbelt backend](https://github.com/latchagent/latch-core/blob/9fd0ccc17c7332bcff506e24a09327267f1e653d/src/main/lib/sandbox/seatbelt-gateway.ts),
  and [per-session proxy](https://github.com/latchagent/latch-core/blob/9fd0ccc17c7332bcff506e24a09327267f1e653d/src/main/services/latch-proxy.ts);
- [Git checkpoint engine](https://github.com/latchagent/latch-core/blob/9fd0ccc17c7332bcff506e24a09327267f1e653d/src/main/services/checkpoint-engine.ts),
  [rewind handler](https://github.com/latchagent/latch-core/blob/9fd0ccc17c7332bcff506e24a09327267f1e653d/src/main/index.ts),
  [attestation engine](https://github.com/latchagent/latch-core/blob/9fd0ccc17c7332bcff506e24a09327267f1e653d/src/main/services/attestation.ts),
  [attestation store](https://github.com/latchagent/latch-core/blob/9fd0ccc17c7332bcff506e24a09327267f1e653d/src/main/stores/attestation-store.ts),
  and [replay/live tailer](https://github.com/latchagent/latch-core/blob/9fd0ccc17c7332bcff506e24a09327267f1e653d/src/main/services/live-tailer.ts).

The Erebor side is grounded in the implemented [Linux
filesystem-surface phase](../plans/revert/filesystem-surface/linux-ostree-overlay-v3-implementation/README.md),
[filesystem implementation](../../crates/erebor-runtime-filesystem/src/), and
[Linux process guard](../../crates/erebor-runtime-session/src/os/linux/process_guard/).

This review did not launch the Electron app, execute the generated harness
configurations, attempt bypasses, audit all dependencies, or validate the
current behavior of the harness versions Latch targets. Where source and
comments disagree, this note treats the executable source path as the stronger
evidence. A claim that a path is ineffective means it is not demonstrated by
the reviewed wiring; it is not a claim that no future version can fix it.

## What Latch actually provides

### A product-shaped desktop workflow

Latch's core value is usability, not just policy. It starts real PTYs for
agent CLIs, gives each session a Git worktree, presents policy and approval
controls in a desktop UI, tails conversation data, tracks usage/budgets, and
offers checkpoints, replay, issues, MCP configuration, skills, service
credentials, and an activity feed. This is a coherent control center for a
developer who runs several coding agents locally.

The worktree model is useful operational isolation:

```text
repo -> one Latch session -> one Git worktree/branch -> one or more PTYs
```

It reduces accidental collisions among concurrent agents and gives a natural
review/merge boundary. It is not a sandbox: a process in the worktree still
runs as the user and may access other host paths, credentials, network routes,
Git refs, or external systems unless another mechanism constrains it.

### A local policy decision service

Latch starts an HTTP authorization server on an operating-system-selected port
bound to `127.0.0.1`. It keeps a random 128-bit shared bearer secret in memory,
maps tool names into coarse action classes (`read`, `write`, `execute`,
`send`), resolves policy rules, applies blocked file globs and command regexes,
records an activity event, and can request user approval.

The base evaluator has useful practical controls:

- allow/deny toggles for shell, file writes, and network-like tools;
- per-tool and per-MCP-server allow/deny/prompt patterns;
- a set of default command rules for obviously dangerous patterns such as
  recursive root deletion, formatting disks, `curl | shell`, power actions,
  `sudo`, force-push, and `git reset --hard`;
- strictest-wins merging for selected policies; and
- approval timeouts and per-session request rate limits.

Those are real features, particularly for cooperative harnesses. The
limitations are equally important:

- Latch has no seeded policy. If no policy is selected, the authorizer's
  effective policy allows Bash, file writes, and network access. If no policies
  exist, the UI enforcement call returns an error but session startup can
  continue.
- Tool classification is a fixed name map plus heuristics. Unknown tools
  default to `execute`, which is conservative in class but does not provide
  semantic understanding of their inputs.
- Glob/path and command regex evaluation operates on paths/command strings
  supplied by the harness. It is not a canonical filesystem or shell-execution
  boundary; symlinks, shell indirection, already-open descriptors, aliases,
  child processes, and non-tool execution paths need separate enforcement.
- The service trusts any caller with its bearer secret. Generated hook/plugin
  code contains that secret under project or user configuration paths, and the
  reviewed writes do not explicitly set restrictive file modes. Binding to
  localhost is not proof of process identity; another local process that reads
  the secret can send requests to the authorizer.

### Harness integrations are not equivalent

The README groups Claude, Codex, and OpenClaw under a shared policy story. The
source shows four materially different paths.

#### Claude Code: hook notification plus terminal-driving supervisor

For Claude, Latch writes `.claude/settings.json` and a generated
`latch-authz.sh` `PreToolUse` hook. The hook posts tool input to
`/supervise/:sessionId`:

```text
policy hard deny -> hook exits nonzero -> Claude blocks
otherwise        -> hook asks Claude to show its native prompt
                   -> Latch watches terminal output and types yes/no
```

This is clever product engineering. Latch combines Claude's native prompt with
its own policy evaluation and approval UI. It also generates native deny rules
as defense in depth.

It is not a hard enforcement chain:

- The shell hook contains `curl ... || exit 0`; an unreachable authorizer is
  explicitly fail-open. Claude's remaining native permission configuration may
  still prompt, but a Latch policy hard deny is not reliably enforced during
  that outage.
- The supervisor recognizes visual/text patterns in PTY output and sends key
  sequences to choose an answer. That depends on terminal prompt format,
  ordering, timing, locale, and the absence of a confusing prompt in output.
  It should be treated as automation around a harness prompt, not proof that
  a particular intended operation received a particular approval.
- For generic `confirmDestructive` controls, the stored `auto-accept` setting
  is interpreted as enabled when it is unset. Thus the default is to
  auto-approve generic write/execute prompts; explicit prompt rules still go
  to the user.
- The hook and settings file are written in the target worktree. An agent with
  authority to modify that worktree can potentially modify, remove, or evade
  its own policy integration unless an outer boundary protects those files.

#### OpenClaw: the best current Latch policy path

For OpenClaw, Latch writes an `api.on('before_tool_call', ...)` plugin that
calls `/authorize/:sessionId`. It maps a 200 response to allow, and maps any
error, timeout, or non-200 response to block. This is the strongest current
source path because an authorizer outage fails closed and the decision happens
before a reported tool call.

It remains cooperative harness enforcement. Latch also writes an
`exec-approvals.json` that tells OpenClaw to skip its own approvals because the
Latch plugin is assumed to decide. The plugin itself lives beneath the
project's `.openclaw/plugins/` directory, where a sufficiently empowered
agent can alter it. There is no reviewed self-integrity check, read-only mount,
or kernel restriction that protects the plugin, the policy config, or the
authorizer secret.

#### Codex: static configuration and observation, not runtime authorization

For Codex, Latch generates:

- `.codex/config.toml` with an approval policy, sandbox mode, environment
  inheritance/exclusions, feature flags, and a turn-complete `notify` script;
- `.codex/rules/latch-policy.rules` with selected native `prefix_rule()`
  entries; and
- CLI flags for non-default approval/sandbox settings, followed by
  `--full-auto`.

The generated `notify` script POSTs only after a Codex agent turn completes.
Unlike the OpenClaw path, no generated Codex component calls Latch's
`/authorize` endpoint before an individual tool call. The activity feed records
`_codex:agent-turn-complete`, not an authoritative sequence of executed tool
actions.

This is still potentially useful as an adapter to Codex's native controls. But
it is materially different from the README's "intercepts tool calls" wording:
the local policy engine's command regexes, per-tool decisions, LLM evaluator,
approval queue, and decision audit are not in Codex's per-tool execution path.
The code comments state that generated Codex rules remain respected with
`--full-auto`; that needs an integration test against the exact Codex version
before it can be relied on as a security claim. In the permissive default
mapping, Latch selects Codex `danger-full-access` when Bash and writes are
allowed and no destructive confirmation is configured.

#### OpenCode: native config plus a likely runtime fail-open bug

Latch generates OpenCode native permissions and installs a global plugin that
posts `tool.execute.before` events to `/supervise/:sessionId`. The intended
behavior is to throw on a 403 decision and fail open only for network errors.

The reviewed code does not implement that intent correctly. It constructs
`new Error(reason)` from the authorizer's 403 response, then catches all
errors and rethrows only if the message starts with `"Blocked by Latch"`.
The authorizer's normal reasons are strings such as `"Policy disallows shell
execution."` or `"Tool ... is denied by policy rule."`; they do not carry
that prefix. Therefore those ordinary policy-deny errors are swallowed by the
plugin's catch block. OpenCode's independently generated native permission
configuration may still block some operations, but the Latch runtime hook does
not provide the claimed deny guarantee in this source revision.

The global plugin also reads `{ port, secret }` from
`~/.config/opencode/latch-connection.json`; the reviewed writer does not set
an explicit restrictive mode. This is another local secret/configuration
boundary that needs a real permissions and tampering audit.

### Optional LLM policy evaluation is not a trusted decision oracle

If enabled, Latch can send an unmatched tool name, its arguments, an action
class, and a natural-language policy intent to `gpt-4o-mini` through the
user's OpenAI API key. It uses the LLM's ALLOW/DENY/PROMPT answer as an
enforcement decision and fails closed when that API call errors or times out.

This may be useful as an *advisory escalation* mechanism, but it is risky as a
security policy decision point:

- tool arguments are attacker-influenced and can contain prompt-injection
  content intended to manipulate the evaluator;
- the function called `sanitizeInput` truncates long strings but does not
  redact sensitive key names, values, nested objects, or data patterns before
  sending them to the external model; and
- a model's natural-language explanation is not deterministic evidence of the
  actual operation.

Erebor should not adopt an LLM as the final allow/deny authority for
high-consequence actions. It can propose a classification or explanation, but
the enforced decision must be based on deterministic policy over canonical
facts, with a human approval path for ambiguity.

## Gateway, sandbox, and network controls

### The proxy has a sensible capability design

Latch's per-session proxy is one of its more promising components. It can:

- allowlist service domains, apply data-tier limits, and scope allowed HTTP
  methods/paths;
- inject service credentials only for an authorized service;
- block credential values discovered in outbound request bodies;
- tokenize matching values in selected text/JSON response bodies;
- optionally generate an ephemeral CA and MITM TLS; and
- retain proxy audit records, including allow/deny and inspection metadata.

This is a good direction for governing external API use. In particular,
service identity, method/path scope, credentials, and an audit event are more
meaningful than a simple "network on/off" flag.

### Proxy coverage is conditional, and TLS inspection is disabled by UI flow

The renderer calls gateway startup with `enableTls: false`. In that default
path, HTTPS `CONNECT` traffic receives domain/port gating but is tunneled
without method/path/body inspection, response scanning, or HTTPS header
injection. The proxy has a TLS-interception implementation, but it is not the
normal path reviewed here.

More fundamentally, setting `HTTP_PROXY`/`HTTPS_PROXY` only asks cooperative
programs to use the proxy. A command can ignore those environment variables,
use an existing socket, or choose another transport. The proxy becomes a true
network policy point only if an outer sandbox forces egress through it.

### The actual gateway launch path does not provide that outer guarantee

The source has detailed `SeatbeltGateway` and `BubblewrapGateway` helpers that
could generate profiles, mounts, and packet-filter rules. Gateway startup does
not call those helpers. Instead it does the following:

| Selected backend | Actual launch arguments in `gateway-start` | Consequence |
| --- | --- | --- |
| Docker | No sandbox command is returned or started by gateway startup. | Detecting Docker is not the same as running the agent in a container. |
| Seatbelt | `/usr/bin/sandbox-exec -n no-network` | Denies networking; it does not use the reviewed workspace/process/loopback profile generator. |
| Bubblewrap | `bwrap --unshare-net --dev /dev --proc /proc` | It does not use the helper that binds a workspace and system paths, nor its iptables/proxy forcing rules. A usable shell and workspace mount need live verification. |
| No backend | Gateway startup still succeeds with no sandbox command. | The documented "refuse to start" behavior is not enforced here. |

The PTY is then created from that returned command/arguments. For Docker,
Latch's renderer explicitly notes that a selected harness runs natively on the
host because the harness is not installed in the container; container-native
harness execution is named as future work. The richer Bubblewrap/Seatbelt
profile builders and their packet-filter rules are currently unused by this
launch path.

This has several direct implications:

- A successful gateway start does not prove an agent is sandboxed.
- Direct network traffic can bypass the proxy whenever a usable outer network
  sandbox is absent or incomplete.
- The reported sandbox type should be treated as a requested/detected backend,
  not an attested enforcement fact.
- A real implementation needs per-session process identity and network
  namespace/packet-filter ownership. Rules keyed only to a host UID can affect
  unrelated user processes and do not identify one sandbox process.

## Checkpoints and rewind are Git recovery, not transactional rollback

Latch automatically calls `git add -A` and `git commit --no-verify` after a
three-second debounce when its Claude JSONL tailer or an OpenCode event reports
a file write. It stores checkpoint metadata in SQLite and exposes both rewind
and fork-from-checkpoint UX.

That is useful developer recovery. It is not equivalent to Erebor's isolated
filesystem-layer lifecycle:

```text
Latch:  observe reported write -> Git add/commit later -> optionally git reset --hard
Erebor: write isolated layer -> inspect/approve -> promote with preimage -> rollback
```

Important Latch limits:

- Checkpoint creation is triggered by harness/replay observations, not a
  filesystem watcher or syscall boundary. It can miss direct shell writes,
  non-covered harnesses, event loss, writes before the debounce, or a crashed
  app.
- The commit runs against the live worktree. The agent's changes already exist
  on disk and Git state has already been mutated before a user reviews them.
- `git add -A` includes untracked files in a checkpoint. Git semantics and
  repository hooks/configuration, rather than a filesystem transaction, define
  what succeeds.
- Rewind is `git reset --hard <checkpoint>`. It does not remove untracked
  files, restore ignored files, repair external effects, restore arbitrary
  metadata, or make a multi-system rollback atomic. There is no host preimage,
  drift check, promotion journal, or recovery transaction.
- A worktree isolates the branch's working copy, not the user account. It does
  not contain credentials, `/tmp`, other repositories, parent-process FDs, or
  network access.

Latch should call this **Git checkpointing and rewind**, which is still a
valuable feature. It should not be called an atomic filesystem snapshot or a
general action rollback mechanism.

## Receipts, audit, and replay

### Good cryptographic building blocks

Latch uses canonical JSON for proxy events, SHA-256 hash chaining, a
domain-separated Merkle root, Ed25519 signatures, and inclusion-proof helpers.
The application persists an Ed25519 key under its user-data directory with a
requested `0600` mode. This is considerably better than a plain mutable CSV
audit log, and it gives the product a useful receipt UX direction.

### Why the current receipt is not a trust proof

The properties above do not establish independent, tamper-resistant provenance:

- The hash chain, Merkle leaves, receipt database, and signing key are all
  local to the same desktop application's trust domain. A local attacker or
  agent with equivalent user authority can modify the database and key then
  create a new self-consistent receipt. The receipt embeds its own public key;
  no external trust anchor, transparency log, hardware-backed key, remote
  witness, or append-only checkpoint is reviewed.
- The hash/Merkle structure covers **proxy audit events**. Tool actions are
  recorded separately in the activity store and appear only as aggregate
  counts in a receipt; the signed proof does not bind an individual tool input,
  policy decision, terminal process, or resulting filesystem effect.
- Gateway shutdown sets `networkForced: true` unconditionally. It also casts a
  missing sandbox status to `seatbelt`. Thus a signed receipt can overstate
  facts that the preceding launch path did not establish.
- The policy hash uses ordinary `JSON.stringify` rather than the project's
  canonical serializer. This is a smaller issue than the trust boundary, but
  another reason not to treat a policy hash as a portable, stable policy
  identity without a precise serialization contract.

The right label is **locally signed session summary with proxy-event integrity
signals**, not independent proof that every action was governed.

### Replay is valuable observation, not causal attribution

Latch can tail Claude JSONL files, parse prompts/thinking/tool calls/results,
and assemble conversation replay; OpenCode plugins can forward event summaries
to SQLite. This is a strong user-facing diagnostic and review feature. The
code also produces useful usage and loop analytics.

It is not yet a trustworthy answer to "why did the effect happen?":

- The source data comes from harness logs/plugins in the same user-controlled
  environment, not a runtime-issued immutable context identity.
- The live tailer summarizes/truncates values and infers tool targets from
  reported input. It does not observe the underlying syscall, browser command,
  API side effect, or file layer.
- There is no reviewed immutable DAG linking a user request, delegated
  subagent, policy version, approval, canonical action, and observed result.
- UI activity can be spoofed: the authorizer deliberately permits unauthenticated
  localhost writes to its feed endpoint.

Latch's replay UI is precisely the sort of operator experience Erebor should
learn from. Erebor's context model should provide the verifiable link beneath
such a UI, rather than treating a rendered timeline as provenance.

## Direct comparison with Erebor

| Dimension | Latch Core | Erebor | Honest conclusion |
| --- | --- | --- | --- |
| Primary shape | Electron desktop control plane for coding harnesses. | Universal action-governance runtime; browser CDP, terminal, and filesystem are current proof surfaces. | Latch is farther ahead in desktop workflow; Erebor is centered on an enforcement/evidence substrate. |
| Harness breadth and UX | Claude, Codex, OpenClaw, OpenCode/Droid paths, terminals, sessions, worktrees, replay, policies, and approvals. | Current integrations are less end-user polished. | Latch clearly leads in immediate developer experience. |
| Policy enforcement | Harness-native configs, hooks/plugins, prompt automation, and local HTTP authorizer. Semantics vary sharply by harness. | Erebor-controlled execution path and runtime action records, but current Linux interception is incomplete and surface coverage is limited. | Latch has broader integration; Erebor has the better place to build non-cooperative enforcement. Neither is a full-host boundary today. |
| Codex control | Static `.codex` config/rules plus post-turn notify; no reviewed per-tool call to Latch authorizer; runs `--full-auto`. | Erebor has active Codex/browser/terminal direction but context attribution remains planned. | Do not count Latch's Codex integration as equivalent to its OpenClaw authorizer path. |
| Filesystem isolation | Git worktrees; optional/unfinished sandbox work; agent writes land in the live worktree. | Linux OverlayFS upper layer keeps covered-volume changes off the host until promotion. | Erebor clearly leads for tentative filesystem effects in supported Linux scope. |
| Reversal | Debounced Git commits and `git reset --hard`; untracked/external effects remain. | Checkpointed overlay layers and preimage-first promotion/rollback. | Latch offers useful code recovery; Erebor has the stronger reversible-state model. |
| Network/API governance | Promising service allowlist proxy, method/path controls, credentials, optional TLS interception; outer egress forcing is not wired in reviewed gateway path. | Network is not currently a startable/enforced session surface. | Latch leads in feature intent and proxy implementation; neither has a demonstrated end-to-end default containment guarantee here. |
| Secrets | Local encrypted store/1Password integration and service injection. | No matching mature credential-broker product currently implemented. | Latch provides useful integration ideas; credential exposure and authority need an Erebor-owned boundary. |
| Evidence integrity | Locally signed receipts, proxy hash chain, Merkle proofs; source does not establish an external trust anchor and may overstate sandbox/network facts. | Decision-bearing evidence but no mature cryptographic receipt/commit packaging yet. | Latch is ahead in receipt UX and primitives; Erebor should avoid inheriting its local-self-attestation overclaim. |
| Prompt-to-action "why" | Parses harness logs and plugin events into replay. | Context DAG is designed to preserve immutable scope/evidence links, but not yet implemented. | Latch has better current replay; Erebor can offer deeper causal provenance after implementation. |
| Platform path | Electron UI targets macOS/Linux/Windows, with platform-specific sandbox aspirations. | Linux filesystem backend implemented; macOS/Windows filesystem work planned. | Latch is broader as a desktop app; its cross-platform enforcement claims need separate validation. |
| Licensing | Repository declares AGPL-3.0-only. | Erebor has its own licensing posture. | Code reuse or in-process distribution needs legal review; learn patterns, not copy source casually. |

## What Latch does well and what Erebor should learn

1. **Make governance visible and usable.** A session drawer, PTY tabs,
   status feed, policy editor, replay, worktree state, approvals, checkpoints,
   and an evidence/receipt affordance make controls tangible. Erebor needs an
   equally clear operator surface, even if it begins with CLI/TUI/JSON rather
   than an Electron app.

2. **Treat session setup as an orchestration product.** Creating a named
   session, worktree, policy, harness invocation, and review lifecycle in one
   flow is good product design. Erebor can offer a compatible session plan and
   preflight without absorbing Latch's entire desktop app.

3. **Use native harness controls as defense in depth.** Configuring a
   harness's own sandbox/approval/disabled-tool features is worthwhile—so long
   as Erebor labels it as a supplemental control, verifies what was actually
   applied, and retains its own outer enforcement path.

4. **Use service-aware capability brokering.** The proxy's service catalog,
   explicit domain/method/path scope, and selective credential injection are
   much better than giving an agent a generic API key. This pairs naturally
   with an identity provider or attenuated credentials such as Ory Talos.

5. **Provide review and fork, not just deny.** Git checkpoints, replay, and
   fork-from-checkpoint make experimentation less scary. Erebor's isolated
   layers and promotion model can support a stronger version of that user
   experience.

6. **Expose evidence as a compact artifact.** A signed session summary is a
   useful product primitive. Erebor should pursue an exportable evidence
   receipt, but bind it to trusted action/effect records and a key/trust model
   that cannot be rewritten with the same local store.

## What Erebor should not copy

- **Do not make project-writable hooks the enforcement root.** A governed
  process must not be able to remove or rewrite its own authorization hook,
  policy, secret, or audit configuration.
- **Do not turn terminal screen scraping into approval evidence.** It is a
  convenient assistive mechanism, not a stable protocol. Approval should bind
  to a canonical action identifier and expire deterministically.
- **Do not silently continue when an expected enforcement component fails.**
  Choose fail-open, fail-closed, or isolated-tentative mode explicitly per
  action class; report the degraded state in the evidence.
- **Do not describe a requested sandbox as an active sandbox.** A capability
  report must be backed by the actual process/mount/network state and must
  report `none` honestly.
- **Do not call Git reset a universal rollback.** It cannot reverse external
  side effects or restore untracked/ignored files and metadata. Use surface-
  specific compensation or transaction models.
- **Do not use an LLM as the final security judge.** It can suggest policy
  intent or identify ambiguity, but it is not a deterministic policy engine
  and tool arguments are hostile input.

## A better division of responsibility

Latch and Erebor could be complementary only if their boundaries are kept
clear:

```text
Latch-like UX / adapter
  session creation, worktree UX, harness selection, replay, approval display
                         |
                         v
Erebor runtime
  canonical action -> policy/approval -> enforced execution path -> effect
  evidence/context -> review, promotion, rollback where supported
                         |
                         v
Identity / credential provider
  user and agent identity, tenant relationship, scoped downstream credential
```

The desktop UX must consume Erebor's actual capability/evidence result, not
invent one from a requested configuration. Similarly, a Latch-originated
approval should be a display/client action against an Erebor-issued pending
action ID; it should not be converted into a blind terminal keypress.

## Suggested validation work before treating Latch as a reference implementation

1. **Run a harness matrix.** For exact supported versions of Claude Code,
   Codex, OpenClaw, and OpenCode, test a known allow, static deny, dynamic
   deny, approval, authorizer outage, timeout, malformed response, and
   worktree-tampering attempt. Record whether the action actually executes.

2. **Exercise gateway claims end to end.** Confirm which process is launched,
   its namespaces/mounts/UID, the reachable paths, direct TCP/UDP/DNS behavior,
   proxy bypass behavior, loopback/proxy reachability, and behavior when no
   backend is installed. Test the exact Bubblewrap and Seatbelt command paths,
   not only helper-unit tests.

3. **Falsify receipts.** Start a gateway session with no sandbox, direct
   network traffic, and no TLS interception; compare observed facts to the
   signed receipt. Modify local audit storage and key material to demonstrate
   the current trust boundary, then define what external witness or hardware/
   remote key would be needed for the intended claim.

4. **Test rewind coverage.** Create tracked, untracked, ignored, symlink,
   metadata, and external changes between checkpoints; then run rewind and
   report the exact residual state.

5. **Audit secret/config ownership.** Inspect mode, location, process access,
   and lifecycle for generated hook scripts, the OpenCode global connection
   file, local bearer secrets, SQLite database, and attestation key. Explicitly
   test whether the governed agent can read or edit each one.

## Bottom line

Latch is strongest where Erebor is currently weakest: it makes coding-agent
control feel like a usable local product. Its worktree/session UI, multi-harness
adapters, policy rollout, replay, checkpoints, service concepts, and receipt
presentation contain many good lessons.

But its source currently demonstrates a **control-plane and UX layer**, not a
reliable general-purpose enforcement runtime. The source is particularly clear
that Codex has no per-tool Latch authorizer, OpenCode's runtime-deny path is
likely swallowed, Claude fails open when its hook cannot reach Latch, and the
gateway/receipt wiring can claim enforcement that the process path did not
prove. These are not small distinctions if the product promise is security,
compliance evidence, or safe autonomous execution.

Erebor should compete on trustworthy, surface-native action/effect control and
contextual evidence, while borrowing Latch's operator experience. Once its
context model is implemented, Erebor can make a more meaningful claim than
"this tool was allowed": it can show the verified request and delegation that
scoped the action, the policy/approval that decided it, the enforced path that
executed it, and the resulting state plus recovery options. Until then, that is
an implementation target—not a current advantage.
