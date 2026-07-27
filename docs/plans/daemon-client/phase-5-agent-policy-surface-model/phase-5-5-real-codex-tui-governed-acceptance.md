# Phase 5.5: Real Codex TUI Governed Acceptance

Status: In progress (started 2026-07-27).

Parent plan: [Phase 5: Agent, Policy, And Surface Resource Model](README.md)

## Purpose

Prove the Phase 5 product outcome: a real local Codex TUI runs through Erebor
as one daemon-created Session of an admitted immutable Agent with the intrinsic
`terminal` and `filesystem` Surface bindings. This is a real-host acceptance
result, not a deterministic fixture or an Agentfile/Docker demonstration.

This is deliberately a terminal/filesystem-only acceptance. Phase 5.4 remains
deferred: the PolicySet selected by this phase has no `mediate` decision and no
rule that names `browser_cdp`. A later run that selects either must first
complete Phase 5.4.

## Scope

- Reuse the verified local-agent enrollment, intrinsic terminal/filesystem
  bindings, and Phase 4 controller PTY from the preceding phases. This is an
  end-to-end proof of the preserved path under the new Session association, not
  a second Codex launcher, filesystem implementation, or TUI controller.
- Use an explicitly selected local Codex candidate with the existing
  `erebor agent load … --from …` flow. The daemon must follow it through the
  descriptor broker, verify the resolved final regular executable's version,
  stage it, and run the staged installation without later `PATH`, home,
  launcher, or symlink rediscovery.
- Select the exact Phase 5.1 PolicySet with the Agent. Admission must bind the
  daemon implementations of the intrinsic terminal and filesystem Surfaces;
  record the resolved Agent, package order, PolicySet name, terminal/filesystem
  bindings, state snapshot, projection, and Session identities in the result
  chain. A named Surface is supplied only if the selected policy requires a
  Surface with independent configuration, such as Browser CDP.
- Run the actual Codex TUI through the daemon-owned Phase 4 controller PTY.
  Preserve initial geometry, controller-only input/resize, read-only
  observation, and detach/reattach of the same session.
- Prove the Phase 5.3 private-state boundary in the live workload: fixed
  private `CODEX_HOME`, managed hook/configuration works, caller state is not
  mutated, source host paths and daemon-control sockets are absent, and secrets
  are absent from logs, output, receipts, and evidence.
- Prove real filesystem policy enforcement, not just policy admission: the
  `codex-runtime-guardrail` package must deny a Codex-attempted write or
  mutation of `.erebor-denied` before any physical effect, while its explicit
  `file_open`, `file_read`, `file_write`, and `file_mutation` rules cover the
  ordinary governed filesystem operations used by the walkthrough.
- Complete the removal audit for foreground surface lifecycle and direct
  filesystem storage callers while proving the daemon reuses
  `FilesystemSessionStorage` for this Session. If Linux-host prerequisites are
  unavailable, report the exact unavailable capability and command/error; do
  not fall back to an ungoverned local Codex launch.
- This walkthrough has no Browser CDP Surface or mediation rule. If a later
  PolicySet includes a terminal `mediate` rule with an explicit
  `replacement_surface: browser_cdp`, Phase 5.4 must first provide the named
  Browser CDP Surface lifecycle and binding it requires.

## Accepted Resource Schemas

Phase 5.5 adds no fields. It accepts only the resource contract from Phases
5.1–5.3 below; a real Codex result is invalid if any document contains an
extra field or a substituted reference. Phase 5.4 is the conditional extension
for a `mediate` Rule with an explicit `replacement_surface: browser_cdp`.

```json
{
  "apiVersion": "erebor.dev/v1",
  "kind": "Agent",
  "metadata": { "name": "local-codex" },
  "spec": { "adapter": "codex-v1" }
}
```

```json
{
  "apiVersion": "erebor.dev/v1",
  "kind": "PolicyPackage",
  "metadata": { "name": "codex-runtime-guardrail" },
  "spec": {
    "rules": [
          {
            "id": "deny-governed-marker-write",
            "match": {
              "surface": "filesystem",
              "action": "file_write",
              "target_contains": ".erebor-denied"
            },
            "decision": "deny",
            "reason": "the governed denied marker must never be written"
          },
          {
            "id": "deny-governed-marker-mutation",
            "match": {
              "surface": "filesystem",
              "action": "file_mutation",
              "target_contains": ".erebor-denied"
            },
            "decision": "deny",
            "reason": "the governed denied marker must never be created, renamed, or removed"
          },
          {
            "id": "allow-filesystem-open",
            "match": {
              "surface": "filesystem",
              "action": "file_open"
            },
            "decision": "allow"
          },
          {
            "id": "allow-filesystem-read",
            "match": {
              "surface": "filesystem",
              "action": "file_read"
            },
            "decision": "allow"
          },
          {
            "id": "allow-filesystem-write",
            "match": {
              "surface": "filesystem",
              "action": "file_write"
            },
            "decision": "allow"
          },
          {
            "id": "allow-filesystem-mutation",
            "match": {
              "surface": "filesystem",
              "action": "file_mutation"
            },
            "decision": "allow"
          },
          {
            "id": "allow-codex-terminal-processes",
            "match": {
              "surface": "terminal",
              "action": "process_exec"
            },
            "decision": "allow"
          }
    ]
  }
}
```

```json
{
  "apiVersion": "erebor.dev/v1",
  "kind": "PolicySet",
  "metadata": { "name": "codex-runtime-guardrail-set" },
  "spec": { "packages": ["codex-runtime-guardrail"] }
}
```

```json
{
  "apiVersion": "erebor.dev/v1",
  "kind": "Session",
  "metadata": { "name": "codex-review-1" },
  "spec": {
    "agent": "local-codex",
    "policySet": "codex-runtime-guardrail-set"
  },
  "status": {
    "stateProjection": {
      "target": "/run/erebor/state/codex",
      "lowerSnapshot": "codex-review-1-state",
      "writableUpper": "upper-codex-review-1",
      "refresh": "explicit",
      "retention": "discard-on-session-removal"
    }
  }
}
```

| Field | Use and validation | Owner |
| --- | --- | --- |
| Every `apiVersion` | Must be `erebor.dev/v1`, selecting the only Phase 5 resource schema. | API contract |
| Every `kind` | Selects the matching resource validator; it must match its document (`Agent`, `PolicyPackage`, `PolicySet`, or `Session`). | API contract |
| Every `metadata.name` | Immutable owner-scoped handle. The user supplies Agent, PolicyPackage, and PolicySet names; the daemon assigns the Session name. | Resource owner / daemon for Session |
| `Agent.spec.adapter` | Explicit compiled integration contract for the staged Codex executable. It is not inferred and cannot contain state, policy, path, or credential configuration. | Agent owner / adapter registry |
| `PolicyPackage.spec.rules` | Ordered canonical Rules. The package governs a surface through each Rule's `match.surface`, not through a duplicate surface field. | PolicyPackage owner |
| `…rules[].id` | Unique evidence identifier for the rule. | PolicyPackage owner |
| `…rules[].match` | Non-empty existing event matcher. Every Phase 5 Rule must include `surface`. | PolicyPackage owner |
| `…rules[].match.surface` | Existing execution-surface value. This package covers both intrinsic `filesystem` and `terminal` events required by the Codex Session. | PolicyPackage owner |
| `…rules[].match.action` | Existing action kind. The example governs actual filesystem operations and terminal process execution. | PolicyPackage owner |
| `…rules[].match.target_contains` | Optional positive target label/URI substring. The example selects the governed denied marker without revealing or mounting a caller path. | PolicyPackage owner |
| `…rules[].match.payload_contains`, `command_contains`, `risk_at_least` | Optional existing positive match criteria for payload, command/argv summary, and risk level. They remain available even though this example does not use them. | PolicyPackage owner |
| `…rules[].decision` | Existing rule outcome: `allow`, `deny`, `require_approval`, or `mediate`. The first rule denies the marker before the general write allow can match. | PolicyPackage owner |
| `…rules[].reason` | Optional human explanation recorded with the decision. | PolicyPackage owner |
| `…rules[].mediation` | Optional structured instruction for `mediate` decisions only; it is interpreted by the owning surface, never executed as arbitrary code. | PolicyPackage owner |
| `PolicySet.spec.packages` | Immutable non-empty ordered PolicyPackage membership. It is the PolicySet's sole static composition edge and keeps Rules defined once, on PolicyPackage. | PolicySet owner |
| `PolicySet.spec.packages[]` | One immutable PolicyPackage name. Every named package is mandatory for evaluation and must cover the intrinsic Surfaces required by this Session. | PolicySet owner |
| `Session.spec.agent` | The Agent reference for this concrete run; it must resolve to `local-codex`. | Session admission |
| `Session.spec.policySet` | The governing PolicySet reference for this concrete run; admission proves it governs terminal and filesystem. | Session admission |
| `Session.spec.surfaces` | Optional named Surface records for independently configured kinds. It is absent from this terminal/filesystem-only Session. | Session admission |
| `Session.status` | Daemon-written observed result, never a Session create input. | Daemon |
| `Session.status.stateProjection` | Daemon-created private view of agent state, proving real Codex did not receive the caller's home. | Filesystem SurfaceRuntime |
| `Session.status.stateProjection.target` | Fixed in-workload target required by `codex-v1`, assigned to `CODEX_HOME`; it is not Agent config or caller input. | Adapter contract / Filesystem SurfaceRuntime |
| `Session.status.stateProjection.lowerSnapshot` | Opaque daemon identity for the read-only state snapshot. It ties evidence to the exact source without exposing a source path or contents. | Filesystem SurfaceRuntime |
| `Session.status.stateProjection.writableUpper` | Opaque daemon identity for this Session's isolated writable overlay. | Filesystem SurfaceRuntime |
| `Session.status.stateProjection.refresh` | `explicit` requires a typed, revalidated refresh; no live state source is followed during the run. | Filesystem SurfaceRuntime |
| `Session.status.stateProjection.retention` | `discard-on-session-removal` cleans this run's mutable state when removed. | Filesystem SurfaceRuntime |

## Examples

### The intended Phase 5 Codex path

The final walkthrough uses the existing enrollment and policy commands, then
the Phase 5 Session lifecycle. Terminal and filesystem bindings come from the
compiled registry; no filesystem Surface command or document participates. The
exact Session argument spelling is fixed by Phase 5.2; no Agentfile
participates.

```text
erebor agent load codex-v1 --from /opt/codex/bin/codex \
  --adapter codex-v1 --name local-codex
  -> name=local-codex

erebor policy package apply "$EREBOR_CODEX_RUNTIME_POLICY" \
  --name codex-runtime-guardrail
  -> name=codex-runtime-guardrail

erebor policyset create --name codex-runtime-guardrail-set \
  --package codex-runtime-guardrail \
  --idempotency-key codex-policy-1
  -> name=codex-runtime-guardrail-set

erebor session run \
  --agent local-codex \
  --policy codex-runtime-guardrail-set
  -> session=session-a31... controller-pty=attached
```

The resulting session inspection must include the complete admitted chain:

```text
agent_name=local-codex
policySet=codex-runtime-guardrail-set
terminal_binding=shared-runtime-interception
filesystem_binding=linux-ostree-overlay
filesystem_repo=session-a31-filesystem-repo
state_lower=session-a31-state
session=session-a31...
```

### Model-provider variants

The same admitted Codex Agent and governed Session support two intentionally
separate provider configurations. The provider configuration is private Codex
state projected by the intrinsic filesystem Surface; it is not an Agent,
PolicyPackage, PolicySet, or Session field.

The committed acceptance uses a loopback provider so CI is deterministic and
never spends model tokens:

```toml
model = "erebor-phase-5-local-mock"
model_provider = "erebor-phase-5"

[model_providers.erebor-phase-5]
name = "Erebor Phase 5 local mock"
base_url = "http://127.0.0.1:<port>/v1"
wire_api = "responses"
requires_openai_auth = false
```

For an interactive example that sends a real prompt to OpenAI, select the
cheapest current model explicitly. It needs the user's normal OpenAI
authentication outside this document; no key is written into the configuration
or retained in Erebor evidence:

```toml
model = "gpt-5-nano"
model_provider = "openai"
```

The local mock proves the TUI, managed hook, daemon admission, PTY, and
filesystem enforcement deterministically. The hosted variant proves the same
Erebor execution boundary with a real model response, but is an operator-run
example rather than CI evidence.

### What does not qualify as Phase 5 acceptance

```text
codex
  -> rejected as evidence: bypasses daemon admission and private state

erebor start --config codex.toml
  -> rejected: foreground start was removed

Agentfile -> Agent -> Session
  -> not tested here: Agentfile belongs to Phase 6
```

## Non-Goals

- Do not validate Agentfile, `FROM`, `COPY`, `ADAPTER`, `RUN`, `Ereborfile`,
  OCI, Docker, Kubernetes, registry, or distribution behavior. Agentfile is
  exclusively Phase 6.
- Do not accept a fixture TTY, `PATH` launch, caller-home bind, mutable
  launcher, agent-selected policy, or client-owned lifecycle as equivalent to
  the real governed path.

## Checkpoint

Add committed daemon/client and privileged Linux-host coverage for:

- explicitly enrolled real Codex final-file/version verification and staged
  execution;
- exact PolicyPackage order, PolicySet name, Agent admission, terminal and
  filesystem binding identities, and durable evidence/receipts for the real
  Session;
- private `CODEX_HOME`, managed hook behavior, source-path/daemon-socket
  absence, caller-state non-mutation, and secret redaction;
- emitted filesystem events and a real denied `.erebor-denied` write/mutation
  with no workspace or state effect; and
- controller geometry, input, observer, detach, and reattach behavior in the
  real TUI;
- two-UID isolation, policy denials, daemon-loss behavior, and physical-effect
  attribution for the advertised Linux-host mode; and
- the complete Phase 5 lifecycle probe and repository Rust CI procedure.

## Acceptance

- A real Codex TUI can run only as a daemon-owned Session whose Agent and
  PolicySet pass compatibility validation and whose intrinsic `terminal` and
  `filesystem` Surface bindings have been admitted.
- The resource model is visible in the real result:
  `PolicySet -> PolicyPackage` for static ordered composition, and
  `Session -> Agent + PolicySet + Surface bindings` for this concrete execution.
- The daemon remains the lifecycle, enforcement, state, PTY, evidence, and
  physical-effect owner; the client, agent, and source files are not alternate
  authorities.
- Phase 5 is done only when this real-host result is recorded. A missing host
  prerequisite leaves Phase 5 not done, with precise diagnostic evidence.
- Browser-CDP mediation is not part of this acceptance. A later mediated
  acceptance may use only the typed replacement Surface required by its
  matching Rule and the named Surface activated for that Session; it cannot
  discover or substitute another Surface.

## Stop Point

Record the final result in this file and update the Phase 5 master/parent
status. Stop before any Agentfile or runner work; those begin in Phase 6.

## Result

State: In progress.

2026-07-27 implementation and verification progress:

- The privileged Docker acceptance now runs the installed static Codex
  `0.145.0` TUI through a daemon-created Session. It uses the actual current
  Responses `function_call` shape for `shell_command`, passes the controller
  geometry/input/observer/detach/reattach checks, rejects the real attempted
  `.erebor-denied` workspace mutation before effect, and finds the filesystem
  Surface evidence at the admitted Session output path
  `output/evidence/filesystem-decisions.jsonl`. The final rebuilt-image run
  passed in `87.41s`.
- The CI provider remains the deterministic, zero-cost
  `erebor-phase-5-local-mock`. The example above separately documents
  `gpt-5-nano` as the explicit hosted-provider option for an operator-run real
  prompt; it is not substituted into CI.
- `cargo fmt --all -- --check`, the focused real-profile and Codex-session
  tests, `cargo check --workspace`, and
  `cargo clippy --workspace --all-targets --all-features -- -D warnings` pass.
  The real-profile test also now returns structured errors rather than using
  disallowed `expect` calls.
- The required `bash .github/scripts/verify-rust-ci.sh` was rerun with host
  local-socket permission after the sandbox correctly blocked CDP WebSocket
  binding. It then reached a legacy Browser-CDP e2e failure: the test invokes
  removed `erebor session diagnose`, while the current CLI deliberately rejects
  that foreground command. Reworking that test to use a named Browser-CDP
  Surface would implement the deferred Phase 5.4 model; suppressing or
  deleting it would weaken coverage. Neither action is included here. The
  phase remains **In progress** until that scope is decided.

2026-07-27 discovery and partial verification:

- `CodexManagedArtifacts` now accepts exactly two intentional target layouts:
  the existing deterministic fixture's private `/run/erebor/codex` layout and
  the real Codex managed-profile layout
  `/etc/codex/requirements.toml` plus
  `/usr/lib/erebor/codex-hooks/{erebor-codex-hook,shell-startup}`. Mixed
  layouts are rejected. This preserves the existing fixture while making the
  real Codex path explicit; it does not add a CLI, Surface resource, or runner.
- `cargo test -p erebor-runtime-packages
  codex_package_binds_exact_entrypoint_and_hook_contract -- --nocapture` and
  `cargo test -p erebor-runtime-packages
  fixture_artifact_targets_cannot_mix_with_the_codex_managed_profile --
  --nocapture` passed.
- A privileged Docker probe mounted the installed static
  `codex-cli 0.145.0` release read-only, including its bundled resources. It
  verified that the real executable reads the system managed requirements,
  sees the managed hook directory, executes the expected ordered hooks, and
  cannot modify either session projection. The ordinary host probe correctly
  did not expose the managed profile. The unprivileged local attempt is not
  acceptance evidence because this host denies `unshare --user --mount` with
  `Operation not permitted`.
- The probe exposed and resolved a contract flaw: a hash of every observed
  payload shape is not a hook schema, because valid Codex contexts omit or add
  optional fields. The package now declares only its enabled event kinds. The
  compiled `codex-v1` adapter validates each raw payload against the current
  upstream event schema: exact event name, required fields, optional fields,
  `additionalProperties: false`, nullable-string fields, permission-mode enum,
  and the deliberately unrestricted `tool_input`/`tool_response` values.
  `HookEvent` IPC no longer carries a caller-supplied schema hash. The daemon
  derives the kind from validated JSON and still requires package admission,
  a guard-issued ticket, and kernel-peer identity. Unknown fields, wrong types,
  unsupported events, and unenabled events fail closed.
- The live privileged probe passed again after this correction for both
  app-server and exec hook sequences. All observed `SessionStart`,
  `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, and `Stop` inputs matched
  the compiled current schema. The fixture's Erebor-only delivery metadata was
  moved beneath `tool_response`, whose upstream schema intentionally accepts
  arbitrary JSON; no foreign top-level field is admitted.
