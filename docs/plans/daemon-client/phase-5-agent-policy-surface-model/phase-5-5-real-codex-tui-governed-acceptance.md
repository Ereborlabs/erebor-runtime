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
  bindings, declared source view, runner base, and Session identities in the
  result chain. A named Surface is supplied only if the selected policy
  requires a Surface with independent configuration, such as Browser CDP.
- Run the actual Codex TUI through the daemon-owned Phase 4 controller PTY.
  Preserve initial geometry, controller-only input/resize, read-only
  observation, and detach/reattach of the same session.
- Prove the declared source-view boundary in the live workload: the admitted
  caller sources, including the configured Bash startup file, Codex state, and
  working directories, are visible at their declared workload targets and are
  subject to filesystem policy. The runner must not expose an undeclared caller
  path, daemon-control socket, Docker socket, or other control credential.
  Secrets remain absent from logs, output, receipts, and evidence.
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

## Declared Source View Decision

The real local Codex experience is a governed use of its configured caller
inputs, not a synthetic temporary user, a fabricated Codex home, or an
implicit caller-home mount. The full workload-visible input set must be
declared on the concrete Session run. It is not part of the immutable Codex
package or Agent: an Agent is portable, while caller paths vary by Session.
The existing `erebor run` route is merely its first caller. The generic
filesystem Surface input is:

```json
{
  "caller_home_sources": [
    { "relative_path": ".bashrc", "kind": "file", "access": "read_only" },
    { "relative_path": ".codex", "kind": "directory", "access": "read_write" },
    { "relative_path": "go/src/project", "kind": "directory", "access": "read_write" }
  ]
}
```

The current Docker-inspired CLI spells the same Session input as repeatable
`--caller-home-source relative-path:kind:access`; it introduces no command or
resource category. A later declarative configuration can express this same
Session input without changing the filesystem Surface contract.

| Field | Use and validation | Owner |
| --- | --- | --- |
| `caller_home_sources` | Optional repeated input for one runtime Session. It is rejected on a static Session association and has no Agent or package equivalent. An empty list retains the adapter's existing isolated-private-state route where that route exists. | Session admission / intrinsic filesystem Surface |
| `…relative_path` | Required normalized non-empty path below the authenticated caller's non-symlink home. It cannot be absolute or contain `.` or `..`; daemon descriptor resolution rejects a missing, symlinked, wrong-kind, or wrong-owner source. | Session admission |
| `…kind` | Required source shape: `file` for one regular file or `directory` for a directory tree. It prevents the request from silently accepting a different filesystem object. | Session admission |
| `…access` | Required projection mode: `read_only` or `read_write`. A Session workspace must fall under a declared writable directory source. | Intrinsic filesystem Surface |

The daemon resolves every `relative_path` below the authenticated caller's
non-symlink home and projects it to the same `$HOME` relative target. The
individual caller paths must be named; a magic, unrestricted `callerHome` is
not an equivalent source declaration. Sources are regular files or directory
trees with explicit access. The requested workspace must be inside one
declared writable directory source.

The projection contract is physical, not just admission metadata:

```text
undeclared path             -> absent from the private caller-home view
read_only source            -> descriptor-verified bind, remounted read-only
read_write directory source -> per-Session COW overlay at that source target
                               (lower=verified source; upper/work=the existing
                               FilesystemSessionStorage volume)
read_write file source      -> private Session copy at that source target
```

`OverlayFS` can mount a directory but not a regular-file target, so the file
case is a session-owned copy rather than a writable host bind. In neither case
does a write reach the caller source. A workspace within a declared writable
directory uses that directory's merged overlay path as its process working
directory; it is never also mounted through a direct writable workspace bind.
No source view is automatically promoted back to the caller. Promotion remains
a later typed, policy-governed filesystem operation.

`~/.bashrc` is both a visible source and
the declared Bash startup input: the daemon admits the caller's `PATH`, fixes
`HOME` and the hook `SHELL`, and sets `BASH_ENV` only when `.bashrc` is
declared. No other inherited client environment is forwarded.

```text
runner base
  linux-host -> admitted host-system base, including Bash
  docker     -> admitted image base, including Bash
```

`host-system` is one Linux-host-only runner base, not a copied list of
`/usr/bin/bash`, the dynamic loader, libraries, `/bin`, and other host paths.
The Linux runner verifies the required Bash contract against that base. A
Docker runner reuses the caller-source mapping but supplies the shell and all
system dependencies from its admitted image; it must not copy or bind the
host's system tree into a container.

A generic filesystem source accepts regular files and directory trees. A
directory source does not implicitly grant live IDE authority: when `.codex`
is projected, the Linux controller masks `.codex/ipc` in the Session. The
socket requires its own explicitly governed live binding before it can be
exposed.

This implemented host profile retains the existing private-state acceptance:
the intrinsic filesystem Surface snapshots Codex state into the Session's
private `CODEX_HOME` view while the separately declared caller sources provide
the permitted `$HOME` and workspace paths. `FilesystemSessionStorage` remains
the owner of that per-Session state storage. This decision does not add a
second Agent, Session, PolicyPackage, or PolicySet resource.

## Accepted Resource Schemas

Phase 5.5 adds no declared-resource field. It adds the runtime-only generic
`caller_home_sources` Session input described above; it is not serializable as
an Agent, PolicyPackage, PolicySet, or Surface field. It accepts only the
resource contract from Phases 5.1–5.3 below; a real Codex result is invalid if
any document contains an extra field or a substituted reference. Phase 5.4 is
the conditional extension for a `mediate` Rule with an explicit
`replacement_surface: browser_cdp`.

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
separate provider configurations. The provider configuration is part of the
declared Codex-state source view governed by the intrinsic filesystem Surface;
it is not an Agent, PolicyPackage, PolicySet, or Session field.

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
  -> rejected as evidence: bypasses daemon admission and the declared source view

erebor start --config codex.toml
  -> rejected: foreground start was removed

Agentfile -> Agent -> Session
  -> not tested here: Agentfile belongs to Phase 6
```

## Non-Goals

- Do not validate Agentfile, `FROM`, `COPY`, `ADAPTER`, `RUN`, `Ereborfile`,
  OCI, Docker, Kubernetes, registry, or distribution behavior. Agentfile is
  exclusively Phase 6.
- Do not accept a fixture TTY, an implicit or undeclared caller-home bind,
  mutable launcher, agent-selected policy, or client-owned lifecycle as
  equivalent to the real governed path.

## Checkpoint

Add committed daemon/client and privileged Linux-host coverage for:

- explicitly enrolled real Codex final-file/version verification and staged
  execution;
- exact PolicyPackage order, PolicySet name, Agent admission, terminal and
  filesystem binding identities, and durable evidence/receipts for the real
  Session;
- declared caller-source mapping, Bash startup behavior, managed hook
  behavior, undeclared-source/daemon-socket absence, source attribution, and
  secret redaction;
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
- The real result records the complete declared source view and selected runner
  base. Linux-host provides its admitted host-system base; a future Docker
  runner must realize the same caller sources against an admitted image base.
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

2026-07-28 writable source-view correction:

- The prior direct writable bind was incorrect: it allowed a governed
  workload to mutate the caller workspace, as demonstrated by a host-visible
  `hello.frominside` file. Declared caller sources now use an internal
  `SessionView` target (Session-spec schema version 7), which masks the caller
  home with an empty private view and creates only the declared target paths.
  This is distinct from the existing `SessionOverlay` target, which remains
  the daemon-managed COW mount-root mechanism for managed `/etc` and `/usr/lib`
  artifacts.
- Every declared writable directory now receives a per-Session OverlayFS view
  backed by a volume in the existing `FilesystemSessionStorage`; its verified
  source is the read-only lower and the Session-owned upper/work directories
  receive changes. Read-only sources remain direct read-only binds. Writable
  regular files receive a private Session copy because Linux OverlayFS cannot
  mount a file target. The runner uses the merged directory view as its
  workspace rather than a separate direct workspace bind.
- Crate-local regression tests cover the new `SessionView` contract, require a
  daemon-owned overlay for a writable directory view, and prove a writable
  regular-file view does not mutate its source. `cargo check --workspace`, the
  focused Rust tests, the real-Codex mock-provider syntax checks, and the
  rebuilt privileged daemon image passed.
- The privileged real-Codex run reached the governed Session and successfully
  read its declared `.codex` SessionView, but stopped before the TUI readiness
  prompt: Codex received `EACCES` while reading the separately projected,
  policy-allowed `/etc/codex/requirements.toml`. A comparison run with both
  caller-source flags removed failed at the same managed-requirements read.
  The writable-source change therefore did not cause that failure, but it
  means the live COW workspace proof is still pending. This phase remains in
  progress; no managed-artifact redesign is included in this correction.
- The final CI procedure passed formatting, workspace checking, and Clippy for
  this source state. Its workspace-test stage remains blocked by the existing
  `erebor-codex-hook` binary test: it supplies a `SessionStart` JSON event
  without the now-required `cwd` field. That stale managed-hook test is outside
  this source-view correction and was not changed.

2026-07-27 implementation and verification progress:

- The interactive example is now a direct persistent host setup, not a lab.
  The recovered Codex revision places its fixed host/systemd daemon profiles,
  managed-hook requirements, and `codex-runtime-guardrail` PolicyPackage under
  `examples/codex-real-tui/config/` and `trust/`. Its README has one
  root-owned install of those checked-in artifacts, one foreground `erebord`
  command, and ordinary same-UID `erebor` enrollment/run commands. It has no
  profile generator. The former temporary-directory, copied-binary,
  temporary-user, `runuser`, mock-provider, and wrapper-shell scripts remain
  removed. This changes only the operator walkthrough: the existing daemon,
  agent loading, policy setup, source-view admission, Linux runner, and
  managed Codex hook contract are retained. The direct example declares the
  caller's `.bashrc`, `.codex`, and selected home-relative workspace; it does
  not expose the live `.codex/ipc` endpoint.
- Recovery verification passed: both recovered daemon profiles parse as JSON;
  the checked-in requirements and shell-startup digests exactly match their
  pinned configuration values; the current `erebor-codex-hook` digest matches
  the pinned managed-hook digest; and the README shell fences parse with
  `bash -n`. This restoration did not rerun a privileged host Session.
  Real-TUI acceptance remains **In progress** pending that operator-run proof.
- The current direct-host/source-view workflow supersedes the temporary-user
  host-lab notes below. The generic Session filesystem input declares
  non-overlapping caller-home file/directory sources with access mode; it is
  deliberately absent from `CodexPackageDefinition` and the Agent resource.
  The direct example passes the caller's `.bashrc`, `.codex`, and current
  repository source through the existing `erebor run` request. Generic and Codex
  admission reject a workspace outside a declared writable directory, project
  only those descriptor-verified paths, hide the rest of the caller home, and
  mask `.codex/ipc`. The root daemon retains ownership of hooks, policy,
  terminal interception, filesystem enforcement, and lifecycle; the normal
  developer UID remains the Erebor client and Codex workload UID. The existing
  isolated fixture path continues to use `FilesystemSessionStorage` and its
  per-Session OSTree repository unchanged.
- The direct workflow starts only the root daemon, then performs enrollment,
  policy setup, and the interactive `erebor run` command as the invoking
  developer. It does not make a user, copy a Codex home, write
  `~/.codex/config.toml`, or start a provider. The real TUI uses the declared
  existing Codex configuration. The deterministic mock remains CI-only.
- Generic source-input verification passed: core source-model tests, daemon
  admission tests, CLI parsing tests, package tests, the real-profile
  integration test, IPC contract test, Linux controller unit tests,
  `bash -n examples/codex-real-tui/run-host-lab.sh`, the complete
  `build-host-lab.sh`, `cargo check --workspace`, clean
  `cargo clippy --workspace --all-targets --all-features -- -D warnings`, and
  `bash .github/scripts/verify-rust-ci.sh`. The fresh privileged host probe
  remains unrun here: `sudo -n true` was rejected because the environment
  requires an interactive sudo password. This is a host-validation gap, not a
  completed real-TUI acceptance claim.
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
- `examples/codex-real-tui/` is the distinct interactive real-Codex **host**
  lab. It starts the existing foreground daemon and direct Linux runner, then
  creates a fresh temporary local user and one daemon-owned real Codex Session.
  `mock` retains the deterministic CI provider; `openai` uses `gpt-5-nano` and
  asks the operator to authenticate only in the governed TUI. The fixture lab
  remains separate and never claims to execute real Codex. The lab intentionally
  omits the caller's live `~/.codex/ipc/ipc.sock`: it is Codex's `/ide`
  IDE-context transport, not copyable persistent state. A governed `/ide`
  capability needs a later explicit live surface binding.
- `bash -n` passed for the real host-lab scripts and `git diff --check`
  passed. Each exact local `cargo build` target used by `build-host-lab.sh`
  passed.
  The agent could not rerun the privileged host lab from this non-interactive
  shell because `sudo` requested an interactive password; existing privileged
  acceptance remains recorded above.
- The first operator host-lab run reached the Linux runner but its controller
  closed the control stream because the lab had made the controller/guard
  binaries non-executable to the temporary Session user. The staged `bin/`
  directory remains root-owned and non-writable (`root:<lab-group> 0750`), but
  its root-owned binaries now use the existing direct-runner host-lab mode
  (`0755`). A fresh lab run is required to verify that correction.
- The host-lab launch instruction now invokes `erebor run` with no trailing
  Codex option. The previously documented `-d` is not a current Codex CLI
  option and was an invalid command. It did not request the TUI. The actual
  dangerous bypass is the distinct long
  `--dangerously-bypass-approvals-and-sandbox`/`--yolo` option, which the host
  lab does not pass. Its private config intentionally uses `never` approval
  and `danger-full-access` sandbox so the deterministic request reaches the
  Erebor boundary; this does not alter that the command starts Codex's real
  interactive TUI.
- The host-lab mock provider previously redirected its temporary user's output
  to the root-only daemon log directory, so its shell could not create the log
  and the provider never started. Its retained log now lives in that temporary
  user's private home directory. Separately, Linux-runner startup now appends a
  bounded controller-stderr tail to a control-stream-closure error before the
  failed Session rolls back its state. This preserves the actionable mount,
  projection, or process-guard cause for the owning CLI caller. The focused
  regression test for bounded, single-line diagnostic tails passes.
- After that final edit, `cargo fmt --all -- --check`, `cargo check --workspace`,
  and clippy within `bash .github/scripts/verify-rust-ci.sh` passed. The script
  then reached the unrelated Browser-CDP `proxy_e2e` tests and this agent's
  sandbox denied their local WebSocket bind with `Operation not permitted` at
  `crates/erebor-runtime-e2e/src/websocket.rs:42`. The three mini-upstream
  proxy tests therefore failed before the suite could reach the existing
  deferred-Phase-5.4 Browser-CDP legacy failure. This is an environment block,
  not evidence that the real-Codex host lab passed; privileged host validation
  remains required.
- The complete `examples/codex-real-tui/build-host-lab.sh` was run after the
  diagnostic change, rebuilding both the standalone controller and `erebord`,
  which statically links the runner that reads startup diagnostics. A lab run
  made before that rebuild necessarily continued to report the old generic
  control-stream error. A fresh privileged host-lab run is still required.
- Real-Codex managed artifacts no longer require host paths such as
  `/etc/codex/requirements.toml` or
  `/usr/lib/erebor/codex-hooks/erebor-codex-hook` to be preinstalled. The
  internal Session admission introduced a `SessionOverlay` projection target
  in schema version 6 (the current source-view contract is schema version 7):
  the Linux controller mounts a private copy-on-write
  overlay over `/etc` and `/usr/lib` only after entering the Session mount
  namespace, then creates the exact managed mountpoints and binds the trusted
  artifacts read-only. The host gets neither the managed hook path nor the
  requirements file. Existing `/run/erebor` intrinsic-runtime projections keep
  their current private-runtime mountpoint behavior. Core, daemon mapping, and
  controller target-creation regression tests pass; the required privileged
  host-lab run remains pending.
- For the overlay implementation, `cargo check --workspace`,
  `cargo clippy --workspace --all-targets --all-features -- -D warnings`, and
  the focused core, daemon, and controller regression tests pass. The host-lab
  binary set was rebuilt. The repository-wide verification procedure was also
  rerun; its Browser-CDP `proxy_e2e` portion remains blocked by this agent
  sandbox's denied local WebSocket bind, as recorded above.
- The first successful real-TUI operator run exposed a managed-hook admission
  defect: Codex displayed `UserPromptSubmit` and `Stop` as exit-code-1 hooks.
  This was not a policy denial. The local Codex command-hook implementation
  launches commands as `$SHELL -lc <managed-hook>`, while static named-Agent
  admission clears caller environment. Codex therefore used its `/bin/sh`
  fallback, but the real profile incorrectly claimed the direct two-process
  lineage `Codex -> hook`. It also recorded the daemon-only prepared-executable
  staging path even though the Linux controller moves that executable into the
  Session namespace at `/run/erebor/admitted-executable` before the guard
  observes it. The lifecycle guard consequently could not mint the required
  exact-lineage ticket, and the hook correctly failed closed.
- The real profile now pins the observable three-process lineage
  `/run/erebor/admitted-executable -> /usr/bin/bash ->
  /usr/lib/erebor/codex-hooks/erebor-codex-hook`. Named Codex admission derives
  `SHELL=/usr/bin/bash` only from that immutable hook contract; callers still
  cannot pass arbitrary session environment. The router retains the
  descriptor-preparation check but gives the hook-registration profile the
  controller's actual workload-visible executable path. The guard still
  requires the complete lineage, original pipe identities, PID identity,
  namespace/cgroup evidence, and one-use ticket; no authentication check was
  relaxed. Package, daemon, session-profile, and real-profile regression tests
  cover the pinned shell and workload-visible executable identity. The exact
  `examples/codex-real-tui/build-host-lab.sh` binary set was rebuilt after this
  correction. A fresh privileged host-lab run is required to prove the hooks
  now complete and the deterministic filesystem policy denial still occurs.
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
