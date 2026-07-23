# Governed OpenClaw Pilot Demo Plan

Plan type: implementation and demo-readiness plan.

Status: in progress. Phase 1 through Phase 7 are complete for their pilot
gates: Docker/OCI session-runner proof, Linux host OpenClaw relaunch,
governed-browser proof, live managed-browser mediation, bounded Linux host
process diagnostics, OAuth workflow packaging, shared browser/process JSONL
audit output, and runtime evidence-trace rendering have all been implemented
and verified through the package assets named below. Phase 8 is now the buyer
discovery phase: rehearse the manual demo under call pressure, run targeted
agent-vendor-first outreach, and identify the first real workflow where the
Erebor trace changes an approval conversation.

Managed browser launch interception now has a Linux-host v1 implementation
using generic `process_interception` handlers with `decision=mediate`, a
session-injected shim, and a fixed Erebor-owned CDP listener. The primary
managed-browser path was live-verified with installed OpenClaw on June 14,
2026.

Terminology:

- One governed session owns the actor, policy, audit, approvals, and surfaces.
- Docker/OCI is the first implemented session runner proof. Linux host
  bare-metal governance is now the next pilot runner because it can govern an
  already-installed OpenClaw without forcing a container-first workflow.
- Browser CDP and terminal/process execution are governed session surfaces, not
  separate runtimes.
- The session runner owns session lifecycle and process membership. Surfaces
  attach to that runner-owned session; they do not launch independent sessions.

Current implementation slice:

- `erebor session run --runner docker --config <path> -- <command>`
  builds one governed session and launches the agent entrypoint through
  Docker/OCI.
- `erebor session diagnose --runner docker --config <path> <name>`
  currently launches a named diagnostic command through the same Docker/OCI
  runner path. This is useful for smoke testing runner mechanics and process
  enforcement, but it is not the richer multi-command terminal/PTY UX needed
  for the buyer-ready pilot.
- Session interception is wired through Docker/OCI sessions, the `linux-host`
  relaunch runner, and `session adopt --runner linux-host --pid`. The current
  backend implementation is the Linux ptrace process guard for `process_exec`.
  Terminal `process_interception` supplies the routed terminal/process policy
  and mediation semantics. Adoption reports host capability and residual risk
  because existing process authority cannot be rewound after the fact.
- If the same session config enables `surfaces.browser_cdp`, session
  execution starts an Erebor-owned governed browser side resource with the same
  session id and actor, then injects `EREBOR_BROWSER_CDP_URL` into the active
  session runner environment. Docker bridge sessions rewrite host-loopback
  endpoints for container reachability; Linux host sessions keep loopback
  endpoints as-is.
- If the same session config enables `session.interception` with the
  `linux_ptrace` backend, session execution launches the session command
  through the static Linux process guard. Docker mounts the guard as the
  container entrypoint; Linux host relaunch uses the guard as a local wrapper.
  The guard traces `execve` and `execveat` for the Linux session process tree,
  sends process-exec requests to the runtime interception broker, and the
  terminal/process surface enforces deny, mediation, or verification-required
  policy before the child exec completes. JSONL audit records are written when
  configured.
- `surfaces.terminal.tty=true` controls Docker TTY allocation. TTY is not a CLI
  flag because it is part of the session surface configuration.
- Browser CDP and terminal surfaces carry their own policy path configuration,
  falling back to the session-level policy list when a surface-specific list is
  not provided.
- Terminal/process policy can define guarded commands with
  `command_contains` and `decision` values such as `deny`,
  `require_approval`, or `require_verification` (an alias for approval). The
  current ptrace backend fails closed for verification-required commands until
  terminal approval UX is implemented.
- Session config now carries actor identity, workspace, Docker/OCI session
  runner settings, named diagnostics, optional browser CDP side resources,
  policies, and audit filtering options.
- Browser CDP command/event enforcement now writes JSONL audit records to the
  same registry-owned session audit file as terminal/process mediation. The
  OpenClaw pilot runbook reads `audit_path` from
  `.erebor/sessions/<session-id>/session.json` so the demo can show terminal
  `process_exec` and browser `browser_cdp` decisions under one session id.
  Audit command logging is configurable per surface; terminal `sleep` is in the
  default debug-command list so allowed sleep loops do not drown the signal.
- Docker session launch is owned by `erebor-runtime-core` behind the
  `SessionRunner` trait; the CLI builds plans and delegates runner execution to
  core.
- `erebor-runtime-terminal` now compiles terminal/process deny and
  verification-required policy for process-exec interception. Docker session
  execution mounts the `erebor-runtime-session` Linux ptrace guard for the pilot
  backend path when `session.interception` is enabled.
- Current Docker terminal/process governance applies to process creation
  attempts made by the guarded session process tree. The guard has been smoke
  tested against direct commands, shell-spawned child processes, Python
  `subprocess` launches, and Linux host relaunched OpenClaw browser CLI
  commands.
- `examples/governed-openclaw-pilot/` contains the current visible governed
  OpenClaw demo package: stage runbook, Control UI runner, automated
  verification runner, prompt, one mediated-browser session config, one OAuth
  policy, and deterministic policy fixtures.
- `examples/governed-openclaw-pilot/session-config.json` contains the preferred
  managed-browser path: OpenClaw can launch Chrome or Chromium normally, while
  the terminal/process surface routes configured browser launches to an Erebor
  shim and the browser CDP surface starts just in time on the debugging port
  requested by the intercepted launch.
- Linux host relaunch, `adopt --pid`, and current process-table
  `adopt --match <text>` for installed/local processes are implemented as Phase
  2 host-enrollment slices. The preferred relaunch path and attach-only CDP
  proof are verified with installed OpenClaw; installed OpenClaw adoption
  remains optional follow-up.

Related architecture:

- [`docs/plans/session-hypervisor/README.md`](../session-hypervisor/README.md)
  owns the universal session model, session runner contract, lifecycle,
  enforcement tiers, Docker/OCI fallback posture, and Linux host/bare-metal
  runner posture.
- [`docs/governed-browser-and-terminal-plan.md`](../../governed-browser-and-terminal-plan.md)
  owns browser, terminal, OpenClaw, endpoint, and bypass-validation work that
  consumes the session model.
- [`docs/plans/semantic-classification/README.md`](../semantic-classification/README.md)
  owns later semantic authority-grant classification before policy evaluation.
- [`docs/plans/managed-browser-launch-mediation/README.md`](../managed-browser-launch-mediation/README.md)
  owns the terminal/process feature that can convert OpenClaw's normal Chrome
  raw-CDP launch into an Erebor-owned governed browser endpoint on the
  requested compatibility port while keeping the owned Chrome upstream on a
  separate private port. Linux-host lazy requested-port mediation is
  implemented; the attach-only profile remains the fallback when host browser
  restrictions block live managed-browser verification.
- Approved office-hours design:
  `/home/navid/.gstack/projects/Ereborlabs-erebor-runtime/navid-main-design-20260616-014622.md`
  reframes the buyer demo as a runtime evidence trace: OpenClaw runs inside one
  governed session, Erebor blocks a risky authority transition, and the run is
  rendered into a reviewer-readable report showing governed resources
  exposed, allowed actions, denied actions, policy rule, and residual risk.

## Phase Gate Status

| Phase | Status | Gate |
| --- | --- | --- |
| Phase 0: Plan and demo boundaries | Complete | The plan, terminology, scope, claims, non-claims, and related-plan links are documented. |
| Phase 1: Docker/OCI session runner proof | Complete for the runner proof gate | Core can build Docker/OCI session plans, inject session metadata, workspace, audit, browser endpoint, session interception backend configuration, and terminal/process handler configuration, then run guarded direct commands and diagnostics. Docker remains the fallback/CI runner, not the only pilot path. Remaining cleanup/capability-report polish does not block later phases. |
| Phase 2: Linux host OpenClaw enrollment | Complete for the preferred relaunch path | Installed OpenClaw `2026.5.20 (e510042)` was relaunched under `session run --runner linux-host`, emitted the Linux ptrace capability report, and ran `openclaw --version` as a governed process. `adopt --pid` and current-process `adopt --match <text>` exist but remain optional/weaker follow-up paths for the call. |
| Phase 3: OpenClaw governed browser proof | Complete for attach-only fallback and live managed-browser mediation | Installed OpenClaw consumed `EREBOR_BROWSER_CDP_URL`, reported the governed `cdpUrl`, opened `https://example.com/`, listed real browser targets through Erebor's Chrome-style discovery shim, and hit an Erebor policy denial for an `owned-denied` script payload. The managed-browser path now uses lazy requested-port mediation: OpenClaw uses its normal local managed browser profile without a workshop-defined `cdpPort`; when OpenClaw attempts to launch Chrome, Erebor intercepts that launch, starts governed CDP on the requested port, launches private Chrome at requested port plus one, opens `https://example.com/`, lists tabs, and denies the expected eval. |
| Phase 4: Bounded shell/process proof | Complete for the Linux host proof | The Linux host process guard denies raw-CDP child-process attempts through the governed session config, and automated Linux-host tests cover direct, shell-spawned, and Python `subprocess` child exec denial plus fail-closed verification-required commands. |
| Phase 5: OAuth workflow package | Visible Control UI demo packaged; automated prompt run verified with the dummy-client plumbing path; throwaway OAuth app branch remains the buyer-demo run | The manual buyer path is the self-contained runbook in `examples/governed-openclaw-pilot/README.md`, backed by `run-openclaw-gateway.sh`, `session-config.json`, `policy.json`, `prompt.txt`, preflight/check scripts, and fixtures. The stage demo asks the operator to paste the prompt into OpenClaw Control UI, shows OpenClaw's normal Chrome launch being mediated by Erebor, validates thread/repro/OAuth lab events, and fails the story if the lab records `oauth_callback_received`. |
| Phase 6: Shared browser/process audit | Complete for the pilot evidence gate | Browser CDP command/event decisions, observer state-recovery records, and terminal/process JSONL records now append to the registry-owned session audit artifact, and the runbook shows `audit tail` over one shared session file. This unblocks the runtime evidence-trace report phase. |
| Phase 7: Runtime evidence trace report | Complete for the pilot evidence gate | `erebor-runtime-audit` renders a reviewer-ready markdown trace from shared JSONL audit records, policy, config, and prompt artifacts; the first sink writes markdown files, and the deterministic fixture report proves purpose, actor, policy hash, governed resources, allowed actions, denied authority transitions, residual risk, control labels, non-claims, and artifact hashes. |
| Phase 8: Call demo package and discovery handoff | Outreach and discovery package in progress | Use the manual demo runbook and runtime evidence packet as the proof artifact, then run discovery with agent vendors first, regulated enterprise AI/security teams second, and gov-contractor proposal teams third. The gate is not more demo code; it is evidence that a specific buyer workflow is blocked today and that Erebor's governed-session trace would change the approval path. |

## Summary

This plan owns the near-term pilot-call demo for Erebor Runtime:

```text
Erebor starts or adopts one governed session for an installed OpenClaw agent.
The preferred pilot session runner is Linux host bare-metal; Docker/OCI remains
the implemented fallback and CI runner.
Inside that session, OpenClaw gets only Erebor-governed browser and process paths.
Erebor blocks a high-risk browser authority transition and a risky shell action,
then emits one shared audit trail for the whole session.
```

The pilot is no longer browser-only. The first sellable proof should be a
browser plus bounded shell/process support-investigation workflow, because that
matches the session-hypervisor product thesis: the governed session is the
product boundary, and the session runner is just the substrate that enrolls and
enforces the agent process tree.

The approved runtime evidence-trace design narrows the buyer-facing "whoa"
moment: OpenClaw investigates a realistic workflow, hits a risky OAuth or
raw-CDP authority transition, Erebor blocks it before execution, and the run is
rendered into a reviewable trace. The trace must show what governed resources were
exposed to the agent, what the agent attempted, what was allowed or denied, what
policy rule decided it, and what residual risk remains. It must not claim GDPR
or HIPAA compliance, legal sufficiency, semantic proof that the agent never read
PII, or whole-device containment.

Docker/OCI is not the product identity. It is the first implemented session
runner proof. For the pilot-call path, Linux host bare-metal is now preferred
because it lets a buyer see Erebor govern an already-installed OpenClaw instead
of requiring a containerized OpenClaw image first. The architecture must remain
compatible with Docker/OCI, Kubernetes, and stronger sandbox session runners
through the same session contract.

## Architecture Decision

The pilot must follow this shape:

```text
Session
  actor: OpenClaw agent
  session runner: Linux host bare-metal, with Docker/OCI as fallback
  surfaces:
    browser_cdp: Erebor-owned browser, governed endpoint only
    terminal/process: Linux ptrace process surface attached to the session
  shared:
    policy set
    approval channel
    audit sink
    session runner capability report
```

The pilot must not create a separate "OpenClaw browser demo" path and a separate
"Docker shell demo" path. Browser and shell actions must be interpreted as
effects inside one governed session.

The first Docker/OCI implementation proved the minimum runner mechanics. The
Linux host pilot runner should now prove:

- Erebor can relaunch an installed OpenClaw process as a session member.
- Erebor can later adopt an already-running OpenClaw PID with residual-risk
  reporting, but relaunch is the preferred first governed demo path.
- Erebor can attach the session interception backend to the OpenClaw process
  tree without relying on OpenClaw hooks as the enforcement boundary.
- The agent receives governed endpoint descriptors, not raw private endpoints.
- Future process creation attempts from OpenClaw, shell children, Python
  subprocesses, and helper scripts are observed and policy-checked.
- Browser and shell events share session identity, actor identity, policy, and
  audit.
- Session runner capability status is reported honestly.

## Existing Repo Facts

Already present:

- `docs/plans/session-hypervisor/README.md` defines the governed session model,
  session runner responsibilities, Docker/OCI as the initial session runner,
  and browser plus shell as the first workflow.
- `docs/governed-browser-and-terminal-plan.md` already depends on the session
  hypervisor plan for session runner, command lifecycle, and enforcement tier
  decisions.
- `examples/playwright-cdp-demo/` proves a client can connect to an
  Erebor-owned browser through the governed CDP endpoint.
- The Playwright smoke demo denies a suspicious `Runtime.evaluate` payload and
  verifies the blocked action does not mutate browser state.
- `examples/openclaw-oauth-click-lab/` provides the buyer-facing browser danger
  story: public web content can guide an authenticated browser toward a GitHub
  OAuth permission grant.
- `integrations/openclaw-ts/README.md` exists as the reserved home for the first
  OpenClaw UX integration.
- `erebor-runtime-audit` has a JSONL sink and reader.
- `erebor-runtime-cli audit tail` can read JSONL audit records.
- Runtime events already include browser and terminal/process action kinds.
- `erebor session run --runner docker` and
  `erebor session diagnose --runner docker` now create a session plan
  and delegate Docker launch to `erebor-runtime-core`.
- `erebor-runtime-core` now owns a `SessionRunner` trait and
  `DockerSessionRunner` implementation.
- Docker bridge sessions rewrite host-loopback governed endpoints to
  `host.docker.internal` for container reachability while keeping the private
  Chrome DevTools endpoint out of the session environment.
- `erebor-runtime-terminal` compiles terminal/process deny rules for
  process-exec interception.
- `erebor-runtime-session` builds a static Rust Linux ptrace process guard,
  mounts it into Docker/OCI sessions, and uses it as the container entrypoint
  when `session.interception` enables the Linux ptrace backend.
- `erebor session run --runner linux-host` now relaunches a local
  command with Erebor session metadata and can wrap it with the Linux ptrace
  process guard when `session.interception` enables the Linux ptrace backend.
- `erebor session adopt --runner linux-host --pid <pid>` now attaches
  the Linux ptrace process guard to an already-running process tree when host
  ptrace permissions allow it. The guard emits a capability/residual-risk
  report and attempts best-effort cgroup v2 membership.
- `docs/plans/session-hypervisor/README.md` defines the broader
  `session adopt --pid <pid>` and future pre-armed `session adopt --match
  <rule>` enrollment model. The pilot implements `--pid` and a narrower
  current-process `--match <text>` resolver that finds exactly one already
  running matching process and then uses the `--pid` adoption path.
- `examples/openclaw-oauth-click-lab/README.md` records an observed ungoverned
  OpenClaw baseline where the OAuth callback is received.

Remaining for the buyer-ready pilot:

- True pre-armed exec-time `session adopt --match <rule>` enrollment has not
  been implemented. The current pilot `--match <text>` resolver only selects an
  already-running process from `/proc`; use relaunch for the strongest demo
  path.
- `session adopt --runner linux-host --pid <pid>` has not yet been manually
  verified against installed OpenClaw, and it depends on host ptrace policy.
  The preferred relaunch path is verified and should remain the call path.
- The live CDP runtime currently enforces and logs browser decisions. The runtime
  evidence trace must not claim governed browser-resource provenance until
  browser CDP JSONL records include target URL/context for allowed navigation
  and denied OAuth actions.
- The OAuth lab is packaged as a governed session demo with runtime config,
  deterministic policy fixtures, prompt, expected results, and non-claims.
  Live validation with a throwaway GitHub OAuth app is still pending.
- The browser policy now has deterministic pilot rules for lab navigation and
  GitHub OAuth authorize script/click denial. Broader semantic authority-grant
  classification remains deferred.
- The approved runtime evidence-trace design is now the buyer-facing packaging
  target. The first report can be generated markdown or HTML; it does not need
  automatic DPIA, ROPA, retention workflow, reviewer routing, or semantic PII
  classification.

Deferred beyond this pilot:

- macOS/Windows host guards.
- Kubernetes session runner.
- MCP governance.
- Full filesystem and network productization beyond the Linux host runner's
  explicit capability report.
- Endpoint bypass claims that exceed the active Linux host session runner
  capability report.
- OS-wide or company-device safety claims.
- Full semantic authority-grant classification beyond the minimum deterministic
  pilot rule.

## Demo Contract

The pilot demo should show an ungoverned baseline first, then one governed
session:

1. Start the OAuth lab with throwaway GitHub OAuth app data.
2. Run OpenClaw normally, outside Erebor, against the lab and show the
   ungoverned baseline can reach `oauth_callback_received`.
3. Reset the lab/browser authorization state so the governed run starts clean.
4. Start a governed Linux host session by relaunching installed OpenClaw under
   Erebor:
   `erebor session run --runner linux-host --config <path> -- openclaw`.
   After relaunch works, add the weaker attach path:
   `erebor session adopt --runner linux-host --config <path> --pid <pid>`.
5. The session prepares an Erebor-owned browser and gives OpenClaw only the
   governed CDP endpoint through an attach-only profile or config overlay.
6. The session attaches the Linux ptrace process surface to the OpenClaw process
   tree.
7. Ask OpenClaw to investigate the support thread/repro.
8. Allow normal browsing, repro navigation, and safe read-only diagnostics.
9. Block the high-risk OAuth authorization action.
10. Block or require approval for at least one risky shell/process action, such
    as an unmanaged browser launch or raw CDP probing helper.
11. Confirm the governed run does not receive `oauth_callback_received`.
12. Show one audit trail containing browser and shell/process decisions under
    the same session id.
13. Render the audit into the runtime evidence trace:
    - session id
    - actor identity
    - user-stated purpose
    - policy package and hash
    - governed resources exposed
    - allowed actions
    - denied or held authority transitions
    - residual risk and explicit non-claims
14. Ask whether this trace would change the review process for agents near PII,
    or whether the buyer still needs a different approval artifact.

The demo must not imply:

- Docker/OCI is the final or only Erebor session runner.
- The pilot provides host-wide bare-metal process governance.
- After-the-fact `adopt --pid` can undo authority OpenClaw already used before
  adoption.
- `adopt --pid` can inject new environment variables into an already-running
  OpenClaw process; if OpenClaw needs a new CDP profile path, use
  `session run --runner linux-host` or `adopt --match` before process start.
- OpenClaw cannot do anything outside the session if it was also started
  outside Erebor or has ungoverned sibling processes.
- Raw CDP and endpoint bypasses are fully prevented beyond the Docker/OCI
  or Linux host runner's reported capabilities.
- API governance alone would catch the OAuth authority transition.
- The Linux host pilot is equivalent to whole-device containment.
- The evidence trace proves every personal-data value the agent semantically
  read. V1 proves governed resource/action provenance; semantic PII
  classification is deferred.
- The evidence trace is legal advice, GDPR/HIPAA compliance, certification, or
  a completed DPIA.

## Status Matrix

| Area | Current status | Required for pilot |
| --- | --- | --- |
| Session architecture | `SessionRunner` path in core and terminal/process policy compilation in `erebor-runtime-terminal` | Add lifecycle cleanup/report polish |
| Docker/OCI session runner | Implemented for the runner proof gate: core runner launches Docker, injects metadata, mounts the Linux ptrace process guard when `session.interception` enables the Linux ptrace backend, requests cleanup, and can capture guarded diagnostics | Keep as fallback/CI path |
| Linux host session runner | Relaunch, `adopt --pid`, and current-process `adopt --match <text>` paths implemented with session metadata, ptrace process guard support, capability reporting, recursive attach, and best-effort cgroup membership. Installed OpenClaw relaunch is verified. | Manually verify installed OpenClaw adoption only if the call needs after-the-fact enrollment; keep true pre-armed exec-time matching deferred |
| OpenClaw agent enrollment | Installed OpenClaw `2026.5.20 (e510042)` relaunch is verified through the Linux host session runner | Keep relaunch as the buyer-demo path; adoption remains an optional/weaker follow-up |
| Erebor-owned browser | Existing Playwright demo works; session side resource injection exists | Attach OpenClaw through session |
| Governed CDP endpoint | OpenClaw attach-only profile is verified through the Linux host session; managed-browser requested-port mediation is implemented and ready for live verification after this correction; Chrome-style discovery on the governed port returns only Erebor URLs and masks private Chrome endpoints | Use the mediated path for the call once live smoke passes; use attach-only as the fallback proof if host browser launch is blocked |
| OpenClaw browser profile | Preferred mediated profile uses OpenClaw's normal local managed browser profile without `cdpPort`; fallback attach-only fixture requires `cdpUrl`, `attachOnly=true`, and `color` | Keep docs aligned with OpenClaw `2026.5.20` config validation |
| Terminal / process surface | Linux ptrace process guard audits and denies matching `execve`/`execveat` attempts from direct commands, shell children, and Python subprocesses in Docker and Linux-host relaunch paths; Linux-host adopt can attach when ptrace permissions allow | Manually verify installed OpenClaw process attempts |
| OAuth consent lab | Existing lab plus prompt-driven governed-session package in `examples/governed-openclaw-pilot/README.md` | Live validate with throwaway GitHub OAuth app data |
| OAuth deny policy | Packaged in `examples/governed-openclaw-pilot/policy.json` with deterministic fixtures | Live validate against the OAuth lab through OpenClaw |
| Shell/process policy | Risky raw-CDP browser launch denial and `git push` verification-required rules exist in pilot policy | Add interactive approval path after fail-closed verification gate |
| JSONL runtime audit | Terminal/process and browser CDP decisions now write to the registry-owned shared session JSONL artifact, with per-surface command logging filters for harmless/debug allowed commands | Use the shared audit as Phase 7 evidence-trace input |
| Runtime evidence trace | `erebor-runtime-audit` renders the markdown evidence trace from the JSONL audit log, the CLI has a thin file-output adapter, and a deterministic fixture report is checked in | Use the report in the call package and discovery handoff |
| Buyer demo script | Prompt-driven OAuth demo runbook and scripts exist | Add final call-pressure script after live OAuth validation and evidence-trace report |

## Phase 0: Plan And Demo Boundaries

Goal: make the pilot scope unambiguous before implementation.

Status: complete.

Deliverables:

- This plan file.
- Cross-links from the session-hypervisor and browser/terminal plans.
- A short "demo claims and non-claims" section in the eventual demo README.
- A visible distinction between Docker/OCI fallback enforcement, Linux host
  pilot enforcement, and future macOS/Windows/Kubernetes enforcement.

Acceptance:

- A reader can tell which parts are already implemented, missing, and deferred.
- No code work is required to understand the implementation order.
- The plan says Linux host process governance is the preferred pilot path and
  Docker/OCI remains a fallback/CI runner.
- The plan does not define a separate session runner architecture outside
  `docs/plans/session-hypervisor/README.md`.

## Phase 1: Implement The Docker/OCI Session Runner

Goal: create the first concrete session runner without changing the product
semantics from the session-hypervisor plan.

Status: complete for the pilot runner gate. Cleanup verification and formal
capability reporting remain polish items before the final buyer package, but
they do not block Phase 2 through Phase 4, which are already complete for their
pilot gates.

Implementation:

- Add a session launch path equivalent to:

```bash
erebor session run --runner docker -- openclaw
```

- Agent-specific presets such as `erebor run openclaw --runner docker` may be
  added later, but they must compile to the same session request shape.
- Create a Docker/OCI session runner that:
  - creates a session id and actor identity
  - prepares a workspace mount with explicit read/write scope
  - starts the agent process as a session member
  - injects governed endpoint descriptors and policy/audit metadata
  - starts or connects owned side resources such as browser CDP proxy and the
    session interception backend for terminal/process governance
  - tears down the container, browser profile, endpoints, and temporary state
  - reports session runner capabilities and residual risks
- Capability reporting must include at least:
  - process tree containment
  - filesystem mount scope
  - network namespace or egress control status
  - loopback/private CDP exposure status
  - shell command enforcement status
  - cleanup status

Acceptance:

- Erebor can start a session using Docker/OCI.
- The agent process is launched by the session runner, not manually started as
  an unrelated local process.
- Session metadata is available to browser, shell, policy, and audit paths.
- The session runner reports what it can and cannot enforce.
- Docker/OCI implementation details do not leak into the universal session
  event schema except as session runner metadata/capabilities.

Current status:

- Implemented and accepted for the pilot runner gate: Docker/OCI runner in
  core, session metadata injection, workspace mount, governed browser endpoint
  injection, config-owned terminal TTY, and Linux ptrace process-guard
  enforcement for bounded diagnostics.
- Verified: core session planning tests and the Linux process guard unit wrapper
  pass locally.
- Follow-up, not blocking Phase 2: cleanup is requested with Docker `--rm` and
  side resources are dropped on command exit, but there is not yet an explicit
  cleanup verifier/report after process exit.
- Follow-up before buyer packaging: formal Docker/OCI runner capability report,
  including shell command enforcement status, cleanup status, and residual risk.
- Not part of the Phase 1 runner gate: Linux host OpenClaw enrollment,
  OpenClaw-specific launch/adoption presets, and approval UX for process
  decisions.

## Phase 2: Implement Linux Host OpenClaw Enrollment

Goal: govern an installed OpenClaw process on Linux without requiring a
Dockerized OpenClaw image.

Status: complete for the preferred relaunch path. The Linux host relaunch path
exists, attaches the ptrace process surface from process start, and was manually
verified with installed OpenClaw `2026.5.20 (e510042)` on June 11, 2026. The
weaker `adopt --pid` path exists for already-running processes when Linux
ptrace permissions allow attachment, but it has not yet been manually verified
against installed OpenClaw.

Public interface:

- Canonical relaunch path:

```bash
erebor session run --runner linux-host --config <path> -- openclaw
```

- Follow-up adoption path:

```bash
erebor session adopt --runner linux-host --config <path> --pid <pid>
```

- Current-process match adoption path:

```bash
erebor session adopt --runner linux-host --config <path> --match openclaw
```

This resolves exactly one already-running matching process from `/proc` and
then uses the same PID adoption path. It is not yet the future pre-armed
exec-time matcher described in the session-hypervisor plan.

- Optional buyer-friendly aliases may be added later, but they must compile to
  the same session request shape:

```bash
erebor-runtime govern pid <pid> --config <path>
erebor-runtime govern openclaw --config <path>
```

Implementation:

- Add a `linux-host` session runner in core, backed by Linux-specific helpers
  in the session crate.
- Support `session run --runner linux-host -- <agent>` for the strongest local
  demo path. This starts installed OpenClaw normally from the user's machine,
  but under Erebor session membership from the first process.
- Support `session adopt --runner linux-host --pid <pid>` for already-running
  OpenClaw. This attaches to the target process tree and governs future effects
  where the Linux backend can enforce them.
- Prefer `session run` or `adopt --match` for the governed demo if OpenClaw
  needs new environment variables or a new attach-only browser profile path,
  because `adopt --pid` cannot rewrite the environment of an already-running
  process.
- Reuse the existing Rust Linux ptrace process guard outside Docker:
  - recursively attach to the root process tree
  - trace `execve` and `execveat`
  - inherit governance to child processes
  - deny matching process attempts before exec completes
  - normalize attempts into the existing terminal/process event shape
- Add cgroup v2 membership where available so the host runner has a stable
  process-tree handle and capability report.
- Record residual risk for adopted sessions:
  - already-open sockets
  - already-open file descriptors
  - existing child processes that could not be attached
  - ptrace permission failures
  - Yama `ptrace_scope` restrictions
  - missing cgroup v2 support or write access
  - lack of socket/network enforcement if only ptrace is active
- Keep policy and audit shared with the browser CDP surface under the same
  session id.

Acceptance:

- Erebor can relaunch local commands under a Linux host governed session.
- OpenClaw-specific acceptance: installed OpenClaw is relaunched and can run
  under the same path.
- Follow-up acceptance: Erebor can adopt an already-running OpenClaw PID when
  Linux permissions allow ptrace attachment.
- Child processes launched by OpenClaw, shells, Node/Python helpers, or browser
  tooling remain in the governed process tree where the backend supports it.
- A direct unmanaged Chrome/Chromium launch with `--remote-debugging-port` is
  denied before exec completes.
- A Python or shell subprocess that attempts the same unmanaged browser launch
  is denied before exec completes.
- The session emits a capability report that distinguishes enforced controls
  from residual risks.
- The plan and demo docs clearly state that Linux host governance is not
  whole-device containment and cannot undo pre-adoption authority.

Current status:

- Implemented prerequisite: the Rust Linux ptrace process guard exists and is
  tested through the session crate.
- Implemented prerequisite: Docker/OCI sessions can mount and invoke the guard.
- Implemented: `linux-host` session runner relaunch, `session adopt --pid`,
  host process-guard wrapper, captured diagnostics, CLI runner selection,
  recursive host attach, best-effort cgroup membership, capability reporting,
  and local allow/deny/adopt tests.
- Verified on June 11, 2026: `openclaw --version` reports
  `OpenClaw 2026.5.20 (e510042)`.
- Verified on June 11, 2026:
  `session run --runner linux-host --config examples/governed-openclaw-pilot/session-config.json openclaw --version`
  relaunches installed OpenClaw under the Linux ptrace process guard and emits
  a session capability report.
- Implemented follow-up: `session adopt --match <text>` resolves exactly one
  currently running process and adopts its PID.
- Verified on June 14, 2026: CLI tests cover `--match` parsing, mutual
  exclusion with `--pid`, missing target rejection, and target construction;
  session-service tests cover unique current-process resolution, ambiguous
  matches, and no-match failure.
- Remaining polish: true pre-armed exec-time `adopt --match <rule>`, manual
  installed-OpenClaw adoption verification, and buyer-friendly OpenClaw host
  enrollment docs.

## Phase 3: Add Browser Surface To The Linux Host Session

Goal: prove installed OpenClaw can use an Erebor-owned browser from inside the
Linux host governed session.

Status: complete for the attach-only fallback proof and live managed-browser
mediation. This phase is complete because OpenClaw was governed as a Linux host
session member, consumed the session-governed CDP endpoint, navigated through
Erebor's governed CDP endpoint, listed real browser targets through Erebor's
discovery shim, hit an Erebor policy denial for a known high-risk script
payload, and then proved the preferred mediated managed-browser path with
OpenClaw's normal browser launch flow.

Implementation:

- Add an OpenClaw setup guide under `integrations/openclaw-ts/`.
- Document a session-injected profile equivalent to:

```json
{
  "browser": {
    "enabled": true,
    "defaultProfile": "erebor",
    "profiles": {
      "erebor": {
        "cdpUrl": "<session-governed-cdp-url>",
        "attachOnly": true
      }
    }
  }
}
```

- Start an Erebor-owned browser as a session side resource.
- For `session run --runner linux-host`, inject only the governed CDP endpoint
  into the OpenClaw session environment or config overlay.
- For `session adopt --pid`, do not assume new environment variables can be
  injected. Use an already-configured attach-only profile, a pre-armed
  `adopt --match` flow, or restart OpenClaw under `session run`.
- Verify OpenClaw connects to the governed endpoint, not Chrome's private
  DevTools endpoint.
- First try direct bare WebSocket attach to the governed CDP endpoint.
- Add a Chrome-style HTTP discovery shim only if direct attach fails or the
  client needs Chrome target discovery for tab operations.

Discovery shim rule:

- If needed, the shim may expose Chrome-compatible discovery endpoints such as
  `/json/version`.
- It must return only governed Erebor URLs.
- It must never expose the private owned-browser CDP URL.
- It must not add Erebor-specific query parameters or client requirements.

Acceptance:

- OpenClaw can connect to Erebor's governed endpoint from inside the session.
- OpenClaw can navigate a simple page through Erebor.
- A known denied CDP action produces a controlled failure.
- The private Chrome DevTools URL is not present in OpenClaw config, docs, or
  user-facing output.
- Browser actions include the session id created by the Linux host session
  runner.

Current status:

- Implemented: the session can start an Erebor-owned browser side resource and
  inject `EREBOR_BROWSER_CDP_URL` into Docker/OCI and Linux host sessions.
- Implemented: attach-only OpenClaw profile shape is documented and an example
  fixture exists.
- Implemented: the CDP runtime serves Chrome-style HTTP discovery endpoints
  such as `/json/version` and `/json/list` on the governed endpoint when
  clients need discovery. The shim mirrors real Chrome target metadata when
  available but rewrites every `webSocketDebuggerUrl` and DevTools frontend URL
  to the Erebor-governed endpoint.
- Verified on June 11, 2026: temporary OpenClaw config with
  `gateway.mode=local`, loopback token auth, and browser profile
  `cdpUrl=$EREBOR_BROWSER_CDP_URL`, `attachOnly=true`, `color=#00AA00`
  validates under OpenClaw `2026.5.20`.
- Verified on June 11, 2026: `openclaw browser ... status` reports
  `cdpUrl: ws://127.0.0.1:<erebor-port>` and does not expose Chrome's private
  `/devtools/browser/...` URL.
- Verified on June 11, 2026: `openclaw browser ... open https://example.com`
  succeeds through Erebor.
- Verified on June 11, 2026: `openclaw browser ... tabs` lists the real
  `Example Domain` target through Erebor's discovery shim.
- Verified on June 11, 2026: `openclaw browser ... evaluate --fn "() => {
  window.__erebor = 'owned-denied'; return window.__erebor; }"` fails after
  Erebor logs `blocking CDP command method=Runtime.callFunctionOn` with reason
  `OpenClaw pilot denied suspicious browser script payload`.
- Added Phase 3 reusable assets, later consolidated into the cleaned
  prompt-driven package under `examples/governed-openclaw-pilot/`.
- Verified on June 11, 2026: the attach-only fallback proof opened
  `https://example.com/`, listed real tabs through Erebor, and completed after
  the expected policy denial.
- Implemented: the mediated managed-browser path lets OpenClaw use a normal
  local managed browser profile without `cdpPort`.
- Implemented on June 14, 2026: the `managed_browser_cdp` broker handler now
  starts the governed browser CDP surface just in time when session
  interception routes a browser process launch and extracts
  `--remote-debugging-port=<port>`.
- Implemented on June 14, 2026: the workshop mediation config maps the
  requested public governed CDP port to a private owned Chrome upstream at
  requested port plus one. For example, OpenClaw request `1000` yields Erebor
  public CDP on `1000` and private Chrome CDP on `1001`.
- Verified on June 14, 2026: unit tests cover lazy broker startup on the
  requested port and the private requested-plus-one mapping.
- Verified on June 14, 2026: the live mediated-browser smoke ran with
  OpenClaw's default managed profile and no workshop-provided `cdpPort`;
  OpenClaw chose port `19132`, the shell wrapper reached the Erebor shim, Erebor
  returned governed endpoint `ws://127.0.0.1:19132/`,
  `https://example.com/` opened, tabs listed, and the expected eval was denied.
- Still not Phase 3 scope: OAuth consent-lab packaging belongs to Phase 5, and
  browser CDP session-audit output is handled by Phase 6.

## Phase 4: Add Bounded Shell/Process Diagnostics To The Session

Goal: show the same session can govern useful shell work, not just browser CDP.

Status: complete for the Linux host proof. Runtime plumbing is implemented for
Docker/OCI and Linux host relaunch. The reusable demo package now keeps the
raw-CDP denial diagnostic in
`examples/governed-openclaw-pilot/session-config.json` instead of a separate
Phase 4 script.

Implementation:

- Add a terminal/process session surface backed by the active session runner:
  Linux host for the preferred pilot path, Docker/OCI for fallback and CI.
- Provide a bounded diagnostic command set for the support-investigation demo,
  such as read-only log inspection, `grep`, `cat` of approved fixtures, `ls`,
  and a safe local repro/status command.
- Normalize shell attempts into runtime events with session id, actor, command,
  argv summary, working directory, target, risk, decision, and policy reason.
- Add policy for:
  - allowed read-only diagnostics
  - denied destructive commands
  - denied or approval-required direct browser launch attempts
  - denied or approval-required raw CDP probing attempts when the session
    runner or terminal surface can observe them
- Keep the trust boundary honest: a PTY is UX. The boundary is the Linux host
  session runner plus ptrace/cgroup capability for the preferred pilot, or
  Docker/OCI containment plus ptrace guard for the fallback path.

Acceptance:

- OpenClaw or the session demo agent can run safe read-only diagnostics while
  session interception observes child execution. Current slice: named
  diagnostics declared in session config run as guarded Docker and Linux-host
  session commands; direct raw-CDP launch attempts, shell-spawned child
  processes, and Python subprocess attempts are denied before the child exec
  completes.
- At least one risky shell/process action is denied or held before it completes.
- Shell audit records share the same session id as browser audit records.
- The demo README states which shell/process controls are hard-enforced by the
  active runner and which are cooperative, best-effort, or unimplemented.

Current status:

- Implemented: `host-support-diagnostic` reads approved OAuth lab fixtures and
  prints the lab event endpoint through the guarded Linux host session.
- Implemented: `host-shell-spawned-raw-cdp-browser-launch` attempts a raw CDP
  child process below `sh -lc` and is expected to be denied by terminal/process
  policy before exec completes.
- Packaged: the cleaned session config retains the raw-CDP child-process denial
  diagnostic for ad hoc checks.
- Verified on June 11, 2026: the Phase 4 proof printed the safe support
  diagnostic, then denied the raw-CDP child process with reason `unmanaged
  browser launch with raw CDP is denied`.
- Verified on June 14, 2026: automated Linux-host integration tests deny direct
  raw-CDP exec, shell-spawned raw-CDP child exec, Python `subprocess` raw-CDP
  child exec, and verification-required `git push` before the risky child
  action completes.
- Not Phase 4 scope: host-wide process governance outside the enrolled session
  process tree.

## Phase 5: Package The OAuth Denial Workflow

Goal: turn `examples/openclaw-oauth-click-lab/` into the browser half of the
first buyer-facing governed session demo.

Implementation:

- Add a governed session demo README or sub-section for the OAuth lab.
- Add a session runner config that uses the Linux host runner, launches or
  adopts installed OpenClaw, starts an Erebor-owned browser, enables bounded
  shell/process diagnostics, and writes registry-owned session audit output.
- Keep a Docker/OCI config as a fallback/CI smoke path if it remains useful.
- Add a demo policy that:
  - allows ordinary browser target management needed by OpenClaw
  - allows support-thread and repro browsing
  - allows visibility into navigation toward GitHub OAuth
  - denies the final high-risk OAuth authorization action
  - allows the safe shell diagnostics used in the story
  - denies or holds the selected risky shell action
- Prefer deterministic matching for the pilot over broad semantic
  classification.
- If the current CDP command payload lacks enough page URL/context to identify
  the consent action reliably, enrich the browser click/input event payload with
  the current page context already tracked by CDP state.

Acceptance:

- Ungoverned baseline can still reproduce the risk:

```text
repro_opened
oauth_authorize_redirect_started
oauth_callback_received
```

- Governed session allows the normal investigation path but prevents:

```text
oauth_callback_received
```

- Governed session also shows one useful shell diagnostic and one denied or
  held risky shell/process action.
- Browser state is not mutated by the denied browser action.
- The result is reproducible with throwaway GitHub OAuth app data.

Current status:

- Implemented: `examples/governed-openclaw-pilot/policy.json` allows local lab
  navigation/click/script actions and OpenClaw target management, denies the
  `owned-denied` smoke-test eval, and denies script/click actions whose current
  browser target is GitHub's OAuth authorize or login-return URL.
- Implemented: `session-config.json` starts the Linux host session with browser
  CDP enabled, session interception enabled, terminal process interception
  configured, and managed browser launch mediation configured.
- Implemented: policy fixtures prove allowed lab navigation, denied
  `owned-denied` browser eval, allowed OAuth authorize navigation visibility,
  denied OAuth authorize script action, denied OAuth authorize click action,
  denied OAuth login-return script action, and denied OAuth login-return click
  action without needing live GitHub credentials.
- Implemented: `preflight-lab.sh` starts the OAuth lab with a dummy
  client id, confirms the local support-thread/repro events, verifies the
  GitHub authorize redirect shape without following it, parses the generated
  OAuth state, and confirms the local callback records
  `oauth_callback_received` with `stateMatches=true`.
- Implemented: the manual runbook starts the OAuth lab, event watcher, audit
  watcher, and governed OpenClaw gateway as separate operator-visible steps.
  The buyer demo is not an all-in-one script; the operator pastes `prompt.txt`
  into the OpenClaw Control UI after the gateway prints readiness.
- Implemented: the developer regression path can feed `prompt.txt` into
  OpenClaw automatically and verify thread/repro/OAuth lab events with no
  `oauth_callback_received`. This validates plumbing, but it is not the stage
  demo.
- Implemented: `run-openclaw-gateway.sh` generates a simple OpenClaw config
  that enables the browser plugin and normal browser profile without setting
  `browser.cdpUrl` or an attach-only profile. It sets `browser.executablePath`
  to the executable path resolved from the ordinary `google-chrome` command
  inside the governed session, which resolves to the Erebor
  process-interception shim. Browser control is governed by the Erebor session
  process-interception shim and managed-browser CDP mediation.
- Implemented: `check-policy.sh` runs the complete deterministic Phase 5 policy
  fixture bundle.
- Implemented: the CDP observer enables `Fetch.requestPaused` for document
  requests in observed page targets, routes those observed network requests
  through policy, continues allowed requests, and fails denied or
  approval-required callback requests with `BlockedByClient`.
- Verified on June 11, 2026: `policy test` allows
  `fixtures/oauth-lab-navigation-event.json` with rule
  `allow-oauth-lab-navigation` and denies
  `fixtures/oauth-authorize-script-event.json` with rule
  `deny-github-oauth-authorize-script-action`.
- Verified on June 14, 2026: `policy test` denies
  `fixtures/openclaw-owned-denied-script-event.json` with rule
  `deny-openclaw-owned-denied-script`.
- Verified on June 17, 2026: `check-policy.sh` allows
  `fixtures/oauth-authorize-navigation-event.json` with rule
  `allow-github-oauth-navigation-visibility` and denies
  `fixtures/oauth-authorize-click-event.json` with rule
  `deny-github-oauth-authorize-click`. This also fixed the lab-navigation allow
  rule to match the navigation target URI instead of any previous-page payload
  text.
- Verified on June 17, 2026: `check-policy.sh` also denies
  `fixtures/oauth-login-return-script-event.json` with rule
  `deny-github-oauth-login-return-script-action` and
  `fixtures/oauth-login-return-click-event.json` with rule
  `deny-github-oauth-login-return-click`.
- Verified on June 17, 2026: the previous lower-level OpenClaw browser CLI proof
  ran installed OpenClaw through the governed mediated-browser session, reached
  `thread_opened`, `repro_opened`, and `oauth_authorize_redirect_started`, and
  denied the GitHub OAuth login-return browser script action with no
  `oauth_callback_received`. That proved the browser enforcement path but was
  not the final buyer demo because it did not feed OpenClaw a task prompt.
- Verified on June 17, 2026: the automated developer regression path fed
  `prompt.txt` through OpenClaw. OpenClaw opened the support thread, opened
  `/repro`, clicked `Connect GitHub`, reached GitHub's OAuth login-return path,
  hit Erebor denials for GitHub login-return browser evals, posted a
  reproduction reply to the thread, and the lab recorded no
  `oauth_callback_received`.
- Verified on June 17, 2026: the full visible Control UI demo was rerun with
  `GITHUB_CLIENT_ID` set to a real throwaway OAuth app. The operator connected
  to `ws://127.0.0.1:19123` with token auth, approved the one-time Control UI
  device pairing, created a new OpenClaw dashboard session, pasted
  `prompt.txt`, and sent it through the OpenClaw Control UI. The run printed
  `[erebor] Chrome launch mediated -> ws://127.0.0.1:19134/`, then lab events
  `thread_opened`, `repro_opened`, and `oauth_authorize_redirect_started`.
  GitHub redirected toward
  `http://127.0.0.1:5105/oauth/callback?code=...&state=...`; Erebor failed the
  observed `Fetch.requestPaused` document request with
  `OAuth callback handoff must not reach the local callback without operator
  approval`, and `curl http://127.0.0.1:5105/events` confirmed no
  `oauth_callback_received` event.
- Verified on June 17, 2026: `preflight-lab.sh` passes against the local
  OAuth lab. The default sandbox blocked binding `127.0.0.1:5105` with
  `listen EPERM`, so the verification was rerun with local-listener approval;
  it confirmed `thread_opened`, `repro_opened`,
  `oauth_authorize_redirect_started`, and `oauth_callback_received` with
  matching OAuth state.
- Verified on June 17, 2026: prior OAuth-lab attempts/tests were consulted.
  The ungoverned OpenClaw baseline in
  `examples/openclaw-oauth-click-lab/README.md` records
  `oauth_callback_received code=redacted stateMatches=true error=null`; the
  governed session audit records OpenClaw reading the OAuth prompt/events
  endpoint through the session and raw-CDP process-launch attempts being denied.
- Verified on June 14, 2026: the previous `oauth-lab-fixtures` diagnostic ran
  through the mediated session config under actor `openclaw` and printed the
  approved lab prompt plus events endpoint.
- Verified on June 17, 2026: the previous `oauth-lab-fixtures` diagnostic
  succeeded under the mediated session config, and
  `oauth-risky-raw-cdp-browser-launch` failed closed with the expected
  `unmanaged browser launch with raw CDP is denied unless routed through an
  Erebor mediation shim` reason. Host cgroup creation was reported as residual
  risk because the local environment denied `/sys/fs/cgroup` writes.
- Implemented: `prompt.txt` and `README.md` document the ungoverned baseline,
  governed prompt-driven run, expected lab events, setup, troubleshooting, and
  non-claims.

## Phase 6: Add Shared Browser/Process Session Audit

Goal: make the governed session explain itself with durable browser and process
audit records under one session id.

Status: implemented for the pilot evidence gate. Terminal/process JSONL audit
uses the registry-owned session audit path under
`.erebor/sessions/<session-id>/`, and browser CDP command/event decisions
append JSONL records to that same session artifact. The visible OpenClaw
runbook reads the audit path from session metadata so the demo can show
terminal `process_exec` mediation and browser `browser_cdp` allow/deny
decisions under one session id.

Implementation:

- The pilot session config controls audit filtering, not audit storage:

```json
{
  "audit": {
    "surfaces": {
      "terminal": {
        "command_level": "signal",
        "debug_commands": ["sleep"]
      },
      "browser_cdp": {
        "command_level": "signal",
        "debug_commands": []
      }
    }
  }
}
```

- `erebor-runtime-session` derives the audit path from the session registry and
  passes that private session storage to eager and lazy browser CDP surfaces.
  This covers the OpenClaw managed-browser path, where Chrome launch mediation
  starts the browser CDP surface just in time.
- `erebor-runtime-cdp` records browser CDP enforcement outcomes to the
  registry-owned session JSONL artifact for governed sessions.
- Browser command decisions, Fetch/network-request decisions, and CDP observer
  state-recovery records use the registry-owned session artifact. Terminal/process
  guard decisions continue using the same session audit path.
- `command_level="signal"` records all non-allow decisions and allowed commands
  unless they match that surface's `debug_commands`. The default terminal
  debug list includes `sleep`. Set a surface to `command_level="all"` or clear
  `debug_commands` when a harmless-looking command needs investigation.
- Runtime-side filtering is implemented as a generic `FilteredAuditSink<S>`
  wrapper over the `AuditSink` trait; JSONL is only the current file-backed
  inner sink, and future ClickHouse/Datadog/object-storage sinks can use the
  same filter boundary.
- Demo docs now use:

```bash
SESSION_JSON=$(ls -t .erebor/sessions/*/session.json | head -1)
SESSION_ID=$(jq -r .session_id "$SESSION_JSON")
cargo run -p erebor-runtime-cli -- audit tail "$SESSION_ID"
```

Audit records shown during the call should include:

- session id
- actor id
- session runner
- session runner capability tier when relevant
- surface
- action
- target
- decision
- policy rule id
- CDP method or shell command summary
- denial reason
- relevant page/URL context when available

Runtime evidence-trace minimum fields that must be available from JSONL or
adjacent hashed artifacts:

| Report field | Source |
| --- | --- |
| Session id | `event.session_id` |
| Actor id and kind | `event.actor.id`, `event.actor.kind` |
| Surface | `event.surface` |
| Action | `event.action` |
| Target label/URI | `event.target.label`, `event.target.uri` |
| Risk level/reasons | `event.risk.level`, `event.risk.reasons[]` |
| Policy decision/reason/rule | `policy_decision.type`, `policy_decision.reason`, `policy_decision.rule_id` |
| Final decision | `final_decision.type` |
| Policy hash | SHA-256 of the policy file |
| Audit/report hash | SHA-256 of JSONL and rendered trace |

Acceptance:

- A denied OAuth callback network request writes a browser CDP JSONL audit
  record with `event.action="network_request"` and
  `final_decision.rule_id="deny-oauth-callback-network-request"`.
- Allowed navigation/target-management actions write browser CDP JSONL audit
  records when a sink is configured.
- Allowed and denied shell diagnostics continue writing terminal/process JSONL
  audit records.
- `audit tail <session-id>` can resolve and print the registry-owned shared file.
- Audit sink failures are reported with `tracing::warn!` and do not silently
  change policy decisions.
- Existing browser demos remain compatible when no JSONL audit path is
  configured because the CDP recorder is optional.
- If browser URL/resource provenance is missing, the README and call script
  downgrade the claim to process/raw-CDP authority-transition evidence only and
  do not pitch the run as a reviewer-ready personal-data workflow trace.

Verification:

- `cargo test -p erebor-runtime-cdp --lib`
- `cargo test -p erebor-runtime-session --lib`
- `cargo test -p erebor-runtime-audit`
- New regressions:
  `server::tests::client_text_appends_denied_command_audit_jsonl` and
  `server::tests::client_text_appends_allowed_command_audit_jsonl` prove
  blocked and forwarded CDP commands append JSONL audit records with browser CDP
  surface/action/decision fields.

## Phase 7: Add The Runtime Evidence Trace Report

Goal: turn the governed run into the approved buyer-facing "whoa" moment:
OpenClaw acts, Erebor blocks a risky authority transition, and the run becomes
a reviewer-ready runtime evidence trace.

Status: implemented for the pilot evidence gate. Phase 6 produces browser and
process audit records, and Phase 7 now renders them into a markdown evidence
trace through the Rust `erebor-runtime-audit` crate. The CLI exposes a thin
`audit evidence-trace` adapter for local file output; report generation and sink
abstractions live beside the JSONL audit log reader/writer so future senders can
target files, ClickHouse, Datadog, object storage, or a service worker without
moving logic into the CLI.

Implementation:

- Added `crates/erebor-runtime-audit/src/evidence_trace.rs` with:
  - `EvidenceTraceRequest` and `EvidenceTracePaths` for typed report inputs.
  - `MarkdownEvidenceTraceRenderer` for the v1 reviewer-ready markdown trace.
  - `EvidenceTraceSink` as the destination abstraction.
  - `FileEvidenceTraceSink` as the first sink.
  - SHA-256 artifact/report hashing without adding a network-fetched
    dependency.
- Added a thin CLI adapter:

```bash
cargo run -p erebor-runtime-cli -- audit evidence-trace "$SESSION_ID" \
  --prompt examples/governed-openclaw-pilot/prompt.txt \
  --out examples/governed-openclaw-pilot/evidence-trace.md
```

- The report includes:
  - executive summary
  - session purpose and actor
  - controlled surfaces and explicit non-claims
  - governed resources exposed
  - allowed action timeline
  - denied or held authority transitions
  - policy package, rule ids, and policy hash
  - residual risk
  - JSONL/report/config hashes
  - intended reviewers and retention recommendation
- Kept the v1 claim to governed resource/action provenance. It does not claim
  semantic PII classification, completed DPIA, legal sufficiency, or
  GDPR/HIPAA compliance.
- Added deterministic fixture input and rendered output:
  - `examples/governed-openclaw-pilot/fixtures/evidence-trace-audit.jsonl`
  - `examples/governed-openclaw-pilot/evidence-trace.fixture.md`
  - `examples/governed-openclaw-pilot/check-evidence-trace.sh`
- Updated `examples/governed-openclaw-pilot/README.md` to point from the OAuth
  denial to the rendered evidence trace.

Acceptance:

- A non-engineering DPO/privacy/GRC reviewer can understand the trace in under
  10 minutes.
- The trace shows session id, actor, purpose, policy hash, governed resources
  exposed, allowed actions, denied authority transitions, and residual risk.
- The trace labels controls as enforced, cooperative, observed, or deferred.
- The trace includes integrity hashes for the JSONL audit and policy artifacts.
- The trace explicitly says "no semantic PII classifier enabled" unless a later
  classifier exists.
- The trace can be generated from a deterministic fixture run if live GitHub
  OAuth data is unavailable.

Verification:

- `cargo test -p erebor-runtime-audit`
- `cargo test -p erebor-runtime-cli`
- `bash examples/governed-openclaw-pilot/check-evidence-trace.sh`

## Phase 8: Call Demo Package And Discovery Handoff

Goal: use the pilot demo to find the first real approval workflow that is
blocked today because teams cannot prove what an AI agent did near sensitive
data.

Phase 8 is not primarily another engineering phase. The manual demo runbook is
the proof artifact, and the runtime evidence packet is the buyer-facing
artifact to send after interest is confirmed. The next work is targeted
outreach, discovery calls, demo rehearsal under call pressure, and a repeatable
way to record whether the evidence trace changes a buyer's approval path.

### Buyer Hypothesis

The first sellable wedge is not "DPOs like audit logs" or "generic AI
governance teams like policy docs." The sharper hypothesis is:

```text
Agent vendors are losing, slowing, or weakening customer pilots because
security, GRC, legal, procurement, federal-contracting, or AI-platform
reviewers cannot see and prove the agent's browser/process actions, authority
transitions, and residual risk.
```

The demo should test whether Erebor's governed-session evidence trace changes
that review conversation for vendors whose agents browse, run commands, use
tools, access SaaS, or touch customer data.

The first call should not ask whether the contact likes the product. It should
ask whether they have a named blocked workflow, who blocks it, what evidence is
missing, and whether the trace would make approval easier.

Public offer:

```text
Erebor turns real AI-agent runs into runtime evidence packets for security,
GRC, and procurement review.
```

Use the open-source demo as the lead magnet:

- demo title: "From Agent Action To Reviewable Evidence"
- sample packet:
  `examples/governed-openclaw-pilot/runtime-evidence-packet.md`
- security-review copy:
  `examples/governed-openclaw-pilot/security-review-guide.md`
- validation plan:
  `docs/research/icp-validation-agent-vendors.md`

### Who To Reach First

Prioritize people close enough to blocked agent workflows to give concrete
evidence. Do not start with broad "AI governance" or "privacy thought leaders"
unless they can name a live approval process.

Priority 1: agent vendors selling computer-using or tool-using agents.

- Titles: `Founder`, `CTO`, `Head of Product`, `Product Security Lead`,
  `Security Engineering Manager`, `Head of AI Platform`.
- Why: they feel customer security and procurement pressure directly when an
  agent pilot needs proof of control.
- Best fit: vendors whose agents browse, run commands, use tools, access SaaS,
  operate internal systems, or touch customer data.

Priority 2: regulated enterprise AI/security platform people.

- Titles: `Head of AI Platform`, `AI Platform Lead`, `Product Security Lead`,
  `Security Engineering Manager`, `Staff Security Engineer`,
  `Responsible AI Lead`, `GRC Lead`.
- Why: they can validate whether runtime evidence would change internal
  deployment approval.
- Best fit: teams evaluating support agents, browser agents, internal ops
  agents, coding/DevOps agents, or SaaS-action agents near customer data.

Priority 3: government contractors and public-sector proposal teams.

- Titles: `Capture Manager`, `Proposal Manager`, `Federal Solutions Lead`,
  `Public Sector Product Lead`, `Compliance Lead`, `AI Governance Lead`.
- Why: they can say whether reusable AI-governance evidence packets would
  improve RFP responses or proposal quality.
- Best fit: teams answering NIST AI RMF-style AI governance questions or
  documenting contractor claims about AI systems.

Priority 4: privacy, GRC, support, success, and operations leaders with agent
pressure.

- Titles: `Data Protection Officer`, `Head of Privacy`, `Privacy Counsel`,
  `Privacy Engineering Manager`, `Head of Support`, `Support Engineering Lead`,
  `Revenue Operations Lead`, `Internal Tools Lead`.
- Why: they can validate reviewer language and identify the real blocker.
- Best fit: teams with tickets, customer debugging, account investigation, or
  internal admin actions near personal data.

Deprioritize for the first 20 calls:

- very large banks, insurers, and hospitals without a warm intro
- generic privacy, compliance, or AI-governance consultants who are not tied to
  a deployment, deal, bid, or procurement decision
- investors, analysts, and community accounts
- people whose only signal is "AI ethics" with no operational approval role

### LinkedIn Search Terms

Use manual LinkedIn searches and save people into a small tracking sheet.

Search title plus pain:

```text
"agent" "product security"
"agent platform" "enterprise security"
"browser agent" "security review"
"computer use" "AI agent" "enterprise"
"AI agent" "procurement"
"AI agent" "RFP"
"AI agent" "customer security"
"tool-using agent" "security"
"autonomous agent" "SaaS"
"AI agent" "GRC"
"AI governance" "agents"
"AI platform" "support agent"
```

Search by company profile:

```text
agent vendor + enterprise security
browser agent startup + customers
computer-use agent startup + enterprise
AI support agent vendor + regulated
AI coding agent vendor + enterprise
AI workflow agent vendor + SOC 2
government contractor + AI governance + RFP
public sector AI + proposal + NIST AI RMF
B2B SaaS + SOC 2 + AI agents
```

For every prospect, record:

- name
- title
- company
- segment: agent vendor, regulated enterprise, government contractor, or other
- likely workflow: support, internal SaaS/tool action, deployment, codebase
  operations, customer investigation, or unknown
- likely blocker: DPO/privacy, security, GRC, legal, AI platform, product team,
  procurement, federal contracting, or unknown
- reason this person might care
- outreach message sent
- response
- call outcome
- next step

### Outreach Positioning

Do not lead with "compliance platform" or "GDPR/HIPAA." That makes the product
sound like a legal claim before the buyer has admitted pain.

Lead with the blocked workflow:

```text
I am trying to understand whether agent vendors lose or slow customer pilots
because reviewers cannot see what the agent was allowed to do, what it actually
did, and what was blocked at runtime.
```

Then state the concrete wedge:

```text
I built a governed-session demo where OpenClaw follows a support-thread repro
into GitHub OAuth, Erebor blocks the callback handoff, and the run renders into
a reviewer-ready evidence trace.
```

Use different emphasis by audience:

- Agent vendors: evidence that can be attached to customer security reviews,
  AI governance reviews, or RFP appendices.
- DPO/privacy/GRC: approval evidence, governed resources exposed, denied
  authority transition, residual risk, non-claims.
- Security/product security: enforceable action path, browser/process
  provenance, bypass attempts, policy decision, shared audit stream.
- AI platform: a runtime boundary for agents, not another SDK-only integration.
- Support/ops/eng: a way to get useful agents approved for workflows that are
  currently too risky.

### LinkedIn Message Sequence

Connection note, agent vendor:

```text
Hi <name> - I am building Erebor, a runtime evidence layer for agents that
browse, run commands, or use tools. I am interviewing agent vendors about
customer security/RFP reviews. Open to a quick question?
```

Connection note, security or AI-platform:

```text
Hi <name> - I am working on runtime governance for AI agents that browse, run
commands, and hit OAuth/SaaS authority transitions. I am trying to learn how
security/AI-platform teams approve these workflows. Open to a quick question?
```

Connection note, government contractor or public-sector proposal:

```text
Hi <name> - I am researching how AI governance sections in RFPs are handled
when the system includes autonomous agents. I have a sample runtime evidence
packet and would value a quick sanity check.
```

After they accept:

```text
Thanks for connecting. Quick context: I am testing whether governed-session
evidence would help agent vendors answer customer security, AI governance, or
RFP review questions.

Have you seen an agent pilot, security review, or proposal get delayed because
reviewers lacked evidence of what the agent could do, what it did, or what was
blocked?
```

If they answer with a real process or blocker:

```text
That is exactly the workflow I am trying to understand.

I have a 6-minute demo: OpenClaw follows a support-thread repro into GitHub
OAuth, Erebor blocks the callback handoff, then produces a reviewer-ready
evidence trace showing allowed actions, denied authority transition, policy
rule, and residual risk.

Would you be open to a 20-minute call? I mostly want to know whether this trace
would change the approval conversation, not pitch you a deck.
```

If they accept but do not answer the question:

```text
Totally understand if this is not your lane. Is there someone on privacy,
security, GRC, procurement, federal contracting, or AI platform who reviews
agent workflows for customers or proposals? I am trying to talk to the person
who actually blocks or signs off.
```

Follow-up 1, after three to five business days:

```text
Quick follow-up. I am trying to learn whether agent projects are getting stuck
because teams cannot prove what the agent accessed, did, or was prevented from
doing.

If you have seen this approval problem, I would value 15-20 minutes. If not,
no worries.
```

Follow-up 2, final:

```text
Last note from me. The narrow question: would a browser/process evidence trace
for an AI-agent session help in a customer security review, AI governance
review, or RFP response, or would the workflow still be blocked?

Even a one-line "yes, maybe" or "no, not our blocker" would help.
```

Post-demo follow-up:

```text
Thanks again. My notes from the call:

- Blocked workflow: <workflow>
- Current approver: <approver>
- Missing evidence: <evidence>
- Trace field that mattered: <field>
- Still blocked by: <remaining blocker>

Did I capture that correctly? Also, who else would need to see this before a
pilot would be worth discussing?
```

### When To Demo

Do not lead the first cold message with a demo request. The first goal is to
identify whether they have lived the approval problem.

Demo when at least one of these is true:

- they name a specific blocked or delayed agent workflow
- they describe an approval process involving privacy, security, GRC, legal, or
  AI platform
- they ask what evidence the product produces
- they ask how Erebor differs from logging, DLP, browser isolation, or SDK-only
  guardrails
- they introduce or offer to introduce the approval owner

Skip or defer the demo when:

- they only say "interesting"
- they discuss AI governance abstractly with no deployed workflow
- they cannot identify who approves or blocks agents
- they want a generic product overview before naming a problem

### 20-Minute Call Script

Minute 0-2: frame.

```text
I am not trying to convince you Erebor is complete compliance software. I am
testing one question: when an AI agent operates near sensitive data, would a
governed-session evidence trace change the approval workflow?
```

Minute 2-7: discovery before demo.

Ask:

1. What agent workflow are you trying to sell, allow, or evaluate?
2. What data or authority makes it sensitive?
3. Who can block it?
4. What evidence exists today?
5. What evidence is missing?

Minute 7-14: demo.

Show only the strongest path:

1. OpenClaw starts normal support work.
2. OpenClaw launches Chrome normally and Erebor mediates the launch.
3. The support thread drives the agent into GitHub OAuth.
4. Erebor blocks the OAuth callback handoff.
5. The shared audit and evidence trace show action provenance, policy decision,
   denied authority transition, and residual risk.

Minute 14-19: approval test.

Ask:

1. Would this have changed the approval answer for the workflow you named?
2. Which part of the trace matters most?
3. Which missing field would still block approval?
4. Who else would need to review this?
5. If this worked for your workflow, what would a pilot need to cover?

Minute 19-20: next step.

Ask for one concrete next action:

- a second call with the actual approver
- a real workflow to model in the demo
- permission to send the evidence trace for review
- a technical validation call with security, GRC, procurement, federal
  contracting, or AI platform

### Signal Scoring

Run 20 validation conversations:

- 12 agent vendors
- 5 regulated enterprise AI/security platform people
- 3 government-contractor or public-sector bid/proposal people

Strong signal:

- names a specific blocked or delayed workflow
- names the approval owner
- says the trace would change or shorten the review
- asks for the sample runtime evidence packet
- wants their workflow modeled
- introduces security, GRC, procurement, privacy, legal, AI platform, or
  federal-contracting reviewer
- says the packet would shorten review or improve bid quality

Medium signal:

- agrees the problem exists but cannot name a current workflow
- asks technical questions but does not own approval
- wants to see the demo but gives no internal path
- says the trace is useful but cannot say who would use it

Weak signal:

- says "interesting" only
- talks about governance abstractly
- redirects to generic compliance content
- cannot name a blocker, workflow, or owner
- wants updates but no call or introduction

Continue with the agent-vendor ICP if at least 5 of 20 conversations produce
strong signal, or at least 2 agent vendors offer a real workflow for a
design-partner pilot.

Pivot toward government contractors only if RFP/proposal teams say they would
pay for reusable AI-governance evidence packets before agent vendors do.

Pivot toward enterprise AI platform only if internal deployment blockers are
more urgent than vendor sales blockers.

### What To Capture After Each Call

Add one note per call with:

```text
Contact:
Company:
Role:
Workflow discussed:
Sensitive data or authority:
Current status quo:
Who blocks or approves:
Evidence they have today:
Evidence missing:
Trace field that mattered:
Still-blocking concern:
Budget owner:
Next step:
Signal score: strong / medium / weak
```

### Phase 8 Acceptance

- The manual demo README can be followed under call pressure.
- At least 40 targeted LinkedIn prospects are identified across the four
  priority groups above.
- At least 20 personalized connection or DM attempts are sent.
- The 20-conversation validation target is tracked as 12 agent vendors,
  5 regulated enterprise AI/security platform people, and 3
  government-contractor or public-sector bid/proposal people.
- Outreach copy is revised after ten non-responses in a row.
- Every call records the workflow, approver, missing evidence, trace reaction,
  and next step.
- At least one prospect names a real workflow that could become a design
  partner pilot.
- The call script does not claim GDPR/HIPAA compliance, semantic PII-read
  proof, legal sufficiency, or whole-device containment.

## Implementation Order

1. Finish this docs plan and cross-link it from related plans.
2. Preserve the implemented Docker/OCI runner as fallback/CI validation. Done
   for the pilot runner gate.
3. Implement the Linux host session runner with `session run --runner
   linux-host`. Done for runtime plumbing and installed-OpenClaw relaunch.
4. Wire the existing Rust Linux ptrace process guard to the Linux host relaunch
   runner. Done and verified through the Phase 4 process proof.
5. Implement Linux host `session adopt --pid`. Done for runtime plumbing.
   Current-process `session adopt --match <text>` is implemented as a resolver
   to the same PID adoption path; true pre-armed exec-time matching remains
   future session-hypervisor work.
6. Add cgroup v2 membership and host-runner capability/residual-risk reporting.
   Done as best-effort Linux-host guard behavior.
7. Add OpenClaw host browser setup documentation and manually verify connection
   through the governed CDP endpoint. Done for the Phase 3 attach-only proof;
   mediated managed-browser packaging is now the primary workshop path.
8. Package the ungoverned OAuth baseline plus governed Linux-host OpenClaw run
   using the mediated browser config by default. Done for fixtures/runbook;
   live throwaway OAuth validation remains.
9. Add runtime JSONL audit config and shared browser/process sink wiring for
   browser CDP records. Done for the pilot evidence gate.
10. Add the reviewer-ready evidence-trace renderer or manual report template.
    The v1 trace should be markdown or HTML generated from one governed run,
    with JSONL and policy/config hashes.
11. Add tests for session config parsing, Linux host plan construction, ptrace
    allow/deny, audit path resolution, JSONL records, evidence-trace report
    fields, and Docker fallback.
12. Verify the existing Playwright CDP demo still passes.
13. Run the full installed-OpenClaw governed-session pilot end to end.
14. Run the call script with the reviewer-ready evidence trace and record
    whether the trace changes the approval conversation.

## Test Plan

Rust checks for later implementation:

```bash
cargo fmt
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Browser validation:

```bash
cargo run -p erebor-runtime-cli -- start --config examples/playwright-cdp-demo/runtime-config.json
cd examples/playwright-cdp-demo
npm run smoke
```

Session pilot validation:

```bash
GITHUB_CLIENT_ID=<client-id> node examples/openclaw-oauth-click-lab/lab.mjs
openclaw
cargo run -p erebor-runtime-cli -- session run --runner linux-host --config <pilot-session-config.json> -- openclaw
cargo run -p erebor-runtime-cli -- session adopt --runner linux-host --config <pilot-session-config.json> --pid <openclaw-pid>
```

Use the first `openclaw` command only for the ungoverned baseline. Reset the lab
and authorization state before the governed run. For the governed run, prefer
`session run --runner linux-host` when the demo needs Erebor to provide a fresh
attach-only profile or `EREBOR_BROWSER_CDP_URL`; use `session adopt --pid` only
when OpenClaw was already configured to use the governed endpoint.

Then verify:

- support thread opens
- repro opens
- GitHub OAuth navigation is visible
- OAuth authorization is blocked
- callback is not received
- safe shell/process diagnostic succeeds
- risky shell/process action is denied or held
- audit JSONL contains browser and shell decisions with the same session id
- evidence trace renders purpose, actor, governed resources exposed, allowed
  actions, denied authority transitions, policy hash, residual risk, and
  integrity hashes
- evidence trace states that semantic PII classification is not enabled unless
  a later classifier exists

Linux host session runner validation:

- installed OpenClaw starts under `session run --runner linux-host`
- an already-running OpenClaw PID can be adopted when ptrace permissions allow
- child processes are attached or reported as residual risk
- session metadata is injected
- governed CDP endpoint is reachable from the agent
- private Chrome CDP endpoint is not exposed to the agent
- safe shell/process command runs under the session
- denied shell/process command does not complete
- session runner capability report is emitted
- cleanup detaches/stops only processes owned by the session and revokes
  temporary browser profile/endpoints

Docker/OCI fallback validation:

- container starts with the requested workspace scope
- guarded diagnostics still work through the Docker-wired process guard
- Docker fallback does not regress while Linux host support is added

Runtime evidence-trace validation:

- report generation works from the registry-owned JSONL audit path
- report includes only review-safe summaries by default, with raw JSONL as an
  attachment for technical review
- report downgrades the claim if browser URL/resource provenance is missing
- report includes policy/config/audit/report hashes
- report labels controls as enforced, cooperative, observed, or deferred
- report can be read without understanding CDP internals

## Risks

- OpenClaw may require HTTP discovery even though direct bare WebSocket attach
  appears likely to work.
- `session adopt --pid` may be weaker than `session run` because it cannot
  rewrite an already-running process environment or undo pre-existing authority.
- Linux ptrace attachment may be blocked by Yama `ptrace_scope`, permissions,
  user namespaces, or distro security policy.
- Host process governance without network hooks can deny risky process launches
  but cannot honestly claim complete raw-CDP socket blocking.
- GitHub UI changes may make a click-specific deny brittle.
- If the browser click payload lacks enough current page context, the pilot may
  need a small CDP state enrichment before policy can target the consent action.
- Linux host governance can prove installed-agent process governance, but it
  should not be overclaimed as whole-device governance.
- Runtime JSONL audit wiring must not accidentally make audit write failures
  change enforcement outcomes.
- The first demo could still be overclaimed. The README and call script must
  clearly separate Linux host session enforcement, Docker/OCI fallback
  enforcement, future macOS/Windows/Kubernetes runners, MCP, and OS-wide
  governance.
- The evidence trace could imply more privacy certainty than v1 supports. It
  must say "governed resources exposed" rather than "all PII read" until
  semantic classification exists.
- The DPO might be the approval stakeholder rather than the budget owner. The
  call package must capture whether security, AI platform, legal, GRC, or the
  product team owns deployment and budget.

## Explicit Defaults

- First pilot story: support investigation using the GitHub OAuth consent lab
  plus bounded shell diagnostics, rendered as a runtime evidence trace from
  shared browser/process audit records.
- First client: OpenClaw.
- First pilot session runner: Linux host bare-metal for installed OpenClaw.
- Fallback/CI session runner: Docker/OCI.
- First browser surface: Erebor-owned browser CDP started just in time when
  OpenClaw's normal managed-browser launch is intercepted, with attach-only
  profile as the fallback proof.
- First process surface: terminal/process `process_exec`, backed by the Linux
  ptrace process guard for bounded read-only diagnostics plus one denied or held
  risky command.
- First audit sink: local JSONL file shared by browser and shell records.
- First buyer-facing report: markdown or HTML runtime evidence trace generated
  from the governed session's JSONL audit plus hashed policy/config artifacts.
- First denial style: deterministic policy rules, not full semantic
  classification.
- First product boundary claim: governed session runner, not browser-only
  wrapper and not host-wide OS guard.
- First privacy/compliance claim: reviewable governed resource/action
  provenance and residual risk, not GDPR/HIPAA compliance or semantic proof of
  every PII value read.
