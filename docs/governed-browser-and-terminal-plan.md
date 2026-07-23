# Governed Browser And Terminal Plan

This plan expands the browser, OpenClaw, Playwright validation, terminal
governance, and endpoint governance work that sits across Milestones 4, 5, 7,
and 9 in `docs/development-plan.md`.

The core decision is:

- Erebor owns the browser or browser session.
- Agents receive only Erebor-governed endpoints.
- SDKs and agent integrations improve UX, but are not enforcement boundaries.
- Process and endpoint governance close the bypass paths that would let an
  agent launch its own browser or connect directly to a DevTools endpoint.

## Session Hypervisor Dependency

The universal session model, session runner abstraction, enforcement tiers,
and platform-specific command execution model are owned by
[`docs/plans/session-hypervisor/README.md`](plans/session-hypervisor/README.md).

This browser and terminal plan consumes that model for CDP, OpenClaw,
Playwright, BrowserUse/browser-use, endpoint bypass, and terminal/process
validation. It should not define a separate `run`, `govern`, container, or OS
guard model.

Managed browser launch mediation is owned by
[`docs/plans/managed-browser-launch-mediation/README.md`](plans/managed-browser-launch-mediation/README.md).
That plan turns the existing "block, mediate, or intercept" rule into a
configurable terminal/process surface feature routed through session
interception: when an agent attempts a Chrome or Chromium raw-CDP launch,
Erebor can start an owned browser and expose only a governed compatibility CDP
listener on the requested port.

## Governed OpenClaw Pilot Dependency

The first pilot implementation slice is owned by
[`docs/plans/governed-openclaw-pilot/README.md`](plans/governed-openclaw-pilot/README.md).
That pilot originally proved the first session runner mechanics with Docker/OCI,
then shifted the active buyer-demo path to Linux host bare-metal so Erebor can
govern an already-installed OpenClaw process. Future stages in this document
should treat Docker/OCI as the implemented fallback/CI runner while preserving
the session-hypervisor contract for Linux host, macOS/Windows host,
Kubernetes, and stronger sandbox session runners.

Terminology alignment:

- Docker/OCI, bare metal, Kubernetes, and microVMs are session runners.
- Browser CDP, terminal/process execution, endpoint checks, and future MCP work
  are governed session surfaces inside one session.
- The session runner owns session lifecycle and process membership. Surfaces do
  not launch independent sessions; they attach/register governed effect paths
  against the runner-owned session.
- This plan must not describe browser CDP or terminal work as a separate
  runtime beside the session runner.

Docker/OCI and Linux host command-interception posture:

- Docker/OCI is different from bare metal because Erebor creates the container,
  controls the root process, workspace mount, network mode, environment, labels,
  and side-resource endpoints before the agent starts.
- `session run --runner docker -- <agent>` is session enrollment. It starts the
  agent inside the runner; it is not the terminal governance boundary and should
  not policy-check the agent launch argv as if it were an agent-issued shell
  command.
- Docker cgroups provide process membership, resource accounting/control, and a
  stable handle for the session process tree. Cgroups do not by themselves
  intercept every `execve` or shell child process inside the container.
- Container namespaces, seccomp profiles, AppArmor/SELinux, read-only mounts,
  dropped capabilities, and network modes improve containment, but they are not
  a complete command-policy interceptor by themselves.
- The current Docker/OCI and Linux-host pilot uses the session-owned Linux
  ptrace interception backend when `session.interception` enables
  `process_exec`, with terminal `process_interception` registered as the
  routed surface handler. The low-level process guard observes `execve` and
  `execveat` attempts from the session process tree, including shell children
  and Python subprocesses, and can deny or fail-closed verification-required
  attempts before the child exec completes.
- Terminal/process policy should use the same policy document shape as CDP
  policy. For command execution, prefer `command_contains` for command/argv
  matching; keep `payload_contains` as a compatibility fallback.
- The active governed OpenClaw pilot should reuse that Linux ptrace process
  guard outside Docker through a Linux host session runner. The host runner is
  responsible for launching or adopting installed OpenClaw, preparing the
  session interception backend for the session process tree, registering the
  terminal/process surface handler, adding cgroup v2 membership where
  available, and reporting residual risk for pre-existing sockets, file
  descriptors, children, missing permissions, and missing network hooks.
- Stronger production hardening may still add seccomp user notification where
  supported, eBPF/LSM hooks on Linux hosts, or a sidecar/runtime hook that
  mediates process creation. Until those exist, the honest claim is
  Linux-ptrace-guarded session process execution plus the active runner's
  reported capability: Docker/OCI containment for Docker sessions, or host
  process adoption/launch without whole-device containment for Linux host
  sessions.

## Verified Browser Facts

OpenClaw has two browser modes that matter for Erebor:

- Managed local browser launch. OpenClaw builds Chrome args with
  `--remote-debugging-port` and `--user-data-dir` in
  [`chrome.ts`](../openclaw/extensions/browser/src/browser/chrome.ts). That path
  can create an ungoverned CDP endpoint unless Erebor owns the launch.
- Remote or attach-only CDP. OpenClaw can attach to an existing CDP endpoint via
  `browser.profiles.<name>.cdpUrl` and `attachOnly: true`, documented in
  [`browser.md`](../openclaw/docs/tools/browser.md).
- Playwright is a browser automation framework, not the agent UX integration.
  OpenClaw uses Playwright over CDP through `chromium.connectOverCDP` in
  [`pw-session.ts`](../openclaw/extensions/browser/src/browser/pw-session.ts).

The first OpenClaw integration should use the attach-only path: Erebor launches
the browser, OpenClaw attaches to Erebor, and OpenClaw never receives the real
browser CDP endpoint.

## Threat Model

The agent, its plugins, subprocesses, generated scripts, and browser automation
libraries are untrusted clients unless they act through an Erebor-controlled
execution path.

Primary bypasses to close:

- direct `chrome` or `chromium` launch with `--remote-debugging-port`
- direct Playwright launch via Node, Python, or wrapper binaries
- direct `connectOverCDP` to a real browser endpoint
- direct HTTP requests to `/json/version`, `/json/list`, or tab WebSocket URLs
- wrapper commands that hide browser launch or CDP connection behavior
- remote CDP endpoints not declared in policy
- spawned terminals that escape the governed session

## Stage Rules

The stages are ordered by trust dependency.

- Stage 1 can use a fake upstream or a manually launched browser to prove CDP
  parsing, forwarding, denial, approval, and audit behavior. That is protocol
  validation, not a trusted governed browser session.
- From Stage 2 onward, browser automation validation must use an Erebor-owned
  browser session. If Playwright or BrowserUse/browser-use navigates through
  Erebor in an acceptance test, that test belongs after Erebor owns the browser.
- OpenClaw integration starts only after Erebor-owned browser sessions and
  browser automation validation are working.
- Process and endpoint governance are required before claiming real bypass
  resistance. Cooperative SDK/config integration alone is not a trust boundary.

## Stage 0 - Evidence And Boundary Mapping

Goal: prove how each agent/browser path works before adding enforcement.

Detailed artifact:

- [`stage-0-browser-boundary-map.md`](stage-0-browser-boundary-map.md)

Current status:

- OpenClaw and Playwright are mapped from local source.
- BrowserUse/browser-use remains a Stage 0 gap until source or a concrete demo
  dependency is added.

Deliverables:

- Map OpenClaw managed-browser launch code paths.
- Map OpenClaw remote-CDP and attach-only profile behavior.
- Map Playwright launch, launch-persistent-context, and connect-over-CDP paths.
- Map BrowserUse/browser-use browser startup and CDP attachment behavior before
  Stage 3 validation.
- List direct browser, terminal, and network bypasses.
- Document which bypasses are block-only and which can be safely mediated.

Acceptance:

- The plan names every known route from agent code to browser control.
- The plan separates agent UX integration from enforcement.
- The plan has enough detail to write e2e tests against real binaries.

## Stage 1 - CDP Enforcement Primitive

Goal: prove that the CDP runtime can enforce decisions on the wire. This stage
may use fake upstreams and a manually provided Chrome endpoint. It does not yet
claim that Erebor owns the browser.

Deliverables:

- Typed CDP command/event handling through `cdp-protocol` where possible.
- CDP proxy tests for allowed, denied, and approval-required commands.
- Audited `Forward`, `Block`, and `AwaitApproval` decisions.
- Tests proving blocked commands are not forwarded upstream.
- Bounded timeouts and diagnostics so real-browser tests do not hang for many
  minutes.
- Clear split between fast fake-upstream tests and later real-Chrome tests.

Acceptance:

- Suspicious `Runtime.evaluate` can be blocked or paused.
- Harmless navigation can be forwarded.
- Audit records include actor, session, action kind, target, decision, and
  source CDP method.
- The docs and examples do not describe this stage as full browser ownership.

## Stage 2 - Erebor-Owned Browser Sessions

Goal: make Erebor the browser owner before any real browser automation client
validation.

Deliverables:

- Browser session manager in the CDP/browser session surface service.
- Erebor-owned Chrome launch with isolated `user-data-dir`.
- Private real CDP endpoint that is never handed to agents or SDK clients.
- Public governed endpoint with session auth.
- Session metadata: actor, agent, workspace, policy set, browser profile,
  approval channel, audit sink.
- Endpoint lease, shutdown, and cleanup model.
- Optional visible/headless mode in config.
- Real Chrome e2e tests using the Erebor-owned browser.

Acceptance:

- `erebor start` starts the configured CDP/browser session surface service.
- A governed browser session can be created through the runtime API.
- The client receives only the governed endpoint.
- The real CDP endpoint is treated as internal state.
- A real Chrome instance can be driven through Erebor's governed endpoint.
- Blocked commands do not mutate browser state.

## Stage 3 - Browser Automation Client Validation

Goal: validate Erebor-owned browser sessions against real browser automation
clients before integrating with OpenClaw UX.

Status: Playwright validation example added; BrowserUse/browser-use validation
is still pending.

Prerequisite:

- Complete browser-level CDP governance in
  [`docs/plans/browser-governance/browser-level-cdp`](plans/browser-governance/browser-level-cdp/).
  A page-level CDP proxy is not enough for honest Playwright or
  BrowserUse/browser-use validation because those clients expect browser-level
  target management and flat-session CDP behavior.

Deliverables:

- Playwright demo and smoke tests that connect only to Erebor's governed CDP
  endpoint.
- BrowserUse/browser-use demo and smoke tests that connect only to Erebor's
  governed CDP endpoint.
- Tests that prove direct connection to the real Chrome endpoint is not part of
  the governed flow.
- Documentation of client-specific limits, especially Playwright behavior when
  connected through CDP.

Acceptance:

- Playwright can navigate through Erebor's owned browser session.
- BrowserUse/browser-use can navigate through Erebor's owned browser session.
- Suspicious script execution is denied or requires approval in both clients.
- Validation clients are still described as test clients, not agent UX
  integrations.

Implementation notes:

- `examples/playwright-cdp-demo/` contains an owned-browser surface config,
  a Playwright-specific smoke policy, and a TypeScript smoke script that uses
  `chromium.connectOverCDP` only against Erebor's governed endpoint.
- The Playwright smoke script accepts the governed CDP endpoint directly and
  refuses raw Chrome `/devtools/browser/...` or `/devtools/page/...` URLs.
- BrowserUse/browser-use validation remains blocked until a matching example is
  added.

## Stage 4 - Local Control Plane

Goal: make policies, approvals, sessions, runtime status, and audit visible
before the OpenClaw UX integration depends on them.

Deliverables:

- Local self-hosted server APIs for sessions, policy packages, runtime status,
  approvals, and audit browsing.
- Minimal Web UI for active sessions, governed endpoints, pending approvals,
  denied actions, installed policy packages, and recent audit records.
- Session creation API that can return governed endpoint descriptors without
  exposing private runtime endpoints.
- Policy validation errors before a governed session starts.

Acceptance:

- A user can see active browser sessions and pending approvals.
- A user can approve or deny browser actions from the UI.
- Audit records show forwarded, denied, and approval-required browser actions.
- Session APIs expose only governed endpoint information.

## Stage 5 - Cooperative OpenClaw Integration

Goal: make OpenClaw use Erebor-owned browser sessions without pretending the SDK
or config integration is a security boundary.

Deliverables:

- OpenClaw config overlay that sets a browser profile to `attachOnly: true`.
- OpenClaw `cdpUrl` points to Erebor's governed endpoint.
- Erebor session metadata is visible in the OpenClaw UX integration.
- Deny and approval-required events can be shown where the user is interacting
  with the agent.
- Documentation for local development and self-hosted use.

Acceptance:

- OpenClaw can operate a browser through Erebor's endpoint.
- OpenClaw does not need the real browser CDP endpoint.
- OpenClaw denial and approval UX is clear.
- The integration docs state that process and endpoint governance are still
  needed for real trust.

## Stage 6 - Governed Agent Session Runner

Goal: give agents an execution environment where Erebor can inject endpoints and
track subprocesses.

Architecture dependency:

- Use the session lifecycle and session runner contract from
  [`docs/plans/session-hypervisor/README.md`](plans/session-hypervisor/README.md).
- This stage validates that browser and terminal surfaces can join a session
  created by the hypervisor. It should not define a second runner architecture.

Deliverables:

- Session runner that starts an agent under Erebor supervision.
- Docker/OCI is the implemented runner proof for this surface. The active
  governed OpenClaw pilot runner is Linux host bare-metal so installed OpenClaw
  can be launched or adopted under Erebor supervision. Later runtimes must
  consume the same session hypervisor contract.
- Agent process launch with governed endpoints supplied in the same endpoint
  field the client already accepts.
- Per-session working directory, policy set, audit sink, and approval channel.
- Process tree tracking.
- Clear lifecycle: create session, attach agent, start surfaces, stop session,
  cleanup browsers and endpoints.

Acceptance:

- An agent started inside a governed session discovers the Erebor browser
  endpoint without seeing the real CDP endpoint.
- The same session model can later host terminal, MCP, API, SaaS, desktop, and
  internal-system surfaces.
- The runner does not claim kernel-level bypass resistance yet.

## Stage 7 - Endpoint Governance

Goal: prevent direct connections to side-door endpoints.

Architecture dependency:

- Use the session runner capability report from the session hypervisor plan to
  decide whether raw CDP and network endpoint blocking is enforced, adopted, or
  cooperative for the active session runner.
- Linux, macOS, container, and Kubernetes enforcement mechanics belong in the
  session hypervisor plan. This stage defines the browser/CDP endpoint behavior
  those session runners must support.

Acceptance:

- A governed agent cannot connect directly to the real Chrome CDP endpoint.
- Attempts to call `/json/version`, `/json/list`, or direct tab WebSocket URLs
  are denied or require approval.
- Endpoint decisions are audited through the shared audit format.

## Stage 8 - Terminal And Process Governance

Goal: prevent direct browser launches and high-risk commands such as commits,
pushes, deployments, destructive file operations, or credential access unless
policy allows or the user approves.

Architecture dependency:

- Use the command lifecycle and backend-specific enforcement model from
  [`docs/plans/session-hypervisor/README.md`](plans/session-hypervisor/README.md).
- Use `session.interception` as the backend owner and route `process_exec`
  decisions to the terminal/process surface; terminal policy is the semantic
  owner, not the low-level backend owner.
- This stage owns the browser/terminal policy cases: direct browser launch,
  direct Playwright launch, command approval, shell escape, and unsafe workflow
  transitions.

Acceptance:

- `git commit` can require user approval inside a governed terminal session.
- Direct Chrome/Chromium launches can be denied or require approval.
- Node/Python browser automation wrappers are either denied, approved, or forced
  through Erebor-owned endpoints.
- Every process decision includes actor, session, command, argv summary, working
  directory, decision, and policy reason.

## Cross-Stage Rule - Block, Mediate, Or Intercept

Default behavior should be block with an actionable explanation.

Mediation is useful when Erebor can preserve user intent safely. For example,
if an agent tries to start a browser, Erebor may create an Erebor-owned browser
session and return the governed endpoint through the approved session channel.

Transparent interception should be avoided until the behavior is explicit in
policy and visible in audit logs. Rewriting a browser launch into a different
endpoint without telling the user can hide important state and make debugging
hard.

Acceptance:

- Each policy rule declares whether it denies, requires approval, or allows
  mediation.
- Mediated actions create audit records for the original attempted action and
  the replacement Erebor-owned action.

## E2E Test Matrix

Fast tests:

- fake CDP upstream
- policy matching
- audit JSONL
- runtime supervisor
- CLI config parsing

Real browser tests:

- Chrome launched by Erebor
- Playwright connected to Erebor
- BrowserUse/browser-use connected to Erebor
- suspicious `Runtime.evaluate` denied or approval-gated
- harmless navigation forwarded

OpenClaw tests:

- OpenClaw attach-only profile points at Erebor.
- OpenClaw browser actions pass through Erebor.
- OpenClaw does not require the real CDP endpoint.

Bypass tests:

- direct Chrome launch inside governed session
- direct Playwright launch inside governed session
- direct Node/Python CDP connection to real browser endpoint
- direct `/json/version` or tab WebSocket access
- wrapper command that hides a browser launch

Session backend integration tests:

- browser and terminal bypass tests run against the initial session hypervisor
  backend
- backend capability report says whether endpoint and process blocking are hard
  enforced, adopted, or cooperative
- browser/terminal claims match the active backend capability report

## Initial Policy Package Examples

Initial policy packages should include:

- browser-basic-safety: deny dangerous `Runtime.evaluate`, allow navigation to
  approved origins, audit input events.
- browser-cdp-endpoint-safety: deny direct access to real CDP endpoints from
  governed sessions.
- openclaw-governed-browser: require OpenClaw attach-only profile and Erebor
  endpoint.
- terminal-approval: require approval for `git commit`, `git push`,
  deployments, destructive file operations, and credential access.
- terminal-browser-bypass: deny unmanaged Chrome/Chromium and Playwright browser
  launches inside governed sessions.

## Open Decisions

- Which Docker/OCI capability tier is honest for the first browser + terminal
  proof, especially around loopback endpoint exposure, network egress, and
  process-launch mediation.
- How to represent mediated actions in the protocol.
- How much endpoint authentication is required for local-only development.
- Whether real-Chrome e2e tests are manual, nightly, or default CI.
- How OpenClaw config overlays are applied without mutating user config
  unexpectedly.

## External References

- Playwright BrowserType API:
  <https://playwright.dev/docs/api/class-browsertype>
