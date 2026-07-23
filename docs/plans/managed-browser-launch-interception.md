# Managed Browser Launch Interception Plan

Plan type: architecture, implementation, and validation plan.

Status: approved and partially implemented.

Related plans:

- [`docs/plans/session-hypervisor/README.md`](../session-hypervisor/README.md)
- [`docs/governed-browser-and-terminal-plan.md`](../../governed-browser-and-terminal-plan.md)
- [`docs/plans/governed-openclaw-pilot/README.md`](../governed-openclaw-pilot/README.md)
- [`docs/plans/process-interception-control-channel/README.md`](../process-interception-control-channel/README.md)
- [`docs/plans/browser-governance/browser-level-cdp/README.md`](../browser-governance/browser-level-cdp/README.md)

## Summary

Add configurable process launch interception to the terminal/process surface,
with `decision=mediate` for managed browser CDP launch as the first concrete
configured outcome.

When an enrolled agent process attempts to launch Chrome or Chromium with a raw
CDP port, Erebor should be able to preserve the agent's intent without allowing
an unmanaged browser:

```text
agent process -> chrome --remote-debugging-port=1000
terminal/process surface detects a configured process intent
policy/config decides allow, deny, require approval, or mediate
the configured replacement surface handles the safe substitute
Erebor binds a governed Chrome-compatible CDP listener on 127.0.0.1:1000
Erebor launches private Chrome CDP upstream on 127.0.0.1:1001
agent connects to the requested port and reaches only Erebor-governed CDP
```

This makes OpenClaw simpler because it can use its normal managed-browser path
instead of a special attach-only profile, while the enforcement boundary still
belongs to the Erebor session.

## Product Claim

The feature should support this claim:

- If an agent inside a governed session tries to create a browser CDP endpoint,
  Erebor can convert that launch into an Erebor-owned governed browser endpoint
  or fail closed.

The feature must not claim:

- host-wide browser launch control outside the enrolled session
- full raw-CDP bypass prevention without endpoint/network governance
- invisible rewriting with no policy/audit trail
- that ptrace alone can safely emulate a successful Chrome process for every
  client

## Design Decision

Use explicit interception decisions, not silent rewriting.

The session should make the behavior visible in config, policy, and audit:

- original attempted process launch is audited
- policy decision is `mediate`
- replacement governed endpoint is audited
- requested compatibility endpoint is audited
- CDP actions through that endpoint are governed by browser CDP policy

Transparent interception is only acceptable when the config explicitly enables
it and the audit log records what happened.

## Why Ptrace Alone Is Not Enough

The current Linux ptrace process guard can observe `execve` and `execveat` and
deny before the child gains authority. That is enough to block unmanaged raw
CDP browser launches.

It is not, by itself, a clean way to make the calling agent believe Chrome
started successfully while actually substituting a managed browser. Preserving
that UX requires one of:

- a session-injected browser launch shim
- a runner-controlled mount/PATH overlay that routes Chrome launches to the shim
- a stronger future exec-substitution backend

For the first implementation, use shim aliases plus the single Linux process
guard binary:

- shim aliases invoke `erebor-linux-process-guard`; the same guard uses
  configured interception handlers to choose `allow`, `deny`, or `mediate`
- process guard denies direct real Chrome launches that bypass the shim
- browser CDP surface owns the real browser and governed listener

## Architecture

```text
Session
  runner: linux_host first, Docker/OCI later
  surfaces:
    terminal/process
      - process guard
      - process interception config
      - shim/overlay preparation
      - process-launch policy event
    browser_cdp
      - owned browser allocator
      - governed CDP endpoint
      - requested-port compatibility listener
  shared:
    policy
    audit
    approval state
    session control broker
```

The terminal surface owns detection and launch interception. The browser CDP
surface owns browser allocation and CDP serving. The current implementation
uses the Erebor-owned session control broker to allocate requested-port browser
leases lazily inside one session. If an intercepted launch requests port
`1000`, Erebor can bind the governed CDP listener on `127.0.0.1:1000` and
launch the private owned Chrome upstream on a separate configured port such as
`127.0.0.1:1001`.

## Proposed Config Shape

Add a terminal-surface process interception block. The config is intentionally
handler-based so future decisions can route other process intents, not just
Chrome/CDP:

```json
{
  "surfaces": {
    "terminal": {
      "enabled": true,
      "tty": true,
      "process_guard": {
        "enabled": true,
        "backend": "linux_ptrace"
      },
      "process_interception": {
        "enabled": true,
        "mode": "shim",
        "handlers": [
          {
            "id": "managed-browser-cdp",
            "decision": "mediate",
            "kind": "managed_browser_cdp",
            "match": {
              "executables": [
                "google-chrome",
                "chrome",
                "chromium",
                "chromium-browser"
              ],
              "required_args": ["--remote-debugging-port"],
              "require_remote_debugging_port": true
            },
            "requested_endpoint": {
              "source": "remote_debugging_port",
              "bind": "127.0.0.1",
              "allowed_ports": [9222]
            },
            "replacement": {
              "surface": "browser_cdp",
              "private_endpoint": {
                "port_strategy": "requested_plus_offset",
                "port_offset": 1
              }
            },
            "compatibility": {
              "print_devtools_listening_line": true,
              "keepalive": true
            }
          }
        ]
      }
    },
    "browser_cdp": {
      "enabled": true,
      "listen": "127.0.0.1:0",
      "browser": {
        "headless": true
      }
    }
  }
}
```

Config semantics:

- `enabled=false` preserves current behavior.
- `mode=shim` is the first implementation mode.
- each handler chooses a `decision`; v1 implements `allow`, `deny`, and
  `mediate`, with `mediate` currently implemented for
  `kind=managed_browser_cdp`.
- `replacement.surface` must reference an enabled `browser_cdp` surface for
  `managed_browser_cdp`.
- `allowed_ports` is optional. If present, interception fails closed for other
  requested ports.
- `replacement.private_endpoint.port_strategy=requested_plus_offset` launches
  the owned private browser CDP upstream at `requested_port + port_offset`.
  With offset `1`, a requested public governed port of `1000` uses private
  Chrome port `1001`.
- `bind` must default to `127.0.0.1`; wildcard binds such as `0.0.0.0` should
  require explicit policy.
- `browser_cdp.listen=127.0.0.1:0` means the browser CDP surface is a lazy
  launch template; the actual governed listener binds to the intercepted
  requested port.

## Proposed Policy Shape

Add a policy decision that can represent mediation:

```json
{
  "id": "mediate-managed-browser-launch",
  "match": {
    "surface": "terminal",
    "action": "process_exec",
    "command_contains": "--remote-debugging-port"
  },
  "decision": "mediate",
  "mediation": {
    "kind": "managed_browser_cdp",
    "return_endpoint": "requested_port"
  },
  "reason": "raw browser CDP launches are converted to Erebor-owned governed CDP"
}
```

If policy returns `deny`, the launch fails closed with an actionable message.
If policy returns `require_approval`, the first implementation should fail
closed until terminal approval UX exists. If policy returns `mediate`, the
terminal surface asks the browser CDP surface to allocate the replacement.

## Runtime Flow

1. `session run --runner linux-host -- openclaw` starts the agent inside one
   governed session.
2. Session side-resource startup enables browser CDP and terminal/process
   surfaces.
3. Terminal surface prepares a browser launch shim directory and prepends it to
   `PATH`.
4. Terminal surface injects common browser executable environment variables
   where useful, such as `CHROME_PATH`, `BROWSER`,
   `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH`, and
   `PUPPETEER_EXECUTABLE_PATH`, all pointing to the shim.
5. Process guard receives deny/fail-closed rules for direct real Chrome raw-CDP
   launches that bypass the shim.
6. OpenClaw or another agent launches `google-chrome
   --remote-debugging-port=1000`.
7. The shim parses the attempted launch and validates it against the configured
   interception handler.
8. The shim sends an interception request to the session broker.
9. The broker evaluates the configured handler and asks the browser CDP surface
   to allocate or reuse a requested-port browser lease dynamically.
10. The shim prints a Chrome-like `DevTools listening on ...` line when enabled
    and stays alive until the session or parent launch is terminated.
11. The agent connects to `127.0.0.1:1000`, hits Erebor's governed CDP listener,
    and browser CDP policy applies to all browser actions.
12. Audit records the original launch attempt, interception decision, replacement
    endpoint, owned browser lease, and later CDP decisions.

## Compatibility Listener

The requested-port listener must look like Chrome CDP:

- `GET /json/version`
- `GET /json/list`
- `GET /json`
- browser-level WebSocket paths such as `/devtools/browser/<id>`
- direct WebSocket attach where supported

Every returned URL must point to the governed listener. The private Chrome
DevTools endpoint must never appear in responses, logs intended for agents, or
OpenClaw-visible config.

## Shim Contract

The shim should be a configured invocation mode of `erebor-linux-process-guard`,
not shell glue and not a second standalone executable. The session creates
browser executable aliases such as `google-chrome` that symlink to
`erebor-linux-process-guard`; the guard decides whether to run as the ptrace
supervisor or handle the configured interception decision from its config and
`argv[0]`.

Responsibilities:

- parse Chrome/Chromium argv
- extract `--remote-debugging-port`
- reject or ignore dangerous args according to session config
- validate against the session-provided handler table
- send an IPC request over the session control channel
- print Chrome-compatible startup output if configured
- keep the process alive while the browser lease is active
- in a future cleanup phase, release the lease or notify the broker on
  SIGTERM/SIGINT.

The shim should not:

- launch real Chrome itself
- evaluate policy locally
- expose the private Chrome endpoint
- silently fall back to unmanaged Chrome

## Enforcement Boundary

For Linux host v1:

- hard boundary: relaunched session process tree plus Linux ptrace process guard
- interception path: session-injected shim plus brokered lazy governed CDP
  listener on the requested port
- bypass handling: direct real Chrome raw-CDP launches are denied by process
  guard
- residual risk: absolute-path launches may bypass PATH shims unless the client
  honors injected executable env vars or the runner provides a mount/exec
  overlay

For Docker/OCI v2:

- mount the shim over known Chrome executable paths inside the container when
  configured
- bind the requested compatibility listener inside the container namespace or
  expose it through the session network path
- keep the same broker and browser CDP allocation semantics

For future stronger Linux host backends:

- use a mount namespace or exec-substitution backend to cover absolute
  `/usr/bin/google-chrome` launches more transparently
- add endpoint/network governance so direct raw-CDP socket connections are
  blocked or redirected by session policy

## Implementation Phases

### Phase 0: Evidence And Contract

- Confirm OpenClaw managed-browser launch behavior:
  - executable resolution
  - whether it honors `CHROME_PATH`, `BROWSER`, or config executable path
  - whether it polls `/json/version` or parses `DevTools listening on`
  - process lifetime expectations
- Confirm Playwright/Puppeteer launch compatibility expectations.
- Decide the first guaranteed path for OpenClaw:
  - PATH shim only
  - injected executable env var
  - OpenClaw config executable override, if available

Acceptance:

- The plan names exactly how OpenClaw will reach the shim.
- The fallback when OpenClaw uses an absolute executable path is documented.

### Phase 1: Config And Policy Model

Status: implemented for generic `process_interception.handlers[]` with
`managed_browser_cdp` as the first handler.

- Add config structs for `terminal.process_interception`.
- Add validation:
  - interception requires terminal enabled
  - interception requires browser CDP enabled
  - requested bind must be loopback unless explicitly allowed
  - `mode=shim` is the only supported first mode
- Add policy decision `mediate` with mediation metadata.
- Ensure old configs continue to load unchanged.

Acceptance:

- Existing configs behave the same when interception is absent.
- Invalid interception configs fail with clear errors.
- Policy fixtures can produce `mediate` for raw-CDP browser launch attempts.

### Phase 2: Session Broker And Browser Lease API

Status: implemented for Linux-host shim mediation and lazy browser CDP surface
startup.

- Add a session-local broker that surfaces can use during `session run`.
- Add a browser CDP lease API:
  - create or reuse owned browser
  - create requested-port governed compatibility listener
  - return public governed endpoint metadata
  - release lease
- Keep browser CDP private endpoint internal.

Acceptance:

- Unit tests can allocate a browser lease using a fake browser/CDP surface.
- Requested port conflicts fail closed with actionable diagnostics.

### Phase 3: Browser Launch Shim

Status: implemented for Linux host relaunch with PATH/env shim injection using
the single `erebor-linux-process-guard` binary.

- Add configured interception handling to the Rust Linux process guard binary.
- Prepare shim directory during session side-resource startup.
- Inject PATH and browser executable env vars for the session runner.
- Wire shim requests to the session broker so browser CDP can allocate a lazy
  requested-port governed listener.
- Ensure the shim never launches unmanaged Chrome.

Acceptance:

- `google-chrome --remote-debugging-port=1000` inside a governed session reaches
  the shim.
- The browser CDP surface creates a governed compatibility listener on
  `127.0.0.1:1000`, and the private Chrome upstream uses the configured
  separate port.
- `/json/version` on `127.0.0.1:1000` exposes only governed URLs.

### Phase 4: Process Guard Bypass Denial

Status: implemented for generated shim allow rules plus policy-derived
terminal deny/approval rules.

- Keep direct real Chrome raw-CDP launches denied unless they are the configured
  shim path.
- Add process guard rule generation that distinguishes:
  - allowed shim launch
  - denied direct real Chrome launch
  - denied suspicious wrapper launch if it hides raw-CDP args
- Audit bypass attempts with residual-risk language.

Acceptance:

- Launching the configured shim is allowed.
- Launching `/usr/bin/google-chrome --remote-debugging-port=9222` directly is
  denied unless a future overlay backend is explicitly enabled.

### Phase 5: OpenClaw Pilot Integration

Status: the governed OpenClaw pilot example now consolidates this mediation path
into the visible Control UI OAuth demo package.

- Add a new example config:
  `examples/governed-openclaw-pilot/session-config.json`.
- Add a runbook:
  `examples/governed-openclaw-pilot/README.md`.
- Start installed OpenClaw normally through:

```bash
GITHUB_CLIENT_ID=<throwaway-oauth-app-client-id> \
bash examples/governed-openclaw-pilot/start-visible-demo.sh
```

- OpenClaw should use its normal managed-browser path.
- Erebor should mediate Chrome launch and provide the requested CDP port.
- OAuth denial policy should still block the high-risk consent action.
- The demo should show the mediation line before the OAuth denial story, rather
  than hiding both behind an automated `openclaw agent --message` run.

Acceptance:

- OpenClaw no longer needs the attach-only profile for the primary demo path.
- OpenClaw reports or uses the requested CDP port, but that port is governed by
  Erebor.
- The private Chrome endpoint is never exposed.
- The current attach-only path remains available as a fallback.

### Phase 6: Audit And Buyer Demo Polish

- Add buyer-readable audit records:
  - original browser launch command
  - policy decision `mediate`
  - replacement governed endpoint
  - compatibility listener port
  - CDP allow/deny decisions
- Update demo docs and troubleshooting.

Acceptance:

- The demo can show one session audit trail for:
  - OpenClaw starting
  - Chrome launch interception
  - normal browsing
  - OAuth denial
  - risky process denial

## Tests

Fast tests:

- config parsing for enabled/disabled interception
- invalid interception config errors
- policy `mediate` decision parsing
- shim argv parsing for `--remote-debugging-port=9222`
- shim rejects unsupported binds and unsafe args
- fake broker lease lifecycle
- compatibility discovery response never exposes private Chrome endpoint

Linux host tests:

- PATH shim is first in session environment
- configured shim launch is allowed
- direct real Chrome raw-CDP launch is denied
- requested port conflict fails closed
- process audit records original and mediated action

Browser/CDP tests:

- client connects to requested port and reaches governed CDP
- `/json/version` and `/json/list` return governed URLs
- denied `Runtime.callFunctionOn` does not reach private Chrome

OpenClaw tests:

- installed OpenClaw starts through Linux host runner
- OpenClaw managed-browser path reaches the shim or configured executable
- OpenClaw can open a page through the requested CDP port
- OAuth authorize action is denied through the browser CDP surface

Regression tests:

- existing attach-only OpenClaw path still works
- existing Playwright CDP demo still works
- configs without interception behave unchanged

## Risks And Mitigations

- Risk: OpenClaw launches Chrome by absolute path.
  Mitigation: Phase 0 must prove executable resolution. If absolute path is
  unavoidable, v1 requires an OpenClaw executable override or documents the
  limitation; v2 can use runner-controlled mount overlays.

- Risk: agent connects directly to another raw CDP endpoint.
  Mitigation: this feature only mediates launches. Endpoint/network governance
  remains required for broader bypass resistance.

- Risk: compatibility listener accidentally exposes private Chrome URL.
  Mitigation: reuse the governed discovery rewriting rules and add regression
  tests.

- Risk: requested port is already in use.
  Mitigation: fail closed by default. Do not silently choose another port unless
  config explicitly allows an alternate and the client can receive it.

- Risk: shim behavior diverges from Chrome enough to break clients.
  Mitigation: implement only the startup and CDP discovery contract clients
  actually use; validate with OpenClaw before claiming support.

## Approval Gate

Before implementation, approve or change these decisions:

- v1 uses a Rust shim plus process-guard denial, not ptrace-only exec
  substitution.
- v1 targets Linux host relaunch first.
- v1 binds the governed compatibility listener on the requested loopback CDP
  port and fails closed if unavailable.
- v1 keeps attach-only OpenClaw as fallback until managed launch interception is
  verified end-to-end.
