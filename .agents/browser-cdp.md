# Browser And CDP Governance Rules

## Boundary Model

The browser/CDP runtime is the first proof surface for the universal governance
architecture. It must be a real enforcement path, not just an SDK helper.

The desired trust model is:

- Erebor launches or owns the browser session.
- Agents receive only an Erebor-governed endpoint.
- The private Chrome DevTools endpoint is internal state.
- Future terminal/process governance prevents direct browser launches.
- Future socket/network governance prevents direct connections to raw DevTools
  ports and similar bypasses.

Do not reintroduce custom public CDP query tokens such as `erebor_session`.
For client compatibility, the public CDP WebSocket should look like a normal CDP
endpoint. If HTTP discovery is added later, it must emulate Chrome discovery
semantics rather than adding Erebor-specific client requirements.

## Protocol Handling

- Use `cdp-protocol` typed commands and events wherever possible.
- Manual JSON is acceptable for JSON-RPC envelope fields such as `id`,
  `sessionId`, generic forwarding, and CDP shapes not exposed by the protocol
  crate.
- Do not create parallel hand-written protocol models when `cdp-protocol`
  already represents the command or event.
- Govern `Target.*` management commands too. Browser-level clients rely on
  target discovery, attach, detach, and session multiplexing.

## Browser State Authority

Browser state must outlive a client WebSocket. A client can disconnect and
reconnect, so command history is not authoritative.

The target design is:

- Erebor observes the browser-level DevTools endpoint.
- `Target.setDiscoverTargets` and `Target.setAutoAttach` track tabs, popups,
  frames, workers, and new windows.
- Browser events are the source of truth.
- Forwarded client commands are provisional hints for UX only.
- Snapshot calls such as `Page.getFrameTree` are bootstrap and recovery tools,
  not continuous polling.

Before changing state behavior, read
[docs/browser-state-authority-plan.md](../docs/browser-state-authority-plan.md)
and
[docs/plans/browser-governance/browser-level-cdp/README.md](../docs/plans/browser-governance/browser-level-cdp/README.md).

## Playwright And Browser-Use Validation

Playwright and browser-use are validation clients, not agent UX integrations.
They prove the governed CDP endpoint behaves like a browser-level endpoint.

The Playwright demo acceptance criterion is:

```sh
cargo run -p erebor-runtime-cli -- start --config examples/playwright-cdp-demo/runtime-config.json
cd examples/playwright-cdp-demo
npm run smoke
```

The demo must connect through Erebor's public governed endpoint, drive an
Erebor-owned browser, and prove a suspicious script action is denied without
mutating browser state.

Do not require extra Playwright-specific configuration for the default demo.
Environment variables may be optional overrides, not required integration
surface.

## OpenClaw And Agent Integrations

OpenClaw, Codex, Claude Code-like tools, browser agents, MCP clients/servers,
and custom agents are untrusted clients unless their actions pass through an
Erebor-controlled execution path.

Agent integrations should live in this repo when they are Erebor UX/adoption
work. They do not all need to be Rust. Choose the best language for the agent
ecosystem, but keep enforcement in the runtime path.
