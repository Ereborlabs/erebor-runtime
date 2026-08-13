# Browser And CDP Governance Rules

Read the applicable browser plan from the [plan map](README.md#plan-map) and
the relevant example README before changing browser/CDP behavior.

## Enforcement Boundary

Browser/CDP is the first proof surface for universal action governance. Erebor
must own the browser session; clients receive only an Erebor-governed endpoint.
The private Chrome DevTools endpoint is internal state. Future process and
network governance must prevent direct browser launches and raw DevTools-port
bypasses.

The public WebSocket must look like a normal CDP endpoint. Do not add
Erebor-specific public query tokens such as `erebor_session`. If HTTP discovery
is added, emulate Chrome discovery semantics.

## Protocol And State

- Use `cdp-protocol` commands and events whenever they cover the needed shape.
  Restrict manual JSON to JSON-RPC envelopes, generic forwarding, and genuine
  crate gaps. Do not create a parallel protocol model.
- Govern `Target.*` management commands, including discovery, attach, detach,
  and session multiplexing.
- Browser events are authoritative state. Enable target discovery and automatic
  attachment to track tabs, popups, frames, workers, and windows.
- Client commands are provisional UX hints. Browser state must survive a client
  WebSocket disconnect; snapshots such as `Page.getFrameTree` are bootstrap or
  recovery tools, not continuous polling.

## Client Acceptance

Playwright and browser-use are validation clients, not special integration
surfaces. The default Playwright demo must connect through the public governed
endpoint, drive an Erebor-owned browser, and prove that a denied suspicious
script does not mutate browser state.

Do not require Playwright-specific configuration for the default demo.
Environment variables may be optional overrides. Follow the real-browser
acceptance and blocked-host reporting rules in [verification.md](verification.md).

## Agent Integrations

OpenClaw, Codex, Claude Code-like tools, browser agents, MCP clients/servers,
and custom agents are untrusted until they act through the Erebor-controlled
execution path. Integrations may use the ecosystem's appropriate language, but
they must not become the enforcement boundary.
