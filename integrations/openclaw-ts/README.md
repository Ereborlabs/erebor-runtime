# OpenClaw TypeScript Integration

This folder is reserved for the first agent UX integration.

The integration should live where users interact with an agent. It should make
erebor-runtime policy visible and actionable by showing governed session status,
active policy packages, approval prompts, denial reasons, and audit references.

It must not become the enforcement layer. Enforcement belongs in the
erebor-runtime data plane and its controlled execution surfaces.

## Pilot Attach-Only Shape

The governed OpenClaw pilot uses OpenClaw as the agent inside one Erebor
session. Docker/OCI is the first session runtime. OpenClaw should receive only
session-injected governed endpoint descriptors.

The browser profile must use OpenClaw's attach-only CDP path:

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

Rules:

- `cdpUrl` points to the Erebor-governed CDP endpoint for the active session.
- The private Chrome DevTools endpoint is never written into OpenClaw config.
- OpenClaw config is adoption/UX wiring, not the security boundary.
- Browser and shell actions must share the same Erebor session id and audit
  stream.

See `examples/governed-openclaw-pilot/` for the current Docker/OCI session
runtime smoke example and profile fixture.
