# OpenClaw TypeScript Integration

This folder is reserved for the first agent UX integration.

The integration should live where users interact with an agent. It should make
erebor policy visible and actionable by showing governed session status,
active policy packages, approval prompts, denial reasons, and audit references.

It must not become the enforcement layer. Enforcement belongs in the
erebor-runtime data plane and its controlled execution surfaces.

## Pilot Managed-Browser Shape

The governed OpenClaw pilot uses OpenClaw as the agent inside one Erebor
session. Linux host relaunch is the preferred pilot runner for installed
OpenClaw; Docker/OCI remains the fallback/CI runner. OpenClaw should receive
only session-injected governed endpoint descriptors.

OpenClaw `2026.5.20` validates both gateway and browser profile shape. The
preferred workshop path lets OpenClaw use a normal local managed-browser
profile while Erebor mediates the Chrome/Chromium launch and owns the governed
CDP listener on the requested port:

```json
{
  "gateway": {
    "mode": "local",
    "bind": "loopback",
    "port": 19121,
    "auth": {
      "mode": "token",
      "token": "erebor-pilot-token"
    }
  },
  "browser": {
    "enabled": true,
    "defaultProfile": "openclaw",
    "headless": true
  }
}
```

Rules:

- OpenClaw uses its normal local managed browser profile and chooses its own
  debugging port during browser launch.
- Erebor starts the governed CDP surface just-in-time when the process guard
  intercepts the attempted Chrome/Chromium launch.
- If OpenClaw requests port `1000`, the workshop config starts Erebor-governed
  CDP on `1000` and the private owned Chrome upstream on `1001`.
- OpenClaw should not receive Chrome's private DevTools endpoint.
- OpenClaw config is adoption/UX wiring, not the security boundary.
- Browser and shell actions must share the same Erebor session id and audit
  stream.
- OpenClaw browser CLI parent options come before the subcommand, for example:
  `openclaw browser --url ws://127.0.0.1:19121 --token erebor-pilot-token --browser-profile openclaw status`.

## Attach-Only Fallback

If host browser launch mediation is blocked by the local environment, use a
temporary local gateway plus attach-only browser profile:

```json
{
  "gateway": {
    "mode": "local",
    "bind": "loopback",
    "port": 19121,
    "auth": {
      "mode": "token",
      "token": "erebor-pilot-token"
    }
  },
  "browser": {
    "enabled": true,
    "defaultProfile": "erebor",
    "profiles": {
      "erebor": {
        "cdpUrl": "<session-governed-cdp-url>",
        "attachOnly": true,
        "headless": true,
        "color": "#00AA00"
      }
    }
  }
}
```

Fallback rules:

- `cdpUrl` points to the Erebor-governed CDP endpoint for the active session.
- The governed pilot session exposes that endpoint to the agent as
  `EREBOR_BROWSER_CDP_URL`.
- The private Chrome DevTools endpoint is never written into OpenClaw config.
- OpenClaw config is adoption/UX wiring, not the security boundary.

See `examples/governed-openclaw-pilot/` for the current Linux host proof,
Docker/OCI fallback smoke example, and profile fixture.
