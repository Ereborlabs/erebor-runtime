# Playwright CDP Validation Demo

This folder contains a browser automation validation demo for the CDP
enforcement surface.

Playwright is useful here as a real CDP client. It is not an agent UX
integration, and it is not the enforcement boundary. The boundary is still the
Erebor-owned browser session and the governed endpoint that Playwright receives.

## Owned Browser Smoke

Start Erebor with the demo config:

```sh
cargo run -p erebor-runtime-cli -- start \
  --config examples/playwright-cdp-demo/runtime-config.json
```

Policy paths in `runtime-config.json` are resolved relative to the config file,
so the same command works with an absolute `--config` path from another current
directory.

The runtime launches its own browser and logs a `browser_cdp=ws://...`
endpoint. Use that exact governed endpoint for the Playwright smoke script. Do
not leave the `...` placeholder in the command.

```sh
cd examples/playwright-cdp-demo
npm install
npm run smoke
```

The smoke script uses `chromium.connectOverCDP` against Erebor only. It fails
fast if the endpoint looks like a raw Chrome `/devtools/browser/...` or
`/devtools/page/...` endpoint.
It defaults to `ws://127.0.0.1:3738/`, matching `runtime-config.json`. Set
`EREBOR_CDP_ENDPOINT` only if you change the demo listen address.

The script validates:

- Playwright can connect to the governed CDP endpoint.
- Playwright can navigate an Erebor-owned browser target.
- A suspicious `Runtime.evaluate` payload is denied by policy.
- The denied script does not mutate browser state.

## Policy Files

- `playwright-smoke-policy.json` is denial-focused so the smoke script receives
  a controlled CDP error instead of waiting on an approval path.
- `browser-policy.json` keeps the earlier approval-focused policy for manual
  CDP experiments.

## Validation Boundary

This demo proves Playwright can operate through Erebor's public governed
endpoint. It does not prove bypass resistance by itself. Process and endpoint
governance are still required to prevent a client from launching its own browser
or connecting directly to a raw Chrome DevTools endpoint.
