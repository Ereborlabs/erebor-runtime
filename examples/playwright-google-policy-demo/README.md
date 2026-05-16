# Playwright Google Policy Demo

This folder contains a focused Playwright-over-CDP demo for URL and search
governance through an Erebor-owned browser.

Playwright is still only the validation client. The enforcement boundary is the
Erebor-owned browser session and the governed CDP endpoint that Playwright
receives.

## Smoke Demo

Start Erebor with this demo config:

```sh
cargo run -p erebor-runtime-cli -- start \
  --config examples/playwright-google-policy-demo/runtime-config.json
```

The runtime launches its own browser and exposes a governed endpoint at
`ws://127.0.0.1:3740/`, matching `runtime-config.json`.

In another shell:

```sh
cd examples/playwright-google-policy-demo
npm install
npm run smoke
```

Set `EREBOR_CDP_ENDPOINT` only if you change the demo listen address.

The smoke script validates:

- Playwright connects through Erebor's governed CDP endpoint.
- Navigation to `https://www.google.com/` is allowed.
- A Google search URL for `Something Something` is allowed.
- Navigation to Microsoft is denied by policy before it reaches Chrome.
- A Google search URL for any other demo query is denied by policy.
- Denied navigation does not mutate browser state.

## Policy

`google-search-policy.json` is ordered from most-specific to broadest rules:
allow the exact Google search first, deny other Google searches, allow ordinary
Google navigation, then deny Microsoft and any other navigation.
