# Verification Rules

## Required Quality Gates

Before saying a code change is complete, run the checks that match the changed
surface. For Rust changes, the full bar is:

```sh
cargo fmt
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

For the Playwright validation demo:

```sh
cd examples/playwright-cdp-demo
./node_modules/.bin/tsc --noEmit
npm run smoke
```

If `npm` is not available in the tool environment, use the local binaries in
`node_modules/.bin` where possible and say exactly what was run.

## Real Browser Checks

The Playwright smoke is the acceptance check for the browser-level CDP demo. Unit
tests and mini-upstream tests are useful, but they do not replace the real demo.

When Chrome cannot launch in the local environment, do not pretend the smoke
passed. Report the exact command and the browser/runtime error. The owned
browser launcher should surface Chrome stderr so host-level restrictions are
diagnosable.

Common blocked-host symptom:

```text
crashpad ... setsockopt: Operation not permitted
```

That means the host sandbox blocked Chrome before DevTools became ready. It is
not a CDP proxy success.

## E2E Framework Rules

- `erebor-runtime-e2e` is the reusable mini-system framework.
- Each runtime crate owns runtime-specific e2e support and tests.
- Fake upstream tests should be fast and deterministic.
- Real Chrome tests should exercise actual browser behavior and skip only when
  Chrome cannot really launch and expose CDP.
- Tests for denied commands must prove blocked commands are not forwarded and
  do not mutate browser state.

## Reporting

Final responses should include:

- What changed.
- What was verified.
- Any command that could not be run and the exact reason.
- A short commit message, because the user commits manually.
