# Verification Rules

## Required Quality Gate

For a Rust change, run this repository-owned CI procedure after the final edit
to Rust source, tests, Cargo files, CI configuration, or verification scripts:

```sh
bash .github/scripts/verify-rust-ci.sh
```

It runs formatting, `cargo check --workspace`, clippy with warnings denied, and
the full workspace test suite in CI order. Focused tests are required while
iterating, but neither they nor an earlier full run can replace this final run.

## Evidence

- Report the procedure and exact source state it covers. Rerun it if any
  covered file changes.
- If a check is blocked, report the exact command and error. Do not claim it
  passed.
- For product-specific work, run the checks named by its current phase and
  report its qualified platform, physical result, and unsupported boundary. A
  prior environment result does not cover a later source state or a different
  phase acceptance matrix.
- For browser/CDP work, run the type-check and smoke commands specified by the
  relevant example and browser plan. If `npm` is unavailable, use local
  `node_modules/.bin` tools where possible and state what ran.
- The Playwright smoke is the browser-level CDP acceptance check. Unit tests
  and fake-upstream tests do not replace it. A Chrome launch failure is a host
  blocker, not a proxy success; surface Chrome stderr for diagnosis. A
  `crashpad ... setsockopt: Operation not permitted` failure means the host
  sandbox blocked Chrome before DevTools was ready.

## E2E Proof

- `erebor-runtime-e2e` is the reusable mini-system framework. Runtime crates
  own their runtime-specific e2e support and tests.
- Fake-upstream tests must be fast and deterministic. Real Chrome tests must
  exercise actual browser behavior and may skip only when Chrome cannot launch
  and expose CDP.
- A denied-command test must prove the command was not forwarded and did not
  mutate browser state.

## Handoff

State what changed, what was verified, any exact blocker, and a concise commit
message for the user to run.
