# Phase 5: Surface Certification, Recovery, And Rollout

Status: Proposed. Blocked on Phase 4 and explicit implementation approval.

## Purpose

Certify only the Linux Codex/IDE surfaces that pass their complete source
profile matrix, then make failure, update, recovery, and deployment state
operationally honest.

## Scope

- Certify CLI, TUI, `codex exec`, VS Code, Desktop, and later IDE profiles
  independently by executable fingerprint, requirements composition, hook
  schema, transport shape, tool matrix, namespace/descriptor state, and network
  behavior.
- Publish the prompt source for every profile: brokered, hook-first,
  action-governed only, or unavailable.
- Persist profile registry, requirements/hash, executable fingerprint, runtime
  admission result, hook/lease decisions, process associations, coverage gaps,
  and retained audit references for recovery. Final Phases 6–7 extend this with
  host-service, auto-adopt route, and derived-context recovery facts.
- On hook, broker, tracer, filesystem, or network health epoch loss,
  drain/terminate affected strict runtimes or keep them explicitly degraded;
  never silently reconstruct live leases from history. Final Phases 6–7 add
  host-service and fanotify health loss for auto-admitted candidates.
- Quarantine changed Codex/IDE binaries and changed hook/requirements
  composition until their profile fixture passes again.
- Add fleet/local deployment diagnostics that distinguish managed strict from
  local cooperative policy. Do not claim a local root administrator is unable
  to remove policy.
- Document safe lifecycle cleanup for session-run processes, pidfds, namespace
  handles, broker endpoints, hook artifacts, and retained filesystem work.
  Final Phases 6–7 add context-root, route, default-route, host-service worker,
  and auto-admitted process cleanup.

## Tests

- Profile matrix tests reject unknown/changed executable, schema, transport,
  hook event, requirements conflict, and unsupported tool configuration.
- Restart/crash tests cover every normal session admission and lease state,
  including PID reuse and incomplete filesystem transaction evidence. Final
  Phases 6–7 add host-service restart, context-root, and default-route
  expiration coverage.
- Update tests prove a changed bundled IDE Codex is unavailable until re-tested.
- Full privileged e2e verifies all certified profiles and emits coverage output
  that never collapses semantic and physical gaps.

## Checkpoint

```sh
cargo fmt
cargo test --workspace --all-targets --all-features
EREBOR_REQUIRE_CODEX_LINUX_V1_PROBE=1 \
  cargo test -p erebor-runtime-e2e --test codex_linux_v1_lifecycle \
  -- --test-threads=1 --nocapture
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

## Acceptance

- Only pinned passing source profiles are strict.
- Crash, restart, update, and policy-composition behavior is fail closed and
  auditable.
- Operators can distinguish strict, action-governed, prompt-governed, degraded,
  and unavailable runtimes.

## Stop Point

Stop after presenting certification evidence. Wait for explicit approval before
starting final Phases 6–7 auto-adopt work, widening a profile matrix, changing
defaults, or deploying fleet policy.

## Phase Result

State: Not started.
