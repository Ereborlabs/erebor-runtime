# Phase 2: Session-Level Interception Config

Status: Done.

## Purpose

Move backend configuration from terminal-owned `process_guard` config to
session-owned interception config.

## Scope

- Add session-owned interception config types in core.
- Remove terminal-owned `process_guard` config types and public re-exports.
- Make session surface start/run/adopt plans carry resolved interception
  config.
- Make terminal process mediation validation depend on session interception
  `process_exec` support.
- Make session startup and Linux-host adoption decide process guard lifecycle
  from session interception capability.
- Add capability reporting for operation families.

## Current Code Owners

- `crates/erebor-runtime-core/src/config.rs`
- `crates/erebor-runtime-core/src/lib.rs`
- `crates/erebor-runtime-session/src/session_side_resources.rs`
- `crates/erebor-runtime-session/src/session_run.rs`

## Implemented

- `SessionInterceptionLayerConfig`
- `SessionInterceptionConfig`
- `SessionInterceptionBackendKind::LinuxPtrace`
- `SessionInterceptionOperation`
- `SessionInterceptionCapabilityReport`
- `RuntimeConfig::session_interception()`
- `RuntimeConfig::session_interception_capabilities()`
- rejection of `surfaces.terminal.process_guard`
- validation that terminal process mediation requires effective
  `session.interception` process-exec support

Current capability reporting can mention future operation families, but
`LinuxPtrace` currently supports only `process_exec` effectively.

## Checkpoint

```sh
cargo fmt
cargo test -p erebor-runtime-core
cargo test -p erebor-runtime-terminal
cargo test -p erebor-runtime-session --lib
cargo test -p erebor-runtime-session --test linux_host_runner
cargo test -p erebor-runtime-e2e --test session_review
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## Acceptance

- `session.interception` can enable Linux ptrace process-exec interception
  without declaring a backend under terminal.
- Migrated configs still produce the same process-exec launch plan.
- Capability reports distinguish backend support from surface enablement.
- Old `surfaces.terminal.process_guard` config is not kept as a compatibility
  input.

## Phase 2 Result

Done. Session-owned interception config exists, terminal-owned process guard
config was removed, and process mediation validation now depends on
session-level process-exec interception support.
