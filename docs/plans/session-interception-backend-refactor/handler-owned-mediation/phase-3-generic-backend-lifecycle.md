# Phase 3: Generic Backend Lifecycle

Status: Done.

## Purpose

Move Linux ptrace backend lifecycle out of terminal surface startup and into the
session interception backend path.

## Scope

- Prepare interception backends before iterating surface launch definitions.
- Keep terminal surface startup responsible only for terminal context.
- Introduce a session-owned backend bundle.
- Keep low-level process guard binary, environment, and rule names where
  renaming would be unrelated churn.
- Keep Linux-host adoption dependent on session interception capability.

## Current Code Owners

- `crates/erebor-runtime-session/src/interception_backend.rs`
- `crates/erebor-runtime-session/src/session_side_resources.rs`
- `crates/erebor-runtime-session/src/session_resources.rs`
- `crates/erebor-runtime-session/src/interception_setup.rs`

## Implemented

- `SessionInterceptionBackendBundle` owns backend lifecycle selection.
- Linux ptrace preparation lives behind the session interception backend.
- Session startup creates backend input from the session start plan.
- Terminal contributes process-exec-specific input only when the terminal
  surface is present and process-exec interception is supported.
- Per-session process guard materialization was removed; local development and
  tests prefer the current build-script guard artifact.
- Runtime interception broker socket is runtime-owned and shared across session
  registrations.
- Broker socket environment uses `EREBOR_RUNTIME_INTERCEPTION_*`.

## Checkpoint

```sh
cargo fmt
cargo test -p erebor-runtime-session --lib
cargo test -p erebor-runtime-session --test linux_host_runner
cargo test -p erebor-runtime-terminal
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## Acceptance

- Linux ptrace backend starts because session interception is enabled, not
  because terminal owns backend config.
- Terminal still consumes process-exec events.
- Linux-host adoption depends on session interception capability.
- Process-exec audit remains terminal/process audit.

## Phase 3 Result

Done. Backend lifecycle is session-owned. Follow-up organization and mediation
ownership work moved into the two subplans under this parent plan.
