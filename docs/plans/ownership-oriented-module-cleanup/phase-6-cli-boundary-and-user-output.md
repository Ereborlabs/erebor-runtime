# Phase 6: CLI Boundary And User Output

Status: Done.

## Purpose

Move CLI errors into a crate-local error module and make the CLI boundary use
the shared status/output behavior.

The CLI is the user-facing boundary. It should print actionable messages while
logging structured diagnostics.

## Scope

Migrate:

```text
crates/erebor-runtime-cli/src/cli.rs
crates/erebor-runtime-cli/src/main.rs
crates/erebor-runtime-cli/src/logging.rs
```

Create:

```text
crates/erebor-runtime-cli/src/error.rs
```

Optionally create submodules if `error.rs` would exceed 300 lines.

## Implementation Steps

1. Add dependencies:
   - `erebor-runtime-error`
   - `erebor-runtime-telemetry`
2. Move `CliError` from `cli.rs` to `error.rs`.
3. Convert `CliError` to SNAFU.
4. Implement `ErrorExt` for `CliError`.
5. Remove `thiserror` from CLI dependencies.
6. Update `main.rs`:
   - log command failure with telemetry error macro
   - include `status_code` and `retry_hint` fields when available
   - print `error.output_msg()` or a CLI-specific user message
   - keep process exit code non-zero
7. Ensure internal/unknown errors do not leak excessive implementation detail
   to normal CLI stderr.
8. Ensure policy denials and invalid input remain understandable to users.
9. Move tracing initialization into `erebor-runtime-telemetry` only if it keeps
   the CLI simpler. Otherwise leave `logging.rs` as the CLI-specific adapter
   and use telemetry macros at call sites.
10. Add/update CLI tests:
   - empty config prints an invalid-argument style message
   - invalid policy syntax prints actionable syntax message
   - denied lifecycle command still contains denial wording expected by
     `lifecycle-probe.md`
   - `--log-level` still controls tracing level
   - unknown/conflicting commands still fail
11. Remove any old compatibility aliases or constructors.

## Non-Goals

- Do not redesign CLI commands.
- Do not change JSON/text renderer formats except where error wording must
  change because old types were removed.
- Do not add colored output.

## Focused Checkpoint

```sh
cargo fmt
cargo test -p erebor-runtime-cli --all-targets --all-features
cargo test -p erebor-runtime-session --all-targets --all-features
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

Then run `lifecycle-probe.md`.

## Required Evidence

- `CliError` final location.
- CLI user-output examples for at least one invalid input and one policy denial.
- Confirmation that `thiserror` was removed from CLI.
- Focused test results.
- Workspace/clippy results.
- Lifecycle probe result.

## Acceptance

- CLI error boundary uses shared error status/output behavior.
- CLI denial output still satisfies lifecycle probe.
- Lifecycle probe passes.

## Current Status

State: Done as of 2026-07-04.

Implemented:

- `CliError` moved from `crates/erebor-runtime-cli/src/cli.rs` to
  `crates/erebor-runtime-cli/src/error.rs`.
- `CliError` now uses SNAFU, `snafu::Location`, SNAFU context selectors, and
  the shared `erebor_runtime_error::ErrorExt` status/output behavior.
- CLI `thiserror` dependency removed.
- CLI dependencies now include `erebor-runtime-error` and
  `erebor-runtime-telemetry`.
- `main.rs` now logs command failures with
  `erebor_runtime_telemetry::error!`, including `status_code` and
  `retry_hint`, then prints `error.output_msg()` and exits non-zero.
- `logging.rs` remains the CLI-specific tracing adapter; this phase only moved
  the command-failure call site to telemetry macros.
- Old `CliError` constructor helpers and compatibility aliases were removed.
- CLI tests cover empty config output, invalid policy syntax output, masked
  internal CLI output, `--log-level`, unknown arguments, and conflicting command
  shapes.

CLI user-output examples:

```text
$ RUST_LOG=off target/debug/erebor-runtime --log-level off start --config /tmp/erebor-empty-config.up0zwy
runtime config is empty
exit_code=1
```

```text
$ RUST_LOG=off target/debug/erebor-runtime --log-level off policy test --policy /tmp/erebor-invalid-policy.KHkoT0 --event /tmp/erebor-event.Z1WqmZ
policy syntax is invalid: EOF while parsing an object at line 1 column 1
exit_code=1
```

Lifecycle policy-denial output contained:

```text
erebor linux process guard: denied exec: ... raw CDP process launch is denied
command failed error=session runner `linux-host` exited unsuccessfully with code Some(126) status_code=External retry_hint=non_retryable
```

Verification:

- `cargo fmt` passed.
- `cargo test -p erebor-runtime-cli --all-targets --all-features` passed
  (`42 passed`).
- `cargo test -p erebor-runtime-session --all-targets --all-features` passed
  (`25` library tests, `23` Linux process guard unit tests, `9`
  `linux_host_runner` tests, and `1` `linux_process_guard` test).
- `cargo test --workspace --all-targets --all-features` passed.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  passed.
- `git diff --check` passed.
- The first sandboxed lifecycle probe was blocked by the host sandbox with
  `runtime interception broker I/O failed: Operation not permitted (os error 1)`.
- The same lifecycle probe passed with host process permissions:
  - allowed command printed `erebor-lifecycle-allowed`
  - denied command failed closed
  - audit evidence contained `"type":"deny"`
  - audit evidence contained `deny-raw-cdp`
  - probe workspace:
    `/tmp/erebor-error-logging-lifecycle.AQRc5X`

## Stop Point

Stop after Phase 6 verification. Wait for user approval for Phase 7.
