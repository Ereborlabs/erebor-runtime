# Phase 7: Extract Browser CDP Mediation

Status: Done.

## Purpose

Move Browser CDP mediation into its own module without changing endpoint
validation or lazy managed-browser startup.

## Scope

Create or update:

- `runtime_interception_broker/browser_cdp_mediation.rs`
- root `runtime_interception_broker.rs`

Move only:

- `BrowserCdpMediationHandler`
- `BrowserCdpMediationMode`
- `LazyBrowserCdpMediation`
- `BrowserCdpMediationHandler::new`
- `BrowserCdpMediationHandler::lazy`
- `impl fmt::Debug for BrowserCdpMediationHandler`
- `impl SurfaceMediationHandler for BrowserCdpMediationHandler`
- `LazyBrowserCdpMediation::endpoint_for_requested_port`
- `remote_debugging_port`
- `effective_browser_cdp_allowed_ports`
- `validate_requested_port`
- `private_remote_debugging_port_for_request`
- `endpoint_port`
- `devtools_browser_url`

## Non-Goals

- Do not move server lifecycle.
- Do not move platform transport.
- Do not alter Browser CDP launch config.
- Do not alter private endpoint port strategy.
- Do not alter compatibility line output.

## Implementation Rules

- Compare stale `browser_cdp_mediation.rs` against the root Browser CDP
  mediation ranges before moving.
- Treat the root file as the source of truth.
- Keep `BrowserCdpMediationHandler` publicly re-exported from the root broker
  module.
- Keep `private_remote_debugging_port_for_request` available only to tests if it
  was test-only before.
- Preserve lazy surface map keying by requested port.
- Preserve fixed endpoint allowed-port behavior.
- Preserve `DevTools listening on .../devtools/browser/erebor-managed-browser`
  compatibility output.

## Checkpoint

```sh
cargo fmt
cargo check -p erebor-runtime-session --all-targets --all-features
cargo test -p erebor-runtime-session --lib
cargo test -p erebor-runtime-session --test linux_host_runner
```

Then run the live governed-session lifecycle probe in `lifecycle-probe.md`.

## Required Evidence

- Stale `browser_cdp_mediation.rs` comparison result.
- Old root code range moved.
- Root and `browser_cdp_mediation.rs` line counts.
- Item inventory showing moved Browser CDP mediation items.
- Verification that Browser CDP mediation tests still pass.
- Compile/check result.
- Test result.
- Live lifecycle probe result.

## Acceptance

- Managed Browser CDP mediation still starts on the requested port.
- Fixed Browser CDP mediation still validates allowed ports.
- Requested-plus-offset private endpoint behavior is unchanged.
- A real Linux-host governed session runs an allowed command.
- A real Linux-host governed session fails closed for the denied
  `remote-debugging-port` command and writes audit evidence.

## Stop Point

Stop after Phase 7 verification. Wait for approval for Phase 8.

## Phase 7 Result

State: Done.

Implemented:

- Compared stale `browser_cdp_mediation.rs` against the current root Browser CDP
  mediation ranges.
- Confirmed the moved item bodies matched root after normalizing only
  `private_remote_debugging_port_for_request` from private root helper to
  `pub(super)` module helper.
- Added `mod browser_cdp_mediation;` to the root broker module.
- Re-exported `BrowserCdpMediationHandler` from the root broker module.
- Kept `private_remote_debugging_port_for_request` available only to tests via a
  root `#[cfg(test)]` import.
- Removed root imports that became Browser CDP mediation-only:
  - `fmt`
  - `SocketAddr`
  - `mpsc`
  - `BrowserCdpSurface`
  - `CdpSessionContext`
  - `BrowserCdpSurfaceConfig`
  - `ProcessMediationPrivatePortStrategy`
  - `RunningSessionSurface`
  - `RuntimeAuditConfig`
  - `SessionSurfaceService`
  - `PolicySet`
  - `tokio::runtime::Runtime`
- Did not move server lifecycle.
- Did not move platform transport.
- Did not alter Browser CDP launch config.
- Did not alter private endpoint port strategy.
- Did not alter compatibility line output.

Old root code ranges moved:

- `runtime_interception_broker.rs` lines 52-205 before Phase 7.
- `runtime_interception_broker.rs` lines 667-734 before Phase 7.

Line counts:

- Root before Phase 7: 1507 lines.
- Root after Phase 7: 1279 lines.
- `browser_cdp_mediation.rs`: 242 lines.

Moved item inventory:

```text
BrowserCdpMediationHandler
BrowserCdpMediationMode
LazyBrowserCdpMediation
BrowserCdpMediationHandler::new
BrowserCdpMediationHandler::lazy
impl fmt::Debug for BrowserCdpMediationHandler
impl SurfaceMediationHandler for BrowserCdpMediationHandler
LazyBrowserCdpMediation::endpoint_for_requested_port
remote_debugging_port
effective_browser_cdp_allowed_ports
validate_requested_port
private_remote_debugging_port_for_request
endpoint_port
devtools_browser_url
```

Visibility changes:

- `private_remote_debugging_port_for_request` is `pub(super)` in
  `browser_cdp_mediation.rs`.
  Justification: it was root-private and used only by tests before the move.
  The root now imports it behind `#[cfg(test)]`, so the helper remains
  test-only from the root broker module and is not part of the public API.

Verification:

- Done: `cargo fmt`
- Done: `cargo check -p erebor-runtime-session --all-targets --all-features`
- Done: `cargo test -p erebor-runtime-session --lib`
  - Included `browser_cdp_lazy_mediation_starts_surface_on_requested_port`.
  - Included `browser_cdp_mediation_handler_owns_endpoint_and_port_validation`.
  - Included `private_browser_port_can_follow_requested_port_plus_offset`.
- Done: `cargo test -p erebor-runtime-session --test linux_host_runner`
- Done: live governed-session lifecycle probe from `lifecycle-probe.md`
  - Re-run with escalated execution because ptrace/session execution is blocked
    by the sandbox without escalation.
  - Allowed Linux-host governed session printed `erebor-lifecycle-allowed`.
  - Denied Linux-host governed session exited non-zero with status `1`.
  - Audit evidence contained `"type":"deny"`.
  - Audit evidence contained `deny-raw-cdp`.
  - Probe workspace:
    `/tmp/erebor-broker-lifecycle.NiiXle`.
  - Host cgroup residual risk remained:
    `cgroup_failed=1 cgroup_reason=failed to create cgroup directory: Permission denied (os error 13)`.
- Done: `cargo test --workspace --all-targets --all-features`
- Done: `cargo clippy --workspace --all-targets --all-features -- -D warnings`

Behavior change:

- No behavior change intended. Managed Browser CDP mediation still starts on the
  requested port, fixed endpoint mediation still validates allowed ports,
  requested-plus-offset private endpoint behavior is unchanged, and the
  `DevTools listening on .../devtools/browser/erebor-managed-browser`
  compatibility output is preserved.
