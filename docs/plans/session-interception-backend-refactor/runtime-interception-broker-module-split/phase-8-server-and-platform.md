# Phase 8: Extract Server And Platform Together

Status: Done.

## Purpose

Move runtime broker server/session ownership and OS transport together because
Phase 0 found the stale `server.rs` and `platform.rs` are tightly coupled.

## Scope

Create or update:

- `runtime_interception_broker/server.rs`
- `runtime_interception_broker/platform.rs`
- root `runtime_interception_broker.rs`
- `runtime_interception_broker/wire.rs`, only if its error import needs
  adjustment

Move only:

- `RuntimeInterceptionBroker`
- `SessionInterceptionRegistration`
- `RuntimeInterceptionBrokerError`
- `RuntimeInterceptionBrokerPlatform`
- `RuntimeInterceptionBrokerServerPlatform`
- `RuntimeInterceptionBrokerServer`
- `BoundConnection`
- `RUNTIME_INTERCEPTION_BROKER_SERVER`
- `shared_runtime_interception_broker_server`
- `read_interception_token`
- server registration/unregistration methods
- server stream/envelope/hello/request dispatch methods
- `deny_unexpected_bound_message`
- Unix platform transport implementation
- Windows unsupported transport implementation

## Non-Goals

- Do not move `InterceptionBrokerClient`.
- Do not move tests.
- Do not change from one runtime-owned socket to per-session sockets.
- Do not change `GuardHello.session_id` binding semantics.
- Do not change token validation semantics.
- Do not change socket path, permissions, timeout, accept loop, or shutdown.

## Ownership Rules

- `server.rs` owns session registrations, `GuardHello` binding, and request
  routing.
- `platform.rs` owns OS transport only: bind, accept, connect, read/write
  through wire helpers, and shutdown.
- The platform must not own the session map.
- The server must not own Unix-specific socket setup details.

## Implementation Rules

- Compare stale `server.rs` and `platform.rs` against the root server/platform
  ranges before moving.
- Treat the root file as the source of truth.
- Phase 0 found `server.rs` must use `handler.id().to_owned()` after handlers
  move; keep that boundary.
- Keep error variants exactly the same.
- Keep singleton semantics exactly the same.
- Keep `Drop` behavior for session registration and server shutdown.
- Keep root public re-exports for:
  - `RuntimeInterceptionBroker`
  - `RuntimeInterceptionBrokerError`
  - `SessionInterceptionRegistration`

## Checkpoint

```sh
cargo fmt
cargo check -p erebor-runtime-session --all-targets --all-features
cargo test -p erebor-runtime-session --lib
cargo test -p erebor-runtime-session --test linux_host_runner
cargo test -p erebor-runtime-session --test linux_process_guard
```

Then run the live governed-session lifecycle probe in `lifecycle-probe.md`.

## Required Evidence

- Stale `server.rs` and `platform.rs` comparison result.
- Old root code ranges moved.
- Root, `server.rs`, and `platform.rs` line counts.
- Item inventory showing moved server/session/platform items.
- Explicit statement that the one runtime-owned socket model is unchanged.
- Compile/check result.
- Test result.
- Live lifecycle probe result.

## Acceptance

- Multiple sessions still register against one shared broker server.
- Guard hello with valid token still binds the connection to the session.
- Bad token and unknown session still fail closed.
- Dropping a session registration still unregisters the session.
- Process guard integration tests pass.
- A real Linux-host governed session runs an allowed command.
- A real Linux-host governed session fails closed for the denied
  `remote-debugging-port` command and writes audit evidence.

## Stop Point

Stop after Phase 8 verification. Wait for approval for Phase 9.

## Phase 8 Result

State: Done.

Implemented:

- Added root module wiring for `runtime_interception_broker/server.rs` and
  `runtime_interception_broker/platform.rs`.
- Moved server/session ownership to `server.rs`.
- Moved OS transport traits and Unix/Windows transport implementations to
  `platform.rs`.
- Kept `InterceptionBrokerClient` in the root module.
- Kept tests in the root module.
- Updated `wire.rs` to import `RuntimeInterceptionBrokerError` from
  `server.rs`, the owning module.
- Kept root public re-exports for `RuntimeInterceptionBroker`,
  `RuntimeInterceptionBrokerError`, and `SessionInterceptionRegistration`.

Stale module comparison:

- Compared the stale `server.rs` and `platform.rs` against the pre-move root
  server/platform ranges before extraction.
- `server.rs` matched the root server/session/error/dispatch code shape, with
  the expected post-Phase-6 handler boundary using `handler.id().to_owned()`.
- `platform.rs` matched the root platform trait and Unix/Windows transport
  implementation, with only range-boundary/blank-line differences observed.
- The root remained the source of truth for the public `InterceptionBrokerClient`;
  the stale `client.rs` was not wired in for this phase.

Old root ranges moved:

- Server/session/error/registration/dispatch code was moved from the pre-Phase-8
  root broker range around lines 44-505.
- Platform traits and Unix/Windows transport code were moved from the
  pre-Phase-8 root broker range around lines 507-741.

Line counts after Phase 8:

- Root `runtime_interception_broker.rs`: 585 lines.
- `server.rs`: 448 lines.
- `platform.rs`: 275 lines.

Moved item inventory:

```text
RuntimeInterceptionBroker
SessionInterceptionRegistration
RuntimeInterceptionBrokerError
RuntimeInterceptionBrokerPlatform
RuntimeInterceptionBrokerServerPlatform
RuntimeInterceptionBrokerServer
BoundConnection
RUNTIME_INTERCEPTION_BROKER_SERVER
shared_runtime_interception_broker_server
read_interception_token
RuntimeInterceptionBroker::register_session
RuntimeInterceptionBroker::register_session_with_mediators
RuntimeInterceptionBroker::register_session_with_router_and_mediators
RuntimeInterceptionBrokerServer::start
RuntimeInterceptionBrokerServer::register_session
RuntimeInterceptionBrokerServer::unregister_session
RuntimeInterceptionBrokerServer::endpoint_path
RuntimeInterceptionBrokerServer::handle_stream
RuntimeInterceptionBrokerServer::handle_runtime_interception_envelope
RuntimeInterceptionBrokerServer::handle_hello_envelope
RuntimeInterceptionBrokerServer::handle_interception_request_envelope
RuntimeInterceptionBrokerServer::interception_decision_for_request
deny_unexpected_bound_message
UnixRuntimeInterceptionBrokerServer
impl RuntimeInterceptionBrokerPlatform for Unix Platform
impl RuntimeInterceptionBrokerServerPlatform for UnixRuntimeInterceptionBrokerServer
impl RuntimeInterceptionBrokerPlatform for Windows Platform
```

One runtime-owned socket model:

- Unchanged. `RUNTIME_INTERCEPTION_BROKER_SERVER` moved to `server.rs` and still
  owns one shared `RuntimeInterceptionBrokerServer` for the runtime process.
- `RuntimeInterceptionBroker::register_session...` still goes through
  `shared_runtime_interception_broker_server()`, so multiple sessions register
  against the same runtime-owned server and socket.
- The platform module still binds one process-local socket path under the temp
  directory and accepts all guard connections there.
- `GuardHello.session_id` plus the per-session token still binds each connection
  to the correct session before request routing.

Verification:

- Done: `cargo fmt`
- Done: `cargo check -p erebor-runtime-session --all-targets --all-features`
- Done: `cargo test -p erebor-runtime-session --lib`
  - Included `broker_accepts_multiple_sessions_on_one_server`.
  - Included valid-token, bad-token, unknown-session/drop, and process-exec
    routing coverage.
- Done: `cargo test -p erebor-runtime-session --test linux_host_runner`
- Done: `cargo test -p erebor-runtime-session --test linux_process_guard`
- Done: live governed-session lifecycle probe from `lifecycle-probe.md`
  - Re-run with escalated execution because ptrace/session execution needs host
    process access outside the sandbox.
  - Allowed Linux-host governed session printed `erebor-lifecycle-allowed`.
  - Session registry directory existed under the probe workspace.
  - Denied Linux-host governed session exited non-zero and reported the
    denied `remote-debugging-port` exec.
  - Audit evidence contained `"type":"deny"`.
  - Audit evidence contained `deny-raw-cdp`.
  - Probe workspace:
    `/tmp/erebor-broker-lifecycle.EkJTAr`.
  - Host cgroup residual risk remained:
    `cgroup_failed=1 cgroup_reason=failed to create cgroup directory: Permission denied (os error 13)`.
- Done: `cargo test --workspace --all-targets --all-features`
- Done: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- Done: `git diff --check`

Behavior change:

- No behavior change intended. Server registration, `GuardHello` binding, token
  validation, request dispatch, one-socket runtime ownership, Unix socket
  permissions, client timeout behavior, and shutdown behavior are preserved.
