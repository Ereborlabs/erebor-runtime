# Phase 1: Privileged Daemon Control Plane

Status: Source implementation, including the single-public-client
consolidation, and normal workspace verification are complete as of
2026-07-19. `erebord` uses generic `--config`, `--runtime-dir`, `--log-dir`,
and `--state-dir` overrides, each defaulting to the installed system path;
there is no development-only launch mode. The reusable, automated disposable
systemd-container probe passes locally: it proves both the installed service
and the temporary-path daemon lifecycle without changing the host. It is an
explicit privileged acceptance command, not a CI job.

## Purpose

Establish exactly one privileged, multi-user `erebord` per host and a typed
local client protocol without moving governed session execution out of the
current CLI yet.

This phase proves the daemon's identity, authorization, storage, logging, and
wire boundaries before those boundaries are allowed to own workloads. It adds
only the `erebord` daemon control service. The current foreground runtime
interception broker remains the separate guard-facing service until Phase 2;
the IPC reorganization must not merge either dispatcher.

## Scope

### Shared IPC Contract

- Split
  `crates/erebor-runtime-ipc/proto/erebor/runtime/ipc/v1/control.proto` into:
  - `envelope.proto` for `Envelope` and `Header`;
  - `guard.proto` for existing guard/interception messages;
  - `hook.proto` for existing Codex hook messages; and
  - `daemon.proto` for daemon handshake, request, response, and stream
    messages.
- Preserve the existing `ERB1` frame and 64 KiB frame bound from
  `crates/erebor-runtime-ipc/src/frame.rs`. There is no compatibility
  requirement for the old protobuf source layout, but existing guard/hook v1
  field numbers, enum values, message-kind ids, and wire bytes must remain
  compatible while the foreground runtime still uses them.
- Preserve `src/standalone/` as a production dependency-free protobuf/frame
  subset: `crates/erebor-runtime-session/build.rs` compiles the Linux process
  guard directly with `rustc`, and `process_guard.rs` includes that module.
  Update it for every affected guard message and keep byte-for-byte conformance
  vectors against the generated prost API.
- Add crate-owned synchronous and asynchronous framed-stream codecs for normal
  Rust crate users, then remove duplicated host-side framing from the current
  interception broker and Codex hook client/broker. The codecs own only
  complete bounded frame reads/writes across partial syscalls, EOF
  classification, and malformed/oversized-frame rejection. Each service
  runtime owns its own queues, deadlines, cancellation, dispatch, draining,
  and shutdown. Do not force the standalone guard to depend on Tokio/prost.
- Keep numeric envelope message/correlation ids as transport identifiers. Add
  the reserved bounded daemon-only `erebor-idempotency-key` header for mutating
  daemon-control requests. Read-only daemon requests and all guard/hook
  requests reject it; no request payload contains a second key or a
  client-computed digest.
- Define the daemon request fingerprint as SHA-256 over a versioned domain
  separator, protocol major, validated daemon message kind, and exact received
  protobuf payload bytes. It excludes envelope message/correlation ids and all
  headers. Persist the scope, fingerprint, and mutation state for Phase 1
  reload/stop operations before their side effect; define
  same-key/same-fingerprint resume/result and
  same-key/different-fingerprint rejection. Phase 2 extends the same contract
  to session mutations.
- Make each socket listener configure an explicit allowlist of message types.
  A daemon message on a guard/hook socket, or a guard/hook message on the
  daemon socket, fails before dispatch. The allowlist is selected by the
  listener's service owner; there is no catch-all `Envelope` dispatcher.
- Bound and allowlist envelope headers by family, key, count, and value length.
  The only initial semantic header is `erebor-idempotency-key` on mutating
  daemon-control requests. Correlation remains exclusively in numeric envelope
  fields. Headers never carry caller identity, authorization decisions, hook
  tickets on the daemon socket, or unchecked tracing baggage.
- Add typed daemon messages only for:
  - client/server hello and protocol capability negotiation;
  - daemon status;
  - daemon log streaming;
  - configuration reload; and
  - graceful daemon stop.

### Daemon And Client Crates

- Add `crates/erebor-runtime-daemon` as a library plus `erebord` binary.
  Add a named daemon-control service owner rather than putting listener,
  authentication, dispatch, and configuration logic on one generic daemon
  object. Responsibilities in this phase:
  - load and validate root-owned, non-world-writable
    `/etc/erebor/erebord.json` without following symlinks;
  - open root-owned mode-`0600` `/run/erebor/erebord.lock` without following
    symlinks and take an exclusive nonblocking `flock`;
  - safely create `/run/erebor`, `/var/log/erebor`, and `/var/lib/erebor`;
  - persist bounded daemon-control idempotency records below
    `/var/lib/erebor/daemon/control-idempotency/`;
  - bind `/run/erebor/daemon.sock`;
  - authenticate accepted peers with Linux Unix-socket peer credentials;
  - authorize every request from the observed UID/GID/PID;
  - dispatch the four control-only operations; and
  - unlink only its owned socket during clean shutdown while still holding the
    lock, then close the descriptor; never unlink the persistent lock file.
- Add generic root-only `erebord --config <path>`, `--runtime-dir <path>`,
  `--log-dir <path>`, and `--state-dir <path>` overrides. Each omitted option
  uses its installed system default; the hands-on example supplies temporary
  local paths for all four. They add no listener type, remote endpoint, or
  daemon-selection model.
- `erebord` will also host the runtime guard service after Phase 2, but Phase 1
  must not add a placeholder listener or route existing foreground guard
  traffic through `/run/erebor/daemon.sock`. This phase establishes the
  service-owner shape and reserves the separation; Phase 2 migrates the real
  `RuntimeInterceptionBroker` behavior with code-backed session tests.
- Add `crates/erebor-runtime-client` as the typed daemon transport owner.
  It discovers the fixed local socket by default, performs the handshake,
  correlates unary responses, consumes bounded streams, and maps daemon errors.
  `erebor daemon --socket <path>` may name one explicit local Unix socket
  instead of its default `/run/erebor/daemon.sock`; it is neither a persisted
  context nor a remote or multi-daemon product interface. The crate must not
  contain CLI rendering or domain decisions.
- Keep `crates/erebor-runtime-cli` as wiring. `erebor` is the only public
  client target from this phase, rooted at `src/main.rs`. Its one `cli.rs`
  command tree contains the existing direct foreground commands and the
  `daemon status|logs|reload|stop` subcommand family in `cli/daemon.rs`. Remove
  the `erebor-runtime` binary and do not provide an alias or compatibility
  wrapper. Phase 3 migrates non-Codex command implementations behind this
  unchanged public command tree; Phase 4 migrates the final Codex direct
  implementation.

### Privilege And Authorization Contract

- `erebord` runs as root. The socket is owned by `root:erebor` with mode
  `0660`; membership in the `erebor` group permits a user to connect.
- Connecting is not authorization for another user's state. The daemon records
  the kernel-observed PID, effective UID, and effective GID on the connection;
  request payloads contain no caller-selected UID.
- An authorized non-root caller may use the sanitized `status` response. Only
  an observed UID 0 caller may stream global daemon logs, reload daemon
  configuration, or stop the daemon. Users inspect their own workload output
  and lifecycle through session commands after Phase 3.
- Log rendering must redact configuration secrets, registry credentials,
  package tokens, hook tickets, and workload payloads.
- Tests use real peer credentials. They must not replace the production
  credential provider with request-supplied identity.

### System Service And Telemetry

- Add the repository-owned Linux service definition and installation
  documentation needed to start one root daemon after boot.
- Add a reusable, explicit Docker acceptance command. It builds an Ubuntu
  24.04 test image containing the staged binaries, the installed
  `erebord.service`, and the repository probes. A dedicated ignored Rust
  integration target starts that image with systemd as PID 1, a private cgroup
  namespace, and disposable `/run` mounts. It uses `docker exec` to prove the
  installed unit can be enabled, started, restarted, and stopped, and that a
  connection-group user and an outsider see the expected socket and
  authorization boundaries. The same disposable container then directly
  starts `erebord` with temporary `--config`, `--runtime-dir`, `--log-dir`, and
  `--state-dir` paths to exercise peer credentials and lifecycle recovery.
  Container removal discards every service account, systemd unit state, socket,
  configuration, log, and temporary path. This privileged acceptance is not a
  CI job; keep ordinary CI unprivileged and fast.
- Report Linux and `SO_PEERCRED` as the supported control-plane platform. The
  repository-owned systemd unit is the installed boot-time launch method and
  the Phase 1 privileged probe exercises it inside the disposable test
  container. Do not imply native macOS or Windows daemon support from the
  portable IPC envelope.
- Foreground startup may log failures to stderr. After the telemetry sink is
  initialized, daemon diagnostics go to rotated JSONL at
  `/var/log/erebor/daemon.jsonl`, not to the CLI or governed workload streams.
- Configuration reload is transactional: validate the complete replacement,
  atomically publish it for future requests, and retain the prior configuration
  on error. This phase has no live session settings to mutate.
- A second daemon fails without unlinking a healthy daemon's socket. A stale
  socket is removed only while holding the persistent lock and after failed
  connect plus protocol/peer checks prove no live owner exists. The lock path
  itself remains across normal shutdown, crashes, and upgrades.

## Non-Goals

- Do not route `session run`, `start`, policy, audit, filesystem, or surface
  commands through the daemon.
- Do not add `SessionSpec`, runner handles, workload output, packages,
  installations, OCI access, Codex migration, or remote/TCP daemon access.
- Do not move the current runtime interception broker into `erebord`, create
  guard endpoints in the daemon control service, or accept `Guard*` messages
  on `/run/erebor/daemon.sock`. That migration belongs to Phase 2.
- Do not retain the old foreground execution path as a final compatibility
  mode; it remains only until the Phase 4 final cutover.

## Ownership Rules

- `erebor-runtime-ipc` owns wire representation and bounded frame I/O, not
  queues, deadlines, cancellation, shutdown, listeners, or authorization.
- In this phase, the daemon-control service inside `erebor-runtime-daemon`
  owns `/run/erebor/daemon.sock`, peer authorization, and control dispatch,
  including its own queues, deadlines, cancellation, draining, and shutdown;
  it owns neither CLI rendering nor guard dispatch.
- The existing foreground `RuntimeInterceptionBroker` remains the guard-family
  listener owner until Phase 2. Sharing codecs does not transfer its listener
  to the daemon-control service.
- `erebor-runtime-client` owns transport behavior, not user commands.
- Returned daemon/client errors use crate-owned SNAFU errors and stable
  `ErrorExt` mappings. Runtime logs use repository telemetry wrappers.

## Checkpoint

Extend `examples/codex-app-server` with the Phase 1 manual daemon/client
walkthrough. It must start `erebord` with explicit temporary local path
overrides, connect `erebor` through the explicit local socket, distinguish the
direct Codex baseline from daemon-owned execution, and supplement rather than
replace privileged CI.

Add crate-local tests plus `erebor-runtime-e2e` control-plane tests covering:

- hello/version negotiation and request correlation;
- partial reads/writes, malformed frames, oversize rejection, timeout, and
  disconnect;
- generated/standalone guard message conformance plus the existing real Linux
  allowed/denied process-guard and Codex hook IPC regressions;
- correlation versus the daemon-only idempotency-header validation, exact
  request-fingerprint vectors, durable reload/stop retry across reconnect or
  restart, and conflicting-key rejection;
- header key/count/value bounds and identity/trust-metadata rejection;
- cross-family message rejection;
- peer credential observation and the absence of caller-selected identity;
- non-root versus root-only daemon commands;
- same-host requests from two real test UIDs;
- singleton startup, healthy socket preservation, stale socket recovery,
  persistent lock-file survival across graceful shutdown/crash,
  lock owner/mode/no-follow rejection, and transactional reload; and
- daemon JSONL output staying separate from CLI stdout/stderr.

Run these tests in two lanes:

- the normal workspace lane runs codec, protocol, config, rendering, and
  unprivileged daemon/client tests;
- the explicit Docker acceptance command builds a disposable privileged
  systemd container, proves the installed unit and its connection-group
  boundary, then runs the temporary-path target inside that same container with
  root-owned paths, two disposable UIDs, peer credentials, socket lifecycle,
  and cleanup. A host without Docker privileged-container capability cannot run
  this local acceptance command; ordinary CI does not run a duplicate.

Then run the shared normal-workspace procedure, which is also the ordinary CI
job's verification contract:

```sh
bash .github/scripts/verify-rust-ci.sh
rtk git diff --check
```

Run the Phase 1 control-plane section of `lifecycle-probe.md`.

## Required Evidence

- Exact new crate and protobuf file inventory.
- Socket owner/group/mode and observed peer credentials from the live probe.
- Configuration owner/mode/no-follow validation and redaction results.
- Root/non-root authorization results for every control command.
- Proof that a second daemon cannot replace a live daemon socket.
- Proof that `erebord.lock` is never unlinked and stale `daemon.sock` removal
  occurs only under the held flock after failed live-owner checks.
- Daemon log path plus proof that daemon records did not enter CLI output.
- Normal and privileged test-lane results, plus lint, formatting, diff-check,
  and live-probe results.

## Acceptance

- One root `erebord` owns its configured local `daemon.sock` and serves
  multiple local users through the shared typed IPC contract. The installed
  default remains `/run/erebor/daemon.sock`; the automated container proof
  covers both the installed path and a separate temporary runtime directory.
- The Phase 1 `erebord` daemon-control service has no guard listener and cannot
  dispatch guard/interception messages. The existing foreground interception
  service remains independently owned and functional.
- Identity comes only from the accepted Unix socket.
- Non-root callers cannot reload or stop the daemon.
- Daemon, guard, and hook message families cannot cross socket boundaries.
- The standalone Linux guard contract remains compatible with the generated
  protocol while normal crate users share the new sync/async codec owners.
- `erebor-runtime-client` is the only reusable CLI-to-daemon transport owner.
- The current direct governed-run behavior remains available through `erebor`
  but is not yet daemonized. This is a temporary implementation boundary, not
  a second public CLI or compatibility command.

## Stop Point

Stop after the Phase 1 evidence and this file's result section are updated.
Wait for explicit approval before Phase 2.

## Phase 1 Result

State: Done — implementation, normal workspace verification, and the full
reusable disposable Docker/systemd acceptance probe pass locally.

Implemented:

- Replaced the monolithic IPC protobuf source with `envelope.proto`,
  `guard.proto`, `hook.proto`, and `daemon.proto`. Existing guard and hook V1
  message definitions remain byte-compatible; the standalone process-guard
  subset remains dependency-free and its generated/standalone contract tests
  pass.
- Added bounded crate-owned `SyncFrameCodec` and `AsyncFrameCodec`, then moved
  the foreground interception broker and Codex hook client/broker to those
  owners. Guard and hook listeners now validate their own header families, so
  the daemon-only idempotency header cannot cross into either service.
- Added `erebor-runtime-daemon` and `erebord`. The Phase 1 daemon-control
  service is root-only at its public binary boundary; it securely opens the
  root-controlled configuration and persistent lock without following the
  final symlink, binds the root/group `0660` control socket, observes Unix peer
  credentials, and serves only hello/status/logs/reload/stop. It has no guard
  listener. It validates the protocol version for every received envelope,
  probes a live socket before recovery, and unlinks only the socket inode it
  created while the persistent lock remains held. Reload/stop persist bounded,
  keyed SHA-256 fingerprint records and their mutation intent before their
  side effect, with resume/result and conflict behavior across a daemon
  restart. Reload publishes configuration and generation together.
- Daemon diagnostics are written through the rotated JSONL sink after startup;
  sensitive diagnostic text is redacted and records are mode `0640`. The
  normal daemon path does not initialize stderr telemetry after that sink is
  available.
- Added `erebor-runtime-client` and consolidated the public client into the
  single `erebor` binary. `cli.rs` owns one command tree; `cli/daemon.rs` owns
  its daemon subcommands. The former `erebor-runtime` executable and its
  separate `daemon_cli.rs` parser are absent. Existing direct foreground
  commands remain temporarily available under `erebor` until their owning
  later phases daemonize them.
- Added generic root-only `erebord --config`, `--runtime-dir`, `--log-dir`,
  and `--state-dir` local path overrides plus explicit local `erebor daemon
  --socket <path>` wiring for the manual example. Each omitted daemon argument
  uses its installed default; the installed client likewise defaults to
  `/run/erebor/daemon.sock`. No context or remote target exists.
- Made `examples/codex-app-server` the cumulative hands-on product example.
  Its Phase 1 two-terminal walkthrough starts a real daemon with temporary
  local path overrides and connects the real client to its socket. It labels
  the current direct Codex App Server command as a Phase 4 migration baseline,
  not daemon-owned behavior.
- Added `packaging/systemd/erebord.service`,
  `packaging/erebord.json.example`, `docs/erebord-installation.md`, the
  repository-owned Ubuntu 24.04 systemd test image, and its ignored Rust
  container probe. The probe boots systemd as PID 1 in a disposable privileged
  container, enables, starts, restarts, and stops the installed root service,
  checks its installed socket permissions and root/non-root authorization, then
  runs the temporary-path control-plane probe in the same container. That
  second probe creates two connection-group users and an outsider and checks
  observed-peer authorization for every control command, singleton and
  stale-socket behavior, recovery after abrupt daemon death, transactional
  reload, persistent lock survival, and JSONL/CLI separation. Both probes
  leave no state on the host. This is a reusable local acceptance command, not
  CI.
- The ordinary CI job installs the GLib and OSTree development packages
  required by the existing `erebor-runtime-filesystem` OSTree dependency, in
  addition to `protoc`, before compiling the workspace.

Verification passed (the normal workspace procedure is now shared with CI):

```sh
bash .github/scripts/verify-rust-ci.sh
rtk git diff --check
bash -n .github/scripts/daemon-control-plane.sh
bash -n .github/scripts/daemon-systemd-control-plane.sh
rtk cargo build -p erebor-runtime-daemon --bin erebord
rtk cargo build -p erebor-runtime-cli --bin erebor
rtk docker build --file .github/containers/daemon-systemd.Dockerfile --tag erebor-daemon-systemd:local .
EREBOR_DAEMON_SYSTEMD_IMAGE=erebor-daemon-systemd:local rtk cargo test -p erebor-runtime-e2e --test daemon_control_plane -- --ignored
rtk cargo test -p erebor-runtime-daemon -- --ignored
rtk cargo test -p erebor-runtime-session --lib
rtk cargo test -p erebor-runtime-cli --all-targets
rtk cargo test -p erebor-runtime-e2e --tests --no-run
rtk cargo test -p erebor-runtime-e2e --test daemon_control_plane --no-run
rtk cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle --no-run
rtk cargo run -p erebor-runtime-cli --bin erebor -- --help
rtk cargo run -p erebor-runtime-daemon --bin erebord -- --help
```

The socket-using workspace and daemon/session commands were run outside the
workspace sandbox because it forbids Unix/TCP socket creation. The normal
workspace suite passed there. The ignored daemon tests passed five real Unix
socket cases: observed peer credentials, guard-family rejection, version
rejection after hello, stale-socket recovery while the lock persists, and safe
cleanup when another socket replaces the daemon path.

The final CLI probe showed one `erebor` root command with its existing `start`,
`session`, `dev`, `policy`, `audit`, and `filesystem` commands plus `daemon`.
`erebor daemon --help` exposes only the Phase 1 `status`, `logs`, `reload`, and
`stop` control operations. `Cargo.toml` exposes no `erebor-runtime` binary.
The hands-on walkthrough itself was not run locally because this sandbox sets
`no_new_privileges`; it cannot start a host root daemon. The automated probe
does not depend on host `sudo`: it requires Docker with permission to start a
privileged systemd container. It was built and run successfully on this host.
It remains an explicit reusable acceptance command and does not run in CI. No
Phase 2 work was started.
