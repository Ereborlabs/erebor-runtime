# Removed Code Replacement Map

Status: Done. The implementation used this map as its deletion control.

Runtime replacement status: **Not done**. The source implementation now has a
Runtime-owned Interceptor path for new Linux Sessions. Its physical VM lane has
not run on the final source. Managed-browser launch replacement and
existing-process adoption remain unsupported.

Parent: [Phase 6.1](./phase-6-1-grpc-service-and-ipc-convergence.md)

## Rule

Delete a legacy path only after this map identifies its replacement owner or
marks its capability unsupported. An unsupported capability must reject its
old configuration or request. It must not continue through an ungoverned
fallback.

## Audit Boundary

This map covers the complete implementation diff from base commit `7496a29`
through implementation and review commit `36c05d3`. The last Rust change is
`f59fd04`. The repository CI gate passed after that change.

The audit uses two inventories:

- The semantic inventory records each removed protocol, authority, state
  machine, configuration path, compatibility switch, test claim, and helper.
- The path inventory records all 69 tracked files that the implementation
  deleted. It does not treat a file move or a generated-code rewrite as a
  deletion.

The following commands reproduce the Git inventory:

```text
git diff --name-only --diff-filter=D 7496a29..36c05d3
git diff-tree --no-commit-id --name-only -r --diff-filter=D fb1353b
git diff-tree --no-commit-id --name-only -r --diff-filter=D 3a4a926
git diff-tree --no-commit-id --name-only -r --diff-filter=D 2a15ba1
```

Only `fb1353b`, `3a4a926`, and `2a15ba1` delete complete tracked files. Other
implementation commits remove code from retained files. The semantic ledger
below records those removals.

## Runtime Replacement Update

This update does not change the completed deletion audit. It records the
current replacement boundary on branch `codex/erebor-runtime-interceptor`.

| Removed capability | Current replacement owner | Current result |
| --- | --- | --- |
| Process exec interception | One daemon-owned Runtime kernel host compiles a static policy image and binds it to an empty held workload cgroup before the first exec. | Source and local tests are complete. Final Linux VM proof is not run. |
| File open, read, and mutation interception | The same kernel host publishes exact operation-family decisions. The VM lane has separate `OpenRead`, `Read`, and `OpenWrite` denial oracles. | Source and harness checks are complete. Final Linux VM proof is not run. |
| Socket connect interception | The same kernel host owns numeric address, port, and protocol decisions for a Runtime-owned workload cgroup. | Source and local tests are complete. Final Linux VM proof is not run. Hostname, scheme, and URL-path policy are unsupported. |
| Existing-process adoption | No owner. | Unsupported. Runtime governs only a workload that it creates in an empty bound cgroup. |
| Managed-browser terminal replacement | No admitted launch-route and endpoint owner. | Unsupported. The retained owned-browser CDP path does not intercept an arbitrary terminal child. |
| Portable policy connection | The Runtime policy compiler accepts one closed static subset. It rejects dynamic string matchers, approval, and mediation. | Implemented and locally tested. |
| Process and resource setup | The Linux controller remains the owner. | Preserved. The held launch adds delegated cgroup identity and atomic `clone3(CLONE_INTO_CGROUP)` release. |
| Guard and broker lifecycle | The daemon-owned kernel host, Session runtime, Linux controller, and typed daemon API own the replacement lifecycle. | The removed guard binary, custom socket protocol, and standalone codec remain removed. |
| Runtime evidence | The daemon-owned evidence reader routes kernel observations to the required Session stream and records explicit coverage. | Local lifecycle and recovery tests pass. Physical completeness is not qualified until the VM lane passes. |

The App Server pipe case is a transport check for the normal Runtime launch.
The daemon owns its structured-input lease, JSONL validation, request
correlation, output projection, terminal reaping, and cleanup. It admits only
the `terminate` daemon-failure mode because request-correlation state is not
recoverable. This transport owner does not implement managed-browser launch
replacement.

## Process Guard Removal

| Removed capability | Decision | Current owner or boundary | Removal commit | Verification |
| --- | --- | --- | --- | --- |
| Linux ptrace process-exec interception | Unsupported | No replacement is approved in this phase. The shared Interceptor is not a replacement until a separate Runtime integration owns authorization and lifecycle. | `fb1353b` | A stale `linux_ptrace` configuration fails deserialization. An enabled session interception request fails validation. |
| Linux ptrace file-open, file-read, and file-mutation interception | Unsupported | Filesystem overlay, retention, preimage, and revert behavior stay with `erebor-runtime-filesystem`. They do not claim syscall policy enforcement. | `fb1353b` | Physical-denial tests that required ptrace are absent. Overlay lifecycle and recovery tests pass. |
| Linux ptrace socket-connect interception | Unsupported | No replacement is approved in this phase. | `fb1353b` | Enabled session interception rejects. No socket decision claim remains. |
| Adoption of an existing Linux process | Unsupported pre-existing boundary | `erebor-runtime-session` rejects Linux-host adoption before launch. This phase did not remove a working adoption path. | Not applicable | The `InvalidAdoptTarget` test remains. |
| Terminal launch interposition for managed browser replacement | Unsupported | `erebor-runtime-cdp` can still own and launch a configured browser. It does not intercept an arbitrary terminal child process. | `fb1353b`, test cleanup in `2a15ba1` | Owned-browser tests remain. Raw terminal-launch interception claims and the unreachable mediation fixture are absent. |
| Portable terminal policy and decision types | Preserved for Erebor | The logical policy compiler and portable request and decision types remain. They do not have an active physical interception backend. A later Runtime integration can connect them to the shared Interceptor only through an approved owner. | Not removed | Policy compilation and rule serialization tests pass. Removed session interception configuration rejects. |
| Process-guard resource and identity setup | Preserved without ptrace | The Linux session controller applies no-new-privileges, resource limits, umask, supplementary groups, GID, and UID before it starts the admitted workload. | Ptrace coupling removed in `fb1353b` | Controller privilege tests and Linux launch tests pass. |
| Runtime interception socket and guard lifecycle protocol | Removed | No supported Runtime guard remains. | `fb1353b`, shared wire cleanup in `3a4a926` | The broker, guard messages, build artifact, packaging path, and standalone codec are absent. The static closure test rejects their return. |
| Historical Runtime audit records | Preserved for Erebor | The audit reader keeps legacy fields that are required to read existing JSONL evidence. New no-interception sessions do not fabricate a ptrace decision or audit record. | Stale live-test claims removed in `2a15ba1`; stored evidence was not removed | The legacy-record audit test and no-interception session-review tests pass. The static source scan excludes stored evidence files. |

## IPC Replacement

| Removed code | Replacement owner | Removal commit | Verification |
| --- | --- | --- | --- |
| Daemon client frame connection, hello exchange, request IDs, message-kind routing, manual stream terminators, and frame errors | Generated daemon clients in `erebor-runtime-client` | `3ac0ca0` | Unary and server-stream tests use generated clients. |
| Daemon server accept loop, hello negotiation, generic dispatcher, per-kind handlers, and envelope encoding | Typed services in `daemon.proto`; `erebor-runtime-daemon` keeps domain state | `0a34b9f` | Wrong-service, stale-frame, shutdown, idempotency, and domain tests pass. |
| Stringly typed durable mutation response tags | `MutationResponseType` and encoded typed Protobuf responses; legacy stored names still deserialize | `01eb6a8` | Typed and legacy idempotency records pass restart and reuse tests. |
| Codex hook envelope and frame I/O | `HookService.Open`; `CodexHookService` keeps registration and event ownership | `fb1353b`, final shared wire cleanup in `3a4a926` | The server uses `SO_PEERCRED`, rechecks `/proc` identity, validates registered profile ancestry, and rejects peer replay. |
| Client hook tickets, ticket expiry and registry authority, guarded-hook exit barriers, process bindings, fork and exit tracking, bootstrap-process authority, command-dispatch trust, and physical-effect lease decisions | Kernel peer identity, registered process ancestry, one-use peer replay state, and the retained logical hook and app-server lease owner | `c29332c`, wire fields removed in `3a4a926` | Live hook tests cover valid events, wrong sessions, unregistered executables, peer replay, bounds, routing, and cancellation. |
| Mithril observation envelope, correlation ID, frame receive and send helpers, and per-connection custom handler | `RuntimeObservationService.GetSnapshot`; the existing observation owner keeps UID, PID, and cgroup authorization | `f27b4c0`, final shared wire cleanup in `3a4a926` | UID, PID, cgroup, response bounds, readiness, coverage, and event truncation tests pass through gRPC. |
| `NodeControl.OpenStream`, `NodeEnvelope`, `ControlEnvelope`, transport sequence, and envelope protocol version | Typed `NodeRegistry`, `NodeTrust`, `NodeEvidence`, `NodeCoverage`, `NodeAdministrativeResolution`, and `NodeAdministrativeArm` services | `8fb63e4` | mTLS identity, boot epoch, replay, durable evidence acknowledgement, coverage revision, reconnect, cancellation, and service-isolation tests pass. |
| `Envelope`, `Header`, frame header, async and sync codecs, message-kind constants, generic payload helpers, standalone guard codec, and `v1::operation` conversion helpers | Versioned Protobuf packages, generated method paths, generated clients and servers, and common tonic Unix transport | `3a4a926` | Runtime and Mithril descriptor inventories and the static closure test pass. |
| Daemon and frame protocol constants and per-message transport-version fields | Versioned Protobuf packages and generated method paths | `3ac0ca0`, `8fb63e4`, `3a4a926` | No supported IPC request contains a generic transport-version switch. |
| Linux and Docker controller numeric protocol constants, handoff fields, and runtime version checks | Strict handoff schemas with `serde(deny_unknown_fields)` | `9d71fb3` | Old handoff fields reject. Current handoffs deserialize without a numeric switch. |
| Ptrace-backed session-review assertions, unreachable terminal mediation fixture, unused filesystem context constructor, unused stored roots, and dead policy constructor | Current no-interception session review, retained terminal policy tests, and active owners | `2a15ba1` | Focused session-review and terminal tests pass. Clippy reports no dead code. |
| Blanket requirement that historical physical evidence use the current architecture digest | One explicit compatibility pair for the gRPC-only architecture amendment; physical evidence keeps its original digest | `f59fd04` | All 70 `mithril-e2e` library tests pass. A future architecture digest fails until it gets an explicit review. |

## Retained Erebor Code

The implementation did not remove these Erebor capabilities:

- generated Runtime request and response messages for supported operations;
- daemon domain state, durable idempotency, authorization, and stream limits;
- Codex hook and app-server logical leases, causal context, operation delivery,
  session registration, and durable audit writes;
- portable process and file request and decision types;
- terminal policy compilation and guard-rule serialization;
- Linux controller privilege setup and admitted workload lifecycle;
- filesystem overlay, preimage, promotion, rollback, retention, and recovery;
- owned-browser CDP launch and command mediation;
- historical audit-record deserialization; and
- Mithril boot, trust, evidence, coverage, WAL, administrative, and mTLS state.

None of these retained owners gains a physical process, file, or socket deny
claim from gRPC. A later Runtime use of the shared Interceptor needs a separate
approved implementation and proof.

## Semantic Removal Ledger By Commit

| Commit | Removal contained in retained files | Replacement or boundary |
| --- | --- | --- |
| `fb1353b` | Ptrace backend selection, guard artifact build and launch, interception setup, guard environment and socket wiring, Runtime interception broker registration, terminal and filesystem guard attachment, process-guard package installation, process-guard examples, and ptrace-only tests | Unsupported configurations reject. Common tonic Unix transport, controller privileges, overlays, owned browsers, hook ownership, and portable logical types remain. |
| `3ac0ca0` | Daemon client framing, hello negotiation, manual correlation, message-kind dispatch, custom stream completion, and custom IPC error mapping | Generated daemon clients and typed server adapters. The old daemon server stayed only until `0a34b9f`. |
| `f27b4c0` | Runtime observation frame accept, decode, correlation, encode, and send logic | One unary observation service with kernel peer credentials and the existing snapshot owner. |
| `8fb63e4` | One multiplexed node stream, both payload unions, generic transport sequence, and envelope protocol version | Six typed mTLS services. Domain boot, nonce, trust, cursor, coverage, and replay fields remain. |
| `0a34b9f` | Daemon frame listener loop, hello handler, generic dispatcher, manual payload decoding, per-kind routing, response envelopes, and frame shutdown path | The typed daemon gRPC adapter becomes the only server. |
| `01eb6a8` | Durable response `message_kind: String` authority and generic response field names | A closed response-type enum with legacy read compatibility. |
| `c29332c` | Client hook-ticket authority and the ptrace-coupled physical lease state machine | Kernel peer authentication and retained logical hook and app-server causal leases. |
| `3a4a926` | Remaining shared frame and envelope source, guard Protobuf contract, generic operation conversions, transport versions, message-kind constants, and hook ticket wire fields | Generated descriptors are the exact contract. Removed Protobuf field numbers are reserved. |
| `9d71fb3` | Linux and Docker controller numeric protocol switches | Strict schemas reject unknown old fields. Recovery-format versions remain because they describe durable runner state. |
| `cb08c7d` | Test-only setup that depended on retired tickets or handcrafted transport assumptions | Live generated-client boundary tests. No production capability was removed. |
| `2a15ba1` | Unreachable ptrace mediation test fixture, stale ptrace audit assertions, and unused migration fields, constructors, imports, and helpers | Current no-interception tests and retained logical-policy tests. No active product behavior was removed. |
| `f59fd04` | Blanket current-document digest equality for historical physical evidence | A narrow reviewed digest pair keeps evidence bound to the document used by its physical run. |

## Complete Deleted Path Inventory

The following list is exhaustive for tracked file deletions in the audited
range.

### Commit `fb1353b` — 61 paths

```text
crates/erebor-runtime-ipc/src/standalone/codec.rs
crates/erebor-runtime-ipc/src/standalone/decision.rs
crates/erebor-runtime-ipc/src/standalone/envelope.rs
crates/erebor-runtime-ipc/src/standalone/file.rs
crates/erebor-runtime-ipc/src/standalone/mod.rs
crates/erebor-runtime-ipc/src/standalone/request.rs
crates/erebor-runtime-ipc/src/standalone/tests.rs
crates/erebor-runtime-ipc/src/standalone/tests/decision.rs
crates/erebor-runtime-ipc/src/standalone/tests/envelope.rs
crates/erebor-runtime-ipc/src/standalone/tests/request.rs
crates/erebor-runtime-session/build.rs
crates/erebor-runtime-session/src/agents/codex/guard_lifecycle.rs
crates/erebor-runtime-session/src/error/interception_broker.rs
crates/erebor-runtime-session/src/interception_backend.rs
crates/erebor-runtime-session/src/interception_backend/env.rs
crates/erebor-runtime-session/src/interception_backend/guard_artifact.rs
crates/erebor-runtime-session/src/interception_backend/inputs.rs
crates/erebor-runtime-session/src/interception_backend/linux_ptrace.rs
crates/erebor-runtime-session/src/interception_backend/path.rs
crates/erebor-runtime-session/src/interception_backend/process_bundle.rs
crates/erebor-runtime-session/src/interception_setup.rs
crates/erebor-runtime-session/src/os/linux/process_guard.rs
crates/erebor-runtime-session/src/os/linux/process_guard/broker.rs
crates/erebor-runtime-session/src/os/linux/process_guard/cgroup.rs
crates/erebor-runtime-session/src/os/linux/process_guard/file_interception.rs
crates/erebor-runtime-session/src/os/linux/process_guard/interception.rs
crates/erebor-runtime-session/src/os/linux/process_guard/interception/broker.rs
crates/erebor-runtime-session/src/os/linux/process_guard/interception/executable.rs
crates/erebor-runtime-session/src/os/linux/process_guard/interception/handlers.rs
crates/erebor-runtime-session/src/os/linux/process_guard/memory.rs
crates/erebor-runtime-session/src/os/linux/process_guard/rules.rs
crates/erebor-runtime-session/src/os/linux/process_guard/status.rs
crates/erebor-runtime-session/src/os/linux/process_guard/sys.rs
crates/erebor-runtime-session/src/os/linux/process_guard/trace.rs
crates/erebor-runtime-session/src/runtime_interception_broker.rs
crates/erebor-runtime-session/src/runtime_interception_broker/audit.rs
crates/erebor-runtime-session/src/runtime_interception_broker/client.rs
crates/erebor-runtime-session/src/runtime_interception_broker/constants.rs
crates/erebor-runtime-session/src/runtime_interception_broker/decision.rs
crates/erebor-runtime-session/src/runtime_interception_broker/endpoint.rs
crates/erebor-runtime-session/src/runtime_interception_broker/handlers.rs
crates/erebor-runtime-session/src/runtime_interception_broker/platform.rs
crates/erebor-runtime-session/src/runtime_interception_broker/protocol.rs
crates/erebor-runtime-session/src/runtime_interception_broker/server.rs
crates/erebor-runtime-session/src/runtime_interception_broker/service.rs
crates/erebor-runtime-session/src/runtime_interception_broker/tests.rs
crates/erebor-runtime-session/src/runtime_interception_broker/tests/browser_mediation.rs
crates/erebor-runtime-session/src/runtime_interception_broker/tests/client_failure.rs
crates/erebor-runtime-session/src/runtime_interception_broker/tests/file_operation.rs
crates/erebor-runtime-session/src/runtime_interception_broker/tests/fixtures.rs
crates/erebor-runtime-session/src/runtime_interception_broker/tests/fixtures/broker.rs
crates/erebor-runtime-session/src/runtime_interception_broker/tests/fixtures/handlers.rs
crates/erebor-runtime-session/src/runtime_interception_broker/tests/fixtures/mediation.rs
crates/erebor-runtime-session/src/runtime_interception_broker/tests/fixtures/request.rs
crates/erebor-runtime-session/src/runtime_interception_broker/tests/lifecycle.rs
crates/erebor-runtime-session/src/runtime_interception_broker/tests/process_exec.rs
crates/erebor-runtime-session/src/runtime_interception_broker/tests/registration.rs
crates/erebor-runtime-session/src/runtime_interception_broker/tests/socket_connect.rs
crates/erebor-runtime-session/src/runtime_interception_broker/wire.rs
crates/erebor-runtime-session/tests/linux_process_guard.rs
crates/erebor-runtime-session/tests/linux_process_guard_broker.rs
```

### Commit `3a4a926` — 6 paths

```text
crates/erebor-runtime-ipc/proto/erebor/runtime/ipc/v1/envelope.proto
crates/erebor-runtime-ipc/proto/erebor/runtime/ipc/v1/guard.proto
crates/erebor-runtime-ipc/src/codec.rs
crates/erebor-runtime-ipc/src/error.rs
crates/erebor-runtime-ipc/src/frame.rs
crates/erebor-runtime-ipc/src/v1/operation.rs
```

### Commit `2a15ba1` — 2 paths

```text
crates/erebor-runtime-terminal/src/tests/fixtures.rs
crates/erebor-runtime-terminal/src/tests/mediation.rs
```

## Map Closure Evidence

The documentation audit on 2026-08-21 produced these results:

- Git reports 69 tracked file deletions from `7496a29` through `36c05d3`.
- Every deleted path appears exactly once in the path inventory.
- No path in the inventory is absent from the Git deletion set.
- The semantic ledger includes all 12 commits that removed or replaced code.
- `rtk cargo test -p erebor-runtime-ipc --test contract --test closure`
  passed two tests in two suites.
- `git diff --check` passed for the documentation change.

This audit changes documentation only. The full Rust CI result recorded in the
parent phase still covers the last Rust change at `f59fd04`.

## Required Work Before `Done`

- [x] Remove all dead daemon dispatcher code after the typed daemon tests pass.
- [x] Remove guard-only lease and physical-effect code that has no hook or app-server caller.
- [x] Keep hook and app-server lease behavior that still has an authenticated caller.
- [x] Replace internal idempotency response tags with typed response storage.
- [x] Delete `guard.proto`, `envelope.proto`, the frame codecs, and their exports.
- [x] Complete the Runtime and Mithril descriptor inventories.
- [x] Complete the static closure test over supported source, packaging, and examples.
- [x] Record every unsupported capability in the phase result and review guide.

## Review Stop Conditions

Stop the implementation and request a product decision if a current supported
test or production path still needs ptrace to provide authorization,
attribution, recovery, evidence, or a physical deny. Do not label a gRPC
transport result as equivalent physical enforcement.
