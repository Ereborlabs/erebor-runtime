# Removed Code Replacement Map

Status: Done. The implementation used this map as its deletion control.

Parent: [Phase 6.1](./phase-6-1-grpc-service-and-ipc-convergence.md)

## Rule

Delete a legacy path only after this map identifies its replacement owner or
marks its capability unsupported. An unsupported capability must reject its
old configuration or request. It must not continue through an ungoverned
fallback.

## Process Guard Removal

| Removed capability | Decision | Current owner or boundary | Required proof |
| --- | --- | --- | --- |
| Linux ptrace process-exec interception | Unsupported | No replacement is approved in this phase. The shared Interceptor is not a replacement until a separate Runtime integration owns authorization and lifecycle. | A stale `linux_ptrace` configuration fails deserialization. An enabled session interception request fails validation. |
| Linux ptrace file-open, file-read, and file-mutation interception | Unsupported | Filesystem overlay, retention, preimage, and revert behavior stay with `erebor-runtime-filesystem`. They do not claim syscall policy enforcement. | Remove physical-denial tests that require ptrace. Keep overlay lifecycle and recovery tests. Document the reduced boundary. |
| Linux ptrace socket-connect interception | Unsupported | No replacement is approved in this phase. | Reject enabled session interception. Remove the socket decision claim. |
| Adoption of an existing Linux process | Unsupported | `erebor-runtime-session` rejects Linux-host adoption before launch. | Test the `InvalidAdoptTarget` result. |
| Terminal launch interposition for managed browser replacement | Unsupported | `erebor-runtime-cdp` can still own and launch a configured browser. It does not intercept an arbitrary terminal child process. | Keep owned-browser tests. Remove raw terminal-launch interception claims and examples. |
| Portable terminal policy and decision types | Preserved for Erebor | The logical policy compiler and portable request and decision types remain. They do not have an active physical interception backend. A later Runtime integration can connect them to the shared Interceptor only through an approved owner. | Keep policy compilation and rule serialization tests. Reject the removed session interception configuration. |
| Process-guard resource and identity setup | Preserved without ptrace | The Linux session controller applies no-new-privileges, resource limits, umask, supplementary groups, GID, and UID before it starts the admitted workload. | Add controller tests for each privilege input and a real Linux launch test. |
| Runtime interception socket and guard lifecycle protocol | Removed | No supported Runtime guard remains. | Delete the broker, guard messages, build artifact, packaging path, and standalone codec. A static closure test rejects their return. |
| Historical Runtime audit records | Preserved for Erebor | The audit reader keeps the legacy fields that are required to read existing JSONL evidence. New no-interception sessions do not fabricate a ptrace decision or audit record. | The legacy-record audit test and the no-interception session-review tests pass. The static source scan excludes stored evidence files. |

## IPC Replacement

| Removed code | Replacement owner | Required proof before deletion |
| --- | --- | --- |
| Daemon frame dispatcher and daemon hello exchange | Typed services in `daemon.proto`; `erebor-runtime-daemon` keeps domain state; `erebor-runtime-client` stays a generated-client wrapper. | Unary, stream, cancellation, deadline, idempotency, restart, and stale-socket tests use generated clients. |
| Codex hook envelope | `HookService.Open`; `CodexHookService` keeps registration and event ownership. | The server uses `SO_PEERCRED`, rechecks `/proc` identity, validates the registered profile ancestry, rejects client ticket authority, and rejects peer replay. |
| Mithril observation envelope | `RuntimeObservationService.GetSnapshot`; the existing observation owner keeps UID and cgroup authorization. | Test UID, PID, cgroup, response bounds, readiness, coverage, and event truncation through gRPC. |
| `NodeControl.OpenStream` unions | Typed `NodeRegistry`, `NodeTrust`, `NodeEvidence`, `NodeCoverage`, `NodeAdministrativeResolution`, and `NodeAdministrativeArm` services. | Test mTLS identity, boot epoch, replay, durable evidence acknowledgement, coverage revision, reconnect, cancellation, and service isolation. |
| Frame header, generic envelope, message-kind strings, and transport versions | Versioned Protobuf packages and generated gRPC method paths. | Descriptor inventory and static closure tests pass after the last consumer moves. |

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
