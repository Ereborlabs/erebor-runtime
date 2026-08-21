# Removed Code Replacement Map

Status: Active implementation control for Phase 6.1.

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
| Process-guard resource and identity setup | Preserved without ptrace | The Linux session controller applies no-new-privileges, resource limits, umask, supplementary groups, GID, and UID before it starts the admitted workload. | Add controller tests for each privilege input and a real Linux launch test. |
| Runtime interception socket and guard lifecycle protocol | Removed | No supported Runtime guard remains. | Delete the broker, guard messages, build artifact, packaging path, and standalone codec. A static closure test rejects their return. |

## IPC Replacement

| Removed code | Replacement owner | Required proof before deletion |
| --- | --- | --- |
| Daemon frame dispatcher and daemon hello exchange | Typed services in `daemon.proto`; `erebor-runtime-daemon` keeps domain state; `erebor-runtime-client` stays a generated-client wrapper. | Unary, stream, cancellation, deadline, idempotency, restart, and stale-socket tests use generated clients. |
| Codex hook envelope | `HookService.Open`; `CodexHookService` keeps registration and event ownership. | The server uses `SO_PEERCRED`, rechecks `/proc` identity, validates the registered profile ancestry, rejects client ticket authority, and rejects peer replay. |
| Mithril observation envelope | `RuntimeObservationService.GetSnapshot`; the existing observation owner keeps UID and cgroup authorization. | Test UID, PID, cgroup, response bounds, readiness, coverage, and event truncation through gRPC. |
| `NodeControl.OpenStream` unions | Typed `NodeRegistry`, `NodeTrust`, `NodeEvidence`, `NodeCoverage`, `NodeAdministrativeResolution`, and `NodeAdministrativeArm` services. | Test mTLS identity, boot epoch, replay, durable evidence acknowledgement, coverage revision, reconnect, cancellation, and service isolation. |
| Frame header, generic envelope, message-kind strings, and transport versions | Versioned Protobuf packages and generated gRPC method paths. | Descriptor inventory and static closure tests pass after the last consumer moves. |

## Required Work Before `Done`

- [ ] Remove all dead daemon dispatcher code after the typed daemon tests pass.
- [ ] Remove guard-only lease and physical-effect code that has no hook or app-server caller.
- [ ] Keep hook and app-server lease behavior that still has an authenticated caller.
- [ ] Replace internal idempotency response tags with typed response storage.
- [ ] Delete `guard.proto`, `envelope.proto`, the frame codecs, and their exports.
- [ ] Complete the Runtime and Mithril descriptor inventories.
- [ ] Complete the static closure test over supported source, packaging, and examples.
- [ ] Record every unsupported capability in the phase result and review guide.

## Review Stop Conditions

Stop the implementation and request a product decision if a current supported
test or production path still needs ptrace to provide authorization,
attribution, recovery, evidence, or a physical deny. Do not label a gRPC
transport result as equivalent physical enforcement.
