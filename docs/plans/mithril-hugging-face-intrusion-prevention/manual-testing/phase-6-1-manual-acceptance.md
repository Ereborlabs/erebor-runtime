# How To Manually Accept Phase 6.1

Status: Ready. Automated acceptance passed on 2026-08-21. This manual
procedure has not been run.

Phase: [gRPC Service And IPC Convergence](../phase-6-1-grpc-service-and-ipc-convergence.md)

Setup: [`SINGLE-NODE`](./environment-setup.md), with one Runtime daemon,
one local client, one hook client, one `mithril-node`, and one
`mithril-control`

## Outcome

Prove that supported local and node-control operations use typed gRPC methods.
Prove that authorization, streaming, bounds, replay state, and durable
acknowledgements remain correct without the custom envelope protocol.

## Automated Companion

```text
PASS: rtk bash .github/scripts/verify-rust-ci.sh
PASS: rtk cargo test -p erebor-runtime-e2e --test session_review (2 tests)
PASS: rtk cargo test -p erebor-runtime-terminal --lib (3 tests)
PASS: rtk cargo test -p mithril-e2e --lib (70 tests)
```

## Procedure

1. Record the source revision, generated descriptor digest, service and method
   list, binaries, socket paths, socket owners and modes, local peer UIDs, node
   certificate identity, node boot epoch, and Control address.
2. Start the Runtime daemon. Use generated clients to run one unary lifecycle
   request and one server stream. Run the bidirectional hook and Mithril
   administrative streams in the later steps.
3. Submit one valid hook event. Repeat with a wrong session, a replayed peer,
   an unregistered copied executable, a wrong peer, and an oversized event.
   Verify that only the valid event reaches the existing session owner.
4. Request one Mithril observation snapshot from the allowed UID and cgroup.
   Repeat from a wrong UID and a process outside the allowed cgroup.
5. Connect `mithril-node` to Control. Exercise registration, readiness, trust,
   evidence, coverage, administrative resolution, and administrative arm on
   their separate service methods.
6. Delay and cancel each streaming RPC. Stop and restart each endpoint. Verify
   bounded cancellation, reconnect, socket cleanup, boot identity, replay,
   and durable cursor behavior.
7. Apply request, response, concurrency, and slow-consumer pressure at each
   transport boundary. Verify stable gRPC status, bounded memory, and no
   authorization or durable-acknowledgement change.
8. Attempt the old frame protocol, a wrong gRPC service method, an unavailable
   package, and a stale client. Verify a bounded rejection without
   cross-service dispatch or fallback.
9. Inspect the built binaries, generated descriptors, source references, and
   packaging. Verify that no supported path contains the custom envelope,
   frame codec, message-kind dispatcher, standalone codec, or ptrace
   process-guard launch path. If a non-ptrace Runtime guard remains, verify its
   typed gRPC service.
10. Repeat the Phase 6 evidence outage and replay control. Verify that Control
    acknowledges only a durable contiguous range and that the node removes no
    earlier WAL record.

## Required Oracles

| Case | Required result |
| --- | --- |
| Typed unary RPC | One method reaches one existing owner and returns its typed result |
| Typed stream | Cancellation, backpressure, reconnect, and completion remain bounded |
| Wrong local peer | The RPC rejects before domain state changes |
| Wrong TLS peer | The RPC rejects before registration or durable state changes |
| Wrong service or package | gRPC rejects the method; no generic dispatcher handles it |
| Oversized message | `RESOURCE_EXHAUSTED` or the documented bounded equivalent; no partial state |
| Deadline or cancellation | Work stops at the owning cancellation boundary; no false success |
| Evidence retry | Only a durable contiguous Control commit advances the node cursor |
| Old frame client | Connection or method rejection; no protocol downgrade |
| Removed ptrace configuration | Configuration rejection; no silent ungoverned fallback |
| Remaining Runtime guard | Typed gRPC service on the common Unix transport; no standalone codec |

## Required Artifacts And Pass Rule

Retain the generated descriptor set, method inventory, local peer records,
socket metadata, TLS identities, gRPC status results, stream cancellation and
pressure results, reconnect history, evidence batches, durable commits,
acknowledgements, WAL before and after state, binary reference scan, and
packaging inventory. Pass requires one typed method per supported operation,
no custom-frame fallback, no ptrace process-guard exception, no authorization
regression, and no false durable acknowledgement.

## Troubleshooting

- A gRPC package version replaces a generic transport-version field. It does
  not replace a policy, trust, boot, coverage, or evidence generation.
- HTTP/2 stream order does not prove replay safety after reconnect. Inspect the
  domain cursor or generation.
- A successful Unix connection does not authorize the request. Inspect
  `SO_PEERCRED` and the service-specific authorization result.
- If a supported path still launches the ptrace process guard, record
  `Blocked`. Do not keep the old codec as an exception.
