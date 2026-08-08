# Phase 1: One-Binary Node Chassis

Status: Proposed; depends on Phase 0 `Done`.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)
Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)

## Purpose

Ship the shared Interceptor owner, one `mithril-node` process, one
`mithril-control` service, and their secure control channel without claiming
effect prevention yet.

## Design Coverage

Chapters 5, 14, 27-30, 32, and 34; Appendices A.3-A.7 and A.12-A.13.

## Deliverables

### D1.1 — Shared Interceptor ABI and host component

Create the Phase 0-approved `erebor-interceptor-abi`, generated C header,
owned BPF source root, and `erebor-interceptor` host owner. Implement kernel
preflight, load/attach, exact manifest readback, links/maps, pin-root lease,
boot/label epochs, readiness, clean shutdown, and structured errors.

### D1.2 — Exclusive owner and partial-attach safety

Prove one owner across Runtime-only, Mithril-only, and co-resident modes. A
second owner, stale pin set, partial attach, ABI mismatch, missing required
hook, or changed program digest cannot become ready. Rollback leaves either the
previous complete generation or no advertised capability.

### D1.3 — `mithril-node` chassis

Create one Rust binary that embeds the Interceptor and owns capability state,
workload inventory, local config/trust cache, health, lifecycle, and shutdown.
No second privileged helper or sidecar is introduced.

### D1.4 — `mithril-control` chassis and secure gRPC

Create the control service and the minimum node-control gRPC needed for:

- mutually authenticated node registration;
- node boot/platform/capability/readiness reports;
- control trust-generation delivery and acknowledgement;
- monotonic stream sequence, keepalive, reconnect, and backoff; and
- fail-closed admission when required control/trust state is unavailable.

No public control API contract is required in this phase.

### D1.5 — Runtime coexistence client

Implement the Phase 0-approved adapter from the existing Runtime interception
broker to the shared Interceptor. In co-resident mode it is authenticated,
cgroup-scoped, and read-only. It cannot load BPF, change Mithril identity or
policy, consume exceptions, or invoke response.

### D1.6 — Packaging and lifecycle fixture

Add development image/DaemonSet/Helm skeletons with the exact required host
mounts/capabilities and one container. Run the worker unchanged through
startup, restart, shutdown, control outage, node reconnect, and second-owner
attempts.

## Required Tests And Fixtures

- `BOOT-ADMISSION-001`.
- `SOURCE-KA-PARTIAL-ATTACH-001`, `SOURCE-KA-CAPACITY-005`.
- Runtime-only, Mithril-only, and co-resident exclusive-owner integration tests.
- gRPC wrong-CA, wrong-node, expired identity, replayed registration, sequence
  gap, control outage, reconnect, and downgrade tests.
- Applicable live two-node lifecycle probe sections.

## Acceptance

- Exactly one process owns the pin root and raw kernel stream on each node.
- Node and Control authenticate each other and reconnect without reusing boot
  or stream identity.
- Capability/readiness reports reflect physical attach/readback results.
- Runtime consumes the shared component without creating another authority.
- No local effect-prevention claim is exposed.

## Excluded

Actor identity, policy compilation, effect-specific observation/enforcement,
durable evidence, graphing, and response.

## Phase Result

State: Not done.  
Completed deliverables: none.  
Verification: not run; this is a plan rewrite.  
Next phase: not authorized.
