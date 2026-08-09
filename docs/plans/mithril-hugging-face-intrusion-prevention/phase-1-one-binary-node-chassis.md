# Phase 1: One-Binary Node Chassis

Status: Blocked at the repository-wide test gate; implementation and
Phase-1-specific acceptance are complete.

Master: [Mithril Hugging Face Intrusion Prevention](./README.md)
Design: [Validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
Manual acceptance: [Phase 1 runbook](./manual-testing/phase-1-manual-acceptance.md)  
Environment setup: [shared setup guide](./manual-testing/environment-setup.md)

## Purpose

Ship the shared Interceptor owner, one `mithril-node` process, one
`mithril-control` service, and their secure control channel without claiming
effect prevention yet.

## Scope And Design Coverage

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

An outage never adds a per-effect Control round trip and never invalidates a
still-valid installed local generation. It blocks only new work requiring
missing, expired, or unverified Control-owned state.

No public control API contract is required in this phase.

### D1.5 — Runtime coexistence client

Implement the Phase 0-approved adapter from the existing Runtime interception
broker to the shared Interceptor. In co-resident mode it is authenticated,
cgroup-scoped, and read-only. It cannot load BPF, change Mithril identity or
policy, consume exceptions, or invoke response.

### D1.6 — Packaging and lifecycle fixture

Add reproducible development binaries, image, DaemonSet, and Helm skeletons
with the exact required host mounts/capabilities and one node container. The
CI build produces the supported development-architecture artifacts consumed
by the lifecycle fixture. Run the worker unchanged through startup, restart,
shutdown, control outage, node reconnect, and second-owner attempts.

## Checkpoint

The unchanged worker boots under exactly one Interceptor owner, node and
Control mutually authenticate and reconnect, and readiness reports only
measured chassis capability. No effect-prevention claim is enabled.

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

```text
State: Blocked at the repository-wide verification gate; D1.1-D1.6 implementation and Phase-1-specific acceptance are complete.
Validated architecture revision/digest: policy-and-protection-algorithm-architecture-readable.md at SHA-256 4a445b4015c4868a87af4893398068c5f362452c316d0cb8d06c038d41ffc0d8.
Completed deliverable IDs: D1.1-D1.6.
Files and durable owners changed: erebor-interceptor owns the single safe libbpf-rs lifecycle and lease; mithril-node embeds it and owns node state, inventory, trust cache, readiness, outbound Control stream, reconnect, local observation, and shutdown; mithril-control owns the private mTLS bidirectional gRPC stream and registration/trust state; erebor-runtime-client owns the bounded read-only Mithril observation client; existing Runtime IPC owns the additive immutable observation envelopes; mithril-e2e owns lifecycle and packaging acceptance; packaging/mithril owns the development image, one-container privileged DaemonSet, Control deployment, and Helm skeleton.
Dependency and upstream practice decision: use pinned fully vendored libbpf-rs 0.27.0 directly for safe object/load/attach/map/link/pin/readback/RAII ownership. The owner follows checked fresh-map, exact-ID readback, pin, lease, and rollback practices without copying an upstream daemon or adding a libbpf-cargo skeleton that this phase does not need. Tonic 0.12.3 and its standard TLS/HTTP2 keepalive are used for the private control stream.
Fixture cases and exact physical results: the privileged lifecycle artifact starts ready with 3/3 maps and 21/21 links pinned and read back; rejects a competing owner; removes pins on clean shutdown; restarts ready with 3/3 maps and 21/21 links; removes pins again; and preserves worker digest 741a9fd0857e360a8b3096924f52dd59695d9f6440aa6610370e4e092b23b1dc. Raw artifact SHA-256 892d34285a709042489cdbcd35874d32ee343c80307a001fb9a2f5530e3fe0bd; checked result SHA-256 c5dc41cc9f9efd34b9be4597e9e9c31c5ffdf936385e1a29a72f50f787382936. BOOT-ADMISSION-001, same-lease Runtime/Mithril/co-resident ownership, partial-pin rollback, missing-hook rejection, mTLS CA/node binding, expired identity, registration replay, sequence gap, downgrade, control outage, reconnect, trust rollback/replay, scoped read-only Runtime observation, and packaging tests pass.
Commands and exact source state covered: cargo check --workspace passed; cargo clippy --workspace --all-targets --all-features -- -D warnings passed; cargo test over erebor-interceptor-abi, erebor-interceptor, erebor-runtime-client, erebor-runtime-ipc, mithril-control, mithril-node, and mithril-e2e with all targets/features passed 91 tests in 14 suites. The repository CI procedure was run after the final Rust edit with host socket access; all prior stages/tests passed until unrelated test browser_cdp_mediation_lifecycle invoked the rejected `erebor session diagnose` subcommand. The current CLI has an explicit test that this removed command is rejected, and neither file is part of this phase diff.
Platform/kernel/runtime manifests: x86_64 Linux 6.8.0-137-generic; LSM order lockdown,capability,landlock,yama,apparmor,bpf; runtime BTF SHA-256 6da9f6b4ebcae9b07e6a717b517884abf7f6b524e46340e40fb164eed4a49a7c; object SHA-256 a2e9089e0a199ec94cabf449413425809bc7243266ebaacd05c8f2c00de68972. The node advertises measured chassis readiness only and effect_prevention_claims_enabled is false.
Performance/capacity results: Phase 0's recorded x86 benchmark is unchanged. Phase 1 adds no per-effect Control round trip and no prevention hot path.
Unsupported/degraded paths: all effect-specific identity, observation, and prevention remain excluded. Phase 2 owns the first real lifecycle/task/process/exec identity BPF work; Phase 3 adds observe-only effect classifiers; Phase 4 adds non-network pre-effect enforcement; Phase 5 adds network/DNS/final-flow/packet enforcement. The Phase 0 object remains a qualification object, not a production prevention claim.
Remaining work in this phase: resolve the unrelated stale CDP lifecycle invocation and rerun bash .github/scripts/verify-rust-ci.sh. There is no known Phase 1 implementation or acceptance gap.
Next phase not authorized: yes.
```
