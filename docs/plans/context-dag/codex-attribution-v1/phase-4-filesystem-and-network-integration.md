# Phase 4: Filesystem And Network Governance Integration

Status: Proposed. Blocked on Phase 3 and explicit implementation approval.

## Purpose

Connect V1 leases to the existing Linux filesystem session view and to a
proven Linux network enforcement boundary without duplicating either domain.

## Scope

- Define a narrow context-bearing action authorization request from the Codex
  lease owner to `erebor-runtime-filesystem`.
- Ensure the Linux OverlayFS session view is prepared before enrolled Codex
  execution and that raw host paths/unauthorized descriptors cannot bypass the
  view under the selected source profile.
- Route supported open/read/mutation decisions through the existing filesystem
  surface with exact runtime/item lease context.
- Preserve existing filesystem manifest, checkpoint, promotion, rollback, and
  transaction ownership. This phase does not redesign storage.
- Establish the Linux network enforcement adapter and rule-distribution owner
  selected by Phase 0. It must bind process lifetime/session/health facts and
  default deny a profiled runtime without a current rule.
- Test direct Internet, DNS/literal IP, IPv4/IPv6, loopback/raw-CDP, Unix-local
  service, proxy/helper, reused connection, broker/guard restart, and network
  namespace/cgroup bypass cases.
- Treat request-level attribution for a long-lived/reused connection as
  unavailable unless a gateway or direct protocol handoff carries the exact
  invocation key.
- Make filesystem/network health loss invalidate affected coverage and deny new
  strict work; it never retrospectively reattributes an already-open descriptor
  or flow.

## Tests

- Existing filesystem lifecycle tests gain a V1 context/lease fixture without
  changing Linux overlay behavior for non-Codex sessions.
- E2E verifies allowed overlay changes, denied raw-host/descriptors, checkpoint,
  promotion, and rollback retain the exact decision context where available.
- Network fixtures prove default deny, allowed command-descendant flow, denied
  direct/loopback bypass, failure/restart behavior, and honest session-only
  classification for reused connections.

## Checkpoint

```sh
cargo fmt
cargo test -p erebor-runtime-filesystem --all-targets --all-features
cargo test -p erebor-runtime-session --all-targets --all-features
EREBOR_REQUIRE_CODEX_LINUX_V1_PROBE=1 \
  cargo test -p erebor-runtime-e2e --test codex_linux_v1_lifecycle \
  filesystem_and_network -- --test-threads=1 --nocapture
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

## Acceptance

- Codex action leases reach existing filesystem policy without owning it.
- Linux workspace isolation and rollback remain unchanged and context-aware.
- Direct and loopback network behavior is governed by a proven native owner.
- Reused flows do not receive invented invocation attribution.

## Stop Point

Stop after filesystem/network lifecycle verification. Wait for Phase 5
approval.

## Phase Result

State: Not started.
