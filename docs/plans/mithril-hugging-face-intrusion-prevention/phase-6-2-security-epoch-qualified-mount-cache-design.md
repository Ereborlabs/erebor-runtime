# Phase 6.2 Independent Runtime Mount-Cache Generation Design Proposal

Status: Implemented in source with incomplete lifecycle and Kubernetes
qualification. Git commit `8c66f0c3` preserves the earlier security-epoch-key
experiment. Stash `487a32fcdd873f43b84c9a157fa0a8e9d3b5e793` preserves the state before that
experiment. This document does not change the signed policy model or the
exact-object contract.

Parent: [Phase 6.2 Control Policy And Evidence Convergence](./phase-6-2-control-policy-and-evidence-convergence.md)

Implementation review: [Phase 6.2 review guide](./phase-6-2-implementation-review.md)

## Problem And Invalidated Design

The kernel mount namespace has a raw event counter. Linux can advance this
counter during detached mount work even when the protected namespace has the
same visible mount topology after the work completes. Stock `runc` can perform
this work while it seals an executable for a later container exec.

The first experiment replaced the raw namespace event in each cache key with
the BPF-owned mount security-view epoch. One event-only transition then reused
the same cache when all of these security facts remained unchanged:

- the protected mount namespace identity;
- the namespace-root unique mount identity;
- the task walk root;
- the security-view mutation epoch;
- the pending-mutation count; and
- the visible `mountinfo` snapshot.

The lightweight K3s-runtime reproduction observed this state:

```text
mount activity sequence: increased
raw namespace event:     1366 -> 1437
security-view epoch:     22 -> 22
pending mutations:       0
mountinfo digest:        unchanged
ready cache states:      2 -> 3
```

BPF published the third state after a complete build. The Rust oracle then
failed because it required equality of the complete global ready-key set. The
Kubernetes oracle correctly required only the protected snapshot's prior keys.
This result did not prove that policy or the protected topology changed.

The next failure exposed a different defect. A ready state recorded 30 mounts,
but the live namespace had 31 mounts. The signed policy and the protected
namespace identity remained unchanged. The cache hit reported stage 15 and
denied the effect. It did not build a replacement.

The design that used the security-view epoch as the complete cache generation
and denied a ready-state count mismatch is invalid. It has two defects:

- A runtime cache repair cannot advance its own publication identity unless a
  security-view mutation also advances.
- A stale ready state denies every later effect instead of publishing a
  complete replacement.

The signed policy generation must remain stable unless signed policy changes.
The mount security-view epoch must remain the mutation fence. The runtime mount
cache needs a separate BPF-owned generation that can advance for a confirmed
topology change or a stale-cache repair.

## Existing Classification

BPF already separates activity evidence from security-view invalidation.

`mount_global_activity_sequence` records observed mount API activity.
`mount_global_mutation_epoch` advances before an operation that can change a
represented namespace's visible topology or security attributes. The pending
counter blocks access while such a mutation is in progress. Unknown
attribution uses the global fail-closed mutation path.

The existing operation classification remains authoritative:

| Operation | Record activity | Advance a security-view epoch |
| --- | --- | --- |
| Create or configure a new detached filesystem context | Yes | No |
| `fsmount` that returns a detached mount FD | Yes | No |
| `open_tree` with `OPEN_TREE_CLONE` | Yes | No |
| `move_mount` that attaches or moves a mount | Yes | Yes |
| `FSCONFIG_CMD_RECONFIGURE` | Yes | Yes, or use the global fallback |
| `mount_setattr` on an attached mount | Yes | Yes |
| `mount`, `umount`, or `pivot_root` | Yes | Yes |
| Unknown target or possible propagation | Yes | Use the global fallback |

This classification is not a `runc` exception. It applies to every caller.

## Proposed Cache Identity

Use `canonical_mount_cache_generation` as the runtime cache publication
identity. BPF owns this monotonic number. It is not a signed policy generation,
a mount security-view epoch, a kernel namespace event, or a per-namespace
allocator.

Keep `mount_global_mutation_epoch` as the security-view mutation fence. It
advances before a tracked mutation and blocks cache use while a mutation is
pending. It does not need to advance for a stale-cache repair.

The cache-generation scope is global and conservative. A confirmed topology
change or stale-cache repair in one represented namespace makes the prior
cache generation unreachable in all represented namespaces. This behavior can
cause an extra cache build. It cannot make an old generation current. A
per-namespace cache generation requires complete propagation attribution and
is outside this design.

Use the raw namespace event only as a synchronous race fence.

```text
cache generation identity
  = mount namespace address
  + namespace-root unique mount ID
  + mount security-view epoch
  + runtime cache generation
  + task walk-root mount address
  + task walk-root dentry address

race fence
  = raw namespace event captured for one build or one path walk
```

Keep the existing private cache-key size. Put `security_view_epoch` in the
former raw namespace-event field. Put `cache_generation` in the former
reserved field. The build and path-walk scratch state retain the raw event and
the selected runtime cache generation.

## Build And Publication

The first mount-dependent effect at security-view epoch `S` and runtime cache
generation `G` performs these steps:

1. Read `S` and `G`. Require zero pending mutations.
2. Read the namespace identity, namespace-root identity, task walk root, mount
   count, and raw namespace event `E`.
3. Look for `READY(namespace, S, G, walk root)`.
4. If no ready state exists, scan the complete live mount tree and insert
   candidate rows under `(S, G)`.
5. Read the raw namespace event again and require `E`.
6. Require the same security-view epoch `S`, cache generation `G`, and zero
   pending mutations.
7. Publish the ready state after all candidate rows exist.
8. Resolve the original object and recheck the raw event, security-view epoch,
   cache generation, and pending state before BPF applies the policy result.

The ready state is the publication point. Candidate rows do not authorize an
effect without that state.

## Event-Only Reuse

Assume BPF built a ready cache at raw event `E1`, security-view epoch `S`, and
cache generation `G`. Detached work then advances the raw event to `E2`
without entering a tracked topology mutation.

The next effect performs these steps:

1. Read `S` and `G`. Require zero pending mutations.
2. Read `E2`.
3. Find the existing ready cache by `(S, G)`.
4. Require the current namespace mount count to equal the ready state's
   namespace mount count. A mismatch enters stale ready-state repair.
5. Use its immutable mount-selection rows.
6. Validate every selected mount's namespace, root dentry, and unique mount
   identity as the current walker consumes the row.
7. Recheck `E2`, `S`, and the pending counter before the decision.

If the raw event changes during the effect, BPF denies that effect. A later
effect can retry against the same cache generation after the event is stable.
BPF does not publish another cache generation only because detached activity
changed the raw event before the effect started.

## Relevant Mutation

A relevant mutation advances the security-view epoch before the visible
change. The mutation attempt records the namespace event and mount count. The
raw syscall exit hook compares both values after the operation. A confirmed
change advances the runtime cache generation before it clears the pending
mutation count.

```text
READY(S, G)
  -> relevant mutation begins
  -> pending > 0 and security-view epoch becomes S+1
  -> effects deny
  -> namespace event or mount count changes
  -> cache generation becomes G+1
  -> pending becomes 0
  -> next effect builds READY(S+1, G+1)
  -> old READY(S, G) is not selected
```

The raw namespace event remains an additional race fence. It does not replace
the mutation hook or the fail-closed global fallback.

## Stale Ready-State Repair

A ready-state count mismatch is a repair trigger. It is not a permanent deny
condition.

1. Read the current cache generation `G`.
2. Find `READY(namespace, S, G, walk root)` with a stale mount count.
3. Change the global cache generation from `G` to `G+1` with one compare and
   swap.
4. Let the compare-and-swap winner build all candidate rows under `G+1`.
5. Publish `READY(namespace, S, G+1, walk root)` only after the complete scan
   and all race checks pass.
6. Evaluate the original effect with the new cache.
7. Deny a concurrent loser. It can retry against `G+1`.

If a build fails after it inserts candidate rows, BPF advances the generation
again. This action makes the incomplete candidate rows unreachable. Explicit
row retirement remains separate work.

## Concurrency And Failure Rules

- A ready state must never publish before its complete row set.
- A cache hit requires the current security-view epoch, runtime cache
  generation, and zero pending mutations.
- A cache hit requires the live namespace mount count recorded by the ready
  state. A mismatch rotates the runtime cache generation and rebuilds.
- A path walk must deny if its raw namespace event changes while it runs.
- A build must deny if its raw namespace event, security-view epoch, runtime
  cache generation, or pending state changes before publication.
- A selected mount row must still match its namespace, root dentry, and unique
  mount ID when BPF consumes it.
- A relevant mutation blocks effects before the visible change. Its completion
  makes the prior cache generation unreachable before a later effect can use
  it.
- A failed build can leave candidate rows, but no failed build can publish a
  ready state. BPF rotates away from candidate rows after a failed build. A
  later lifecycle change must retire unreachable rows.
- A reader must recheck its cache generation before it applies a policy result.
  A concurrent generation change denies that reader.
- Exact-object event validation remains unchanged in this experiment.

## Policy Separation

This design changes runtime cache qualification only.

- A signed policy generation changes only after an accepted signed policy
  change.
- Signed entry declarations and roles remain stable for the binding and policy
  generation.
- Canonical initial mount routes remain binding-scoped policy material.
- Detached mount activity does not reinstall policy rows.
- A relevant mount mutation changes runtime evidence, not signed policy.
- The retained seccomp server remains unlinked from the active OCI path.

## Implementation Surface

| File | Change |
| --- | --- |
| `crates/erebor-interceptor-abi/src/abi/path.rs` | Record the namespace address, event, and mount count for one tracked mutation attempt. |
| `bpf/erebor-interceptor/programs/identity_maps.h` | Add the global runtime cache generation. Key ready states and rows by the security-view epoch and runtime cache generation without changing the private cache-key sizes. |
| `bpf/erebor-interceptor/programs/identity_path.bpf.h` | Advance the runtime cache generation after a confirmed topology change. Rotate and rebuild after a stale ready-state count. Recheck the generation before a decision. |
| `crates/mithril-node/src/policy.rs` | Initialize and validate the BPF-owned runtime cache generation without changing signed policy rows. |
| `crates/mithril-e2e/src/effect/runc.rs` | Require detached-activity stability, confirmed-mutation generation advance, and deterministic stale-cache repair. |
| `crates/mithril-e2e/harness/vm/two-node-convergence.sh` | Apply the same cache-stability rule and capture a final timeout snapshot. |

## Qualification

Run the tests in this order:

1. Compile the BPF object and run focused Rust tests.
2. Run the lightweight direct-runc case with the distribution runtime.
3. Run the lightweight case with the exact K3s-bundled runc and containerd.
4. Require detached activity to advance the activity sequence without
   advancing the security-view epoch, cache generation, or protected ready
   key set.
5. Require the concurrent protected read to produce a normal
   `PATH_TREE_POLICY_DENY` result with no `UNRESOLVED_OBJECT` result.
6. Require runc's confirmed post-create mount work to advance both the
   security-view epoch and runtime cache generation.
7. Corrupt the active ready-state mount count without changing live topology.
   Require the next protected effect to rotate the cache generation, publish a
   replacement, and return its normal policy result with no unresolved object.
8. Run a separate attached-mutation case. Require a new security-view epoch
   and a new ready cache generation after reconciliation.
9. Run the paired Kubernetes case only after the lightweight cases pass.
10. Capture cache, epoch, event, process, and stop-marker visibility evidence if
   the Kubernetes reader does not finish.

The Kubernetes result is complete only when the six entry roles pass, the
concurrent reader finishes after the stop marker, the stable follow-up read
passes its denial oracle, and no unresolved object appears.

## Rejected Shortcuts

Do not add a ready state for a new raw event while its rows still use the old
event. The lookup would miss the rows.

Do not delete and replace rows in the current generation. A concurrent reader
can still use those rows. Publish under a new generation and make the prior
generation unreachable.

Do not deny every later effect after a ready-state count mismatch. Rotate the
runtime cache generation, build a complete replacement, and recheck the
generation before the decision.

Do not advance the signed policy generation for a mount event or cache repair.
These operations change runtime evidence only.

Do not trust an endpoint `mountinfo` digest as the synchronous kernel guard.
The digest is test evidence. It does not protect a BPF decision from a
concurrent mutation.

Do not ignore the raw namespace event. It remains the race detector for one
build and one path walk.

Do not weaken `exact_mount_events` as part of this cache experiment. Exact
object identity has a separate transition and ambiguity contract.

## Result Record

Not done.

The current implementation uses the working tree based on `8c66f0c3`. The
earlier checkpoint stash remains available as
`487a32fcdd873f43b84c9a157fa0a8e9d3b5e793`.

The following focused checks pass:

```text
rtk cargo check -p erebor-interceptor -p mithril-node -p mithril-e2e
rtk cargo test -p erebor-interceptor-abi \
  canonical_path_abi_is_bounded_and_padding_is_explicit
rtk cargo test -p mithril-e2e \
  capability::tests::every_checked_in_vmlinux_header_compiles_the_production_identity_object \
  --lib
rtk cargo test -p erebor-interceptor -p mithril-node -p mithril-e2e --lib
344 passed; 2 ignored
rtk cargo run -p mithril-e2e --bin mithril-effect-test -- \
  --repo-root . compile-retained-identity \
  --output-directory target/mithril-r188-retained-build
rtk bash .github/scripts/verify-rust-ci.sh
Format, workspace check, strict Clippy, and complete workspace tests passed.
```

The mount-hook trace records this sequence for the protected `/proc/scsi`
mount:

- runc called `mount("tmpfs", "/proc/scsi", ..., MS_RDONLY)`;
- `security_sb_mount` ran in the represented namespace;
- the tracked mutation branch ran;
- the kernel committed the mount; and
- the namespace event, mount count, and global mutation epoch advanced.

This trace proves that the normal `/proc/scsi` operation is not outside the BPF
hook set. It does not prove which intermittent condition produced the earlier
30-to-31 stale ready state.

The distribution-runc probe with object `r185` loaded through the real kernel
verifier. It passed the detached-exec cache-stability check and the
deterministic stale-ready-state repair. The repair kept the security-view epoch
and live `mountinfo` digest stable, advanced the runtime cache generation,
published a new protected ready-key set, returned `PATH_TREE_POLICY_DENY`, and
reported no `UNRESOLVED_OBJECT`. The probe then stopped at the pre-existing
external-cgroup test because its expected cgroup path was absent. Its partial
output is
`/var/tmp/mithril-runtime-qualification-3098320/r185-stock-runc` on VM
`mithril-runtime-qualification-3098320`.

The K3s-runc probe with object `r188` also loaded through the real verifier. It
passed the prepublication generation check, confirmed post-create generation
advance, detached-exec stability, and deterministic stale-cache repair. It then
stopped in the later external-cgroup case because the expected runtime cgroup
was absent. Its partial output is
`/var/tmp/mithril-runtime-qualification-3098320/r188-k3s-prepublication` on the
same retained VM.

These partial runs prove the new cache transitions. They do not prove the
complete direct-runc lifecycle or the Kubernetes lifecycle. The paired
Kubernetes case has not run with this implementation. Explicit retirement of
unreachable candidate and ready rows, the intermittent stale-state capture,
the complete direct-runc lifecycle, the paired Kubernetes concurrent-read
proof, and the complete phase acceptance matrix remain open.
